#Requires -Version 7.0
<#
.SYNOPSIS
    Runs PSScriptAnalyzer's security rules and Microsoft's InjectionHunter
    rules over the repository and fails on any finding that is not reviewed.

.DESCRIPTION
    The "PowerShell Security Analysis" CI job, and the same check locally.
    The rules are in PSScriptAnalyzerSecurity.psd1. The analyzer must be the
    pinned version (tools/pinned-modules.psd1), so CI and a workstation judge
    the same code with the same rules; tools/Install-TPPinnedModule.ps1
    installs it.

    An in-source [SuppressMessage()] does not silence these rules: the run
    uses -IncludeSuppressed and a suppressed finding fails like any other,
    named as suppressed.

    InjectionHunter (Microsoft's PSScriptAnalyzer rules for code injection:
    Invoke-Expression, Add-Type, ScriptBlock.Create and the other dangerous
    methods, cmd/powershell with an expandable string, dynamic member and
    method names, hand-rolled quote escaping) runs as a second pass, pinned
    and hash-verified like the analyzer. Its rules are deliberately broad, so
    a finding passes only if it is one of two kinds:
      - Reviewed: listed in tools/injection-baseline.json with the reason it
        is not an injection (matched by file, rule and code text, with a
        count, so a second copy of the same line is new). An entry nothing
        matches any more is stale and also fails, so the list only shrinks.
      - Not escaping: an UnsafeEscaping finding where every -replace in the
        expression replaces with the empty string. The rule flags any
        replacement text containing '' and so cannot tell a removal from a
        quote-doubling escape; the AST can, and removal escapes nothing.
    Anything else fails, and the SARIF carries it to Code Scanning.

    A SARIF file is written on every run when -SarifPath is given, empty when
    nothing was found, so Code Scanning closes an alert once its finding is
    fixed.

    TenantPosture — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Data: PSScriptAnalyzerSecurity.psd1, tools/pinned-modules.psd1 (read).

.PARAMETER Path
    The folder to analyze. Default: the repository root.

.PARAMETER SarifPath
    Where to write the SARIF 2.1.0 results.

.PARAMETER DefinitionsOnly
    Defines the functions and runs nothing (for the tests).
#>
[CmdletBinding()]
param(
    [string] $Path = (Split-Path -Parent $PSScriptRoot),

    [string] $BaselinePath = (Join-Path $PSScriptRoot 'injection-baseline.json'),

    [string] $SarifPath,

    [switch] $DefinitionsOnly
)

# The gate's decision: every finding is a problem, whatever its severity.
# Returns one line per finding; none means the tree passed.
function Get-TPSecurityAnalysisProblem {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [string] $RepoRoot
    )
    Set-StrictMode -Version Latest
    foreach ($f in @($Findings | Where-Object { $null -ne $_ })) {
        $rel = if ($f.ScriptPath) { [System.IO.Path]::GetRelativePath($RepoRoot, $f.ScriptPath) -replace '\\', '/' } else { '(no file)' }
        $suppressed = if ($f.GetType().Name -eq 'SuppressedRecord') { ' [suppressed in source; not allowed]' } else { '' }
        '{0}:{1} {2} ({3}){4}: {5}' -f $rel, $f.Line, $f.RuleName, $f.Severity, $suppressed, $f.Message
    }
}

# SARIF 2.1.0 for Code Scanning. Every finding is an error here, because each
# one fails the build.
function ConvertTo-TPAnalyzerSarif {
    [CmdletBinding()]
    param(
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [string] $RepoRoot,
        [Parameter(Mandatory)] [string] $ToolName,
        [Parameter(Mandatory)] [string] $ToolVersion
    )
    Set-StrictMode -Version Latest
    $results = @(foreach ($f in @($Findings | Where-Object { $null -ne $_ })) {
        $rel = if ($f.ScriptPath) { [System.IO.Path]::GetRelativePath($RepoRoot, $f.ScriptPath) -replace '\\', '/' } else { '' }
        [ordered]@{
            ruleId    = [string]$f.RuleName
            level     = 'error'
            message   = [ordered]@{ text = [string]$f.Message }
            locations = @([ordered]@{
                physicalLocation = [ordered]@{
                    artifactLocation = [ordered]@{ uri = $rel }
                    # SARIF requires line and column >= 1; whole-file rules report 0.
                    region = [ordered]@{ startLine = [Math]::Max(1, [int]$f.Line); startColumn = [Math]::Max(1, [int]$f.Column) }
                }
            })
        }
    })
    [ordered]@{
        '$schema' = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'
        version   = '2.1.0'
        runs      = @([ordered]@{
            tool    = [ordered]@{ driver = [ordered]@{ name = $ToolName; version = $ToolVersion; informationUri = 'https://github.com/PowerShell/PSScriptAnalyzer' } }
            results = $results
        })
    }
}

# One line of code text as the baseline stores it: the finding's first line,
# whitespace runs collapsed, so reindenting a line does not make it new.
function Get-TPFindingText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [object] $Finding)
    Set-StrictMode -Version Latest
    $first = ([string]$Finding.Extent.Text -split '\r?\n', 2)[0]
    return ($first -replace '\s+', ' ').Trim()
}

# True when the UnsafeEscaping finding is a removal, not an escape: the flagged
# expression and every -replace inside it replace with the constant empty
# string. Read from the file's AST at the finding's offsets, never from text.
function Test-TPRemovalOnlyReplace {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [object] $Finding,
        [hashtable] $AstCache = @{}
    )
    Set-StrictMode -Version Latest
    if ($Finding.RuleName -ne 'InjectionRisk.UnsafeEscaping' -or -not $Finding.ScriptPath) { return $false }
    $file = [string]$Finding.ScriptPath
    if (-not $AstCache.ContainsKey($file)) {
        $tokens = $null; $errors = $null
        $AstCache[$file] = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    }
    $start = $Finding.Extent.StartOffset
    $end = $Finding.Extent.EndOffset
    $node = $AstCache[$file].Find({
        param($a)
        $a -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        $a.Extent.StartOffset -eq $start -and $a.Extent.EndOffset -eq $end
    }, $true)
    if (-not $node) { return $false }
    $replaces = @($node.FindAll({
        param($a)
        $a -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        $a.Operator -in @([System.Management.Automation.Language.TokenKind]::Ireplace, [System.Management.Automation.Language.TokenKind]::Creplace)
    }, $true))
    if ($replaces.Count -eq 0) { return $false }
    foreach ($r in $replaces) {
        $right = $r.Right
        if ($right -isnot [System.Management.Automation.Language.ArrayLiteralAst] -or $right.Elements.Count -ne 2) { return $false }
        $with = $right.Elements[1]
        if ($with -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or $with.Value -ne '') { return $false }
    }
    return $true
}

# Sorts InjectionHunter findings against the reviewed baseline. Returns the
# findings that are new, the baseline entries nothing matched (stale), and
# counts of what passed and why.
function Compare-TPInjectionBaseline {
    [CmdletBinding()]
    param(
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Findings,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Baseline,
        [Parameter(Mandatory)] [string] $RepoRoot
    )
    Set-StrictMode -Version Latest
    $cache = @{}
    $remaining = @{}
    foreach ($e in @($Baseline | Where-Object { $null -ne $_ })) {
        $key = '{0}|{1}|{2}' -f $e.Path, $e.Rule, $e.Text
        $remaining[$key] = [int]$remaining[$key] + [int]$e.Count
    }
    $new = [System.Collections.Generic.List[object]]::new()
    $reviewed = 0
    $removal = 0
    foreach ($f in @($Findings | Where-Object { $null -ne $_ })) {
        if (Test-TPRemovalOnlyReplace -Finding $f -AstCache $cache) { $removal++; continue }
        $rel = [System.IO.Path]::GetRelativePath($RepoRoot, [string]$f.ScriptPath) -replace '\\', '/'
        $key = '{0}|{1}|{2}' -f $rel, $f.RuleName, (Get-TPFindingText -Finding $f)
        if ($remaining.ContainsKey($key) -and $remaining[$key] -gt 0) { $remaining[$key]--; $reviewed++; continue }
        $new.Add($f)
    }
    $stale = @(foreach ($k in $remaining.Keys) { if ($remaining[$k] -gt 0) { '{0} (x{1})' -f $k, $remaining[$k] } })
    [pscustomobject]@{ New = @($new); Stale = $stale; Reviewed = $reviewed; RemovalOnly = $removal }
}

# A baseline entry must say why its finding is not an injection.
function Test-TPInjectionBaselineEntry {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Baseline)
    Set-StrictMode -Version Latest
    foreach ($e in @($Baseline | Where-Object { $null -ne $_ })) {
        foreach ($field in 'Path', 'Rule', 'Text', 'Count', 'Reason') {
            if (-not $e.PSObject.Properties[$field] -or [string]::IsNullOrWhiteSpace([string]$e.PSObject.Properties[$field].Value)) { "Baseline entry is missing '$field': $($e | ConvertTo-Json -Compress)"; continue }
        }
        if ($e.PSObject.Properties['Count'] -and [int]$e.Count -lt 1) { "Baseline entry has a count below 1: $($e.Path) $($e.Rule)" }
        if ($e.PSObject.Properties['Rule'] -and [string]$e.Rule -notlike 'InjectionRisk.*') { "Baseline entry is not an InjectionHunter rule: $($e.Rule)" }
        if ($e.PSObject.Properties['Reason'] -and ([string]$e.Reason).Trim().Length -lt 20) { "Baseline entry's reason is too short to review: $($e.Path) $($e.Rule)" }
    }
}

if ($DefinitionsOnly) { return }

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath $Path).Path
$pin = (Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'pinned-modules.psd1'))['PSScriptAnalyzer']
try {
    Import-Module PSScriptAnalyzer -RequiredVersion $pin.Version -ErrorAction Stop
} catch {
    Write-Host ("PSScriptAnalyzer {0} is not installed. Install the pinned version with: ./tools/Install-TPPinnedModule.ps1 -Name PSScriptAnalyzer -Destination <folder on PSModulePath>" -f $pin.Version) -ForegroundColor Red
    exit 4
}
$settings = Join-Path $repoRoot 'PSScriptAnalyzerSecurity.psd1'

# The analyzer occasionally dies inside its own rule engine on a first run and
# passes on the next; a finding is returned as data, never thrown, so only
# that crash is retried.
$findings = $null
for ($attempt = 1; $attempt -le 3; $attempt++) {
    try { $findings = @(Invoke-ScriptAnalyzer -Path $repoRoot -Recurse -Settings $settings -IncludeSuppressed -ErrorAction Stop); break }
    catch {
        if ($attempt -eq 3) { throw }
        Write-Host ('Invoke-ScriptAnalyzer attempt {0} crashed: {1}' -f $attempt, $_.Exception.Message)
        Start-Sleep -Seconds (5 * $attempt)
    }
}

# Second pass: InjectionHunter, pinned like the analyzer.
$ihPin = (Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'pinned-modules.psd1'))['InjectionHunter']
$ih = Get-Module -ListAvailable InjectionHunter | Where-Object { [string]$_.Version -eq $ihPin.Version } | Select-Object -First 1
if (-not $ih) {
    Write-Host ("InjectionHunter {0} is not installed. Install the pinned version with: ./tools/Install-TPPinnedModule.ps1 -Name InjectionHunter -Destination <folder on PSModulePath>" -f $ihPin.Version) -ForegroundColor Red
    exit 4
}
$ihRules = Join-Path $ih.ModuleBase 'InjectionHunter.psm1'
$ihFindings = $null
for ($attempt = 1; $attempt -le 3; $attempt++) {
    try { $ihFindings = @(Invoke-ScriptAnalyzer -Path $repoRoot -Recurse -CustomRulePath $ihRules -IncludeRule 'Measure-*' -IncludeSuppressed -ErrorAction Stop | Where-Object { $_.RuleName -like 'InjectionRisk.*' }); break }
    catch {
        if ($attempt -eq 3) { throw }
        Write-Host ('InjectionHunter attempt {0} crashed: {1}' -f $attempt, $_.Exception.Message)
        Start-Sleep -Seconds (5 * $attempt)
    }
}
$baseline = @((Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json).entries)
$baselineProblems = @(Test-TPInjectionBaselineEntry -Baseline $baseline)
$cmp = Compare-TPInjectionBaseline -Findings $ihFindings -Baseline $baseline -RepoRoot $repoRoot

if ($SarifPath) {
    $sarif = ConvertTo-TPAnalyzerSarif -Findings (@($findings) + @($cmp.New)) -RepoRoot $repoRoot -ToolName 'PSScriptAnalyzer (security rules) + InjectionHunter' -ToolVersion ('{0}+{1}' -f $pin.Version, $ihPin.Version)
    $sarif | ConvertTo-Json -Depth 12 | Out-File -LiteralPath $SarifPath -Encoding utf8NoBOM
}

$problems = @(Get-TPSecurityAnalysisProblem -Findings (@($findings) + @($cmp.New)) -RepoRoot $repoRoot)
$problems += @($cmp.Stale | ForEach-Object { "Stale baseline entry (nothing matches it any more; remove it from tools/injection-baseline.json): $_" })
$problems += $baselineProblems
Write-Host ('InjectionHunter {0}: {1} finding(s): {2} reviewed in the baseline, {3} removal-only replaces, {4} new.' -f $ihPin.Version, @($ihFindings).Count, $cmp.Reviewed, $cmp.RemovalOnly, @($cmp.New).Count)
Write-Host ''
Write-Host ('PowerShell security analysis — PSScriptAnalyzer {0}, {1} rule(s)' -f $pin.Version, @((Import-PowerShellDataFile -LiteralPath $settings).IncludeRules).Count) -ForegroundColor Cyan
if ($problems.Count -gt 0) {
    foreach ($p in $problems) { Write-Host ('  {0}' -f $p) -ForegroundColor Red }
    Write-Host ''
    Write-Host ('FAILED: {0} problem(s). Fix the code; a security-rule finding has no allowance, and an InjectionHunter finding passes only once reviewed into tools/injection-baseline.json with its reason.' -f $problems.Count) -ForegroundColor Red
    exit 1
}
Write-Host 'PASSED: no security-rule finding, and every InjectionHunter finding is reviewed or removal-only.' -ForegroundColor Green
exit 0

#Requires -Version 7.0
<#
.SYNOPSIS
    Runs PSScriptAnalyzer's security rules over the repository and fails on
    any finding, at any severity.

.DESCRIPTION
    The "PowerShell Security Analysis" CI job, and the same check locally.
    The rules are in PSScriptAnalyzerSecurity.psd1. The analyzer must be the
    pinned version (tools/pinned-modules.psd1), so CI and a workstation judge
    the same code with the same rules; tools/Install-TPPinnedModule.ps1
    installs it.

    An in-source [SuppressMessage()] does not silence these rules: the run
    uses -IncludeSuppressed and a suppressed finding fails like any other,
    named as suppressed.

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

if ($SarifPath) {
    $sarif = ConvertTo-TPAnalyzerSarif -Findings $findings -RepoRoot $repoRoot -ToolName 'PSScriptAnalyzer (security rules)' -ToolVersion $pin.Version
    $sarif | ConvertTo-Json -Depth 12 | Out-File -LiteralPath $SarifPath -Encoding utf8NoBOM
}

$problems = @(Get-TPSecurityAnalysisProblem -Findings $findings -RepoRoot $repoRoot)
Write-Host ''
Write-Host ('PowerShell security analysis — PSScriptAnalyzer {0}, {1} rule(s)' -f $pin.Version, @((Import-PowerShellDataFile -LiteralPath $settings).IncludeRules).Count) -ForegroundColor Cyan
if ($problems.Count -gt 0) {
    foreach ($p in $problems) { Write-Host ('  {0}' -f $p) -ForegroundColor Red }
    Write-Host ''
    Write-Host ('FAILED: {0} security finding(s). Fix each one; these rules have no allowance.' -f $problems.Count) -ForegroundColor Red
    exit 1
}
Write-Host 'PASSED: no security rule reported a finding.' -ForegroundColor Green
exit 0

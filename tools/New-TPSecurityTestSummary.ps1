#Requires -Version 7.0
<#
.SYNOPSIS
    Writes the security test summary for TenantPosture's own attack surface,
    laid out after the facts an OSSTMM 3 Security Test Audit Report (STAR)
    asks for.

.DESCRIPTION
    Built from three sources, none of them edited by hand for a run:
      - docs/security/osstmm-modules.json: scope, channels, vectors, test type,
        the status of every OSSTMM 3 module (A.1 to D.17) and the error types
        that apply to these results;
      - Lib/Start-TPWebServer.ps1, parsed: the porosity counts (visibility,
        access, trust) come from the server's own endpoint and route
        registrations, never from a hand count;
      - optionally, the active ZAP scan's JSON report (-ZapReport) and the
        reviewed rules: each alert is counted under the OSSTMM limitation type
        .zap/osstmm-limitations.tsv gives its rule, and an alert whose rule has
        no type is counted as an Anomaly.

    It is NOT an ISECOM STAR: it is not on ISECOM's template, is signed by no
    certified analyst and is verified by no one, and it computes no rav, because
    the rav needs the control and limitation values weighted as the manual
    defines and these tests do not count controls per access point. The summary
    says each of these on its first lines. No text of the OSSTMM manual is
    reproduced; module numbers and names are cited.

    TenantPosture — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Data: reads the files above. Connects to nothing.

.PARAMETER ZapReport
    zap-active-report.json from the active scan (optional). Without it the
    limitation counts are stated as not measured in this run.
.PARAMETER OutputPath
    The Markdown file to write. Without it the Markdown is returned.
.PARAMETER RunLabel
    A line naming the run (commit, workflow run), printed under the title.
#>
[CmdletBinding()]
param(
    [string] $ZapReport,
    [string] $OutputPath,
    [ValidateLength(0, 200)] [string] $RunLabel = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$data = Get-Content -LiteralPath (Join-Path $repo 'docs' 'security' 'osstmm-modules.json') -Raw | ConvertFrom-Json -Depth 16
$md = { param([string] $s) ($s -replace '[\r\n]+', ' ' -replace '\|', '\|') }

# Porosity from the server's own registrations.
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'Lib' 'Start-TPWebServer.ps1'), [ref]$tokens, [ref]$errors)
$calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
$endpoints = @($calls | Where-Object { $_.GetCommandName() -eq 'Add-PodeEndpoint' })
$routes = @($calls | Where-Object { $_.GetCommandName() -eq 'Add-PodeRoute' })
$routeRows = foreach ($r in $routes) {
    $methods = ''; $path = ''
    for ($i = 0; $i -lt $r.CommandElements.Count - 1; $i++) {
        $el = $r.CommandElements[$i]
        if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
            $next = $r.CommandElements[$i + 1]
            if ($el.ParameterName -eq 'Method') { $methods = $next.Extent.Text }
            if ($el.ParameterName -eq 'Path') { $path = $next.Extent.Text.Trim("'", '"') }
        }
    }
    [pscustomobject]@{ Path = $path; Methods = $methods }
}
$routeRows = @($routeRows)
$named = @($routeRows | Where-Object { $_.Path -ne '/*' })

# Limitations from the active scan, typed by the reviewed classification.
$typeOf = @{}
foreach ($line in Get-Content -LiteralPath (Join-Path $repo '.zap' 'osstmm-limitations.tsv')) {
    if ($line -match '^\s*(#|$)') { continue }
    $cols = $line -split "`t"
    if ($cols.Count -ge 2) { $typeOf[$cols[0].Trim()] = $cols[1].Trim() }
}
$limitTypes = @('Vulnerability', 'Weakness', 'Concern', 'Exposure', 'Anomaly')
$limits = [ordered]@{}; foreach ($t in $limitTypes) { $limits[$t] = 0 }
$alertRows = [System.Collections.Generic.List[object]]::new()
$scanNote = 'Not measured in this run: no active scan report was given.'
if ($ZapReport) {
    if (-not (Test-Path -LiteralPath $ZapReport -PathType Leaf)) {
        $scanNote = 'Not measured: the active scan report named for this run does not exist.'
    } else {
        $report = Get-Content -LiteralPath $ZapReport -Raw | ConvertFrom-Json -Depth 32
        $sites = @($report.PSObject.Properties['site'] | ForEach-Object { $_.Value } | ForEach-Object { $_ })
        foreach ($s in $sites) {
            foreach ($a in @($s.alerts)) {
                $id = [string]$a.pluginid
                $type = if ($typeOf.ContainsKey($id)) { $typeOf[$id] } else { 'Anomaly' }
                if ($limits.Contains($type)) { $limits[$type]++ }
                $alertRows.Add([pscustomobject]@{ Id = $id; Name = [string]$a.name; Risk = ([string]$a.riskdesc -replace '\s*\(.*\)$', ''); Type = $type; Site = [string]$s.'@name' })
            }
        }
        $scanNote = "Counted from the active scan report: $($alertRows.Count) alert(s) across $($sites.Count) site(s). Each alert counts once, under its rule's reviewed type; an alert whose rule has no reviewed type is an Anomaly."
    }
}

$sb = [System.Text.StringBuilder]::new()
$w = { param([string] $line = '') $null = $sb.AppendLine($line) }
& $w '# TenantPosture security test summary'
& $w ''
if ($RunLabel) { & $w "Run: $(& $md $RunLabel)"; & $w '' }
& $w "Laid out after the facts an $($data.methodology) Security Test Audit Report (STAR) asks for. **This is not an ISECOM STAR**: it does not use ISECOM's template, no certified analyst signed it, and ISECOM did not verify it. **No rav is calculated**: the rav weighs controls and limitations per access point as the manual defines, and these tests do not count controls per access point. Nothing here is a pass or a fail of the tool as a whole."
& $w ''
& $w '## Scope and index'
& $w ''
foreach ($t in @($data.scope.targets)) { & $w "- $(& $md $t)" }
& $w ''
& $w 'Excluded:'
& $w ''
foreach ($t in @($data.scope.excluded)) { & $w "- $(& $md $t)" }
& $w ''
& $w "Index: $(& $md $data.scope.index)"
& $w ''
& $w '## Channels'
& $w ''
& $w '| Channel | Status |'
& $w '|---|---|'
foreach ($p in $data.scope.channels.PSObject.Properties) { & $w "| $($p.Name) | $(& $md $p.Value) |" }
& $w ''
& $w '## Vectors'
& $w ''
foreach ($v in @($data.scope.vectors)) { & $w "- $(& $md $v)" }
& $w ''
& $w '## Test type'
& $w ''
& $w (& $md $data.scope.testType)
& $w ''
& $w '## Attack surface: porosity of the web GUI'
& $w ''
& $w 'Counted from the server''s own registrations in `Lib/Start-TPWebServer.ps1`.'
& $w ''
& $w '| Measure | Count | Basis |'
& $w '|---|---|---|'
& $w "| Visibility | $($endpoints.Count) | Listening endpoints (Add-PodeEndpoint), bound to 127.0.0.1. The MCP server adds none: it opens no socket. |"
& $w "| Access | $($named.Count) | Named routes (Add-PodeRoute), plus one wildcard route that answers every other path and method with a fixed 404. |"
& $w "| Trust | $($named.Count) | Named routes that accept an interaction without authentication. The GUI has no sign-in: who can reach loopback on the machine is trusted, and the request policy decides which browser requests are let in. |"
& $w ''
& $w '| Route | Methods |'
& $w '|---|---|'
foreach ($r in $routeRows) { & $w "| ``$($r.Path)`` | $(& $md $r.Methods) |" }
& $w ''
& $w '## Limitations found by the active scan'
& $w ''
& $w (& $md $scanNote)
& $w ''
if ($ZapReport -and (Test-Path -LiteralPath $ZapReport -PathType Leaf)) {
    & $w '| Type | Count |'
    & $w '|---|---|'
    foreach ($t in $limitTypes) { & $w "| $t | $($limits[$t]) |" }
    & $w ''
    if ($alertRows.Count) {
        & $w '| Rule | Alert | Risk | Type | Site |'
        & $w '|---|---|---|---|---|'
        foreach ($a in $alertRows) { & $w "| $($a.Id) | $(& $md $a.Name) | $(& $md $a.Risk) | $($a.Type) | $(& $md $a.Site) |" }
        & $w ''
    }
    & $w 'Type None (an informational rule describing a design fact) is listed above and counted in no limitation.'
    & $w ''
}
& $w '## Completion status by module'
& $w ''
& $w '| Module | Status | Evidence | Not covered |'
& $w '|---|---|---|---|'
foreach ($m in @($data.modules)) {
    $ev = if (@($m.Evidence).Count) { (@($m.Evidence) | ForEach-Object { & $md $_ }) -join '; ' } else { 'None' }
    $gap = if ($m.Gap) { & $md $m.Gap } else { '' }
    & $w "| $($m.Id) $($m.Name) | $($m.Status) | $ev | $gap |"
}
& $w ''
$counts = @($data.modules) | Group-Object Status | Sort-Object Name | ForEach-Object { "$($_.Count) $($_.Name)" }
& $w "Modules: $($counts -join ', ')."
& $w ''
& $w '## Errors that apply to these results'
& $w ''
& $w '| Error type | Applies to | Why |'
& $w '|---|---|---|'
foreach ($e in @($data.errorTypes)) { & $w "| $($e.Type) | $(& $md $e.AppliesTo) | $(& $md $e.Note) |" }
& $w ''
& $w 'Module numbers, names and error and limitation types follow OSSTMM 3 (ISECOM, www.isecom.org). The descriptions are this project''s own.'

$text = $sb.ToString()
if ($OutputPath) {
    [System.IO.File]::WriteAllText($OutputPath, $text, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Security test summary written: $OutputPath"
} else {
    $text
}

#Requires -Version 7.0
<#
.SYNOPSIS
    Judges the active ZAP scan of the -Web GUI from its JSON report.

.DESCRIPTION
    The active scan (.github/workflows/dast.yml, job zap-active, plan
    .zap/active-scan.yaml) writes ZAP's traditional JSON report. This script
    reads it and passes only when:

      - the report exists, parses, and names the scanned server (a scan that
        reached nothing is a failure, never a clean result);
      - every alert's rule is reviewed IGNORE in .zap/rules.tsv, the same file
        and review rule the baseline scan uses (a rule listed WARN or FAIL, or
        not listed, fails);
      - the server's output folder holds exactly what it held before the scan
        (-Before, a sorted listing), since a new entry would mean a request
        started an assessment.

    It prints each unreviewed alert as rule id, risk, name and the first
    instance's method and URL, never the evidence or the response body.

    TenantPosture — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Data: reads the report, the rules file and the output folder. No network.

.PARAMETER ReportPath
    zap-active-report.json.
.PARAMETER RulesPath
    The reviewed rules file. Default: .zap/rules.tsv beside this repository.
.PARAMETER Target
    The scanned origin, as the workflow passes it (the loopback address and
    port the server binds; the request policy requires that Host header).
.PARAMETER OutputRoot
    The server's output folder.
.PARAMETER Before
    A file listing every path under -OutputRoot before the scan, one per line.

.OUTPUTS
    Exit 0 when the scan passes, 1 otherwise.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ReportPath,
    [string] $RulesPath,
    [Parameter(Mandatory)] [string] $Target,
    [Parameter(Mandatory)] [string] $OutputRoot,
    [Parameter(Mandatory)] [string] $Before
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $RulesPath) { $RulesPath = Join-Path (Split-Path -Parent $PSScriptRoot) '.zap' 'rules.tsv' }
$problems = [System.Collections.Generic.List[string]]::new()

# Reviewed rules: <id> TAB <IGNORE|WARN|FAIL> TAB <reason>. Only IGNORE accepts.
$ignored = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($line in Get-Content -LiteralPath $RulesPath) {
    if ($line -match '^\s*(#|$)') { continue }
    $cols = $line -split "`t"
    if ($cols.Count -ge 3 -and $cols[1] -ceq 'IGNORE') { $null = $ignored.Add($cols[0].Trim()) }
}

$report = $null
if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
    $problems.Add('The active scan wrote no JSON report.')
} else {
    try { $report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json -Depth 32 }
    catch { $problems.Add('The active scan report is not valid JSON.') }
}

$alertCount = 0
if ($null -ne $report) {
    $sites = @($report.PSObject.Properties['site'] | ForEach-Object { $_.Value } | ForEach-Object { $_ })
    $site = @($sites | Where-Object { [string]$_.'@name' -eq $Target })
    if (-not $site.Count) {
        $problems.Add("The report names no site $Target, so the scan reached nothing.")
    }
    # Every site's alerts are judged: ZAP also probes the target's https
    # form, and an alert there is still an alert about this server.
    foreach ($s in $sites) {
        foreach ($alert in @($s.alerts)) {
            $alertCount++
            $id = [string]$alert.pluginid
            if ($ignored.Contains($id)) { continue }
            $first = @($alert.instances) | Select-Object -First 1
            $where = if ($first) { '{0} {1}' -f $first.method, $first.uri } else { '(no instance)' }
            $problems.Add(('Unreviewed alert {0} ({1}): {2} at {3}' -f $id, ($alert.riskdesc -replace '\s*\(.*\)$', ''), $alert.name, $where))
        }
    }
}

# A request that started an assessment would have created a tenant folder.
$beforeList = @(Get-Content -LiteralPath $Before | Where-Object { $_ })
$afterList = @(Get-ChildItem -LiteralPath $OutputRoot -Recurse -Force | ForEach-Object { $_.FullName }) + @((Get-Item -LiteralPath $OutputRoot).FullName)
$new = @($afterList | Where-Object { $beforeList -notcontains $_ } | Sort-Object)
foreach ($n in $new) { $problems.Add("The output folder gained $n during the scan: a request reached a route that writes.") }

Write-Host ("Active scan: {0} alert(s) reported, {1} rule(s) reviewed IGNORE." -f $alertCount, $ignored.Count)
if ($problems.Count) {
    foreach ($p in $problems) { Write-Host "  [!] $p" }
    Write-Host 'FAILED: fix each finding, or review its rule into .zap/rules.tsv with the reason.'
    exit 1
}
Write-Host 'PASSED: every alert is a reviewed rule, and nothing was written.'
exit 0

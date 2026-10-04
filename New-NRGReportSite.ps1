#Requires -Version 7.0
<#
.SYNOPSIS
    New-NRGReportSite.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Build the multi-page HTML report site (landing page, one page per workload, action-plan
             CSV) from an EXISTING results JSON. Connects to nothing, collects nothing, changes no
             verdict. Optionally places an independent ScubaGear scan beside each mapped control.
.PARAMETER ResultsPath
    A results JSON written by Invoke-NRGAssessment (contains Findings, Metadata, BaselineCompliance).
.PARAMETER OutputPath
    Folder to write index.html, one <workload>.html per workload and ActionPlan.csv into.
.PARAMETER ScubaResultsPath
    Optional ScubaResults.csv from ScubaGear. Its results are shown beside mapped controls as an
    independent comparison, never as a score.
.EXAMPLE
    ./New-NRGReportSite.ps1 -ResultsPath .\output\contoso-20260930-104906-results.json -OutputPath .\output\site
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })] [string] $ResultsPath,
    [Parameter(Mandatory)] [string] $OutputPath,
    [string] $ScubaResultsPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'NRG-Assessment.psm1') -Force
$j = Get-Content -LiteralPath $ResultsPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 60
$meta = if ($j.ContainsKey('Metadata')) { [hashtable]$j.Metadata } else { @{} }
# Two statements: an if-statement that yields an empty array assigns null (see CLAUDE.md).
$findings = @()
if ($j.ContainsKey('Findings')) { $findings = @($j.Findings | Where-Object { $null -ne $_ }) }
$baseline = if ($j.ContainsKey('BaselineCompliance')) { $j.BaselineCompliance } else { $null }
# The run's coverage (a -Skip flag) and raw data, so the site files each unscored control as the
# report's scope section does.
$coverage = if ($j.ContainsKey('Coverage') -and $j.Coverage -is [System.Collections.IDictionary]) { $j.Coverage } else { $null }
$rawData = if ($j.ContainsKey('RawData') -and $j.RawData -is [System.Collections.IDictionary]) { $j.RawData } else { $null }
$r = Publish-NRGReportSite -Metadata $meta -Findings $findings -OutputPath $OutputPath -BaselineCompliance $baseline -Coverage $coverage -RawData $rawData -ScubaResultsPath $ScubaResultsPath
Write-Host ("Report site: {0} findings across {1} workload page(s); {2} action-plan row(s)." -f $r.Findings, @($r.Workloads).Count, $r.ActionPlanRows)
Write-Host ("Open {0}" -f (Join-Path $OutputPath 'index.html'))

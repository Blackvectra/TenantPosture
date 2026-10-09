#Requires -Version 7.0
<#
.SYNOPSIS
    Get-TPControlStatus.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Check specific controls (for example those named on a ticket)
             against a results file and say whether each is in place, open,
             partly in place, or was not assessed and why.
    CONNECTS TO NOTHING: reads the results JSON and Config/controls.json only.
    Data keys consumed: Findings and Metadata from a results JSON.
    Graph scopes / cmdlets: none.

.PARAMETER ResultsPath
    A results JSON from Invoke-TPAssessment.ps1.
.PARAMETER ControlId
    Control IDs (AAD-1.4, EXO-7.2) and/or workload prefixes (TMS, SPO), which
    expand to every control in that workload. Comma or space separated.
.PARAMETER ControlIdFile
    A text file with control IDs, one or more per line; lines starting with #
    are ignored.
.PARAMETER OutputPath
    Optional CSV path for the rows.
.EXAMPLE
    .\Get-TPControlStatus.ps1 -ResultsPath .\output\client-20260929-results.json -ControlId TMS,SPO,PVW
.EXAMPLE
    .\Get-TPControlStatus.ps1 -ResultsPath .\output\r.json -ControlId AAD-1.4,EXO-7.2 -OutputPath .\ticket-check.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ResultsPath,
    [string[]] $ControlId = @(),
    [string]   $ControlIdFile = '',
    [string]   $OutputPath = '',
    [switch]   $PassThru
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
# The psm1, not the manifest: nothing here needs the Graph modules.
Import-Module (Join-Path $scriptDir 'TenantPosture.psm1') -Force -ErrorAction Stop

if (-not (Test-Path -LiteralPath $ResultsPath)) { throw "Results file not found: $ResultsPath" }
$ids = @($ControlId)
if ($ControlIdFile) {
    if (-not (Test-Path -LiteralPath $ControlIdFile)) { throw "Control ID file not found: $ControlIdFile" }
    $ids += @(Get-Content -LiteralPath $ControlIdFile -Encoding utf8 | Where-Object { $_ -and $_ -notmatch '^\s*#' })
}
if ($ids.Count -eq 0) { throw 'Give at least one control ID or workload prefix (-ControlId or -ControlIdFile).' }

$results = Get-Content -LiteralPath (Resolve-Path -LiteralPath $ResultsPath).Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
$findings = @(Get-TPObjectField -Item $results -Key 'Findings' -Default @())
$catalog = @()
$controlsPath = Join-Path $scriptDir 'Config' 'controls.json'
if (Test-Path -LiteralPath $controlsPath) {
    $cj = Get-Content -LiteralPath $controlsPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10
    $catalog = @(Get-TPObjectField -Item $cj -Key 'controls' -Default @())
    if ($catalog.Count -eq 0 -and $cj -is [System.Array]) { $catalog = @($cj) }
}

$tenant = [string](Get-TPNestedProperty -Object $results -Path 'Metadata.TenantDomain' -Default '?')
$when   = [string](Get-TPNestedProperty -Object $results -Path 'Metadata.AssessmentTime' -Default '?')
$rows   = @(Get-TPControlStatus -Findings $findings -ControlId $ids -ControlCatalog $catalog)

Write-Host "Results: $(Split-Path -Leaf $ResultsPath)  tenant: $tenant  run: $when" -ForegroundColor Cyan
Write-Host 'Only "In place" means the assessment found it configured. "Not assessed" and "No result" are not fixes.' -ForegroundColor DarkGray
Write-Host ''
foreach ($r in $rows) {
    Write-Host ('  {0,-9} {1,-18} {2}' -f $r.ControlId, $r.Status, $r.Title)
    if ($r.Status -ne 'In place') { Write-Host ('            {0}' -f $r.Reason) -ForegroundColor DarkGray }
}
Write-Host ''
$counts = $rows | Group-Object { $_.Status } | Sort-Object Name
Write-Host (($counts | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) -join '   ')

if ($OutputPath) {
    $rows | ForEach-Object { [pscustomobject]$_ } | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding utf8
    Write-Host "Rows written: $OutputPath" -ForegroundColor Green
}
if ($PassThru) { return $rows }

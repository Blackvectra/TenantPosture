#Requires -Version 7.0
<#
.SYNOPSIS
    Build the fleet dashboard: every client's latest full assessment, what
    changed since the one before, and who is due. Offline: it connects to
    nothing.

.DESCRIPTION
    Reads the saved results files under the output folder (both layouts:
    output\<tenant>\ from the GUI and the batch runner, and the flat output\
    of a command-line run; incident-response outputs are never read), groups
    them by tenant, and writes an HTML dashboard, a Markdown summary and a CSV
    with one row per client.

    Only a FULL run sets a client's score and maturity label (the values the
    run recorded). A partial -ControlId re-check or a -Quick scan is shown
    beside it and never replaces it. Age is judged by the NRG Security
    Baseline's freshness classes (Weekly and Monthly windows in
    Config/tp-baseline.json). Active clients in the clients file with no run
    are listed as never assessed.

    It does not sign in, does not query Microsoft Graph or Exchange Online,
    makes no network call, and changes nothing. INTERNAL by default: the files
    name clients. -Anonymize labels them Client A, Client B, ...

.PARAMETER OutputRoot
    The output folder holding the runs. Default: <script folder>\output.
.PARAMETER ClientsFile
    The clients file (client names and Active flags). Default:
    Config\clients.json when it exists. A file named here that is missing or
    not valid JSON is fatal.
.PARAMETER OutPath
    Folder for the three files. Default: <OutputRoot>\fleet.
.PARAMETER Anonymize
    Label clients Client A, Client B, ... in every output, with no client
    name, domain or tenant ID.
.PARAMETER PassThru
    Return the model and the file paths.

.EXAMPLE
    .\New-TPFleetDashboard.ps1
.EXAMPLE
    .\New-TPFleetDashboard.ps1 -OutputRoot D:\TP\output -Anonymize

.NOTES
    Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
    Data consumed: <OutputRoot>\**\*-results.json, Config\clients.json.
    Graph scopes / cmdlets used: none.
    Exit codes: 0 success, 2 no assessment runs found, 4 fatal error.
#>
[CmdletBinding()]
param(
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $OutputRoot,

    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $ClientsFile,

    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $OutPath,

    [switch] $Anonymize,

    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    # The psm1, not the manifest: the manifest declares the Graph modules as
    # required and this script needs none of them.
    Import-Module (Join-Path $scriptDir 'TenantPosture.psm1') -Force -ErrorAction Stop

    if (-not $OutputRoot) { $OutputRoot = Join-Path $scriptDir 'output' }
    $OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
    $clientsPath = ''
    if ($ClientsFile) {
        if (-not (Test-Path -LiteralPath $ClientsFile -PathType Leaf)) { throw '-ClientsFile was not found.' }
        $clientsPath = [System.IO.Path]::GetFullPath($ClientsFile)
    } else {
        $default = Join-Path $scriptDir 'Config' 'clients.json'
        if (Test-Path -LiteralPath $default -PathType Leaf) { $clientsPath = $default }
    }
    if (-not $OutPath) { $OutPath = Join-Path $OutputRoot 'fleet' }

    $model = Get-TPFleetModel -OutputRoot $OutputRoot -ClientsFile $clientsPath -Anonymize:$Anonymize

    Write-Host ''
    if (-not $model.Available) {
        Write-Host "  [!] $($model.Note)" -ForegroundColor Yellow
        Write-Host ''
        exit 2
    }

    $files = Publish-TPFleetDashboard -Model $model -OutputPath $OutPath
    $k = $model.Kpis
    Write-Host '  Fleet posture' -ForegroundColor Green
    Write-Host "  $($k.Clients) client(s): $($k.InWindow) assessed within $($model.Freshness.OverdueDays) days, $($k.Overdue) overdue, $($k.NoFullRun) with no full run, $($k.NeverAssessed) never assessed."
    Write-Host "  Open across latest full runs: $($k.OpenCritical) Critical, $($k.OpenHigh) High."
    foreach ($n in @($model.Notes)) { Write-Host "  [i] $n" -ForegroundColor DarkGray }
    Write-Host ''
    Write-Host "  [+] HTML:     $($files.Html)" -ForegroundColor Green
    Write-Host "  [+] Markdown: $($files.Markdown)" -ForegroundColor Green
    Write-Host "  [+] CSV:      $($files.Csv)" -ForegroundColor Green
    Write-Host "  $(if ($Anonymize) { 'Anonymized: clients are labeled Client A, Client B, ...' } else { 'Internal: these files name clients.' }) This script connected to nothing." -ForegroundColor DarkGray
    Write-Host ''

    if ($PassThru) { return [pscustomobject]@{ Model = $model; Files = $files } }
    exit 0
} catch {
    Write-Error "Fleet dashboard failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 4
}

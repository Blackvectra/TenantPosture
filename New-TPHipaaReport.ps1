#Requires -Version 7.0
<#
.SYNOPSIS
    Build the client-facing HIPAA Security Rule report (HTML and PDF) from a
    saved results file. Offline: it connects to nothing.

.DESCRIPTION
    Reads one -results.json written by a FULL assessment run and writes
    <tenant>-hipaa-report-<yyyyMMdd-HHmmss>.html and, unless -NoPdf, a PDF of
    it printed by the Microsoft Edge (or Chrome) already on this computer.

    The report groups all 63 HIPAA Security Rule standards and implementation
    specifications into: verified in Microsoft 365, partly verified, needs
    attention, not verified in this review, and your documentation (a
    checklist). Page one says what it is and is not: a review of Microsoft 365
    configuration that supports the client's HIPAA program, not a risk analysis
    and not a compliance determination.

    A partial (-ControlId) or quick (-Quick) run is refused (exit 4): a report a
    client forwards must not read as the whole tenant when it is not. An
    incident-response output is refused too.

.PARAMETER ResultsPath
    The results file (-results.json) of a full run.
.PARAMETER ClientName
    The name printed on the report. Default: the tenant domain.
.PARAMETER PreparedBy
    Who prepared it. Default: the company name of the loaded profile.
.PARAMETER Profile
    A practice profile (Config/profiles/<name>.psd1) for branding.
.PARAMETER OutputPath
    Folder for the files. Default: the folder of -ResultsPath.
.PARAMETER NoPdf
    Write the HTML only.

.EXAMPLE
    .\New-TPHipaaReport.ps1 -ResultsPath .\output\contoso-20261028-090000-results.json -ClientName 'Contoso Family Health' -Profile nls

.NOTES
    Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
    Data consumed: one -results.json. Graph scopes / cmdlets used: none.
    Exit codes: 0 success (a PDF that could not be printed is reported, the HTML
    is still written), 4 refused or fatal.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Results file not found: $_" }
        return $true
    })]
    [string] $ResultsPath,

    [ValidateLength(0, 120)]
    [string] $ClientName = '',

    [ValidateLength(0, 120)]
    [string] $PreparedBy = '',

    [ValidatePattern('^[a-z0-9-]{0,40}$', Options = 'None')]
    [string] $Profile = '',

    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $OutputPath,

    [switch] $NoPdf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$profileEnvBefore = $env:TP_PROFILE
try {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    if ($Profile) { $env:TP_PROFILE = $Profile }
    try { Import-Module (Join-Path $scriptDir 'TenantPosture.psm1') -Force -ErrorAction Stop }
    finally {
        if ($Profile) {
            if ($null -eq $profileEnvBefore) { Remove-Item -LiteralPath Env:TP_PROFILE -ErrorAction SilentlyContinue }
            else { $env:TP_PROFILE = $profileEnvBefore }
        }
    }

    $resultsFull = (Resolve-Path -LiteralPath $ResultsPath).Path
    if (-not $OutputPath) { $OutputPath = Split-Path -Parent $resultsFull }
    $null = [System.IO.Directory]::CreateDirectory($OutputPath)
    # The same proof every entry point makes before writing tenant data: the
    # folder can hold an owner-only file (an exFAT stick cannot).
    try { $null = Test-TPSensitiveOutputFolder -Path $OutputPath }
    catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red; exit 4 }

    $run = Read-TPRunRecord -Path $resultsFull
    if ($run.IsIncidentResponse) {
        Write-Host '  [!] That file is an incident-response output, not an assessment. Nothing was written.' -ForegroundColor Yellow
        exit 4
    }
    $model = Get-TPHipaaClientReport -Findings @($run.Findings) -Metadata $run.Metadata -ClientName $ClientName -PreparedBy $PreparedBy
    Write-Host ''
    if (-not $model.Available) {
        Write-Host "  [!] $($model.Note)" -ForegroundColor Yellow
        Write-Host '      Nothing was written.' -ForegroundColor Yellow
        exit 4
    }

    $tag = (($model.TenantDomain -split '\.')[0]) -replace '[^a-zA-Z0-9-]', ''
    if (-not $tag) { $tag = 'tenant' }
    $base = "$tag-hipaa-report-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $files = Publish-TPHipaaClientReport -Model $model -OutputPath (Join-Path $OutputPath "$base.html") -Pdf:(-not $NoPdf)

    $names = $model.GroupNames
    Write-Host "  HIPAA Security Rule review: $($model.ClientName)" -ForegroundColor Green
    foreach ($k in $names.Keys) { Write-Host ("    {0,-30} {1,3} of {2}" -f $names[$k], $model.Counts[$k], $model.Total) }
    Write-Host ''
    Write-Host "  [+] HTML: $($files.Html)" -ForegroundColor Green
    if ($files.Pdf) { Write-Host "  [+] PDF:  $($files.Pdf)" -ForegroundColor Green }
    elseif ($files.PdfNote) { Write-Host "  [!] $($files.PdfNote)" -ForegroundColor Yellow }
    Write-Host '  This script connected to nothing.' -ForegroundColor DarkGray
    Write-Host ''
    exit 0
} catch {
    Write-Error "HIPAA report failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 4
}

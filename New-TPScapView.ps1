#Requires -Version 7.0
<#
.SYNOPSIS
    Build the endpoint baseline results view from SCAP scan results (XCCDF /
    ARF from DISA SCC or OpenSCAP). Offline: it connects to nothing.

.DESCRIPTION
    Reads every .xml file under -Path (or one file), keeps the newest result
    per host and benchmark, and writes scap-view-<yyyyMMdd-HHmmss>.html and .md:
    per benchmark, each rule with how many hosts passed or failed it and which
    hosts failed.

    A separate view: it creates no finding and no score. TenantPosture did not
    scan these hosts and does not verify the results; the page says so, says the
    hosts are only those in the files, and lists results older than -MaxAgeDays
    as not current. Files with a DTD, over the size limit or not XCCDF are listed
    with the reason and skipped.

.PARAMETER Path
    A folder of SCAP results (searched recursively for *.xml) or one file.
.PARAMETER MaxAgeDays
    Results older than this are listed but not counted. Default 30.
.PARAMETER Profile
    A practice profile (Config/profiles/<name>.psd1) for branding.
.PARAMETER OutputPath
    Folder for the files. Default: the current folder's output\ subfolder.

.EXAMPLE
    .\New-TPScapView.ps1 -Path 'C:\Users\me\SCC\Sessions\2026-10-30_090000\Results\SCAP' -Profile nrg

.NOTES
    Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
    Data consumed: XCCDF / ARF files. Graph scopes / cmdlets used: none.
    Exit codes: 0 written, 2 no readable results, 4 fatal.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        if (-not (Test-Path -LiteralPath $_)) { throw "SCAP results path not found: $_" }
        return $true
    })]
    [string] $Path,

    [ValidateRange(1, 3650)]
    [int] $MaxAgeDays = 30,

    [ValidatePattern('^[a-z0-9-]{0,40}$', Options = 'None')]
    [string] $Profile = '',

    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $OutputPath
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

    if (-not $OutputPath) { $OutputPath = Join-Path $scriptDir 'output' }
    $null = [System.IO.Directory]::CreateDirectory($OutputPath)
    try { $null = Test-TPSensitiveOutputFolder -Path $OutputPath }
    catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red; exit 4 }

    $model = Get-TPScapView -Path ((Resolve-Path -LiteralPath $Path).Path) -MaxAgeDays $MaxAgeDays
    Write-Host ''
    if (-not $model.Available) {
        Write-Host "  [!] $($model.Note)" -ForegroundColor Yellow
        foreach ($s in @($model.FilesSkipped | Select-Object -First 10)) { Write-Host "      $($s.File): $($s.Reason)" -ForegroundColor Yellow }
        Write-Host '      Nothing was written.' -ForegroundColor Yellow
        exit 2
    }
    $base = "scap-view-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $files = Publish-TPScapView -Model $model -OutputPath (Join-Path $OutputPath "$base.html") -ToolVersion ([string]$TPAssessmentVersion)
    foreach ($b in @($model.Benchmarks)) {
        Write-Host ("  {0}: {1} of {2} host(s) current; {3} failing, {4} not established, {5} manual, {6} met" -f $b.Title, $b.HostsCurrent, $b.HostsTotal, $b.Counts.Failing, $b.Counts.NotEstablished, $b.Counts.Manual, $b.Counts.Met)
    }
    if (@($model.FilesSkipped).Count) { Write-Host "  [!] $(@($model.FilesSkipped).Count) file(s) skipped; the view lists them and why." -ForegroundColor Yellow }
    Write-Host ''
    Write-Host "  [+] HTML: $($files.Html)" -ForegroundColor Green
    Write-Host "  [+] MD:   $($files.Markdown)" -ForegroundColor Green
    Write-Host '  This script connected to nothing.' -ForegroundColor DarkGray
    Write-Host ''
    exit 0
} catch {
    Write-Error "SCAP view failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 4
}

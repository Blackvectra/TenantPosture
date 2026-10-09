#Requires -Version 7.0
<#
.SYNOPSIS
    Compare two tenants against the NRG Security Baseline, offline, from two
    results JSON files. Internal working tool: it connects to nothing.

.DESCRIPTION
    Answers one question: on the controls both runs could verify, do the two
    tenants sit in the same place against the NRG Security Baseline? Use it
    to set a prospective client beside an existing one.

    It reads the BaselineCompliance block of each -results.json and nothing
    else the baseline view did not already decide. It does not sign in, does
    not query Microsoft Graph or Exchange Online, makes no network call, and
    changes nothing in either tenant. It creates no findings and moves no
    score; the output is a view.

    Any tier may be compared. Only controls required at BOTH tenants are
    compared, so a Minimum run against a Standard run compares the Minimum
    controls; the rest are listed as not compared, with the tier that
    required them. If the two runs used different baseline versions the
    report says the standard changed and compares only controls whose
    required tier and expected state are the same in both files.

    A control that either run could not verify (NotVerified, NotApplicable,
    LicenseBlocked, ThirdPartyHandled) is listed as not comparable with each
    side's reason code and is never counted as a match. The headline is a
    count of controls both tenants verified. There is no score, no ranking,
    and the word "compliant" appears nowhere.

    This is not the run-over-run comparison. To see ONE tenant change over
    time, use -BaselineResults on Invoke-TPAssessment.ps1; that guard (it
    refuses a baseline from a different tenant) is unchanged.

    Output is Markdown, a self-contained HTML page (no script, no external
    asset) and a CSV, written to -OutputPath. By default the files name both
    tenants. Use -Anonymize to label them A and B everywhere, file names
    included, so a shareable version is possible later. No client-facing
    wording or branding is added.

.PARAMETER ResultsA
    Results JSON for the first tenant (the -results.json an assessment wrote).
.PARAMETER ResultsB
    Results JSON for the second tenant.
.PARAMETER OutputPath
    Folder for the three output files. Created if absent.
.PARAMETER Anonymize
    Label the tenants A and B in the console, the files and their names. No
    tenant name, domain or ID is written, and any identifier found inside a
    control title is replaced.
.PARAMETER MaxRunGapDays
    Warn when the two runs are further apart than this many days. Default 7.
.PARAMETER PassThru
    Return the comparison model and the file paths.

.EXAMPLE
    .\Compare-TPTenantBaseline.ps1 -ResultsA .\output\prospect-20260930-101500-results.json `
        -ResultsB .\output\client-20260930-094500-results.json -OutputPath .\output\comparison

.EXAMPLE
    .\Compare-TPTenantBaseline.ps1 -ResultsA .\a.json -ResultsB .\b.json -OutputPath .\out -Anonymize

.NOTES
    Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
    Exit codes: 0 success, 2 nothing to compare (a file carries no baseline
    controls), 4 fatal error.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Results file not found: $_" }
        return $true
    })]
    [string] $ResultsA,

    [Parameter(Mandatory)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Results file not found: $_" }
        return $true
    })]
    [string] $ResultsB,

    [Parameter(Mandatory)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $OutputPath,

    [switch] $Anonymize,

    [ValidateRange(1, 3650)]
    [int] $MaxRunGapDays = 7,

    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    # The psm1, not the manifest: the manifest declares the Graph modules as
    # required and this script needs none of them.
    Import-Module (Join-Path $PSScriptRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

    $pathA = (Resolve-Path -LiteralPath $ResultsA).Path
    $pathB = (Resolve-Path -LiteralPath $ResultsB).Path
    if ($pathA -eq $pathB) {
        Write-Warning '-ResultsA and -ResultsB are the same file. This compares a tenant with itself.'
    }

    # Errors name the parameter, never the path: the path may carry a tenant
    # name, and an anonymized run must not echo one.
    $read = {
        param([string] $Path, [string] $Which)
        try {
            return (Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20 -ErrorAction Stop)
        } catch {
            throw "-Results$Which could not be read as JSON: $($_.Exception.Message)"
        }
    }
    $a = & $read $pathA 'A'
    $b = & $read $pathB 'B'

    $cmp = Get-TPBaselineTenantComparison -ResultsA $a -ResultsB $b -Anonymize:$Anonymize -MaxRunGapDays $MaxRunGapDays

    Write-Host ''
    if (-not $cmp.Available) {
        Write-Host "  [!] $($cmp.Note)" -ForegroundColor Yellow
        Write-Host ''
        exit 2
    }

    $files = Publish-TPBaselineTenantComparison -Comparison $cmp -OutputPath $OutputPath

    Write-Host '  NRG Security Baseline: tenant comparison' -ForegroundColor Green
    Write-Host "  A: $($cmp.SideA.Name)  ($($cmp.SideA.TargetTier), baseline v$($cmp.SideA.BaselineVersion), run $($cmp.SideA.RunDate))"
    Write-Host "  B: $($cmp.SideB.Name)  ($($cmp.SideB.TargetTier), baseline v$($cmp.SideB.BaselineVersion), run $($cmp.SideB.RunDate))"
    Write-Host ''
    Write-Host "  $($cmp.Headline)" -ForegroundColor Cyan
    Write-Host "  $($cmp.HeadlineDetail)" -ForegroundColor DarkGray
    foreach ($w in @($cmp.Warnings)) { Write-Host "  [!] $w" -ForegroundColor Yellow }
    Write-Host ''
    Write-Host "  [+] Markdown: $($files.Markdown)" -ForegroundColor Green
    Write-Host "  [+] HTML:     $($files.Html)" -ForegroundColor Green
    Write-Host "  [+] CSV:      $($files.Csv)" -ForegroundColor Green
    Write-Host "  $(if ($Anonymize) { 'Anonymized: the tenants are labeled A and B.' } else { 'Internal: these files name both tenants.' }) This script connected to nothing." -ForegroundColor DarkGray
    Write-Host ''

    if ($PassThru) { return [pscustomobject]@{ Comparison = $cmp; Files = $files } }
    exit 0

} catch {
    # -ErrorAction Continue: under 'Stop', Write-Error itself throws and the
    # exit code below would never be reached.
    Write-Error "Tenant baseline comparison failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 4
}

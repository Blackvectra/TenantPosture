#Requires -Version 7.0
<#
.SYNOPSIS
    Get-NRGBaselinePlan.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Standalone entry point for the NRG Security Baseline plan: before
             a real run, say which tier applies, how many controls are required,
             which collectors are needed, and how each required control is
             expected to resolve (automatic, manual, third-party handled,
             optional collector required, skipped, expected license-blocked,
             or licensing unknown until connection).
    CONNECTS TO NOTHING: no sign-in, no Graph, no Exchange, no endpoint access.
    Licensing is unknown unless -ResultsPath points at a prior run, whose
    SubscribedSkus are read from the JSON on disk.
    Data keys consumed: none live. Config: clients.json, nrg-baseline.json,
    optional-collectors.json, controls.json, baseline-exceptions/.
    Graph scopes / cmdlets: none.

.PARAMETER TenantDomain
    Client domain. When it matches a Config/clients.json entry, BaselineTier,
    ThirdPartyEDR and the Skip* flags are read from it unless given here.
.PARAMETER BaselineTier
    Minimum, Standard or Hardened. Defaults to the client's BaselineTier, the
    prior run's TargetTier (-ResultsPath), else Standard.
.PARAMETER ResultsPath
    A prior results JSON. Its SubscribedSkus give the license profile, and its
    metadata supplies TenantDomain, tier and EDR defaults.
.PARAMETER OutputPath
    Optional path to write the plan as JSON.
.EXAMPLE
    .\Get-NRGBaselinePlan.ps1 -TenantDomain client.com -BaselineTier Standard
.EXAMPLE
    .\Get-NRGBaselinePlan.ps1 -ResultsPath .\output\client-20260929-124455-results.json
#>
[CmdletBinding()]
param(
    [string] $TenantDomain = '',
    [ValidateSet('', 'Minimum', 'Standard', 'Hardened')] [string] $BaselineTier = '',
    [string] $ThirdPartyEDR = '',
    [switch] $IncludeSharePointShell,
    [switch] $SkipPurview,
    [switch] $SkipTeams,
    [switch] $SkipSharePoint,
    [switch] $SkipIntune,
    [switch] $SkipPowerPlatform,
    [switch] $SkipDNS,
    [string] $ResultsPath = '',
    [string] $OutputPath = '',
    [switch] $PassThru
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
# The psm1, not the manifest: the manifest declares the Graph modules as
# required and this script needs none of them.
Import-Module (Join-Path $scriptDir 'NRG-Assessment.psm1') -Force -ErrorAction Stop

# ── Prior run: licensing and defaults, from disk only ─────────────────────────
$licenseProfile = $null
$licenseSource  = ''
$prior = $null
if ($ResultsPath) {
    if (-not (Test-Path -LiteralPath $ResultsPath)) { throw "Results file not found: $ResultsPath" }
    $prior = Get-Content -LiteralPath (Resolve-Path -LiteralPath $ResultsPath).Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
    $skus = @(Get-NRGNestedProperty -Object $prior -Path 'RawData.AAD-Inventory.Data.SubscribedSkus' -Default @())
    if ($skus.Count -gt 0) {
        $licenseProfile = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
        $at = Get-NRGNestedProperty -Object $prior -Path 'Metadata.AssessmentTime' -Default '?'
        $atText = if ($at -is [datetime]) { $at.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) } else { [string]$at }
        $licenseSource  = "prior run $atText ($(Split-Path -Leaf $ResultsPath))"
    }
    if (-not $TenantDomain)  { $TenantDomain  = [string](Get-NRGNestedProperty -Object $prior -Path 'Metadata.TenantDomain' -Default '') }
    if (-not $ThirdPartyEDR) { $ThirdPartyEDR = [string](Get-NRGNestedProperty -Object $prior -Path 'Metadata.ThirdPartyEDR' -Default '') }
    if (-not $BaselineTier) {
        $t = [string](Get-NRGNestedProperty -Object $prior -Path 'Metadata.TargetTier' -Default '')
        if ($t -in @('Minimum', 'Standard', 'Hardened')) { $BaselineTier = $t }
    }
}

# ── Client profile from clients.json (by domain), never a sign-in ────────────
$clientRec = $null
if ($TenantDomain) {
    $clientsPath = Join-Path $scriptDir 'Config' 'clients.json'
    if (Test-Path -LiteralPath $clientsPath) {
        try {
            $cfg = Get-Content -LiteralPath $clientsPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10
            $list = @(Get-NRGObjectField -Item $cfg -Key 'clients' -Default @())
            $clientRec = @($list | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'TenantDomain' -Default '') -eq $TenantDomain })
            $clientRec = if ($clientRec.Count -gt 0) { $clientRec[0] } else { $null }
        } catch { Write-Warning "clients.json could not be read: $($_.Exception.Message)"; $clientRec = $null }
    }
}
if ($clientRec) {
    if (-not $BaselineTier) {
        $t = [string](Get-NRGObjectField -Item $clientRec -Key 'BaselineTier' -Default '')
        if ($t -in @('Minimum', 'Standard', 'Hardened')) { $BaselineTier = $t }
    }
    if (-not $ThirdPartyEDR) { $ThirdPartyEDR = [string](Get-NRGObjectField -Item $clientRec -Key 'ThirdPartyEDR' -Default '') }
    foreach ($sf in Get-NRGWorkloadSkipMap) {
        if ([bool](Get-NRGObjectField -Item $clientRec -Key $sf.Flag -Default $false)) { Set-Variable -Name $sf.Flag -Value $true }
    }
    $flags = Get-NRGClientCollectorFlags -ClientRecord $clientRec
    if ($flags['SharePointShell']) { $IncludeSharePointShell = $true }
}
if (-not $BaselineTier) { $BaselineTier = 'Standard' }

$skipKeys = @(foreach ($sf in Get-NRGWorkloadSkipMap) { if ((Get-Variable -Name $sf.Flag -ValueOnly)) { $sf.Keys } })

$plan = Get-NRGBaselinePlan -TenantDomain $TenantDomain -TargetTier $BaselineTier -ThirdPartyEDR $ThirdPartyEDR `
    -IncludeSharePointShell:($IncludeSharePointShell -and -not $SkipSharePoint) -SkipCollectors $skipKeys `
    -LicenseProfile $licenseProfile -LicenseSource $licenseSource

foreach ($line in Format-NRGBaselinePlanSummary -Plan $plan) { Write-Host $line }
Write-Host ''
Write-Host 'Per control' -ForegroundColor Cyan
foreach ($r in @($plan.Controls)) {
    Write-Host ('  {0,-13} {1,-9} {2,-26} {3}' -f $r.ControlId, $r.Tier, $r.Expected, $r.Reason)
}
Write-Host ''
Write-Host $plan.Note -ForegroundColor DarkGray

if ($OutputPath) {
    $plan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
    Write-Host "Plan written: $OutputPath" -ForegroundColor Green
}
if ($PassThru) { return $plan }

#Requires -Version 7.0
<#
.SYNOPSIS
    One-time: grant, in a client tenant, the Microsoft Graph read permissions
    the assessment requests.

.DESCRIPTION
    Grant-NRGGraphConsent.ps1
    NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson

    Purpose: close the "not granted in this tenant" gap that leaves AAD-8.2
    (AccessReview.Read.All), AAD-11.3 (IdentityRiskyServicePrincipal.Read.All)
    and DEF-4.6 (AttackSimulation.Read.All) unassessed.

    Signs in to the named tenant requesting the assessment's full read-only
    scope list. Microsoft shows its consent prompt for anything not yet
    granted; a Global Administrator (or Privileged Role Administrator) ticks
    "Consent on behalf of your organization" and accepts. The script then
    reads the token's granted scopes back, reports anything still missing and
    signs out.

    This script makes no API writes itself: the grant is made by the
    administrator in Microsoft's consent prompt. It lives outside the
    read-only module for that reason. Every scope requested is *.Read.* —
    the same list Connect-NRGServices requests on every run.

    Data keys: none. Graph: sign-in only (Get-MgContext).
    Exit codes: 0 all granted, 1 sign-in failed, 3 some scopes still missing.

.PARAMETER TenantDomain
    Any verified domain of the client tenant (e.g. contoso.com).

.EXAMPLE
    .\Grant-NRGGraphConsent.ps1 -TenantDomain contoso.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61})+$')]
    [string] $TenantDomain
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Interactive browser sign-in, as Connect-NRGServices does (no WAM broker).
$env:MSAL_ALLOW_BROKER        = '0'
$env:MSAL_DISABLE_TOKENBROKER = '1'

$mod = Import-Module (Join-Path $PSScriptRoot 'NRG-Assessment.psd1') -Force -PassThru
$scopes    = & $mod { Get-NRGGraphScopeList }
$consentMap = @(& $mod { Get-NRGConsentScopeMap })

$tenantId = Resolve-NRGTenantId -Domain $TenantDomain
if (-not $tenantId) {
    Write-Host "[!] Could not resolve a tenant for $TenantDomain. Check the domain is verified in the tenant." -ForegroundColor Red
    exit 1
}

Write-Host "[-] Signing in to $TenantDomain ($tenantId)." -ForegroundColor Cyan
Write-Host '    Sign in as a Global Administrator. On the consent prompt, tick' -ForegroundColor DarkGray
Write-Host '    "Consent on behalf of your organization", then Accept.' -ForegroundColor DarkGray
try {
    Connect-MgGraph -TenantId $tenantId -Scopes $scopes -ContextScope Process -NoWelcome -ErrorAction Stop
} catch {
    Write-Host "[!] Sign-in failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

try {
    $ctx = Get-MgContext
    if (-not $ctx -or "$($ctx.TenantId)" -ne $tenantId) {
        Write-Host "[!] Signed in to tenant $($ctx.TenantId), not $tenantId. Nothing was checked." -ForegroundColor Red
        exit 1
    }
    $granted = @($ctx.Scopes)
    $missing = @($scopes | Where-Object { $granted -notcontains $_ })
    if ($missing.Count -eq 0) {
        Write-Host "[+] All $($scopes.Count) read permissions are granted in $TenantDomain." -ForegroundColor Green
        Write-Host '    AAD-8.2, AAD-11.3 and DEF-4.6 will be assessed on the next run.' -ForegroundColor Green
        exit 0
    }
    Write-Host "[!] Still not granted in ${TenantDomain}: $($missing -join ', ')" -ForegroundColor Yellow
    $blocked = @($consentMap | Where-Object { $_.Scope -in $missing } | ForEach-Object { $_.ControlId })
    if ($blocked.Count -gt 0) { Write-Host "    Still unassessed: $($blocked -join ', ')" -ForegroundColor Yellow }
    Write-Host '    The account may not be an administrator, or the organization-wide box was not ticked.' -ForegroundColor DarkGray
    exit 3
} finally {
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
}

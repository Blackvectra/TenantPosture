#Requires -Version 7.0

<#
.SYNOPSIS
    Distribution-list scan: lists every distribution list with its members and settings,
    compares each setting with a documented recommendation, and writes a worksheet an
    administrator uses to harden the lists.

.DESCRIPTION
    Connects to Exchange Online ONLY. It reads distribution groups, mail-enabled security
    groups, room lists and dynamic distribution groups, their settings and their members,
    and nothing else. Every other area (Entra ID, Defender, Teams, SharePoint, Intune,
    Purview, Power Platform, DNS) and Microsoft 365 (Unified) groups, including
    Teams-connected groups, are NOT assessed, and the worksheet says so.

    READ-ONLY. It creates, adds, removes and changes no user, group or setting. The
    worksheet prints the PowerShell an administrator would run to close a shortfall; those
    commands are TEXT and this script never runs them.

    Each list is compared with the recommendations in Config/distribution-list-baseline.json
    (DL-1.1 to DL-2.3). Microsoft's documented defaults are judged as written. A setting that
    is NRG's own judgment (a member cap, external members, the join and leave policy) is
    judged only against a value approved in Config/nrg-standards.json; those lists ship
    empty, so until the owner approves them the setting is reported and not assessed.

.PARAMETER UserPrincipalName
    Optional sign-in hint for the Exchange Online sign-in window.

.PARAMETER DelegatedOrganization
    GDAP: the client's .onmicrosoft.com routing domain. Without it Exchange connects to
    the signed-in operator's own organization.

.PARAMETER TenantId
    Optional tenant GUID. A session for any other tenant is refused.

.PARAMETER OutputPath
    Output directory. Defaults to .\output.

.PARAMETER MemberReadLimit
    The most members read per list (default 5000). A larger list is read up to the limit and
    marked truncated; the worksheet never says "no external member" for a list it did not
    read in full.

.PARAMETER KeepSession
    Leave the Exchange Online session open (a caller that connected it keeps it).

.EXAMPLE
    .\Invoke-NRGDistributionListScan.ps1 -UserPrincipalName admin@contoso.com

.EXAMPLE
    .\Invoke-NRGDistributionListScan.ps1 -DelegatedOrganization contoso.onmicrosoft.com -TenantId 00000000-0000-0000-0000-000000000000

.OUTPUTS
    .\output\<tenant>-<timestamp>-distribution-lists.txt   one section per list
    .\output\<tenant>-<timestamp>-distribution-lists.csv   one row per list per recommendation

.NOTES
    NRG Technology Services / NextLayerSec LLC — nrgtechservices.com
    Read-only. Exit codes: 0 success | 1 sign-in failure | 2 no lists found |
                           3 partial read | 4 fatal error.
#>

[CmdletBinding()]
param(
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
    [string] $UserPrincipalName,

    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*\.onmicrosoft\.com$')]
    [string] $DelegatedOrganization,

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $TenantId,

    [string] $OutputPath,

    [ValidateRange(1, 100000)]
    [int] $MemberReadLimit = 5000,

    [switch] $KeepSession
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
if (-not $OutputPath) { $OutputPath = Join-Path $scriptDir 'output' }
# OWASP A01: refuse a traversal sequence before the path is used.
if ($OutputPath -match '\.\.[/\\]') {
    Write-Host "  [!] OutputPath contains a traversal sequence: $OutputPath" -ForegroundColor Red
    exit 4
}

Write-Host ''
Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ' NRG Distribution-List Scan' -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
Write-Host '  Connects to Exchange Online ONLY.' -ForegroundColor Yellow
Write-Host '  Reads distribution lists, their settings and their members.' -ForegroundColor Yellow
Write-Host '  NOT assessed: Entra ID, Defender, Teams, SharePoint, Intune, Purview, Power Platform, DNS,' -ForegroundColor Yellow
Write-Host '                and Microsoft 365 (Unified) groups, including Teams-connected groups.' -ForegroundColor Yellow
Write-Host '  Read-only: it changes no user, group or setting. Commands in the worksheet are text only.' -ForegroundColor Yellow
Write-Host "  Member read limit: $MemberReadLimit per list    Output: $OutputPath" -ForegroundColor White
Write-Host ''

Write-Host '[-] Loading NRG-Assessment module...' -ForegroundColor Cyan
try {
    Import-Module (Join-Path $scriptDir 'NRG-Assessment.psd1') -Force -ErrorAction Stop
    Write-Host '  [+] Module loaded' -ForegroundColor Green
} catch {
    Write-Host "  [!] Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 4
}
Clear-NRGState

$exitCode = 0
$connected = $false
try {
    # ── Connect: Exchange Online only ────────────────────────────────────────
    Write-Host '[-] Connecting to Exchange Online...' -ForegroundColor Cyan
    $connectParams = @{}
    if ($UserPrincipalName)     { $connectParams['UserPrincipalName'] = $UserPrincipalName }
    if ($DelegatedOrganization) { $connectParams['DelegatedOrganization'] = $DelegatedOrganization }
    if ($TenantId)              { $connectParams['ExpectedTenantId'] = $TenantId }
    $conn = Connect-NRGExchangeOnly @connectParams
    if (-not $conn.EXO) {
        Write-Host "  [!] Exchange Online sign-in failed: $($conn.Error)" -ForegroundColor Red
        $exitCode = 1
    } else {
        $connected = -not $conn.ReusedSession
        Write-Host $(if ($conn.ReusedSession) { "  [+] Exchange Online (reusing the existing session for this tenant)" } else { '  [+] Exchange Online connected' }) -ForegroundColor Green

        # ── Collect, evaluate, publish ──────────────────────────────────────
        Write-Host '[-] Reading distribution lists, settings and members...' -ForegroundColor Cyan
        $raw = Invoke-NRGCollectDistributionLists -MemberReadLimit $MemberReadLimit
        $sec = $raw.Data.SectionStatus
        $stats = $raw.Data.Stats
        Write-Host ("  [+] {0} list(s) read: {1} distribution/security, {2} dynamic" -f $stats.ListsRead, $stats.DistributionGroups, $stats.DynamicDistributionGroups) -ForegroundColor Green
        Write-Host ("      Members read in full: {0}   truncated at the limit: {1}   failed: {2}   throttle retries: {3}" -f $stats.ListsMembersCollected, $stats.ListsMembersTruncated, $stats.ListsMembersFailed, $stats.ThrottleRetries) -ForegroundColor White
        foreach ($k in $sec.Keys) {
            if ($sec[$k] -ne 'Collected') { Write-Host "  [!] Section $k : $($sec[$k]); the worksheet reports what it covers as NOT assessed" -ForegroundColor Yellow }
        }

        Test-NRGControlDistributionLists

        $tenantDomain = [string]$raw.Data.TenantDomain
        $tenantTag = if ($tenantDomain) { ($tenantDomain -split '\.')[0] } else { 'tenant' }
        # OWASP A01 — strip any non-[a-zA-Z0-9-] before using the tag in a file path.
        $tenantTag = $tenantTag -replace '[^a-zA-Z0-9-]', ''
        if (-not $tenantTag) { $tenantTag = 'tenant' }
        $baseName = "$tenantTag-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $meta = @{
            TenantDomain   = $tenantDomain
            AssessmentTime = (Get-Date).ToString('o')
            ToolVersion    = $(if (Get-Variable -Name NRGAssessmentVersion -ErrorAction SilentlyContinue) { [string]$NRGAssessmentVersion } else { 'unknown' })
        }
        $out = Publish-NRGDistributionListWorksheet -OutputDirectory $OutputPath -BaseName $baseName -Metadata $meta -Raw $raw
        Write-Host ''
        Write-Host "  [+] Worksheet (text): $($out.TextPath)" -ForegroundColor Green
        Write-Host "  [+] Worksheet (CSV):  $($out.CsvPath)" -ForegroundColor Green
        Write-Host '      These files hold tenant inventory; their access is restricted to you, SYSTEM and Administrators.' -ForegroundColor DarkYellow

        # Why a read failed is in the worksheet ("Collection problems"); the first few are printed here too.
        foreach ($p in @($out.Model.Problems | Select-Object -First 5)) { Write-Host "  [!] $p" -ForegroundColor Yellow }
        if (@($out.Model.Problems).Count -gt 5) { Write-Host "      ... and $(@($out.Model.Problems).Count - 5) more in the worksheet." -ForegroundColor Yellow }

        $shortfalls = @($out.Model.Lists | ForEach-Object { $_.Rows | Where-Object { $_.Status -eq 'Shortfall' } }).Count
        Write-Host ("      {0} shortfall(s) across {1} list(s). Review every command before running it; this tool did not." -f $shortfalls, $out.ListCount) -ForegroundColor White

        # "No lists found" (2) is only true when every section read. A section that failed is a
        # partial read (3) even when the other one returned nothing, and both failing is fatal (4).
        $exitCode = if ($sec.DistributionGroups -ne 'Collected' -and $sec.DynamicDistributionGroups -ne 'Collected') { 4 }
                    elseif (@($sec.Values | Where-Object { $_ -ne 'Collected' }).Count -gt 0 -or $stats.ListsMembersTruncated -gt 0) { 3 }
                    elseif ($stats.ListsRead -eq 0) { 2 }
                    else { 0 }
    }
} catch {
    Write-Host "  [!] Fatal error: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 4
} finally {
    if ($connected -and -not $KeepSession) {
        Disconnect-NRGExchangeOnly
        Write-Host '[-] Exchange Online session disconnected.' -ForegroundColor DarkGray
    }
}
exit $exitCode

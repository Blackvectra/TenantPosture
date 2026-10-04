#Requires -Version 7.0
#
# Invoke-NRGDistributionListScan.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: The -DistributionListsOnly run, end to end: sign in to Exchange Online ONLY,
#          collect the distribution lists and the tenant-wide filtering bypasses,
#          evaluate them into DL-* findings, and write the worksheet (text and CSV).
#          Read-only throughout. It says plainly that every other area was not assessed.
#
# Sets:     EXO-DistributionLists, the DL-* findings, two files in -OutputPath.
# Consumes: Exchange Online (Get-* cmdlets only).
#
# Exit codes (returned in .ExitCode, applied by the entry point): 0 success, 1 sign-in
# failure, 2 the read completed and Exchange returned no distribution list, 3 partial
# collection (a section did not collect, or lists beyond -MaxLists were left out, so
# part of the worksheet reads "Not assessed" or is missing), 4 fatal error.

function Invoke-NRGDistributionListScan {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $OutputPath,

        [string] $UserPrincipalName,
        [string] $ExpectedTenantId,
        [string] $DelegatedOrganization,
        [string] $AppId,
        [string] $TenantId,
        [string] $CertificateThumbprint,
        [string] $OrganizationDomain,
        # The domain the operator asked for, shown in the worksheet header. The CONNECTED tenant is what is verified.
        [string] $TenantDomain,

        [ValidateRange(1, 50000)] [int] $MaxMembersPerList = 500,
        [ValidateRange(1, 100000)] [int] $MaxLists = 5000,
        [switch] $KeepSession
    )

    $out = [ordered]@{ ExitCode = 4; TextPath = ''; CsvPath = ''; Summary = $null; TenantDomain = ''; Error = '' }
    Clear-NRGState

    Write-Host ''
    Write-Host 'Distribution-list scan: READ-ONLY. It lists members and settings; it never creates, adds, removes or changes anything.' -ForegroundColor Cyan
    Write-Host 'Connecting to Exchange Online ONLY. Every other area (identity, Conditional Access, Defender, Purview, Teams, SharePoint, Intune, Power Platform, DNS) is NOT assessed.' -ForegroundColor Cyan
    Write-Host ''

    $conn = $null
    try {
        try {
            $connect = @{}
            if ($AppId -and $TenantId -and $CertificateThumbprint) {
                if ($OrganizationDomain -notmatch '^[a-zA-Z0-9][a-zA-Z0-9-]*\.onmicrosoft\.com$') {
                    throw "App-only sign-in needs the tenant's .onmicrosoft.com routing domain (-OrganizationDomain); '$OrganizationDomain' is not one. Find it in the Microsoft 365 admin center under Settings, Domains."
                }
                $connect = @{ AppId = $AppId; TenantId = $TenantId; CertificateThumbprint = $CertificateThumbprint; OrganizationDomain = $OrganizationDomain }
            } else {
                if ($UserPrincipalName) { $connect['UserPrincipalName'] = $UserPrincipalName }
                if ($ExpectedTenantId) { $connect['ExpectedTenantId'] = $ExpectedTenantId }
                if ($DelegatedOrganization) { $connect['DelegatedOrganization'] = $DelegatedOrganization }
            }
            $conn = Connect-NRGExchangeOnly @connect
        } catch {
            $out.ExitCode = 1; $out.Error = $_.Exception.Message
            Write-Host "  [!] $($out.Error)" -ForegroundColor Red
            return $out
        }
        if (-not $conn -or -not [bool](Get-NRGObjectField -Item $conn -Key 'EXO' -Default $false)) {
            $out.ExitCode = 1; $out.Error = 'No Exchange Online session was established.'
            Write-Host "  [!] $($out.Error)" -ForegroundColor Red
            return $out
        }
        Write-Host '  [+] Exchange Online connected' -ForegroundColor Green

        $connTenant = [string](Get-NRGObjectField -Item $conn -Key 'TenantDomain' -Default '')
        $out.TenantDomain = if ($connTenant) { $connTenant } else { $TenantDomain }

        Write-Host '[-] Reading distribution lists, members and filtering bypasses (read-only)...' -ForegroundColor Cyan
        $raw = Invoke-NRGCollectDistributionLists -MaxMembersPerList $MaxMembersPerList -MaxLists $MaxLists
        Test-NRGDistributionLists

        # The session may name no domain (an interactive sign-in carries none). The tenant's own routing domain is then
        # taken from its accepted domains, never from the signed-in account, which may belong to the MSP.
        if (-not $out.TenantDomain) {
            $routing = @(@(Get-NRGNestedProperty -Object $raw -Path 'Data.AcceptedDomains' -Default @()) | ForEach-Object { [string]$_ } |
                Where-Object { $_ -match '\.onmicrosoft\.com$' -and $_ -notmatch '\.mail\.onmicrosoft\.com$' } | Select-Object -First 1)
            if ($routing.Count) { $out.TenantDomain = $routing[0] }
        }
        $meta = [ordered]@{
            TenantDomain   = $out.TenantDomain
            TenantId       = [string](Get-NRGObjectField -Item $conn -Key 'TenantId' -Default '')
            AssessmentDate = (Get-Date -Format 'yyyy-MM-dd HH:mm')
            ToolVersion    = [string]$script:NRGAssessmentVersion
        }
        $ws = Get-NRGDistributionListWorksheet -Metadata $meta

        $tag = ((($out.TenantDomain -split '\.')[0]) -replace '[^a-zA-Z0-9_-]', '')
        if (-not $tag) { $tag = 'tenant' }
        $base = Join-Path $OutputPath ("{0}-{1}" -f $tag, (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $paths = Publish-NRGDistributionListWorksheet -Worksheet $ws -OutputBase $base
        $out.TextPath = $paths.TextPath; $out.CsvPath = $paths.CsvPath
        $out.Summary = $ws.Summary

        $notCollected = @(@('Lists', 'DynamicLists', 'Members', 'AcceptedDomains', 'TransportRules', 'ConnectionFilter', 'AntiSpam') |
            Where-Object { [string](Get-NRGNestedProperty -Object $raw -Path "Data.SectionStatus.$_" -Default 'NotRun') -ne 'Collected' })
        # Lists the -MaxLists cap left out are as incomplete as a section that failed: the worksheet reads whole and is not.
        $beyondCap = [int](Get-NRGObjectField -Item $ws.Summary -Key 'ListsBeyondCap' -Default 0)
        $out.ExitCode = if (-not [bool](Get-NRGObjectField -Item $raw -Key 'Success' -Default $false) -or $notCollected.Count -gt 0 -or $beyondCap -gt 0) { 3 }
                        elseif ([int]$ws.Summary.ListCount -eq 0) { 2 }
                        else { 0 }

        Write-Host ''
        Write-Host ("  Lists read: {0}   Lists that accept mail from anyone: {1}   Lists with an external member: {2}   Allow lists proposed: {3}   Lists whose members were not read: {4}" -f $ws.Summary.ListCount, $ws.Summary.ListsReachableFromOutside, $ws.Summary.ListsWithExternalMembers, $ws.Summary.AllowListsProposed, $ws.Summary.ListsMembersNotRead) -ForegroundColor White
        if ($beyondCap -gt 0) { Write-Host "  [!] $beyondCap list(s) beyond -MaxLists $MaxLists were NOT read and are not in the worksheet. That is not a clean result for them; raise -MaxLists and run again." -ForegroundColor Yellow }
        if ($ws.Summary.ListCount -eq 0 -and $notCollected.Count -eq 0) { Write-Host '  [!] Exchange returned no distribution list. If the signed-in account is scoped to part of the directory, lists outside that scope are not returned.' -ForegroundColor Yellow }
        if ($notCollected.Count) { Write-Host "  [!] Not collected: $($notCollected -join ', '). Those parts read 'Not assessed' in the worksheet; they are not clean." -ForegroundColor Yellow }
        Write-Host "  [+] Worksheet (text): $($out.TextPath)" -ForegroundColor Green
        Write-Host "  [+] Worksheet (CSV):  $($out.CsvPath)" -ForegroundColor Green
        Write-Host '      Internal use only: the files hold member names and addresses. Commands in them are text for an administrator; nothing was changed.' -ForegroundColor DarkGray
    } catch {
        $out.ExitCode = 4; $out.Error = $_.Exception.Message
        Write-Host "  [!] Distribution-list scan failed: $($out.Error)" -ForegroundColor Red
    } finally {
        if (-not $KeepSession) { try { Disconnect-NRGServices } catch { } }
    }
    return $out
}

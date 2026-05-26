#Requires -Version 7.0
#
# Invoke-NRGCollectSharePoint.ps1
# Collects SharePoint Online tenant configuration via Graph API.
#
# READ-ONLY. Uses Graph instead of PnP.PowerShell to avoid the old Graph.Core
# assembly that PnP loads, which breaks Microsoft.Graph cmdlets in the same session.
#
# Some SharePoint admin properties are only in beta — endpoints used:
#   /v1.0/admin/sharepoint/settings
#   /v1.0/sites/root  (for root site)
#
# Required Graph scopes: SharePointTenantSettings.Read.All, Sites.Read.All
#   (v4.6.4 EMERGENCY FIX Medium #9 added SharePointTenantSettings.Read.All to
#    Connect-NRGServices — /admin/sharepoint/settings now requires it; the
#    Sites.Read.All path Microsoft historically permitted is being deprecated.)
#
# NIST SP 800-53: AC-3 (access enforcement), AC-17 (remote access), MP-7 (media use)
# MITRE ATT&CK:   T1567.002 (Exfiltration to Cloud Storage), T1530
#

function Invoke-NRGCollectSharePoint {
    [CmdletBinding()] param()
    $result = @{
        Success = $false
        Data    = @{
            TenantSettings = $null
            RootSite       = $null
            ExternalSharing = $null
        }
    }

    try {
        # Tenant-level SharePoint settings
        # v4.6.4 EMERGENCY FIX (Medium #10): explicit null guards on every
        # property read. Under Set-StrictMode -Version Latest, accessing a
        # missing property on the response object raises a terminating error;
        # the prior `[int]$settings.deletedUserPersonalSiteRetentionPeriodInDays`
        # crashed the collector if Graph returned a partial response. Each
        # value is now read with ?? defaults appropriate to the field's type.
        try {
            $settings = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -ErrorAction Stop
            if ($settings) {
                $retentionDays = 0
                $retentionRaw = $settings.deletedUserPersonalSiteRetentionPeriodInDays
                if ($null -ne $retentionRaw) {
                    try { $retentionDays = [int]$retentionRaw } catch { $retentionDays = 0 }
                }

                $result.Data.TenantSettings = @{
                    IsLegacyAuthProtocolsEnabled         = [bool]($settings.isLegacyAuthProtocolsEnabled ?? $false)
                    IsLoopEnabled                        = [bool]($settings.isLoopEnabled ?? $false)
                    IsMacSyncAppEnabled                  = [bool]($settings.isMacSyncAppEnabled ?? $false)
                    IsRequireAcceptingUserToMatchInvitedUserEnabled = [bool]($settings.isRequireAcceptingUserToMatchInvitedUserEnabled ?? $false)
                    IsResharingByExternalUsersEnabled    = [bool]($settings.isResharingByExternalUsersEnabled ?? $false)
                    IsSharePointMobileNotificationEnabled = [bool]($settings.isSharePointMobileNotificationEnabled ?? $false)
                    IsSharePointNewsfeedEnabled          = [bool]($settings.isSharePointNewsfeedEnabled ?? $false)
                    IsSiteCreationEnabled                = [bool]($settings.isSiteCreationEnabled ?? $false)
                    IsSiteCreationUIEnabled              = [bool]($settings.isSiteCreationUIEnabled ?? $false)
                    IsSitePagesCreationEnabled           = [bool]($settings.isSitePagesCreationEnabled ?? $false)
                    IsSitesStorageLimitAutomatic         = [bool]($settings.isSitesStorageLimitAutomatic ?? $false)
                    IsSyncButtonHiddenOnPersonalSite     = [bool]($settings.isSyncButtonHiddenOnPersonalSite ?? $false)
                    IsUnmanagedSyncAppForTenantRestricted = [bool]($settings.isUnmanagedSyncAppForTenantRestricted ?? $false)
                    SharingCapability                    = [string]($settings.sharingCapability ?? '')
                    SharingDomainRestrictionMode         = [string]($settings.sharingDomainRestrictionMode ?? '')
                    AllowedDomainGuidsForSyncApp         = @($settings.allowedDomainGuidsForSyncApp ?? @())
                    AvailableManagedPathsForSiteCreation = @($settings.availableManagedPathsForSiteCreation ?? @())
                    DeletedUserPersonalSiteRetentionPeriodInDays = $retentionDays
                    SharingAllowedDomainList             = @($settings.sharingAllowedDomainList ?? @())
                    SharingBlockedDomainList             = @($settings.sharingBlockedDomainList ?? @())
                }
                $result.Data.ExternalSharing = [string]($settings.sharingCapability ?? '')
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'SPO-TenantSettings' -Message $_.Exception.Message
            }
        }

        # Root site
        try {
            $root = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/sites/root' -ErrorAction Stop
            if ($root) {
                $result.Data.RootSite = @{
                    Id          = $root.id
                    DisplayName = $root.displayName
                    WebUrl      = $root.webUrl
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'SPO-RootSite' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'SharePoint-Collector' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'SharePoint' -Data $result
}

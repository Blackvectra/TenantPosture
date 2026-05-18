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
        try {
            $settings = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -ErrorAction Stop
            if ($settings) {
                $result.Data.TenantSettings = @{
                    IsLegacyAuthProtocolsEnabled         = [bool]$settings.isLegacyAuthProtocolsEnabled
                    IsLoopEnabled                        = [bool]$settings.isLoopEnabled
                    IsMacSyncAppEnabled                  = [bool]$settings.isMacSyncAppEnabled
                    IsRequireAcceptingUserToMatchInvitedUserEnabled = [bool]$settings.isRequireAcceptingUserToMatchInvitedUserEnabled
                    IsResharingByExternalUsersEnabled    = [bool]$settings.isResharingByExternalUsersEnabled
                    IsSharePointMobileNotificationEnabled = [bool]$settings.isSharePointMobileNotificationEnabled
                    IsSharePointNewsfeedEnabled          = [bool]$settings.isSharePointNewsfeedEnabled
                    IsSiteCreationEnabled                = [bool]$settings.isSiteCreationEnabled
                    IsSiteCreationUIEnabled              = [bool]$settings.isSiteCreationUIEnabled
                    IsSitePagesCreationEnabled           = [bool]$settings.isSitePagesCreationEnabled
                    IsSitesStorageLimitAutomatic         = [bool]$settings.isSitesStorageLimitAutomatic
                    IsSyncButtonHiddenOnPersonalSite     = [bool]$settings.isSyncButtonHiddenOnPersonalSite
                    IsUnmanagedSyncAppForTenantRestricted = [bool]$settings.isUnmanagedSyncAppForTenantRestricted
                    SharingCapability                    = [string]$settings.sharingCapability
                    SharingDomainRestrictionMode         = [string]$settings.sharingDomainRestrictionMode
                    AllowedDomainGuidsForSyncApp         = @($settings.allowedDomainGuidsForSyncApp)
                    AvailableManagedPathsForSiteCreation = @($settings.availableManagedPathsForSiteCreation)
                    DeletedUserPersonalSiteRetentionPeriodInDays = [int]$settings.deletedUserPersonalSiteRetentionPeriodInDays
                    SharingAllowedDomainList             = @($settings.sharingAllowedDomainList)
                    SharingBlockedDomainList             = @($settings.sharingBlockedDomainList)
                }
                $result.Data.ExternalSharing = [string]$settings.sharingCapability
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

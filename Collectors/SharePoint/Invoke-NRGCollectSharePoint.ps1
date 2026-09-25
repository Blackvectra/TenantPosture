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
            # Populated only when a SharePoint Online Management Shell session
            # exists (Connect-SPOService). Graph /admin/sharepoint/settings does
            # NOT expose these fields; the five SPO-2.2/2.4/2.6/3.2/3.4 controls
            # depend on them. $null → those evaluators report NotApplicable.
            TenantSettingsSPO = $null
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
            $settings = Invoke-NRGGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -ErrorAction Stop
            if ($settings) {
                # $null when absent or unparseable — never 0, which read as
                # "OneDrive destroyed after 0 days" (SPO-4.1 Gap) for a value
                # nothing had returned.
                $retentionDays = $null
                $retentionRaw = Get-NRGObjectField -Item $settings -Key 'deletedUserPersonalSiteRetentionPeriodInDays' -Default $null
                if ($null -ne $retentionRaw) {
                    $parsed = 0
                    if ([int]::TryParse([string]$retentionRaw, [ref]$parsed)) { $retentionDays = $parsed }
                }

                # A flag Graph did not return stays $null. A `?? $false`
                # default read an absent isLegacyAuthProtocolsEnabled as
                # "legacy auth disabled" (SPO-1.3 pass) and an absent
                # isUnmanagedSyncAppForTenantRestricted as "not restricted".
                $flag = { param([string] $k) $v = Get-NRGObjectField -Item $settings -Key $k -Default $null; if ($null -eq $v) { $null } else { [bool]$v } }
                $result.Data.TenantSettings = @{
                    IsLegacyAuthProtocolsEnabled         = (& $flag 'isLegacyAuthProtocolsEnabled')
                    IsLoopEnabled                        = (& $flag 'isLoopEnabled')
                    IsMacSyncAppEnabled                  = (& $flag 'isMacSyncAppEnabled')
                    IsRequireAcceptingUserToMatchInvitedUserEnabled = (& $flag 'isRequireAcceptingUserToMatchInvitedUserEnabled')
                    IsResharingByExternalUsersEnabled    = (& $flag 'isResharingByExternalUsersEnabled')
                    IsSharePointMobileNotificationEnabled = (& $flag 'isSharePointMobileNotificationEnabled')
                    IsSharePointNewsfeedEnabled          = (& $flag 'isSharePointNewsfeedEnabled')
                    IsSiteCreationEnabled                = (& $flag 'isSiteCreationEnabled')
                    IsSiteCreationUIEnabled              = (& $flag 'isSiteCreationUIEnabled')
                    IsSitePagesCreationEnabled           = (& $flag 'isSitePagesCreationEnabled')
                    IsSitesStorageLimitAutomatic         = (& $flag 'isSitesStorageLimitAutomatic')
                    IsSyncButtonHiddenOnPersonalSite     = (& $flag 'isSyncButtonHiddenOnPersonalSite')
                    IsUnmanagedSyncAppForTenantRestricted = (& $flag 'isUnmanagedSyncAppForTenantRestricted')
                    SharingCapability                    = [string](Get-NRGObjectField -Item $settings -Key 'sharingCapability' -Default '')
                    SharingDomainRestrictionMode         = [string](Get-NRGObjectField -Item $settings -Key 'sharingDomainRestrictionMode' -Default '')
                    AllowedDomainGuidsForSyncApp         = @(Get-NRGObjectField -Item $settings -Key 'allowedDomainGuidsForSyncApp' -Default @())
                    AvailableManagedPathsForSiteCreation = @(Get-NRGObjectField -Item $settings -Key 'availableManagedPathsForSiteCreation' -Default @())
                    DeletedUserPersonalSiteRetentionPeriodInDays = $retentionDays
                    SharingAllowedDomainList             = @(Get-NRGObjectField -Item $settings -Key 'sharingAllowedDomainList' -Default @())
                    SharingBlockedDomainList             = @(Get-NRGObjectField -Item $settings -Key 'sharingBlockedDomainList' -Default @())
                }
                $result.Data.ExternalSharing = [string](Get-NRGObjectField -Item $settings -Key 'sharingCapability' -Default '')
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'SPO-TenantSettings' -Message $_.Exception.Message
            }
        }

        # Root site
        try {
            $root = Invoke-NRGGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/sites/root' -ErrorAction Stop
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

        # SharePoint Online Management Shell tenant settings — only if a
        # Connect-SPOService session is live (see Connect-NRGServices section 5).
        # Get-SPOTenant surfaces the sharing-governance fields Graph omits.
        # Field names verified against Set-SPOTenant docs.
        if (Get-Command Get-SPOTenant -ErrorAction SilentlyContinue) {
            try {
                $t = Get-SPOTenant -ErrorAction Stop
                if ($t) {
                    $result.Data.TenantSettingsSPO = @{
                        RequireAnonymousLinksExpireInDays = [int]($t.RequireAnonymousLinksExpireInDays ?? -1)   # SPO-2.2
                        EmailAttestationRequired          = [bool]($t.EmailAttestationRequired ?? $false)       # SPO-2.6
                        EmailAttestationReAuthDays        = [int]($t.EmailAttestationReAuthDays ?? 0)           # SPO-2.6
                        NotifyOwnersWhenItemsReshared     = [bool]($t.NotifyOwnersWhenItemsReshared ?? $false)  # SPO-3.2
                        ExternalUserExpirationRequired    = [bool]($t.ExternalUserExpirationRequired ?? $false) # SPO-3.4
                        ExternalUserExpireInDays          = [int]($t.ExternalUserExpireInDays ?? 0)             # SPO-3.4
                        # SPO-3.3: org-wide version-history default applied to NEW document
                        # libraries / OneDrive accounts. Field names per Get-SPOTenant docs.
                        # SPO-1.2 / SPO-1.5. Read through Get-NRGObjectField: absent
                        # means "not read" ($null), never a default verdict.
                        DefaultSharingLinkType            = [string](Get-NRGObjectField -Item $t -Key 'DefaultSharingLinkType' -Default '')
                        ConditionalAccessPolicy           = [string](Get-NRGObjectField -Item $t -Key 'ConditionalAccessPolicy' -Default '')
                        EnableAutoExpirationVersionTrim   = [bool]($t.EnableAutoExpirationVersionTrim ?? $false)
                        MajorVersionLimit                 = [int]($t.MajorVersionLimit ?? 0)
                        ExpireVersionsAfterDays           = [int]($t.ExpireVersionsAfterDays ?? 0)
                    }
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'SPO-TenantSettingsShell' -Message $_.Exception.Message
                }
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

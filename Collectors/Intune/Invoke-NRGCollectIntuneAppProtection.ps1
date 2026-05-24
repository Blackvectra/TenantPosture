#Requires -Version 7.0
#
# Invoke-NRGCollectIntuneAppProtection.ps1
# Collects Intune app protection (MAM) and app configuration policies.
#
# READ-ONLY: GET-only Graph calls. Does not create, modify, or remove configuration.
#
# Returns: structured hashtable under key 'Intune-AppProtection' via Set-NRGRawData.
# Reads:   deviceAppManagement/managedAppPolicies, deviceAppManagement/mobileAppConfigurations,
#          deviceAppManagement/targetedManagedAppConfigurations.
#
# NIST SP 800-53: AC-19 (access control for mobile devices), SC-28 (protection of
#                 information at rest), CM-7 (least functionality)
# MITRE ATT&CK:   T1530 (Data from Cloud Storage), T1567 (Exfiltration over Web Service)
#

function Invoke-NRGCollectIntuneAppProtection {
    [CmdletBinding()] param()
    $result = @{
        Success = $false
        Data    = @{
            AppProtectionPolicies = @()
            AppConfigPolicies     = @()
        }
    }

    try {
        # ── App protection (MAM) policies ────────────────────────────────────
        try {
            $mam = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/managedAppPolicies' -ErrorAction Stop
            foreach ($p in @($mam.value)) {
                $result.Data.AppProtectionPolicies += @{
                    Id          = $p.id
                    DisplayName = [string]$p.displayName
                    Description = [string]$p.description
                    Type        = [string]$p.'@odata.type'
                    Version     = $p.version
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-AppProtection-MAM' -Message $_.Exception.Message
            }
        }

        # ── App configuration policies — device-managed (MDM-channel) ────────
        try {
            $appCfgMdm = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileAppConfigurations' -ErrorAction Stop
            foreach ($p in @($appCfgMdm.value)) {
                $result.Data.AppConfigPolicies += @{
                    Id          = $p.id
                    DisplayName = [string]$p.displayName
                    Description = [string]$p.description
                    Type        = [string]$p.'@odata.type'
                    Channel     = 'MDM'
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-AppProtection-AppCfg-MDM' -Message $_.Exception.Message
            }
        }

        # ── App configuration policies — MAM-channel (targeted, no device enrollment) ──
        try {
            $appCfgMam = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/targetedManagedAppConfigurations' -ErrorAction Stop
            foreach ($p in @($appCfgMam.value)) {
                $result.Data.AppConfigPolicies += @{
                    Id          = $p.id
                    DisplayName = [string]$p.displayName
                    Description = [string]$p.description
                    Type        = [string]$p.'@odata.type'
                    Channel     = 'MAM'
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-AppProtection-AppCfg-MAM' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Intune-AppProtection-Collector' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'Intune-AppProtection' -Data $result
}

#Requires -Version 7.0
#
# Invoke-NRGCollectIntuneDeviceCompliance.ps1
# Collects Intune device compliance, configuration, update rings, WHfB, enrollment
# restrictions, and OS compliance summary.
#
# READ-ONLY: GET-only Graph calls. Does not create, modify, or remove configuration.
#
# Returns: structured hashtable under key 'Intune-DeviceCompliance' via Set-NRGRawData.
# Reads:   deviceCompliancePolicies, deviceConfigurations,
#          deviceEnrollmentConfigurations, managedDevices.
#
# NIST SP 800-53: CM-2 (baseline configuration), CM-6 (configuration settings),
#                 CM-8 (component inventory), SI-2 (flaw remediation),
#                 IA-2 (identification and authentication — WHfB)
# MITRE ATT&CK:   T1078 (Valid Accounts), T1133 (External Remote Services)
#

function Invoke-NRGCollectIntuneDeviceCompliance {
    [CmdletBinding()] param()
    $result = @{
        Success = $false
        Data    = @{
            CompliancePolicies     = @()
            ConfigurationProfiles  = @()
            UpdatePolicies         = @()
            WindowsHelloPolicies   = @()
            EnrollmentRestrictions = @()
            EnrollmentConfig       = @()
            OSComplianceSummary    = @{
                TotalCount       = 0
                CompliantCount   = 0
                NonCompliantCount= 0
                ByPlatform       = @{}
            }
        }
    }

    try {
        # ── Device compliance policies ───────────────────────────────────────
        try {
            $compliance = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies' -ErrorAction Stop
            foreach ($p in @($compliance.value)) {
                $result.Data.CompliancePolicies += @{
                    Id          = $p.id
                    DisplayName = [string]$p.displayName
                    Platform    = [string]$p.'@odata.type'
                    Description = [string]$p.description
                    Version     = $p.version
                    # Pull through fields the evaluator looks at; not all platforms expose them
                    BitLockerEnabled        = $p.bitLockerEnabled
                    SecureBootEnabled       = $p.secureBootEnabled
                    PasswordRequired        = $p.passwordRequired
                    StorageRequireEncryption= $p.storageRequireEncryption
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-DeviceCompliance-Policies' -Message $_.Exception.Message
            }
        }

        # ── Device configuration profiles (legacy + Update for Business) ─────
        try {
            $config = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations' -ErrorAction Stop
            foreach ($p in @($config.value)) {
                $odata = [string]$p.'@odata.type'
                $entry = @{
                    Id          = $p.id
                    DisplayName = [string]$p.displayName
                    Platform    = $odata
                    Description = [string]$p.description
                }
                $result.Data.ConfigurationProfiles += $entry

                # Windows Update for Business rings live in deviceConfigurations
                if ($odata -match 'windowsUpdateForBusinessConfiguration') {
                    $result.Data.UpdatePolicies += $entry
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-DeviceCompliance-Config' -Message $_.Exception.Message
            }
        }

        # ── Enrollment configurations (WHfB, platform restrictions, limits) ──
        try {
            $enroll = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations' -ErrorAction Stop
            foreach ($p in @($enroll.value)) {
                $odata = [string]$p.'@odata.type'
                $entry = @{
                    Id          = $p.id
                    DisplayName = [string]$p.displayName
                    Type        = $odata
                    Priority    = $p.priority
                }
                $result.Data.EnrollmentConfig += $entry

                if ($odata -match 'WindowsHelloForBusinessConfiguration') {
                    $result.Data.WindowsHelloPolicies += @{
                        Id                          = $p.id
                        DisplayName                 = [string]$p.displayName
                        State                       = [string]$p.state
                        SecurityDeviceRequired      = $p.securityDeviceRequired
                        UnlockWithBiometricsEnabled = $p.unlockWithBiometricsEnabled
                        PinMinimumLength            = $p.pinMinimumLength
                        PinMaximumLength            = $p.pinMaximumLength
                        PinExpirationInDays         = $p.pinExpirationInDays
                        PinPreviousBlockCount       = $p.pinPreviousBlockCount
                        EnhancedBiometricsState     = [string]$p.enhancedBiometricsState
                        Priority                    = $p.priority
                    }
                } elseif ($odata -match 'Limit|PlatformRestriction|EnrollmentRestriction|DeviceEnrollmentConfiguration$') {
                    $result.Data.EnrollmentRestrictions += $entry
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-DeviceCompliance-Enrollment' -Message $_.Exception.Message
            }
        }

        # ── Managed devices → OS compliance summary ──────────────────────────
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,operatingSystem,complianceState'
            $devList = @()
            while ($next) {
                $page = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $devList += $page.value }
                $next = $page.'@odata.nextLink'
            }
            $result.Data.OSComplianceSummary.TotalCount        = $devList.Count
            $result.Data.OSComplianceSummary.CompliantCount    = @($devList | Where-Object { $_.complianceState -eq 'compliant' }).Count
            $result.Data.OSComplianceSummary.NonCompliantCount = @($devList | Where-Object { $_.complianceState -ne 'compliant' }).Count
            $byPlatform = @{}
            foreach ($d in $devList) {
                $p = if ($d.operatingSystem) { [string]$d.operatingSystem } else { 'Unknown' }
                if (-not $byPlatform.ContainsKey($p)) { $byPlatform[$p] = 0 }
                $byPlatform[$p]++
            }
            $result.Data.OSComplianceSummary.ByPlatform = $byPlatform
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-DeviceCompliance-Devices' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Intune-DeviceCompliance-Collector' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'Intune-DeviceCompliance' -Data $result
}

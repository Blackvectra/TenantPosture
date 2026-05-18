#Requires -Version 7.0
#
# Invoke-NRGCollectIntune.ps1
# Collects Intune device compliance, MAM, MTD, and enrollment configuration via Graph.
#
# READ-ONLY: This collector executes only Get-Mg* and Invoke-MgGraphRequest GET calls.
# It does not create, modify, or remove any configuration.
#
# Returns: structured hashtable stored under key 'Intune' via Set-NRGRawData.
# Reads:   Graph DeviceManagement.* endpoints.
#
# NIST SP 800-53: CM-2 (baseline configuration), CM-8 (component inventory)
# MITRE ATT&CK:   T1078 (Valid Accounts), T1005 (Data from Local System)
#

function Invoke-NRGCollectIntune {
    [CmdletBinding()] param()
    $result = @{
        Success = $false
        Data    = @{
            CompliancePolicies   = @()
            ConfigurationProfiles = @()
            AppProtectionPolicies = @()
            EnrolledDevices       = @{ Total = 0; Compliant = 0; NonCompliant = 0; ByPlatform = @{} }
            EnrollmentConfig      = $null
        }
    }

    try {
        # Device compliance policies
        try {
            $compliance = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies' -ErrorAction Stop
            if ($compliance.value) {
                $result.Data.CompliancePolicies = @($compliance.value | ForEach-Object {
                    @{
                        Id          = $_.id
                        DisplayName = $_.displayName
                        Platform    = $_.'@odata.type'
                        Description = $_.description
                        Version     = $_.version
                    }
                })
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-Compliance' -Message $_.Exception.Message
            }
        }

        # Configuration profiles
        try {
            $config = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations' -ErrorAction Stop
            if ($config.value) {
                $result.Data.ConfigurationProfiles = @($config.value | ForEach-Object {
                    @{
                        Id          = $_.id
                        DisplayName = $_.displayName
                        Platform    = $_.'@odata.type'
                    }
                })
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-Config' -Message $_.Exception.Message
            }
        }

        # App protection (MAM) policies
        try {
            $mam = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/managedAppPolicies' -ErrorAction Stop
            if ($mam.value) {
                $result.Data.AppProtectionPolicies = @($mam.value | ForEach-Object {
                    @{
                        Id          = $_.id
                        DisplayName = $_.displayName
                        Type        = $_.'@odata.type'
                    }
                })
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-MAM' -Message $_.Exception.Message
            }
        }

        # Managed devices (compliance state)
        try {
            $devices = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,operatingSystem,complianceState' -ErrorAction Stop
            if ($devices.value) {
                $devList = @($devices.value)
                $result.Data.EnrolledDevices.Total        = $devList.Count
                $result.Data.EnrolledDevices.Compliant    = @($devList | Where-Object { $_.complianceState -eq 'compliant' }).Count
                $result.Data.EnrolledDevices.NonCompliant = @($devList | Where-Object { $_.complianceState -ne 'compliant' }).Count
                $byPlatform = @{}
                foreach ($d in $devList) {
                    $p = if ($d.operatingSystem) { [string]$d.operatingSystem } else { 'Unknown' }
                    if (-not $byPlatform.ContainsKey($p)) { $byPlatform[$p] = 0 }
                    $byPlatform[$p]++
                }
                $result.Data.EnrolledDevices.ByPlatform = $byPlatform
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-Devices' -Message $_.Exception.Message
            }
        }

        # Enrollment configuration
        try {
            $enroll = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations' -ErrorAction Stop
            if ($enroll.value) {
                $result.Data.EnrollmentConfig = @($enroll.value | ForEach-Object {
                    @{
                        Id          = $_.id
                        DisplayName = $_.displayName
                        Type        = $_.'@odata.type'
                        Priority    = $_.priority
                    }
                })
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-Enrollment' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Intune-Collector' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'Intune' -Data $result
}

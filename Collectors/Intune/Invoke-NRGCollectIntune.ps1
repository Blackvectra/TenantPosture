#
# Invoke-NRGCollectIntune.ps1
# Collects Microsoft Intune (Endpoint Manager) configuration via Microsoft Graph.
#
# Requires: Microsoft Graph connection
# Scopes:   DeviceManagementConfiguration.Read.All, DeviceManagementApps.Read.All
#
# Data keys stored:
#   Intune.CompliancePolicies       — /v1.0/deviceManagement/deviceCompliancePolicies
#   Intune.EnrollmentConfigs        — /v1.0/deviceManagement/deviceEnrollmentConfigurations
#   Intune.ManagedDeviceOverview    — /v1.0/deviceManagement/managedDeviceOverview
#   Intune.MtdConnectors            — /v1.0/deviceManagement/mobileThreatDefenseConnectors
#   Intune.AppProtectionPolicies    — /v1.0/deviceAppManagement/managedAppPolicies
#   Intune.DeviceConfigurations     — /v1.0/deviceManagement/deviceConfigurations
#
# NIST SP 800-53: CM-2, CM-6, CM-7, SC-8, SC-28, SI-3
# MITRE ATT&CK:   T1082, T1005, T1078
#

function Invoke-NRGCollectIntune {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'Intune'
        Timestamp  = (Get-Date -Format 'o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    function GraphGet {
        param([string]$Uri)
        $all = @()
        $next = $Uri
        do {
            try {
                $r = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($r.value) { $all += $r.value }
                elseif ($r -and -not $r.ContainsKey('value')) { $all += $r }
                $next = if ($r.'@odata.nextLink') { $r.'@odata.nextLink' } else { $null }
            } catch {
                throw $_
            }
        } while ($next)
        return $all
    }

    try {
        # ── Managed device overview ────────────────────────────────────────────
        try {
            $overview = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDeviceOverview' `
                -ErrorAction Stop
            $result.Data['ManagedDeviceOverview'] = $overview
        } catch {
            $result.Exceptions += "DeviceOverview: $($_.Exception.Message)"
            $result.Data['ManagedDeviceOverview'] = $null
        }

        # ── Device compliance policies ─────────────────────────────────────────
        try {
            $policies = @(GraphGet 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies')
            # Expand settings for each policy
            $expanded = @()
            foreach ($p in $policies) {
                try {
                    $detail = Invoke-MgGraphRequest -Method GET `
                        -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$($p.id)" `
                        -ErrorAction Stop
                    $expanded += $detail
                } catch {
                    $expanded += $p
                }
            }
            $result.Data['CompliancePolicies'] = $expanded
        } catch {
            $result.Exceptions += "CompliancePolicies: $($_.Exception.Message)"
            $result.Data['CompliancePolicies'] = @()
        }

        # ── Enrollment configurations ──────────────────────────────────────────
        try {
            $enroll = @(GraphGet 'https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations')
            $result.Data['EnrollmentConfigs'] = $enroll
        } catch {
            $result.Exceptions += "EnrollmentConfigs: $($_.Exception.Message)"
            $result.Data['EnrollmentConfigs'] = @()
        }

        # ── Mobile Threat Defense connectors ──────────────────────────────────
        try {
            $mtd = @(GraphGet 'https://graph.microsoft.com/v1.0/deviceManagement/mobileThreatDefenseConnectors')
            $result.Data['MtdConnectors'] = $mtd
        } catch {
            $result.Exceptions += "MtdConnectors: $($_.Exception.Message)"
            $result.Data['MtdConnectors'] = @()
        }

        # ── App protection (MAM) policies ──────────────────────────────────────
        try {
            $mam = @(GraphGet 'https://graph.microsoft.com/v1.0/deviceAppManagement/managedAppPolicies')
            $result.Data['AppProtectionPolicies'] = $mam
        } catch {
            $result.Exceptions += "AppProtectionPolicies: $($_.Exception.Message)"
            $result.Data['AppProtectionPolicies'] = @()
        }

        # ── Device configurations ──────────────────────────────────────────────
        try {
            $devCfg = @(GraphGet 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations')
            $result.Data['DeviceConfigurations'] = $devCfg
        } catch {
            $result.Exceptions += "DeviceConfigurations: $($_.Exception.Message)"
            $result.Data['DeviceConfigurations'] = @()
        }

        $result.Success = $true

    } catch {
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'Invoke-NRGCollectIntune' -Message $_.Exception.Message
    }

    Set-NRGRawData -Key 'Intune' -Data $result
    return $result
}

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
        # v4.6.4 EMERGENCY FIX (Critical #3): added @odata.nextLink pagination.
        # Previously truncated to first 100 policies on enterprise tenants.
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies'
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($p in @($page.value)) {
                    $result.Data.CompliancePolicies += @{
                        Id          = $p.id
                        DisplayName = [string]$p.displayName
                        Platform    = [string]$p['@odata.type']
                        Description = [string]$p.description
                        Version     = $p.version
                        # Pull through fields the evaluator looks at; not all platforms expose them
                        BitLockerEnabled        = $p.bitLockerEnabled
                        SecureBootEnabled       = $p.secureBootEnabled
                        PasswordRequired        = $p.passwordRequired
                        StorageRequireEncryption= $p.storageRequireEncryption
                    }
                }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Intune-DeviceCompliance-Policies' `
                        -Message "Pagination cap reached ($maxPages pages); compliance policy list may be truncated."
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-DeviceCompliance-Policies' -Message $_.Exception.Message
            }
        }

        # ── Device configuration profiles (legacy + Update for Business) ─────
        # v4.6.4 EMERGENCY FIX (Critical #3): paginated.
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations'
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($p in @($page.value)) {
                    $odata = [string]$p['@odata.type']
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
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Intune-DeviceCompliance-Config' `
                        -Message "Pagination cap reached ($maxPages pages); configuration profile list may be truncated."
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-DeviceCompliance-Config' -Message $_.Exception.Message
            }
        }

        # ── Enrollment configurations (WHfB, platform restrictions, limits) ──
        # v4.6.4 EMERGENCY FIX (Critical #3): paginated.
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations'
            $maxPages  = 200
            $pageCount = 0
            $enrollAll = @()
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $enrollAll += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Intune-DeviceCompliance-Enrollment' `
                        -Message "Pagination cap reached ($maxPages pages); enrollment configuration list may be truncated."
                }
            }
            foreach ($p in $enrollAll) {
                $odata = [string]$p['@odata.type']
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
            # Pagination cap (v4.6.3 P2): managed device count can run into
            # tens of thousands on large tenants. Cap at 200 pages (~200k
            # devices at default $top) and surface the cap as an exception.
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $devList += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Intune-DeviceCompliance' `
                        -Message "Pagination cap reached ($maxPages pages); managed device list may be truncated."
                }
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
    # v4.6.4 EMERGENCY FIX (Critical #3): added missing Register-NRGCoverage call
    # per CLAUDE.md collector contract.
    if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
        $status = if ($result.Success) { 'Collected' } else { 'Failed' }
        $note   = "CompPolicies=$($result.Data.CompliancePolicies.Count) Devices=$($result.Data.OSComplianceSummary.TotalCount)"
        Register-NRGCoverage -Family 'Intune-DeviceCompliance' -Status $status -Note $note
    }
}

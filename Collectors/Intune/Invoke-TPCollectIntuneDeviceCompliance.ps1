#Requires -Version 7.0
#
# Invoke-TPCollectIntuneDeviceCompliance.ps1
# Collects Intune device compliance, configuration, update rings, WHfB, enrollment
# restrictions, and OS compliance summary.
#
# READ-ONLY: GET-only Graph calls. Does not create, modify, or remove configuration.
#
# Returns: structured hashtable under key 'Intune-DeviceCompliance' via Set-TPRawData.
# Reads:   deviceCompliancePolicies, deviceConfigurations,
#          deviceEnrollmentConfigurations, managedDevices.
#
# NIST SP 800-53: CM-2 (baseline configuration), CM-6 (configuration settings),
#                 CM-8 (component inventory), SI-2 (flaw remediation),
#                 IA-2 (identification and authentication — WHfB)
# MITRE ATT&CK:   T1078 (Valid Accounts), T1133 (External Remote Services)
#

function Invoke-TPCollectIntuneDeviceCompliance {
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
            # Empty is not clean. Every section above initializes to @(), so an
            # empty list is ambiguous — "queried, this tenant has none"
            # (compliant) or "the query failed" (unknown). Success cannot tell
            # them apart because it reports on the collector, not the query.
            # Each sub-query flips its own sections to 'Failed' in its catch,
            # and evaluators read this through Test-TPSectionCollected before
            # concluding anything from an empty list.
            SectionStatus          = @{
                CompliancePolicies     = 'Collected'
                ConfigurationProfiles  = 'Collected'
                UpdatePolicies         = 'Collected'
                WindowsHelloPolicies   = 'Collected'
                EnrollmentRestrictions = 'Collected'
                EnrollmentConfig       = 'Collected'
                OSComplianceSummary    = 'Collected'
            }
        }
    }

    try {
        # ── Device compliance policies ───────────────────────────────────────
        # v4.6.4 EMERGENCY FIX (Critical #3): added @odata.nextLink pagination.
        # Previously truncated to first 100 policies on enterprise tenants.
        try {
            # $expand=assignments: an unassigned policy evaluates no device, so
            # "a policy exists" is not "devices are held to it".
            $next = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$expand=assignments'
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($p in @($page.value)) {
                    $result.Data.CompliancePolicies += @{
                        Id          = (Get-TPObjectField -Item $p -Key 'id' -Default $null)
                        DisplayName = [string](Get-TPObjectField -Item $p -Key 'displayName' -Default '')
                        Platform    = [string](Get-TPObjectField -Item $p -Key '@odata.type' -Default '')
                        Description = [string](Get-TPObjectField -Item $p -Key 'description' -Default '')
                        Version     = (Get-TPObjectField -Item $p -Key 'version' -Default $null)
                        # Pull through fields the evaluator looks at; not all platforms expose
                        # them (deviceCompliancePolicies is polymorphic — a bare dot-read of a
                        # Windows-only key throws under StrictMode on an iOS/Android/macOS row),
                        # so read each through Get-TPObjectField and default to $null.
                        BitLockerEnabled        = Get-TPObjectField -Item $p -Key 'bitLockerEnabled' -Default $null
                        SecureBootEnabled       = Get-TPObjectField -Item $p -Key 'secureBootEnabled' -Default $null
                        PasswordRequired        = Get-TPObjectField -Item $p -Key 'passwordRequired' -Default $null
                        StorageRequireEncryption= Get-TPObjectField -Item $p -Key 'storageRequireEncryption' -Default $null
                        # iOS names the lock requirement passcodeRequired, not passwordRequired.
                        PasscodeRequired        = Get-TPObjectField -Item $p -Key 'passcodeRequired' -Default $null
                        OsMinimumVersion        = [string](Get-TPObjectField -Item $p -Key 'osMinimumVersion' -Default '')
                        IsAssigned              = $(if ($null -ne (Get-TPObjectField -Item $p -Key 'assignments' -Default $null)) { @(Get-TPObjectField -Item $p -Key 'assignments' -Default @() | Where-Object { $_ }).Count -gt 0 } else { $null })
                    }
                }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'Intune-DeviceCompliance-Policies' `
                        -Message "Pagination cap reached ($maxPages pages); compliance policy list may be truncated."
                }
            }
        } catch {
            $result.Data.SectionStatus['CompliancePolicies'] = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Intune-DeviceCompliance-Policies' -Message $_.Exception.Message
            }
        }

        # ── Device configuration profiles (legacy + Update for Business) ─────
        # v4.6.4 EMERGENCY FIX (Critical #3): paginated.
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$expand=assignments'
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($p in @($page.value)) {
                    $odata = [string](Get-TPObjectField -Item $p -Key '@odata.type' -Default '')
                    $asg = Get-TPObjectField -Item $p -Key 'assignments' -Default $null
                    $entry = @{
                        Id          = (Get-TPObjectField -Item $p -Key 'id' -Default $null)
                        DisplayName = [string](Get-TPObjectField -Item $p -Key 'displayName' -Default '')
                        Platform    = $odata
                        Description = [string](Get-TPObjectField -Item $p -Key 'description' -Default '')
                        IsAssigned  = $(if ($null -ne $asg) { @($asg | Where-Object { $_ }).Count -gt 0 } else { $null })
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
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'Intune-DeviceCompliance-Config' `
                        -Message "Pagination cap reached ($maxPages pages); configuration profile list may be truncated."
                }
            }
        } catch {
            $result.Data.SectionStatus['ConfigurationProfiles'] = 'Failed'
            $result.Data.SectionStatus['UpdatePolicies'] = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Intune-DeviceCompliance-Config' -Message $_.Exception.Message
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
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $enrollAll += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'Intune-DeviceCompliance-Enrollment' `
                        -Message "Pagination cap reached ($maxPages pages); enrollment configuration list may be truncated."
                }
            }
            foreach ($p in $enrollAll) {
                $odata = [string](Get-TPObjectField -Item $p -Key '@odata.type' -Default '')
                # The four configurations every tenant has (priority 0, id
                # ending _Default...) are Microsoft's defaults — present on a
                # tenant nobody configured. What a restriction does lives in
                # its per-platform blocks.
                $id = [string](Get-TPObjectField -Item $p -Key 'id' -Default '')
                $prio = Get-TPObjectField -Item $p -Key 'priority' -Default $null
                $blocks = @()
                foreach ($plat in @('windows','windowsHome','windowsMobile','ios','android','androidForWork','mac','macOS')) {
                    $r = Get-TPObjectField -Item $p -Key "${plat}Restriction" -Default $null
                    if ($r) { $blocks += @{ Platform = $plat; PlatformBlocked = [bool](Get-TPObjectField -Item $r -Key 'platformBlocked' -Default $false); PersonalBlocked = [bool](Get-TPObjectField -Item $r -Key 'personalDeviceEnrollmentBlocked' -Default $false); OsMinimumVersion = [string](Get-TPObjectField -Item $r -Key 'osMinimumVersion' -Default '') } }
                }
                $single = Get-TPObjectField -Item $p -Key 'platformRestriction' -Default $null
                if ($single) { $blocks += @{ Platform = [string](Get-TPObjectField -Item $p -Key 'platformType' -Default ''); PlatformBlocked = [bool](Get-TPObjectField -Item $single -Key 'platformBlocked' -Default $false); PersonalBlocked = [bool](Get-TPObjectField -Item $single -Key 'personalDeviceEnrollmentBlocked' -Default $false); OsMinimumVersion = [string](Get-TPObjectField -Item $single -Key 'osMinimumVersion' -Default '') } }
                $entry = @{
                    Id          = $id
                    DisplayName = [string](Get-TPObjectField -Item $p -Key 'displayName' -Default '')
                    Type        = $odata
                    Priority    = $prio
                    IsDefault   = ($id -match '_Default' -or "$prio" -eq '0')
                    Limit       = Get-TPObjectField -Item $p -Key 'limit' -Default $null
                    Restrictions = @($blocks)
                }
                $result.Data.EnrollmentConfig += $entry

                if ($odata -match 'WindowsHelloForBusinessConfiguration') {
                    $result.Data.WindowsHelloPolicies += @{
                        Id                          = $id
                        DisplayName                 = [string](Get-TPObjectField -Item $p -Key 'displayName' -Default '')
                        State                       = [string](Get-TPObjectField -Item $p -Key 'state' -Default '')
                        SecurityDeviceRequired      = Get-TPObjectField -Item $p -Key 'securityDeviceRequired' -Default $null
                        UnlockWithBiometricsEnabled = Get-TPObjectField -Item $p -Key 'unlockWithBiometricsEnabled' -Default $null
                        PinMinimumLength            = Get-TPObjectField -Item $p -Key 'pinMinimumLength' -Default $null
                        PinMaximumLength            = Get-TPObjectField -Item $p -Key 'pinMaximumLength' -Default $null
                        PinExpirationInDays         = Get-TPObjectField -Item $p -Key 'pinExpirationInDays' -Default $null
                        PinPreviousBlockCount       = Get-TPObjectField -Item $p -Key 'pinPreviousBlockCount' -Default $null
                        EnhancedBiometricsState     = [string](Get-TPObjectField -Item $p -Key 'enhancedBiometricsState' -Default '')
                        Priority                    = $prio
                    }
                } elseif ($odata -match 'Limit|PlatformRestriction|EnrollmentRestriction|DeviceEnrollmentConfiguration$') {
                    $result.Data.EnrollmentRestrictions += $entry
                }
            }
        } catch {
            $result.Data.SectionStatus['EnrollmentConfig'] = 'Failed'
            $result.Data.SectionStatus['WindowsHelloPolicies'] = 'Failed'
            $result.Data.SectionStatus['EnrollmentRestrictions'] = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Intune-DeviceCompliance-Enrollment' -Message $_.Exception.Message
            }
        }

        # ── Managed devices → OS compliance summary ──────────────────────────
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,complianceState'
            $devList = @()
            # Pagination cap (v4.6.3 P2): managed device count can run into
            # tens of thousands on large tenants. Cap at 200 pages (~200k
            # devices at default $top) and surface the cap as an exception.
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $devList += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'Intune-DeviceCompliance' `
                        -Message "Pagination cap reached ($maxPages pages); managed device list may be truncated."
                }
            }
            $result.Data.OSComplianceSummary.TotalCount        = $devList.Count
            # complianceState is the device's OVERALL state against every rule
            # of its compliance policies — not an OS-version verdict.
            $result.Data.OSComplianceSummary.CompliantCount    = @($devList | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'complianceState' -Default '') -eq 'compliant' }).Count
            $result.Data.OSComplianceSummary.NonCompliantCount = @($devList | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'complianceState' -Default '') -ne 'compliant' }).Count
            $byPlatform = @{}
            foreach ($d in $devList) {
                $os = [string](Get-TPObjectField -Item $d -Key 'operatingSystem' -Default '')
                $p = if ($os) { $os } else { 'Unknown' }
                if (-not $byPlatform.ContainsKey($p)) { $byPlatform[$p] = 0 }
                $byPlatform[$p]++
            }
            $result.Data.OSComplianceSummary.ByPlatform = $byPlatform
            # The Windows devices by name, so endpoint results can be matched to the
            # managed inventory by identity, not by count alone.
            # Blank names are kept, not dropped: the evaluator must see a managed
            # device with no usable name to know it cannot be matched.
            $winNames = @($devList | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'operatingSystem' -Default '') -like 'Windows*' } |
                ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'deviceName' -Default '') })
            $result.Data.OSComplianceSummary.WindowsDeviceNames = $winNames
        } catch {
            $result.Data.SectionStatus['OSComplianceSummary'] = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Intune-DeviceCompliance-Devices' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'Intune-DeviceCompliance-Collector' -Message $_.Exception.Message
        }
    }

    Set-TPRawData -Key 'Intune-DeviceCompliance' -Data $result
    # v4.6.4 EMERGENCY FIX (Critical #3): added missing Register-TPCoverage call
    # per CLAUDE.md collector contract.
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        $status = if ($result.Success) { 'Collected' } else { 'Failed' }
        $note   = "CompPolicies=$($result.Data.CompliancePolicies.Count) Devices=$($result.Data.OSComplianceSummary.TotalCount)"
        Register-TPCoverage -Family 'Intune-DeviceCompliance' -Status $status -Note $note
    }
}

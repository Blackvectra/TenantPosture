#Requires -Version 7.0
#
# Invoke-TPCollectIntuneDeviceCompliance.ps1
# Collects Intune device compliance, configuration, update rings, WHfB, enrollment
# restrictions, and OS compliance summary.
#
# READ-ONLY: GET-only Graph calls. Does not create, modify, or remove configuration.
#
# Returns: structured hashtable under key 'Intune-DeviceCompliance' via Set-TPRawData.
# Reads:   deviceCompliancePolicies (with assignments and scheduledActionsForRule), deviceConfigurations,
#          deviceEnrollmentConfigurations, managedDevices; beta deviceEnrollmentConfigurations
#          for the priority-0 default platform restriction (DefaultPlatformRestriction, INT-3.1),
#          because v1.0 does not return its Android Enterprise work profile row.
#          Scope: DeviceManagementServiceConfig.Read.All (already requested).
#
# NIST SP 800-53: CM-2 (baseline configuration), CM-6 (configuration settings),
#                 CM-8 (component inventory), SI-2 (flaw remediation),
#                 IA-2 (identification and authentication — WHfB)
# MITRE ATT&CK:   T1078 (Valid Accounts), T1133 (External Remote Services)
#

# The non-compliance actions of one compliance policy as Graph returns them:
# scheduledActionsForRule[].scheduledActionConfigurations[], each with an actionType
# (block = Intune's "mark device noncompliant", retire, wipe, remoteLock,
# removeResourceAccessProfiles, pushNotification, notification, noAction), a
# gracePeriodHours and a notification template. Read is $true only when the policy
# carries the scheduledActionsForRule property at all: an absent property means the
# expand was not applied, which is "not read", never "no action".
function Get-TPComplianceActionList {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [AllowNull()] $Policy)
    $present = $false
    if ($Policy -is [System.Collections.IDictionary]) { $present = $Policy.Contains('scheduledActionsForRule') }
    elseif ($null -ne $Policy) { $present = $null -ne $Policy.PSObject.Properties['scheduledActionsForRule'] }
    if (-not $present) { return @{ Read = $false; Actions = @() } }
    $list = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($rule in @(Get-TPObjectField -Item $Policy -Key 'scheduledActionsForRule' -Default @())) {
        if ($null -eq $rule) { continue }
        foreach ($cfg in @(Get-TPObjectField -Item $rule -Key 'scheduledActionConfigurations' -Default @())) {
            if ($null -eq $cfg) { continue }
            $list.Add(@{
                RuleName               = [string](Get-TPObjectField -Item $rule -Key 'ruleName' -Default '')
                ActionType             = [string](Get-TPObjectField -Item $cfg -Key 'actionType' -Default '')
                GracePeriodHours       = (Get-TPObjectField -Item $cfg -Key 'gracePeriodHours' -Default $null)
                NotificationTemplateId = [string](Get-TPObjectField -Item $cfg -Key 'notificationTemplateId' -Default '')
            })
        }
    }
    return @{ Read = $true; Actions = @($list.ToArray()) }
}

# Whether a policy read with $expand=assignments is assigned: $true / $false from the
# expanded list, $null when the list was not returned. The list is read off the object
# directly, because Get-TPObjectField hands an empty array back as $null, which made a
# policy with no assignment "not read" and so counted as assigned. Shared by the
# Intune collectors (the endpoint-security collector calls it as -Item).
function Get-TPExpandedAssignmentState {
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)] [Alias('Item')] [AllowNull()] $Policy)
    if ($null -eq $Policy) { return $null }
    if ($Policy -is [System.Collections.IDictionary]) {
        if (-not $Policy.Contains('assignments')) { return $null }
        $list = $Policy['assignments']
    } else {
        $prop = $Policy.PSObject.Properties['assignments']
        if ($null -eq $prop) { return $null }
        $list = $prop.Value
    }
    if ($null -eq $list) { return $null }
    return (@($list | Where-Object { $_ }).Count -gt 0)
}

# The five Windows Update for Business values INT-2.5 judges, read off one update ring
# (Graph windowsUpdateForBusinessConfiguration) as Graph returned them. Only properties
# PRESENT on the object are copied: an absent property is "not returned" (a value not
# read), which the evaluator keeps apart from a property returned empty ("not set").
#   automaticUpdateMode                    -> Update/AllowAutoUpdate
#   featureUpdatesDeferralPeriodInDays     -> Update/DeferFeatureUpdatesPeriodInDays
#   businessReadyUpdatesOnly               -> Update/BranchReadinessLevel (pre-release channel)
#   installationSchedule.scheduledInstallDay -> Update/ScheduledInstallDay
#   userPauseAccess                        -> Update/SetDisablePauseUXAccess
function Get-TPWufbRingSettings {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [AllowNull()] $Ring)
    $out = [ordered]@{}
    if ($null -eq $Ring) { return $out }
    $has = {
        param($o, [string] $k)
        if ($o -is [System.Collections.IDictionary]) { return $o.Contains($k) }
        return ($null -ne $o -and $null -ne $o.PSObject.Properties[$k])
    }
    foreach ($pair in @(@('automaticUpdateMode', 'AutomaticUpdateMode'), @('featureUpdatesDeferralPeriodInDays', 'FeatureUpdatesDeferralPeriodInDays'),
                         @('businessReadyUpdatesOnly', 'BusinessReadyUpdatesOnly'), @('userPauseAccess', 'UserPauseAccess'))) {
        if (& $has $Ring $pair[0]) { $out[$pair[1]] = Get-TPObjectField -Item $Ring -Key $pair[0] -Default $null }
    }
    if (& $has $Ring 'installationSchedule') {
        $sch = Get-TPObjectField -Item $Ring -Key 'installationSchedule' -Default $null
        $out['InstallationSchedule'] = if ($null -eq $sch) { $null } else {
            [ordered]@{
                Type                = [string](Get-TPObjectField -Item $sch -Key '@odata.type' -Default '')
                ScheduledInstallDay = $(if (& $has $sch 'scheduledInstallDay') { Get-TPObjectField -Item $sch -Key 'scheduledInstallDay' -Default $null } else { $null })
            }
        }
    }
    return $out
}

# The priority-0 default device platform restriction ("All users and all devices",
# id ending _DefaultPlatformRestrictions) as the beta deviceEnrollmentConfigurations
# list returns it, reduced to the five platforms CIS Microsoft 365 Foundations
# v7.0.0 4.2 audits. Graph v1.0 omits androidForWorkRestriction, which is why this
# row is read from beta. Each platform keeps whether its restriction object was
# returned and each flag only when Graph returned a boolean ($null = not read).
function Get-TPDefaultPlatformRestriction {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Configurations)
    $def = @($Configurations | Where-Object {
        $null -ne $_ -and
        [string](Get-TPObjectField -Item $_ -Key 'id' -Default '') -match '_DefaultPlatformRestrictions$' -and
        "$(Get-TPObjectField -Item $_ -Key 'priority' -Default '')" -eq '0' })
    if ($def.Count -ne 1) { return @{ Found = $false; Count = $def.Count; Id = ''; Platforms = [ordered]@{} } }
    $d = $def[0]
    $flag = { param($o, [string] $k) $v = Get-TPObjectField -Item $o -Key $k -Default $null; if ($v -is [bool]) { $v } else { $null } }
    $platforms = [ordered]@{}
    foreach ($pair in @(@('Windows', 'windowsRestriction'), @('iOS/iPadOS', 'iosRestriction'), @('macOS', 'macOSRestriction'),
                         @('Android Enterprise (work profile)', 'androidForWorkRestriction'), @('Android device administrator', 'androidRestriction'))) {
        $r = Get-TPObjectField -Item $d -Key $pair[1] -Default $null
        $platforms[$pair[0]] = @{
            Property        = $pair[1]
            Returned        = ($null -ne $r)
            PlatformBlocked = $(if ($null -ne $r) { & $flag $r 'platformBlocked' } else { $null })
            PersonalBlocked = $(if ($null -ne $r) { & $flag $r 'personalDeviceEnrollmentBlocked' } else { $null })
        }
    }
    return @{ Found = $true; Count = 1; Id = [string](Get-TPObjectField -Item $d -Key 'id' -Default ''); Platforms = $platforms }
}

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
            DefaultPlatformRestriction = $null
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
                DefaultPlatformRestriction = 'NotRun'
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
            # scheduledActionsForRule: what the policy does to a noncompliant device
            # (mark noncompliant after a grace period, retire, wipe, lock, notify).
            # INT-1.1 is half a verdict without it. Should a tenant's Graph refuse the
            # nested expand, the plain read is kept and every policy is recorded with
            # ActionsRead = $false, so the control says "not read", never "no action".
            $plainUri   = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$expand=assignments'
            $actionsUri = $plainUri + ',scheduledActionsForRule($expand=scheduledActionConfigurations)'
            $next = $actionsUri
            $actionsExpanded = $true
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                try {
                    $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                } catch {
                    if ($pageCount -eq 0 -and $actionsExpanded) {
                        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                            Register-TPException -Source 'Intune-DeviceCompliance-Actions' `
                                -Message "The non-compliance actions could not be read with the policies (scheduledActionsForRule expand refused: $($_.Exception.Message)); policies were read without them."
                        }
                        $actionsExpanded = $false
                        $next = $plainUri
                        continue
                    }
                    throw
                }
                foreach ($p in @($page.value)) {
                    $acts = Get-TPComplianceActionList -Policy $p
                    $result.Data.CompliancePolicies += @{
                        # The non-compliance actions as Graph returned them, and whether they were
                        # read at all (an absent property is not an empty action list).
                        ActionsRead          = ($actionsExpanded -and $acts.Read)
                        NonComplianceActions = $acts.Actions
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
                    $entry = @{
                        Id          = (Get-TPObjectField -Item $p -Key 'id' -Default $null)
                        DisplayName = [string](Get-TPObjectField -Item $p -Key 'displayName' -Default '')
                        Platform    = $odata
                        Description = [string](Get-TPObjectField -Item $p -Key 'description' -Default '')
                        IsAssigned  = Get-TPExpandedAssignmentState -Policy $p
                    }
                    $result.Data.ConfigurationProfiles += $entry

                    # Windows Update for Business rings live in deviceConfigurations. The list
                    # returns each derived type's own properties, so the ring's values ride the
                    # same request (no per-ring read). A ring entry is its own copy: the values
                    # are INT-2.5's, not part of the generic configuration profile list.
                    if ($odata -match 'windowsUpdateForBusinessConfiguration') {
                        $ring = $entry.Clone()
                        $ring.WufbSettings = Get-TPWufbRingSettings -Ring $p
                        $result.Data.UpdatePolicies += $ring
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

        # ── Default platform restriction (beta: INT-3.1, CIS 4.2) ───────────
        # Read separately so a refused beta read leaves only this section unread.
        try {
            $betaRows = @(Get-TPGraphAllPages -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations')
            $result.Data.DefaultPlatformRestriction = Get-TPDefaultPlatformRestriction -Configurations $betaRows
            $result.Data.SectionStatus['DefaultPlatformRestriction'] = 'Collected'
        } catch {
            $result.Data.SectionStatus['DefaultPlatformRestriction'] = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Intune-DeviceCompliance-DefaultPlatformRestriction' -Message $_.Exception.Message
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

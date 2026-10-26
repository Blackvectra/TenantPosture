#Requires -Version 7.0
#
# TP.IntuneTruth.Tests.ps1
# NRG Technology Services / NextLayerSec LLC — Author: Matthew Levorson
# Pins the Intune verdicts to what each Graph object means, driving the REAL
# collectors with raw Graph shapes (Invoke-TPGraphRequest injected into
# module scope). Every case produced a wrong verdict before this change.
#
# Data keys: Intune-DeviceCompliance, Intune-EndpointSecurity,
#            Intune-AppProtection, AAD-CAPolicies.
#

Describe 'Intune controls count what enforces something' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        & $script:Mod { Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value {
            param([string] $Uri, [string] $Method = 'GET', $Headers, $Body, [string] $OutputType = 'HashTable')
            $script:SeenUris += @($Uri)
            # A tenant whose Graph refuses the nested expand answers 400; the collector must keep the plain read.
            if ($script:RefuseActions -and $Uri -match 'scheduledActionsForRule') { throw 'Request_BadRequest: the expand is not supported' }
            if ($script:FailSettings -and $Uri -match '/settings') { throw 'Request_Forbidden' }
            foreach ($k in $script:Graph.Keys) { if ($Uri -match $k) { return @{ value = @($script:Graph[$k]) } } }
            return @{ value = @() }
        } }
        & $script:Mod { $script:SeenUris = @(); $script:RefuseActions = $false; $script:FailSettings = $false }
        $script:Tid = '00000000-1111-2222-3333-444444444444'
        # The four enrollment configurations every tenant has.
        $script:Defaults = @(
            @{ '@odata.type' = '#microsoft.graph.deviceEnrollmentLimitConfiguration'; id = "$($script:Tid)_DefaultLimit"; displayName = 'All users and all devices'; priority = 0; limit = 15 },
            @{ '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; id = "$($script:Tid)_DefaultPlatformRestrictions"; displayName = 'All users and all devices'; priority = 0
               windowsRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $false }; iosRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $false } },
            @{ '@odata.type' = '#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration'; id = "$($script:Tid)_DefaultWindowsHelloForBusiness"; displayName = 'All users and all devices'; priority = 0; state = 'notConfigured' })
        function script:Run { param([hashtable] $Graph)
            Clear-TPState
            & $script:Mod { param($g) $script:Graph = $g; $script:SeenUris = @() } $Graph
            Invoke-TPCollectIntuneDeviceCompliance | Out-Null
            Invoke-TPCollectIntuneEndpointSecurity | Out-Null
            Invoke-TPCollectIntuneAppProtection | Out-Null
        }
        function script:Verdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
        $script:Assigned = @(@{ id = 'a1'; target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
        # A Settings Catalog choice setting as Graph returns it from configurationPolicies/{id}/settings.
        function script:Setting { param([string] $DefinitionId, [string] $Value)
            @{ id = '0'; settingInstance = @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = $DefinitionId; choiceSettingValue = @{ value = $Value; children = @() } } } }
    }
    AfterAll { & $script:Mod { Remove-Item -Path 'function:script:Invoke-TPGraphRequest' -ErrorAction SilentlyContinue }; Clear-TPState }

    It 'INT-1.2 reads Conditional Access, not "a configuration profile exists" (a Wi-Fi profile passed)' {
        Run @{ 'deviceConfigurations' = @(@{ '@odata.type' = '#microsoft.graph.windowsWifiConfiguration'; id = 'd1'; displayName = 'Office Wi-Fi'; assignments = $script:Assigned }) }
        Set-TPRawData -Key 'AAD-CAPolicies' -Data @{ Success = $true; Data = @{ Policies = @() } }
        (Verdict 'Test-TPControlIntune' 'INT-1.2').State | Should -Be 'Gap'
        Clear-TPState
        Set-TPRawData -Key 'Intune-DeviceCompliance' -Data @{ Success = $true; Data = @{ CompliancePolicies = @() } }
        Set-TPRawData -Key 'AAD-CAPolicies' -Data @{ Success = $true; Data = @{ Policies = @(@{ DisplayName = 'Require compliant device'; State = 'enabled'
            Conditions = @{ Users = @{ IncludeUsers = @('All') }; Applications = @{ Include = @('All') } }; GrantControls = @{ Operator = 'OR'; BuiltInControls = @('compliantDevice') } }) } }
        (Verdict 'Test-TPControlIntune' 'INT-1.2').State | Should -Be 'Satisfied'
    }
    It 'INT-1.4 does not count an app CONFIGURATION policy as app protection' {
        Run @{ 'managedAppPolicies' = @(@{ '@odata.type' = '#microsoft.graph.targetedManagedAppConfiguration'; id = 'a1'; displayName = 'Outlook settings' }) }
        (Verdict 'Test-TPControlIntune' 'INT-1.4').State | Should -Be 'Gap'
    }
    It 'INT-3.1: Intune''s default enrollment configurations are not restrictions' {
        Run @{ 'deviceEnrollmentConfigurations' = $script:Defaults }
        (Verdict 'Test-TPControlIntuneEnrollmentRestrictions' 'INT-3.1').State | Should -Be 'Gap'
        $d = $script:Defaults.Clone(); $d[1] = $d[1].Clone(); $d[1].windowsRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $true }
        Run @{ 'deviceEnrollmentConfigurations' = $d }
        (Verdict 'Test-TPControlIntuneEnrollmentRestrictions' 'INT-3.1').State | Should -Be 'Satisfied'
    }
    It 'INT-4.2 reads the WHfB state, not the presence of the default configuration, and a disabled tenant-wide policy is not assessed, never a Gap' {
        # Microsoft: the tenant-wide policy "is usually disabled and Windows Hello for Business is
        # enabled using a policy targeted to a security group", which the collectors do not read.
        Run @{ 'deviceEnrollmentConfigurations' = $script:Defaults }
        $f = Verdict 'Test-TPControlIntuneWindowsHello' 'INT-4.2'
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'Account protection'
        $f.Detail | Should -Match 'not assessed'
        @($f.FrameworkIds).Count | Should -BeGreaterThan 0
    }
    It 'unassigned drafts and same-family templates are not LAPS / ASR' {
        Run @{
            'configurationPolicies' = @(
                @{ id = 'p1'; name = 'Credential Guard'; templateReference = @{ templateFamily = 'endpointSecurityAccountProtection'; templateDisplayName = 'Account Protection' }; assignments = $script:Assigned },
                @{ id = 'p2'; name = 'Block USB'; templateReference = @{ templateFamily = 'endpointSecurityAttackSurfaceReduction'; templateDisplayName = 'Device Control' }; assignments = $script:Assigned })
            'intents' = @(@{ id = 'i1'; displayName = 'Windows LAPS'; isAssigned = $false }, @{ id = 'i2'; displayName = 'ASR rules'; isAssigned = $false })
        }
        (Verdict 'Test-TPControlIntuneWindowsLAPS' 'INT-4.1').State | Should -Be 'Gap'
        (Verdict 'Test-TPControlIntuneASR' 'INT-2.2').State | Should -Be 'Gap'
        Run @{ 'configurationPolicies\?' = @(@{ id = 'p3'; name = 'LAPS'; templateReference = @{ templateFamily = 'endpointSecurityAccountProtection'; templateDisplayName = 'Local admin password solution (Windows LAPS)' }; assignments = $script:Assigned })
               'configurationPolicies/p3/settings' = @(Setting 'device_vendor_msft_laps_policies_backupdirectory' 'device_vendor_msft_laps_policies_backupdirectory_1') }
        (Verdict 'Test-TPControlIntuneWindowsLAPS' 'INT-4.1').State | Should -Be 'Satisfied'
    }
    It 'INT-1.3 requires "Require BitLocker"; "Require encryption of data storage" alone is a Gap; INT-2.4 does not accept System Integrity Protection' {
        # Microsoft's Zero Trust Windows compliance settings list both rules; the second
        # alone never asks for BitLocker, and it passed this control.
        Run @{ 'deviceCompliancePolicies' = @(
            @{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'w'; displayName = 'Win'; storageRequireEncryption = $true; bitLockerEnabled = $false; assignments = $script:Assigned },
            @{ '@odata.type' = '#microsoft.graph.macOSCompliancePolicy'; id = 'm'; displayName = 'Mac'; systemIntegrityProtectionEnabled = $true; storageRequireEncryption = $false; assignments = $script:Assigned })
               'managedDevices' = @(@{ id = 'mac1'; operatingSystem = 'macOS'; complianceState = 'compliant' }) }
        $f = Verdict 'Test-TPControlIntune' 'INT-1.3'
        $f.State  | Should -Be 'Gap'
        $f.Detail | Should -Match 'require encryption of data storage on the device \(Win\), a different rule that is not counted'
        (Verdict 'Test-TPControlIntuneMacEncryption' 'INT-2.4').State | Should -Be 'Gap'
    }
    It 'INT-1.3 is Satisfied only when every assigned Windows policy requires BitLocker, Partial when some do' {
        $pol = { param($id, $bl) @{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = $id; displayName = $id; bitLockerEnabled = $bl; storageRequireEncryption = $false; assignments = $script:Assigned } }
        Run @{ 'deviceCompliancePolicies' = @((& $pol 'A' $true), (& $pol 'B' $true)) }
        $f = Verdict 'Test-TPControlIntune' 'INT-1.3'
        $f.State | Should -Be 'Satisfied'
        $f.Detail | Should -Match 'Every assigned Windows compliance policy \(2: A, B\) requires BitLocker'
        Run @{ 'deviceCompliancePolicies' = @((& $pol 'A' $true), (& $pol 'B' $false)) }
        $f = Verdict 'Test-TPControlIntune' 'INT-1.3'
        $f.State  | Should -Be 'Partial'
        $f.Detail | Should -Match 'Shortfall: 1 do not \(B\)'
    }
    It 'INT-1.3: a Windows policy whose bitLockerEnabled was not returned is not assessed, never credited' {
        # windows81CompliancePolicy has storageRequireEncryption and no Require BitLocker rule.
        Run @{ 'deviceCompliancePolicies' = @(
            @{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'w'; displayName = 'Win10'; bitLockerEnabled = $true; assignments = $script:Assigned },
            @{ '@odata.type' = '#microsoft.graph.windows81CompliancePolicy'; id = 'w81'; displayName = 'Win81'; storageRequireEncryption = $true; assignments = $script:Assigned }) }
        $f = Verdict 'Test-TPControlIntune' 'INT-1.3'
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'Not assessed: whether Win81 require BitLocker'
        @($f.FrameworkIds).Count | Should -BeGreaterThan 0
    }
    Context 'INT-2.3 reads each Windows Firewall network profile from the assigned policy''s settings' {
        BeforeAll {
            $script:FwList = @(@{ id = 'fw1'; name = 'Firewall baseline'; templateReference = @{ templateFamily = 'endpointSecurityFirewall'; templateDisplayName = 'Windows Firewall' }; assignments = $script:Assigned })
            function script:FirewallVerdict { param([string] $Domain, [string] $Private, [string] $Public)
                $set = @()
                foreach ($pair in @(@('domain', $Domain), @('private', $Private), @('public', $Public))) {
                    if ($pair[1]) { $id = "vendor_msft_firewall_mdmstore_$($pair[0])profile_enablefirewall"; $set += Setting $id "${id}_$($pair[1])" }
                }
                # A Hyper-V firewall node shares the leaf name and must not count.
                $hv = 'vendor_msft_firewall_mdmstore_hypervvmsettings_{vmcreatorid}_publicprofile_enablefirewall'
                $set += Setting $hv "${hv}_true"
                Run @{ 'configurationPolicies\?' = $script:FwList; 'configurationPolicies/fw1/settings' = $set }
                Verdict 'Test-TPControlIntuneFirewall' 'INT-2.3'
            }
        }
        It 'all three profiles on is Satisfied, and the settings were read with no new scope' {
            $f = FirewallVerdict 'true' 'true' 'true'
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'The Domain profile firewall is turned on \(Firewall baseline\)'
            @(& $script:Mod { $script:SeenUris } | Where-Object { $_ -match 'configurationPolicies/fw1/settings' }).Count | Should -Be 1
            @(& $script:Mod { Get-TPGraphScopeList }) | Should -Contain 'DeviceManagementConfiguration.Read.All'
        }
        It 'a policy turning a profile off is a shortfall: Partial beside profiles turned on' {
            $f = FirewallVerdict 'true' 'true' 'false'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Shortfall: The Public profile firewall is turned off by Firewall baseline'
            $f.Detail | Should -Not -Match 'Public profile firewall is turned on' -Because 'the Hyper-V node is not the host profile'
        }
        It 'a profile no policy sets is a shortfall (Windows default on is not enforcement), and a policy setting nothing is a Gap' {
            (FirewallVerdict 'true' 'true' '').State | Should -Be 'Partial'
            $f = FirewallVerdict '' '' ''
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'No assigned policy turns on the Domain profile firewall'
        }
        It 'a policy whose settings were not read (legacy intents, an older results file) is not assessed, never Satisfied' {
            Run @{ 'intents' = @(@{ id = 'i1'; displayName = 'Windows Firewall'; isAssigned = $true }) }
            $f = Verdict 'Test-TPControlIntuneFirewall' 'INT-2.3'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Not assessed: .*settings of Windows Firewall were not read'
            Clear-TPState
            Set-TPRawData -Key 'Intune-EndpointSecurity' -Data ([pscustomobject]@{ Success = $true; Data = [pscustomobject]@{
                FirewallPolicies = @([pscustomobject]@{ Id = 'fw1'; DisplayName = 'Old'; IsAssigned = $true; TemplateType = 'Firewall' }) } })
            (Verdict 'Test-TPControlIntuneFirewall' 'INT-2.3').State | Should -Be 'NotApplicable'
        }
        It 'a failed settings read is recorded on the policy and leaves the profiles not assessed' {
            & $script:Mod { $script:FailSettings = $true }
            try {
                Run @{ 'configurationPolicies\?' = $script:FwList }
                @((Get-TPRawData -Key 'Intune-EndpointSecurity').Data.FirewallPolicies)[0].SettingsStatus | Should -Be 'Failed'
                (Verdict 'Test-TPControlIntuneFirewall' 'INT-2.3').State | Should -Be 'NotApplicable'
            } finally { & $script:Mod { $script:FailSettings = $false } }
        }
    }
    Context 'INT-4.1 credits only a LAPS policy that backs the password up to Microsoft Entra ID' {
        BeforeAll {
            function script:Laps { param([string[]] $Values)
                $list = @(); $graph = @{}
                for ($i = 0; $i -lt $Values.Count; $i++) {
                    $list += @{ id = "l$i"; name = "LAPS $i"; templateReference = @{ templateFamily = 'endpointSecurityAccountProtection'; templateDisplayName = 'Local admin password solution (Windows LAPS)' }; assignments = $script:Assigned }
                    $id = 'device_vendor_msft_laps_policies_backupdirectory'
                    $graph["configurationPolicies/l$i/settings"] = @(if ($Values[$i] -ne 'unset') { Setting $id "${id}_$($Values[$i])" })
                }
                $graph['configurationPolicies\?'] = $list
                Run $graph
                Verdict 'Test-TPControlIntuneWindowsLAPS' 'INT-4.1'
            }
        }
        It 'Backup Directory = Disabled is a Gap, not a deployed LAPS' {
            $f = Laps @('0')
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'Backup Directory to Disabled'
        }
        It 'Backup Directory not set is a Gap (Windows LAPS treats it as Disabled)' {
            (Laps @('unset')).State | Should -Be 'Gap'
        }
        It 'Active Directory backup is a shortfall; beside an Entra ID policy it is Partial' {
            (Laps @('2')).State | Should -Be 'Gap'
            $f = Laps @('1', '2')
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'LAPS 1 backs the password up to Active Directory'
        }
        It 'an unrecognized value or an unread policy is not assessed, never Satisfied' {
            (Laps @('7')).State | Should -Be 'NotApplicable'
            Run @{ 'intents' = @(@{ id = 'i1'; displayName = 'Windows LAPS'; isAssigned = $true }) }
            $f = Verdict 'Test-TPControlIntuneWindowsLAPS' 'INT-4.1'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'settings were not read'
        }
    }
    Context 'INT-2.5 judges every assigned update ring against the CIS Intune for Windows 11 v5.0.0 Windows Update for Business values' {
        BeforeAll {
            # An update ring as Graph returns it from deviceManagement/deviceConfigurations?$expand=assignments.
            function script:Ring { param([string] $Id = 'r1', [string] $Name = 'Ring A', [hashtable] $Override = @{}, [string[]] $Omit = @())
                $r = @{ '@odata.type' = '#microsoft.graph.windowsUpdateForBusinessConfiguration'; id = $Id; displayName = $Name; assignments = $script:Assigned
                    automaticUpdateMode = 'autoInstallAndRebootAtScheduledTime'; featureUpdatesDeferralPeriodInDays = 180; qualityUpdatesDeferralPeriodInDays = 0
                    businessReadyUpdatesOnly = 'all'; prereleaseFeatures = 'userDefined'; userPauseAccess = 'disabled'
                    installationSchedule = @{ '@odata.type' = '#microsoft.graph.windowsUpdateScheduledInstall'; scheduledInstallDay = 'everyday'; scheduledInstallTime = '03:00:00.0000000' } }
                foreach ($k in $Override.Keys) { $r[$k] = $Override[$k] }
                foreach ($k in $Omit) { $r.Remove($k) }
                $r
            }
            $script:Mpb = 'device_vendor_msft_policy_config_update_managepreviewbuilds'
            # A general Settings Catalog policy (template family none) setting Update CSP nodes.
            function script:WuVerdict { param([object[]] $Rings, [object[]] $CatalogSettings = @((Setting $script:Mpb "$($script:Mpb)_0")), [switch] $NoCatalog)
                $g = @{ 'deviceConfigurations' = @($Rings) }
                if (-not $NoCatalog) {
                    $g['configurationPolicies\?'] = @(@{ id = 'wu1'; name = 'WUfB catalog'; platforms = 'windows10'; templateReference = @{ templateFamily = 'none'; templateDisplayName = '' }; assignments = $script:Assigned })
                    $g['configurationPolicies/wu1/settings'] = @($CatalogSettings)
                }
                Run $g
                Verdict 'Test-TPControlIntuneWindowsUpdate' 'INT-2.5'
            }
        }
        It 'a ring meeting the four ring values, with Manage preview builds disabled in a Settings Catalog policy, is Satisfied; the ring values ride the list request' {
            $f = WuVerdict @(Ring)
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'Ring A meets CIS 104\.1 .*CIS 104\.2 \(feature updates deferred 180 days\).*CIS 104\.4 .*CIS 104\.5'
            $f.Detail | Should -Match 'CIS 104\.3 Manage preview builds is Disable preview builds \(WUfB catalog\)'
            @(& $script:Mod { $script:SeenUris } | Where-Object { $_ -match 'deviceConfigurations' }).Count | Should -Be 1 -Because 'no per-ring read'
            @(& $script:Mod { $script:SeenUris } | Where-Object { $_ -match 'configurationPolicies/wu1/settings' }).Count | Should -Be 1
            $ring = @((Get-TPRawData -Key 'Intune-DeviceCompliance').Data.UpdatePolicies)[0]
            $ring.WufbSettings.InstallationSchedule.ScheduledInstallDay | Should -Be 'everyday'
            @((Get-TPRawData -Key 'Intune-DeviceCompliance').Data.ConfigurationProfiles)[0].Keys | Should -Not -Contain 'WufbSettings'
        }
        It '104.2 boundary: 179 days is a shortfall, 180 and 365 are met' {
            $f = WuVerdict @(Ring -Override @{ featureUpdatesDeferralPeriodInDays = 179 })
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Shortfall: .*CIS 104\.2 Defer Feature Updates Period in Days: in Ring A feature updates deferred 179 days \(180 or more required\)'
            (WuVerdict @(Ring -Override @{ featureUpdatesDeferralPeriodInDays = 365 })).State | Should -Be 'Satisfied'
        }
        It '104.1: a ring left at the Windows default sets nothing (shortfall, the default is never credited); every documented mode is met' {
            foreach ($v in 'windowsDefault', 'userDefined') {
                $f = WuVerdict @(Ring -Override @{ automaticUpdateMode = $v })
                $f.State  | Should -Be 'Partial'
                $f.Detail | Should -Match "CIS 104\.1 Allow Auto Update: in Ring A automatic update behavior is not set \($v\)"
            }
            # Windows applies a scheduled day only to modes 3 and 4 (CIS 104.4's warning), so the
            # other modes meet 104.1 here and the schedule is judged on its own.
            foreach ($v in 'notifyDownload', 'autoInstallAtMaintenanceTime', 'autoInstallAndRebootAtMaintenanceTime', 'autoInstallAndRebootWithoutEndUserControl') {
                (WuVerdict @(Ring -Override @{ automaticUpdateMode = $v })).Detail | Should -Match 'Ring A meets CIS 104\.1'
            }
        }
        It '104.4: a weekday, an active-hours schedule or no schedule is a shortfall; only Every day is met' {
            $f = WuVerdict @(Ring -Override @{ installationSchedule = @{ '@odata.type' = '#microsoft.graph.windowsUpdateScheduledInstall'; scheduledInstallDay = 'tuesday'; scheduledInstallTime = '03:00:00' } })
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'scheduled install day is tuesday \(every day required\)'
            (WuVerdict @(Ring -Override @{ automaticUpdateMode = 'autoInstallAtMaintenanceTime'; installationSchedule = @{ '@odata.type' = '#microsoft.graph.windowsUpdateActiveHoursInstall'; activeHoursStart = '08:00:00'; activeHoursEnd = '17:00:00' } })).Detail |
                Should -Match 'installs around active hours, so no scheduled install day is set'
            (WuVerdict @(Ring -Override @{ installationSchedule = $null })).Detail | Should -Match 'no installation schedule is set'
        }
        It '104.5: users allowed to pause, or the option not configured, is a shortfall' {
            (WuVerdict @(Ring -Override @{ userPauseAccess = 'enabled' })).Detail | Should -Match 'CIS 104\.5 .*users may pause updates'
            $f = WuVerdict @(Ring -Override @{ userPauseAccess = 'notConfigured' })
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'option to pause updates is not configured'
        }
        It '104.3: a ring on a pre-release channel, or a catalog policy enabling preview builds, is a shortfall' {
            $f = WuVerdict @(Ring -Override @{ businessReadyUpdatesOnly = 'windowsInsiderBuildSlow' })
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'CIS 104\.3 Manage preview builds: in Ring A the ring enables pre-release builds \(Beta Channel\)'
            $f.Detail | Should -Not -Match 'is Disable preview builds'
            $f = WuVerdict @(Ring) -CatalogSettings @((Setting $script:Mpb "$($script:Mpb)_2"))
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'CIS 104\.3: WUfB catalog sets Manage preview builds to enable preview builds'
        }
        It 'a Settings Catalog policy turning automatic updates off or allowing pause defeats the ring: shortfall' {
            $aau = 'device_vendor_msft_policy_config_update_allowautoupdate'; $pause = 'device_vendor_msft_policy_config_update_setdisablepauseuxaccess'
            $f = WuVerdict @(Ring) -CatalogSettings @((Setting $script:Mpb "$($script:Mpb)_0"), (Setting $aau "${aau}_5"), (Setting $pause "${pause}_0"))
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'CIS 104\.1: WUfB catalog turns off automatic updates'
            $f.Detail | Should -Match 'CIS 104\.5: WUfB catalog lets users pause updates'
        }
        It 'Manage preview builds not established is not assessed, never Satisfied: no catalog policy, an unread one, or one that sets nothing' {
            $f = WuVerdict @(Ring) -NoCatalog
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'pages disagree on whether a ring writes that setting'
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0
            & $script:Mod { $script:FailSettings = $true }
            try {
                $f = WuVerdict @(Ring)
                $f.State  | Should -Be 'NotApplicable'
                $f.Detail | Should -Match 'the settings of WUfB catalog were not read'
                @((Get-TPRawData -Key 'Intune-EndpointSecurity').Data.UpdateSettingsPolicies)[0].SettingsStatus | Should -Be 'Failed'
            } finally { & $script:Mod { $script:FailSettings = $false } }
            # A catalog policy setting no Update node is not kept as an Update policy.
            $f = WuVerdict @(Ring) -CatalogSettings @((Setting 'device_vendor_msft_policy_config_browser_allowautofill' 'device_vendor_msft_policy_config_browser_allowautofill_0'))
            $f.State | Should -Be 'NotApplicable'
            @((Get-TPRawData -Key 'Intune-EndpointSecurity').Data.UpdateSettingsPolicies).Count | Should -Be 0
        }
        It 'every ring is judged: one ring falling short beside a compliant ring is Partial naming it; nothing met is a Gap' {
            $f = WuVerdict @((Ring), (Ring -Id 'r2' -Name 'Ring B' -Override @{ featureUpdatesDeferralPeriodInDays = 30 }))
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'in Ring B feature updates deferred 30 days'
            @($f.AffectedObjects | Where-Object { $_.Ring -eq 'Ring B' -and $_.Cis -eq '104.2' }).Count | Should -Be 1
            $bad = Ring -Override @{ automaticUpdateMode = 'windowsDefault'; featureUpdatesDeferralPeriodInDays = 0; userPauseAccess = 'enabled'; businessReadyUpdatesOnly = 'windowsInsiderBuildFast'
                installationSchedule = @{ '@odata.type' = '#microsoft.graph.windowsUpdateActiveHoursInstall'; activeHoursStart = '08:00:00'; activeHoursEnd = '17:00:00' } }
            $f = WuVerdict @($bad) -NoCatalog
            $f.State  | Should -Be 'Gap'
            $f.Severity | Should -Be 'High'
        }
        It 'no assigned ring is a Gap (unassigned rings are named, not counted)' {
            $r = Ring; $r.assignments = @()
            $f = WuVerdict @($r)
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match '1 unassigned ring\(s\) were not counted'
        }
        It 'a value Graph did not return, an unrecognized value, or a results file from before the read is not assessed, never Satisfied and never a Gap' {
            $f = WuVerdict @(Ring -Omit @('userPauseAccess'))
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'CIS 104\.5 .*userPauseAccess was not returned'
            (WuVerdict @(Ring -Override @{ featureUpdatesDeferralPeriodInDays = 'soon' })).State | Should -Be 'NotApplicable'
            (WuVerdict @(Ring -Override @{ userPauseAccess = 'sometimes' })).State | Should -Be 'NotApplicable'
            Clear-TPState
            Set-TPRawData -Key 'Intune-DeviceCompliance' -Data ([pscustomobject]@{ Success = $true; Data = [pscustomobject]@{
                UpdatePolicies = @([pscustomobject]@{ Id = 'r1'; DisplayName = 'Old ring'; Platform = '#microsoft.graph.windowsUpdateForBusinessConfiguration'; IsAssigned = $true }) } })
            $f = Verdict 'Test-TPControlIntuneWindowsUpdate' 'INT-2.5'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'settings were not read'
        }
        It 'a replayed results file (JSON round trip) keeps the verdict' {
            WuVerdict @(Ring) | Out-Null
            $dc = (Get-TPRawData -Key 'Intune-DeviceCompliance') | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
            $es = (Get-TPRawData -Key 'Intune-EndpointSecurity') | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
            Clear-TPState
            Set-TPRawData -Key 'Intune-DeviceCompliance' -Data $dc
            Set-TPRawData -Key 'Intune-EndpointSecurity' -Data $es
            (Verdict 'Test-TPControlIntuneWindowsUpdate' 'INT-2.5').State | Should -Be 'Satisfied'
    Context 'INT-2.6 judges the assigned Office policies against the approved CIS Intune for Office macro core' {
        BeforeAll {
            $script:OffCat = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config' 'cis-intune-office-macro.json') -Raw | ConvertFrom-Json -Depth 10
            $script:OffList = @(@{ id = 'o1'; name = 'Office hardening'; platforms = 'windows10'; templateReference = @{ templateFamily = 'none'; templateDisplayName = '' }; assignments = $script:Assigned })
            # One Office setting as configurationPolicies/{id}/settings?$expand=settingDefinitions returns it:
            # an ADMX-backed choice instance (value <id>_1 / <id>_0) with its definition and options named.
            # $Option adds the dropdown child Office uses for VBA Macro Notification Settings.
            function script:OfficeSetting { param($S, [string] $State, [string] $Option, [switch] $NoDefinitions)
                $id = "user_vendor_msft_policy_config_$($S.AppKey)~policy~l_microsoftoffice~l_security~l_trustcenter_$($S.Node)"
                $children = @(); $defs = @(@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition'; id = $id; displayName = "$($S.Title) (User)"
                    options = @(@{ itemId = "${id}_0"; displayName = 'Disabled' }, @{ itemId = "${id}_1"; displayName = 'Enabled' }) })
                if ($Option) {
                    $cid = "${id}_l_empty19"
                    $labels = @('Enable all macros (not recommended)', 'Disable all with notification', 'Disable all except digitally signed macros', 'Disable all without notification')
                    $opts = @(for ($i = 0; $i -lt $labels.Count; $i++) { @{ itemId = "${cid}_$($i + 1)"; displayName = $labels[$i] } })
                    $pick = @($opts | Where-Object { $_.displayName -eq $Option })
                    $val = if ($pick.Count) { $pick[0].itemId } else { $opts += @{ itemId = "${cid}_9"; displayName = $Option }; "${cid}_9" }
                    $children = @(@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'; settingDefinitionId = $cid; choiceSettingValue = @{ value = $val; children = @() } })
                    $defs += @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition'; id = $cid; displayName = 'VBA Macro Notification Settings'; options = $opts }
                }
                $out = @{ id = '0'; settingInstance = @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                    settingDefinitionId = $id; choiceSettingValue = @{ value = "${id}_$State"; children = $children } } }
                if (-not $NoDefinitions) { $out.settingDefinitions = $defs }
                $out
            }
            # Every catalog setting in its required state, with overrides by CIS number:
            # $null leaves it out, '0'/'1' sets that state, 'vba:<label>' picks the VBA option.
            function script:OfficePayload { param([hashtable] $Override = @{}, [switch] $NoDefinitions)
                @(foreach ($s in $script:OffCat.Settings) {
                    $state = [string]@($s.Compliant)[0]; $opt = if ($s.Kind -eq 'Dropdown') { 'Disable all except digitally signed macros' } else { '' }
                    if ($Override.ContainsKey($s.Cis)) {
                        $o = $Override[$s.Cis]; if ($null -eq $o) { continue }
                        if ($o -like 'vba:*') { $opt = $o.Substring(4) } else { $state = $o }
                    }
                    OfficeSetting $s $state $opt -NoDefinitions:$NoDefinitions
                }) }
            function script:OfficeVerdict { param([hashtable] $Graph) Run $Graph; Verdict 'Test-TPControlIntuneOfficeMacro' 'INT-2.6' }
            $script:GpOffice = @(@{ id = 'g1'; displayName = 'Office ADMX'; assignments = $script:Assigned })
            $script:GpOfficeValues = @(@{ id = 'v1'; enabled = $true; definition = @{ id = 'd1'; displayName = 'Block macros from running in Office files from the Internet'; categoryPath = '\Microsoft Word 2016\Word Options\Security\Trust Center'; classType = 'user' } })
            $script:GpOtherValues = @(@{ id = 'v2'; enabled = $true; definition = @{ id = 'd2'; displayName = 'Prevent the usage of OneDrive for file storage'; categoryPath = '\OneDrive'; classType = 'machine' } })
        }
        It 'the catalog is the approved Level 1 core: 27 settings for Word, Excel, PowerPoint and Access, each sourced, and the approval names it' {
            @($script:OffCat.Settings).Count | Should -Be 27
            @($script:OffCat.Settings.Cis | Select-Object -Unique).Count | Should -Be 27
            foreach ($s in $script:OffCat.Settings) {
                $s.Level | Should -Be 1
                $s.App | Should -BeIn @('Word', 'Excel', 'PowerPoint', 'Access')
                $s.Kind | Should -BeIn @('Toggle', 'Dropdown')
                @($s.Compliant).Count | Should -Be 1
                [string]$s.Source | Should -Match '^https://learn\.microsoft\.com/'
            }
            # Easy to get backwards: the Protected View and network trusted-location policies are met by DISABLED.
            @($script:OffCat.Settings | Where-Object { $_.Title -match 'Protected View|Trusted Locations on the network' } | ForEach-Object { @($_.Compliant)[0] } | Select-Object -Unique) | Should -Be @('0')
            @($script:OffCat.Settings | Where-Object Kind -eq 'Dropdown').Cis | Should -Be @('2.2.4.7.2.7', '2.6.6.6.2.8', '2.11.8.7.2.10')
            foreach ($o in $script:OffCat.NotInApprovedSubset) { ([string]$o.Reason).Length | Should -BeGreaterThan 20 }
            $b = & $script:Mod { Get-TPIntuneOfficeMacroBaseline }
            $b | Should -Not -BeNullOrEmpty
            $b.Name | Should -Be 'CIS Microsoft Intune for Office Benchmark v1.1.0'
        }
        It 'every setting in its required state is Satisfied, read with the definitions expanded and no new scope' {
            $f = OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList; 'configurationPolicies/o1/settings' = (OfficePayload) }
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match '27 of 27 settings'
            @(& $script:Mod { $script:SeenUris } | Where-Object { $_ -match 'configurationPolicies/o1/settings\?\$expand=settingDefinitions' }).Count | Should -Be 1
            @(& $script:Mod { Get-TPGraphScopeList }) | Should -Contain 'DeviceManagementConfiguration.Read.All'
            $raw = @((Get-TPRawData -Key 'Intune-EndpointSecurity').Data.OfficePolicies)
            $raw.Count | Should -Be 1
            $raw[0].OfficeSettingsStatus | Should -Be 'Read'
        }
        It 'a setting in the other state is a shortfall (Below), and Partial beside settings met' {
            $f = OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList; 'configurationPolicies/o1/settings' = (OfficePayload @{ '2.2.4.7.2.6' = '0'; '2.11.8.7.2.2.5' = '1' }) }
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Set to a state the benchmark does not accept: 2\.2\.4\.7\.2\.6 Excel Block macros'
            $f.Detail | Should -Match '2\.11\.8\.7\.2\.2\.5 Word Turn off Protected View for attachments opened from Outlook \(Office hardening \(Enabled\); requires Disabled\)'
        }
        It 'a setting no assigned policy sets is a shortfall (the not-configured rule), with the Office default named' {
            $f = OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList; 'configurationPolicies/o1/settings' = (OfficePayload @{ '2.2.4.7.2.8' = $null }) }
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Not set by any assigned Office policy, which the benchmark requires: 2\.2\.4\.7\.2\.8 Excel Prevent Excel from running XLM macros \(not configured:'
        }
        It 'the VBA option is judged by name: a weaker option or the stricter no-notification option is Below, an unknown option is not assessed' {
            (OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList; 'configurationPolicies/o1/settings' = (OfficePayload @{ '2.11.8.7.2.10' = 'vba:Enable all macros (not recommended)' }) }).State | Should -Be 'Partial'
            $f = OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList; 'configurationPolicies/o1/settings' = (OfficePayload @{ '2.11.8.7.2.10' = 'vba:Disable all without notification' }) }
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'stricter than the benchmark'
            $f = OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList; 'configurationPolicies/o1/settings' = (OfficePayload @{ '2.11.8.7.2.10' = 'vba:Some future option' }) }
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'a value this assessment does not recognize for 2\.11\.8\.7\.2\.10'
        }
        It 'without the expanded definitions a setting is still matched by its ADMX policy name and its _1 / _0 suffix, and a VBA option without a name is never credited' {
            $f = OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList; 'configurationPolicies/o1/settings' = (OfficePayload -NoDefinitions) }
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '24 of 27 settings'
            $f.Detail | Should -Match 'option not read'
        }
        It 'an unrecognized state value is not assessed, never Satisfied' {
            $f = OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList; 'configurationPolicies/o1/settings' = (OfficePayload -NoDefinitions -Override @{ '2.2.4.7.2.6' = '7'; '2.2.4.7.2.7' = $null; '2.6.6.6.2.8' = $null; '2.11.8.7.2.10' = $null }) }
            $f.State | Should -Not -Be 'Satisfied'
            $f.Detail | Should -Match 'does not recognize for 2\.2\.4\.7\.2\.6'
        }
        It 'no Settings Catalog Office policy and no Administrative Templates Office policy is a Gap; an unassigned Office policy does not count' {
            $f = OfficeVerdict @{ 'groupPolicyConfigurations\?' = @(@{ id = 'g2'; displayName = 'OneDrive ADMX'; assignments = $script:Assigned }); 'groupPolicyConfigurations/g2/definitionValues' = $script:GpOtherValues }
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'Office cloud policy service'
            $unassigned = @(@{ id = 'o1'; name = 'Office hardening'; platforms = 'windows10'; templateReference = @{ templateFamily = 'none' }; assignments = @() })
            (OfficeVerdict @{ 'configurationPolicies\?' = $unassigned; 'configurationPolicies/o1/settings' = (OfficePayload) }).State | Should -Be 'Gap'
            @(& $script:Mod { $script:SeenUris } | Where-Object { $_ -match 'configurationPolicies/o1/settings' }).Count | Should -Be 0 -Because 'an unassigned policy is not read'
            # Graph returns an unassigned policy as "assignments": []; it was recorded as "not reported" and counted as assigned.
            @((Get-TPRawData -Key 'Intune-EndpointSecurity').Data.EndpointSecurityPolicies)[0].IsAssigned | Should -BeFalse
        }
        It 'Office settings only in Administrative Templates policies are not assessed, never a Gap' {
            $f = OfficeVerdict @{ 'groupPolicyConfigurations\?' = $script:GpOffice; 'groupPolicyConfigurations/g1/definitionValues' = $script:GpOfficeValues }
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'only in Administrative Templates policy\(ies\) \(Office ADMX\)'
            $g = @((Get-TPRawData -Key 'Intune-EndpointSecurity').Data.AdminTemplatePolicies)
            $g[0].OfficeDefinitionCount | Should -Be 1
        }
        It 'a compliant Settings Catalog policy beside an Administrative Templates Office policy is not assessed, never Satisfied' {
            $f = OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList; 'configurationPolicies/o1/settings' = (OfficePayload)
                                  'groupPolicyConfigurations\?' = $script:GpOffice; 'groupPolicyConfigurations/g1/definitionValues' = $script:GpOfficeValues }
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Administrative Templates policy\(ies\) that hold Office settings \(Office ADMX\)'
        }
        It 'a settings read that fails leaves the control not assessed, recorded on the policy' {
            & $script:Mod { $script:FailSettings = $true }
            try {
                $f = OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList }
                $f.State | Should -Be 'NotApplicable'
                @((Get-TPRawData -Key 'Intune-EndpointSecurity').Data.OfficePolicies)[0].OfficeSettingsStatus | Should -Be 'Failed'
            } finally { & $script:Mod { $script:FailSettings = $false } }
        }
        It 'a results file from before the Office read, or a withdrawn approval, is not assessed' {
            Clear-TPState
            Set-TPRawData -Key 'Intune-EndpointSecurity' -Data ([pscustomobject]@{ Success = $true; Data = [pscustomobject]@{ SectionStatus = [pscustomobject]@{ EndpointSecurityPolicies = 'Collected' }; EndpointSecurityPolicies = @() } })
            $f = Verdict 'Test-TPControlIntuneOfficeMacro' 'INT-2.6'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^OfficePolicies was not collected; not assessed\.'
            Mock -ModuleName 'TenantPosture' -CommandName Get-TPIntuneOfficeMacroBaseline -MockWith { $null }
            $f = OfficeVerdict @{ 'configurationPolicies\?' = $script:OffList; 'configurationPolicies/o1/settings' = (OfficePayload @{ '2.2.4.7.2.6' = '0' }) }
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'because no Office macro configuration standard is approved'
        }
        It 'the approval gate returns no catalog when the approval is empty or names another version' {
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-off-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.json')
            try {
                Set-Content -LiteralPath $tmp -Value '{ "IntuneOfficeMacroBaseline": { "Benchmark": "" } }' -Encoding utf8
                (& $script:Mod { param($p) Get-TPIntuneOfficeMacroBaseline -StandardsPath $p } $tmp) | Should -BeNullOrEmpty
                Set-Content -LiteralPath $tmp -Value '{ "IntuneOfficeMacroBaseline": { "Benchmark": "CIS Microsoft Intune for Office Benchmark v1.0.0" } }' -Encoding utf8
                (& $script:Mod { param($p) Get-TPIntuneOfficeMacroBaseline -StandardsPath $p } $tmp) | Should -BeNullOrEmpty
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'INT-4.4 reads the iOS passcodeRequired (an iOS-only fleet failed)' {
        Run @{ 'deviceCompliancePolicies' = @(@{ '@odata.type' = '#microsoft.graph.iosCompliancePolicy'; id = 'c1'; displayName = 'iOS'; passcodeRequired = $true; osMinimumVersion = '17.0'; assignments = $script:Assigned })
               'managedDevices' = @(@{ id = 'ip1'; operatingSystem = 'iOS'; complianceState = 'compliant' }) }
        (Verdict 'Test-TPControlIntuneMobilePIN' 'INT-4.4').State | Should -Be 'Satisfied'
    }
    It 'INT-4.3 is not "OS-version compliant" when no policy sets a minimum OS version' {
        Run @{ 'deviceCompliancePolicies' = @(@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'w'; displayName = 'Win'; assignments = $script:Assigned })
               'managedDevices' = @(1..10 | ForEach-Object { @{ id = "$_"; operatingSystem = 'Windows'; complianceState = 'compliant' } }) }
        (Verdict 'Test-TPControlIntuneUpdateCompliance' 'INT-4.3').State | Should -Be 'Gap'
    }
    It 'INT-3.3 does not count the default PIN-retry / offline-wipe limits as conditional launch' {
        Run @{ 'managedAppPolicies' = @(@{ '@odata.type' = '#microsoft.graph.iosManagedAppProtection'; id = 'p'; displayName = 'iOS MAM'; maximumPinRetries = 5; periodOfflineBeforeWipeIsEnforced = 'P90D'; isAssigned = $true }) }
        (Verdict 'Test-TPControlIntuneConditionalLaunch' 'INT-3.3').State | Should -Be 'Gap'
    }
    Context 'INT-3.3 judges conditional launch against the App Protection Framework, Level 2 (owner, 2026-10-26)' {
        BeforeAll {
            # An app protection policy as Graph v1.0 returns it from deviceAppManagement/managedAppPolicies.
            function script:Mam { param([string] $Type = 'iosManagedAppProtection', [string] $Name = 'iOS MAM', [hashtable] $Over = @{})
                $p = @{ '@odata.type' = "#microsoft.graph.$Type"; id = $Name; displayName = $Name; isAssigned = $true
                        deviceComplianceRequired = $true; minimumRequiredOsVersion = '17.0'; maximumPinRetries = 5
                        periodOfflineBeforeAccessCheck = 'PT720M'; periodOfflineBeforeWipeIsEnforced = 'P30D' }
                foreach ($k in $Over.Keys) { if ($null -eq $Over[$k]) { $p.Remove($k) } else { $p[$k] = $Over[$k] } }
                $p }
            function script:Int33 { param([object[]] $Policies, [object[]] $Devices = @())
                Run @{ 'managedAppPolicies' = $Policies; 'managedDevices' = $Devices }
                Verdict 'Test-TPControlIntuneConditionalLaunch' 'INT-3.3' }
        }
        It 'every judged Level 2 row met on iOS and Android is Satisfied, and the unread rows are named' {
            $f = Int33 @((Mam), (Mam 'androidManagedAppProtection' 'Android MAM' @{ minimumRequiredOsVersion = '13.0'; periodOfflineBeforeAccessCheck = 'P7D'; periodOfflineBeforeWipeIsEnforced = 'P1D' }))
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'Jailbroken/rooted devices blocked in all 2'
            $f.RequiredValue | Should -Match 'does not read: Disabled account'
            $f.RequiredValue | Should -Match 'Samsung Knox'
        }
        It 'each boundary: 10080 minutes and 30 days pass, one more fails; six PIN attempts fail' {
            (Int33 @(Mam -Over @{ periodOfflineBeforeAccessCheck = 'PT10080M' })).State | Should -Be 'Satisfied'
            (Int33 @(Mam -Over @{ periodOfflineBeforeAccessCheck = 'PT10081M' })).State | Should -Be 'Gap'
            (Int33 @(Mam -Over @{ periodOfflineBeforeWipeIsEnforced = 'P31D' })).State | Should -Be 'Gap' -Because 'Microsoft''s default of 90 days is Level 1, not Level 2'
            $f = Int33 @(Mam -Over @{ maximumPinRetries = 6 })
            $f.State | Should -Be 'Gap'
            $f.Detail | Should -Match 'Max PIN attempts 5 or fewer: not met by 1 of 1'
            (Int33 @(Mam -Over @{ deviceComplianceRequired = $false })).State | Should -Be 'Gap'
            (Int33 @(Mam -Over @{ minimumRequiredOsVersion = $null })).State | Should -Be 'Gap'
        }
        It 'a row met by one policy and missed by another is Partial, naming the policy' {
            $f = Int33 @((Mam), (Mam 'androidManagedAppProtection' 'Android MAM' @{ minimumRequiredOsVersion = '' }))
            $f.State | Should -Be 'Partial'
            $f.Detail | Should -Match 'Min OS version set \(Block access\): not met by 1 of 2 policy\(ies\) \(Android MAM\)'
        }
        It 'a duration Graph did not return, or one that is not ISO 8601, is not assessed, never met and never short' {
            (Int33 @(Mam -Over @{ periodOfflineBeforeAccessCheck = $null })).State | Should -Be 'NotApplicable'
            $f = Int33 @(Mam -Over @{ periodOfflineBeforeWipeIsEnforced = '30 days' })
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Not assessed: Offline grace period Wipe data'
            (Int33 @(Mam -Over @{ deviceComplianceRequired = $null })).State | Should -Be 'NotApplicable'
        }
        It 'a results file from before the offline grace periods were read is not assessed' {
            Clear-TPState
            Set-TPRawData -Key 'Intune-AppProtection' -Data @{ Success = $true; Data = @{ SectionStatus = @{ AppProtectionPolicies = 'Collected' }
                AppProtectionPolicies = @(@{ Type = '#microsoft.graph.iosManagedAppProtection'; DisplayName = 'old'; IsAssigned = $true; DeviceComplianceRequired = $true; MinimumRequiredOsVersion = '16.0'; MaximumPinRetries = 5 }) } }
            (Verdict 'Test-TPControlIntuneConditionalLaunch' 'INT-3.3').State | Should -Be 'NotApplicable'
        }
        It 'no mobile policy and no enrolled mobile device is not applicable, saying so; enrolled phones make it a Gap' {
            $f = Int33 @() @(@{ id = 'w1'; operatingSystem = 'Windows'; complianceState = 'compliant' })
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'no iOS, iPadOS or Android device is enrolled'
            (Int33 @() @(@{ id = 'a1'; operatingSystem = 'Android'; complianceState = 'compliant' })).State | Should -Be 'Gap'
            # A Windows MAM policy is not an iOS/Android app protection policy.
            (Int33 @(Mam 'windowsManagedAppProtection' 'Win MAM') @(@{ id = 'w1'; operatingSystem = 'Windows'; complianceState = 'compliant' })).State | Should -Be 'NotApplicable'
        }
        It 'an unassigned policy is not judged' {
            (Int33 @(Mam -Over @{ isAssigned = $false }) @(@{ id = 'i1'; operatingSystem = 'iOS'; complianceState = 'compliant' })).State | Should -Be 'Gap'
        }
    }
    It 'INT-3.1: the Windows Mobile block Intune ships in every tenant is not a restriction' {
        # Live tenant, 2026-09-25: passed on "windowsMobile: platform blocked" alone.
        $d = $script:Defaults.Clone(); $d[1] = $d[1].Clone()
        $d[1].windowsMobileRestriction = @{ platformBlocked = $true; personalDeviceEnrollmentBlocked = $false }
        Run @{ 'deviceEnrollmentConfigurations' = $d }
        (Verdict 'Test-TPControlIntuneEnrollmentRestrictions' 'INT-3.1').State | Should -Be 'Gap'
    }
    It 'INT-2.4 / INT-4.4 state the enrolled platforms instead of guessing, and a Mac with no policy is a Gap' {
        # 37 Windows devices, no Macs, no phones; a Microsoft default Android
        # policy whose assignment could not be read.
        $win = @(1..3 | ForEach-Object { @{ id = "w$_"; operatingSystem = 'Windows'; complianceState = 'compliant' } })
        Run @{ 'managedDevices' = $win
               'deviceCompliancePolicies' = @(@{ '@odata.type' = '#microsoft.graph.androidCompliancePolicy'; id = 'a'; displayName = 'Default compliance policy for Android'; passwordRequired = $false }) }
        $mac = Verdict 'Test-TPControlIntuneMacEncryption' 'INT-2.4'
        $mac.State  | Should -Be 'NotApplicable'
        $mac.Detail | Should -Match 'No macOS devices are enrolled in Intune \(enrolled: 3 Windows\)'
        (Verdict 'Test-TPControlIntuneMobilePIN' 'INT-4.4').State | Should -Be 'NotApplicable' -Because 'no phone is enrolled, so a phone passcode setting governs nothing'
        Run @{ 'managedDevices' = @($win + @{ id = 'm1'; operatingSystem = 'macOS'; complianceState = 'compliant' }) }
        (Verdict 'Test-TPControlIntuneMacEncryption' 'INT-2.4').State | Should -Be 'Gap'
    }
    It 'INT-1.5 does not give half credit for enrollment configurations every tenant has' {
        Run @{ 'deviceEnrollmentConfigurations' = $script:Defaults }
        (Verdict 'Test-TPControlIntune' 'INT-1.5').State | Should -Be 'Gap'
    }
    It 'INT-1.1 is Satisfied when every platform is covered and every policy acts on a noncompliant device; the actions ride the policy request' {
        Run @{ 'deviceCompliancePolicies' = @(@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'w'; displayName = 'Win'; assignments = $script:Assigned
                   scheduledActionsForRule = @(@{ ruleName = 'PasswordRequired'; scheduledActionConfigurations = @(
                       @{ id = 's1'; actionType = 'block'; gracePeriodHours = 0; notificationTemplateId = '' }
                       @{ id = 's2'; actionType = 'notification'; gracePeriodHours = 24; notificationTemplateId = 't1' }) }) })
               'managedDevices' = @(@{ id = 'd1'; operatingSystem = 'Windows'; complianceState = 'compliant' }) }
        $f = Verdict 'Test-TPControlIntune' 'INT-1.1'
        $f.State | Should -Be 'Satisfied'
        $f.Detail | Should -Match 'Win \(mark noncompliant immediately\)'
        $pol = @((Get-TPRawData -Key 'Intune-DeviceCompliance').Data.CompliancePolicies)[0]
        $pol.ActionsRead | Should -BeTrue
        @($pol.NonComplianceActions).Count | Should -Be 2
        $seen = @(& $script:Mod { $script:SeenUris } | Where-Object { $_ -match 'deviceCompliancePolicies' })
        $seen.Count | Should -Be 1 -Because 'the actions are expanded with the policies, not fetched per policy'
        $seen[0] | Should -Match ([regex]::Escape('$expand=assignments,scheduledActionsForRule($expand=scheduledActionConfigurations)'))
    }
    It 'INT-1.1 is Partial when an assigned policy only notifies' {
        Run @{ 'deviceCompliancePolicies' = @(@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'w'; displayName = 'Win'; assignments = $script:Assigned
                   scheduledActionsForRule = @(@{ ruleName = 'PasswordRequired'; scheduledActionConfigurations = @(@{ id = 's2'; actionType = 'notification'; gracePeriodHours = 24; notificationTemplateId = 't1' }) }) })
               'managedDevices' = @(@{ id = 'd1'; operatingSystem = 'Windows'; complianceState = 'compliant' }) }
        $f = Verdict 'Test-TPControlIntune' 'INT-1.1'
        $f.State | Should -Be 'Partial'
        $f.Detail | Should -Match 'beyond a notification \(Win\)'
    }
    It 'INT-1.1 is not assessed, never a Gap, when Graph refuses the actions expand: the policies are read without it and say so' {
        & $script:Mod { $script:RefuseActions = $true }
        try {
            Run @{ 'deviceCompliancePolicies' = @(@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'w'; displayName = 'Win'; assignments = $script:Assigned })
                   'managedDevices' = @(@{ id = 'd1'; operatingSystem = 'Windows'; complianceState = 'compliant' }) }
            $f = Verdict 'Test-TPControlIntune' 'INT-1.1'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'were not read \(Win\)'
            $raw = Get-TPRawData -Key 'Intune-DeviceCompliance'
            $raw.Data.SectionStatus.CompliancePolicies | Should -Be 'Collected'
            @($raw.Data.CompliancePolicies)[0].ActionsRead | Should -BeFalse
            $seen = @(& $script:Mod { $script:SeenUris } | Where-Object { $_ -match 'deviceCompliancePolicies' })
            $seen.Count | Should -Be 2
            $seen[1] | Should -Not -Match 'scheduledActionsForRule'
        } finally { & $script:Mod { $script:RefuseActions = $false } }
    }
    It 'a replayed policy with no ActionsRead field is "not read", and an empty action list is "no action" (Get-TPComplianceActionVerdict)' {
        $v = & $script:Mod { Get-TPComplianceActionVerdict -Policies @(
            @{ DisplayName = 'Old'; IsAssigned = $true },
            @{ DisplayName = 'Empty'; IsAssigned = $true; ActionsRead = $true; NonComplianceActions = @() },
            @{ DisplayName = 'Lock'; IsAssigned = $true; ActionsRead = $true; NonComplianceActions = @(@{ ActionType = 'remoteLock'; GracePeriodHours = 0 }) }) }
        @($v.Unread)  | Should -Be @('Old')
        @($v.Lacking) | Should -Be @('Empty')
        @($v.Acting)  | Should -Be @('Lock (remoteLock immediately)')
    }
    It 'the compliance read needs no new Graph scope' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Collectors/Intune/Invoke-TPCollectIntuneDeviceCompliance.ps1') -Raw
        $src | Should -Match 'deviceManagement/deviceCompliancePolicies\?\$expand=assignments'
        @(& $script:Mod { Get-TPGraphScopeList }) | Should -Contain 'DeviceManagementConfiguration.Read.All'
    }
}

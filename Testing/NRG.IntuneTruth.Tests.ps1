#Requires -Version 7.0
#
# NRG.IntuneTruth.Tests.ps1
# NRG Technology Services / NextLayerSec LLC — Author: Matthew Levorson
# Pins the Intune verdicts to what each Graph object means, driving the REAL
# collectors with raw Graph shapes (Invoke-NRGGraphRequest injected into
# module scope). Every case produced a wrong verdict before this change.
#
# Data keys: Intune-DeviceCompliance, Intune-EndpointSecurity,
#            Intune-AppProtection, AAD-CAPolicies.
#

Describe 'Intune controls count what enforces something' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        & $script:Mod { Set-Item -Path 'function:script:Invoke-NRGGraphRequest' -Value {
            param([string] $Uri, [string] $Method = 'GET', $Headers, $Body, [string] $OutputType = 'HashTable')
            foreach ($k in $script:Graph.Keys) { if ($Uri -match $k) { return @{ value = @($script:Graph[$k]) } } }
            return @{ value = @() }
        } }
        $script:Tid = '00000000-1111-2222-3333-444444444444'
        # The four enrollment configurations every tenant has.
        $script:Defaults = @(
            @{ '@odata.type' = '#microsoft.graph.deviceEnrollmentLimitConfiguration'; id = "$($script:Tid)_DefaultLimit"; displayName = 'All users and all devices'; priority = 0; limit = 15 },
            @{ '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration'; id = "$($script:Tid)_DefaultPlatformRestrictions"; displayName = 'All users and all devices'; priority = 0
               windowsRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $false }; iosRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $false } },
            @{ '@odata.type' = '#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration'; id = "$($script:Tid)_DefaultWindowsHelloForBusiness"; displayName = 'All users and all devices'; priority = 0; state = 'notConfigured' })
        function script:Run { param([hashtable] $Graph)
            Clear-NRGState
            & $script:Mod { param($g) $script:Graph = $g } $Graph
            Invoke-NRGCollectIntuneDeviceCompliance | Out-Null
            Invoke-NRGCollectIntuneEndpointSecurity | Out-Null
            Invoke-NRGCollectIntuneAppProtection | Out-Null
        }
        function script:Verdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
        $script:Assigned = @(@{ id = 'a1'; target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
    }
    AfterAll { & $script:Mod { Remove-Item -Path 'function:script:Invoke-NRGGraphRequest' -ErrorAction SilentlyContinue }; Clear-NRGState }

    It 'INT-1.2 reads Conditional Access, not "a configuration profile exists" (a Wi-Fi profile passed)' {
        Run @{ 'deviceConfigurations' = @(@{ '@odata.type' = '#microsoft.graph.windowsWifiConfiguration'; id = 'd1'; displayName = 'Office Wi-Fi'; assignments = $script:Assigned }) }
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data @{ Success = $true; Data = @{ Policies = @() } }
        (Verdict 'Test-NRGControlIntune' 'INT-1.2').State | Should -Be 'Gap'
        Clear-NRGState
        Set-NRGRawData -Key 'Intune-DeviceCompliance' -Data @{ Success = $true; Data = @{ CompliancePolicies = @() } }
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data @{ Success = $true; Data = @{ Policies = @(@{ DisplayName = 'Require compliant device'; State = 'enabled'
            Conditions = @{ Users = @{ IncludeUsers = @('All') }; Applications = @{ Include = @('All') } }; GrantControls = @{ Operator = 'OR'; BuiltInControls = @('compliantDevice') } }) } }
        (Verdict 'Test-NRGControlIntune' 'INT-1.2').State | Should -Be 'Satisfied'
    }
    It 'INT-1.4 does not count an app CONFIGURATION policy as app protection' {
        Run @{ 'managedAppPolicies' = @(@{ '@odata.type' = '#microsoft.graph.targetedManagedAppConfiguration'; id = 'a1'; displayName = 'Outlook settings' }) }
        (Verdict 'Test-NRGControlIntune' 'INT-1.4').State | Should -Be 'Gap'
    }
    It 'INT-3.1: Intune''s default enrollment configurations are not restrictions' {
        Run @{ 'deviceEnrollmentConfigurations' = $script:Defaults }
        (Verdict 'Test-NRGControlIntuneEnrollmentRestrictions' 'INT-3.1').State | Should -Be 'Gap'
        $d = $script:Defaults.Clone(); $d[1] = $d[1].Clone(); $d[1].windowsRestriction = @{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $true }
        Run @{ 'deviceEnrollmentConfigurations' = $d }
        (Verdict 'Test-NRGControlIntuneEnrollmentRestrictions' 'INT-3.1').State | Should -Be 'Satisfied'
    }
    It 'INT-4.2 reads the WHfB state, not the presence of the default configuration' {
        Run @{ 'deviceEnrollmentConfigurations' = $script:Defaults }
        (Verdict 'Test-NRGControlIntuneWindowsHello' 'INT-4.2').State | Should -Be 'Gap'
    }
    It 'unassigned drafts and same-family templates are not LAPS / ASR' {
        Run @{
            'configurationPolicies' = @(
                @{ id = 'p1'; name = 'Credential Guard'; templateReference = @{ templateFamily = 'endpointSecurityAccountProtection'; templateDisplayName = 'Account Protection' }; assignments = $script:Assigned },
                @{ id = 'p2'; name = 'Block USB'; templateReference = @{ templateFamily = 'endpointSecurityAttackSurfaceReduction'; templateDisplayName = 'Device Control' }; assignments = $script:Assigned })
            'intents' = @(@{ id = 'i1'; displayName = 'Windows LAPS'; isAssigned = $false }, @{ id = 'i2'; displayName = 'ASR rules'; isAssigned = $false })
        }
        (Verdict 'Test-NRGControlIntuneWindowsLAPS' 'INT-4.1').State | Should -Be 'Gap'
        (Verdict 'Test-NRGControlIntuneASR' 'INT-2.2').State | Should -Be 'Gap'
        Run @{ 'configurationPolicies' = @(@{ id = 'p3'; name = 'LAPS'; templateReference = @{ templateFamily = 'endpointSecurityAccountProtection'; templateDisplayName = 'Local admin password solution (Windows LAPS)' }; assignments = $script:Assigned }) }
        (Verdict 'Test-NRGControlIntuneWindowsLAPS' 'INT-4.1').State | Should -Be 'Satisfied'
    }
    It 'INT-1.3 accepts "Require encryption of data storage"; INT-2.4 does not accept System Integrity Protection' {
        Run @{ 'deviceCompliancePolicies' = @(
            @{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'w'; displayName = 'Win'; storageRequireEncryption = $true; bitLockerEnabled = $false; assignments = $script:Assigned },
            @{ '@odata.type' = '#microsoft.graph.macOSCompliancePolicy'; id = 'm'; displayName = 'Mac'; systemIntegrityProtectionEnabled = $true; storageRequireEncryption = $false; assignments = $script:Assigned }) }
        (Verdict 'Test-NRGControlIntune' 'INT-1.3').State | Should -Be 'Satisfied'
        (Verdict 'Test-NRGControlIntuneMacEncryption' 'INT-2.4').State | Should -Be 'Gap'
    }
    It 'INT-4.4 reads the iOS passcodeRequired (an iOS-only fleet failed)' {
        Run @{ 'deviceCompliancePolicies' = @(@{ '@odata.type' = '#microsoft.graph.iosCompliancePolicy'; id = 'c1'; displayName = 'iOS'; passcodeRequired = $true; osMinimumVersion = '17.0'; assignments = $script:Assigned }) }
        (Verdict 'Test-NRGControlIntuneMobilePIN' 'INT-4.4').State | Should -Be 'Satisfied'
    }
    It 'INT-4.3 is not "OS-version compliant" when no policy sets a minimum OS version' {
        Run @{ 'deviceCompliancePolicies' = @(@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'w'; displayName = 'Win'; assignments = $script:Assigned })
               'managedDevices' = @(1..10 | ForEach-Object { @{ id = "$_"; operatingSystem = 'Windows'; complianceState = 'compliant' } }) }
        (Verdict 'Test-NRGControlIntuneUpdateCompliance' 'INT-4.3').State | Should -Be 'Gap'
    }
    It 'INT-3.3 does not count the default PIN-retry / offline-wipe limits as conditional launch' {
        Run @{ 'managedAppPolicies' = @(@{ '@odata.type' = '#microsoft.graph.iosManagedAppProtection'; id = 'p'; displayName = 'iOS MAM'; maximumPinRetries = 5; periodOfflineBeforeWipeIsEnforced = 'P90D'; isAssigned = $true }) }
        (Verdict 'Test-NRGControlIntuneConditionalLaunch' 'INT-3.3').State | Should -Be 'Gap'
    }
    It 'INT-1.5 does not give half credit for enrollment configurations every tenant has' {
        Run @{ 'deviceEnrollmentConfigurations' = $script:Defaults }
        (Verdict 'Test-NRGControlIntune' 'INT-1.5').State | Should -Be 'Gap'
    }
}

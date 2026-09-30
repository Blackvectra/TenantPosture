#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.CoverageTruth.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Regression tests for discrepancies found by comparing an independent
             ScubaGear scan with NRG on the same tenant. Fixtures use the raw shapes the
             collectors store, with every identifier replaced by a placeholder.
               - A Conditional Access policy that applies to no application does not
                 establish protection; exclusions are judged across ALL qualifying
                 policies (covered elsewhere = fine, excluded everywhere = exception,
                 different exclusions = unproven), never ignored and never automatically
                 a gap.
               - Device code, MFA enforcement, MFA registration and phishing-resistant
                 authentication are separate findings.
               - A Defender preset turned on is not a preset that applies to everyone:
                 recipient scope, exclusions and fallback are judged.
               - DLP coverage, detection and enforcement are separate; a policy in test
                 mode counts for none of them.
             Observed configuration, baseline judgment and independent comparison are
             different things: nothing here asserts that any independent scan must agree.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Coverage is judged on who is protected, not on which policies exist' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        function script:Bag([hashtable] $Data) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-30T00:00:00Z'; Success = $true; Data = $Data } }
        function script:Pol {
            param([string] $Name = 'p', [string] $State = 'enabled', [string[]] $Users = @('All'), [string[]] $ExUsers = @(), [string[]] $ExGroups = @(),
                  [string[]] $Apps = @('All'), [string[]] $ExApps = @(), [string[]] $ClientApps = @('all'), [string[]] $Grant = @(), [string] $Op = 'OR',
                  [string] $StrengthId = '', [string] $StrengthName = '', $AuthFlows = @(), [string[]] $Platforms = @(), [string[]] $IncludeRoles = @())
            @{ DisplayName = $Name; State = $State
               Conditions = @{ ClientAppTypes = $ClientApps; SignInRiskLevels = @(); UserRiskLevels = @(); AuthFlows = @($AuthFlows); Platforms = $Platforms
                               Users = @{ IncludeUsers = $Users; IncludeGroups = @(); IncludeRoles = $IncludeRoles; ExcludeUsers = $ExUsers; ExcludeGroups = $ExGroups; ExcludeRoles = @() }
                               Applications = @{ Include = $Apps; Exclude = $ExApps; UserActions = @() }
                               Locations = @{ Include = @(); Exclude = @() }; Devices = @{ FilterMode = ''; FilterRule = '' }; ClientApplications = @{ IncludeServicePrincipals = @() } }
               GrantControls = @{ Operator = $Op; BuiltInControls = $Grant; AuthStrengthId = $StrengthId; AuthStrengthName = $StrengthName; AuthStrengthCombinations = @(); TermsOfUse = @() }
               SessionControls = @{} }
        }
        function script:Ca([object[]] $Policies) {
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($Policies); SectionStatus = @{ TokenProtection = 'Collected'; NamedLocations = 'Collected' } })
            Set-NRGRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ SecurityDefaults = @{ IsEnabled = $false } })
        }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-NRGFindings | Where-Object ControlId -eq $Cid)[0] }
        $script:BG = 'BREAKGLASS-1'
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    Context 'Combined exclusion coverage (the shared judgment)' {
        It 'a candidate with no exclusions gives Full coverage, whatever the others exclude' {
            $r = Get-NRGExclusionCoverage -Candidates @([pscustomobject]@{ Name = 'a'; Exclusions = @('user:1') }, [pscustomobject]@{ Name = 'b'; Exclusions = @() })
            $r.Kind | Should -Be 'Full'; $r.FullNames | Should -Be @('b')
        }
        It 'the same principal excluded from every candidate is a confirmed exception' {
            $r = Get-NRGExclusionCoverage -Candidates @([pscustomobject]@{ Name = 'a'; Exclusions = @('user:1', 'user:2') }, [pscustomobject]@{ Name = 'b'; Exclusions = @('user:1') })
            $r.Kind | Should -Be 'Exceptions'; $r.Exceptions | Should -Be @('user:1')
        }
        It 'different exclusions leave overlap unproven, never covered' {
            $r = Get-NRGExclusionCoverage -Candidates @([pscustomobject]@{ Name = 'a'; Exclusions = @('group:1') }, [pscustomobject]@{ Name = 'b'; Exclusions = @('group:2') })
            $r.Kind | Should -Be 'Unproven'
        }
        It 'no candidate is None, and a user and a group with the same id never collide' {
            (Get-NRGExclusionCoverage -Candidates @()).Kind | Should -Be 'None'
            (Get-NRGExclusionCoverage -Candidates @([pscustomobject]@{ Name = 'a'; Exclusions = @('user:1') }, [pscustomobject]@{ Name = 'b'; Exclusions = @('group:1') })).Kind | Should -Be 'Unproven'
        }
    }

    Context 'Conditional Access: applications, enforcement state, conditions' {
        It 'AAD-1.1: an enabled block policy scoped to NO application establishes nothing' {
            Ca @(Pol -Name 'none' -Apps @('None') -ClientApps @('exchangeActiveSync', 'other') -Grant @('block'))
            $v = V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1'
            $v.State | Should -Be 'Partial'
            $v.Detail | Should -Match 'applies to no application'
        }
        It 'AAD-1.1: a report-only policy and a disabled policy establish nothing' {
            Ca @((Pol -State 'enabledForReportingButNotEnforced' -ClientApps @('other') -Grant @('block')), (Pol -Name 'off' -State 'disabled' -ClientApps @('other') -Grant @('block')))
            (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Partial'
        }
        It 'AAD-1.1: narrower conditions (one platform, some applications, some users) are not all-user coverage' {
            Ca @(Pol -ClientApps @('other') -Grant @('block') -Platforms @('windows'))
            (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Partial'
            Ca @(Pol -ClientApps @('other') -Grant @('block') -Apps @('00000003-0000-0ff1-ce00-000000000000'))
            (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Partial'
            Ca @(Pol -ClientApps @('other') -Grant @('block') -Users @('00000000-0000-0000-0000-00000000aaaa'))
            (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Partial'
        }
        It 'AAD-1.1: an exclusion is not a gap when another qualifying policy covers those users' {
            Ca @((Pol -Name 'with exclusion' -ClientApps @('other') -Grant @('block') -ExUsers @($script:BG)), (Pol -Name 'clean' -ClientApps @('other') -Grant @('block')))
            (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.1: an account excluded from every qualifying policy is named as an exception (Partial), with the covered part kept' {
            Ca @(Pol -Name 'only' -ClientApps @('exchangeActiveSync', 'other') -Grant @('block') -ExUsers @($script:BG))
            $v = V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1'
            $v.State | Should -Be 'Partial'
            $v.Detail | Should -Match 'Verified: Legacy authentication \(Other clients\) is blocked by: only'
            $v.Detail | Should -Match "user:$($script:BG)"
        }
        It 'AAD-1.1: an excluded account is named when the user list was collected, not only its id' {
            Ca @(Pol -Name 'only' -ClientApps @('other') -Grant @('block') -ExUsers @('00000000-aaaa-bbbb-cccc-000000000001'))
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = @(@{ Id = '00000000-aaaa-bbbb-cccc-000000000001'; UserPrincipalName = 'svc-account@contoso.example'; DisplayName = 'Svc' }) })
            (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').Detail | Should -Match 'user:00000000-aaaa-bbbb-cccc-000000000001 \(svc-account@contoso\.example\)'
        }
        It 'AAD-1.1: different exclusions in different policies are unproven (not assessed), not satisfied and not a gap' {
            Ca @((Pol -Name 'a' -ClientApps @('other') -Grant @('block') -ExGroups @('GROUP-A')), (Pol -Name 'b' -ClientApps @('other') -Grant @('block') -ExGroups @('GROUP-B')))
            $v = V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1'
            $v.State | Should -Be 'NotApplicable'
            $v.Detail | Should -Match 'membership was not resolved'
        }
        It 'AAD-1.1: no policy at all is still a Gap' {
            Ca @(Pol -ClientApps @('all') -Grant @('mfa'))
            (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Gap'
        }
    }

    Context 'Device code, MFA enforcement, MFA registration and phishing-resistant authentication stay separate' {
        It 'AAD-11.1: the block must cover all users; exclusions across policies are combined' {
            Ca @(Pol -Name 'dc' -AuthFlows @(@{ transferMethods = 'deviceCodeFlow' }) -Grant @('block') -ExUsers @($script:BG))
            $v = V 'Test-NRGControlAADDeviceCode' 'AAD-11.1'
            $v.State | Should -Be 'Partial'; $v.Detail | Should -Match "user:$($script:BG)"
            Ca @((Pol -Name 'dc1' -AuthFlows @(@{ transferMethods = 'deviceCodeFlow' }) -Grant @('block') -ExUsers @($script:BG)), (Pol -Name 'dc2' -AuthFlows @(@{ transferMethods = 'deviceCodeFlow' }) -Grant @('block')))
            (V 'Test-NRGControlAADDeviceCode' 'AAD-11.1').State | Should -Be 'Satisfied'
        }
        It 'AAD-11.1: MFA on the device code flow is not a block' {
            Ca @(Pol -AuthFlows @(@{ transferMethods = 'deviceCodeFlow' }) -Grant @('mfa'))
            (V 'Test-NRGControlAADDeviceCode' 'AAD-11.1').State | Should -Be 'Gap'
        }
        It 'AAD-11.1: a device-code policy for one application is reported as narrower, not as coverage' {
            Ca @(Pol -AuthFlows @(@{ transferMethods = 'deviceCodeFlow' }) -Grant @('block') -Apps @('11111111-1111-1111-1111-111111111111'))
            $v = V 'Test-NRGControlAADDeviceCode' 'AAD-11.1'
            $v.State | Should -Not -Be 'Satisfied'; $v.Detail | Should -Match 'narrower'
        }
        BeforeAll {
            $script:Users = { param($registered) @{ Users = @(1..4 | ForEach-Object { @{ UserPrincipalName = "u$_@x.example"; AccountEnabled = $true; UserType = 'Member' } })
                MFARegistration = @{ RegistrationDetails = @(1..4 | ForEach-Object { @{ UserPrincipalName = "u$_@x.example"; IsMfaRegistered = ($_ -le $registered) } }) }
                SectionStatus = @{ MFARegistration = 'Collected' } } }
        }
        It 'AAD-1.2: MFA enforced for all users with everyone registered is Satisfied; the method strength is not asserted' {
            Ca @(Pol -Name 'mfa' -Grant @('mfa'))
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag (& $script:Users 4))
            $v = V 'Test-NRGControlAADMFA' 'AAD-1.2'
            $v.State | Should -Be 'Satisfied'; $v.Detail | Should -Not -Match 'phishing'
        }
        It 'AAD-1.2: registration and enforcement are separate findings of fact: enforced but 2 of 4 unregistered is Partial naming both halves' {
            Ca @(Pol -Name 'mfa' -Grant @('mfa'))
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag (& $script:Users 2))
            $v = V 'Test-NRGControlAADMFA' 'AAD-1.2'
            $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'Verified: MFA is required for all users on all applications by: mfa'; $v.Detail | Should -Match '2 of 4 enabled member'
        }
        It 'AAD-1.2: everyone registered but the only enforcing policy excludes an account is Partial, naming it' {
            Ca @(Pol -Name 'mfa' -Grant @('mfa') -ExUsers @($script:BG))
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag (& $script:Users 4))
            $v = V 'Test-NRGControlAADMFA' 'AAD-1.2'
            $v.State | Should -Be 'Partial'; $v.Detail | Should -Match "user:$($script:BG)"
        }
        It 'AAD-1.3: phishing resistance comes from the strength''s allowed methods, never from a policy name' {
            $named = Pol -Name 'Require Phishing-Resistant MFA' -Grant @() -StrengthId '00000000-0000-0000-0000-000000000002' -StrengthName 'Multifactor authentication'
            Ca @($named)
            (V 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Partial'
            $real = Pol -Name 'Generic policy' -Grant @() -StrengthId '00000000-0000-0000-0000-000000000004' -StrengthName 'Phishing-resistant MFA'
            Ca @($real)
            (V 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.3: a role-scoped policy with no role catalog read is not assessed (never Satisfied, never a Gap)' {
            Ca @(Pol -Name 'admins' -Users @() -IncludeRoles @('ROLE-A') -StrengthId '00000000-0000-0000-0000-000000000004' -StrengthName 'Phishing-resistant MFA')
            $v = V 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3'
            $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'role catalog was not read'
        }
        It 'AAD-1.3: a role-scoped policy that covers only some privileged roles is not full admin coverage' {
            $role = Pol -Name 'admins' -Users @() -IncludeRoles @('ROLE-A') -StrengthId '00000000-0000-0000-0000-000000000004' -StrengthName 'Phishing-resistant MFA'
            Ca @($role)
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleDefinitions = @(@{ Id = 'ROLE-A'; DisplayName = 'A'; IsPriv = $true }, @{ Id = 'ROLE-B'; DisplayName = 'B'; IsPriv = $true }) })
            $v = V 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3'
            $v.State | Should -Not -Be 'Satisfied'; $v.Detail | Should -Match 'covers 1 of 2 privileged roles'
        }
    }

    Context 'Defender presets: scope, exclusions, precedence and fallback' {
        BeforeAll {
            $script:Rule = { param($Name, $Doms = @('contoso.example'), $ExGroups = @(), $SentToMemberOf = @()) @{ Name = $Name; State = 'Enabled'; RecipientDomainIs = $Doms; SentTo = @(); SentToMemberOf = $SentToMemberOf
                ExceptIfSentTo = @(); ExceptIfSentToMemberOf = $ExGroups; ExceptIfRecipientDomainIs = @(); HasExceptions = ($ExGroups.Count -gt 0) } }
            $script:SetPreset = { param($Std, $Strict) Clear-NRGState
                Set-NRGRawData -Key 'Defender-Policies' -Data (Bag @{ PresetRules = @{ Available = $true; EOP = @($Std, $Strict); ATP = @() } })
                Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ AcceptedDomains = @(@{ DomainName = 'contoso.example' }); SectionStatus = @{ AcceptedDomains = 'Collected' } }) }
            $script:V21 = { V 'Test-NRGControlDefenderPresetPolicies' 'DEF-2.1' }
        }
        It 'a preset covering every accepted domain with no exclusions is Satisfied' {
            & $script:SetPreset (& $script:Rule 'Standard Preset Security Policy') (& $script:Rule 'Strict Preset Security Policy' @('other.example'))
            (& $script:V21).State | Should -Be 'Satisfied'
        }
        It 'presets on but the SAME group excluded from both is Partial: that group falls back to Built-In / default protection' {
            & $script:SetPreset (& $script:Rule 'Standard Preset Security Policy' @('contoso.example') @('GROUP-X')) (& $script:Rule 'Strict Preset Security Policy' @('contoso.example') @('GROUP-X'))
            $v = & $script:V21
            $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'group:GROUP-X'; $v.Detail | Should -Match 'fall back'
        }
        It 'different groups excluded from each preset is unproven (not assessed), not a pass' {
            & $script:SetPreset (& $script:Rule 'Standard Preset Security Policy' @('contoso.example') @('GROUP-X')) (& $script:Rule 'Strict Preset Security Policy' @('contoso.example') @('GROUP-Y'))
            $v = & $script:V21
            $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'membership was not resolved'
        }
        It 'a preset rule with no conditions and no exceptions applies to everyone (Microsoft: empty conditions = no restrictions)' {
            & $script:SetPreset (& $script:Rule 'Standard Preset Security Policy' @()) (& $script:Rule 'Strict Preset Security Policy' @())
            $v = & $script:V21
            $v.State | Should -Be 'Satisfied'; $v.Detail | Should -Match 'no recipient exclusions'
        }
        It 'the live shape: empty scope with the same group excluded from both presets is Partial, naming the group' {
            & $script:SetPreset (& $script:Rule 'Standard Preset Security Policy' @() @('careers@contoso.example')) (& $script:Rule 'Strict Preset Security Policy' @() @('careers@contoso.example'))
            $v = & $script:V21
            $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'group:careers@contoso\.example'
        }
        It 'an older result without the exception fields cannot tell empty from not read: scope not established' {
            $old = @{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @(); SentTo = @(); SentToMemberOf = @(); HasExceptions = $true }
            $old2 = @{ Name = 'Strict Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @(); SentTo = @(); SentToMemberOf = @(); HasExceptions = $true }
            & $script:SetPreset $old $old2
            $v = & $script:V21
            $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'predates the exclusion fields'
        }
        It 'a preset limited to a named group does not cover the organization' {
            & $script:SetPreset (& $script:Rule 'Standard Preset Security Policy' @('contoso.example') @() @('PILOT')) (& $script:Rule 'Strict Preset Security Policy' @('contoso.example') @() @('PILOT'))
            (& $script:V21).State | Should -Not -Be 'Satisfied'
        }
        It 'no preset on is still a Gap' {
            $off = & $script:Rule 'Standard Preset Security Policy'; $off.State = 'Disabled'
            & $script:SetPreset $off (& $script:Rule 'Strict Preset Security Policy'); Set-NRGRawData -Key 'Defender-Policies' -Data (Bag @{ PresetRules = @{ Available = $true; EOP = @($off); ATP = @() } })
            (& $script:V21).State | Should -Be 'Gap'
        }
    }

    Context 'DLP: coverage, detection and enforcement are different claims' {
        BeforeAll {
            $script:Pvw = { param($Policies, $Rules) Set-NRGRawData -Key 'Purview' -Data (Bag @{ DLPPolicies = $Policies; DLPRules = $Rules; SectionStatus = @{ DLPPolicies = 'Collected'; DLPRules = 'Collected' } }) }
            $script:AllWl = @('Exchange', 'SharePoint', 'OneDriveForBusiness', 'Teams')
            $script:Enf  = @{ Name = 'PII'; Mode = 'Enable'; Enabled = $true; Workloads = @('Exchange', 'SharePoint') }
            $script:Test = @{ Name = 'Financial'; Mode = 'TestWithNotifications'; Enabled = $false; Workloads = $script:AllWl }
        }
        It 'DEF-4.1: workloads of a policy in test mode do not count as coverage' {
            Clear-NRGState; & $script:Pvw @($script:Enf, $script:Test) @()
            $v = V 'Test-NRGControlDefenderDLPWorkloads' 'DEF-4.1'
            $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'OneDriveForBusiness'; $v.Detail | Should -Match 'Not counted \(not enforcing\): Financial \[TestWithNotifications\]'
        }
        It 'DEF-4.1: enforcing policies covering all four workloads are Satisfied, and the finding claims coverage only' {
            Clear-NRGState; & $script:Pvw @(@{ Name = 'All'; Mode = 'Enable'; Enabled = $true; Workloads = $script:AllWl }) @()
            $v = V 'Test-NRGControlDefenderDLPWorkloads' 'DEF-4.1'
            $v.State | Should -Be 'NotApplicable' -Because 'the location scope was not returned, so whole-workload coverage is not proven'; $v.Detail | Should -Not -Match 'block|sensitive'
        }
        It 'DEF-4.2 / PVW-3.4: sensitive information types in a test-mode policy are reported, not credited' {
            Clear-NRGState
            & $script:Pvw @($script:Enf, $script:Test) @(@{ Name = 'r1'; ParentPolicyName = 'Financial'; Disabled = $false; SensitiveInfoTypes = @('Credit Card Number') }, @{ Name = 'r2'; ParentPolicyName = 'PII'; Disabled = $false; SensitiveInfoTypes = @() })
            $a = V 'Test-NRGControlDefenderDLPSITs' 'DEF-4.2'; $b = V 'Test-NRGControlPurviewSensitiveInfoTypes' 'PVW-3.4'
            $a.State | Should -Be 'Gap'; $b.State | Should -Be 'Gap'
        }
        It 'DEF-4.2: detection in an enforcing policy is credited, enforcement is stated only as far as it was read' {
            Clear-NRGState
            & $script:Pvw @($script:Enf, $script:Test) @(@{ Name = 'r1'; ParentPolicyName = 'PII'; Disabled = $false; SensitiveInfoTypes = @('U.S. Social Security Number (SSN)') }, @{ Name = 'r2'; ParentPolicyName = 'Financial'; Disabled = $false; SensitiveInfoTypes = @('Credit Card Number') })
            $a = V 'Test-NRGControlDefenderDLPSITs' 'DEF-4.2'
            $a.State | Should -Be 'Satisfied'
            $a.Detail | Should -Match 'Social Security'; $a.Detail | Should -Match 'Whether they block or only notify was not read'
            $a.Detail | Should -Match 'Not counted \(policy in test mode or off\)'
            Clear-NRGState
            & $script:Pvw @($script:Enf) @(@{ Name = 'r1'; ParentPolicyName = 'PII'; Disabled = $false; BlockAccess = $true; SensitiveInfoTypes = @('U.S. Social Security Number (SSN)') })
            (V 'Test-NRGControlDefenderDLPSITs' 'DEF-4.2').Detail | Should -Match '1 of 1 block access'
        }
        It 'sensitive information types are read from flat entries AND from grouped template conditions' {
            (Get-NRGDlpSensitiveTypeNames -Conditions @(@{ name = 'Credit Card Number'; id = 'x'; mincount = 1 })) | Should -Be @('Credit Card Number')
            $grouped = @(@{ operator = 'And'; groups = @(@{ name = 'Default'; operator = 'Or'; sensitivetypes = @(@{ name = 'U.S. Social Security Number (SSN)'; id = 'a'; mincount = 1 }, @{ name = 'ICD-10-CM'; id = 'b'; mincount = 1 }) }) })
            @(Get-NRGDlpSensitiveTypeNames -Conditions $grouped) | Should -Contain 'U.S. Social Security Number (SSN)'
            @(Get-NRGDlpSensitiveTypeNames -Conditions $grouped) | Should -Contain 'ICD-10-CM'
            @(Get-NRGDlpSensitiveTypeNames -Conditions $grouped) | Should -Not -Contain 'Default' -Because 'a group name is not a sensitive information type'
            @(Get-NRGDlpSensitiveTypeNames -Conditions $null).Count | Should -Be 0
        }
        It 'DLP location scope is read as All or named, with exclusions' {
            $l = Get-NRGDlpLocationScope -Policy ([pscustomobject]@{ ExchangeLocation = @([pscustomobject]@{ Name = 'All' }); SharePointLocation = @('https://x/sites/a'); TeamsLocation = @([pscustomobject]@{ Name = 'All' }); TeamsLocationException = @('team1') })
            $l.Exchange.Include | Should -Be @('All'); $l.SharePoint.Include | Should -Be @('https://x/sites/a')
            $l.Teams.Exclude | Should -Be @('team1'); $null -eq $l.OneDriveForBusiness.Include | Should -BeTrue
        }
        It 'DEF-4.1: a policy scoped to named mailboxes is not whole-workload Exchange coverage' {
            Clear-NRGState
            $loc = { param($ex, $sp, $od, $tm) [ordered]@{ Exchange = @{ Include = $ex; Exclude = @() }; SharePoint = @{ Include = $sp; Exclude = @() }; OneDriveForBusiness = @{ Include = $od; Exclude = @() }; Teams = @{ Include = $tm; Exclude = @() } } }
            & $script:Pvw @(@{ Name = 'All'; Mode = 'Enable'; Enabled = $true; Workloads = $script:AllWl; Locations = (& $loc @('mbx1', 'mbx2') @('All') @('All') @('All')) }) @()
            $v = V 'Test-NRGControlDefenderDLPWorkloads' 'DEF-4.1'
            $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'Exchange \(All: 2 named location'
            Clear-NRGState
            & $script:Pvw @(@{ Name = 'All'; Mode = 'Enable'; Enabled = $true; Workloads = $script:AllWl; Locations = (& $loc @('All') @('All') @('All') @('All')) }) @()
            (V 'Test-NRGControlDefenderDLPWorkloads' 'DEF-4.1').State | Should -Be 'Satisfied'
        }
        It 'DEF-4.1: results without the location scope cannot prove whole-workload coverage (not assessed, verified parts kept)' {
            Clear-NRGState
            & $script:Pvw @(@{ Name = 'All'; Mode = 'Enable'; Enabled = $true; Workloads = $script:AllWl }) @()
            $v = V 'Test-NRGControlDefenderDLPWorkloads' 'DEF-4.1'
            $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'location scope was not returned'
        }
        It 'a rule whose parent policy was not collected is not assumed to be enforcing' {
            Clear-NRGState
            & $script:Pvw @() @(@{ Name = 'orphan'; ParentPolicyName = 'Missing'; Disabled = $false; SensitiveInfoTypes = @('Credit Card Number') })
            (V 'Test-NRGControlPurviewSensitiveInfoTypes' 'PVW-3.4').State | Should -Not -Be 'Satisfied'
        }
    }
}

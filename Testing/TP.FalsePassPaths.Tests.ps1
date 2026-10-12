#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.FalsePassPaths.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Regression tests for the four unsupported-Satisfied paths found by the
             2026-10-11 review of main at 1f2f790. Fixtures use the raw shapes the
             collectors store, with every identifier replaced by a placeholder.
               1. AAD-1.4 / AAD-1.5 merged the risk levels of every enabled policy whatever
                  its scope: a pilot-group policy, a policy excluding a group, or one
                  applying to no application counted as tenant-wide risk protection, and
                  High from one narrow policy plus Medium from another read as complete.
                  Each required level is now judged on who the policies selecting it
                  protect (Get-TPRiskLevelCoverage).
               2. Get-TPCANarrowing never read Conditions.ClientAppTypes, so a browser-only
                  MFA policy satisfied AAD-1.2 (and AAD-1.3, and the CA view's MFA
                  templates) while every desktop and mobile client went unprompted.
               3. Get-TPCAGrantAlternatives left out GrantControls.CustomControls, so
                  "MFA OR custom control" read as MFA mandatory.
               4. DEF-4.5 passed on any policy listing the Devices location, whatever its
                  Mode and whether it had an enabled rule: a disabled or test-mode
                  Endpoint DLP policy was reported as active protection.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'False-pass paths from the 2026-10-11 review' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        function script:Bag([hashtable] $Data) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-11T00:00:00Z'; Success = $true; Data = $Data } }
        function script:Pol {
            param([string] $Name = 'p', [string] $State = 'enabled', [string[]] $Users = @('All'), [string[]] $Groups = @(), [string[]] $Roles = @(),
                  [string[]] $ExUsers = @(), [string[]] $ExGroups = @(), [string[]] $Apps = @('All'), [string[]] $ExApps = @(),
                  [string[]] $ClientApps = @('all'), [string[]] $Grant = @(), [string] $Op = 'OR', [string[]] $Custom = @(),
                  [string] $StrengthId = '', [string[]] $Combos = @(), [string[]] $SignInRisk = @(), [string[]] $UserRisk = @(), [string[]] $Platforms = @())
            @{ Id = $Name; DisplayName = $Name; State = $State
               Conditions = @{ ClientAppTypes = $ClientApps; SignInRiskLevels = $SignInRisk; UserRiskLevels = $UserRisk; AuthFlows = @(); Platforms = $Platforms; ExcludePlatforms = @()
                               Users = @{ IncludeUsers = $Users; IncludeGroups = $Groups; IncludeRoles = $Roles; ExcludeUsers = $ExUsers; ExcludeGroups = $ExGroups; ExcludeRoles = @() }
                               Applications = @{ Include = $Apps; Exclude = $ExApps; UserActions = @() }
                               Locations = @{ Include = @(); Exclude = @() }; Devices = @{ FilterMode = ''; FilterRule = '' }; ClientApplications = @{ IncludeServicePrincipals = @() } }
               GrantControls = @{ Operator = $Op; BuiltInControls = $Grant; CustomControls = $Custom; AuthStrengthId = $StrengthId; AuthStrengthName = ''; AuthStrengthCombinations = $Combos; TermsOfUse = @() }
               SessionControls = @{} }
        }
        function script:Ca([object[]] $Policies) {
            Clear-TPState
            Set-TPRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($Policies); SectionStatus = @{ TokenProtection = 'Collected'; NamedLocations = 'Collected' } })
            Set-TPRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ SecurityDefaults = @{ IsEnabled = $false } })
        }
        # Two enabled members, $Registered of them MFA-registered (AAD-1.2 reads registration beside enforcement).
        function script:Set-Users([int] $Registered = 2) {
            $u = @(@{ Id = 'u-1'; UserPrincipalName = 'a@corp.example'; AccountEnabled = $true; UserType = 'Member' },
                   @{ Id = 'u-2'; UserPrincipalName = 'b@corp.example'; AccountEnabled = $true; UserType = 'Member' })
            $reg = @(0..1 | ForEach-Object { @{ UserPrincipalName = $u[$_].UserPrincipalName; IsMfaRegistered = ($_ -lt $Registered) } })
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $u; MFARegistration = @{ RegistrationDetails = $reg }; SectionStatus = @{ MFARegistration = 'Collected' } })
        }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0] }
        function script:Baseline([string] $Id) { $v = & $script:Mod { Get-TPConditionalAccessView }; @($v.Baseline | Where-Object { $_.Id -eq $Id })[0] }
        $script:GA = '62e90394-69f5-4237-9190-012177145e10'
        $script:Interactive = @('browser', 'mobileAppsAndDesktopClients')
    }
    AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    Context '3. A custom control is a grant alternative' {
        It 'mfa OR custom control does not require MFA; mfa AND custom control does' {
            # The grant helpers are module-private (the CA view calls them in module scope).
            $alts = { param($p) & $script:Mod { param($x) Get-TPCAGrantAlternatives -Policy $x } $p }
            $requires = { param($p) & $script:Mod { param($x) Test-TPCAGrantRequires -Policy $x -Any @('mfa', 'authStrength') } $p }
            $or = Pol -Grant @('mfa') -Custom @('cc-1') -Op 'OR'
            @((& $alts $or).Controls) | Should -Contain 'customControl'
            (& $alts $or).Operator | Should -Be 'OR'
            & $requires $or | Should -BeFalse -Because 'the custom provider satisfies the grant on its own'
            & $requires (Pol -Grant @('mfa') -Custom @('cc-1') -Op 'AND') | Should -BeTrue
            & $requires (Pol -Grant @('mfa')) | Should -BeTrue -Because 'no custom control: unchanged'
        }
        It 'AAD-1.2: an all-users "MFA or custom control" policy is Partial (MFA is one alternative), never Satisfied' {
            Ca @(Pol -Grant @('mfa') -Custom @('cc-1') -Op 'OR'); Set-Users
            $v = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $v.State | Should -Be 'Partial'
            $v.Detail | Should -Match 'MFA is one alternative \(OR\)'
            Ca @(Pol -Grant @('mfa') -Custom @('cc-1') -Op 'AND'); Set-Users
            (V 'Test-TPControlAADMFA' 'AAD-1.2').State | Should -Be 'Satisfied'
        }
        It 'the Conditional Access view names the custom control and never reads the OR policy as the enforced MFA template' {
            Ca @(Pol -Name 'mfa-or-custom' -Grant @('mfa') -Custom @('cc-1') -Op 'OR')
            $view = & $script:Mod { Get-TPConditionalAccessView }
            @($view.Policies | Where-Object { $_.DisplayName -eq 'mfa-or-custom' })[0].Description | Should -Match 'multifactor authentication or a custom control'
            (Baseline 'mfa-all-users').Status | Should -Not -Be 'Enforced'
        }
    }

    Context '2. A protection has to reach the browser and the mobile and desktop clients' {
        It 'Get-TPCANarrowing: browser-only is narrowed when the interactive types are required; all, both types, an empty list, and no requirement are not' {
            @(Get-TPCANarrowing -Policy (Pol -ClientApps @('browser')) -RequiredClientAppTypes $script:Interactive) | Should -Contain 'limited to some client app types (browser), so mobileAppsAndDesktopClients sign-ins are outside it'
            @(Get-TPCANarrowing -Policy (Pol -ClientApps @('mobileAppsAndDesktopClients')) -RequiredClientAppTypes $script:Interactive).Count | Should -Be 1
            @(Get-TPCANarrowing -Policy (Pol -ClientApps @('all')) -RequiredClientAppTypes $script:Interactive).Count | Should -Be 0
            @(Get-TPCANarrowing -Policy (Pol -ClientApps @('browser', 'mobileAppsAndDesktopClients')) -RequiredClientAppTypes $script:Interactive).Count | Should -Be 0
            @(Get-TPCANarrowing -Policy (Pol -ClientApps @('browser', 'mobileAppsAndDesktopClients', 'other')) -RequiredClientAppTypes $script:Interactive).Count | Should -Be 0
            @(Get-TPCANarrowing -Policy (Pol -ClientApps @()) -RequiredClientAppTypes $script:Interactive).Count | Should -Be 0 -Because 'an empty list is not a read value and is not judged'
            @(Get-TPCANarrowing -Policy (Pol -ClientApps @('browser'))).Count | Should -Be 0 -Because 'nothing required: the legacy block and device-code callers are unchanged'
            @(Get-TPCANarrowing -Policy (Pol -ClientApps @('browser') -SignInRisk @('high')) -RequiredClientAppTypes $script:Interactive -Ignore @('applies only at certain risk levels')) | Should -Not -Contain 'applies only at certain risk levels'
        }
        It 'AAD-1.2: a browser-only all-users MFA policy is not all-user coverage (Partial with every user registered, Gap otherwise), and the detail names the client app types' {
            Ca @(Pol -Name 'browser-mfa' -ClientApps @('browser') -Grant @('mfa')); Set-Users
            $v = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $v.State | Should -Be 'Partial' -Because "registration is verified, enforcement is narrower (got: $($v.Detail))"
            $v.Detail | Should -Match 'limited to some client app types \(browser\)'
            $v.Detail | Should -Not -Match 'Verified: MFA is required for all users'
            Ca @(Pol -Name 'browser-mfa' -ClientApps @('browser') -Grant @('mfa')); Set-Users -Registered 1
            (V 'Test-TPControlAADMFA' 'AAD-1.2').State | Should -Be 'Gap'
            Ca @(Pol -Name 'all-mfa' -ClientApps @('browser', 'mobileAppsAndDesktopClients') -Grant @('mfa')); Set-Users
            (V 'Test-TPControlAADMFA' 'AAD-1.2').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.3: a browser-only phishing-resistant admin policy is a shortfall, never Satisfied' {
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleDefinitions = @(@{ Id = $script:GA; DisplayName = 'Global Administrator'; IsPriv = $true }) })
            $roles = Get-TPRawData -Key 'AAD-DirectoryRoles'
            Ca @(Pol -Name 'admin-fido' -Users @() -Roles @($script:GA) -ClientApps @('browser') -StrengthId '00000000-0000-0000-0000-000000000004' -Combos @('fido2'))
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data $roles
            $v = V 'Test-TPControlAADPhishResistantMFA' 'AAD-1.3'
            $v.State | Should -Be 'Gap' -Because "only a narrower policy delivers it (got: $($v.Detail))"
            $v.Detail | Should -Match 'limited to some client app types'
            Ca @(Pol -Name 'admin-fido' -Users @() -Roles @($script:GA) -StrengthId '00000000-0000-0000-0000-000000000004' -Combos @('fido2'))
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data $roles
            (V 'Test-TPControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.1 is unchanged: the legacy block needs the other client type, not the browser' {
            Ca @(Pol -ClientApps @('exchangeActiveSync', 'other') -Grant @('block'))
            (V 'Test-TPControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Satisfied'
        }
        It 'the Conditional Access view: a browser-only MFA or risk policy is Similar, never Enforced' {
            Ca @(Pol -Name 'browser-mfa' -ClientApps @('browser') -Grant @('mfa'))
            (Baseline 'mfa-all-users').Status | Should -Be 'Similar'
            Ca @(Pol -Name 'all-mfa' -Grant @('mfa'))
            (Baseline 'mfa-all-users').Status | Should -Be 'Enforced'
            Ca @(Pol -Name 'risk' -ClientApps @('browser') -SignInRisk @('high', 'medium') -Grant @('mfa'))
            (Baseline 'sign-in-risk').Status | Should -Be 'Similar'
        }
    }

    Context '1. Risk policies are judged on who they protect, level by level' {
        It 'AAD-1.4: an enabled high+medium policy scoped to one group, to no application, or to one application is a Gap naming the policy' {
            Ca @(Pol -Name 'pilot' -Users @() -Groups @('g-pilot') -SignInRisk @('high', 'medium') -Grant @('mfa'))
            $v = V 'Test-TPControlAADSignInRisk' 'AAD-1.4'
            $v.State | Should -Be 'Gap' -Because "a pilot-group policy is not tenant-wide protection (got: $($v.Detail))"
            $v.Detail | Should -Match "'pilot' also delivers it but applies to only some users, groups or roles"
            Ca @(Pol -Name 'none' -Apps @('None') -SignInRisk @('high', 'medium') -Grant @('mfa'))
            (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Gap'
            Ca @(Pol -Name 'one-app' -Apps @('00000003-0000-0ff1-ce00-000000000000') -SignInRisk @('high', 'medium') -Grant @('mfa'))
            (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Gap'
            Ca @(Pol -Name 'browser' -ClientApps @('browser') -SignInRisk @('high', 'medium') -Grant @('mfa'))
            (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Gap'
        }
        It 'AAD-1.4: a tenant-wide policy excluding a group is Partial and names the exclusion' {
            Ca @(Pol -Name 'risk' -ExGroups @('g-excluded') -SignInRisk @('high', 'medium') -Grant @('mfa'))
            $v = V 'Test-TPControlAADSignInRisk' 'AAD-1.4'
            $v.State | Should -Be 'Partial'
            $v.Detail | Should -Match 'group:g-excluded'
        }
        It 'AAD-1.4: levels are not merged across differently scoped policies; two tenant-wide policies combine' {
            Ca @((Pol -Name 'high-all' -SignInRisk @('high') -Grant @('mfa')), (Pol -Name 'medium-pilot' -Users @() -Groups @('g-pilot') -SignInRisk @('medium') -Grant @('mfa')))
            $v = V 'Test-TPControlAADSignInRisk' 'AAD-1.4'
            $v.State | Should -Be 'Partial' -Because "High is tenant-wide, Medium only for a pilot group (got: $($v.Detail))"
            $v.Detail | Should -Match 'Verified: A responding policy applies to high sign-in risk for all users on all applications by: high-all'
            $v.Detail | Should -Match "Shortfall: .*'medium-pilot' also delivers it but applies to only some users"
            Ca @((Pol -Name 'high-all' -SignInRisk @('high') -Grant @('mfa')), (Pol -Name 'medium-all' -SignInRisk @('medium') -Grant @('block')))
            (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Satisfied'
            Ca @(Pol -Name 'high-only' -SignInRisk @('high') -Grant @('mfa'))
            $h = V 'Test-TPControlAADSignInRisk' 'AAD-1.4'; $h.State | Should -Be 'Partial'; $h.Detail | Should -Match 'No enabled policy responds to medium sign-in risk'
        }
        It 'AAD-1.5: a group-scoped high user-risk policy is a Gap; tenant-wide passes; different exclusions in two policies are not assessed' {
            Ca @(Pol -Name 'pilot' -Users @() -Groups @('g-pilot') -UserRisk @('high') -Grant @('riskRemediation'))
            (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap'
            Ca @(Pol -Name 'all' -UserRisk @('high') -Grant @('riskRemediation'))
            (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied'
            Ca @((Pol -Name 'a' -ExGroups @('g-1') -UserRisk @('high') -Grant @('riskRemediation')), (Pol -Name 'b' -ExGroups @('g-2') -UserRisk @('high') -Grant @('block')))
            $u = V 'Test-TPControlAADUserRisk' 'AAD-1.5'
            $u.State | Should -Be 'NotApplicable' -Because "whether anyone is excluded from both was not resolved (got: $($u.Detail))"
            $u.Detail | Should -Match 'Not assessed: whether any user is excluded from every one of these policies'
            Ca @((Pol -Name 'a' -ExGroups @('g-1') -UserRisk @('high') -Grant @('riskRemediation')), (Pol -Name 'b' -UserRisk @('high') -Grant @('block')))
            (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied' -Because 'the second policy covers everyone the first excludes'
        }
        It 'AAD-1.4 / 1.5: the report-only qualification applies the same client-app rule' {
            Ca @(Pol -Name 'ro' -State 'enabledForReportingButNotEnforced' -ClientApps @('browser') -SignInRisk @('high', 'medium') -Grant @('mfa'))
            $v = V 'Test-TPControlAADSignInRisk' 'AAD-1.4'
            $v.State | Should -Be 'Gap'; $v.Detail | Should -Match 'limited to some client app types'
        }
    }

    Context '4. DEF-4.5 Endpoint DLP: Mode and an enabled rule decide, not the Devices label' {
        BeforeAll {
            function script:Pvw([object[]] $Policies, [object[]] $Rules = @(), [string] $RulesStatus = 'Collected') {
                Clear-TPState
                Set-TPRawData -Key 'Purview' -Data (Bag @{ DLPPolicies = @($Policies); DLPRules = @($Rules); SectionStatus = @{ DLPPolicies = 'Collected'; DLPRules = $RulesStatus } })
            }
            $script:Ep = { param($Mode, $Name = 'Endpoint') @{ Name = $Name; Enabled = ($Mode -eq 'Enable'); Mode = $Mode; Workloads = @('Exchange', 'EndpointDevices') } }
            $script:Rule = { param($Policy, $Disabled = $false, $Block = $true, $Name = 'r') @{ Name = $Name; ParentPolicyName = $Policy; Disabled = $Disabled; BlockAccess = $Block; SensitiveInfoTypes = @('Credit Card Number') } }
        }
        It 'an enforcing policy (Mode Enable) with an enabled rule is Satisfied, with the rule and its action named' {
            Pvw @(& $script:Ep 'Enable') @(& $script:Rule 'Endpoint')
            $v = V 'Test-TPControlDefenderEndpointDLP' 'DEF-4.5'
            $v.State | Should -Be 'Satisfied'
            $v.Detail | Should -Match 'Verified: 1 Endpoint DLP policy in enforcing mode \(Mode Enable\) with 1 enabled rule\(s\).*r \[Endpoint\] \(1 blocks access\)'
        }
        It 'test mode (TestWithNotifications / TestWithoutNotifications) and Disable are a Gap, reported and never credited' {
            foreach ($m in 'TestWithNotifications', 'TestWithoutNotifications', 'Disable', 'PendingDeletion') {
                Pvw @(& $script:Ep $m) @(& $script:Rule 'Endpoint')
                $v = V 'Test-TPControlDefenderEndpointDLP' 'DEF-4.5'
                $v.State | Should -Be 'Gap' -Because "$m enforces nothing (got: $($v.Detail))"
                $v.Detail | Should -Match "Not counted \(not enforcing.*Endpoint \[$m\]"
                $v.Detail | Should -Not -Match 'Verified:'
            }
        }
        It 'an enforcing policy whose rules are all disabled is a Gap' {
            Pvw @(& $script:Ep 'Enable') @((& $script:Rule 'Endpoint' $true), (& $script:Rule 'Endpoint' $true $false 'r2'))
            $v = V 'Test-TPControlDefenderEndpointDLP' 'DEF-4.5'
            $v.State | Should -Be 'Gap'
            $v.Detail | Should -Match 'no enabled rule \(2 disabled\)'
        }
        It 'an enforcing policy whose rules were not collected is not assessed and filed as a collection gap' {
            Pvw @(& $script:Ep 'Enable') @() 'Failed'
            $v = V 'Test-TPControlDefenderEndpointDLP' 'DEF-4.5'
            $v.State | Should -Be 'NotApplicable'
            $v.Detail | Should -Match 'Not assessed: whether the enforcing Endpoint DLP policy \(Endpoint\) has an enabled rule, because DLP rules were not collected'
            @((Get-TPAssessmentScope -Findings @(Get-TPFindings)).CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Contain 'DEF-4.5'
        }
        It 'a Mode that was not read is not assessed, never Satisfied and never a Gap' {
            Pvw @(@{ Name = 'legacy'; Workloads = @('Exchange', 'EndpointDevices') }) @(& $script:Rule 'legacy')
            $v = V 'Test-TPControlDefenderEndpointDLP' 'DEF-4.5'
            $v.State | Should -Be 'NotApplicable'
            $v.Detail | Should -Match 'Not assessed: whether legacy \[mode not read\] enforces'
        }
        It 'an enforcing policy with a live rule beside a test-mode policy is Satisfied, with the test-mode policy noted' {
            Pvw @((& $script:Ep 'Enable'), (& $script:Ep 'TestWithNotifications' 'Pilot')) @(& $script:Rule 'Endpoint')
            $v = V 'Test-TPControlDefenderEndpointDLP' 'DEF-4.5'
            $v.State | Should -Be 'Satisfied'
            $v.Detail | Should -Match 'Not counted \(not enforcing.*Pilot \[TestWithNotifications\]'
        }
        It 'no policy naming the Devices location is a Gap, as before' {
            Pvw @(@{ Name = 'mail'; Mode = 'Enable'; Workloads = @('Exchange') }) @()
            (V 'Test-TPControlDefenderEndpointDLP' 'DEF-4.5').State | Should -Be 'Gap'
        }
    }
}

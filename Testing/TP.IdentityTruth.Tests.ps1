#Requires -Version 7.0
#
# TP.IdentityTruth.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Identity verdicts found false by audit (raw Graph shapes, documented values):
#   - AAD-6.2 read permissionGrantPoliciesAssigned at the top level; Graph
#     nests it under defaultUserRolePermissions, so every tenant — including
#     "users can consent to any app" — scored consent restricted (Critical).
#   - Conditional Access: a pilot-group or EAS-only legacy block passed; an
#     all-users MFA policy did not cover admins; block / riskRemediation risk
#     policies were misses; "compliant OR MFA" counted as requiring a device;
#     a device-code policy that only required MFA passed; a policy NAMED
#     "PAW" passed; a risk-only "every time" re-prompt passed as periodic
#     sign-in frequency; token protection and CAE strict mode never matched.
#   - Roles: activated PIM and break-glass accounts counted as standing
#     access; eligible guests / synced accounts were invisible; a failed
#     roleDefinitions read hid a permanent Global Administrator.
#   - SSPR, break-glass alerting: verdicts from data that answers a different
#     question — now manual review.
#   - Literal NIST ids on AAD-1.2 / AAD-3.1 kept both out of the NIST rollup
#     and the SSP.

Describe 'Identity controls report what the tenant is configured to do' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:GA  = '62e90394-69f5-4237-9190-012177145e10'

        function script:Bag([hashtable] $Data) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $true; Data = $Data } }
        function script:Pol {
            param([string] $Name = 'p', [string] $State = 'enabled', [string[]] $Users = @('All'), [string[]] $Groups = @(), [string[]] $Roles = @(),
                  [string[]] $Apps = @('All'), [string[]] $ClientApps = @('all'), [string[]] $Grant = @(), [string] $Op = 'AND',
                  [string[]] $SignInRisk = @(), [string[]] $UserRisk = @(), [hashtable] $Session = @{}, [string] $DeviceRule = '', $AuthFlows = @())
            @{ DisplayName = $Name; State = $State
               Conditions = @{ ClientAppTypes = $ClientApps; SignInRiskLevels = $SignInRisk; UserRiskLevels = $UserRisk; AuthFlows = @($AuthFlows)
                               Users = @{ IncludeUsers = $Users; IncludeGroups = $Groups; IncludeRoles = $Roles; ExcludeUsers = @(); ExcludeGroups = @() }
                               Applications = @{ Include = $Apps; Exclude = @() }
                               Devices = @{ FilterMode = $(if ($DeviceRule) { 'include' } else { '' }); FilterRule = $DeviceRule }
                               ClientApplications = @{ IncludeServicePrincipals = @() } }
               GrantControls = @{ Operator = $Op; BuiltInControls = $Grant; AuthStrengthId = ''; TermsOfUse = @() }
               SessionControls = $Session }
        }
        function script:Ca([object[]] $Policies) {
            Clear-TPState
            Set-TPRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($Policies); SectionStatus = @{ TokenProtection = 'Collected'; NamedLocations = 'Collected' } })
        }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0] }
    }

    Context 'AAD-6.2 user consent, collected from the documented authorizationPolicy shape' {
        BeforeAll {
            $script:Orig = & $script:Mod { ${function:Invoke-TPGraphRequest} }
            function script:Consent([string] $Assigned) {
                $json = '{"id":"authorizationPolicy","allowInvitesFrom":"adminsAndGuestInviters","allowedToSignUpEmailBasedSubscriptions":false,"allowedToUseSSPR":true,"allowEmailVerifiedUsersToJoinOrganization":false,"blockMsolPowerShell":false,"guestUserRoleId":"2af84b1e-32c8-42b7-82bc-daa82404023b","defaultUserRolePermissions":{"allowedToCreateApps":false,"allowedToCreateSecurityGroups":false,"allowedToCreateTenants":false,"allowedToReadBitlockerKeysForOwnedDevice":true,"allowedToReadOtherUsers":true,"permissionGrantPoliciesAssigned":' + $Assigned + '}}'
                & $script:Mod { param($j) $script:T_Auth = $j | ConvertFrom-Json -AsHashtable
                    Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value {
                        param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                        if ($Uri -match 'authorizationPolicy') { return $script:T_Auth }
                        throw "no route: $Uri" } } $json
                Clear-TPState
                Invoke-TPCollectAADIdentityGovernance 3>$null | Out-Null
                V 'Test-TPControlAADUserConsent' 'AAD-6.2'
            }
        }
        AfterAll { & $script:Mod { param($o) Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $o } $script:Orig }

        It 'any-app user consent is a Gap; none or low-impact verified publishers passes the consent half' {
            (Consent '["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]').State | Should -Be 'Gap'
            # Restricted consent is Satisfied on its own. The admin consent workflow is a different control
            # (AAD-6.3) and cannot be read through this route, which must not change this verdict.
            $low = Consent '["ManagePermissionGrantsForSelf.microsoft-user-default-low"]'
            $low.State | Should -Be 'Satisfied'; $low.Detail | Should -Match 'Verified: User consent is limited to low-impact'
            $none = Consent '[]'
            $none.State | Should -Be 'Satisfied' -Because 'an empty list (no user consent) must not unroll into "not returned"'
            $none.Detail | Should -Match 'Verified: Users cannot consent'
        }
    }

    Context 'Conditional Access' {
        It 'AAD-1.1: a pilot-group legacy block is Partial; an EAS-only block is a Gap; all users on Other clients passes' {
            Ca @(Pol -Users @() -Groups @('g1') -ClientApps @('other','exchangeActiveSync') -Grant @('block')); (V 'Test-TPControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Partial'
            Ca @(Pol -ClientApps @('exchangeActiveSync') -Grant @('block'));                                   (V 'Test-TPControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Gap'
            Ca @(Pol -ClientApps @('other','exchangeActiveSync') -Grant @('block'));                           (V 'Test-TPControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.1: a legacy-auth block whose application scope is None (or one app) blocks nothing and is not credited' {
            Ca @(Pol -Apps @('None') -ClientApps @('exchangeActiveSync','mobileAppsAndDesktopClients','other') -Grant @('block'))
            $v = V 'Test-TPControlAADLegacyAuth' 'AAD-1.1'; $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'applications'
            Ca @(Pol -Apps @('00000003-0000-0ff1-ce00-000000000000') -ClientApps @('other') -Grant @('block'))
            (V 'Test-TPControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Partial'
            Ca (@(Pol -Apps @('None') -ClientApps @('other') -Grant @('block')) + @(Pol -Name 'all' -ClientApps @('other') -Grant @('block')))
            (V 'Test-TPControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.4 / 1.5: report-only is Partial only when the policy meets every scope, risk and grant condition; otherwise Gap; disabled is Gap' {
            $mk = { param($state, $risk, $levels, $grant, $apps = @('All'), $users = @('All'))
                $p = Pol -Name "risk-$state" -State $state -Grant $grant -Users $users
                $p.Conditions.Applications.Include = $apps
                if ($risk -eq 'user') { $p.Conditions.UserRiskLevels = $levels } else { $p.Conditions.SignInRiskLevels = $levels }
                $p }
            # AAD-1.5 user risk
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'user' @('high') @('riskRemediation')))
            $f = V 'Test-TPControlAADUserRisk' 'AAD-1.5'; $f.State | Should -Be 'Partial'; $f.Detail | Should -Match 'report-only mode'; $f.Detail | Should -Match 'still a failed baseline requirement'
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'user' @('low') @('riskRemediation')));            (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap'    # wrong level
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'user' @('high') @('compliantDevice')));         (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap'    # grant does not respond
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'user' @('high') @('riskRemediation') @('00000003-0000-0ff1-ce00-000000000000'))); (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap' # one application only
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'user' @('high') @('riskRemediation') @('All') @()));                                  (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap' # no users
            Ca @((& $mk 'disabled' 'user' @('high') @('riskRemediation')));                                  (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap'    # disabled
            Ca @();                                                                                          $none = V 'Test-TPControlAADUserRisk' 'AAD-1.5'; $none.State | Should -Be 'Gap'; $none.Detail | Should -Not -Match 'Report-only'
            # AAD-1.4 sign-in risk: Microsoft's template selects High and Medium
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'signin' @('high', 'medium') @('mfa')));         $g = V 'Test-TPControlAADSignInRisk' 'AAD-1.4'; $g.State | Should -Be 'Partial'; $g.Detail | Should -Match 'report-only mode'
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'signin' @('high') @('mfa')));                   (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Gap'  # only one level
            Ca @((& $mk 'disabled' 'signin' @('high', 'medium') @('mfa')));                                  (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Gap'
            # an enforced policy still wins over a report-only one
            Ca @((& $mk 'enabled' 'user' @('high') @('riskRemediation')), (& $mk 'enabledForReportingButNotEnforced' 'user' @('high') @('riskRemediation')))
            (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.4 / 1.5: a policy list that could not be proven complete is not assessed, never a Gap; an absent key replays as complete' {
            $incomplete = { param($pols) Clear-TPState; Set-TPRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($pols); SectionStatus = @{ TokenProtection = 'Collected'; NamedLocations = 'Collected'; PolicyCompleteness = 'Failed' } }) }
            & $incomplete @()
            $a = V 'Test-TPControlAADUserRisk' 'AAD-1.5'; $a.State | Should -Be 'NotApplicable'; $a.Detail | Should -Match '^Not assessed: the Conditional Access policy list could not be read in full'
            (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'NotApplicable'
            @((Get-TPAssessmentScope -Findings @(Get-TPFindings)).CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Contain 'AAD-1.5' -Because 'it must be named as a collection gap, not filed as an advisory'
            # an enforced qualifying policy is still a pass: the missing policies cannot make it worse
            $ok = Pol -Name 'u' -Grant @('riskRemediation'); $ok.Conditions.UserRiskLevels = @('high')
            & $incomplete @($ok)
            (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied'
            Ca @()
            (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap' -Because 'results collected before the beta merge have no PolicyCompleteness and replay unchanged'
        }
        It 'AAD-1.4 / 1.5: blocking and risk-remediation responses count' {
            Ca @(Pol -SignInRisk @('high', 'medium') -Grant @('block'));   (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Satisfied'
            Ca @(Pol -UserRisk @('high') -Grant @('riskRemediation'));     (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied'
        }
        # A policy applies only to the risk levels it selects. Microsoft's
        # templates select High and Medium (sign-in) and High (user); a
        # low-only policy used to score Satisfied on both controls.
        It 'AAD-1.4 / 1.5: only the risk levels Microsoft''s templates select count' {
            Ca @(Pol -SignInRisk @('low') -Grant @('mfa'));    (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Gap'
            Ca @(Pol -SignInRisk @('high') -Grant @('mfa'));   (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Partial'
            $f = V 'Test-TPControlAADSignInRisk' 'AAD-1.4';   $f.Detail | Should -Match 'medium-risk sign-in is let through'
            Ca @(Pol -SignInRisk @('medium') -Grant @('mfa')); (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Partial'
            Ca @((Pol -SignInRisk @('high') -Grant @('block')), (Pol -SignInRisk @('medium') -Grant @('mfa')))
            (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Satisfied' -Because 'levels combine across the enabled policies'
            Ca @(Pol -UserRisk @('low', 'medium') -Grant @('passwordChange')); (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap'
            Ca @(Pol -UserRisk @('medium', 'high') -Grant @('passwordChange')); (V 'Test-TPControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied'
        }
        It 'AAD-2.3: "compliant OR MFA" does not enforce a device' {
            Ca @(Pol -Grant @('compliantDevice','domainJoinedDevice','mfa') -Op 'OR'); (V 'Test-TPControlAADDeviceComplianceCA' 'AAD-2.3').State | Should -Be 'Partial'
            Ca @(Pol -Grant @('compliantDevice','domainJoinedDevice') -Op 'OR');       (V 'Test-TPControlAADDeviceComplianceCA' 'AAD-2.3').State | Should -Be 'Satisfied'
        }
        It 'AAD-11.1: a device-code policy must block, not only require MFA' {
            $flow = @{ transferMethods = 'deviceCodeFlow' }
            Ca @(Pol -AuthFlows $flow -Grant @('mfa'));   (V 'Test-TPControlAADDeviceCode' 'AAD-11.1').State | Should -Be 'Gap'
            Ca @(Pol -AuthFlows $flow -Grant @('block')); (V 'Test-TPControlAADDeviceCode' 'AAD-11.1').State | Should -Be 'Satisfied'
        }
        It 'AAD-11.7: judged on configuration, not on a policy name containing "PAW"' {
            $roles = { Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleDefinitions = @(@{ Id = $script:GA; DisplayName = 'Global Administrator'; IsPriv = $true }) }) }
            Ca @(Pol -Name 'Block legacy auth (PAW accounts excluded)' -ClientApps @('other') -Grant @('block')); & $roles; (V 'Test-TPControlAADPrivilegedWorkstation' 'AAD-11.7').State | Should -Be 'Gap'
            # One half (compliant device) is Partial; both halves (Microsoft's PAW check) are needed for Satisfied.
            Ca @(Pol -Users @() -Roles @($script:GA) -Grant @('compliantDevice'));                              & $roles; (V 'Test-TPControlAADPrivilegedWorkstation' 'AAD-11.7').State | Should -Be 'Partial'
            $paw = Pol -Name 'PAW only' -Users @() -Roles @($script:GA) -Grant @('block') -DeviceRule 'device.extensionAttribute1 -eq "PAW"'
            $paw.Conditions.Devices.FilterMode = 'exclude'
            Ca @((Pol -Users @() -Roles @($script:GA) -Grant @('compliantDevice')), $paw);                    & $roles; (V 'Test-TPControlAADPrivilegedWorkstation' 'AAD-11.7').State | Should -Be 'Satisfied'
        }
        It 'AAD-10.4: a risk-only "every time" re-prompt is not a periodic sign-in frequency' {
            Ca @(Pol -SignInRisk @('high') -Grant @('mfa') -Session @{ SignInFrequency = @{ IsEnabled = $true; FrequencyInterval = 'everyTime' } })
            (V 'Test-TPControlAADSignInFrequency' 'AAD-10.4').State | Should -Be 'Gap'
        }
        It 'AAD-11.4 / 11.5: token protection and CAE strict mode read their real values' {
            $tp = Pol -Session @{ SecureSignInSession = $true }; $tp.Conditions.Platforms = @('windows')
            Ca @($tp);                                                              (V 'Test-TPControlAADTokenProtection' 'AAD-11.4').State | Should -Be 'Satisfied'
            Ca @(Pol -Session @{ ContinuousAccessEvaluation = 'strictEnforcement' }); (V 'Test-TPControlAADContinuousAccess' 'AAD-11.5').State | Should -Be 'Satisfied'
        }
    }

    Context 'roles' {
        BeforeAll {
            function script:Asg([string] $Id, [string] $Name, [string] $Upn, $Synced = $null, [string] $Role = $script:GA) {
                @{ PrincipalId = $Id; PrincipalDisplayName = $Name; PrincipalUPN = $Upn; PrincipalType = '#microsoft.graph.user'
                   RoleDefinitionId = $Role; RoleDefinitionName = 'Global Administrator'; IsPriv = $true; OnPremisesSyncEnabled = $Synced }
            }
        }
        It 'AAD-3.2: an activated PIM assignment and CA-excluded break-glass accounts are not standing access' {
            Clear-TPState
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1' 'bg1@x.onmicrosoft.com'), (Asg 'bg2' 'BG2' 'bg2@x.onmicrosoft.com'), (Asg 'alice' 'Alice' 'alice@x.com')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-TPRawData -Key 'AAD-PIMSchedules' -Data (Bag @{ EligibleSchedules = @('e1'); ActiveSchedules = @(@{ PrincipalId = 'alice'; RoleDefinitionId = $script:GA; AssignmentType = 'Activated' }); SectionStatus = @{ EligibleSchedules = 'Collected' } })
            Set-TPRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ BreakGlassIndicators = @(@{ PrincipalId = 'bg1'; CAExcluded = $true; Synced = $false }, @{ PrincipalId = 'bg2'; CAExcluded = $true; Synced = $false }) })
            (V 'Test-TPControlAADNoPermanentAdmins' 'AAD-3.2').State | Should -Be 'Satisfied'
        }
        It 'AAD-11.2 / 10.2: an ELIGIBLE guest or synced Global Administrator counts' {
            Clear-TPState
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'a' 'A' 'a@x.com')); PrivRoles = @((Asg 'a' 'A' 'a@x.com'))
                AllPrivilegedAssignments = @((Asg 'g' 'Guest' 'g_msp.com#EXT#@x.onmicrosoft.com'), (Asg 'b' 'Bob' 'bob@x.com' $true)); SectionStatus = @{ RoleAssignments = 'Collected' } })
            (V 'Test-TPControlAADNoGuestInPrivRoles' 'AAD-11.2').State | Should -Be 'Gap'
            (V 'Test-TPControlAADPrivCloudOnly' 'AAD-10.2').State      | Should -Be 'Gap'
        }
        It 'the collector names privileged built-in roles by template id when roleDefinitions fails' {
            $src = Get-Content -Raw (Join-Path $script:RepoRoot 'Collectors/AAD/Invoke-TPCollectAADRoles.ps1')
            $src | Should -Match "'62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'"
            ([regex]::Matches($src, '\$privRoleTemplates\[')).Count | Should -BeGreaterOrEqual 2
        }
    }

    Context 'controls whose data answers a different question are manual review' {
        It 'AAD-5.1, AAD-5.2 and AAD-10.3 never pass or fail from unrelated data' {
            Clear-TPState
            Set-TPRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ AuthorizationPolicy = @{ AllowedToUseSSPR = $true }; SectionStatus = @{ AuthorizationPolicy = 'Collected' } })
            Set-TPRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ SSPRPolicy = @{ MethodsConfigured = @(@{ State = 'enabled' }, @{ State = 'enabled' }) }; BreakGlassIndicators = @(@{ PrincipalId = 'a'; CAExcluded = $true }, @{ PrincipalId = 'b'; CAExcluded = $true }) })
            foreach ($p in @(@('Test-TPControlAADSSPR','AAD-5.1'), @('Test-TPControlAADSSPRMethods','AAD-5.2'), @('Test-TPControlAADBreakGlassMonitoring','AAD-10.3'))) {
                $f = V $p[0] $p[1]
                $f.State  | Should -Be 'NotApplicable' -Because $p[1]
                $f.Detail | Should -Match 'requires manual verification'
            }
        }
    }

    Context 'authentication methods' {
        It 'AAD-9.1 is enforced by the platform and never scored, whatever the retired property says; AAD-9.2 counts Authenticator phone sign-in' {
            # Graph v1.0 no longer defines numberMatchingRequiredState, so the read is always empty; the
            # old evaluator mapped empty to "default" and scored Satisfied from nothing on every tenant.
            foreach ($state in @('', 'enabled', 'disabled')) {
                Clear-TPState
                Set-TPRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ AuthMethodsPolicy = @{ AuthenticationMethodConfigs = @(@{ Id = 'Fido2'; State = 'disabled' }, @{ Id = 'MicrosoftAuthenticator'; State = 'enabled'; AuthenticationModes = @('any'); FeatureSettings = @{ NumberMatchingRequiredState = $state; AdditionalContextFeatureState = '' } }) }; SectionStatus = @{ AuthMethodsPolicy = 'Collected' } })
                $f = V 'Test-TPControlAADAuthenticatorNumberMatch' 'AAD-9.1'
                $f.State  | Should -Be 'NotApplicable' -Because "state '$state' is not a tenant setting"
                $f.Detail | Should -Match 'Enforced by the platform'
                @($f.FrameworkIds).Count | Should -BeGreaterThan 0
                (V 'Test-TPControlAADPasswordless' 'AAD-9.2').State | Should -Be 'Satisfied'
            }
        }
    }

    It 'no evaluator passes literal framework ids (they bypass the NIST: prefix the rollups parse)' {
        $hits = Get-ChildItem (Join-Path $script:RepoRoot 'Evaluators') -Filter *.ps1 | Select-String -Pattern "-FrameworkIds @\('"
        @($hits | ForEach-Object { "$($_.Filename):$($_.LineNumber)" }) | Should -BeNullOrEmpty
    }
}

Describe 'Not configured is a Gap, not half credit; no data is not a verdict' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        function script:V { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
    }
    BeforeEach { Clear-TPState }
    AfterAll   { Clear-TPState }

    It 'the default Guest User role (Microsoft''s default, nothing configured) is a Gap, not Partial' {
        Set-TPRawData -Key 'AAD-IdentityGovernance' -Data @{ Success = $true; Data = @{ ExternalCollab = @{ GuestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3' } } }
        (V 'Test-TPControlAADGuestPermissions' 'AAD-4.3').State | Should -Be 'Gap'
        # The three ids Microsoft documents: a0b1b346 is the default (limited access), 10dae51f
        # is the same access as members, 2af84b1e is Restricted; a fourth is not judged.
        Clear-TPState
        Set-TPRawData -Key 'AAD-IdentityGovernance' -Data @{ Success = $true; Data = @{ ExternalCollab = @{ GuestUserRoleId = 'a0b1b346-4d3e-4e8b-98f8-753987be4970' } } }
        $g = V 'Test-TPControlAADGuestPermissions' 'AAD-4.3'
        $g.State  | Should -Be 'Gap'
        $g.Detail | Should -Match 'default Guest User role'
        $g.Detail | Should -Not -Match 'may have'
        Clear-TPState
        Set-TPRawData -Key 'AAD-IdentityGovernance' -Data @{ Success = $true; Data = @{ ExternalCollab = @{ GuestUserRoleId = 'ffffffff-ffff-ffff-ffff-ffffffffffff' } } }
        (V 'Test-TPControlAADGuestPermissions' 'AAD-4.3').State | Should -Be 'NotApplicable'
    }
    It 'CAE strict mode not enforced (the default) is a Gap, not Partial' {
        Set-TPRawData -Key 'AAD-CAPolicies' -Data @{ Success = $true; Data = @{ Policies = @() } }
        (V 'Test-TPControlAADContinuousAccess' 'AAD-11.5').State | Should -Be 'Gap'
    }
    It 'cross-tenant access settings that were not returned are not assessed (was: Partial, half credit for no data)' {
        Set-TPRawData -Key 'AAD-AuthPolicies' -Data @{ Success = $true; Data = @{ CrossTenantAccess = $null; SectionStatus = @{ CrossTenantAccess = 'Collected' } } }
        $f = @(& { Test-TPControlAADCrossTenantAccess | Out-Null; Get-TPFindings | Where-Object { $_.ControlId -eq 'AAD-11.6' } })
        $f.Count | Should -Be 1
        $f[0].State | Should -Be 'NotApplicable'
    }
}

# While Security Defaults is enabled, Microsoft lets Conditional Access
# policies be created but not turned on, so the CA list is empty or holds only
# policies that cannot take effect. Every CA control read that as a tenant with
# nothing protecting it: "no CA policy blocks legacy authentication" (Critical)
# while Security Defaults blocked it, "no MFA for admins" while 16 admin roles
# did MFA at every sign-in, "no emergency access path" on every Security
# Defaults tenant, and a report-only policy that could never be switched on
# earned half credit. Security Defaults is read in one place
# (Get-TPSecurityDefaultsState); a state that was not read changes nothing.
Describe 'Security Defaults: Conditional Access controls account for it' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:GA  = '62e90394-69f5-4237-9190-012177145e10'

        function script:Bag([hashtable] $Data, [bool] $Success = $true) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $Success; Data = $Data } }
        # Raw collector shape. $null omits SecurityDefaults (the sub-read failed).
        function script:Set-SD($Value) {
            $d = @{}
            if ($null -ne $Value) { $d.SecurityDefaults = @{ IsEnabled = $Value } }
            Set-TPRawData -Key 'AAD-AuthPolicies' -Data (Bag $d)
        }
        function script:Set-CA([object[]] $Policies = @(), [bool] $Success = $true, [object[]] $Locations = @(), [hashtable] $Status = @{ NamedLocations = 'Collected'; TokenProtection = 'Collected' }) {
            Set-TPRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($Policies); NamedLocations = @($Locations); SectionStatus = $Status } $Success)
        }
        # The policy shape Invoke-TPCollectAADCAPolicies stores.
        function script:New-Pol {
            param([string] $Name = 'p', [string] $State = 'enabled', [string[]] $Users = @('All'), [string[]] $Roles = @(),
                  [string[]] $ClientApps = @('all'), [string[]] $Grant = @(), [string] $Op = 'AND', [string] $Strength = '',
                  [hashtable] $Session = @{}, $AuthFlows = @())
            @{ Id = [guid]::NewGuid().ToString(); DisplayName = $Name; State = $State
               Conditions = @{ ClientAppTypes = $ClientApps; SignInRiskLevels = @(); UserRiskLevels = @(); AuthFlows = @($AuthFlows)
                               Users = @{ IncludeUsers = $Users; IncludeGroups = @(); IncludeRoles = $Roles; ExcludeUsers = @(); ExcludeGroups = @() }
                               Applications = @{ Include = @('All'); Exclude = @() }
                               Devices = @{ FilterMode = ''; FilterRule = '' }
                               ClientApplications = @{ IncludeServicePrincipals = @() } }
               GrantControls = @{ Operator = $Op; BuiltInControls = $Grant; AuthStrengthId = $Strength; TermsOfUse = @() }
               SessionControls = $Session }
        }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-TPFindings | Where-Object ControlId -eq $Cid)[-1] }
        function script:Asg([string] $Id, [string] $Name, [string] $Role = 'Global Administrator', [string] $RoleId = $script:GA, $Synced = $null) {
            @{ PrincipalId = $Id; PrincipalDisplayName = $Name; PrincipalUPN = "$Id@x.onmicrosoft.com"; PrincipalType = '#microsoft.graph.user'
               RoleDefinitionId = $RoleId; RoleDefinitionName = $Role; IsPriv = $true; OnPremisesSyncEnabled = $Synced }
        }
        # Swaps Invoke-TPGraphRequest inside the module (the only way to
        # intercept a call made from a collector) and restores it afterwards.
        $script:OrigGraph = & $script:Mod { ${function:Invoke-TPGraphRequest} }
        function script:Set-Graph([scriptblock] $Body) {
            & $script:Mod { param($b) Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $b } $Body
        }
    }

    BeforeEach { Clear-TPState }
    AfterEach  { & $script:Mod { param($o) Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $o } $script:OrigGraph }
    AfterAll   { Clear-TPState }

    Context 'the one reader' {
        It 'Get-TPSecurityDefaultsState returns $true/$false only for a boolean read from a successful AAD-AuthPolicies, $null otherwise' {
            $read = { param($auth) & (Get-Module TenantPosture) { param($a) Get-TPSecurityDefaultsState -AuthPolicies $a } $auth }
            $null -eq (& $read $null) | Should -BeTrue -Because 'no key'
            $null -eq (& $read (Bag @{ SecurityDefaults = @{ IsEnabled = $true } } $false)) | Should -BeTrue -Because 'Success is false'
            $null -eq (& $read (Bag @{ SecurityDefaults = $null })) | Should -BeTrue -Because 'the sub-read failed'
            $null -eq (& $read (Bag @{ SecurityDefaults = @{ IsEnabled = $null } })) | Should -BeTrue -Because 'IsEnabled null is not read, never disabled'
            $null -eq (& $read (Bag @{ SecurityDefaults = @{ IsEnabled = 'true' } })) | Should -BeTrue -Because 'a string is not a boolean'
            $null -eq (& $read (Bag @{ SecurityDefaults = @{ IsEnabled = 1 } })) | Should -BeTrue -Because 'a number is not a boolean'
            $replayed = (Bag @{ SecurityDefaults = @{ IsEnabled = $true } }) | ConvertTo-Json -Depth 5 | ConvertFrom-Json
            (& $read $replayed) | Should -BeExactly $true -Because 'replayed results JSON carries a real boolean'
            (& $read (Bag @{ SecurityDefaults = @{ IsEnabled = $false } })) | Should -BeExactly $false
            # With no argument it reads module state, and never throws without it.
            & (Get-Module TenantPosture) { $null -eq (Get-TPSecurityDefaultsState) } | Should -BeTrue
            Set-SD $true
            & (Get-Module TenantPosture) { Get-TPSecurityDefaultsState } | Should -BeExactly $true
            # Internal to the module: the export lists (and the README's count) do not change.
            Get-Command -Module TenantPosture -Name 'Get-TPSecurityDefaultsState', 'Add-TPSecurityDefaultsFinding', 'Test-TPSecurityDefaultsLicenseFree',
                'Test-TPSecurityDefaultsUnresolved', 'Add-TPSecurityDefaultsUnreadFinding', 'Get-TPFindingRemediation', 'Test-TPSecurityDefaultsVerdictDetail' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It 'Security Defaults is read in one place, and every value it returns is compared with -eq $true / -eq $false, never tested for truthiness' {
            $evals = Get-ChildItem (Join-Path $script:RepoRoot 'Evaluators') -Filter *.ps1
            @($evals | Select-String -Pattern 'SecurityDefaults\.IsEnabled').Count | Should -Be 0
            $L = [System.Management.Automation.Language.TokenKind]
            # A comparison with a literal $true/$false on the other side.
            $isBoolCompare = {
                param($bin, $side)
                if ($bin -isnot [System.Management.Automation.Language.BinaryExpressionAst]) { return $false }
                if ($bin.Operator -notin @($L::Ieq, $L::Ine, $L::Ceq, $L::Cne)) { return $false }
                $other = if ([object]::ReferenceEquals($bin.Left, $side)) { $bin.Right } else { $bin.Left }
                return ($other -is [System.Management.Automation.Language.VariableExpressionAst]) -and ($other.VariablePath.UserPath -in @('true', 'false'))
            }
            $sites = 0
            foreach ($f in $evals) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-TPSecurityDefaultsState' }, $true))
                foreach ($call in $calls) {
                    $sites++
                    $where = "$($f.Name):$($call.Extent.StartLineNumber)"
                    $pipe = $call.Parent
                    $pipe | Should -BeOfType [System.Management.Automation.Language.PipelineAst] -Because $where
                    $holder = $pipe.Parent
                    if ($holder -is [System.Management.Automation.Language.ParenExpressionAst]) {
                        # (Get-TPSecurityDefaultsState) -eq $true
                        (& $isBoolCompare $holder.Parent $holder) | Should -BeTrue -Because "$where must compare the state with -eq `$true / -eq `$false"
                    } elseif ($holder -is [System.Management.Automation.Language.AssignmentStatementAst]) {
                        # $x = Get-TPSecurityDefaultsState ...: every later read of $x compares it.
                        $name = $holder.Left.VariablePath.UserPath
                        $fn = $holder.Parent
                        while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
                        $reads = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq $name -and -not [object]::ReferenceEquals($n, $holder.Left) }, $true))
                        $reads.Count | Should -BeGreaterThan 0 -Because $where
                        foreach ($r in $reads) {
                            (& $isBoolCompare $r.Parent $r) | Should -BeTrue -Because "`$$name ($where) is read at line $($r.Extent.StartLineNumber) without -eq `$true / -eq `$false"
                        }
                    } else {
                        throw "$where uses Get-TPSecurityDefaultsState in an unrecognized position: $($holder.GetType().Name)"
                    }
                }
            }
            $sites | Should -BeGreaterOrEqual 20 -Because 'the check must have found the call sites (guards against a vacuous pass)'
        }
    }

    Context 'collectors' {
        It 'the AuthPolicies collector records a response without a boolean isEnabled as not read, never disabled' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'identitySecurityDefaultsEnforcementPolicy') { return @{ isEnabled = $null } }
                return @{ value = @() }
            }
            Invoke-TPCollectAADAuthPolicies 3>$null | Out-Null
            $sdData = (Get-TPRawData -Key 'AAD-AuthPolicies').Data.SecurityDefaults
            $sdData | Should -Not -BeNullOrEmpty -Because 'the endpoint answered'
            $sdData.ContainsKey('IsEnabled') | Should -BeTrue
            ($null -eq $sdData['IsEnabled']) | Should -BeTrue -Because 'a null isEnabled used to cast to $false ("disabled")'
            @(Get-TPExceptions | Where-Object Source -eq 'AAD-SecurityDefaults').Count | Should -BeGreaterThan 0

            Clear-TPState
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'identitySecurityDefaultsEnforcementPolicy') { return @{ isEnabled = $true } }
                return @{ value = @() }
            }
            Invoke-TPCollectAADAuthPolicies 3>$null | Out-Null
            (Get-TPRawData -Key 'AAD-AuthPolicies').Data.SecurityDefaults.IsEnabled | Should -BeExactly $true
        }

        It 'the Users collector records a premium-license refusal of the registration report, and nothing for any other failure' {
            foreach ($case in @(
                    @{ Msg = 'Neither tenant is B2C or tenant doesn''t have premium license'; Expect = 'PremiumLicenseRequired' },
                    @{ Msg = 'Graph 403 Forbidden: insufficient privileges'; Expect = $null })) {
                Clear-TPState
                $script:RegMsg = $case.Msg
                Set-Graph {
                    param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                    if ($Uri -match 'userRegistrationDetails') { throw $script:RegMsg }
                    # Every property the collector $selects (Graph returns a selected property as null, not absent).
                    return @{ value = @(@{ id = 'u1'; displayName = 'A'; userPrincipalName = 'a@corp.example'; accountEnabled = $true; userType = 'Member'
                                           onPremisesSyncEnabled = $null; assignedLicenses = @(); createdDateTime = '2026-01-01T00:00:00Z'; lastPasswordChangeDateTime = '2026-01-01T00:00:00Z' }) }
                }
                & $script:Mod { param($m) $script:RegMsg = $m } $case.Msg
                Invoke-TPCollectAADUsers 3>$null | Out-Null
                $raw = Get-TPRawData -Key 'AAD-Users'
                Get-TPNestedProperty -Object $raw -Path 'Data.SectionStatus.MFARegistration' | Should -Be 'Failed'
                $got = Get-TPNestedProperty -Object $raw -Path 'Data.MFARegistrationFailure' -Default $null
                if ($null -eq $case.Expect) { $got | Should -BeNullOrEmpty } else { $got | Should -Be $case.Expect }
            }
        }

        It 'the inventory collector re-reads guests and members without signInActivity when Graph refuses it for lack of Entra ID P1, and AAD-12.2 / 12.3 say license, not failure' {
            Clear-TPState
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'signInActivity') { throw "Neither tenant is B2C or tenant doesn't have premium license" }
                # Two rows each: one row cannot tell a list of one from a list nested as one.
                if ($Uri -match "userType eq 'Guest'") { return @{ value = @(
                    @{ id = 'g1'; displayName = 'Guest One'; userPrincipalName = 'g1_x#EXT#@corp.example'; accountEnabled = $true; userType = 'Guest'; createdDateTime = '2024-01-01T00:00:00Z' },
                    @{ id = 'g2'; displayName = 'Guest Two'; userPrincipalName = 'g2_x#EXT#@corp.example'; accountEnabled = $true; userType = 'Guest'; createdDateTime = '2024-01-01T00:00:00Z' }) } }
                if ($Uri -match "userType eq 'Member'") { return @{ value = @(
                    @{ id = 'u1'; displayName = 'A'; userPrincipalName = 'a@corp.example'; accountEnabled = $true; createdDateTime = '2024-01-01T00:00:00Z'; assignedLicenses = @(@{ skuId = 'x' }) },
                    @{ id = 'u2'; displayName = 'B'; userPrincipalName = 'b@corp.example'; accountEnabled = $true; createdDateTime = '2024-01-01T00:00:00Z'; assignedLicenses = @(@{ skuId = 'x' }) }) } }
                return @{ value = @() }
            }
            Invoke-TPCollectAADInventory 3>$null | Out-Null
            $raw = Get-TPRawData -Key 'AAD-Inventory'
            $raw.Data.SignInActivityLicensed | Should -BeFalse
            $raw.Data.SectionStatus.GuestUsers | Should -Be 'Collected'
            $raw.Data.SectionStatus.StaleMembers | Should -Be 'Collected'
            @($raw.Data.GuestUsers).Count | Should -Be 2 -Because 'the guest list itself does not need the license'
            @($raw.Data.GuestUsers)[0].DisplayName | Should -Be 'Guest One'
            @($raw.Data.GuestUsers)[1].UPN | Should -Be 'g2_x#EXT#@corp.example'
            @($raw.Data.GuestUsers)[0].IsStale | Should -BeNullOrEmpty -Because 'no sign-in data: neither stale nor fresh'
            @($raw.Data.StaleMembers).Count | Should -Be 0
            $f = V 'Test-TPControlInventoryStaleGuests' 'AAD-12.2'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'Entra ID P1'; $f.Detail | Should -Match 'upgrade opportunity'; $f.Detail | Should -Match '2 guest account'
            $g = V 'Test-TPControlInventoryStaleMembers' 'AAD-12.3'
            $g.State | Should -Be 'NotApplicable'; $g.Detail | Should -Match 'upgrade opportunity'
            @(Get-TPExceptions | Where-Object { $_.Message -match 'requires Microsoft Entra ID P1 or P2' }).Count | Should -Be 2
        }
        It 'any other failure of the sign-in read still fails the section and the controls stay "did not complete"' {
            Clear-TPState
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'signInActivity') { throw 'Graph 403 Forbidden: insufficient privileges' }
                return @{ value = @() }
            }
            Invoke-TPCollectAADInventory 3>$null | Out-Null
            $raw = Get-TPRawData -Key 'AAD-Inventory'
            $raw.Data.SignInActivityLicensed | Should -BeTrue
            $raw.Data.SectionStatus.GuestUsers | Should -Be 'Failed'
            (V 'Test-TPControlInventoryStaleGuests' 'AAD-12.2').State | Should -Be 'NotApplicable'
        }
        It 'an empty guest and member list (the smoke-run shape) is Collected with zero rows and records no exception' {
            Clear-TPState
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                return @{ value = @() }
            }
            Invoke-TPCollectAADInventory 3>$null | Out-Null
            $raw = Get-TPRawData -Key 'AAD-Inventory'
            $raw.Data.SectionStatus.GuestUsers | Should -Be 'Collected'
            $raw.Data.SectionStatus.StaleMembers | Should -Be 'Collected'
            @($raw.Data.GuestUsers).Count | Should -Be 0
            @($raw.Data.StaleMembers).Count | Should -Be 0
            @(Get-TPExceptions | Where-Object { $_.Source -in @('AAD-GuestInventory', 'AAD-StaleAccounts') }).Count | Should -Be 0 -Because 'an empty list returned as one nested row threw on .displayName under StrictMode'
        }
        It 'with the license the reads carry signInActivity and the controls judge staleness as before' {
            Clear-TPState
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match "userType eq 'Guest'") { $Uri | Should -Match 'signInActivity'; return @{ value = @(
                    @{ id = 'g1'; displayName = 'Guest One'; userPrincipalName = 'g1_x#EXT#@corp.example'; accountEnabled = $true; userType = 'Guest'; createdDateTime = '2024-01-01T00:00:00Z'; signInActivity = @{ lastSignInDateTime = '2024-02-01T00:00:00Z' } },
                    @{ id = 'g2'; displayName = 'Guest Two'; userPrincipalName = 'g2_x#EXT#@corp.example'; accountEnabled = $true; userType = 'Guest'; createdDateTime = '2024-01-01T00:00:00Z'; signInActivity = @{ lastSignInDateTime = [datetime]::UtcNow.AddDays(-1).ToString('o'); lastSuccessfulSignInDateTime = [datetime]::UtcNow.AddDays(-1).ToString('o') } }) } }
                return @{ value = @() }
            }
            Invoke-TPCollectAADInventory 3>$null | Out-Null
            $raw = Get-TPRawData -Key 'AAD-Inventory'
            $raw.Data.SignInActivityLicensed | Should -BeTrue
            @($raw.Data.GuestUsers).Count | Should -Be 2
            @($raw.Data.GuestUsers)[0].DisplayName | Should -Be 'Guest One'
            @($raw.Data.GuestUsers)[1].IsStale | Should -BeFalse
            @($raw.Data.GuestUsers)[0].IsStale | Should -BeTrue
            (V 'Test-TPControlInventoryStaleGuests' 'AAD-12.2').State | Should -Be 'Gap'
        }
        It 'the Users collector records each user''s assigned subscription ids (AssignedSkuIds) beside the count' {
            Clear-TPState
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'userRegistrationDetails') { return @{ value = @() } }
                return @{ value = @(
                    @{ id = 'u1'; displayName = 'A'; userPrincipalName = 'a@corp.example'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $null
                       assignedLicenses = @(@{ skuId = '06ebc4ee-1bb5-47dd-8e1b-7f71b5a2d2e3'; disabledPlans = @() }, @{ skuId = 'f8a1db68-be16-40ed-86d5-cb42ce701560'; disabledPlans = @() })
                       createdDateTime = '2026-01-01T00:00:00Z'; lastPasswordChangeDateTime = '2026-01-01T00:00:00Z' },
                    @{ id = 'u2'; displayName = 'B'; userPrincipalName = 'b@corp.example'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $null
                       assignedLicenses = @(); createdDateTime = '2026-01-01T00:00:00Z'; lastPasswordChangeDateTime = '2026-01-01T00:00:00Z' }) }
            }
            Invoke-TPCollectAADUsers 3>$null | Out-Null
            $users = @((Get-TPRawData -Key 'AAD-Users').Data.Users)
            @($users[0].AssignedSkuIds) | Should -Be @('06ebc4ee-1bb5-47dd-8e1b-7f71b5a2d2e3', 'f8a1db68-be16-40ed-86d5-cb42ce701560')
            $users[0].LicenseCount | Should -Be 2
            @($users[1].AssignedSkuIds).Count | Should -Be 0
        }

        It 'the Conditional Access collector says Security Defaults is on in its console note, within the 70-character console line, and says nothing when it was not read' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                return @{ value = @() }
            }
            Set-SD $true
            Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            $cov = (Get-TPCoverage)['AAD-CAPolicies']
            $cov.Status | Should -Be 'Collected'
            $cov.Note   | Should -Match '^Security Defaults on: CA policies cannot be turned on \(0 found\)$'
            $cov.Note.Length | Should -BeLessOrEqual 70

            Clear-TPState
            Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            (Get-TPCoverage)['AAD-CAPolicies'].Note | Should -Be '' -Because 'a Security Defaults state that was not read changes nothing'
        }

        It 'a policy only the beta list returns is kept, flagged and readable by AAD-1.5 (the v1.0 list returned 15 where the beta list returned 17)' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                $a = @{ id = 'p1'; displayName = 'All users MFA'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') } }; grantControls = @{ operator = 'OR'; builtInControls = @('mfa') } }
                $b = @{ id = 'p2'; displayName = 'CA-IDP-001-UserRisk-High-RequireRiskRemediation'; state = 'enabledForReportingButNotEnforced'
                        conditions = @{ userRiskLevels = @('high'); users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') } }
                        grantControls = @{ operator = 'OR'; builtInControls = @('riskRemediation') } }
                if ($Uri -match 'v1\.0/identity/conditionalAccess/policies') { return @{ value = @($a) } }
                if ($Uri -match 'beta/identity/conditionalAccess/policies') { return @{ value = @($a, $b) } }
                return @{ value = @() }
            }
            Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            $raw = Get-TPRawData -Key 'AAD-CAPolicies'
            @($raw.Data.Policies).Count | Should -Be 2
            @($raw.Data.PoliciesOnlyInBeta) | Should -Be @('CA-IDP-001-UserRisk-High-RequireRiskRemediation')
            $raw.Data.SectionStatus.PolicyCompleteness | Should -Be 'Collected'
            $extra = @($raw.Data.Policies | Where-Object { $_.Id -eq 'p2' })[0]
            $extra.State | Should -Be 'enabledForReportingButNotEnforced'
            @($extra.Conditions.UserRiskLevels) | Should -Be @('high')
            @($extra.GrantControls.BuiltInControls) | Should -Be @('riskRemediation')
        }

        It 'when the beta list cannot be read the v1.0 policies stay and the list is marked not proven complete' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'beta/identity') { throw 'Graph beta 403' }
                return @{ value = @(@{ id = 'p1'; displayName = 'All users MFA'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') } }; grantControls = @{ builtInControls = @('mfa') } }) }
            }
            Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            $raw = Get-TPRawData -Key 'AAD-CAPolicies'
            $raw.Success | Should -BeTrue
            @($raw.Data.Policies).Count | Should -Be 1
            $raw.Data.SectionStatus.PolicyCompleteness | Should -Be 'Failed'
        }

        It 'when the CA read fails on a Security Defaults tenant the Failed note still says so' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'v1\.0/identity/conditionalAccess/policies') { throw 'Graph 403' }
                return @{ value = @() }
            }
            Set-SD $true
            Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            $cov = (Get-TPCoverage)['AAD-CAPolicies']
            $cov.Status | Should -Be 'Failed'
            $cov.Note   | Should -Match 'Security Defaults is on'
            ('failed: ' + $cov.Note).Length | Should -BeLessOrEqual 70
            (Get-TPRawData -Key 'AAD-CAPolicies').Success | Should -BeFalse
        }
    }

    Context 'protections Security Defaults provides' {
        It 'AAD-1.1: Security Defaults on is Satisfied through Security Defaults; the same CA data with Security Defaults disabled is still the Gap' {
            Set-CA @(); Set-SD $true
            $f = V 'Test-TPControlAADLegacyAuth' 'AAD-1.1'
            $f.State    | Should -Be 'Satisfied'
            $f.Severity | Should -Be 'Informational'
            $f.Detail   | Should -Match '^Security Defaults is enabled\.'
            $f.Detail   | Should -Match 'Exchange ActiveSync basic authentication'
            (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
            Clear-TPState; Set-CA @(); Set-SD $false
            $g = V 'Test-TPControlAADLegacyAuth' 'AAD-1.1'
            $g.State  | Should -Be 'Gap'
            $g.Detail | Should -Match 'No Conditional Access policy found that blocks legacy authentication'
        }

        It 'AAD-1.1: Security Defaults on stays Satisfied when the Conditional Access read failed' {
            Set-CA @() -Success $false; Set-SD $true
            (V 'Test-TPControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Satisfied'
        }

        It 'AAD-1.1: a report-only legacy block beside Security Defaults earns no half credit and is named, never "nothing is blocked"' {
            Set-CA @(New-Pol -Name 'CA01 Block legacy' -State 'enabledForReportingButNotEnforced' -ClientApps @('other') -Grant @('block')); Set-SD $true
            $f = V 'Test-TPControlAADLegacyAuth' 'AAD-1.1'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'CA01 Block legacy \[report-only\]'
            $f.Detail | Should -Not -Match 'nothing is blocked'
        }

        It 'AAD-11.1: Security Defaults on is Satisfied — device code flow is blocked by Security Defaults' {
            Set-CA @(); Set-SD $true
            $f = V 'Test-TPControlAADDeviceCode' 'AAD-11.1'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'device code flow are blocked'
        }

        It 'AAD-1.3: Security Defaults on is Partial (Medium) for standard admin MFA at every sign-in, never the Critical Gap' {
            Set-CA @(); Set-SD $true
            $f = V 'Test-TPControlAADPhishResistantMFA' 'AAD-1.3'
            $f.State       | Should -Be 'Partial'
            $f.Severity    | Should -Be 'Medium'
            $f.Detail      | Should -Match 'every sign-in'
            $f.Detail      | Should -Match 'phishing-resistant'
            $f.Remediation | Should -Match 'turn off Security Defaults'
        }

        It 'Security Defaults on while the Conditional Access read lists a policy as On is not assessed and never credited (AAD-1.3, AAD-11.1, AAD-10.4)' {
            Set-SD $true
            Set-CA @(
                (New-Pol -Name 'Admins phishing-resistant' -Users @() -Roles @($script:GA) -Strength '00000000-0000-0000-0000-000000000004'),
                (New-Pol -Name 'Block device code' -AuthFlows @{ transferMethods = 'deviceCodeFlow' } -Grant @('block')),
                (New-Pol -Name 'Sign-in frequency' -Grant @('mfa') -Session @{ SignInFrequency = @{ IsEnabled = $true; FrequencyInterval = 'timeBased'; Value = 12; Type = 'hours' } }))
            foreach ($p in @(@('Test-TPControlAADPhishResistantMFA','AAD-1.3'), @('Test-TPControlAADDeviceCode','AAD-11.1'), @('Test-TPControlAADSignInFrequency','AAD-10.4'))) {
                $f = V $p[0] $p[1]
                $f.State  | Should -Be 'NotApplicable' -Because $p[1]
                $f.Detail | Should -Match 'not assessed'
                (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
            }
        }
    }

    Context 'capabilities only Conditional Access provides' {
        It 'AAD-2.1: Security Defaults on is a Gap that names what Security Defaults provides and never says password-only; read as disabled it says disabled' {
            Set-CA @(); Set-SD $true
            $f = V 'Test-TPControlAADCA' 'AAD-2.1'
            $f.State       | Should -Be 'Gap'
            $f.Detail      | Should -Match 'AAD-1\.1'
            $f.Detail      | Should -Match 'cannot be turned on'
            $f.Detail      | Should -Not -Match 'password-only'
            $f.Remediation | Should -Not -Match 'report-only mode first'
            Clear-TPState; Set-CA @(); Set-SD $false
            $g = V 'Test-TPControlAADCA' 'AAD-2.1'
            $g.Detail | Should -Match 'Security Defaults is disabled'
            $g.Detail | Should -Not -Match 'relies on Security Defaults'
        }

        It 'AAD-2.2: under Security Defaults none defined is still the Gap (licensed but not configured); defined locations earn no credit; not read is not assessed' {
            Set-CA @(); Set-SD $true
            $g = V 'Test-TPControlAADNamedLocations' 'AAD-2.2'
            $g.State       | Should -Be 'Gap' -Because 'with Security Defaults off the same data is a Gap; license gating, not this evaluator, handles an unlicensed tenant'
            $g.Detail      | Should -Match '^Security Defaults is enabled\. No named locations are defined\.'
            $g.Remediation | Should -Match 'turn off Security Defaults'
            (@($g.FrameworkIds) -join ' ') | Should -Match 'NIST:'
            Clear-TPState; Set-CA @(); Set-SD $false
            (V 'Test-TPControlAADNamedLocations' 'AAD-2.2').State | Should -Be 'Gap'

            Clear-TPState; Set-CA @() -Locations @(@{ DisplayName = 'Office'; IsTrusted = $true }); Set-SD $true
            $f = V 'Test-TPControlAADNamedLocations' 'AAD-2.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '1 marked trusted'
            $f.Detail | Should -Match 'earn no credit'
            (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'

            foreach ($unread in @({ Set-CA @() -Status @{ NamedLocations = 'Failed'; TokenProtection = 'Collected' } }, { Set-CA @() -Success $false })) {
                Clear-TPState; & $unread; Set-SD $true
                $n = V 'Test-TPControlAADNamedLocations' 'AAD-2.2'
                $n.State  | Should -Be 'NotApplicable'
                $n.Detail | Should -Match 'not collected'
            }
        }

        It 'AAD-11.4: Security Defaults on is a Gap even when the beta token-protection read failed' {
            Set-CA @() -Status @{ NamedLocations = 'Collected'; TokenProtection = 'Failed' }; Set-SD $true
            (V 'Test-TPControlAADTokenProtection' 'AAD-11.4').State | Should -Be 'Gap'
        }

        It 'AAD-1.4, AAD-1.5, AAD-10.1, AAD-11.5 under Security Defaults stay Gaps and name it; AAD-1.4 no longer says "let through without a challenge"' {
            Set-CA @(); Set-SD $true
            foreach ($p in @(@('Test-TPControlAADSignInRisk','AAD-1.4'), @('Test-TPControlAADUserRisk','AAD-1.5'), @('Test-TPControlAADIdentityProtection','AAD-10.1'), @('Test-TPControlAADContinuousAccess','AAD-11.5'))) {
                $f = V $p[0] $p[1]
                $f.State  | Should -Be 'Gap' -Because $p[1]
                $f.Detail | Should -Match 'Security Defaults is enabled' -Because $p[1]
                if ($p[1] -eq 'AAD-1.4') { $f.Detail | Should -Not -Match 'without a challenge' }
            }
        }

        It 'AAD-2.3 and INT-1.2: a report-only compliant-device policy beside Security Defaults is a Gap for both, not Partial' {
            Set-CA @(New-Pol -Name 'Require compliant device' -State 'enabledForReportingButNotEnforced' -Grant @('compliantDevice')); Set-SD $true
            Set-TPRawData -Key 'Intune-DeviceCompliance' -Data (Bag @{})
            $d = V 'Test-TPControlAADDeviceComplianceCA' 'AAD-2.3'
            $d.State  | Should -Be 'Gap'
            # Microsoft: users are prompted "based on factors such as location,
            # device, role, and task", so the prompts DO consider the device;
            # what Security Defaults lacks is a device requirement.
            $d.Detail | Should -Not -Match 'do not check the device'
            $d.Detail | Should -Match 'do not require the device to be compliant, managed or hybrid-joined'
            $i = V 'Test-TPControlIntune' 'INT-1.2'
            $i.State  | Should -Be 'Gap'
            $i.Detail | Should -Match 'Security Defaults'
        }
    }

    Context 'break-glass and standing access' {
        It 'AAD-7.2: Security Defaults on requires manual verification, never the no-break-glass Gap; with Security Defaults disabled the same data is still the Gap' {
            $gov = Bag @{ BreakGlassIndicators = @(@{ PrincipalId = 'ga1'; DisplayName = 'GA1'; CAExcluded = $false; Synced = $false }, @{ PrincipalId = 'ga2'; DisplayName = 'GA2'; CAExcluded = $false; Synced = $false }); SectionStatus = @{ BreakGlassIndicators = 'Collected' } }
            Set-TPRawData -Key 'AAD-IdentityGovernance' -Data $gov; Set-SD $true
            $f = V 'Test-TPControlAADBreakGlass' 'AAD-7.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'emergency access'
            $f.Detail | Should -Match 'requires manual verification'
            $f.Detail | Should -Match 'directory synchronization accounts' -Because 'Microsoft excludes them automatically, so "no account can be excluded" is overstated'
            $f.Detail | Should -Not -Match 'no account can be excluded from it[,.]'
            $f.Detail | Should -Not -Match 'If CA policies break'
            (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
            Clear-TPState; Set-TPRawData -Key 'AAD-IdentityGovernance' -Data $gov; Set-SD $false
            (V 'Test-TPControlAADBreakGlass' 'AAD-7.2').State | Should -Be 'Gap'
        }

        It 'AAD-7.2: drives the real AAD-IdentityGovernance collector on a Security Defaults tenant and still reports not applicable' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                return @{ value = @() }
            }
            # The Roles collector's shape: permanent assignments plus the
            # permanent-and-eligible pool the break-glass check reads.
            $gas = @((Asg 'ga1' 'GA1'), (Asg 'ga2' 'GA2'))
            $pool = @($gas | ForEach-Object { $c = @{} + $_; $c.Source = 'permanent'; $c })
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = $gas; AllPrivilegedAssignments = $pool; SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-CA @(); Set-SD $true
            Invoke-TPCollectAADIdentityGovernance 3>$null | Out-Null
            Get-TPNestedProperty -Object (Get-TPRawData -Key 'AAD-IdentityGovernance') -Path 'Data.SectionStatus.BreakGlassIndicators' | Should -Be 'Collected' -Because 'the collector must reach the exclusion check, which writes CAExcluded = $false for both'
            $f = V 'Test-TPControlAADBreakGlass' 'AAD-7.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '2 permanent Global Administrator assignment\(s\) are on accounts not marked as synchronized'
            $f.Detail | Should -Match 'requires manual verification'
            $f.CurrentValue | Should -Match 'GA1, GA2'
        }

        # First live run on the owner's tenant: the break-glass account was
        # excluded from every policy that can block sign-in, but SharePoint's
        # app-enforced restrictions policy (session control only, no grant)
        # reached it, so AAD-7.2 said "no emergency access path".
        It 'AAD-7.2: every enabled policy counts (a session-only one too); an account excluded from every grant policy is a named candidate, not a pass' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                return @{ value = @() }
            }
            $gas = @((Asg 'bg1' 'BG1'), (Asg 'bg2' 'BG2'), (Asg 'adm' 'Admin'))
            $pool = @($gas | ForEach-Object { $c = @{} + $_; $c.Source = 'permanent'; $c })
            $roles = { Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = $gas; AllPrivilegedAssignments = $pool; SectionStatus = @{ RoleAssignments = 'Collected' } }) }
            $session = New-Pol -Name 'SharePoint app-enforced restrictions' -Session @{ ApplicationEnforcedRestrictions = $true }
            $block = New-Pol -Name 'Block legacy' -ClientApps @('other') -Grant @('block'); $block.Conditions.Users.ExcludeUsers = @('bg1', 'bg2')

            # 1. Excluded from the block policy, reached by the session-only one: candidates, Partial, the policy named.
            & $roles; Set-CA @($session, $block); Set-SD $false
            Invoke-TPCollectAADIdentityGovernance 3>$null | Out-Null
            $f = V 'Test-TPControlAADBreakGlass' 'AAD-7.2'
            $f.State  | Should -Be 'Partial' -Because 'Microsoft: exclude emergency access accounts from policies that block OR RESTRICT sign-in'
            $f.Detail | Should -Match "BG1 \(bg1@x\.onmicrosoft\.com\) is excluded from every policy with a grant control but is still reached by 'SharePoint app-enforced restrictions'"
            $f.Detail | Should -Match 'BG2 \(bg2@x\.onmicrosoft\.com\)'
            $f.CurrentValue | Should -Match '2 candidate break-glass account'

            # 2. Excluded from that policy too: Satisfied.
            Clear-TPState
            $session.Conditions.Users.ExcludeUsers = @('bg1', 'bg2')
            & $roles; Set-CA @($session, $block); Set-SD $false
            Invoke-TPCollectAADIdentityGovernance 3>$null | Out-Null
            (V 'Test-TPControlAADBreakGlass' 'AAD-7.2').State | Should -Be 'Satisfied'

            # 3. A report-only policy enforces nothing and is not counted.
            Clear-TPState
            $staged = New-Pol -Name 'Staged MFA' -State 'enabledForReportingButNotEnforced' -Grant @('mfa')
            & $roles; Set-CA @($session, $block, $staged); Set-SD $false
            Invoke-TPCollectAADIdentityGovernance 3>$null | Out-Null
            (V 'Test-TPControlAADBreakGlass' 'AAD-7.2').State | Should -Be 'Satisfied'

            # 4. One account fully excluded; the other still reached by a grant policy: Partial, the policy named.
            Clear-TPState
            $mfa = New-Pol -Name 'Require MFA all users' -Grant @('mfa'); $mfa.Conditions.Users.ExcludeUsers = @('bg1')
            & $roles; Set-CA @($session, $block, $mfa); Set-SD $false
            Invoke-TPCollectAADIdentityGovernance 3>$null | Out-Null
            $f = V 'Test-TPControlAADBreakGlass' 'AAD-7.2'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match "BG2 \(bg2@x\.onmicrosoft\.com\) is still reached by 'Require MFA all users'"
            $f.Detail | Should -Not -Match 'is excluded from every policy with a grant control' -Because 'BG2 is reached by a grant policy, so it is not a candidate'
        }

        It 'AAD-7.2: results collected before the candidate fields replay unchanged' {
            $gov = Bag @{ BreakGlassIndicators = @(@{ PrincipalId = 'bg1'; DisplayName = 'BG1'; UPN = 'bg1@x'; CAExcluded = $false; Synced = $false }) }
            Set-TPRawData -Key 'AAD-IdentityGovernance' -Data $gov
            Set-SD $false
            $f = V 'Test-TPControlAADBreakGlass' 'AAD-7.2'
            $f.State | Should -Be 'Gap'
        }

        It 'AAD-3.2: under Security Defaults a stale CAExcluded=$true is not credited — two permanent cloud-only Global Administrators beside PIM-eligible assignments are not applicable, and a permanent Exchange Administrator is still a Gap that says none was set aside' {
            $pim = Bag @{ EligibleSchedules = @('e1'); ActiveSchedules = @(); SectionStatus = @{ EligibleSchedules = 'Collected' } }
            $gov = Bag @{ BreakGlassIndicators = @(@{ PrincipalId = 'bg1'; CAExcluded = $true; Synced = $false }, @{ PrincipalId = 'bg2'; CAExcluded = $true; Synced = $false }) }
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1'), (Asg 'bg2' 'BG2')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-TPRawData -Key 'AAD-PIMSchedules' -Data $pim
            Set-TPRawData -Key 'AAD-IdentityGovernance' -Data $gov
            Set-SD $true
            $f = V 'Test-TPControlAADNoPermanentAdmins' 'AAD-3.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Not -Match 'BG1|BG2' -Because 'account names go in CurrentValue only'
            $f.Detail | Should -Match 'requires manual verification'
            $f.Detail | Should -Match 'not marked as synchronized from on-premises' -Because 'a $null OnPremisesSyncEnabled is what was read, not proof of cloud-only'
            $f.Detail | Should -Match 'directory synchronization accounts'

            Clear-TPState
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1'), (Asg 'bg2' 'BG2'), (Asg 'ex1' 'Ex Admin' 'Exchange Administrator' '29232cdf-9323-42fd-ade2-1d097af3e4de')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-TPRawData -Key 'AAD-PIMSchedules' -Data $pim
            Set-TPRawData -Key 'AAD-IdentityGovernance' -Data $gov
            Set-SD $true
            $g = V 'Test-TPControlAADNoPermanentAdmins' 'AAD-3.2'
            $g.State  | Should -Be 'Gap'
            $g.Detail | Should -Match 'none was set aside'
            $g.Detail | Should -Match '^Security Defaults is enabled\. 3 permanent' -Because 'the two Global Administrators are not set aside beside Security Defaults'
            (@($g.FrameworkIds) -join ' ') | Should -Match 'NIST:'
        }

        It 'AAD-3.2: Security Defaults on while the Conditional Access read lists a policy as On is not assessed, never a Security Defaults verdict' {
            $pim = Bag @{ EligibleSchedules = @('e1'); ActiveSchedules = @(); SectionStatus = @{ EligibleSchedules = 'Collected' } }
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1'), (Asg 'ex1' 'Ex Admin' 'Exchange Administrator' '29232cdf-9323-42fd-ade2-1d097af3e4de')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-TPRawData -Key 'AAD-PIMSchedules' -Data $pim
            Set-TPRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ BreakGlassIndicators = @(@{ PrincipalId = 'bg1'; CAExcluded = $true; Synced = $false }) })
            Set-CA @(New-Pol -Name 'MFA all users' -Grant @('mfa')); Set-SD $true
            $f = V 'Test-TPControlAADNoPermanentAdmins' 'AAD-3.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'not assessed'
            $f.Detail | Should -Not -Match 'none was set aside'
        }
    }

    Context 'controls outside Entra ID that depend on Conditional Access' {
        # Microsoft: "Blocking or limiting access on unmanaged devices relies
        # on Microsoft Entra Conditional Access policies"; none can be on
        # beside Security Defaults, so the SharePoint setting is not credited.
        It 'SPO-1.5: a restricting unmanaged-device setting beside Security Defaults is a Gap naming it, never Satisfied; not read, it passes as before' {
            $ts = @{ IsLegacyAuthProtocolsEnabled = $false; IsUnmanagedSyncAppForTenantRestricted = $false; SharingCapability = 'externalUserAndGuestSharing'; AllowedDomainGuidsForSyncApp = @(); DeletedUserPersonalSiteRetentionPeriodInDays = 365 }
            foreach ($cap in 'AllowLimitedAccess', 'BlockAccess', 'AuthenticationContext', 'AllowFullAccess') {
                Clear-TPState
                Set-TPRawData -Key 'SharePoint' -Data (Bag @{ TenantSettings = $ts; TenantSettingsSPO = @{ ConditionalAccessPolicy = $cap }; ExternalSharing = $ts.SharingCapability })
                Set-SD $true
                $f = V 'Test-TPControlSharePoint' 'SPO-1.5'
                $f.State       | Should -Be 'Gap' -Because $cap
                $f.Detail      | Should -Match '^Security Defaults is enabled\.' -Because $cap
                $f.Detail      | Should -Match 'relies on Microsoft Entra Conditional Access policies' -Because $cap
                $f.Remediation | Should -Match 'turn off Security Defaults' -Because $cap
                (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
            }
            foreach ($sd in @($null, $false)) {
                Clear-TPState
                Set-TPRawData -Key 'SharePoint' -Data (Bag @{ TenantSettings = $ts; TenantSettingsSPO = @{ ConditionalAccessPolicy = 'AllowLimitedAccess' }; ExternalSharing = $ts.SharingCapability })
                Set-SD $sd
                (V 'Test-TPControlSharePoint' 'SPO-1.5').State | Should -Be 'Satisfied' -Because "Security Defaults read as '$sd'"
            }
        }
    }

    Context 'definitions match the verdicts' {
        # Security Defaults prompts ordinary users only when Microsoft decides
        # it is necessary; only 16 administrator roles do MFA at every sign-in.
        # The definition AAD-1.2 is scored against must say that, or a
        # Satisfied under Security Defaults contradicts its own detail.
        It 'AAD-1.2''s definition does not claim Security Defaults requires MFA of every user at every sign-in' {
            $c = @(Get-TPControlDefinitions | Where-Object ControlId -eq 'AAD-1.2')[0]
            $c.Description | Should -Not -Match 'Security Defaults requires MFA for all users on every sign-in'
            $c.Description | Should -Match 'when Microsoft decides it is necessary'
            $c.Description | Should -Match '16 administrator roles'
        }
    }

    Context 'reporting' {
        It 'AAD-3.2 and AAD-7.2 under Security Defaults are filed for manual review and reach the questionnaire; AAD-2.2 with unusable locations does not apply; none is license gated' {
            Set-SD $true
            Set-CA @() -Locations @(@{ DisplayName = 'Office'; IsTrusted = $true })
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1'), (Asg 'bg2' 'BG2')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-TPRawData -Key 'AAD-PIMSchedules' -Data (Bag @{ EligibleSchedules = @('e1'); ActiveSchedules = @(); SectionStatus = @{ EligibleSchedules = 'Collected' } })
            Set-TPRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ BreakGlassIndicators = @(
                @{ PrincipalId = 'bg1'; DisplayName = 'BG1'; CAExcluded = $false; Synced = $false; Source = 'permanent' },
                @{ PrincipalId = 'bg2'; DisplayName = 'BG2'; CAExcluded = $false; Synced = $false; Source = 'permanent' }); SectionStatus = @{ BreakGlassIndicators = 'Collected' } })
            foreach ($fn in 'Test-TPControlAADNamedLocations', 'Test-TPControlAADNoPermanentAdmins', 'Test-TPControlAADBreakGlass') { & $fn 3>$null | Out-Null }
            $scope = Get-TPAssessmentScope -Findings (Get-TPFindings) -RawData (Get-TPRawData)
            # Emergency access accounts apply to every tenant; the tool cannot
            # identify them beside Security Defaults. "Checked and not
            # applicable to this tenant" would be false.
            foreach ($cid in 'AAD-3.2', 'AAD-7.2') {
                @($scope.NoProgrammaticCheck   | ForEach-Object ControlId) | Should -Contain $cid
                @($scope.NotApplicableToTenant | ForEach-Object ControlId) | Should -Not -Contain $cid
                @($scope.CollectionIncomplete  | ForEach-Object ControlId) | Should -Not -Contain $cid
                @($scope.LicenceBlocked        | ForEach-Object ControlId) | Should -Not -Contain $cid
            }
            $items = @(Get-TPManualReviewItems -Scope $scope)
            $asked = @($items | ForEach-Object { $_['ControlId'] })
            $asked | Should -Contain 'AAD-3.2'
            $asked | Should -Contain 'AAD-7.2'
            # The question is the Description verbatim: beside Security Defaults
            # a CA exclusion has no effect, so it must say what to confirm then.
            $q = @($items | Where-Object { $_['ControlId'] -eq 'AAD-7.2' })[0]['Question']
            $q | Should -Match 'While Security Defaults is enabled'
            $q | Should -Match 'confirmed to exist'
            # Both controls ran their automated check; the limitation must not
            # say they have none.
            $lim = @($scope.Limitations | Where-Object { $_ -match 'manual review' })[0]
            $lim | Should -Match 'could not reach a verdict'
            @($scope.NotApplicableToTenant | ForEach-Object ControlId) | Should -Contain 'AAD-2.2'
            @($scope.LicenceBlocked        | ForEach-Object ControlId) | Should -Not -Contain 'AAD-2.2'
        }

        # Set-TPLicenseGating never moves a Satisfied, so asserting AAD-1.1 /
        # AAD-11.1 stay Satisfied after gating proved nothing. What the
        # exemption decides is the per-finding license answer every consumer
        # asks; assert that directly, both ways.
        It 'on a Business Standard tenant with Security Defaults, AAD-1.1 and AAD-11.1 findings need no license; the gated AAD-1.3 keeps the Security Defaults reason' {
            Set-CA @(); Set-SD $true
            foreach ($fn in 'Test-TPControlAADLegacyAuth', 'Test-TPControlAADDeviceCode', 'Test-TPControlAADPhishResistantMFA') { & $fn 3>$null | Out-Null }
            $prof = Get-TPTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','INTUNE_O365','TEAMS1','SHAREPOINTSTANDARD','RMS_S_BASIC') })
            $byId = @{}; foreach ($f in Get-TPFindings) { $byId[$f.ControlId] = $f }
            foreach ($cid in 'AAD-1.1', 'AAD-11.1') {
                Test-TPLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId $cid -Finding $byId[$cid] | Should -BeTrue -Because "$cid is met by Security Defaults, which needs no license"
                Test-TPLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId $cid | Should -BeFalse -Because 'without the finding the Conditional Access requirement applies'
            }
            Test-TPLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId 'AAD-1.3' -Finding $byId['AAD-1.3'] | Should -BeFalse -Because 'phishing-resistant MFA needs Conditional Access'
            $null = Set-TPLicenseGating -LicenseProfile $prof
            $byId = @{}; foreach ($f in Get-TPFindings) { $byId[$f.ControlId] = $f }
            $byId['AAD-1.3'].State  | Should -Be 'NotApplicable'
            $byId['AAD-1.3'].Detail | Should -Match 'upgrade opportunity'
            $byId['AAD-1.3'].Detail | Should -Match 'Security Defaults is enabled'
        }

        # Security Defaults is free, yet AAD-1.2's requirement string names
        # Entra ID P1 (the Conditional Access route). Gating the Security
        # Defaults shortfall said "requires ... P1, upgrade opportunity" when
        # the fix is a registration campaign, while the all-registered pass
        # stayed scored: the pass counted and the shortfall never did.
        It 'AAD-1.2 through Security Defaults on a Business Standard tenant: a registration shortfall stays a scored Partial, and registration not collected is a collection gap, not license gated' {
            $prof = Get-TPTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','INTUNE_O365','TEAMS1','SHAREPOINTSTANDARD','RMS_S_BASIC') })
            $users = @(@{ UserPrincipalName = 'a@corp.example'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' }, @{ UserPrincipalName = 'b@corp.example'; DisplayName = 'B'; AccountEnabled = $true; UserType = 'Member' })
            $reg = @(@{ UserPrincipalName = 'a@corp.example'; IsMfaRegistered = $true }, @{ UserPrincipalName = 'b@corp.example'; IsMfaRegistered = $false })
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = $reg }; SectionStatus = @{ MFARegistration = 'Collected' } })
            Set-CA @(); Set-SD $true
            & 'Test-TPControlAADMFA' 3>$null | Out-Null
            $null = Set-TPLicenseGating -LicenseProfile $prof
            $f = @(Get-TPFindings | Where-Object ControlId -eq 'AAD-1.2')[0]
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Not -Match 'upgrade opportunity'
            Test-TPLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId 'AAD-1.2' -Finding $f | Should -BeTrue
            Test-TPLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId 'AAD-1.2' | Should -BeFalse -Because 'without the finding the Conditional Access requirement still applies'

            # The CA-path AAD-1.2 on the same tenant is still gated.
            Clear-TPState
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = $reg }; SectionStatus = @{ MFARegistration = 'Collected' } })
            Set-CA @(); Set-SD $false
            & 'Test-TPControlAADMFA' 3>$null | Out-Null
            $null = Set-TPLicenseGating -LicenseProfile $prof
            $c = @(Get-TPFindings | Where-Object ControlId -eq 'AAD-1.2')[0]
            $c.State  | Should -Be 'NotApplicable'
            $c.Detail | Should -Match 'upgrade opportunity'

            Clear-TPState
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = @() }; SectionStatus = @{ MFARegistration = 'Failed' } })
            Set-CA @(); Set-SD $true
            & 'Test-TPControlAADMFA' 3>$null | Out-Null
            $null = Set-TPLicenseGating -LicenseProfile $prof
            $scope = Get-TPAssessmentScope -Findings (Get-TPFindings) -RawData (Get-TPRawData) -LicenseProfile $prof
            @($scope.CollectionIncomplete | ForEach-Object ControlId) | Should -Contain 'AAD-1.2'
            @($scope.LicenceBlocked       | ForEach-Object ControlId) | Should -Not -Contain 'AAD-1.2'
        }

        It 'AAD-1.2 through Security Defaults says the registration report needs Entra ID P1 or P2, and says re-running will not help only when Graph refused it for that reason' {
            $users = @(@{ UserPrincipalName = 'a@corp.example'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' })
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = @() }; MFARegistrationFailure = 'PremiumLicenseRequired'; SectionStatus = @{ MFARegistration = 'Failed' } })
            Set-CA @(); Set-SD $true
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'P1 or P2'
            $f.Detail | Should -Match 'Re-running will not change this'
            $f.Detail | Should -Match 'not collected'
            (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'

            Clear-TPState
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = @() }; SectionStatus = @{ MFARegistration = 'Failed' } })
            Set-CA @(); Set-SD $true
            $g = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $g.Detail | Should -Match 'P1 or P2'
            $g.Detail | Should -Not -Match 'Re-running will not change this' -Because 'the failure was not the license refusal'
        }

        It 'AAD-1.2 through Security Defaults with no enabled members is not applicable and carries its citations' {
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = @(); MFARegistration = @{ RegistrationDetails = @() }; SectionStatus = @{ MFARegistration = 'Collected' } })
            Set-CA @(); Set-SD $true
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'NotApplicable'
            (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
        }
    }

    # $null means "not read", never "disabled". Microsoft documents that no
    # Conditional Access policy can be turned on while Security Defaults is
    # enabled, so a CA read with a policy On proves it is off and the CA
    # logic stands. With no policy On it may be either, and a control whose
    # verdict differs between the two (AAD-1.1, AAD-11.1, AAD-1.3, AAD-1.2)
    # scored the Gap — "Device code authentication flow is not blocked" on a
    # tenant whose Security Defaults may be blocking it.
    Context 'Security Defaults not read' {
        BeforeAll {
            $script:SdPairs = @(@('Test-TPControlAADLegacyAuth','AAD-1.1'), @('Test-TPControlAADDeviceCode','AAD-11.1'), @('Test-TPControlAADPhishResistantMFA','AAD-1.3'))
            $script:BSProf = { Get-TPTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','INTUNE_O365','TEAMS1','SHAREPOINTSTANDARD','RMS_S_BASIC') }) }
        }

        It 'AAD-1.1, AAD-11.1 and AAD-1.3 with the state not read and no CA policy On are not assessed, with citations, never the Gap that assumes it is off' {
            foreach ($pols in @(@(), @(New-Pol -Name 'Pilot MFA' -State 'enabledForReportingButNotEnforced' -Grant @('mfa')))) {
                foreach ($p in $script:SdPairs) {
                    Clear-TPState; Set-CA $pols; Set-SD $null
                    $f = V $p[0] $p[1]
                    $f.State  | Should -Be 'NotApplicable' -Because $p[1]
                    $f.Detail | Should -Match '^Security Defaults state was not read\. No Conditional Access policy is On' -Because $p[1]
                    $f.Detail | Should -Match 'if Security Defaults is enabled, .+; if it is disabled, ' -Because $p[1]
                    $f.Detail | Should -Not -Match 'is not blocked|No CA policy found' -Because $p[1]
                    (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:' -Because $p[1]
                }
            }
        }

        It 'the same evaluators keep the Conditional Access verdict when a CA policy is On, since Security Defaults cannot be on' {
            foreach ($p in $script:SdPairs) {
                Clear-TPState; Set-CA @(New-Pol -Name 'Pilot device' -Users @('u1') -Grant @('compliantDevice')); Set-SD $null
                (V $p[0] $p[1]).State | Should -Be 'Gap' -Because $p[1]
            }
        }

        It 'a Security Defaults state that was not read is filed as a collection gap on a Business Standard tenant, never license gated' {
            $users = @(@{ UserPrincipalName = 'a@corp.example'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' })
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = @(@{ UserPrincipalName = 'a@corp.example'; IsMfaRegistered = $true }) }; SectionStatus = @{ MFARegistration = 'Collected' } })
            Set-CA @(); Set-SD $null
            foreach ($p in $script:SdPairs) { & $p[0] 3>$null | Out-Null }
            Test-TPControlAADMFA 3>$null | Out-Null
            $prof = & $script:BSProf
            $null = Set-TPLicenseGating -LicenseProfile $prof
            $scope = Get-TPAssessmentScope -Findings (Get-TPFindings) -RawData (Get-TPRawData) -LicenseProfile $prof
            foreach ($cid in 'AAD-1.1', 'AAD-11.1', 'AAD-1.3', 'AAD-1.2') {
                @($scope.CollectionIncomplete | ForEach-Object ControlId) | Should -Contain $cid
                @($scope.LicenceBlocked       | ForEach-Object ControlId) | Should -Not -Contain $cid
            }
        }
    }

    Context 'break-glass beside Security Defaults: what the role data proves' {
        BeforeAll {
            function script:Set-Gov([object[]] $Gas) {
                Set-TPRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ BreakGlassIndicators = @($Gas); SectionStatus = @{ BreakGlassIndicators = 'Collected' } })
            }
        }

        # Microsoft recommends two cloud-only emergency access accounts
        # PERMANENTLY assigned Global Administrator. With every Global
        # Administrator synchronized from on-premises, none can be one of
        # them; the finding was "not assessed" and the score went up.
        It 'AAD-7.2: every Global Administrator synchronized from on-premises is a Gap — no emergency access account of the recommended kind exists' {
            Set-Gov @(@{ PrincipalId = 'ga1'; DisplayName = 'GA1'; CAExcluded = $false; Synced = $true; Source = 'permanent' },
                      @{ PrincipalId = 'ga2'; DisplayName = 'GA2'; CAExcluded = $false; Synced = $true; Source = 'permanent' })
            Set-SD $true
            $f = V 'Test-TPControlAADBreakGlass' 'AAD-7.2'
            $f.State    | Should -Be 'Gap'
            $f.Severity | Should -Be 'High'
            $f.Detail   | Should -Match '^Security Defaults is enabled\. 2 Global Administrator assignment\(s\) were read \(2 on accounts marked as synchronized'
            $f.Detail   | Should -Match 'no emergency access account of the recommended kind exists'
            $f.Detail   | Should -Not -Match 'requires manual verification|If CA policies break'
            $f.Remediation | Should -Match 'register an MFA method'
            (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
        }

        It 'AAD-7.2: one permanent Global Administrator not marked as synchronized (a second only PIM-eligible) is a Gap that says the two-account recommendation is not met' {
            Set-Gov @(@{ PrincipalId = 'ga1'; DisplayName = 'GA1'; CAExcluded = $false; Synced = $false; Source = 'permanent' },
                      @{ PrincipalId = 'ga2'; DisplayName = 'GA2'; CAExcluded = $false; Synced = $false; Source = 'eligible' })
            Set-SD $true
            $f = V 'Test-TPControlAADBreakGlass' 'AAD-7.2'
            $f.State        | Should -Be 'Gap'
            $f.Detail       | Should -Match '1 PIM-eligible'
            $f.Detail       | Should -Match 'two-account recommendation is not met'
            $f.CurrentValue | Should -Match ': 1 \(GA1\)$'
        }

        It 'AAD-7.2: with the Global Administrator list not collected the finding is a collection gap, not manual review' {
            Set-TPRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ BreakGlassIndicators = @(); SectionStatus = @{ BreakGlassIndicators = 'Failed' } })
            Set-SD $true
            $f = V 'Test-TPControlAADBreakGlass' 'AAD-7.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'was not collected'
            $f.Detail | Should -Not -Match 'requires manual verification'
            $scope = Get-TPAssessmentScope -Findings (Get-TPFindings) -RawData (Get-TPRawData)
            @($scope.CollectionIncomplete | ForEach-Object ControlId) | Should -Contain 'AAD-7.2'
        }

        It 'AAD-3.2: a single remaining permanent Global Administrator is described as one account, not "these are the two"' {
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-TPRawData -Key 'AAD-PIMSchedules' -Data (Bag @{ EligibleSchedules = @('e1'); ActiveSchedules = @(); SectionStatus = @{ EligibleSchedules = 'Collected' } })
            Set-SD $true
            $f = V 'Test-TPControlAADNoPermanentAdmins' 'AAD-3.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'on 1 account\(s\)'
            $f.Detail | Should -Match 'whether this account is one of the two'
            $f.Detail | Should -Not -Match 'these are the two'
            $f.Detail | Should -Match 'requires manual verification'
        }
    }

    Context 'details state only what was read' {
        # Security Defaults does not REQUIRE a phishing-resistant method, but
        # it does not rule one out (passkeys are available on every edition),
        # and the tool never read which methods administrators use.
        It 'AAD-2.1 does not claim the administrators'' methods are not phishing-resistant' {
            Set-CA @(); Set-SD $true
            $f = V 'Test-TPControlAADCA' 'AAD-2.1'
            $f.Detail | Should -Not -Match 'methods that are not phishing-resistant'
            $f.Detail | Should -Match 'no requirement that the method be phishing-resistant'
        }

        # The tool reads Conditional Access only; the legacy Identity
        # Protection risk policies (retiring October 1, 2026) can still be
        # enforcing and are not read, so "no risk policy is in force" claimed
        # more than was read.
        It 'AAD-1.4, AAD-1.5 and AAD-10.1 scope "no risk policy" to Conditional Access and Security Defaults' {
            Set-CA @(); Set-SD $true
            foreach ($p in @(@('Test-TPControlAADSignInRisk','AAD-1.4'), @('Test-TPControlAADUserRisk','AAD-1.5'), @('Test-TPControlAADIdentityProtection','AAD-10.1'))) {
                $f = V $p[0] $p[1]
                $f.State  | Should -Be 'Gap' -Because $p[1]
                $f.Detail | Should -Not -Match '^Security Defaults is enabled\. No (sign-in|user) risk policy is in force' -Because $p[1]
                $f.Detail | Should -Not -Match 'No automated response to user risk is in force' -Because $p[1]
                $f.Detail | Should -Match 'No Conditional Access (sign-in|user) risk policy can' -Because $p[1]
                $f.Detail | Should -Match 'legacy Identity Protection .+ is not read by this tool' -Because $p[1]
            }
        }
    }

    Context 'Assessment Scope names the right cause' {
        # Beside Security Defaults AAD-1.2 does not read Conditional Access,
        # so a failed CA read is not why it went unassessed; the reason said
        # it was, ahead of a detail saying something else.
        It 'AAD-1.2 beside Security Defaults with the CA read failed and registration refused: the reason does not blame the Conditional Access collector' {
            $users = @(@{ UserPrincipalName = 'a@corp.example'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' })
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = @() }; MFARegistrationFailure = 'PremiumLicenseRequired'; SectionStatus = @{ MFARegistration = 'Failed' } })
            Set-CA @() -Success $false; Set-SD $true
            Test-TPControlAADMFA 3>$null | Out-Null
            $scope = Get-TPAssessmentScope -Findings (Get-TPFindings) -RawData (Get-TPRawData)
            $row = @($scope.CollectionIncomplete | Where-Object ControlId -eq 'AAD-1.2')
            $row.Count | Should -Be 1
            $row[0].Reason | Should -Not -Match "'AAD-CAPolicies' collector did not return data"
            $row[0].Reason | Should -Match 'Re-running will not change this'
        }

        It 'a license-gated Security Defaults finding with the CA read failed is license gated, not "the AAD-CAPolicies collector did not return data"' {
            Set-CA @() -Success $false; Set-SD $true
            Test-TPControlAADPhishResistantMFA 3>$null | Out-Null
            $prof = Get-TPTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','INTUNE_O365','TEAMS1','SHAREPOINTSTANDARD','RMS_S_BASIC') })
            $null = Set-TPLicenseGating -LicenseProfile $prof
            $scope = Get-TPAssessmentScope -Findings (Get-TPFindings) -RawData (Get-TPRawData) -LicenseProfile $prof
            @($scope.LicenceBlocked       | ForEach-Object ControlId) | Should -Contain 'AAD-1.3'
            @($scope.CollectionIncomplete | ForEach-Object ControlId) | Should -Not -Contain 'AAD-1.3'
        }
    }

    Context 'licensing: what remains after Security Defaults decides it' {
        BeforeAll {
            $script:BSSkus = @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','INTUNE_O365','TEAMS1','SHAREPOINTSTANDARD','RMS_S_BASIC') })
            function script:Set-TwoUsers([int] $Registered) {
                $u = @(@{ UserPrincipalName = 'a@corp.example'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' },
                       @{ UserPrincipalName = 'b@corp.example'; DisplayName = 'B'; AccountEnabled = $true; UserType = 'Member' })
                $r = @(0..1 | ForEach-Object { @{ UserPrincipalName = $u[$_].UserPrincipalName; IsMfaRegistered = ($_ -lt $Registered) } })
                Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $u; MFARegistration = @{ RegistrationDetails = $r }; SectionStatus = @{ MFARegistration = 'Collected' } })
            }
            function script:Set-BSInventory { Set-TPRawData -Key 'AAD-Inventory' -Data (Bag @{ SubscribedSkus = $script:BSSkus }) }
            function script:Render-Html {
                $out = Join-Path ([IO.Path]::GetTempPath()) ('tp-sd-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.html')
                Publish-TPAssessmentHTML -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; Operator = 't'; ToolVersion = 'test' } `
                    -Findings @(Get-TPFindings) -Connections @{ Graph = $true } -OutputPath $out -ClientName 'Test Co' 3>$null | Out-Null
                $h = Get-Content -Raw $out; Remove-Item $out -ErrorAction SilentlyContinue; $h
            }
        }

        # With every user registered, what remains (MFA at every sign-in for
        # all users) needs a Conditional Access policy, i.e. Entra ID P1: the
        # same "not licensed is not scored" rule as any other control.
        It 'AAD-1.2 with every user registered beside Security Defaults is gated on a tenant without Entra ID P1, keeping the Security Defaults verdict in the detail' {
            Set-TwoUsers 2; Set-CA @(); Set-SD $true
            Test-TPControlAADMFA 3>$null | Out-Null
            $prof = Get-TPTenantLicenseProfile -SubscribedSkus $script:BSSkus
            $f = @(Get-TPFindings | Where-Object ControlId -eq 'AAD-1.2')[0]
            $f.State | Should -Be 'Partial'
            Test-TPLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId 'AAD-1.2' -Finding $f | Should -BeFalse
            $null = Set-TPLicenseGating -LicenseProfile $prof
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'upgrade opportunity'
            $f.Detail | Should -Match 'Result before the license check: Partial — Security Defaults is enabled\.'
        }

        It 'the registration shortfall is licensed for every consumer: gating, roadmap, improvement plan and the HTML license tag' {
            Set-BSInventory; Set-TwoUsers 1; Set-CA @(); Set-SD $true
            Test-TPControlAADMFA 3>$null | Out-Null
            $prof = Get-TPTenantLicenseProfile
            $prof.HasLicenseData | Should -BeTrue
            $null = Set-TPLicenseGating -LicenseProfile $prof
            @(Get-TPFindings | Where-Object ControlId -eq 'AAD-1.2')[0].State | Should -Be 'Partial'

            $rm = Get-TPRemediationRoadmap -Findings @(Get-TPFindings) -LicenseProfile $prof
            @($rm.QuickWins      | ForEach-Object ControlId) | Should -Contain 'AAD-1.2'
            @($rm.LicenseUnlocks | ForEach-Object ControlId) | Should -Not -Contain 'AAD-1.2'

            $plan = Get-TPNISTImprovementPlan -Findings @(Get-TPFindings) -LicenseProfile $prof
            $steps = @(@($plan.Tracks) | ForEach-Object { @($_['Steps']) }) + @($plan.Blocked)
            $step = @($steps | Where-Object { $null -ne $_ -and $_['ControlId'] -eq 'AAD-1.2' })
            $step.Count | Should -Be 1
            $step[0]['Licensed'] | Should -BeTrue

            $h = Render-Html
            $h | Should -Not -Match "ex-lic'>&#128273; M365 Business Premium or Entra ID P1"
            $h | Should -Match 'Run an MFA registration campaign' -Because 'the finding''s own fix, not "Or enable Security Defaults"'

            # The tag is live: the Conditional Access path on the same tenant
            # (not gated here) carries it.
            Clear-TPState; Set-BSInventory; Set-TwoUsers 1; Set-CA @(); Set-SD $false
            Test-TPControlAADMFA 3>$null | Out-Null
            Render-Html | Should -Match "ex-lic'>&#128273; M365 Business Premium or Entra ID P1"
        }

        It 'compliance matrix: the Security Defaults AAD-1.2 not-assessed finding is not listed as a license gap; a gated control is' -Skip:(-not (
            (& { foreach ($py in 'python3','python') { try { $null = & $py -c 'import openpyxl' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } } return $false })
        )) {
            Set-BSInventory
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = @(@{ UserPrincipalName = 'a@corp.example'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' }); MFARegistration = @{ RegistrationDetails = @() }; SectionStatus = @{ MFARegistration = 'Failed' } })
            Set-CA @(); Set-SD $true
            Test-TPControlAADMFA 3>$null | Out-Null
            Test-TPControlAADPhishResistantMFA 3>$null | Out-Null
            $null = Set-TPLicenseGating -LicenseProfile (Get-TPTenantLicenseProfile)
            $dir = Join-Path ([IO.Path]::GetTempPath()) ('tp-sdm-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            try {
                $x = Join-Path $dir 'm.xlsx'
                Publish-TPComplianceMatrix -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; ToolVersion = 'test' } -Findings @(Get-TPFindings) -OutputPath $x -ErrorAction Stop 3>$null | Out-Null
                $py = if (Get-Command python3 -ErrorAction SilentlyContinue) { 'python3' } else { 'python' }
                $ids = @(& $py -c "import openpyxl,sys; ws=openpyxl.load_workbook(sys.argv[1])['License Gaps']; [print(r[0]) for r in ws.iter_rows(min_row=2, values_only=True) if r and r[0]]" $x)
                $ids | Should -Contain 'AAD-1.3'
                $ids | Should -Not -Contain 'AAD-1.2'
            } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        # No evaluator emits an exempt Security Defaults finding as a Gap, so
        # the playbook (Gaps only) is pinned with a synthetic one: it checks
        # the -Finding pass-through, both ways.
        It 'playbook: a Security Defaults finding the license helper exempts carries no key tag; the same finding without the prefix does' {
            Set-BSInventory
            $dir = Join-Path ([IO.Path]::GetTempPath()) ('tp-sdp-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            try {
                # (The Partial beside it: the playbook reads $partials.Count, which
                # throws under StrictMode when a run has no Partial finding.)
                $filler = @{ ControlId = 'AAD-2.2'; State = 'Partial'; Category = 'Identity'; Title = 'Named Locations'; Severity = 'Medium'; Detail = 'x'; CurrentValue = 'x'; RequiredValue = 'y'; Remediation = ''; FrameworkIds = @() }
                foreach ($case in @(@{ Detail = 'Security Defaults is enabled. Synthetic.'; Tag = $false }, @{ Detail = 'Synthetic.'; Tag = $true })) {
                    $syn = @{ ControlId = 'AAD-1.1'; State = 'Gap'; Category = 'Identity'; Title = 'Legacy Authentication Blocked'; Severity = 'Critical'; Detail = $case.Detail
                              CurrentValue = 'x'; RequiredValue = 'y'; Remediation = ''; FrameworkIds = @() }
                    $md = Join-Path $dir 'p.md'
                    Publish-TPRemediationPlaybook -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; ToolVersion = 'test' } -Findings @($syn, $filler) `
                        -Connections @{ Graph = $true } -OutputPath $md -ExecutivePath (Join-Path $dir 'e.md') 3>$null | Out-Null
                    $text = Get-Content -Raw $md
                    if ($case.Tag) {
                        $text | Should -Match 'AAD-1\.1 — Legacy Authentication Blocked 🔑'
                        $text | Should -Match 'License Upgrades Required'
                    } else {
                        $text | Should -Not -Match 'AAD-1\.1 — Legacy Authentication Blocked 🔑'
                        $text | Should -Not -Match 'License Upgrades Required' -Because 'the callout counts with the same per-finding answer'
                    }
                }
            } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # The HTML and the playbook preferred the control's generic remediation,
    # so a Security Defaults finding showed "Set-SPOTenant
    # -ConditionalAccessPolicy AllowLimitedAccess" on a tenant already set
    # that way, and never the move to Conditional Access.
    Context 'publishers render the Security Defaults remediation' {
        BeforeAll {
            function script:Set-SpoLimited {
                $ts = @{ IsLegacyAuthProtocolsEnabled = $false; IsUnmanagedSyncAppForTenantRestricted = $false; SharingCapability = 'externalUserAndGuestSharing'; AllowedDomainGuidsForSyncApp = @(); DeletedUserPersonalSiteRetentionPeriodInDays = 365 }
                Set-TPRawData -Key 'SharePoint' -Data (Bag @{ TenantSettings = $ts; TenantSettingsSPO = @{ ConditionalAccessPolicy = 'AllowLimitedAccess' }; ExternalSharing = $ts.SharingCapability })
            }
            $script:Transition = 'Security Defaults must be turned off before any Conditional Access policy can be turned on'
        }

        It 'HTML: the SPO-1.5 Gap does not offer the Set-SPOTenant change already made as its fix, and Priority Actions show the move to Conditional Access' {
            Set-SpoLimited; Set-CA @(); Set-SD $true
            Test-TPControlSharePoint 3>$null | Out-Null
            Test-TPControlAADSignInRisk 3>$null | Out-Null
            $keep = @(Get-TPFindings | Where-Object { $_.ControlId -in @('SPO-1.5', 'AAD-1.4') })
            $out = Join-Path ([IO.Path]::GetTempPath()) ('tp-sdh-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.html')
            Publish-TPAssessmentHTML -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; Operator = 't'; ToolVersion = 'test' } `
                -Findings $keep -Connections @{ Graph = $true } -OutputPath $out -ClientName 'Test Co' 3>$null | Out-Null
            $h = Get-Content -Raw $out; Remove-Item $out -ErrorAction SilentlyContinue
            $h | Should -Not -Match 'Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess'
            $h | Should -Match "How to fix it</div><div class='ex-bd'>$([regex]::Escape($script:Transition))"
            $h | Should -Match 'already AllowLimitedAccess and needs no change'
            $h | Should -Match "(?s)act-cid'>AAD-1\.4<.*?How to fix it</span>$([regex]::Escape($script:Transition))"
        }

        It 'playbook: the SPO-1.5 Gap leads with the move to Conditional Access and does not offer the Set-SPOTenant change already made' {
            Set-SpoLimited; Set-CA @(); Set-SD $true
            Test-TPControlSharePoint 3>$null | Out-Null
            Test-TPControlAADPhishResistantMFA 3>$null | Out-Null
            # AAD-1.3 (Partial) rides along: the playbook reads $partials.Count,
            # which throws under StrictMode when a run has no Partial finding.
            $keep = @(Get-TPFindings | Where-Object { $_.ControlId -in @('SPO-1.5', 'AAD-1.3') })
            $dir = Join-Path ([IO.Path]::GetTempPath()) ('tp-sdq-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            try {
                $md = Join-Path $dir 'p.md'; $ht = Join-Path $dir 'p.html'
                Publish-TPRemediationPlaybook -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; ToolVersion = 'test' } -Findings $keep `
                    -Connections @{ Graph = $true } -OutputPath $md -ExecutivePath (Join-Path $dir 'e.md') -HtmlOutputPath $ht 3>$null | Out-Null
                $text = Get-Content -Raw $md
                $text | Should -Match "\*\*Before anything else:\*\* $([regex]::Escape($script:Transition))"
                $text | Should -Match 'already AllowLimitedAccess and needs no change'
                $text | Should -Not -Match 'Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess'
                $html = Get-Content -Raw $ht
                $html | Should -Match ([regex]::Escape($script:Transition))
                $html | Should -Not -Match 'Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess'
            } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }

        # SPO-1.5's restriction relies on Conditional Access (Microsoft: "The
        # settings in this section require Microsoft Entra ID P1 or P2"), so
        # on a tenant without P1 it is not scored — the Security Defaults Gap
        # included.
        It 'SPO-1.5 requires Entra ID P1, so its Security Defaults Gap is not scored on a Business Standard tenant' {
            (@(Get-TPControlDefinitions | Where-Object ControlId -eq 'SPO-1.5')[0]).LicenseRequirement | Should -Be 'M365 Business Premium or Entra ID P1'
            Set-SpoLimited; Set-SD $true
            Test-TPControlSharePoint 3>$null | Out-Null
            $null = Set-TPLicenseGating -LicenseProfile (Get-TPTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','SHAREPOINTSTANDARD') }))
            $f = @(Get-TPFindings | Where-Object ControlId -eq 'SPO-1.5')[0]
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'upgrade opportunity'
        }
    }

    # The shapes Graph actually returns: a collection split across pages, and
    # directory-setting values that are strings ("True"/"False").
    Context 'collectors read the shape Graph returns' {
        It 'the CA collector follows @odata.nextLink, so a trusted named location on page two is collected' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'namedLocations\?\$top=100$') {
                    return @{ value = @(@{ id = 'loc1'; displayName = 'Branch countries'; '@odata.type' = '#microsoft.graph.countryNamedLocation'; countriesAndRegions = @('US') })
                              '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations?$skiptoken=p2' }
                }
                if ($Uri -match 'namedLocations\?\$skiptoken=p2$') {
                    return @{ value = @(@{ id = 'loc2'; displayName = 'HQ'; '@odata.type' = '#microsoft.graph.ipNamedLocation'; isTrusted = $true; ipRanges = @(@{ cidrAddress = '203.0.113.0/24' }) }) }
                }
                return @{ value = @() }
            }
            Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            $raw = Get-TPRawData -Key 'AAD-CAPolicies'
            Get-TPNestedProperty -Object $raw -Path 'Data.SectionStatus.NamedLocations' | Should -Be 'Collected'
            $locs = @($raw.Data.NamedLocations)
            $locs.Count | Should -Be 2 -Because 'the first page held only one of the two'
            @($locs | Where-Object { $_['IsTrusted'] -eq $true }).Count | Should -Be 1 -Because 'the trusted location was on page two'
        }

        It 'the CA collector marks named locations unread, never empty, when Graph returns no collection' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'namedLocations') { return @{ error = @{ code = 'Unexpected' } } }
                return @{ value = @() }
            }
            Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            Get-TPNestedProperty -Object (Get-TPRawData -Key 'AAD-CAPolicies') -Path 'Data.SectionStatus.NamedLocations' | Should -Be 'Failed'
        }

        It 'the inventory collector names every consented app (the lookup URL read $cid? and failed for all of them; only 30 were tried)' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'oauth2PermissionGrants') {
                    return @{ value = @(1..35 | ForEach-Object { @{ clientId = "sp-$_"; scope = 'User.Read'; resourceId = 'res-graph'; consentType = 'AllPrincipals' } }) }
                }
                if ($Uri -match '/servicePrincipals/(sp-\d+)\?') { return @{ displayName = "App $($Matches[1])" } }
                return @{ value = @() }
            }
            Invoke-TPCollectAADInventory 3>$null | Out-Null
            $raw = Get-TPRawData -Key 'AAD-Inventory'
            Get-TPNestedProperty -Object $raw -Path 'Data.SectionStatus.OAuthGrantedApps' | Should -Be 'Collected'
            $apps = @($raw.Data.OAuthGrantedApps)
            $apps.Count | Should -Be 35
            @($apps | Where-Object { $_['AppName'] -eq $_['ClientId'] }).Count | Should -Be 0 -Because 'every app is looked up, and the lookup URL is built'
        }

        It 'the password rule collector reads the string "False" as $false, not as enabled' {
            foreach ($case in @(@{ Raw = 'False'; Want = $false }, @{ Raw = 'True'; Want = $true }, @{ Raw = 'garbage'; Want = $null })) {
                Clear-TPState
                $script:PwRaw = $case.Raw
                & $script:Mod { param($r) $script:PwRaw = $r } $case.Raw
                Set-Graph {
                    param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                    if ($Uri -match 'groupSettings') {
                        return @{ value = @(@{ templateId = '5cf42378-d67d-4f36-ba46-e8b86229381d'; values = @(
                                    @{ name = 'LockoutThreshold'; value = '10' },
                                    @{ name = 'EnableBannedPasswordCheck'; value = $script:PwRaw },
                                    @{ name = 'EnableBannedPasswordCheckOnPremises'; value = $script:PwRaw }) }) }
                    }
                    return @{ value = @() }
                }
                Invoke-TPCollectAADAuthPolicies 3>$null | Out-Null
                $pp = (Get-TPRawData -Key 'AAD-AuthPolicies').Data.PasswordProtection
                $pp | Should -Not -BeNullOrEmpty -Because "the settings were returned ($($case.Raw))"
                foreach ($k in 'EnableBannedPasswordCheck', 'EnableBannedPasswordCheckOnPremises') {
                    if ($null -eq $case.Want) {
                        ($null -eq $pp[$k]) | Should -BeTrue -Because "'$($case.Raw)' is neither True nor False, so it was not read"
                    } else {
                        $pp[$k] | Should -BeExactly $case.Want -Because "the setting value was the string '$($case.Raw)'"
                    }
                }
            }
        }
    }
}

# ── Benchmark gap fixes (2026-10-26) ─────────────────────────────────────────

# Pins the identity verdicts tightened so each Satisfied is true for what the
# control (and the benchmark item it is mapped to) claims. Real collectors are
# driven with raw Graph shapes wherever a collector changed.
#   AAD-7.1   lockout threshold 10 or fewer (CIS 5.2.3.8); AAD-7.3 lockout
#             duration 60 s or more (5.2.3.9); AAD-7.4 custom banned list
#             enforced and non-empty (5.2.3.2, only its count is collected);
#             AAD-7.5 every verified domain set to never expire (1.3.1).
#             Setting values are strings.
#   AAD-11.2  a guest is userType Guest (or #EXT#); a privileged role is the
#             tool's list or Microsoft's isPrivileged flag (beta); eligible
#             assignments count; anything unread is not assessed.
#   AAD-11.4  token protection counts only on Windows, for users, on Exchange
#             Online and SharePoint Online (or All resources).
#   AAD-11.7  both halves of Microsoft's PAW check: compliant device for a
#             privileged role AND a device-filter (exclude) block.
#   AAD-11.9  a workload identity policy must block on service principal risk.
#   AAD-12.2  enabled guests, judged on the last SUCCESSFUL sign-in, else the
#             creation date; disabled guests are reported, not scored.
#   AAD-14.1  the tenant application management policy is a component.

Describe 'Benchmark gap fixes (AAD)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:GA  = '62e90394-69f5-4237-9190-012177145e10'
        $script:HIA = '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'   # Hybrid Identity Administrator: privileged per Microsoft, not in the tool's list
        $script:EXO = '00000002-0000-0ff1-ce00-000000000000'
        $script:SPO = '00000003-0000-0ff1-ce00-000000000000'

        function script:Bag([hashtable] $Data, [bool] $Success = $true) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-26T00:00:00Z'; Success = $Success; Data = $Data } }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-TPFindings | Where-Object ControlId -eq $Cid)[-1] }
        $script:OrigGraph = & $script:Mod { ${function:Invoke-TPGraphRequest} }
        function script:Set-Graph([scriptblock] $Body) {
            & $script:Mod { param($b) Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $b } $Body
        }
        function script:Pol {
            param([string] $Name = 'p', [string] $State = 'enabled', [string[]] $Users = @('All'), [string[]] $Roles = @(),
                  [string[]] $Apps = @('All'), [string[]] $Platforms = @(), [string[]] $Grant = @(), [hashtable] $Session = @{},
                  [string] $FilterMode = '', [string] $FilterRule = '', [string[]] $Sps = @(), $SpRisk = 'absent')
            $cond = @{ ClientAppTypes = @('all'); SignInRiskLevels = @(); UserRiskLevels = @(); Platforms = $Platforms; ExcludePlatforms = @()
                       Users = @{ IncludeUsers = $Users; IncludeGroups = @(); IncludeRoles = $Roles; ExcludeUsers = @(); ExcludeGroups = @(); ExcludeRoles = @() }
                       Applications = @{ Include = $Apps; Exclude = @() }
                       Locations = @{ Include = @(); Exclude = @() }
                       Devices = @{ FilterMode = $FilterMode; FilterRule = $FilterRule }
                       ClientApplications = @{ IncludeServicePrincipals = $Sps } }
            if ($PSBoundParameters.ContainsKey('SpRisk')) { $cond.ServicePrincipalRiskLevels = @($SpRisk) }
            @{ DisplayName = $Name; State = $State; Conditions = $cond
               GrantControls = @{ Operator = 'OR'; BuiltInControls = $Grant; AuthStrengthId = ''; TermsOfUse = @() }
               SessionControls = $Session }
        }
        function script:Ca([object[]] $Policies) {
            Set-TPRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($Policies); SectionStatus = @{ TokenProtection = 'Collected'; PolicyCompleteness = 'Collected' } })
        }
        function script:PrivCatalog { Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleDefinitions = @(@{ Id = $script:GA; DisplayName = 'Global Administrator'; IsPriv = $true }, @{ Id = 'reader'; DisplayName = 'Reports Reader'; IsPriv = $false }) }) }
    }

    BeforeEach { Clear-TPState }
    AfterEach  { & $script:Mod { param($o) Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $o } $script:OrigGraph }
    AfterAll   { Clear-TPState }

    Context 'AAD-7.1 to AAD-7.5 password settings (real collector)' {
        BeforeAll {
            function script:Run-Pwd([object[]] $Values, [bool] $Instantiated = $true, [object[]] $Domains = @(), [bool] $DomainsFail = $false) {
                Clear-TPState
                $script:T_Lock = $Values; $script:T_Inst = $Instantiated; $script:T_Doms = $Domains; $script:T_DomFail = $DomainsFail
                Set-Graph {
                    param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                    if ($Uri -match 'groupSettings') {
                        if (-not $script:T_Inst) { return @{ value = @() } }
                        return @{ value = @(@{ templateId = '5cf42378-d67d-4f36-ba46-e8b86229381d'; values = @($script:T_Lock) }) }
                    }
                    if ($Uri -match '/v1\.0/domains') { if ($script:T_DomFail) { throw 'Graph 403 Forbidden' }; return @{ value = @($script:T_Doms) } }
                    return @{ value = @() }
                }
                Invoke-TPCollectAADAuthPolicies 3>$null | Out-Null
            }
            function script:Lk([string] $T, [string] $D) { @(@{ name = 'LockoutThreshold'; value = $T }, @{ name = 'LockoutDurationInSeconds'; value = $D }) }
            function script:Bp([string] $On, [string] $List) { @(@{ name = 'EnableBannedPasswordCheck'; value = $On }, @{ name = 'BannedPasswordList'; value = $List }) }
            function script:Dom([string] $Id, $Days, [string] $Auth = 'Managed', [bool] $Verified = $true) { @{ id = $Id; isVerified = $Verified; authenticationType = $Auth; passwordValidityPeriodInDays = $Days } }
        }
        It 'AAD-7.1 judges the threshold only; the duration is context, never a second failure' {
            Run-Pwd (Lk '10' '30')
            $f = V 'Test-TPControlAADPasswordProtection' 'AAD-7.1'
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'not part of this verdict.*lockout duration 30 seconds'
            Run-Pwd (Lk '11' '900'); (V 'Test-TPControlAADPasswordProtection' 'AAD-7.1').State | Should -Be 'Gap'
        }
        It 'AAD-7.3: 60 seconds (a string, as Graph returns it) is Satisfied, 59 is a Gap, and a value that is not a number is not assessed' {
            Run-Pwd (Lk '10' '60')
            (V 'Test-TPControlAADLockoutDuration' 'AAD-7.3').State | Should -Be 'Satisfied'
            (Get-TPRawData -Key 'AAD-AuthPolicies').Data.PasswordProtection.LockoutDurationSeconds | Should -BeExactly 60
            Run-Pwd (Lk '10' '59'); (V 'Test-TPControlAADLockoutDuration' 'AAD-7.3').State | Should -Be 'Gap'
            Run-Pwd (Lk '10' 'sixty')
            (V 'Test-TPControlAADLockoutDuration' 'AAD-7.3').State | Should -Be 'NotApplicable'
            (V 'Test-TPControlAADPasswordProtection' 'AAD-7.1').State | Should -Be 'Satisfied' -Because 'the rest of the block survives'
        }
        It 'an uninstantiated Password Rule Settings object is Microsoft''s defaults (10, 60): AAD-7.1 and AAD-7.3 Satisfied' {
            Run-Pwd @() -Instantiated $false
            (V 'Test-TPControlAADPasswordProtection' 'AAD-7.1').State | Should -Be 'Satisfied'
            (V 'Test-TPControlAADLockoutDuration' 'AAD-7.3').State | Should -Be 'Satisfied'
        }
        It 'AAD-7.4 needs the custom list enforced AND holding entries, and never collects the entries' {
            Run-Pwd ((Lk '10' '60') + (Bp 'True' "contoso`tcontosoltd`tseattle"))
            $f = V 'Test-TPControlAADBannedPasswords' 'AAD-7.4'
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'holds 3 entries'
            $pp = (Get-TPRawData -Key 'AAD-AuthPolicies').Data.PasswordProtection
            $pp.BannedPasswordCount | Should -BeExactly 3
            $pp.Contains('BannedPasswordList') | Should -BeFalse -Because 'the entries are the tenant''s chosen weak passwords'
            ($pp | ConvertTo-Json -Depth 5) | Should -Not -Match 'contoso'
            Run-Pwd ((Lk '10' '60') + (Bp 'False' 'contoso')); (V 'Test-TPControlAADBannedPasswords' 'AAD-7.4').State | Should -Be 'Partial'
            Run-Pwd ((Lk '10' '60') + (Bp 'True' ''));        (V 'Test-TPControlAADBannedPasswords' 'AAD-7.4').State | Should -Be 'Partial'
            Run-Pwd ((Lk '10' '60') + (Bp 'False' ''));       (V 'Test-TPControlAADBannedPasswords' 'AAD-7.4').State | Should -Be 'Gap'
            Run-Pwd @() -Instantiated $false;                 (V 'Test-TPControlAADBannedPasswords' 'AAD-7.4').State | Should -Be 'Gap' -Because 'a custom list is off until someone creates the settings object'
            Run-Pwd ((Lk '10' '60') + (Bp 'maybe' 'x'))
            (V 'Test-TPControlAADBannedPasswords' 'AAD-7.4').State | Should -Be 'NotApplicable'
        }
        It 'AAD-7.4 on an older results file reads only whether the list held entries' {
            Clear-TPState
            Set-TPRawData -Key 'AAD-AuthPolicies' -Data @{ Success = $true; Data = @{ PasswordProtection = @{ EnableBannedPasswordCheck = $true; BannedPasswordListPresent = $true } } }
            (V 'Test-TPControlAADBannedPasswords' 'AAD-7.4').State | Should -Be 'Satisfied'
        }
        It 'AAD-7.5 passes only when every verified domain never expires; an unset value is the 90-day default' {
            Run-Pwd (Lk '10' '60') -Domains @((Dom 'contoso.com' 2147483647), (Dom 'contoso.onmicrosoft.com' 2147483647), (Dom 'pending.example' 90 -Verified $false))
            (V 'Test-TPControlAADPasswordExpiry' 'AAD-7.5').State | Should -Be 'Satisfied' -Because 'an unverified domain cannot be used to sign in'
            Run-Pwd (Lk '10' '60') -Domains @((Dom 'contoso.com' 2147483647), (Dom 'contoso.onmicrosoft.com' $null))
            $f = V 'Test-TPControlAADPasswordExpiry' 'AAD-7.5'
            $f.State | Should -Be 'Partial'
            $f.Detail | Should -Match "contoso\.onmicrosoft\.com \(not set: Microsoft's 90-day default\)"
            Run-Pwd (Lk '10' '60') -Domains @((Dom 'contoso.com' 90))
            (V 'Test-TPControlAADPasswordExpiry' 'AAD-7.5').State | Should -Be 'Gap'
        }
        It 'AAD-7.5 names a federated domain as governed by the federation provider, without changing the verdict' {
            Run-Pwd (Lk '10' '60') -Domains @((Dom 'corp.example' 2147483647 -Auth 'Federated'))
            $f = V 'Test-TPControlAADPasswordExpiry' 'AAD-7.5'
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'federation provider'
        }
        It 'AAD-7.5 is not assessed when the domains were not read, or the results file predates the read' {
            Run-Pwd (Lk '10' '60') -DomainsFail $true
            (V 'Test-TPControlAADPasswordExpiry' 'AAD-7.5').State | Should -Be 'NotApplicable'
            Clear-TPState
            Set-TPRawData -Key 'AAD-AuthPolicies' -Data @{ Success = $true; Data = @{ PasswordProtection = @{ LockoutThreshold = 10 } } }
            $f = V 'Test-TPControlAADPasswordExpiry' 'AAD-7.5'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'from before this check'
        }
    }

    Context 'AAD-6.4 agent identity blueprint creation (real collector)' {
        BeforeAll {
            function script:Run-Abp($Durp, [bool] $Fail = $false) {
                Clear-TPState
                $script:T_Durp = $Durp; $script:T_AbpFail = $Fail
                Set-Graph {
                    param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                    if ($Uri -match '/beta/policies/authorizationPolicy') {
                        if ($script:T_AbpFail) { throw 'Graph 403 Forbidden' }
                        $pol = @{ id = 'authorizationPolicy' }
                        if ($null -ne $script:T_Durp) { $pol.defaultUserRolePermissions = $script:T_Durp }
                        return $pol
                    }
                    if ($Uri -match '/v1\.0/policies/authorizationPolicy') { return @{ id = 'authorizationPolicy'; defaultUserRolePermissions = @{ allowedToCreateApps = $false } } }
                    return @{ value = @() }
                }
                Invoke-TPCollectAADAuthPolicies 3>$null | Out-Null
                V 'Test-TPControlAADAgentBlueprintCreation' 'AAD-6.4'
            }
        }
        It 'False is Satisfied and True a Gap, judged apart from app registration' {
            (Run-Abp @{ allowedToCreateApps = $false; allowedToCreateAgentIdentityBlueprints = $false }).State | Should -Be 'Satisfied'
            $f = Run-Abp @{ allowedToCreateApps = $false; allowedToCreateAgentIdentityBlueprints = $true }
            $f.State  | Should -Be 'Gap' -Because 'Microsoft documents that the app-registration restriction does not cover agent blueprints'
            $f.Detail | Should -Match 'outside the app-registration restriction'
        }
        It 'a tenant that does not return the property yet is not assessed, never a pass or a Gap' {
            $f = Run-Abp @{ allowedToCreateApps = $false }
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'did not return defaultUserRolePermissions\.allowedToCreateAgentIdentityBlueprints'
            (Get-TPRawData -Key 'AAD-AuthPolicies').Data.SectionStatus.AgentBlueprintCreation | Should -Be 'Collected'
        }
        It 'a string value is parsed, and anything else is not read' {
            (Run-Abp @{ allowedToCreateAgentIdentityBlueprints = 'False' }).State | Should -Be 'Satisfied'
            (Run-Abp @{ allowedToCreateAgentIdentityBlueprints = 'maybe' }).State | Should -Be 'NotApplicable'
        }
        It 'a failed beta read or an older results file is not assessed' {
            $f = Run-Abp $null -Fail $true
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'section Failed'
            (Get-TPRawData -Key 'AAD-AuthPolicies').Data.AuthorizationPolicy | Should -Not -BeNullOrEmpty -Because 'the v1.0 read is independent'
            Clear-TPState
            Set-TPRawData -Key 'AAD-AuthPolicies' -Data @{ Success = $true; Data = @{ PasswordProtection = @{ LockoutThreshold = 10 } } }
            (V 'Test-TPControlAADAgentBlueprintCreation' 'AAD-6.4').Detail | Should -Match 'from before this check'
        }
    }

    Context 'AAD-11.2 guests in privileged roles (real roles collector)' {
        BeforeAll {
            function script:Run-Roles([object[]] $Assign, [object[]] $Elig = @(), [object[]] $Flags = @(), [bool] $FlagsFail = $false) {
                Clear-TPState
                $script:T_Asg = $Assign; $script:T_Elig = $Elig; $script:T_Flags = $Flags; $script:T_FlagsFail = $FlagsFail
                Set-Graph {
                    param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                    if ($Uri -match '/beta/roleManagement/directory/roleDefinitions') { if ($script:T_FlagsFail) { throw 'Graph 400 BadRequest' }; return @{ value = @($script:T_Flags) } }
                    if ($Uri -match 'roleDefinitions') { return @{ value = @(
                        @{ id = '62e90394-69f5-4237-9190-012177145e10'; displayName = 'Global Administrator'; isBuiltIn = $true; isEnabled = $true },
                        @{ id = '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'; displayName = 'Hybrid Identity Administrator'; isBuiltIn = $true; isEnabled = $true },
                        @{ id = '4a5d8f65-41da-4de4-8968-e035b65339cf'; displayName = 'Reports Reader'; isBuiltIn = $true; isEnabled = $true }) } }
                    if ($Uri -match 'roleAssignments') { return @{ value = @($script:T_Asg) } }
                    if ($Uri -match 'roleEligibilitySchedules') { return @{ value = @($script:T_Elig) } }
                    return @{ value = @() }
                }
                Invoke-TPCollectAADRoles 3>$null | Out-Null
                V 'Test-TPControlAADNoGuestInPrivRoles' 'AAD-11.2'
            }
            # Raw Graph shape of an assignment with $expand=principal (Microsoft's list example).
            function script:RawAsg([string] $Role, [string] $Upn, [string] $Type, [string] $Name = 'X') {
                @{ id = "a-$Upn"; principalId = "id-$Upn"; roleDefinitionId = $Role; directoryScopeId = '/'
                   principal = @{ '@odata.type' = '#microsoft.graph.user'; id = "id-$Upn"; displayName = $Name; userPrincipalName = $Upn; userType = $Type } }
            }
            $script:Flags = @(@{ id = '62e90394-69f5-4237-9190-012177145e10'; isPrivileged = $true }, @{ id = '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'; isPrivileged = $true }, @{ id = '4a5d8f65-41da-4de4-8968-e035b65339cf'; isPrivileged = $false })
        }
        It 'the collector records userType and Microsoft''s isPrivileged flags' {
            $null = Run-Roles @((RawAsg $script:GA 'admin@contoso.com' 'Member')) -Flags $script:Flags
            $r = Get-TPRawData -Key 'AAD-DirectoryRoles'
            $r.Data.SectionStatus.PrivilegedRoleFlags | Should -Be 'Collected'
            @($r.Data.PrivilegedRoleIds) | Should -Contain $script:HIA
            @($r.Data.RoleAssignments)[0].PrincipalUserType | Should -Be 'Member'
            (@($r.Data.RoleDefinitions) | Where-Object Id -eq $script:HIA).IsPrivileged | Should -BeTrue
        }
        It 'only members in privileged roles, every read complete, is Satisfied' {
            (Run-Roles @((RawAsg $script:GA 'admin@contoso.com' 'Member')) -Flags $script:Flags).State | Should -Be 'Satisfied'
        }
        It 'a userType Guest without #EXT# in a role Microsoft marks privileged (not in the tool''s list) is a Gap' {
            $f = Run-Roles @((RawAsg $script:HIA 'partner@contoso.com' 'Guest' 'Converted Partner')) -Flags $script:Flags
            $f.State | Should -Be 'Gap'
            $f.Detail | Should -Match 'Converted Partner'
        }
        It 'a guest ELIGIBLE for Global Administrator is a Gap' {
            $elig = @{ id = 'e1'; principalId = 'g'; roleDefinitionId = $script:GA; directoryScopeId = '/'; memberType = 'Direct'
                       principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Eligible Guest'; userPrincipalName = 'g_x.com#EXT#@contoso.onmicrosoft.com'; userType = 'Guest' } }
            $f = Run-Roles @((RawAsg $script:GA 'admin@contoso.com' 'Member')) -Elig @($elig) -Flags $script:Flags
            $f.State | Should -Be 'Gap'
            $f.Detail | Should -Match 'eligible'
        }
        It 'a guest in a role Microsoft does not mark privileged is not flagged' {
            (Run-Roles @((RawAsg $script:GA 'admin@contoso.com' 'Member'), (RawAsg '4a5d8f65-41da-4de4-8968-e035b65339cf' 'g_x#EXT#@contoso.onmicrosoft.com' 'Guest')) -Flags $script:Flags).State | Should -Be 'Satisfied'
        }
        It 'the privileged-role flags not read is not assessed, never Satisfied' {
            $f = Run-Roles @((RawAsg $script:GA 'admin@contoso.com' 'Member')) -FlagsFail $true
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'isPrivileged'
        }
        It 'a user principal with no recorded userType is not assessed' {
            $a = RawAsg $script:GA 'admin@contoso.com' 'Member'; $a.principal.Remove('userType')
            $f = Run-Roles @($a) -Flags $script:Flags
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'user type'
        }
    }

    Context 'AAD-11.4 token protection scope' {
        It 'requires Windows, some users, and Exchange Online plus SharePoint Online (or All)' {
            $tp = @{ SecureSignInSession = $true }
            Ca @(Pol -Platforms @('windows') -Apps @($script:EXO, $script:SPO) -Session $tp); (V 'Test-TPControlAADTokenProtection' 'AAD-11.4').State | Should -Be 'Satisfied'
            Clear-TPState; Ca @(Pol -Platforms @('windows', 'macOS') -Apps @('All') -Session $tp); (V 'Test-TPControlAADTokenProtection' 'AAD-11.4').State | Should -Be 'Satisfied'
            Clear-TPState; Ca @(Pol -Platforms @('iOS') -Apps @('All') -Session $tp)
            $f = V 'Test-TPControlAADTokenProtection' 'AAD-11.4'
            $f.State | Should -Be 'Gap'; $f.Detail | Should -Match 'does not include the Windows platform'
            Clear-TPState; Ca @(Pol -Platforms @('windows') -Apps @($script:EXO) -Session $tp)
            $f = V 'Test-TPControlAADTokenProtection' 'AAD-11.4'
            $f.State | Should -Be 'Gap'; $f.Detail | Should -Match 'SharePoint Online'
            Clear-TPState; Ca @(Pol -Platforms @('windows') -Users @('None') -Session $tp); (V 'Test-TPControlAADTokenProtection' 'AAD-11.4').State | Should -Be 'Gap'
            Clear-TPState; Ca @(Pol -Platforms @() -Session $tp); (V 'Test-TPControlAADTokenProtection' 'AAD-11.4').State | Should -Be 'Gap' -Because 'no platform condition read is not the Windows platform'
        }
    }

    Context 'AAD-11.7 privileged access workstation: both halves' {
        It 'compliant device for a privileged role AND a device-filter exclude block is Satisfied; each half alone is Partial' {
            $comp = Pol -Name 'Admins compliant' -Users @() -Roles @($script:GA) -Grant @('compliantDevice')
            $paw  = Pol -Name 'Admins PAW only' -Users @() -Roles @($script:GA) -Grant @('block') -FilterMode 'exclude' -FilterRule 'device.extensionAttribute1 -eq "PAW"'
            Ca @($comp, $paw); PrivCatalog; (V 'Test-TPControlAADPrivilegedWorkstation' 'AAD-11.7').State | Should -Be 'Satisfied'
            Clear-TPState; Ca @($comp); PrivCatalog; (V 'Test-TPControlAADPrivilegedWorkstation' 'AAD-11.7').State | Should -Be 'Partial'
            Clear-TPState; Ca @($paw);  PrivCatalog; (V 'Test-TPControlAADPrivilegedWorkstation' 'AAD-11.7').State | Should -Be 'Partial'
        }
        It 'an include-mode filter, a hybrid-join requirement or a non-privileged role does not count' {
            $inc  = Pol -Users @() -Roles @($script:GA) -Grant @('block') -FilterMode 'include' -FilterRule 'device.extensionAttribute1 -eq "PAW"'
            $hyb  = Pol -Users @() -Roles @($script:GA) -Grant @('domainJoinedDevice')
            Ca @($inc, $hyb); PrivCatalog; (V 'Test-TPControlAADPrivilegedWorkstation' 'AAD-11.7').State | Should -Be 'Gap'
            $comp = Pol -Users @() -Roles @('reader') -Grant @('compliantDevice')
            $paw  = Pol -Users @() -Roles @('reader') -Grant @('block') -FilterMode 'exclude' -FilterRule 'device.extensionAttribute1 -eq "PAW"'
            Clear-TPState; Ca @($comp, $paw); PrivCatalog
            $f = V 'Test-TPControlAADPrivilegedWorkstation' 'AAD-11.7'
            $f.State | Should -Be 'Gap'; $f.Detail | Should -Match 'no privileged role included'
        }
        It 'report-only halves are shortfalls naming them; the role catalog unread is not assessed' {
            $comp = Pol -Name 'Staged compliant' -State 'enabledForReportingButNotEnforced' -Users @() -Roles @($script:GA) -Grant @('compliantDevice')
            Ca @($comp); PrivCatalog
            $f = V 'Test-TPControlAADPrivilegedWorkstation' 'AAD-11.7'
            $f.State | Should -Be 'Gap'; $f.Detail | Should -Match 'report-only.*Staged compliant'
            Clear-TPState; Ca @(Pol -Users @() -Roles @($script:GA) -Grant @('compliantDevice'))
            (V 'Test-TPControlAADPrivilegedWorkstation' 'AAD-11.7').State | Should -Be 'NotApplicable'
        }
    }

    Context 'AAD-11.9 workload identity policy must block on service principal risk' {
        It 'blocks at a service principal risk level: Satisfied; location-only or no block: Gap; field not recorded: not assessed' {
            Ca @(Pol -Users @() -Sps @('ServicePrincipalsInMyTenant') -SpRisk @('high') -Grant @('block')); (V 'Test-TPControlAADWorkloadIdentityCA' 'AAD-11.9').State | Should -Be 'Satisfied'
            Clear-TPState; Ca @(Pol -Name 'SP locations' -Users @() -Sps @('ServicePrincipalsInMyTenant') -SpRisk @() -Grant @('block'))
            $f = V 'Test-TPControlAADWorkloadIdentityCA' 'AAD-11.9'
            $f.State | Should -Be 'Gap'; $f.Detail | Should -Match 'SP locations'
            Clear-TPState; Ca @(Pol -Users @() -Sps @('ServicePrincipalsInMyTenant') -SpRisk @('high') -Grant @('mfa')); (V 'Test-TPControlAADWorkloadIdentityCA' 'AAD-11.9').State | Should -Be 'Gap'
            Clear-TPState; Ca @(Pol -Users @() -Sps @('ServicePrincipalsInMyTenant') -Grant @('block')); (V 'Test-TPControlAADWorkloadIdentityCA' 'AAD-11.9').State | Should -Be 'NotApplicable'
        }
        It 'the CA collector projects servicePrincipalRiskLevels and the authentication context claim values' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'conditionalAccess/policies') { return @{ value = @(
                    @{ id = 'p1'; displayName = 'WI risk'; state = 'enabled'; conditions = @{ servicePrincipalRiskLevels = @('high', 'medium'); clientApplications = @{ includeServicePrincipals = @('ServicePrincipalsInMyTenant') }; applications = @{ includeApplications = @('All') } }; grantControls = @{ operator = 'OR'; builtInControls = @('block') } },
                    @{ id = 'p2'; displayName = 'Ctx'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeAuthenticationContextClassReferences = @('c1') } }; grantControls = @{ operator = 'OR'; builtInControls = @('mfa') } }) } }
                return @{ value = @() }
            }
            Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            $pols = @((Get-TPRawData -Key 'AAD-CAPolicies').Data.Policies)
            @(($pols | Where-Object { $_.Id -eq 'p1' }).Conditions.ServicePrincipalRiskLevels) | Should -Be @('high', 'medium')
            @(($pols | Where-Object { $_.Id -eq 'p2' }).Conditions.Applications.AuthenticationContext) | Should -Be @('c1')
            ($pols | Where-Object { $_.Id -eq 'p2' }).Conditions.Contains('ServicePrincipalRiskLevels') | Should -BeTrue -Because 'a fresh read always records the field, so an empty list means none selected'
        }
    }

    Context 'AAD-12.2 stale guests (real inventory collector)' {
        BeforeAll {
            function script:Run-Guests([object[]] $Rows) {
                Clear-TPState
                $script:T_Guests = $Rows
                Set-Graph {
                    param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                    if ($Uri -match "userType eq 'Guest'") { return @{ value = @($script:T_Guests) } }
                    return @{ value = @() }
                }
                Invoke-TPCollectAADInventory 3>$null | Out-Null
                V 'Test-TPControlInventoryStaleGuests' 'AAD-12.2'
            }
            $script:Ago = { param([int] $d) [datetime]::UtcNow.AddDays(-$d).ToString('o') }
            function script:G([string] $Id, [bool] $Enabled, [string] $Created, $Sia) {
                $g = @{ id = $Id; displayName = $Id; userPrincipalName = "$Id#EXT#@contoso.onmicrosoft.com"; accountEnabled = $Enabled; userType = 'Guest'; createdDateTime = $Created }
                if ($Sia) { $g.signInActivity = $Sia }
                $g
            }
        }
        It 'a failed interactive attempt last week does not make a guest active: the last SUCCESSFUL sign-in decides' {
            $f = Run-Guests @((G 'sprayed' $true (& $script:Ago 800) @{ lastSignInDateTime = (& $script:Ago 7); lastSuccessfulSignInDateTime = (& $script:Ago 400) }),
                              (G 'active' $true (& $script:Ago 800) @{ lastSignInDateTime = (& $script:Ago 300); lastSuccessfulSignInDateTime = (& $script:Ago 3) }))
            $f.State | Should -Be 'Gap'
            @($f.AffectedObjects) -join ' ' | Should -Match 'sprayed'
            @($f.AffectedObjects) -join ' ' | Should -Not -Match 'active \('
        }
        It 'no successful sign-in recorded is judged from the creation date' {
            (Run-Guests @((G 'new' $true (& $script:Ago 10) $null))).State | Should -Be 'Satisfied'
            $f = Run-Guests @((G 'old' $true (& $script:Ago 200) $null))
            $f.State | Should -Be 'Gap'
            @($f.AffectedObjects) -join ' ' | Should -Match 'account creation'
        }
        It 'a stale DISABLED guest is reported, not scored' {
            $f = Run-Guests @((G 'gone' $false (& $script:Ago 800) @{ lastSuccessfulSignInDateTime = (& $script:Ago 400) }),
                              (G 'active' $true (& $script:Ago 800) @{ lastSuccessfulSignInDateTime = (& $script:Ago 3) }))
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match '1 disabled guest'
        }
        It 'a guest with neither date readable is not assessed, and an older results file is not assessed' {
            (Run-Guests @((G 'nodate' $true '' $null))).State | Should -Be 'NotApplicable'
            Clear-TPState
            Set-TPRawData -Key 'AAD-Inventory' -Data (Bag @{ GuestUsers = @(@{ DisplayName = 'Old'; UPN = 'o'; AccountEnabled = $true; LastSignIn = (& $script:Ago 3); DaysSinceSignIn = 3; IsStale = $false }); SectionStatus = @{ GuestUsers = 'Collected' } })
            $f = V 'Test-TPControlInventoryStaleGuests' 'AAD-12.2'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'predates'
        }
    }

    Context 'AAD-14.1 tenant application management policy (real inventory collector)' {
        BeforeAll {
            function script:Run-AppPolicy($Policy, [bool] $Fail = $false) {
                Clear-TPState
                $script:T_Amp = $Policy; $script:T_AmpFail = $Fail
                Set-Graph {
                    param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                    if ($Uri -match 'defaultAppManagementPolicy') { if ($script:T_AmpFail) { throw 'Graph 403 Forbidden' }; return $script:T_Amp }
                    return @{ value = @() }
                }
                Invoke-TPCollectAADInventory 3>$null | Out-Null
                V 'Test-TPControlAADAppCredentialExpiry' 'AAD-14.1'
            }
            # Raw shape of tenantAppManagementPolicy (Graph v1.0).
            function script:Amp([bool] $Enabled = $true, [string] $Pw = 'P180D', [string] $Key = 'P180D', [string] $State = 'enabled', $After = $null) {
                @{ id = '00000000-0000-0000-0000-000000000000'; isEnabled = $Enabled
                   applicationRestrictions = @{
                       passwordCredentials = @(@{ restrictionType = 'passwordLifetime'; state = $State; maxLifetime = $Pw; restrictForAppsCreatedAfterDateTime = $After })
                       keyCredentials      = @(@{ restrictionType = 'asymmetricKeyLifetime'; state = $State; maxLifetime = $Key; restrictForAppsCreatedAfterDateTime = $After }) } }
            }
        }
        It 'no credentials and the policy capping both at 180 days for every app is Satisfied' {
            $f = Run-AppPolicy (Amp)
            $f.State | Should -Be 'Satisfied'
            (Get-TPRawData -Key 'AAD-Inventory').Data.SectionStatus.AppManagementPolicy | Should -Be 'Collected'
        }
        It 'a lifetime above the control''s 180 days, a disabled policy, a disabled restriction or a created-after date is a shortfall' {
            (Run-AppPolicy (Amp -Key 'P365D')).State | Should -Be 'Partial'
            (Run-AppPolicy (Amp -Enabled $false)).State | Should -Be 'Partial'
            (Run-AppPolicy (Amp -State 'disabled')).State | Should -Be 'Partial'
            $f = Run-AppPolicy (Amp -After '2025-01-01T00:00:00Z')
            $f.State | Should -Be 'Partial'; $f.Detail | Should -Match 'created after 2025-01-01'
            $f = Run-AppPolicy @{ id = 'x'; isEnabled = $true; applicationRestrictions = @{ passwordCredentials = @(); keyCredentials = @() } }
            $f.State | Should -Be 'Partial'; $f.Detail | Should -Match 'no lifetime limit for client secrets'
        }
        It 'the policy not read, or an unreadable duration, is not assessed' {
            (Run-AppPolicy $null -Fail $true).State | Should -Be 'NotApplicable'
            (Run-AppPolicy (Amp -Pw 'forever')).State | Should -Be 'NotApplicable'
            Clear-TPState
            Set-TPRawData -Key 'AAD-Inventory' -Data (Bag @{ AppCredentials = @(); SectionStatus = @{ AppCredentials = 'Collected' } })
            $f = V 'Test-TPControlAADAppCredentialExpiry' 'AAD-14.1'
            $f.State | Should -Be 'NotApplicable' -Because 'a results file from before the policy was read is not a pass'
        }
        It 'an expired or long-lived credential stays a Gap even with the policy in place' {
            Clear-TPState
            Set-TPRawData -Key 'AAD-Inventory' -Data (Bag @{
                AppCredentials = @(@{ AppDisplayName = 'Legacy'; AppId = 'a'; CredentialType = 'Secret'; DaysRemaining = 500; LifetimeDays = 730 })
                AppManagementPolicy = @{ IsEnabled = $true
                    PasswordRestrictions = @(@{ RestrictionType = 'passwordLifetime'; State = 'enabled'; MaxLifetime = 'P180D'; RestrictForAppsCreatedAfterDateTime = ''; ExcludedActorAttributes = 0 })
                    KeyRestrictions      = @(@{ RestrictionType = 'asymmetricKeyLifetime'; State = 'enabled'; MaxLifetime = 'P180D'; RestrictForAppsCreatedAfterDateTime = ''; ExcludedActorAttributes = 0 }) }
                SectionStatus = @{ AppCredentials = 'Collected'; AppManagementPolicy = 'Collected' } })
            (V 'Test-TPControlAADAppCredentialExpiry' 'AAD-14.1').State | Should -Be 'Gap'
        }
    }

    # AAD-10.4 (owner's decision 2026-10-26): Zero Trust Assessment tests 21825 (every
    # privileged role named in an enabled policy whose sign-in frequency is type hours,
    # 4 or less) and 21824 (an enabled policy selecting guest or external users at 24
    # hours or less, 1 day, or every time). One half is Partial; neither is a Gap.
    Context 'AAD-10.4 sign-in frequency per population' {
        BeforeAll {
            $script:SifH = { param([int] $v, [string] $t = 'hours') @{ SignInFrequency = @{ IsEnabled = $true; FrequencyInterval = 'timeBased'; Value = $v; Type = $t } } }
            function script:GuestPol([string] $Name = 'Guests SIF', [hashtable] $Session, [string] $State = 'enabled') {
                $p = Pol -Name $Name -State $State -Users @() -Session $Session
                $p.Conditions.Users.IncludeGuestsOrExternalUsers = @{ GuestOrExternalUserTypes = 'internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider'; ExternalTenantsMembershipKind = 'all' }
                $p
            }
            function script:Ca104([object[]] $Policies, [bool] $GuestRead = $true) {
                $d = @{ Policies = @($Policies); SectionStatus = @{ TokenProtection = 'Collected'; PolicyCompleteness = 'Collected' } }
                if ($GuestRead) { $d.GuestConditionsRead = $true }
                Set-TPRawData -Key 'AAD-CAPolicies' -Data (Bag $d)
            }
            function script:Catalog104 {
                Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleDefinitions = @(
                    @{ Id = $script:GA;  DisplayName = 'Global Administrator';           IsPriv = $true;  IsPrivileged = $true },
                    @{ Id = $script:HIA; DisplayName = 'Hybrid Identity Administrator'; IsPriv = $false; IsPrivileged = $true },
                    @{ Id = 'reader';    DisplayName = 'Reports Reader';                IsPriv = $false; IsPrivileged = $false }) })
            }
            function script:V104 { V 'Test-TPControlAADSignInFrequency' 'AAD-10.4' }
        }

        It 'every privileged role (tool list and Microsoft isPrivileged) at 4 hours and guests at 24 hours is Satisfied' {
            Catalog104
            Ca104 @((Pol -Name 'Admins 4h' -Users @() -Roles @($script:GA, $script:HIA) -Session (& $script:SifH 4)), (GuestPol -Session (& $script:SifH 24)))
            $f = V104
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'Every one of the 2 privileged roles'
            $f.Detail | Should -Match "Microsoft marks isPrivileged"
            $f.Detail | Should -Match 'Guests SIF \[24 hour\(s\); guest types: internalGuest'
        }

        It 'boundaries: 5 hours, or 1 day, for privileged roles fails the half; 1 day and every time pass for guests, 25 hours and 2 days do not' {
            foreach ($c in @(@{ S = (& $script:SifH 5); Ok = $false }, @{ S = (& $script:SifH 1 'days'); Ok = $false }, @{ S = (& $script:SifH 1); Ok = $true })) {
                Clear-TPState; Catalog104
                Ca104 @((Pol -Name 'Admins' -Users @() -Roles @($script:GA, $script:HIA) -Session $c.S), (GuestPol -Session (& $script:SifH 24)))
                (V104).State | Should -Be $(if ($c.Ok) { 'Satisfied' } else { 'Partial' }) -Because "privileged $($c.S.SignInFrequency.Value) $($c.S.SignInFrequency.Type)"
            }
            foreach ($c in @(@{ S = (& $script:SifH 1 'days'); Ok = $true }, @{ S = @{ SignInFrequency = @{ IsEnabled = $true; FrequencyInterval = 'everyTime'; Value = $null; Type = '' } }; Ok = $true },
                             @{ S = (& $script:SifH 25); Ok = $false }, @{ S = (& $script:SifH 2 'days'); Ok = $false })) {
                Clear-TPState; Catalog104
                Ca104 @((Pol -Name 'Admins' -Users @() -Roles @($script:GA, $script:HIA) -Session (& $script:SifH 4)), (GuestPol -Session $c.S))
                (V104).State | Should -Be $(if ($c.Ok) { 'Satisfied' } else { 'Partial' }) -Because "guest $($c.S.SignInFrequency.Value) $($c.S.SignInFrequency.Type) $($c.S.SignInFrequency.FrequencyInterval)"
            }
        }

        It 'a role left out of every policy is a shortfall naming it; an all-users policy is not credited (the test counts policies that name the role)' {
            Catalog104
            Ca104 @((Pol -Name 'GA 4h' -Users @() -Roles @($script:GA) -Session (& $script:SifH 4)), (Pol -Name 'Everyone 4h' -Session (& $script:SifH 4)), (GuestPol -Session (& $script:SifH 8)))
            $f = V104
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match '1 of 2 privileged roles .* Hybrid Identity Administrator'
        }

        It 'a privileged-role policy excluding the role, scoped to one application, or report-only is not counted' {
            Catalog104
            $excl = Pol -Name 'Excludes HIA' -Users @() -Roles @($script:GA, $script:HIA) -Session (& $script:SifH 4); $excl.Conditions.Users.ExcludeRoles = @($script:HIA)
            Ca104 @($excl, (GuestPol -Session (& $script:SifH 8))); (V104).State | Should -Be 'Partial'
            Clear-TPState; Catalog104
            Ca104 @((Pol -Name 'Portal only' -Users @() -Roles @($script:GA, $script:HIA) -Apps @('797f4846-ba00-4fd7-ba43-dac1f8f63013') -Session (& $script:SifH 4)), (GuestPol -Session (& $script:SifH 8)))
            $f = V104; $f.State | Should -Be 'Partial'; $f.Detail | Should -Match "'Portal only' .* applies to only some applications"
            Clear-TPState; Catalog104
            Ca104 @((Pol -Name 'Staged' -State 'enabledForReportingButNotEnforced' -Users @() -Roles @($script:GA, $script:HIA) -Session (& $script:SifH 4)), (GuestPol -Session (& $script:SifH 8)))
            $f = V104; $f.State | Should -Be 'Partial'; $f.Detail | Should -Match 'Report-only for privileged roles .* Staged'
        }

        It 'neither half met is a Gap; a policy for all users with a long frequency earns nothing' {
            Catalog104
            Ca104 @((Pol -Name 'Everyone 30 days' -Session (& $script:SifH 30 'days')))
            $f = V104
            $f.State | Should -Be 'Gap'
            $f.Detail | Should -Match 'guest or external users'
        }

        It 'a user excluded from every counted policy is a shortfall carrying structured exclusions for the emergency-access approval' {
            Catalog104
            $p = Pol -Name 'Admins 4h' -Users @() -Roles @($script:GA, $script:HIA) -Session (& $script:SifH 4); $p.Conditions.Users.ExcludeUsers = @('bg-1')
            Ca104 @($p, (GuestPol -Session (& $script:SifH 8)))
            $f = V104
            $f.State | Should -Be 'Partial'
            $f.Detail | Should -Match 'excludes the same principal\(s\).*user:bg-1'
            @($f.AffectedObjects | Where-Object { (Get-TPObjectField -Item $_ -Key 'Exclusion' -Default '') -eq 'SharedByEveryQualifyingPolicy' }).Count | Should -Be 1
        }

        It 'not read is not assessed: no role catalog, a results file without the guest selection, or an incomplete policy list' {
            Ca104 @((Pol -Name 'Admins 4h' -Users @() -Roles @($script:GA) -Session (& $script:SifH 4)), (GuestPol -Session (& $script:SifH 8)))
            $f = V104; $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'role catalog was not read'
            Clear-TPState; Catalog104
            Ca104 @((Pol -Name 'Admins 4h' -Users @() -Roles @($script:GA, $script:HIA) -Session (& $script:SifH 4)), (GuestPol -Session (& $script:SifH 8))) -GuestRead $false
            $f = V104; $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'predates the read'
            Clear-TPState; Catalog104
            Set-TPRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @(); GuestConditionsRead = $true; SectionStatus = @{ PolicyCompleteness = 'Failed' } })
            (V104).State | Should -Be 'NotApplicable'
        }

        It 'the CA collector projects the guest or external users selection and records that it read it' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'conditionalAccess/policies') { return @{ value = @(
                    @{ id = 'g1'; displayName = 'Guests'; state = 'enabled'
                       conditions = @{ users = @{ includeUsers = @(); includeGuestsOrExternalUsers = @{ guestOrExternalUserTypes = 'b2bCollaborationGuest,serviceProvider'; externalTenants = @{ '@odata.type' = '#microsoft.graph.conditionalAccessAllExternalTenants'; membershipKind = 'all' } } }; applications = @{ includeApplications = @('All') } }
                       sessionControls = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 12; frequencyInterval = 'timeBased'; authenticationType = 'primaryAndSecondaryAuthentication' } } },
                    @{ id = 'a1'; displayName = 'All'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') } } }) } }
                return @{ value = @() }
            }
            Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            $raw = Get-TPRawData -Key 'AAD-CAPolicies'
            $raw.Data.GuestConditionsRead | Should -BeTrue
            $g = @($raw.Data.Policies) | Where-Object { $_.Id -eq 'g1' }
            $g.Conditions.Users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes | Should -Be 'b2bCollaborationGuest,serviceProvider'
            $g.Conditions.Users.IncludeGuestsOrExternalUsers.ExternalTenantsMembershipKind | Should -Be 'all'
            $g.SessionControls.SignInFrequency.Value | Should -Be 12
            $null -eq (@($raw.Data.Policies) | Where-Object { $_.Id -eq 'a1' }).Conditions.Users.IncludeGuestsOrExternalUsers | Should -BeTrue
        }
    }

    # AAD-12.3 (owner's decision 2026-10-26): DISA Entra ID STIG V-270204 at 35 days over
    # every enabled member account; the real collector is driven in TP.ExchangeTruth.Tests.ps1.
    Context 'AAD-12.3 inactive member accounts (STIG V-270204)' {
        BeforeAll {
            function script:Inv123([hashtable] $Extra, [object[]] $Rows = @()) {
                $d = @{ StaleMembers = @($Rows); SectionStatus = @{ StaleMembers = 'Collected' } }
                foreach ($k in $Extra.Keys) { $d[$k] = $Extra[$k] }
                Set-TPRawData -Key 'AAD-Inventory' -Data (Bag $d)
                V 'Test-TPControlInventoryStaleMembers' 'AAD-12.3'
            }
        }
        It 'none inactive under the 35-day read is Satisfied, saying emergency-access accounts are counted' {
            $f = Inv123 @{ StaleMembersThresholdDays = 35; StaleMembersUndetermined = 0 }
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match '35 days'
            $f.Detail | Should -Match 'V-270204'
            $f.Detail | Should -Match 'Emergency-access .* counted'
        }
        It 'an account whose activity could not be dated leaves a clean list not assessed' {
            (Inv123 @{ StaleMembersThresholdDays = 35; StaleMembersUndetermined = 2 }).State | Should -Be 'NotApplicable'
        }
        It 'an unlicensed inactive member is a Gap (the licensed-only filter is gone)' {
            $f = Inv123 @{ StaleMembersThresholdDays = 35 } @(@{ DisplayName = 'Idle'; UPN = 'idle@contoso.com'; LastSignIn = 'x'; LastSignInBasis = 'last sign-in 40 days ago'; DaysSinceSignIn = 40; HasLicense = $false })
            $f.State | Should -Be 'Gap'
            @($f.AffectedObjects) -join ' ' | Should -Match 'unlicensed\] .* last sign-in 40 days ago'
        }
        It 'a results file from before the 35-day read: a clean 90-day list is not assessed, a 90-day row is still a Gap and says the list may be incomplete' {
            $f = Inv123 @{}
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'predates the 35-day'
            Clear-TPState
            $g = Inv123 @{} @(@{ DisplayName = 'Old'; UPN = 'old@contoso.com'; LastSignIn = 'x'; LastSignInBasis = 'last successful sign-in'; DaysSinceSignIn = 120; HasLicense = $true })
            $g.State | Should -Be 'Gap'; $g.Detail | Should -Match '36 to 90 days may exist'
        }
    }
}

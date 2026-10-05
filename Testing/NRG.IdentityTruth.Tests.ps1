#Requires -Version 7.0
#
# NRG.IdentityTruth.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
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
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
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
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($Policies); SectionStatus = @{ TokenProtection = 'Collected'; NamedLocations = 'Collected' } })
        }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-NRGFindings | Where-Object ControlId -eq $Cid)[0] }
    }

    Context 'AAD-6.2 user consent, collected from the documented authorizationPolicy shape' {
        BeforeAll {
            $script:Orig = & $script:Mod { ${function:Invoke-NRGGraphRequest} }
            function script:Consent([string] $Assigned) {
                $json = '{"id":"authorizationPolicy","allowInvitesFrom":"adminsAndGuestInviters","allowedToSignUpEmailBasedSubscriptions":false,"allowedToUseSSPR":true,"allowEmailVerifiedUsersToJoinOrganization":false,"blockMsolPowerShell":false,"guestUserRoleId":"2af84b1e-32c8-42b7-82bc-daa82404023b","defaultUserRolePermissions":{"allowedToCreateApps":false,"allowedToCreateSecurityGroups":false,"allowedToCreateTenants":false,"allowedToReadBitlockerKeysForOwnedDevice":true,"allowedToReadOtherUsers":true,"permissionGrantPoliciesAssigned":' + $Assigned + '}}'
                & $script:Mod { param($j) $script:T_Auth = $j | ConvertFrom-Json -AsHashtable
                    Set-Item -Path 'function:script:Invoke-NRGGraphRequest' -Value {
                        param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                        if ($Uri -match 'authorizationPolicy') { return $script:T_Auth }
                        throw "no route: $Uri" } } $json
                Clear-NRGState
                Invoke-NRGCollectAADIdentityGovernance 3>$null | Out-Null
                V 'Test-NRGControlAADUserConsent' 'AAD-6.2'
            }
        }
        AfterAll { & $script:Mod { param($o) Set-Item -Path 'function:script:Invoke-NRGGraphRequest' -Value $o } $script:Orig }

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
            Ca @(Pol -Users @() -Groups @('g1') -ClientApps @('other','exchangeActiveSync') -Grant @('block')); (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Partial'
            Ca @(Pol -ClientApps @('exchangeActiveSync') -Grant @('block'));                                   (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Gap'
            Ca @(Pol -ClientApps @('other','exchangeActiveSync') -Grant @('block'));                           (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.1: a legacy-auth block whose application scope is None (or one app) blocks nothing and is not credited' {
            Ca @(Pol -Apps @('None') -ClientApps @('exchangeActiveSync','mobileAppsAndDesktopClients','other') -Grant @('block'))
            $v = V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1'; $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'applications'
            Ca @(Pol -Apps @('00000003-0000-0ff1-ce00-000000000000') -ClientApps @('other') -Grant @('block'))
            (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Partial'
            Ca (@(Pol -Apps @('None') -ClientApps @('other') -Grant @('block')) + @(Pol -Name 'all' -ClientApps @('other') -Grant @('block')))
            (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.4 / 1.5: report-only is Partial only when the policy meets every scope, risk and grant condition; otherwise Gap; disabled is Gap' {
            $mk = { param($state, $risk, $levels, $grant, $apps = @('All'), $users = @('All'))
                $p = Pol -Name "risk-$state" -State $state -Grant $grant -Users $users
                $p.Conditions.Applications.Include = $apps
                if ($risk -eq 'user') { $p.Conditions.UserRiskLevels = $levels } else { $p.Conditions.SignInRiskLevels = $levels }
                $p }
            # AAD-1.5 user risk
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'user' @('high') @('riskRemediation')))
            $f = V 'Test-NRGControlAADUserRisk' 'AAD-1.5'; $f.State | Should -Be 'Partial'; $f.Detail | Should -Match 'report-only mode'; $f.Detail | Should -Match 'still a failed baseline requirement'
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'user' @('low') @('riskRemediation')));            (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap'    # wrong level
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'user' @('high') @('compliantDevice')));         (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap'    # grant does not respond
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'user' @('high') @('riskRemediation') @('00000003-0000-0ff1-ce00-000000000000'))); (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap' # one application only
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'user' @('high') @('riskRemediation') @('All') @()));                                  (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap' # no users
            Ca @((& $mk 'disabled' 'user' @('high') @('riskRemediation')));                                  (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap'    # disabled
            Ca @();                                                                                          $none = V 'Test-NRGControlAADUserRisk' 'AAD-1.5'; $none.State | Should -Be 'Gap'; $none.Detail | Should -Not -Match 'Report-only'
            # AAD-1.4 sign-in risk: Microsoft's template selects High and Medium
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'signin' @('high', 'medium') @('mfa')));         $g = V 'Test-NRGControlAADSignInRisk' 'AAD-1.4'; $g.State | Should -Be 'Partial'; $g.Detail | Should -Match 'report-only mode'
            Ca @((& $mk 'enabledForReportingButNotEnforced' 'signin' @('high') @('mfa')));                   (V 'Test-NRGControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Gap'  # only one level
            Ca @((& $mk 'disabled' 'signin' @('high', 'medium') @('mfa')));                                  (V 'Test-NRGControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Gap'
            # an enforced policy still wins over a report-only one
            Ca @((& $mk 'enabled' 'user' @('high') @('riskRemediation')), (& $mk 'enabledForReportingButNotEnforced' 'user' @('high') @('riskRemediation')))
            (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.4 / 1.5: a policy list that could not be proven complete is not assessed, never a Gap; an absent key replays as complete' {
            $incomplete = { param($pols) Clear-NRGState; Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($pols); SectionStatus = @{ TokenProtection = 'Collected'; NamedLocations = 'Collected'; PolicyCompleteness = 'Failed' } }) }
            & $incomplete @()
            $a = V 'Test-NRGControlAADUserRisk' 'AAD-1.5'; $a.State | Should -Be 'NotApplicable'; $a.Detail | Should -Match '^Not assessed: the Conditional Access policy list could not be read in full'
            (V 'Test-NRGControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'NotApplicable'
            @((Get-NRGAssessmentScope -Findings @(Get-NRGFindings)).CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Contain 'AAD-1.5' -Because 'it must be named as a collection gap, not filed as an advisory'
            # an enforced qualifying policy is still a pass: the missing policies cannot make it worse
            $ok = Pol -Name 'u' -Grant @('riskRemediation'); $ok.Conditions.UserRiskLevels = @('high')
            & $incomplete @($ok)
            (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied'
            Ca @()
            (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap' -Because 'results collected before the beta merge have no PolicyCompleteness and replay unchanged'
        }
        It 'AAD-1.4 / 1.5: blocking and risk-remediation responses count' {
            Ca @(Pol -SignInRisk @('high', 'medium') -Grant @('block'));   (V 'Test-NRGControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Satisfied'
            Ca @(Pol -UserRisk @('high') -Grant @('riskRemediation'));     (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied'
        }
        # A policy applies only to the risk levels it selects. Microsoft's
        # templates select High and Medium (sign-in) and High (user); a
        # low-only policy used to score Satisfied on both controls.
        It 'AAD-1.4 / 1.5: only the risk levels Microsoft''s templates select count' {
            Ca @(Pol -SignInRisk @('low') -Grant @('mfa'));    (V 'Test-NRGControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Gap'
            Ca @(Pol -SignInRisk @('high') -Grant @('mfa'));   (V 'Test-NRGControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Partial'
            $f = V 'Test-NRGControlAADSignInRisk' 'AAD-1.4';   $f.Detail | Should -Match 'medium-risk sign-in is let through'
            Ca @(Pol -SignInRisk @('medium') -Grant @('mfa')); (V 'Test-NRGControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Partial'
            Ca @((Pol -SignInRisk @('high') -Grant @('block')), (Pol -SignInRisk @('medium') -Grant @('mfa')))
            (V 'Test-NRGControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Satisfied' -Because 'levels combine across the enabled policies'
            Ca @(Pol -UserRisk @('low', 'medium') -Grant @('passwordChange')); (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Gap'
            Ca @(Pol -UserRisk @('medium', 'high') -Grant @('passwordChange')); (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied'
        }
        It 'AAD-2.3: "compliant OR MFA" does not enforce a device' {
            Ca @(Pol -Grant @('compliantDevice','domainJoinedDevice','mfa') -Op 'OR'); (V 'Test-NRGControlAADDeviceComplianceCA' 'AAD-2.3').State | Should -Be 'Partial'
            Ca @(Pol -Grant @('compliantDevice','domainJoinedDevice') -Op 'OR');       (V 'Test-NRGControlAADDeviceComplianceCA' 'AAD-2.3').State | Should -Be 'Satisfied'
        }
        It 'AAD-11.1: a device-code policy must block, not only require MFA' {
            $flow = @{ transferMethods = 'deviceCodeFlow' }
            Ca @(Pol -AuthFlows $flow -Grant @('mfa'));   (V 'Test-NRGControlAADDeviceCode' 'AAD-11.1').State | Should -Be 'Gap'
            Ca @(Pol -AuthFlows $flow -Grant @('block')); (V 'Test-NRGControlAADDeviceCode' 'AAD-11.1').State | Should -Be 'Satisfied'
        }
        It 'AAD-11.7: judged on configuration, not on a policy name containing "PAW"' {
            Ca @(Pol -Name 'Block legacy auth (PAW accounts excluded)' -ClientApps @('other') -Grant @('block')); (V 'Test-NRGControlAADPrivilegedWorkstation' 'AAD-11.7').State | Should -Be 'Gap'
            Ca @(Pol -Users @() -Roles @($script:GA) -Grant @('compliantDevice'));                              (V 'Test-NRGControlAADPrivilegedWorkstation' 'AAD-11.7').State | Should -Be 'Satisfied'
        }
        It 'AAD-10.4: a risk-only "every time" re-prompt is not a periodic sign-in frequency' {
            Ca @(Pol -SignInRisk @('high') -Grant @('mfa') -Session @{ SignInFrequency = @{ IsEnabled = $true; FrequencyInterval = 'everyTime' } })
            (V 'Test-NRGControlAADSignInFrequency' 'AAD-10.4').State | Should -Be 'Gap'
        }
        It 'AAD-11.4 / 11.5: token protection and CAE strict mode read their real values' {
            Ca @(Pol -Session @{ SecureSignInSession = $true });                    (V 'Test-NRGControlAADTokenProtection' 'AAD-11.4').State | Should -Be 'Satisfied'
            Ca @(Pol -Session @{ ContinuousAccessEvaluation = 'strictEnforcement' }); (V 'Test-NRGControlAADContinuousAccess' 'AAD-11.5').State | Should -Be 'Satisfied'
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
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1' 'bg1@x.onmicrosoft.com'), (Asg 'bg2' 'BG2' 'bg2@x.onmicrosoft.com'), (Asg 'alice' 'Alice' 'alice@x.com')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-NRGRawData -Key 'AAD-PIMSchedules' -Data (Bag @{ EligibleSchedules = @('e1'); ActiveSchedules = @(@{ PrincipalId = 'alice'; RoleDefinitionId = $script:GA; AssignmentType = 'Activated' }); SectionStatus = @{ EligibleSchedules = 'Collected' } })
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ BreakGlassIndicators = @(@{ PrincipalId = 'bg1'; CAExcluded = $true; Synced = $false }, @{ PrincipalId = 'bg2'; CAExcluded = $true; Synced = $false }) })
            (V 'Test-NRGControlAADNoPermanentAdmins' 'AAD-3.2').State | Should -Be 'Satisfied'
        }
        It 'AAD-11.2 / 10.2: an ELIGIBLE guest or synced Global Administrator counts' {
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'a' 'A' 'a@x.com')); PrivRoles = @((Asg 'a' 'A' 'a@x.com'))
                AllPrivilegedAssignments = @((Asg 'g' 'Guest' 'g_msp.com#EXT#@x.onmicrosoft.com'), (Asg 'b' 'Bob' 'bob@x.com' $true)); SectionStatus = @{ RoleAssignments = 'Collected' } })
            (V 'Test-NRGControlAADNoGuestInPrivRoles' 'AAD-11.2').State | Should -Be 'Gap'
            (V 'Test-NRGControlAADPrivCloudOnly' 'AAD-10.2').State      | Should -Be 'Gap'
        }
        It 'the collector names privileged built-in roles by template id when roleDefinitions fails' {
            $src = Get-Content -Raw (Join-Path $script:RepoRoot 'Collectors/AAD/Invoke-NRGCollectAADRoles.ps1')
            $src | Should -Match "'62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'"
            ([regex]::Matches($src, '\$privRoleTemplates\[')).Count | Should -BeGreaterOrEqual 2
        }
    }

    Context 'controls whose data answers a different question are manual review' {
        It 'AAD-5.1, AAD-5.2 and AAD-10.3 never pass or fail from unrelated data' {
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ AuthorizationPolicy = @{ AllowedToUseSSPR = $true }; SectionStatus = @{ AuthorizationPolicy = 'Collected' } })
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ SSPRPolicy = @{ MethodsConfigured = @(@{ State = 'enabled' }, @{ State = 'enabled' }) }; BreakGlassIndicators = @(@{ PrincipalId = 'a'; CAExcluded = $true }, @{ PrincipalId = 'b'; CAExcluded = $true }) })
            foreach ($p in @(@('Test-NRGControlAADSSPR','AAD-5.1'), @('Test-NRGControlAADSSPRMethods','AAD-5.2'), @('Test-NRGControlAADBreakGlassMonitoring','AAD-10.3'))) {
                $f = V $p[0] $p[1]
                $f.State  | Should -Be 'NotApplicable' -Because $p[1]
                $f.Detail | Should -Match 'requires manual verification'
            }
        }
    }

    Context 'authentication methods' {
        It 'AAD-9.1 reads the feature setting''s state; AAD-9.2 counts Authenticator phone sign-in' {
            $src = Get-Content -Raw (Join-Path $script:RepoRoot 'Collectors/AAD/Invoke-NRGCollectAADAuthPolicies.ps1')
            $src | Should -Match "featureSettings\.numberMatchingRequiredState\.state"
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ AuthMethodsPolicy = @{ AuthenticationMethodConfigs = @(@{ Id = 'Fido2'; State = 'disabled' }, @{ Id = 'MicrosoftAuthenticator'; State = 'enabled'; AuthenticationModes = @('any') }) }; SectionStatus = @{ AuthMethodsPolicy = 'Collected' } })
            (V 'Test-NRGControlAADPasswordless' 'AAD-9.2').State | Should -Be 'Satisfied'
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
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        function script:V { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
    }
    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    It 'the default Guest User role (Microsoft''s default, nothing configured) is a Gap, not Partial' {
        Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data @{ Success = $true; Data = @{ ExternalCollab = @{ GuestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3' } } }
        (V 'Test-NRGControlAADGuestPermissions' 'AAD-4.3').State | Should -Be 'Gap'
    }
    It 'CAE strict mode not enforced (the default) is a Gap, not Partial' {
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data @{ Success = $true; Data = @{ Policies = @() } }
        (V 'Test-NRGControlAADContinuousAccess' 'AAD-11.5').State | Should -Be 'Gap'
    }
    It 'cross-tenant access settings that were not returned are not assessed (was: Partial, half credit for no data)' {
        Set-NRGRawData -Key 'AAD-AuthPolicies' -Data @{ Success = $true; Data = @{ CrossTenantAccess = $null; SectionStatus = @{ CrossTenantAccess = 'Collected' } } }
        $f = @(& { Test-NRGControlAADCrossTenantAccess | Out-Null; Get-NRGFindings | Where-Object { $_.ControlId -eq 'AAD-11.6' } })
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
# (Get-NRGSecurityDefaultsState); a state that was not read changes nothing.
Describe 'Security Defaults: Conditional Access controls account for it' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        $script:GA  = '62e90394-69f5-4237-9190-012177145e10'

        function script:Bag([hashtable] $Data, [bool] $Success = $true) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $Success; Data = $Data } }
        # Raw collector shape. $null omits SecurityDefaults (the sub-read failed).
        function script:Set-SD($Value) {
            $d = @{}
            if ($null -ne $Value) { $d.SecurityDefaults = @{ IsEnabled = $Value } }
            Set-NRGRawData -Key 'AAD-AuthPolicies' -Data (Bag $d)
        }
        function script:Set-CA([object[]] $Policies = @(), [bool] $Success = $true, [object[]] $Locations = @(), [hashtable] $Status = @{ NamedLocations = 'Collected'; TokenProtection = 'Collected' }) {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($Policies); NamedLocations = @($Locations); SectionStatus = $Status } $Success)
        }
        # The policy shape Invoke-NRGCollectAADCAPolicies stores.
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
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-NRGFindings | Where-Object ControlId -eq $Cid)[-1] }
        function script:Asg([string] $Id, [string] $Name, [string] $Role = 'Global Administrator', [string] $RoleId = $script:GA, $Synced = $null) {
            @{ PrincipalId = $Id; PrincipalDisplayName = $Name; PrincipalUPN = "$Id@x.onmicrosoft.com"; PrincipalType = '#microsoft.graph.user'
               RoleDefinitionId = $RoleId; RoleDefinitionName = $Role; IsPriv = $true; OnPremisesSyncEnabled = $Synced }
        }
        # Swaps Invoke-NRGGraphRequest inside the module (the only way to
        # intercept a call made from a collector) and restores it afterwards.
        $script:OrigGraph = & $script:Mod { ${function:Invoke-NRGGraphRequest} }
        function script:Set-Graph([scriptblock] $Body) {
            & $script:Mod { param($b) Set-Item -Path 'function:script:Invoke-NRGGraphRequest' -Value $b } $Body
        }
    }

    BeforeEach { Clear-NRGState }
    AfterEach  { & $script:Mod { param($o) Set-Item -Path 'function:script:Invoke-NRGGraphRequest' -Value $o } $script:OrigGraph }
    AfterAll   { Clear-NRGState }

    Context 'the one reader' {
        It 'Get-NRGSecurityDefaultsState returns $true/$false only for a boolean read from a successful AAD-AuthPolicies, $null otherwise' {
            $read = { param($auth) & (Get-Module NRG-Assessment) { param($a) Get-NRGSecurityDefaultsState -AuthPolicies $a } $auth }
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
            & (Get-Module NRG-Assessment) { $null -eq (Get-NRGSecurityDefaultsState) } | Should -BeTrue
            Set-SD $true
            & (Get-Module NRG-Assessment) { Get-NRGSecurityDefaultsState } | Should -BeExactly $true
            # Internal to the module: the export lists (and the README's count) do not change.
            Get-Command -Module NRG-Assessment -Name 'Get-NRGSecurityDefaultsState', 'Add-NRGSecurityDefaultsFinding', 'Test-NRGSecurityDefaultsLicenseFree',
                'Test-NRGSecurityDefaultsUnresolved', 'Add-NRGSecurityDefaultsUnreadFinding', 'Get-NRGFindingRemediation', 'Test-NRGSecurityDefaultsVerdictDetail' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
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
                $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-NRGSecurityDefaultsState' }, $true))
                foreach ($call in $calls) {
                    $sites++
                    $where = "$($f.Name):$($call.Extent.StartLineNumber)"
                    $pipe = $call.Parent
                    $pipe | Should -BeOfType [System.Management.Automation.Language.PipelineAst] -Because $where
                    $holder = $pipe.Parent
                    if ($holder -is [System.Management.Automation.Language.ParenExpressionAst]) {
                        # (Get-NRGSecurityDefaultsState) -eq $true
                        (& $isBoolCompare $holder.Parent $holder) | Should -BeTrue -Because "$where must compare the state with -eq `$true / -eq `$false"
                    } elseif ($holder -is [System.Management.Automation.Language.AssignmentStatementAst]) {
                        # $x = Get-NRGSecurityDefaultsState ...: every later read of $x compares it.
                        $name = $holder.Left.VariablePath.UserPath
                        $fn = $holder.Parent
                        while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
                        $reads = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq $name -and -not [object]::ReferenceEquals($n, $holder.Left) }, $true))
                        $reads.Count | Should -BeGreaterThan 0 -Because $where
                        foreach ($r in $reads) {
                            (& $isBoolCompare $r.Parent $r) | Should -BeTrue -Because "`$$name ($where) is read at line $($r.Extent.StartLineNumber) without -eq `$true / -eq `$false"
                        }
                    } else {
                        throw "$where uses Get-NRGSecurityDefaultsState in an unrecognized position: $($holder.GetType().Name)"
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
            Invoke-NRGCollectAADAuthPolicies 3>$null | Out-Null
            $sdData = (Get-NRGRawData -Key 'AAD-AuthPolicies').Data.SecurityDefaults
            $sdData | Should -Not -BeNullOrEmpty -Because 'the endpoint answered'
            $sdData.ContainsKey('IsEnabled') | Should -BeTrue
            ($null -eq $sdData['IsEnabled']) | Should -BeTrue -Because 'a null isEnabled used to cast to $false ("disabled")'
            @(Get-NRGExceptions | Where-Object Source -eq 'AAD-SecurityDefaults').Count | Should -BeGreaterThan 0

            Clear-NRGState
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'identitySecurityDefaultsEnforcementPolicy') { return @{ isEnabled = $true } }
                return @{ value = @() }
            }
            Invoke-NRGCollectAADAuthPolicies 3>$null | Out-Null
            (Get-NRGRawData -Key 'AAD-AuthPolicies').Data.SecurityDefaults.IsEnabled | Should -BeExactly $true
        }

        It 'the Users collector records a premium-license refusal of the registration report, and nothing for any other failure' {
            foreach ($case in @(
                    @{ Msg = 'Neither tenant is B2C or tenant doesn''t have premium license'; Expect = 'PremiumLicenseRequired' },
                    @{ Msg = 'Graph 403 Forbidden: insufficient privileges'; Expect = $null })) {
                Clear-NRGState
                $script:RegMsg = $case.Msg
                Set-Graph {
                    param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                    if ($Uri -match 'userRegistrationDetails') { throw $script:RegMsg }
                    # Every property the collector $selects (Graph returns a selected property as null, not absent).
                    return @{ value = @(@{ id = 'u1'; displayName = 'A'; userPrincipalName = 'a@corp.example'; accountEnabled = $true; userType = 'Member'
                                           onPremisesSyncEnabled = $null; assignedLicenses = @(); createdDateTime = '2026-01-01T00:00:00Z'; lastPasswordChangeDateTime = '2026-01-01T00:00:00Z' }) }
                }
                & $script:Mod { param($m) $script:RegMsg = $m } $case.Msg
                Invoke-NRGCollectAADUsers 3>$null | Out-Null
                $raw = Get-NRGRawData -Key 'AAD-Users'
                Get-NRGNestedProperty -Object $raw -Path 'Data.SectionStatus.MFARegistration' | Should -Be 'Failed'
                $got = Get-NRGNestedProperty -Object $raw -Path 'Data.MFARegistrationFailure' -Default $null
                if ($null -eq $case.Expect) { $got | Should -BeNullOrEmpty } else { $got | Should -Be $case.Expect }
            }
        }

        It 'the Conditional Access collector says Security Defaults is on in its console note, within the 70-character console line, and says nothing when it was not read' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                return @{ value = @() }
            }
            Set-SD $true
            Invoke-NRGCollectAADCAPolicies 3>$null | Out-Null
            $cov = (Get-NRGCoverage)['AAD-CAPolicies']
            $cov.Status | Should -Be 'Collected'
            $cov.Note   | Should -Match '^Security Defaults on: CA policies cannot be turned on \(0 found\)$'
            $cov.Note.Length | Should -BeLessOrEqual 70

            Clear-NRGState
            Invoke-NRGCollectAADCAPolicies 3>$null | Out-Null
            (Get-NRGCoverage)['AAD-CAPolicies'].Note | Should -Be '' -Because 'a Security Defaults state that was not read changes nothing'
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
            Invoke-NRGCollectAADCAPolicies 3>$null | Out-Null
            $raw = Get-NRGRawData -Key 'AAD-CAPolicies'
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
            Invoke-NRGCollectAADCAPolicies 3>$null | Out-Null
            $raw = Get-NRGRawData -Key 'AAD-CAPolicies'
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
            Invoke-NRGCollectAADCAPolicies 3>$null | Out-Null
            $cov = (Get-NRGCoverage)['AAD-CAPolicies']
            $cov.Status | Should -Be 'Failed'
            $cov.Note   | Should -Match 'Security Defaults is on'
            ('failed: ' + $cov.Note).Length | Should -BeLessOrEqual 70
            (Get-NRGRawData -Key 'AAD-CAPolicies').Success | Should -BeFalse
        }
    }

    Context 'protections Security Defaults provides' {
        It 'AAD-1.1: Security Defaults on is Satisfied through Security Defaults; the same CA data with Security Defaults disabled is still the Gap' {
            Set-CA @(); Set-SD $true
            $f = V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1'
            $f.State    | Should -Be 'Satisfied'
            $f.Severity | Should -Be 'Informational'
            $f.Detail   | Should -Match '^Security Defaults is enabled\.'
            $f.Detail   | Should -Match 'Exchange ActiveSync basic authentication'
            (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
            Clear-NRGState; Set-CA @(); Set-SD $false
            $g = V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1'
            $g.State  | Should -Be 'Gap'
            $g.Detail | Should -Match 'No Conditional Access policy found that blocks legacy authentication'
        }

        It 'AAD-1.1: Security Defaults on stays Satisfied when the Conditional Access read failed' {
            Set-CA @() -Success $false; Set-SD $true
            (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Satisfied'
        }

        It 'AAD-1.1: a report-only legacy block beside Security Defaults earns no half credit and is named, never "nothing is blocked"' {
            Set-CA @(New-Pol -Name 'CA01 Block legacy' -State 'enabledForReportingButNotEnforced' -ClientApps @('other') -Grant @('block')); Set-SD $true
            $f = V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'CA01 Block legacy \[report-only\]'
            $f.Detail | Should -Not -Match 'nothing is blocked'
        }

        It 'AAD-11.1: Security Defaults on is Satisfied — device code flow is blocked by Security Defaults' {
            Set-CA @(); Set-SD $true
            $f = V 'Test-NRGControlAADDeviceCode' 'AAD-11.1'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'device code flow are blocked'
        }

        It 'AAD-1.3: Security Defaults on is Partial (Medium) for standard admin MFA at every sign-in, never the Critical Gap' {
            Set-CA @(); Set-SD $true
            $f = V 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3'
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
            foreach ($p in @(@('Test-NRGControlAADPhishResistantMFA','AAD-1.3'), @('Test-NRGControlAADDeviceCode','AAD-11.1'), @('Test-NRGControlAADSignInFrequency','AAD-10.4'))) {
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
            $f = V 'Test-NRGControlAADCA' 'AAD-2.1'
            $f.State       | Should -Be 'Gap'
            $f.Detail      | Should -Match 'AAD-1\.1'
            $f.Detail      | Should -Match 'cannot be turned on'
            $f.Detail      | Should -Not -Match 'password-only'
            $f.Remediation | Should -Not -Match 'report-only mode first'
            Clear-NRGState; Set-CA @(); Set-SD $false
            $g = V 'Test-NRGControlAADCA' 'AAD-2.1'
            $g.Detail | Should -Match 'Security Defaults is disabled'
            $g.Detail | Should -Not -Match 'relies on Security Defaults'
        }

        It 'AAD-2.2: under Security Defaults none defined is still the Gap (licensed but not configured); defined locations earn no credit; not read is not assessed' {
            Set-CA @(); Set-SD $true
            $g = V 'Test-NRGControlAADNamedLocations' 'AAD-2.2'
            $g.State       | Should -Be 'Gap' -Because 'with Security Defaults off the same data is a Gap; license gating, not this evaluator, handles an unlicensed tenant'
            $g.Detail      | Should -Match '^Security Defaults is enabled\. No named locations are defined\.'
            $g.Remediation | Should -Match 'turn off Security Defaults'
            (@($g.FrameworkIds) -join ' ') | Should -Match 'NIST:'
            Clear-NRGState; Set-CA @(); Set-SD $false
            (V 'Test-NRGControlAADNamedLocations' 'AAD-2.2').State | Should -Be 'Gap'

            Clear-NRGState; Set-CA @() -Locations @(@{ DisplayName = 'Office'; IsTrusted = $true }); Set-SD $true
            $f = V 'Test-NRGControlAADNamedLocations' 'AAD-2.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '1 marked trusted'
            $f.Detail | Should -Match 'earn no credit'
            (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'

            foreach ($unread in @({ Set-CA @() -Status @{ NamedLocations = 'Failed'; TokenProtection = 'Collected' } }, { Set-CA @() -Success $false })) {
                Clear-NRGState; & $unread; Set-SD $true
                $n = V 'Test-NRGControlAADNamedLocations' 'AAD-2.2'
                $n.State  | Should -Be 'NotApplicable'
                $n.Detail | Should -Match 'not collected'
            }
        }

        It 'AAD-11.4: Security Defaults on is a Gap even when the beta token-protection read failed' {
            Set-CA @() -Status @{ NamedLocations = 'Collected'; TokenProtection = 'Failed' }; Set-SD $true
            (V 'Test-NRGControlAADTokenProtection' 'AAD-11.4').State | Should -Be 'Gap'
        }

        It 'AAD-1.4, AAD-1.5, AAD-10.1, AAD-11.5 under Security Defaults stay Gaps and name it; AAD-1.4 no longer says "let through without a challenge"' {
            Set-CA @(); Set-SD $true
            foreach ($p in @(@('Test-NRGControlAADSignInRisk','AAD-1.4'), @('Test-NRGControlAADUserRisk','AAD-1.5'), @('Test-NRGControlAADIdentityProtection','AAD-10.1'), @('Test-NRGControlAADContinuousAccess','AAD-11.5'))) {
                $f = V $p[0] $p[1]
                $f.State  | Should -Be 'Gap' -Because $p[1]
                $f.Detail | Should -Match 'Security Defaults is enabled' -Because $p[1]
                if ($p[1] -eq 'AAD-1.4') { $f.Detail | Should -Not -Match 'without a challenge' }
            }
        }

        It 'AAD-2.3 and INT-1.2: a report-only compliant-device policy beside Security Defaults is a Gap for both, not Partial' {
            Set-CA @(New-Pol -Name 'Require compliant device' -State 'enabledForReportingButNotEnforced' -Grant @('compliantDevice')); Set-SD $true
            Set-NRGRawData -Key 'Intune-DeviceCompliance' -Data (Bag @{})
            $d = V 'Test-NRGControlAADDeviceComplianceCA' 'AAD-2.3'
            $d.State  | Should -Be 'Gap'
            # Microsoft: users are prompted "based on factors such as location,
            # device, role, and task", so the prompts DO consider the device;
            # what Security Defaults lacks is a device requirement.
            $d.Detail | Should -Not -Match 'do not check the device'
            $d.Detail | Should -Match 'do not require the device to be compliant, managed or hybrid-joined'
            $i = V 'Test-NRGControlIntune' 'INT-1.2'
            $i.State  | Should -Be 'Gap'
            $i.Detail | Should -Match 'Security Defaults'
        }
    }

    Context 'break-glass and standing access' {
        It 'AAD-7.2: Security Defaults on requires manual verification, never the no-break-glass Gap; with Security Defaults disabled the same data is still the Gap' {
            $gov = Bag @{ BreakGlassIndicators = @(@{ PrincipalId = 'ga1'; DisplayName = 'GA1'; CAExcluded = $false; Synced = $false }, @{ PrincipalId = 'ga2'; DisplayName = 'GA2'; CAExcluded = $false; Synced = $false }); SectionStatus = @{ BreakGlassIndicators = 'Collected' } }
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data $gov; Set-SD $true
            $f = V 'Test-NRGControlAADBreakGlass' 'AAD-7.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'emergency access'
            $f.Detail | Should -Match 'requires manual verification'
            $f.Detail | Should -Match 'directory synchronization accounts' -Because 'Microsoft excludes them automatically, so "no account can be excluded" is overstated'
            $f.Detail | Should -Not -Match 'no account can be excluded from it[,.]'
            $f.Detail | Should -Not -Match 'If CA policies break'
            (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
            Clear-NRGState; Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data $gov; Set-SD $false
            (V 'Test-NRGControlAADBreakGlass' 'AAD-7.2').State | Should -Be 'Gap'
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
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = $gas; AllPrivilegedAssignments = $pool; SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-CA @(); Set-SD $true
            Invoke-NRGCollectAADIdentityGovernance 3>$null | Out-Null
            Get-NRGNestedProperty -Object (Get-NRGRawData -Key 'AAD-IdentityGovernance') -Path 'Data.SectionStatus.BreakGlassIndicators' | Should -Be 'Collected' -Because 'the collector must reach the exclusion check, which writes CAExcluded = $false for both'
            $f = V 'Test-NRGControlAADBreakGlass' 'AAD-7.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '2 permanent Global Administrator assignment\(s\) are on accounts not marked as synchronized'
            $f.Detail | Should -Match 'requires manual verification'
            $f.CurrentValue | Should -Match 'GA1, GA2'
        }

        # First live run on the owner's tenant: the break-glass account was
        # excluded from every policy that can block sign-in, but SharePoint's
        # app-enforced restrictions policy (session control only, no grant)
        # reached it, so AAD-7.2 said "no emergency access path".
        It 'AAD-7.2: a session-only policy (no grant control) does not disqualify a break-glass account; a blocking policy that reaches it is named' {
            Set-Graph {
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                return @{ value = @() }
            }
            $gas = @((Asg 'bg1' 'BG1'), (Asg 'bg2' 'BG2'), (Asg 'adm' 'Admin'))
            $pool = @($gas | ForEach-Object { $c = @{} + $_; $c.Source = 'permanent'; $c })
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = $gas; AllPrivilegedAssignments = $pool; SectionStatus = @{ RoleAssignments = 'Collected' } })
            $session = New-Pol -Name 'SharePoint app-enforced restrictions' -Session @{ ApplicationEnforcedRestrictions = $true }
            $block = New-Pol -Name 'Block legacy' -ClientApps @('other') -Grant @('block'); $block.Conditions.Users.ExcludeUsers = @('bg1', 'bg2')
            Set-CA @($session, $block); Set-SD $false
            Invoke-NRGCollectAADIdentityGovernance 3>$null | Out-Null
            $f = V 'Test-NRGControlAADBreakGlass' 'AAD-7.2'
            $f.State | Should -Be 'Satisfied' -Because 'the only policy that does not exclude them cannot deny a sign-in'

            Clear-NRGState
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = $gas; AllPrivilegedAssignments = $pool; SectionStatus = @{ RoleAssignments = 'Collected' } })
            $mfa = New-Pol -Name 'Require MFA all users' -Grant @('mfa'); $mfa.Conditions.Users.ExcludeUsers = @('bg1')
            Set-CA @($session, $block, $mfa); Set-SD $false
            Invoke-NRGCollectAADIdentityGovernance 3>$null | Out-Null
            $f = V 'Test-NRGControlAADBreakGlass' 'AAD-7.2'
            $f.State | Should -Be 'Partial'
            $f.Detail | Should -Match "BG2 \(bg2@x\.onmicrosoft\.com\) is still reached by: 'Require MFA all users'"
            $f.Detail | Should -Not -Match 'SharePoint app-enforced'
        }

        It 'AAD-3.2: under Security Defaults a stale CAExcluded=$true is not credited — two permanent cloud-only Global Administrators beside PIM-eligible assignments are not applicable, and a permanent Exchange Administrator is still a Gap that says none was set aside' {
            $pim = Bag @{ EligibleSchedules = @('e1'); ActiveSchedules = @(); SectionStatus = @{ EligibleSchedules = 'Collected' } }
            $gov = Bag @{ BreakGlassIndicators = @(@{ PrincipalId = 'bg1'; CAExcluded = $true; Synced = $false }, @{ PrincipalId = 'bg2'; CAExcluded = $true; Synced = $false }) }
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1'), (Asg 'bg2' 'BG2')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-NRGRawData -Key 'AAD-PIMSchedules' -Data $pim
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data $gov
            Set-SD $true
            $f = V 'Test-NRGControlAADNoPermanentAdmins' 'AAD-3.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Not -Match 'BG1|BG2' -Because 'account names go in CurrentValue only'
            $f.Detail | Should -Match 'requires manual verification'
            $f.Detail | Should -Match 'not marked as synchronized from on-premises' -Because 'a $null OnPremisesSyncEnabled is what was read, not proof of cloud-only'
            $f.Detail | Should -Match 'directory synchronization accounts'

            Clear-NRGState
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1'), (Asg 'bg2' 'BG2'), (Asg 'ex1' 'Ex Admin' 'Exchange Administrator' '29232cdf-9323-42fd-ade2-1d097af3e4de')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-NRGRawData -Key 'AAD-PIMSchedules' -Data $pim
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data $gov
            Set-SD $true
            $g = V 'Test-NRGControlAADNoPermanentAdmins' 'AAD-3.2'
            $g.State  | Should -Be 'Gap'
            $g.Detail | Should -Match 'none was set aside'
            $g.Detail | Should -Match '^Security Defaults is enabled\. 3 permanent' -Because 'the two Global Administrators are not set aside beside Security Defaults'
            (@($g.FrameworkIds) -join ' ') | Should -Match 'NIST:'
        }

        It 'AAD-3.2: Security Defaults on while the Conditional Access read lists a policy as On is not assessed, never a Security Defaults verdict' {
            $pim = Bag @{ EligibleSchedules = @('e1'); ActiveSchedules = @(); SectionStatus = @{ EligibleSchedules = 'Collected' } }
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1'), (Asg 'ex1' 'Ex Admin' 'Exchange Administrator' '29232cdf-9323-42fd-ade2-1d097af3e4de')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-NRGRawData -Key 'AAD-PIMSchedules' -Data $pim
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ BreakGlassIndicators = @(@{ PrincipalId = 'bg1'; CAExcluded = $true; Synced = $false }) })
            Set-CA @(New-Pol -Name 'MFA all users' -Grant @('mfa')); Set-SD $true
            $f = V 'Test-NRGControlAADNoPermanentAdmins' 'AAD-3.2'
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
                Clear-NRGState
                Set-NRGRawData -Key 'SharePoint' -Data (Bag @{ TenantSettings = $ts; TenantSettingsSPO = @{ ConditionalAccessPolicy = $cap }; ExternalSharing = $ts.SharingCapability })
                Set-SD $true
                $f = V 'Test-NRGControlSharePoint' 'SPO-1.5'
                $f.State       | Should -Be 'Gap' -Because $cap
                $f.Detail      | Should -Match '^Security Defaults is enabled\.' -Because $cap
                $f.Detail      | Should -Match 'relies on Microsoft Entra Conditional Access policies' -Because $cap
                $f.Remediation | Should -Match 'turn off Security Defaults' -Because $cap
                (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
            }
            foreach ($sd in @($null, $false)) {
                Clear-NRGState
                Set-NRGRawData -Key 'SharePoint' -Data (Bag @{ TenantSettings = $ts; TenantSettingsSPO = @{ ConditionalAccessPolicy = 'AllowLimitedAccess' }; ExternalSharing = $ts.SharingCapability })
                Set-SD $sd
                (V 'Test-NRGControlSharePoint' 'SPO-1.5').State | Should -Be 'Satisfied' -Because "Security Defaults read as '$sd'"
            }
        }
    }

    Context 'definitions match the verdicts' {
        # Security Defaults prompts ordinary users only when Microsoft decides
        # it is necessary; only 16 administrator roles do MFA at every sign-in.
        # The definition AAD-1.2 is scored against must say that, or a
        # Satisfied under Security Defaults contradicts its own detail.
        It 'AAD-1.2''s definition does not claim Security Defaults requires MFA of every user at every sign-in' {
            $c = @(Get-NRGControlDefinitions | Where-Object ControlId -eq 'AAD-1.2')[0]
            $c.Description | Should -Not -Match 'Security Defaults requires MFA for all users on every sign-in'
            $c.Description | Should -Match 'when Microsoft decides it is necessary'
            $c.Description | Should -Match '16 administrator roles'
        }
    }

    Context 'reporting' {
        It 'AAD-3.2 and AAD-7.2 under Security Defaults are filed for manual review and reach the questionnaire; AAD-2.2 with unusable locations does not apply; none is license gated' {
            Set-SD $true
            Set-CA @() -Locations @(@{ DisplayName = 'Office'; IsTrusted = $true })
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1'), (Asg 'bg2' 'BG2')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-NRGRawData -Key 'AAD-PIMSchedules' -Data (Bag @{ EligibleSchedules = @('e1'); ActiveSchedules = @(); SectionStatus = @{ EligibleSchedules = 'Collected' } })
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ BreakGlassIndicators = @(
                @{ PrincipalId = 'bg1'; DisplayName = 'BG1'; CAExcluded = $false; Synced = $false; Source = 'permanent' },
                @{ PrincipalId = 'bg2'; DisplayName = 'BG2'; CAExcluded = $false; Synced = $false; Source = 'permanent' }); SectionStatus = @{ BreakGlassIndicators = 'Collected' } })
            foreach ($fn in 'Test-NRGControlAADNamedLocations', 'Test-NRGControlAADNoPermanentAdmins', 'Test-NRGControlAADBreakGlass') { & $fn 3>$null | Out-Null }
            $scope = Get-NRGAssessmentScope -Findings (Get-NRGFindings) -RawData (Get-NRGRawData)
            # Emergency access accounts apply to every tenant; the tool cannot
            # identify them beside Security Defaults. "Checked and not
            # applicable to this tenant" would be false.
            foreach ($cid in 'AAD-3.2', 'AAD-7.2') {
                @($scope.NoProgrammaticCheck   | ForEach-Object ControlId) | Should -Contain $cid
                @($scope.NotApplicableToTenant | ForEach-Object ControlId) | Should -Not -Contain $cid
                @($scope.CollectionIncomplete  | ForEach-Object ControlId) | Should -Not -Contain $cid
                @($scope.LicenceBlocked        | ForEach-Object ControlId) | Should -Not -Contain $cid
            }
            $items = @(Get-NRGManualReviewItems -Scope $scope)
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

        # Set-NRGLicenseGating never moves a Satisfied, so asserting AAD-1.1 /
        # AAD-11.1 stay Satisfied after gating proved nothing. What the
        # exemption decides is the per-finding license answer every consumer
        # asks; assert that directly, both ways.
        It 'on a Business Standard tenant with Security Defaults, AAD-1.1 and AAD-11.1 findings need no license; the gated AAD-1.3 keeps the Security Defaults reason' {
            Set-CA @(); Set-SD $true
            foreach ($fn in 'Test-NRGControlAADLegacyAuth', 'Test-NRGControlAADDeviceCode', 'Test-NRGControlAADPhishResistantMFA') { & $fn 3>$null | Out-Null }
            $prof = Get-NRGTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','INTUNE_O365','TEAMS1','SHAREPOINTSTANDARD','RMS_S_BASIC') })
            $byId = @{}; foreach ($f in Get-NRGFindings) { $byId[$f.ControlId] = $f }
            foreach ($cid in 'AAD-1.1', 'AAD-11.1') {
                Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId $cid -Finding $byId[$cid] | Should -BeTrue -Because "$cid is met by Security Defaults, which needs no license"
                Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId $cid | Should -BeFalse -Because 'without the finding the Conditional Access requirement applies'
            }
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId 'AAD-1.3' -Finding $byId['AAD-1.3'] | Should -BeFalse -Because 'phishing-resistant MFA needs Conditional Access'
            $null = Set-NRGLicenseGating -LicenseProfile $prof
            $byId = @{}; foreach ($f in Get-NRGFindings) { $byId[$f.ControlId] = $f }
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
            $prof = Get-NRGTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','INTUNE_O365','TEAMS1','SHAREPOINTSTANDARD','RMS_S_BASIC') })
            $users = @(@{ UserPrincipalName = 'a@corp.example'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' }, @{ UserPrincipalName = 'b@corp.example'; DisplayName = 'B'; AccountEnabled = $true; UserType = 'Member' })
            $reg = @(@{ UserPrincipalName = 'a@corp.example'; IsMfaRegistered = $true }, @{ UserPrincipalName = 'b@corp.example'; IsMfaRegistered = $false })
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = $reg }; SectionStatus = @{ MFARegistration = 'Collected' } })
            Set-CA @(); Set-SD $true
            & 'Test-NRGControlAADMFA' 3>$null | Out-Null
            $null = Set-NRGLicenseGating -LicenseProfile $prof
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'AAD-1.2')[0]
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Not -Match 'upgrade opportunity'
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId 'AAD-1.2' -Finding $f | Should -BeTrue
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId 'AAD-1.2' | Should -BeFalse -Because 'without the finding the Conditional Access requirement still applies'

            # The CA-path AAD-1.2 on the same tenant is still gated.
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = $reg }; SectionStatus = @{ MFARegistration = 'Collected' } })
            Set-CA @(); Set-SD $false
            & 'Test-NRGControlAADMFA' 3>$null | Out-Null
            $null = Set-NRGLicenseGating -LicenseProfile $prof
            $c = @(Get-NRGFindings | Where-Object ControlId -eq 'AAD-1.2')[0]
            $c.State  | Should -Be 'NotApplicable'
            $c.Detail | Should -Match 'upgrade opportunity'

            Clear-NRGState
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = @() }; SectionStatus = @{ MFARegistration = 'Failed' } })
            Set-CA @(); Set-SD $true
            & 'Test-NRGControlAADMFA' 3>$null | Out-Null
            $null = Set-NRGLicenseGating -LicenseProfile $prof
            $scope = Get-NRGAssessmentScope -Findings (Get-NRGFindings) -RawData (Get-NRGRawData) -LicenseProfile $prof
            @($scope.CollectionIncomplete | ForEach-Object ControlId) | Should -Contain 'AAD-1.2'
            @($scope.LicenceBlocked       | ForEach-Object ControlId) | Should -Not -Contain 'AAD-1.2'
        }

        It 'AAD-1.2 through Security Defaults says the registration report needs Entra ID P1 or P2, and says re-running will not help only when Graph refused it for that reason' {
            $users = @(@{ UserPrincipalName = 'a@corp.example'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' })
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = @() }; MFARegistrationFailure = 'PremiumLicenseRequired'; SectionStatus = @{ MFARegistration = 'Failed' } })
            Set-CA @(); Set-SD $true
            $f = V 'Test-NRGControlAADMFA' 'AAD-1.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'P1 or P2'
            $f.Detail | Should -Match 'Re-running will not change this'
            $f.Detail | Should -Match 'not collected'
            (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'

            Clear-NRGState
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = @() }; SectionStatus = @{ MFARegistration = 'Failed' } })
            Set-CA @(); Set-SD $true
            $g = V 'Test-NRGControlAADMFA' 'AAD-1.2'
            $g.Detail | Should -Match 'P1 or P2'
            $g.Detail | Should -Not -Match 'Re-running will not change this' -Because 'the failure was not the license refusal'
        }

        It 'AAD-1.2 through Security Defaults with no enabled members is not applicable and carries its citations' {
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = @(); MFARegistration = @{ RegistrationDetails = @() }; SectionStatus = @{ MFARegistration = 'Collected' } })
            Set-CA @(); Set-SD $true
            $f = V 'Test-NRGControlAADMFA' 'AAD-1.2'
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
            $script:SdPairs = @(@('Test-NRGControlAADLegacyAuth','AAD-1.1'), @('Test-NRGControlAADDeviceCode','AAD-11.1'), @('Test-NRGControlAADPhishResistantMFA','AAD-1.3'))
            $script:BSProf = { Get-NRGTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','INTUNE_O365','TEAMS1','SHAREPOINTSTANDARD','RMS_S_BASIC') }) }
        }

        It 'AAD-1.1, AAD-11.1 and AAD-1.3 with the state not read and no CA policy On are not assessed, with citations, never the Gap that assumes it is off' {
            foreach ($pols in @(@(), @(New-Pol -Name 'Pilot MFA' -State 'enabledForReportingButNotEnforced' -Grant @('mfa')))) {
                foreach ($p in $script:SdPairs) {
                    Clear-NRGState; Set-CA $pols; Set-SD $null
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
                Clear-NRGState; Set-CA @(New-Pol -Name 'Pilot device' -Users @('u1') -Grant @('compliantDevice')); Set-SD $null
                (V $p[0] $p[1]).State | Should -Be 'Gap' -Because $p[1]
            }
        }

        It 'a Security Defaults state that was not read is filed as a collection gap on a Business Standard tenant, never license gated' {
            $users = @(@{ UserPrincipalName = 'a@corp.example'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' })
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = @(@{ UserPrincipalName = 'a@corp.example'; IsMfaRegistered = $true }) }; SectionStatus = @{ MFARegistration = 'Collected' } })
            Set-CA @(); Set-SD $null
            foreach ($p in $script:SdPairs) { & $p[0] 3>$null | Out-Null }
            Test-NRGControlAADMFA 3>$null | Out-Null
            $prof = & $script:BSProf
            $null = Set-NRGLicenseGating -LicenseProfile $prof
            $scope = Get-NRGAssessmentScope -Findings (Get-NRGFindings) -RawData (Get-NRGRawData) -LicenseProfile $prof
            foreach ($cid in 'AAD-1.1', 'AAD-11.1', 'AAD-1.3', 'AAD-1.2') {
                @($scope.CollectionIncomplete | ForEach-Object ControlId) | Should -Contain $cid
                @($scope.LicenceBlocked       | ForEach-Object ControlId) | Should -Not -Contain $cid
            }
        }
    }

    Context 'break-glass beside Security Defaults: what the role data proves' {
        BeforeAll {
            function script:Set-Gov([object[]] $Gas) {
                Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ BreakGlassIndicators = @($Gas); SectionStatus = @{ BreakGlassIndicators = 'Collected' } })
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
            $f = V 'Test-NRGControlAADBreakGlass' 'AAD-7.2'
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
            $f = V 'Test-NRGControlAADBreakGlass' 'AAD-7.2'
            $f.State        | Should -Be 'Gap'
            $f.Detail       | Should -Match '1 PIM-eligible'
            $f.Detail       | Should -Match 'two-account recommendation is not met'
            $f.CurrentValue | Should -Match ': 1 \(GA1\)$'
        }

        It 'AAD-7.2: with the Global Administrator list not collected the finding is a collection gap, not manual review' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (Bag @{ BreakGlassIndicators = @(); SectionStatus = @{ BreakGlassIndicators = 'Failed' } })
            Set-SD $true
            $f = V 'Test-NRGControlAADBreakGlass' 'AAD-7.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'was not collected'
            $f.Detail | Should -Not -Match 'requires manual verification'
            $scope = Get-NRGAssessmentScope -Findings (Get-NRGFindings) -RawData (Get-NRGRawData)
            @($scope.CollectionIncomplete | ForEach-Object ControlId) | Should -Contain 'AAD-7.2'
        }

        It 'AAD-3.2: a single remaining permanent Global Administrator is described as one account, not "these are the two"' {
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleAssignments = @((Asg 'bg1' 'BG1')); SectionStatus = @{ RoleAssignments = 'Collected' } })
            Set-NRGRawData -Key 'AAD-PIMSchedules' -Data (Bag @{ EligibleSchedules = @('e1'); ActiveSchedules = @(); SectionStatus = @{ EligibleSchedules = 'Collected' } })
            Set-SD $true
            $f = V 'Test-NRGControlAADNoPermanentAdmins' 'AAD-3.2'
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
            $f = V 'Test-NRGControlAADCA' 'AAD-2.1'
            $f.Detail | Should -Not -Match 'methods that are not phishing-resistant'
            $f.Detail | Should -Match 'no requirement that the method be phishing-resistant'
        }

        # The tool reads Conditional Access only; the legacy Identity
        # Protection risk policies (retiring October 1, 2026) can still be
        # enforcing and are not read, so "no risk policy is in force" claimed
        # more than was read.
        It 'AAD-1.4, AAD-1.5 and AAD-10.1 scope "no risk policy" to Conditional Access and Security Defaults' {
            Set-CA @(); Set-SD $true
            foreach ($p in @(@('Test-NRGControlAADSignInRisk','AAD-1.4'), @('Test-NRGControlAADUserRisk','AAD-1.5'), @('Test-NRGControlAADIdentityProtection','AAD-10.1'))) {
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
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = @() }; MFARegistrationFailure = 'PremiumLicenseRequired'; SectionStatus = @{ MFARegistration = 'Failed' } })
            Set-CA @() -Success $false; Set-SD $true
            Test-NRGControlAADMFA 3>$null | Out-Null
            $scope = Get-NRGAssessmentScope -Findings (Get-NRGFindings) -RawData (Get-NRGRawData)
            $row = @($scope.CollectionIncomplete | Where-Object ControlId -eq 'AAD-1.2')
            $row.Count | Should -Be 1
            $row[0].Reason | Should -Not -Match "'AAD-CAPolicies' collector did not return data"
            $row[0].Reason | Should -Match 'Re-running will not change this'
        }

        It 'a license-gated Security Defaults finding with the CA read failed is license gated, not "the AAD-CAPolicies collector did not return data"' {
            Set-CA @() -Success $false; Set-SD $true
            Test-NRGControlAADPhishResistantMFA 3>$null | Out-Null
            $prof = Get-NRGTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','INTUNE_O365','TEAMS1','SHAREPOINTSTANDARD','RMS_S_BASIC') })
            $null = Set-NRGLicenseGating -LicenseProfile $prof
            $scope = Get-NRGAssessmentScope -Findings (Get-NRGFindings) -RawData (Get-NRGRawData) -LicenseProfile $prof
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
                Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = $u; MFARegistration = @{ RegistrationDetails = $r }; SectionStatus = @{ MFARegistration = 'Collected' } })
            }
            function script:Set-BSInventory { Set-NRGRawData -Key 'AAD-Inventory' -Data (Bag @{ SubscribedSkus = $script:BSSkus }) }
            function script:Render-Html {
                $out = Join-Path ([IO.Path]::GetTempPath()) ('nrg-sd-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.html')
                Publish-NRGAssessmentHTML -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; Operator = 't'; ToolVersion = 'test' } `
                    -Findings @(Get-NRGFindings) -Connections @{ Graph = $true } -OutputPath $out -ClientName 'Test Co' 3>$null | Out-Null
                $h = Get-Content -Raw $out; Remove-Item $out -ErrorAction SilentlyContinue; $h
            }
        }

        # With every user registered, what remains (MFA at every sign-in for
        # all users) needs a Conditional Access policy, i.e. Entra ID P1: the
        # same "not licensed is not scored" rule as any other control.
        It 'AAD-1.2 with every user registered beside Security Defaults is gated on a tenant without Entra ID P1, keeping the Security Defaults verdict in the detail' {
            Set-TwoUsers 2; Set-CA @(); Set-SD $true
            Test-NRGControlAADMFA 3>$null | Out-Null
            $prof = Get-NRGTenantLicenseProfile -SubscribedSkus $script:BSSkus
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'AAD-1.2')[0]
            $f.State | Should -Be 'Partial'
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $prof -ControlId 'AAD-1.2' -Finding $f | Should -BeFalse
            $null = Set-NRGLicenseGating -LicenseProfile $prof
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'upgrade opportunity'
            $f.Detail | Should -Match 'Result before the license check: Partial — Security Defaults is enabled\.'
        }

        It 'the registration shortfall is licensed for every consumer: gating, roadmap, improvement plan and the HTML license tag' {
            Set-BSInventory; Set-TwoUsers 1; Set-CA @(); Set-SD $true
            Test-NRGControlAADMFA 3>$null | Out-Null
            $prof = Get-NRGTenantLicenseProfile
            $prof.HasLicenseData | Should -BeTrue
            $null = Set-NRGLicenseGating -LicenseProfile $prof
            @(Get-NRGFindings | Where-Object ControlId -eq 'AAD-1.2')[0].State | Should -Be 'Partial'

            $rm = Get-NRGRemediationRoadmap -Findings @(Get-NRGFindings) -LicenseProfile $prof
            @($rm.QuickWins      | ForEach-Object ControlId) | Should -Contain 'AAD-1.2'
            @($rm.LicenseUnlocks | ForEach-Object ControlId) | Should -Not -Contain 'AAD-1.2'

            $plan = Get-NRGNISTImprovementPlan -Findings @(Get-NRGFindings) -LicenseProfile $prof
            $steps = @(@($plan.Tracks) | ForEach-Object { @($_['Steps']) }) + @($plan.Blocked)
            $step = @($steps | Where-Object { $null -ne $_ -and $_['ControlId'] -eq 'AAD-1.2' })
            $step.Count | Should -Be 1
            $step[0]['Licensed'] | Should -BeTrue

            $h = Render-Html
            $h | Should -Not -Match "ex-lic'>&#128273; M365 Business Premium or Entra ID P1"
            $h | Should -Match 'Run an MFA registration campaign' -Because 'the finding''s own fix, not "Or enable Security Defaults"'

            # The tag is live: the Conditional Access path on the same tenant
            # (not gated here) carries it.
            Clear-NRGState; Set-BSInventory; Set-TwoUsers 1; Set-CA @(); Set-SD $false
            Test-NRGControlAADMFA 3>$null | Out-Null
            Render-Html | Should -Match "ex-lic'>&#128273; M365 Business Premium or Entra ID P1"
        }

        It 'compliance matrix: the Security Defaults AAD-1.2 not-assessed finding is not listed as a license gap; a gated control is' -Skip:(-not (
            (& { foreach ($py in 'python3','python') { try { $null = & $py -c 'import openpyxl' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } } return $false })
        )) {
            Set-BSInventory
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = @(@{ UserPrincipalName = 'a@corp.example'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' }); MFARegistration = @{ RegistrationDetails = @() }; SectionStatus = @{ MFARegistration = 'Failed' } })
            Set-CA @(); Set-SD $true
            Test-NRGControlAADMFA 3>$null | Out-Null
            Test-NRGControlAADPhishResistantMFA 3>$null | Out-Null
            $null = Set-NRGLicenseGating -LicenseProfile (Get-NRGTenantLicenseProfile)
            $dir = Join-Path ([IO.Path]::GetTempPath()) ('nrg-sdm-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            try {
                $x = Join-Path $dir 'm.xlsx'
                Publish-NRGComplianceMatrix -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; ToolVersion = 'test' } -Findings @(Get-NRGFindings) -OutputPath $x -ErrorAction Stop 3>$null | Out-Null
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
            $dir = Join-Path ([IO.Path]::GetTempPath()) ('nrg-sdp-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            try {
                # (The Partial beside it: the playbook reads $partials.Count, which
                # throws under StrictMode when a run has no Partial finding.)
                $filler = @{ ControlId = 'AAD-2.2'; State = 'Partial'; Category = 'Identity'; Title = 'Named Locations'; Severity = 'Medium'; Detail = 'x'; CurrentValue = 'x'; RequiredValue = 'y'; Remediation = ''; FrameworkIds = @() }
                foreach ($case in @(@{ Detail = 'Security Defaults is enabled. Synthetic.'; Tag = $false }, @{ Detail = 'Synthetic.'; Tag = $true })) {
                    $syn = @{ ControlId = 'AAD-1.1'; State = 'Gap'; Category = 'Identity'; Title = 'Legacy Authentication Blocked'; Severity = 'Critical'; Detail = $case.Detail
                              CurrentValue = 'x'; RequiredValue = 'y'; Remediation = ''; FrameworkIds = @() }
                    $md = Join-Path $dir 'p.md'
                    Publish-NRGRemediationPlaybook -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; ToolVersion = 'test' } -Findings @($syn, $filler) `
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
                Set-NRGRawData -Key 'SharePoint' -Data (Bag @{ TenantSettings = $ts; TenantSettingsSPO = @{ ConditionalAccessPolicy = 'AllowLimitedAccess' }; ExternalSharing = $ts.SharingCapability })
            }
            $script:Transition = 'Security Defaults must be turned off before any Conditional Access policy can be turned on'
        }

        It 'HTML: the SPO-1.5 Gap does not offer the Set-SPOTenant change already made as its fix, and Priority Actions show the move to Conditional Access' {
            Set-SpoLimited; Set-CA @(); Set-SD $true
            Test-NRGControlSharePoint 3>$null | Out-Null
            Test-NRGControlAADSignInRisk 3>$null | Out-Null
            $keep = @(Get-NRGFindings | Where-Object { $_.ControlId -in @('SPO-1.5', 'AAD-1.4') })
            $out = Join-Path ([IO.Path]::GetTempPath()) ('nrg-sdh-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.html')
            Publish-NRGAssessmentHTML -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; Operator = 't'; ToolVersion = 'test' } `
                -Findings $keep -Connections @{ Graph = $true } -OutputPath $out -ClientName 'Test Co' 3>$null | Out-Null
            $h = Get-Content -Raw $out; Remove-Item $out -ErrorAction SilentlyContinue
            $h | Should -Not -Match 'Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess'
            $h | Should -Match "How to fix it</div><div class='ex-bd'>$([regex]::Escape($script:Transition))"
            $h | Should -Match 'already AllowLimitedAccess and needs no change'
            $h | Should -Match "(?s)act-cid'>AAD-1\.4<.*?How to fix it</span>$([regex]::Escape($script:Transition))"
        }

        It 'playbook: the SPO-1.5 Gap leads with the move to Conditional Access and does not offer the Set-SPOTenant change already made' {
            Set-SpoLimited; Set-CA @(); Set-SD $true
            Test-NRGControlSharePoint 3>$null | Out-Null
            Test-NRGControlAADPhishResistantMFA 3>$null | Out-Null
            # AAD-1.3 (Partial) rides along: the playbook reads $partials.Count,
            # which throws under StrictMode when a run has no Partial finding.
            $keep = @(Get-NRGFindings | Where-Object { $_.ControlId -in @('SPO-1.5', 'AAD-1.3') })
            $dir = Join-Path ([IO.Path]::GetTempPath()) ('nrg-sdq-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            try {
                $md = Join-Path $dir 'p.md'; $ht = Join-Path $dir 'p.html'
                Publish-NRGRemediationPlaybook -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; ToolVersion = 'test' } -Findings $keep `
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
            (@(Get-NRGControlDefinitions | Where-Object ControlId -eq 'SPO-1.5')[0]).LicenseRequirement | Should -Be 'M365 Business Premium or Entra ID P1'
            Set-SpoLimited; Set-SD $true
            Test-NRGControlSharePoint 3>$null | Out-Null
            $null = Set-NRGLicenseGating -LicenseProfile (Get-NRGTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','SHAREPOINTSTANDARD') }))
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SPO-1.5')[0]
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
            Invoke-NRGCollectAADCAPolicies 3>$null | Out-Null
            $raw = Get-NRGRawData -Key 'AAD-CAPolicies'
            Get-NRGNestedProperty -Object $raw -Path 'Data.SectionStatus.NamedLocations' | Should -Be 'Collected'
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
            Invoke-NRGCollectAADCAPolicies 3>$null | Out-Null
            Get-NRGNestedProperty -Object (Get-NRGRawData -Key 'AAD-CAPolicies') -Path 'Data.SectionStatus.NamedLocations' | Should -Be 'Failed'
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
            Invoke-NRGCollectAADInventory 3>$null | Out-Null
            $raw = Get-NRGRawData -Key 'AAD-Inventory'
            Get-NRGNestedProperty -Object $raw -Path 'Data.SectionStatus.OAuthGrantedApps' | Should -Be 'Collected'
            $apps = @($raw.Data.OAuthGrantedApps)
            $apps.Count | Should -Be 35
            @($apps | Where-Object { $_['AppName'] -eq $_['ClientId'] }).Count | Should -Be 0 -Because 'every app is looked up, and the lookup URL is built'
        }

        It 'the password rule collector reads the string "False" as $false, not as enabled' {
            foreach ($case in @(@{ Raw = 'False'; Want = $false }, @{ Raw = 'True'; Want = $true }, @{ Raw = 'garbage'; Want = $null })) {
                Clear-NRGState
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
                Invoke-NRGCollectAADAuthPolicies 3>$null | Out-Null
                $pp = (Get-NRGRawData -Key 'AAD-AuthPolicies').Data.PasswordProtection
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

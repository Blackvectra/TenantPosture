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

        It 'any-app user consent is a Gap; none or low-impact verified publishers is Satisfied' {
            (Consent '["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]').State | Should -Be 'Gap'
            (Consent '["ManagePermissionGrantsForSelf.microsoft-user-default-low"]').State    | Should -Be 'Satisfied'
            (Consent '[]').State | Should -Be 'Satisfied' -Because 'an empty list (no user consent) must not unroll into "not returned"'
        }
    }

    Context 'Conditional Access' {
        It 'AAD-1.1: a pilot-group legacy block is Partial; an EAS-only block is a Gap; all users on Other clients passes' {
            Ca @(Pol -Users @() -Groups @('g1') -ClientApps @('other','exchangeActiveSync') -Grant @('block')); (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Partial'
            Ca @(Pol -ClientApps @('exchangeActiveSync') -Grant @('block'));                                   (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Gap'
            Ca @(Pol -ClientApps @('other','exchangeActiveSync') -Grant @('block'));                           (V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Satisfied'
        }
        It 'AAD-1.4 / 1.5: blocking and risk-remediation responses count' {
            Ca @(Pol -SignInRisk @('high') -Grant @('block'));             (V 'Test-NRGControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Satisfied'
            Ca @(Pol -UserRisk @('high') -Grant @('riskRemediation'));     (V 'Test-NRGControlAADUserRisk' 'AAD-1.5').State | Should -Be 'Satisfied'
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

#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.CANarrowing.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Batch 1 of the 2026-10-31 coverage plan (docs/validation/batch-1-ca-narrowing.md).
             D1: a Conditional Access policy excluding guests or external users counted
             as covering everyone. D2: a policy limited to an authentication flow
             (device code, authentication transfer) counted as covering every sign-in.
             Both were false passes in the shared coverage helper
             (Lib/Get-TPEffectiveCoverage.ps1) behind AAD-1.1, 1.2, 1.4, 1.5, 2.3,
             11.1 and INT-1.2. These tests drive the real evaluators over the raw
             shapes the collector stores; the shapes of the guest exclusion and the
             authentication-flow condition were recorded from an authorized live run
             on 2026-10-30, with every identifier and name replaced.
    Data keys consumed: none. Graph scopes / cmdlets: none (the collector test stubs Graph).
#>

Describe 'Conditional Access scope narrowing (batch 1: guest exclusions and authentication flows)' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        function script:Bag([hashtable] $Data) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-31T00:00:00Z'; Success = $true; Data = $Data } }
        # The guest shape the collector stores (recorded live 2026-10-30): a comma-joined
        # type list and the external-tenants membership kind; Members only from this batch on.
        function script:Guests([string] $Types, [string] $Kind = 'all', $Members = $null) {
            $g = @{ GuestOrExternalUserTypes = $Types; ExternalTenantsMembershipKind = $Kind }
            if ($null -ne $Members) { $g.ExternalTenantsMembers = @($Members) }
            $g
        }
        function script:Pol {
            param([string] $Name = 'p', [string] $State = 'enabled', [string[]] $Users = @('All'), [string[]] $Groups = @(), [string[]] $Roles = @(),
                  [string[]] $ExUsers = @(), [string[]] $ExGroups = @(), $ExGuests = $null, $IncGuests = $null,
                  [string[]] $Apps = @('All'), [string[]] $ClientApps = @('all'), [string[]] $Grant = @('mfa'), [string] $Op = 'OR',
                  [string[]] $SignInRisk = @(), [string[]] $UserRisk = @(), [object[]] $Flows = @(), [hashtable] $Session = @{})
            @{ Id = $Name; DisplayName = $Name; State = $State
               Conditions = @{ ClientAppTypes = $ClientApps; SignInRiskLevels = $SignInRisk; UserRiskLevels = $UserRisk; AuthFlows = @($Flows); Platforms = @(); ExcludePlatforms = @()
                               Users = @{ IncludeUsers = $Users; IncludeGroups = $Groups; IncludeRoles = $Roles; ExcludeUsers = $ExUsers; ExcludeGroups = $ExGroups; ExcludeRoles = @()
                                          IncludeGuestsOrExternalUsers = $IncGuests; ExcludeGuestsOrExternalUsers = $ExGuests }
                               Applications = @{ Include = $Apps; Exclude = @(); UserActions = @() }
                               Locations = @{ Include = @(); Exclude = @() }; Devices = @{ FilterMode = ''; FilterRule = '' }; ClientApplications = @{ IncludeServicePrincipals = @() } }
               GrantControls = @{ Operator = $Op; BuiltInControls = $Grant; CustomControls = @(); AuthStrengthId = ''; AuthStrengthName = ''; AuthStrengthCombinations = @(); TermsOfUse = @() }
               SessionControls = $Session }
        }
        $script:EveryTime = @{ SignInFrequency = @{ IsEnabled = $true; FrequencyInterval = 'everyTime'; Value = $null; Type = '' }; PersistentBrowser = $null }
        $script:DeviceCode = @{ transferMethods = 'deviceCodeFlow' }
        function script:Ca([object[]] $Policies) {
            Clear-TPState
            Set-TPRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($Policies); SectionStatus = @{ TokenProtection = 'Collected'; NamedLocations = 'Collected' } })
            Set-TPRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ SecurityDefaults = @{ IsEnabled = $false } })
            $u = @(@{ Id = 'u-1'; UserPrincipalName = 'a@corp.example'; AccountEnabled = $true; UserType = 'Member' },
                   @{ Id = 'u-2'; UserPrincipalName = 'b@corp.example'; AccountEnabled = $true; UserType = 'Member' })
            $reg = @($u | ForEach-Object { @{ UserPrincipalName = $_.UserPrincipalName; IsMfaRegistered = $true } })
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $u; MFARegistration = @{ RegistrationDetails = $reg }; SectionStatus = @{ MFARegistration = 'Collected' } })
            # INT-1.2 sits behind the Intune evaluator's "any Intune data" gate.
            Set-TPRawData -Key 'Intune-DeviceCompliance' -Data (Bag @{ Policies = @(); Devices = @(); SectionStatus = @{} })
        }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0] }
        $script:Legacy  = @{ ClientApps = @('exchangeActiveSync', 'other'); Grant = @('block') }
        $script:Device  = @{ Grant = @('compliantDevice'); Op = 'AND' }
    }
    AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    Context 'D1: a guest or external-user exclusion narrows the policy' {

        It 'AAD-1.2: MFA for All users excluding B2B collaboration guests is Partial (members credited), never Satisfied' {
            Ca @(Pol -Name 'mfa-all' -ExGuests (Guests 'b2bCollaborationGuest'))
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'Partial' -Because "guests are outside the only MFA policy (got: $($f.State): $($f.Detail))"
            $f.Detail | Should -Match 'B2B collaboration guests'
            $f.Detail | Should -Match 'Verified: MFA is required by: mfa-all'
            $f.Detail | Should -Not -Match 'EmergencyAccess' -Because 'a guest population is never an emergency-access account'
        }

        It 'AAD-1.1, AAD-11.1, AAD-2.3 and INT-1.2: the same exclusion is not Satisfied' {
            Ca @(Pol -Name 'legacy' @script:Legacy -ExGuests (Guests 'b2bCollaborationGuest'))
            (V 'Test-TPControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Partial'
            Ca @(Pol -Name 'dc' -Grant @('block') -Flows @($script:DeviceCode) -ExGuests (Guests 'internalGuest,b2bCollaborationGuest'))
            (V 'Test-TPControlAADDeviceCode' 'AAD-11.1').State | Should -Be 'Partial'
            Ca @(Pol -Name 'dev' @script:Device -ClientApps @('browser', 'mobileAppsAndDesktopClients') -ExGuests (Guests 'b2bCollaborationGuest'))
            (V 'Test-TPControlAADDeviceComplianceCA' 'AAD-2.3').State | Should -Be 'Partial'
            (V 'Test-TPControlIntune' 'INT-1.2').State | Should -Be 'Partial'
        }

        It 'AAD-1.4: a risk policy excluding guests is not Satisfied' {
            Ca @(Pol -Name 'risk' -SignInRisk @('high', 'medium') -Session $script:EveryTime -ExGuests (Guests 'b2bCollaborationGuest'))
            (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Not -Be 'Satisfied'
        }

        It 'a guestOrExternalUserTypes of "none" excludes nothing (no new false failure)' {
            Ca @(Pol -Name 'mfa-all' -ExGuests (Guests 'none'))
            (V 'Test-TPControlAADMFA' 'AAD-1.2').State | Should -Be 'Satisfied'
        }

        It 'another all-user policy without the guest exclusion still gives full coverage' {
            Ca @((Pol -Name 'mfa-members' -ExGuests (Guests 'b2bCollaborationGuest')), (Pol -Name 'mfa-everyone'))
            (V 'Test-TPControlAADMFA' 'AAD-1.2').State | Should -Be 'Satisfied'
        }

        It 'the legacy ExcludeUsers value GuestsOrExternalUsers is read as every guest type, not as a user' {
            Ca @(Pol -Name 'mfa-all' -ExUsers @('GuestsOrExternalUsers'))
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'Partial'
            $f.Detail | Should -Not -Match 'user:GuestsOrExternalUsers'
            $f.Detail | Should -Match 'internal guests'
        }

        It 'a shortfall on guests is kept when another component of the control was not read' {
            Ca @(Pol -Name 'mfa-all' -ExGuests (Guests 'b2bCollaborationGuest'))
            $u = @(@{ Id = 'u-1'; UserPrincipalName = 'a@corp.example'; AccountEnabled = $true; UserType = 'Member' })
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $u; MFARegistration = $null; SectionStatus = @{ MFARegistration = 'Failed' } })
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'Partial' -Because "a demonstrated scope shortfall must survive missing registration evidence (got: $($f.State): $($f.Detail))"
            $f.Detail | Should -Match 'B2B collaboration guests'
            $f.Detail | Should -Match 'Not assessed: whether every enabled member has registered an MFA method'
        }

        It 'AAD-1.2: no MFA policy at all is still a Gap when registration was not read (the Gap is not erased)' {
            Ca @()
            $u = @(@{ Id = 'u-1'; UserPrincipalName = 'a@corp.example'; AccountEnabled = $true; UserType = 'Member' })
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $u; MFARegistration = $null; SectionStatus = @{ MFARegistration = 'Failed' } })
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'Gap' -Because "no policy requires MFA; missing registration evidence does not change that (got: $($f.State): $($f.Detail))"
            $f.Detail | Should -Match 'registration was not assessed'
        }
    }

    Context 'D1: complementary guest policies' {

        It 'a guest-only MFA policy covering the excluded type with no exclusions of its own gives full coverage' {
            Ca @((Pol -Name 'mfa-members' -ExGuests (Guests 'b2bCollaborationGuest')),
                 (Pol -Name 'mfa-guests' -Users @() -IncGuests (Guests 'b2bCollaborationGuest')))
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'Satisfied' -Because "the guest policy covers exactly the excluded population (got: $($f.Detail))"
            $f.Detail | Should -Match 'mfa-guests'
        }

        It 'a guest policy covering only some of the excluded types leaves the rest named as a shortfall' {
            Ca @((Pol -Name 'mfa-members' -ExGuests (Guests 'internalGuest,b2bCollaborationGuest')),
                 (Pol -Name 'mfa-guests' -Users @() -IncGuests (Guests 'b2bCollaborationGuest')))
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'Partial'
            $f.Detail | Should -Match 'internal guests'
            $f.Detail | Should -Not -Match 'Shortfall:[^.]*B2B collaboration guests'
        }

        It 'a guest policy with exclusions of its own leaves guest coverage not established, never a shortfall' {
            Ca @((Pol -Name 'mfa-members' -ExGuests (Guests 'b2bCollaborationGuest')),
                 (Pol -Name 'mfa-guests' -Users @() -IncGuests (Guests 'b2bCollaborationGuest') -ExGroups @('g-partners')))
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'NotApplicable' -Because "uncertainty is disclosed, not reported as a gap (got: $($f.State): $($f.Detail))"
            $f.Detail | Should -Match 'Not assessed: .*mfa-guests'
            $f.Detail | Should -Match 'Verified: MFA is required'
        }

        It 'a guest policy limited to some external organizations does not cover an exclusion of all of them' {
            Ca @((Pol -Name 'mfa-members' -ExGuests (Guests 'b2bCollaborationGuest')),
                 (Pol -Name 'mfa-guests' -Users @() -IncGuests (Guests 'b2bCollaborationGuest' 'enumerated' @('t-1'))))
            (V 'Test-TPControlAADMFA' 'AAD-1.2').State | Should -Be 'Partial'
        }
    }

    Context 'D1: exclusions limited to listed external organizations' {

        It 'two policies excluding the same listed organizations share the exclusion (Partial)' {
            Ca @((Pol -Name 'a' -ExGuests (Guests 'b2bCollaborationGuest' 'enumerated' @('t-1', 't-2'))),
                 (Pol -Name 'b' -ExGuests (Guests 'b2bCollaborationGuest' 'enumerated' @('t-2', 't-1'))))
            (V 'Test-TPControlAADMFA' 'AAD-1.2').State | Should -Be 'Partial'
        }

        It 'listed organizations that were not recorded (an older results file) are never treated as the same exclusion' {
            Ca @((Pol -Name 'a' -ExGuests (Guests 'b2bCollaborationGuest' 'enumerated')),
                 (Pol -Name 'b' -ExGuests (Guests 'b2bCollaborationGuest' 'enumerated')))
            (V 'Test-TPControlAADMFA' 'AAD-1.2').State | Should -Be 'NotApplicable'
        }
    }

    Context 'D1: emergency-access approval never approves a guest population' {

        It 'the approval pass names a guest exclusion as never an emergency-access principal' {
            Ca @(Pol -Name 'mfa-all' -ExGuests (Guests 'b2bCollaborationGuest'))
            V 'Test-TPControlAADMFA' 'AAD-1.2' | Out-Null
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N') + '.psd1')
            Set-Content -LiteralPath $tmp -Encoding utf8 -Value "@{`n    Exceptions = @()`n    EmergencyAccess = @()`n}`n"
            try { $null = Set-TPEmergencyAccessApproval -Path $tmp } finally { Remove-Item -LiteralPath $tmp -Force }
            $f = @(Get-TPFindings | Where-Object ControlId -eq 'AAD-1.2')[0]
            $f.State | Should -Be 'Partial'
            $f.Detail | Should -Match 'never an emergency-access principal'
        }
    }

    Context 'D2: an authentication-flow condition narrows the policy' {

        It 'AAD-1.2: MFA for All users limited to the device-code flow is not all-user coverage (Partial with every user registered, as for a browser-only policy), never Satisfied' {
            Ca @(Pol -Name 'mfa-dc' -Flows @($script:DeviceCode))
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'Partial' -Because "MFA is enforced only for device-code sign-ins (got: $($f.State): $($f.Detail))"
            $f.Detail | Should -Match "Shortfall: .*'mfa-dc' also delivers it but applies only to some authentication flows \(deviceCodeFlow\)"
        }

        It 'AAD-1.4: a risk policy limited to an authentication flow is not Satisfied and earns no CIS credit' {
            Ca @(Pol -Name 'risk-dc' -SignInRisk @('high', 'medium') -Session $script:EveryTime -Flows @($script:DeviceCode))
            $f = V 'Test-TPControlAADSignInRisk' 'AAD-1.4'
            $f.State | Should -Not -Be 'Satisfied'
            $f.Detail | Should -Match 'No enabled policy meets CIS 5\.2\.2\.7'
        }

        It 'AAD-1.1: a legacy block limited to an authentication flow is not Satisfied' {
            Ca @(Pol -Name 'legacy-dc' @script:Legacy -Flows @($script:DeviceCode))
            (V 'Test-TPControlAADLegacyAuth' 'AAD-1.1').State | Should -Not -Be 'Satisfied'
        }

        It 'AAD-11.1: a device-code block keeps its verdict (it judges that flow itself)' {
            Ca @(Pol -Name 'dc' -Grant @('block') -Flows @($script:DeviceCode))
            (V 'Test-TPControlAADDeviceCode' 'AAD-11.1').State | Should -Be 'Satisfied'
            Ca @(Pol -Name 'dc' -Grant @('block') -Flows @(@{ transferMethods = 'deviceCodeFlow,authenticationTransfer' }))
            (V 'Test-TPControlAADDeviceCode' 'AAD-11.1').State | Should -Be 'Satisfied'
        }

        It 'transferMethods "none" narrows nothing (no new false failure)' {
            Ca @(Pol -Name 'mfa-all' -Flows @(@{ transferMethods = 'none' }))
            (V 'Test-TPControlAADMFA' 'AAD-1.2').State | Should -Be 'Satisfied'
        }

        It 'AAD-1.3 names the flow condition once (one shared reason, no private copy)' {
            $f = & $script:Mod { param($p) @(Get-TPCANarrowing -Policy $p) } (Pol -Flows @($script:DeviceCode))
            @($f | Where-Object { $_ -match 'authentication flows' }).Count | Should -Be 1
            $src = Get-Content -LiteralPath (Join-Path $script:Root 'Evaluators/Test-TPControl-AAD.ps1') -Raw
            $src | Should -Not -Match 'limited to some authentication flows' -Because 'AAD-1.3 uses the shared narrowing reason'
        }
    }

    Context 'Collector-to-evaluator contract' {

        It 'the real collector stores the guest exclusion (with listed organizations) and the flow condition in the shape the helpers read' {
            $orig = & $script:Mod { ${function:Invoke-TPGraphRequest} }
            try {
                & $script:Mod { Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value {
                    param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, $Body, [string] $OutputType = 'HashTable')
                    if ($Uri -match 'conditionalAccess/policies') {
                        return @{ value = @(
                            @{ id = 'p1'; displayName = 'mfa-members'; state = 'enabled'
                               conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }
                                               users = @{ includeUsers = @('All')
                                                          excludeGuestsOrExternalUsers = @{ guestOrExternalUserTypes = 'internalGuest,b2bCollaborationGuest'
                                                                                            externalTenants = @{ '@odata.type' = '#microsoft.graph.conditionalAccessEnumeratedExternalTenants'; membershipKind = 'enumerated'; members = @('t-2', 't-1') } } } }
                               grantControls = @{ operator = 'OR'; builtInControls = @('mfa') } }
                            @{ id = 'p2'; displayName = 'dc-block'; state = 'enabled'
                               conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }; users = @{ includeUsers = @('All') }
                                               authenticationFlows = @{ transferMethods = 'deviceCodeFlow' } }
                               grantControls = @{ operator = 'OR'; builtInControls = @('block') } }) }
                    }
                    return @{ value = @() }
                } }
                Clear-TPState
                Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            } finally { & $script:Mod { param($o) Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $o } $orig }
            $raw = Get-TPRawData -Key 'AAD-CAPolicies'
            $p1 = @($raw.Data.Policies | Where-Object { $_.DisplayName -eq 'mfa-members' })[0]
            $g = $p1.Conditions.Users.ExcludeGuestsOrExternalUsers
            $g.GuestOrExternalUserTypes | Should -Be 'internalGuest,b2bCollaborationGuest'
            $g.ExternalTenantsMembershipKind | Should -Be 'enumerated'
            @($g.ExternalTenantsMembers) | Should -Be @('t-2', 't-1')
            $ex = & $script:Mod { param($p) @(Get-TPCAPrincipalExclusions -Policy $p) } $p1
            $ex | Should -Contain 'guests:internalGuest:tenants:t-1+t-2'
            $ex | Should -Contain 'guests:b2bCollaborationGuest:tenants:t-1+t-2'
            $p2 = @($raw.Data.Policies | Where-Object { $_.DisplayName -eq 'dc-block' })[0]
            $why = & $script:Mod { param($p) @(Get-TPCANarrowing -Policy $p) } $p2
            $why | Should -Contain 'applies only to some authentication flows (deviceCodeFlow)'
            $why2 = & $script:Mod { param($p) @(Get-TPCANarrowing -Policy $p -AllowAuthFlows) } $p2
            @($why2 | Where-Object { $_ -match 'authentication flows' }).Count | Should -Be 0
        }

        It 'a policy stored before ExternalTenantsMembers was collected (recorded 2026-10-30 shape) is still judged' {
            Ca @(Pol -Name 'recorded' -ExGuests @{ ExternalTenantsMembershipKind = 'all'; GuestOrExternalUserTypes = 'b2bCollaborationGuest' })
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'Partial'
        }
    }
}

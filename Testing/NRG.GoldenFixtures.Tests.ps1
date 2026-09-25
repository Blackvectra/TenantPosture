#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
#
# NRG.GoldenFixtures.Tests.ps1
#
# Correctness proofs for the highest-stakes controls. Every other suite proves
# the tool doesn't CRASH or LIE BY OMISSION; this one proves the verdicts are
# actually RIGHT. Each control is driven twice against synthetic raw data shaped
# like the real Graph / EXO payload:
#
#     known-COMPLIANT tenant  -> must report Satisfied
#     known-VULNERABLE tenant -> must report Gap
#
# Both directions matter. A control that always says Gap is a false alarm that
# burns client trust; a control that always says Satisfied is a false assurance
# that leaves a client exposed. Only a test that pins BOTH can prove the
# evaluator discriminates rather than guesses.
#
# Starting set = the Critical-severity controls, where a wrong verdict has the
# largest consequence. Fixtures mirror the collector's real output shape: an
# [ordered] result object with Success + a Data block keyed as the collector
# writes it.

Describe 'Golden fixtures — Critical controls produce the right verdict' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        # Shape a collector result exactly as the collectors do.
        function script:NewRaw {
            param([string] $CollectorId, [hashtable] $Data, [bool] $Success = $true)
            [ordered]@{
                CollectorId = $CollectorId
                CollectedAt = '2026-07-30T00:00:00.0000000+00:00'
                Success     = $Success
                Data        = $Data
            }
        }

        # Run one evaluator in isolation and return the finding for $ControlId.
        function script:GetVerdict {
            param([string] $Evaluator, [string] $ControlId)
            & $Evaluator | Out-Null
            return @(Get-NRGFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
        }

        # CA policy factory — mirrors the Graph conditionalAccessPolicy shape the
        # AAD collector stores under Data.Policies.
        function script:NewCaPolicy {
            param(
                [string]   $DisplayName    = 'Policy',
                [string]   $State           = 'enabled',
                [string[]] $ClientAppTypes  = @('all'),
                [string[]] $BuiltInControls = @(),
                [string[]] $IncludeRoles    = @(),
                [string]   $AuthStrengthId  = '',
                # Graph always returns conditions.users and conditions.applications;
                # a policy with no users condition does not exist. All users /
                # All apps unless the policy targets roles.
                [string[]] $IncludeUsers    = $(if ($IncludeRoles.Count -gt 0) { @() } else { @('All') })
            )
            [pscustomobject]@{
                DisplayName = $DisplayName
                State       = $State
                Conditions  = [pscustomobject]@{
                    ClientAppTypes = $ClientAppTypes
                    Users          = [pscustomobject]@{ IncludeUsers = $IncludeUsers; IncludeRoles = $IncludeRoles }
                    Applications   = [pscustomobject]@{ Include = @('All') }
                }
                GrantControls = [pscustomobject]@{
                    BuiltInControls = $BuiltInControls
                    AuthStrengthId  = $AuthStrengthId
                }
            }
        }
    }

    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    Context 'AAD-1.1 — Legacy Authentication Blocked' {

        It 'Satisfied when an enabled CA policy blocks legacy clients' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @( NewCaPolicy -DisplayName 'Block legacy auth' -State 'enabled' `
                                -ClientAppTypes @('other', 'exchangeActiveSync') -BuiltInControls @('block') )
            })
            (GetVerdict 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Satisfied'
        }

        It 'Gap when no policy blocks legacy clients' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @( NewCaPolicy -DisplayName 'Require MFA' -State 'enabled' `
                                -ClientAppTypes @('browser') -BuiltInControls @('mfa') )
            })
            (GetVerdict 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Gap'
        }

        It 'Gap when the blocking policy exists but is DISABLED (report-only/off must not count)' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @( NewCaPolicy -DisplayName 'Block legacy (disabled)' -State 'disabled' `
                                -ClientAppTypes @('other') -BuiltInControls @('block') )
            })
            (GetVerdict 'Test-NRGControlAADLegacyAuth' 'AAD-1.1').State | Should -Be 'Gap' `
                -Because 'a policy that is not enabled provides no protection and must never read as compliant'
        }
    }

    Context 'AAD-6.1 — User App Registration Disabled' {

        # A missing value used to default to "users CAN register apps" (a High
        # Gap). On a live tenant the setting lived only under AAD-AuthPolicies
        # and read false, yet the control reported a Gap.
        It 'Gap when users may register applications' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (NewRaw 'AAD' @{
                ExternalCollab = @{ DefaultUserRolePermissions = @{ AllowedToCreateApps = $true } } })
            (GetVerdict 'Test-NRGControlAADUserAppReg' 'AAD-6.1').State | Should -Be 'Gap'
        }
        It 'Satisfied from the authorization-policy copy when the governance copy is absent' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (NewRaw 'AAD' @{ })
            Set-NRGRawData -Key 'AAD-AuthPolicies' -Data (NewRaw 'AAD' @{
                AuthorizationPolicy = @{ DefaultUserRolePermissions = @{ AllowedToCreateApps = $false } } })
            (GetVerdict 'Test-NRGControlAADUserAppReg' 'AAD-6.1').State | Should -Be 'Satisfied'
        }
        It 'NotApplicable, never Gap, when the setting was not collected at all' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (NewRaw 'AAD' @{ })
            (GetVerdict 'Test-NRGControlAADUserAppReg' 'AAD-6.1').State | Should -Be 'NotApplicable'
        }
    }

    Context 'AAD-1.3 — Phishing-Resistant MFA for Admins' {

        It 'Satisfied when a role-targeted policy uses an Authentication Strength' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @( NewCaPolicy -DisplayName 'Admins: phish-resistant' -State 'enabled' `
                                -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10') `
                                -AuthStrengthId '00000000-0000-0000-0000-000000000004' )
            })
            (GetVerdict 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Satisfied'
        }

        It 'Partial when admins have only standard MFA (AiTM-bypassable), not Auth Strength' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @( NewCaPolicy -DisplayName 'Admins: MFA' -State 'enabled' `
                                -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10') `
                                -BuiltInControls @('mfa') )
            })
            (GetVerdict 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Partial' `
                -Because 'standard MFA for admins is real but insufficient — the verdict must distinguish it from both full compliance and no protection'
        }

        It 'an all-users MFA policy covers admins (they are users) with standard MFA: Partial, not "no MFA"' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @( NewCaPolicy -DisplayName 'All users MFA' -State 'enabled' -BuiltInControls @('mfa') )
            })
            (GetVerdict 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Partial'
        }

        It 'Gap when no policy requires MFA of admins at all' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @( NewCaPolicy -DisplayName 'Block legacy' -State 'enabled' -ClientAppTypes @('other') -BuiltInControls @('block') )
            })
            (GetVerdict 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Gap'
        }

        # Any authentication strength used to count as phishing-resistant. A
        # live tenant's admin policy used a CUSTOM strength whose methods were
        # never checked, and scored Satisfied on this Critical control.
        It 'Partial, not Satisfied, for the built-in "Multifactor authentication" strength (allows SMS/voice)' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @( NewCaPolicy -DisplayName 'Admins: MFA strength' -State 'enabled' `
                                -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10') `
                                -AuthStrengthId '00000000-0000-0000-0000-000000000002' )
            })
            (GetVerdict 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Partial'
        }

        It 'judges a custom strength by every combination it allows' {
            $mk = { param([string[]] $Combos)
                $p = NewCaPolicy -DisplayName 'Admins: custom' -State 'enabled' `
                        -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10') -AuthStrengthId 'd6c840e6-b1ff-4cc2-8253-10409d809f22'
                $p.GrantControls | Add-Member -NotePropertyName AuthStrengthName -NotePropertyValue 'Custom'
                $p.GrantControls | Add-Member -NotePropertyName AuthStrengthCombinations -NotePropertyValue $Combos
                $p }
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{ Policies = @( & $mk @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor') ) })
            (GetVerdict 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Satisfied'

            Clear-NRGState
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{ Policies = @( & $mk @('fido2', 'password,sms') ) })
            (GetVerdict 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Partial' `
                -Because 'one SMS combination makes the whole strength relayable by AiTM phishing'
        }

        It 'NotApplicable, never Satisfied, when a custom strength''s methods are not visible' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @( NewCaPolicy -DisplayName 'Admins: custom' -State 'enabled' `
                                -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10') `
                                -AuthStrengthId 'd6c840e6-b1ff-4cc2-8253-10409d809f22' )
            })
            (GetVerdict 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'NotApplicable'
        }
    }

    Context 'EXO-1.6 — Modern Authentication Enabled' {

        It 'Satisfied when OAuth2ClientProfileEnabled is true' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (NewRaw 'EXO' @{
                OrganizationConfig = [pscustomobject]@{ OAuth2ClientProfileEnabled = $true }
            })
            (GetVerdict 'Test-NRGControlEXOModernAuth' 'EXO-1.6').State | Should -Be 'Satisfied'
        }

        It 'Gap when modern auth is explicitly disabled (basic auth bypasses MFA)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (NewRaw 'EXO' @{
                OrganizationConfig = [pscustomobject]@{ OAuth2ClientProfileEnabled = $false }
            })
            (GetVerdict 'Test-NRGControlEXOModernAuth' 'EXO-1.6').State | Should -Be 'Gap'
        }

        It 'NotApplicable when the flag is absent — unknown must never read as compliant' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (NewRaw 'EXO' @{
                OrganizationConfig = [pscustomobject]@{}
            })
            (GetVerdict 'Test-NRGControlEXOModernAuth' 'EXO-1.6').State | Should -Be 'NotApplicable' `
                -Because 'an undeterminable setting is not evidence of compliance'
        }
    }

    Context 'AAD-11.2 — No Guest Accounts in Privileged Roles' {

        It 'Satisfied when only member accounts hold privileged roles' {
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRaw 'AAD' @{
                RoleAssignments = @(
                    [pscustomobject]@{ RoleDefinitionName = 'Global Administrator'
                                       PrincipalUPN = 'admin@contoso.com'
                                       PrincipalDisplayName = 'Alice Admin' }
                )
            })
            (GetVerdict 'Test-NRGControlAADNoGuestInPrivRoles' 'AAD-11.2').State | Should -Be 'Satisfied'
        }

        It 'Gap when a guest (#EXT#) holds a privileged role' {
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRaw 'AAD' @{
                RoleAssignments = @(
                    [pscustomobject]@{ RoleDefinitionName = 'Global Administrator'
                                       PrincipalUPN = 'vendor_partner.com#EXT#@contoso.onmicrosoft.com'
                                       PrincipalDisplayName = 'Vendor Guest' }
                )
            })
            $v = GetVerdict 'Test-NRGControlAADNoGuestInPrivRoles' 'AAD-11.2'
            $v.State | Should -Be 'Gap'
            $v.Detail | Should -Match 'Vendor Guest' -Because 'the finding must name the offending principal so it is actionable'
        }

        It 'Satisfied when a guest holds only a NON-privileged role (no false alarm)' {
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRaw 'AAD' @{
                RoleAssignments = @(
                    [pscustomobject]@{ RoleDefinitionName = 'Directory Readers'
                                       PrincipalUPN = 'vendor_partner.com#EXT#@contoso.onmicrosoft.com'
                                       PrincipalDisplayName = 'Vendor Guest' }
                )
            })
            (GetVerdict 'Test-NRGControlAADNoGuestInPrivRoles' 'AAD-11.2').State | Should -Be 'Satisfied' `
                -Because 'flagging a guest in a harmless role would be a false positive that erodes trust in the report'
        }
    }

    Context 'DNS-1.3 — DMARC Policy at Quarantine or Reject' {

        It 'Satisfied when DMARC is p=reject at 100%' {
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data (NewRaw 'DNS' @{
                DomainCount = 1
                Domains     = @{ 'contoso.com' = [pscustomobject]@{
                    DMARC = 'v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com'
                    DMARCPolicy = 'reject'; DMARCPct = 100 } }
            })
            (GetVerdict 'Test-NRGControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Satisfied'
        }

        It 'Partial when p=reject is only partially enforced (pct < 100)' {
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data (NewRaw 'DNS' @{
                DomainCount = 1
                Domains     = @{ 'contoso.com' = [pscustomobject]@{
                    DMARC = 'v=DMARC1; p=reject; pct=20'
                    DMARCPolicy = 'reject'; DMARCPct = 20 } }
            })
            (GetVerdict 'Test-NRGControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Partial' `
                -Because 'p=reject at pct=20 enforces on only a fifth of mail — reporting it as full compliance would be a false assurance'
        }

        It 'Gap when the domain has no DMARC record at all' {
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data (NewRaw 'DNS' @{
                DomainCount = 1
                Domains     = @{ 'contoso.com' = [pscustomobject]@{ DMARC = $null } }
            })
            (GetVerdict 'Test-NRGControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Gap'
        }
    }

    Context 'EXO-1.2 — SMTP AUTH Disabled (legacy protocol that bypasses MFA)' {

        It 'Satisfied when SMTP AUTH is off tenant-wide with no per-mailbox exceptions' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (NewRaw 'EXO' @{
                SmtpAuthConfig = [pscustomobject]@{ TenantDisabled = $true; PerMailboxEnabledCount = 0 }
            })
            (GetVerdict 'Test-NRGControlEXOSmtpAuth' 'EXO-1.2').State | Should -Be 'Satisfied'
        }

        It 'Partial when disabled tenant-wide but individual mailboxes re-enable it' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (NewRaw 'EXO' @{
                SmtpAuthConfig = [pscustomobject]@{
                    TenantDisabled = $true; PerMailboxEnabledCount = 3
                    SampleEnabled  = @('scanner@contoso.com', 'crm@contoso.com') }
            })
            $v = GetVerdict 'Test-NRGControlEXOSmtpAuth' 'EXO-1.2'
            $v.State | Should -Be 'Partial' `
                -Because 'per-mailbox exceptions are the exact hole attackers use — a tenant-wide "off" must not mask them'
            $v.Detail | Should -Match 'scanner@contoso\.com' -Because 'the client needs to know WHICH mailboxes are exposed'
        }

        It 'NotApplicable when SMTP auth config was not collected' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (NewRaw 'EXO' @{ })
            (GetVerdict 'Test-NRGControlEXOSmtpAuth' 'EXO-1.2').State | Should -Be 'NotApplicable'
        }
    }

    Context 'EXO-1.3 — External Auto-Forwarding Blocked (the classic BEC exfil path)' {

        It 'Satisfied only when BOTH the spam policy and remote domain block forwarding' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (NewRaw 'EXO' @{
                OutboundSpamPolicies = @( [pscustomobject]@{ IsDefault = $true; AutoForwardingMode = 'Off' } )
                RemoteDomains        = @( [pscustomobject]@{ IsDefault = $true; AutoForwardEnabled = $false } )
            })
            (GetVerdict 'Test-NRGControlEXOAutoForward' 'EXO-1.3').State | Should -Be 'Satisfied'
        }

        It 'Partial when the spam policy blocks but the remote-domain wildcard still allows forwarding' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (NewRaw 'EXO' @{
                OutboundSpamPolicies = @( [pscustomobject]@{ IsDefault = $true; AutoForwardingMode = 'Off' } )
                RemoteDomains        = @( [pscustomobject]@{ IsDefault = $true; AutoForwardEnabled = $true } )
            })
            (GetVerdict 'Test-NRGControlEXOAutoForward' 'EXO-1.3').State | Should -Be 'Partial' `
                -Because 'half-blocked forwarding still leaks mail — reporting this as Satisfied would be a false assurance in a BEC scenario'
        }

        It 'Gap when neither control blocks external forwarding' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (NewRaw 'EXO' @{
                OutboundSpamPolicies = @( [pscustomobject]@{ IsDefault = $true; AutoForwardingMode = 'On' } )
                RemoteDomains        = @( [pscustomobject]@{ IsDefault = $true; AutoForwardEnabled = $true } )
            })
            (GetVerdict 'Test-NRGControlEXOAutoForward' 'EXO-1.3').State | Should -Be 'Gap'
        }
    }

    Context 'DNS-1.1 — SPF Record Hardening' {

        It 'Satisfied on hard fail (-all)' {
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data (NewRaw 'DNS' @{
                DomainCount = 1
                Domains     = @{ 'contoso.com' = [pscustomobject]@{
                    SPF = 'v=spf1 include:spf.protection.outlook.com -all' } }
            })
            (GetVerdict 'Test-NRGControlDNSSPF' 'DNS-1.1').State | Should -Be 'Satisfied'
        }

        It 'Partial on soft fail (~all) — spoofed mail still gets delivered' {
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data (NewRaw 'DNS' @{
                DomainCount = 1
                Domains     = @{ 'contoso.com' = [pscustomobject]@{
                    SPF = 'v=spf1 include:spf.protection.outlook.com ~all' } }
            })
            (GetVerdict 'Test-NRGControlDNSSPF' 'DNS-1.1').State | Should -Be 'Partial'
        }

        It 'Gap when the domain has no SPF record at all' {
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data (NewRaw 'DNS' @{
                DomainCount = 1
                Domains     = @{ 'contoso.com' = [pscustomobject]@{ SPF = $null } }
            })
            (GetVerdict 'Test-NRGControlDNSSPF' 'DNS-1.1').State | Should -Be 'Gap'
        }
    }

    Context 'Cross-cutting — a compliant tenant is never reported as vulnerable' {

        It 'the compliant fixtures above produce zero Gap findings for their controls' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @(
                    (NewCaPolicy -DisplayName 'Block legacy' -State 'enabled' `
                        -ClientAppTypes @('other', 'exchangeActiveSync') -BuiltInControls @('block')),
                    (NewCaPolicy -DisplayName 'Admins phish-resistant' -State 'enabled' `
                        -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10') `
                        -AuthStrengthId '00000000-0000-0000-0000-000000000004')
                )
            })
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (NewRaw 'EXO' @{
                OrganizationConfig = [pscustomobject]@{ OAuth2ClientProfileEnabled = $true }
            })

            Test-NRGControlAADLegacyAuth        | Out-Null
            Test-NRGControlAADPhishResistantMFA | Out-Null
            Test-NRGControlEXOModernAuth        | Out-Null

            $gaps = @(Get-NRGFindings | Where-Object {
                $_.ControlId -in @('AAD-1.1', 'AAD-1.3', 'EXO-1.6') -and $_.State -eq 'Gap'
            })
            $gaps.Count | Should -Be 0 `
                -Because 'false positives on a well-configured tenant destroy the credibility of every other finding in the report'
        }
    }
}

Describe 'Golden fixtures — privilege escalation attack path' {

    # The tenant-takeover chain: an attacker who lands one account works toward
    # standing admin rights. These controls are what stop the escalation, and
    # their middle verdicts encode distinctions most assessment tools miss —
    # notably that a correct GA COUNT still leaves you exposed if any of those
    # admins is synced from on-prem AD (MITRE T1078.002: compromise the domain
    # controller, inherit Global Admin).

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        $script:GA_ROLE_ID = '62e90394-69f5-4237-9190-012177145e10'

        function script:NewRaw2 {
            param([string] $CollectorId, [hashtable] $Data, [bool] $Success = $true)
            [ordered]@{
                CollectorId = $CollectorId
                CollectedAt = '2026-07-30T00:00:00.0000000+00:00'
                Success     = $Success
                Data        = $Data
            }
        }
        function script:GetVerdict2 {
            param([string] $Evaluator, [string] $ControlId)
            & $Evaluator | Out-Null
            return @(Get-NRGFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
        }
        function script:NewGA {
            param([string] $Upn, [bool] $Synced = $false)
            [pscustomobject]@{
                RoleDefinitionId     = $script:GA_ROLE_ID
                RoleDefinitionName   = 'Global Administrator'
                PrincipalUPN         = $Upn
                PrincipalDisplayName = $Upn
                OnPremisesSyncEnabled = $Synced
                PrincipalType        = 'user'
                IsPriv               = $true
            }
        }
    }

    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    Context 'AAD-3.1 — Global Administrator count and origin' {

        It 'Satisfied when 2-8 Global Admins exist and all are cloud-only' {
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRaw2 'AAD' @{
                RoleAssignments = @( (NewGA 'admin1@contoso.com'), (NewGA 'admin2@contoso.com'), (NewGA 'admin3@contoso.com') )
            })
            (GetVerdict2 'Test-NRGControlAADPrivAccess' 'AAD-3.1').State | Should -Be 'Satisfied'
        }

        It 'Partial when the count is right but a GA is synced from on-prem AD (T1078.002)' {
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRaw2 'AAD' @{
                RoleAssignments = @(
                    (NewGA 'admin1@contoso.com'),
                    (NewGA 'admin2@contoso.com'),
                    (NewGA 'dcadmin@contoso.com' -Synced $true)
                )
            })
            $v = GetVerdict2 'Test-NRGControlAADPrivAccess' 'AAD-3.1'
            $v.State | Should -Be 'Partial' `
                -Because 'a synced GA means on-prem AD compromise yields immediate Entra Global Admin — a correct count alone is not safety, and most tools only count'
            $v.CurrentValue | Should -Match 'dcadmin@contoso\.com' -Because 'the client must know which admin is the escalation path'
        }

        It 'Gap when fewer than 2 Global Admins exist (lockout / recovery risk)' {
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRaw2 'AAD' @{
                RoleAssignments = @( (NewGA 'onlyadmin@contoso.com') )
            })
            (GetVerdict2 'Test-NRGControlAADPrivAccess' 'AAD-3.1').State | Should -Be 'Gap' `
                -Because 'a single GA is a availability risk, not just a security one — losing it locks the client out of their own tenant'
        }

        It 'Gap when more than 8 permanent Global Admins exist (excess attack surface)' {
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRaw2 'AAD' @{
                RoleAssignments = @( 1..9 | ForEach-Object { NewGA "admin$_@contoso.com" } )
            })
            (GetVerdict2 'Test-NRGControlAADPrivAccess' 'AAD-3.1').State | Should -Be 'Gap'
        }
    }

    Context 'AAD-3.2 — No standing privileged access (PIM)' {

        It 'Satisfied when no permanent privileged assignments exist and PIM eligibility is configured' {
            Set-NRGRawData -Key 'AAD-PIMSchedules'   -Data (NewRaw2 'AAD' @{ EligibleSchedules = @('sched1', 'sched2') })
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRaw2 'AAD' @{ RoleAssignments   = @() })
            (GetVerdict2 'Test-NRGControlAADNoPermanentAdmins' 'AAD-3.2').State | Should -Be 'Satisfied'
        }

        It 'Gap when a human holds a permanent privileged role' {
            Set-NRGRawData -Key 'AAD-PIMSchedules'   -Data (NewRaw2 'AAD' @{ EligibleSchedules = @('sched1') })
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRaw2 'AAD' @{
                RoleAssignments = @( [pscustomobject]@{
                    IsPriv = $true; PrincipalType = 'user'
                    PrincipalDisplayName = 'Standing Admin'; PrincipalUPN = 'standing@contoso.com' } )
            })
            $v = GetVerdict2 'Test-NRGControlAADNoPermanentAdmins' 'AAD-3.2'
            $v.State | Should -Be 'Gap'
            $v.CurrentValue | Should -Match 'Standing Admin'
        }

        It 'does NOT flag a service principal as a standing admin (no false positive)' {
            Set-NRGRawData -Key 'AAD-PIMSchedules'   -Data (NewRaw2 'AAD' @{ EligibleSchedules = @('sched1') })
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRaw2 'AAD' @{
                RoleAssignments = @( [pscustomobject]@{
                    IsPriv = $true; PrincipalType = 'servicePrincipal'
                    PrincipalDisplayName = 'Backup App'; PrincipalUPN = '' } )
            })
            (GetVerdict2 'Test-NRGControlAADNoPermanentAdmins' 'AAD-3.2').State | Should -Be 'Satisfied' `
                -Because 'service principals are excluded by design — flagging them would generate noise the client cannot action'
        }

        It 'NotApplicable when PIM is unlicensed rather than pretending it is a gap' {
            $pim = NewRaw2 'AAD' @{} $false
            $pim['PIMAvailable'] = $false
            Set-NRGRawData -Key 'AAD-PIMSchedules' -Data $pim
            (GetVerdict2 'Test-NRGControlAADNoPermanentAdmins' 'AAD-3.2').State | Should -Be 'NotApplicable' `
                -Because 'a client without Entra P2 cannot use PIM — scoring it as a failure would be an unfair, unfixable finding'
        }
    }

    Context 'AAD-6.2 — User Consent to Apps (consent-phishing entry point)' {

        It 'Satisfied when user consent is restricted to low-impact permissions' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (NewRaw2 'AAD' @{
                ExternalCollab = @{ PermissionGrantPolicies = @('ManagePermissionGrantsForSelf.microsoft-user-default-low') }
            })
            (GetVerdict2 'Test-NRGControlAADUserConsent' 'AAD-6.2').State | Should -Be 'Satisfied'
        }

        It 'Gap when the legacy unrestricted consent policy is in place' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (NewRaw2 'AAD' @{
                ExternalCollab = @{ PermissionGrantPolicies = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy') }
            })
            (GetVerdict2 'Test-NRGControlAADUserConsent' 'AAD-6.2').State | Should -Be 'Gap' `
                -Because 'unrestricted consent lets a phishing app read mail and files with no admin involvement — the OAuth consent-phishing path'
        }
    }
}

Describe 'Failed collection is never reported as compliance (EXO inventory)' {

    # The EXO-Inventory collector runs several independent queries, each with its
    # own try/catch, then sets Success = $true regardless. A failure therefore
    # leaves one list empty while the overall result still looks healthy. These
    # are the named-list controls an MSP actually sells on, so an empty-means-
    # clean reading is the highest-consequence false result in the tool.
    #
    # Each control is pinned twice: FAILED section must be NotApplicable, and a
    # COLLECTED-but-empty section must still be Satisfied so the guard does not
    # suppress genuine passes.

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:NewInv {
            param([hashtable] $Data)
            [ordered]@{
                CollectorId = 'EXO-Inventory'
                CollectedAt = '2026-07-30T00:00:00.0000000+00:00'
                Success     = $true
                Data        = $Data
            }
        }
        function script:InvVerdict {
            param([string] $Evaluator, [string] $ControlId)
            & $Evaluator | Out-Null
            return @(Get-NRGFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
        }
    }

    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    $cases = @(
        @{ Control = 'EXO-6.1'; Evaluator = 'Test-NRGControlInventoryExternalForwarding'; Key = 'ForwardingMailboxes';    Section = 'ForwardingMailboxes' }
        @{ Control = 'EXO-6.2'; Evaluator = 'Test-NRGControlInventorySharedMailboxSignIn'; Key = 'AllSharedMailboxes';    Section = 'SharedMailboxes' }
        @{ Control = 'EXO-6.3'; Evaluator = 'Test-NRGControlInventoryMailboxAuditDisabled'; Key = 'AuditDisabledMailboxes'; Section = 'AuditDisabledMailboxes' }
        @{ Control = 'EXO-6.4'; Evaluator = 'Test-NRGControlInventorySMTPAuthUsers';        Key = 'SmtpAuthEnabledPerUser'; Section = 'SmtpAuthEnabledPerUser' }
    )

    It '<Control> reports NotApplicable when its collection section FAILED' -TestCases $cases {
        Set-NRGRawData -Key 'EXO-Inventory' -Data (NewInv @{
            $Key          = @()
            SectionStatus = @{ $Section = 'Failed' }
        })
        (InvVerdict $Evaluator $Control).State | Should -Be 'NotApplicable' `
            -Because "$Control would otherwise tell the client they are clean on the strength of a query that never returned"
    }

    It '<Control> still reports Satisfied when the section COLLECTED and found nothing' -TestCases $cases {
        Set-NRGRawData -Key 'EXO-Inventory' -Data (NewInv @{
            $Key          = @()
            SectionStatus = @{ $Section = 'Collected' }
        })
        (InvVerdict $Evaluator $Control).State | Should -Be 'Satisfied' `
            -Because 'a genuinely clean tenant must still pass — the guard must not suppress real compliance'
    }
}

Describe 'Newly implemented controls — EXO-3.4, TMS-3.4, SPO-2.5, PPL-1.3' {

    # Four manual-review placeholders replaced with real checks against data the
    # collectors were already gathering (or, for PPL-1.3, one documented call in
    # a module the collector already imports). Each pins the honest-degradation
    # arm too: when the source could not be read the verdict is NotApplicable,
    # never a confident pass or a false alarm.

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:Raw {
            param([string]$Id,[hashtable]$Data,[bool]$Success=$true)
            [ordered]@{ CollectorId=$Id; CollectedAt='2026-07-30T00:00:00.0000000+00:00'
                        Success=$Success; Data=$Data }
        }
        function script:V { param([string]$Fn,[string]$Cid)
            & $Fn | Out-Null
            return @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid })[0]
        }
    }
    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    Context 'EXO-3.4 — unusual mail volume alerting' {
        It 'Satisfied when a phish-reporting alert policy is enabled with recipients' {
            Set-NRGRawData -Key 'Purview' -Data (Raw 'Purview' @{
                ProtectionAlerts=@([pscustomobject]@{ Name='Unusual increase in email reported as phish'
                    Severity='High'; Disabled=$false; NotifyUser=@('soc@contoso.com'); ThreatType=''; Operation=@() })
                SectionStatus=@{ ProtectionAlerts='Collected' } })
            (V 'Test-NRGControlEXOAlertVolume' 'EXO-3.4').State | Should -Be 'Satisfied'
        }
        It 'Gap — disclosing the name-match caveat — when nothing covers mail volume' {
            Set-NRGRawData -Key 'Purview' -Data (Raw 'Purview' @{
                ProtectionAlerts=@([pscustomobject]@{ Name='Malware detected'; Severity='High'
                    Disabled=$false; NotifyUser=@('soc@contoso.com'); ThreatType=''; Operation=@() })
                SectionStatus=@{ ProtectionAlerts='Collected' } })
            $v = V 'Test-NRGControlEXOAlertVolume' 'EXO-3.4'
            $v.State | Should -Be 'Gap'
            $v.Detail | Should -Match 'verify in the portal'
        }
        It 'NotApplicable when Get-ProtectionAlert never ran' {
            Set-NRGRawData -Key 'Purview' -Data (Raw 'Purview' @{
                ProtectionAlerts=@(); SectionStatus=@{ ProtectionAlerts='NotRun' } })
            (V 'Test-NRGControlEXOAlertVolume' 'EXO-3.4').State | Should -Be 'NotApplicable'
        }
    }

    Context 'TMS-3.4 — Teams chat DLP coverage' {
        It 'Satisfied when an enabled DLP policy targets Teams' {
            Set-NRGRawData -Key 'Purview' -Data (Raw 'Purview' @{
                DLPPolicies=@([pscustomobject]@{ Name='Teams PII'; Enabled=$true; Mode='Enable'
                                                 Workloads=@('Teams','Exchange') }) })
            (V 'Test-NRGControlTeamsChatCopy' 'TMS-3.4').State | Should -Be 'Satisfied'
        }
        It 'Partial when a Teams DLP policy exists but is not enabled' {
            Set-NRGRawData -Key 'Purview' -Data (Raw 'Purview' @{
                DLPPolicies=@([pscustomobject]@{ Name='Teams PII'; Enabled=$false; Mode='TestWithNotifications'
                                                 Workloads=@('Teams') }) })
            (V 'Test-NRGControlTeamsChatCopy' 'TMS-3.4').State | Should -Be 'Partial' `
                -Because 'a policy in test mode enforces nothing, so reporting it as coverage would overstate protection'
        }
        It 'Gap when DLP exists but never covers Teams' {
            Set-NRGRawData -Key 'Purview' -Data (Raw 'Purview' @{
                DLPPolicies=@([pscustomobject]@{ Name='Mail only'; Enabled=$true; Mode='Enable'
                                                 Workloads=@('Exchange') }) })
            (V 'Test-NRGControlTeamsChatCopy' 'TMS-3.4').State | Should -Be 'Gap'
        }
        It 'NotApplicable when Purview data is absent' {
            (V 'Test-NRGControlTeamsChatCopy' 'TMS-3.4').State | Should -Be 'NotApplicable'
        }
    }

    Context 'SPO-2.5 — third-party cloud storage connectors' {
        It 'Satisfied when every connector is off' {
            Set-NRGRawData -Key 'Teams' -Data (Raw 'Teams' @{
                ClientConfiguration=@{ AllowDropBox=$false; AllowBox=$false
                                       AllowGoogleDrive=$false; AllowShareFile=$false } })
            (V 'Test-NRGControlSPO3PStorage' 'SPO-2.5').State | Should -Be 'Satisfied'
        }
        It 'Gap naming each enabled connector' {
            Set-NRGRawData -Key 'Teams' -Data (Raw 'Teams' @{
                ClientConfiguration=@{ AllowDropBox=$true; AllowBox=$false
                                       AllowGoogleDrive=$true; AllowShareFile=$false } })
            $v = V 'Test-NRGControlSPO3PStorage' 'SPO-2.5'
            $v.State | Should -Be 'Gap'
            $v.CurrentValue | Should -Match 'Dropbox'
            $v.CurrentValue | Should -Match 'GoogleDrive'
        }
        It 'states which surface it actually verified' {
            Set-NRGRawData -Key 'Teams' -Data (Raw 'Teams' @{
                ClientConfiguration=@{ AllowDropBox=$false; AllowBox=$false
                                       AllowGoogleDrive=$false; AllowShareFile=$false } })
            (V 'Test-NRGControlSPO3PStorage' 'SPO-2.5').Detail | Should -Match 'admin centre' `
                -Because 'the control cannot read the admin-centre toggle, so the finding must say what it did and did not verify'
        }
        It 'NotApplicable when Teams client configuration was not collected' {
            Set-NRGRawData -Key 'Teams' -Data (Raw 'Teams' @{})
            (V 'Test-NRGControlSPO3PStorage' 'SPO-2.5').State | Should -Be 'NotApplicable'
        }
    }

    Context 'PPL-1.3 — environment creation restricted' {
        It 'Satisfied when creation is restricted to admins' {
            Set-NRGRawData -Key 'PowerPlatform' -Data (Raw 'PowerPlatform' @{
                Environments=@('e1'); TenantIsolation=$null; DLPPolicies=@()
                TenantGovernance=@{ EnvironmentCreationRestricted=$true; TrialEnvironmentCreationRestricted=$true }
                SectionStatus=@{ TenantGovernance='Collected' } })
            (V 'Test-NRGControlPowerPlatform' 'PPL-1.3').State | Should -Be 'Satisfied'
        }
        It 'Partial when standard creation is locked but trial creation is not' {
            Set-NRGRawData -Key 'PowerPlatform' -Data (Raw 'PowerPlatform' @{
                Environments=@('e1'); TenantIsolation=$null; DLPPolicies=@()
                TenantGovernance=@{ EnvironmentCreationRestricted=$true; TrialEnvironmentCreationRestricted=$false }
                SectionStatus=@{ TenantGovernance='Collected' } })
            (V 'Test-NRGControlPowerPlatform' 'PPL-1.3').State | Should -Be 'Partial' `
                -Because 'a trial environment is a fully functional environment outside the DLP baseline — the same gap by another route'
        }
        It 'Gap when any user can create environments' {
            Set-NRGRawData -Key 'PowerPlatform' -Data (Raw 'PowerPlatform' @{
                Environments=@('e1'); TenantIsolation=$null; DLPPolicies=@()
                TenantGovernance=@{ EnvironmentCreationRestricted=$false; TrialEnvironmentCreationRestricted=$false }
                SectionStatus=@{ TenantGovernance='Collected' } })
            (V 'Test-NRGControlPowerPlatform' 'PPL-1.3').State | Should -Be 'Gap'
        }
        It 'NotApplicable when the settings call could not run (BAP fallback path)' {
            Set-NRGRawData -Key 'PowerPlatform' -Data (Raw 'PowerPlatform' @{
                Environments=@('e1'); TenantIsolation=$null; DLPPolicies=@()
                TenantGovernance=$null; SectionStatus=@{ TenantGovernance='NotRun' } })
            (V 'Test-NRGControlPowerPlatform' 'PPL-1.3').State | Should -Be 'NotApplicable' `
                -Because 'the BAP-API fallback cannot read tenant settings, and absence is not evidence of an open tenant'
        }
    }
}

Describe 'DEF-3.4 / DEF-4.3 alert policy configuration — implemented' {

    # Both were High severity manual-review placeholders. They read alert POLICY
    # configuration from Get-ProtectionAlert, which answers a different question
    # from the /security/alerts_v2 feed collected elsewhere: that lists alerts
    # which fired, this asks whether anyone is configured to be told when they
    # do. An enabled policy with an empty NotifyUser raises an alert into an
    # empty room.

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:PvwRaw {
            param([object[]] $Alerts = @(), [string] $Section = 'Collected')
            [ordered]@{
                CollectorId='Purview'; CollectedAt='2026-07-30T00:00:00.0000000+00:00'; Success=$true
                Data=@{ ProtectionAlerts = $Alerts; SectionStatus = @{ ProtectionAlerts = $Section } }
            }
        }
        function script:Pol {
            param([string]$Name,[string]$Sev='High',[bool]$Disabled=$false,[string[]]$Notify=@('soc@contoso.com'),
                  [string]$Threat='',[string[]]$Op=@())
            [pscustomobject]@{ Name=$Name; Category='ThreatManagement'; Severity=$Sev
                               Disabled=$Disabled; NotifyUser=$Notify; ThreatType=$Threat; Operation=$Op }
        }
        function script:AlertVerdict {
            param([string]$Evaluator,[string]$ControlId)
            & $Evaluator | Out-Null
            return @(Get-NRGFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
        }
    }

    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    Context 'DEF-3.4 — high severity alerts reach a human' {

        It 'no longer returns a permanent placeholder' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @((Pol 'Malware campaign detected')))
            (AlertVerdict 'Test-NRGControlDefenderAlertNotification' 'DEF-3.4').State | Should -Not -Be 'NotApplicable'
        }

        It 'Satisfied when every enabled High/Critical policy has recipients' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @(
                (Pol 'Malware campaign detected'), (Pol 'Elevation of privilege' 'Critical')))
            (AlertVerdict 'Test-NRGControlDefenderAlertNotification' 'DEF-3.4').State | Should -Be 'Satisfied'
        }

        It 'Gap — naming the policy — when a High policy has no recipients' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @(
                (Pol 'Malware campaign detected'),
                (Pol 'Elevation of privilege' 'Critical' $false @())))
            $v = AlertVerdict 'Test-NRGControlDefenderAlertNotification' 'DEF-3.4'
            $v.State | Should -Be 'Gap'
            ($v.AffectedObjects | ConvertTo-Json -Depth 4) | Should -Match 'Elevation of privilege'
        }

        It 'ignores DISABLED policies when judging coverage' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @(
                (Pol 'Malware campaign detected'),
                (Pol 'Retired policy' 'High' $true @())))
            (AlertVerdict 'Test-NRGControlDefenderAlertNotification' 'DEF-3.4').State | Should -Be 'Satisfied' `
                -Because 'a disabled policy with no recipients is not a live blind spot'
        }

        It 'Gap when the tenant has no alert policies at all' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @())
            (AlertVerdict 'Test-NRGControlDefenderAlertNotification' 'DEF-3.4').State | Should -Be 'Gap'
        }

        It 'NotApplicable when Get-ProtectionAlert could not run (no IPPS session)' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @() -Section 'NotRun')
            (AlertVerdict 'Test-NRGControlDefenderAlertNotification' 'DEF-3.4').State | Should -Be 'NotApplicable' `
                -Because 'an unavailable session is not evidence that alerting is unconfigured'
        }
    }

    Context 'DEF-4.3 — OAuth consent alerting' {

        It 'Satisfied when a consent-related policy is enabled with recipients' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @(
                (Pol 'Tenant-wide admin consent to an application')))
            (AlertVerdict 'Test-NRGControlDefenderRiskyAppAlerts' 'DEF-4.3').State | Should -Be 'Satisfied'
        }

        It 'matches on Operation as well as Name' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @(
                (Pol 'Custom policy 7' 'High' $false @('soc@contoso.com') '' @('ConsentToApplication'))))
            (AlertVerdict 'Test-NRGControlDefenderRiskyAppAlerts' 'DEF-4.3').State | Should -Be 'Satisfied' `
                -Because 'a differently-named policy is still real coverage — matching only on Name would under-detect'
        }

        It 'Gap when nothing covers OAuth consent' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @((Pol 'Malware campaign detected')))
            $v = AlertVerdict 'Test-NRGControlDefenderRiskyAppAlerts' 'DEF-4.3'
            $v.State | Should -Be 'Gap'
            $v.Detail | Should -Match 'verify in the portal' `
                -Because 'the finding must disclose that detection is name-based and could miss a custom-named policy'
        }

        It 'Partial — not Satisfied — when the consent policy notifies nobody' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @(
                (Pol 'Tenant-wide admin consent to an application' 'High' $false @())))
            (AlertVerdict 'Test-NRGControlDefenderRiskyAppAlerts' 'DEF-4.3').State | Should -Be 'Partial'
        }

        It 'a disabled consent policy does not count as coverage' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @(
                (Pol 'Tenant-wide admin consent to an application' 'High' $true)))
            (AlertVerdict 'Test-NRGControlDefenderRiskyAppAlerts' 'DEF-4.3').State | Should -Be 'Gap'
        }

        It 'NotApplicable when Get-ProtectionAlert could not run' {
            Set-NRGRawData -Key 'Purview' -Data (PvwRaw -Alerts @() -Section 'Failed')
            (AlertVerdict 'Test-NRGControlDefenderRiskyAppAlerts' 'DEF-4.3').State | Should -Be 'NotApplicable'
        }
    }
}

Describe 'EXO-2.6 shared mailbox sign-in — implemented, evidence-graded' {

    # Was a manual-review placeholder that always returned NotApplicable despite
    # being High severity. The join it needed (EXO shared mailboxes against AAD
    # accountEnabled) was already being done by the collector and published as
    # SharedMailboxSignIn. Each hit is tagged with the evidence behind it, and
    # the verdict follows that evidence rather than flattening a heuristic into
    # a confirmed finding.

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:SharedRaw {
            param([object[]] $All = @(), [object[]] $Risky = @(), [string] $Section = 'Collected')
            [ordered]@{
                CollectorId='EXO-Inventory'; CollectedAt='2026-07-30T00:00:00.0000000+00:00'; Success=$true
                Data=@{
                    AllSharedMailboxes  = $All
                    SharedMailboxSignIn = $Risky
                    SectionStatus       = @{ SharedMailboxes = $Section }
                }
            }
        }
        function script:MB { param([string]$Name) [pscustomobject]@{ DisplayName=$Name; PrimarySmtp="$Name@contoso.com" } }
        function script:Risk {
            param([string]$Name,[string]$Source='AAD-Users',[string]$State='Enabled')
            [pscustomobject]@{ DisplayName=$Name; UPN="$Name@contoso.com"
                               PrimarySmtp="$Name@contoso.com"; SignInState=$State; Source=$Source }
        }
        function script:SharedVerdict {
            Test-NRGControlEXOSharedMailbox | Out-Null
            return @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'EXO-2.6' })[0]
        }
    }

    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    It 'no longer returns a permanent NotApplicable placeholder' {
        Set-NRGRawData -Key 'EXO-Inventory' -Data (SharedRaw -All @((MB 'billing')) -Risky @())
        (SharedVerdict).State | Should -Not -Be 'NotApplicable' `
            -Because 'a High severity control that can only ever say "manual review required" is scaffolding, not an assessment'
    }

    It 'Satisfied when shared mailboxes exist and none can sign in' {
        Set-NRGRawData -Key 'EXO-Inventory' -Data (SharedRaw -All @((MB 'billing'),(MB 'support')) -Risky @())
        (SharedVerdict).State | Should -Be 'Satisfied'
    }

    It 'Satisfied when the tenant has no shared mailboxes at all' {
        Set-NRGRawData -Key 'EXO-Inventory' -Data (SharedRaw -All @() -Risky @())
        (SharedVerdict).State | Should -Be 'Satisfied'
    }

    It 'Gap — naming the mailbox — when sign-in is CONFIRMED enabled via Entra' {
        Set-NRGRawData -Key 'EXO-Inventory' -Data (SharedRaw `
            -All @((MB 'billing'),(MB 'support')) -Risky @((Risk 'billing')))
        $v = SharedVerdict
        $v.State | Should -Be 'Gap'
        $v.Severity | Should -Be 'High'
        ($v.AffectedObjects | ConvertTo-Json -Depth 4) | Should -Match 'billing@contoso\.com'
        ($v.AffectedObjects | ConvertTo-Json -Depth 4) | Should -Match 'Confirmed via Entra'
    }

    It 'Partial — not Gap — when only the license heuristic fired and Entra data was unavailable' {
        Set-NRGRawData -Key 'EXO-Inventory' -Data (SharedRaw `
            -All @((MB 'billing')) -Risky @((Risk 'billing' 'LicenseProxy' 'Probable')))
        $v = SharedVerdict
        $v.State | Should -Be 'Partial' `
            -Because 'an inferred signal is not a confirmed finding — reporting a guess as a Gap is how a report loses credibility'
        ($v.AffectedObjects | ConvertTo-Json -Depth 4) | Should -Match 'Inferred from license state'
    }

    It 'a confirmed hit outranks heuristic-only noise in the same tenant' {
        Set-NRGRawData -Key 'EXO-Inventory' -Data (SharedRaw `
            -All @((MB 'billing'),(MB 'support')) `
            -Risky @((Risk 'billing' 'LicenseProxy' 'Probable'), (Risk 'support')))
        (SharedVerdict).State | Should -Be 'Gap'
    }

    It 'NotApplicable when the shared mailbox enumeration itself failed' {
        Set-NRGRawData -Key 'EXO-Inventory' -Data (SharedRaw -All @() -Risky @() -Section 'Failed')
        (SharedVerdict).State | Should -Be 'NotApplicable'
    }
}

Describe 'EXO-4.4 anti-spam thresholds agree with the control remediation' {

    # The evaluator previously passed BulkThreshold = 7 while the control's own
    # Remediation instructed -BulkThreshold 6, so a client on Microsoft's
    # default was told Satisfied by a control whose remediation told them to
    # change the very setting that passed. These pin the resolved boundary.

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:SpamRaw {
            param([int] $Bulk, [string] $Action = 'MoveToJmf', [bool] $Zap = $true)
            [ordered]@{
                CollectorId='EXO'; CollectedAt='2026-07-30T00:00:00.0000000+00:00'; Success=$true
                Data=@{ AntiSpamPolicies = @([pscustomobject]@{
                    IsDefault=$true; SpamAction=$Action; BulkThreshold=$Bulk; ZapEnabled=$Zap }) }
            }
        }
        function script:SpamVerdict {
            Test-NRGControlEXOAntiSpamInbound | Out-Null
            return @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'EXO-4.4' })[0]
        }
    }

    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    It 'Satisfied at BulkThreshold 6 (the value the remediation instructs)' {
        Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (SpamRaw -Bulk 6)
        (SpamVerdict).State | Should -Be 'Satisfied'
    }

    It 'Partial at BulkThreshold 7 — Microsoft default is above the control requirement' {
        Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (SpamRaw -Bulk 7)
        $v = SpamVerdict
        $v.State | Should -Be 'Partial' `
            -Because 'passing 7 while the remediation says 6 made the control contradict itself in the client report'
        $v.CurrentValue | Should -Match 'BulkThreshold=7'
    }

    It 'Partial when spam action leaves mail in the inbox' {
        Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (SpamRaw -Bulk 6 -Action 'NoAction')
        (SpamVerdict).State | Should -Be 'Partial'
    }

    It 'Partial when zero-hour auto purge is off' {
        Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (SpamRaw -Bulk 6 -Zap $false)
        (SpamVerdict).State | Should -Be 'Partial'
    }
}

Describe 'Failed collection is never reported as compliance (AAD inventory + joins)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:NewAADInv {
            param([hashtable] $Data)
            [ordered]@{ CollectorId='AAD-Inventory'; CollectedAt='2026-07-30T00:00:00.0000000+00:00'
                        Success=$true; Data=$Data }
        }
        function script:AADInvVerdict {
            param([string] $Evaluator, [string] $ControlId)
            & $Evaluator | Out-Null
            return @(Get-NRGFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
        }
    }

    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    $invCases = @(
        @{ Control='AAD-12.2'; Evaluator='Test-NRGControlInventoryStaleGuests';  Key='GuestUsers';       Section='GuestUsers' }
        @{ Control='AAD-12.3'; Evaluator='Test-NRGControlInventoryStaleMembers'; Key='StaleMembers';     Section='StaleMembers' }
        @{ Control='AAD-12.4'; Evaluator='Test-NRGControlInventoryOAuthApps';    Key='OAuthGrantedApps'; Section='OAuthGrantedApps' }
    )

    It '<Control> reports NotApplicable when its enumeration FAILED' -TestCases $invCases {
        Set-NRGRawData -Key 'AAD-Inventory' -Data (NewAADInv @{
            $Key = @(); SectionStatus = @{ $Section = 'Failed' }
        })
        (AADInvVerdict $Evaluator $Control).State | Should -Be 'NotApplicable' `
            -Because "$Control would otherwise state a definitive all-clear from a query that never returned"
    }

    It '<Control> still reports Satisfied when the enumeration COMPLETED and found nothing' -TestCases $invCases {
        Set-NRGRawData -Key 'AAD-Inventory' -Data (NewAADInv @{
            $Key = @(); SectionStatus = @{ $Section = 'Collected' }
        })
        (AADInvVerdict $Evaluator $Control).State | Should -Be 'Satisfied'
    }

    It 'EXO-6.2 reports NotApplicable when the AAD user join data is missing' {
        # Shared-mailbox sign-in state is only knowable by joining against AAD
        # users. Without them the join yields zero matches and the evaluator
        # would claim "all have interactive sign-in blocked" — a definitive
        # verdict on a comparison that never happened.
        Set-NRGRawData -Key 'EXO-Inventory' -Data ([ordered]@{
            CollectorId='EXO-Inventory'; CollectedAt='2026-07-30T00:00:00.0000000+00:00'; Success=$true
            Data=@{
                AllSharedMailboxes = @([pscustomobject]@{ DisplayName='Billing'; PrimarySmtp='billing@contoso.com' })
                SectionStatus      = @{ SharedMailboxes = 'Collected' }
            }
        })
        # AAD-Users deliberately absent
        (AADInvVerdict 'Test-NRGControlInventorySharedMailboxSignIn' 'EXO-6.2').State | Should -Be 'NotApplicable' `
            -Because 'a cross-reference that could not run is not evidence that every shared mailbox is blocked'
    }
}

Describe 'Failed role collection is never reported as compliance (AAD roles)' {

    # Invoke-NRGCollectAADRoles sets Success = (assignments -OR- eligibility).
    # On a PIM-managed tenant where the permanent-assignment read 403s but
    # eligibility succeeds, Success stays $true while RoleAssignments and
    # PrivRoles are empty. Every real tenant has at least one privileged
    # assignment, so empty there is a failed read — never a clean tenant.

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:NewRoles {
            param([hashtable] $Data)
            [ordered]@{
                CollectorId = 'AAD-Roles'
                CollectedAt = '2026-07-30T00:00:00.0000000+00:00'
                Success     = $true      # eligibility succeeded, assignments did not
                Data        = $Data
            }
        }
        function script:RoleVerdict {
            param([string] $Evaluator, [string] $ControlId)
            & $Evaluator | Out-Null
            return @(Get-NRGFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
        }
    }

    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    It 'AAD-11.2 reports NotApplicable — not "no guest admins" — when the assignment read failed' {
        Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRoles @{
            RoleAssignments = @(); PrivRoles = @()
            SectionStatus   = @{ RoleAssignments = 'Failed'; RoleEligibilitySchedules = 'Collected' }
        })
        (RoleVerdict 'Test-NRGControlAADNoGuestInPrivRoles' 'AAD-11.2').State | Should -Be 'NotApplicable' `
            -Because 'claiming no guest holds a privileged role after failing to read role assignments is a false pass on a tenant-takeover control'
    }

    It 'AAD-10.2 reports NotApplicable — not "no synced admins" — when the assignment read failed' {
        Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRoles @{
            RoleAssignments = @(); PrivRoles = @()
            SectionStatus   = @{ RoleAssignments = 'Failed'; RoleEligibilitySchedules = 'Collected' }
        })
        (RoleVerdict 'Test-NRGControlAADPrivCloudOnly' 'AAD-10.2').State | Should -Be 'NotApplicable'
    }

    It 'AAD-3.1 reports NotApplicable — not "fewer than 2 Global Admins" — when the assignment read failed' {
        Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRoles @{
            RoleAssignments = @(); PrivRoles = @()
            SectionStatus   = @{ RoleAssignments = 'Failed'; RoleEligibilitySchedules = 'Collected' }
        })
        (RoleVerdict 'Test-NRGControlAADPrivAccess' 'AAD-3.1').State | Should -Be 'NotApplicable' `
            -Because 'telling a client they have no Global Administrators when the read failed is a false ALARM — just as damaging to credibility as a false pass'
    }

    It 'a COLLECTED-but-genuinely-clean tenant still passes AAD-11.2' {
        Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data (NewRoles @{
            RoleAssignments = @( [pscustomobject]@{ RoleDefinitionName = 'Global Administrator'
                                                    PrincipalUPN = 'admin@contoso.com'
                                                    PrincipalDisplayName = 'Alice' } )
            PrivRoles     = @()
            SectionStatus = @{ RoleAssignments = 'Collected'; RoleEligibilitySchedules = 'Collected' }
        })
        (RoleVerdict 'Test-NRGControlAADNoGuestInPrivRoles' 'AAD-11.2').State | Should -Be 'Satisfied' `
            -Because 'the guard must not suppress genuine compliance'
    }
}

Describe 'Golden fixtures — ransomware attack path' {

    # Ransomware in M365 arrives by mail, executes on an endpoint, and spreads
    # through cloud storage. These controls cover that chain: block the delivery
    # (attachment filtering), harden the endpoint (ASR), and detect the
    # exfiltration/persistence step (attacker inbox rules forwarding mail out).

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:NewRaw3 {
            param([string] $CollectorId, [hashtable] $Data, [bool] $Success = $true)
            [ordered]@{
                CollectorId = $CollectorId
                CollectedAt = '2026-07-30T00:00:00.0000000+00:00'
                Success     = $Success
                Data        = $Data
            }
        }
        function script:GetVerdict3 {
            param([string] $Evaluator, [string] $ControlId)
            & $Evaluator | Out-Null
            return @(Get-NRGFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
        }
    }

    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    Context 'DEF-2.3 — Common attachment filter (malware delivery)' {

        It 'Satisfied when the common attachment filter is enabled on a malware policy' {
            Set-NRGRawData -Key 'Defender-Policies' -Data (NewRaw3 'DEF' @{
                MalwareFilter = [pscustomobject]@{ Available = $true; FileFilterEnabledCount = 1 }
            })
            (GetVerdict3 'Test-NRGControlDefenderCommonAttachments' 'DEF-2.3').State | Should -Be 'Satisfied'
        }

        It 'Gap when no policy blocks high-risk file types' {
            Set-NRGRawData -Key 'Defender-Policies' -Data (NewRaw3 'DEF' @{
                MalwareFilter = [pscustomobject]@{ Available = $true; FileFilterEnabledCount = 0 }
            })
            (GetVerdict3 'Test-NRGControlDefenderCommonAttachments' 'DEF-2.3').State | Should -Be 'Gap'
        }

        It 'NotApplicable when malware filter data could not be read' {
            Set-NRGRawData -Key 'Defender-Policies' -Data (NewRaw3 'DEF' @{
                MalwareFilter = [pscustomobject]@{ Available = $false }
            })
            (GetVerdict3 'Test-NRGControlDefenderCommonAttachments' 'DEF-2.3').State | Should -Be 'NotApplicable'
        }
    }

    Context 'INT-2.2 — Attack Surface Reduction rules (endpoint execution)' {

        It 'Satisfied when ASR policies are deployed' {
            Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (NewRaw3 'INT' @{
                ASRPolicies = @([pscustomobject]@{ DisplayName = 'ASR Baseline' })
            })
            (GetVerdict3 'Test-NRGControlIntuneASR' 'INT-2.2').State | Should -Be 'Satisfied'
        }

        It 'Gap when no ASR policy exists (Office macro and credential-theft vectors open)' {
            Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (NewRaw3 'INT' @{ ASRPolicies = @() })
            (GetVerdict3 'Test-NRGControlIntuneASR' 'INT-2.2').State | Should -Be 'Gap'
        }
    }

    Context 'EXO-7.2 — Attacker inbox rules forwarding externally (persistence/exfil)' {

        It 'Satisfied when no inbox rule forwards mail outside the tenant' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{ InboxRulesForwarding = @() })
            (GetVerdict3 'Test-NRGControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'Satisfied'
        }

        It 'Gap naming the mailbox and rule when external forwarding is found' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                InboxRulesForwarding = @(
                    [pscustomobject]@{ IsExternal = $true; Mailbox = 'cfo@contoso.com'
                                       RuleName = '.'; ExternalRecipients = @('attacker@evil.tld') }
                )
            })
            $v = GetVerdict3 'Test-NRGControlEXOInboxRulesForwarding' 'EXO-7.2'
            $v.State | Should -Be 'Gap'
            @($v.AffectedObjects).Count | Should -BeGreaterThan 0 `
                -Because 'this finding is only actionable during an incident if it names the mailbox, the rule and the destination'
            ($v.AffectedObjects | ConvertTo-Json -Depth 4) | Should -Match 'attacker@evil\.tld'
        }

        It 'reports NotApplicable — never Satisfied — when the inbox rule sweep FAILED' {
            # Regression guard. The collector defaults every list to @() and gives
            # each query its own try/catch, so a throttled per-mailbox sweep still
            # leaves Success = $true with an empty list. Before SectionStatus this
            # rendered as "No inbox rules forward mail externally" — a false
            # all-clear on the primary BEC persistence check.
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                InboxRulesForwarding = @()
                SectionStatus        = @{ InboxRulesForwarding = 'Failed' }
            })
            (GetVerdict3 'Test-NRGControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'NotApplicable' `
                -Because 'a failed scan is not evidence of a clean tenant — claiming otherwise is the exact false assurance this tool exists to avoid'
        }

        It 'still reports Satisfied when the sweep COMPLETED and genuinely found nothing' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                InboxRulesForwarding = @()
                SectionStatus        = @{ InboxRulesForwarding = 'Collected' }
            })
            (GetVerdict3 'Test-NRGControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'Satisfied' `
                -Because 'the fix must not turn every genuinely clean tenant into NotApplicable'
        }

        It 'ignores internal-only forwarding rules (no false positive)' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                InboxRulesForwarding = @(
                    [pscustomobject]@{ IsExternal = $false; Mailbox = 'sales@contoso.com'
                                       RuleName = 'To team'; ExternalRecipients = @() }
                )
            })
            (GetVerdict3 'Test-NRGControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'Satisfied' `
                -Because 'internal forwarding is normal business behavior — flagging it would bury the real attacker rule in noise'
        }

        It 'refuses to claim clean when Exchange could not interpret some rules' {
            # Exchange WARNS rather than throws on a rule whose actions it
            # cannot parse, and returns it with empty action properties. The
            # sweep succeeded and the external list is empty — every
            # SectionStatus guard passes — but these are rules nobody read.
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                InboxRulesForwarding = @()
                UnparseableRules     = @(
                    [pscustomobject]@{ Mailbox = 'cfo@contoso.com'; Warning = 'The rule "." contains errors.' }
                )
                SectionStatus        = @{ InboxRulesForwarding = 'Collected' }
            })
            (GetVerdict3 'Test-NRGControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'NotApplicable' `
                -Because 'a rule the tool could not read is not a rule that forwards nowhere'
        }

        It 'refuses to claim clean when a rule recipient could not be resolved' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                InboxRulesForwarding = @(
                    [pscustomobject]@{ IsExternal = $false; IsUnresolved = $true
                                       Mailbox = 'ops@contoso.com'; RuleName = 'Legacy'
                                       ExternalRecipients = @(); UnresolvedRecipients = @('"X" [EX:/o=x/cn=y]') }
                )
                SectionStatus        = @{ InboxRulesForwarding = 'Collected' }
            })
            (GetVerdict3 'Test-NRGControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'NotApplicable'
        }

        It 'survives result JSON written before UnparseableRules existed' {
            # Replay compatibility. Under StrictMode a missing property throws,
            # so reading these fields by dot-access would make every older
            # results file un-replayable.
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                InboxRulesForwarding = @(
                    [pscustomobject]@{ IsExternal = $false; Mailbox = 'a@contoso.com'
                                       RuleName = 'Old'; ExternalRecipients = @() }
                )
                SectionStatus        = @{ InboxRulesForwarding = 'Collected' }
            })
            (GetVerdict3 'Test-NRGControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'Satisfied'
        }
    }

    Context 'EXO-6.1 / EXO-7.1 — mailbox forwarding is scored on the EXTERNAL subset' {

        # The regression: both evaluators read ForwardingMailboxes unfiltered
        # and reported the total as "forwarding externally", while the
        # collector had already classified every row. A tenant whose only
        # forwarding is internal delegation got a Critical Gap it had not
        # earned — and the pattern was already applied correctly in EXO-7.2
        # thirty lines away.

        It 'EXO-6.1 Satisfied when every forwarding target is inside the tenant' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                ForwardingMailboxes = @(
                    [pscustomobject]@{ IsExternal = $false; Classification = 'Internal'
                                       DisplayName = 'Reception'; UPN = 'front@contoso.com'
                                       ForwardingAddress = 'smtp:ops@contoso.com'
                                       ForwardingMechanism = 'ForwardingSmtpAddress'
                                       DeliverToMailboxAndForward = $true }
                )
                SectionStatus = @{ ForwardingMailboxes = 'Collected' }
            })
            (GetVerdict3 'Test-NRGControlInventoryExternalForwarding' 'EXO-6.1').State | Should -Be 'Satisfied' `
                -Because 'internal forwarding is a delegation pattern, not exfiltration — scoring it as a Critical gap is a false positive on a correctly configured tenant'
        }

        It 'EXO-7.1 Satisfied when every forwarding target is inside the tenant' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                ForwardingMailboxes = @(
                    [pscustomobject]@{ IsExternal = $false; Classification = 'Internal'
                                       DisplayName = 'Reception'; UPN = 'front@contoso.com'
                                       ForwardingAddress = 'smtp:ops@contoso.com'
                                       ForwardingMechanism = 'ForwardingSmtpAddress'
                                       DeliverToMailboxAndForward = $true }
                )
                SectionStatus = @{ ForwardingMailboxes = 'Collected' }
            })
            (GetVerdict3 'Test-NRGControlEXOMailboxForwarding' 'EXO-7.1').State | Should -Be 'Satisfied'
        }

        It 'EXO-6.1 Gap — and counts mailboxes, not forwarding rows — when a target is external' {
            # One mailbox carrying BOTH properties produces two rows. Counting
            # rows would report two mailboxes exfiltrating when there is one.
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                ForwardingMailboxes = @(
                    [pscustomobject]@{ IsExternal = $true; Classification = 'External'
                                       DisplayName = 'CFO'; UPN = 'cfo@contoso.com'
                                       ForwardingAddress = 'smtp:attacker@evil.tld'
                                       ForwardingMechanism = 'ForwardingSmtpAddress'
                                       DeliverToMailboxAndForward = $false }
                    [pscustomobject]@{ IsExternal = $true; Classification = 'External'
                                       DisplayName = 'CFO'; UPN = 'cfo@contoso.com'
                                       ForwardingAddress = 'Outside Contact'
                                       ForwardingMechanism = 'ForwardingAddress'
                                       DeliverToMailboxAndForward = $false }
                )
                SectionStatus = @{ ForwardingMailboxes = 'Collected' }
            })
            $v = GetVerdict3 'Test-NRGControlInventoryExternalForwarding' 'EXO-6.1'
            $v.State | Should -Be 'Gap'
            $v.CurrentValue | Should -Match '^1 mailbox'
            ($v.AffectedObjects | ConvertTo-Json -Depth 4) | Should -Match 'ForwardingAddress' `
                -Because 'the finding must name which mechanism carries the forward, or the remediation misses one of them'
        }

        It 'EXO-6.1 NotApplicable when a forwarding target could not be classified' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                ForwardingMailboxes = @(
                    [pscustomobject]@{ IsExternal = $false; Classification = 'Unresolved'
                                       DisplayName = 'Ops'; UPN = 'ops@contoso.com'
                                       ForwardingAddress = 'Legacy Contact'
                                       ForwardingMechanism = 'ForwardingAddress'
                                       DeliverToMailboxAndForward = $false }
                )
                SectionStatus = @{ ForwardingMailboxes = 'Collected' }
            })
            (GetVerdict3 'Test-NRGControlInventoryExternalForwarding' 'EXO-6.1').State | Should -Be 'NotApplicable' `
                -Because 'a target we could not resolve is not evidence of internal forwarding'
        }

        It 'both survive result JSON written before Classification existed' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                ForwardingMailboxes = @(
                    [pscustomobject]@{ IsExternal = $true; DisplayName = 'CFO'; UPN = 'cfo@contoso.com'
                                       ForwardingAddress = 'smtp:attacker@evil.tld'
                                       DeliverToMailboxAndForward = $false }
                )
                SectionStatus = @{ ForwardingMailboxes = 'Collected' }
            })
            (GetVerdict3 'Test-NRGControlInventoryExternalForwarding' 'EXO-6.1').State | Should -Be 'Gap'
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-Inventory' -Data (NewRaw3 'EXO' @{
                ForwardingMailboxes = @(
                    [pscustomobject]@{ IsExternal = $true; DisplayName = 'CFO'; UPN = 'cfo@contoso.com'
                                       ForwardingAddress = 'smtp:attacker@evil.tld'
                                       DeliverToMailboxAndForward = $false }
                )
                SectionStatus = @{ ForwardingMailboxes = 'Collected' }
            })
            (GetVerdict3 'Test-NRGControlEXOMailboxForwarding' 'EXO-7.1').State | Should -Be 'Gap'
        }
    }
}

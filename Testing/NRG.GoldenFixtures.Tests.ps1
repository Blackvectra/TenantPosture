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
                [string]   $AuthStrengthId  = ''
            )
            [pscustomobject]@{
                DisplayName = $DisplayName
                State       = $State
                Conditions  = [pscustomobject]@{
                    ClientAppTypes = $ClientAppTypes
                    Users          = [pscustomobject]@{ IncludeRoles = $IncludeRoles }
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

        It 'Gap when no policy targets privileged roles at all' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (NewRaw 'AAD' @{
                Policies = @( NewCaPolicy -DisplayName 'All users MFA' -State 'enabled' -BuiltInControls @('mfa') )
            })
            (GetVerdict 'Test-NRGControlAADPhishResistantMFA' 'AAD-1.3').State | Should -Be 'Gap'
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
                -Because 'internal forwarding is normal business behaviour — flagging it would bury the real attacker rule in noise'
        }
    }
}

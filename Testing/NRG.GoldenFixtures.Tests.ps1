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

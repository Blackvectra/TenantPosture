#Requires -Version 7.0
#
# TP.CisV7Thresholds.Tests.ps1
#
# Dependencies: TenantPosture.psm1 (evaluators, Set-TPRawData, Get-TPFindings)
# TenantPosture
# Author: Matthew Levorson
# Purpose: Pin the eight evaluators tightened on 2026-10-25 so each cites a CIS
#          Microsoft 365 Foundations v7.0.0 recommendation honestly: every state
#          the evaluator scores Satisfied must pass that recommendation's audit,
#          and a value the check needs that was not read is not assessed, never
#          a pass (docs/TP-CIS-M365-ALIGNMENT.md).
#
# Consumes: AAD-Users, EXO-MailboxConfig, Defender-Policies, SharePoint, Purview
#           (fixtures in the collectors' stored shapes).
# Sets:     nothing.

Describe 'Evaluators tightened to CIS Microsoft 365 Foundations v7.0.0' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        function script:Bag([hashtable] $Data) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-25T00:00:00Z'; Success = $true; Data = $Data } }
        function script:Verdict([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0] }
        $script:Controls = (Get-Content (Join-Path $script:RepoRoot 'Config/controls.json') -Raw | ConvertFrom-Json).controls
    }

    Context 'Each tightened control cites its recommendation' {
        It '<Cid> cites CIS <Rec>' -TestCases @(
            @{ Cid = 'DEF-1.5'; Rec = '2.1.7' }, @{ Cid = 'AAD-12.1'; Rec = '5.2.3.4' }, @{ Cid = 'EXO-1.4'; Rec = '2.1.9' },
            @{ Cid = 'SPO-1.4'; Rec = '7.2.9' }, @{ Cid = 'SPO-3.4'; Rec = '7.2.9' }, @{ Cid = 'SPO-2.6'; Rec = '7.2.10' },
            @{ Cid = 'SPO-2.7'; Rec = '7.2.10' }, @{ Cid = 'PVW-1.3'; Rec = '3.2.1' }) {
            param($Cid, $Rec)
            ($script:Controls | Where-Object ControlId -eq $Cid).References.CIS | Should -Be $Rec
        }
    }

    Context 'DEF-1.5 requires phishing threshold 3 (2.1.7)' {
        BeforeAll {
            function script:Phish([int] $Level) {
                Clear-TPState
                Set-TPRawData -Key 'Defender-Policies' -Data (Bag @{
                    AntiPhishing = @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Office365 AntiPhish Default'; IsDefault = $true; PhishThresholdLevel = $Level }) }
                    PresetRules  = @{ Available = $true; EOP = @(); ATP = @() } })
                Verdict 'Test-TPControlDefender' 'DEF-1.5'
            }
        }
        It 'threshold 2 (Aggressive) no longer passes' { (Phish 2).State | Should -Not -Be 'Satisfied' }
        It 'threshold 3 (More aggressive) passes'       { (Phish 3).State | Should -Be 'Satisfied' }
        It 'threshold 4 (Most aggressive) passes'       { (Phish 4).State | Should -Be 'Satisfied' }
    }

    Context 'AAD-12.1 judges MFA capable, not registered (5.2.3.4)' {
        BeforeAll {
            function script:Mfa([object[]] $Reg) {
                Clear-TPState
                $users = @($Reg | ForEach-Object { @{ UserPrincipalName = $_.UserPrincipalName; DisplayName = $_.UserPrincipalName; AccountEnabled = $true; UserType = 'Member' } })
                Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $users; MFARegistration = @{ RegistrationDetails = $Reg } })
                Verdict 'Test-TPControlInventoryMFAUsers' 'AAD-12.1'
            }
        }
        It 'every member capable passes' {
            (Mfa @(@{ UserPrincipalName = 'a@corp.example'; IsMfaRegistered = $true; IsMfaCapable = $true })).State | Should -Be 'Satisfied'
        }
        It 'a user registered with a method the policy does not allow is listed, not passed' {
            $f = Mfa @(@{ UserPrincipalName = 'a@corp.example'; IsMfaRegistered = $true; IsMfaCapable = $true },
                       @{ UserPrincipalName = 'b@corp.example'; IsMfaRegistered = $true; IsMfaCapable = $false })
            $f.State | Should -Be 'Gap'
            @($f.AffectedObjects) -join ' ' | Should -Match 'b@corp\.example'
        }
        It 'a results file without isMfaCapable is not assessed, never a pass' {
            $f = Mfa @(@{ UserPrincipalName = 'a@corp.example'; IsMfaRegistered = $true })
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'not recorded'
            $f.FrameworkIds -join ' ' | Should -Match 'CIS:5\.2\.3\.4'
        }
        It 'an unregistered user is still a Gap in an older results file' {
            (Mfa @(@{ UserPrincipalName = 'a@corp.example'; IsMfaRegistered = $false })).State | Should -Be 'Gap'
        }
    }

    Context 'EXO-1.4 requires DKIM signing (Status Valid) on every accepted domain (2.1.9)' {
        BeforeAll {
            function script:Dkim([object[]] $Cfg, [object[]] $Domains = @(@{ DomainName = 'contoso.com'; DomainType = 'Authoritative' })) {
                Clear-TPState
                Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ DkimSigningConfigs = $Cfg; AcceptedDomains = $Domains
                    SectionStatus = @{ DkimSigningConfigs = 'Collected'; AcceptedDomains = 'Collected' } })
                Verdict 'Test-TPControlEXODKIM' 'EXO-1.4'
            }
        }
        It 'enabled and Valid passes' {
            (Dkim @(@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'; Selector1KeySize = 2048 })).State | Should -Be 'Satisfied'
        }
        It 'enabled but not signing (CnameMissing) is not signing' {
            $f = Dkim @(@{ Domain = 'contoso.com'; Enabled = $true; Status = 'CnameMissing'; Selector1KeySize = 2048 })
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'CnameMissing'
        }
        It 'an enabled configuration whose Status was not recorded is not assessed' {
            (Dkim @(@{ Domain = 'contoso.com'; Enabled = $true; Selector1KeySize = 2048 })).State | Should -Be 'NotApplicable'
        }
        It 'a relay domain is judged as well' {
            $f = Dkim @(@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'; Selector1KeySize = 2048 }) `
                      @(@{ DomainName = 'contoso.com'; DomainType = 'Authoritative' }, @{ DomainName = 'relay.contoso.com'; DomainType = 'InternalRelay' })
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'relay\.contoso\.com'
        }
    }

    Context 'SharePoint guest expiry 30 days (7.2.9) and re-verification 15 days (7.2.10)' {
        BeforeAll {
            function script:Spo([string] $Fn, [string] $Cid, [hashtable] $Shell) {
                Clear-TPState
                $ts = @{ SharingCapability = 'externalUserAndGuestSharing' }
                Set-TPRawData -Key 'SharePoint' -Data (Bag @{ TenantSettings = $ts; TenantSettingsSPO = $Shell; ExternalSharing = $ts.SharingCapability })
                Verdict $Fn $Cid
            }
        }
        It '<Cid> guest expiry: 30 days passes, 31 is part-way, off is a Gap' -TestCases @(
            @{ Cid = 'SPO-1.4'; Fn = 'Test-TPControlSharePoint' }, @{ Cid = 'SPO-3.4'; Fn = 'Test-TPControlSPOGuestExpiry' }) {
            param($Cid, $Fn)
            (Spo $Fn $Cid @{ ExternalUserExpirationRequired = $true;  ExternalUserExpireInDays = 30 }).State | Should -Be 'Satisfied'
            (Spo $Fn $Cid @{ ExternalUserExpirationRequired = $true;  ExternalUserExpireInDays = 31 }).State | Should -Be 'Partial'
            (Spo $Fn $Cid @{ ExternalUserExpirationRequired = $false; ExternalUserExpireInDays = 30 }).State | Should -Be 'Gap'
        }
        It '<Cid> re-verification: 15 days passes, 16 is part-way, attestation off is a Gap' -TestCases @(
            @{ Cid = 'SPO-2.6'; Fn = 'Test-TPControlSPOEmailAttestation' }, @{ Cid = 'SPO-2.7'; Fn = 'Test-TPControlSPOReauth' }) {
            param($Cid, $Fn)
            (Spo $Fn $Cid @{ EmailAttestationRequired = $true;  EmailAttestationReAuthDays = 15 }).State | Should -Be 'Satisfied'
            (Spo $Fn $Cid @{ EmailAttestationRequired = $true;  EmailAttestationReAuthDays = 16 }).State | Should -Be 'Partial'
            (Spo $Fn $Cid @{ EmailAttestationRequired = $false; EmailAttestationReAuthDays = 15 }).State | Should -Be 'Gap'
        }
    }

    Context 'PVW-1.3 counts DLP that reaches mail or files (3.2.1)' {
        BeforeAll {
            function script:Dlp([object[]] $Policies) {
                Clear-TPState
                Set-TPRawData -Key 'Purview' -Data (Bag @{ UnifiedAuditEnabled = $true; AuditConfig = @{ Source = 'ExchangeOnline' }; DLPPolicies = $Policies; AuditRetentionPolicies = @()
                    SectionStatus = @{ AuditConfig = 'Collected'; DLPPolicies = 'Collected'; AuditRetentionPolicies = 'Collected' } })
                Verdict 'Test-TPControlPurview' 'PVW-1.3'
            }
        }
        It 'an enforced Exchange policy passes' {
            (Dlp @(@{ Name = 'PII'; Enabled = $true; Mode = 'Enable'; Workloads = @('Exchange', 'EndpointDevices') })).State | Should -Be 'Satisfied'
        }
        It 'an enforced Endpoint-only policy does not protect mail or files' {
            $f = Dlp @(@{ Name = 'Devices'; Enabled = $true; Mode = 'Enable'; Workloads = @('EndpointDevices') })
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'EndpointDevices'
        }
        It 'an enforced policy whose workloads were not recorded is not assessed' {
            (Dlp @(@{ Name = 'Old'; Enabled = $true; Mode = 'Enable' })).State | Should -Be 'NotApplicable'
        }
    }
}

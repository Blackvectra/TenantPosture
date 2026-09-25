#Requires -Version 7.0
#
# NRG.EXOProtocolControls.Tests.ps1
#
# Proves the newly-implemented EXO legacy-protocol / outbound-spam controls
# (EXO-2.3 POP3, EXO-2.4 IMAP, EXO-3.2 outbound-spam notification) genuinely
# DISCRIMINATE: a secure config yields Satisfied and an insecure config yields
# Gap, driven by the real collector fields (CASMailboxPlans / OutboundSpamPolicies).
# The coverage honesty-gate confirms they discriminate statically; these tests
# confirm the branching is correct on real-shaped data.

Describe 'EXO protocol + outbound-spam controls discriminate' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function Set-EXO {
            param($CasPlans, $OutboundPolicies)
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data ([pscustomobject]@{
                CollectorId = 'x'; CollectedAt = 'n'; Success = $true
                # Existing mailboxes all have POP / IMAP off: the plans set the
                # default for NEW mailboxes only, so a verdict needs both.
                Data = @{ CASMailboxPlans = @($CasPlans); OutboundSpamPolicies = @($OutboundPolicies)
                          CASMailboxProtocols = @{ Total = 5; PopEnabledCount = 0; ImapEnabledCount = 0; PopSample = @(); ImapSample = @() } }
            })
        }
        function State($id) { (Get-NRGFindings | Where-Object { $_.ControlId -eq $id } | Select-Object -First 1).State }
    }

    It 'EXO-2.3 POP3: Satisfied when disabled on all plans, Gap when enabled on any' {
        Set-EXO -CasPlans @(@{ Name='ExchangeOnline'; PopEnabled=$false; ImapEnabled=$false }) -OutboundPolicies @()
        Test-NRGControlEXOPop3
        State 'EXO-2.3' | Should -Be 'Satisfied'

        Set-EXO -CasPlans @(@{ Name='ExchangeOnline'; PopEnabled=$true; ImapEnabled=$false }) -OutboundPolicies @()
        Test-NRGControlEXOPop3
        State 'EXO-2.3' | Should -Be 'Gap'
    }

    It 'EXO-2.4 IMAP: Satisfied when disabled on all plans, Gap when enabled on any' {
        Set-EXO -CasPlans @(@{ Name='ExchangeOnline'; PopEnabled=$false; ImapEnabled=$false }) -OutboundPolicies @()
        Test-NRGControlEXOImap
        State 'EXO-2.4' | Should -Be 'Satisfied'

        Set-EXO -CasPlans @(@{ Name='ExchangeOnlineEnterprise'; PopEnabled=$false; ImapEnabled=$true }) -OutboundPolicies @()
        Test-NRGControlEXOImap
        State 'EXO-2.4' | Should -Be 'Gap'
    }

    It 'EXO-2.3/2.4: NotApplicable when no CAS plan data collected' {
        Set-EXO -CasPlans @() -OutboundPolicies @()
        Test-NRGControlEXOPop3; Test-NRGControlEXOImap
        State 'EXO-2.3' | Should -Be 'NotApplicable'
        State 'EXO-2.4' | Should -Be 'NotApplicable'
    }

    It 'EXO-3.2 outbound spam: Satisfied when NotifyOutboundSpam on, Gap when off' {
        Set-EXO -CasPlans @() -OutboundPolicies @(@{ Name='Default'; IsDefault=$true; NotifyOutboundSpam=$true; ActionWhenThresholdReached='BlockUser' })
        Test-NRGControlEXOOutboundLimits
        State 'EXO-3.2' | Should -Be 'Satisfied'

        # NotifyOutboundSpam off is Microsoft's default: the notification now
        # comes from the "User restricted from sending email" alert policy.
        # Off, with the alert policy disabled, is the Gap.
        Set-EXO -CasPlans @() -OutboundPolicies @(@{ Name='Default'; IsDefault=$true; NotifyOutboundSpam=$false; ActionWhenThresholdReached='BlockUser' })
        Set-NRGRawData -Key 'Purview' -Data @{ Success = $true; Data = @{ SectionStatus = @{ ProtectionAlerts = 'Collected' }
            ProtectionAlerts = @(@{ Name = 'User restricted from sending email'; Disabled = $true; NotifyUser = @('TenantAdmins') }) } }
        Test-NRGControlEXOOutboundLimits
        State 'EXO-3.2' | Should -Be 'Gap'
    }

    It 'EXO-3.2: the enabled restricted-sender alert policy satisfies it; alerts unread is not assessed' {
        Set-EXO -CasPlans @() -OutboundPolicies @(@{ Name='Default'; IsDefault=$true; NotifyOutboundSpam=$false })
        Set-NRGRawData -Key 'Purview' -Data @{ Success = $true; Data = @{ SectionStatus = @{ ProtectionAlerts = 'Collected' }
            ProtectionAlerts = @(@{ Name = 'User restricted from sending email'; Disabled = $false; NotifyUser = @('TenantAdmins') }) } }
        Test-NRGControlEXOOutboundLimits
        State 'EXO-3.2' | Should -Be 'Satisfied'

        Set-EXO -CasPlans @() -OutboundPolicies @(@{ Name='Default'; IsDefault=$true; NotifyOutboundSpam=$false })
        Test-NRGControlEXOOutboundLimits
        State 'EXO-3.2' | Should -Be 'NotApplicable'
    }
}

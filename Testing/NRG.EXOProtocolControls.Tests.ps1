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
                Data = @{ CASMailboxPlans = @($CasPlans); OutboundSpamPolicies = @($OutboundPolicies) }
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

        Set-EXO -CasPlans @() -OutboundPolicies @(@{ Name='Default'; IsDefault=$true; NotifyOutboundSpam=$false; ActionWhenThresholdReached='BlockUser' })
        Test-NRGControlEXOOutboundLimits
        State 'EXO-3.2' | Should -Be 'Gap'
    }
}

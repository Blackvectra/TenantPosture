#Requires -Version 7.0
#
# TP.EXOProtocolControls.Tests.ps1
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
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        function Set-EXO {
            param($CasPlans, $OutboundPolicies)
            Clear-TPState
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data ([pscustomobject]@{
                CollectorId = 'x'; CollectedAt = 'n'; Success = $true
                # Existing mailboxes all have POP / IMAP off: the plans set the
                # default for NEW mailboxes only, so a verdict needs both.
                Data = @{ CASMailboxPlans = @($CasPlans); OutboundSpamPolicies = @($OutboundPolicies)
                          CASMailboxProtocols = @{ Total = 5; PopEnabledCount = 0; ImapEnabledCount = 0; PopSample = @(); ImapSample = @() } }
            })
        }
        function State($id) { (Get-TPFindings | Where-Object { $_.ControlId -eq $id } | Select-Object -First 1).State }
    }

    It 'EXO-2.3 POP3: Satisfied when disabled on all plans, Gap when enabled on any' {
        Set-EXO -CasPlans @(@{ Name='ExchangeOnline'; PopEnabled=$false; ImapEnabled=$false }) -OutboundPolicies @()
        Test-TPControlEXOPop3
        State 'EXO-2.3' | Should -Be 'Satisfied'

        Set-EXO -CasPlans @(@{ Name='ExchangeOnline'; PopEnabled=$true; ImapEnabled=$false }) -OutboundPolicies @()
        Test-TPControlEXOPop3
        State 'EXO-2.3' | Should -Be 'Gap'
    }

    It 'EXO-2.4 IMAP: Satisfied when disabled on all plans, Gap when enabled on any' {
        Set-EXO -CasPlans @(@{ Name='ExchangeOnline'; PopEnabled=$false; ImapEnabled=$false }) -OutboundPolicies @()
        Test-TPControlEXOImap
        State 'EXO-2.4' | Should -Be 'Satisfied'

        Set-EXO -CasPlans @(@{ Name='ExchangeOnlineEnterprise'; PopEnabled=$false; ImapEnabled=$true }) -OutboundPolicies @()
        Test-TPControlEXOImap
        State 'EXO-2.4' | Should -Be 'Gap'
    }

    It 'EXO-2.3/2.4: NotApplicable when no CAS plan data collected' {
        Set-EXO -CasPlans @() -OutboundPolicies @()
        Test-TPControlEXOPop3; Test-TPControlEXOImap
        State 'EXO-2.3' | Should -Be 'NotApplicable'
        State 'EXO-2.4' | Should -Be 'NotApplicable'
    }

    It 'EXO-3.2 outbound spam: Satisfied on Microsoft''s Standard sending limits, Gap on the shipped defaults' {
        Set-EXO -CasPlans @() -OutboundPolicies @(@{ Name='Default'; IsDefault=$true; NotifyOutboundSpam=$false; ActionWhenThresholdReached='BlockUser'
            RecipientLimitExternalPerHour=500; RecipientLimitInternalPerHour=1000; RecipientLimitPerDay=1000 })
        Test-TPControlEXOOutboundLimits
        State 'EXO-3.2' | Should -Be 'Satisfied'

        # 0 is "use the service default" and BlockUserForToday the default action: not configured.
        # NotifyOutboundSpam on does not change that; it is context, not the verdict.
        Set-EXO -CasPlans @() -OutboundPolicies @(@{ Name='Default'; IsDefault=$true; NotifyOutboundSpam=$true; NotifyOutboundSpamRecipients=@('admin@contoso.com')
            ActionWhenThresholdReached='BlockUserForToday'; RecipientLimitExternalPerHour=0; RecipientLimitInternalPerHour=0; RecipientLimitPerDay=0 })
        Test-TPControlEXOOutboundLimits
        State 'EXO-3.2' | Should -Be 'Gap'
    }
}

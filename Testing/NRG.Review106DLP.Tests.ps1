#Requires -Version 7.0
#
# NRG.Review106DLP.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Regression tests for review #106 (DLP and preset scope verdicts):
#   D1  a failed DLP policy read (or a rule whose parent policy is unknown) left every
#       rule Unknown, nothing counted as enforcing, and DEF-4.2 / PVW-3.4 reported a Gap.
#       Enforcement is unknown, so the controls are not assessed.
#   D2  DEF-4.1 put "Not counted (not enforcing)" among the VERIFIED components, so a
#       tenant whose only DLP policy is in test mode scored Partial instead of Gap.
#   D3  DEF-2.1 counted "the accepted domains were not read" as a shortfall, so a preset
#       scoped by domain scored Partial when nothing had been shown to fall short.
#
# Data consumed: Purview (DLPPolicies, DLPRules, SectionStatus), Defender-Policies
# (PresetRules), EXO-MailboxConfig (AcceptedDomains).  Graph scopes / cmdlets: none.

Describe 'Review 106: DLP and preset scope verdicts' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        function script:Bag([hashtable] $Data) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-04T00:00:00Z'; Success = $true; Data = $Data } }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-NRGFindings | Where-Object ControlId -eq $Cid)[0] }
        $script:AllWl = @('Exchange', 'SharePoint', 'OneDriveForBusiness', 'Teams')
        $script:CardRule = @{ Name = 'Card rule'; ParentPolicyName = 'Financial'; Disabled = $false; BlockAccess = $true; SensitiveInfoTypes = @('Credit Card Number') }
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    Context 'D1: a DLP rule whose policy mode is unknown is never a Gap' {
        It 'DLPPolicies Failed and DLPRules Collected: DEF-4.2 and PVW-3.4 are not assessed' {
            Clear-NRGState
            Set-NRGRawData -Key 'Purview' -Data (Bag @{ DLPPolicies = @(); DLPRules = @($script:CardRule); SectionStatus = @{ DLPPolicies = 'Failed'; DLPRules = 'Collected' } })
            $a = V 'Test-NRGControlDefenderDLPSITs' 'DEF-4.2'
            $b = V 'Test-NRGControlPurviewSensitiveInfoTypes' 'PVW-3.4'
            $a.State | Should -Be 'NotApplicable' -Because "the policy read failed, so whether the rule is enforcing is unknown (got: $($a.Detail))"
            $b.State | Should -Be 'NotApplicable' -Because "the policy read failed, so whether the rule is enforcing is unknown (got: $($b.Detail))"
            $a.Detail | Should -Match 'not assessed'
            $b.Detail | Should -Match 'not assessed'
        }
        It 'policies collected but the rule''s parent is not among them: not assessed, never a Gap' {
            Clear-NRGState
            Set-NRGRawData -Key 'Purview' -Data (Bag @{ DLPPolicies = @(@{ Name = 'Other'; Mode = 'Enable'; Workloads = $script:AllWl }); DLPRules = @($script:CardRule)
                                                        SectionStatus = @{ DLPPolicies = 'Collected'; DLPRules = 'Collected' } })
            (V 'Test-NRGControlDefenderDLPSITs' 'DEF-4.2').State | Should -Be 'NotApplicable'
            (V 'Test-NRGControlPurviewSensitiveInfoTypes' 'PVW-3.4').State | Should -Be 'NotApplicable'
        }
        It 'a real Gap is still a Gap: the parent policy was read and is enforcing, the rule matches no type' {
            Clear-NRGState
            Set-NRGRawData -Key 'Purview' -Data (Bag @{ DLPPolicies = @(@{ Name = 'Financial'; Mode = 'Enable'; Workloads = $script:AllWl })
                                                        DLPRules = @(@{ Name = 'No types'; ParentPolicyName = 'Financial'; Disabled = $false; SensitiveInfoTypes = @() })
                                                        SectionStatus = @{ DLPPolicies = 'Collected'; DLPRules = 'Collected' } })
            (V 'Test-NRGControlDefenderDLPSITs' 'DEF-4.2').State | Should -Be 'Gap'
            (V 'Test-NRGControlPurviewSensitiveInfoTypes' 'PVW-3.4').State | Should -Be 'Gap'
        }
    }

    Context 'D2: a DLP policy in test mode is reported, never credited' {
        It 'DEF-4.1: the only policy in TestWithNotifications covering all four workloads is a Gap, with the note kept' {
            Clear-NRGState
            Set-NRGRawData -Key 'Purview' -Data (Bag @{ DLPPolicies = @(@{ Name = 'P1'; Mode = 'TestWithNotifications'; Enabled = $false; Workloads = $script:AllWl }); DLPRules = @()
                                                        SectionStatus = @{ DLPPolicies = 'Collected'; DLPRules = 'Collected' } })
            $v = V 'Test-NRGControlDefenderDLPWorkloads' 'DEF-4.1'
            $v.State | Should -Be 'Gap' -Because "nothing enforces (got: $($v.Detail))"
            $v.Detail | Should -Match 'Not counted \(not enforcing\): P1 \[TestWithNotifications\]'
            $v.Detail | Should -Not -Match 'Verified:'
        }
        It 'DEF-4.1: an enforcing policy that covers none of the required workloads is a Gap' {
            Clear-NRGState
            Set-NRGRawData -Key 'Purview' -Data (Bag @{ DLPPolicies = @(@{ Name = 'Devices'; Mode = 'Enable'; Enabled = $true; Workloads = @('EndpointDevices') }); DLPRules = @()
                                                        SectionStatus = @{ DLPPolicies = 'Collected'; DLPRules = 'Collected' } })
            (V 'Test-NRGControlDefenderDLPWorkloads' 'DEF-4.1').State | Should -Be 'Gap'
        }
        It 'DEF-4.1: an enforcing policy covering part of the workloads beside a test-mode one stays Partial, note kept' {
            Clear-NRGState
            Set-NRGRawData -Key 'Purview' -Data (Bag @{ DLPPolicies = @(@{ Name = 'PII'; Mode = 'Enable'; Enabled = $true; Workloads = @('Exchange') },
                                                                        @{ Name = 'P1'; Mode = 'TestWithoutNotifications'; Enabled = $false; Workloads = $script:AllWl }); DLPRules = @()
                                                        SectionStatus = @{ DLPPolicies = 'Collected'; DLPRules = 'Collected' } })
            $v = V 'Test-NRGControlDefenderDLPWorkloads' 'DEF-4.1'
            $v.State | Should -Be 'Partial'
            $v.Detail | Should -Match 'Not counted \(not enforcing\): P1 \[TestWithoutNotifications\]'
        }
    }

    Context 'D3: unread accepted domains leave preset scope not assessed, not short' {
        BeforeAll {
            $script:Preset = { param([hashtable] $Rule)
                Clear-NRGState
                Set-NRGRawData -Key 'Defender-Policies' -Data (Bag @{ PresetRules = @{ Available = $true; ATP = @(); EOP = @($Rule) } })
            }
            $script:DomRule = @{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @('contoso.com'); SentTo = @(); SentToMemberOf = @()
                                 ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @(); HasExceptions = $false }
        }
        It 'a preset scoped by domain with AcceptedDomains not read is NotApplicable' {
            & $script:Preset $script:DomRule
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ AcceptedDomains = @(); SectionStatus = @{ AcceptedDomains = 'Failed' } })
            $v = V 'Test-NRGControlDefenderPresetPolicies' 'DEF-2.1'
            $v.State | Should -Be 'NotApplicable' -Because "who the preset covers was not established (got: $($v.Detail))"
            $v.Detail | Should -Match 'Not assessed: .*accepted domains were not read'
            $v.Detail | Should -Not -Match 'Shortfall:'
        }
        It 'with the accepted domains read and covered, the same preset is Satisfied' {
            & $script:Preset $script:DomRule
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ AcceptedDomains = @(@{ DomainName = 'contoso.com' }); SectionStatus = @{ AcceptedDomains = 'Collected' } })
            (V 'Test-NRGControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'Satisfied'
        }
        It 'a real shortfall (a missing accepted domain) is still reported' {
            & $script:Preset $script:DomRule
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ AcceptedDomains = @(@{ DomainName = 'contoso.com' }, @{ DomainName = 'fabrikam.com' }); SectionStatus = @{ AcceptedDomains = 'Collected' } })
            $v = V 'Test-NRGControlDefenderPresetPolicies' 'DEF-2.1'
            $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'fabrikam.com'
        }
    }
}

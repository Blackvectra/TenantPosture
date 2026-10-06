#Requires -Version 7.0
#
# NRG.DefenderPurviewTruth.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Defender / Purview / Power Platform verdicts found false by audit:
#   - Defender judged the DEFAULT policy only (or "any" policy): the Built-in
#     protection Safe Links policy (click-through allowed, internal senders off)
#     was called hardened; a custom policy switched OFF by its own settings but
#     applied by an enabled rule was ignored; a preset covering everyone left
#     the default's values reported as the tenant's.
#   - DEF-2.1 matched policy NAMES ('Standard|Strict'), passing a custom policy
#     called "Standard users"; the preset is on only when its rule is Enabled.
#   - DEF-2.2 read the deprecated ZapEnabled (absent -> section threw).
#   - DEF-4.6 counted a scheduled, not-yet-run simulation; DEF-4.7 threw on an
#     absent EnableSafeLinksForO365.
#   - PPL-1.1 "Tenant Isolation Enabled" scored the ENVIRONMENT COUNT.
#   - PVW-2.1 read AdminAuditLogEnabled (always true), PVW-3.4 counted DLP
#     policies instead of rules with sensitive info types, PVW-1.4 counted
#     defined labels instead of published ones.
#   - PPL-3.1/3.2/3.5 scored gaps from Purview sections that never ran;
#     PPL-3.4 inferred "external publishing" from an app's publisher domain.

Describe 'Defender, Purview and Power Platform verdicts' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        function script:Bag([hashtable] $Data) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $true; Data = $Data } }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-NRGFindings | Where-Object ControlId -eq $Cid)[0] }
        $script:BuiltInSL = @{ Name = 'Built-In Protection Policy'; IsBuiltInProtection = $true; EnableSafeLinksForEmail = $true; EnableSafeLinksForOffice = $true
                               AllowClickThrough = $true; TrackClicks = $true; EnableForInternalSenders = $false; DisableUrlRewrite = $true }
        function script:Def([hashtable] $Extra) {
            $d = @{ SafeLinks = @{ Available = $true; Policies = @($script:BuiltInSL); Rules = @() }
                    SafeAttachments = @{ Available = $true; Policies = @(@{ Name = 'Built-In Protection Policy'; IsBuiltInProtection = $true; Enable = $true; Action = 'Block' }); Rules = @() }
                    AntiPhishing = @{ Available = $true; Policies = @(@{ Name = 'Office365 AntiPhish Default'; IsDefault = $true; PhishThresholdLevel = 1 }); Rules = @() }
                    PresetRules = @{ Available = $true; EOP = @(); ATP = @() } }
            foreach ($k in $Extra.Keys) { $d[$k] = $Extra[$k] }
            Clear-NRGState
            Set-NRGRawData -Key 'Defender-Policies' -Data (Bag $d)
        }
    }

    Context 'Defender evaluates the policies actually in force' {
        It 'the Built-in protection Safe Links policy is not "hardened"' {
            Def @{}
            (V 'Test-NRGControlDefender' 'DEF-1.2').State | Should -Be 'Gap'
        }
        It 'a custom Safe Attachments policy that is off, applied by an enabled rule, is not hidden by Built-in protection' {
            Def @{ SafeAttachments = @{ Available = $true
                Policies = @(@{ Name = 'Built-In Protection Policy'; IsBuiltInProtection = $true; Enable = $true; Action = 'Block' }, @{ Name = 'All staff'; Enable = $false; Action = 'Block' })
                Rules = @(@{ Name = 'All staff'; SafeAttachmentPolicy = 'All staff'; State = 'Enabled'; RecipientDomainIs = @('contoso.com'); HasExceptions = $false }) } }
            (V 'Test-NRGControlDefender' 'DEF-1.1').State | Should -Be 'Partial'
        }
        It 'a preset whose rule covers every accepted domain replaces the default policy' {
            Def @{ AntiPhishing = @{ Available = $true; Rules = @()
                    Policies = @(@{ Name = 'Office365 AntiPhish Default'; IsDefault = $true; PhishThresholdLevel = 1 },
                                 @{ Name = 'Strict Preset Security Policy1'; RecommendedPolicyType = 'Strict'; PhishThresholdLevel = 4 }) }
                   PresetRules = @{ Available = $true; ATP = @()
                    EOP = @(@{ Name = 'Strict Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @('contoso.com'); SentTo = @(); SentToMemberOf = @(); HasExceptions = $false }) } }
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ AcceptedDomains = @(@{ DomainName = 'contoso.com' }); SectionStatus = @{ AcceptedDomains = 'Collected' } })
            (V 'Test-NRGControlDefender' 'DEF-1.5').State | Should -Be 'Satisfied'
        }
        It 'DEF-2.1 needs an ENABLED preset rule, not a policy named "Standard"' {
            Def @{ AntiPhishing = @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Standard users - anti-phish' }) } }
            (V 'Test-NRGControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'Gap'
            Def @{ PresetRules = @{ Available = $true; ATP = @(); EOP = @(@{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @('contoso.com'); SentTo = @(); SentToMemberOf = @(); HasExceptions = $false }) } }
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ AcceptedDomains = @(@{ DomainName = 'contoso.com' }); SectionStatus = @{ AcceptedDomains = 'Collected' } })
            (V 'Test-NRGControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'Satisfied'
        }
        It 'DEF-4.7 reads EnableSafeLinksForOffice without throwing; DEF-4.6 does not count a scheduled simulation' {
            Def @{}
            (V 'Test-NRGControlDefenderSafeLinksOffice' 'DEF-4.7').State | Should -Be 'Satisfied'
            Def @{ AttackSimulations = @{ Available = $true; Count = 1; LaunchedCount = 0; ScheduledCount = 1 } }
            (V 'Test-NRGControlDefenderAttackSim' 'DEF-4.6').State | Should -Be 'Partial'
        }
        It 'DEF-2.2 reads SpamZapEnabled / PhishZapEnabled' {
            Clear-NRGState
            Set-NRGRawData -Key 'Defender-Policies' -Data (Bag @{ MalwareFilter = @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true }) } })
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $true; ZapEnabled = $null }); AntiSpamRules = @(); SectionStatus = @{ AntiSpamPolicies = 'Collected' } })
            (V 'Test-NRGControlDefenderZAP' 'DEF-2.2').State | Should -Be 'Satisfied'
        }
    }

    Context 'An empty rule list is not an unread one' {
        It 'Get-NRGRuleList keeps an empty list empty and an absent or null field null' {
            InModuleScope 'NRG-Assessment' {
                $e = Get-NRGRuleList -Item @{ Rules = @() } -Key 'Rules'
                $null -ne $e | Should -BeTrue
                @($e).Count | Should -Be 0
                Get-NRGRuleList -Item @{ Rules = $null } -Key 'Rules' | Should -BeNullOrEmpty
                $null -eq (Get-NRGRuleList -Item @{} -Key 'Rules') | Should -BeTrue
                @((Get-NRGRuleList -Item ([pscustomobject]@{ Rules = @(@{ Name = 'r' }) }) -Key 'Rules')).Count | Should -Be 1
            }
        }
        It 'DEF-2.2: a custom policy with no enabled rule applies to nobody and is not counted against the default in force' {
            Clear-NRGState
            Set-NRGRawData -Key 'Defender-Policies' -Data (Bag @{ MalwareFilter = @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true }) } })
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Bag @{
                AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $true },
                                     @{ Name = 'Unused weak'; IsDefault = $false; SpamZapEnabled = $false; PhishZapEnabled = $false })
                AntiSpamRules = @(); SectionStatus = @{ AntiSpamPolicies = 'Collected' } })
            (V 'Test-NRGControlDefenderZAP' 'DEF-2.2').State | Should -Be 'Satisfied'
        }
        It 'DEF-2.2: rules that could not be read (null) keep every custom policy, because it cannot be told which apply' {
            Clear-NRGState
            Set-NRGRawData -Key 'Defender-Policies' -Data (Bag @{ MalwareFilter = @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true }) } })
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Bag @{
                AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $true },
                                     @{ Name = 'Maybe weak'; IsDefault = $false; SpamZapEnabled = $false; PhishZapEnabled = $false })
                AntiSpamRules = $null; SectionStatus = @{ AntiSpamPolicies = 'Collected' } })
            (V 'Test-NRGControlDefenderZAP' 'DEF-2.2').State | Should -Be 'Partial'
        }
    }

    Context 'DEF-2.3 common attachments is judged over the policies in force' {
        It 'the filter on in a policy that applies to nobody does not satisfy it: the default policy in force lacks it' {
            Clear-NRGState
            Set-NRGRawData -Key 'Defender-Policies' -Data (Bag @{ MalwareFilter = @{ Available = $true; FileFilterEnabledCount = 1
                Policies = @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $false }, @{ Name = 'Unassigned strict'; IsDefault = $false; EnableFileFilter = $true })
                Rules = @() } })
            $v = V 'Test-NRGControlDefenderCommonAttachments' 'DEF-2.3'
            $v.State  | Should -Be 'Gap'
            $v.Detail | Should -Match 'filter is off in: Default'
        }
        It 'the default policy in force with the filter on is verified; with no approved blocked-type list it is not assessed, never Satisfied' {
            # Pins the 'no approved list' scenario: the shipped lists are approved, so the file is replaced for this test.
            Mock -ModuleName NRG-Assessment Get-NRGStandards { [ordered]@{ DmarcReportingAddresses = @(); CommonAttachmentFileTypes = @(); PriorityUsers = @(); RequiredConditionalAccessTemplates = @() } }
            Clear-NRGState
            Set-NRGRawData -Key 'Defender-Policies' -Data (Bag @{ MalwareFilter = @{ Available = $true; FileFilterEnabledCount = 1
                Policies = @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $true }); Rules = @() } })
            $v = V 'Test-NRGControlDefenderCommonAttachments' 'DEF-2.3'
            $v.State  | Should -Be 'NotApplicable'
            $v.Detail | Should -Match 'Verified: The common attachments filter is on'
        }
    }

    Context 'Purview' {
        BeforeAll {
            function script:Pvw([hashtable] $Data) {
                Clear-NRGState
                $base = @{ UnifiedAuditEnabled = $false; AuditConfig = @{ Source = 'ExchangeOnline'; AdminAuditLogEnabled = $true }; DLPPolicies = @(); DLPRules = @(); SensitivityLabels = @(); LabelPolicies = @()
                           SectionStatus = @{ AuditConfig = 'Collected'; DLPPolicies = 'Collected'; DLPRules = 'Collected'; SensitivityLabels = 'Collected'; LabelPolicies = 'Collected'; AuditRetentionPolicies = 'NotRun' } }
                foreach ($k in $Data.Keys) { $base[$k] = $Data[$k] }
                Set-NRGRawData -Key 'Purview' -Data (Bag $base)
            }
        }
        It 'PVW-2.1 follows the Unified Audit Log, not the always-on admin audit log' {
            Pvw @{}
            (V 'Test-NRGControlPurviewAuditSearch' 'PVW-2.1').State | Should -Be 'Gap'
        }
        It 'PVW-3.4 needs an enabled DLP RULE with sensitive info types' {
            Pvw @{ DLPPolicies = @(@{ Name = 'p'; Enabled = $true }); DLPRules = @(@{ Name = 'r'; Disabled = $false; SensitiveInfoTypes = @() }) }
            (V 'Test-NRGControlPurviewSensitiveInfoTypes' 'PVW-3.4').State | Should -Be 'Gap'
        }
        It 'PVW-1.4 needs a publishing policy, not just defined labels' {
            Pvw @{ SensitivityLabels = @(@{ Name = 'Confidential'; IsValid = $true }) }
            (V 'Test-NRGControlPurview' 'PVW-1.4').State | Should -Be 'Gap'
        }
    }

    Context 'Power Platform and Copilot' {
        It 'PPL-1.1 scores tenant isolation, not the number of environments' {
            Clear-NRGState
            Set-NRGRawData -Key 'PowerPlatform' -Data (Bag @{ Environments = @(@{ Name = 'Default' }); TenantIsolation = @{ IsDisabled = $true; Rules = @() }; SectionStatus = @{ Environments = 'Collected'; TenantIsolation = 'Collected' } })
            (V 'Test-NRGControlPowerPlatform' 'PPL-1.1').State | Should -Be 'Gap'
        }
        It 'PPL-3.1 is not a Gap when sensitivity labels were never read; PPL-3.4 is manual review' {
            Clear-NRGState
            Set-NRGRawData -Key 'M365Copilot' -Data (Bag @{ CopilotLicensedUserCount = 10; TotalUserCount = 50; LicensedSkus = @(@{ SkuId = 's' }); SensitivityLabelsEnabled = $false; SensitivityLabelCount = 0; AutoLabelPoliciesEnabled = $false; CopilotStudioBots = @() })
            (V 'Test-NRGControlAICopilotSensitivityLabels' 'PPL-3.1').State | Should -Be 'NotApplicable'
            $f = V 'Test-NRGControlAICopilotStudio' 'PPL-3.4'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'requires manual verification'
        }
    }
}

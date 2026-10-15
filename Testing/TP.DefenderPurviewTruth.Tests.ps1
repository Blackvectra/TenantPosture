#Requires -Version 7.0
#
# TP.DefenderPurviewTruth.Tests.ps1
# TenantPosture
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
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        function script:Bag([hashtable] $Data) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $true; Data = $Data } }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0] }
        $script:BuiltInSL = @{ Name = 'Built-In Protection Policy'; IsBuiltInProtection = $true; EnableSafeLinksForEmail = $true; EnableSafeLinksForOffice = $true
                               AllowClickThrough = $true; TrackClicks = $true; EnableForInternalSenders = $false; DisableUrlRewrite = $true }
        function script:Def([hashtable] $Extra) {
            $d = @{ SafeLinks = @{ Available = $true; Policies = @($script:BuiltInSL); Rules = @() }
                    SafeAttachments = @{ Available = $true; Policies = @(@{ Name = 'Built-In Protection Policy'; IsBuiltInProtection = $true; Enable = $true; Action = 'Block' }); Rules = @() }
                    AntiPhishing = @{ Available = $true; Policies = @(@{ Name = 'Office365 AntiPhish Default'; IsDefault = $true; PhishThresholdLevel = 1 }); Rules = @() }
                    PresetRules = @{ Available = $true; EOP = @(); ATP = @() } }
            foreach ($k in $Extra.Keys) { $d[$k] = $Extra[$k] }
            Clear-TPState
            Set-TPRawData -Key 'Defender-Policies' -Data (Bag $d)
        }
    }

    Context 'Defender evaluates the policies actually in force' {
        It 'the Built-in protection Safe Links policy is not "hardened"' {
            Def @{}
            (V 'Test-TPControlDefender' 'DEF-1.2').State | Should -Be 'Gap'
        }
        It 'a custom Safe Attachments policy that is off, applied by an enabled rule, is not hidden by Built-in protection' {
            Def @{ SafeAttachments = @{ Available = $true
                Policies = @(@{ Name = 'Built-In Protection Policy'; IsBuiltInProtection = $true; Enable = $true; Action = 'Block' }, @{ Name = 'All staff'; Enable = $false; Action = 'Block' })
                Rules = @(@{ Name = 'All staff'; SafeAttachmentPolicy = 'All staff'; State = 'Enabled'; RecipientDomainIs = @('contoso.com'); HasExceptions = $false }) } }
            (V 'Test-TPControlDefender' 'DEF-1.1').State | Should -Be 'Partial'
        }
        It 'a preset whose rule covers every accepted domain replaces the default policy' {
            Def @{ AntiPhishing = @{ Available = $true; Rules = @()
                    Policies = @(@{ Name = 'Office365 AntiPhish Default'; IsDefault = $true; PhishThresholdLevel = 1 },
                                 @{ Name = 'Strict Preset Security Policy1'; RecommendedPolicyType = 'Strict'; PhishThresholdLevel = 4 }) }
                   PresetRules = @{ Available = $true; ATP = @()
                    EOP = @(@{ Name = 'Strict Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @('contoso.com'); SentTo = @(); SentToMemberOf = @(); HasExceptions = $false }) } }
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ AcceptedDomains = @(@{ DomainName = 'contoso.com' }); SectionStatus = @{ AcceptedDomains = 'Collected' } })
            (V 'Test-TPControlDefender' 'DEF-1.5').State | Should -Be 'Satisfied'
        }
        It 'DEF-2.1 needs an ENABLED preset rule, not a policy named "Standard"' {
            Def @{ AntiPhishing = @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Standard users - anti-phish' }) } }
            (V 'Test-TPControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'Gap'
            Def @{ PresetRules = @{ Available = $true; ATP = @(); EOP = @(@{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @('contoso.com'); SentTo = @(); SentToMemberOf = @(); HasExceptions = $false }) } }
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ AcceptedDomains = @(@{ DomainName = 'contoso.com' }); SectionStatus = @{ AcceptedDomains = 'Collected' } })
            (V 'Test-TPControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'Satisfied'
        }
        It 'DEF-4.7 reads EnableSafeLinksForOffice without throwing; DEF-4.6 does not count a scheduled simulation' {
            Def @{}
            (V 'Test-TPControlDefenderSafeLinksOffice' 'DEF-4.7').State | Should -Be 'Satisfied'
            Def @{ AttackSimulations = @{ Available = $true; Count = 1; LaunchedCount = 0; ScheduledCount = 1 } }
            (V 'Test-TPControlDefenderAttackSim' 'DEF-4.6').State | Should -Be 'Partial'
        }
        It 'DEF-2.2 reads SpamZapEnabled / PhishZapEnabled' {
            Clear-TPState
            Set-TPRawData -Key 'Defender-Policies' -Data (Bag @{ MalwareFilter = @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true }) } })
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Bag @{ AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $true; ZapEnabled = $null }); AntiSpamRules = @(); SectionStatus = @{ AntiSpamPolicies = 'Collected' } })
            (V 'Test-TPControlDefenderZAP' 'DEF-2.2').State | Should -Be 'Satisfied'
        }
    }

    Context 'An empty rule list is not an unread one' {
        It 'Get-TPRuleList keeps an empty list empty and an absent or null field null' {
            InModuleScope 'TenantPosture' {
                $e = Get-TPRuleList -Item @{ Rules = @() } -Key 'Rules'
                $null -ne $e | Should -BeTrue
                @($e).Count | Should -Be 0
                Get-TPRuleList -Item @{ Rules = $null } -Key 'Rules' | Should -BeNullOrEmpty
                $null -eq (Get-TPRuleList -Item @{} -Key 'Rules') | Should -BeTrue
                @((Get-TPRuleList -Item ([pscustomobject]@{ Rules = @(@{ Name = 'r' }) }) -Key 'Rules')).Count | Should -Be 1
            }
        }
        It 'DEF-2.2: a custom policy with no enabled rule applies to nobody and is not counted against the default in force' {
            Clear-TPState
            Set-TPRawData -Key 'Defender-Policies' -Data (Bag @{ MalwareFilter = @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true }) } })
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Bag @{
                AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $true },
                                     @{ Name = 'Unused weak'; IsDefault = $false; SpamZapEnabled = $false; PhishZapEnabled = $false })
                AntiSpamRules = @(); SectionStatus = @{ AntiSpamPolicies = 'Collected' } })
            (V 'Test-TPControlDefenderZAP' 'DEF-2.2').State | Should -Be 'Satisfied'
        }
        It 'DEF-2.2: rules that could not be read (null) keep every custom policy, because it cannot be told which apply' {
            Clear-TPState
            Set-TPRawData -Key 'Defender-Policies' -Data (Bag @{ MalwareFilter = @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true }) } })
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Bag @{
                AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $true },
                                     @{ Name = 'Maybe weak'; IsDefault = $false; SpamZapEnabled = $false; PhishZapEnabled = $false })
                AntiSpamRules = $null; SectionStatus = @{ AntiSpamPolicies = 'Collected' } })
            (V 'Test-TPControlDefenderZAP' 'DEF-2.2').State | Should -Be 'Partial'
        }
    }

    Context 'DEF-2.3 common attachments is judged over the policies in force' {
        It 'the filter on in a policy that applies to nobody does not satisfy it: the default policy in force lacks it' {
            Clear-TPState
            Set-TPRawData -Key 'Defender-Policies' -Data (Bag @{ MalwareFilter = @{ Available = $true; FileFilterEnabledCount = 1
                Policies = @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $false }, @{ Name = 'Unassigned strict'; IsDefault = $false; EnableFileFilter = $true })
                Rules = @() } })
            $v = V 'Test-TPControlDefenderCommonAttachments' 'DEF-2.3'
            $v.State  | Should -Be 'Gap'
            $v.Detail | Should -Match 'filter is off in: Default'
        }
        It 'the default policy in force with the filter on is verified; with no approved blocked-type list it is not assessed, never Satisfied' {
            # Pins the 'no approved list' scenario: the shipped lists are approved, so the file is replaced for this test.
            Mock -ModuleName TenantPosture Get-TPStandards { [ordered]@{ DmarcReportingAddresses = @(); CommonAttachmentFileTypes = @(); PriorityUsers = @(); RequiredConditionalAccessTemplates = @() } }
            Clear-TPState
            Set-TPRawData -Key 'Defender-Policies' -Data (Bag @{ MalwareFilter = @{ Available = $true; FileFilterEnabledCount = 1
                Policies = @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $true }); Rules = @() } })
            $v = V 'Test-TPControlDefenderCommonAttachments' 'DEF-2.3'
            $v.State  | Should -Be 'NotApplicable'
            $v.Detail | Should -Match 'Verified: The common attachments filter is on'
        }
    }

    Context 'Purview' {
        BeforeAll {
            function script:Pvw([hashtable] $Data) {
                Clear-TPState
                $base = @{ UnifiedAuditEnabled = $false; AuditConfig = @{ Source = 'ExchangeOnline'; AdminAuditLogEnabled = $true }; DLPPolicies = @(); DLPRules = @(); SensitivityLabels = @(); LabelPolicies = @()
                           SectionStatus = @{ AuditConfig = 'Collected'; DLPPolicies = 'Collected'; DLPRules = 'Collected'; SensitivityLabels = 'Collected'; LabelPolicies = 'Collected'; AuditRetentionPolicies = 'NotRun' } }
                foreach ($k in $Data.Keys) { $base[$k] = $Data[$k] }
                Set-TPRawData -Key 'Purview' -Data (Bag $base)
            }
        }
        It 'PVW-2.1 follows the Unified Audit Log, not the always-on admin audit log' {
            Pvw @{}
            (V 'Test-TPControlPurviewAuditSearch' 'PVW-2.1').State | Should -Be 'Gap'
        }
        It 'PVW-3.4 needs an enabled DLP RULE with sensitive info types' {
            Pvw @{ DLPPolicies = @(@{ Name = 'p'; Enabled = $true }); DLPRules = @(@{ Name = 'r'; Disabled = $false; SensitiveInfoTypes = @() }) }
            (V 'Test-TPControlPurviewSensitiveInfoTypes' 'PVW-3.4').State | Should -Be 'Gap'
        }
        It 'PVW-1.4 needs a publishing policy, not just defined labels' {
            Pvw @{ SensitivityLabels = @(@{ Name = 'Confidential'; IsValid = $true }) }
            (V 'Test-TPControlPurview' 'PVW-1.4').State | Should -Be 'Gap'
        }
    }

    Context 'Power Platform and Copilot' {
        It 'PPL-1.1 scores tenant isolation, not the number of environments' {
            Clear-TPState
            Set-TPRawData -Key 'PowerPlatform' -Data (Bag @{ Environments = @(@{ Name = 'Default' }); TenantIsolation = @{ IsDisabled = $true; Rules = @() }; SectionStatus = @{ Environments = 'Collected'; TenantIsolation = 'Collected' } })
            (V 'Test-TPControlPowerPlatform' 'PPL-1.1').State | Should -Be 'Gap'
        }
        It 'PPL-3.1 is not a Gap when sensitivity labels were never read; PPL-3.4 is manual review' {
            Clear-TPState
            Set-TPRawData -Key 'M365Copilot' -Data (Bag @{ CopilotLicensedUserCount = 10; TotalUserCount = 50; LicensedSkus = @(@{ SkuId = 's' }); SensitivityLabelsEnabled = $false; SensitivityLabelCount = 0; AutoLabelPoliciesEnabled = $false; CopilotStudioBots = @() })
            (V 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').State | Should -Be 'NotApplicable'
            $f = V 'Test-TPControlAICopilotStudio' 'PPL-3.4'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'requires manual verification'
        }
    }
}

# ── PVW-4.1: Audit (Premium) is judged from licensing the tool already reads ──────────
# The evaluator read a key the collector never populated and emitted "requires manual
# verification" on every tenant, while the fact that decides the control (which
# subscription carries the Microsoft 365 Advanced Auditing service plan, and who is
# assigned it) sat in the same results file. Every case below feeds raw collector
# shapes: SubscribedSkus rows with their ServicePlans and user rows with AssignedSkuIds.
Describe 'PVW-4.1 judges Audit (Premium) from subscriptions and assignments' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        function script:Bag41([hashtable] $Data, [bool] $Success = $true) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-01T00:00:00Z'; Success = $Success; Data = $Data } }
        function script:V41([string] $Cid) { Test-TPControlPurviewAuditPremium 3>$null | Out-Null; @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0] }
        $script:E5 = @{ SkuPartNumber = 'SPE_E5'; SkuId = '06ebc4ee-1bb5-47dd-8e1b-7f71b5a2d2e3'; ServicePlans = @('EXCHANGE_S_ENTERPRISE', 'M365_ADVANCED_AUDITING', 'AAD_PREMIUM_P2') }
        $script:E3 = @{ SkuPartNumber = 'SPE_E3'; SkuId = '05e9a617-0261-4cee-bb44-138d3ef5d965'; ServicePlans = @('EXCHANGE_S_ENTERPRISE', 'AAD_PREMIUM') }
        function script:User([string] $Upn, [string[]] $Skus, [string] $Type = 'Member', [bool] $Enabled = $true, [switch] $NoSkuField) {
            $row = @{ UserPrincipalName = $Upn; DisplayName = $Upn; AccountEnabled = $Enabled; UserType = $Type; LicenseCount = @($Skus).Count }
            if (-not $NoSkuField) { $row['AssignedSkuIds'] = @($Skus) }
            $row
        }
        function script:Arrange {
            param([object[]] $Skus, [object[]] $Users, [object] $Ingestion = $true, [switch] $NoLicensing, [switch] $NoUsers)
            Clear-TPState
            Set-TPRawData -Key 'Purview' -Data (Bag41 @{ AuditConfig = @{ UnifiedAuditLogIngestionEnabled = $Ingestion; AdminAuditLogEnabled = $true }; SectionStatus = @{ AuditConfig = 'Collected' } })
            if (-not $NoLicensing) { Set-TPRawData -Key 'AAD-Inventory' -Data (Bag41 @{ SubscribedSkus = @($Skus) }) }
            if (-not $NoUsers) { Set-TPRawData -Key 'AAD-Users' -Data (Bag41 @{ Users = @($Users) }) }
        }
    }
    AfterAll { Clear-TPState }

    It 'no subscription with the Advanced Auditing plan is a Gap that names the subscriptions read (was: manual verification)' {
        Arrange -Skus @($script:E3) -Users @((User 'a@contoso.com' @($script:E3.SkuId)))
        $f = V41 'PVW-4.1'
        $f.State        | Should -Be 'Gap'
        $f.Detail       | Should -Match 'Advanced Auditing'
        $f.Detail       | Should -Match 'SPE_E3'
        $f.CurrentValue | Should -Be 'No subscription with the Audit (Premium) service plan'
        $f.Detail       | Should -Not -Match '(?i)manual verification'
    }
    It 'the plan on every licensed member user with the audit log on is Satisfied, naming the subscription' {
        Arrange -Skus @($script:E5, $script:E3) -Users @((User 'a@contoso.com' @($script:E5.SkuId)), (User 'b@contoso.com' @($script:E5.SkuId, $script:E3.SkuId)))
        $f = V41 'PVW-4.1'
        $f.State  | Should -Be 'Satisfied'
        $f.Detail | Should -Match 'SPE_E5'
        $f.Detail | Should -Match 'All 2 enabled, licensed member user'
        $f.Detail | Should -Match 'audit log is on'
    }
    It 'some licensed users without the plan is Partial, naming who gets Audit \(Standard\) only' {
        Arrange -Skus @($script:E5, $script:E3) -Users @((User 'a@contoso.com' @($script:E5.SkuId)), (User 'b@contoso.com' @($script:E5.SkuId)), (User 'c@contoso.com' @($script:E3.SkuId)))
        $f = V41 'PVW-4.1'
        $f.State  | Should -Be 'Partial'
        $f.Detail | Should -Match '2 of 3 enabled, licensed member users'
        $f.Detail | Should -Match 'c@contoso\.com'
        @($f.AffectedObjects) | Should -Be @('c@contoso.com')
    }
    It 'the plan held but assigned to no licensed user is a Gap, not Partial (licensed but not configured)' {
        Arrange -Skus @($script:E5, $script:E3) -Users @((User 'a@contoso.com' @($script:E3.SkuId)), (User 'b@contoso.com' @($script:E3.SkuId)))
        $f = V41 'PVW-4.1'
        $f.State  | Should -Be 'Gap'
        $f.Detail | Should -Match 'no enabled, licensed member user is assigned'
    }
    It 'guests, disabled accounts and unlicensed users are outside the population' {
        Arrange -Skus @($script:E5, $script:E3) -Users @(
            (User 'a@contoso.com' @($script:E5.SkuId)),
            (User 'guest_x#EXT#@contoso.com' @($script:E3.SkuId) -Type 'Guest'),
            (User 'old@contoso.com' @($script:E3.SkuId) -Enabled $false),
            (User 'shared@contoso.com' @()))
        (V41 'PVW-4.1').State | Should -Be 'Satisfied'
    }
    It 'a results file whose users carry no AssignedSkuIds is not assessed, with the licensing stated as verified' {
        Arrange -Skus @($script:E5) -Users @((User 'a@contoso.com' @($script:E5.SkuId) -NoSkuField))
        $f = V41 'PVW-4.1'
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'Verified: Audit \(Premium\) is licensed'
        $f.Detail | Should -Match 'Not assessed: which users hold'
    }
    It 'users not collected at all is not assessed the same way' {
        Arrange -Skus @($script:E5) -Users @() -NoUsers
        (V41 'PVW-4.1').State | Should -Be 'NotApplicable'
    }
    It 'subscriptions not read is not assessed, never a Gap' {
        Arrange -Skus @() -Users @((User 'a@contoso.com' @($script:E5.SkuId))) -NoLicensing
        $f = V41 'PVW-4.1'
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'not read'
    }
    It 'the audit log being off is a shortfall even with every user licensed' {
        Arrange -Skus @($script:E5) -Users @((User 'a@contoso.com' @($script:E5.SkuId))) -Ingestion $false
        $f = V41 'PVW-4.1'
        $f.State  | Should -Be 'Partial'
        $f.Detail | Should -Match 'audit log is off'
    }
    It 'an unlicensed tenant''s Gap is what license gating turns into an upgrade opportunity' {
        Arrange -Skus @($script:E3) -Users @((User 'a@contoso.com' @($script:E3.SkuId)))
        V41 'PVW-4.1' | Out-Null
        Set-TPLicenseGating | Out-Null
        $f = @(Get-TPFindings | Where-Object ControlId -eq 'PVW-4.1')[0]
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'upgrade opportunity'
    }
}

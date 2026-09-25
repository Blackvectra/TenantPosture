#Requires -Version 7.0
#
# NRG.ExchangeTruth.Tests.ps1
# NRG Technology Services / NextLayerSec LLC — Author: Matthew Levorson
# Pins the Exchange, Defender-for-Office and identity-inventory verdicts to
# what Microsoft documents each setting to mean. Every case here produced a
# wrong verdict before this change; each names the old one.
#
# Data keys: EXO-MailboxConfig, EXO-Inventory, Defender-Policies, Purview,
#            AAD-Inventory. Collector cases inject cmdlet stand-ins into
#            MODULE scope (Set-Item function:script:), as NRG.DnsCollector
#            does, and feed raw cmdlet shapes rather than derived fields.
#

Describe 'Exchange controls read the setting they name' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        function script:Raw { param([hashtable] $Data, [bool] $Success = $true) [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-01T00:00:00Z'; Success = $Success; Data = $Data } }
        function script:Verdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
        # Stand-ins for Exchange / Graph cmdlets the module does not define.
        # Module functions (Get-NRGExoCommand) are replaced with Pester's
        # Mock -ModuleName instead, which restores them after each test.
        function script:Inject { param([string] $Name, [string] $Body)
            & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } $Name $Body }
        function script:Remove { param([string] $Name)
            & $script:Mod { param($n) Remove-Item -Path "function:script:$n" -ErrorAction SilentlyContinue } $Name }

        $script:Accepted = @(@{ DomainName = 'contoso.com'; DomainType = 'Authoritative' })
    }
    BeforeEach { Clear-NRGState }
    AfterAll   { Clear-NRGState }

    Context 'EXO-1.2 SMTP AUTH' {
        It 'is not assessed when Get-TransportConfig was not read (was: Gap "enabled at the tenant level")' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ TransportConfig = $null
                SmtpAuthConfig = @{ TenantDisabled = $null; PerMailboxEnabledCount = 0; SampleEnabled = @() }
                SectionStatus = @{ TransportConfig = 'Failed'; SmtpAuthConfig = 'Collected' } })
            (Verdict 'Test-NRGControlEXOSmtpAuth' 'EXO-1.2').State | Should -Be 'NotApplicable'
        }
        It 'identifies per-mailbox exceptions by PrimarySmtpAddress: CASMailbox has no UserPrincipalName' {
            Inject 'Get-TransportConfig' '[pscustomobject]@{ SmtpClientAuthenticationDisabled = $true }'
            Inject 'Get-CASMailbox' '[pscustomobject]@{ Name = "scan1"; PrimarySmtpAddress = "scanner@contoso.com"; SmtpClientAuthenticationDisabled = $false }; [pscustomobject]@{ Name = "u"; PrimarySmtpAddress = "u@contoso.com"; SmtpClientAuthenticationDisabled = $null }'
            try {
                $r = Invoke-NRGCollectEXOMailboxConfig
                $r.Data.SectionStatus.SmtpAuthConfig | Should -Be 'Collected'
                $r.Data.SmtpAuthConfig.SampleEnabled | Should -Be @('scanner@contoso.com')
                (Verdict 'Test-NRGControlEXOSmtpAuth' 'EXO-1.2').State | Should -Be 'Partial'
            } finally { Remove 'Get-TransportConfig'; Remove 'Get-CASMailbox' }
        }
    }

    Context 'EXO-1.3 external auto-forwarding' {
        It 'a custom On policy with an enabled rule leaves its senders forwarding (was: Satisfied from the default alone)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{
                OutboundSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; AutoForwardingMode = 'Off' }, @{ Name = 'Finance forwarding'; IsDefault = $false; AutoForwardingMode = 'On' })
                OutboundSpamRules    = @(@{ Name = 'Finance'; HostedOutboundSpamFilterPolicy = 'Finance forwarding'; State = 'Enabled' })
                RemoteDomains        = @(@{ IsDefault = $true; DomainName = '*'; AutoForwardEnabled = $true })
                SectionStatus        = @{ OutboundSpamPolicies = 'Collected'; RemoteDomains = 'Collected' } })
            (Verdict 'Test-NRGControlEXOAutoForward' 'EXO-1.3').State | Should -Be 'Partial'
        }
        It 'the same custom policy with its rule disabled applies to no one' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{
                OutboundSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; AutoForwardingMode = 'Off' }, @{ Name = 'Finance forwarding'; IsDefault = $false; AutoForwardingMode = 'On' })
                OutboundSpamRules    = @(@{ Name = 'Finance'; HostedOutboundSpamFilterPolicy = 'Finance forwarding'; State = 'Disabled' })
                RemoteDomains        = @(@{ IsDefault = $true; DomainName = '*'; AutoForwardEnabled = $true })
                SectionStatus        = @{ OutboundSpamPolicies = 'Collected'; RemoteDomains = 'Collected' } })
            (Verdict 'Test-NRGControlEXOAutoForward' 'EXO-1.3').State | Should -Be 'Satisfied'
        }
        It 'Automatic is not counted as a block and the detail says why' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{
                OutboundSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; AutoForwardingMode = 'Automatic' })
                RemoteDomains        = @(@{ IsDefault = $true; DomainName = '*'; AutoForwardEnabled = $true })
                SectionStatus        = @{ OutboundSpamPolicies = 'Collected'; RemoteDomains = 'Collected' } })
            $f = Verdict 'Test-NRGControlEXOAutoForward' 'EXO-1.3'
            $f.State | Should -Be 'Gap'
            $f.Detail | Should -Match 'before 2021'
        }
    }

    Context 'EXO-1.4 DKIM' {
        It 'a custom domain with no DKIM configuration is unsigned (was: NotApplicable "no configuration found")' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ DkimSigningConfigs = @(); AcceptedDomains = $script:Accepted
                SectionStatus = @{ DkimSigningConfigs = 'Collected'; AcceptedDomains = 'Collected' } })
            (Verdict 'Test-NRGControlEXODKIM' 'EXO-1.4').State | Should -Be 'Gap'
        }
        It 'reads the documented Selector1KeySize / Selector2KeySize (was: Satisfied on 1024-bit keys)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ AcceptedDomains = $script:Accepted
                DkimSigningConfigs = @(@{ Domain = 'contoso.com'; Enabled = $true; Selector1KeySize = 1024; Selector2KeySize = 1024 })
                SectionStatus = @{ DkimSigningConfigs = 'Collected'; AcceptedDomains = 'Collected' } })
            (Verdict 'Test-NRGControlEXODKIM' 'EXO-1.4').State | Should -Be 'Partial'
        }
        It 'one 2048-bit selector beside a 1024-bit one is a rotation in progress, not a weakness' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ AcceptedDomains = $script:Accepted
                DkimSigningConfigs = @(@{ Domain = 'contoso.com'; Enabled = $true; Selector1KeySize = 1024; Selector2KeySize = 2048 })
                SectionStatus = @{ DkimSigningConfigs = 'Collected'; AcceptedDomains = 'Collected' } })
            (Verdict 'Test-NRGControlEXODKIM' 'EXO-1.4').State | Should -Be 'Satisfied'
        }
    }

    Context 'Audit: EXO-3.5, EXO-4.1, EXO-4.2 read the audit settings, not the mailbox audit switch' {
        BeforeEach {
            $script:Exo = @{ OrganizationConfig = @{ AuditDisabled = $false }
                AdminAuditLogConfig = @{ AdminAuditLogEnabled = $true; UnifiedAuditLogIngestionEnabled = $true }
                MailboxAuditSummary = @{ SampleMailboxAudit = @{ AuditLogAgeLimit = '90.00:00:00'; AllEnabled = $true; SampleCount = 1 } }
                SectionStatus = @{ OrganizationConfig = 'Collected'; AdminAuditLogConfig = 'Collected' } }
        }
        It 'EXO-3.5 is a Gap when Unified Audit Log ingestion is off (was: Satisfied from AuditDisabled = False)' {
            $script:Exo.AdminAuditLogConfig.UnifiedAuditLogIngestionEnabled = $false
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw $script:Exo)
            (Verdict 'Test-NRGControlEXOTransportAudit' 'EXO-3.5').State | Should -Be 'Gap'
        }
        It 'EXO-4.2 is a Gap when AdminAuditLogEnabled is False (was: Satisfied)' {
            $script:Exo.AdminAuditLogConfig.AdminAuditLogEnabled = $false
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw $script:Exo)
            (Verdict 'Test-NRGControlEXOAdminAudit' 'EXO-4.2').State | Should -Be 'Gap'
        }
        It 'EXO-4.2 and EXO-3.5 are not assessed when the audit config was not read' {
            $script:Exo.Remove('AdminAuditLogConfig'); $script:Exo.SectionStatus.AdminAuditLogConfig = 'Failed'
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw $script:Exo)
            (Verdict 'Test-NRGControlEXOAdminAudit' 'EXO-4.2').State | Should -Be 'NotApplicable'
            (Verdict 'Test-NRGControlEXOTransportAudit' 'EXO-3.5').State | Should -Be 'NotApplicable'
        }
        It 'EXO-4.1 does not score AuditLogAgeLimit, which Microsoft says no longer governs retention (was: Partial at 90)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw $script:Exo)
            (Verdict 'Test-NRGControlEXOAuditAgeLimit' 'EXO-4.1').State | Should -Be 'Satisfied'
        }
        It 'EXO-4.1 is a Gap when a custom audit retention policy keeps Exchange records under 180 days' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw $script:Exo)
            Set-NRGRawData -Key 'Purview' -Data (Raw @{ SectionStatus = @{ AuditRetentionPolicies = 'Collected' }
                AuditRetentionPolicies = @(@{ Name = 'Short Exchange'; RetentionDuration = 'ThreeMonths'; RetentionDays = 90; RecordTypes = @('ExchangeItem') }) })
            (Verdict 'Test-NRGControlEXOAuditAgeLimit' 'EXO-4.1').State | Should -Be 'Gap'
        }
        It 'the collector pins Get-AdminAuditLogConfig to Exchange Online and discards an ingestion value from anywhere else' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'NRG-Assessment' Get-NRGExoCommand -ParameterFilter { $Name -eq 'Get-AdminAuditLogConfig' } -MockWith {
                [pscustomobject]@{ Command = { [pscustomobject]@{ AdminAuditLogEnabled = $true; UnifiedAuditLogIngestionEnabled = $false } }; Source = 'SecurityCompliance' } }
            $r = Invoke-NRGCollectEXOMailboxConfig
            $r.Data.AdminAuditLogConfig.UnifiedAuditLogIngestionEnabled | Should -BeNullOrEmpty -Because 'Security & Compliance always reports it False'
            $r.Data.AdminAuditLogConfig.AdminAuditLogEnabled | Should -BeTrue
        }
    }

    Context 'EXO-3.2 outbound spam notification' {
        It 'the enabled "User restricted from sending email" alert policy satisfies it (was: Gap on NotifyOutboundSpam = False, the default)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ OutboundSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; NotifyOutboundSpam = $false })
                SectionStatus = @{ OutboundSpamPolicies = 'Collected' } })
            Set-NRGRawData -Key 'Purview' -Data (Raw @{ SectionStatus = @{ ProtectionAlerts = 'Collected' }
                ProtectionAlerts = @(@{ Name = 'User restricted from sending email'; Disabled = $false }) })
            (Verdict 'Test-NRGControlEXOOutboundLimits' 'EXO-3.2').State | Should -Be 'Satisfied'
        }
    }

    Context 'Defender-for-Office controls judge the policies in force' {
        BeforeEach {
            $script:Def = @{ AntiPhishing = @{ Available = $true; Rules = @()
                Policies = @(@{ Name = 'Office365 AntiPhish Default'; IsDefault = $true; HonorDmarcPolicy = $true
                    EnableTargetedUserProtection = $true; TargetedUsersToProtect = @('CEO;ceo@contoso.com'); TargetedUserProtectionAction = 'NoAction'
                    EnableOrganizationDomainsProtection = $true; TargetedDomainProtectionAction = 'Quarantine'
                    EnableMailboxIntelligence = $true; EnableMailboxIntelligenceProtection = $true; MailboxIntelligenceProtectionAction = 'MoveToJmf' }) }
                PresetRules = @{ Available = $true; EOP = @(); ATP = @() } }
        }
        It 'EXO-5.2: named users with action NoAction are detected, not protected (was: Satisfied)' {
            Set-NRGRawData -Key 'Defender-Policies' -Data (Raw $script:Def)
            (Verdict 'Test-NRGControlEXOPriorityAccountProtection' 'EXO-5.2').State | Should -Be 'Gap'
        }
        It 'EXO-5.2: the same list with Quarantine is protection' {
            $script:Def.AntiPhishing.Policies[0].TargetedUserProtectionAction = 'Quarantine'
            Set-NRGRawData -Key 'Defender-Policies' -Data (Raw $script:Def)
            (Verdict 'Test-NRGControlEXOPriorityAccountProtection' 'EXO-5.2').State | Should -Be 'Satisfied'
        }
        It 'EXO-1.5: a custom policy in force with impersonation actions set to NoAction makes it part-way' {
            $script:Def.AntiPhishing.Policies += @{ Name = 'Sales'; IsDefault = $false; EnableOrganizationDomainsProtection = $true; TargetedDomainProtectionAction = 'NoAction'
                EnableMailboxIntelligence = $true; EnableMailboxIntelligenceProtection = $false; MailboxIntelligenceProtectionAction = 'NoAction' }
            $script:Def.AntiPhishing.Rules = @(@{ Name = 'Sales'; AntiPhishPolicy = 'Sales'; State = 'Enabled'; SentToMemberOf = @('Sales') })
            Set-NRGRawData -Key 'Defender-Policies' -Data (Raw $script:Def)
            (Verdict 'Test-NRGControlEXOAntiPhish' 'EXO-1.5').State | Should -Be 'Partial'
        }
        It 'EXO-4.3 reads EnableATPForSPOTeamsODB, not "some Safe Attachments mail policy is on" (was: Satisfied)' {
            Set-NRGRawData -Key 'Defender-Policies' -Data (Raw @{ SafeAttachments = @{ Available = $true; Policies = @(@{ Name = 'SA'; Enable = $true; Action = 'Block' }) }
                AtpPolicyForO365 = @{ Available = $true; EnableATPForSPOTeamsODB = $false } })
            (Verdict 'Test-NRGControlEXOSafeAttachmentsSPO' 'EXO-4.3').State | Should -Be 'Gap'
        }
    }

    Context 'EXO-5.3 allowed senders' {
        It 'an allowed domain in a custom policy in force is found (was: Satisfied — the list was never collected)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ SectionStatus = @{ AntiSpamPolicies = 'Collected' }
                AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; AllowedSenderDomains = @(); AllowedSenders = @() },
                                     @{ Name = 'All staff'; IsDefault = $false; AllowedSenderDomains = @('vendor-mail.com'); AllowedSenders = @() })
                AntiSpamRules = @(@{ Name = 'All staff'; HostedContentFilterPolicy = 'All staff'; State = 'Enabled'; RecipientDomainIs = @('contoso.com') }) })
            (Verdict 'Test-NRGControlEXOSafeSenderOverride' 'EXO-5.3').State | Should -Be 'Gap'
        }
        It 'results that predate the field are not assessed rather than clean' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ SectionStatus = @{ AntiSpamPolicies = 'Collected' }
                AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true }) })
            (Verdict 'Test-NRGControlEXOSafeSenderOverride' 'EXO-5.3').State | Should -Be 'NotApplicable'
        }
    }

    Context 'EXO-6.3 / EXO-7.3 read audit bypass, which is what actually disables per-user audit' {
        BeforeEach {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ OrganizationConfig = @{ AuditDisabled = $false }; SectionStatus = @{ OrganizationConfig = 'Collected' } })
        }
        It 'a mailbox with AuditEnabled = False is still audited while org auditing is on (was: Gap)' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ AuditDisabledMailboxes = @(@{ UPN = 'carol@contoso.com'; MailboxType = 'UserMailbox' })
                AuditBypassAccounts = @(); SectionStatus = @{ AuditDisabledMailboxes = 'Collected'; AuditBypassAccounts = 'Collected' } })
            (Verdict 'Test-NRGControlEXOAuditDisabledMailboxes' 'EXO-7.3').State | Should -Be 'Satisfied'
            (Verdict 'Test-NRGControlInventoryMailboxAuditDisabled' 'EXO-6.3').State | Should -Be 'Satisfied'
        }
        It 'an audit bypass association is the Gap' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ AuditBypassAccounts = @(@{ Name = 'svc-backup'; Identity = 'svc-backup' })
                SectionStatus = @{ AuditBypassAccounts = 'Collected' } })
            (Verdict 'Test-NRGControlEXOAuditDisabledMailboxes' 'EXO-7.3').State | Should -Be 'Gap'
        }
        It 'with org auditing OFF no mailbox is audited, so "all mailboxes audited" is never claimed (was: Satisfied)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ OrganizationConfig = @{ AuditDisabled = $true }; SectionStatus = @{ OrganizationConfig = 'Collected' } })
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ AuditBypassAccounts = @(); SectionStatus = @{ AuditBypassAccounts = 'Collected' } })
            (Verdict 'Test-NRGControlInventoryMailboxAuditDisabled' 'EXO-6.3').State | Should -Be 'NotApplicable'
        }
    }

    Context 'EXO-6.4 / EXO-7.4 SMTP AUTH overrides' {
        It 'with SMTP AUTH enabled org-wide there is no disable to override (was: Satisfied "org-level disable enforced")' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ TransportConfig = @{ SmtpClientAuthenticationDisabled = $false } })
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ SmtpAuthEnabledPerUser = @(); SectionStatus = @{ SmtpAuthEnabledPerUser = 'Collected' } })
            (Verdict 'Test-NRGControlInventorySMTPAuthUsers' 'EXO-6.4').State | Should -Be 'NotApplicable'
            (Verdict 'Test-NRGControlEXOSmtpAuthExceptions' 'EXO-7.4').State | Should -Be 'NotApplicable'
        }
        It 'reports the full count, not the length of the capped name list (was: 100 of 250)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ TransportConfig = @{ SmtpClientAuthenticationDisabled = $true } })
            $list = @(1..100 | ForEach-Object { @{ DisplayName = "Svc $_"; UPN = "svc$_@contoso.com" } })
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ SmtpAuthEnabledPerUser = $list; SmtpAuthEnabledPerUserCount = 250; SectionStatus = @{ SmtpAuthEnabledPerUser = 'Collected' } })
            (Verdict 'Test-NRGControlEXOSmtpAuthExceptions' 'EXO-7.4').CurrentValue | Should -Be '250 per-user SMTP AUTH exception(s)'
        }
    }

    Context 'Mail flow' {
        It 'EXO-8.1 recognizes the address-space form "smtp:*;1" as unscoped (was: Satisfied)' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ SectionStatus = @{ MailFlowConnectors = 'Collected' }; OutboundConnectors = @()
                InboundConnectors = @(@{ Name = 'Partner inbound'; Enabled = $true; RequireTls = $true; SenderDomains = @('smtp:*;1'); SenderIPAddresses = @() }) })
            (Verdict 'Test-NRGControlEXOMailFlowConnectors' 'EXO-8.1').State | Should -Be 'Gap'
        }
        It 'EXO-8.2 does not give half credit for a recipient it could not resolve (was: Partial)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ AcceptedDomains = $script:Accepted; SectionStatus = @{ AcceptedDomains = 'Collected' } })
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ SectionStatus = @{ TransportRules = 'Collected' }
                TransportRules = @(@{ Name = 'Copy finance to archive'; State = 'Enabled'; BlindCopyTo = @('Finance Archive'); RedirectMessageTo = @(); CopyTo = @() }) })
            (Verdict 'Test-NRGControlEXOTransportRuleContents' 'EXO-8.2').State | Should -Be 'NotApplicable'
        }
    }

    Context 'Collector: EXO-9.1 holds, DEF-5.1 spoof allows' {
        BeforeAll {
            Inject 'Get-AcceptedDomain' '[pscustomobject]@{ DomainName = "contoso.com" }'
            Inject 'Get-OrganizationConfig' '[pscustomobject]@{ InPlaceHolds = @($script:OrgHolds) }'
            Inject 'Get-Mailbox' '$script:Mbx'
        }
        AfterAll { Remove 'Get-AcceptedDomain'; Remove 'Get-OrganizationConfig'; Remove 'Get-Mailbox' }

        It 'the MRM "Default MRM Policy" is not a hold; an org-wide policy covers mailboxes not excluded from it' {
            & $script:Mod {
                $script:OrgHolds = @('mbxa1b2c3:1')
                $script:Mbx = @(
                    [pscustomobject]@{ UserPrincipalName = 'a@contoso.com'; DisplayName = 'A'; RecipientTypeDetails = 'UserMailbox'; LitigationHoldEnabled = $false; InPlaceHolds = @(); RetentionPolicy = 'Default MRM Policy'; RetainDeletedItemsFor = '14.00:00:00' },
                    [pscustomobject]@{ UserPrincipalName = 'b@contoso.com'; DisplayName = 'B'; RecipientTypeDetails = 'UserMailbox'; LitigationHoldEnabled = $false; InPlaceHolds = @('-mbxa1b2c3:1'); RetentionPolicy = 'Default MRM Policy'; RetainDeletedItemsFor = '14.00:00:00' })
            }
            $r = Invoke-NRGCollectEXOInventory
            $r.Data.MailboxRecoverability.WithoutHold | Should -Be 1 -Because 'b is excluded from the org-wide policy and MRM holds nothing'
            $r.Data.MailboxRecoverability.WithoutHoldSample[0].UPN | Should -Be 'b@contoso.com'
        }
        It 'with no org-wide policy, MRM alone leaves every mailbox unheld (was: every mailbox held)' {
            & $script:Mod { $script:OrgHolds = @(); $script:Mbx = @([pscustomobject]@{ UserPrincipalName = 'a@contoso.com'; DisplayName = 'A'; RecipientTypeDetails = 'UserMailbox'; LitigationHoldEnabled = $false; InPlaceHolds = @(); RetentionPolicy = 'Default MRM Policy'; RetainDeletedItemsFor = '14.00:00:00' }) }
            $r = Invoke-NRGCollectEXOInventory
            $r.Data.MailboxRecoverability.WithoutHold | Should -Be 1
        }
        It 'reads spoofed-sender allow entries, which never expire' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'NRG-Assessment' Get-NRGExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListItems' } -MockWith {
                [pscustomobject]@{ Command = { param($ListType, [switch]$Allow, [switch]$Block) @() }; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'NRG-Assessment' Get-NRGExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListSpoofItems' } -MockWith {
                [pscustomobject]@{ Command = { [pscustomobject]@{ Action = 'Allow'; SpoofedUser = 'partner.com'; SendingInfrastructure = '198.51.100.0/24'; SpoofType = 'External' } }; Source = 'ExchangeOnline' } }
            & $script:Mod { $script:OrgHolds = @(); $script:Mbx = @() }
            $r = Invoke-NRGCollectEXOInventory
            $r.Data.SectionStatus.TenantAllowBlockList | Should -Be 'Collected'
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-Inventory' -Data $r
            (Verdict 'Test-NRGControlDefenderTenantAllowBlockList' 'DEF-5.1').State | Should -Be 'Gap'
        }
    }

    Context 'Identity inventory' {
        It 'AAD-12.4: a tenant-wide grant of sign-in scopes only exposes no one''s data (was: Gap, HIGH RISK)' {
            Set-NRGRawData -Key 'AAD-Inventory' -Data (Raw @{ SectionStatus = @{ OAuthGrantedApps = 'Collected' }
                OAuthGrantedApps = @(@{ AppName = 'Contoso SSO'; ClientId = '1111'; Scope = 'openid profile email offline_access User.Read' }) })
            (Verdict 'Test-NRGControlInventoryOAuthApps' 'AAD-12.4').State | Should -Be 'Satisfied'
        }
        It 'AAD-12.4: Mail.Read tenant-wide is still a Gap' {
            Set-NRGRawData -Key 'AAD-Inventory' -Data (Raw @{ SectionStatus = @{ OAuthGrantedApps = 'Collected' }
                OAuthGrantedApps = @(@{ AppName = 'Mail app'; ClientId = '2222'; Scope = 'openid Mail.Read' }) })
            (Verdict 'Test-NRGControlInventoryOAuthApps' 'AAD-12.4').State | Should -Be 'Gap'
        }
        It 'AAD-12.3 judges last SUCCESSFUL activity and ignores new hires' {
            $now = [datetime]::UtcNow
            & $script:Mod { param($n) $script:Users = @(
                # departed: last success 400 days ago, sprayed 3 days ago
                @{ displayName = 'Departed'; userPrincipalName = 'gone@contoso.com'; createdDateTime = $n.AddDays(-900).ToString('o'); assignedLicenses = @(@{ skuId = 'x' })
                   signInActivity = @{ lastSignInDateTime = $n.AddDays(-3).ToString('o'); lastSuccessfulSignInDateTime = $n.AddDays(-400).ToString('o') } },
                # active: interactive 120 days ago, token refresh yesterday (no lastSuccessful on old records)
                @{ displayName = 'Busy'; userPrincipalName = 'sales@contoso.com'; createdDateTime = $n.AddDays(-900).ToString('o'); assignedLicenses = @(@{ skuId = 'x' })
                   signInActivity = @{ lastSignInDateTime = $n.AddDays(-120).ToString('o'); lastNonInteractiveSignInDateTime = $n.AddDays(-1).ToString('o') } },
                # new hire, created last week, never signed in (signInActivity absent)
                @{ displayName = 'New Hire'; userPrincipalName = 'newhire@contoso.com'; createdDateTime = $n.AddDays(-7).ToString('o'); assignedLicenses = @(@{ skuId = 'x' }) }) } $now
            Inject 'Invoke-NRGGraphRequest' @'
param([string] $Uri, [string] $Method = 'GET', $Body, $Headers, [string] $OutputType = 'HashTable')
if ($Uri -like '*/users?*userType eq ''Member''*') { return @{ value = @($script:Users) } }
return @{ value = @() }
'@
            try {
                $r = Invoke-NRGCollectAADInventory
                $r.Data.SectionStatus.StaleMembers | Should -Be 'Collected'
                @($r.Data.StaleMembers | ForEach-Object { $_.UPN }) | Should -Be @('gone@contoso.com')
            } finally { Remove 'Invoke-NRGGraphRequest' }
        }
    }

    Context 'Sweep coverage and existing mailboxes' {
        It 'EXO-7.2 is not "clean" when the inbox-rule sweep stopped at the scan limit' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ InboxRulesForwarding = @(); UnparseableRules = @()
                Stats = @{ MailboxesScanned = 2000; ScanLimitReached = $true; MailboxesRuleScanFailed = 0 }
                SectionStatus = @{ InboxRulesForwarding = 'Collected' } })
            $f = Verdict 'Test-NRGControlEXOInboxRulesForwarding' 'EXO-7.2'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'first 2000 mailboxes'
        }
        It 'EXO-7.2 names disabled forwarding rules as disabled rather than active' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ UnparseableRules = @(); Stats = @{ MailboxesScanned = 5 }
                InboxRulesForwarding = @(@{ Mailbox = 'a@contoso.com'; RuleName = 'x'; Enabled = $false; IsExternal = $true; ExternalRecipients = @('e@evil.tld') })
                SectionStatus = @{ InboxRulesForwarding = 'Collected' } })
            (Verdict 'Test-NRGControlEXOInboxRulesForwarding' 'EXO-7.2').Detail | Should -Match '0 enabled.*disabled'
        }
        It 'EXO-2.3 is not satisfied by the mailbox plans while existing mailboxes still have POP on' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ CASMailboxPlans = @(@{ Name = 'Plan'; PopEnabled = $false; ImapEnabled = $false })
                CASMailboxProtocols = @{ Total = 10; PopEnabledCount = 3; ImapEnabledCount = 0; PopSample = @('a@contoso.com'); ImapSample = @() }
                SectionStatus = @{ CASMailboxPlans = 'Collected'; CASMailboxProtocols = 'Collected' } })
            (Verdict 'Test-NRGControlEXOPop3' 'EXO-2.3').State | Should -Be 'Partial'
            (Verdict 'Test-NRGControlEXOImap' 'EXO-2.4').State | Should -Be 'Satisfied'
        }
    }

    Context 'Live-run corrections (2026-09-25)' {
        It 'EXO-9.2 stays a Gap on a 14-day window but does not call held mail unrecoverable' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ SectionStatus = @{ MailboxRecoverability = 'Collected' }
                MailboxRecoverability = @{ TotalMailboxes = 80; ShortRetentionCount = 80; MinRetentionDays = 14; WithoutHold = 0; OrgHoldsRead = $true; ShortRetentionSample = @() } })
            $f = Verdict 'Test-NRGControlEXODeletedItemRetention' 'EXO-9.2'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Not -Match 'unrecoverable'
            $f.Detail | Should -Match 'under a hold'
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-Inventory' -Data (Raw @{ SectionStatus = @{ MailboxRecoverability = 'Collected' }
                MailboxRecoverability = @{ TotalMailboxes = 80; ShortRetentionCount = 80; MinRetentionDays = 14; WithoutHold = 5; OrgHoldsRead = $true; ShortRetentionSample = @() } })
            (Verdict 'Test-NRGControlEXODeletedItemRetention' 'EXO-9.2').Detail | Should -Match '5 mailbox\(es\) have no hold'
        }
        It 'EXO-2.3 no longer says POP3 uses basic auth or bypasses MFA (retired in Exchange Online, October 2022)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ CASMailboxPlans = @(@{ Name = 'ExchangeOnlineEnterprise'; PopEnabled = $true; ImapEnabled = $true })
                CASMailboxProtocols = @{ Total = 81; PopEnabledCount = 0; ImapEnabledCount = 0 }
                SectionStatus = @{ CASMailboxProtocols = 'Collected' } })
            $f = Verdict 'Test-NRGControlEXOPop3' 'EXO-2.3'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Not -Match 'bypasses|basic-auth protocol'
            $f.Detail | Should -Match '0 of the 81 existing mailboxes have POP3 on'
        }
        It 'EXO-3.1 is collected: the connection filter collector is run and reads EnableSafeList' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGExoCommand { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'NRG-Assessment' Get-NRGExoCommand -ParameterFilter { $Name -eq 'Get-HostedConnectionFilterPolicy' } {
                [pscustomobject]@{ Command = { [pscustomobject]@{ Name = 'Default'; IsDefault = $true; EnableSafeList = $false; IPAllowList = @() } }; Source = 'ExchangeOnline' } }
            $r = Invoke-NRGCollectEXOConnectionFilter
            $r.Success | Should -BeTrue
            (Verdict 'Test-NRGControlEXOConnectionFilter' 'EXO-3.1').State | Should -Be 'Satisfied'
        }
        It 'PPL-3.3 with no Copilot licenses is not applicable, not a pass that claims nobody can use Copilot' {
            Set-NRGRawData -Key 'M365Copilot' -Data (Raw @{ CopilotLicensedUserCount = 0; TotalUserCount = 124; LicensedSkus = @('SPB') })
            $f = Verdict 'Test-NRGControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Copilot Chat'
        }
        It 'AAD-12.1 counts the same members as AAD-1.2: the Entra Connect sync account is left out of both' {
            # Live tenant: AAD-12.1 said 52 of 103 without MFA, AAD-1.2 said 48 of 99.
            Set-NRGRawData -Key 'AAD-Users' -Data (Raw @{
                Users = @(
                    @{ UserPrincipalName = 'a@contoso.com'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' },
                    @{ UserPrincipalName = 'b@contoso.com'; DisplayName = 'B'; AccountEnabled = $true; UserType = 'Member' },
                    @{ UserPrincipalName = 'Sync_DC01_1a2b3c@contoso.onmicrosoft.com'; DisplayName = 'On-Premises Directory Synchronization Service Account'; AccountEnabled = $true; UserType = 'Member' })
                MFARegistration = @{ RegistrationDetails = @(@{ UserPrincipalName = 'a@contoso.com'; IsMfaRegistered = $true; IsEnabled = $true }) } })
            $f = Verdict 'Test-NRGControlInventoryMFAUsers' 'AAD-12.1'
            $f.Detail | Should -Match '^1 of 2 enabled member accounts'
            $f.Detail | Should -Match '1 Entra Connect sync service account\(s\) excluded'
            @($f.AffectedObjects) | Should -Not -Match 'Sync_'
        }
        It 'a finding with no Detail carries its CurrentValue, so no verdict prints without a reason' {
            Add-NRGFinding -ControlId 'TMS-1.4' -State 'Satisfied' -Category 'Teams' -Title 't' -CurrentValue 'External participants cannot give or request control'
            @(Get-NRGFindings)[0].Detail | Should -Be 'External participants cannot give or request control.'
        }
    }
}

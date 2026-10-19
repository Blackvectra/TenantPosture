#Requires -Version 7.0
#
# TP.ExchangeTruth.Tests.ps1
# NRG Technology Services / NextLayerSec LLC — Author: Matthew Levorson
# Pins the Exchange, Defender-for-Office and identity-inventory verdicts to
# what Microsoft documents each setting to mean. Every case here produced a
# wrong verdict before this change; each names the old one.
#
# Data keys: EXO-MailboxConfig, EXO-Inventory, Defender-Policies, Purview,
#            AAD-Inventory. Collector cases inject cmdlet stand-ins into
#            MODULE scope (Set-Item function:script:), as TP.DnsCollector
#            does, and feed raw cmdlet shapes rather than derived fields.
#

Describe 'Exchange controls read the setting they name' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'

        function script:Raw { param([hashtable] $Data, [bool] $Success = $true) [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-01T00:00:00Z'; Success = $Success; Data = $Data } }
        function script:Verdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
        # Stand-ins for Exchange / Graph cmdlets the module does not define.
        # Module functions (Get-TPExoCommand) are replaced with Pester's
        # Mock -ModuleName instead, which restores them after each test.
        function script:Inject { param([string] $Name, [string] $Body)
            & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } $Name $Body }
        function script:Remove { param([string] $Name)
            & $script:Mod { param($n) Remove-Item -Path "function:script:$n" -ErrorAction SilentlyContinue } $Name }

        $script:Accepted = @(@{ DomainName = 'contoso.com'; DomainType = 'Authoritative' })
    }
    BeforeEach { Clear-TPState }
    AfterAll   { Clear-TPState }

    Context 'EXO-1.2 SMTP AUTH' {
        It 'is not assessed when Get-TransportConfig was not read (was: Gap "enabled at the tenant level")' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ TransportConfig = $null
                SmtpAuthConfig = @{ TenantDisabled = $null; PerMailboxEnabledCount = 0; SampleEnabled = @() }
                SectionStatus = @{ TransportConfig = 'Failed'; SmtpAuthConfig = 'Collected' } })
            (Verdict 'Test-TPControlEXOSmtpAuth' 'EXO-1.2').State | Should -Be 'NotApplicable'
        }
        It 'identifies per-mailbox exceptions by PrimarySmtpAddress: CASMailbox has no UserPrincipalName' {
            Inject 'Get-TransportConfig' '[pscustomobject]@{ SmtpClientAuthenticationDisabled = $true }'
            Inject 'Get-CASMailbox' '[pscustomobject]@{ Name = "scan1"; PrimarySmtpAddress = "scanner@contoso.com"; SmtpClientAuthenticationDisabled = $false }; [pscustomobject]@{ Name = "u"; PrimarySmtpAddress = "u@contoso.com"; SmtpClientAuthenticationDisabled = $null }'
            try {
                $r = Invoke-TPCollectEXOMailboxConfig
                $r.Data.SectionStatus.SmtpAuthConfig | Should -Be 'Collected'
                $r.Data.SmtpAuthConfig.SampleEnabled | Should -Be @('scanner@contoso.com')
                (Verdict 'Test-TPControlEXOSmtpAuth' 'EXO-1.2').State | Should -Be 'Partial'
            } finally { Remove 'Get-TransportConfig'; Remove 'Get-CASMailbox' }
        }
    }

    Context 'EXO-1.3 external auto-forwarding' {
        It 'a custom On policy with an enabled rule leaves its senders forwarding (was: Satisfied from the default alone)' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{
                OutboundSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; AutoForwardingMode = 'Off' }, @{ Name = 'Finance forwarding'; IsDefault = $false; AutoForwardingMode = 'On' })
                OutboundSpamRules    = @(@{ Name = 'Finance'; HostedOutboundSpamFilterPolicy = 'Finance forwarding'; State = 'Enabled' })
                RemoteDomains        = @(@{ IsDefault = $true; DomainName = '*'; AutoForwardEnabled = $true })
                SectionStatus        = @{ OutboundSpamPolicies = 'Collected'; RemoteDomains = 'Collected' } })
            (Verdict 'Test-TPControlEXOAutoForward' 'EXO-1.3').State | Should -Be 'Partial'
        }
        It 'the same custom policy with its rule disabled applies to no one' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{
                OutboundSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; AutoForwardingMode = 'Off' }, @{ Name = 'Finance forwarding'; IsDefault = $false; AutoForwardingMode = 'On' })
                OutboundSpamRules    = @(@{ Name = 'Finance'; HostedOutboundSpamFilterPolicy = 'Finance forwarding'; State = 'Disabled' })
                RemoteDomains        = @(@{ IsDefault = $true; DomainName = '*'; AutoForwardEnabled = $true })
                SectionStatus        = @{ OutboundSpamPolicies = 'Collected'; RemoteDomains = 'Collected' } })
            (Verdict 'Test-TPControlEXOAutoForward' 'EXO-1.3').State | Should -Be 'Satisfied'
        }
        It 'Automatic is not counted as a block and the detail says why' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{
                OutboundSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; AutoForwardingMode = 'Automatic' })
                RemoteDomains        = @(@{ IsDefault = $true; DomainName = '*'; AutoForwardEnabled = $true })
                SectionStatus        = @{ OutboundSpamPolicies = 'Collected'; RemoteDomains = 'Collected' } })
            $f = Verdict 'Test-TPControlEXOAutoForward' 'EXO-1.3'
            $f.State | Should -Be 'Gap'
            $f.Detail | Should -Match 'before 2021'
        }
    }

    Context 'EXO-1.4 DKIM' {
        It 'a custom domain with no DKIM configuration is unsigned (was: NotApplicable "no configuration found")' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ DkimSigningConfigs = @(); AcceptedDomains = $script:Accepted
                SectionStatus = @{ DkimSigningConfigs = 'Collected'; AcceptedDomains = 'Collected' } })
            (Verdict 'Test-TPControlEXODKIM' 'EXO-1.4').State | Should -Be 'Gap'
        }
        It 'reads the documented Selector1KeySize / Selector2KeySize (was: Satisfied on 1024-bit keys)' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ AcceptedDomains = $script:Accepted
                DkimSigningConfigs = @(@{ Domain = 'contoso.com'; Enabled = $true; Selector1KeySize = 1024; Selector2KeySize = 1024 })
                SectionStatus = @{ DkimSigningConfigs = 'Collected'; AcceptedDomains = 'Collected' } })
            (Verdict 'Test-TPControlEXODKIM' 'EXO-1.4').State | Should -Be 'Partial'
        }
        It 'one 2048-bit selector beside a 1024-bit one is a rotation in progress, not a weakness' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ AcceptedDomains = $script:Accepted
                DkimSigningConfigs = @(@{ Domain = 'contoso.com'; Enabled = $true; Selector1KeySize = 1024; Selector2KeySize = 2048 })
                SectionStatus = @{ DkimSigningConfigs = 'Collected'; AcceptedDomains = 'Collected' } })
            (Verdict 'Test-TPControlEXODKIM' 'EXO-1.4').State | Should -Be 'Satisfied'
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
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw $script:Exo)
            (Verdict 'Test-TPControlEXOTransportAudit' 'EXO-3.5').State | Should -Be 'Gap'
        }
        It 'EXO-4.2 is a Gap when AdminAuditLogEnabled is False (was: Satisfied)' {
            $script:Exo.AdminAuditLogConfig.AdminAuditLogEnabled = $false
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw $script:Exo)
            (Verdict 'Test-TPControlEXOAdminAudit' 'EXO-4.2').State | Should -Be 'Gap'
        }
        It 'EXO-4.2 and EXO-3.5 are not assessed when the audit config was not read' {
            $script:Exo.Remove('AdminAuditLogConfig'); $script:Exo.SectionStatus.AdminAuditLogConfig = 'Failed'
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw $script:Exo)
            (Verdict 'Test-TPControlEXOAdminAudit' 'EXO-4.2').State | Should -Be 'NotApplicable'
            (Verdict 'Test-TPControlEXOTransportAudit' 'EXO-3.5').State | Should -Be 'NotApplicable'
        }
        It 'EXO-4.1 does not score AuditLogAgeLimit, which Microsoft says no longer governs retention (was: Partial at 90)' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw $script:Exo)
            (Verdict 'Test-TPControlEXOAuditAgeLimit' 'EXO-4.1').State | Should -Be 'Satisfied'
        }
        It 'EXO-4.1 is a Gap when a custom audit retention policy keeps Exchange records under 180 days' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw $script:Exo)
            Set-TPRawData -Key 'Purview' -Data (Raw @{ SectionStatus = @{ AuditRetentionPolicies = 'Collected' }
                AuditRetentionPolicies = @(@{ Name = 'Short Exchange'; RetentionDuration = 'ThreeMonths'; RetentionDays = 90; RecordTypes = @('ExchangeItem') }) })
            (Verdict 'Test-TPControlEXOAuditAgeLimit' 'EXO-4.1').State | Should -Be 'Gap'
        }
        It 'the collector pins Get-AdminAuditLogConfig to Exchange Online and discards an ingestion value from anywhere else' {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-AdminAuditLogConfig' } -MockWith {
                [pscustomobject]@{ Command = { [pscustomobject]@{ AdminAuditLogEnabled = $true; UnifiedAuditLogIngestionEnabled = $false } }; Source = 'SecurityCompliance' } }
            $r = Invoke-TPCollectEXOMailboxConfig
            $r.Data.AdminAuditLogConfig.UnifiedAuditLogIngestionEnabled | Should -BeNullOrEmpty -Because 'Security & Compliance always reports it False'
            $r.Data.AdminAuditLogConfig.AdminAuditLogEnabled | Should -BeTrue
        }
    }

    Context 'EXO-3.2 outbound spam notification' {
        It 'the enabled "User restricted from sending email" alert policy satisfies it (was: Gap on NotifyOutboundSpam = False, the default)' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ OutboundSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; NotifyOutboundSpam = $false })
                SectionStatus = @{ OutboundSpamPolicies = 'Collected' } })
            Set-TPRawData -Key 'Purview' -Data (Raw @{ SectionStatus = @{ ProtectionAlerts = 'Collected' }
                ProtectionAlerts = @(@{ Name = 'User restricted from sending email'; Disabled = $false }) })
            (Verdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2').State | Should -Be 'Satisfied'
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
            Set-TPRawData -Key 'Defender-Policies' -Data (Raw $script:Def)
            (Verdict 'Test-TPControlEXOPriorityAccountProtection' 'EXO-5.2').State | Should -Be 'Gap'
        }
        It 'EXO-5.2: the same list with Quarantine is protection' {
            $script:Def.AntiPhishing.Policies[0].TargetedUserProtectionAction = 'Quarantine'
            Set-TPRawData -Key 'Defender-Policies' -Data (Raw $script:Def)
            (Verdict 'Test-TPControlEXOPriorityAccountProtection' 'EXO-5.2').State | Should -Be 'Satisfied'
        }
        It 'EXO-1.5: a custom policy in force with impersonation actions set to NoAction makes it part-way' {
            $script:Def.AntiPhishing.Policies += @{ Name = 'Sales'; IsDefault = $false; EnableOrganizationDomainsProtection = $true; TargetedDomainProtectionAction = 'NoAction'
                EnableMailboxIntelligence = $true; EnableMailboxIntelligenceProtection = $false; MailboxIntelligenceProtectionAction = 'NoAction' }
            $script:Def.AntiPhishing.Rules = @(@{ Name = 'Sales'; AntiPhishPolicy = 'Sales'; State = 'Enabled'; SentToMemberOf = @('Sales') })
            Set-TPRawData -Key 'Defender-Policies' -Data (Raw $script:Def)
            (Verdict 'Test-TPControlEXOAntiPhish' 'EXO-1.5').State | Should -Be 'Partial'
        }
        It 'EXO-4.3 reads EnableATPForSPOTeamsODB, not "some Safe Attachments mail policy is on" (was: Satisfied)' {
            Set-TPRawData -Key 'Defender-Policies' -Data (Raw @{ SafeAttachments = @{ Available = $true; Policies = @(@{ Name = 'SA'; Enable = $true; Action = 'Block' }) }
                AtpPolicyForO365 = @{ Available = $true; EnableATPForSPOTeamsODB = $false } })
            (Verdict 'Test-TPControlEXOSafeAttachmentsSPO' 'EXO-4.3').State | Should -Be 'Gap'
        }
    }

    Context 'EXO-5.3 allowed senders' {
        It 'an allowed domain in a custom policy in force is found (was: Satisfied — the list was never collected)' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ SectionStatus = @{ AntiSpamPolicies = 'Collected' }
                AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; AllowedSenderDomains = @(); AllowedSenders = @() },
                                     @{ Name = 'All staff'; IsDefault = $false; AllowedSenderDomains = @('vendor-mail.com'); AllowedSenders = @() })
                AntiSpamRules = @(@{ Name = 'All staff'; HostedContentFilterPolicy = 'All staff'; State = 'Enabled'; RecipientDomainIs = @('contoso.com') }) })
            (Verdict 'Test-TPControlEXOSafeSenderOverride' 'EXO-5.3').State | Should -Be 'Gap'
        }
        It 'results that predate the field are not assessed rather than clean' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ SectionStatus = @{ AntiSpamPolicies = 'Collected' }
                AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true }) })
            (Verdict 'Test-TPControlEXOSafeSenderOverride' 'EXO-5.3').State | Should -Be 'NotApplicable'
        }
    }

    Context 'EXO-6.3 / EXO-7.3 read audit bypass, which is what actually disables per-user audit' {
        BeforeEach {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ OrganizationConfig = @{ AuditDisabled = $false }; SectionStatus = @{ OrganizationConfig = 'Collected' } })
        }
        It 'a mailbox with AuditEnabled = False is still audited while org auditing is on (was: Gap)' {
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ AuditDisabledMailboxes = @(@{ UPN = 'carol@contoso.com'; MailboxType = 'UserMailbox' })
                AuditBypassAccounts = @(); SectionStatus = @{ AuditDisabledMailboxes = 'Collected'; AuditBypassAccounts = 'Collected' } })
            (Verdict 'Test-TPControlEXOAuditDisabledMailboxes' 'EXO-7.3').State | Should -Be 'Satisfied'
            (Verdict 'Test-TPControlInventoryMailboxAuditDisabled' 'EXO-6.3').State | Should -Be 'Satisfied'
        }
        It 'an audit bypass association is the Gap' {
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ AuditBypassAccounts = @(@{ Name = 'svc-backup'; Identity = 'svc-backup' })
                SectionStatus = @{ AuditBypassAccounts = 'Collected' } })
            (Verdict 'Test-TPControlEXOAuditDisabledMailboxes' 'EXO-7.3').State | Should -Be 'Gap'
        }
        It 'with org auditing OFF no mailbox is audited, so "all mailboxes audited" is never claimed (was: Satisfied)' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ OrganizationConfig = @{ AuditDisabled = $true }; SectionStatus = @{ OrganizationConfig = 'Collected' } })
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ AuditBypassAccounts = @(); SectionStatus = @{ AuditBypassAccounts = 'Collected' } })
            (Verdict 'Test-TPControlInventoryMailboxAuditDisabled' 'EXO-6.3').State | Should -Be 'NotApplicable'
        }
    }

    Context 'EXO-6.4 / EXO-7.4 SMTP AUTH overrides' {
        It 'with SMTP AUTH enabled org-wide there is no disable to override (was: Satisfied "org-level disable enforced")' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ TransportConfig = @{ SmtpClientAuthenticationDisabled = $false } })
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ SmtpAuthEnabledPerUser = @(); SectionStatus = @{ SmtpAuthEnabledPerUser = 'Collected' } })
            (Verdict 'Test-TPControlInventorySMTPAuthUsers' 'EXO-6.4').State | Should -Be 'NotApplicable'
            (Verdict 'Test-TPControlEXOSmtpAuthExceptions' 'EXO-7.4').State | Should -Be 'NotApplicable'
        }
        It 'reports the full count, not the length of the capped name list (was: 100 of 250)' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ TransportConfig = @{ SmtpClientAuthenticationDisabled = $true } })
            $list = @(1..100 | ForEach-Object { @{ DisplayName = "Svc $_"; UPN = "svc$_@contoso.com" } })
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ SmtpAuthEnabledPerUser = $list; SmtpAuthEnabledPerUserCount = 250; SectionStatus = @{ SmtpAuthEnabledPerUser = 'Collected' } })
            (Verdict 'Test-TPControlEXOSmtpAuthExceptions' 'EXO-7.4').CurrentValue | Should -Be '250 per-user SMTP AUTH exception(s)'
        }
    }

    Context 'Mail flow' {
        It 'EXO-8.1 recognizes the address-space form "smtp:*;1" as unscoped (was: Satisfied)' {
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ SectionStatus = @{ MailFlowConnectors = 'Collected' }; OutboundConnectors = @()
                InboundConnectors = @(@{ Name = 'Partner inbound'; Enabled = $true; RequireTls = $true; SenderDomains = @('smtp:*;1'); SenderIPAddresses = @() }) })
            (Verdict 'Test-TPControlEXOMailFlowConnectors' 'EXO-8.1').State | Should -Be 'Gap'
        }
        It 'EXO-8.2 does not give half credit for a recipient it could not resolve (was: Partial)' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ AcceptedDomains = $script:Accepted; SectionStatus = @{ AcceptedDomains = 'Collected' } })
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ SectionStatus = @{ TransportRules = 'Collected' }
                TransportRules = @(@{ Name = 'Copy finance to archive'; State = 'Enabled'; BlindCopyTo = @('Finance Archive'); RedirectMessageTo = @(); CopyTo = @() }) })
            (Verdict 'Test-TPControlEXOTransportRuleContents' 'EXO-8.2').State | Should -Be 'NotApplicable'
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
            $r = Invoke-TPCollectEXOInventory
            $r.Data.MailboxRecoverability.WithoutHold | Should -Be 1 -Because 'b is excluded from the org-wide policy and MRM holds nothing'
            $r.Data.MailboxRecoverability.WithoutHoldSample[0].UPN | Should -Be 'b@contoso.com'
        }
        It 'with no org-wide policy, MRM alone leaves every mailbox unheld (was: every mailbox held)' {
            & $script:Mod { $script:OrgHolds = @(); $script:Mbx = @([pscustomobject]@{ UserPrincipalName = 'a@contoso.com'; DisplayName = 'A'; RecipientTypeDetails = 'UserMailbox'; LitigationHoldEnabled = $false; InPlaceHolds = @(); RetentionPolicy = 'Default MRM Policy'; RetainDeletedItemsFor = '14.00:00:00' }) }
            $r = Invoke-TPCollectEXOInventory
            $r.Data.MailboxRecoverability.WithoutHold | Should -Be 1
        }
        It 'reads spoofed-sender allow entries, which never expire' {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListItems' } -MockWith {
                [pscustomobject]@{ Command = { param($ListType, [switch]$Allow, [switch]$Block) @() }; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListSpoofItems' } -MockWith {
                [pscustomobject]@{ Command = { [pscustomobject]@{ Action = 'Allow'; SpoofedUser = 'partner.com'; SendingInfrastructure = '198.51.100.0/24'; SpoofType = 'External' } }; Source = 'ExchangeOnline' } }
            & $script:Mod { $script:OrgHolds = @(); $script:Mbx = @() }
            $r = Invoke-TPCollectEXOInventory
            $r.Data.SectionStatus.TenantAllowBlockList | Should -Be 'Collected'
            Clear-TPState
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            # Microsoft: allow entries for spoofed senders never expire, so they cannot be
            # time-boxed and are never this control's Gap; they are listed for review.
            $f = Verdict 'Test-TPControlDefenderTenantAllowBlockList' 'DEF-5.1'
            $f.State  | Should -Be 'Satisfied' -Because 'a spoof allow cannot be time-boxed (was: a High Gap on every tenant with a phishing-simulation spoof allow)'
            $f.Detail | Should -Match 'never expire by design'
            $f.Detail | Should -Match 'partner\.com via 198\.51\.100\.0/24'
            $f.Detail | Should -Not -Match 'override filtering indefinitely'
            # The HTML report renders a Satisfied finding's CurrentValue and not its Detail.
            $f.CurrentValue | Should -Match 'to confirm: partner\.com via 198\.51\.100\.0/24'
        }
        It 'DEF-5.1: inline entry lists are bounded to five names plus the count of the rest, on the Gap and on the pass' {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListItems' } -MockWith {
                [pscustomobject]@{ Command = {
                    param($ListType, [switch]$Allow, [switch]$Block, [switch]$NoExpiration)
                    if ($ListType -ne 'Sender' -or -not $Allow) { return @() }
                    @(1..7 | ForEach-Object { [pscustomobject]@{ Value = "permanent$_.example"; ExpirationDate = $null; Notes = '' } })
                }; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListSpoofItems' } -MockWith {
                [pscustomobject]@{ Command = { @(1..7 | ForEach-Object { [pscustomobject]@{ Action = 'Allow'; SpoofedUser = "spoof$_.example"; SendingInfrastructure = "203.0.113.$_"; SpoofType = 'External' } }) }; Source = 'ExchangeOnline' } }
            & $script:Mod { $script:OrgHolds = @(); $script:Mbx = @() }
            $r = Invoke-TPCollectEXOInventory
            Clear-TPState
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            $f = Verdict 'Test-TPControlDefenderTenantAllowBlockList' 'DEF-5.1'
            $f.State | Should -Be 'Gap'
            $f.Detail | Should -Match 'Sender permanent5\.example and 2 more'
            $f.Detail | Should -Not -Match 'permanent6\.example'
            $f.Detail | Should -Match 'spoof5\.example via 203\.0\.113\.5 and 2 more'
            $f.Detail | Should -Not -Match 'spoof6\.example'
            @($f.AffectedObjects).Count | Should -Be 7 -Because 'the bound is on the prose; every entry stays in AffectedObjects'
            # The pass names the spoof entries to confirm in CurrentValue, bounded the same way.
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListItems' } -MockWith {
                [pscustomobject]@{ Command = { param($ListType, [switch]$Allow, [switch]$Block, [switch]$NoExpiration) @() }; Source = 'ExchangeOnline' } }
            $r = Invoke-TPCollectEXOInventory
            Clear-TPState
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            $f = Verdict 'Test-TPControlDefenderTenantAllowBlockList' 'DEF-5.1'
            $f.State | Should -Be 'Satisfied'
            $f.CurrentValue | Should -Match '7 spoofed-sender allow entr\(ies\) to confirm: spoof1\.example via 203\.0\.113\.1; .* spoof5\.example via 203\.0\.113\.5 and 2 more'
            $f.CurrentValue | Should -Not -Match 'spoof6\.example'
        }
        It 'DEF-5.1: a domain allow entry the cmdlet lists as never expiring is the Gap; one with no date that the filter does not list expires 45 days after last use' {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListItems' } -MockWith {
                [pscustomobject]@{ Command = {
                    param($ListType, [switch]$Allow, [switch]$Block, [switch]$NoExpiration)
                    if ($ListType -ne 'Sender' -or -not $Allow) { return @() }
                    if ($NoExpiration) { return @([pscustomobject]@{ Value = 'legacy.example'; ExpirationDate = $null; Notes = 'added 2021' }) }
                    @([pscustomobject]@{ Value = 'legacy.example'; ExpirationDate = $null; Notes = 'added 2021' }, [pscustomobject]@{ Value = 'vendor.example'; ExpirationDate = $null; Notes = 'from submission' })
                }; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListSpoofItems' } -MockWith { [pscustomobject]@{ Command = { @() }; Source = 'ExchangeOnline' } }
            & $script:Mod { $script:OrgHolds = @(); $script:Mbx = @() }
            $r = Invoke-TPCollectEXOInventory
            $r.Data.SectionStatus.TenantAllowBlockList | Should -Be 'Collected'
            $rows = @($r.Data.TenantAllowBlockList | Where-Object { $_.Action -eq 'Allow' })
            @($rows | Where-Object { $_.Value -eq 'legacy.example' })[0].NoExpiration | Should -BeTrue
            @($rows | Where-Object { $_.Value -eq 'vendor.example' })[0].NoExpiration | Should -BeFalse -Because 'an empty ExpirationDate is the 45-days-after-last-use default, not never'
            Clear-TPState
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            $f = Verdict 'Test-TPControlDefenderTenantAllowBlockList' 'DEF-5.1'
            $f.State | Should -Be 'Gap'
            $f.CurrentValue | Should -Match '^1 never-expiring allow entr\(ies\) of 2 '
            $f.Detail | Should -Match 'Sender legacy\.example'
            $f.Detail | Should -Not -Match 'vendor\.example'
            @($f.AffectedObjects).Count | Should -Be 1
        }
        It 'DEF-5.1: with no entry listed as never expiring, allow entries without a date are the 45-day default: Satisfied' {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListItems' } -MockWith {
                [pscustomobject]@{ Command = {
                    param($ListType, [switch]$Allow, [switch]$Block, [switch]$NoExpiration)
                    if ($ListType -ne 'Url' -or -not $Allow -or $NoExpiration) { return @() }
                    @([pscustomobject]@{ Value = 'files.vendor.example'; ExpirationDate = $null; Notes = '' })
                }; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListSpoofItems' } -MockWith { [pscustomobject]@{ Command = { @() }; Source = 'ExchangeOnline' } }
            & $script:Mod { $script:OrgHolds = @(); $script:Mbx = @() }
            $r = Invoke-TPCollectEXOInventory
            Clear-TPState
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            $f = Verdict 'Test-TPControlDefenderTenantAllowBlockList' 'DEF-5.1'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'none is permanent'
        }
        It 'DEF-5.1: when the never-expiring filter cannot be read, the entries are not judged: never a Gap, never a pass, and the reason is recorded' {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListItems' } -MockWith {
                [pscustomobject]@{ Command = {
                    param($ListType, [switch]$Allow, [switch]$Block, [switch]$NoExpiration)
                    if ($NoExpiration) { throw 'A parameter cannot be found that matches parameter name ''NoExpiration''.' }
                    if ($ListType -ne 'Sender' -or -not $Allow) { return @() }
                    @([pscustomobject]@{ Value = 'legacy.example'; ExpirationDate = $null; Notes = '' })
                }; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-TenantAllowBlockListSpoofItems' } -MockWith { [pscustomobject]@{ Command = { @() }; Source = 'ExchangeOnline' } }
            & $script:Mod { $script:OrgHolds = @(); $script:Mbx = @() }
            $r = Invoke-TPCollectEXOInventory
            $why = @(Get-TPExceptions | Where-Object { $_.Source -eq 'EXO-TenantAllowBlockList' })
            $why.Count | Should -BeGreaterOrEqual 1
            $why[0].Message | Should -Match 'NoExpiration'
            @($r.Data.TenantAllowBlockList)[0].ExpiryRead | Should -BeFalse
            Clear-TPState
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            $f = Verdict 'Test-TPControlDefenderTenantAllowBlockList' 'DEF-5.1'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'not read'
        }
    }

    Context 'Identity inventory' {
        It 'AAD-12.4: a tenant-wide grant of sign-in scopes only exposes no one''s data (was: Gap, HIGH RISK)' {
            Set-TPRawData -Key 'AAD-Inventory' -Data (Raw @{ SectionStatus = @{ OAuthGrantedApps = 'Collected' }
                OAuthGrantedApps = @(@{ AppName = 'Contoso SSO'; ClientId = '1111'; Scope = 'openid profile email offline_access User.Read' }) })
            (Verdict 'Test-TPControlInventoryOAuthApps' 'AAD-12.4').State | Should -Be 'Satisfied'
        }
        It 'AAD-12.4: Mail.Read tenant-wide is still a Gap' {
            Set-TPRawData -Key 'AAD-Inventory' -Data (Raw @{ SectionStatus = @{ OAuthGrantedApps = 'Collected' }
                OAuthGrantedApps = @(@{ AppName = 'Mail app'; ClientId = '2222'; Scope = 'openid Mail.Read' }) })
            (Verdict 'Test-TPControlInventoryOAuthApps' 'AAD-12.4').State | Should -Be 'Gap'
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
            Inject 'Invoke-TPGraphRequest' @'
param([string] $Uri, [string] $Method = 'GET', $Body, $Headers, [string] $OutputType = 'HashTable')
if ($Uri -like '*/users?*userType eq ''Member''*') { return @{ value = @($script:Users) } }
return @{ value = @() }
'@
            try {
                $r = Invoke-TPCollectAADInventory
                $r.Data.SectionStatus.StaleMembers | Should -Be 'Collected'
                @($r.Data.StaleMembers | ForEach-Object { $_.UPN }) | Should -Be @('gone@contoso.com')
            } finally { Remove 'Invoke-TPGraphRequest' }
        }
    }

    Context 'Sweep coverage and existing mailboxes' {
        It 'EXO-7.2 is not "clean" when the inbox-rule sweep stopped at the scan limit' {
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ InboxRulesForwarding = @(); UnparseableRules = @()
                Stats = @{ MailboxesScanned = 2000; ScanLimitReached = $true; MailboxesRuleScanFailed = 0 }
                SectionStatus = @{ InboxRulesForwarding = 'Collected' } })
            $f = Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'first 2000 mailboxes'
        }
        It 'EXO-7.2 names disabled forwarding rules as disabled rather than active' {
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ UnparseableRules = @(); Stats = @{ MailboxesScanned = 5 }
                InboxRulesForwarding = @(@{ Mailbox = 'a@contoso.com'; RuleName = 'x'; Enabled = $false; IsExternal = $true; ExternalRecipients = @('e@evil.tld') })
                SectionStatus = @{ InboxRulesForwarding = 'Collected' } })
            (Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2').Detail | Should -Match '0 enabled.*disabled'
        }
        It 'EXO-7.2 names the mailbox, the rule and the recipients of a rule it could not resolve (synthetic values in the shape of a live tenant run)' {
            $dn1 = '"Pat Example" [EX:/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=00000000000000000000000000000001-pat.exampl]'
            $dn2 = '"Sam Q. Sample" [EX:/o=ExampleOrg/ou=Example Unit/cn=Recipients/cn=ssample_unmapped00000000000000000000000000000002]'
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ UnparseableRules = @(); Stats = @{ MailboxesScanned = 12 }
                InboxRulesForwarding = @(
                    @{ Mailbox = 'pat@contoso.com'; RuleName = 'Newsletter Distribution'; Enabled = $true; IsExternal = $false; IsUnresolved = $true; ExternalRecipients = @(); UnresolvedRecipients = @($dn1) }
                    @{ Mailbox = 'reports@contoso.com'; RuleName = 'Subscription Services Report'; Enabled = $true; IsExternal = $false; IsUnresolved = $true; ExternalRecipients = @(); UnresolvedRecipients = @($dn2) })
                SectionStatus = @{ InboxRulesForwarding = 'Collected' } })
            $f = Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match "pat@contoso\.com rule 'Newsletter Distribution' forwards to Pat Example"
            $f.Detail | Should -Match "reports@contoso\.com rule 'Subscription Services Report' forwards to Sam Q\. Sample"
            $f.Detail | Should -Not -Match 'EX:/o='
            @($f.AffectedObjects).Count | Should -Be 2
        }
        It 'EXO-2.3 is not satisfied by the mailbox plans while existing mailboxes still have POP on' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ CASMailboxPlans = @(@{ Name = 'Plan'; PopEnabled = $false; ImapEnabled = $false })
                CASMailboxProtocols = @{ Total = 10; PopEnabledCount = 3; ImapEnabledCount = 0; PopSample = @('a@contoso.com'); ImapSample = @() }
                SectionStatus = @{ CASMailboxPlans = 'Collected'; CASMailboxProtocols = 'Collected' } })
            (Verdict 'Test-TPControlEXOPop3' 'EXO-2.3').State | Should -Be 'Partial'
            (Verdict 'Test-TPControlEXOImap' 'EXO-2.4').State | Should -Be 'Satisfied'
        }
    }

    Context 'Live-run corrections (2026-09-25)' {
        It 'EXO-9.2 stays a Gap on a 14-day window but does not call held mail unrecoverable' {
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ SectionStatus = @{ MailboxRecoverability = 'Collected' }
                MailboxRecoverability = @{ TotalMailboxes = 80; ShortRetentionCount = 80; MinRetentionDays = 14; WithoutHold = 0; OrgHoldsRead = $true; ShortRetentionSample = @() } })
            $f = Verdict 'Test-TPControlEXODeletedItemRetention' 'EXO-9.2'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Not -Match 'unrecoverable'
            $f.Detail | Should -Match 'under a hold'
            Clear-TPState
            Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ SectionStatus = @{ MailboxRecoverability = 'Collected' }
                MailboxRecoverability = @{ TotalMailboxes = 80; ShortRetentionCount = 80; MinRetentionDays = 14; WithoutHold = 5; OrgHoldsRead = $true; ShortRetentionSample = @() } })
            (Verdict 'Test-TPControlEXODeletedItemRetention' 'EXO-9.2').Detail | Should -Match '5 mailbox\(es\) have no hold'
        }
        It 'EXO-2.3 no longer says POP3 uses basic auth or bypasses MFA (retired in Exchange Online, October 2022)' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ CASMailboxPlans = @(@{ Name = 'ExchangeOnlineEnterprise'; PopEnabled = $true; ImapEnabled = $true })
                CASMailboxProtocols = @{ Total = 81; PopEnabledCount = 0; ImapEnabledCount = 0 }
                SectionStatus = @{ CASMailboxProtocols = 'Collected' } })
            $f = Verdict 'Test-TPControlEXOPop3' 'EXO-2.3'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Not -Match 'bypasses|basic-auth protocol'
            $f.Detail | Should -Match '0 of the 81 existing mailboxes have POP3 on'
        }
        It 'EXO-3.1 is collected: the connection filter collector is run and reads EnableSafeList' {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-HostedConnectionFilterPolicy' } {
                [pscustomobject]@{ Command = { [pscustomobject]@{ Name = 'Default'; IsDefault = $true; EnableSafeList = $false; IPAllowList = @() } }; Source = 'ExchangeOnline' } }
            $r = Invoke-TPCollectEXOConnectionFilter
            $r.Success | Should -BeTrue
            (Verdict 'Test-TPControlEXOConnectionFilter' 'EXO-3.1').State | Should -Be 'Satisfied'
        }
        It 'PPL-3.3 with no Copilot licenses is not applicable, not a pass that claims nobody can use Copilot' {
            Set-TPRawData -Key 'M365Copilot' -Data (Raw @{ CopilotLicensedUserCount = 0; TotalUserCount = 124; LicensedSkus = @('SPB') })
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Copilot Chat'
        }
        It 'AAD-12.1 counts the same members as AAD-1.2: the Entra Connect sync account is left out of both' {
            # Live tenant: AAD-12.1 said 52 of 103 without MFA, AAD-1.2 said 48 of 99.
            Set-TPRawData -Key 'AAD-Users' -Data (Raw @{
                Users = @(
                    @{ UserPrincipalName = 'a@contoso.com'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' },
                    @{ UserPrincipalName = 'b@contoso.com'; DisplayName = 'B'; AccountEnabled = $true; UserType = 'Member' },
                    @{ UserPrincipalName = 'Sync_DC01_1a2b3c@contoso.onmicrosoft.com'; DisplayName = 'On-Premises Directory Synchronization Service Account'; AccountEnabled = $true; UserType = 'Member' })
                MFARegistration = @{ RegistrationDetails = @(@{ UserPrincipalName = 'a@contoso.com'; IsMfaRegistered = $true; IsEnabled = $true }) } })
            $f = Verdict 'Test-TPControlInventoryMFAUsers' 'AAD-12.1'
            $f.Detail | Should -Match '^1 of 2 enabled member accounts'
            $f.Detail | Should -Match '1 Entra Connect sync service account\(s\) excluded'
            @($f.AffectedObjects) | Should -Not -Match 'Sync_'
        }
        It 'AAD-12.1 describes a registration gap and does not assert that a stolen password compromises the mailbox' {
            Set-TPRawData -Key 'AAD-Users' -Data (Raw @{
                Users = @(@{ UserPrincipalName = 'a@contoso.com'; DisplayName = 'A'; AccountEnabled = $true; UserType = 'Member' })
                MFARegistration = @{ RegistrationDetails = @(@{ UserPrincipalName = 'a@contoso.com'; IsMfaRegistered = $false; IsEnabled = $true }) } })
            $f = Verdict 'Test-TPControlInventoryMFAUsers' 'AAD-12.1'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'registration gap'
            $f.Detail | Should -Not -Match 'stolen password away|full mailbox compromise|guaranteed'
        }
        It 'a finding with no Detail carries its CurrentValue, so no verdict prints without a reason' {
            Add-TPFinding -ControlId 'TMS-1.4' -State 'Satisfied' -Category 'Teams' -Title 't' -CurrentValue 'External participants cannot give or request control'
            @(Get-TPFindings)[0].Detail | Should -Be 'External participants cannot give or request control.'
        }
    }
}

Describe 'Shared mailbox sign-in: a failed section is never a clean list (live run, 2026-09-29)' {
    # EXO-Inventory enumerated 28 shared mailboxes, then the sign-in loop threw
    # (Get-Mailbox omitted LicenseReconciliationNeeded; StrictMode), so
    # SectionStatus.SharedMailboxes read Failed and SharedMailboxSignIn stayed
    # empty. EXO-2.6 scored the empty list as "none have sign-in enabled".
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Inv = {
            param([string] $SectionState)
            @{ CollectorId = 'EXO-Inventory'; CollectedAt = (Get-Date).ToString('o'); Success = $true
               Data = @{
                   SectionStatus = @{ SharedMailboxes = $SectionState; ForwardingMailboxes = 'Collected'; InboxRulesForwarding = 'Collected' }
                   AllSharedMailboxes = @(@{ DisplayName = 'Shared A'; UPN = 'shared-a@contoso.com' }, @{ DisplayName = 'Shared B'; UPN = 'shared-b@contoso.com' })
                   SharedMailboxSignIn = @()
               } }
        }
        $script:Users = @{ CollectorId = 'AAD-Users'; CollectedAt = (Get-Date).ToString('o'); Success = $true; Data = @{ Users = @() } }
    }
    AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-TPState }

    It 'EXO-2.6 and EXO-6.2 are not assessed when the SharedMailboxes section failed, even with mailboxes enumerated' {
        Set-TPRawData -Key 'EXO-Inventory' -Data (& $script:Inv 'Failed')
        Set-TPRawData -Key 'AAD-Users' -Data $script:Users
        Test-TPControlEXOSharedMailbox
        Test-TPControlInventorySharedMailboxSignIn
        foreach ($cid in 'EXO-2.6', 'EXO-6.2') {
            $f = @(Get-TPFindings | Where-Object { $_.ControlId -eq $cid })[0]
            $f.State | Should -Be 'NotApplicable' -Because "$cid must not read an empty sign-in list as clean when the section failed"
            $f.Detail | Should -Match 'not collected|did not complete'
        }
    }
    It 'the collector reads LicenseReconciliationNeeded and SkuAssigned through Get-TPObjectField' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Collectors/EXO/Invoke-TPCollectEXOInventory.ps1') -Raw
        $src | Should -Not -Match '\$mbx\.LicenseReconciliationNeeded'
        $src | Should -Not -Match '\$mbx\.SkuAssigned'
    }
}

# ── EXO-7.2: a recipient the directory no longer holds is an answer, not a blind spot ──
# A legacy DN in an inbox rule that no object carries (by LegacyExchangeDN and by X500
# proxy address) is a former employee or a pre-migration identity: mail to it is not
# delivered. The classifier filed it as Unresolved, and one such recipient left the
# control "not assessed" on every run of the tenant, for months. The collector cases
# below drive the real collector with Get-Recipient stand-ins that answer the way the
# Exchange Online module does, so the field that changes the verdict (IsOrphaned) is
# produced by the real code path, never by a fixture.
Describe 'EXO-7.2 reaches a verdict when the only unresolvable recipients are gone from the directory' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'

        function script:Raw { param([hashtable] $Data, [bool] $Success = $true) [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-01T00:00:00Z'; Success = $Success; Data = $Data } }
        function script:Verdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
        function script:Inject { param([string] $Name, [string] $Body)
            & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } $Name $Body }
        function script:Remove { param([string] $Name)
            & $script:Mod { param($n) Remove-Item -Path "function:script:$n" -ErrorAction SilentlyContinue } $Name }

        # The not-found error exactly as the Exchange Online module renders a server error: |Type|Message.
        $script:NotFoundMessage = "|Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException|The operation couldn't be performed because object '/o=x' couldn't be found on 'DM6PR01A008DC01.PROD.OUTLOOK.COM'."
        $script:GoneDn   = '/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=f2bb7dfe65834a758b4fde49a010aab7-mexample'
        $script:GoneRcpt = ('"Mike Example" [EX:{0}]' -f $script:GoneDn)
    }
    AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-TPState }

    Context 'Test-TPExoNotFoundError recognizes only the Exchange not-found error' {
        It 'recognizes the Exchange Online module shape (|Type|Message) in the message' {
            $rec = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new($script:NotFoundMessage), 'Write-ErrorMessage', 'NotSpecified', $null)
            & $script:Mod { param($r) Test-TPExoNotFoundError -ErrorRecord $r } $rec | Should -BeTrue
        }
        It 'recognizes the FailureCategory form in the fully qualified error id' {
            $rec = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('The operation could not be performed.'),
                '[Server=X,RequestId=Y,TimeStamp=Z] [FailureCategory=Cmdlet-ManagementObjectNotFoundException] Write-ErrorMessage', 'ObjectNotFound', $null)
            & $script:Mod { param($r) Test-TPExoNotFoundError -ErrorRecord $r } $rec | Should -BeTrue
        }
        It 'recognizes the module 3.x REST shape, ||Message with the type blank, as the 2026-10-15 live run returned it (either apostrophe)' {
            foreach ($apos in @("'", [string][char]0x2019)) {
                $m = "||The operation couldn{0}t be performed because object '/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=f2bb7dfe65834a758b4fde49a010aab7-mwolf' couldn{0}t be found on 'BL4PR06A03DC003.NAMPR06A003.prod.outlook.com'." -f $apos
                $rec = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new($m), 'x', 'NotSpecified', $null)
                & $script:Mod { param($r) Test-TPExoNotFoundError -ErrorRecord $r } $rec | Should -BeTrue -Because $m
            }
        }
        It 'does not read any other could-not-be-found or could-not-be-performed wording as a missing recipient' {
            foreach ($m in "The specified folder couldn't be found.", "The operation couldn't be performed because the object is in use.", "A server side error has occurred because of which the operation could not be completed. Please try again after some time.") {
                $rec = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new($m), 'x', 'NotSpecified', $null)
                & $script:Mod { param($r) Test-TPExoNotFoundError -ErrorRecord $r } $rec | Should -BeFalse -Because $m
            }
        }
        It 'does not read the ObjectNotFound CATEGORY as a missing recipient: a missing command reports it too' {
            $ex  = [System.Management.Automation.CommandNotFoundException]::new("The term 'Get-Recipient' is not recognized")
            $rec = [System.Management.Automation.ErrorRecord]::new($ex, 'CommandNotFoundException', 'ObjectNotFound', $null)
            & $script:Mod { param($r) Test-TPExoNotFoundError -ErrorRecord $r } $rec | Should -BeFalse
        }
        It 'does not recognize throttling or a dropped session' {
            foreach ($m in 'The request was throttled. Try again later.', 'The remote server returned an error: (401) Unauthorized.', 'Object reference not set to an instance of an object.') {
                $rec = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new($m), 'x', 'NotSpecified', $null)
                & $script:Mod { param($r) Test-TPExoNotFoundError -ErrorRecord $r } $rec | Should -BeFalse -Because $m
            }
        }
    }

    Context 'Resolve-TPExoRecipient: three answers' {
        BeforeAll {
            # A Get-Recipient stand-in that records every call and answers by $script:RcptMode:
            #   NotFound  Identity throws the not-found error; Filter returns nothing
            #   X500      Identity throws the not-found error; Filter returns a mail contact
            #   Throttled Identity throws a throttling error; Filter returns nothing
            #   Found     Identity returns a mailbox
            Inject 'Get-Recipient' @'
[CmdletBinding()] param([string] $Identity, [string] $Filter, [object] $ResultSize)
$script:RcptCalls.Add([ordered]@{ Identity = $Identity; Filter = $Filter })
if ($PSBoundParameters.ContainsKey('Identity')) {
    switch ($script:RcptMode) {
        'Found'     { return [pscustomobject]@{ PrimarySmtpAddress = 'mike@contoso.com' } }
        'Throttled' { throw [System.Exception]::new('The request was throttled. Try again later.') }
        default     { throw [System.Exception]::new($script:NotFoundMessage) }
    }
}
if ($script:RcptMode -eq 'X500') { return [pscustomobject]@{ ExternalEmailAddress = 'SMTP:mike@evil.tld' } }
return
'@
            & $script:Mod { param($m) $script:NotFoundMessage = $m } $script:NotFoundMessage
            $script:GetRcpt = & $script:Mod { Get-Command Get-Recipient }
            function script:Resolve { param([string] $Lookup, [string] $Mode)
                & $script:Mod { param($l, $m, $c) $script:RcptMode = $m; $script:RcptCalls = [System.Collections.Generic.List[object]]::new(); Resolve-TPExoRecipient -Lookup $l -Command $c } $Lookup $Mode $script:GetRcpt }
            # Callers wrap this in @(): a one-element list unrolls to its hashtable, whose .Count is its key count.
            function script:Calls { & $script:Mod { @($script:RcptCalls) } }
        }
        AfterAll { Remove 'Get-Recipient' }

        It 'answers $null for a legacy DN only after both the Identity and the X500 lookup found nothing' {
            Resolve $script:GoneDn 'NotFound' | Should -BeNullOrEmpty
            $calls = @(Calls)
            $calls.Count | Should -Be 2
            $calls[0].Identity | Should -Be $script:GoneDn
            $calls[1].Filter   | Should -Be ("EmailAddresses -eq 'X500:{0}'" -f $script:GoneDn)
        }
        It 'returns the object an X500 proxy address routes the DN to (a migrated contact, possibly external)' {
            $hit = Resolve $script:GoneDn 'X500'
            [string](Get-TPObjectField -Item $hit -Key 'ExternalEmailAddress') | Should -Be 'SMTP:mike@evil.tld'
        }
        It 'returns the object the Identity lookup found without asking twice' {
            $hit = Resolve $script:GoneDn 'Found'
            [string](Get-TPObjectField -Item $hit -Key 'PrimarySmtpAddress') | Should -Be 'mike@contoso.com'
            @(Calls).Count | Should -Be 1
        }
        It 'throws when the Identity lookup failed for any reason but not-found and the X500 lookup found nothing' {
            { Resolve $script:GoneDn 'Throttled' } | Should -Throw -ExpectedMessage '*throttled*'
        }
        It 'throws with no Exchange Online session instead of answering $null' {
            { & $script:Mod { Resolve-TPExoRecipient -Lookup '/o=x/cn=y' -Command $null } } | Should -Throw -ExpectedMessage '*no Exchange Online session*'
        }
        It 'doubles an apostrophe in the DN inside the OPATH filter and refuses a control character' {
            Resolve "/o=ExchangeLabs/ou=x/cn=Recipients/cn=o'brien" 'NotFound' | Should -BeNullOrEmpty
            @(Calls)[1].Filter | Should -Be "EmailAddresses -eq 'X500:/o=ExchangeLabs/ou=x/cn=Recipients/cn=o''brien'"
            { Resolve "/o=x/cn=y$([char]0x202E)" 'NotFound' } | Should -Throw -ExpectedMessage '*control or format character*'
            @(Calls).Count | Should -Be 0 -Because 'a refused identifier never reaches the directory'
        }
        It 'refuses a DN holding a typographic quotation mark, which a filter could read as the closing quote' {
            foreach ($cp in 0x2018, 0x2019, 0x201A, 0x201B) {
                $dn = "/o=x/cn=a$([char]$cp) -or Name -like $([char]$cp)*"
                { Resolve $dn 'NotFound' } | Should -Throw -ExpectedMessage '*typographic quotation mark*'
                @(Calls).Count | Should -Be 0 -Because 'a refused identifier never reaches the directory, by Identity or by Filter'
            }
        }
        It 'does not ask the X500 lookup for a display name, and answers $null when the name is unknown' {
            Resolve 'Sales Team' 'NotFound' | Should -BeNullOrEmpty
            @(Calls).Count | Should -Be 1
        }
    }

    Context 'Collector: the real sweep produces IsOrphaned from Get-Recipient''s answers' {
        BeforeAll {
            Inject 'Get-AcceptedDomain' '[pscustomobject]@{ DomainName = "contoso.com" }'
            Inject 'Get-OrganizationConfig' '[pscustomobject]@{ InPlaceHolds = @() }'
            Inject 'Get-Mailbox' '[CmdletBinding()] param([string] $Filter, [object] $ResultSize) if ($PSBoundParameters.ContainsKey("Filter")) { return } [pscustomobject]@{ UserPrincipalName = "cathy@contoso.com"; DisplayName = "Cathy"; RecipientTypeDetails = "UserMailbox"; LitigationHoldEnabled = $false; InPlaceHolds = @(); RetentionPolicy = "Default MRM Policy"; RetainDeletedItemsFor = "14.00:00:00" }'
            Inject 'Get-InboxRule' '[CmdletBinding()] param([string] $Mailbox) [pscustomobject]@{ Name = "Tribune feed"; Enabled = $true; Priority = 1; ForwardTo = @($script:PatRcpt, $script:GoneRcpt); ForwardAsAttachmentTo = $null; RedirectTo = $null }'
            Inject 'Get-Recipient' @'
[CmdletBinding()] param([string] $Identity, [string] $Filter, [object] $ResultSize)
if ($PSBoundParameters.ContainsKey('Identity')) {
    if ($script:RcptMode -eq 'Throttled') { throw [System.Exception]::new('The request was throttled. Try again later.') }
    throw [System.Exception]::new($script:NotFoundMessage)
}
if ($script:RcptMode -eq 'X500') { return [pscustomobject]@{ ExternalEmailAddress = 'SMTP:mike@evil.tld' } }
return
'@
            & $script:Mod { param($m, $g, $p) $script:NotFoundMessage = $m; $script:GoneRcpt = $g; $script:PatRcpt = $p } $script:NotFoundMessage $script:GoneRcpt '"Pat Internal" [SMTP:pat@contoso.com]'
            $script:GetRcpt = & $script:Mod { Get-Command Get-Recipient }
            function script:Sweep { param([string] $Mode, [switch] $NoSession)
                $cmd = if ($NoSession) { $null } else { $script:GetRcpt }
                Mock -ModuleName 'TenantPosture' Get-TPExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
                Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-Recipient' } -MockWith { [pscustomobject]@{ Command = $cmd; Source = 'ExchangeOnline' } }.GetNewClosure()
                & $script:Mod { param($m) $script:RcptMode = $m } $Mode
                $r = Invoke-TPCollectEXOInventory
                $r.Data.SectionStatus.InboxRulesForwarding | Should -Be 'Collected'
                # Clear-TPState wipes the exceptions the sweep registered; keep them for the assertions.
                $script:SweepExceptions = @(Get-TPExceptions | Where-Object { $_.Source -eq 'EXO-RecipientLookup' })
                Clear-TPState
                Set-TPRawData -Key 'EXO-Inventory' -Data $r
                $r }
        }
        AfterAll { foreach ($n in 'Get-AcceptedDomain', 'Get-OrganizationConfig', 'Get-Mailbox', 'Get-InboxRule', 'Get-Recipient') { Remove $n } }

        It 'files a DN the directory holds nothing for as Orphaned, and EXO-7.2 is a Gap that names the rule (was: not assessed)' {
            $r = Sweep 'NotFound'
            $rule = @($r.Data.InboxRulesForwarding)[0]
            $rule.IsOrphaned | Should -BeTrue
            $rule.IsUnresolved | Should -BeFalse
            $rule.IsExternal | Should -BeFalse
            @($rule.OrphanedRecipients) | Should -Be @($script:GoneRcpt)
            @($rule.UnresolvedRecipients).Count | Should -Be 0
            @($script:SweepExceptions).Count | Should -Be 0 -Because 'the directory answered; nothing failed'
            $f = Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2'
            $f.State    | Should -Be 'Gap'
            $f.Severity | Should -Be 'Medium'
            $f.Detail   | Should -Match "cathy@contoso\.com rule 'Tribune feed' forwards to Mike Example"
            $f.Detail   | Should -Match 'not delivered'
            $f.Detail   | Should -Not -Match 'EX:/o='
            $f.Detail   | Should -Not -Match '(?i)not assessed'
            @($f.AffectedObjects).Count | Should -Be 1
        }
        It 'files the module 3.x REST shape (||Message, type blank) as Orphaned too: the 2026-10-15 live run left two such rules not assessed' {
            $live = "||The operation couldn't be performed because object '{0}' couldn't be found on 'BL4PR06A03DC003.NAMPR06A003.prod.outlook.com'." -f $script:GoneDn
            & $script:Mod { param($m) $script:NotFoundMessage = $m } $live
            try {
                $r = Sweep 'NotFound'
                $rule = @($r.Data.InboxRulesForwarding)[0]
                $rule.IsOrphaned   | Should -BeTrue
                $rule.IsUnresolved | Should -BeFalse
                @($script:SweepExceptions).Count | Should -Be 0 -Because 'the directory answered in the REST wording; nothing failed'
                $f = Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2'
                $f.State    | Should -Be 'Gap'
                $f.Severity | Should -Be 'Medium'
                $f.Detail   | Should -Not -Match '(?i)not assessed'
            } finally { & $script:Mod { param($m) $script:NotFoundMessage = $m } $script:NotFoundMessage }
        }
        It 'classifies a DN an X500 proxy address still routes by the object it reaches: external here, never Orphaned' {
            $r = Sweep 'X500'
            $rule = @($r.Data.InboxRulesForwarding)[0]
            $rule.IsExternal | Should -BeTrue
            $rule.IsOrphaned | Should -BeFalse
            @($rule.ExternalRecipients) | Should -Be @($script:GoneRcpt)
            (Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2').CurrentValue | Should -Be '1 inbox rule(s) forwarding externally'
        }
        It 'keeps a lookup that failed as Unresolved, records why, and leaves the control not assessed' {
            $r = Sweep 'Throttled'
            $rule = @($r.Data.InboxRulesForwarding)[0]
            $rule.IsUnresolved | Should -BeTrue
            $rule.IsOrphaned | Should -BeFalse
            $why = @($script:SweepExceptions)
            $why.Count | Should -Be 1
            $why[0].Message | Should -Match 'throttled'
            (Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'NotApplicable'
        }
        It 'with no Exchange Online session the recipient is Unresolved and the reason is recorded' {
            $r = Sweep 'NotFound' -NoSession
            @($r.Data.InboxRulesForwarding)[0].IsUnresolved | Should -BeTrue
            @($script:SweepExceptions)[0].Message | Should -Match 'no Exchange Online session'
        }
    }

    Context 'Evaluator: orphaned rules beside external, unresolved and disabled ones' {
        BeforeAll {
            function script:Rule { param([string] $Mbx, [string] $Name, [string[]] $External = @(), [string[]] $Unresolved = @(), [string[]] $Orphaned = @(), [bool] $Enabled = $true)
                @{ Mailbox = $Mbx; RuleName = $Name; Enabled = $Enabled
                   ExternalRecipients = $External; UnresolvedRecipients = $Unresolved; OrphanedRecipients = $Orphaned
                   IsExternal = ($External.Count -gt 0); IsUnresolved = ($Unresolved.Count -gt 0); IsOrphaned = ($Orphaned.Count -gt 0) } }
            function script:Inv { param([object[]] $Rules, [hashtable] $Stats = @{ MailboxesScanned = 10 })
                Set-TPRawData -Key 'EXO-Inventory' -Data (Raw @{ UnparseableRules = @(); Stats = $Stats; InboxRulesForwarding = @($Rules); SectionStatus = @{ InboxRulesForwarding = 'Collected' } }) }
        }

        It 'orphaned beside unresolved stays not assessed, and still names the orphaned rule' {
            Inv @((Rule 'a@contoso.com' 'Old feed' -Orphaned @('"Gone" [EX:/o=x/cn=gone]')), (Rule 'b@contoso.com' 'Legacy' -Unresolved @('"Who" [EX:/o=x/cn=who]')))
            $f = Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match "b@contoso\.com rule 'Legacy' forwards to Who"
            $f.Detail | Should -Match "a@contoso\.com rule 'Old feed' forwards to Gone"
            @($f.AffectedObjects).Count | Should -Be 2
        }
        It 'a rule with both an orphaned and an unresolved recipient is a blind spot, not an orphaned rule' {
            Inv @((Rule 'a@contoso.com' 'Mixed' -Orphaned @('"Gone" [EX:/o=x/cn=gone]') -Unresolved @('"Who" [EX:/o=x/cn=who]')))
            (Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'NotApplicable'
        }
        It 'external rules are counted and the orphaned rule is named beside them, not counted' {
            Inv @((Rule 'a@contoso.com' 'Exfil' -External @('"x" [SMTP:x@evil.tld]')), (Rule 'b@contoso.com' 'Old feed' -Orphaned @('"Gone" [EX:/o=x/cn=gone]')))
            $f = Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2'
            $f.State        | Should -Be 'Gap'
            $f.Severity     | Should -Be 'High'
            $f.CurrentValue | Should -Be '1 inbox rule(s) forwarding externally'
            $f.Detail       | Should -Match "1 further rule\(s\) forward to a recipient the directory no longer holds.*b@contoso\.com rule 'Old feed' forwards to Gone"
            @($f.AffectedObjects).Count | Should -Be 2
            @($f.AffectedObjects)[1].Recipients | Should -Match 'no longer in the directory'
        }
        It 'a disabled orphaned rule is still named, as disabled' {
            Inv @((Rule 'a@contoso.com' 'Old feed' -Orphaned @('"Gone" [EX:/o=x/cn=gone]') -Enabled $false))
            $f = Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match '\(0 enabled\)'
            $f.Detail | Should -Match "'Old feed' \(disabled\) forwards to Gone"
        }
        It 'an orphaned rule found under a capped sweep is still a Gap, with the sweep limit stated' {
            Inv @((Rule 'a@contoso.com' 'Old feed' -Orphaned @('"Gone" [EX:/o=x/cn=gone]'))) -Stats @{ MailboxesScanned = 2000; ScanLimitReached = $true; MailboxesRuleScanFailed = 0 }
            $f = Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'first 2000 mailboxes'
        }
        It 'result JSON written before IsOrphaned existed replays as before' {
            Inv @(@{ Mailbox = 'a@contoso.com'; RuleName = 'Legacy'; Enabled = $true; IsExternal = $false; IsUnresolved = $true; ExternalRecipients = @(); UnresolvedRecipients = @('"X" [EX:/o=x/cn=y]') })
            (Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'NotApplicable'
            Clear-TPState
            Inv @(@{ Mailbox = 'a@contoso.com'; RuleName = 'Old'; Enabled = $true; IsExternal = $false; ExternalRecipients = @() })
            (Verdict 'Test-TPControlEXOInboxRulesForwarding' 'EXO-7.2').State | Should -Be 'Satisfied'
        }
    }
}

# ── DEF-4.4: the Priority account tag is read, not screenshotted ──────────────────────
# The evaluator said for a year that the tag "is not exposed by any supported Graph/EXO
# read API" and asked the assessor for a portal screenshot. Microsoft documents
# `Get-User -IsVIP` as the way to list priority accounts and `Get-EmailTenantSettings`
# EnablePriorityAccountProtection as the Plan 2 protection switch. The collector cases
# drive the real collector with stand-ins for both, through Get-TPExoCommand, so the
# verdict rests on the real read path and never on a fixture that pre-computes it.
Describe 'DEF-4.4 reads the Priority account tag' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        function script:Raw { param([hashtable] $Data, [bool] $Success = $true) [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-01T00:00:00Z'; Success = $Success; Data = $Data } }
        function script:Verdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
        # The stand-in commands carry their data as closures (never $script: variables, which a
        # mock body does not share with the test file), and the mock bodies capture the commands
        # the same way, as the orphaned-recipient cases above do.
        function script:Collect {
            param([object[]] $Vips = @(), [object] $Settings = $null, [switch] $NoGetUser, [switch] $NoSettings)
            $vipRows = @($Vips)
            $getUserCommand = {
                [CmdletBinding()] param([switch] $IsVIP, [object] $ResultSize)
                if (-not $IsVIP) { throw 'the collector must ask for -IsVIP, never list every user' }
                $vipRows
            }.GetNewClosure()
            $settingsRow = $Settings
            $settingsCommand = { [CmdletBinding()] param() $settingsRow }.GetNewClosure()
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            if (-not $NoGetUser) {
                Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-User' } -MockWith {
                    [pscustomobject]@{ Source = 'ExchangeOnline'; Command = $getUserCommand }
                }.GetNewClosure()
            }
            if (-not $NoSettings) {
                Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-EmailTenantSettings' } -MockWith {
                    [pscustomobject]@{ Source = 'ExchangeOnline'; Command = $settingsCommand }
                }.GetNewClosure()
            }
            $r = Invoke-TPCollectDefender
            $r.Success | Should -BeTrue
            $r
        }
        $script:TwoVips = @(
            [pscustomobject]@{ DisplayName = 'Chief Example'; UserPrincipalName = 'ceo@contoso.com'; RecipientTypeDetails = 'UserMailbox' },
            [pscustomobject]@{ DisplayName = 'Finance Lead';  UserPrincipalName = 'cfo@contoso.com'; RecipientTypeDetails = 'UserMailbox' })
    }
    AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-TPState }

    Context 'Collector: Get-User -IsVIP and Get-EmailTenantSettings through the Exchange Online session' {
        It 'stores the tagged accounts and the protection switch, and the control is Satisfied (was: manual verification)' {
            $r = Collect -Vips $script:TwoVips -Settings ([pscustomobject]@{ EnablePriorityAccountProtection = $true })
            $pa = $r.Data['PriorityAccounts']
            $pa.Available | Should -BeTrue
            $pa.Count | Should -Be 2
            @($pa.Accounts | ForEach-Object { $_.UserPrincipalName }) | Should -Be @('ceo@contoso.com', 'cfo@contoso.com')
            $pa.ProtectionRead | Should -BeTrue
            $pa.ProtectionEnabled | Should -BeTrue
            $f = Verdict 'Test-TPControlDefenderPriorityAccounts' 'DEF-4.4'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'ceo@contoso\.com, cfo@contoso\.com'
            $f.Detail | Should -Match 'protection is on'
            $f.Detail | Should -Not -Match '(?i)manual verification|screenshot'
        }
        It 'no tagged account is a Gap, not a screenshot request' {
            Collect -Vips @() -Settings ([pscustomobject]@{ EnablePriorityAccountProtection = $true }) | Out-Null
            $f = Verdict 'Test-TPControlDefenderPriorityAccounts' 'DEF-4.4'
            $f.State        | Should -Be 'Gap'
            $f.CurrentValue | Should -Be '0 priority accounts tagged'
            $f.Detail       | Should -Match 'No account carries the Priority account tag'
        }
        It 'tagged accounts with the protection switch read as off is Partial, naming the switch' {
            Collect -Vips $script:TwoVips -Settings ([pscustomobject]@{ EnablePriorityAccountProtection = $false }) | Out-Null
            $f = Verdict 'Test-TPControlDefenderPriorityAccounts' 'DEF-4.4'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'EnablePriorityAccountProtection = False'
        }
        It 'a switch that could not be read is context, never a shortfall: the tag verdict stands' {
            $r = Collect -Vips $script:TwoVips -NoSettings
            $r.Data['PriorityAccounts'].ProtectionRead | Should -BeFalse
            $f = Verdict 'Test-TPControlDefenderPriorityAccounts' 'DEF-4.4'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'was not read'
            $f.Detail | Should -Match 'Get-EmailTenantSettings is not available'
        }
        It 'a string-valued switch ("True") is read as on, and anything else is not read' {
            Collect -Vips $script:TwoVips -Settings ([pscustomobject]@{ EnablePriorityAccountProtection = 'True' }) | Out-Null
            (Verdict 'Test-TPControlDefenderPriorityAccounts' 'DEF-4.4').Detail | Should -Match 'protection is on'
            Clear-TPState
            $r = Collect -Vips $script:TwoVips -Settings ([pscustomobject]@{ EnablePriorityAccountProtection = 'Maybe' })
            $r.Data['PriorityAccounts'].ProtectionRead | Should -BeFalse
            $r.Data['PriorityAccounts'].ProtectionError | Should -Match 'not returned'
        }
        It 'with no Get-User in the session the control is not assessed, with the reason recorded' {
            $r = Collect -NoGetUser
            $r.Data['PriorityAccounts'].Available | Should -BeFalse
            @(Get-TPExceptions | Where-Object { $_.Source -eq 'Defender-PriorityAccounts' }).Count | Should -Be 1
            $f = Verdict 'Test-TPControlDefenderPriorityAccounts' 'DEF-4.4'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Get-User -IsVIP failed'
            $f.Detail | Should -Match 'not available in the Exchange Online session'
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0 -Because 'an uncited not-assessed finding vanishes from the NIST rollup'
        }
    }

    Context 'Evaluator: replay and failure shapes' {
        It 'a results file from before the read is not assessed, never a verdict' {
            Set-TPRawData -Key 'Defender-Policies' -Data (Raw @{ AntiPhishing = @{ Available = $true; Policies = @(); Rules = @() } })
            $f = Verdict 'Test-TPControlDefenderPriorityAccounts' 'DEF-4.4'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'predate'
        }
        It 'a failed read with Available = false is not assessed and names the failure' {
            Set-TPRawData -Key 'Defender-Policies' -Data (Raw @{ PriorityAccounts = @{ Available = $false; Error = 'The request was throttled.' } })
            $f = Verdict 'Test-TPControlDefenderPriorityAccounts' 'DEF-4.4'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'throttled'
        }
        It 'the sample names at most five accounts and counts the rest' {
            $many = @(1..8 | ForEach-Object { @{ DisplayName = "User $_"; UserPrincipalName = "user$_@contoso.com"; RecipientType = 'UserMailbox' } })
            Set-TPRawData -Key 'Defender-Policies' -Data (Raw @{ PriorityAccounts = @{ Available = $true; Count = 8; Accounts = $many; ProtectionRead = $true; ProtectionEnabled = $true; ProtectionError = '' } })
            $f = Verdict 'Test-TPControlDefenderPriorityAccounts' 'DEF-4.4'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'user5@contoso\.com and 3 more'
            $f.Detail | Should -Not -Match 'user6@contoso\.com'
        }
    }
}

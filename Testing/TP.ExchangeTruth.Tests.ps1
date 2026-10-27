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
                DkimSigningConfigs = @(@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'; Selector1KeySize = 1024; Selector2KeySize = 1024 })
                SectionStatus = @{ DkimSigningConfigs = 'Collected'; AcceptedDomains = 'Collected' } })
            (Verdict 'Test-TPControlEXODKIM' 'EXO-1.4').State | Should -Be 'Partial'
        }
        It 'one 2048-bit selector beside a 1024-bit one is a rotation in progress, not a weakness' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ AcceptedDomains = $script:Accepted
                DkimSigningConfigs = @(@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'; Selector1KeySize = 1024; Selector2KeySize = 2048 })
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
            Set-TPRawData -Key 'Purview' -Data (Raw @{ SectionStatus = @{ AuditRetentionPolicies = 'Collected' }; AuditRetentionPolicies = @() })
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

    Context 'EXO-3.2 outbound spam' {
        It 'NotifyOutboundSpam = False (Microsoft''s recommended value) never costs the verdict; the alert policy is reported as context' {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (Raw @{ OutboundSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; NotifyOutboundSpam = $false
                    RecipientLimitExternalPerHour = 500; RecipientLimitInternalPerHour = 1000; RecipientLimitPerDay = 1000; ActionWhenThresholdReached = 'BlockUser' })
                SectionStatus = @{ OutboundSpamPolicies = 'Collected' } })
            Set-TPRawData -Key 'Purview' -Data (Raw @{ SectionStatus = @{ ProtectionAlerts = 'Collected' }
                ProtectionAlerts = @(@{ Name = 'User restricted from sending email'; Disabled = $false }) })
            $f = Verdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match "Context \(not part of this verdict\): alert policy 'User restricted from sending email' is enabled"
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
        # DISA Entra ID STIG V-270204 (owner's decision 2026-10-26): an enabled member is
        # inactive when its last sign-in (lastSignInDateTime) is more than 35 days old, or it
        # never signed in and was created more than 35 days ago; the tool also counts a last
        # SUCCESSFUL sign-in more than 35 days old, so a sprayed departed account is not active.
        It 'AAD-12.3 applies STIG V-270204 at 35 days, counts a stale last success, and ignores new hires' {
            $now = [datetime]::UtcNow
            & $script:Mod { param($n) $script:Users = @(
                # departed: last success 400 days ago, sprayed 3 days ago
                @{ id = 'u1'; displayName = 'Departed'; userPrincipalName = 'gone@contoso.com'; createdDateTime = $n.AddDays(-900).ToString('o'); assignedLicenses = @(@{ skuId = 'x' })
                   signInActivity = @{ lastSignInDateTime = $n.AddDays(-3).ToString('o'); lastSuccessfulSignInDateTime = $n.AddDays(-400).ToString('o') } },
                # interactive 120 days ago, token refresh yesterday: the STIG reads lastSignInDateTime
                @{ id = 'u2'; displayName = 'Busy'; userPrincipalName = 'sales@contoso.com'; createdDateTime = $n.AddDays(-900).ToString('o'); assignedLicenses = @(@{ skuId = 'x' })
                   signInActivity = @{ lastSignInDateTime = $n.AddDays(-120).ToString('o'); lastNonInteractiveSignInDateTime = $n.AddDays(-1).ToString('o') } },
                # 36 days idle, unlicensed: inactive under the STIG, licensed or not
                @{ id = 'u3'; displayName = 'Idle'; userPrincipalName = 'idle@contoso.com'; createdDateTime = $n.AddDays(-900).ToString('o'); assignedLicenses = @()
                   signInActivity = @{ lastSignInDateTime = $n.AddDays(-36).ToString('o'); lastSuccessfulSignInDateTime = $n.AddDays(-36).ToString('o') } },
                # 34 days idle: active
                @{ id = 'u4'; displayName = 'Recent'; userPrincipalName = 'recent@contoso.com'; createdDateTime = $n.AddDays(-900).ToString('o'); assignedLicenses = @(@{ skuId = 'x' })
                   signInActivity = @{ lastSignInDateTime = $n.AddDays(-34).ToString('o'); lastSuccessfulSignInDateTime = $n.AddDays(-34).ToString('o') } },
                # never signed in, created 36 days ago (signInActivity absent)
                @{ id = 'u5'; displayName = 'Never'; userPrincipalName = 'never@contoso.com'; createdDateTime = $n.AddDays(-36).ToString('o'); assignedLicenses = @(@{ skuId = 'x' }) },
                # new hire, created last week, never signed in (signInActivity absent)
                @{ id = 'u6'; displayName = 'New Hire'; userPrincipalName = 'newhire@contoso.com'; createdDateTime = $n.AddDays(-7).ToString('o'); assignedLicenses = @(@{ skuId = 'x' }) },
                # never signed in, no creation date: not known, counted as undetermined
                @{ id = 'u7'; displayName = 'Unknown'; userPrincipalName = 'unknown@contoso.com'; assignedLicenses = @() }) } $now
            Inject 'Invoke-TPGraphRequest' @'
param([string] $Uri, [string] $Method = 'GET', $Body, $Headers, [string] $OutputType = 'HashTable')
if ($Uri -like '*/users?*userType eq ''Member''*') { return @{ value = @($script:Users) } }
return @{ value = @() }
'@
            try {
                $r = Invoke-TPCollectAADInventory
                $r.Data.SectionStatus.StaleMembers | Should -Be 'Collected'
                $r.Data.StaleMembersThresholdDays | Should -Be 35
                $r.Data.StaleMembersUndetermined | Should -Be 1
                @($r.Data.StaleMembers | ForEach-Object { $_.UPN } | Sort-Object) | Should -Be @('gone@contoso.com', 'idle@contoso.com', 'never@contoso.com', 'sales@contoso.com')
                (@($r.Data.StaleMembers) | Where-Object { $_.UPN -eq 'gone@contoso.com' }).LastSignInBasis | Should -Match 'last successful sign-in 400 days ago'
                (@($r.Data.StaleMembers) | Where-Object { $_.UPN -eq 'never@contoso.com' }).LastSignInBasis | Should -Match 'no sign-in recorded; created 36 days ago'
                Set-TPRawData -Key 'AAD-Inventory' -Data $r
                $f = Verdict 'Test-TPControlInventoryStaleMembers' 'AAD-12.3'
                $f.State | Should -Be 'Gap'
                $f.Detail | Should -Match '4 enabled member account\(s\) are inactive \(3 licensed\)'
                $f.Detail | Should -Match 'V-270204'
                $f.Detail | Should -Match 'Emergency-access .* counted'
                $f.Detail | Should -Match '1 account\(s\) have no sign-in and no readable creation date'
                @($f.AffectedObjects) -join ' ' | Should -Match 'Idle \(idle@contoso.com\) \[unlicensed\]'
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
                MFARegistration = @{ RegistrationDetails = @(@{ UserPrincipalName = 'a@contoso.com'; IsMfaRegistered = $true; IsMfaCapable = $true; IsEnabled = $true }) } })
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

# ── 2026-10-26: five verdicts pinned to the settings their controls claim ────
#   EXO-3.2  outbound sending limits (Microsoft's recommended-settings page,
#            Outbound spam policy table, Standard column) on every policy in force
#   EXO-2.6  shared mailbox sign-in read from Entra accountEnabled; the license
#            heuristic is never a verdict
#   EXO-4.1  custom audit retention policies not read -> not assessed
#   EXO-4.4  SpamZapEnabled / PhishZapEnabled, never the deprecated ZapEnabled
#   DEF-2.1  a preset is on only with BOTH its EOP and its Defender for Office
#            365 rule Enabled
# Helpers carry a J prefix so they never replace the ones above.
Describe 'Exchange and Defender controls judge the settings they claim' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'

        function script:JRaw { param([hashtable] $Data, [bool] $Success = $true) [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-01T00:00:00Z'; Success = $Success; Data = $Data } }
        function script:JVerdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
        # The stand-in is a literal scriptblock, unbound from this file (Ast.GetScriptBlock) so it
        # runs in module scope and reads the module's $script: variables, as the cmdlet's caller does.
        function script:JInject { param([string] $Name, [scriptblock] $Body)
            & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value $b.Ast.GetScriptBlock() } $Name $Body }
        function script:JRemove { param([string] $Name)
            # function:script:X removes nothing inside a module; function:X does.
            & $script:Mod { param($n) Remove-Item -Path "function:$n" -ErrorAction SilentlyContinue } $Name }

        # Microsoft's Standard values for the outbound spam policy.
        function script:JOutbound { param([hashtable] $Over = @{})
            $p = @{ Name = 'Default'; IsDefault = $true; RecommendedPolicyType = ''; Enabled = $true; AutoForwardingMode = 'Off'
                    NotifyOutboundSpam = $false; NotifyOutboundSpamRecipients = @()
                    RecipientLimitExternalPerHour = 500; RecipientLimitInternalPerHour = 1000; RecipientLimitPerDay = 1000; ActionWhenThresholdReached = 'BlockUser' }
            foreach ($k in $Over.Keys) { if ($null -eq $Over[$k]) { $p.Remove($k) } else { $p[$k] = $Over[$k] } }
            $p }
        function script:JSetOutbound { param([object[]] $Policies, $Rules = @())
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (JRaw @{ OutboundSpamPolicies = @($Policies); OutboundSpamRules = $Rules
                AcceptedDomains = @(@{ DomainName = 'contoso.com' })
                SectionStatus = @{ OutboundSpamPolicies = 'Collected'; AcceptedDomains = 'Collected' } }) }
    }
    BeforeEach { Clear-TPState }
    AfterAll   { Clear-TPState }

    Context 'EXO-3.2 outbound sending limits' {
        It 'Microsoft Standard values on the default policy are Satisfied; the notification is context only' {
            JSetOutbound @(JOutbound)
            $f = JVerdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'RecipientLimitExternalPerHour = 500'
            $f.Detail | Should -Match 'Context \(not part of this verdict\)'
        }
        It 'the Strict values (400, 800, 800) are lower and pass' {
            JSetOutbound @(JOutbound @{ RecipientLimitExternalPerHour = 400; RecipientLimitInternalPerHour = 800; RecipientLimitPerDay = 800 })
            (JVerdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2').State | Should -Be 'Satisfied'
        }
        It 'the shipped defaults (0 = service default, BlockUserForToday) are a Gap even with NotifyOutboundSpam on (was: Satisfied on the notification alone)' {
            JSetOutbound @(JOutbound @{ RecipientLimitExternalPerHour = 0; RecipientLimitInternalPerHour = 0; RecipientLimitPerDay = 0
                ActionWhenThresholdReached = 'BlockUserForToday'; NotifyOutboundSpam = $true; NotifyOutboundSpamRecipients = @('admin@contoso.com') })
            $f = JVerdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'service default'
            $f.Detail | Should -Match 'BlockUserForToday'
        }
        It 'boundaries: 501 external, 1001 internal and 1001 per day each fall short; 500/1000/1000 do not' {
            foreach ($case in @(@{ RecipientLimitExternalPerHour = 501 }, @{ RecipientLimitInternalPerHour = 1001 }, @{ RecipientLimitPerDay = 1001 })) {
                Clear-TPState
                JSetOutbound @(JOutbound $case)
                $f = JVerdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2'
                $f.State  | Should -Be 'Partial' -Because "$(@($case.Keys)[0]) above the Standard value is a shortfall beside the settings that meet it"
                $f.Detail | Should -Match "Shortfall: Default: $(@($case.Keys)[0]) = $(@($case.Values)[0])"
            }
        }
        It 'judges every policy in force: a custom policy with an enabled rule and default limits is a shortfall' {
            JSetOutbound @((JOutbound), (JOutbound @{ Name = 'Sales'; IsDefault = $false; RecipientLimitPerDay = 0 })) @(@{ Name = 'Sales'; HostedOutboundSpamFilterPolicy = 'Sales'; State = 'Enabled' })
            $f = JVerdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Sales: RecipientLimitPerDay = 0'
            @($f.AffectedObjects).Count | Should -Be 1
        }
        It 'a custom policy whose rule is disabled applies to no one and is not judged' {
            JSetOutbound @((JOutbound), (JOutbound @{ Name = 'Sales'; IsDefault = $false; RecipientLimitPerDay = 0 })) @(@{ Name = 'Sales'; HostedOutboundSpamFilterPolicy = 'Sales'; State = 'Disabled' })
            (JVerdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2').State | Should -Be 'Satisfied'
        }
        It 'a limit not returned (an older results file) is not assessed, never a pass' {
            JSetOutbound @(JOutbound @{ RecipientLimitPerDay = $null })
            $f = JVerdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Not assessed: Default: RecipientLimitPerDay was not returned'
            Clear-TPState
            JSetOutbound @(JOutbound @{ ActionWhenThresholdReached = $null })
            (JVerdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2').State | Should -Be 'NotApplicable'
        }
        It 'a shortfall is still reported when another value was not read' {
            JSetOutbound @(JOutbound @{ RecipientLimitPerDay = $null; ActionWhenThresholdReached = 'Alert' })
            (JVerdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2').State | Should -Be 'Partial'
        }
        It 'the collector keeps an omitted limit as not read, never 0, and stores the returned values' {
            JInject 'Get-HostedOutboundSpamFilterPolicy' { [pscustomobject]@{ Name = 'Default'; IsDefault = $true; Enabled = $true; AutoForwardingMode = 'Off'; NotifyOutboundSpam = $false; NotifyOutboundSpamRecipients = @(); RecipientLimitExternalPerHour = 500; RecipientLimitInternalPerHour = 1000; ActionWhenThresholdReached = 'BlockUser' } }
            JInject 'Get-HostedOutboundSpamFilterRule' { @() }
            try {
                $r = Invoke-TPCollectEXOMailboxConfig
                $r.Data.SectionStatus.OutboundSpamPolicies | Should -Be 'Collected'
                $p = $r.Data.OutboundSpamPolicies[0]
                $p.RecipientLimitExternalPerHour | Should -Be 500
                $p.RecipientLimitInternalPerHour | Should -Be 1000
                $p.RecipientLimitPerDay          | Should -BeNullOrEmpty -Because 'an omitted value is not the service default'
                $p.ActionWhenThresholdReached    | Should -Be 'BlockUser'
                Clear-TPState
                Set-TPRawData -Key 'EXO-MailboxConfig' -Data $r
                (JVerdict 'Test-TPControlEXOOutboundLimits' 'EXO-3.2').State | Should -Be 'NotApplicable'
            } finally { JRemove 'Get-HostedOutboundSpamFilterPolicy'; JRemove 'Get-HostedOutboundSpamFilterRule' }
        }
    }

    Context 'EXO-2.6 shared mailbox sign-in' {
        BeforeAll {
            JInject 'Get-Mailbox' { param($RecipientTypeDetails, $ResultSize, $Identity, [Parameter(ValueFromRemainingArguments)] $Rest) if ($RecipientTypeDetails -eq 'SharedMailbox') { @($script:SharedMbx) } else { @() } }
        }
        AfterAll { JRemove 'Get-Mailbox' }

        It 'every shared mailbox read from Entra as blocked is Satisfied' {
            & $script:Mod { $script:SharedMbx = @([pscustomobject]@{ DisplayName = 'Info'; PrimarySmtpAddress = 'info@contoso.com'; Guid = 'g1'; UserPrincipalName = 'info@contoso.com'; SkuAssigned = $false }) }
            Set-TPRawData -Key 'AAD-Users' -Data (JRaw @{ Users = @(@{ UserPrincipalName = 'info@contoso.com'; AccountEnabled = $false }) })
            $r = Invoke-TPCollectEXOInventory
            $r.Data.SectionStatus.SharedMailboxes | Should -Be 'Collected'
            @($r.Data.SharedMailboxUnconfirmed).Count | Should -Be 0
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            $f = JVerdict 'Test-TPControlEXOSharedMailbox' 'EXO-2.6'
            $f.State | Should -Be 'Satisfied'
        }
        It 'Entra data unavailable: an unlicensed mailbox the heuristic does not flag is not assessed (was: Satisfied)' {
            & $script:Mod { $script:SharedMbx = @([pscustomobject]@{ DisplayName = 'Info'; PrimarySmtpAddress = 'info@contoso.com'; Guid = 'g1'; UserPrincipalName = 'info@contoso.com'; SkuAssigned = $false }) }
            $r = Invoke-TPCollectEXOInventory
            @($r.Data.SharedMailboxSignIn).Count | Should -Be 0 -Because 'the license heuristic does not fire'
            $r.Data.SharedMailboxUnconfirmed[0].Reason | Should -Be 'AAD-Users data unavailable'
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            $f = JVerdict 'Test-TPControlEXOSharedMailbox' 'EXO-2.6'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'info@contoso\.com'
        }
        It 'Entra data unavailable: a mailbox the license heuristic flags is not assessed, never a Partial verdict' {
            & $script:Mod { $script:SharedMbx = @([pscustomobject]@{ DisplayName = 'Info'; PrimarySmtpAddress = 'info@contoso.com'; Guid = 'g1'; UserPrincipalName = 'info@contoso.com'; SkuAssigned = $true }) }
            $r = Invoke-TPCollectEXOInventory
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            $f = JVerdict 'Test-TPControlEXOSharedMailbox' 'EXO-2.6'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'license or reconciliation flag'
        }
        It 'a mailbox not found in AAD-Users is not assessed; a confirmed enabled one is still the Gap' {
            & $script:Mod { $script:SharedMbx = @(
                [pscustomobject]@{ DisplayName = 'Info'; PrimarySmtpAddress = 'info@contoso.com'; Guid = 'g1'; UserPrincipalName = 'info@contoso.com' },
                [pscustomobject]@{ DisplayName = 'HR'; PrimarySmtpAddress = 'hr@contoso.com'; Guid = 'g2'; UserPrincipalName = 'hr@contoso.com' }) }
            Set-TPRawData -Key 'AAD-Users' -Data (JRaw @{ Users = @(@{ UserPrincipalName = 'info@contoso.com'; AccountEnabled = $false }) })
            $r = Invoke-TPCollectEXOInventory
            $r.Data.SharedMailboxUnconfirmed[0].Reason | Should -Be 'Not found in AAD-Users'
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            (JVerdict 'Test-TPControlEXOSharedMailbox' 'EXO-2.6').State | Should -Be 'NotApplicable'

            Clear-TPState
            Set-TPRawData -Key 'AAD-Users' -Data (JRaw @{ Users = @(@{ UserPrincipalName = 'info@contoso.com'; AccountEnabled = $true }) })
            $r = Invoke-TPCollectEXOInventory
            Set-TPRawData -Key 'EXO-Inventory' -Data $r
            $f = JVerdict 'Test-TPControlEXOSharedMailbox' 'EXO-2.6'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'A further 1 shared mailbox'
        }
        It 'an older results file without the unconfirmed list is not assessed' {
            Set-TPRawData -Key 'EXO-Inventory' -Data (JRaw @{ AllSharedMailboxes = @(@{ DisplayName = 'Info'; UPN = 'info@contoso.com' }); SharedMailboxSignIn = @()
                SectionStatus = @{ AllSharedMailboxes = 'Collected'; SharedMailboxes = 'Collected' } })
            (JVerdict 'Test-TPControlEXOSharedMailbox' 'EXO-2.6').State | Should -Be 'NotApplicable'
        }
    }

    Context 'EXO-4.1 audit retention' {
        BeforeEach {
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (JRaw @{ OrganizationConfig = @{ AuditDisabled = $false }; AdminAuditLogConfig = @{ UnifiedAuditLogIngestionEnabled = $true }
                SectionStatus = @{ OrganizationConfig = 'Collected'; AdminAuditLogConfig = 'Collected' } })
        }
        It 'custom audit retention policies not read is not assessed (was: Satisfied)' {
            $f = JVerdict 'Test-TPControlEXOAuditAgeLimit' 'EXO-4.1'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'custom audit retention policies were not read'
            Clear-TPState
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (JRaw @{ OrganizationConfig = @{ AuditDisabled = $false }; AdminAuditLogConfig = @{ UnifiedAuditLogIngestionEnabled = $true }
                SectionStatus = @{ OrganizationConfig = 'Collected'; AdminAuditLogConfig = 'Collected' } })
            Set-TPRawData -Key 'Purview' -Data (JRaw @{ AuditRetentionPolicies = @(); SectionStatus = @{ AuditRetentionPolicies = 'Failed' } })
            (JVerdict 'Test-TPControlEXOAuditAgeLimit' 'EXO-4.1').State | Should -Be 'NotApplicable'
        }
        It 'read with none shortening Exchange records is Satisfied; a 90-day Exchange policy is the Gap' {
            Set-TPRawData -Key 'Purview' -Data (JRaw @{ AuditRetentionPolicies = @(@{ Name = 'Teams 90'; RetentionDuration = 'ThreeMonths'; RetentionDays = 90; RecordTypes = @('MicrosoftTeams') }); SectionStatus = @{ AuditRetentionPolicies = 'Collected' } })
            (JVerdict 'Test-TPControlEXOAuditAgeLimit' 'EXO-4.1').State | Should -Be 'Satisfied'
            Clear-TPState
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (JRaw @{ OrganizationConfig = @{ AuditDisabled = $false }; AdminAuditLogConfig = @{ UnifiedAuditLogIngestionEnabled = $true }
                SectionStatus = @{ OrganizationConfig = 'Collected'; AdminAuditLogConfig = 'Collected' } })
            Set-TPRawData -Key 'Purview' -Data (JRaw @{ AuditRetentionPolicies = @(@{ Name = 'Mail 90'; RetentionDuration = 'ThreeMonths'; RetentionDays = 90; RecordTypes = @('ExchangeItem') }); SectionStatus = @{ AuditRetentionPolicies = 'Collected' } })
            (JVerdict 'Test-TPControlEXOAuditAgeLimit' 'EXO-4.1').State | Should -Be 'Gap'
        }
        It 'an Exchange policy whose duration was not recognized is not assessed, never a pass' {
            Set-TPRawData -Key 'Purview' -Data (JRaw @{ AuditRetentionPolicies = @(@{ Name = 'All'; RetentionDuration = ''; RetentionDays = $null; RecordTypes = @() }); SectionStatus = @{ AuditRetentionPolicies = 'Collected' } })
            (JVerdict 'Test-TPControlEXOAuditAgeLimit' 'EXO-4.1').State | Should -Be 'NotApplicable'
        }
    }

    Context 'EXO-4.4 inbound anti-spam' {
        BeforeAll {
            function script:JSetSpam { param([hashtable] $Over = @{})
                $p = @{ Name = 'Default'; IsDefault = $true; SpamAction = 'MoveToJmf'; BulkThreshold = 6; SpamZapEnabled = $true; PhishZapEnabled = $true }
                foreach ($k in $Over.Keys) { if ($null -eq $Over[$k]) { $p.Remove($k) } else { $p[$k] = $Over[$k] } }
                Set-TPRawData -Key 'EXO-MailboxConfig' -Data (JRaw @{ AntiSpamPolicies = @($p); SectionStatus = @{ AntiSpamPolicies = 'Collected' } }) }
        }
        It 'Standard values with spam and phishing ZAP on are Satisfied' {
            JSetSpam
            (JVerdict 'Test-TPControlEXOAntiSpamInbound' 'EXO-4.4').State | Should -Be 'Satisfied'
        }
        It 'PhishZapEnabled off is a shortfall even when the deprecated ZapEnabled reads True (was: Satisfied)' {
            JSetSpam @{ PhishZapEnabled = $false; ZapEnabled = $true }
            $f = JVerdict 'Test-TPControlEXOAntiSpamInbound' 'EXO-4.4'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'PhishZapEnabled = False'
        }
        It 'only the deprecated ZapEnabled present is not assessed, never credited' {
            JSetSpam @{ SpamZapEnabled = $null; PhishZapEnabled = $null; ZapEnabled = $true }
            (JVerdict 'Test-TPControlEXOAntiSpamInbound' 'EXO-4.4').State | Should -Be 'NotApplicable'
        }
        It 'BulkThreshold 6 passes, 7 falls short, and an absent value is not assessed (was: a pass)' {
            JSetSpam @{ BulkThreshold = 7 }
            (JVerdict 'Test-TPControlEXOAntiSpamInbound' 'EXO-4.4').State | Should -Be 'Partial'
            Clear-TPState; JSetSpam @{ BulkThreshold = $null }
            (JVerdict 'Test-TPControlEXOAntiSpamInbound' 'EXO-4.4').State | Should -Be 'NotApplicable'
        }
        It 'every setting short is a Gap' {
            JSetSpam @{ SpamAction = 'AddXHeader'; BulkThreshold = 9; SpamZapEnabled = $false; PhishZapEnabled = $false }
            (JVerdict 'Test-TPControlEXOAntiSpamInbound' 'EXO-4.4').State | Should -Be 'Gap'
        }
    }

    Context 'DEF-2.1 preset rules' {
        BeforeAll {
            function script:JRule { param([string] $Name, [string] $State)
                [pscustomobject]@{ Name = $Name; State = $State; RecipientDomainIs = @(); SentTo = @(); SentToMemberOf = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() } }
            function script:JRunDefender { param([string] $EopState, [string] $AtpState, [switch] $NoAtpCmdlet)
                & $script:Mod { param($e, $a) $script:EopRules = @($e); $script:AtpRules = @($a) } (JRule 'Standard Preset Security Policy' $EopState) $(if ($AtpState) { JRule 'Standard Preset Security Policy' $AtpState } else { @() })
                JInject 'Get-EOPProtectionPolicyRule' { @($script:EopRules) }
                if (-not $NoAtpCmdlet) { JInject 'Get-ATPProtectionPolicyRule' { @($script:AtpRules) } }
                try { Invoke-TPCollectDefender } finally { JRemove 'Get-EOPProtectionPolicyRule'; JRemove 'Get-ATPProtectionPolicyRule' }
            }
            function script:JSetAccepted { Set-TPRawData -Key 'EXO-MailboxConfig' -Data (JRaw @{ AcceptedDomains = @(@{ DomainName = 'contoso.com' }); SectionStatus = @{ AcceptedDomains = 'Collected' } }) }
        }
        It 'both rules Enabled and applying to everyone is Satisfied' {
            $r = JRunDefender -EopState 'Enabled' -AtpState 'Enabled'
            $r.Data.PresetRules.ATPRead | Should -BeTrue
            Clear-TPState; JSetAccepted; Set-TPRawData -Key 'Defender-Policies' -Data $r
            (JVerdict 'Test-TPControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'Satisfied'
        }
        It 'the EOP rule on and the Defender for Office 365 rule off is Partial (was: Satisfied)' {
            $r = JRunDefender -EopState 'Enabled' -AtpState 'Disabled'
            Clear-TPState; JSetAccepted; Set-TPRawData -Key 'Defender-Policies' -Data $r
            $f = JVerdict 'Test-TPControlDefenderPresetPolicies' 'DEF-2.1'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Defender for Office 365 rule is Disabled'
        }
        It 'the EOP rule on with no Defender rule returned is Partial' {
            $r = JRunDefender -EopState 'Enabled'
            Clear-TPState; JSetAccepted; Set-TPRawData -Key 'Defender-Policies' -Data $r
            (JVerdict 'Test-TPControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'Partial'
        }
        It 'only the Defender rule on is a Gap' {
            $r = JRunDefender -EopState 'Disabled' -AtpState 'Enabled'
            Clear-TPState; JSetAccepted; Set-TPRawData -Key 'Defender-Policies' -Data $r
            (JVerdict 'Test-TPControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'Gap'
        }
        It 'the Defender rules not read (no cmdlet in the session) is not assessed' {
            $r = JRunDefender -EopState 'Enabled' -NoAtpCmdlet
            $r.Data.PresetRules.ATPRead | Should -BeFalse
            Clear-TPState; JSetAccepted; Set-TPRawData -Key 'Defender-Policies' -Data $r
            (JVerdict 'Test-TPControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'NotApplicable'
        }
        It 'an older result without ATPRead and no Defender rules is not assessed; one holding them was read' {
            JSetAccepted
            $eop = @{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; RecipientDomainIs = @(); SentTo = @(); SentToMemberOf = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() }
            Set-TPRawData -Key 'Defender-Policies' -Data (JRaw @{ PresetRules = @{ Available = $true; EOP = @($eop); ATP = @() } })
            (JVerdict 'Test-TPControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'NotApplicable'
            Clear-TPState; JSetAccepted
            $atp = $eop.Clone(); $atp.State = 'Enabled'
            Set-TPRawData -Key 'Defender-Policies' -Data (JRaw @{ PresetRules = @{ Available = $true; EOP = @($eop); ATP = @($atp) } })
            (JVerdict 'Test-TPControlDefenderPresetPolicies' 'DEF-2.1').State | Should -Be 'Satisfied'
        }
        It 'a fully-on Strict preset covering everyone is not undone by a half-on Standard preset' {
            JSetAccepted
            $mk = { param($n, $s) @{ Name = $n; State = $s; RecipientDomainIs = @(); SentTo = @(); SentToMemberOf = @(); ExceptIfSentTo = @(); ExceptIfSentToMemberOf = @(); ExceptIfRecipientDomainIs = @() } }
            Set-TPRawData -Key 'Defender-Policies' -Data (JRaw @{ PresetRules = @{ Available = $true; ATPRead = $true
                EOP = @((& $mk 'Strict Preset Security Policy' 'Enabled'), (& $mk 'Standard Preset Security Policy' 'Enabled'))
                ATP = @((& $mk 'Strict Preset Security Policy' 'Enabled'), (& $mk 'Standard Preset Security Policy' 'Disabled')) } })
            $f = JVerdict 'Test-TPControlDefenderPresetPolicies' 'DEF-2.1'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'Also: Standard Preset Security Policy has its EOP rule on'
        }
    }
}

Describe 'CIS v7.0.0 Exchange and Defender settings no control read before (EXO-10.x, DEF-6.x)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        function script:KRaw { param([hashtable] $Data, [bool] $Success = $true) [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-27T00:00:00Z'; Success = $Success; Data = $Data } }
        function script:KVerdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid }) }
        # Cmdlet stand-ins in MODULE scope; the bodies are raw cmdlet output shapes.
        function script:KInject { param([string] $Name, [string] $Body)
            & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } $Name $Body }
        function script:KRemove { param([string[]] $Name)
            foreach ($n in $Name) { & $script:Mod { param($x) Remove-Item -Path "function:script:$x" -ErrorAction SilentlyContinue } $n } }
        function script:KCollectExo { param([hashtable] $Cmds)
            foreach ($k in $Cmds.Keys) { KInject $k $Cmds[$k] }
            try { $r = Invoke-TPCollectEXOMailboxConfig } finally { KRemove @($Cmds.Keys) }
            $r }
        function script:KCollectDefender { param([hashtable] $Cmds)
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            foreach ($k in $Cmds.Keys) { KInject $k $Cmds[$k] }
            try { $r = Invoke-TPCollectDefender } finally { KRemove @($Cmds.Keys) }
            $r.Success | Should -BeTrue
            $r }
        $script:CisTypes = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/cis-m365-comprehensive-attachment-types.json') -Raw | ConvertFrom-Json).Values)
    }
    BeforeEach { Clear-TPState }
    AfterAll   { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    Context 'Every new control is defined, exported and cites its CIS recommendation' {
        It '<Cid> cites CIS <Cis> and names <Fn>' -TestCases @(
            @{ Cid = 'EXO-10.1'; Cis = '1.3.3';  Fn = 'Test-TPControlEXOCalendarSharing' }
            @{ Cid = 'EXO-10.2'; Cis = '6.5.3';  Fn = 'Test-TPControlEXOOwaStorageProviders' }
            @{ Cid = 'EXO-10.3'; Cis = '2.1.12'; Fn = 'Test-TPControlEXOConnectionIPAllowList' }
            @{ Cid = 'DEF-6.1';  Cis = '2.1.3';  Fn = 'Test-TPControlDefenderInternalMalwareNotify' }
            @{ Cid = 'DEF-6.2';  Cis = '2.1.6';  Fn = 'Test-TPControlDefenderOutboundSpamNotify' }
            @{ Cid = 'DEF-6.3';  Cis = '2.1.11'; Fn = 'Test-TPControlDefenderComprehensiveAttachments' }
            @{ Cid = 'DEF-6.4';  Cis = '2.4.4';  Fn = 'Test-TPControlDefenderTeamsZap' }
        ) {
            $c = Get-TPControlById -ControlId $Cid
            $c | Should -Not -BeNullOrEmpty
            $c.References.CIS | Should -Be $Cis
            $c.EvaluatorFunction | Should -Be $Fn
            (Get-Command $Fn -Module 'TenantPosture' -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty -Because 'the evaluator is exported'
        }
        It 'every new evaluator with no data is not assessed and keeps its citations' {
            foreach ($fn in 'Test-TPControlEXOCalendarSharing', 'Test-TPControlEXOOwaStorageProviders', 'Test-TPControlEXOConnectionIPAllowList',
                            'Test-TPControlDefenderInternalMalwareNotify', 'Test-TPControlDefenderOutboundSpamNotify',
                            'Test-TPControlDefenderComprehensiveAttachments', 'Test-TPControlDefenderTeamsZap') { & $fn | Out-Null }
            $f = @(Get-TPFindings | Where-Object { $_.ControlId -match '^(EXO-10|DEF-6)\.' })
            $f.Count | Should -Be 7
            @($f | Where-Object { $_.State -ne 'NotApplicable' }).Count | Should -Be 0
            @($f | Where-Object { -not $_.FrameworkIds }).Count | Should -Be 0
        }
        It 'the CIS 2.1.11 list holds 186 distinct types' {
            @($script:CisTypes | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique).Count | Should -Be 186
        }
    }

    Context 'EXO-10.1 external calendar sharing (CIS 1.3.3), through the real collector' {
        It 'the Default Sharing Policy enabled is a Gap naming what it shares' {
            $r = KCollectExo @{ 'Get-SharingPolicy' = '[pscustomobject]@{ Name = "Default Sharing Policy"; Default = $true; Enabled = $true; Domains = @("*:CalendarSharingFreeBusySimple", "Anonymous:CalendarSharingFreeBusyReviewer") }' }
            $r.Data.SectionStatus.SharingPolicies | Should -Be 'Collected'
            $f = @(KVerdict 'Test-TPControlEXOCalendarSharing' 'EXO-10.1')[0]
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'Anonymous:CalendarSharingFreeBusyReviewer'
        }
        It 'the default enabled with partner domains only is still a Gap: CIS audits the switch, not the domains' {
            KCollectExo @{ 'Get-SharingPolicy' = '[pscustomobject]@{ Name = "Default Sharing Policy"; Default = $true; Enabled = $true; Domains = @("fabrikam.com:CalendarSharingFreeBusyDetail") }' } | Out-Null
            @(KVerdict 'Test-TPControlEXOCalendarSharing' 'EXO-10.1')[0].State | Should -Be 'Gap'
        }
        It 'the default disabled is Satisfied; another enabled policy limited to a partner domain does not change that' {
            KCollectExo @{ 'Get-SharingPolicy' = '[pscustomobject]@{ Name = "Default Sharing Policy"; Default = $true; Enabled = $false; Domains = @("*:CalendarSharingFreeBusySimple") }; [pscustomobject]@{ Name = "Partners"; Default = $false; Enabled = $true; Domains = @("fabrikam.com:CalendarSharingFreeBusyDetail, ContactsSharing") }' } | Out-Null
            @(KVerdict 'Test-TPControlEXOCalendarSharing' 'EXO-10.1')[0].State | Should -Be 'Satisfied'
        }
        It 'the default disabled beside another enabled policy that publishes anonymously is Partial, naming it' {
            KCollectExo @{ 'Get-SharingPolicy' = '[pscustomobject]@{ Name = "Default Sharing Policy"; Default = $true; Enabled = $false; Domains = @() }; [pscustomobject]@{ Name = "Publishing"; Default = $false; Enabled = $true; Domains = @("Anonymous:CalendarSharingFreeBusySimple") }' } | Out-Null
            $f = @(KVerdict 'Test-TPControlEXOCalendarSharing' 'EXO-10.1')[0]
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match "Publishing"
        }
        It 'Enabled not returned is not assessed, never a pass' {
            KCollectExo @{ 'Get-SharingPolicy' = '[pscustomobject]@{ Name = "Default Sharing Policy"; Default = $true; Domains = @() }' } | Out-Null
            @(KVerdict 'Test-TPControlEXOCalendarSharing' 'EXO-10.1')[0].State | Should -Be 'NotApplicable'
        }
        It 'a failed read is not assessed, and so is an older results file without the section' {
            $r = KCollectExo @{ 'Get-SharingPolicy' = 'throw "The term Get-SharingPolicy is not recognized"' }
            $r.Data.SectionStatus.SharingPolicies | Should -Be 'Failed'
            @(KVerdict 'Test-TPControlEXOCalendarSharing' 'EXO-10.1')[0].State | Should -Be 'NotApplicable'
            Clear-TPState
            Set-TPRawData -Key 'EXO-MailboxConfig' -Data (KRaw @{ SectionStatus = @{ TransportConfig = 'Collected' } })
            @(KVerdict 'Test-TPControlEXOCalendarSharing' 'EXO-10.1')[0].State | Should -Be 'NotApplicable'
        }
    }

    Context 'EXO-10.2 additional storage providers in Outlook on the web (CIS 6.5.3), through the real collector' {
        It "Microsoft's default (True) on the default policy is a Gap" {
            $r = KCollectExo @{ 'Get-OwaMailboxPolicy' = '[pscustomobject]@{ Name = "OwaMailboxPolicy-Default"; IsDefault = $true; AdditionalStorageProvidersAvailable = $true }' }
            $r.Data.SectionStatus.OwaMailboxPolicies | Should -Be 'Collected'
            @(KVerdict 'Test-TPControlEXOOwaStorageProviders' 'EXO-10.2')[0].State | Should -Be 'Gap'
        }
        It 'every policy False is Satisfied' {
            KCollectExo @{ 'Get-OwaMailboxPolicy' = '[pscustomobject]@{ Name = "OwaMailboxPolicy-Default"; IsDefault = $true; AdditionalStorageProvidersAvailable = $false }; [pscustomobject]@{ Name = "Kiosk"; IsDefault = $false; AdditionalStorageProvidersAvailable = $false }' } | Out-Null
            @(KVerdict 'Test-TPControlEXOOwaStorageProviders' 'EXO-10.2')[0].State | Should -Be 'Satisfied'
        }
        It 'the default restricted but another policy allowing providers is Partial, naming it' {
            KCollectExo @{ 'Get-OwaMailboxPolicy' = '[pscustomobject]@{ Name = "OwaMailboxPolicy-Default"; IsDefault = $true; AdditionalStorageProvidersAvailable = $false }; [pscustomobject]@{ Name = "Sales"; IsDefault = $false; AdditionalStorageProvidersAvailable = $true }' } | Out-Null
            $f = @(KVerdict 'Test-TPControlEXOOwaStorageProviders' 'EXO-10.2')[0]
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Sales'
        }
        It 'the property not returned is not assessed' {
            KCollectExo @{ 'Get-OwaMailboxPolicy' = '[pscustomobject]@{ Name = "OwaMailboxPolicy-Default"; IsDefault = $true }' } | Out-Null
            @(KVerdict 'Test-TPControlEXOOwaStorageProviders' 'EXO-10.2')[0].State | Should -Be 'NotApplicable'
        }
    }

    Context 'EXO-10.3 connection filter IP Allow List (CIS 2.1.12), through the real collector' {
        BeforeEach {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
        }
        It 'an IP Allow List with entries is a Gap naming them' {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-HostedConnectionFilterPolicy' } {
                [pscustomobject]@{ Command = { [pscustomobject]@{ Name = 'Default'; IsDefault = $true; EnableSafeList = $false; IPAllowList = @('192.0.2.10', '198.51.100.0/24') } }; Source = 'ExchangeOnline' } }
            (Invoke-TPCollectEXOConnectionFilter).Success | Should -BeTrue
            $f = @(KVerdict 'Test-TPControlEXOConnectionIPAllowList' 'EXO-10.3')[0]
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match '198\.51\.100\.0/24'
        }
        It 'an empty IP Allow List is Satisfied' {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-HostedConnectionFilterPolicy' } {
                [pscustomobject]@{ Command = { [pscustomobject]@{ Name = 'Default'; IsDefault = $true; EnableSafeList = $false; IPAllowList = @() } }; Source = 'ExchangeOnline' } }
            Invoke-TPCollectEXOConnectionFilter | Out-Null
            @(KVerdict 'Test-TPControlEXOConnectionIPAllowList' 'EXO-10.3')[0].State | Should -Be 'Satisfied'
        }
        It 'IPAllowList omitted from the output is not assessed: an omitted list reads as empty' {
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-HostedConnectionFilterPolicy' } {
                [pscustomobject]@{ Command = { [pscustomobject]@{ Name = 'Default'; IsDefault = $true; EnableSafeList = $false } }; Source = 'ExchangeOnline' } }
            $r = Invoke-TPCollectEXOConnectionFilter
            $r.Data.ConnectionFilter[0].IPAllowListReturned | Should -BeFalse
            @(KVerdict 'Test-TPControlEXOConnectionIPAllowList' 'EXO-10.3')[0].State | Should -Be 'NotApplicable'
        }
        It 'an older results file (no IPAllowListReturned) is not assessed' {
            Set-TPRawData -Key 'EXO-ConnectionFilter' -Data (KRaw @{ ConnectionFilter = @(@{ Name = 'Default'; IsDefault = $true; IPAllowList = @(); EnableSafeList = $false }) })
            @(KVerdict 'Test-TPControlEXOConnectionIPAllowList' 'EXO-10.3')[0].State | Should -Be 'NotApplicable'
        }
    }

    Context 'DEF-6.1 internal malware sender notifications (CIS 2.1.3), through the real collector' {
        It 'the default policy notifying an administrator is Satisfied' {
            $r = KCollectDefender @{
                'Get-MalwareFilterPolicy' = '[pscustomobject]@{ Name = "Default"; IsDefault = $true; EnableFileFilter = $true; FileTypes = @("exe"); EnableInternalSenderAdminNotifications = $true; InternalSenderAdminAddress = "secops@contoso.com" }'
                'Get-MalwareFilterRule'   = '@()' }
            $r.Data.MalwareFilter.Policies[0].InternalSenderAdminAddress | Should -Be 'secops@contoso.com'
            $r.Data.MalwareFilter.AdminAddressRead | Should -BeTrue
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            @(KVerdict 'Test-TPControlDefenderInternalMalwareNotify' 'DEF-6.1')[0].State | Should -Be 'Satisfied'
        }
        It 'notifications on with no administrator address is a Gap' {
            $r = KCollectDefender @{
                'Get-MalwareFilterPolicy' = '[pscustomobject]@{ Name = "Default"; IsDefault = $true; EnableFileFilter = $true; FileTypes = @(); EnableInternalSenderAdminNotifications = $true; InternalSenderAdminAddress = $null }'
                'Get-MalwareFilterRule'   = '@()' }
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            @(KVerdict 'Test-TPControlDefenderInternalMalwareNotify' 'DEF-6.1')[0].State | Should -Be 'Gap'
        }
        It 'a custom policy with an enabled rule that does not notify, beside a default that does, is Partial' {
            $r = KCollectDefender @{
                'Get-MalwareFilterPolicy' = '[pscustomobject]@{ Name = "Default"; IsDefault = $true; EnableFileFilter = $true; FileTypes = @(); EnableInternalSenderAdminNotifications = $true; InternalSenderAdminAddress = "secops@contoso.com" }; [pscustomobject]@{ Name = "Finance"; IsDefault = $false; EnableFileFilter = $true; FileTypes = @(); EnableInternalSenderAdminNotifications = $false; InternalSenderAdminAddress = $null }'
                'Get-MalwareFilterRule'   = '[pscustomobject]@{ Name = "Finance"; MalwareFilterPolicy = "Finance"; State = "Enabled"; SentToMemberOf = @("finance@contoso.com") }' }
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            $f = @(KVerdict 'Test-TPControlDefenderInternalMalwareNotify' 'DEF-6.1')[0]
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Finance'
        }
        It 'an older results file without the administrator address is not assessed' {
            Set-TPRawData -Key 'Defender-Policies' -Data (KRaw @{ MalwareFilter = @{ Available = $true; Rules = @()
                Policies = @(@{ Name = 'Default'; IsDefault = $true; EnableInternalSenderAdminNotifications = $true }) } })
            @(KVerdict 'Test-TPControlDefenderInternalMalwareNotify' 'DEF-6.1')[0].State | Should -Be 'NotApplicable'
        }
    }

    Context 'DEF-6.2 outbound spam notifications (CIS 2.1.6), through the real collector' {
        It 'Bcc copy and notification both on with recipients is Satisfied' {
            KCollectExo @{ 'Get-HostedOutboundSpamFilterPolicy' = '[pscustomobject]@{ Name = "Default"; IsDefault = $true; Enabled = $true; AutoForwardingMode = "Off"; BccSuspiciousOutboundMail = $true; BccSuspiciousOutboundAdditionalRecipients = @("secops@contoso.com"); NotifyOutboundSpam = $true; NotifyOutboundSpamRecipients = @("secops@contoso.com") }'
                           'Get-HostedOutboundSpamFilterRule' = '@()' } | Out-Null
            @(KVerdict 'Test-TPControlDefenderOutboundSpamNotify' 'DEF-6.2')[0].State | Should -Be 'Satisfied'
        }
        It 'notification on without the Bcc copy is a Gap: CIS audits both' {
            KCollectExo @{ 'Get-HostedOutboundSpamFilterPolicy' = '[pscustomobject]@{ Name = "Default"; IsDefault = $true; Enabled = $true; BccSuspiciousOutboundMail = $false; BccSuspiciousOutboundAdditionalRecipients = @(); NotifyOutboundSpam = $true; NotifyOutboundSpamRecipients = @("secops@contoso.com") }'
                           'Get-HostedOutboundSpamFilterRule' = '@()' } | Out-Null
            $f = @(KVerdict 'Test-TPControlDefenderOutboundSpamNotify' 'DEF-6.2')[0]
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'User restricted from sending email'
        }
        It 'switches on with no recipient address is a Gap' {
            KCollectExo @{ 'Get-HostedOutboundSpamFilterPolicy' = '[pscustomobject]@{ Name = "Default"; IsDefault = $true; Enabled = $true; BccSuspiciousOutboundMail = $true; BccSuspiciousOutboundAdditionalRecipients = @(); NotifyOutboundSpam = $true; NotifyOutboundSpamRecipients = @() }'
                           'Get-HostedOutboundSpamFilterRule' = '@()' } | Out-Null
            @(KVerdict 'Test-TPControlDefenderOutboundSpamNotify' 'DEF-6.2')[0].State | Should -Be 'Gap'
        }
        It 'NotifyOutboundSpam not returned is not assessed, though the stored flag defaults to False' {
            KCollectExo @{ 'Get-HostedOutboundSpamFilterPolicy' = '[pscustomobject]@{ Name = "Default"; IsDefault = $true; Enabled = $true; BccSuspiciousOutboundMail = $true; BccSuspiciousOutboundAdditionalRecipients = @("secops@contoso.com") }'
                           'Get-HostedOutboundSpamFilterRule' = '@()' } | Out-Null
            @(KVerdict 'Test-TPControlDefenderOutboundSpamNotify' 'DEF-6.2')[0].State | Should -Be 'NotApplicable'
        }
    }

    Context 'DEF-6.3 comprehensive attachment filtering (CIS 2.1.11), through the real collector' {
        It 'every listed type blocked (with leading dots and mixed case) is Satisfied' {
            $types = (@($script:CisTypes | ForEach-Object { '"' + '.' + $_.ToUpperInvariant() + '"' }) -join ',')
            $r = KCollectDefender @{ 'Get-MalwareFilterPolicy' = "[pscustomobject]@{ Name = 'Default'; IsDefault = `$true; EnableFileFilter = `$true; FileTypes = @($types); EnableInternalSenderAdminNotifications = `$false }"
                                     'Get-MalwareFilterRule' = '@()' }
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            @(KVerdict 'Test-TPControlDefenderComprehensiveAttachments' 'DEF-6.3')[0].State | Should -Be 'Satisfied'
        }
        It "Microsoft's default list alone is a Gap naming the missing types" {
            $r = KCollectDefender @{ 'Get-MalwareFilterPolicy' = '[pscustomobject]@{ Name = "Default"; IsDefault = $true; EnableFileFilter = $true; FileTypes = @("ace","ani","apk","app","exe","iso"); EnableInternalSenderAdminNotifications = $false }'
                                     'Get-MalwareFilterRule' = '@()' }
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            $f = @(KVerdict 'Test-TPControlDefenderComprehensiveAttachments' 'DEF-6.3')[0]
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match '6 of 186'
            $f.Detail | Should -Match '7z'
        }
        It 'the full list with the filter off is a Gap' {
            $types = (@($script:CisTypes | ForEach-Object { '"' + $_ + '"' }) -join ',')
            $r = KCollectDefender @{ 'Get-MalwareFilterPolicy' = "[pscustomobject]@{ Name = 'Default'; IsDefault = `$true; EnableFileFilter = `$false; FileTypes = @($types); EnableInternalSenderAdminNotifications = `$false }"
                                     'Get-MalwareFilterRule' = '@()' }
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            @(KVerdict 'Test-TPControlDefenderComprehensiveAttachments' 'DEF-6.3')[0].State | Should -Be 'Gap'
        }
        It 'a comprehensive custom policy whose rule is disabled applies to nobody; the default decides' {
            $types = (@($script:CisTypes | ForEach-Object { '"' + $_ + '"' }) -join ',')
            $r = KCollectDefender @{ 'Get-MalwareFilterPolicy' = "[pscustomobject]@{ Name = 'Default'; IsDefault = `$true; EnableFileFilter = `$true; FileTypes = @('exe'); EnableInternalSenderAdminNotifications = `$false }; [pscustomobject]@{ Name = 'CIS L2'; IsDefault = `$false; EnableFileFilter = `$true; FileTypes = @($types); EnableInternalSenderAdminNotifications = `$false }"
                                     'Get-MalwareFilterRule' = '[pscustomobject]@{ Name = "CIS L2"; MalwareFilterPolicy = "CIS L2"; State = "Disabled"; RecipientDomainIs = @("contoso.com") }' }
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            $f = @(KVerdict 'Test-TPControlDefenderComprehensiveAttachments' 'DEF-6.3')[0]
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Not -Match 'CIS L2'
        }
        It 'malware policies not read is not assessed' {
            $r = KCollectDefender @{ 'Get-MalwareFilterPolicy' = 'throw "Access denied"' }
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            $f = @(KVerdict 'Test-TPControlDefenderComprehensiveAttachments' 'DEF-6.3')[0]
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Access denied'
        }
    }

    Context 'DEF-6.4 zero-hour auto purge for Microsoft Teams (CIS 2.4.4), through the real collector' {
        It 'ZapEnabled True is Satisfied and the rule exceptions are reported for review' {
            $r = KCollectDefender @{ 'Get-TeamsProtectionPolicy' = '[pscustomobject]@{ Name = "Teams Protection Policy"; ZapEnabled = $true }'
                                     'Get-TeamsProtectionPolicyRule' = '[pscustomobject]@{ Name = "Teams Protection Policy Rule"; ExceptIfSentToMemberOf = @("research@contoso.com"); ExceptIfSentTo = $null; ExceptIfRecipientDomainIs = $null }' }
            $r.Data.TeamsProtection.Available | Should -BeTrue
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            $f = @(KVerdict 'Test-TPControlDefenderTeamsZap' 'DEF-6.4')[0]
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'ExceptIfSentToMemberOf \(1\)'
        }
        It 'ZapEnabled False is a Gap' {
            $r = KCollectDefender @{ 'Get-TeamsProtectionPolicy' = '[pscustomobject]@{ Name = "Teams Protection Policy"; ZapEnabled = $false }'
                                     'Get-TeamsProtectionPolicyRule' = '@()' }
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            @(KVerdict 'Test-TPControlDefenderTeamsZap' 'DEF-6.4')[0].State | Should -Be 'Gap'
        }
        It 'ZapEnabled not returned is not assessed; a rule read that failed is named, not read as no exceptions' {
            $r = KCollectDefender @{ 'Get-TeamsProtectionPolicy' = '[pscustomobject]@{ Name = "Teams Protection Policy" }'
                                     'Get-TeamsProtectionPolicyRule' = 'throw "rule read failed"' }
            $r.Data.TeamsProtection.Rules | Should -BeNullOrEmpty
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            @(KVerdict 'Test-TPControlDefenderTeamsZap' 'DEF-6.4')[0].State | Should -Be 'NotApplicable'
            Clear-TPState
            $r = KCollectDefender @{ 'Get-TeamsProtectionPolicy' = '[pscustomobject]@{ Name = "Teams Protection Policy"; ZapEnabled = $true }'
                                     'Get-TeamsProtectionPolicyRule' = 'throw "rule read failed"' }
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            $f = @(KVerdict 'Test-TPControlDefenderTeamsZap' 'DEF-6.4')[0]
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'rule was not read'
        }
        It 'the cmdlet unavailable is not assessed, and an older results file is too' {
            $r = KCollectDefender @{ 'Get-TeamsProtectionPolicy' = 'throw "The term Get-TeamsProtectionPolicy is not recognized"' }
            $r.Data.TeamsProtection.Available | Should -BeFalse
            Set-TPRawData -Key 'Defender-Policies' -Data $r
            @(KVerdict 'Test-TPControlDefenderTeamsZap' 'DEF-6.4')[0].State | Should -Be 'NotApplicable'
            Clear-TPState
            Set-TPRawData -Key 'Defender-Policies' -Data (KRaw @{ MalwareFilter = @{ Available = $true; Policies = @() } })
            $f = @(KVerdict 'Test-TPControlDefenderTeamsZap' 'DEF-6.4')[0]
            $f.State  | Should -Be 'NotApplicable'
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0
        }
    }
}

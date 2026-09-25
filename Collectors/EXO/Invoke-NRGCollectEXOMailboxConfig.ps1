#Requires -Version 7.0
#
# Invoke-NRGCollectEXOMailboxConfig.ps1  (v4.5.5)
# Collects Exchange Online transport, mailbox audit, SMTP AUTH, and accepted domain data.
# READ-ONLY. Uses EXO V3 Get-* cmdlets only.
#
# Required session: Exchange Online (Connect-ExchangeOnline)
#
# NIST SP 800-53: AU-2 (audit), SI-8 (spam protection), SC-7 (boundary protection)
# MITRE ATT&CK:   T1114.003 (Email Forwarding Rule), T1078 (Valid Accounts)
#

function Invoke-NRGCollectEXOMailboxConfig {
    [CmdletBinding()] param()

    $result = @{
        Success = $false
        Data    = @{
            TransportConfig          = $null
            OutboundSpamPolicies     = @()
            CASMailboxPlans          = @()
            RemoteDomains            = @()
            AcceptedDomains          = @()
            OrganizationConfig       = $null
            MailboxAuditSummary      = @{
                AuditDisabledOrg     = $null
                SampleMailboxAudit   = $null
            }
            SmtpAuthConfig           = $null
            DkimSigningConfigs       = @()
            AntiPhishPolicies        = @()
            AntiSpamPolicies         = @()
            OutboundSpamRules        = $null
            AdminAuditLogConfig      = $null
            ExternalInOutlook        = $null
            # Each of these seven sections runs its own independent try/catch
            # below so one query failing does not abort the rest, and Success
            # is set $true for the whole collector regardless. That makes an
            # empty list ambiguous ("queried, found nothing" vs. "the query
            # failed") — SectionStatus is the explicit contract that tells
            # Test-NRGSectionCollected which is which, per CLAUDE.md.
            SectionStatus            = @{
                OutboundSpamPolicies = 'NotRun'
                CASMailboxPlans      = 'NotRun'
                RemoteDomains        = 'NotRun'
                AcceptedDomains      = 'NotRun'
                DkimSigningConfigs   = 'NotRun'
                AntiPhishPolicies    = 'NotRun'
                AntiSpamPolicies     = 'NotRun'
                TransportConfig      = 'NotRun'
                OrganizationConfig   = 'NotRun'
                SmtpAuthConfig       = 'NotRun'
                CASMailboxProtocols  = 'NotRun'
                AdminAuditLogConfig  = 'NotRun'
                ExternalInOutlook    = 'NotRun'
            }
        }
    }

    try {
        # Transport Config (auto-forwarding, modern auth)
        try {
            $tc = Get-TransportConfig -ErrorAction Stop
            $result.Data.TransportConfig = @{
                SmtpClientAuthenticationDisabled = if ($null -ne $tc.SmtpClientAuthenticationDisabled) { [bool]$tc.SmtpClientAuthenticationDisabled } else { $null }
                AutoForwardEnabled               = [bool](Get-NRGObjectField -Item $tc -Key 'AutoForwardEnabled' -Default $true)
                MaxRecipientEnvelopeLimit        = try {
                    $raw = [string]$tc.MaxRecipientEnvelopeLimit
                    if ($raw -match '^\d+$') { [int]$raw } else { $null }  # 'Unlimited' → $null
                } catch { $null }
            }
            $result.Data.SectionStatus.TransportConfig = 'Collected'
        } catch {
            $result.Data.SectionStatus.TransportConfig = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-TransportConfig' -Message $_.Exception.Message
            }
        }

        # Outbound Spam Filter Policies (auto-forward blocking)
        try {
            $policies = @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop)
            $result.Data.OutboundSpamPolicies = @($policies | ForEach-Object {
                @{
                    Name                          = [string]$_.Name
                    IsDefault                     = [bool](Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false)
                    RecommendedPolicyType         = [string](Get-NRGObjectField -Item $_ -Key 'RecommendedPolicyType' -Default '')
                    AutoForwardingMode            = [string](Get-NRGObjectField -Item $_ -Key 'AutoForwardingMode' -Default '')
                    Enabled                       = [bool]$_.Enabled
                    # EXO-3.2: admin notification on outbound spam (CIS/MDO recommend $true)
                    NotifyOutboundSpam            = [bool](Get-NRGObjectField -Item $_ -Key 'NotifyOutboundSpam' -Default $false)
                    NotifyOutboundSpamRecipients  = @(Get-NRGObjectField -Item $_ -Key 'NotifyOutboundSpamRecipients' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
                    ActionWhenThresholdReached    = [string]$_.ActionWhenThresholdReached
                    RecipientLimitExternalPerHour = [int]($_.RecipientLimitExternalPerHour -as [int])
                    RecipientLimitInternalPerHour = [int]($_.RecipientLimitInternalPerHour -as [int])
                    RecipientLimitPerDay          = [int]($_.RecipientLimitPerDay -as [int])
                }
            })
            # Which custom outbound policies actually apply: a custom policy
            # only governs the senders its enabled rule scopes, and an "On"
            # forwarding policy with an enabled rule overrides the default's
            # "Off" for those senders. $null = rules not read.
            try {
                $result.Data.OutboundSpamRules = @(@(Get-HostedOutboundSpamFilterRule -ErrorAction Stop) | ForEach-Object {
                    @{
                        Name  = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
                        HostedOutboundSpamFilterPolicy = [string](Get-NRGObjectField -Item $_ -Key 'HostedOutboundSpamFilterPolicy' -Default '')
                        State = [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '')
                    }
                })
            } catch {
                $result.Data.OutboundSpamRules = $null
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'EXO-OutboundSpamRules' -Message $_.Exception.Message
                }
            }
            $result.Data.SectionStatus.OutboundSpamPolicies = 'Collected'
        } catch {
            $result.Data.SectionStatus.OutboundSpamPolicies = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-OutboundSpam' -Message $_.Exception.Message
            }
        }

        # CAS mailbox plans — org-level default POP3/IMAP enablement (EXO-2.3/2.4).
        # POP/IMAP are legacy basic-auth protocols; CIS recommends disabling them.
        # Get-CASMailboxPlan exposes the per-license default that new mailboxes
        # inherit — a tenant-scope, read-only signal (no per-user enumeration).
        try {
            $plans = @(Get-CASMailboxPlan -ErrorAction Stop)
            $result.Data.CASMailboxPlans = @($plans | ForEach-Object {
                @{
                    Name        = [string]$_.Name
                    DisplayName = [string]$_.DisplayName
                    PopEnabled  = if ($null -ne $_.PopEnabled)  { [bool]$_.PopEnabled }  else { $true }
                    ImapEnabled = if ($null -ne $_.ImapEnabled) { [bool]$_.ImapEnabled } else { $true }
                }
            })
            $result.Data.SectionStatus.CASMailboxPlans = 'Collected'
        } catch {
            $result.Data.SectionStatus.CASMailboxPlans = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-CASMailboxPlans' -Message $_.Exception.Message
            }
        }

        # Remote Domains (catch-all auto-forward setting)
        try {
            $domains = @(Get-RemoteDomain -ErrorAction Stop)
            $result.Data.RemoteDomains = @($domains | ForEach-Object {
                @{
                    DomainName         = [string]$_.DomainName
                    Name               = [string]$_.Name
                    AutoForwardEnabled = [bool]$_.AutoForwardEnabled
                    IsDefault          = $_.DomainName -eq '*'
                }
            })
            $result.Data.SectionStatus.RemoteDomains = 'Collected'
        } catch {
            $result.Data.SectionStatus.RemoteDomains = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-RemoteDomains' -Message $_.Exception.Message
            }
        }

        # Accepted Domains (used by DNS collector to determine domains to check)
        try {
            $accepted = @(Get-AcceptedDomain -ErrorAction Stop)
            $result.Data.AcceptedDomains = @($accepted | ForEach-Object {
                @{
                    Name         = [string]$_.Name
                    DomainName   = [string]$_.DomainName
                    DomainType   = [string]$_.DomainType
                    IsDefault    = [bool]$_.Default
                }
            })
            $result.Data.SectionStatus.AcceptedDomains = 'Collected'
        } catch {
            $result.Data.SectionStatus.AcceptedDomains = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AcceptedDomains' -Message $_.Exception.Message
            }
        }

        # Organization Config (mailbox audit, modern auth)
        try {
            $org = Get-OrganizationConfig -ErrorAction Stop
            # CustomerLockBoxEnabled is on Get-OrganizationConfig for every
            # tenant; $null only when the property was not returned.
            $lockbox = Get-NRGObjectField -Item $org -Key 'CustomerLockBoxEnabled' -Default $null
            $result.Data.OrganizationConfig = @{
                AuditDisabled             = [bool](Get-NRGObjectField -Item $org -Key 'AuditDisabled' -Default $false)
                OAuth2ClientProfileEnabled= [bool](Get-NRGObjectField -Item $org -Key 'OAuth2ClientProfileEnabled' -Default $false)
                DefaultMinimumNumberOfDaysForDumpster = Get-NRGObjectField -Item $org -Key 'DefaultMinimumNumberOfDaysForDumpster' -Default $null
                CustomerLockBoxEnabled    = $(if ($null -ne $lockbox) { [bool]$lockbox } else { $null })
                Name                      = [string](Get-NRGObjectField -Item $org -Key 'Name' -Default '')
            }
            $result.Data.MailboxAuditSummary.AuditDisabledOrg = $result.Data.OrganizationConfig.AuditDisabled
            $result.Data.SectionStatus.OrganizationConfig = 'Collected'
        } catch {
            $result.Data.SectionStatus.OrganizationConfig = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-OrgConfig' -Message $_.Exception.Message
            }
        }

        # Sample mailbox audit config (check first 10 user mailboxes). -WarningAction
        # SilentlyContinue suppresses EXO's expected "more results available" warning
        # — the 10-mailbox cap is intentional sampling, not an undercount.
        try {
            $mailboxes = @(Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize 10 -WarningAction SilentlyContinue -ErrorAction Stop)
            if ($mailboxes.Count -gt 0) {
                $sample = $mailboxes[0]
                # AuditLogAgeLimit per sampled mailbox: EXO-4.1 judges the
                # shortest, not whichever mailbox happened to come first.
                $ages = @($mailboxes | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'AuditLogAgeLimit' -Default '') } | Where-Object { $_ })
                $result.Data.MailboxAuditSummary.SampleMailboxAudit = @{
                    AuditEnabled      = [bool](Get-NRGObjectField -Item $sample -Key 'AuditEnabled' -Default $false)
                    AuditLogAgeLimit  = [string](Get-NRGObjectField -Item $sample -Key 'AuditLogAgeLimit' -Default '')
                    AuditLogAgeLimits = $ages
                    AuditDelegate     = @(Get-NRGObjectField -Item $sample -Key 'AuditDelegate' -Default @())
                    AuditOwner        = @(Get-NRGObjectField -Item $sample -Key 'AuditOwner' -Default @())
                    AuditAdmin        = @(Get-NRGObjectField -Item $sample -Key 'AuditAdmin' -Default @())
                    SampleCount       = $mailboxes.Count
                    AllEnabled        = (@($mailboxes | Where-Object { -not (Get-NRGObjectField -Item $_ -Key 'AuditEnabled' -Default $false) }).Count -eq 0)
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-MailboxAudit' -Message $_.Exception.Message
            }
        }

        # SMTP Auth per-mailbox (check for any explicitly enabled)
        # v4.6.4 EMERGENCY FIX (Medium #10): if Get-TransportConfig threw
        # earlier in this collector, $result.Data.TransportConfig is $null
        # and the subsequent .SmtpClientAuthenticationDisabled access would
        # crash under Set-StrictMode -Version Latest. Read TransportConfig
        # via a local guard variable.
        try {
            # CASMailbox carries no UserPrincipalName (reading it threw under
            # StrictMode and discarded the section); identify by
            # PrimarySmtpAddress, then Name.
            $cas = @(Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop)
            $smtpEnabled = @($cas | Where-Object { (Get-NRGObjectField -Item $_ -Key 'SmtpClientAuthenticationDisabled' -Default $null) -eq $false })
            # POP / IMAP on EXISTING mailboxes (EXO-2.3 / 2.4). The CAS
            # mailbox PLANS only set the default for new mailboxes; a mailbox
            # created before the plan changed keeps POP / IMAP on.
            $casId = { param($m) $i = [string](Get-NRGObjectField -Item $m -Key 'PrimarySmtpAddress' -Default ''); if (-not $i) { $i = [string](Get-NRGObjectField -Item $m -Key 'Name' -Default '') }; $i }
            $popOn  = @($cas | Where-Object { (Get-NRGObjectField -Item $_ -Key 'PopEnabled'  -Default $null) -eq $true })
            $imapOn = @($cas | Where-Object { (Get-NRGObjectField -Item $_ -Key 'ImapEnabled' -Default $null) -eq $true })
            $result.Data.CASMailboxProtocols = @{
                Total            = $cas.Count
                PopEnabledCount  = $popOn.Count
                ImapEnabledCount = $imapOn.Count
                PopSample        = @($popOn  | Select-Object -First 25 | ForEach-Object { & $casId $_ })
                ImapSample       = @($imapOn | Select-Object -First 25 | ForEach-Object { & $casId $_ })
            }
            $result.Data.SectionStatus.CASMailboxProtocols = 'Collected'
            $transportConfig = $result.Data.TransportConfig
            $tenantSmtpDisabled = if ($transportConfig) {
                $transportConfig.SmtpClientAuthenticationDisabled
            } else { $null }
            $result.Data.SmtpAuthConfig = @{
                TenantDisabled        = $tenantSmtpDisabled
                PerMailboxEnabledCount= $smtpEnabled.Count
                SampleEnabled         = @($smtpEnabled | Select-Object -First 5 | ForEach-Object {
                    $id = [string](Get-NRGObjectField -Item $_ -Key 'PrimarySmtpAddress' -Default '')
                    if (-not $id) { $id = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '') }
                    $id })
            }
            $result.Data.SectionStatus.SmtpAuthConfig = 'Collected'
        } catch {
            $result.Data.SectionStatus.SmtpAuthConfig = 'Failed'
            $result.Data.SectionStatus.CASMailboxProtocols = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-SmtpAuth' -Message $_.Exception.Message
            }
        }

        # DKIM Signing Configs
        try {
            $dkimConfigs = @(Get-DkimSigningConfig -ErrorAction Stop)
            $result.Data.DkimSigningConfigs = @($dkimConfigs | ForEach-Object {
                @{
                    Domain          = [string]$_.Domain
                    Enabled         = [bool](Get-NRGObjectField -Item $_ -Key 'Enabled' -Default $false)
                    Status          = [string](Get-NRGObjectField -Item $_ -Key 'Status' -Default '')
                    KeySize         = Get-NRGObjectField -Item $_ -Key 'KeySize' -Default $null
                    # The documented properties; KeySize is not one of them.
                    Selector1KeySize = Get-NRGObjectField -Item $_ -Key 'Selector1KeySize' -Default $null
                    Selector2KeySize = Get-NRGObjectField -Item $_ -Key 'Selector2KeySize' -Default $null
                    LastChecked     = [string](Get-NRGObjectField -Item $_ -Key 'LastChecked' -Default '')
                    Selector1       = [string](Get-NRGObjectField -Item $_ -Key 'Selector1' -Default '')
                    Selector2       = [string](Get-NRGObjectField -Item $_ -Key 'Selector2' -Default '')
                    # KeyCreationTime and RotateOnDate let the DNS evaluator
                    # compute key rotation age. NIST 800-53 SC-12 / SC-17 expects
                    # cryptographic keys to be rotated on a documented cadence;
                    # Microsoft auto-rotates DKIM but only if explicitly enabled.
                    KeyCreationTime = [string](Get-NRGObjectField -Item $_ -Key 'KeyCreationTime' -Default '')
                    RotateOnDate    = [string](Get-NRGObjectField -Item $_ -Key 'RotateOnDate' -Default '')
                }
            })
            $result.Data.SectionStatus.DkimSigningConfigs = 'Collected'
        } catch {
            $result.Data.SectionStatus.DkimSigningConfigs = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-DKIM' -Message $_.Exception.Message
            }
        }

        # Anti-phish policies
        try {
            $apPolicies = @(Get-AntiPhishPolicy -ErrorAction Stop)
            $result.Data.AntiPhishPolicies = @($apPolicies | ForEach-Object {
                @{
                    Name                             = [string]$_.Name
                    IsDefault                        = [bool]$_.IsDefault
                    Enabled                          = [bool]$_.Enabled
                    EnableTargetedUserProtection     = [bool]$_.EnableTargetedUserProtection
                    EnableOrganizationDomainsProtection = [bool]$_.EnableOrganizationDomainsProtection
                    EnableMailboxIntelligence        = [bool]$_.EnableMailboxIntelligence
                    EnableMailboxIntelligenceProtection = [bool]($_.EnableMailboxIntelligenceProtection ?? $false)
                    EnableExternalSenderTag          = [bool](Get-NRGObjectField -Item $_ -Key 'EnableExternalSenderTag' -Default $false)
                    HonorDmarcPolicy                 = [bool]($_.HonorDmarcPolicy ?? $false)
                    TargetedUsersToProtect           = @($_.TargetedUsersToProtect ?? @())
                    TargetedDomainsToProtect         = @($_.TargetedDomainsToProtect ?? @())
                }
            })
            $result.Data.SectionStatus.AntiPhishPolicies = 'Collected'
        } catch {
            $result.Data.SectionStatus.AntiPhishPolicies = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AntiPhish' -Message $_.Exception.Message
            }
        }

        # Anti-spam / inbound policies
        try {
            $spamPolicies = @(Get-HostedContentFilterPolicy -ErrorAction Stop)
            # Every field through Get-NRGObjectField: ZapEnabled is deprecated
            # (SpamZapEnabled / PhishZapEnabled replace it) and absent from
            # current output, and a bare read threw under StrictMode and failed
            # the whole anti-spam section.
            $result.Data.AntiSpamPolicies = @($spamPolicies | ForEach-Object {
                @{
                    Name                = [string]$_.Name
                    IsDefault           = [bool](Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false)
                    RecommendedPolicyType = [string](Get-NRGObjectField -Item $_ -Key 'RecommendedPolicyType' -Default '')
                    HighConfidenceSpamAction = [string](Get-NRGObjectField -Item $_ -Key 'HighConfidenceSpamAction' -Default '')
                    SpamAction          = [string](Get-NRGObjectField -Item $_ -Key 'SpamAction' -Default '')
                    PhishSpamAction     = [string](Get-NRGObjectField -Item $_ -Key 'PhishSpamAction' -Default '')
                    HighConfidencePhishAction = [string](Get-NRGObjectField -Item $_ -Key 'HighConfidencePhishAction' -Default '')
                    PhishQuarantineTag  = [string](Get-NRGObjectField -Item $_ -Key 'PhishQuarantineTag' -Default '')
                    BulkThreshold       = (Get-NRGObjectField -Item $_ -Key 'BulkThreshold' -Default $null)
                    SpamZapEnabled      = (Get-NRGObjectField -Item $_ -Key 'SpamZapEnabled' -Default $null)
                    PhishZapEnabled     = (Get-NRGObjectField -Item $_ -Key 'PhishZapEnabled' -Default $null)
                    ZapEnabled          = (Get-NRGObjectField -Item $_ -Key 'ZapEnabled' -Default $null)
                    AllowedSenderDomains = @(Get-NRGObjectField -Item $_ -Key 'AllowedSenderDomains' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
                    AllowedSenders      = @(Get-NRGObjectField -Item $_ -Key 'AllowedSenders' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
                }
            })
            # Which custom policies are actually applied (an enabled rule).
            $result.Data.AntiSpamRules = @()
            try {
                $result.Data.AntiSpamRules = @(@(Get-HostedContentFilterRule -ErrorAction Stop) | ForEach-Object {
                    @{
                        Name = [string]$_.Name
                        HostedContentFilterPolicy = [string](Get-NRGObjectField -Item $_ -Key 'HostedContentFilterPolicy' -Default '')
                        State = [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '')
                        RecipientDomainIs = @(Get-NRGObjectField -Item $_ -Key 'RecipientDomainIs' -Default @())
                        SentTo = @(Get-NRGObjectField -Item $_ -Key 'SentTo' -Default @())
                        SentToMemberOf = @(Get-NRGObjectField -Item $_ -Key 'SentToMemberOf' -Default @())
                        HasExceptions = [bool]@(@(Get-NRGObjectField -Item $_ -Key 'ExceptIfSentTo' -Default @()) + @(Get-NRGObjectField -Item $_ -Key 'ExceptIfSentToMemberOf' -Default @()) + @(Get-NRGObjectField -Item $_ -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ }).Count
                    }
                })
            } catch {
                $result.Data.AntiSpamRules = $null
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'EXO-AntiSpamRules' -Message $_.Exception.Message
                }
            }
            $result.Data.SectionStatus.AntiSpamPolicies = 'Collected'
        } catch {
            $result.Data.SectionStatus.AntiSpamPolicies = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AntiSpam' -Message $_.Exception.Message
            }
        }

        # Admin audit log (EXO-4.2) and Unified Audit Log ingestion (EXO-3.5).
        # Read from the Exchange Online session: Security & Compliance
        # PowerShell always reports UnifiedAuditLogIngestionEnabled as False.
        # The cmdlet exists in both sessions, so it is pinned to Exchange
        # Online (Lib/Get-NRGExoCommand.ps1); a value read from anywhere else
        # is not recorded.
        try {
            $auditCmd = Get-NRGExoCommand -Name 'Get-AdminAuditLogConfig' -Session ExchangeOnline
            if (-not $auditCmd.Command) { throw 'Get-AdminAuditLogConfig is not available from the Exchange Online session.' }
            $aal = & $auditCmd.Command -ErrorAction Stop
            $fromExo = [string]$auditCmd.Source -eq 'ExchangeOnline'
            $result.Data.AdminAuditLogConfig = @{
                AdminAuditLogEnabled            = Get-NRGObjectField -Item $aal -Key 'AdminAuditLogEnabled' -Default $null
                UnifiedAuditLogIngestionEnabled = $(if ($fromExo) { Get-NRGObjectField -Item $aal -Key 'UnifiedAuditLogIngestionEnabled' -Default $null } else { $null })
                Source                          = [string]$auditCmd.Source
            }
            $result.Data.SectionStatus.AdminAuditLogConfig = 'Collected'
        } catch {
            $result.Data.SectionStatus.AdminAuditLogConfig = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AdminAuditLogConfig' -Message $_.Exception.Message
            }
        }

        # External sender tag (EXO-1.5). The anti-phish EnableExternalSenderTag
        # property does not exist; the Outlook "External" tag is this setting.
        try {
            $ext = @(Get-ExternalInOutlook -ErrorAction Stop) | Select-Object -First 1
            $result.Data.ExternalInOutlook = @{ Enabled = Get-NRGObjectField -Item $ext -Key 'Enabled' -Default $null }
            $result.Data.SectionStatus.ExternalInOutlook = 'Collected'
        } catch {
            $result.Data.SectionStatus.ExternalInOutlook = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-ExternalInOutlook' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'EXO-MailboxConfig' -Status 'Collected'
        }

    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'EXO-MailboxConfig' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'EXO-MailboxConfig' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'EXO-MailboxConfig' -Data $result
    }
    return $result
}

function Invoke-NRGCollectEXOConnectionFilter {
    [CmdletBinding()] param()

    $result = @{ Success = $false; Data = @{} }
    try {
        $cf = @(Get-HostedConnectionFilterPolicy -ErrorAction Stop)
        $result.Data['ConnectionFilter'] = @($cf | ForEach-Object {
            @{
                Name            = [string]$_.Name
                IsDefault       = [bool]$_.IsDefault
                IPAllowList     = @($_.IPAllowList ?? @())
                IPBlockList     = @($_.IPBlockList ?? @())
                EnableSafeList  = [bool]($_.EnableSafeList ?? $false)
            }
        })

        # Alert policies for forwarding and unusual volume
        try {
            $alerts = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/security/alerts_v2?$filter=status ne ''resolved''&$top=50' `
                -ErrorAction Stop
            $result.Data['AlertPolicies'] = @{
                ActiveAlerts = @($alerts.value ?? @() | ForEach-Object {
                    @{ Id=[string]$_.id; Title=[string]$_.title; Severity=[string]$_.severity }
                })
            }
        } catch { }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'EXO-ConnectionFilter' -Status 'Collected'
        }
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'EXO-ConnectionFilter' -Message $_.Exception.Message
        }
    }
    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'EXO-ConnectionFilter' -Data $result
    }
    return $result
}
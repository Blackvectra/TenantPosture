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
        }
    }

    try {
        # Transport Config (auto-forwarding, modern auth)
        try {
            $tc = Get-TransportConfig -ErrorAction Stop
            $result.Data.TransportConfig = @{
                SmtpClientAuthenticationDisabled = if ($null -ne $tc.SmtpClientAuthenticationDisabled) { [bool]$tc.SmtpClientAuthenticationDisabled } else { $null }
                AutoForwardEnabled               = if ($null -ne $tc.AutoForwardEnabled) { [bool]$tc.AutoForwardEnabled } else { $true }
                MaxRecipientEnvelopeLimit        = try {
                    $raw = [string]$tc.MaxRecipientEnvelopeLimit
                    if ($raw -match '^\d+$') { [int]$raw } else { $null }  # 'Unlimited' → $null
                } catch { $null }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-TransportConfig' -Message $_.Exception.Message
            }
        }

        # Outbound Spam Filter Policies (auto-forward blocking)
        try {
            $policies = @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop)
            $result.Data.OutboundSpamPolicies = @($policies | ForEach-Object {
                @{
                    Name               = [string]$_.Name
                    IsDefault          = [bool]$_.IsDefault
                    AutoForwardingMode = [string]$_.AutoForwardingMode
                    Enabled            = [bool]$_.Enabled
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-OutboundSpam' -Message $_.Exception.Message
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
        } catch {
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
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AcceptedDomains' -Message $_.Exception.Message
            }
        }

        # Organization Config (mailbox audit, modern auth)
        try {
            $org = Get-OrganizationConfig -ErrorAction Stop
            $result.Data.OrganizationConfig = @{
                AuditDisabled             = [bool]$org.AuditDisabled
                OAuth2ClientProfileEnabled= [bool]$org.OAuth2ClientProfileEnabled
                DefaultMinimumNumberOfDaysForDumpster = $org.DefaultMinimumNumberOfDaysForDumpster
                Name                      = [string]$org.Name
            }
            $result.Data.MailboxAuditSummary.AuditDisabledOrg = [bool]$org.AuditDisabled
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-OrgConfig' -Message $_.Exception.Message
            }
        }

        # Sample mailbox audit config (check first 10 user mailboxes)
        try {
            $mailboxes = @(Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize 10 -ErrorAction Stop)
            if ($mailboxes.Count -gt 0) {
                $sample = $mailboxes[0]
                $result.Data.MailboxAuditSummary.SampleMailboxAudit = @{
                    AuditEnabled      = [bool]$sample.AuditEnabled
                    AuditLogAgeLimit  = [string]$sample.AuditLogAgeLimit
                    AuditDelegate     = @($sample.AuditDelegate ?? @())
                    AuditOwner        = @($sample.AuditOwner ?? @())
                    AuditAdmin        = @($sample.AuditAdmin ?? @())
                    SampleCount       = $mailboxes.Count
                    AllEnabled        = (@($mailboxes | Where-Object { -not $_.AuditEnabled }).Count -eq 0)
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
            $smtpEnabled = @(Get-CASMailbox -ResultSize 500 -ErrorAction Stop | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false })
            $transportConfig = $result.Data.TransportConfig
            $tenantSmtpDisabled = if ($transportConfig) {
                $transportConfig.SmtpClientAuthenticationDisabled
            } else { $null }
            $result.Data.SmtpAuthConfig = @{
                TenantDisabled        = $tenantSmtpDisabled
                PerMailboxEnabledCount= $smtpEnabled.Count
                SampleEnabled         = @($smtpEnabled | Select-Object -First 5 | ForEach-Object { [string]$_.UserPrincipalName })
            }
        } catch {
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
                    Enabled         = [bool]$_.Enabled
                    Status          = [string]$_.Status
                    KeySize         = $_.KeySize
                    LastChecked     = [string]($_.LastChecked ?? '')
                    Selector1       = [string]($_.Selector1 ?? '')
                    Selector2       = [string]($_.Selector2 ?? '')
                    # KeyCreationTime and RotateOnDate let the DNS evaluator
                    # compute key rotation age. NIST 800-53 SC-12 / SC-17 expects
                    # cryptographic keys to be rotated on a documented cadence;
                    # Microsoft auto-rotates DKIM but only if explicitly enabled.
                    KeyCreationTime = [string]($_.KeyCreationTime ?? '')
                    RotateOnDate    = [string]($_.RotateOnDate ?? '')
                }
            })
        } catch {
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
                    EnableExternalSenderTag          = [bool]($_.EnableExternalSenderTag ?? $false)
                    HonorDmarcPolicy                 = [bool]($_.HonorDmarcPolicy ?? $false)
                    TargetedUsersToProtect           = @($_.TargetedUsersToProtect ?? @())
                    TargetedDomainsToProtect         = @($_.TargetedDomainsToProtect ?? @())
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AntiPhish' -Message $_.Exception.Message
            }
        }

        # Anti-spam / inbound policies
        try {
            $spamPolicies = @(Get-HostedContentFilterPolicy -ErrorAction Stop)
            $result.Data.AntiSpamPolicies = @($spamPolicies | ForEach-Object {
                @{
                    Name                = [string]$_.Name
                    IsDefault           = [bool]$_.IsDefault
                    HighConfidenceSpamAction = [string]$_.HighConfidenceSpamAction
                    SpamAction          = [string]$_.SpamAction
                    PhishSpamAction     = [string]$_.PhishSpamAction
                    BulkThreshold       = $_.BulkThreshold
                    ZapEnabled          = [bool]$_.ZapEnabled
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AntiSpam' -Message $_.Exception.Message
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
            $alerts = Invoke-MgGraphRequest -Method GET `
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
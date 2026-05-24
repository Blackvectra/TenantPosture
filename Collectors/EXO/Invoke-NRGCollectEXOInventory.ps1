#Requires -Version 7.0
#
# Invoke-NRGCollectEXOInventory.ps1  (v4.5.6)
# Per-mailbox inventory for named findings the EXO/Inventory evaluators consume.
#
# READ-ONLY: Uses EXO V3 Get-* cmdlets and Graph GET for AAD cross-reference only.
#
# Returns: structured hashtable under key 'EXO-Inventory' via Set-NRGRawData.
# Reads:   Get-Mailbox, Get-CASMailbox, Get-InboxRule, Get-AcceptedDomain,
#          plus AAD-Users raw data (set by Invoke-NRGCollectAADUsers).
#
# Data populated:
#   - ForwardingMailboxes      mailboxes with ForwardingSmtpAddress set
#   - InboxRulesForwarding     mailbox rules forwarding to external recipients
#                              (actual exfil vector after credential compromise)
#   - SharedMailboxSignIn      shared mailboxes whose AAD account is not blocked
#                              (sign-in attack surface — should be BlockCredential)
#   - AllSharedMailboxes       inventory join key for evaluators
#   - AuditDisabledMailboxes   mailboxes with AuditEnabled = $false
#   - SmtpAuthEnabledPerUser   per-user SMTP AUTH override bypassing org disable
#
# NIST SP 800-53: AU-2 (audit events), AC-6 (least privilege), SI-8 (spam protection)
# MITRE ATT&CK:   T1114.003 (Email Forwarding Rule), T1098 (Account Manipulation),
#                 T1078 (Valid Accounts)
#

function Invoke-NRGCollectEXOInventory {
    [CmdletBinding()] param(
        # Cap how many mailboxes we scan inbox rules on for very large tenants.
        # A real attacker only needs one compromised mailbox to set up exfil, so
        # sampling is not a substitute; we want full coverage when feasible.
        # 0 = unlimited.
        [int] $InboxRuleScanLimit = 2000
    )

    $result = @{
        Success = $false
        Data = @{
            ForwardingMailboxes    = @()
            InboxRulesForwarding   = @()
            SharedMailboxSignIn    = @()
            AllSharedMailboxes     = @()
            AuditDisabledMailboxes = @()
            SmtpAuthEnabledPerUser = @()
            Stats = @{
                MailboxesScanned     = 0
                InboxRulesEvaluated  = 0
                AcceptedDomainsKnown = 0
                ScanLimitReached     = $false
            }
        }
    }

    try {
        # ── Build the tenant's accepted-domain set up front ──────────────────
        # We use it to classify rule recipients as internal vs external.
        $acceptedDomains = @()
        try {
            $acc = @(Get-AcceptedDomain -ErrorAction Stop)
            $acceptedDomains = @($acc | ForEach-Object { [string]$_.DomainName.ToLowerInvariant() })
            $result.Data.Stats.AcceptedDomainsKnown = $acceptedDomains.Count
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-Inventory-AcceptedDomains' -Message $_.Exception.Message
            }
        }

        $isExternalRecipient = {
            param([string] $Recipient)
            if ([string]::IsNullOrWhiteSpace($Recipient)) { return $false }
            # Rule recipients are sometimes display names; we only flag plausible
            # email addresses for external classification — internal-name recipients
            # are surfaced separately by the evaluator.
            $addr = $Recipient.Trim().TrimEnd('>').TrimStart('<')
            $atSplit = $addr -split '@'
            if ($atSplit.Count -ne 2) { return $false }
            $domain = $atSplit[1].ToLowerInvariant()
            return ($domain -and ($acceptedDomains -notcontains $domain))
        }

        # ── Forwarding via ForwardingSmtpAddress (server-side, persistent) ───
        try {
            $fwd = @(Get-Mailbox -ResultSize 1000 -Filter "ForwardingSmtpAddress -ne `$null" -ErrorAction Stop)
            $result.Data.ForwardingMailboxes = @($fwd | ForEach-Object {
                $smtp = [string]$_.ForwardingSmtpAddress
                @{
                    DisplayName               = [string]$_.DisplayName
                    UPN                       = [string]$_.UserPrincipalName
                    ForwardingAddress         = $smtp
                    IsExternal                = (& $isExternalRecipient $smtp)
                    DeliverToMailboxAndForward = [bool]$_.DeliverToMailboxAndForward
                    MailboxType               = [string]$_.RecipientTypeDetails
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-ForwardingMailboxes' -Message $_.Exception.Message
            }
        }

        # ── Inbox rules with ForwardTo / ForwardAsAttachmentTo / RedirectTo ──
        # This is the post-credential-compromise exfil pattern: attacker creates
        # an Outlook rule that quietly forwards or redirects mail to a domain
        # they control. ForwardingSmtpAddress alone misses this entirely.
        try {
            $boxes = if ($InboxRuleScanLimit -le 0) {
                @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop)
            } else {
                @(Get-Mailbox -ResultSize $InboxRuleScanLimit -ErrorAction Stop)
            }
            $result.Data.Stats.MailboxesScanned = $boxes.Count
            if ($InboxRuleScanLimit -gt 0 -and $boxes.Count -eq $InboxRuleScanLimit) {
                $result.Data.Stats.ScanLimitReached = $true
            }

            $rulesFound = [System.Collections.Generic.List[object]]::new()
            foreach ($mbx in $boxes) {
                try {
                    $rules = @(Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction Stop)
                    foreach ($r in $rules) {
                        $result.Data.Stats.InboxRulesEvaluated++

                        # Aggregate every recipient surface: ForwardTo,
                        # ForwardAsAttachmentTo, RedirectTo. Each is a string[]
                        # of SMTP / display-name entries.
                        $recipients = @()
                        if ($r.ForwardTo)             { $recipients += @($r.ForwardTo) }
                        if ($r.ForwardAsAttachmentTo) { $recipients += @($r.ForwardAsAttachmentTo) }
                        if ($r.RedirectTo)            { $recipients += @($r.RedirectTo) }
                        if ($recipients.Count -eq 0)  { continue }

                        $externalHits = @($recipients | ForEach-Object { [string]$_ } |
                            Where-Object { & $isExternalRecipient $_ })

                        # Only surface a rule when it's forwarding or when it's
                        # disabled (disabled rules can be re-enabled silently —
                        # attackers stage them ahead of activation).
                        if ($externalHits.Count -gt 0 -or -not $r.Enabled) {
                            $rulesFound.Add([ordered]@{
                                Mailbox      = [string]$mbx.UserPrincipalName
                                DisplayName  = [string]$mbx.DisplayName
                                RuleName     = [string]$r.Name
                                Enabled      = [bool]$r.Enabled
                                Priority     = $r.Priority
                                Recipients   = @($recipients | ForEach-Object { [string]$_ })
                                ExternalRecipients = $externalHits
                                IsExternal   = ($externalHits.Count -gt 0)
                                ForwardAction = @(
                                    if ($r.ForwardTo)             { 'ForwardTo' }
                                    if ($r.ForwardAsAttachmentTo) { 'ForwardAsAttachmentTo' }
                                    if ($r.RedirectTo)            { 'RedirectTo' }
                                ) -join ','
                            })
                        }
                    }
                } catch {
                    # Per-mailbox failure is non-fatal — record it and continue.
                    if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                        Register-NRGException -Source 'EXO-InboxRule' `
                            -Message "[$($mbx.UserPrincipalName)] $($_.Exception.Message)"
                    }
                }
            }
            $result.Data.InboxRulesForwarding = @($rulesFound)
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-InboxRulesForwarding' -Message $_.Exception.Message
            }
        }

        # ── Shared mailboxes — cross-reference AAD for real sign-in state ────
        # The previous proxy via LicenseReconciliationNeeded was unreliable.
        # AAD-Users raw data (set by Invoke-NRGCollectAADUsers) holds the truth:
        # accountEnabled = $true on a shared mailbox account means sign-in is
        # possible. Each licensed shared mailbox with accountEnabled is an
        # attack-surface entry that should be BlockCredential / disabled.
        try {
            $shared = @(Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize 1000 -ErrorAction Stop)
            $result.Data.AllSharedMailboxes = @($shared | ForEach-Object {
                @{
                    DisplayName          = [string]$_.DisplayName
                    PrimarySmtp          = [string]$_.PrimarySmtpAddress
                    Guid                 = [string]$_.Guid
                    UPN                  = [string]$_.UserPrincipalName
                    ExternalEmailAddress = [string]$_.ExternalEmailAddress
                }
            })

            # Pull AAD user data; if collector didn't run, fall back to the
            # weaker LicenseReconciliationNeeded heuristic.
            $aadUsers = $null
            if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) {
                $aad = Get-NRGRawData -Key 'AAD-Users'
                if ($aad -and $aad.Success -and $aad.Data.Users) {
                    $aadUsers = @{}
                    foreach ($u in @($aad.Data.Users)) {
                        if ($u.UserPrincipalName) {
                            $aadUsers[[string]$u.UserPrincipalName] = $u
                        }
                    }
                }
            }

            $signInRisky = foreach ($mbx in $shared) {
                $upn = [string]$mbx.UserPrincipalName
                $aadHit = if ($aadUsers) { $aadUsers[$upn] } else { $null }
                if ($aadHit) {
                    # accountEnabled comes through Graph; if missing assume $true
                    # for shared mailboxes (default state) which is the unsafe side
                    $enabled = if ($null -ne $aadHit.AccountEnabled) { [bool]$aadHit.AccountEnabled } else { $true }
                    if (-not $enabled) { continue }
                    [ordered]@{
                        DisplayName = [string]$mbx.DisplayName
                        UPN         = $upn
                        PrimarySmtp = [string]$mbx.PrimarySmtpAddress
                        SignInState = 'Enabled'
                        Source      = 'AAD-Users'
                    }
                } else {
                    # No AAD data — fall back to the per-mailbox heuristic
                    if ($mbx.LicenseReconciliationNeeded -or $mbx.SkuAssigned) {
                        [ordered]@{
                            DisplayName = [string]$mbx.DisplayName
                            UPN         = $upn
                            PrimarySmtp = [string]$mbx.PrimarySmtpAddress
                            SignInState = 'Probable'  # weaker signal
                            Source      = 'LicenseProxy'
                        }
                    }
                }
            }
            $result.Data.SharedMailboxSignIn = @($signInRisky)
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-SharedMailbox' -Message $_.Exception.Message
            }
        }

        # ── Audit explicitly disabled per mailbox ────────────────────────────
        try {
            $noAudit = @(Get-Mailbox -ResultSize 1000 -Filter "AuditEnabled -eq `$false" -ErrorAction Stop)
            $result.Data.AuditDisabledMailboxes = @($noAudit | ForEach-Object {
                @{
                    DisplayName = [string]$_.DisplayName
                    UPN         = [string]$_.UserPrincipalName
                    MailboxType = [string]$_.RecipientTypeDetails
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AuditDisabled' -Message $_.Exception.Message
            }
        }

        # ── Per-user SMTP AUTH overrides (bypass org-level disable) ──────────
        try {
            $smtpEnabled = @(Get-CASMailbox -ResultSize 1000 -ErrorAction Stop |
                Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false })
            $result.Data.SmtpAuthEnabledPerUser = @($smtpEnabled | Select-Object -First 100 | ForEach-Object {
                @{
                    DisplayName = [string]$_.DisplayName
                    UPN         = [string]$_.Name
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-SMTPAuthPerUser' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            $note = "Scanned $($result.Data.Stats.MailboxesScanned) mailboxes / $($result.Data.Stats.InboxRulesEvaluated) inbox rules"
            Register-NRGCoverage -Family 'EXO-Inventory' -Status 'Collected' -Note $note
        }
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'EXO-Inventory' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'EXO-Inventory' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'EXO-Inventory' -Data $result
    }
    return $result
}

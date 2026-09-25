#Requires -Version 7.0
#
# Test-NRGEmailControls.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Evaluators for the NRG Email Account Assessment (incident-response
#          mode). Consumes mailbox data collected by
#          Invoke-NRGEmailCollectMailbox, scores findings, and ranks the most
#          likely original phishing email.
#
# Reads:   IR-MailboxSentItems, IR-MailboxInbox, IR-MailboxRecoverable,
#          IR-MailboxRules, IR-MailboxForwarding, IR-MailboxProfile.
# Writes:  Findings via Add-NRGFinding with EMAIL-* control IDs.
#
# Heuristics intentionally tuned for SIGNAL not certainty — the operator
# reviews and confirms. False-positive rate is acceptable because the
# alternative is missing the real phish.

# Microsoft "real" login domains that legitimately host auth flows.
$script:NRGEmailLegitMSDomains = @(
    'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com',
    'office.com', 'office365.com', 'azure.com', 'onmicrosoft.com',
    'sharepoint.com', 'msft.net', 'azureedge.net', 'azurewebsites.net'
)

# Microsoft-impersonation substrings — domains that mention Microsoft
# branding while NOT being legit MS-owned. Tuned for typo-squat patterns
# the threat intel community sees in the wild.
$script:NRGEmailMSImpersonationPatterns = @(
    'microsft', 'micrsoft', 'mircosoft', 'micorsoft', 'micros0ft',
    'm1crosoft', 'microsofte', 'microsofts', 'microsoftonine',
    'micro-soft', 'micros-oft', 'office356', 'office-365',
    'login-microsoft', 'microsoft-login', 'ms-office', 'msoffice365'
)

# Urgency keywords in subject lines — classic phish/BEC indicators
$script:NRGEmailUrgencyKeywords = @(
    'password\s+expir',
    'account\s+(?:lock|suspen|disab)',
    'verify\s+(?:your|now|account|identity)',
    'urgent\s+action',
    'immediate\s+action',
    '(?:re-?)?confirm\s+your\s+(?:identity|account|password)',
    'unauthorized\s+(?:login|access|sign)',
    'unusual\s+(?:activity|sign-in)',
    'mfa\s+(?:disabled|expired|setup)',
    '2fa\s+(?:disabled|reset)',
    'invoice\s+(?:overdue|attached)',
    'wire\s+transfer',
    'payroll\s+update',
    'salary\s+(?:revision|update)',
    'gift\s+card',
    'docusign\s+(?:request|requires)',
    'signed\s+document\s+ready',
    'voicemail\s+(?:received|new)',
    'shared\s+document\s+(?:with\s+you|expiring)'
)

# BEC outbound subject patterns — phrases the attacker sends from the
# compromised account to chain the fraud
$script:NRGEmailBECOutboundPatterns = @(
    'wire\s+transfer',
    'change\s+(?:of\s+)?(?:bank|account|payment)',
    'updated\s+(?:invoice|banking|payment)',
    'urgent\s+(?:payment|invoice|approval)',
    'process\s+(?:this\s+)?payment',
    'gift\s+card',
    'are\s+you\s+available',
    'quick\s+favor',
    'wage\s+(?:adjustment|change)'
)


# ---- Helper: pull domain from a sender address ------------------------------
function Get-NRGEmailDomainFromAddress {
    [CmdletBinding()]
    param([string] $Address)
    if (-not $Address) { return $null }
    $at = $Address.IndexOf('@')
    if ($at -lt 0 -or $at -ge ($Address.Length - 1)) { return $null }
    return $Address.Substring($at + 1).ToLowerInvariant().Trim('"', "'", ' ', '<', '>')
}

function Test-NRGEmailIsLegitMSDomain {
    [CmdletBinding()]
    param([string] $Domain)
    if (-not $Domain) { return $false }
    $d = $Domain.ToLowerInvariant()
    foreach ($legit in $script:NRGEmailLegitMSDomains) {
        if ($d -eq $legit -or $d.EndsWith(".$legit")) { return $true }
    }
    return $false
}

function Test-NRGEmailMatchesMSImpersonation {
    [CmdletBinding()]
    param([string] $Domain, [string] $DisplayName)
    if (-not $Domain) { return $false }
    $d = $Domain.ToLowerInvariant()
    # If it claims to be Microsoft in the display name but isn't a legit MS
    # domain, that's a high-signal impersonation indicator.
    if ($DisplayName -and ($DisplayName -match '(?i)microsoft|office\s*365|outlook|onedrive') -and
        -not (Test-NRGEmailIsLegitMSDomain $d)) {
        return $true
    }
    foreach ($pat in $script:NRGEmailMSImpersonationPatterns) {
        if ($d -like "*$pat*") { return $true }
    }
    return $false
}


# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-1.1 — Inbox rules with persistence / cover-tracks signatures
# ─────────────────────────────────────────────────────────────────────────────
function Test-NRGEmailControlInboxRules {
    [CmdletBinding()] param()
    $cid = 'EMAIL-1.1'
    $title = 'Suspicious inbox rules (BEC persistence / cover-tracks)'
    $cat = 'Email'

    $rulesRaw = Get-NRGRawData -Key 'IR-MailboxRules'
    if (-not $rulesRaw -or -not $rulesRaw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' -Detail 'Inbox-rules collection did not succeed.'
        return
    }

    $rules = @($rulesRaw.Data.Rules)
    $iocRules = @()
    foreach ($r in $rules) {
        $reasons = @()
        $name = [string]$r.displayName

        # Hidden-name pattern (attacker convention): single ".", "..", "/", "-"
        if ($name -match '^[\.\-/_ ]{1,3}$') { $reasons += "hidden-name '$name'" }

        # Forwarding-to-external
        $forwardTo = @()
        if ($r.actions) {
            foreach ($key in 'forwardTo','forwardAsAttachmentTo','redirectTo') {
                if ($r.actions.$key) {
                    foreach ($recip in $r.actions.$key) {
                        if ($recip.emailAddress -and $recip.emailAddress.address) {
                            $forwardTo += $recip.emailAddress.address
                        }
                    }
                }
            }
            if ($forwardTo.Count -gt 0) {
                $reasons += "forwards to: $($forwardTo -join ', ')"
            }
            # Delete + Move-to-Deleted (cover tracks)
            if ($r.actions.delete -eq $true) { $reasons += 'deletes matching mail' }
            if ($r.actions.moveToFolder) { $reasons += "moves to folder '$($r.actions.moveToFolder)'" }
            if ($r.actions.permanentDelete -eq $true) { $reasons += 'permanently deletes' }
        }

        # Always-applies pattern (no filter conditions = applies to everything)
        $noConditions = (-not $r.conditions -or
                        ($r.conditions.PSObject.Properties.Count -eq 0 -and (-not ($r.conditions -is [hashtable]) -or $r.conditions.Count -eq 0)))
        if ($noConditions -and $forwardTo.Count -gt 0) {
            $reasons += 'no filter conditions (applies to all mail)'
        }

        if ($reasons.Count -gt 0) {
            $iocRules += [ordered]@{
                Name    = $name
                Id      = [string]$r.id
                Enabled = $r.isEnabled
                Reasons = $reasons
                ForwardTo = $forwardTo
            }
        }
    }

    if ($iocRules.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail ("Reviewed $($rules.Count) inbox rule(s). No persistence/cover-tracks indicators found.")
    } else {
        $detail = "FOUND $($iocRules.Count) suspicious rule(s).`n" + (
            ($iocRules | ForEach-Object { "  - '$($_.Name)' [enabled=$($_.Enabled)]: $($_.Reasons -join '; ')" }) -join "`n"
        )
        # Attach the flagged rules as structured AffectedObjects so the
        # containment runbook can name each one (and emit a precise delete
        # command). RuleType marks these as inbox rules so the publisher /
        # runbook can distinguish them from EMAIL-2.1 recipient objects.
        $ruleObjects = foreach ($ir in $iocRules) {
            [pscustomobject]@{
                RuleType = 'InboxRule'
                Name     = $ir.Name
                Id       = $ir.Id
                Enabled  = $ir.Enabled
                Reason   = ($ir.Reasons -join '; ')
            }
        }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
            -Title $title -Severity 'Critical' `
            -Detail $detail `
            -AffectedObjects @($ruleObjects) `
            -Remediation "Delete each suspicious rule (named in the Containment Runbook). PowerShell: Get-MgUserMailFolderMessageRule -UserId <upn> -MailFolderId Inbox  then  Remove-MgUserMailFolderMessageRule -UserId <upn> -MailFolderId Inbox -MessageRuleId <id>"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-1.2 — Mailbox forwarding (server-side, separate from inbox rules)
# ─────────────────────────────────────────────────────────────────────────────
function Test-NRGEmailControlForwarding {
    [CmdletBinding()] param()
    $cid = 'EMAIL-1.2'
    $title = 'Mailbox server-side forwarding'
    $cat = 'Email'

    # The Graph mailboxSettings endpoint doesn't expose the forwarding
    # SMTP address directly under delegated scope (it's typically EXO-only
    # via Set-Mailbox -ForwardingSmtpAddress). What we CAN check via Graph
    # is whether ANY rule forwards externally — which Test-NRGEmailControlInboxRules
    # already does. Here we just note the gap.
    $settingsRaw = Get-NRGRawData -Key 'IR-MailboxForwarding'
    if (-not $settingsRaw -or -not $settingsRaw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail 'Mailbox-settings collection did not succeed.'
        return
    }

    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
        -Title $title -Severity 'Medium' `
        -Detail 'Server-side ForwardingSmtpAddress is not exposed under delegated Graph scope. To rule out, run from an admin context: Get-Mailbox <upn> | Select ForwardingSmtpAddress,DeliverToMailboxAndForward'
}

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-2.1 — Outbound activity scan (what did the attacker send?)
# ─────────────────────────────────────────────────────────────────────────────
function Test-NRGEmailControlOutboundActivity {
    [CmdletBinding()] param()
    $cid = 'EMAIL-2.1'
    $title = 'Outbound activity from compromised account'
    $cat = 'Email'

    $sentRaw = Get-NRGRawData -Key 'IR-MailboxSentItems'
    if (-not $sentRaw -or -not $sentRaw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' -Detail 'Sent-items collection did not succeed.'
        return
    }

    $profileBag = Get-NRGRawData -Key 'IR-MailboxProfile'
    $tenantDomain = $null
    if ($profileBag -and $profileBag.Success -and $profileBag.Data.UserPrincipalName) {
        $tenantDomain = Get-NRGEmailDomainFromAddress $profileBag.Data.UserPrincipalName
    }

    $messages = @($sentRaw.Data.Messages)
    if ($messages.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail "No outbound mail in the last $($sentRaw.Data.WindowDays) days. Account either not actively used or attacker has not yet used outbound."
        return
    }

    $externalRecipients = [System.Collections.Generic.HashSet[string]]::new()
    $internalRecipients = [System.Collections.Generic.HashSet[string]]::new()
    $becMatches = @()
    $burstWindows = @{}  # hour-bucket → count

    foreach ($m in $messages) {
        foreach ($r in $m.Recipients) {
            $rDomain = Get-NRGEmailDomainFromAddress $r
            if ($rDomain -and $tenantDomain -and $rDomain -eq $tenantDomain) {
                [void]$internalRecipients.Add($r)
            } else {
                [void]$externalRecipients.Add($r)
            }
        }
        # BEC subject patterns
        foreach ($pat in $script:NRGEmailBECOutboundPatterns) {
            if ([string]$m.Subject -match "(?i)$pat") {
                $becMatches += [ordered]@{
                    Time       = $m.SentDateTime
                    Subject    = $m.Subject
                    Recipients = $m.Recipients
                    Pattern    = $pat
                }
                break
            }
        }
        # Burst detection — group by hour bucket
        try {
            $hour = [datetime]::Parse($m.SentDateTime).ToString('yyyy-MM-dd HH')
            if (-not $burstWindows.ContainsKey($hour)) { $burstWindows[$hour] = 0 }
            $burstWindows[$hour]++
        } catch { }
    }

    $maxBurst = if ($burstWindows.Count -gt 0) { ($burstWindows.Values | Measure-Object -Maximum).Maximum } else { 0 }
    $burstHour = if ($maxBurst -gt 0) { ($burstWindows.GetEnumerator() | Where-Object { $_.Value -eq $maxBurst } | Select-Object -First 1).Key } else { $null }

    $isSuspicious = ($becMatches.Count -gt 0) -or ($maxBurst -ge 20) -or ($externalRecipients.Count -ge 25)

    # ── Recipient warn-list (the response deliverable) ───────────────────────
    # Every person who received the attacker's outbound during the compromise
    # window — internal coworkers + external partners — so the operator can
    # warn all of them. When BEC patterns matched, we scope to those messages'
    # recipients (the actual fraud targets); otherwise, when the whole burst
    # is suspicious, we include every recipient in the window. Each entry is
    # an AffectedObject (rendered as a named table + exported to recipients.csv
    # by the publisher).
    $becRecipientSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($b in $becMatches) {
        foreach ($r in @($b.Recipients)) { if ($r) { [void]$becRecipientSet.Add($r) } }
    }
    # If BEC patterns matched, the warn-list is those recipients; else (burst /
    # high-external-volume suspicion) it's all recipients seen this window.
    $warnSource = if ($becRecipientSet.Count -gt 0) {
        @($becRecipientSet)
    } else {
        @($externalRecipients) + @($internalRecipients)
    }
    $warnList = foreach ($r in ($warnSource | Sort-Object -Unique)) {
        $rDomain = Get-NRGEmailDomainFromAddress $r
        $scope = if ($rDomain -and $tenantDomain -and $rDomain -eq $tenantDomain) { 'Internal' } else { 'External' }
        [pscustomobject]@{
            Recipient = $r
            Scope     = $scope
            Reason    = if ($becRecipientSet.Contains($r)) { 'Received BEC-pattern message' } else { 'Received mail during compromise window' }
        }
    }
    $warnList = @($warnList)

    $detail = "OUTBOUND SUMMARY (last $($sentRaw.Data.WindowDays) days)`n" +
              "  Messages sent       : $($messages.Count)`n" +
              "  External recipients : $($externalRecipients.Count)`n" +
              "  Internal recipients : $($internalRecipients.Count)`n" +
              "  Peak burst (1hr)    : $maxBurst$(if ($burstHour) { " at $burstHour UTC" })`n"
    if ($becMatches.Count -gt 0) {
        $detail += "  BEC PATTERN MATCHES : $($becMatches.Count)`n"
        foreach ($b in ($becMatches | Select-Object -First 5)) {
            $detail += "    - [$($b.Time)] '$($b.Subject)' -> $(@($b.Recipients) -join ', ')`n"
        }
    }
    if ($warnList.Count -gt 0) {
        $detail += "  RECIPIENTS TO WARN  : $($warnList.Count) (full list in the report + recipients.csv)`n"
    }

    $state    = if ($isSuspicious) { 'Gap' }       else { 'Satisfied' }
    $severity = if ($isSuspicious) { 'Critical' }  else { 'High' }

    # Only attach the warn-list as AffectedObjects when the activity is
    # suspicious — a clean account shouldn't dump its whole address book.
    $affected = if ($isSuspicious) { $warnList } else { @() }

    Add-NRGFinding -ControlId $cid -State $state -Category $cat `
        -Title $title -Severity $severity -Detail $detail `
        -CurrentValue "$($messages.Count) messages, $($warnList.Count) recipients to warn" `
        -AffectedObjects $affected `
        -Remediation "Notify every recipient in the warn-list (report + recipients.csv) that mail from this account during the compromise window may be fraudulent. Preserve sent-item evidence before any cleanup."
}

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-3.1 — Most-likely original phishing email
# ─────────────────────────────────────────────────────────────────────────────
function Test-NRGEmailControlPhishOrigin {
    [CmdletBinding()] param()
    $cid = 'EMAIL-3.1'
    $title = 'Most-likely original phishing email'
    $cat = 'Email'

    $inboxRaw = Get-NRGRawData -Key 'IR-MailboxInbox'
    if (-not $inboxRaw -or -not $inboxRaw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' -Detail 'Inbox collection did not succeed.'
        return
    }
    $recRaw = Get-NRGRawData -Key 'IR-MailboxRecoverable'

    $profileBag = Get-NRGRawData -Key 'IR-MailboxProfile'
    $tenantDomain = $null
    if ($profileBag -and $profileBag.Success -and $profileBag.Data.UserPrincipalName) {
        $tenantDomain = Get-NRGEmailDomainFromAddress $profileBag.Data.UserPrincipalName
    }

    # Combine inbox + recoverable items (attacker may have deleted the phish)
    $candidates = @($inboxRaw.Data.Messages)
    $recoveredCount = 0
    if ($recRaw -and $recRaw.Success -and $recRaw.Data.Messages) {
        $candidates += @($recRaw.Data.Messages)
        $recoveredCount = @($recRaw.Data.Messages).Count
    }

    # Score each candidate
    $scored = foreach ($m in $candidates) {
        $score = 0
        $reasons = @()
        $senderDomain = Get-NRGEmailDomainFromAddress $m.FromAddress

        # +30 if external sender (any external is the prerequisite; internal
        # phishes are out-of-scope for user-level IR)
        if ($senderDomain -and $tenantDomain -and $senderDomain -ne $tenantDomain) {
            $score += 30
            $reasons += "external sender ($senderDomain)"
        } elseif (-not $senderDomain) {
            # Couldn't parse — possibly a spoofed display name only
            $score += 20
            $reasons += 'unparseable sender'
        } else {
            # Internal sender — skip
            continue
        }

        # +25 if domain mentions Microsoft branding without being legit MS
        $fromName = Get-NRGObjectField -Item $m -Key 'FromName' -Default $null
        if (Test-NRGEmailMatchesMSImpersonation -Domain $senderDomain -DisplayName $fromName) {
            $score += 25
            $reasons += "Microsoft-impersonation pattern"
        }

        # +20 if subject contains urgency keywords
        $subject = [string]$m.Subject
        foreach ($pat in $script:NRGEmailUrgencyKeywords) {
            if ($subject -match "(?i)$pat") {
                $score += 20
                $reasons += "urgency keyword: $pat"
                break
            }
        }

        # +20 if body contains a URL whose host doesn't match a legit MS domain
        # while subject/sender mentions Microsoft
        $hasSuspiciousLoginUrl = $false
        foreach ($url in @($m.BodyURLs)) {
            try {
                $uri = [Uri]$url
                if ($uri.Host -and -not (Test-NRGEmailIsLegitMSDomain $uri.Host) -and
                    ($url -match '(?i)login|signin|auth|verify|reset|password|account')) {
                    $hasSuspiciousLoginUrl = $true
                    break
                }
            } catch { }
        }
        if ($hasSuspiciousLoginUrl) {
            $score += 20
            $reasons += "non-MS URL with auth-flow keywords"
        }

        # +10 if attached to display-name spoofing (FromName has Microsoft but
        # FromAddress is external — caught by impersonation above too, but
        # account for the case where it's a different brand)
        if ($fromName -and ($fromName -match '(?i)microsoft|docusign|adobe|dropbox|onedrive') -and
            $senderDomain -and -not (Test-NRGEmailIsLegitMSDomain $senderDomain)) {
            $score += 10
            $reasons += "display-name brand spoof: '$fromName'"
        }

        # If recovered from Deletions, that's a HUGE signal — attacker covered tracks
        $isRecovered = $false
        if ($recRaw -and $recRaw.Success -and $recRaw.Data.Messages) {
            $recIds = @($recRaw.Data.Messages | ForEach-Object { Get-NRGObjectField -Item $_ -Key 'Id' -Default $null })
            if ($recIds -contains $m.Id) {
                $score += 30
                $isRecovered = $true
                $reasons += "RECOVERED from Deletions (attacker deleted)"
            }
        }

        [ordered]@{
            ReceivedDateTime = $m.ReceivedDateTime
            From             = $m.FromAddress
            FromName         = $fromName
            Subject          = $subject
            Score            = $score
            Reasons          = $reasons
            URLs             = @($m.BodyURLs)
            Recovered        = $isRecovered
        }
    }

    # Inclusion threshold: score > 30, i.e. external sender (worth 30) PLUS at
    # least one additional phish indicator (impersonation +25, urgency +20,
    # suspicious URL +20, display-name spoof +10, recovered-from-Deletions +30).
    # A bare external sender with no other signal scores exactly 30 — almost
    # all inbound mail is external, so a >= 30 threshold would flood the report
    # with every correspondent. > 30 keeps it to actual phish candidates.
    $top = @($scored | Where-Object { $_.Score -gt 30 } | Sort-Object { $_.Score } -Descending | Select-Object -First 5)

    if ($top.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Medium' `
            -Detail ("Scanned $($candidates.Count) inbound messages (incl $recoveredCount recovered from Deletions). No high-confidence phish candidate found. Could indicate: phish predates 30-day window, attacker used credential stuffing not phish, or original phish has been permanently deleted from Recoverable Items.")
        return
    }

    $detail = "TOP $($top.Count) PHISH CANDIDATES (highest score first):`n"
    foreach ($t in $top) {
        $detail += "`n  Score $($t.Score) | $($t.ReceivedDateTime)`n"
        $detail += "    From    : `"$($t.FromName)`" <$($t.From)>`n"
        $detail += "    Subject : $($t.Subject)`n"
        $detail += "    Why     : $($t.Reasons -join '; ')`n"
        if ($t.URLs.Count -gt 0) {
            $detail += "    URLs    : $(($t.URLs | Select-Object -First 3) -join ', ')`n"
        }
    }
    $detail += "`nThe top result is the most-likely original phish. Operator verifies by reviewing the message in Outlook."

    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
        -Title $title -Severity 'High' -Detail $detail `
        -CurrentValue "Top candidate: $($top[0].Subject) (score $($top[0].Score))" `
        -Remediation "Validate the top candidate is the actual phish. If so: 1) submit URL+sender to Microsoft Defender Submissions, 2) block the sender domain at the tenant boundary, 3) search-and-purge any other users who received the same phish (admin scope required)."
}

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-3.2 — Threat-intel enrichment on top sender domains
# ─────────────────────────────────────────────────────────────────────────────
function Test-NRGEmailControlThreatIntel {
    [CmdletBinding()] param()
    $cid = 'EMAIL-3.2'
    $title = 'Threat-intel enrichment on top sender / URL domains'
    $cat = 'Email'

    if (-not (Get-Command Get-NRGDomainAge -ErrorAction SilentlyContinue)) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Medium' -Detail 'Get-NRGDomainAge helper not loaded.'
        return
    }

    $inboxRaw = Get-NRGRawData -Key 'IR-MailboxInbox'
    if (-not $inboxRaw -or -not $inboxRaw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Medium' -Detail 'Inbox data unavailable for enrichment.'
        return
    }

    # Pull sender domains from top phish candidates (re-score quickly)
    $profileBag = Get-NRGRawData -Key 'IR-MailboxProfile'
    $tenantDomain = $null
    if ($profileBag -and $profileBag.Success -and $profileBag.Data.UserPrincipalName) {
        $tenantDomain = Get-NRGEmailDomainFromAddress $profileBag.Data.UserPrincipalName
    }

    $domains = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in @($inboxRaw.Data.Messages)) {
        $d = Get-NRGEmailDomainFromAddress $m.FromAddress
        if ($d -and $tenantDomain -and $d -ne $tenantDomain -and -not (Test-NRGEmailIsLegitMSDomain $d)) {
            [void]$domains.Add($d)
        }
    }
    # Cap at 10 — RDAP is rate-limited and operators don't need 100 lookups
    $topDomains = @($domains | Select-Object -First 10)

    $enriched = foreach ($d in $topDomains) {
        $age = Get-NRGDomainAge -Domain $d
        $age
    }

    $young = @($enriched | Where-Object { $null -ne $_.AgeDays -and $_.AgeDays -lt 30 })

    if ($young.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'Medium' `
            -Detail ("Enriched $($enriched.Count) external sender domain(s). No domains registered in the last 30 days.")
        return
    }

    $detail = "FOUND $($young.Count) sender domain(s) registered in the last 30 days:`n"
    foreach ($y in $young) {
        $detail += "  - $($y.Domain): registered $($y.Registered) (age $($y.AgeDays) days)"
        if ($y.Registrar) { $detail += " via $($y.Registrar)" }
        $detail += "`n"
    }
    $detail += "`nNew domain + sender to your user = very strong phish indicator."

    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
        -Title $title -Severity 'High' -Detail $detail `
        -CurrentValue "$($young.Count) suspicious newly-registered domains"
}

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-4.1 — OAuth consent grants (persistence that survives password reset)
# ─────────────────────────────────────────────────────────────────────────────
# Attackers who phish a user increasingly skip credential theft entirely and
# instead trick the user into consenting to a mail-reading OAuth app
# ("illicit consent grant"). That access token pipeline keeps working after
# the password is reset and MFA is re-enrolled — only revoking the grant
# kills it. Flag any grant carrying a mail/file-write or send scope.
function Test-NRGEmailControlOAuthConsents {
    [CmdletBinding()] param()
    $cid = 'EMAIL-4.1'
    $title = 'OAuth consent grants on the account'
    $cat = 'Email'

    $consentRaw = Get-NRGRawData -Key 'IR-UserConsents'
    if (-not $consentRaw -or -not $consentRaw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Critical' `
            -Detail 'OAuth consent collection did not succeed (requires Directory.Read.All — available in admin triage mode, usually not under delegated user scope). To rule out manually: Entra > Users > the user > Applications, or Get-MgUserOauth2PermissionGrant -UserId <upn>.'
        return
    }

    $grants = @($consentRaw.Data.Grants)
    if ($grants.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'Critical' `
            -Detail 'No user-principal OAuth consent grants on this account.'
        return
    }

    # Scopes that give an app standing access to the mailbox/files. Any ONE
    # of these on a user-consented grant during an incident deserves review;
    # write/send scopes are the classic BEC persistence shape.
    $riskScopes = @(
        'Mail.ReadWrite', 'Mail.Send', 'MailboxSettings.ReadWrite',
        'Files.ReadWrite.All', 'EWS.AccessAsUser.All',
        'full_access_as_user', 'IMAP.AccessAsUser.All',
        'POP.AccessAsUser.All', 'SMTP.Send'
    )
    $watchScopes = @('Mail.Read', 'MailboxSettings.Read', 'offline_access', 'Files.ReadWrite')

    $flagged = @()
    $watched = @()
    foreach ($g in $grants) {
        $scopeList = @(([string]$g.Scope) -split '\s+' | Where-Object { $_ })
        $hits  = @($scopeList | Where-Object { $riskScopes  -contains $_ })
        $soft  = @($scopeList | Where-Object { $watchScopes -contains $_ })
        $appLabel = if ($g.App -and $g.App.DisplayName) { $g.App.DisplayName } else { "spId $($g.ClientSpId)" }
        $verified = if ($g.App -and $g.App.PublisherName) { "publisher '$($g.App.PublisherName)'" } else { 'UNVERIFIED publisher' }
        if ($hits.Count -gt 0) {
            $flagged += "  - '$appLabel' ($verified): $($hits -join ', ')  [full scope: $($g.Scope)]"
        } elseif ($soft.Count -gt 0) {
            $watched += "  - '$appLabel' ($verified): $($soft -join ', ')"
        }
    }

    if ($flagged.Count -gt 0) {
        $detail = "FOUND $($flagged.Count) grant(s) with mail/file write-or-send scopes — OAuth persistence survives password reset + MFA re-enrollment; only revoking the grant kills it.`n" +
                  ($flagged -join "`n") +
                  $(if ($watched.Count -gt 0) { "`nAlso review (read-level scopes):`n" + ($watched -join "`n") } else { '' })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
            -Title $title -Severity 'Critical' -Detail $detail `
            -CurrentValue "$($flagged.Count) high-risk grant(s) of $($grants.Count) total" `
            -RequiredValue 'No unrecognized grants with mail/file write scopes' `
            -Remediation 'Revoke each unrecognized grant: Entra > Enterprise applications > the app > Permissions, or Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <grantId>. Then check the app is not tenant-consented for other users.'
        return
    }

    if ($watched.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail ("No write/send-scope grants, but $($watched.Count) grant(s) carry mail/file READ scopes — verify the user recognizes each app:`n" + ($watched -join "`n")) `
            -CurrentValue "$($watched.Count) read-scope grant(s)" `
            -Remediation 'Confirm each app with the user; revoke anything unrecognized (Entra > Users > the user > Applications).'
        return
    }

    Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
        -Title $title -Severity 'Critical' `
        -Detail "Reviewed $($grants.Count) consent grant(s) — none carry mail or file scopes."
}

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-4.2 — Registered authentication methods (attacker-added MFA)
# ─────────────────────────────────────────────────────────────────────────────
# After stealing a session, attackers add their OWN phone/authenticator so
# they can satisfy MFA on re-auth. Surface every registered method so the
# operator can verify each one with the user on the containment call —
# this feeds Containment Runbook step 2 (delete unrecognized methods).
function Test-NRGEmailControlAuthMethods {
    [CmdletBinding()] param()
    $cid = 'EMAIL-4.2'
    $title = 'Registered MFA / authentication methods'
    $cat = 'Email'

    $methodRaw = Get-NRGRawData -Key 'IR-UserAuthMethods'
    if (-not $methodRaw -or -not $methodRaw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail 'Auth-method collection did not succeed (requires UserAuthenticationMethod.Read.All — available in admin triage mode, not under delegated user scope). To rule out manually: Entra > Users > the user > Authentication methods.'
        return
    }

    $methods = @($methodRaw.Data.Methods)
    if ($methods.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail 'NO authentication methods registered. Either MFA was never set up (account protected by password alone) or all methods were deleted. Both warrant follow-up.' `
            -Remediation 'Enroll a trusted MFA method (or issue a Temporary Access Pass to bootstrap one).'
        return
    }

    # Inventory always goes in the Detail — the operator reads this list TO
    # the user on the call ("do you have a phone ending in ..34?").
    $inv = foreach ($m in $methods) {
        $disp = if ($m.Display) { " — $($m.Display)" } else { '' }
        $when = if ($m.CreatedDateTime) { " (registered $($m.CreatedDateTime))" } else { '' }
        "  - $($m.MethodType)$disp$when"
    }

    $signals = @()
    $phoneCount = @($methods | Where-Object { $_.MethodType -like 'phone*' }).Count
    if ($phoneCount -gt 1) { $signals += "$phoneCount phone methods registered (attackers add a second phone)" }
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-14)
    $recent = @($methods | Where-Object {
        $_.CreatedDateTime -and ([datetime]::Parse([string]$_.CreatedDateTime).ToUniversalTime() -gt $cutoff)
    })
    if ($recent.Count -gt 0) {
        $signals += "$($recent.Count) method(s) registered in the last 14 days: " + (@($recent | ForEach-Object { $_.MethodType }) -join ', ')
    }

    if ($signals.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail ("SIGNALS: " + ($signals -join '; ') + "`nRegistered methods — verify EACH with the user:`n" + ($inv -join "`n")) `
            -CurrentValue "$($methods.Count) method(s), $($signals.Count) signal(s)" `
            -Remediation 'Read the method list to the user. Delete anything they do not recognize: Entra > Users > the user > Authentication methods (Containment Runbook step 2).'
        return
    }

    Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
        -Title $title -Severity 'High' `
        -Detail ("No anomaly signals. Registered methods — still verify with the user during containment:`n" + ($inv -join "`n"))
}

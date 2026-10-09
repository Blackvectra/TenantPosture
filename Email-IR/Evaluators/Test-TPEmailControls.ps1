#Requires -Version 7.0
#
# Test-TPEmailControls.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Evaluators for the NRG Email Account Assessment (incident-response
#          mode). Consumes mailbox data collected by
#          Invoke-TPEmailCollectMailbox, scores findings, and ranks the most
#          likely original phishing email.
#
# Reads:   IR-MailboxSentItems, IR-MailboxInbox, IR-MailboxRecoverable,
#          IR-MailboxRules, IR-MailboxForwarding, IR-MailboxProfile.
# Writes:  Findings via Add-TPFinding with EMAIL-* control IDs.
#
# Heuristics intentionally tuned for SIGNAL not certainty — the operator
# reviews and confirms. False-positive rate is acceptable because the
# alternative is missing the real phish.

# Microsoft "real" login domains that legitimately host auth flows.
$script:TPEmailLegitMSDomains = @(
    'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com',
    'office.com', 'office365.com', 'azure.com', 'onmicrosoft.com',
    'sharepoint.com', 'sharepointonline.com', 'microsoft365.com', 'msft.net', 'azureedge.net', 'azurewebsites.net'
)

# Microsoft-impersonation substrings — domains that mention Microsoft
# branding while NOT being legit MS-owned. Tuned for typo-squat patterns
# the threat intel community sees in the wild.
$script:TPEmailMSImpersonationPatterns = @(
    'microsft', 'micrsoft', 'mircosoft', 'micorsoft', 'micros0ft',
    'm1crosoft', 'microsofte', 'microsofts', 'microsoftonine',
    'micro-soft', 'micros-oft', 'office356', 'office-365',
    'login-microsoft', 'microsoft-login', 'ms-office', 'msoffice365'
)

# Urgency keywords in subject lines — classic phish/BEC indicators
$script:TPEmailUrgencyKeywords = @(
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
$script:TPEmailBECOutboundPatterns = @(
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
function Get-TPEmailDomainFromAddress {
    [CmdletBinding()]
    param([string] $Address)
    if (-not $Address) { return $null }
    $at = $Address.IndexOf('@')
    if ($at -lt 0 -or $at -ge ($Address.Length - 1)) { return $null }
    return $Address.Substring($at + 1).ToLowerInvariant().Trim('"', "'", ' ', '<', '>')
}

function Test-TPEmailIsLegitMSDomain {
    [CmdletBinding()]
    param([string] $Domain)
    if (-not $Domain) { return $false }
    $d = $Domain.ToLowerInvariant()
    foreach ($legit in $script:TPEmailLegitMSDomains) {
        if ($d -eq $legit -or $d.EndsWith(".$legit")) { return $true }
    }
    return $false
}

# Brands other than Microsoft are judged against THEIR OWN sending domains, not
# Microsoft's: a genuine DocuSign or Adobe message is not a spoof because its
# domain is not a Microsoft one.
$script:TPEmailBrandDomains = [ordered]@{
    'docusign' = @('docusign.com', 'docusign.net')
    'adobe'    = @('adobe.com', 'adobesign.com', 'echosign.com', 'adobe.io')
    'dropbox'  = @('dropbox.com', 'dropboxmail.com')
}

function Get-TPEmailBrandSpoof {
    [CmdletBinding()]
    param([string] $Domain, [string] $DisplayName)
    if (-not $Domain -or -not $DisplayName) { return $null }
    $d = $Domain.ToLowerInvariant()
    foreach ($brand in $script:TPEmailBrandDomains.Keys) {
        if ($DisplayName -match "(?i)$brand") {
            $legit = $false
            foreach ($ld in $script:TPEmailBrandDomains[$brand]) { if ($d -eq $ld -or $d.EndsWith(".$ld")) { $legit = $true } }
            if (-not $legit) { return $brand }
        }
    }
    if ($DisplayName -match '(?i)microsoft|onedrive' -and -not (Test-TPEmailIsLegitMSDomain $d)) { return 'microsoft' }
    return $null
}

# The strong half of the impersonation test: the SENDING DOMAIN itself imitates Microsoft's
# (a typo-squat such as microsft or office356). A display name alone is not this.
function Test-TPEmailMSDomainTyposquat {
    [CmdletBinding()]
    param([string] $Domain)
    if (-not $Domain) { return $false }
    $d = $Domain.ToLowerInvariant()
    foreach ($pat in $script:TPEmailMSImpersonationPatterns) {
        if ($d -like "*$pat*") { return $true }
    }
    return $false
}

function Test-TPEmailMatchesMSImpersonation {
    [CmdletBinding()]
    param([string] $Domain, [string] $DisplayName)
    if (-not $Domain) { return $false }
    $d = $Domain.ToLowerInvariant()
    # If it claims to be Microsoft in the display name but isn't a legit MS
    # domain, that's a high-signal impersonation indicator.
    if ($DisplayName -and ($DisplayName -match '(?i)microsoft|office\s*365|outlook|onedrive') -and
        -not (Test-TPEmailIsLegitMSDomain $d)) {
        return $true
    }
    foreach ($pat in $script:TPEmailMSImpersonationPatterns) {
        if ($d -like "*$pat*") { return $true }
    }
    return $false
}


# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-1.1 — Inbox rules with persistence / cover-tracks signatures
# ─────────────────────────────────────────────────────────────────────────────
function Test-TPEmailControlInboxRules {
    [CmdletBinding()] param()
    $cid = 'EMAIL-1.1'
    $title = 'Suspicious inbox rules (BEC persistence / cover-tracks)'
    $cat = 'Email'

    $rulesRaw = Get-TPRawData -Key 'IR-MailboxRules'
    if (-not $rulesRaw -or -not $rulesRaw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' -Detail 'Inbox-rules collection did not succeed.'
        return
    }

    $rules = @($rulesRaw.Data.Rules)

    # The domain the mailbox belongs to, when the profile was read: the only
    # reference this mode has for "inside" versus "outside". It is NOT the full
    # accepted-domain list, so a different domain may still be another domain of
    # the same organization; the finding says so instead of calling it external.
    $refDomain = ''
    $profileRaw = Get-TPRawData -Key 'IR-MailboxProfile'
    if ($profileRaw -and (Get-TPObjectField -Item $profileRaw -Key 'Success' -Default $false)) {
        $pu = [string](Get-TPNestedProperty -Object $profileRaw -Path 'Data.UserPrincipalName' -Default '')
        if ($pu -match '@([^@\s]+)$') { $refDomain = $Matches[1].ToLowerInvariant() }
    }

    # Each rule is scored on what it DOES, not on which action keyword appears.
    # A folder move alone is routine (every newsletter rule has one) and is
    # never flagged; forwarding to the mailbox's own domain is not flagged; the
    # combinations attackers use (hidden name, forward out, no filter, delete)
    # are. A disabled rule cannot be acting now, so it is kept as historical
    # evidence, never as current persistence.
    $iocRules = @()
    $routine  = 0
    foreach ($r in $rules) {
        $reasons = @()
        $points  = 0
        # Graph omits properties that are not set, so a rule carries only the
        # actions it has: every read goes through Get-TPObjectField (a bare
        # $r.actions.forwardAsAttachmentTo throws under StrictMode on a rule that
        # only forwards, which failed this evaluator on real rules).
        $name = [string](Get-TPObjectField -Item $r -Key 'displayName' -Default '')
        $actions = Get-TPObjectField -Item $r -Key 'actions' -Default $null
        $enabledRaw = Get-TPObjectField -Item $r -Key 'isEnabled' -Default $null
        $active = ($enabledRaw -ne $false)

        # Hidden-name pattern (attacker convention): single ".", "..", "/", "-"
        if ($name -match '^[\.\-/_ ]{1,3}$') { $reasons += "hidden-name '$name'"; $points += 3 }

        $forwardTo = @()
        $destClass = 'None'
        if ($actions) {
            foreach ($key in 'forwardTo','forwardAsAttachmentTo','redirectTo') {
                $list = Get-TPObjectField -Item $actions -Key $key -Default $null
                if ($list) {
                    foreach ($recip in @($list)) {
                        $addr = [string](Get-TPNestedProperty -Object $recip -Path 'emailAddress.address' -Default '')
                        if ($addr) { $forwardTo += $addr }
                    }
                }
            }
            if ($forwardTo.Count -gt 0) {
                $classes = foreach ($a in $forwardTo) {
                    $dom = if (([string]$a) -match '@([^@\s]+)$') { $Matches[1].ToLowerInvariant() } else { '' }
                    if (-not $dom -or -not $refDomain) { 'Unknown' } elseif ($dom -eq $refDomain) { 'SameDomain' } else { 'OtherDomain' }
                }
                $destClass = if ($classes -contains 'OtherDomain') { 'OtherDomain' } elseif ($classes -contains 'Unknown') { 'Unknown' } else { 'SameDomain' }
                switch ($destClass) {
                    'OtherDomain' { $reasons += "forwards to a different domain than the mailbox's ($($forwardTo -join ', ')); may be another domain of the same organization, verify"; $points += 3 }
                    'Unknown'     { $reasons += "forwards to $($forwardTo -join ', '); the destination could not be compared with the mailbox's domain"; $points += 2 }
                    default       { }   # same domain: internal forwarding, not an indicator by itself
                }
            }
            if ((Get-TPObjectField -Item $actions -Key 'delete' -Default $false) -eq $true)          { $reasons += 'deletes matching mail'; $points += 2 }
            if ((Get-TPObjectField -Item $actions -Key 'permanentDelete' -Default $false) -eq $true) { $reasons += 'permanently deletes'; $points += 2 }
        }

        # Always-applies pattern (no filter conditions = applies to everything)
        $cond = Get-TPObjectField -Item $r -Key 'conditions' -Default $null
        $noConditions = (-not $cond) -or
                        (($cond -is [System.Collections.IDictionary]) -and $cond.Count -eq 0) -or
                        (($cond -isnot [System.Collections.IDictionary]) -and @($cond.PSObject.Properties).Count -eq 0)
        if ($noConditions -and $forwardTo.Count -gt 0 -and $destClass -ne 'SameDomain') {
            $reasons += 'no filter conditions (applies to all mail)'; $points += 2
        }

        # Thresholds: a single weak signal is not an indicator.
        $minPoints = if ($active) { 2 } else { 3 }
        if ($points -lt $minPoints) { $routine++; continue }

        $severity = if (-not $active) { 'Medium' } elseif ($points -ge 5) { 'Critical' } elseif ($points -ge 3) { 'High' } else { 'Medium' }
        $confidence = if ($points -ge 5) { 'High' } elseif ($points -ge 3) { 'Medium' } else { 'Low' }
        $iocRules += [ordered]@{
            Name        = $name
            Id          = [string](Get-TPObjectField -Item $r -Key 'id' -Default '')
            Enabled     = $enabledRaw
            Active      = $active
            Severity    = $severity
            Confidence  = $confidence
            Destination = $destClass
            Reasons     = $reasons
            ForwardTo   = $forwardTo
        }
    }

    if ($iocRules.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail ("Reviewed $($rules.Count) inbox rule(s). None combined the actions attackers use for persistence or covering tracks ($routine rule(s) had only routine actions such as a folder move or internal forwarding). This describes the rules read, not other persistence mechanisms.")
    } else {
        $order = @{ 'Critical' = 3; 'High' = 2; 'Medium' = 1 }
        $top = ($iocRules | Sort-Object { $order[$_.Severity] } -Descending | Select-Object -First 1).Severity
        $activeCount = @($iocRules | Where-Object { $_.Active }).Count
        $detail = "FOUND $($iocRules.Count) inbox rule(s) worth review ($activeCount enabled, $($iocRules.Count - $activeCount) disabled).`n" + (
            ($iocRules | ForEach-Object {
                $st = if ($_.Active) { if ($null -eq $_.Enabled) { 'enabled state not reported, treated as active' } else { 'enabled' } } else { 'DISABLED: historical, not acting now' }
                "  - '$($_.Name)' [$st; $($_.Severity), confidence $($_.Confidence)]: $($_.Reasons -join '; ')"
            }) -join "`n"
        )
        # Attach the flagged rules as structured AffectedObjects so the
        # containment runbook can name each one (and emit a precise delete
        # command). RuleType marks these as inbox rules so the publisher /
        # runbook can distinguish them from EMAIL-2.1 recipient objects.
        $ruleObjects = foreach ($ir in $iocRules) {
            [pscustomobject]@{
                RuleType    = 'InboxRule'
                Name        = $ir.Name
                Id          = $ir.Id
                Enabled     = $ir.Enabled
                Severity    = $ir.Severity
                Confidence  = $ir.Confidence
                Destination = $ir.Destination
                Reason      = ($ir.Reasons -join '; ')
            }
        }
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $cat `
            -Title $title -Severity $top `
            -Detail $detail `
            -AffectedObjects @($ruleObjects) `
            -Remediation "Confirm each enabled rule with the mailbox owner, then delete the ones that are not theirs (named in the Containment Runbook). A disabled rule is not acting now: review it as evidence of earlier tampering and remove it, but it is not evidence of current persistence. PowerShell: Get-MgUserMailFolderMessageRule -UserId <upn> -MailFolderId Inbox  then  Remove-MgUserMailFolderMessageRule -UserId <upn> -MailFolderId Inbox -MessageRuleId <id>"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-1.2 — Mailbox forwarding (server-side, separate from inbox rules)
# ─────────────────────────────────────────────────────────────────────────────
function Test-TPEmailControlForwarding {
    [CmdletBinding()] param()
    $cid = 'EMAIL-1.2'
    $title = 'Mailbox server-side forwarding'
    $cat = 'Email'

    # The Graph mailboxSettings endpoint doesn't expose the forwarding
    # SMTP address directly under delegated scope (it's typically EXO-only
    # via Set-Mailbox -ForwardingSmtpAddress). What we CAN check via Graph
    # is whether ANY rule forwards externally — which Test-TPEmailControlInboxRules
    # already does. Here we just note the gap.
    $settingsRaw = Get-TPRawData -Key 'IR-MailboxForwarding'
    if (-not $settingsRaw -or -not $settingsRaw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail 'Mailbox-settings collection did not succeed.'
        return
    }

    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
        -Title $title -Severity 'Medium' `
        -Detail 'Server-side ForwardingSmtpAddress is not exposed under delegated Graph scope. To rule out, run from an admin context: Get-Mailbox <upn> | Select ForwardingSmtpAddress,DeliverToMailboxAndForward'
}

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-2.1 — Outbound activity scan (what did the attacker send?)
# ─────────────────────────────────────────────────────────────────────────────
function Test-TPEmailControlOutboundActivity {
    [CmdletBinding()] param()
    $cid = 'EMAIL-2.1'
    $title = 'Outbound activity from compromised account'
    $cat = 'Email'

    $sentRaw = Get-TPRawData -Key 'IR-MailboxSentItems'
    if (-not $sentRaw -or -not $sentRaw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' -Detail 'Sent-items collection did not succeed.'
        return
    }

    $profileBag = Get-TPRawData -Key 'IR-MailboxProfile'
    $tenantDomain = $null
    if ($profileBag -and $profileBag.Success -and $profileBag.Data.UserPrincipalName) {
        $tenantDomain = Get-TPEmailDomainFromAddress $profileBag.Data.UserPrincipalName
    }

    $messages = @($sentRaw.Data.Messages)
    if ($messages.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $cat `
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
            $rDomain = Get-TPEmailDomainFromAddress $r
            if ($rDomain -and $tenantDomain -and $rDomain -eq $tenantDomain) {
                [void]$internalRecipients.Add($r)
            } else {
                [void]$externalRecipients.Add($r)
            }
        }
        # BEC subject patterns
        foreach ($pat in $script:TPEmailBECOutboundPatterns) {
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
        # Burst detection — group by hour bucket (UTC, culture-invariant; an
        # unparseable time is unknown and is left out of the buckets).
        $sentUtc = ConvertTo-TPUtcDateTime $m.SentDateTime
        if ($sentUtc) {
            $hour = $sentUtc.ToString('yyyy-MM-dd HH', [cultureinfo]::InvariantCulture)
            if (-not $burstWindows.ContainsKey($hour)) { $burstWindows[$hour] = 0 }
            $burstWindows[$hour]++
        }
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
        $rDomain = Get-TPEmailDomainFromAddress $r
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

    Add-TPFinding -ControlId $cid -State $state -Category $cat `
        -Title $title -Severity $severity -Detail $detail `
        -CurrentValue "$($messages.Count) messages, $($warnList.Count) recipients to warn" `
        -AffectedObjects $affected `
        -Remediation "Notify every recipient in the warn-list (report + recipients.csv) that mail from this account during the compromise window may be fraudulent. Preserve sent-item evidence before any cleanup."
}

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-3.1 — Most-likely original phishing email
# ─────────────────────────────────────────────────────────────────────────────
function Test-TPEmailControlPhishOrigin {
    [CmdletBinding()] param()
    $cid = 'EMAIL-3.1'
    $title = 'Most-likely original phishing email'
    $cat = 'Email'

    $inboxRaw = Get-TPRawData -Key 'IR-MailboxInbox'
    if (-not $inboxRaw -or -not $inboxRaw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' -Detail 'Inbox collection did not succeed.'
        return
    }
    $recRaw = Get-TPRawData -Key 'IR-MailboxRecoverable'

    $profileBag = Get-TPRawData -Key 'IR-MailboxProfile'
    $tenantDomain = $null
    if ($profileBag -and $profileBag.Success -and $profileBag.Data.UserPrincipalName) {
        $tenantDomain = Get-TPEmailDomainFromAddress $profileBag.Data.UserPrincipalName
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
        $senderDomain = Get-TPEmailDomainFromAddress $m.FromAddress
        $contentSignals = 0   # strong signals: urgency, a sign-in link to a non-Microsoft host, a typo-squatted domain
        $weakSignals    = 0   # a display name that claims a brand; legitimate vendors and distributors do this too
        $isInternal = $false

        # +30 if the sender is outside the mailbox's domain. A sender INSIDE it is
        # not dropped: a compromised or spoofed internal account is a real
        # phishing route. It gets no sender points and must earn its place on
        # content alone (two or more content signals), and is marked lower
        # confidence.
        if ($senderDomain -and $tenantDomain -and $senderDomain -ne $tenantDomain) {
            $score += 30
            $reasons += "sender outside the mailbox's domain ($senderDomain)"
        } elseif (-not $senderDomain) {
            # Couldn't parse — possibly a spoofed display name only
            $score += 20
            $reasons += 'unparseable sender'
        } else {
            $isInternal = $true
            $reasons += "sender inside the mailbox's own domain ($senderDomain): a compromised or spoofed internal account is possible"
        }

        # +25 if domain mentions Microsoft branding without being legit MS
        $fromName = Get-TPObjectField -Item $m -Key 'FromName' -Default $null
        # A typo-squatted sending domain is a strong signal. A display name that merely says
        # "Microsoft" from a non-Microsoft domain is weak: Microsoft partners, distributors and training
        # services do exactly that (the first live run ranked LevelUp, an Ingram Micro reminder and a
        # Loop digest as the "most likely phish"), so it is counted once, as a weak signal.
        $msDomainTypo = Test-TPEmailMSDomainTyposquat -Domain $senderDomain
        $msNameClaim  = Test-TPEmailMatchesMSImpersonation -Domain $senderDomain -DisplayName $fromName
        if ($msDomainTypo) {
            $score += 25; $contentSignals++
            $reasons += "Microsoft-impersonation pattern in the sending domain"
        } elseif ($msNameClaim) {
            $score += 15; $weakSignals++
            $reasons += "the display name says Microsoft but the sending domain is not a Microsoft domain (weak on its own: vendors, distributors and training services do this)"
        }

        # +20 if subject contains urgency keywords
        $subject = [string]$m.Subject
        foreach ($pat in $script:TPEmailUrgencyKeywords) {
            if ($subject -match "(?i)$pat") {
                $score += 20; $contentSignals++
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
                if ($uri.Host -and -not (Test-TPEmailIsLegitMSDomain $uri.Host) -and
                    ($url -match '(?i)login|signin|auth|verify|reset|password|account')) {
                    $hasSuspiciousLoginUrl = $true
                    break
                }
            } catch { }
        }
        if ($hasSuspiciousLoginUrl) {
            $score += 20; $contentSignals++
            $reasons += "link in the message preview to a non-Microsoft host, with sign-in keywords"
        }

        # +10 when the display name claims a brand the sending domain does not
        # belong to. Each brand is judged against its own domains.
        # (Microsoft itself is already judged above; counting it again made one display name two signals.)
        $spoofBrand = Get-TPEmailBrandSpoof -Domain $senderDomain -DisplayName $fromName
        if ($spoofBrand -and -not ($spoofBrand -eq 'microsoft' -and $msNameClaim)) {
            $score += 10; $weakSignals++
            $reasons += "display name claims '$spoofBrand' but the sending domain is not one of its domains: '$fromName'"
        }

        # Found in Recoverable Items: the message was deleted by someone, a user
        # or rule or an attacker. Exchange does not say which, so this adds a
        # small amount of rank and NEVER assigns the deletion to an actor. It
        # cannot qualify a message on its own.
        $isRecovered = $false
        if ($recRaw -and $recRaw.Success -and $recRaw.Data.Messages) {
            $recIds = @($recRaw.Data.Messages | ForEach-Object { Get-TPObjectField -Item $_ -Key 'Id' -Default $null })
            if ($recIds -contains $m.Id) {
                $score += 15
                $isRecovered = $true
                $reasons += "found in Recoverable Items (deleted; who deleted it is not known)"
            }
        }

        # A lead needs at least one content signal (two for an internal sender);
        # sender location, an unparseable address or a deletion alone do not
        # make a phishing candidate.
        $needed = if ($isInternal) { 2 } else { 1 }
        if (($contentSignals + $weakSignals) -lt $needed) { continue }

        [ordered]@{
            Internal         = $isInternal
            ReceivedDateTime = $m.ReceivedDateTime
            From             = $m.FromAddress
            FromName         = $fromName
            Subject          = $subject
            Score            = $score
            WeakOnly         = ($contentSignals -eq 0)
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
    # Leads with a strong signal come first; a lead resting on a display name alone is kept (so nothing
    # is hidden) but ranks below them and is labeled.
    $top = @($scored | Where-Object { $_.Score -gt 30 -or $_.Internal } |
        Sort-Object @{ Expression = { -not $_.WeakOnly }; Descending = $true }, @{ Expression = { $_.Score }; Descending = $true } |
        Select-Object -First 5)

    # What was read, stated with every result: the folders, the window, whether
    # the read was complete, and that links come from the message PREVIEW only.
    $inboxTrunc = [bool](Get-TPNestedProperty -Object $inboxRaw -Path 'Data.Truncated' -Default $false)
    $recTrunc   = [bool](Get-TPNestedProperty -Object $recRaw -Path 'Data.Truncated' -Default $false)
    $inboxWin   = [int](Get-TPNestedProperty -Object $inboxRaw -Path 'Data.WindowDays' -Default 30)
    $scope = "Scope: Inbox messages from the last $inboxWin days$(if ($inboxTrunc) { ' (the read stopped at its page cap, so older messages in that window were not read)' }) and the first page of Recoverable Items Deletions$(if ($recTrunc) { ' (more items exist than were read)' }); $($candidates.Count) message(s) examined, $recoveredCount of them from Recoverable Items. Links were read from the message preview only (roughly the first 255 characters), so a link later in the body was not seen. Other folders, and mail the user already permanently deleted, are not covered."

    if ($top.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Medium' `
            -Detail ("No lead looked like a phishing message within what was read. This is not evidence there was none: the phish may predate the window, arrive by another route (credential stuffing, a token theft), sit in a folder not read, or have been permanently deleted. $scope")
        return
    }

    $detail = "TOP $($top.Count) LEADS (highest rank first; a rank orders messages for review, it is not a probability):`n"
    foreach ($t in $top) {
        $detail += "`n  Rank score $($t.Score) | $($t.ReceivedDateTime)$(if ($t.Internal) { ' | lower confidence: sender inside the mailbox domain' })$(if ($t.WeakOnly) { ' | weaker lead: a display name alone, no other phishing signal' })`n"
        $detail += "    From    : `"$($t.FromName)`" <$($t.From)>`n"
        $detail += "    Subject : $($t.Subject)`n"
        $detail += "    Why     : $($t.Reasons -join '; ')`n"
        if ($t.URLs.Count -gt 0) {
            $detail += "    URLs    : $(($t.URLs | Select-Object -First 3) -join ', ')`n"
        }
    }
    $detail += "`nThese are investigative leads to review in Outlook, not a finding that any of them caused the compromise. $scope"

    # High only when a lead carries a strong signal; leads that rest on a display name alone are
    # worth a look, not a High indicator.
    $leadSeverity = if (@($top | Where-Object { -not $_.WeakOnly }).Count -gt 0) { 'High' } else { 'Medium' }
    if ($leadSeverity -eq 'Medium') {
        $detail = "No lead carries a strong phishing signal (urgency wording, a sign-in link to a non-Microsoft host, or a typo-squatted sending domain); every lead below rests on a display name alone.`n`n" + $detail
    }
    Add-TPFinding -ControlId $cid -State 'Gap' -Category $cat `
        -Title $title -Severity $leadSeverity -Detail $detail `
        -CurrentValue "Top lead: $($top[0].Subject) (rank score $($top[0].Score))" `
        -Remediation "Review the leads and confirm whether any is a real phish. If one is: 1) submit its URL and sender to Microsoft Defender Submissions, 2) block the sender domain at the tenant boundary, 3) search for and purge the same message for other users (admin scope required)."
}

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL-3.2 — Threat-intel enrichment on top sender domains
# ─────────────────────────────────────────────────────────────────────────────
function Test-TPEmailControlThreatIntel {
    [CmdletBinding()] param()
    $cid = 'EMAIL-3.2'
    $title = 'Threat-intel enrichment on top sender / URL domains'
    $cat = 'Email'

    if (-not (Get-Command Get-TPDomainAge -ErrorAction SilentlyContinue)) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Medium' -Detail 'Get-TPDomainAge helper not loaded.'
        return
    }

    $inboxRaw = Get-TPRawData -Key 'IR-MailboxInbox'
    if (-not $inboxRaw -or -not $inboxRaw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Medium' -Detail 'Inbox data unavailable for enrichment.'
        return
    }

    # Pull sender domains from top phish candidates (re-score quickly)
    $profileBag = Get-TPRawData -Key 'IR-MailboxProfile'
    $tenantDomain = $null
    if ($profileBag -and $profileBag.Success -and $profileBag.Data.UserPrincipalName) {
        $tenantDomain = Get-TPEmailDomainFromAddress $profileBag.Data.UserPrincipalName
    }

    $domains = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in @($inboxRaw.Data.Messages)) {
        $d = Get-TPEmailDomainFromAddress $m.FromAddress
        if ($d -and $tenantDomain -and $d -ne $tenantDomain -and -not (Test-TPEmailIsLegitMSDomain $d)) {
            [void]$domains.Add($d)
        }
    }
    # Cap at 10 — RDAP is rate-limited and operators don't need 100 lookups
    $topDomains = @($domains | Select-Object -First 10)

    $enriched = foreach ($d in $topDomains) {
        $age = Get-TPDomainAge -Domain $d
        $age
    }

    $young = @($enriched | Where-Object { $null -ne $_.AgeDays -and $_.AgeDays -lt 30 })

    if ($young.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $cat `
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

    Add-TPFinding -ControlId $cid -State 'Gap' -Category $cat `
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
function Test-TPEmailControlOAuthConsents {
    [CmdletBinding()] param()
    $cid = 'EMAIL-4.1'
    $title = 'OAuth consent grants on the account'
    $cat = 'Email'

    $consentRaw = Get-TPRawData -Key 'IR-UserConsents'
    if (-not $consentRaw -or -not $consentRaw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Critical' `
            -Detail 'OAuth consent collection did not succeed (requires Directory.Read.All — available in admin triage mode, usually not under delegated user scope). To rule out manually: Entra > Users > the user > Applications, or Get-MgUserOauth2PermissionGrant -UserId <upn>.'
        return
    }

    $grants = @($consentRaw.Data.Grants)
    # The collector reads one page. A next link means more grants exist than were
    # read: what the page holds can be reported, "none" cannot be concluded.
    $grantsTruncated = [bool](Get-TPNestedProperty -Object $consentRaw -Path 'Data.Truncated' -Default $false)
    $truncNote = 'The grant list stopped at one page (Graph returned a next link), so more grants exist than were read.'
    if ($grants.Count -eq 0) {
        if ($grantsTruncated) {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
                -Title $title -Severity 'Critical' `
                -Detail "Not cleared: no grant was on the page read. $truncNote"
            return
        }
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $cat `
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
    $identifiedFlagged = 0
    $noPublisherFlagged = 0
    $unidentifiedFlagged = 0
    foreach ($g in $grants) {
        $scopeList = @(([string]$g.Scope) -split '\s+' | Where-Object { $_ })
        $hits  = @($scopeList | Where-Object { $riskScopes  -contains $_ })
        $soft  = @($scopeList | Where-Object { $watchScopes -contains $_ })
        # Say only what was checked. The app lookup needs Directory.Read.All, which a delegated
        # user sign-in does not have, so "UNVERIFIED publisher" was printed for every app whose publisher
        # was never read (Microsoft's own apps included).
        $appKnown = [bool]($g.App -and $g.App.DisplayName)
        $appLabel = if ($appKnown) { $g.App.DisplayName } else { "app not identified, service principal $($g.ClientSpId)" }
        $verified = if ($g.App -and $g.App.PublisherName) { "publisher '$($g.App.PublisherName)'" }
                    elseif ($appKnown) { 'UNVERIFIED publisher (the lookup returned no publisher name)' }
                    else { 'publisher not checked: the lookup needs Directory.Read.All' }
        if ($hits.Count -gt 0) {
            $flagged += "  - '$appLabel' ($verified): $($hits -join ', ')  [full scope: $($g.Scope)]"
            if ($appKnown) {
                $identifiedFlagged++
                if (-not $g.App.PublisherName) { $noPublisherFlagged++ }
            } else { $unidentifiedFlagged++ }
        } elseif ($soft.Count -gt 0) {
            $watched += "  - '$appLabel' ($verified): $($soft -join ', ')"
        }
    }

    if ($flagged.Count -gt 0) {
        $detail = "FOUND $($flagged.Count) grant(s) with mail/file write-or-send scopes — OAuth persistence survives password reset + MFA re-enrollment; only revoking the grant kills it.`n" +
                  ($flagged -join "`n") +
                  $(if ($unidentifiedFlagged -gt 0) { "`n`nIdentify each app first: Entra admin center > Enterprise applications > search the service principal ID (the Object ID). A Microsoft or other recognized app that holds this scope on purpose is expected; an app nobody recognizes is not." } else { '' }) +
                  $(if ($watched.Count -gt 0) { "`nAlso review (read-level scopes):`n" + ($watched -join "`n") } else { '' }) +
                  $(if ($grantsTruncated) { "`n$truncNote" } else { '' })
        # Critical only when an app was identified AND its lookup returned no publisher
        # name. An identified app with a publisher name is High ("verify the app"): Graph
        # documents publisherName as the name of the Entra tenant that published the app,
        # so it is a lead to check, not proof either way, and a Microsoft app holding a
        # mail scope on purpose must not read as Critical. An unidentified app is High,
        # because it may be an ordinary Microsoft one.
        $grantSeverity = if ($noPublisherFlagged -gt 0) { 'Critical' } else { 'High' }
        if ($identifiedFlagged -gt $noPublisherFlagged) {
            $detail += "`nVerify each app that names a publisher: the publisher name is the Entra tenant that published the app, not a verification. Confirm the app and publisher are ones the user and the organization expect."
        }
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $cat `
            -Title $title -Severity $grantSeverity -Detail $detail `
            -CurrentValue "$($flagged.Count) high-risk grant(s) of $($grants.Count) total" `
            -RequiredValue 'No unrecognized grants with mail/file write scopes' `
            -Remediation 'Revoke each unrecognized grant: Entra > Enterprise applications > the app > Permissions, or Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <grantId>. Then check the app is not tenant-consented for other users.'
        return
    }

    if ($watched.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail ("No write/send-scope grants among those read, but $($watched.Count) grant(s) carry mail/file READ scopes — verify the user recognizes each app:`n" + ($watched -join "`n") + $(if ($grantsTruncated) { "`n$truncNote" } else { '' })) `
            -CurrentValue "$($watched.Count) read-scope grant(s)" `
            -Remediation 'Confirm each app with the user; revoke anything unrecognized (Entra > Users > the user > Applications).'
        return
    }

    if ($grantsTruncated) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Critical' `
            -Detail "Not cleared: none of the $($grants.Count) grant(s) read carry mail or file scopes. $truncNote"
        return
    }
    Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $cat `
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
function Test-TPEmailControlAuthMethods {
    [CmdletBinding()] param()
    $cid = 'EMAIL-4.2'
    $title = 'Registered MFA / authentication methods'
    $cat = 'Email'

    $methodRaw = Get-TPRawData -Key 'IR-UserAuthMethods'
    if (-not $methodRaw -or -not $methodRaw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail 'Auth-method collection did not succeed (requires UserAuthenticationMethod.Read.All — available in admin triage mode, not under delegated user scope). To rule out manually: Entra > Users > the user > Authentication methods.'
        return
    }

    $methods = @($methodRaw.Data.Methods)
    if ($methods.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $cat `
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
        # Culture-invariant; an unparseable date is unknown, not recent and not a throw.
        $createdUtc = ConvertTo-TPUtcDateTime $_.CreatedDateTime
        $createdUtc -and ($createdUtc -gt $cutoff)
    })
    if ($recent.Count -gt 0) {
        $signals += "$($recent.Count) method(s) registered in the last 14 days: " + (@($recent | ForEach-Object { $_.MethodType }) -join ', ')
    }

    if ($signals.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail ("SIGNALS: " + ($signals -join '; ') + "`nRegistered methods — verify EACH with the user:`n" + ($inv -join "`n")) `
            -CurrentValue "$($methods.Count) method(s), $($signals.Count) signal(s)" `
            -Remediation 'Read the method list to the user. Delete anything they do not recognize: Entra > Users > the user > Authentication methods (Containment Runbook step 2).'
        return
    }

    Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $cat `
        -Title $title -Severity 'High' `
        -Detail ("No anomaly signals. Registered methods — still verify with the user during containment:`n" + ($inv -join "`n"))
}

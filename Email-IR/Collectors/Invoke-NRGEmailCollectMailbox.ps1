#Requires -Version 7.0
#
# Invoke-NRGEmailCollectMailbox.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Collect mailbox data for incident response — the compromised
#          user's sent items, inbox (for phish hunting), inbox rules,
#          mailbox forwarding settings, and recoverable items (the
#          "deleted items dumpster" where attackers hide the phish
#          they used to compromise the account).
#
#          Single-user delegated scopes only (Mail.Read + MailboxSettings.Read).
#          Does NOT read other users' mailboxes, does NOT touch tenant policy.
#
# Sets:    IR-MailboxSentItems     — recent sent messages (window-filtered)
#          IR-MailboxInbox         — recent inbox (for phish ranking)
#          IR-MailboxRecoverable   — recoverable items (deleted phish recovery)
#          IR-MailboxRules         — inbox rules (forward/delete/hide IoCs)
#          IR-MailboxForwarding    — server-side forwarding settings
#          IR-MailboxProfile       — /me basics (UPN, display name, tenant)
#
# Graph cmdlets: Invoke-NRGGraphRequest (REST), all GET-only.
#
# Privacy: Bodies are NOT collected — only headers + a stripped URL list.
#          Subjects + recipients + URLs are retained because they're the
#          IoCs the IR report needs. Operator's responsibility to handle
#          the resulting JSON under their incident-response data handling
#          policy.

function Invoke-NRGEmailCollectMailbox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 90)]
        [int] $WindowDays = 7,

        # v4.12.0 admin-scope IR triage: when supplied, read /users/<upn>/mailFolders/...
        # instead of /me/mailFolders/... so an admin with Mail.Read.All can
        # deep-dive into a flagged user's mailbox without that user's credentials.
        # When omitted, falls back to /me/ (delegated user-scope IR — original behavior).
        [Parameter(Mandatory = $false)]
        [ValidatePattern('^$|^[a-zA-Z0-9][a-zA-Z0-9._+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
        [string] $TargetUpn
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $cutoff      = (Get-Date).ToUniversalTime().AddDays(-$WindowDays).ToString('o')
    # v4.12.0: pivot the URI prefix when running in admin -TargetUpn mode
    $userPrefix = if ($TargetUpn) { "users/$([uri]::EscapeDataString($TargetUpn))" } else { 'me' }
    $collectorId = 'IR-Mailbox'
    Register-NRGCoverage -Family 'Email-IR' -Status 'Collected'

    # ── Profile ──────────────────────────────────────────────────────────────
    $profileBag = [ordered]@{
        CollectorId = "$collectorId-Profile"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        $me = Invoke-NRGGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/${userPrefix}?`$select=id,displayName,mail,userPrincipalName" -ErrorAction Stop
        $profileBag.Data = [ordered]@{
            Id                = $me.id
            DisplayName       = $me.displayName
            Mail              = $me.mail
            UserPrincipalName = $me.userPrincipalName
        }
        $profileBag.Success = $true
    } catch {
        Register-NRGException -Source "$collectorId-Profile" -Message $_.Exception.Message
    }
    Set-NRGRawData -Key 'IR-MailboxProfile' -Data $profileBag

    # ── Sent Items (the attacker's outbound activity) ────────────────────────
    $sentOut = [ordered]@{
        CollectorId = "$collectorId-SentItems"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        $sentItems = @()
        $uri = "https://graph.microsoft.com/v1.0/$userPrefix/mailFolders/SentItems/messages?`$top=200&`$filter=sentDateTime ge $cutoff&`$select=id,subject,sentDateTime,toRecipients,ccRecipients,bccRecipients,bodyPreview,hasAttachments,internetMessageHeaders,from,sender,webLink"
        $pageCap = 5  # Hard cap to keep collection bounded
        $pages   = 0
        while ($uri -and $pages -lt $pageCap) {
            $resp = Invoke-NRGGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if ($resp.value) { $sentItems += $resp.value }
            $uri = if ($resp['@odata.nextLink']) { $resp['@odata.nextLink'] } else { $null }
            $pages++
        }

        # Sanitize: extract URLs from bodyPreview (the first ~250 chars), don't
        # retain bodies. Subject and recipients stay (they're the IoCs).
        $normalized = foreach ($m in $sentItems) {
            $urls = @()
            if ($m.bodyPreview) {
                $urlMatches = [regex]::Matches([string]$m.bodyPreview, 'https?://[^\s"''<>)]+')
                foreach ($mm in $urlMatches) { $urls += $mm.Value }
            }
            $recipients = @()
            foreach ($r in @($m.toRecipients) + @($m.ccRecipients) + @($m.bccRecipients)) {
                if ($r -and $r.emailAddress -and $r.emailAddress.address) {
                    $recipients += $r.emailAddress.address.ToLowerInvariant()
                }
            }
            [ordered]@{
                Id              = $m.id
                Subject         = [string]$m.subject
                SentDateTime    = $m.sentDateTime
                FromAddress     = if ($m.from -and $m.from.emailAddress) { $m.from.emailAddress.address } else { $null }
                Recipients      = $recipients
                HasAttachments  = [bool]$m.hasAttachments
                BodyURLs        = @($urls | Select-Object -Unique)
                # Body itself NOT retained.
            }
        }
        $sentOut.Data = [ordered]@{
            WindowDays = $WindowDays
            Cutoff     = $cutoff
            Count      = $normalized.Count
            Messages   = @($normalized)
        }
        $sentOut.Success = $true
    } catch {
        Register-NRGException -Source "$collectorId-SentItems" -Message $_.Exception.Message
    }
    Set-NRGRawData -Key 'IR-MailboxSentItems' -Data $sentOut

    # ── Inbox (for phish hunting — what got the user compromised?) ───────────
    $inboxOut = [ordered]@{
        CollectorId = "$collectorId-Inbox"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        # Wider window for inbox — the phish that compromised the account
        # may have been received days/weeks before the first attacker
        # outbound. Default 30-day cutoff.
        $inboxCutoff = (Get-Date).ToUniversalTime().AddDays(-30).ToString('o')
        $inboxItems = @()
        $uri = "https://graph.microsoft.com/v1.0/$userPrefix/mailFolders/Inbox/messages?`$top=200&`$filter=receivedDateTime ge $inboxCutoff&`$select=id,subject,receivedDateTime,from,sender,bodyPreview,internetMessageHeaders,webLink"
        $pages = 0
        while ($uri -and $pages -lt 5) {
            $resp = Invoke-NRGGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if ($resp.value) { $inboxItems += $resp.value }
            $uri = if ($resp['@odata.nextLink']) { $resp['@odata.nextLink'] } else { $null }
            $pages++
        }
        $normalized = foreach ($m in $inboxItems) {
            $urls = @()
            if ($m.bodyPreview) {
                $urlMatches = [regex]::Matches([string]$m.bodyPreview, 'https?://[^\s"''<>)]+')
                foreach ($mm in $urlMatches) { $urls += $mm.Value }
            }
            $fromAddr = if ($m.from -and $m.from.emailAddress) { $m.from.emailAddress.address } else { $null }
            $fromName = if ($m.from -and $m.from.emailAddress) { $m.from.emailAddress.name }    else { $null }
            [ordered]@{
                Id               = $m.id
                Subject          = [string]$m.subject
                ReceivedDateTime = $m.receivedDateTime
                FromAddress      = $fromAddr
                FromName         = $fromName
                BodyURLs         = @($urls | Select-Object -Unique)
                BodyPreviewLen   = if ($m.bodyPreview) { $m.bodyPreview.Length } else { 0 }
            }
        }
        $inboxOut.Data = [ordered]@{
            WindowDays = 30
            Cutoff     = $inboxCutoff
            Count      = $normalized.Count
            Messages   = @($normalized)
        }
        $inboxOut.Success = $true
    } catch {
        Register-NRGException -Source "$collectorId-Inbox" -Message $_.Exception.Message
    }
    Set-NRGRawData -Key 'IR-MailboxInbox' -Data $inboxOut

    # ── Recoverable Items (the dumpster — where attacker-deleted phish lives) ─
    $recOut = [ordered]@{
        CollectorId = "$collectorId-Recoverable"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        # The Recoverable Items "Deletions" folder is hidden under
        # RecoverableItemsRoot. Microsoft hides this from the standard
        # mailFolders listing — we navigate to it by name via the
        # well-known childFolders path.
        $recItems = @()
        $recUri = "https://graph.microsoft.com/v1.0/$userPrefix/mailFolders/recoverableitemsdeletions/messages?`$top=200&`$select=id,subject,receivedDateTime,from,bodyPreview"
        try {
            $resp = Invoke-NRGGraphRequest -Method GET -Uri $recUri -ErrorAction Stop
            if ($resp.value) { $recItems = $resp.value }
        } catch {
            # Some tenant configurations + scopes return 404 for this path;
            # if so, skip silently — Recoverable Items not always accessible
            # via delegated Graph. Operator can still check via Outlook
            # "Recover deleted items" if scope is insufficient.
            $recOut.Data = [ordered]@{
                WindowDays         = 30
                Cutoff             = $cutoff
                Count              = 0
                Messages           = @()
                CollectionLimitation = 'Recoverable Items folder not accessible via delegated Graph in this tenant'
            }
            $recOut.Success = $true
            Set-NRGRawData -Key 'IR-MailboxRecoverable' -Data $recOut
            $recItems = $null  # signal we already wrote
        }
        if ($null -ne $recItems) {
            $normalized = foreach ($m in $recItems) {
                $urls = @()
                if ($m.bodyPreview) {
                    $urlMatches = [regex]::Matches([string]$m.bodyPreview, 'https?://[^\s"''<>)]+')
                    foreach ($mm in $urlMatches) { $urls += $mm.Value }
                }
                $fromAddr = if ($m.from -and $m.from.emailAddress) { $m.from.emailAddress.address } else { $null }
                [ordered]@{
                    Id               = $m.id
                    Subject          = [string]$m.subject
                    ReceivedDateTime = $m.receivedDateTime
                    FromAddress      = $fromAddr
                    BodyURLs         = @($urls | Select-Object -Unique)
                }
            }
            $recOut.Data = [ordered]@{
                Count    = $normalized.Count
                Messages = @($normalized)
            }
            $recOut.Success = $true
            Set-NRGRawData -Key 'IR-MailboxRecoverable' -Data $recOut
        }
    } catch {
        Register-NRGException -Source "$collectorId-Recoverable" -Message $_.Exception.Message
        Set-NRGRawData -Key 'IR-MailboxRecoverable' -Data $recOut
    }

    # ── Inbox Rules (persistence + cover-tracks IoCs) ────────────────────────
    $rulesOut = [ordered]@{
        CollectorId = "$collectorId-Rules"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        $rules = Invoke-NRGGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/$userPrefix/mailFolders/Inbox/messageRules" -ErrorAction Stop
        $rulesOut.Data = [ordered]@{
            Count = if ($rules.value) { $rules.value.Count } else { 0 }
            Rules = @($rules.value)
        }
        $rulesOut.Success = $true
    } catch {
        Register-NRGException -Source "$collectorId-Rules" -Message $_.Exception.Message
    }
    Set-NRGRawData -Key 'IR-MailboxRules' -Data $rulesOut

    # ── Mailbox Settings (server-side forwarding, AutoReplies) ───────────────
    $settingsOut = [ordered]@{
        CollectorId = "$collectorId-Forwarding"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        $settings = Invoke-NRGGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/$userPrefix/mailboxSettings" -ErrorAction Stop
        $settingsOut.Data = [ordered]@{
            DelegateMeetingMessageDeliveryOptions = $settings.delegateMeetingMessageDeliveryOptions
            AutomaticRepliesSetting               = $settings.automaticRepliesSetting
            # Server-side forwarding lives in the Outlook setting object
            # which Graph exposes only partially via mailboxSettings; the
            # forwarding rule itself comes through messageRules.
            Language                              = $settings.language
            TimeZone                              = $settings.timeZone
            WorkingHours                          = $settings.workingHours
        }
        $settingsOut.Success = $true
    } catch {
        Register-NRGException -Source "$collectorId-Forwarding" -Message $_.Exception.Message
    }
    Set-NRGRawData -Key 'IR-MailboxForwarding' -Data $settingsOut
}

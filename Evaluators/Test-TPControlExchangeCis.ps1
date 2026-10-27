#Requires -Version 7.0
#
# Test-TPControlExchangeCis.ps1
# NRG Technology Services / NextLayerSec LLC — Author: Matthew Levorson
# Evaluates the Exchange Online and Defender for Office 365 settings seven CIS
# Microsoft 365 Foundations Benchmark v7.0.0 recommendations audit and no other
# control judged: 1.3.3, 2.1.3, 2.1.6, 2.1.11, 2.1.12, 2.4.4 and 6.5.3.
# SCORING ONLY — no API calls.
#
# Consumes: EXO-MailboxConfig (SharingPolicies, OwaMailboxPolicies,
#           OutboundSpamPolicies, OutboundSpamRules, AcceptedDomains),
#           EXO-ConnectionFilter (ConnectionFilter),
#           Defender-Policies (MalwareFilter, TeamsProtection, PresetRules)
# Cmdlets behind the data (collectors): Get-SharingPolicy, Get-OwaMailboxPolicy,
#           Get-HostedOutboundSpamFilterPolicy/Rule, Get-HostedConnectionFilterPolicy,
#           Get-MalwareFilterPolicy/Rule, Get-TeamsProtectionPolicy/Rule
# Config:   Config/cis-m365-comprehensive-attachment-types.json (DEF-6.3)
#
# NIST SP 800-53: AC-3, AC-20, CM-7, SI-3, SI-4, SI-8, IR-6
#

# The 186 file types CIS 2.1.11 lists, lower-case and without a leading dot.
# An unreadable file returns an empty list, which leaves DEF-6.3 not assessed.
function Get-TPCisComprehensiveAttachmentTypes {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $root = Split-Path -Parent $PSScriptRoot
    $path = Join-Path $root 'Config' 'cis-m365-comprehensive-attachment-types.json'
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    try {
        $j = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 5
        return @(@(Get-TPObjectField -Item $j -Key 'Values' -Default @()) | ForEach-Object { ([string]$_).Trim().TrimStart('.').ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    } catch { return @() }
}

# A sharing policy Domains entry, "<domain>:<action>[, <action>...]", parsed.
# Returns $null for an entry that does not have that shape.
function ConvertFrom-TPSharingDomainEntry {
    [CmdletBinding()]
    param([AllowNull()] [string] $Entry)
    if (-not $Entry) { return $null }
    $i = $Entry.IndexOf(':')
    if ($i -lt 1) { return $null }
    $dom = $Entry.Substring(0, $i).Trim()
    $actions = @($Entry.Substring($i + 1).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    [pscustomobject]@{ Domain = $dom; Actions = $actions }
}

# ── EXO-10.1 External calendar sharing not available (CIS 1.3.3) ────────────
function Test-TPControlEXOCalendarSharing {
    [CmdletBinding()] param()
    $cid = 'EXO-10.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $exo = Get-TPRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected; not assessed.'; return
    }
    if (-not (Test-TPSectionCollected $exo 'SharingPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Sharing policies were not collected; not assessed.'; return
    }
    $pols = @(@(Get-TPObjectField -Item $exo.Data -Key 'SharingPolicies' -Default @()) | Where-Object { $null -ne $_ })
    if ($pols.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'No sharing policy was returned, so the Default Sharing Policy could not be read; not assessed.'; return
    }
    $name = { param($p) [string](Get-TPObjectField -Item $p -Key 'Name' -Default '?') }
    $default = @($pols | Where-Object { (Get-TPObjectField -Item $_ -Key 'Default' -Default $null) -eq $true }) | Select-Object -First 1
    if (-not $default) { $default = @($pols | Where-Object { (& $name $_) -eq 'Default Sharing Policy' }) | Select-Object -First 1 }
    if (-not $default) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The default sharing policy could not be identified among the sharing policies returned; not assessed.'; return
    }
    # Calendar sharing with every domain (*) or through anonymous published links.
    $openEntries = { param($p) @(@(Get-TPObjectField -Item $p -Key 'Domains' -Default @()) | ForEach-Object { ConvertFrom-TPSharingDomainEntry -Entry ([string]$_) } |
        Where-Object { $_ -and ($_.Domain -eq '*' -or $_.Domain -eq 'Anonymous') -and @($_.Actions | Where-Object { $_ -like 'CalendarSharing*' }).Count -gt 0 } |
        ForEach-Object { "$($_.Domain):$($_.Actions -join ', ')" }) }
    $verified = @(); $short = @(); $unknown = @(); $affected = @()
    $state = 'Auto'
    $dn = & $name $default
    $den = Get-TPObjectField -Item $default -Key 'Enabled' -Default $null
    $ddoms = @(@(Get-TPObjectField -Item $default -Key 'Domains' -Default @()) | ForEach-Object { [string]$_ })
    if ($null -eq $den) { $unknown += "whether the default sharing policy '$dn' is enabled (Enabled was not returned)." }
    elseif ($den -eq $true) {
        $short += "The default sharing policy '$dn' is enabled ($(if ($ddoms.Count) { "sharing: $($ddoms -join '; ')" } else { 'no domain entries' })), so users can share their calendars with people outside the organization."
        $affected += [ordered]@{ DisplayName = $dn; Shortfall = 'Default sharing policy enabled' }
        $state = 'Gap'
    } else { $verified += "The default sharing policy '$dn' is disabled." }
    foreach ($p in @($pols | Where-Object { $_ -ne $default })) {
        $pn = & $name $p
        $open = @(& $openEntries $p)
        if ($open.Count -eq 0) { continue }
        $pen = Get-TPObjectField -Item $p -Key 'Enabled' -Default $null
        if ($null -eq $pen) { $unknown += "whether sharing policy '$pn' ($($open -join '; ')) is enabled (Enabled was not returned)." }
        elseif ($pen -eq $true) {
            $short += "Sharing policy '$pn' is enabled and shares calendars with $($open -join '; '); it applies to the mailboxes assigned to it (mailbox assignment is not read)."
            $affected += [ordered]@{ DisplayName = $pn; Shortfall = ($open -join '; ') }
        }
    }
    if (-not $short.Count -and -not $unknown.Count -and $pols.Count -gt 1) { $verified += 'No other enabled sharing policy shares calendars with every domain (*) or through anonymous links.' }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknown `
        -ShortfallState $state -AffectedObjects $affected `
        -CurrentValue "Default sharing policy '$dn' Enabled = $(if ($null -eq $den) { 'not returned' } else { $den })" `
        -RequiredValue 'The default sharing policy disabled (Enabled = False), and no enabled sharing policy that shares calendars with * or Anonymous'
}

# ── EXO-10.2 Additional storage providers restricted in Outlook on the web (CIS 6.5.3) ──
function Test-TPControlEXOOwaStorageProviders {
    [CmdletBinding()] param()
    $cid = 'EXO-10.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $exo = Get-TPRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected; not assessed.'; return
    }
    if (-not (Test-TPSectionCollected $exo 'OwaMailboxPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Outlook on the web mailbox policies were not collected; not assessed.'; return
    }
    $pols = @(@(Get-TPObjectField -Item $exo.Data -Key 'OwaMailboxPolicies' -Default @()) | Where-Object { $null -ne $_ })
    $name = { param($p) [string](Get-TPObjectField -Item $p -Key 'Name' -Default '?') }
    $default = @($pols | Where-Object { (Get-TPObjectField -Item $_ -Key 'IsDefault' -Default $null) -eq $true }) | Select-Object -First 1
    if (-not $default) { $default = @($pols | Where-Object { (& $name $_) -eq 'OwaMailboxPolicy-Default' }) | Select-Object -First 1 }
    if (-not $default) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The default Outlook on the web mailbox policy was not found among the policies returned; not assessed.'; return
    }
    $verified = @(); $short = @(); $unknown = @(); $affected = @(); $state = 'Auto'
    $dn = & $name $default
    $dv = Get-TPObjectField -Item $default -Key 'AdditionalStorageProvidersAvailable' -Default $null
    if ($null -eq $dv) { $unknown += "AdditionalStorageProvidersAvailable on the default policy '$dn' (not returned)." }
    elseif ($dv -eq $true) {
        $short += "The default policy '$dn' allows additional storage providers (AdditionalStorageProvidersAvailable = True, Microsoft's default), so users can open and attach files from third-party storage such as Box, Dropbox and Google Drive in Outlook on the web."
        $affected += [ordered]@{ DisplayName = $dn; Shortfall = 'AdditionalStorageProvidersAvailable = True' }
        $state = 'Gap'
    } else { $verified += "The default policy '$dn' restricts additional storage providers." }
    $others = @($pols | Where-Object { $_ -ne $default })
    $otherOn = @(); $otherUnread = @()
    foreach ($p in $others) {
        $v = Get-TPObjectField -Item $p -Key 'AdditionalStorageProvidersAvailable' -Default $null
        if ($null -eq $v) { $otherUnread += (& $name $p) } elseif ($v -eq $true) { $otherOn += (& $name $p) }
    }
    if ($otherOn.Count) {
        $short += "Other Outlook on the web policies allow additional storage providers: $($otherOn -join ', ') (they apply to the mailboxes assigned to them; mailbox assignment is not read)."
        foreach ($n in $otherOn) { $affected += [ordered]@{ DisplayName = $n; Shortfall = 'AdditionalStorageProvidersAvailable = True' } }
    }
    if ($otherUnread.Count) { $unknown += "AdditionalStorageProvidersAvailable on $($otherUnread -join ', ') (not returned)." }
    if ($others.Count -and -not $otherOn.Count -and -not $otherUnread.Count) { $verified += "The other $($others.Count) Outlook on the web policy(ies) restrict additional storage providers too." }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknown `
        -ShortfallState $state -AffectedObjects $affected `
        -CurrentValue "Default policy '$dn' AdditionalStorageProvidersAvailable = $(if ($null -eq $dv) { 'not returned' } else { $dv })" `
        -RequiredValue 'AdditionalStorageProvidersAvailable = False on the default Outlook on the web mailbox policy and on every other policy'
}

# ── EXO-10.3 Connection filter IP Allow List not used (CIS 2.1.12) ──────────
function Test-TPControlEXOConnectionIPAllowList {
    [CmdletBinding()] param()
    $cid = 'EXO-10.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $cf = Get-TPRawData -Key 'EXO-ConnectionFilter'
    if (-not $cf -or -not $cf.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Connection filter data not collected; not assessed.'; return
    }
    $pols = @(@(Get-TPObjectField -Item $cf.Data -Key 'ConnectionFilter' -Default @()) | Where-Object { $null -ne $_ })
    if ($pols.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'No connection filter policy was returned; not assessed.'; return
    }
    # An omitted IPAllowList reads as an empty list, so a list is judged only when the
    # collector recorded that the property was returned (results files from before
    # EXO-10.3 do not say, and are not assessed).
    $unread = @($pols | Where-Object { (Get-TPObjectField -Item $_ -Key 'IPAllowListReturned' -Default $null) -ne $true })
    if ($unread.Count) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Whether IPAllowList was returned is not recorded for $(@($unread | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '?') }) -join ', '); not assessed."
        return
    }
    $withEntries = @($pols | Where-Object { @(@(Get-TPObjectField -Item $_ -Key 'IPAllowList' -Default @()) | Where-Object { $_ }).Count -gt 0 })
    if ($withEntries.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "The IP Allow List is empty on every connection filter policy ($(@($pols | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '?') }) -join ', ')): no source IP address skips spam filtering and sender authentication." `
            -CurrentValue 'IPAllowList empty' -RequiredValue 'IPAllowList empty'
        return
    }
    $desc = @(); $affected = @()
    foreach ($p in $withEntries) {
        $pn = [string](Get-TPObjectField -Item $p -Key 'Name' -Default '?')
        $ips = @(@(Get-TPObjectField -Item $p -Key 'IPAllowList' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $shown = @($ips | Select-Object -First 5) -join ', '
        $desc += "$pn`: $($ips.Count) entr$(if ($ips.Count -eq 1) { 'y' } else { 'ies' }) ($shown$(if ($ips.Count -gt 5) { ", and $($ips.Count - 5) more" }))"
        $affected += [ordered]@{ DisplayName = $pn; IPAllowList = $ips }
    }
    Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
        -Detail "The connection filter IP Allow List is in use: $($desc -join '; '). Mail from these sources skips spam filtering and sender authentication (SPF, DKIM, DMARC); only malware and high confidence phishing are still filtered." `
        -CurrentValue ($desc -join '; ') -RequiredValue 'IPAllowList empty on the connection filter policy' -Remediation $ctrl.Remediation -AffectedObjects $affected
}

# ── DEF-6.1 Notifications for internal users sending malware (CIS 2.1.3) ────
function Test-TPControlDefenderInternalMalwareNotify {
    [CmdletBinding()] param()
    $cid = 'DEF-6.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $def = Get-TPRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Defender data not collected; not assessed.'; return
    }
    $mf = Get-TPObjectField -Item $def.Data -Key 'MalwareFilter' -Default $null
    if (-not $mf -or (Get-TPObjectField -Item $mf -Key 'Available' -Default $false) -ne $true) {
        $why = [string](Get-TPObjectField -Item $mf -Key 'Error' -Default '')
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Malware filter policies were not collected$(if ($why) { " ($why)" }); not assessed."; return
    }
    if ((Get-TPObjectField -Item $mf -Key 'AdminAddressRead' -Default $null) -ne $true) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The malware filter policies were read without InternalSenderAdminAddress (a results file from before this control); not assessed.'; return
    }
    $inForce = @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $mf -Key 'Policies' -Default @()) -Rules (Get-TPRuleList -Item $mf -Key 'Rules') -RulePolicyKey 'MalwareFilterPolicy' -PresetKind 'EOP')
    Add-TPPolicySetFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $inForce `
        -Pass { param($p) (Get-TPObjectField -Item $p -Key 'EnableInternalSenderAdminNotifications' -Default $null) -eq $true -and [string](Get-TPObjectField -Item $p -Key 'InternalSenderAdminAddress' -Default '') } `
        -Value { param($p) "internal sender admin notifications $(if ((Get-TPObjectField -Item $p -Key 'EnableInternalSenderAdminNotifications' -Default $null) -eq $true) { 'on' } else { 'off' }), administrator address $(if ([string](Get-TPObjectField -Item $p -Key 'InternalSenderAdminAddress' -Default '')) { 'set' } else { 'not set' })" } `
        -PassDetail 'Every anti-malware policy in force notifies an administrator when an internal user sends a message that contains malware, a sign the account or device may be compromised.' `
        -FailDetail 'An administrator is not notified when an internal user covered by these policies sends malware, so a compromised account or device spreading malware inside the organization can go unnoticed. Preset security policies do not offer this setting.' `
        -RequiredValue 'EnableInternalSenderAdminNotifications = True and InternalSenderAdminAddress set on every anti-malware policy in force' `
        -Empty 'No anti-malware policy in force was found; not assessed.'
}

# ── DEF-6.2 Outbound spam policies notify administrators (CIS 2.1.6) ─────────
function Test-TPControlDefenderOutboundSpamNotify {
    [CmdletBinding()] param()
    $cid = 'DEF-6.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $exo = Get-TPRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected; not assessed.'; return
    }
    if (-not (Test-TPSectionCollected $exo 'OutboundSpamPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Outbound spam policies were not collected; not assessed.'; return
    }
    $inForce = @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $exo.Data -Key 'OutboundSpamPolicies' -Default @()) `
        -Rules (Get-TPRuleList -Item $exo.Data -Key 'OutboundSpamRules') -RulePolicyKey 'HostedOutboundSpamFilterPolicy' -PresetKind 'EOP')
    $unread = @($inForce | Where-Object {
        $null -eq (Get-TPObjectField -Item $_ -Key 'BccSuspiciousOutboundMail' -Default $null) -or
        (Get-TPObjectField -Item $_ -Key 'NotifyOutboundSpamReturned' -Default $null) -ne $true })
    if ($unread.Count) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "BccSuspiciousOutboundMail or NotifyOutboundSpam was not returned for $(@($unread | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '?') }) -join ', ') (or the results file predates this control); not assessed."
        return
    }
    $cnt = { param($p, $k) @(@(Get-TPObjectField -Item $p -Key $k -Default @()) | Where-Object { $_ }).Count }
    Add-TPPolicySetFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $inForce `
        -Pass { param($p) (Get-TPObjectField -Item $p -Key 'BccSuspiciousOutboundMail' -Default $null) -eq $true -and (& $cnt $p 'BccSuspiciousOutboundAdditionalRecipients') -gt 0 -and
            (Get-TPObjectField -Item $p -Key 'NotifyOutboundSpam' -Default $null) -eq $true -and (& $cnt $p 'NotifyOutboundSpamRecipients') -gt 0 } `
        -Value { param($p) "Bcc copy $(if ((Get-TPObjectField -Item $p -Key 'BccSuspiciousOutboundMail' -Default $null) -eq $true) { 'on' } else { 'off' }) to $(& $cnt $p 'BccSuspiciousOutboundAdditionalRecipients') recipient(s), notify $(if ((Get-TPObjectField -Item $p -Key 'NotifyOutboundSpam' -Default $null) -eq $true) { 'on' } else { 'off' }) to $(& $cnt $p 'NotifyOutboundSpamRecipients') recipient(s)" } `
        -PassDetail 'Every outbound spam policy in force copies messages over the sending limits to an administrator (BccSuspiciousOutboundMail) and notifies administrators when a sender is blocked for outbound spam (NotifyOutboundSpam). Microsoft now recommends the default alert policy "User restricted from sending email" for the notification; that alert is not part of this verdict.' `
        -FailDetail 'Administrators are not both copied on suspicious outbound mail and notified when a sender is blocked for spam, and a blocked sender is a strong sign of a compromised account. Microsoft documents NotifyOutboundSpam as replaced by the alert policy "User restricted from sending email"; CIS 2.1.6 still audits both settings.' `
        -RequiredValue 'BccSuspiciousOutboundMail = True with BccSuspiciousOutboundAdditionalRecipients set, and NotifyOutboundSpam = True with NotifyOutboundSpamRecipients set, on every outbound spam policy in force' `
        -Empty 'No outbound spam policy in force was found; not assessed.'
}

# ── DEF-6.3 Comprehensive attachment filtering (CIS 2.1.11) ──────────────────
function Test-TPControlDefenderComprehensiveAttachments {
    [CmdletBinding()] param()
    $cid = 'DEF-6.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $def = Get-TPRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Defender data not collected; not assessed.'; return
    }
    $mf = Get-TPObjectField -Item $def.Data -Key 'MalwareFilter' -Default $null
    if (-not $mf -or (Get-TPObjectField -Item $mf -Key 'Available' -Default $false) -ne $true) {
        $why = [string](Get-TPObjectField -Item $mf -Key 'Error' -Default '')
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Malware filter policies were not collected$(if ($why) { " ($why)" }); not assessed."; return
    }
    $cisTypes = @(Get-TPCisComprehensiveAttachmentTypes)
    if ($cisTypes.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The CIS 2.1.11 file type list (Config/cis-m365-comprehensive-attachment-types.json) could not be read; not assessed.'; return
    }
    $inForce = @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $mf -Key 'Policies' -Default @()) -Rules (Get-TPRuleList -Item $mf -Key 'Rules') -RulePolicyKey 'MalwareFilterPolicy' -PresetKind 'EOP')
    $missing = { param($p)
        $types = @(@(Get-TPObjectField -Item $p -Key 'FileTypes' -Default @()) | ForEach-Object { ([string]$_).Trim().TrimStart('.').ToLowerInvariant() })
        @($cisTypes | Where-Object { $_ -notin $types }) }
    Add-TPPolicySetFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $inForce `
        -Pass { param($p) (Get-TPObjectField -Item $p -Key 'EnableFileFilter' -Default $null) -eq $true -and @(& $missing $p).Count -eq 0 } `
        -Value { param($p)
            $m = @(& $missing $p)
            "filter $(if ((Get-TPObjectField -Item $p -Key 'EnableFileFilter' -Default $null) -eq $true) { 'on' } else { 'off' }), $($cisTypes.Count - $m.Count) of $($cisTypes.Count) CIS file types blocked$(if ($m.Count) { "; not blocked: $(@($m | Select-Object -First 8) -join ', ')$(if ($m.Count -gt 8) { ", and $($m.Count - 8) more" })" })" } `
        -PassDetail "Every anti-malware policy in force has the common attachments filter on and blocks all $($cisTypes.Count) file types CIS 2.1.11 lists." `
        -FailDetail "The common attachments filter in these policies does not block every one of the $($cisTypes.Count) file types CIS 2.1.11 lists (legacy, executable, script, archive and disk image formats used to deliver malware). Microsoft's default list holds 53 types and the preset security policies cannot be extended." `
        -RequiredValue "EnableFileFilter = True and all $($cisTypes.Count) CIS 2.1.11 file types in FileTypes, on every anti-malware policy in force" `
        -Empty 'No anti-malware policy in force was found; not assessed.'
}

# ── DEF-6.4 Zero-hour auto purge for Microsoft Teams (CIS 2.4.4) ─────────────
function Test-TPControlDefenderTeamsZap {
    [CmdletBinding()] param()
    $cid = 'DEF-6.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $def = Get-TPRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Defender data not collected; not assessed.'; return
    }
    $tp = Get-TPObjectField -Item $def.Data -Key 'TeamsProtection' -Default $null
    if ($null -eq $tp) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The Teams protection policy was not collected (a results file from before this control); not assessed.'; return
    }
    if ((Get-TPObjectField -Item $tp -Key 'Available' -Default $false) -ne $true) {
        Add-TPDefenderUnavailableFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Section $tp -Feature 'Teams protection (zero-hour auto purge for Microsoft Teams)'
        return
    }
    $pols = @(@(Get-TPObjectField -Item $tp -Key 'Policies' -Default @()) | Where-Object { $null -ne $_ })
    if ($pols.Count -eq 0) {
        Add-TPDefenderUnavailableFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Section @{ Error = 'Get-TeamsProtectionPolicy returned no policy' } -Feature 'Teams protection (zero-hour auto purge for Microsoft Teams)'
        return
    }
    $name = { param($p) [string](Get-TPObjectField -Item $p -Key 'Name' -Default '?') }
    $unread = @($pols | Where-Object { $null -eq (Get-TPObjectField -Item $_ -Key 'ZapEnabled' -Default $null) })
    $off    = @($pols | Where-Object { (Get-TPObjectField -Item $_ -Key 'ZapEnabled' -Default $null) -eq $false })
    # Exceptions on the Teams protection policy rule: reported for review, never the verdict.
    $rules = Get-TPRuleList -Item $tp -Key 'Rules'
    $ctx = if ($null -eq $rules) { 'The Teams protection policy rule was not read, so exceptions to ZAP for Teams were not reviewed.' } else {
        $ex = @(foreach ($r in @($rules)) { foreach ($k in 'ExceptIfSentTo', 'ExceptIfSentToMemberOf', 'ExceptIfRecipientDomainIs') {
            $v = @(@(Get-TPObjectField -Item $r -Key $k -Default @()) | Where-Object { $_ }); if ($v.Count) { "$k ($($v.Count))" } } })
        if ($ex.Count) { "Exceptions on the Teams protection policy rule exclude recipients from ZAP for Teams: $($ex -join ', '); review them." } else { 'The Teams protection policy rule has no exceptions.' }
    }
    if ($off.Count) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "Zero-hour auto purge is off for Microsoft Teams ($(@($off | ForEach-Object { & $name $_ }) -join ', ') ZapEnabled = False): a Teams chat message later found to be malware or high confidence phishing stays in the chat. $ctx" `
            -CurrentValue 'ZapEnabled = False' -RequiredValue 'ZapEnabled = True on the Teams protection policy' -Remediation $ctrl.Remediation
    } elseif ($unread.Count) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "ZapEnabled was not returned for $(@($unread | ForEach-Object { & $name $_ }) -join ', '); not assessed."
    } else {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Zero-hour auto purge is on for Microsoft Teams ($(@($pols | ForEach-Object { & $name $_ }) -join ', ') ZapEnabled = True). $ctx" `
            -CurrentValue 'ZapEnabled = True' -RequiredValue 'ZapEnabled = True on the Teams protection policy'
    }
}

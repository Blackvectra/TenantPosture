#Requires -Version 7.0
#
# Get-NRGDistributionListRules.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Pure helpers for the distribution-list scan. They turn the raw shape
#          Exchange Online returns for a list, or for one of its members, into
#          the plain answers the evaluator and the worksheet both print: who can
#          send to the list today, what kind of list it is, whether a member is
#          outside the organization, and how to paste a value into a command
#          without it being able to break out of the command.
#
# Sets:     nothing (pure functions, no I/O)
# Consumes: nothing. Callers pass one list record or one raw recipient.
# Cmdlets:  none. Get-NRGRecipientClass / Get-NRGObjectField / Get-NRGRuleList only.
#
# WHY THESE LIVE IN ONE PLACE
# ---------------------------
# The evaluator writes a finding and the publisher writes the worksheet row for
# the same list. If each derived "who can send to it" on its own, the two would
# drift and the worksheet could say "authenticated senders only" beside a Gap
# that says the opposite. Both call Get-NRGDistributionListSenderAccess.
#
# Exchange omits properties rather than nulling them, and an empty owner list is
# not the same fact as an owner list that was never returned, so every read here
# goes through Get-NRGObjectField / Get-NRGRuleList and keeps $null (unknown)
# apart from an empty list (known to be empty).

# 'True' / 'False' only. [bool]'False' is $true in PowerShell, so a string is
# parsed explicitly and anything else is "not read", never a default.
function ConvertTo-NRGDLBoolean {
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [string]) {
        if ($Value -eq 'True')  { return $true }
        if ($Value -eq 'False') { return $false }
    }
    return $null
}

# One line of printable text. Names come from the tenant, and a worksheet is
# read by an administrator who may paste from it: control and format characters
# (newlines, bidirectional overrides, zero-width joiners) are removed so a name
# cannot reorder what the reader sees or end a line early.
function ConvertTo-NRGDLText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] $Value,
        [int] $MaxLength = 256
    )
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s -replace '[\r\n\t  ]+', ' '
    $s = $s -replace '[\p{Cc}\p{Cf}]', ''
    $s = ($s -replace '\s{2,}', ' ').Trim()
    if ($MaxLength -gt 0 -and $s.Length -gt $MaxLength) { $s = $s.Substring(0, $MaxLength - 3) + '...' }
    return $s
}

# What kind of list this is, from the raw RecipientTypeDetails Exchange returns.
function Get-NRGDistributionListKind {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [string] $RecipientTypeDetails)
    switch ([string]$RecipientTypeDetails) {
        'MailUniversalDistributionGroup' { return 'Distribution list' }
        'MailUniversalSecurityGroup'     { return 'Mail-enabled security group' }
        'MailNonUniversalGroup'          { return 'Mail-enabled non-universal group' }
        'DynamicDistributionGroup'       { return 'Dynamic distribution list' }
        'RoomList'                       { return 'Room list' }
        ''                               { return 'Unknown type' }
        default                          { return (ConvertTo-NRGDLText -Value $RecipientTypeDetails -MaxLength 60) }
    }
}

# Display names or addresses out of one of Exchange's list-valued properties.
# A GUID is what Exchange returns when it was not asked to resolve names, and a
# GUID tells a reader nothing, so those are counted, not printed.
function Get-NRGDLNamedItems {
    [CmdletBinding()]
    param(
        [AllowNull()] $Item,
        [Parameter(Mandatory)] [string] $Key,
        [string] $NamesKey
    )
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $raw   = Get-NRGRuleList -Item $Item -Key $Key
    $named = $null
    if ($NamesKey) { $named = Get-NRGRuleList -Item $Item -Key $NamesKey }
    $known = ($null -ne $raw) -or ($null -ne $named)

    # @($null).Count is 1, not 0: count only a list that was actually returned.
    # Two statements each: an if-block that yields an empty array assigns $null.
    $rawItems = @();   if ($null -ne $raw)   { $rawItems = @($raw) }
    $namedItems = @(); if ($null -ne $named) { $namedItems = @($named) }

    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($n in $namedItems) {
        $t = ConvertTo-NRGDLText -Value $n -MaxLength 120
        if ($t -and $names -notcontains $t) { $names.Add($t) }
    }
    $total = [Math]::Max($rawItems.Count, $names.Count)
    if ($names.Count -eq 0) {
        foreach ($n in $rawItems) {
            $t = ConvertTo-NRGDLText -Value $n -MaxLength 120
            if ($t -and $t -notmatch $guid -and $names -notcontains $t) { $names.Add($t) }
        }
        $total = $rawItems.Count
    }
    return [pscustomobject]@{
        Known   = $known
        Count   = $(if ($known) { [int]$total } else { 0 })
        Names   = @($names)
        Unnamed = $(if ($known) { [Math]::Max(0, [int]$total - $names.Count) } else { 0 })
    }
}

# Who can send to this list today. Takes the stored list record (a hashtable on a
# live run, a PSCustomObject on a replayed results file).
#
# What Microsoft documents for the sender settings of distribution lists and dynamic lists:
#   RequireSenderAuthenticationEnabled $true  = accept mail only from authenticated
#       (internal) senders; mail from unauthenticated (external) senders is rejected.
#   RequireSenderAuthenticationEnabled $false = accept mail from authenticated and
#       unauthenticated senders: anyone on the internet can email the list.
#   AcceptMessagesOnlyFrom / ...DLMembers / ...SendersOrMembers = an allow-list; when
#       any is set, only those senders may send.
#   ModerationEnabled = every message waits for a moderator.
# A property Exchange did not return is unknown, never the safe value.
function Get-NRGDistributionListSenderAccess {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowNull()] $List)

    $require   = ConvertTo-NRGDLBoolean (Get-NRGObjectField -Item $List -Key 'RequireSenderAuthenticationEnabled' -Default $null)
    $moderated = ConvertTo-NRGDLBoolean (Get-NRGObjectField -Item $List -Key 'ModerationEnabled' -Default $null)

    $allowKnown = $false
    $allowCount = 0
    $allowNames = [System.Collections.Generic.List[string]]::new()
    $allowUnnamed = 0
    foreach ($pair in @(
            @('AcceptMessagesOnlyFrom',                'AcceptMessagesOnlyFromWithDisplayNames'),
            @('AcceptMessagesOnlyFromDLMembers',       'AcceptMessagesOnlyFromDLMembersWithDisplayNames'),
            @('AcceptMessagesOnlyFromSendersOrMembers', 'AcceptMessagesOnlyFromSendersOrMembersWithDisplayNames'))) {
        $a = Get-NRGDLNamedItems -Item $List -Key $pair[0] -NamesKey $pair[1]
        if ($a.Known) { $allowKnown = $true }
        $allowCount   += $a.Count
        $allowUnnamed += $a.Unnamed
        foreach ($n in @($a.Names)) { if ($allowNames -notcontains $n) { $allowNames.Add($n) } }
    }

    $mods = Get-NRGDLNamedItems -Item $List -Key 'ModeratedBy' -NamesKey 'ModeratedByWithDisplayNames'
    $modText = ''
    if ($moderated -eq $true) {
        $modText = if ($mods.Names.Count -gt 0) { 'approval by ' + (@($mods.Names) -join ', ') }
                   elseif ($mods.Count -gt 0)   { "approval by $($mods.Count) moderator(s)" }
                   else                          { 'a moderator (none could be read)' }
    }

    $mode = 'Unknown'
    if ($null -ne $require) {
        if     ($allowCount -gt 0)        { $mode = 'AllowList' }
        elseif ($require -eq $true)       { $mode = 'AuthenticatedOnly' }
        elseif ($moderated -eq $true)     { $mode = 'OpenToOutsideModerated' }
        else                              { $mode = 'OpenToOutside' }
    }

    $summary = switch ($mode) {
        'Unknown' { 'Not read: Exchange did not return the sender-authentication setting for this list' }
        'AuthenticatedOnly' {
            $t = 'Anyone inside the organization (mail from outside senders is rejected)'
            if ($modText) { $t += "; every message waits for $modText" }
            $t
        }
        'AllowList' {
            $who = if ($allowNames.Count -gt 0) { (@($allowNames) -join ', ') } else { "$allowCount sender(s) (names not returned)" }
            if ($allowNames.Count -gt 0 -and $allowUnnamed -gt 0) { $who += " and $allowUnnamed more (names not returned)" }
            $t = "Only the senders on its allow-list: $who"
            if ($require -eq $false) { $t += '; the list is not limited to authenticated senders, so an outside sender on that list is accepted' }
            if ($modText) { $t += "; every message waits for $modText" }
            $t
        }
        'OpenToOutsideModerated' { "Anyone, including people outside the organization, but every message waits for $modText" }
        'OpenToOutside' {
            $t = 'Anyone, including people outside the organization (unauthenticated senders are accepted)'
            if (-not $allowKnown) { $t += '; the sender allow-list was not returned, so a restriction could not be confirmed' }
            $t
        }
    }

    return [pscustomobject]@{
        Mode           = $mode
        RequireAuth    = $require
        AllowListKnown = $allowKnown
        AllowListCount = [int]$allowCount
        AllowListNames = @($allowNames)
        Moderated      = $moderated
        Moderators     = @($mods.Names)
        Summary        = [string]$summary
    }
}

# Whether one raw member recipient is outside the organization, and whether it is
# really a person at all. Takes the recipient exactly as Get-DistributionGroupMember
# returns it; returns only what the worksheet may print: a display name and one
# identifier (the UPN, or for a recipient with no UPN, such as a mail contact, its
# address).
#
#   GuestMailUser          -> External (a guest is by definition not staff)
#   MailContact / MailUser -> judged by ExternalEmailAddress, because mail is
#                             delivered THERE; a primary address inside the tenant
#                             would call a forwarded recipient internal
#   everything else        -> judged by PrimarySmtpAddress
#   groups                 -> IsGroup; not a person, listed under nested groups
# An empty accepted-domain set classifies nothing: Get-NRGRecipientClass would
# call every address external, and a blank address would come back Internal.
function Get-NRGDistributionListMemberClass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Member,
        [AllowEmptyCollection()] [string[]] $AcceptedDomains = @()
    )

    $details = [string](Get-NRGObjectField -Item $Member -Key 'RecipientTypeDetails' -Default '')
    $rtype   = [string](Get-NRGObjectField -Item $Member -Key 'RecipientType' -Default '')
    $display = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Member -Key 'DisplayName' -Default (Get-NRGObjectField -Item $Member -Key 'Name' -Default ''))
    $primary = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Member -Key 'PrimarySmtpAddress' -Default '') -MaxLength 320
    $upn     = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Member -Key 'UserPrincipalName' -Default '') -MaxLength 320
    if (-not $upn) { $upn = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Member -Key 'WindowsLiveID' -Default '') -MaxLength 320 }
    $ext     = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Member -Key 'ExternalEmailAddress' -Default '') -MaxLength 320
    $identifier = if ($upn) { $upn } else { $primary }

    $groupKinds = @('MailUniversalDistributionGroup', 'MailUniversalSecurityGroup', 'MailNonUniversalGroup', 'DynamicDistributionGroup', 'GroupMailbox', 'RoomList')
    $isGroup = ($details -in $groupKinds) -or ($rtype -in $groupKinds)

    $class = 'Unresolved'
    if ($isGroup) {
        $class = 'Group'
    } elseif ($details -eq 'GuestMailUser') {
        $class = 'External'
    } else {
        $target = if ($ext) { $ext } else { $primary }
        $domains = @($AcceptedDomains | Where-Object { $_ })
        if ($target -and $domains.Count -gt 0) {
            $class = [string](Get-NRGRecipientClass -Recipient $target -AcceptedDomains $domains)
        }
    }

    return [pscustomobject]@{
        IsGroup           = $isGroup
        Class             = $class
        DisplayName       = $display
        UserPrincipalName = $identifier
        PrimarySmtpAddress = $primary
    }
}

# A value that is safe to place between single quotes in a command an
# administrator may paste. Only address-shaped text is accepted; anything else
# returns $null, and the caller prints "find this one by hand" instead of a
# command. PowerShell treats the four typographic single quotes like an ASCII
# apostrophe, so they are rejected by the allow-list rather than escaped.
function ConvertTo-NRGDLQuotedLiteral {
    [CmdletBinding()]
    param([AllowNull()] [string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    if ($v -notmatch '^[A-Za-z0-9!#$%&''*+/=?^_`{|}~.\-]{1,64}@[A-Za-z0-9.\-]{1,255}$') { return $null }
    return "'" + ($v -replace "'", "''") + "'"
}

# The hardening commands are DATA (Config/distribution-list-hardening.json), kept
# out of every file the module executes, so no module code path can call them.
function Get-NRGDistributionListHardeningTemplates {
    [CmdletBinding()]
    param()
    $path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config/distribution-list-hardening.json'
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $cfg = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    return @($cfg.Templates)
}

# Text for the worksheet. Substitutes {Identity} and {Member} with a quoted,
# validated literal. Returns $null when a placeholder cannot be filled safely.
# Nothing here executes the result.
function Format-NRGDistributionListCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Template,
        [AllowNull()] [string] $Identity,
        [AllowNull()] [string] $Member
    )
    $out = $Template
    if ($out.Contains('{Identity}')) {
        $q = ConvertTo-NRGDLQuotedLiteral -Value $Identity
        if ($null -eq $q) { return $null }
        $out = $out.Replace('{Identity}', $q)
    }
    if ($out.Contains('{Member}')) {
        $q = ConvertTo-NRGDLQuotedLiteral -Value $Member
        if ($null -eq $q) { return $null }
        $out = $out.Replace('{Member}', $q)
    }
    return $out
}

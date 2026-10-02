#Requires -Version 7.0
#
# Test-NRGDistributionLists.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Judge the distribution-list inventory (EXO-DistributionLists) against the
#          recommendation catalog (Config/distribution-list-baseline.json) and emit
#          the DL-* finding series. SCORING ONLY -- no API calls, and nothing here is
#          ever executed against a tenant.
#
# Sets:     findings DL-1.1 (who can send to a list), DL-2.1, DL-2.2, DL-2.4, DL-2.5
#           (owner, moderation, member cap, join restriction),
#           DL-3.1 .. DL-3.5 (filtering bypasses that apply to every list),
#           DL-4.1 (context the tool cannot detect). DL-1.2 (allowed senders) and
#           DL-2.3 (external members) are worksheet context rows, not findings.
# Consumes: EXO-DistributionLists. Nothing else: this series is NOT in
#           Config/controls.json, and the function is deliberately NOT named
#           Test-NRGControl*, because Invoke-NRGAssessment.ps1 runs every function
#           with that name in a full assessment and these findings belong to the
#           -DistributionListsOnly run only.
#
# THE RULES
# ---------
# 1. Missing evidence is NotApplicable ("not assessed"), never Satisfied. An empty
#    list is read as "none" only when its SectionStatus says Collected.
# 2. A property Exchange omitted is not a value. RequireSenderAuthenticationEnabled
#    $null is "not returned", never "authenticated senders only".
# 3. An NRG judgment (member cap, join restriction) is judged only
#    against a value approved in Config/nrg-standards.json. Until then ONE tenant-level
#    "not assessed" finding says so; it is never a pass and never a per-list wall of
#    noise.
# 4. Every Detail says what was read and what was not.
# 5. A citation is a mapping, not a quotation: Nist80053 is the tool's own mapping.

# Predicate names (the Exchange predicate class name without its namespace and the
# 'Predicate' suffix) that VERIFY something about the sender beyond who it claims to
# be: an authentication header, or the connecting address.
$script:NRGDlVerifyingPredicates = @('HeaderContains', 'HeaderMatchesPatterns', 'HeaderMatches', 'SenderIpRanges')
# Predicates that identify the sender by what it claims, which is what an attacker controls.
$script:NRGDlSenderPredicates    = @('SenderDomainIs', 'From', 'FromMemberOf', 'FromAddressContainsWords', 'FromAddressMatchesPatterns', 'SenderAddressLocation')

# The width of one IP Allow List entry: a single address, a CIDR block, or an a-b range.
# The service accepts only /24 to /32 CIDR blocks, so a range is the only way an entry
# gets wider than a /24, which is what Microsoft recommends staying within.
function Get-NRGDlIpEntryWidth {
    [CmdletBinding()]
    param([AllowNull()] [string] $Entry)
    $e = ([string]$Entry).Trim()
    $isIp = { param([string] $s) ($s -match '^\d{1,3}(\.\d{1,3}){3}$') -and (@($s -split '\.' | Where-Object { [int]$_ -gt 255 }).Count -eq 0) }
    $toNum = { param([string] $s) $b = ([System.Net.IPAddress]::Parse($s)).GetAddressBytes(); [double](([double]$b[0] * 16777216) + ([double]$b[1] * 65536) + ([double]$b[2] * 256) + [double]$b[3]) }
    if (& $isIp $e) { return [pscustomobject]@{ Entry = $e; Valid = $true; Width = 1.0; Kind = 'Address' } }
    if ($e -match '^([^/\s]+)/(\d{1,2})$' -and (& $isIp $Matches[1]) -and [int]$Matches[2] -le 32) {
        return [pscustomobject]@{ Entry = $e; Valid = $true; Width = [math]::Pow(2, 32 - [int]$Matches[2]); Kind = 'Cidr' }
    }
    if ($e -match '^([^-\s]+)\s*-\s*([^-\s]+)$' -and (& $isIp $Matches[1]) -and (& $isIp $Matches[2])) {
        $lo = & $toNum $Matches[1]; $hi = & $toNum $Matches[2]
        if ($hi -ge $lo) { return [pscustomobject]@{ Entry = $e; Valid = $true; Width = ($hi - $lo + 1); Kind = 'Range' } }
    }
    return [pscustomobject]@{ Entry = $e; Valid = $false; Width = 0.0; Kind = 'Unparsed' }
}

# Whether a domain is one the tenant owns: an accepted domain, or a subdomain of one.
function Test-NRGDlOwnDomain {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [string] $Domain, [AllowEmptyCollection()] [string[]] $AcceptedDomains)
    $d = ([string]$Domain).Trim().TrimStart('*', '@', '.').ToLowerInvariant()
    if (-not $d) { return $false }
    foreach ($a in @($AcceptedDomains)) {
        $x = ([string]$a).Trim().ToLowerInvariant()
        if ($x -and ($d -eq $x -or $d.EndsWith('.' + $x))) { return $true }
    }
    return $false
}

# Classify one SCL-setting mail flow rule. Only SCL -1 is a bypass: Microsoft documents
# the other values as inputs to filtering, not as a skip.
#   NotBypass         the rule does not set SCL -1
#   Unclassified      the rule's conditions were not returned, so its breadth is unknown
#   Verified          carries a condition that verifies the sender (an authentication
#                     header, or a restricted source address): Microsoft's own pattern
#   SenderDomainOnly  the only sender condition is the sender domain: Microsoft says never
#   NoSenderCondition no condition limits who the sender is, so it applies to any sender
#   Other             other conditions this scan does not judge weak or strong
function Get-NRGDlTransportRuleClass {
    [CmdletBinding()]
    param([AllowNull()] $Rule)
    $scl = Get-NRGObjectField -Item $Rule -Key 'SetSCL' -Default $null
    $state = [string](Get-NRGObjectField -Item $Rule -Key 'State' -Default '')
    $mode  = [string](Get-NRGObjectField -Item $Rule -Key 'Mode' -Default '')
    # A disabled rule, or one in test mode, takes no action. A blank state or mode is not
    # evidence of either, so the rule is treated as in force and judged.
    $inForce = -not ($state -ieq 'Disabled' -or $mode -imatch '^Audit')

    $preds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in @(Get-NRGObjectField -Item $Rule -Key 'Predicates' -Default @())) { if ($p) { [void]$preds.Add([string]$p) } }
    if (@(Get-NRGObjectField -Item $Rule -Key 'SenderDomainIs' -Default @()).Count -gt 0)  { [void]$preds.Add('SenderDomainIs') }
    if (@(Get-NRGObjectField -Item $Rule -Key 'SenderIpRanges' -Default @()).Count -gt 0)  { [void]$preds.Add('SenderIpRanges') }
    if (@(Get-NRGObjectField -Item $Rule -Key 'From' -Default @()).Count -gt 0)            { [void]$preds.Add('From') }
    if ([string](Get-NRGObjectField -Item $Rule -Key 'HeaderContainsMessageHeader' -Default '') -or @(Get-NRGObjectField -Item $Rule -Key 'HeaderContainsWords' -Default @()).Count -gt 0) { [void]$preds.Add('HeaderContains') }
    if (@(Get-NRGObjectField -Item $Rule -Key 'SubjectContainsWords' -Default @()).Count -gt 0)       { [void]$preds.Add('SubjectContainsWords') }
    if (@(Get-NRGObjectField -Item $Rule -Key 'SubjectOrBodyContainsWords' -Default @()).Count -gt 0) { [void]$preds.Add('SubjectOrBodyContainsWords') }
    $names = @($preds | Sort-Object)

    $class = 'NotBypass'; $reason = 'does not set SCL -1'
    if ($null -ne $scl -and "$scl" -eq '-1') {
        $conditionsKnown = [bool](Get-NRGObjectField -Item $Rule -Key 'ConditionsKnown' -Default $false)
        $verifying = @($names | Where-Object { $_ -in $script:NRGDlVerifyingPredicates })
        $senderPreds    = @($names | Where-Object { $_ -in $script:NRGDlSenderPredicates })
        $content   = @($names | Where-Object { $_ -match '^(Subject|Body|Attachment|Message)' })
        if (-not $conditionsKnown -and $names.Count -eq 0) {
            $class = 'Unclassified'; $reason = 'its conditions were not returned, so how broad it is cannot be judged'
        } elseif ($verifying.Count -gt 0) {
            $class = 'Verified'; $reason = 'carries a verifying condition (' + ($verifying -join ', ') + '), which is the pattern Microsoft describes'
        } elseif ($senderPreds.Count -eq 0) {
            $class = 'NoSenderCondition'; $reason = 'no condition limits who the sender is, so it applies to mail from any sender'
        } elseif ($senderPreds.Count -eq 1 -and $senderPreds[0] -eq 'SenderDomainIs' -and $content.Count -eq 0) {
            $class = 'SenderDomainOnly'; $reason = 'its only sender condition is the sender domain, which Microsoft says never to use alone to skip spam filtering'
        } else {
            $class = 'Other'; $reason = 'has conditions (' + ($names -join ', ') + ') that this scan does not judge weak or strong'
        }
    }
    return [pscustomobject]@{
        IsBypass   = ($null -ne $scl -and "$scl" -eq '-1')
        InForce    = $inForce
        Class      = $class
        Reason     = $reason
        Predicates = @($names)
    }
}

function Add-NRGDlFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Entry,
        [Parameter(Mandatory)] [ValidateSet('Satisfied', 'Partial', 'Gap', 'NotApplicable', 'Error')] [string] $State,
        [Parameter(Mandatory)] [string] $Detail,
        [string] $Instance = '',
        [string] $CurrentValue = '',
        [string] $RequiredValue = '',
        [object[]] $AffectedObjects = @()
    )
    $sev = 'Informational'
    if ($State -eq 'Gap') { $sev = [string]$Entry.Severity }
    elseif ($State -eq 'Partial') { $sev = $(if ([string]$Entry.Severity -eq 'High') { 'Medium' } else { [string]$Entry.Severity }) }
    $p = @{
        ControlId = [string]$Entry.ControlId; State = $State; Category = 'Email'; Title = [string]$Entry.Title
        Severity = $sev; Detail = $Detail; FrameworkIds = @()
    }
    # The tool's own mapping to 800-53 Rev 5, in the prefixed form the rollups read.
    if (@($Entry.Nist80053).Count -gt 0) { $p.FrameworkIds = @('NIST:' + (@($Entry.Nist80053) -join ', ')) }
    if ($Instance)      { $p.Instance = $Instance }
    if ($CurrentValue)  { $p.CurrentValue = $CurrentValue }
    if ($RequiredValue) { $p.RequiredValue = $RequiredValue }
    if ($State -in @('Gap', 'Partial')) { $p.Remediation = "$($Entry.Recommended). Source: $($Entry.SourceUrl)" }
    if (@($AffectedObjects).Count -gt 0) { $p.AffectedObjects = @($AffectedObjects) }
    Add-NRGFinding @p
}

function Test-NRGDistributionLists {
    [CmdletBinding()]
    param()

    $base = Get-NRGDistributionListBaseline
    if (-not $base.Available) {
        # No catalog means no titles, recommendations or citations to judge against. Say so loudly
        # rather than emitting findings with nothing behind them.
        Register-NRGException -Source 'DL-Catalog' -Message ("Distribution-list recommendations were not loaded: " + [string]$base.Error)
        return
    }
    $Rec = $base.ById
    $std = Get-NRGDistributionListStandards
    $raw = Get-NRGRawData -Key 'EXO-DistributionLists'

    # ── Guard: no data, no verdicts ──────────────────────────────────────────────
    if (-not $raw -or -not [bool](Get-NRGObjectField -Item $raw -Key 'Success' -Default $false)) {
        foreach ($id in @($base.Entries | Where-Object { $_.EmitsFinding } | ForEach-Object { $_.ControlId })) {
            if ($id -in @('DL-3.5', 'DL-4.1')) { continue }   # reported below, since they are never assessed
            Add-NRGDlFinding -Entry $Rec[$id] -State 'NotApplicable' -Detail 'Not assessed: the distribution-list inventory was not collected (the Exchange Online read failed or did not run), so no list was judged.'
        }
        Add-NRGDlFinding -Entry $Rec['DL-3.5'] -State 'NotApplicable' -Detail 'Not assessed: Outlook Safe Senders live in each mailbox and this scan does not read them.'
        Add-NRGDlFinding -Entry $Rec['DL-4.1'] -State 'NotApplicable' -Detail 'Not assessed: lookalike domains and display-name impersonation cannot be detected by this scan.'
        return
    }

    $data = Get-NRGObjectField -Item $raw -Key 'Data' -Default $null
    $lists = @(Get-NRGObjectField -Item $data -Key 'Lists' -Default @())
    $accepted = @(@(Get-NRGObjectField -Item $data -Key 'AcceptedDomains' -Default @()) | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ })
    $bypass = Get-NRGObjectField -Item $data -Key 'BypassInputs' -Default $null
    $limits = Get-NRGObjectField -Item $data -Key 'Limits' -Default $null
    $listsOk = (Test-NRGSectionCollected $raw 'Lists')
    $dynOk   = (Test-NRGSectionCollected $raw 'DynamicLists')
    $acceptedOk = (Test-NRGSectionCollected $raw 'AcceptedDomains') -and $accepted.Count -gt 0

    # ── Inventory coverage: said once, under the first control ────────────────────
    $gaps = @()
    if (-not $listsOk) { $gaps += 'distribution lists (Get-DistributionGroup failed or did not run)' }
    if (-not $dynOk)   { $gaps += 'dynamic distribution lists (Get-DynamicDistributionGroup failed or did not run)' }
    if ([bool](Get-NRGObjectField -Item $limits -Key 'ListsTruncated' -Default $false)) {
        $gaps += ("lists beyond the first $([int](Get-NRGObjectField -Item $limits -Key 'MaxLists' -Default 0)) of $([int](Get-NRGObjectField -Item $limits -Key 'ListsSeen' -Default 0)) seen (raise the cap and re-run)")
    }
    if ($gaps.Count -gt 0) {
        Add-NRGDlFinding -Entry $Rec['DL-1.1'] -State 'NotApplicable' -Detail ('Not assessed: ' + ($gaps -join '; ') + '. A list that was not read is not a clean list; the findings below cover only the lists that were read.')
    }
    if ($lists.Count -eq 0 -and $gaps.Count -eq 0) {
        Add-NRGDlFinding -Entry $Rec['DL-1.1'] -State 'NotApplicable' -Detail 'Exchange returned no distribution list, so no list was assessed. If the signed-in account is scoped to part of the directory, lists outside that scope would not be returned.'
    }

    # ── Per list ──────────────────────────────────────────────────────────────────
    $capStd = $std.MaxMembers; $joinStd = $std.JoinRestriction
    foreach ($l in $lists) {
        $addr = [string](Get-NRGObjectField -Item $l -Key 'PrimarySmtpAddress' -Default '')
        $name = [string](Get-NRGObjectField -Item $l -Key 'Name' -Default '')
        $inst = if ($addr) { $addr } else { $name }
        $kind = [string](Get-NRGObjectField -Item $l -Key 'Kind' -Default '')
        $ref  = [ordered]@{ List = $name; Address = $addr; Type = $kind }
        $who  = "'$name'"

        # DL-1.1 who can send to the list
        $auth = Get-NRGObjectField -Item $l -Key 'RequireSenderAuthenticationEnabled' -Default $null
        $allowedKnown = [bool](Get-NRGObjectField -Item $l -Key 'AllowedSendersKnown' -Default $false)
        $allowedN = @(Get-NRGObjectField -Item $l -Key 'AllowedSenders' -Default @()).Count
        # External members are expected on these lists. Requiring authenticated senders would stop them sending (Microsoft: True
        # rejects unauthenticated, external senders), so a list that holds some is pointed at the allowed-senders option instead.
        $extN11 = if ([string](Get-NRGObjectField -Item $l -Key 'MemberStatus' -Default 'NotRun') -eq 'Collected') { [int](Get-NRGObjectField -Item $l -Key 'ExternalMemberCount' -Default 0) } else { 0 }
        $extNote = if ($extN11 -gt 0) { " This list has $extN11 external member(s): requiring authenticated senders would stop them sending to it, so the allowed-senders option (DL-1.2) is the one that keeps them." } else { '' }
        if ($null -eq $auth) {
            Add-NRGDlFinding -Entry $Rec['DL-1.1'] -State 'NotApplicable' -Instance $inst -AffectedObjects @($ref) -Detail "Not assessed: Exchange did not return RequireSenderAuthenticationEnabled for $who, so who can send to it is unknown."
        } elseif ($auth -eq $true) {
            Add-NRGDlFinding -Entry $Rec['DL-1.1'] -State 'Satisfied' -Instance $inst -AffectedObjects @($ref) -CurrentValue 'RequireSenderAuthenticationEnabled = True' `
                -Detail "Read: $who accepts mail only from authenticated senders inside the organization (RequireSenderAuthenticationEnabled = True). Not assessed here: filtering bypasses that apply to every list (DL-3.x)."
        } elseif ($allowedKnown -and $allowedN -gt 0) {
            Add-NRGDlFinding -Entry $Rec['DL-1.1'] -State 'Partial' -Instance $inst -AffectedObjects @($ref) -CurrentValue 'RequireSenderAuthenticationEnabled = False' -RequiredValue $Rec['DL-1.1'].Recommended `
                -Detail "Shortfall: $who accepts mail from outside the organization (RequireSenderAuthenticationEnabled = False), limited to $allowedN specified sender(s). Not assessed: whether those senders are themselves reachable by a spoofed message, or any filtering bypass (DL-3.x).$extNote"
        } else {
            $tail = if ($allowedKnown) { 'No allowed-senders list limits it.' } else { 'Exchange did not return an allowed-senders list, so it may be narrower than this shows.' }
            Add-NRGDlFinding -Entry $Rec['DL-1.1'] -State 'Gap' -Instance $inst -AffectedObjects @($ref) -CurrentValue 'RequireSenderAuthenticationEnabled = False' -RequiredValue $Rec['DL-1.1'].Recommended `
                -Detail "Shortfall: $who accepts mail from anyone, including senders outside the organization (RequireSenderAuthenticationEnabled = False). $tail DMARC does not change this: it judges only mail that claims your own domain.$extNote"
        }

        # DL-2.1 owner
        if (-not [bool](Get-NRGObjectField -Item $l -Key 'OwnersKnown' -Default $false)) {
            Add-NRGDlFinding -Entry $Rec['DL-2.1'] -State 'NotApplicable' -Instance $inst -AffectedObjects @($ref) -Detail "Not assessed: Exchange did not return ManagedBy for $who, so its owners are unknown."
        } elseif ([int](Get-NRGObjectField -Item $l -Key 'OwnerCount' -Default 0) -gt 0) {
            Add-NRGDlFinding -Entry $Rec['DL-2.1'] -State 'Satisfied' -Instance $inst -AffectedObjects @($ref) -CurrentValue "$([int](Get-NRGObjectField -Item $l -Key 'OwnerCount' -Default 0)) owner(s)" -Detail "Read: $who has $([int](Get-NRGObjectField -Item $l -Key 'OwnerCount' -Default 0)) owner(s). Not assessed: whether the owners are current employees."
        } else {
            Add-NRGDlFinding -Entry $Rec['DL-2.1'] -State 'Gap' -Instance $inst -AffectedObjects @($ref) -CurrentValue 'No owner' -RequiredValue $Rec['DL-2.1'].Recommended -Detail "Shortfall: $who has no owner (ManagedBy is empty), so no one is accountable for its members, its join setting or its moderation."
        }

        # DL-2.2 moderation: judged only where moderation is on (or unknown)
        $mod = Get-NRGObjectField -Item $l -Key 'ModerationEnabled' -Default $null
        if ($null -eq $mod) {
            Add-NRGDlFinding -Entry $Rec['DL-2.2'] -State 'NotApplicable' -Instance $inst -AffectedObjects @($ref) -Detail "Not assessed: Exchange did not return ModerationEnabled for $who."
        } elseif ($mod -eq $true) {
            $mods = @(Get-NRGObjectField -Item $l -Key 'ModeratedBy' -Default @()).Count
            $ownN = [int](Get-NRGObjectField -Item $l -Key 'OwnerCount' -Default 0)
            if ($mods -gt 0) {
                Add-NRGDlFinding -Entry $Rec['DL-2.2'] -State 'Satisfied' -Instance $inst -AffectedObjects @($ref) -Detail "Read: moderation is on for $who with $mods moderator(s)."
            } elseif (-not [bool](Get-NRGObjectField -Item $l -Key 'ModeratedByKnown' -Default $false) -or -not [bool](Get-NRGObjectField -Item $l -Key 'OwnersKnown' -Default $false)) {
                Add-NRGDlFinding -Entry $Rec['DL-2.2'] -State 'NotApplicable' -Instance $inst -AffectedObjects @($ref) -Detail "Not assessed: moderation is on for $who but Exchange did not return its moderators or owners, so who approves mail is unknown."
            } elseif ($ownN -gt 0) {
                Add-NRGDlFinding -Entry $Rec['DL-2.2'] -State 'Satisfied' -Instance $inst -AffectedObjects @($ref) -Detail "Read: moderation is on for $who with no moderator, so messages go to its $ownN owner(s) for approval (Microsoft's documented behavior)."
            } else {
                Add-NRGDlFinding -Entry $Rec['DL-2.2'] -State 'Gap' -Instance $inst -AffectedObjects @($ref) -CurrentValue 'ModerationEnabled = True; no moderator; no owner' -RequiredValue $Rec['DL-2.2'].Recommended -Detail "Shortfall: moderation is on for $who but it has no moderator and no owner, so no one can approve its mail."
            }
        }
        # Moderation off is Microsoft's default and there is no recommendation to turn it on: nothing is judged.

        # External members (DL-2.3) are shown in the worksheet and not judged here: the owner decided they stay, so there is
        # no standard and no finding. What limits their exposure is DL-1.1 and the allowed-senders list the worksheet proposes.

        # DL-2.4 member cap (against the approved NRG standard only)
        if ($capStd.Approved) {
            $mst = [string](Get-NRGObjectField -Item $l -Key 'MemberStatus' -Default 'NotRun')
            $cnt = [int](Get-NRGObjectField -Item $l -Key 'MemberCount' -Default 0)
            $trunc = [bool](Get-NRGObjectField -Item $l -Key 'MembersTruncated' -Default $false)
            $capN = [int]$capStd.Value
            if ($mst -ne 'Collected') {
                Add-NRGDlFinding -Entry $Rec['DL-2.4'] -State 'NotApplicable' -Instance $inst -AffectedObjects @($ref) -Detail "Not assessed: the members of $who were not read, so its size is unknown."
            } elseif ((($trunc) -and $cnt -ge $capN) -or (-not $trunc -and $cnt -gt $capN)) {
                # A truncated read means the list has MORE than the $cnt read, so $cnt already at the cap proves it is over.
                Add-NRGDlFinding -Entry $Rec['DL-2.4'] -State 'Gap' -Instance $inst -AffectedObjects @($ref) -CurrentValue "$(if ($trunc) { 'More than ' })$cnt member(s)" -RequiredValue "At most $capN (approved NRG standard)" `
                    -Detail "Shortfall against the approved NRG standard: $who has $(if ($trunc) { 'more than ' })$cnt member(s); the approved maximum is $capN."
            } elseif ($trunc) {
                Add-NRGDlFinding -Entry $Rec['DL-2.4'] -State 'NotApplicable' -Instance $inst -AffectedObjects @($ref) -Detail "Not assessed: only the first $cnt members of $who were read and the list has more, so whether it exceeds $capN is not established. Raise -MaxMembersPerList to settle it."
            } else {
                Add-NRGDlFinding -Entry $Rec['DL-2.4'] -State 'Satisfied' -Instance $inst -AffectedObjects @($ref) -CurrentValue "$cnt member(s)" -Detail "Read: $who has $cnt member(s), within the approved maximum of $capN."
            }
        }

        # DL-2.5 join restriction (against the approved NRG standard only; dynamic lists have no join setting)
        if ($joinStd.Approved -and $kind -ne 'Dynamic') {
            $join = [string](Get-NRGObjectField -Item $l -Key 'MemberJoinRestriction' -Default '')
            if (-not $join) {
                Add-NRGDlFinding -Entry $Rec['DL-2.5'] -State 'NotApplicable' -Instance $inst -AffectedObjects @($ref) -Detail "Not assessed: Exchange did not return MemberJoinRestriction for $who."
            } elseif ($join -in @($joinStd.Allowed)) {
                Add-NRGDlFinding -Entry $Rec['DL-2.5'] -State 'Satisfied' -Instance $inst -AffectedObjects @($ref) -CurrentValue "MemberJoinRestriction = $join" -Detail "Read: $who has MemberJoinRestriction = $join, which the approved NRG standard accepts ($(@($joinStd.Allowed) -join ', '))."
            } else {
                Add-NRGDlFinding -Entry $Rec['DL-2.5'] -State 'Gap' -Instance $inst -AffectedObjects @($ref) -CurrentValue "MemberJoinRestriction = $join" -RequiredValue ('One of: ' + (@($joinStd.Allowed) -join ', ') + ' (approved NRG standard)') `
                    -Detail "Shortfall against the approved NRG standard: $who has MemberJoinRestriction = $join; the standard accepts $(@($joinStd.Allowed) -join ', ')."
            }
        }
    }

    # ── Standards that are not approved: said once, never per list, never as a pass ──
    $notApproved = @(
        @{ Id = 'DL-2.4'; Std = $capStd; Key = 'DistributionListMaxMembers';      What = 'how many members a list may have' }
        @{ Id = 'DL-2.5'; Std = $joinStd; Key = 'DistributionListMemberJoinRestriction'; What = 'which join setting a list may have' }
    )
    foreach ($n in $notApproved) {
        if ($n.Std.Approved) { continue }
        $why = if ($n.Std.Issue) { $n.Std.Issue } else { "No value is approved in Config/nrg-standards.json ($($n.Key))." }
        Add-NRGDlFinding -Entry $Rec[$n.Id] -State 'NotApplicable' -Detail "Not assessed: $($n.What) is an NRG judgment and no standard is approved. $why The setting is read and shown in the worksheet, but no list is judged against it."
    }

    # ── Tenant-level filtering bypasses (these apply to every list) ───────────────
    $trOk = (Test-NRGSectionCollected $raw 'TransportRules')
    $cfOk = (Test-NRGSectionCollected $raw 'ConnectionFilter')
    $asOk = (Test-NRGSectionCollected $raw 'AntiSpam')
    $rules = @(Get-NRGObjectField -Item $bypass -Key 'TransportRules' -Default @())
    $classified = @($rules | ForEach-Object { [pscustomobject]@{ Rule = $_; Class = (Get-NRGDlTransportRuleClass -Rule $_) } } | Where-Object { $_.Class.IsBypass })
    $inForceRules = @($classified | Where-Object { $_.Class.InForce })
    $offRules = @($classified | Where-Object { -not $_.Class.InForce })

    # DL-3.1 SCL -1 mail flow rules
    if (-not $trOk) {
        Add-NRGDlFinding -Entry $Rec['DL-3.1'] -State 'NotApplicable' -Detail 'Not assessed: the mail flow rules were not read (Get-TransportRule failed or did not run), so whether a rule bypasses spam filtering for the lists is unknown.'
    } else {
        $weak = @($inForceRules | Where-Object { $_.Class.Class -in @('NoSenderCondition', 'SenderDomainOnly') })
        $unk  = @($inForceRules | Where-Object { $_.Class.Class -eq 'Unclassified' })
        $offNote = if ($offRules.Count) { " $($offRules.Count) further SCL -1 rule(s) are disabled or in test mode and were not judged." } else { '' }
        if ($weak.Count -gt 0) {
            $ao = @($weak | ForEach-Object { [ordered]@{ Source = 'Mail flow rule'; Name = [string](Get-NRGObjectField -Item $_.Rule -Key 'Name' -Default ''); Class = $_.Class.Class; Detail = $_.Class.Reason } })
            Add-NRGDlFinding -Entry $Rec['DL-3.1'] -State 'Gap' -AffectedObjects $ao -CurrentValue "$($weak.Count) weak SCL -1 rule(s)" -RequiredValue $Rec['DL-3.1'].Recommended `
                -Detail ("Shortfall: $($weak.Count) enabled mail flow rule(s) set SCL -1 (bypass spam filtering) on a weak condition: " + (($ao | ForEach-Object { "'$($_.Name)' ($($_.Detail))" }) -join '; ') + ". A bypass rule reaches every list it matches. SCL -1 skips spam filtering only, not malware or high confidence phishing.$offNote")
        } elseif ($unk.Count -gt 0) {
            Add-NRGDlFinding -Entry $Rec['DL-3.1'] -State 'NotApplicable' -AffectedObjects @($unk | ForEach-Object { [ordered]@{ Source = 'Mail flow rule'; Name = [string](Get-NRGObjectField -Item $_.Rule -Key 'Name' -Default ''); Class = 'Unclassified'; Detail = $_.Class.Reason } }) `
                -Detail "Not assessed: $($unk.Count) enabled mail flow rule(s) set SCL -1 but their conditions were not returned, so how broad they are cannot be judged.$offNote"
        } elseif ($inForceRules.Count -gt 0) {
            Add-NRGDlFinding -Entry $Rec['DL-3.1'] -State 'Satisfied' -CurrentValue "$($inForceRules.Count) SCL -1 rule(s), none weak" `
                -Detail ("Read: $($inForceRules.Count) enabled mail flow rule(s) set SCL -1, none on a sender domain alone or on no sender condition: " + (($inForceRules | ForEach-Object { "'$([string](Get-NRGObjectField -Item $_.Rule -Key 'Name' -Default ''))' ($($_.Class.Class))" }) -join '; ') + ". They still skip spam filtering for the mail they match; review them.$offNote")
        } else {
            Add-NRGDlFinding -Entry $Rec['DL-3.1'] -State 'Satisfied' -CurrentValue 'No SCL -1 rule' -Detail "Read: no enabled mail flow rule sets SCL -1.$offNote"
        }
    }

    # DL-3.2 IP Allow List
    if (-not $cfOk) {
        Add-NRGDlFinding -Entry $Rec['DL-3.2'] -State 'NotApplicable' -Detail 'Not assessed: the connection filter policy was not read, so whether an IP Allow List skips spam filtering for the lists is unknown.'
    } else {
        $entries = @(@(Get-NRGObjectField -Item $bypass -Key 'ConnectionFilter' -Default @()) | ForEach-Object { @(Get-NRGObjectField -Item $_ -Key 'IPAllowList' -Default @()) } | Where-Object { $_ })
        if ($entries.Count -eq 0) {
            Add-NRGDlFinding -Entry $Rec['DL-3.2'] -State 'Satisfied' -CurrentValue 'IP Allow List empty' -Detail 'Read: the connection filter IP Allow List is empty.'
        } else {
            $w = @($entries | ForEach-Object { Get-NRGDlIpEntryWidth -Entry $_ })
            $wide = @($w | Where-Object { -not $_.Valid -or $_.Width -gt 256 })
            $ao = @($w | ForEach-Object { [ordered]@{ Source = 'IP Allow List'; Name = $_.Entry; Class = $(if (-not $_.Valid) { 'Unparsed' } elseif ($_.Width -gt 256) { 'WiderThan24' } else { 'Within24' }); Detail = $(if ($_.Valid) { "$([int64]$_.Width) address(es)" } else { 'not a recognized IPv4 address, block or range' }) } })
            if ($wide.Count -gt 0) {
                Add-NRGDlFinding -Entry $Rec['DL-3.2'] -State 'Gap' -AffectedObjects $ao -CurrentValue "$($entries.Count) entr$(if ($entries.Count -eq 1) { 'y' } else { 'ies' }), $($wide.Count) wider than a /24 or unparsed" -RequiredValue $Rec['DL-3.2'].Recommended `
                    -Detail "Shortfall: the IP Allow List has $($entries.Count) entr$(if ($entries.Count -eq 1) { 'y' } else { 'ies' }); $($wide.Count) cover more than a /24 or could not be parsed ($(($wide | ForEach-Object { $_.Entry }) -join ', ')). Mail from an allowed address skips spam filtering for every list. Microsoft recommends a /24 or smaller per entry."
            } else {
                Add-NRGDlFinding -Entry $Rec['DL-3.2'] -State 'Partial' -AffectedObjects $ao -CurrentValue "$($entries.Count) entr$(if ($entries.Count -eq 1) { 'y' } else { 'ies' }), each within a /24" -RequiredValue $Rec['DL-3.2'].Recommended `
                    -Detail "Shortfall: the IP Allow List is not empty ($(($entries) -join ', ')). Each entry is within a /24, as Microsoft recommends, but mail from an allowed address skips spam filtering for every list. Confirm each entry is still needed and is not consumer or shared infrastructure."
            }
        }
    }

    # DL-3.3 anti-spam allowed senders / domains
    $asEntries = @()
    $asOffNote = ''
    if (-not $asOk) {
        Add-NRGDlFinding -Entry $Rec['DL-3.3'] -State 'NotApplicable' -Detail 'Not assessed: the anti-spam policies were not read, so whether allowed senders or domains skip spam filtering for the lists is unknown.'
    } else {
        $pols = @(Get-NRGObjectField -Item $bypass -Key 'AntiSpamPolicies' -Default @())
        $skipped = 0
        foreach ($p in $pols) {
            $pn = [string](Get-NRGObjectField -Item $p -Key 'Name' -Default ''); $inF = Get-NRGObjectField -Item $p -Key 'InForce' -Default $null
            foreach ($kv in @(@{ K = 'AllowedSenders'; Label = 'allowed sender' }, @{ K = 'AllowedSenderDomains'; Label = 'allowed domain' })) {
                foreach ($v in @(Get-NRGObjectField -Item $p -Key $kv.K -Default @())) {
                    if ($v -isnot [string] -and $null -eq $v) { continue }
                    if ($inF -eq $false) { $skipped++; continue }   # a custom policy no enabled rule applies: it bypasses nothing
                    $asEntries += [pscustomobject]@{ Policy = $pn; Kind = $kv.Label; Value = [string]$v; InForce = $inF }
                }
            }
        }
        if ($skipped) { $asOffNote = " $skipped further entr$(if ($skipped -eq 1) { 'y is' } else { 'ies are' }) on a custom policy no enabled rule applies, so they bypass nothing and were not judged." }
        $rulesNote = if (-not [bool](Get-NRGObjectField -Item $bypass -Key 'AntiSpamRulesRead' -Default $false)) { ' The anti-spam rules were not read, so whether a custom policy is applied to anyone is unknown and its entries are counted.' } else { '' }
        if ($asEntries.Count -eq 0) {
            Add-NRGDlFinding -Entry $Rec['DL-3.3'] -State 'Satisfied' -CurrentValue 'No allowed senders or domains' -Detail "Read: no anti-spam policy that applies lists an allowed sender or an allowed domain.$asOffNote$rulesNote"
        } else {
            $ao = @($asEntries | ForEach-Object { [ordered]@{ Source = 'Anti-spam policy'; Name = $_.Value; Class = $_.Kind; Detail = "policy '$($_.Policy)'" } })
            Add-NRGDlFinding -Entry $Rec['DL-3.3'] -State 'Gap' -AffectedObjects $ao -CurrentValue "$($asEntries.Count) allow entr$(if ($asEntries.Count -eq 1) { 'y' } else { 'ies' })" -RequiredValue $Rec['DL-3.3'].Recommended `
                -Detail ("Shortfall: $($asEntries.Count) allowed sender/domain entr$(if ($asEntries.Count -eq 1) { 'y' } else { 'ies' }) in policies that apply: " + (($asEntries | ForEach-Object { "$($_.Value) ($($_.Kind), policy '$($_.Policy)')" }) -join '; ') + ". Microsoft: avoid these lists if at all possible; senders on them skip spam, spoof and phishing protection except high confidence phishing.$asOffNote$rulesNote")
        }
    }

    # DL-3.4 a domain the tenant owns on an allow list or in a bypass rule condition
    if (-not $acceptedOk) {
        Add-NRGDlFinding -Entry $Rec['DL-3.4'] -State 'NotApplicable' -Detail 'Not assessed: the tenant''s accepted domains were not read, so which domains are its own cannot be told.'
    } else {
        $ownRule = @(); $ownAs = @()
        if ($trOk) {
            foreach ($r in $inForceRules) {
                foreach ($dm in @(Get-NRGObjectField -Item $r.Rule -Key 'SenderDomainIs' -Default @())) {
                    if (Test-NRGDlOwnDomain -Domain ([string]$dm) -AcceptedDomains $accepted) { $ownRule += [ordered]@{ Source = 'Mail flow rule'; Name = [string]$dm; Class = 'OwnDomainCondition'; Detail = "rule '$([string](Get-NRGObjectField -Item $r.Rule -Key 'Name' -Default ''))' sets SCL -1 for sender domain $dm" } }
                }
            }
        }
        if ($asOk) {
            foreach ($ae in $asEntries) {
                $dom = if ($ae.Kind -eq 'allowed sender') { ([string]$ae.Value -split '@')[-1] } else { [string]$ae.Value }
                if (Test-NRGDlOwnDomain -Domain $dom -AcceptedDomains $accepted) { $ownAs += [ordered]@{ Source = 'Anti-spam policy'; Name = $ae.Value; Class = 'OwnDomainAllowEntry'; Detail = "$($ae.Kind) in policy '$($ae.Policy)'" } }
            }
        }
        $ao = @($ownRule + $ownAs)
        $unreadSrc = @(); if (-not $trOk) { $unreadSrc += 'mail flow rules' }; if (-not $asOk) { $unreadSrc += 'anti-spam policies' }
        if ($ownRule.Count -gt 0) {
            Add-NRGDlFinding -Entry $Rec['DL-3.4'] -State 'Gap' -AffectedObjects $ao -CurrentValue "$($ao.Count) own-domain entr$(if ($ao.Count -eq 1) { 'y' } else { 'ies' })" -RequiredValue $Rec['DL-3.4'].Recommended `
                -Detail ("Shortfall: a domain this tenant owns is the condition of a mail flow rule that skips spam filtering: " + (($ownRule | ForEach-Object { $_.Detail }) -join '; ') + ". Microsoft: do not use accepted domains as mail flow rule conditions. Unlike an allowed-domain entry, a rule carries no requirement that the mail pass authentication." + $(if ($ownAs.Count) { " Also on an anti-spam allow list: " + (($ownAs | ForEach-Object { $_.Name }) -join ', ') + '.' } else { '' }) + $(if ($unreadSrc.Count) { " Not assessed: $($unreadSrc -join ' and ')." } else { '' }))
        } elseif ($ownAs.Count -gt 0) {
            Add-NRGDlFinding -Entry $Rec['DL-3.4'] -State 'Partial' -AffectedObjects $ao -CurrentValue "$($ownAs.Count) own-domain allow entr$(if ($ownAs.Count -eq 1) { 'y' } else { 'ies' })" -RequiredValue $Rec['DL-3.4'].Recommended `
                -Detail ("Shortfall: a domain this tenant owns is on an anti-spam allow list: " + (($ownAs | ForEach-Object { "$($_.Name) ($($_.Detail))" }) -join '; ') + ". Microsoft notes that since September 2022 allowed entries in your own accepted domains must pass email authentication to skip spam filtering, so spoofed mail claiming that domain does not skip filtering by this route; the entry is still a standing exception." + $(if ($unreadSrc.Count) { " Not assessed: $($unreadSrc -join ' and ')." } else { '' }))
        } elseif ($unreadSrc.Count -gt 0) {
            Add-NRGDlFinding -Entry $Rec['DL-3.4'] -State 'NotApplicable' -Detail "Not assessed: $($unreadSrc -join ' and ') were not read, so no own-domain entry was found in what was read but the rest is unknown."
        } else {
            Add-NRGDlFinding -Entry $Rec['DL-3.4'] -State 'Satisfied' -CurrentValue 'No own-domain entry' -Detail "Read: no accepted domain ($($accepted.Count)) is a condition of an enabled SCL -1 rule or an entry in an applied anti-spam allow list. Not assessed: Outlook Safe Senders (DL-3.5)."
        }
    }

    # DL-3.5 and DL-4.1 are never assessed by this scan: they say so, they never pass
    Add-NRGDlFinding -Entry $Rec['DL-3.5'] -State 'NotApplicable' -Detail 'Not assessed: Outlook Safe Senders live in each mailbox (one query per mailbox) and this scan does not read them. The exposure is unmeasured, not absent.'
    Add-NRGDlFinding -Entry $Rec['DL-4.1'] -State 'NotApplicable' -Detail 'Not assessed: DMARC reject does not cover a lookalike domain or display-name impersonation (the From domain is a different, real domain), and this scan cannot detect either. A clean worksheet does not mean a list is safe from them.'
}

#Requires -Version 7.0
#
# Test-NRGControlDistributionLists.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Compares every distribution list with the recommendations in
#          Config/distribution-list-baseline.json and emits one DL-* finding per list
#          per recommendation (Instance = the list), plus DL-0.1 for the scan itself.
#
# Data key consumed: EXO-DistributionLists   Graph scopes / cmdlets: none (evaluates data only).
#
# STRUCTURE. Test-NRGControlDistributionLists is a dispatcher. Each rule is its own function,
# Get-NRGDlVerdict<Rule>, that takes one list's context (Get-NRGDlListContext) and RETURNS a verdict
# object (New-NRGDlVerdict); it emits nothing. The dispatcher turns each verdict into one finding
# through Add-NRGDlFinding. A rule can therefore be read, and tested, on its own, and the one place
# that writes findings is one function.
#
# THE DL-* SERIES IS NOT IN Config/controls.json. These are worksheet findings for an
# administrator hardening lists, not baseline controls: nothing here is scored, and the
# series is judged by the worksheet only. The ids come from the catalog, never from a
# literal in this file.
#
# THE RULES, each one a past failure of this tool:
#   * Missing evidence is NotApplicable ("not assessed"), never Satisfied. A property
#     Exchange omitted, a member read that failed, and a section that did not collect
#     all land there, and each finding says what was read and what was not.
#   * A setting that is NRG's judgment (member cap, external members, join and leave
#     policy) is judged only against an APPROVED value in Config/nrg-standards.json.
#     With none approved the setting is reported and not assessed, never met.
#   * A setting Microsoft documents is judged against what Microsoft documents. A
#     setting with no documented recommendation is reported only, never judged.
#   * Every finding carries the Microsoft Learn source and the NIST SP 800-53 Rev 5
#     mapping from the catalog, labeled as this tool's mapping and not NIST's text.
#     Where no framework item was verified the finding says exactly that.
#   * A NotApplicable verdict says WHICH kind it is (not assessed / reported only / no approved
#     NRG standard / does not apply) through a structured Kind that becomes the first words of the
#     Detail. The worksheet reads that prefix; it never searches the prose, which carries the list's
#     display name.
#   * Add-NRGFinding is called with literal -State values in Add-NRGDlFinding, the same
#     shape Add-NRGExpectedStateFinding uses, so audits that derive what a verdict
#     helper can emit from its calls keep working.

function New-NRGDlVerdict {
    # What a rule concluded about one list. A NotApplicable verdict always names its Kind.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateSet('Satisfied', 'Partial', 'Gap', 'NotApplicable')] [string] $State,
        [Parameter(Mandatory)] [string] $Lead,
        [string[]] $Read = @(),
        [string[]] $NotRead = @(),
        [string] $Current = '',
        [object[]] $Affected = @(),
        [ValidateSet('', 'NotAssessed', 'ReportedOnly', 'NoStandard', 'DoesNotApply')] [string] $Kind = ''
    )
    if ($State -eq 'NotApplicable' -and -not $Kind) { $Kind = 'NotAssessed' }
    return [pscustomobject]@{ State = $State; Lead = $Lead; Read = @($Read); NotRead = @($NotRead); Current = $Current; Affected = @($Affected); Kind = $Kind }
}

function Get-NRGDlNames {
    # "A, B, C (+n more)": the first few names of a longer list, for a sentence.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Items, [int] $Max = 5)
    $a = @($Items)
    if ($a.Count -eq 0) { return '' }
    $shown = @($a | Select-Object -First $Max) -join ', '
    if ($a.Count -gt $Max) { return "$shown (+$($a.Count - $Max) more)" }
    return $shown
}

function Get-NRGDlListContext {
    # One list, read once into the fields the rules use. A list field is $null when it was not
    # returned and an array (possibly empty) when it was, so "owner not read" and "no owner" differ.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $List,
        [Parameter(Mandatory)] $Standards,
        [Parameter(Mandatory)] [string] $AcceptedDomainsSection
    )
    $disp = [string](Get-NRGObjectField -Item $List -Key 'DisplayName' -Default (Get-NRGObjectField -Item $List -Key 'Name' -Default ''))
    $type = [string](Get-NRGObjectField -Item $List -Key 'ListType' -Default 'Other')
    $memStatus = [string](Get-NRGObjectField -Item $List -Key 'MemberStatus' -Default 'NotRun')
    $onlyFrom = [ordered]@{
        AcceptMessagesOnlyFrom                 = (Get-NRGRuleList -Item $List -Key 'AcceptMessagesOnlyFrom')
        AcceptMessagesOnlyFromDLMembers        = (Get-NRGRuleList -Item $List -Key 'AcceptMessagesOnlyFromDLMembers')
        AcceptMessagesOnlyFromSendersOrMembers = (Get-NRGRuleList -Item $List -Key 'AcceptMessagesOnlyFromSendersOrMembers')
    }
    return [pscustomobject]@{
        Key          = Get-NRGDlListKey -List $List
        Label        = "List '$disp' ($type):"
        Type         = $type
        DirSynced    = ((Get-NRGObjectField -Item $List -Key 'IsDirSynced' -Default $null) -eq $true)
        Owners       = (Get-NRGRuleList -Item $List -Key 'Owners')
        Rsae         = (Get-NRGObjectField -Item $List -Key 'RequireSenderAuthenticationEnabled' -Default $null)
        OnlyFrom     = $onlyFrom
        Moderated    = (Get-NRGObjectField -Item $List -Key 'ModerationEnabled' -Default $null)
        Moderators   = (Get-NRGRuleList -Item $List -Key 'ModeratedBy')
        Join         = (Get-NRGObjectField -Item $List -Key 'MemberJoinRestriction' -Default $null)
        Depart       = (Get-NRGObjectField -Item $List -Key 'MemberDepartRestriction' -Default $null)
        Hidden       = (Get-NRGObjectField -Item $List -Key 'HiddenFromAddressListsEnabled' -Default $null)
        MemStatus    = $memStatus
        MemError     = [string](Get-NRGObjectField -Item $List -Key 'MemberError' -Default '')
        MemCount     = (Get-NRGObjectField -Item $List -Key 'MemberCount' -Default $null)
        MemTrunc     = ((Get-NRGObjectField -Item $List -Key 'MembersTruncated' -Default $false) -eq $true)
        External     = @(Get-NRGDlArray -Item $List -Key 'ExternalMembers')
        Nested       = @(Get-NRGDlArray -Item $List -Key 'NestedGroups')
        Unclassified = [int](Get-NRGObjectField -Item $List -Key 'UnclassifiedMemberCount' -Default 0)
        MembersRead  = ($memStatus -in 'Collected', 'Truncated')
        DomainsRead  = ($AcceptedDomainsSection -eq 'Collected')
        Standards    = $Standards
    }
}

# ── The rules. Each returns a verdict; none writes a finding. ─────────────────

function Get-NRGDlVerdictExternalSenders {   # DL-1.1
    [CmdletBinding()] param([Parameter(Mandatory)] $Ctx)
    $of = $Ctx.OnlyFrom
    $unread = @($of.Keys | Where-Object { $null -eq $of[$_] })
    $named  = @($of.Keys | Where-Object { $null -ne $of[$_] -and @($of[$_]).Count -gt 0 })
    if ($null -eq $Ctx.Rsae -or $Ctx.Rsae -isnot [bool]) {
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) RequireSenderAuthenticationEnabled was not returned." `
            -NotRead @('RequireSenderAuthenticationEnabled') -Current 'RequireSenderAuthenticationEnabled = not read'
    }
    if ($Ctx.Rsae) {
        return New-NRGDlVerdict -State Satisfied -Lead "$($Ctx.Label) requires authenticated (internal) senders, so mail from outside the organization is rejected." `
            -Read @('RequireSenderAuthenticationEnabled = True') -NotRead $unread -Current 'RequireSenderAuthenticationEnabled = True'
    }
    if ($named.Count -gt 0) {
        # SendersOrMembers repeats the other two, so count distinct senders, not entries.
        $n = @($named | ForEach-Object { $of[$_] } | ForEach-Object { $_ } | Sort-Object -Unique).Count
        return New-NRGDlVerdict -State Partial -Lead "$($Ctx.Label) accepts mail from unauthenticated (external) senders, but only from the $n sender(s) named in an AcceptMessagesOnlyFrom setting." `
            -Read @('RequireSenderAuthenticationEnabled = False', "sender allow-list: $n named sender(s) in $($named -join ', ')") -NotRead $unread `
            -Current "RequireSenderAuthenticationEnabled = False; allow-list: $n named sender(s)"
    }
    if ($unread.Count -eq 0) {
        return New-NRGDlVerdict -State Gap -Lead "$($Ctx.Label) accepts mail from anyone, including unauthenticated external senders, with no sender restriction." `
            -Read @('RequireSenderAuthenticationEnabled = False', 'AcceptMessagesOnlyFrom, AcceptMessagesOnlyFromDLMembers and AcceptMessagesOnlyFromSendersOrMembers = none') `
            -Current 'RequireSenderAuthenticationEnabled = False; no sender allow-list'
    }
    return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) RequireSenderAuthenticationEnabled is False but whether the senders are restricted could not be read." `
        -Read @('RequireSenderAuthenticationEnabled = False') -NotRead $unread -Current 'RequireSenderAuthenticationEnabled = False; sender allow-list not read'
}

function Get-NRGDlVerdictOwner {   # DL-1.2
    [CmdletBinding()] param([Parameter(Mandatory)] $Ctx)
    if ($null -eq $Ctx.Owners) {
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) ManagedBy (the owners) was not returned." -NotRead @('ManagedBy') -Current 'Owners = not read'
    }
    if (@($Ctx.Owners).Count -eq 0) {
        $syncNote = if ($Ctx.DirSynced) { ' This list is directory-synced: set the owner where the list is mastered (on-premises).' } else { '' }
        return New-NRGDlVerdict -State Gap -Lead "$($Ctx.Label) has no owner (ManagedBy is empty).$syncNote" -Read @('ManagedBy = none') -Current 'Owners = none'
    }
    $n = @($Ctx.Owners).Count
    return New-NRGDlVerdict -State Satisfied -Lead "$($Ctx.Label) has $n owner(s) named: $(Get-NRGDlNames $Ctx.Owners)." `
        -Read @("ManagedBy = $n owner(s)") -NotRead @('whether each named owner is a current, active account') -Current "Owners = $n"
}

function Get-NRGDlVerdictModeration {   # DL-1.3
    [CmdletBinding()] param([Parameter(Mandatory)] $Ctx)
    if ($null -eq $Ctx.Moderated -or $Ctx.Moderated -isnot [bool]) {
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) ModerationEnabled was not returned." -NotRead @('ModerationEnabled') -Current 'ModerationEnabled = not read'
    }
    if (-not $Ctx.Moderated) {
        return New-NRGDlVerdict -State NotApplicable -Kind ReportedOnly -Lead "$($Ctx.Label) moderation is off (Microsoft's default); there is nothing to assess." `
            -Read @('ModerationEnabled = False') -Current 'ModerationEnabled = False'
    }
    if ($null -eq $Ctx.Moderators -or $null -eq $Ctx.Owners) {
        $miss = @(@(if ($null -eq $Ctx.Moderators) { 'ModeratedBy' }) + @(if ($null -eq $Ctx.Owners) { 'ManagedBy' }))
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) moderation is on but who can approve could not be read." `
            -Read @('ModerationEnabled = True') -NotRead $miss -Current 'ModerationEnabled = True; approvers not read'
    }
    if (@($Ctx.Moderators).Count -gt 0) {
        return New-NRGDlVerdict -State Satisfied -Lead "$($Ctx.Label) moderation is on with $(@($Ctx.Moderators).Count) moderator(s): $(Get-NRGDlNames $Ctx.Moderators)." `
            -Read @('ModerationEnabled = True', 'ModeratedBy named') -Current "ModerationEnabled = True; moderators $(@($Ctx.Moderators).Count)"
    }
    if (@($Ctx.Owners).Count -gt 0) {
        return New-NRGDlVerdict -State Satisfied -Lead "$($Ctx.Label) moderation is on with no moderator named, so messages go to the $(@($Ctx.Owners).Count) owner(s) for approval (Microsoft)." `
            -Read @('ModerationEnabled = True', 'ModeratedBy = none', 'ManagedBy named') -Current "ModerationEnabled = True; owners approve ($(@($Ctx.Owners).Count))"
    }
    return New-NRGDlVerdict -State Gap -Lead "$($Ctx.Label) moderation is on but no moderator and no owner is named, so nobody is set up to approve its mail." `
        -Read @('ModerationEnabled = True', 'ModeratedBy = none', 'ManagedBy = none') -Current 'ModerationEnabled = True; no approver'
}

function Get-NRGDlVerdictMembershipRestriction {   # DL-1.4 (join) and DL-1.5 (leave)
    [CmdletBinding()] param([Parameter(Mandatory)] $Ctx, [Parameter(Mandatory)] $Rec)
    $isJoin = ($Rec.Id -eq 'DL-1.4')
    $val     = if ($isJoin) { $Ctx.Join } else { $Ctx.Depart }
    $prop    = if ($isJoin) { 'MemberJoinRestriction' } else { 'MemberDepartRestriction' }
    $allowed = @(if ($isJoin) { Get-NRGDlArray -Item $Ctx.Standards -Key 'AllowedJoin' } else { Get-NRGDlArray -Item $Ctx.Standards -Key 'AllowedDepart' })
    $msDefault = if ($isJoin) { "Microsoft's documented default for universal distribution groups is Closed" } else { "Microsoft's documented default for universal distribution groups is Open" }
    if ($null -eq $val -or [string]::IsNullOrWhiteSpace([string]$val)) {
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) $prop was not returned." -NotRead @($prop) -Current "$prop = not read"
    }
    if ($allowed.Count -eq 0) {
        return New-NRGDlVerdict -State NotApplicable -Kind NoStandard `
            -Lead "$($Ctx.Label) $prop is $val; no NRG standard is approved for it, because none is approved ($($Rec.StandardKey) is empty in Config/nrg-standards.json). $msDefault." `
            -Read @("$prop = $val") -NotRead @("whether $val meets an NRG standard") -Current "$prop = $val"
    }
    if ($allowed -contains [string]$val) {
        return New-NRGDlVerdict -State Satisfied -Lead "$($Ctx.Label) $prop is $val, which the approved NRG standard accepts." -Read @("$prop = $val") -Current "$prop = $val"
    }
    return New-NRGDlVerdict -State Gap -Lead "$($Ctx.Label) $prop is $val; the approved NRG standard accepts only $($allowed -join ', ')." -Read @("$prop = $val") -Current "$prop = $val"
}

function Get-NRGDlVerdictHidden {   # DL-1.6
    [CmdletBinding()] param([Parameter(Mandatory)] $Ctx)
    if ($null -eq $Ctx.Hidden -or $Ctx.Hidden -isnot [bool]) {
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) HiddenFromAddressListsEnabled was not returned." -NotRead @('HiddenFromAddressListsEnabled') -Current 'HiddenFromAddressListsEnabled = not read'
    }
    $tail = if ($Ctx.Hidden) { ' Hidden does not stop mail: anyone who types the address can still send to the list (Microsoft).' } else { '' }
    return New-NRGDlVerdict -State NotApplicable -Kind ReportedOnly -Lead "$($Ctx.Label) HiddenFromAddressListsEnabled is $($Ctx.Hidden); there is no recommendation to assess it against.$tail" `
        -Read @("HiddenFromAddressListsEnabled = $($Ctx.Hidden)") -Current "HiddenFromAddressListsEnabled = $($Ctx.Hidden)"
}

function Get-NRGDlVerdictMemberCount {   # DL-2.1
    [CmdletBinding()] param([Parameter(Mandatory)] $Ctx)
    $max = Get-NRGObjectField -Item $Ctx.Standards -Key 'MaxMembers' -Default $null
    $count = $Ctx.MemCount
    if (-not $Ctx.MembersRead -or $null -eq $count) {
        $why = if ($Ctx.MemError) { ": $($Ctx.MemError)" } else { '' }
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) the members were not read ($($Ctx.MemStatus)$why)." -NotRead @('the member list') -Current 'Members = not read'
    }
    $countText = if ($Ctx.MemTrunc) { "at least $count" } else { "$count" }
    $nested = 'members of nested groups (not expanded)'
    if ($null -eq $max) {
        return New-NRGDlVerdict -State NotApplicable -Kind NoStandard `
            -Lead "$($Ctx.Label) $countText direct member(s); no NRG maximum is approved, because none is approved (DistributionListMaxMembers is empty in Config/nrg-standards.json)." `
            -Read @("$countText direct member(s)") -NotRead @('whether the count meets an NRG maximum', $nested) -Current "Members = $countText"
    }
    if ($count -gt $max) {
        return New-NRGDlVerdict -State Gap -Lead "$($Ctx.Label) has $countText direct member(s), over the approved NRG maximum of $max." `
            -Read @("$countText direct member(s)") -NotRead @($nested) -Current "Members = $countText (max $max)"
    }
    if ($Ctx.MemTrunc) {
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) the list was read only up to $count member(s), so it cannot be shown to be within the approved maximum of $max." `
            -Read @("$countText direct member(s)") -NotRead @('members beyond the read limit') -Current "Members = $countText (max $max)"
    }
    return New-NRGDlVerdict -State Satisfied -Lead "$($Ctx.Label) has $countText direct member(s), within the approved NRG maximum of $max." `
        -Read @("$countText direct member(s)") -NotRead @($nested) -Current "Members = $countText (max $max)"
}

function Get-NRGDlVerdictExternalMembers {   # DL-2.2
    [CmdletBinding()] param([Parameter(Mandatory)] $Ctx)
    $prohibited = ((Get-NRGObjectField -Item $Ctx.Standards -Key 'ExternalMembersProhibited' -Default $false) -eq $true)
    $ext = @($Ctx.External)
    if (-not $Ctx.MembersRead) {
        $why = if ($Ctx.MemError) { ": $($Ctx.MemError)" } else { '' }
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) the members were not read ($($Ctx.MemStatus)$why)." -NotRead @('the member list') -Current 'External members = not read'
    }
    if (-not $Ctx.DomainsRead) {
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) the tenant's accepted domains were not read, so no member can be called external." `
            -Read @("$($Ctx.MemCount) member(s)") -NotRead @('accepted domains') -Current 'External members = not classified'
    }
    # What limits "none found": a truncated read and members that could not be classified.
    $limits = @($(if ($Ctx.MemTrunc) { 'members beyond the read limit' }), $(if ($Ctx.Unclassified -gt 0) { "$($Ctx.Unclassified) member(s) whose address could not be classified" }))
    if (-not $prohibited) {
        $who = if ($ext.Count) { "; they are $(Get-NRGDlNames @($ext | ForEach-Object { Get-NRGObjectField -Item $_ -Key 'UPN' -Default '' }))" } else { '' }
        $partial = if ($Ctx.MemTrunc) { ' (list not read in full)' } else { '' }
        return New-NRGDlVerdict -State NotApplicable -Kind NoStandard -Affected $ext `
            -Lead "$($Ctx.Label) $($ext.Count) external member(s) among those read$who; no NRG standard on external members is approved, because none is approved (DistributionListExternalMembers is empty in Config/nrg-standards.json)." `
            -Read @("$($ext.Count) external member(s)") -NotRead (@('whether external members are allowed by NRG') + $limits) -Current "External members = $($ext.Count)$partial"
    }
    if ($ext.Count -gt 0) {
        return New-NRGDlVerdict -State Gap -Affected $ext -Lead "$($Ctx.Label) has $($ext.Count) external member(s) (outside the tenant's accepted domains); the approved NRG standard prohibits them." `
            -Read @("$($ext.Count) external member(s)") -NotRead $limits -Current "External members = $($ext.Count)"
    }
    if ($Ctx.MemTrunc -or $Ctx.Unclassified -gt 0) {
        $because = if ($Ctx.MemTrunc) { 'the list was read only up to the limit' } else { "$($Ctx.Unclassified) member(s) could not be classified" }
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) no external member was found among those read, but $because." `
            -Read @('0 external member(s) among those classified') -NotRead $limits -Current 'External members = 0 found, not complete'
    }
    return New-NRGDlVerdict -State Satisfied -Lead "$($Ctx.Label) has no external member among its $($Ctx.MemCount) direct member(s)." `
        -Read @("$($Ctx.MemCount) direct member(s), all classified") -NotRead @('members of nested groups (not expanded)') -Current 'External members = 0'
}

function Get-NRGDlVerdictNestedGroups {   # DL-2.3
    [CmdletBinding()] param([Parameter(Mandatory)] $Ctx)
    if (-not $Ctx.MembersRead) {
        $why = if ($Ctx.MemError) { ": $($Ctx.MemError)" } else { '' }
        return New-NRGDlVerdict -State NotApplicable -Lead "$($Ctx.Label) the members were not read ($($Ctx.MemStatus)$why)." -NotRead @('the member list') -Current 'Nested groups = not read'
    }
    $nested = @($Ctx.Nested)
    $names = @($nested | ForEach-Object { Get-NRGObjectField -Item $_ -Key 'UPN' -Default '' })
    $lead = if ($nested.Count) { "$($nested.Count) nested group(s): $(Get-NRGDlNames $names); their members are not expanded here." } else { 'no nested group among the members read.' }
    return New-NRGDlVerdict -State NotApplicable -Kind ReportedOnly -Affected $nested -Lead "$($Ctx.Label) $lead" `
        -Read @("$($nested.Count) nested group(s)") -NotRead @('the members inside any nested group', $(if ($Ctx.MemTrunc) { 'members beyond the read limit' })) -Current "Nested groups = $($nested.Count)"
}

# ── Emission: the one place a verdict becomes a finding ───────────────────────

function Add-NRGDlFinding {
    # One emission point so every state is a literal -State below.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] [ValidateSet('Satisfied', 'Partial', 'Gap', 'NotApplicable')] [string] $State,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Severity,
        [Parameter(Mandatory)] [string] $Detail,
        [string] $CurrentValue = '',
        [string] $RequiredValue = '',
        [string] $Instance = '',
        [string[]] $FrameworkIds = @(),
        [object[]] $AffectedObjects = @(),
        [string] $Remediation = ''
    )
    $p = @{ ControlId = $ControlId; Category = 'Email'; Title = $Title; Detail = $Detail; Instance = $Instance
            CurrentValue = $CurrentValue; RequiredValue = $RequiredValue; FrameworkIds = $FrameworkIds
            AffectedObjects = @($AffectedObjects); Remediation = $Remediation }
    switch ($State) {
        'Satisfied'     { Add-NRGFinding @p -State 'Satisfied' -Severity 'Informational' }
        'NotApplicable' { Add-NRGFinding @p -State 'NotApplicable' -Severity 'Informational' }
        'Partial'       { Add-NRGFinding @p -State 'Partial' -Severity $Severity }
        'Gap'           { Add-NRGFinding @p -State 'Gap' -Severity $Severity }
    }
}

function Test-NRGControlDistributionLists {
    [CmdletBinding()]
    param(
        # Tests inject a parsed baseline / standards; a run reads both from Config/.
        [AllowNull()] $Baseline,
        [AllowNull()] $Standards
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($null -eq $Baseline)  { $Baseline  = Get-NRGDistributionListBaseline }
    if ($null -eq $Standards) { $Standards = Get-NRGDistributionListStandards }
    $recs = @($Baseline.Recommendations)
    if (-not $Baseline.Available -or $recs.Count -eq 0) {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'DL-Evaluator' -Message 'Config/distribution-list-baseline.json is missing or empty; no distribution-list finding was produced.'
        }
        return
    }

    # The citation is the same for every list, so it is built once per recommendation.
    $cite = @{}
    foreach ($rec in $recs) {
        $cite[$rec.Id] = @{ Ids = @(@($rec.Nist80053) | ForEach-Object { "NIST:$_" }); Text = (Get-NRGDlCitationText -Rec $rec) }
    }

    # ── Scan-level finding: was the inventory read? (not a catalog recommendation) ──
    $scanId = 'DL-0.1'
    $scanRec = [pscustomobject]@{ RecommendedValue = 'Every list and its members read in full'; RecommendedValueSource = 'None'
        SourceUrl = 'https://learn.microsoft.com/powershell/module/exchangepowershell/get-distributiongroup'; Nist80053 = @() }
    $scanCite = Get-NRGDlCitationText -Rec $scanRec
    $raw = Get-NRGRawData -Key 'EXO-DistributionLists'
    $ok  = ($null -ne $raw) -and [bool](Get-NRGNestedProperty -Object $raw -Path 'Success' -Default $false)
    if (-not $ok) {
        Add-NRGDlFinding -ControlId $scanId -State 'NotApplicable' -Severity 'Informational' -Title 'Distribution-list inventory was read' -Instance '(scan)' `
            -Detail (Format-NRGDlDetail -Rec $scanRec -Kind NotAssessed -CitationText $scanCite -Lead 'The distribution-list read did not run or failed, so no list was evaluated.' -NotRead @('every list, its settings and its members'))
        return
    }
    $secOf = { param([string] $n) [string](Get-NRGNestedProperty -Object $raw -Path "Data.SectionStatus.$n" -Default 'NotRun') }
    $secDG = & $secOf 'DistributionGroups'; $secDDG = & $secOf 'DynamicDistributionGroups'
    $secAD = & $secOf 'AcceptedDomains';    $secMem = & $secOf 'Members'
    $lists = @(Get-NRGNestedProperty -Object $raw -Path 'Data.Lists' -Default @())
    $maxRead = [int](Get-NRGNestedProperty -Object $raw -Path 'Data.Stats.MemberReadLimit' -Default 0)

    # What limits this read. The first group is specific to this run; the second is true of every run.
    $runLimits = [System.Collections.Generic.List[string]]::new()
    if ($secDG  -ne 'Collected') { $runLimits.Add("distribution groups and mail-enabled security groups were not read (section $secDG)") }
    if ($secDDG -ne 'Collected') { $runLimits.Add("dynamic distribution groups were not read (section $secDDG)") }
    if ($secAD  -ne 'Collected') { $runLimits.Add("accepted domains were not read (section $secAD), so no member can be called external or internal") }
    if ($secMem -ne 'Collected') { $runLimits.Add('the member read failed for at least one list (see that list)') }
    $truncN = @($lists | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'MemberStatus' -Default '') -eq 'Truncated' }).Count
    if ($truncN -gt 0) { $runLimits.Add("$truncN list(s) exceeded the $maxRead-member read limit and were read only up to it") }
    $alwaysLimits = @('Microsoft 365 (Unified) groups and Teams-connected groups are not read', 'members of a nested group are not expanded')
    $incomplete = ($runLimits.Count -gt 0)
    $scanLead = if ($incomplete) { "Not assessed in full: $($runLimits -join '; ')." } else { "$($lists.Count) list(s) read; every section collected." }
    Add-NRGDlFinding -ControlId $scanId -State $(if ($incomplete) { 'NotApplicable' } else { 'Satisfied' }) -Severity 'Informational' -Title 'Distribution-list inventory was read' -Instance '(scan)' `
        -CurrentValue ("Lists read: {0}; sections: DistributionGroups {1}, DynamicDistributionGroups {2}, AcceptedDomains {3}, Members {4}" -f $lists.Count, $secDG, $secDDG, $secAD, $secMem) `
        -Detail (Format-NRGDlDetail -Rec $scanRec -CitationText $scanCite -Lead $scanLead -Read @("$($lists.Count) list(s)") -NotRead (@($runLimits) + $alwaysLimits))

    # ── Per list, per recommendation ───────────────────────────────────────────
    foreach ($l in $lists) {
        $ctx = Get-NRGDlListContext -List $l -Standards $Standards -AcceptedDomainsSection $secAD
        foreach ($rec in $recs) {
            # A recommendation that does not apply to this kind of list is not a pass.
            $v = if (@($rec.AppliesTo).Count -gt 0 -and $ctx.Type -notin @($rec.AppliesTo)) {
                New-NRGDlVerdict -State NotApplicable -Kind DoesNotApply -Lead "$($ctx.Label) this recommendation does not apply to a $($ctx.Type) list."
            } else {
                switch ($rec.Id) {
                    'DL-1.1' { Get-NRGDlVerdictExternalSenders -Ctx $ctx }
                    'DL-1.2' { Get-NRGDlVerdictOwner -Ctx $ctx }
                    'DL-1.3' { Get-NRGDlVerdictModeration -Ctx $ctx }
                    { $_ -in 'DL-1.4', 'DL-1.5' } { Get-NRGDlVerdictMembershipRestriction -Ctx $ctx -Rec $rec }
                    'DL-1.6' { Get-NRGDlVerdictHidden -Ctx $ctx }
                    'DL-2.1' { Get-NRGDlVerdictMemberCount -Ctx $ctx }
                    'DL-2.2' { Get-NRGDlVerdictExternalMembers -Ctx $ctx }
                    'DL-2.3' { Get-NRGDlVerdictNestedGroups -Ctx $ctx }
                    # A recommendation this evaluator has no rule for is not evidence of anything.
                    default  { New-NRGDlVerdict -State NotApplicable -Lead "$($ctx.Label) no evaluator rule exists for $($rec.Id)." -NotRead @($rec.Setting) }
                }
            }
            $sev = if ($v.State -eq 'Partial' -and $rec.Severity -eq 'High') { 'Medium' } else { $rec.Severity }
            Add-NRGDlFinding -ControlId $rec.Id -State $v.State -Severity $sev -Title $rec.Title -Instance $ctx.Key `
                -CurrentValue $v.Current -RequiredValue $rec.RecommendedValue -FrameworkIds $cite[$rec.Id].Ids -AffectedObjects $v.Affected -Remediation $rec.FixNote `
                -Detail (Format-NRGDlDetail -Rec $rec -Kind $v.Kind -CitationText $cite[$rec.Id].Text -Lead $v.Lead -Read $v.Read -NotRead $v.NotRead)
        }
    }
}

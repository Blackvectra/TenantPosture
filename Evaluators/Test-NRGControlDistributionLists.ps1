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
#   * Add-NRGFinding is called with literal -State values in Add-NRGDlFinding, the same
#     shape Add-NRGExpectedStateFinding uses, so audits that derive what a verdict
#     helper can emit from its calls keep working.

function Get-NRGDlSourceLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Source)
    switch ($Source) {
        'MicrosoftDefault'  { 'Microsoft documented default' }
        'MicrosoftGuidance' { 'Microsoft documented guidance' }
        'NRGStandard'       { 'NRG standard' }
        default             { 'no recommendation' }
    }
}

function Format-NRGDlRecommended {
    # The recommended value as a reader sees it. A Microsoft value names where it comes from;
    # an NRG standard or "no recommendation" already says so in its own words.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Rec)
    if ($Rec.RecommendedValueSource -in 'MicrosoftDefault', 'MicrosoftGuidance') {
        return ('{0} ({1})' -f $Rec.RecommendedValue, (Get-NRGDlSourceLabel -Source $Rec.RecommendedValueSource))
    }
    return [string]$Rec.RecommendedValue
}

function Format-NRGDlDetail {
    # One sentence of verdict, then what was read, what was not, the recommendation, its
    # source and the NIST mapping. Every output prints this text unchanged.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Rec,
        [Parameter(Mandatory)] [string] $Lead,
        [string[]] $Read = @(),
        [string[]] $NotRead = @()
    )
    $nist = @(@($Rec.Nist80053) | ForEach-Object {
        $t = if (Get-Command Get-NRGNISTControlTitle -ErrorAction SilentlyContinue) { Get-NRGNISTControlTitle -ControlId $_ } else { '' }
        if ($t) { "$_ $t" } else { [string]$_ } })
    $fw = if ($nist.Count -gt 0) {
        "NIST SP 800-53 Rev 5 (this tool's mapping, not NIST text): $($nist -join '; ')."
    } else { 'Framework: no framework item verified.' }
    $Read = @($Read | Where-Object { $_ }); $NotRead = @($NotRead | Where-Object { $_ })
    $readText    = if ($Read.Count)    { ($Read -join '; ') }    else { 'nothing for this setting' }
    $notReadText = if ($NotRead.Count) { ($NotRead -join '; ') } else { 'nothing further for this setting' }
    # The recommended value is not repeated here: it travels as the finding's RequiredValue and
    # the worksheet's own Recommended field. What stays is the verdict, what was read and not
    # read, and the citation, so a finding printed anywhere still carries its source.
    return ("{0} Read: {1}. Not read: {2}. Source: {3}. {4}" -f $Lead.Trim(), $readText, $notReadText, $Rec.SourceUrl, $fw)
}

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
    $fwIds = { param($r) , @(@($r.Nist80053) | ForEach-Object { "NIST:$_" }) }

    # ── Scan-level finding: was the inventory read? (not a catalog recommendation) ──
    $scanId = 'DL-0.1'
    $scanRec = [pscustomobject]@{ RecommendedValue = 'Every list and its members read in full'; RecommendedValueSource = 'None'
        SourceUrl = 'https://learn.microsoft.com/powershell/module/exchangepowershell/get-distributiongroup'; Nist80053 = @() }
    $raw = Get-NRGRawData -Key 'EXO-DistributionLists'
    $ok  = ($null -ne $raw) -and [bool](Get-NRGNestedProperty -Object $raw -Path 'Success' -Default $false)
    if (-not $ok) {
        Add-NRGDlFinding -ControlId $scanId -State 'NotApplicable' -Severity 'Informational' -Title 'Distribution-list inventory was read' -Instance '(scan)' `
            -Detail (Format-NRGDlDetail -Rec $scanRec -Lead 'Not assessed: the distribution-list read did not run or failed, so no list was evaluated.' -NotRead @('every list, its settings and its members'))
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
    $scanLead  = if ($incomplete) { "Not assessed in full: $($runLimits -join '; ')." } else { "$($lists.Count) list(s) read; every section collected." }
    $scanState = if ($incomplete) { 'NotApplicable' } else { 'Satisfied' }
    Add-NRGDlFinding -ControlId $scanId -State $scanState -Severity 'Informational' -Title 'Distribution-list inventory was read' -Instance '(scan)' `
        -CurrentValue ("Lists read: {0}; sections: DistributionGroups {1}, DynamicDistributionGroups {2}, AcceptedDomains {3}, Members {4}" -f $lists.Count, $secDG, $secDDG, $secAD, $secMem) `
        -Detail (Format-NRGDlDetail -Rec $scanRec -Lead $scanLead -Read @("$($lists.Count) list(s)") -NotRead (@($runLimits) + $alwaysLimits))

    # ── Per list, per recommendation ───────────────────────────────────────────
    $names = { param($arr, [int] $n = 5) $a = @($arr); if ($a.Count -eq 0) { return '' }
               $shown = @($a | Select-Object -First $n) -join ', '; if ($a.Count -gt $n) { "$shown (+$($a.Count - $n) more)" } else { $shown } }
    foreach ($l in $lists) {
        $disp = [string](Get-NRGObjectField -Item $l -Key 'DisplayName' -Default (Get-NRGObjectField -Item $l -Key 'Name' -Default ''))
        $inst = Get-NRGDlListKey -List $l
        $type = [string](Get-NRGObjectField -Item $l -Key 'ListType' -Default 'Other')
        $dirSynced = ((Get-NRGObjectField -Item $l -Key 'IsDirSynced' -Default $null) -eq $true)
        $owners = Get-NRGRuleList -Item $l -Key 'Owners'
        $rsae = Get-NRGObjectField -Item $l -Key 'RequireSenderAuthenticationEnabled' -Default $null
        $onlyFrom = [ordered]@{
            AcceptMessagesOnlyFrom                 = (Get-NRGRuleList -Item $l -Key 'AcceptMessagesOnlyFrom')
            AcceptMessagesOnlyFromDLMembers        = (Get-NRGRuleList -Item $l -Key 'AcceptMessagesOnlyFromDLMembers')
            AcceptMessagesOnlyFromSendersOrMembers = (Get-NRGRuleList -Item $l -Key 'AcceptMessagesOnlyFromSendersOrMembers')
        }
        $moderated = Get-NRGObjectField -Item $l -Key 'ModerationEnabled' -Default $null
        $moderators = Get-NRGRuleList -Item $l -Key 'ModeratedBy'
        $join = Get-NRGObjectField -Item $l -Key 'MemberJoinRestriction' -Default $null
        $depart = Get-NRGObjectField -Item $l -Key 'MemberDepartRestriction' -Default $null
        $hidden = Get-NRGObjectField -Item $l -Key 'HiddenFromAddressListsEnabled' -Default $null
        $memStatus = [string](Get-NRGObjectField -Item $l -Key 'MemberStatus' -Default 'NotRun')
        $memError = [string](Get-NRGObjectField -Item $l -Key 'MemberError' -Default '')
        $memCount = Get-NRGObjectField -Item $l -Key 'MemberCount' -Default $null
        $memTrunc = ((Get-NRGObjectField -Item $l -Key 'MembersTruncated' -Default $false) -eq $true)
        $external = @(Get-NRGDlArray -Item $l -Key 'ExternalMembers')
        $nestedG = @(Get-NRGDlArray -Item $l -Key 'NestedGroups')
        $unclassified = [int](Get-NRGObjectField -Item $l -Key 'UnclassifiedMemberCount' -Default 0)
        $membersRead = ($memStatus -in 'Collected', 'Truncated')
        $emit = {
            param($Rec, [string] $State, [string] $Lead, [string[]] $Read, [string[]] $NotRead, [string] $Current = '', [object[]] $Affected = @())
            $sev = if ($State -eq 'Partial' -and $Rec.Severity -eq 'High') { 'Medium' } else { $Rec.Severity }
            Add-NRGDlFinding -ControlId $Rec.Id -State $State -Severity $sev -Title $Rec.Title -Instance $inst `
                -CurrentValue $Current -RequiredValue $Rec.RecommendedValue -FrameworkIds (& $fwIds $Rec) -AffectedObjects $Affected `
                -Remediation $Rec.FixNote -Detail (Format-NRGDlDetail -Rec $Rec -Lead $Lead -Read $Read -NotRead $NotRead)
        }
        $label = "List '$disp' ($type):"

        foreach ($rec in $recs) {
            # A recommendation that does not apply to this kind of list is not a pass.
            if ($rec.AppliesTo.Count -gt 0 -and $type -notin @($rec.AppliesTo)) {
                & $emit $rec 'NotApplicable' "$label not assessed, this recommendation does not apply to a $type list." @() @() ''
                continue
            }
            $std = $rec.StandardKey
            switch ($rec.Id) {

                'DL-1.1' {
                    $unread = @($onlyFrom.Keys | Where-Object { $null -eq $onlyFrom[$_] })
                    $named  = @($onlyFrom.Keys | Where-Object { $null -ne $onlyFrom[$_] -and @($onlyFrom[$_]).Count -gt 0 })
                    if ($null -eq $rsae -or $rsae -isnot [bool]) {
                        & $emit $rec 'NotApplicable' "$label not assessed, RequireSenderAuthenticationEnabled was not returned." @() @('RequireSenderAuthenticationEnabled') 'RequireSenderAuthenticationEnabled = not read'
                    } elseif ($rsae) {
                        & $emit $rec 'Satisfied' "$label requires authenticated (internal) senders, so mail from outside the organization is rejected." @('RequireSenderAuthenticationEnabled = True') $unread 'RequireSenderAuthenticationEnabled = True'
                    } elseif ($named.Count -gt 0) {
                        # SendersOrMembers repeats the other two, so count distinct senders, not entries.
                        $n = @($named | ForEach-Object { $onlyFrom[$_] } | ForEach-Object { $_ } | Sort-Object -Unique).Count
                        & $emit $rec 'Partial' "$label accepts mail from unauthenticated (external) senders, but only from the $n sender(s) named in an AcceptMessagesOnlyFrom setting." @('RequireSenderAuthenticationEnabled = False', "sender allow-list: $n named sender(s) in $($named -join ', ')") $unread "RequireSenderAuthenticationEnabled = False; allow-list: $n named sender(s)"
                    } elseif ($unread.Count -eq 0) {
                        & $emit $rec 'Gap' "$label accepts mail from anyone, including unauthenticated external senders, with no sender restriction." @('RequireSenderAuthenticationEnabled = False', 'AcceptMessagesOnlyFrom, AcceptMessagesOnlyFromDLMembers and AcceptMessagesOnlyFromSendersOrMembers = none') @() 'RequireSenderAuthenticationEnabled = False; no sender allow-list'
                    } else {
                        & $emit $rec 'NotApplicable' "$label not assessed, RequireSenderAuthenticationEnabled is False but whether the senders are restricted could not be read." @('RequireSenderAuthenticationEnabled = False') $unread 'RequireSenderAuthenticationEnabled = False; sender allow-list not read'
                    }
                }

                'DL-1.2' {
                    $dsNote = if ($dirSynced) { ' This list is directory-synced: set the owner where the list is mastered (on-premises).' } else { '' }
                    if ($null -eq $owners) {
                        & $emit $rec 'NotApplicable' "$label not assessed, ManagedBy (the owners) was not returned." @() @('ManagedBy') 'Owners = not read'
                    } elseif (@($owners).Count -eq 0) {
                        & $emit $rec 'Gap' "$label has no owner (ManagedBy is empty).$dsNote" @('ManagedBy = none') @() 'Owners = none'
                    } else {
                        & $emit $rec 'Satisfied' "$label has $(@($owners).Count) owner(s) named: $(& $names $owners)." @("ManagedBy = $(@($owners).Count) owner(s)") @('whether each named owner is a current, active account') "Owners = $(@($owners).Count)"
                    }
                }

                'DL-1.3' {
                    if ($null -eq $moderated -or $moderated -isnot [bool]) {
                        & $emit $rec 'NotApplicable' "$label not assessed, ModerationEnabled was not returned." @() @('ModerationEnabled') 'ModerationEnabled = not read'
                    } elseif (-not $moderated) {
                        & $emit $rec 'NotApplicable' "$label reported only, moderation is off (Microsoft's default); there is nothing to assess." @('ModerationEnabled = False') @() 'ModerationEnabled = False'
                    } elseif ($null -eq $moderators -or $null -eq $owners) {
                        $miss = @(@(if ($null -eq $moderators) { 'ModeratedBy' }) + @(if ($null -eq $owners) { 'ManagedBy' }))
                        & $emit $rec 'NotApplicable' "$label not assessed, moderation is on but who can approve could not be read." @('ModerationEnabled = True') $miss 'ModerationEnabled = True; approvers not read'
                    } elseif (@($moderators).Count -gt 0) {
                        & $emit $rec 'Satisfied' "$label moderation is on with $(@($moderators).Count) moderator(s): $(& $names $moderators)." @('ModerationEnabled = True', 'ModeratedBy named') @() "ModerationEnabled = True; moderators $(@($moderators).Count)"
                    } elseif (@($owners).Count -gt 0) {
                        & $emit $rec 'Satisfied' "$label moderation is on with no moderator named, so messages go to the $(@($owners).Count) owner(s) for approval (Microsoft)." @('ModerationEnabled = True', 'ModeratedBy = none', 'ManagedBy named') @() "ModerationEnabled = True; owners approve ($(@($owners).Count))"
                    } else {
                        & $emit $rec 'Gap' "$label moderation is on but no moderator and no owner is named, so nobody is set up to approve its mail." @('ModerationEnabled = True', 'ModeratedBy = none', 'ManagedBy = none') @() 'ModerationEnabled = True; no approver'
                    }
                }

                { $_ -in 'DL-1.4', 'DL-1.5' } {
                    $isJoin = ($rec.Id -eq 'DL-1.4')
                    $val = if ($isJoin) { $join } else { $depart }
                    # @(if ...) around the whole statement: an if yielding an empty array assigns $null.
                    $allowed = @(if ($isJoin) { Get-NRGDlArray -Item $Standards -Key 'AllowedJoin' } else { Get-NRGDlArray -Item $Standards -Key 'AllowedDepart' })
                    $prop = if ($isJoin) { 'MemberJoinRestriction' } else { 'MemberDepartRestriction' }
                    $msDefault = if ($isJoin) { "Microsoft's documented default for universal distribution groups is Closed" } else { "Microsoft's documented default for universal distribution groups is Open" }
                    if ($null -eq $val -or [string]::IsNullOrWhiteSpace([string]$val)) {
                        & $emit $rec 'NotApplicable' "$label not assessed, $prop was not returned." @() @($prop) "$prop = not read"
                    } elseif ($allowed.Count -eq 0) {
                        & $emit $rec 'NotApplicable' "$label reported, not assessed: $prop is $val; no NRG standard is approved for it, because none is approved ($std is empty in Config/nrg-standards.json). $msDefault." @("$prop = $val") @("whether $val meets an NRG standard") "$prop = $val"
                    } elseif ($allowed -contains [string]$val) {
                        & $emit $rec 'Satisfied' "$label $prop is $val, which the approved NRG standard accepts." @("$prop = $val") @() "$prop = $val"
                    } else {
                        & $emit $rec 'Gap' "$label $prop is $val; the approved NRG standard accepts only $($allowed -join ', ')." @("$prop = $val") @() "$prop = $val"
                    }
                }

                'DL-1.6' {
                    if ($null -eq $hidden -or $hidden -isnot [bool]) {
                        & $emit $rec 'NotApplicable' "$label not assessed, HiddenFromAddressListsEnabled was not returned." @() @('HiddenFromAddressListsEnabled') 'HiddenFromAddressListsEnabled = not read'
                    } else {
                        $tail = if ($hidden) { ' Hidden does not stop mail: anyone who types the address can still send to the list (Microsoft).' } else { '' }
                        & $emit $rec 'NotApplicable' "$label reported only, HiddenFromAddressListsEnabled is $hidden; there is no recommendation to assess it against.$tail" @("HiddenFromAddressListsEnabled = $hidden") @() "HiddenFromAddressListsEnabled = $hidden"
                    }
                }

                'DL-2.1' {
                    $max = Get-NRGObjectField -Item $Standards -Key 'MaxMembers' -Default $null
                    $countText = if ($null -eq $memCount) { 'unknown' } elseif ($memTrunc) { "at least $memCount" } else { "$memCount" }
                    if (-not $membersRead -or $null -eq $memCount) {
                        & $emit $rec 'NotApplicable' "$label not assessed, the members were not read ($memStatus$(if ($memError) { ": $memError" }))." @() @('the member list') 'Members = not read'
                    } elseif ($null -eq $max) {
                        & $emit $rec 'NotApplicable' "$label reported, not assessed: $countText direct member(s); no NRG maximum is approved, because none is approved (DistributionListMaxMembers is empty in Config/nrg-standards.json)." @("$countText direct member(s)") @('whether the count meets an NRG maximum', 'members of nested groups (not expanded)') "Members = $countText"
                    } elseif ($memCount -gt $max) {
                        & $emit $rec 'Gap' "$label has $countText direct member(s), over the approved NRG maximum of $max." @("$countText direct member(s)") @('members of nested groups (not expanded)') "Members = $countText (max $max)"
                    } elseif ($memTrunc) {
                        & $emit $rec 'NotApplicable' "$label not assessed, the list was read only up to $memCount member(s), so it cannot be shown to be within the approved maximum of $max." @("$countText direct member(s)") @('members beyond the read limit') "Members = $countText (max $max)"
                    } else {
                        & $emit $rec 'Satisfied' "$label has $countText direct member(s), within the approved NRG maximum of $max." @("$countText direct member(s)") @('members of nested groups (not expanded)') "Members = $countText (max $max)"
                    }
                }

                'DL-2.2' {
                    $prohibited = ((Get-NRGObjectField -Item $Standards -Key 'ExternalMembersProhibited' -Default $false) -eq $true)
                    if (-not $membersRead) {
                        & $emit $rec 'NotApplicable' "$label not assessed, the members were not read ($memStatus$(if ($memError) { ": $memError" }))." @() @('the member list') 'External members = not read'
                    } elseif ($secAD -ne 'Collected') {
                        & $emit $rec 'NotApplicable' "$label not assessed, the tenant's accepted domains were not read, so no member can be called external." @("$memCount member(s)") @('accepted domains') 'External members = not classified'
                    } elseif (-not $prohibited) {
                        $who = if ($external.Count) { "; they are $(& $names (@($external | ForEach-Object { Get-NRGObjectField -Item $_ -Key 'UPN' -Default '' })))" } else { '' }
                        $limits = @($(if ($memTrunc) { 'members beyond the read limit' }), $(if ($unclassified -gt 0) { "$unclassified member(s) whose address could not be classified" }))
                        & $emit $rec 'NotApplicable' "$label reported, not assessed: $($external.Count) external member(s) among those read$who; no NRG standard on external members is approved, because none is approved (DistributionListExternalMembers is empty in Config/nrg-standards.json)." @("$($external.Count) external member(s)") (@('whether external members are allowed by NRG') + $limits) "External members = $($external.Count)$(if ($memTrunc) { ' (list not read in full)' })" $external
                    } elseif ($external.Count -gt 0) {
                        & $emit $rec 'Gap' "$label has $($external.Count) external member(s) (outside the tenant's accepted domains); the approved NRG standard prohibits them." @("$($external.Count) external member(s)") @($(if ($memTrunc) { 'members beyond the read limit' }), $(if ($unclassified -gt 0) { "$unclassified member(s) whose address could not be classified" })) "External members = $($external.Count)" $external
                    } elseif ($memTrunc -or $unclassified -gt 0) {
                        & $emit $rec 'NotApplicable' "$label not assessed in full, no external member was found among those read, but $(if ($memTrunc) { 'the list was read only up to the limit' } else { "$unclassified member(s) could not be classified" })." @('0 external member(s) among those classified') @($(if ($memTrunc) { 'members beyond the read limit' }), $(if ($unclassified) { "$unclassified unclassified member(s)" })) 'External members = 0 found, not complete'
                    } else {
                        & $emit $rec 'Satisfied' "$label has no external member among its $memCount direct member(s)." @("$memCount direct member(s), all classified") @('members of nested groups (not expanded)') 'External members = 0'
                    }
                }

                'DL-2.3' {
                    if (-not $membersRead) {
                        & $emit $rec 'NotApplicable' "$label not assessed, the members were not read ($memStatus$(if ($memError) { ": $memError" }))." @() @('the member list') 'Nested groups = not read'
                    } else {
                        $nm = @($nestedG | ForEach-Object { Get-NRGObjectField -Item $_ -Key 'UPN' -Default '' })
                        $lead = if ($nestedG.Count) { "reported only: $($nestedG.Count) nested group(s): $(& $names $nm); their members are not expanded here." } else { 'reported only: no nested group among the members read.' }
                        & $emit $rec 'NotApplicable' "$label $lead" @("$($nestedG.Count) nested group(s)") @('the members inside any nested group', $(if ($memTrunc) { 'members beyond the read limit' })) "Nested groups = $($nestedG.Count)" $nestedG
                    }
                }

                default {
                    # A recommendation this evaluator has no rule for is not evidence of anything.
                    & $emit $rec 'NotApplicable' "$label not assessed, no evaluator rule exists for $($rec.Id)." @() @($rec.Setting) ''
                }
            }
        }
    }
}

#Requires -Version 7.0
#
# Test-NRGDistributionListControls.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Evaluators for the distribution-list scan. One finding per list per
#          control (Instance = the list's primary address), so the worksheet can
#          print one row per list from the findings alone, and a replayed results
#          file reproduces it.
#
# Reads:   EXO-DistributionLists (Invoke-NRGCollectDistributionLists)
# Writes:  Findings via Add-NRGFinding with DL-* control IDs.
#
# These are hardening checks for one scan, NOT baseline controls: they are not in
# Config/controls.json, carry no framework citation, and move no score. They follow
# the Email-IR pattern (a separate control series with its own evaluators).
#
#   DL-1.1  Who can send: a list that accepts mail from outside with no allow-list
#           and no moderation is a Gap (the way an "all staff" list gets used for
#           phishing); moderated is Partial; authenticated-only or an allow-list is
#           Satisfied.
#   DL-2.1  Owners: no owner is a Gap.
#   DL-2.2  Who can join: Open is a Gap. Not evaluated for dynamic lists (their
#           members come from a filter, not from joining).
#   DL-3.1  Outside members: any is a Gap to confirm, none found is Satisfied only
#           when every direct member was read and classified.
#
# States follow the repo rules. A value Exchange did not return, a section that did
# not collect, a member read that failed, was capped, or could not be classified is
# NotApplicable ("Not assessed: ..."), never Satisfied, and an empty list from a
# failed query is never "none". Each Detail starts with the list's name and address
# and says what was read, so the same sentence reads the same in the worksheet, the
# CSV and the results JSON.

$script:NRGDistributionListControls = [ordered]@{
    'DL-1.1' = @{
        Title       = 'Distribution list accepts mail from senders outside the organization'
        Remediation = 'Set the list to accept mail only from authenticated senders (RequireSenderAuthenticationEnabled = True). If outside senders must write to it, restrict it to a named sender allow-list or require moderator approval instead.'
        Required    = 'Accept mail only from authenticated senders (RequireSenderAuthenticationEnabled = True), a named sender allow-list, or moderator approval'
    }
    'DL-2.1' = @{
        Title       = 'Distribution list has no owner'
        Remediation = 'Assign at least one accountable owner (ManagedBy) who decides who is on the list and who can send to it.'
        Required    = 'At least one owner (ManagedBy)'
    }
    'DL-2.2' = @{
        Title       = 'Anyone in the organization can join the distribution list'
        Remediation = 'Set MemberJoinRestriction to Closed, or to ApprovalRequired if people must be able to ask to join.'
        Required    = 'MemberJoinRestriction = Closed (or ApprovalRequired)'
    }
    'DL-3.1' = @{
        Title       = 'Distribution list delivers to members outside the organization'
        Remediation = 'Confirm with the list owner that each outside member should receive everything sent to the list, and remove the ones that should not.'
        Required    = 'Only members the owner has confirmed; no unintended outside members'
    }
}

# What was collected, in one place, so every control reads the same evidence and
# decides "not assessed" the same way. Returns Usable = $false with the reason when
# no list inventory can be trusted at all.
function Get-NRGDistributionListEvidence {
    [CmdletBinding()]
    param()

    $raw = Get-NRGRawData -Key 'EXO-DistributionLists'
    $ev = [ordered]@{
        Usable        = $false
        Reason        = ''
        Lists         = @()
        Domains       = 'NotRun'
        Groups        = 'NotRun'
        Dynamic       = 'NotRun'
        PartialNote   = ''
        ErrorSummary  = ''
    }
    if ($null -eq $raw) {
        $ev['Reason'] = 'the distribution-list collector did not run'
        return [pscustomobject]$ev
    }

    $errs = @(Get-NRGObjectField -Item (Get-NRGObjectField -Item $raw -Key 'Data' -Default $null) -Key 'Errors' -Default @() | ForEach-Object { [string]$_ } | Where-Object { $_ })
    $ev['ErrorSummary'] = (@($errs | Select-Object -First 3) -join ' | ')

    $success = Get-NRGObjectField -Item $raw -Key 'Success' -Default $false
    $status  = Get-NRGNestedProperty -Object $raw -Path 'Data.SectionStatus' -Default $null
    $ev['Domains']  = [string](Get-NRGObjectField -Item $status -Key 'AcceptedDomains'    -Default 'NotRun')
    $ev['Groups']   = [string](Get-NRGObjectField -Item $status -Key 'DistributionGroups' -Default 'NotRun')
    $ev['Dynamic']  = [string](Get-NRGObjectField -Item $status -Key 'DynamicGroups'      -Default 'NotRun')

    if ($success -ne $true -or ($ev['Groups'] -ne 'Collected' -and $ev['Dynamic'] -ne 'Collected')) {
        $why = if ($ev['ErrorSummary']) { $ev['ErrorSummary'] } else { 'no list query completed' }
        $ev['Reason'] = "no distribution list could be read ($why)"
        return [pscustomobject]$ev
    }

    # Two statements: an if-block that yields an empty array assigns $null, and @($null).Count is 1.
    $lists = Get-NRGRuleList -Item (Get-NRGObjectField -Item $raw -Key 'Data' -Default $null) -Key 'Lists'
    $listArray = @()
    if ($null -ne $lists) { $listArray = @($lists) }
    $ev['Lists'] = $listArray
    $ev['Usable'] = $true

    # One section collected and the other not: the collected kind is evaluated, and
    # the gap is named once per control so it cannot be mistaken for "none exist".
    $missing = [System.Collections.Generic.List[string]]::new()
    if ($ev['Groups']  -ne 'Collected') { $missing.Add('distribution lists and mail-enabled security groups') }
    if ($ev['Dynamic'] -ne 'Collected') { $missing.Add('dynamic distribution lists') }
    if ($missing.Count -gt 0) {
        $why = if ($ev['ErrorSummary']) { " ($($ev['ErrorSummary']))" } else { '' }
        $ev['PartialNote'] = 'the ' + ($missing -join ' and ') + " could not be read$why"
    }
    return [pscustomobject]$ev
}

# "Name (address): " in front of every per-list sentence.
function Get-NRGDistributionListLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $List)
    $name = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $List -Key 'DisplayName' -Default (Get-NRGObjectField -Item $List -Key 'Name' -Default '')) -MaxLength 120
    $addr = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $List -Key 'PrimarySmtpAddress' -Default '') -MaxLength 320
    if ($name -and $addr) { return "$name ($addr)" }
    if ($addr) { return $addr }
    if ($name) { return $name }
    return '(unnamed list)'
}

function Get-NRGDistributionListInstance {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $List)
    foreach ($k in 'PrimarySmtpAddress', 'Guid', 'Name') {
        $v = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $List -Key $k -Default '') -MaxLength 320
        if ($v) { return $v }
    }
    return '(unnamed list)'
}

# Tenant-level "not assessed", for when there are no lists to attach a finding to.
function Add-NRGDistributionListNotAssessed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] [string] $Reason
    )
    $def = $script:NRGDistributionListControls[$ControlId]
    Add-NRGFinding -ControlId $ControlId -State 'NotApplicable' -Category 'Email' `
        -Title $def.Title -Severity 'Informational' `
        -Detail ("Not assessed: " + (ConvertTo-NRGDLText -Value $Reason -MaxLength 600) + '.') `
        -RequiredValue $def.Required -Remediation $def.Remediation
}

# Runs one control's per-list rule over every list, with the not-assessed paths
# shared: no usable inventory, one list kind unread, or no lists returned.
function Invoke-NRGDistributionListControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] [scriptblock] $Rule,
        # Dynamic lists have no join step; the control skips them.
        [switch] $SkipDynamic
    )

    $ev = Get-NRGDistributionListEvidence
    if (-not $ev.Usable) {
        Add-NRGDistributionListNotAssessed -ControlId $ControlId -Reason $ev.Reason
        return
    }
    if ($ev.PartialNote) {
        Add-NRGDistributionListNotAssessed -ControlId $ControlId -Reason $ev.PartialNote
    }
    $lists = @($ev.Lists)
    if ($lists.Count -eq 0 -and -not $ev.PartialNote) {
        Add-NRGDistributionListNotAssessed -ControlId $ControlId -Reason 'Exchange returned no distribution lists to this account (a role-scoped administrator sees only the lists in that scope, so this does not prove none exist)'
        return
    }
    foreach ($list in $lists) {
        if ($SkipDynamic -and (ConvertTo-NRGDLBoolean (Get-NRGObjectField -Item $list -Key 'IsDynamic' -Default $false)) -eq $true) { continue }
        & $Rule $list $ev $ControlId $script:NRGDistributionListControls[$ControlId]
    }
}

function Test-NRGDistributionListSenderExposure {
    [CmdletBinding()]
    param()
    $id = 'DL-1.1'
    Invoke-NRGDistributionListControl -ControlId $id -Rule {
        param($List, $Evidence, $ControlId, $Def)
        $label = Get-NRGDistributionListLabel -List $List
        $inst  = Get-NRGDistributionListInstance -List $List
        $sa    = Get-NRGDistributionListSenderAccess -List $List
        $obj   = @([pscustomobject]@{ List = $label; Address = $inst })
        $common = @{ ControlId = $ControlId; Category = 'Email'; Title = $Def.Title; Instance = $inst; CurrentValue = $sa.Summary; RequiredValue = $Def.Required; Remediation = $Def.Remediation; AffectedObjects = $obj }

        switch ($sa.Mode) {
            'Unknown' {
                Add-NRGFinding @common -State 'NotApplicable' -Severity 'Informational' `
                    -Detail "${label}: Not assessed: Exchange did not return the sender-authentication setting (RequireSenderAuthenticationEnabled) for this list, so who can send to it is not known."
            }
            'AuthenticatedOnly' {
                Add-NRGFinding @common -State 'Satisfied' -Severity 'Informational' `
                    -Detail "${label}: Accepts mail only from authenticated senders inside the organization; mail from outside senders is rejected."
            }
            'AllowList' {
                $extra = if ($sa.RequireAuth -eq $false) { ' The list is not limited to authenticated senders, so confirm each sender on the allow-list is intended, especially any outside contact.' } else { '' }
                Add-NRGFinding @common -State 'Satisfied' -Severity 'Informational' `
                    -Detail "${label}: Only the senders on its allow-list ($($sa.AllowListCount)) can send to it.$extra"
            }
            'OpenToOutsideModerated' {
                Add-NRGFinding @common -State 'Partial' -Severity 'Medium' `
                    -Detail "${label}: Accepts mail from anyone, including people outside the organization, but every message waits for moderator approval. The exposure depends on the moderators; an unattended or fast-approving moderator leaves it open."
            }
            'OpenToOutside' {
                $unconfirmed = if (-not $sa.AllowListKnown) { ' The sender allow-list was not returned, so a restriction could not be confirmed.' } else { '' }
                Add-NRGFinding @common -State 'Gap' -Severity 'High' `
                    -Detail "${label}: Accepts mail from anyone, including people outside the organization, with no sender allow-list and no moderation. Anyone on the internet can email every member of this list; this is how an all-staff list gets used for phishing.$unconfirmed"
            }
        }
    }
}

function Test-NRGDistributionListOwners {
    [CmdletBinding()]
    param()
    $id = 'DL-2.1'
    Invoke-NRGDistributionListControl -ControlId $id -Rule {
        param($List, $Evidence, $ControlId, $Def)
        $label = Get-NRGDistributionListLabel -List $List
        $inst  = Get-NRGDistributionListInstance -List $List
        $owners = Get-NRGDLNamedItems -Item $List -Key 'ManagedBy' -NamesKey 'ManagedByWithDisplayNames'
        $obj   = @([pscustomobject]@{ List = $label; Address = $inst })
        $common = @{ ControlId = $ControlId; Category = 'Email'; Title = $Def.Title; Instance = $inst; RequiredValue = $Def.Required; Remediation = $Def.Remediation; AffectedObjects = $obj }

        if (-not $owners.Known) {
            Add-NRGFinding @common -State 'NotApplicable' -Severity 'Informational' -CurrentValue 'Not read' `
                -Detail "${label}: Not assessed: Exchange did not return the owner list (ManagedBy) for this list."
        } elseif ($owners.Count -eq 0) {
            Add-NRGFinding @common -State 'Gap' -Severity 'Low' -CurrentValue 'No owner' `
                -Detail "${label}: Has no owner. Nobody is accountable for who is on this list or who can send to it."
        } else {
            $who = if ($owners.Names.Count -gt 0) { (@($owners.Names) -join ', ') } else { "$($owners.Count) owner(s) (names not returned)" }
            Add-NRGFinding @common -State 'Satisfied' -Severity 'Informational' -CurrentValue $who `
                -Detail "${label}: Has $($owners.Count) owner(s): $who."
        }
    }
}

function Test-NRGDistributionListJoinRestriction {
    [CmdletBinding()]
    param()
    $id = 'DL-2.2'
    Invoke-NRGDistributionListControl -ControlId $id -SkipDynamic -Rule {
        param($List, $Evidence, $ControlId, $Def)
        $label = Get-NRGDistributionListLabel -List $List
        $inst  = Get-NRGDistributionListInstance -List $List
        $join  = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $List -Key 'MemberJoinRestriction' -Default '') -MaxLength 40
        $obj   = @([pscustomobject]@{ List = $label; Address = $inst })
        $common = @{ ControlId = $ControlId; Category = 'Email'; Title = $Def.Title; Instance = $inst; RequiredValue = $Def.Required; Remediation = $Def.Remediation; AffectedObjects = $obj }

        switch ($join) {
            'Open' {
                Add-NRGFinding @common -State 'Gap' -Severity 'Medium' -CurrentValue 'MemberJoinRestriction = Open' `
                    -Detail "${label}: Anyone in the organization can add themselves to this list and then receive everything sent to it (MemberJoinRestriction is Open)."
            }
            'ApprovalRequired' {
                Add-NRGFinding @common -State 'Satisfied' -Severity 'Informational' -CurrentValue 'MemberJoinRestriction = ApprovalRequired' `
                    -Detail "${label}: Joining needs the owner's approval (MemberJoinRestriction is ApprovalRequired)."
            }
            'Closed' {
                Add-NRGFinding @common -State 'Satisfied' -Severity 'Informational' -CurrentValue 'MemberJoinRestriction = Closed' `
                    -Detail "${label}: Only an owner or administrator can add members (MemberJoinRestriction is Closed)."
            }
            default {
                $shown = if ($join) { "an unrecognized value ('$join')" } else { 'no value' }
                Add-NRGFinding @common -State 'NotApplicable' -Severity 'Informational' -CurrentValue 'Not read' `
                    -Detail "${label}: Not assessed: Exchange returned $shown for MemberJoinRestriction, so who can join this list is not known."
            }
        }
    }
}

function Test-NRGDistributionListExternalMembers {
    [CmdletBinding()]
    param()
    $id = 'DL-3.1'
    Invoke-NRGDistributionListControl -ControlId $id -Rule {
        param($List, $Evidence, $ControlId, $Def)
        $label = Get-NRGDistributionListLabel -List $List
        $inst  = Get-NRGDistributionListInstance -List $List
        $status = [string](Get-NRGObjectField -Item $List -Key 'MembersStatus' -Default 'NotRead')
        $note   = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $List -Key 'MembersNote' -Default '') -MaxLength 400
        $isDynamic = (ConvertTo-NRGDLBoolean (Get-NRGObjectField -Item $List -Key 'IsDynamic' -Default $false)) -eq $true

        $members  = Get-NRGRuleList -Item $List -Key 'Members'
        $external = Get-NRGRuleList -Item $List -Key 'ExternalMembers'
        $nested   = Get-NRGRuleList -Item $List -Key 'NestedGroups'
        $memberCount   = if ($null -ne $members) { @($members).Count } else { 0 }
        $nestedCount   = if ($null -ne $nested)  { @($nested).Count }  else { 0 }
        $externalList  = @()
        if ($null -ne $external) { $externalList = @($external) }
        $unresolved    = [int](Get-NRGObjectField -Item $List -Key 'UnresolvedMemberCount' -Default 0)

        $common = @{ ControlId = $ControlId; Category = 'Email'; Title = $Def.Title; Instance = $inst; RequiredValue = $Def.Required; Remediation = $Def.Remediation }

        if ($status -notin @('Read', 'Truncated')) {
            $why = if ($note) { $note.TrimEnd('.') } else { "the members of this list were not read ($status)" }
            Add-NRGFinding @common -State 'NotApplicable' -Severity 'Informational' -CurrentValue 'Members not read' `
                -AffectedObjects @() -Detail "${label}: Not assessed: $why."
            return
        }

        $limits = ''
        if ($status -eq 'Truncated') { $limits = ' Only part of the list was read: ' + $(if ($note) { $note.TrimEnd('.') } else { 'it is larger than the member limit' }) + '.' }
        $domainsNote = if ($Evidence.Domains -ne 'Collected') { ' The tenant''s accepted domains could not be read, so only guest accounts could be recognized as outside members.' } else { '' }

        if ($externalList.Count -gt 0) {
            $shown = @($externalList | Select-Object -First 100 | ForEach-Object {
                [pscustomobject]@{ DisplayName = (ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '')); UserPrincipalName = (ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $_ -Key 'UserPrincipalName' -Default '') -MaxLength 320) }
            })
            $more = if ($externalList.Count -gt 100) { " (the first 100 are listed)" } else { '' }
            Add-NRGFinding @common -State 'Gap' -Severity 'Medium' -CurrentValue "$($externalList.Count) outside member(s) of $memberCount read" -AffectedObjects $shown `
                -Detail "${label}: $($externalList.Count) of $memberCount direct member(s) read are outside the organization$more, so everything sent to this list is delivered outside it. Confirm each is intended.$limits$domainsNote"
            return
        }

        $caveats = [System.Collections.Generic.List[string]]::new()
        if ($status -eq 'Truncated') { $caveats.Add("the list is larger than the $memberCount member(s) read (-MemberLimit)") }
        if ($unresolved -gt 0)       { $caveats.Add("$unresolved member(s) could not be classified as inside or outside") }
        if ($nestedCount -gt 0)      { $caveats.Add("$nestedCount nested group(s) were not expanded (only direct members are read)") }
        if ($isDynamic -and $memberCount -eq 0) { $caveats.Add('the calculated membership is empty, and Exchange has not calculated a new or recently changed dynamic list yet') }

        if ($caveats.Count -gt 0) {
            Add-NRGFinding @common -State 'NotApplicable' -Severity 'Informational' -CurrentValue "None found among $memberCount direct member(s) read" -AffectedObjects @() `
                -Detail "${label}: Not assessed in full: no outside member was found among the $memberCount direct member(s) read, but $($caveats -join '; ').$domainsNote"
        } else {
            Add-NRGFinding @common -State 'Satisfied' -Severity 'Informational' -CurrentValue "0 outside of $memberCount direct member(s)" -AffectedObjects @() `
                -Detail "${label}: All $memberCount direct member(s) were read and none is outside the organization.$domainsNote"
        }
    }
}

# Runs every distribution-list control. A check that throws is recorded as an
# exception AND reported as "not assessed" for its own control, so a defect in one
# check can neither stop the others nor leave its control silently missing from the
# worksheet (these controls are not in controls.json, so Invoke-NRGEvaluatorSafe has
# nothing to back-fill from).
function Test-NRGDistributionListControls {
    [CmdletBinding()]
    param()
    $checks = [ordered]@{
        'DL-1.1' = 'Test-NRGDistributionListSenderExposure'
        'DL-2.1' = 'Test-NRGDistributionListOwners'
        'DL-2.2' = 'Test-NRGDistributionListJoinRestriction'
        'DL-3.1' = 'Test-NRGDistributionListExternalMembers'
    }
    foreach ($controlId in $checks.Keys) {
        $fn = $checks[$controlId]
        try {
            & $fn
        } catch {
            $msg = (($_.Exception.Message) -split "`r?`n")[0]
            Write-Warning "Distribution-list check $fn did not finish: $msg"
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                try { Register-NRGException -Source $fn -Message $(if ($msg) { $msg } else { 'unknown error' }) } catch { Write-Verbose "Could not record the exception for ${fn}: $($_.Exception.Message)" }
            }
            Add-NRGDistributionListNotAssessed -ControlId $controlId -Reason "the check did not finish ($msg)"
        }
    }
}

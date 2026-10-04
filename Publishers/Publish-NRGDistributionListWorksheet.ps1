#Requires -Version 7.0
#
# Publish-NRGDistributionListWorksheet.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Turns the DL-* findings into a worksheet an administrator uses to harden
#          distribution lists: for each list, who is in it, its current settings, how
#          each setting compares with a documented recommendation, the Microsoft source,
#          the mapped NIST control, and the PowerShell the administrator would run.
#
# Output (both written through Set-NRGSensitiveFileContent, because they hold tenant
# inventory: member addresses, owners, list settings):
#   <base>-distribution-lists.txt   one section per list
#   <base>-distribution-lists.csv   one row per list per recommendation (plus a scan row)
#
# Data keys consumed: EXO-DistributionLists, the DL-* findings.  Graph scopes / cmdlets: none.
#
# THE COMMANDS ARE TEXT. The worksheet prints, for example,
#     Set-DistributionGroup -Identity 'sales@contoso.com' -RequireSenderAuthenticationEnabled $true
# as a string built by Get-NRGDistributionListFixCommand and shows it only beside a
# shortfall. This file never runs it, never writes it to a .ps1, and never hands it to
# anything that evaluates text. The worksheet is not a script: a .txt and a .csv.
#
# ONE ROW MODEL, TWO RENDERERS. Get-NRGDistributionListWorksheet builds the model once;
# the text and the CSV both render it, so a verdict and the limitation that qualifies it
# read the same in each. NRG.DistributionLists.Tests.ps1 checks that.
#
# TENANT TEXT IS HOSTILE. A display name is free text an end user can set. Control
# characters (a newline would forge a line, an escape would drive a terminal) and
# bidirectional overrides are stripped as text enters the model, and every CSV cell goes
# through ConvertTo-NRGCsvCell, which defuses a leading = + - @ so a spreadsheet does not
# read a name as a formula.

$script:NRGDlScopeStatement = 'Scope: distribution lists only. This scan connected to Exchange Online and read distribution groups, mail-enabled security groups, room lists and dynamic distribution groups. Every other area was NOT assessed: Entra ID, Microsoft Defender, Teams, SharePoint, Intune, Purview, Power Platform, DNS, and Microsoft 365 (Unified) groups, including Teams-connected groups.'
$script:NRGDlModeStatement  = 'Read-only. This tool read the lists and changed nothing: it created, added, removed and modified no user, group or setting. Every command in this worksheet is text for an administrator to review and run; the tool never runs it.'
$script:NRGDlCsvCellMax     = 30000

function ConvertTo-NRGDlText {
    # Tenant-controlled text, made safe to print: control characters, line and paragraph
    # separators and bidirectional overrides become a space.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return '' }
    return (([string]$Value) -replace '[\x00-\x1F\x7F\u0080-\u009F  ‪-‮⁦-⁩]+', ' ').Trim()
}

function Get-NRGDlStatus {
    # The reader's word for a finding. NotApplicable is four different things and the worksheet keeps
    # them apart: reported only (no recommendation to judge it by), not assessed (evidence missing),
    # not assessed because no NRG standard is approved, and does not apply. Which one is read from the
    # label the evaluator put at the START of the Detail (Get-NRGDlKindFromDetail), never searched for
    # in the prose: the Detail contains the list's display name, which a user can set to any text.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Finding)
    if ($null -eq $Finding) { return 'No finding produced' }
    switch ([string](Get-NRGObjectField -Item $Finding -Key 'State' -Default '')) {
        'Satisfied' { return 'Meets' }
        'Gap'       { return 'Shortfall' }
        'Partial'   { return 'Partly meets' }
        'NotApplicable' {
            $kind = Get-NRGDlKindFromDetail -Detail ([string](Get-NRGObjectField -Item $Finding -Key 'Detail' -Default ''))
            if ($kind) { return $kind }
            return 'Not assessed'
        }
        default     { return 'Not assessed' }
    }
}

function Get-NRGDistributionListWorksheet {
    <#
    .SYNOPSIS
        Builds the worksheet model: scan-level scope and limits, the NRG standards status,
        per-recommendation counts, and one entry per list with its facts and one row per
        recommendation (current value, recommended value, status, the finding's own Detail,
        the Microsoft source, the NIST mapping, and the command text).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Raw,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowNull()] [object[]] $Findings,
        [AllowNull()] $Baseline,
        [AllowNull()] $Standards,
        [AllowNull()] [hashtable] $Metadata,
        # Why a read failed (the registered exceptions), already filtered by the caller.
        [AllowNull()] [string[]] $Problems
    )
    Set-StrictMode -Version Latest
    if ($null -eq $Baseline)  { $Baseline  = Get-NRGDistributionListBaseline }
    if ($null -eq $Standards) { $Standards = Get-NRGDistributionListStandards }
    $Findings = @($Findings | Where-Object { $null -ne $_ })
    $recs = @($Baseline.Recommendations)
    # One lookup per (control, list) instead of a scan of every finding per row: with a scan, the cost
    # grows with the SQUARE of the list count (800 lists took 280 seconds to publish).
    $byKey = @{}
    foreach ($f in $Findings) {
        $k = "$([string]$f.ControlId)|$([string]$f.Instance)"
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = $f }
    }

    $tenant = ConvertTo-NRGDlText (Get-NRGObjectField -Item $Metadata -Key 'TenantDomain' -Default (Get-NRGNestedProperty -Object $Raw -Path 'Data.TenantDomain' -Default ''))
    $generated = [string](Get-NRGObjectField -Item $Metadata -Key 'AssessmentTime' -Default (Get-Date).ToString('o'))
    $version = ConvertTo-NRGDlText (Get-NRGObjectField -Item $Metadata -Key 'ToolVersion' -Default 'unknown')

    # The scan-level finding (DL-0.1): what was read, what was not.
    $scanF = @($Findings | Where-Object { $_.ControlId -eq $script:NRGDlScan.Id }) | Select-Object -First 1

    # The NRG standards, as a reader needs them: approved or not, never blank.
    $stdLines = [System.Collections.Generic.List[string]]::new()
    $maxM = Get-NRGObjectField -Item $Standards -Key 'MaxMembers' -Default $null
    $stdLines.Add($(if ($null -ne $maxM) { "DistributionListMaxMembers: approved, $maxM direct members" } else { 'DistributionListMaxMembers: NOT approved (empty), so the member count is reported and not assessed' }))
    $jn = @(Get-NRGDlArray -Item $Standards -Key 'AllowedJoin')
    $stdLines.Add($(if ($jn.Count) { "DistributionListAllowedJoinRestrictions: approved, $($jn -join ', ')" } else { 'DistributionListAllowedJoinRestrictions: NOT approved (empty), so the join setting is reported and not assessed' }))
    $dp = @(Get-NRGDlArray -Item $Standards -Key 'AllowedDepart')
    $stdLines.Add($(if ($dp.Count) { "DistributionListAllowedDepartRestrictions: approved, $($dp -join ', ')" } else { 'DistributionListAllowedDepartRestrictions: NOT approved (empty), so the leave setting is reported and not assessed' }))
    $stdLines.Add($(if ((Get-NRGObjectField -Item $Standards -Key 'ExternalMembersProhibited' -Default $false) -eq $true) { 'DistributionListExternalMembers: approved, Prohibited' } else { 'DistributionListExternalMembers: NOT approved (empty), so external members are listed and not assessed' }))
    foreach ($n in @(Get-NRGDlArray -Item $Standards -Key 'Notes')) { $stdLines.Add("Standards note: $n") }

    $fwCov = Get-NRGObjectField -Item $Baseline -Key 'FrameworkCoverage' -Default $null
    $frameworkLines = @(
        [string](Get-NRGObjectField -Item $fwCov -Key 'NIST_SP_800-53_Rev5' -Default "NIST SP 800-53 Rev 5 ids are this tool's mapping, not NIST text.")
        [string](Get-NRGObjectField -Item $fwCov -Key 'CIS_Microsoft_365_Foundations' -Default 'No CIS item verified; none cited.')
        [string](Get-NRGObjectField -Item $fwCov -Key 'CISA_SCuBA' -Default 'No SCuBA rule verified; none cited.')
    )

    $listsRaw = @(Get-NRGNestedProperty -Object $Raw -Path 'Data.Lists' -Default @())
    $sorted = @($listsRaw | Sort-Object { [string](Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '') }, { Get-NRGDlListKey -List $_ })

    $arr = { param($l, $k) Get-NRGRuleList -Item $l -Key $k }
    $show = { param($a) if ($null -eq $a) { 'not returned' } elseif (@($a).Count -eq 0) { 'none' } else { (@($a) | ForEach-Object { ConvertTo-NRGDlText $_ }) -join '; ' } }
    $boolText = { param($v) if ($null -eq $v) { 'not returned' } else { [string]$v } }

    $outLists = [System.Collections.Generic.List[object]]::new()
    foreach ($l in $sorted) {
        $key  = Get-NRGDlListKey -List $l
        $type = [string](Get-NRGObjectField -Item $l -Key 'ListType' -Default 'Other')
        $owners = & $arr $l 'Owners'
        $members = @(Get-NRGDlArray -Item $l -Key 'Members')
        $external = @(Get-NRGDlArray -Item $l -Key 'ExternalMembers')
        $nested = @(Get-NRGDlArray -Item $l -Key 'NestedGroups')
        $fmtMember = { param($m) $u = ConvertTo-NRGDlText (Get-NRGObjectField -Item $m -Key 'UPN' -Default ''); $d = ConvertTo-NRGDlText (Get-NRGObjectField -Item $m -Key 'DisplayName' -Default '')
            if (-not $u) { "(no address returned) $d".Trim() } elseif ($d -and $d -ne $u) { "$u ($d)" } else { $u } }

        $settings = [ordered]@{
            RequireSenderAuthenticationEnabled     = (& $boolText (Get-NRGObjectField -Item $l -Key 'RequireSenderAuthenticationEnabled' -Default $null))
            AcceptMessagesOnlyFrom                 = (& $show (& $arr $l 'AcceptMessagesOnlyFrom'))
            AcceptMessagesOnlyFromDLMembers        = (& $show (& $arr $l 'AcceptMessagesOnlyFromDLMembers'))
            AcceptMessagesOnlyFromSendersOrMembers = (& $show (& $arr $l 'AcceptMessagesOnlyFromSendersOrMembers'))
            ModerationEnabled                      = (& $boolText (Get-NRGObjectField -Item $l -Key 'ModerationEnabled' -Default $null))
            ModeratedBy                            = (& $show (& $arr $l 'ModeratedBy'))
            MemberJoinRestriction                  = $(if ($type -eq 'Dynamic') { 'not applicable (dynamic list)' } else { ConvertTo-NRGDlText (& $boolText (Get-NRGObjectField -Item $l -Key 'MemberJoinRestriction' -Default $null)) })
            MemberDepartRestriction                = $(if ($type -eq 'Dynamic') { 'not applicable (dynamic list)' } else { ConvertTo-NRGDlText (& $boolText (Get-NRGObjectField -Item $l -Key 'MemberDepartRestriction' -Default $null)) })
            HiddenFromAddressListsEnabled          = (& $boolText (Get-NRGObjectField -Item $l -Key 'HiddenFromAddressListsEnabled' -Default $null))
        }

        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($rec in $recs) {
            $f = $byKey["$($rec.Id)|$key"]
            $status = Get-NRGDlStatus -Finding $f
            # A command is offered only beside a shortfall: it is what an administrator would
            # run to close it, never a suggestion for a setting that already meets or is unjudged.
            $cmd = if ($status -in 'Shortfall', 'Partly meets') { Get-NRGDistributionListFixCommand -Recommendation $rec -List $l -Standards $Standards } else { $null }
            # A directory-synced list is mastered elsewhere: say so beside the command, once, in the note.
            $synced = ((Get-NRGObjectField -Item $l -Key 'IsDirSynced' -Default $null) -eq $true)
            $note = [string]$rec.FixNote
            if ($cmd -and $synced) { $note = ($note + ' This list is directory-synced: make the equivalent change where the list is mastered (on-premises); the cloud command is expected to be refused (not confirmed against a live tenant).').Trim() }
            $nist = @($rec.Nist80053 | ForEach-Object { $t = if (Get-Command Get-NRGNISTControlTitle -ErrorAction SilentlyContinue) { Get-NRGNISTControlTitle -ControlId $_ } else { '' }; if ($t) { "$_ $t" } else { [string]$_ } })
            $rows.Add([pscustomobject][ordered]@{
                Id          = $rec.Id
                Title       = $rec.Title
                Setting     = $rec.Setting
                Current     = $(if ($f) { ConvertTo-NRGDlText $f.CurrentValue } else { '' })
                Recommended = (Format-NRGDlRecommended -Rec $rec)
                Status      = $status
                State       = $(if ($f) { [string]$f.State } else { '' })
                Finding     = $(if ($f) { ConvertTo-NRGDlText $f.Detail } else { 'No finding was produced for this recommendation; treat it as not assessed.' })
                SourceUrl   = $rec.SourceUrl
                Nist        = $nist
                NistNote    = $rec.NistMappingNote
                Command     = $cmd
                FixNote     = $note
            })
        }

        $outLists.Add([pscustomobject][ordered]@{
            Key             = ConvertTo-NRGDlText $key
            Name            = ConvertTo-NRGDlText (Get-NRGObjectField -Item $l -Key 'DisplayName' -Default (Get-NRGObjectField -Item $l -Key 'Name' -Default ''))
            Address         = ConvertTo-NRGDlText (Get-NRGObjectField -Item $l -Key 'PrimarySmtpAddress' -Default '')
            Type            = $type
            DirectorySynced = $(switch (Get-NRGObjectField -Item $l -Key 'IsDirSynced' -Default $null) { $true { 'Yes' } $false { 'No' } default { 'not returned' } })
            RecipientFilter = ConvertTo-NRGDlText (Get-NRGObjectField -Item $l -Key 'RecipientFilter' -Default '')
            Owners          = & $show $owners
            MemberStatus    = [string](Get-NRGObjectField -Item $l -Key 'MemberStatus' -Default 'NotRun')
            MemberError     = ConvertTo-NRGDlText (Get-NRGObjectField -Item $l -Key 'MemberError' -Default '')
            MemberCount     = Get-NRGObjectField -Item $l -Key 'MemberCount' -Default $null
            MembersTruncated = ((Get-NRGObjectField -Item $l -Key 'MembersTruncated' -Default $false) -eq $true)
            Unclassified    = [int](Get-NRGObjectField -Item $l -Key 'UnclassifiedMemberCount' -Default 0)
            Members         = @($members | ForEach-Object { & $fmtMember $_ })
            ExternalMembers = @($external | ForEach-Object { & $fmtMember $_ })
            NestedGroups    = @($nested | ForEach-Object { & $fmtMember $_ })
            Settings        = $settings
            Rows            = @($rows)
        })
    }

    # Counts per recommendation, with every status shown so a row adds up to the list count.
    $statusOrder = @('Meets', 'Shortfall', 'Partly meets', 'Not assessed', 'Not assessed (no approved NRG standard)', 'Reported only', 'Does not apply', 'No finding produced')
    $summary = foreach ($rec in $recs) {
        $rowsFor = @($outLists | ForEach-Object { $_.Rows | Where-Object { $_.Id -eq $rec.Id } })
        $c = [ordered]@{ Id = $rec.Id; Title = $rec.Title; Total = $rowsFor.Count }
        foreach ($s in $statusOrder) { $c[$s] = @($rowsFor | Where-Object { $_.Status -eq $s }).Count }
        [pscustomobject]$c
    }

    return [pscustomobject][ordered]@{
        Tenant         = $tenant
        Generated      = $generated
        ToolVersion    = $version
        Scope          = $script:NRGDlScopeStatement
        Mode           = $script:NRGDlModeStatement
        Frameworks     = $frameworkLines
        Standards      = @($stdLines)
        ScanState      = $(if ($scanF) { [string]$scanF.State } else { '' })
        ScanStatus     = $(if ($scanF) { Get-NRGDlStatus -Finding $scanF } else { 'No finding produced' })
        ScanFinding    = $(if ($scanF) { ConvertTo-NRGDlText $scanF.Detail } else { 'No scan-level finding was produced; treat the whole read as not assessed.' })
        ScanCurrent    = $(if ($scanF) { ConvertTo-NRGDlText $scanF.CurrentValue } else { '' })
        Problems       = @(@($Problems) | Where-Object { $_ } | ForEach-Object { ConvertTo-NRGDlText $_ } | Where-Object { $_ })
        StatusOrder    = $statusOrder
        Summary        = @($summary)
        Lists          = @($outLists)
    }
}

function ConvertTo-NRGDlWorksheetText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Model)
    $sb = [System.Text.StringBuilder]::new()
    $line = { param([string] $t = '') [void]$sb.AppendLine($t) }
    $rule = ('=' * 100)
    & $line 'NRG DISTRIBUTION-LIST WORKSHEET'
    & $line ("Tenant: {0}   Generated: {1}   Tool: {2}" -f $(if ($Model.Tenant) { $Model.Tenant } else { '(not read)' }), $Model.Generated, $Model.ToolVersion)
    & $line 'INTERNAL USE: this file holds tenant inventory (list members, owners and settings). Keep it with the engagement record, not in a shared folder.'
    & $line
    & $line 'SCOPE AND LIMITS'
    & $line "  $($Model.Scope)"
    & $line "  $($Model.Mode)"
    & $line "  Scan result ($($Model.ScanStatus)): $($Model.ScanFinding)"
    if ($Model.ScanCurrent) { & $line "  $($Model.ScanCurrent)" }
    if (@($Model.Problems).Count) {
        & $line
        & $line 'COLLECTION PROBLEMS (why a read failed; what it covered is reported above as not assessed)'
        foreach ($p in $Model.Problems) { & $line "  - $p" }
    }
    & $line
    & $line 'FRAMEWORKS'
    foreach ($f in $Model.Frameworks) { & $line "  - $f" }
    & $line
    & $line 'NRG STANDARDS (a judgment NRG has not approved is reported, never assessed; approve in Config/nrg-standards.json)'
    foreach ($s in $Model.Standards) { & $line "  - $s" }
    & $line
    & $line ("SUMMARY: {0} list(s). Each row adds up to the list count." -f @($Model.Lists).Count)
    foreach ($r in $Model.Summary) {
        $cells = @($Model.StatusOrder | Where-Object { $r.$_ -gt 0 } | ForEach-Object { "$_ $($r.$_)" })
        & $line ("  {0}  {1}: {2}" -f $r.Id, $r.Title, $(if ($cells.Count) { $cells -join ', ' } else { 'no list' }))
    }
    & $line
    & $line 'HOW TO READ A LIST: Members and Current settings are what was read. Each recommendation shows the current value, the recommended value and where that value comes from, the status, what was read and what was not, the Microsoft source, the mapped NIST control (the tool''s mapping, not NIST text), and, only beside a shortfall, the command an administrator would run. Review every command before running it.'
    & $line
    $i = 0; $n = @($Model.Lists).Count
    foreach ($l in $Model.Lists) {
        $i++
        & $line $rule
        & $line ("LIST {0} of {1}: {2}  <{3}>" -f $i, $n, $l.Name, $(if ($l.Address) { $l.Address } else { 'no address read' }))
        & $line ("  Type: {0}   Directory-synced: {1}   Owners: {2}" -f $l.Type, $l.DirectorySynced, $l.Owners)
        if ($l.RecipientFilter) { & $line "  Membership rule (dynamic list): $($l.RecipientFilter)" }
        $count = if ($null -eq $l.MemberCount) { 'not read' } elseif ($l.MembersTruncated) { "at least $($l.MemberCount)" } else { "$($l.MemberCount)" }
        & $line ("  Members read: {0} ({1})   External: {2}   Nested groups: {3}   Unclassified: {4}" -f $count, $l.MemberStatus, @($l.ExternalMembers).Count, @($l.NestedGroups).Count, $l.Unclassified)
        if ($l.MemberError) { & $line "  Member read error: $($l.MemberError)" }
        & $line '  Members:'
        if (@($l.Members).Count -eq 0) { & $line $(if ($l.MemberStatus -in 'Collected', 'Truncated') { '    (none)' } else { '    (not read)' }) }
        foreach ($m in $l.Members) { & $line "    $m" }
        if (@($l.ExternalMembers).Count) { & $line '  External members (outside the tenant''s accepted domains):'; foreach ($m in $l.ExternalMembers) { & $line "    $m" } }
        if (@($l.NestedGroups).Count)    { & $line '  Nested groups (their members are NOT expanded here):';       foreach ($m in $l.NestedGroups)    { & $line "    $m" } }
        & $line '  Current settings:'
        foreach ($k in $l.Settings.Keys) { & $line ("    {0,-40} {1}" -f $k, $l.Settings[$k]) }
        & $line '  Comparison with recommendations:'
        foreach ($r in $l.Rows) {
            & $line ("    [{0}] {1}  {2}" -f $r.Status.ToUpperInvariant(), $r.Id, $r.Title)
            & $line "        Setting:     $($r.Setting)"
            & $line "        Current:     $(if ($r.Current) { $r.Current } else { 'not read' })"
            & $line "        Recommended: $($r.Recommended)"
            & $line "        Finding:     $($r.Finding)"
            if ($r.Command) {
                & $line '        Command for an administrator (TEXT ONLY, this tool never runs it):'
                & $line "            $($r.Command)"
                if ($r.FixNote) { & $line "            Note: $($r.FixNote)" }
            }
        }
    }
    & $line $rule
    & $line 'END OF WORKSHEET'
    return $sb.ToString()
}

function ConvertTo-NRGDlWorksheetCsv {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Model)
    $cell = { param($v) ConvertTo-NRGCsvCell $v }
    $cap = {
        param([object[]] $items)
        $t = (@($items) -join '; ')
        if ($t.Length -gt $script:NRGDlCsvCellMax) { $t.Substring(0, $script:NRGDlCsvCellMax) + " ... (cut at $($script:NRGDlCsvCellMax) characters; the .txt worksheet has the full list)" } else { $t }
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    $row = {
        param($l, $r)
        [pscustomobject][ordered]@{
            List             = & $cell $l.Name
            ListAddress      = & $cell $l.Address
            ListType         = & $cell $l.Type
            DirectorySynced  = & $cell $l.DirectorySynced
            Owners           = & $cell $l.Owners
            MemberCount      = & $cell $(if ($null -eq $l.MemberCount) { 'not read' } elseif ($l.MembersTruncated) { "at least $($l.MemberCount)" } else { $l.MemberCount })
            MembersRead      = & $cell $l.MemberStatus
            Members          = & $cell (& $cap $l.Members)
            ExternalMembers  = & $cell (& $cap $l.ExternalMembers)
            NestedGroups     = & $cell (& $cap $l.NestedGroups)
            Id               = & $cell $r.Id
            Recommendation   = & $cell $r.Title
            Setting          = & $cell $r.Setting
            Current          = & $cell $(if ($r.Current) { $r.Current } else { 'not read' })
            Recommended      = & $cell $r.Recommended
            Status           = & $cell $r.Status
            Finding          = & $cell $r.Finding
            Source           = & $cell $r.SourceUrl
            NIST80053ToolMapping = & $cell $(if (@($r.Nist).Count) { (@($r.Nist) -join '; ') } else { 'no framework item verified' })
            CommandTextOnly  = & $cell $r.Command
            Note             = & $cell $r.FixNote
            Scope            = & $cell 'Distribution lists only; every other Microsoft 365 area was not assessed. Read-only: the command text is never run by this tool.'
        }
    }
    # The scan row first: what was read and what was not travels with the data.
    $scan = [pscustomobject]@{ Name = '(scan)'; Address = ''; Type = ''; DirectorySynced = ''; Owners = ''; MemberCount = ''; MembersTruncated = $false; MemberStatus = ''; Members = @(); ExternalMembers = @(); NestedGroups = @() }
    $scanRow = [pscustomobject]@{ Id = $script:NRGDlScan.Id; Title = $script:NRGDlScan.Title; Setting = $script:NRGDlScan.Setting; Current = $Model.ScanCurrent
        Recommended = "$($script:NRGDlScan.Recommended) (no recommendation)"; Status = $Model.ScanStatus; Finding = $Model.ScanFinding
        SourceUrl = $script:NRGDlScan.SourceUrl; Nist = @(); Command = $null
        FixNote = $(if (@($Model.Problems).Count) { 'Collection problems: ' + ((@($Model.Problems) | Select-Object -First 5) -join ' | ') + $(if (@($Model.Problems).Count -gt 5) { " | ... and $(@($Model.Problems).Count - 5) more in the text worksheet" } else { '' }) } else { '' }) }
    $rows.Add((& $row $scan $scanRow))
    foreach ($l in $Model.Lists) { foreach ($r in $l.Rows) { $rows.Add((& $row $l $r)) } }
    return ((@($rows) | ConvertTo-Csv -NoTypeInformation) -join "`r`n") + "`r`n"
}

function Publish-NRGDistributionListWorksheet {
    <#
    .SYNOPSIS
        Writes <base>-distribution-lists.txt and .csv through the restricted-file writer and
        returns their paths. Read-only: the commands inside are text and are never run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $OutputDirectory,
        [Parameter(Mandatory)] [string] $BaseName,
        [AllowNull()] [hashtable] $Metadata,
        [AllowNull()] $Raw,
        [AllowNull()] [object[]] $Findings,
        [AllowNull()] $Baseline,
        [AllowNull()] $Standards,
        [AllowNull()] [string[]] $Problems
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # The base name becomes part of a file name: nothing but letters, digits and hyphens.
    $stem = ($BaseName -replace '[^a-zA-Z0-9-]', '')
    if (-not $stem) { $stem = 'tenant' }
    if ($OutputDirectory -match '\.\.[/\\]') { throw "OutputDirectory '$OutputDirectory' contains a traversal sequence." }
    # A relative path is relative to the PowerShell location. [System.IO.Directory] resolves against the
    # PROCESS working directory, which Set-Location does not change, so a relative path would land
    # somewhere the operator is not looking.
    $OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    $null = [System.IO.Directory]::CreateDirectory($OutputDirectory)

    if ($null -eq $Raw)      { $Raw = Get-NRGRawData -Key 'EXO-DistributionLists' }
    if ($null -eq $Findings) { $Findings = @(Get-NRGFindings | Where-Object { [string]$_.ControlId -like 'DL-*' }) }
    if ($null -eq $Problems) {
        $Problems = @(Get-NRGExceptions | Where-Object { [string]$_.Source -match '^(EXO-DL-|EXO-DistributionLists|DL-Evaluator|Connect-EXO)' } |
            ForEach-Object { '{0}: {1}' -f $_.Source, $_.Message })
    }
    $model = Get-NRGDistributionListWorksheet -Raw $Raw -Findings $Findings -Baseline $Baseline -Standards $Standards -Metadata $Metadata -Problems $Problems

    $txtPath = Join-Path $OutputDirectory "$stem-distribution-lists.txt"
    $csvPath = Join-Path $OutputDirectory "$stem-distribution-lists.csv"
    # The restricted-file writer creates the file, restricts its ACL (0600 off Windows),
    # and only then writes tenant data into it.
    Set-NRGSensitiveFileContent -Path $txtPath -Content (ConvertTo-NRGDlWorksheetText -Model $model)
    # A byte-order mark so a spreadsheet opens non-ASCII names correctly.
    Set-NRGSensitiveFileContent -Path $csvPath -Content (ConvertTo-NRGDlWorksheetCsv -Model $model) -Encoding ([System.Text.UTF8Encoding]::new($true))

    return [pscustomobject]@{
        TextPath  = $txtPath
        CsvPath   = $csvPath
        ListCount = @($model.Lists).Count
        RowCount  = 1 + (@($model.Lists | ForEach-Object { @($_.Rows).Count } | Measure-Object -Sum).Sum)
        Model     = $model
    }
}

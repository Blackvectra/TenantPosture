#Requires -Version 7.0
#
# Get-NRGDistributionListWorksheet.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Join the distribution-list inventory (EXO-DistributionLists), the DL-*
#          findings and the recommendation catalog into ONE worksheet model, so the
#          text file and the CSV are rendered from the same strings and cannot
#          disagree about a verdict or a limitation.
#
# Sets:     nothing
# Consumes: EXO-DistributionLists, the DL-* findings (Get-NRGFindings),
#           Config/distribution-list-baseline.json, Config/nrg-standards.json.
#           No Graph, no Exchange, no network: this is a view.
#
# A VIEW, LIKE Get-NRGAssessmentScope: it emits no finding and moves no score.
#
# COMMANDS ARE TEXT. The worksheet carries the exact PowerShell an administrator
# would run to apply a recommendation, as STRINGS. Nothing here, in the publisher, or
# anywhere the module loads runs them: NRG.DistributionLists.Tests.ps1 parses these
# files and fails on any call to a cmdlet that is not a read.
#
# TENANT TEXT NEVER BECOMES CODE. A list's name can be set by its owner, so a name
# is never interpolated into a command. The command uses the primary SMTP address,
# in a single-quoted literal with embedded quotes doubled, and PowerShell treats the
# typographic single quotes (U+2018 .. U+201B) as quotes too, so an identity holding
# one, or a line break, is refused rather than quoted: the worksheet says to use the
# portal for that object.

# One value as a single-quoted PowerShell literal, or $null when it cannot be quoted safely.
function ConvertTo-NRGDlPsLiteral {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [string] $Value)
    $v = [string]$Value
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }
    # PowerShell reads U+2018 .. U+201B as single-quote characters even INSIDE a single-quoted string, so a value holding one
    # could end its literal early. Those, the Unicode line separators and control characters are refused. The code points are
    # built at run time on purpose: typing the characters in this file would make the parser read them as quotes and change
    # what the pattern means (NRG.DistributionLists.Tests.ps1 scans the source for any such character).
    foreach ($cp in 0x2018, 0x2019, 0x201A, 0x201B, 0x0085, 0x2028, 0x2029) { if ($v.Contains([string][char]$cp)) { return $null } }
    if ($v -match '[\r\n\0]') { return $null }
    # Invisible and direction-changing characters (Unicode format characters: bidirectional overrides and isolates, zero-width
    # characters, the byte order mark, the soft hyphen, tag characters) can make a command LOOK different from what runs
    # ("Trojan Source"). Every command here is reviewed by eye before it is run, so a value holding one is refused.
    if ($v -match '[\p{Cf}\p{Cc}\p{Zl}\p{Zp}]' -or $v -match '\uDB40[\uDC00-\uDC7F]') { return $null }
    return "'" + ($v -replace "'", "''") + "'"
}

# Fill a catalog command template. {List}/{Member}/{Value}/{Policy} become quoted literals;
# {Senders} is a LIST of addresses, each its own quoted literal, joined with commas (an
# allowed-senders list is multi-valued); {Parameter} is one of two fixed words. Returns $null
# when any value cannot be quoted safely, when {Senders} is empty, or when the template is
# empty, so the caller prints the portal note instead. A command with one sender dropped
# would be WORSE than none: an allow list that leaves a member out rejects that member.
#
# ONE PASS, on purpose. Substituting the placeholders one after another re-scans text that
# was already inserted, so a tenant-controlled address containing the literal text {Member}
# would be substituted a second time, and that second literal's quotes would end the first
# literal early: a quote breakout from tenant data. A single regex pass never rescans what
# it inserted.
function Format-NRGDlCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [string] $Template,
        [hashtable] $Values = @{}
    )
    if ([string]::IsNullOrWhiteSpace($Template)) { return $null }
    $pattern = '\{(List|Member|Value|Policy|Parameter|Senders)\}'
    $fill = @{}
    foreach ($k in @([regex]::Matches($Template, $pattern) | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)) {
        if ($k -eq 'Senders') {
            $items = @(@($(if ($Values.ContainsKey($k)) { $Values[$k] } else { @() })) | ForEach-Object { [string]$_ })
            if ($items.Count -eq 0) { return $null }
            # An explicit loop, not `$x = foreach { ... return $null ... }`: a return inside a foreach whose output is captured emits the
            # literals gathered so far, which would hand the caller a command with senders missing.
            $lits = [System.Collections.Generic.List[string]]::new()
            foreach ($it in $items) {
                $q = ConvertTo-NRGDlPsLiteral -Value $it
                if ($null -eq $q) { return $null }
                $lits.Add($q)
            }
            $fill[$k] = ($lits -join ',')
            continue
        }
        $raw = [string]$(if ($Values.ContainsKey($k)) { $Values[$k] } else { '' })
        if ($k -eq 'Parameter') {
            if ($raw -notin @('AllowedSenders', 'AllowedSenderDomains')) { return $null }
            $fill[$k] = $raw
        } else {
            $lit = ConvertTo-NRGDlPsLiteral -Value $raw
            if ($null -eq $lit) { return $null }
            $fill[$k] = $lit
        }
    }
    return [regex]::Replace($Template, $pattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $fill[$m.Groups[1].Value] })
}

# The limitations every output prints, in this order, in these words.
function Get-NRGDlLimitations {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [int] $MaxMembersPerList = 500, [string[]] $SectionsNotCollected = @(),
        # A truncated inventory and an empty one are limitations in their own right: every section can read "Collected" and the
        # worksheet still not be the whole tenant, which a reader would otherwise take it to be.
        [bool] $ListsTruncated = $false, [int] $ListsSeen = 0, [int] $MaxLists = 0, [bool] $NoListsReturned = $false
    )
    $l = @(
        'Read-only: this scan lists members and settings. It never creates, adds, removes or changes a user, group, rule or setting.',
        'Only Exchange Online was connected. Every other area was not assessed: Entra ID identity, Conditional Access, Defender for Office 365 beyond the anti-spam allow lists read here, Purview, Teams, SharePoint, Intune, Power Platform and DNS.',
        'Scope: distribution lists, mail-enabled security groups and dynamic distribution lists. Microsoft 365 Groups and Teams-connected lists were not read.',
        "Members: direct members only, at most $MaxMembersPerList per list. A nested group is listed, not expanded. A dynamic list's members are the calculated list Microsoft stores on the group (refreshed about every 24 hours), or a preview of its filter when that cannot be read, so they can differ from who receives mail sent now.",
        'Outlook Safe Senders live in each mailbox and were not read, so that bypass is unmeasured, not absent.',
        'DMARC reject protects only mail that claims your own domain in the From address. It does not cover a lookalike domain or a display-name impersonation, and this scan cannot detect either; a clean worksheet does not mean a list is safe from them.',
        "A recommendation marked Basis 'NRG' is judged only against a value approved in Config/nrg-standards.json. An unapproved standard is reported as not assessed, never as met.",
        "NIST SP 800-53 Rev 5 identifiers are NRG's own mapping, not a quotation of NIST. No CISA ScubaGear or CIS item written for distribution lists was found, so none is cited: no framework item verified."
    )
    if ($ListsTruncated) {
        $l += "Lists: only the first $MaxLists of $ListsSeen lists were read (-MaxLists $MaxLists). The other $($ListsSeen - $MaxLists) are NOT in this worksheet, so their members, settings and reach are not assessed. This is not a clean result for them; raise -MaxLists and run again."
    }
    if ($NoListsReturned) {
        $l += 'Lists: Exchange returned no distribution list, so none was assessed. If the signed-in account is scoped to part of the directory, lists outside that scope would not be returned.'
    }
    $bad = @($SectionsNotCollected | Where-Object { $_ })
    if ($bad.Count) { $l += ('Not collected in this run: ' + ($bad -join ', ') + '. Anything that depends on them reads "Not assessed", not clean.') }
    return $l
}

function Get-NRGDlVerdictWord {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [string] $State)
    switch ($State) {
        'Satisfied'     { 'Met' }
        'Gap'           { 'Gap' }
        'Partial'       { 'Partial' }
        'NotApplicable' { 'Not assessed' }
        'Error'         { 'Error' }
        default         { '' }
    }
}

function Get-NRGDistributionListWorksheet {
    <#
    .SYNOPSIS
        Builds the worksheet model: Header, Limitations, Summary, Tenant (the bypasses
        that apply to every list) and Lists (members, settings, who can reach each one
        today, the recommendation, its source and mapped control, and the command text).
    .PARAMETER Raw
        The EXO-DistributionLists envelope. Read from module state when omitted.
    .PARAMETER Findings
        The findings to read DL-* verdicts from. Read from module state when omitted.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] $Raw,
        [AllowNull()] [object[]] $Findings,
        [AllowNull()] $Metadata,
        [AllowNull()] $Baseline,
        [AllowNull()] $Standards
    )

    if ($null -eq $Raw) { $Raw = Get-NRGRawData -Key 'EXO-DistributionLists' }
    if ($null -eq $Findings) { $Findings = @(Get-NRGFindings) }
    if ($null -eq $Baseline) { $Baseline = Get-NRGDistributionListBaseline }
    if ($null -eq $Standards) { $Standards = Get-NRGDistributionListStandards }
    $Findings = @($Findings | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'ControlId' -Default '') -like 'DL-*' })

    $data   = Get-NRGObjectField -Item $Raw -Key 'Data' -Default $null
    $ok     = [bool](Get-NRGObjectField -Item $Raw -Key 'Success' -Default $false)
    $limits = Get-NRGObjectField -Item $data -Key 'Limits' -Default $null
    $stats  = Get-NRGObjectField -Item $data -Key 'Stats' -Default $null
    $ss     = Get-NRGObjectField -Item $data -Key 'SectionStatus' -Default $null
    $maxM   = [int](Get-NRGObjectField -Item $limits -Key 'MaxMembersPerList' -Default 500)
    $listsTrunc = [bool](Get-NRGObjectField -Item $limits -Key 'ListsTruncated' -Default $false)
    $listsSeen  = [int](Get-NRGObjectField -Item $limits -Key 'ListsSeen' -Default 0)
    $maxL       = [int](Get-NRGObjectField -Item $limits -Key 'MaxLists' -Default 0)
    $notCollected = @()
    if (-not $ok) { $notCollected = @('the distribution-list inventory') }
    else { foreach ($k in 'Lists', 'DynamicLists', 'Members', 'AcceptedDomains', 'TransportRules', 'ConnectionFilter', 'AntiSpam') { if ([string](Get-NRGObjectField -Item $ss -Key $k -Default 'NotRun') -ne 'Collected') { $notCollected += $k } } }

    # An inventory that came back empty from a read that completed (a failed read is in $notCollected, not here).
    $noLists = $ok -and ([string](Get-NRGObjectField -Item $ss -Key 'Lists' -Default 'NotRun') -eq 'Collected') -and ([string](Get-NRGObjectField -Item $ss -Key 'DynamicLists' -Default 'NotRun') -eq 'Collected') -and (@(Get-NRGObjectField -Item $data -Key 'Lists' -Default @()).Count -eq 0)

    # Findings indexed by control and instance. A tenant-level finding (no instance) is the fallback
    # for a per-list row, which is how "no approved standard" reads on every list.
    $byInst = @{}; $tenantF = @{}
    foreach ($f in $Findings) {
        $cid = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
        $inst = [string](Get-NRGObjectField -Item $f -Key 'Instance' -Default '')
        if ($inst) { $byInst["$cid|$($inst.ToLowerInvariant())"] = $f } elseif (-not $tenantF.ContainsKey($cid)) { $tenantF[$cid] = $f }
    }
    $rec = $Baseline.ById
    $fwNote = [string]$Baseline.FrameworkNote

    $mkRow = {
        param($cid, $item, $current, $verdict, $detail, $list, $commands)
        $r = $null; if ($cid -and $rec.ContainsKey($cid)) { $r = $rec[$cid] }
        [ordered]@{
            RowType      = 'Setting'
            ListName     = $(if ($list) { [string]$list.Name } else { '' })
            ListAddress  = $(if ($list) { [string]$list.Address } else { '' })
            ListType     = $(if ($list) { [string]$list.Kind } else { '' })
            ControlId    = [string]$cid
            Item         = [string]$item
            Current      = [string]$current
            Recommended  = $(if ($r) { [string]$r.Recommended } else { '' })
            Verdict      = [string]$verdict
            Basis        = $(if ($r) { [string]$r.Basis } else { '' })
            Detail       = [string]$detail
            Why          = $(if ($r) { [string]$r.Why } else { '' })
            Source       = $(if ($r) { [string]$r.SourceUrl } else { '' })
            AlsoSee      = $(if ($r) { @($r.AlsoSee) } else { @() })
            Nist80053    = $(if ($r) { @($r.Nist80053) } else { @() })
            FrameworkItem = $fwNote
            Commands     = @($commands | Where-Object { $_ })
        }
    }

    # ── Tenant-wide bypass rows ───────────────────────────────────────────────────
    $rules = @(Get-NRGObjectField -Item (Get-NRGObjectField -Item $data -Key 'BypassInputs' -Default $null) -Key 'TransportRules' -Default @())
    $tenantRows = [System.Collections.Generic.List[object]]::new()
    foreach ($cid in @('DL-3.1', 'DL-3.2', 'DL-3.3', 'DL-3.4', 'DL-3.5', 'DL-4.1')) {
        if (-not $rec.ContainsKey($cid)) { continue }
        $f = if ($tenantF.ContainsKey($cid)) { $tenantF[$cid] } else { $null }
        $verdict = if ($f) { Get-NRGDlVerdictWord -State ([string](Get-NRGObjectField -Item $f -Key 'State' -Default '')) } else { 'Not assessed' }
        $detail  = if ($f) { [string](Get-NRGObjectField -Item $f -Key 'Detail' -Default '') } else { 'Not assessed: the distribution-list scan produced no verdict for this item.' }
        $cur     = if ($f) { [string](Get-NRGObjectField -Item $f -Key 'CurrentValue' -Default '') } else { '' }
        $cmds = @()
        $objs = if ($f) { @(Get-NRGObjectField -Item $f -Key 'AffectedObjects' -Default @()) } else { @() }
        $r = $rec[$cid]
        if ($verdict -in @('Gap', 'Partial')) {
            foreach ($t in @($r.AdminCommands.Values)) { if ($t) { $cmds += $t } }   # the read-only look at the setting, as Microsoft prints it
            foreach ($o in $objs) {
                # An IP Allow List entry that is within a /24 is what Microsoft recommends staying within: no command removes it.
                if ($cid -eq 'DL-3.2' -and [string](Get-NRGObjectField -Item $o -Key 'Class' -Default '') -notin @('WiderThan24', 'Unparsed')) { continue }
                $nm = [string](Get-NRGObjectField -Item $o -Key 'Name' -Default '')
                $src = [string](Get-NRGObjectField -Item $o -Key 'Source' -Default '')
                $c = $null
                if ($r.RuleCommand -and $src -eq 'Mail flow rule' -and $cid -eq 'DL-3.1') { $c = Format-NRGDlCommand -Template $r.RuleCommand -Values @{ Value = $nm } }
                elseif ($r.RuleCommand -and $src -eq 'IP Allow List' -and $cid -eq 'DL-3.2') { $c = Format-NRGDlCommand -Template $r.RuleCommand -Values @{ Value = $nm } }
                elseif ($r.RuleCommand -and $src -eq 'Anti-spam policy' -and $cid -eq 'DL-3.3') {
                    $pn = [string](Get-NRGObjectField -Item $o -Key 'Policy' -Default '')
                    $par = if ([string](Get-NRGObjectField -Item $o -Key 'Class' -Default '') -eq 'allowed domain') { 'AllowedSenderDomains' } else { 'AllowedSenders' }
                    $c = Format-NRGDlCommand -Template $r.RuleCommand -Values @{ Policy = $pn; Parameter = $par; Value = $nm }
                }
                if ($c) { $cmds += $c } elseif ($r.RuleCommand -and $src) { $cmds += "# '$src' entry has a name that cannot be quoted safely here; change it in the portal." }
            }
        }
        $row = & $mkRow $cid $r.Title $cur $verdict $detail $null @($cmds | Select-Object -Unique)
        $row.RowType = 'Tenant bypass'
        $row.Objects = @($objs | ForEach-Object { "$([string](Get-NRGObjectField -Item $_ -Key 'Source' -Default '')): $([string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')) ($([string](Get-NRGObjectField -Item $_ -Key 'Detail' -Default '')))" })
        $tenantRows.Add($row)
    }
    $bypassWord = { param($cid) $x = $tenantRows | Where-Object { $_.ControlId -eq $cid } | Select-Object -First 1; if ($x) { [string]$x.Verdict } else { 'Not assessed' } }

    # ── Lists ─────────────────────────────────────────────────────────────────────
    $listRows = [System.Collections.Generic.List[object]]::new()
    $joinStd = $Standards.JoinRestriction
    # The rule classification does not depend on the list, so it is done once, not once per list.
    $bypassRules = @($rules | ForEach-Object { [pscustomobject]@{ Rule = $_; Class = (Get-NRGDlTransportRuleClass -Rule $_) } } | Where-Object { $_.Class.IsBypass -and $_.Class.InForce })
    foreach ($l in @(Get-NRGObjectField -Item $data -Key 'Lists' -Default @())) {
        $addr = [string](Get-NRGObjectField -Item $l -Key 'PrimarySmtpAddress' -Default '')
        $name = [string](Get-NRGObjectField -Item $l -Key 'Name' -Default '')
        $kind = [string](Get-NRGObjectField -Item $l -Key 'Kind' -Default '')
        $inst = if ($addr) { $addr } else { $name }
        $ident = [ordered]@{ Name = $name; Address = $addr; Kind = $kind }
        $fnd = { param($cid) $k = "$cid|$($inst.ToLowerInvariant())"; if ($byInst.ContainsKey($k)) { $byInst[$k] } elseif ($tenantF.ContainsKey($cid)) { $tenantF[$cid] } else { $null } }
        $verdictOf = { param($f, $fallback) if ($f) { Get-NRGDlVerdictWord -State ([string](Get-NRGObjectField -Item $f -Key 'State' -Default '')) } else { $fallback } }
        $detailOf  = { param($f, $fallback) if ($f) { [string](Get-NRGObjectField -Item $f -Key 'Detail' -Default '') } else { $fallback } }
        $cmdFor = {
            param($cid, $vals)
            $r = $rec[$cid]; $t = ''
            if ($r.AdminCommands.Contains($(if ($kind -eq 'Dynamic') { 'Dynamic' } else { 'Distribution' }))) { $t = [string]$r.AdminCommands[$(if ($kind -eq 'Dynamic') { 'Dynamic' } else { 'Distribution' })] }
            $c = Format-NRGDlCommand -Template $t -Values $vals
            if ($c) { $c } elseif ($t) { "# '$name': its address cannot be quoted safely here; change this setting in the portal." } else { $null }
        }

        $auth = Get-NRGObjectField -Item $l -Key 'RequireSenderAuthenticationEnabled' -Default $null
        $allowedKnown = [bool](Get-NRGObjectField -Item $l -Key 'AllowedSendersKnown' -Default $false)
        $allowedN = @(Get-NRGObjectField -Item $l -Key 'AllowedSenders' -Default @()).Count
        $ownKnown = [bool](Get-NRGObjectField -Item $l -Key 'OwnersKnown' -Default $false)
        $ownN = [int](Get-NRGObjectField -Item $l -Key 'OwnerCount' -Default 0)
        $mst = [string](Get-NRGObjectField -Item $l -Key 'MemberStatus' -Default 'NotRun')
        $cnt = Get-NRGObjectField -Item $l -Key 'MemberCount' -Default $null
        $trunc = [bool](Get-NRGObjectField -Item $l -Key 'MembersTruncated' -Default $false)
        $mod = Get-NRGObjectField -Item $l -Key 'ModerationEnabled' -Default $null
        $join = [string](Get-NRGObjectField -Item $l -Key 'MemberJoinRestriction' -Default '')
        $depart = [string](Get-NRGObjectField -Item $l -Key 'MemberDepartRestriction' -Default '')
        $hidden = Get-NRGObjectField -Item $l -Key 'HiddenFromAddressListsEnabled' -Default $null
        $extN = [int](Get-NRGObjectField -Item $l -Key 'ExternalMemberCount' -Default 0)
        $members = @(Get-NRGObjectField -Item $l -Key 'Members' -Default @())
        # Microsoft: a group created by directory synchronization must be managed in the on-premises environment, and Exchange Online
        # refuses these changes ("the object is being synchronized from your on-premises organization"). $null = not returned.
        $dirSynced = ((Get-NRGObjectField -Item $l -Key 'IsDirSynced' -Default $null) -eq $true)
        $syncNote = ''
        if ($dirSynced) { $syncNote = 'Synchronized from on-premises Active Directory: Microsoft says it must be managed there, and Exchange Online refuses these changes. No Exchange Online command is printed for this list; make the change on-premises (the same cmdlets in the on-premises Exchange Management Shell).' }

        $rows = [System.Collections.Generic.List[object]]::new()

        # 1. Who can send
        $f11 = & $fnd 'DL-1.1'; $v11 = & $verdictOf $f11 'Not assessed'
        $cur11 = if ($null -eq $auth) { 'Not returned' } else { "RequireSenderAuthenticationEnabled = $auth" }
        # Requiring authenticated senders would stop a list's external members sending to it, so no such command is printed for a list
        # that holds one: the allowed-senders proposal (DL-1.2) is the option that keeps them. The finding's Detail says why.
        $c11 = @(); if ($v11 -in @('Gap', 'Partial') -and -not ($mst -eq 'Collected' -and $extN -gt 0)) { $c11 += (& $cmdFor 'DL-1.1' @{ List = $addr }) }
        $rows.Add((& $mkRow 'DL-1.1' 'Who can send to the list' $cur11 $v11 (& $detailOf $f11 'Not assessed.') $ident $c11))

        # 2. Allowed senders: context, plus a PROPOSED allow list built from the members read now, offered only where it is safe to offer.
        # It is a SNAPSHOT and it is TEXT: nothing here sets anything. An allow list built from part of the membership, over an existing
        # list, or with one address dropped would reject people who should be able to send, so each of those withholds the command.
        $cur12 = if (-not $allowedKnown) { 'Not returned' } elseif ($allowedN -eq 0) { 'None specified' } else { "$allowedN specified sender(s)" }
        $proposalCmd = $null
        $addrs = @()
        if ($dirSynced) {
            $proposal = 'No allow list command is printed: this list is synchronized from on-premises Active Directory, where it must be managed.'
        } elseif ($kind -eq 'Dynamic') {
            $proposal = 'No allow list is proposed for a dynamic list: its members are calculated from a filter, so a snapshot of them would not follow who is a member later.'
        } elseif ($null -eq $auth) {
            $proposal = 'No allow list is proposed: Exchange did not return RequireSenderAuthenticationEnabled for this list.'
        } elseif ($auth -eq $true) {
            $proposal = "No allow list is needed to keep outside mail out: the list accepts mail only from authenticated senders inside the organization$(if ($mst -eq 'Collected' -and $extN -gt 0) { "; its $extN external member(s) cannot send to it while that is True (Microsoft)" })."
        } elseif (-not $allowedKnown) {
            $proposal = 'No allow list is proposed: Exchange did not return the allowed-senders setting, so a command that sets it could overwrite a list that already exists.'
        } elseif ($allowedN -gt 0) {
            $proposal = "No allow list is proposed: this list already has $allowedN allowed sender(s) and this scan does not propose replacing them."
        } elseif ($mst -ne 'Collected') {
            $proposal = 'No allow list is proposed: the members were not read, and an allow list built from part of the membership would reject the members it left out.'
        } elseif ($trunc) {
            $proposal = "No allow list is proposed: only the first $cnt members were read and the list has more, and an allow list built from part of the membership would reject the rest. Raise -MaxMembersPerList to cover the whole list."
        } elseif ($members.Count -eq 0) {
            $proposal = 'No allow list is proposed: the list has no members, so a snapshot would be empty, and an empty allowed-senders list restricts nothing.'
        } else {
            $seenAddr = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $blank = 0
            foreach ($m in $members) {
                $a = [string](Get-NRGObjectField -Item $m -Key 'Address' -Default '')
                if ([string]::IsNullOrWhiteSpace($a)) { $blank++ } elseif ($seenAddr.Add($a)) { $addrs += $a }
            }
            if ($blank -gt 0) {
                $proposal = "No allow list is proposed: $blank member(s) returned no primary address, so the list would be incomplete and would reject them."
            } else {
                $built = Format-NRGDlCommand -Template ([string]$rec['DL-1.2'].AdminCommands['Distribution']) -Values @{ List = $addr; Senders = $addrs }
                if (-not $built) {
                    $proposal = "No allow list is proposed: this list's address or a member's address cannot be quoted safely in a command (a quote-like or line-break character), and a command with a member left out would reject that member. Set the allowed senders in the portal."
                } elseif ($built.Length -gt 30000) {
                    $proposal = "No allow list is proposed: the command for $($addrs.Count) members would be longer than one spreadsheet cell holds (about 32,000 characters). Split the list or set the allowed senders in the portal."
                } else {
                    $proposalCmd = $built
                    $nestedN = [int](Get-NRGObjectField -Item $l -Key 'NestedGroupCount' -Default 0)
                    $proposal = "Proposed allow list: the $($addrs.Count) address(es) read now ($extN external, $nestedN nested group(s)) become the only senders this list accepts, and anyone else is rejected, staff who are not members included. It is a snapshot: a member added later is not on it, so add a new member to the allowed senders when adding them to the list. An owner, shared mailbox or application that sends to the list and is not a member is rejected unless it is added to the command. External members can send only while RequireSenderAuthenticationEnabled is False, which it is on this list. An allow list matches the sender's address; it does not authenticate an outside sender. Run it with -WhatIf first."
                }
            }
        }
        $v12 = if ($proposalCmd) { 'Proposal' } else { 'Context' }
        $rows.Add((& $mkRow 'DL-1.2' 'Allowed senders' $cur12 $v12 ("Context only: an allowed-senders list narrows who can send; it is judged under who can send (DL-1.1). " + $proposal) $ident @($proposalCmd)))

        # 3. Owner
        $f21 = & $fnd 'DL-2.1'; $v21 = & $verdictOf $f21 'Not assessed'
        $cur21 = if (-not $ownKnown) { 'Not returned' } else { "$ownN owner(s)" }
        $c21 = @(); if ($v21 -eq 'Gap') { $c21 += (& $cmdFor 'DL-2.1' @{ List = $addr }) }
        $rows.Add((& $mkRow 'DL-2.1' 'Owner' $cur21 $v21 (& $detailOf $f21 'Not assessed.') $ident $c21))

        # 4. Moderation
        $f22 = & $fnd 'DL-2.2'
        $cur22 = if ($null -eq $mod) { 'Not returned' } elseif ($mod -eq $true) { "On, $(@(Get-NRGObjectField -Item $l -Key 'ModeratedBy' -Default @()).Count) moderator(s)" } else { 'Off' }
        $v22 = if ($f22) { & $verdictOf $f22 'Not assessed' } elseif ($mod -eq $false) { 'Not applicable' } else { 'Not assessed' }
        $d22 = if ($f22) { & $detailOf $f22 '' } elseif ($mod -eq $false) { "Not applicable: moderation is off, which is Microsoft's default; there is no recommendation to turn it on." } else { 'Not assessed.' }
        $c22 = @(); if ($v22 -eq 'Gap') { $c22 += (& $cmdFor 'DL-2.2' @{ List = $addr }) }
        $rows.Add((& $mkRow 'DL-2.2' 'Moderation' $cur22 $v22 $d22 $ident $c22))

        # 5. External members: shown, never judged (the owner decided external members stay) and no command removes one.
        $cur23 = if ($mst -ne 'Collected') { 'Members not read' } else { "$extN external of $(if ($trunc) { 'at least ' })$cnt" }
        $rows.Add((& $mkRow 'DL-2.3' 'External members' $cur23 'Context' 'Context only: external members are expected on a list that serves outside parties, so they are shown and not judged; this scan prints no command that removes one. What limits their exposure is who can send to the list (DL-1.1, DL-1.2). They are listed under Members with class External; a nested group is listed, not expanded.' $ident @()))

        # 6. Member count
        $f24 = & $fnd 'DL-2.4'; $v24 = & $verdictOf $f24 'Not assessed'
        $cur24 = if ($mst -ne 'Collected') { 'Members not read' } else { "$(if ($trunc) { 'More than ' })$cnt member(s)$(if ($kind -eq 'Dynamic') { ' (dynamic)' })" }
        $rows.Add((& $mkRow 'DL-2.4' 'Member count' $cur24 $v24 (& $detailOf $f24 'Not assessed.') $ident @()))

        # 7. Join restriction
        $f25 = & $fnd 'DL-2.5'
        $cur25 = if ($kind -eq 'Dynamic') { 'Not applicable: a dynamic list has no join setting' } elseif ($join) { "MemberJoinRestriction = $join" } else { 'Not returned' }
        $v25 = if ($kind -eq 'Dynamic') { 'Not applicable' } else { & $verdictOf $f25 'Not assessed' }
        $d25 = if ($kind -eq 'Dynamic') { 'Not applicable: membership of a dynamic list comes from its recipient filter, not from join requests.' } else { & $detailOf $f25 'Not assessed.' }
        # With several approved values the command uses the MOST restrictive (Closed, then ApprovalRequired, then Open), never the first
        # in some arbitrary order: picking Open would loosen a list that is only approval-gated.
        $c25 = @()
        if ($v25 -eq 'Gap' -and $joinStd.Approved -and @($joinStd.Allowed).Count) {
            $joinPick = [string](@('Closed', 'ApprovalRequired', 'Open') | Where-Object { $_ -in @($joinStd.Allowed) } | Select-Object -First 1)
            $c25 += (& $cmdFor 'DL-2.5' @{ List = $addr; Value = $joinPick })
            if (@($joinStd.Allowed).Count -gt 1) { $d25 += " The command uses '$joinPick', the most restrictive of the approved values." }
        }
        $rows.Add((& $mkRow 'DL-2.5' 'Who can join' $cur25 $v25 $d25 $ident $c25))

        # 8/9. Leave restriction and hidden: read and shown, no recommendation
        $rows.Add((& $mkRow '' 'Who can leave' $(if ($kind -eq 'Dynamic') { 'Not applicable' } elseif ($depart) { "MemberDepartRestriction = $depart" } else { 'Not returned' }) 'No recommendation' 'Shown for the administrator; neither Microsoft nor an approved NRG standard recommends a value.' $ident @()))
        $rows.Add((& $mkRow 'DL-1.3' 'Hidden from address lists' $(if ($null -eq $hidden) { 'Not returned' } else { "HiddenFromAddressListsEnabled = $hidden" }) 'Context' 'Context only: hiding a list does not stop mail reaching it.' $ident @()))

        # An Exchange Online command for a synchronized list would be refused, so none is printed for it (the list's note says why).
        if ($dirSynced) { foreach ($row in $rows) { $row.Commands = @() } }

        # Who can reach it today: the setting plus every bypass that applies to all mail
        $outside = switch ($v11) {
            'Met'      { 'Outside senders: blocked (authenticated senders inside the organization only).' }
            'Partial'  { "Outside senders: accepted, limited to $allowedN specified sender(s)." }
            'Gap'      { 'Outside senders: accepted from anyone.' }
            default    { 'Outside senders: unknown (the setting was not returned).' }
        }
        $ruleHits = @()
        foreach ($br in $bypassRules) {
            $rr = $br.Rule; $cls = $br.Class
            foreach ($st in @(Get-NRGObjectField -Item $rr -Key 'SentTo' -Default @())) {
                if ([string]$st -ieq $addr -or [string]$st -ieq $name -or [string]$st -ieq [string](Get-NRGObjectField -Item $l -Key 'DisplayName' -Default '')) {
                    $ruleHits += "Mail flow rule '$([string](Get-NRGObjectField -Item $rr -Key 'Name' -Default ''))' sets SCL -1 (skips spam filtering) for mail sent to this list ($($cls.Class))."
                }
            }
        }
        $reach = @($outside,
            ("Filtering bypasses that apply to every list: SCL -1 mail flow rules: $(& $bypassWord 'DL-3.1'); IP Allow List: $(& $bypassWord 'DL-3.2'); anti-spam allowed senders/domains: $(& $bypassWord 'DL-3.3'); own domain on an allow list: $(& $bypassWord 'DL-3.4'); Outlook Safe Senders: not assessed."),
            'DMARC reject does not make this list safe: it judges only mail that claims your own domain, not a lookalike domain or a display-name impersonation.') + $ruleHits
        $reachRow = & $mkRow '' 'Who can reach it today' ($reach -join ' ') $(if ($v11 -eq 'Gap' -or $ruleHits.Count) { 'Gap' } elseif ($v11 -eq 'Partial') { 'Partial' } elseif ($v11 -eq 'Met') { 'Met' } else { 'Not assessed' }) 'Setting plus tenant-wide bypasses; see the tenant section for each.' $ident @()
        $reachRow.RowType = 'Reach'
        $reachRow.Lines = @($reach)

        # Members
        $memberRows = @($members | ForEach-Object {
            [ordered]@{ RowType = 'Member'; ListName = $name; ListAddress = $addr; ListType = $kind
                        DisplayName = [string](Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '')
                        UPN = [string](Get-NRGObjectField -Item $_ -Key 'UPN' -Default '')
                        RecipientType = [string](Get-NRGObjectField -Item $_ -Key 'RecipientType' -Default '')
                        Class = [string](Get-NRGObjectField -Item $_ -Key 'Class' -Default '') } })
        $memberLine = switch ($mst) {
            'Collected' { "$(if ($trunc) { 'More than ' })$cnt member(s) read$(if ($trunc) { " (listing stops at $maxM)" })$(if ($kind -eq 'Dynamic') { if ([string](Get-NRGObjectField -Item $l -Key 'MembershipBasis' -Default '') -eq 'DynamicPreview') { '; a preview of the list''s filter taken at scan time, not the stored membership' } else { '; the calculated list Microsoft stores on the group, which can differ from who receives mail sent now' } })" }
            'Failed'    { "Members NOT read: $([string](Get-NRGObjectField -Item $l -Key 'MemberError' -Default 'no error recorded')). This is not an empty list." }
            default     { 'Members not read.' }
        }

        $worst = (@($rows | Where-Object { $_.Verdict -eq 'Gap' }).Count * 100) + (@($rows | Where-Object { $_.Verdict -eq 'Partial' }).Count * 10) + (@($rows | Where-Object { $_.Verdict -eq 'Not assessed' }).Count)
        if ($reachRow.Verdict -eq 'Gap') { $worst += 100 }
        $listRows.Add([ordered]@{
            Name = $name; Address = $addr; Kind = $kind
            Owners = @(Get-NRGObjectField -Item $l -Key 'Owners' -Default @())
            # 'none' and 'not returned' are different answers: Exchange omits a property it does not return.
            OwnersLine = $(if (-not $ownKnown) { 'not returned by Exchange' } elseif ($ownN -eq 0) { 'none (ManagedBy is empty)' } else { (@(Get-NRGObjectField -Item $l -Key 'Owners' -Default @()) -join '; ') })
            MemberStatus = $mst; MemberLine = $memberLine; Members = $memberRows
            NestedGroups = @(Get-NRGObjectField -Item $l -Key 'NestedGroups' -Default @())
            Reach = $reachRow; Settings = @($rows); Risk = $worst
            # An observation, not a verdict: counted only when the member read completed (a failed read leaves Members empty, not clean).
            ExternalMemberCount = $(if ($mst -eq 'Collected') { $extN } else { 0 })
            AllowListProposed = [bool]$proposalCmd
            AcceptsFromAnyone = ($v11 -eq 'Gap')
            DirSynced = $dirSynced
            SyncNote = $syncNote
        })
    }
    # Most exposed first; among equals, the list with more external members first, because those are the lists this scan is aimed at.
    $sortedLists = @($listRows | Sort-Object @{ Expression = { $_.Risk }; Descending = $true }, @{ Expression = { $_.ExternalMemberCount }; Descending = $true }, @{ Expression = { $_.Name } })

    # ── Summary ───────────────────────────────────────────────────────────────────
    $count = { param($v) @($sortedLists | ForEach-Object { $_.Settings } | Where-Object { $_.Verdict -eq $v }).Count }
    $summary = [ordered]@{
        ListCount            = $sortedLists.Count
        ListsReachableFromOutside = @($sortedLists | Where-Object { $_.AcceptsFromAnyone }).Count
        # Lists the cap left out of the worksheet (they are not assessed, and not clean).
        ListsBeyondCap       = $(if ($listsTrunc -and $listsSeen -gt $maxL) { $listsSeen - $maxL } else { 0 })
        ListsMembersNotRead  = @($sortedLists | Where-Object { $_.MemberStatus -ne 'Collected' }).Count
        # At least one external member among the lists whose members were read (a truncated list can only have more). Lists whose
        # members were not read are in ListsMembersNotRead and are not counted here, so this is a floor, never a clean bill.
        ListsWithExternalMembers = @($sortedLists | Where-Object { $_.ExternalMemberCount -gt 0 }).Count
        # Lists for which the worksheet prints an allowed-senders command (text only; a list it withholds one for says why on its row).
        AllowListsProposed   = @($sortedLists | Where-Object { $_.AllowListProposed }).Count
        SettingGaps          = (& $count 'Gap')
        SettingPartials      = (& $count 'Partial')
        SettingsNotAssessed  = (& $count 'Not assessed')
        TenantBypassGaps     = @($tenantRows | Where-Object { $_.Verdict -eq 'Gap' }).Count
        MembersRead          = [int](Get-NRGObjectField -Item $stats -Key 'MembersRead' -Default 0)
    }

    return [ordered]@{
        Header = [ordered]@{
            Title        = 'NRG Distribution List Worksheet'
            TenantDomain = [string](Get-NRGObjectField -Item $Metadata -Key 'TenantDomain' -Default '')
            TenantId     = [string](Get-NRGObjectField -Item $Metadata -Key 'TenantId' -Default '')
            Generated    = [string](Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'yyyy-MM-dd HH:mm'))
            ToolVersion  = [string](Get-NRGObjectField -Item $Metadata -Key 'ToolVersion' -Default '')
            Mode         = 'Distribution lists only (Exchange Online; every other area not assessed)'
            Handling     = 'INTERNAL USE ONLY. This file holds tenant inventory: member names and addresses, list settings and mail flow rules.'
        }
        Limitations = @(Get-NRGDlLimitations -MaxMembersPerList $maxM -SectionsNotCollected $notCollected -ListsTruncated $listsTrunc -ListsSeen $listsSeen -MaxLists $maxL -NoListsReturned $noLists)
        NistMappingNote = [string]$Baseline.NistMappingNote
        FrameworkNote   = $fwNote
        Summary = $summary
        Tenant  = @($tenantRows)
        Lists   = $sortedLists
        CommandNote = 'Commands are TEXT for an administrator to review and run, with -WhatIf first. This scan never runs them.'
    }
}

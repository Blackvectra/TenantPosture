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
    return "'" + ($v -replace "'", "''") + "'"
}

# Fill a catalog command template. {List}/{Member}/{Value}/{Policy} become quoted literals;
# {Parameter} is one of two fixed words. Returns $null when any value cannot be quoted
# safely or the template is empty, so the caller prints the portal note instead.
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
    $pattern = '\{(List|Member|Value|Policy|Parameter)\}'
    $fill = @{}
    foreach ($k in @([regex]::Matches($Template, $pattern) | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)) {
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
    param([int] $MaxMembersPerList = 500, [string[]] $SectionsNotCollected = @())
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
    $notCollected = @()
    if (-not $ok) { $notCollected = @('the distribution-list inventory') }
    else { foreach ($k in 'Lists', 'DynamicLists', 'Members', 'AcceptedDomains', 'TransportRules', 'ConnectionFilter', 'AntiSpam') { if ([string](Get-NRGObjectField -Item $ss -Key $k -Default 'NotRun') -ne 'Collected') { $notCollected += $k } } }

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
                $nm = [string](Get-NRGObjectField -Item $o -Key 'Name' -Default '')
                $src = [string](Get-NRGObjectField -Item $o -Key 'Source' -Default '')
                $det = [string](Get-NRGObjectField -Item $o -Key 'Detail' -Default '')
                $c = $null
                if ($r.RuleCommand -and $src -eq 'Mail flow rule' -and $cid -eq 'DL-3.1') { $c = Format-NRGDlCommand -Template $r.RuleCommand -Values @{ Value = $nm } }
                elseif ($r.RuleCommand -and $src -eq 'IP Allow List' -and $cid -eq 'DL-3.2') { $c = Format-NRGDlCommand -Template $r.RuleCommand -Values @{ Value = $nm } }
                elseif ($r.RuleCommand -and $src -eq 'Anti-spam policy' -and $cid -eq 'DL-3.3') {
                    $pn = if ($det -match "policy '([^']*)'") { $Matches[1] } else { '' }
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

        $rows = [System.Collections.Generic.List[object]]::new()

        # 1. Who can send
        $f11 = & $fnd 'DL-1.1'; $v11 = & $verdictOf $f11 'Not assessed'
        $cur11 = if ($null -eq $auth) { 'Not returned' } else { "RequireSenderAuthenticationEnabled = $auth" }
        $c11 = @(); if ($v11 -in @('Gap', 'Partial')) { $c11 += (& $cmdFor 'DL-1.1' @{ List = $addr }) }
        $rows.Add((& $mkRow 'DL-1.1' 'Who can send to the list' $cur11 $v11 (& $detailOf $f11 'Not assessed.') $ident $c11))

        # 2. Allowed senders (context)
        $cur12 = if (-not $allowedKnown) { 'Not returned' } elseif ($allowedN -eq 0) { 'None specified' } else { "$allowedN specified sender(s)" }
        $rows.Add((& $mkRow 'DL-1.2' 'Allowed senders' $cur12 'Context' 'Context only: an allowed-senders list narrows who can send; it is judged under who can send (DL-1.1).' $ident @()))

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

        # 5. External members
        $f23 = & $fnd 'DL-2.3'; $v23 = & $verdictOf $f23 'Not assessed'
        $cur23 = if ($mst -ne 'Collected') { 'Members not read' } else { "$extN external of $(if ($trunc) { 'at least ' })$cnt" }
        $c23 = @()
        if ($v23 -eq 'Gap' -and $kind -ne 'Dynamic') {
            $extM = @($members | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Class' -Default '') -eq 'External' })
            foreach ($m in @($extM | Select-Object -First 25)) {
                $c = Format-NRGDlCommand -Template ([string]$rec['DL-2.3'].AdminCommands['Distribution']) -Values @{ List = $addr; Member = [string](Get-NRGObjectField -Item $m -Key 'UPN' -Default '') }
                $c23 += $(if ($c) { $c } else { "# member '$([string](Get-NRGObjectField -Item $m -Key 'DisplayName' -Default ''))' cannot be quoted safely here; remove it in the portal." })
            }
            if ($extM.Count -gt 25) { $c23 += "# $($extM.Count - 25) further external member(s) are not shown; the member rows list them all." }
        }
        $rows.Add((& $mkRow 'DL-2.3' 'External members' $cur23 $v23 (& $detailOf $f23 'Not assessed.') $ident $c23))

        # 6. Member count
        $f24 = & $fnd 'DL-2.4'; $v24 = & $verdictOf $f24 'Not assessed'
        $cur24 = if ($mst -ne 'Collected') { 'Members not read' } else { "$(if ($trunc) { 'More than ' })$cnt member(s)$(if ($kind -eq 'Dynamic') { ' (dynamic)' })" }
        $rows.Add((& $mkRow 'DL-2.4' 'Member count' $cur24 $v24 (& $detailOf $f24 'Not assessed.') $ident @()))

        # 7. Join restriction
        $f25 = & $fnd 'DL-2.5'
        $cur25 = if ($kind -eq 'Dynamic') { 'Not applicable: a dynamic list has no join setting' } elseif ($join) { "MemberJoinRestriction = $join" } else { 'Not returned' }
        $v25 = if ($kind -eq 'Dynamic') { 'Not applicable' } else { & $verdictOf $f25 'Not assessed' }
        $d25 = if ($kind -eq 'Dynamic') { 'Not applicable: membership of a dynamic list comes from its recipient filter, not from join requests.' } else { & $detailOf $f25 'Not assessed.' }
        $c25 = @(); if ($v25 -eq 'Gap' -and $joinStd.Approved -and @($joinStd.Allowed).Count) { $c25 += (& $cmdFor 'DL-2.5' @{ List = $addr; Value = [string]@($joinStd.Allowed)[0] }) }
        $rows.Add((& $mkRow 'DL-2.5' 'Who can join' $cur25 $v25 $d25 $ident $c25))

        # 8/9. Leave restriction and hidden: read and shown, no recommendation
        $rows.Add((& $mkRow '' 'Who can leave' $(if ($kind -eq 'Dynamic') { 'Not applicable' } elseif ($depart) { "MemberDepartRestriction = $depart" } else { 'Not returned' }) 'No recommendation' 'Shown for the administrator; neither Microsoft nor an approved NRG standard recommends a value.' $ident @()))
        $rows.Add((& $mkRow 'DL-1.3' 'Hidden from address lists' $(if ($null -eq $hidden) { 'Not returned' } else { "HiddenFromAddressListsEnabled = $hidden" }) 'Context' 'Context only: hiding a list does not stop mail reaching it.' $ident @()))

        # Who can reach it today: the setting plus every bypass that applies to all mail
        $outside = switch ($v11) {
            'Met'      { 'Outside senders: blocked (authenticated senders inside the organization only).' }
            'Partial'  { "Outside senders: accepted, limited to $allowedN specified sender(s)." }
            'Gap'      { 'Outside senders: accepted from anyone.' }
            default    { 'Outside senders: unknown (the setting was not returned).' }
        }
        $ruleHits = @()
        foreach ($rr in $rules) {
            $cls = Get-NRGDlTransportRuleClass -Rule $rr
            if (-not ($cls.IsBypass -and $cls.InForce)) { continue }
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
        })
    }
    # Most exposed first; among equals, the list with more external members first, because those are the lists this scan is aimed at.
    $sortedLists = @($listRows | Sort-Object @{ Expression = { $_.Risk }; Descending = $true }, @{ Expression = { $_.ExternalMemberCount }; Descending = $true }, @{ Expression = { $_.Name } })

    # ── Summary ───────────────────────────────────────────────────────────────────
    $count = { param($v) @($sortedLists | ForEach-Object { $_.Settings } | Where-Object { $_.Verdict -eq $v }).Count }
    $summary = [ordered]@{
        ListCount            = $sortedLists.Count
        ListsReachableFromOutside = @($sortedLists | Where-Object { $_.Reach.Lines[0] -like '*accepted from anyone*' }).Count
        ListsMembersNotRead  = @($sortedLists | Where-Object { $_.MemberStatus -ne 'Collected' }).Count
        # At least one external member among the lists whose members were read (a truncated list can only have more). Lists whose
        # members were not read are in ListsMembersNotRead and are not counted here, so this is a floor, never a clean bill.
        ListsWithExternalMembers = @($sortedLists | Where-Object { $_.ExternalMemberCount -gt 0 }).Count
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
        Limitations = @(Get-NRGDlLimitations -MaxMembersPerList $maxM -SectionsNotCollected $notCollected)
        NistMappingNote = [string]$Baseline.NistMappingNote
        FrameworkNote   = $fwNote
        Summary = $summary
        Tenant  = @($tenantRows)
        Lists   = $sortedLists
        CommandNote = 'Commands are TEXT for an administrator to review and run, with -WhatIf first. This scan never runs them.'
    }
}

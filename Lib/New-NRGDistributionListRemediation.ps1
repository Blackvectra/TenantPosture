#Requires -Version 7.0
#
# New-NRGDistributionListRemediation.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Turn one recommendation into a REMEDIATION BUNDLE: the state this scan read,
#          a check an administrator runs first, a preview, the apply command, a check
#          afterwards, and a rollback that restores the state this scan CAPTURED. Also
#          holds the quoting rules every printed command goes through.
#
# Sets:     nothing
# Consumes: a catalog entry (Config/distribution-list-baseline.json, Remediation node) and
#           values read by the collector. No Graph, no Exchange, no network: pure functions.
#
# COMMANDS ARE TEXT. NRG observes and recommends; an administrator authorizes and executes.
# Nothing here, or anywhere the module loads, runs a command it builds, and
# NRG.DistributionLists.Tests.ps1 parses these files and fails on any call that is not a
# read. A future remediation capability would be a separate subsystem with its own
# identity, permissions, approvals and audit log; it is not this file.
#
# THE SAFETY MODEL
# ----------------
# 1. NO CAPTURED STATE, NO COMMAND. The rollback is built from the value this scan read, so
#    a bundle whose original state is not known (a property Exchange omitted, a value
#    outside Microsoft's documented set, an entry that cannot be quoted) is returned with
#    Available = $false, a Reason, and NO command in any field. "Known to be empty"
#    (@()) and "not known" ($null) are different answers and are never confused.
# 2. ROLLBACK IS RESTORATION, NEVER AN INVERSE. The rollback command writes back the value
#    that was captured (Before False -> After True -> Rollback False; Before ApprovalRequired
#    -> After Closed -> Rollback ApprovalRequired, not 'Open'). A rollback command that can
#    restore only one particular value (Enable-TransportRule restores 'Enabled') is offered
#    only when that is the value that was captured.
# 3. PREVIEW IS THE APPLY COMMAND PLUS -WhatIf, nothing else, so what was previewed is what
#    is applied. The Apply is its own field and is never joined to the Preview.
# 4. TENANT-WIDE CHANGES ARE STRICTER. A change that reaches every recipient (a mail flow
#    rule, an anti-spam or connection-filter list) also carries a Backup step and -Confirm
#    on the Apply and the Rollback, and is withheld outright when no rollback can be built.
#    A change to one list may be one-way (OneWay = $true, said in words) only when the
#    original state cannot be written back, such as "no owner".
# 5. TENANT TEXT NEVER BECOMES CODE. A name or address is placed only in a single-quoted
#    literal with embedded quotes doubled, and a value holding a quote-like, line-break,
#    control or invisible character is refused rather than quoted. Placeholders are filled
#    in ONE pass, so inserted text is never scanned for placeholders again.

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

# One typed value as PowerShell text: a boolean as $true / $false, a string as a quoted literal, a list of strings as
# comma-joined quoted literals. $null means "not known" and is refused (returns $null); an EMPTY list is "known to be empty"
# and is written $null only when -AllowEmptyList says the caller is restoring a captured empty value.
function ConvertTo-NRGDlPsValue {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value, [switch] $AllowEmptyList)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { if ($Value) { return '$true' } else { return '$false' } }
    if ($Value -is [string]) { return (ConvertTo-NRGDlPsLiteral -Value $Value) }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($i in $Value) { $items.Add($i) }
        if ($items.Count -eq 0) { if ($AllowEmptyList) { return '$null' } else { return $null } }
        # An explicit loop, not `$x = foreach { ... return $null ... }`: a return inside a foreach whose output is captured emits the
        # literals gathered so far, which would hand the caller a command with entries missing. A command with one entry
        # dropped would be WORSE than none: a restored list that leaves one out loses it.
        $lits = [System.Collections.Generic.List[string]]::new()
        foreach ($it in $items) {
            if ($it -isnot [string]) { return $null }
            $q = ConvertTo-NRGDlPsLiteral -Value $it
            if ($null -eq $q) { return $null }
            $lits.Add($q)
        }
        return ($lits -join ',')
    }
    return $null
}

# Fill a catalog command template. {Target} is one quoted literal; {Parameter} is one of two fixed words; {Before}, {After}
# and {Remove} are typed values (see ConvertTo-NRGDlPsValue; only {Before} may be an empty list). Returns $null when a
# placeholder has no value, a value cannot be quoted safely, or the template is empty, so the caller withholds the command
# instead of printing a partial one.
#
# ONE PASS, on purpose. Substituting the placeholders one after another re-scans text that was already inserted, so a
# tenant-controlled address containing the literal text {Before} would be substituted a second time, and that second
# literal's quotes would end the first literal early: a quote breakout from tenant data. A single regex pass never
# rescans what it inserted.
function Format-NRGDlCommand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [string] $Template,
        [hashtable] $Values = @{}
    )
    if ([string]::IsNullOrWhiteSpace($Template)) { return $null }
    $pattern = '\{(Target|Parameter|Before|After|Remove)\}'
    $fill = @{}
    foreach ($k in @([regex]::Matches($Template, $pattern) | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)) {
        if (-not $Values.ContainsKey($k)) { return $null }
        $v = $Values[$k]
        if ($k -eq 'Parameter') {
            if ([string]$v -notin @('AllowedSenders', 'AllowedSenderDomains')) { return $null }
            $fill[$k] = [string]$v
            continue
        }
        if ($k -eq 'Target') {
            if ($v -isnot [string]) { return $null }
            $lit = ConvertTo-NRGDlPsLiteral -Value $v
        } else {
            $lit = ConvertTo-NRGDlPsValue -Value $v -AllowEmptyList:($k -eq 'Before')
        }
        if ($null -eq $lit) { return $null }
        $fill[$k] = $lit
    }
    return [regex]::Replace($Template, $pattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $fill[$m.Groups[1].Value] })
}

# How a captured value reads in a sentence: False, Open, (empty), a, b, c.
function Format-NRGDlValueText {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return 'not returned by Exchange' }
    if ($Value -is [bool]) { return $(if ($Value) { 'True' } else { 'False' }) }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) {
        $a = @($Value | ForEach-Object { [string]$_ })
        if ($a.Count -eq 0) { return '(empty)' }
        return ($a -join ', ')
    }
    return [string]$Value
}

# The one bundle shape. A withheld bundle has no step objects at all: not one command-shaped string for a reader to copy.
function New-NRGDlWithheldBundle {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([string] $ControlId, [string] $Impact, [string] $TargetKind, [string] $Target, [string] $Reason, [System.Collections.IDictionary] $Observed, [string] $ObservedAt, [string] $Property = '', [string] $TargetLabel = '')
    return [ordered]@{
        ControlId     = $ControlId
        Impact        = $Impact
        Available     = $false
        Reason        = $Reason
        OneWay        = $false
        RequiresInput = @()
        Target        = [ordered]@{ Kind = $TargetKind; Identity = $Target; Label = $TargetLabel }
        Property      = $Property
        ObservedAt    = $ObservedAt
        Observed      = $(if ($Observed) { $Observed } else { [ordered]@{} })
        Backup        = $null
        Precheck      = $null
        Preview       = $null
        Apply         = $null
        Verify        = $null
        Rollback      = $null
        Notes         = @()
    }
}

function New-NRGDlRemediation {
    <#
    .SYNOPSIS
        Builds one remediation bundle from a catalog entry and the state this scan captured.
    .PARAMETER Entry
        The catalog entry (Get-NRGDistributionListBaseline .ById[id]); its Remediation node holds the command templates.
    .PARAMETER Kind
        Which template set applies: Distribution, Dynamic or Tenant.
    .PARAMETER Target
        The identity the commands name: a list's primary SMTP address, a rule name, a policy name. $null or blank withholds.
    .PARAMETER BeforeValue
        The captured value of the changed property. $null means NOT KNOWN and withholds the bundle; an empty list means
        known to be empty (a rollback then writes $null).
    .PARAMETER AfterValue
        The value the Apply sets (a boolean or a string).
    .PARAMETER Remove
        For a list property changed by removing entries: the entries to remove. Every one must be in BeforeValue.
    .PARAMETER Parameter
        AllowedSenders or AllowedSenderDomains, for the anti-spam policy template.
    .PARAMETER Context
        Other captured values shown in the check and the observed state (display only), such as RequireSenderAuthenticationEnabled.
    .PARAMETER Withhold
        A reason the caller already knows the recommendation cannot be offered (a synchronized list, an external member, a
        preset policy). The bundle is returned withheld with this reason and no command.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] $Entry,
        [Parameter(Mandatory)] [ValidateSet('Distribution', 'Dynamic', 'Tenant')] [string] $Kind,
        [AllowNull()] [string] $Target,
        [string] $TargetLabel = '',
        [AllowNull()] $BeforeValue,
        [AllowNull()] $AfterValue,
        [AllowNull()] [string[]] $Remove,
        [string] $Parameter = '',
        [System.Collections.IDictionary] $Context,
        [string] $Withhold = '',
        [string] $ObservedAt = ''
    )

    $cid = [string]$Entry.ControlId
    $rem = Get-NRGObjectField -Item $Entry -Key 'Remediation' -Default $null
    $impact = if ($rem) { [string](Get-NRGObjectField -Item $rem -Key 'Impact' -Default 'Standard') } else { 'Standard' }
    $kinds = Get-NRGObjectField -Item $rem -Key 'Kinds' -Default $null
    $tpl = Get-NRGObjectField -Item $kinds -Key $Kind -Default $null
    $targetKind = if ($tpl) { [string](Get-NRGObjectField -Item $tpl -Key 'TargetKind' -Default '') } else { '' }
    $observed = [ordered]@{}
    if ($Context) { foreach ($k in $Context.Keys) { $observed[[string]$k] = [string]$Context[$k] } }

    $property = ''
    $withheld = { param([string] $why) New-NRGDlWithheldBundle -ControlId $cid -Impact $impact -TargetKind $targetKind -Target ([string]$Target) -TargetLabel $TargetLabel -Reason $why -Observed $observed -ObservedAt $ObservedAt -Property $property }

    if ($Withhold) { return (& $withheld $Withhold) }
    if (-not $tpl) { return (& $withheld "This recommendation has no command for a $Kind object.") }

    $property = [string](Get-NRGObjectField -Item $tpl -Key 'Property' -Default '')
    if ($property -eq '{Parameter}') { $property = $Parameter }
    if ([string]::IsNullOrWhiteSpace($property) -or $property -notmatch '^[A-Za-z]+$') { return (& $withheld 'The catalog names no property to verify for this recommendation.') }
    $observed[$property] = Format-NRGDlValueText -Value $BeforeValue

    # Rule 1: no captured state, no command.
    if ($null -eq $BeforeValue) { return (& $withheld "The original value of $property was not returned by Exchange, so there is nothing to restore and no command is offered.") }
    if ([string]::IsNullOrWhiteSpace($Target)) { return (& $withheld 'The name of the object to change was not returned by Exchange, so no command is offered.') }

    $isList = ($BeforeValue -is [System.Collections.IEnumerable]) -and ($BeforeValue -isnot [string])
    $beforeList = @(); if ($isList) { $beforeList = @($BeforeValue | ForEach-Object { [string]$_ }) }

    # A rollback command that can restore only one particular captured state: Enable-TransportRule writes 'Enabled'. It is offered
    # only when that is the state this scan captured.
    $restores = [string](Get-NRGObjectField -Item $tpl -Key 'RollbackRestores' -Default '')
    if ($restores -and ([string]$BeforeValue -ine $restores)) {
        return (& $withheld "The rollback command restores '$restores'; the captured value of $property is '$(Format-NRGDlValueText -Value $BeforeValue)', so a rollback that restores it cannot be built and no command is offered.")
    }

    # Values for the templates. A list changed by removing entries applies only when every entry is in the captured list.
    $vals = @{ Target = $Target; Before = $BeforeValue; After = $AfterValue; Parameter = $Parameter }
    $afterValue = $AfterValue
    if ($PSBoundParameters.ContainsKey('Remove') -and $null -ne $Remove) {
        $rm = @($Remove | ForEach-Object { [string]$_ })
        if ($rm.Count -eq 0) { return (& $withheld 'No entry was named for removal, so no command is offered.') }
        $beforeSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$beforeList, [System.StringComparer]::OrdinalIgnoreCase)
        $missing = @($rm | Where-Object { -not $beforeSet.Contains($_) })
        if ($missing.Count) { return (& $withheld 'An entry to remove is not in the list this scan captured, so the state is not what the recommendation was built from and no command is offered.') }
        $rmSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$rm, [System.StringComparer]::OrdinalIgnoreCase)
        $afterValue = @($beforeList | Where-Object { -not $rmSet.Contains($_) })
        $vals.Remove = $rm
        $vals.After = $afterValue
    }

    # The commands. Each is filled in one pass; a value that cannot be quoted safely withholds the WHOLE bundle (a list with an
    # entry dropped would be worse than none).
    $applyBase    = Format-NRGDlCommand -Template ([string](Get-NRGObjectField -Item $tpl -Key 'Apply' -Default '')) -Values $vals
    $rollbackTpl  = [string](Get-NRGObjectField -Item $tpl -Key 'Rollback' -Default '')
    $rollbackBase = $null
    if ($rollbackTpl) { $rollbackBase = Format-NRGDlCommand -Template $rollbackTpl -Values $vals }
    $getBase      = Format-NRGDlCommand -Template ([string](Get-NRGObjectField -Item $tpl -Key 'Get' -Default '')) -Values $vals
    if (-not $applyBase -or -not $getBase) { return (& $withheld 'A name or value in this recommendation cannot be quoted safely in a command (a quote-like, line-break, control or invisible character, or a missing value), so no command is offered. Make the change in the portal.') }
    if ($rollbackTpl -and -not $rollbackBase) { return (& $withheld 'A captured value cannot be quoted safely in a rollback command, so no command is offered. Make the change in the portal.') }

    $show = @(@(Get-NRGObjectField -Item $tpl -Key 'Show' -Default @()) | ForEach-Object { [string]$_ } | Where-Object { $_ -match '^[A-Za-z]+$' })
    $getCmd = $getBase
    if ($show.Count) { $getCmd = "$getBase | Format-List " + ($show -join ', ') }

    # Rule 4: a tenant-wide change is withheld when it cannot be rolled back; a single-object change may be one-way, said in words.
    $oneWay = $false
    if (-not $rollbackBase) {
        if ($impact -eq 'TenantWide') { return (& $withheld 'A tenant-wide change is offered only with a rollback that restores the captured state, and none can be built for it, so no command is offered.') }
        $oneWay = $true
    }

    $tenantWide = ($impact -eq 'TenantWide')
    $apply = if ($tenantWide) { "$applyBase -Confirm" } else { $applyBase }
    $preview = "$applyBase -WhatIf"
    $notes = [System.Collections.Generic.List[string]]::new()

    $beforeText = if ($isList) { if ($beforeList.Count) { "$property holds exactly: $($beforeList -join ', ')" } else { "$property is empty" } } else { "$property = $(Format-NRGDlValueText -Value $BeforeValue)" }
    $expectBefore = @($beforeText) + @($observed.Keys | Where-Object { $_ -ne $property } | ForEach-Object { "$_ = $($observed[$_])" })
    $precheckExpect = ($expectBefore -join '; ') + '. If the output differs, STOP: the state has changed since this scan, and this bundle was built from the earlier state. Re-run the scan.'

    $namesOnly = [bool](Get-NRGObjectField -Item $tpl -Key 'ShowsNames' -Default $false)
    $afterText = if ($afterValue -is [System.Collections.IEnumerable] -and $afterValue -isnot [string]) {
        $al = @($afterValue | ForEach-Object { [string]$_ })
        if ($namesOnly) { "$property lists $($al.Count) entr$(if ($al.Count -eq 1) { 'y' } else { 'ies' }), one for each address in the Apply command (Exchange shows names rather than addresses)" }
        elseif ($al.Count) { "$property holds exactly: $($al -join ', ')" } else { "$property is empty" }
    } else { "$property = $(Format-NRGDlValueText -Value $afterValue)" }
    if ($property -in @('ManagedBy', 'ModeratedBy')) { $afterText = "$property lists the person you named in the Apply command" }

    $backup = $null
    if ($tenantWide) {
        # The captured state is in this worksheet; the backup is a read that prints EVERY property of the live object just before the
        # change, for the administrator to save (a transcript, a screenshot, a ticket). It writes no file: the repo's security tests
        # ban serializing objects to disk, and a file name would be one more thing built around tenant text.
        $backup = [ordered]@{ Command = "$getBase | Format-List *"; Purpose = 'Prints every property of the live object just before the change. Save the output (for example with Start-Transcript) in addition to the state captured in this worksheet.' }
        $notes.Add('Tenant-wide: this change applies to every recipient, not to one list. Make it in a change window, take the Backup first, and confirm each prompt.')
    }
    if (-not $oneWay) {
        $notes.Add('Rollback restores the state this scan captured (the check and the Verify expectation say what that is). Run the check first: if the state changed after the scan, this bundle was built from state that no longer exists.')
        # A captured EMPTY list is restored by writing $null. Where the cmdlet page does not document clearing with $null, the
        # catalog says so, and the check after the rollback is what proves the state came back.
        $emptyNote = [string](Get-NRGObjectField -Item $tpl -Key 'EmptyRestoreNote' -Default '')
        if ($emptyNote -and $isList -and $beforeList.Count -eq 0) { $notes.Add($emptyNote) }
    }
    $requires = @(@(Get-NRGObjectField -Item $tpl -Key 'RequiresInput' -Default @()) | ForEach-Object { [string]$_ })
    if ($requires.Count) { $notes.Add("The command contains $(@($requires | ForEach-Object { "<$_>" }) -join ', '), which is a person's name only an administrator can choose. Replace it before running anything.") }

    $rollbackStep = if ($oneWay) {
        [ordered]@{ Available = $false; Command = ''; Expect = ''; Reason = [string](Get-NRGObjectField -Item $tpl -Key 'RollbackReason' -Default 'The captured original state cannot be written back by a command.') }
    } else {
        [ordered]@{ Available = $true; Command = $(if ($tenantWide) { "$rollbackBase -Confirm" } else { $rollbackBase }); Expect = "After the rollback, run the check again. $beforeText."; Reason = '' }
    }

    return [ordered]@{
        ControlId     = $cid
        Impact        = $impact
        Available     = $true
        Reason        = ''
        OneWay        = $oneWay
        RequiresInput = @($requires)
        Target        = [ordered]@{ Kind = $targetKind; Identity = $Target; Label = $TargetLabel }
        Property      = $property
        ObservedAt    = $ObservedAt
        Observed      = $observed
        Backup        = $backup
        Precheck      = [ordered]@{ Command = $getCmd; Expect = $precheckExpect }
        Preview       = [ordered]@{ Command = $preview; Note = 'Makes no change: -WhatIf shows what the Apply would do.' }
        Apply         = [ordered]@{ Command = $apply; Effect = [string](Get-NRGObjectField -Item $tpl -Key 'Effect' -Default '') }
        Verify        = [ordered]@{ Command = $getCmd; Expect = "$afterText." }
        Rollback      = $rollbackStep
        Notes         = @($notes)
    }
}

# The tenant-wide bundles for one finding (DL-3.1 mail flow rules, DL-3.2 the IP Allow List, DL-3.3 anti-spam allow lists): the
# finding names WHAT to remove, and the state to capture (a rule's State, a policy's whole list) is read from the collector's
# inputs, never from the rendered finding text. One bundle per rule, and one per policy (and per list property) so that one
# apply has one rollback. Any entry that cannot be tied to exactly one captured object withholds that bundle, with the reason.
function Get-NRGDlTenantRemediations {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] $Entry,
        [AllowNull()] [object[]] $AffectedObjects,
        [AllowNull()] $BypassInputs,
        [string] $ObservedAt = ''
    )
    $cid = [string]$Entry.ControlId
    $objs = @($AffectedObjects | Where-Object { $null -ne $_ })
    $out = [System.Collections.Generic.List[object]]::new()
    $text = { param($o, $k) [string](Get-NRGObjectField -Item $o -Key $k -Default '') }
    $named = { param($rows, $name) @($rows | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '') -ceq $name }) }

    if ($cid -eq 'DL-3.1') {
        $rules = @(Get-NRGObjectField -Item $BypassInputs -Key 'TransportRules' -Default @())
        foreach ($o in @($objs | Where-Object { (& $text $_ 'Source') -eq 'Mail flow rule' })) {
            $nm = & $text $o 'Name'
            $hit = @(& $named $rules $nm)
            $state = $null; $withhold = ''; $ctx = [ordered]@{}
            if ([string]::IsNullOrWhiteSpace($nm)) { $withhold = 'The rule has no name in what Exchange returned, so no command can name it.' }
            elseif ($hit.Count -ne 1) { $withhold = "$($hit.Count) mail flow rules read by this scan are named exactly like this one, so a command could not name one rule; no command is offered." }
            else {
                $st = & $text $hit[0] 'State'
                if ($st) { $state = $st }
                $mode = & $text $hit[0] 'Mode'; if ($mode) { $ctx['Mode'] = $mode }
            }
            $out.Add((New-NRGDlRemediation -Entry $Entry -Kind Tenant -Target $nm -TargetLabel $nm -BeforeValue $state -AfterValue 'Disabled' -Context $ctx -Withhold $withhold -ObservedAt $ObservedAt))
        }
        return @($out)
    }

    if ($cid -eq 'DL-3.2') {
        $policies = @(Get-NRGObjectField -Item $BypassInputs -Key 'ConnectionFilter' -Default @())
        $cand = @($objs | Where-Object { (& $text $_ 'Source') -eq 'IP Allow List' -and (& $text $_ 'Class') -in @('WiderThan24', 'Unparsed') })
        foreach ($g in @($cand | Group-Object -Property { (& $text $_ 'Policy') })) {
            $pn = [string]$g.Name
            $hit = @(& $named $policies $pn)
            $before = $null; $withhold = ''
            if ([string]::IsNullOrWhiteSpace($pn)) { $withhold = 'The connection filter policy has no name in what Exchange returned, so no command can name it.' }
            elseif ($hit.Count -ne 1) { $withhold = "$($hit.Count) connection filter policies read by this scan are named exactly like this one, so a command could not name one policy; no command is offered." }
            else {
                $list = @(@(Get-NRGObjectField -Item $hit[0] -Key 'IPAllowList' -Default @()) | ForEach-Object { [string]$_ })
                if ($list.Count) { $before = [string[]]$list }
            }
            $remove = [string[]]@($g.Group | ForEach-Object { & $text $_ 'Name' } | Select-Object -Unique)
            $out.Add((New-NRGDlRemediation -Entry $Entry -Kind Tenant -Target $pn -TargetLabel $pn -BeforeValue $before -Remove $remove -Withhold $withhold -ObservedAt $ObservedAt))
        }
        return @($out)
    }

    if ($cid -eq 'DL-3.3') {
        $policies = @(Get-NRGObjectField -Item $BypassInputs -Key 'AntiSpamPolicies' -Default @())
        $cand = @($objs | Where-Object { (& $text $_ 'Source') -eq 'Anti-spam policy' } | ForEach-Object {
            [pscustomobject]@{ Policy = (& $text $_ 'Policy'); Parameter = $(if ((& $text $_ 'Class') -eq 'allowed domain') { 'AllowedSenderDomains' } else { 'AllowedSenders' }); Value = (& $text $_ 'Name') } })
        foreach ($g in @($cand | Group-Object -Property Policy, Parameter)) {
            $pn = [string]$g.Group[0].Policy; $par = [string]$g.Group[0].Parameter
            $hit = @(& $named $policies $pn)
            $before = $null; $withhold = ''
            if ([string]::IsNullOrWhiteSpace($pn)) { $withhold = 'The anti-spam policy has no name in what Exchange returned, so no command can name it.' }
            elseif ($hit.Count -ne 1) { $withhold = "$($hit.Count) anti-spam policies read by this scan are named exactly like this one, so a command could not name one policy; no command is offered." }
            elseif ((& $text $hit[0] 'RecommendedPolicyType') -in @('Standard', 'Strict')) {
                $withhold = "This policy belongs to the $((& $text $hit[0] 'RecommendedPolicyType')) preset security policy. Microsoft says not to modify the individual threat policies associated with preset security policies, so no command is offered; change the preset security policy in the Defender portal."
            } else {
                $list = @(@(Get-NRGObjectField -Item $hit[0] -Key $par -Default @()) | ForEach-Object { [string]$_ })
                if ($list.Count) { $before = [string[]]$list }
            }
            $remove = [string[]]@($g.Group | ForEach-Object { $_.Value } | Select-Object -Unique)
            $out.Add((New-NRGDlRemediation -Entry $Entry -Kind Tenant -Target $pn -TargetLabel "$pn ($par)" -BeforeValue $before -Remove $remove -Parameter $par -Withhold $withhold -ObservedAt $ObservedAt))
        }
        return @($out)
    }
    return @()
}

#Requires -Version 7.0
#
# Publish-NRGDistributionListWorksheet.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Write the distribution-list worksheet as <base>-distribution-lists.txt and
#          <base>-distribution-lists.csv, both rendered from the ONE model
#          Get-NRGDistributionListWorksheet builds, so a verdict or a limitation reads
#          the same in each (NRG.DistributionLists.Tests.ps1 pins that).
#
# Sets:     two files on disk. Consumes: the worksheet model. No tenant calls.
#
# THESE FILES HOLD TENANT INVENTORY (member names and addresses, list settings, mail
# flow rules). They are written only through Set-NRGSensitiveFileContent, which applies
# the restricted ACL BEFORE any data lands, exactly as the results JSON is. If that
# writer is not loaded the publisher refuses to write rather than fall back to a plain
# write. Internal use only.
#
# COMMAND TEXT IS NEVER A SCRIPT. The administrator commands are printed in a .txt and a
# .csv. They are not written to a .ps1, not dot-sourced, not passed to any invoker, and
# this file contains no call that could run them. Compare Publish-NRGRemediationScript,
# which generates a script on purpose; this publisher deliberately does not.
#
# TENANT TEXT IS DATA. A list name or member display name is set by people, so each value
# is stripped of control characters (a terminal escape in a .txt is a real attack) and, in
# the CSV, a cell that starts with = + - @ is neutralized so a spreadsheet does not read it
# as a formula.

# A tenant-supplied value made safe to print: no line breaks, no control characters.
function ConvertTo-NRGDlSafeText {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return '' }
    $s = if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { (@($Value) | ForEach-Object { [string]$_ }) -join '; ' } else { [string]$Value }
    $s = $s -replace '[\r\n\u0085]+', ' '
    foreach ($cp in 0x2028, 0x2029) { $s = $s.Replace([string][char]$cp, ' ') }   # code points, not typed: see Get-NRGDistributionListWorksheet.ps1
    $s = $s -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ''
    # An invisible or direction-changing character (bidirectional override, zero-width, byte order mark, tag character) is shown as
    # <U+XXXX> rather than passed through or silently dropped: a reviewer should SEE that a name was tampered with, and a name
    # must not be able to reorder the text around it.
    $s = [regex]::Replace($s, '\p{Cf}|\uDB40[\uDC00-\uDC7F]', [System.Text.RegularExpressions.MatchEvaluator]{ param($m) '<U+{0:X4}>' -f [char]::ConvertToUtf32($m.Value, 0) })
    return $s.Trim()
}

# One CSV cell: safe text, and a leading apostrophe when a spreadsheet would read it as a formula.
function ConvertTo-NRGDlCsvCell {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)
    $s = ConvertTo-NRGDlSafeText -Value $Value
    if ($s -match '^[=+\-@\t]') { return "'" + $s }
    return $s
}

# Wrap prose to a width, with a first-line prefix and a hanging indent.
function Format-NRGDlWrap {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] [string] $Text, [int] $Indent = 0, [int] $Width = 110, [string] $Prefix = '')
    $hang = ' ' * ($Indent + $Prefix.Length)
    $lines = [System.Collections.Generic.List[string]]::new()
    $cur = (' ' * $Indent) + $Prefix
    $hasWord = $false
    foreach ($w in @(([string]$Text) -split '\s+' | Where-Object { $_ })) {
        if ($hasWord -and ($cur.Length + 1 + $w.Length) -gt $Width) { $lines.Add($cur.TrimEnd()); $cur = $hang + $w }
        elseif ($hasWord) { $cur = "$cur $w" }
        else { $cur = $cur + $w }
        $hasWord = $true
    }
    $lines.Add($cur.TrimEnd())
    return @($lines)
}

# One remediation bundle as text lines. The Apply is its own labeled step, never on the same line as the Preview, and every
# command is on a line of its own beginning with "> " so it can be selected whole.
function Get-NRGDlBundleLines {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] $Bundle, [string] $Item = '', [int] $Indent = 4)
    $t = ${function:ConvertTo-NRGDlSafeText}
    $lines = [System.Collections.Generic.List[string]]::new()
    $pad = ' ' * $Indent
    $wrap = { param($text, $ind, $prefix) foreach ($ln in @(Format-NRGDlWrap -Text (& $t $text) -Indent $ind -Prefix $prefix)) { $lines.Add($ln) } }
    $b = $Bundle
    $scope = if ([string]$b.Impact -eq 'TenantWide') { 'TENANT-WIDE' } else { 'one object' }
    $obs = @($b.Observed.Keys | ForEach-Object { "$_ = $($b.Observed[$_])" }) -join '; '
    if (-not [bool]$b.Available) {
        $lines.Add("$($pad)REMEDIATION WITHHELD [$($b.ControlId)] $(& $t $Item)  --  no command is printed")
        & $wrap ([string]$b.Reason) ($Indent + 2) 'Reason: '
        if ($obs) { & $wrap $obs ($Indent + 2) 'State read: ' }
        return @($lines)
    }
    $lines.Add("$($pad)REMEDIATION BUNDLE [$($b.ControlId)] $(& $t $Item)  --  scope: $scope")
    $target = [string](Get-NRGObjectField -Item $b.Target -Key 'Label' -Default '')
    if (-not $target) { $target = [string](Get-NRGObjectField -Item $b.Target -Key 'Identity' -Default '') }
    & $wrap ("$([string]$b.Target.Kind) $target") ($Indent + 2) 'Target: '
    $when = if ([string]$b.ObservedAt) { " (read $([string]$b.ObservedAt))" } else { '' }
    & $wrap $obs ($Indent + 2) "State read$($when): "
    if ($b.Backup) {
        $lines.Add("$($pad)  BACKUP  (read-only; prints every property of the live object: save the output before you change anything)")
        $lines.Add("$($pad)    > $(& $t $b.Backup.Command)")
    }
    $lines.Add("$($pad)  1. CHECK first  (read-only)")
    $lines.Add("$($pad)    > $(& $t $b.Precheck.Command)")
    & $wrap ([string]$b.Precheck.Expect) ($Indent + 4) 'Expect: '
    $lines.Add("$($pad)  2. PREVIEW  (makes no change; -WhatIf shows what step 3 would do)")
    $lines.Add("$($pad)    > $(& $t $b.Preview.Command)")
    $lines.Add("$($pad)  3. APPLY  (CHANGES THE TENANT: run only after the check and the preview look right)")
    if ([string]$b.Apply.Effect) { & $wrap ([string]$b.Apply.Effect) ($Indent + 4) 'Effect: ' }
    $lines.Add("$($pad)    > $(& $t $b.Apply.Command)")
    $lines.Add("$($pad)  4. VERIFY  (read-only)")
    $lines.Add("$($pad)    > $(& $t $b.Verify.Command)")
    & $wrap ([string]$b.Verify.Expect) ($Indent + 4) 'Expect: '
    if ([bool]$b.Rollback.Available) {
        $lines.Add("$($pad)  ROLLBACK  (restores the state this scan read; run the check first and the check again afterwards)")
        $lines.Add("$($pad)    > $(& $t $b.Rollback.Command)")
        & $wrap ([string]$b.Rollback.Expect) ($Indent + 4) 'Expect: '
    } else {
        $lines.Add("$($pad)  ROLLBACK  NOT AVAILABLE")
        & $wrap ([string]$b.Rollback.Reason) ($Indent + 4) 'Reason: '
    }
    foreach ($note in @($b.Notes)) { & $wrap ([string]$note) ($Indent + 2) 'Note: ' }
    return @($lines)
}

function ConvertTo-NRGDlWorksheetText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Worksheet)
    $t = ${function:ConvertTo-NRGDlSafeText}
    $sb = [System.Text.StringBuilder]::new()
    $add = { param($line) [void]$sb.AppendLine([string]$line) }
    $wrap = { param($text, $indent, $prefix) foreach ($ln in @(Format-NRGDlWrap -Text (& $t $text) -Indent $indent -Prefix $prefix)) { & $add $ln } }
    $rule = ('=' * 100)
    $h = $Worksheet.Header

    & $add $h.Title
    & $add $rule
    & $add ("Tenant:    {0}" -f ((@((& $t $h.TenantDomain), $(if ($h.TenantId) { $(if ($h.TenantDomain) { "($(& $t $h.TenantId))" } else { & $t $h.TenantId }) } else { '' })) | Where-Object { $_ }) -join ' '))
    & $add ("Generated: {0}" -f (& $t $h.Generated))
    & $add ("Tool:      {0}" -f (& $t $h.ToolVersion))
    & $add ("Mode:      {0}" -f (& $t $h.Mode))
    & $add ''
    & $wrap $h.Handling 0 ''
    & $add ''
    & $add 'WHAT THIS IS, AND WHAT IT IS NOT'
    & $add ('-' * 100)
    $i = 0
    foreach ($lim in @($Worksheet.Limitations)) { $i++; & $wrap $lim 0 ("$i. ") }
    & $add ''
    & $wrap $Worksheet.CommandNote 0 'Note: '
    & $wrap $Worksheet.NistMappingNote 0 'NIST mapping: '
    & $add ''

    $s = $Worksheet.Summary
    & $add 'SUMMARY'
    & $add ('-' * 100)
    & $add ("Lists read:                              {0}" -f $s.ListCount)
    & $add ("Lists beyond -MaxLists, NOT in this file: {0}  (not assessed, and not clean)" -f (Get-NRGObjectField -Item $s -Key 'ListsBeyondCap' -Default 0))
    & $add ("Lists that accept mail from anyone:      {0}" -f $s.ListsReachableFromOutside)
    & $add ("Lists with an external member:           {0}  (counted only among lists whose members were read)" -f (Get-NRGObjectField -Item $s -Key 'ListsWithExternalMembers' -Default 0))
    & $add ("Lists with an allow list proposed:       {0}  (a snapshot of the members read now; text only, never applied)" -f (Get-NRGObjectField -Item $s -Key 'AllowListsProposed' -Default 0))
    & $add ("Lists whose members were not read:       {0}" -f $s.ListsMembersNotRead)
    & $add ("Members read:                            {0}" -f $s.MembersRead)
    & $add ("Setting gaps / partials / not assessed:  {0} / {1} / {2}" -f $s.SettingGaps, $s.SettingPartials, $s.SettingsNotAssessed)
    & $add ("Tenant-wide bypass gaps:                 {0}" -f $s.TenantBypassGaps)
    & $add ''

    & $add 'TENANT-WIDE FILTERING BYPASSES (these apply to every list)'
    & $add ('-' * 100)
    foreach ($r in @($Worksheet.Tenant)) {
        & $add ("[{0}] {1}  --  {2}" -f $r.ControlId, (& $t $r.Item), $r.Verdict)
        & $wrap $r.Detail 4 ''
        foreach ($o in @($r.Objects)) { & $wrap $o 6 '- ' }
        if ($r.Recommended) { & $wrap $r.Recommended 4 'Recommended: ' }
        & $add ("    Source: {0}" -f $r.Source)
        & $add ("    Mapped NIST 800-53 Rev 5 (NRG mapping): {0}    Other frameworks: {1}" -f (@($r.Nist80053) -join ', '), $r.FrameworkItem)
        if (@($r.Inspect).Count) {
            & $add '    Read-only look at the setting (no change):'
            foreach ($c in @($r.Inspect)) { & $add ("      > {0}" -f (& $t $c)) }
        }
        foreach ($b in @($r.Remediations)) { & $add ''; foreach ($ln in @(Get-NRGDlBundleLines -Bundle $b -Item ([string]$r.Item) -Indent 4)) { & $add $ln } }
        & $add ''
    }

    & $add 'DISTRIBUTION LISTS (most exposed first)'
    & $add ('=' * 100)
    foreach ($l in @($Worksheet.Lists)) {
        & $add ''
        & $add ("LIST: {0} <{1}>   [{2}]" -f (& $t $l.Name), (& $t $l.Address), (& $t $l.Kind))
        & $add ('-' * 100)
        & $add ("  Owners:  {0}" -f (& $t $l.OwnersLine))
        if ([string](Get-NRGObjectField -Item $l -Key 'SyncNote' -Default '')) { & $wrap ([string]$l.SyncNote) 2 'Source of truth: ' }
        & $add ("  Members: {0}" -f (& $t $l.MemberLine))
        foreach ($m in @($l.Members)) { & $add ("    - {0} <{1}>  [{2}, {3}]" -f (& $t $m.DisplayName), (& $t $m.UPN), (& $t $m.RecipientType), $m.Class) }
        if (@($l.NestedGroups).Count) { & $wrap ("Nested groups (listed, not expanded): " + ((@($l.NestedGroups) | ForEach-Object { & $t $_ }) -join '; ')) 2 '' }
        & $add ''
        & $add ("  Who can reach it today:  [{0}]" -f $l.Reach.Verdict)
        foreach ($ln in @($l.Reach.Lines)) { & $wrap $ln 4 '- ' }
        & $add ''
        & $add '  Settings against the recommendation:'
        $n = 0
        $bundles = [System.Collections.Generic.List[object]]::new()
        foreach ($r in @($l.Settings)) {
            $n++
            & $add ("    {0}. {1}  [{2}]" -f $n, $r.Item, $r.Verdict)
            & $add ("       Current:     {0}" -f (& $t $r.Current))
            if ($r.Recommended) { & $wrap $r.Recommended 7 'Recommended: ' ; if ($r.Basis) { & $add ("       Basis:       {0}" -f $r.Basis) } }
            & $wrap $r.Detail 7 'Finding:     '
            if ($r.Source) { & $add ("       Source:      {0}" -f $r.Source) }
            if (@($r.Nist80053).Count) { & $add ("       Mapped NIST 800-53 Rev 5 (NRG mapping): {0}    Other frameworks: {1}" -f (@($r.Nist80053) -join ', '), $r.FrameworkItem) }
            foreach ($b in @($r.Remediations)) { $bundles.Add([pscustomobject]@{ Item = [string]$r.Item; Bundle = $b }) }
        }
        if ($bundles.Count) {
            & $add ''
            & $add '  Remediation (text for an administrator; this tool never runs a command):'
            foreach ($x in $bundles) { & $add ''; foreach ($ln in @(Get-NRGDlBundleLines -Bundle $x.Bundle -Item $x.Item -Indent 4)) { & $add $ln } }
        }
    }

    # Why each recommendation exists, once, instead of on every list.
    & $add ''
    & $add 'RECOMMENDATION REFERENCE (why each recommendation exists, and where it comes from)'
    & $add ('=' * 100)
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $refRows = @(@($Worksheet.Tenant) + @($Worksheet.Lists | ForEach-Object { $_.Settings }))
    foreach ($r in $refRows) {
        if (-not $r.ControlId -or -not $seen.Add([string]$r.ControlId)) { continue }
        & $add ("[{0}] {1}  (basis: {2})" -f $r.ControlId, (& $t $r.Item), $r.Basis)
        & $wrap $r.Why 4 ''
        & $add ("    Source: {0}" -f $r.Source)
        foreach ($a in @($r.AlsoSee)) { & $add ("    Also:   {0}" -f $a) }
        & $add ''
    }
    & $add 'END OF WORKSHEET'
    return $sb.ToString()
}

function ConvertTo-NRGDlWorksheetCsv {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Worksheet)
    $cell = ${function:ConvertTo-NRGDlCsvCell}
    $cols = @('RowType', 'ListName', 'ListAddress', 'ListType', 'ControlId', 'Item', 'Current', 'Recommended', 'Verdict', 'Basis', 'Detail', 'Why',
              'Source', 'AlsoSee', 'Nist80053Mapping', 'OtherFrameworks', 'Impact', 'Step', 'Command', 'Expect', 'Member', 'MemberUPN', 'MemberType', 'MemberClass')
    $rows = [System.Collections.Generic.List[object]]::new()
    # One row from named values: a column left out is blank, and a value can never land in the wrong column.
    $mk = { param([hashtable] $v) $o = [ordered]@{}; foreach ($k in $cols) { $o[$k] = & $cell $(if ($v.ContainsKey($k)) { $v[$k] } else { '' }) }; $rows.Add([pscustomobject]$o) }
    # A remediation bundle as one row per step, so a Command cell holds exactly ONE command: a cell that joined a preview and an
    # apply with ';' would run both when pasted. The Apply row is its own row, never on the Preview's.
    $mkRem = {
        param([hashtable] $id, $r, $b)
        $base = $id + @{ RowType = 'Remediation'; ControlId = [string]$b.ControlId; Item = [string]$r.Item; Impact = [string]$b.Impact }
        $obs = @($b.Observed.Keys | ForEach-Object { "$_ = $($b.Observed[$_])" }) -join '; '
        if (-not [bool]$b.Available) { & $mk ($base + @{ Step = 'Withheld'; Current = $obs; Detail = [string]$b.Reason }); return }
        $tgt = [string](Get-NRGObjectField -Item $b.Target -Key 'Label' -Default ''); if (-not $tgt) { $tgt = [string](Get-NRGObjectField -Item $b.Target -Key 'Identity' -Default '') }
        & $mk ($base + @{ Step = 'Observed'; Current = $obs; Detail = "Read $([string]$b.ObservedAt). Target: $([string]$b.Target.Kind) $tgt" })
        if ($b.Backup) { & $mk ($base + @{ Step = 'Backup'; Command = [string]$b.Backup.Command; Detail = [string]$b.Backup.Purpose }) }
        & $mk ($base + @{ Step = 'Check'; Command = [string]$b.Precheck.Command; Expect = [string]$b.Precheck.Expect })
        & $mk ($base + @{ Step = 'Preview'; Command = [string]$b.Preview.Command; Detail = [string]$b.Preview.Note })
        & $mk ($base + @{ Step = 'Apply'; Command = [string]$b.Apply.Command; Detail = [string]$b.Apply.Effect })
        & $mk ($base + @{ Step = 'Verify'; Command = [string]$b.Verify.Command; Expect = [string]$b.Verify.Expect })
        if ([bool]$b.Rollback.Available) { & $mk ($base + @{ Step = 'Rollback'; Command = [string]$b.Rollback.Command; Expect = [string]$b.Rollback.Expect }) }
        else { & $mk ($base + @{ Step = 'Rollback'; Detail = 'NOT AVAILABLE: ' + [string]$b.Rollback.Reason }) }
        foreach ($note in @($b.Notes)) { & $mk ($base + @{ Step = 'Note'; Detail = [string]$note }) }
    }
    $h = $Worksheet.Header
    foreach ($kv in @(@('Tenant', "$($h.TenantDomain) $($h.TenantId)".Trim()), @('Generated', $h.Generated), @('Tool', $h.ToolVersion), @('Mode', $h.Mode), @('Handling', $h.Handling))) {
        & $mk @{ RowType = 'Info'; Item = $kv[0]; Current = $kv[1] }
    }
    foreach ($lim in @($Worksheet.Limitations)) { & $mk @{ RowType = 'Limitation'; Item = 'Limitation'; Detail = $lim } }
    & $mk @{ RowType = 'Limitation'; Item = 'Commands'; Detail = $Worksheet.CommandNote }
    & $mk @{ RowType = 'Limitation'; Item = 'NIST mapping'; Detail = $Worksheet.NistMappingNote }
    foreach ($r in @($Worksheet.Tenant)) {
        & $mk @{ RowType = 'Tenant bypass'; ControlId = $r.ControlId; Item = $r.Item; Current = $r.Current; Recommended = $r.Recommended; Verdict = $r.Verdict; Basis = $r.Basis
                 Detail = $r.Detail; Source = $r.Source; Nist80053Mapping = ($r.Nist80053 -join ', ')
                 OtherFrameworks = $r.FrameworkItem }
        foreach ($c in @($r.Inspect)) { & $mk @{ RowType = 'Inspect'; ControlId = $r.ControlId; Item = $r.Item; Step = 'Inspect'; Command = [string]$c; Detail = 'Read-only look at the setting; no change.' } }
        foreach ($b in @($r.Remediations)) { & $mkRem @{} $r $b }
        foreach ($o in @($r.Objects)) { & $mk @{ RowType = 'Tenant bypass entry'; ControlId = $r.ControlId; Item = $r.Item; Current = $o; Verdict = $r.Verdict; Source = $r.Source } }
    }
    foreach ($l in @($Worksheet.Lists)) {
        $id = @{ ListName = $l.Name; ListAddress = $l.Address; ListType = $l.Kind }
        & $mk ($id + @{ RowType = 'Reach'; Item = 'Who can reach it today'; Current = ($l.Reach.Lines -join ' '); Verdict = $l.Reach.Verdict
                        Detail = 'Setting plus tenant-wide bypasses; see the tenant rows for each.'; OtherFrameworks = $l.Reach.FrameworkItem })
        if ([string](Get-NRGObjectField -Item $l -Key 'SyncNote' -Default '')) { & $mk ($id + @{ RowType = 'Directory'; Item = 'Source of truth'; Current = 'Synchronized from on-premises Active Directory'; Detail = [string]$l.SyncNote }) }
        & $mk ($id + @{ RowType = 'Members'; Item = 'Members'; Current = $l.MemberLine })
        foreach ($m in @($l.Members)) { & $mk ($id + @{ RowType = 'Member'; Item = 'Member'; Member = $m.DisplayName; MemberUPN = $m.UPN; MemberType = $m.RecipientType; MemberClass = $m.Class }) }
        foreach ($r in @($l.Settings)) {
            & $mk ($id + @{ RowType = 'Setting'; ControlId = $r.ControlId; Item = $r.Item; Current = $r.Current; Recommended = $r.Recommended; Verdict = $r.Verdict; Basis = $r.Basis
                            Detail = $r.Detail; Source = $r.Source; Nist80053Mapping = ($r.Nist80053 -join ', ')
                            OtherFrameworks = $r.FrameworkItem })
            foreach ($b in @($r.Remediations)) { & $mkRem $id $r $b }
        }
    }
    # Why each recommendation exists, ONCE per control (the text file does the same in its reference section), instead of repeating a
    # paragraph on every setting row of every list, which made the CSV large and slow to filter in a spreadsheet.
    $seenRef = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($r in @(@($Worksheet.Tenant) + @($Worksheet.Lists | ForEach-Object { $_.Settings }))) {
        if (-not $r.ControlId -or -not $seenRef.Add([string]$r.ControlId)) { continue }
        & $mk @{ RowType = 'Reference'; ControlId = $r.ControlId; Item = $r.Item; Recommended = $r.Recommended; Basis = $r.Basis; Why = $r.Why; Source = $r.Source
                 AlsoSee = ($r.AlsoSee -join '; '); Nist80053Mapping = ($r.Nist80053 -join ', '); OtherFrameworks = $r.FrameworkItem }
    }
    return (($rows | ConvertTo-Csv -NoTypeInformation) -join "`r`n") + "`r`n"
}

function Publish-NRGDistributionListWorksheet {
    <#
    .SYNOPSIS
        Writes <OutputBase>-distribution-lists.txt and .csv from a worksheet model,
        through the restricted-file writer. Returns the two paths.
    .PARAMETER OutputBase
        Path without extension, for example .\output\contoso-20261002-101500.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] $Worksheet,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $OutputBase
    )

    # Tenant inventory is written only through the restricted writer. No plain fallback.
    if (-not (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue)) {
        throw 'Set-NRGSensitiveFileContent is not loaded; refusing to write tenant inventory without the restricted-file writer.'
    }
    if ($OutputBase -match '\.\.[\\/]') { throw "OutputBase rejected: contains '..[/\\]' traversal sequence." }
    $dir = Split-Path -Parent $OutputBase
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }

    $txtPath = "$OutputBase-distribution-lists.txt"
    $csvPath = "$OutputBase-distribution-lists.csv"
    Set-NRGSensitiveFileContent -Path $txtPath -Content (ConvertTo-NRGDlWorksheetText -Worksheet $Worksheet)
    Set-NRGSensitiveFileContent -Path $csvPath -Content (ConvertTo-NRGDlWorksheetCsv -Worksheet $Worksheet)
    return [ordered]@{ TextPath = $txtPath; CsvPath = $csvPath }
}

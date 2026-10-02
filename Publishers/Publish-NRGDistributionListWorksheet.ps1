#Requires -Version 7.0
#
# Publish-NRGDistributionListWorksheet.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Turn the distribution-list scan into a plain worksheet an administrator
#          can work through to close each list's email exposure: a text file
#          (<base>-distribution-lists.txt) and a CSV (<base>-distribution-lists.csv),
#          one row per list.
#
# Sets:     nothing
# Consumes: findings (DL-*) and the EXO-DistributionLists raw-data envelope.
# Cmdlets:  none against a tenant. File writes go through Set-NRGSensitiveFileContent,
#           the restricted-file writer the results JSON uses (the output holds the
#           tenant's list inventory and member names).
#
# THE COMMANDS ARE TEXT
# ---------------------
# For each list that needs a change the worksheet prints the command an Exchange
# administrator would run. The commands are data in Config/distribution-list-hardening.json,
# filled in by Format-NRGDistributionListCommand, and written into the worksheet as
# lines of text. Nothing in this file, or anywhere in the module, executes them: the
# tool is read-only toward the tenant. A command that needs the administrator to supply
# a value (a quoted placeholder), or that needs a human decision (removing a member,
# or an alternative to the main change), is printed commented out, so pasting the whole
# block cannot apply it.
#
# ONE MODEL, TWO RENDERINGS
# -------------------------
# The text and the CSV are both rendered from Get-NRGDistributionListWorksheetModel, and
# every "finding" sentence is the finding's own Detail, verbatim. A verdict or a limit
# ("the first 2000 members were read") therefore reads the same in the worksheet, the
# CSV and the results JSON. A list with no finding at all is "not assessed", never
# "fine": absence of a finding is not evidence.

# Display order and wording for a list's overall state.
function Get-NRGDLStateLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $State)
    switch ($State) {
        'Error'         { return 'ERROR' }
        'Gap'           { return 'NEEDS ATTENTION' }
        'Partial'       { return 'PARTLY PROTECTED' }
        'NotApplicable' { return 'NOT FULLY ASSESSED' }
        'Satisfied'     { return 'OK IN WHAT WAS READ' }
        default         { return 'NOT ASSESSED' }
    }
}

function Get-NRGDistributionListWorksheetModel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [AllowNull()] $RawData
    )

    $rank    = @{ 'Error' = 5; 'Gap' = 4; 'Partial' = 3; 'NotApplicable' = 2; 'Satisfied' = 1 }
    $sevRank = @{ 'Critical' = 5; 'High' = 4; 'Medium' = 3; 'Low' = 2; 'Informational' = 1 }

    $dl = @($Findings | Where-Object { ([string](Get-NRGObjectField -Item $_ -Key 'ControlId' -Default '')) -like 'DL-*' })
    $data = Get-NRGObjectField -Item $RawData -Key 'Data' -Default $null
    $storedLists = Get-NRGRuleList -Item $data -Key 'Lists'
    $lists = @()
    if ($null -ne $storedLists) { $lists = @($storedLists) }

    $byInstance = @{}
    $tenantLevel = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $dl) {
        $inst = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $f -Key 'Instance' -Default '') -MaxLength 320
        if (-not $inst) { $tenantLevel.Add($f); continue }
        if (-not $byInstance.ContainsKey($inst)) { $byInstance[$inst] = [System.Collections.Generic.List[object]]::new() }
        $byInstance[$inst].Add($f)
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($list in $lists) {
        $inst  = Get-NRGDistributionListInstance -List $list
        $name  = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $list -Key 'DisplayName' -Default (Get-NRGObjectField -Item $list -Key 'Name' -Default '')) -MaxLength 120
        $addr  = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $list -Key 'PrimarySmtpAddress' -Default '') -MaxLength 320
        $kind  = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $list -Key 'Kind' -Default 'Unknown type') -MaxLength 60
        $isDynamic = (ConvertTo-NRGDLBoolean (Get-NRGObjectField -Item $list -Key 'IsDynamic' -Default $false)) -eq $true
        $mine = @()
        if ($byInstance.ContainsKey($inst)) { $mine = @($byInstance[$inst] | Sort-Object { [string](Get-NRGObjectField -Item $_ -Key 'ControlId' -Default '') }) }

        # Worst state across this list's findings. No finding at all is not a pass.
        $worst = 'NotApplicable'
        $worstRank = 0
        foreach ($f in $mine) {
            $st = [string](Get-NRGObjectField -Item $f -Key 'State' -Default 'NotApplicable')
            $r = if ($rank.ContainsKey($st)) { $rank[$st] } else { 2 }
            if ($r -gt $worstRank) { $worstRank = $r; $worst = $st }
        }
        if ($mine.Count -eq 0) { $worst = 'NotApplicable'; $worstRank = $rank['NotApplicable'] }

        $topSev = ''; $topSevRank = 0
        $findingText = [System.Collections.Generic.List[string]]::new()
        $recommended = [System.Collections.Generic.List[string]]::new()
        $actions = [System.Collections.Generic.List[object]]::new()
        foreach ($f in $mine) {
            $st  = [string](Get-NRGObjectField -Item $f -Key 'State' -Default 'NotApplicable')
            $cid = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
            $sev = [string](Get-NRGObjectField -Item $f -Key 'Severity' -Default 'Informational')
            $detail = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $f -Key 'Detail' -Default '') -MaxLength 1200
            $req = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $f -Key 'RequiredValue' -Default '') -MaxLength 300
            if ($st -eq 'Satisfied') { continue }
            # A not-assessed Detail already begins "Not assessed", so it is not prefixed twice.
            $stWord = switch ($st) { 'Gap' { ' Gap' } 'Partial' { ' Partial' } 'Error' { ' Error' } default { '' } }
            $sevText = if ($st -in @('Gap', 'Partial') -and $sev) { " ($sev)" } else { '' }
            $findingText.Add("${cid}${stWord}${sevText}: $detail")
            if ($st -in @('Gap', 'Partial')) {
                if ($req) { $recommended.Add("${cid}: $req") }
                $actions.Add([pscustomobject]@{ ControlId = $cid; Finding = $f })
                $sr = if ($sevRank.ContainsKey($sev)) { $sevRank[$sev] } else { 0 }
                if ($sr -gt $topSevRank) { $topSevRank = $sr; $topSev = $sev }
            } else {
                $recommended.Add("${cid}: check by hand (not assessed; the finding says what could not be read)")
            }
        }
        if ($mine.Count -eq 0) {
            $findingText.Add('No finding was produced for this list, so it was not assessed.')
            $recommended.Add('Re-run the scan; if this repeats, check the Exceptions in the results JSON')
        } elseif ($findingText.Count -eq 0) {
            $findingText.Add('Nothing to change in the settings that were read.')
            $recommended.Add('No change')
        }

        $sa = Get-NRGDistributionListSenderAccess -List $list
        $owners = Get-NRGDLNamedItems -Item $list -Key 'ManagedBy' -NamesKey 'ManagedByWithDisplayNames'
        $ownerText = if (-not $owners.Known) { 'not read' }
                     elseif ($owners.Count -eq 0) { 'none' }
                     elseif ($owners.Names.Count -gt 0) { (@($owners.Names) -join '; ') }
                     else { "$($owners.Count) (names not returned)" }

        $mStatus = [string](Get-NRGObjectField -Item $list -Key 'MembersStatus' -Default 'NotRead')
        $mNote   = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $list -Key 'MembersNote' -Default '') -MaxLength 400
        $members = Get-NRGRuleList -Item $list -Key 'Members'
        $external = Get-NRGRuleList -Item $list -Key 'ExternalMembers'
        $memberList = @(); if ($null -ne $members)  { $memberList = @($members) }
        $externalList = @(); if ($null -ne $external) { $externalList = @($external) }
        $memberCount = switch ($mStatus) {
            'Read'      { if ($isDynamic) { "$($memberList.Count) (calculated snapshot)" } else { "$($memberList.Count)" } }
            'Truncated' { "$($memberList.Count)+ (the first $($memberList.Count) were read; the list is larger)" }
            default     { 'not read' }
        }
        $externalText = if ($mStatus -notin @('Read', 'Truncated')) { 'not read' }
                        elseif ($externalList.Count -eq 0) { 'none found' }
                        else {
                            $shown = @($externalList | Select-Object -First 25 | ForEach-Object {
                                $dn = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '') -MaxLength 120
                                $up = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $_ -Key 'UserPrincipalName' -Default '') -MaxLength 320
                                if ($dn -and $up) { "$dn <$up>" } elseif ($up) { $up } else { $dn }
                            })
                            $more = if ($externalList.Count -gt 25) { " (+$($externalList.Count - 25) more)" } else { '' }
                            "$($externalList.Count): " + ($shown -join '; ') + $more
                        }
        $hidden = ConvertTo-NRGDLBoolean (Get-NRGObjectField -Item $list -Key 'HiddenFromAddressListsEnabled' -Default $null)
        $listed = if ($null -eq $hidden) { 'not read' } elseif ($hidden) { 'No (hidden)' } else { 'Yes' }

        $rows.Add([pscustomobject]@{
            List          = $(if ($name) { $name } else { $addr })
            Address       = $addr
            Type          = $kind
            IsDynamic     = $isDynamic
            WhoCanSend    = $sa.Summary
            Owners        = $ownerText
            MemberCount   = $memberCount
            ExternalMembers = $externalText
            ListedInAddressBook = $listed
            State         = $worst
            Status        = (Get-NRGDLStateLabel -State $worst)
            Severity      = $topSev
            Finding       = (@($findingText) -join ' | ')
            FindingLines  = @($findingText)
            Recommended   = (@($recommended) -join '; ')
            MembersStatus = $mStatus
            ReadLimit     = $(if ($mStatus -in @('Read')) { $(if ($isDynamic) { $mNote } else { '' }) } elseif ($mNote) { $mNote } else { "Members not read ($mStatus)" })
            Actions       = @($actions)
            Members       = $memberList
            ExternalList  = $externalList
            Instance      = $inst
            Guid          = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $list -Key 'Guid' -Default '') -MaxLength 64
            Rank          = $worstRank
            SeverityRank  = $topSevRank
        })
    }

    # Findings with no list to hang on (the inventory could not be read, or one kind of
    # list could not): one note per distinct sentence, with the controls it covers.
    $notes = [System.Collections.Generic.List[object]]::new()
    $groups = $tenantLevel | Group-Object { ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $_ -Key 'Detail' -Default '') -MaxLength 1200 }
    foreach ($g in @($groups)) {
        $ids = @($g.Group | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'ControlId' -Default '') } | Sort-Object -Unique)
        $notes.Add([pscustomobject]@{ ControlIds = $ids; Detail = [string]$g.Name })
    }

    $ordered = @($rows | Sort-Object @{ Expression = { $_.Rank }; Descending = $true }, @{ Expression = { $_.SeverityRank }; Descending = $true }, @{ Expression = { $_.List } })
    $counts = [ordered]@{ NeedsAttention = 0; PartlyProtected = 0; NotFullyAssessed = 0; OkInWhatWasRead = 0; Error = 0 }
    foreach ($r in $ordered) {
        switch ($r.State) {
            'Gap'           { $counts['NeedsAttention']++ }
            'Partial'       { $counts['PartlyProtected']++ }
            'NotApplicable' { $counts['NotFullyAssessed']++ }
            'Satisfied'     { $counts['OkInWhatWasRead']++ }
            'Error'         { $counts['Error']++ }
        }
    }

    return [pscustomobject]@{
        Rows        = $ordered
        TenantNotes = @($notes)
        Counts      = $counts
        ListCount   = $ordered.Count
    }
}

# The command lines for one row, as text. Returns objects: Text (the line to print),
# Commented (it must not be run as printed), Intent, Impact.
function Get-NRGDistributionListWorksheetCommands {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Row, [AllowEmptyCollection()] [object[]] $Templates = @())

    $applies = if ($Row.IsDynamic) { 'Dynamic' } else { 'Distribution' }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($action in @($Row.Actions)) {
        $cid = [string]$action.ControlId
        foreach ($t in @($Templates | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'ControlId' -Default '') -eq $cid -and [string](Get-NRGObjectField -Item $_ -Key 'AppliesTo' -Default '') -eq $applies })) {
            $kind    = [string](Get-NRGObjectField -Item $t -Key 'Kind' -Default 'Primary')
            $intent  = [string](Get-NRGObjectField -Item $t -Key 'Intent' -Default '')
            $impact  = [string](Get-NRGObjectField -Item $t -Key 'Impact' -Default '')
            $command = [string](Get-NRGObjectField -Item $t -Key 'Command' -Default '')

            if ($kind -eq 'Instruction' -or -not $command) {
                $out.Add([pscustomobject]@{ ControlId = $cid; Kind = $kind; Intent = $intent; Impact = $impact; Text = ''; Commented = $true; Unsafe = $false })
                continue
            }

            # {Member} commands are one line per outside member.
            if ($command.Contains('{Member}')) {
                foreach ($m in @($Row.ExternalList | Select-Object -First 25)) {
                    $upn = [string](Get-NRGObjectField -Item $m -Key 'UserPrincipalName' -Default '')
                    $text = Format-NRGDistributionListCommand -Template $command -Identity $Row.Address -Member $upn
                    if ($null -eq $text) {
                        $out.Add([pscustomobject]@{ ControlId = $cid; Kind = $kind; Intent = $intent; Impact = $impact; Text = ''; Commented = $true; Unsafe = $true })
                    } else {
                        $out.Add([pscustomobject]@{ ControlId = $cid; Kind = $kind; Intent = $intent; Impact = $impact; Text = $text; Commented = $true; Unsafe = $false })
                    }
                }
                continue
            }

            $text = Format-NRGDistributionListCommand -Template $command -Identity $Row.Address
            if ($null -eq $text) {
                $out.Add([pscustomobject]@{ ControlId = $cid; Kind = $kind; Intent = $intent; Impact = $impact; Text = ''; Commented = $true; Unsafe = $true })
                continue
            }
            # Commented out unless it is the main change and needs nothing from the reader.
            $needsEdit = $text.Contains("'<")
            $commented = ($kind -ne 'Primary') -or $needsEdit
            $out.Add([pscustomobject]@{ ControlId = $cid; Kind = $kind; Intent = $intent; Impact = $impact; Text = $text; Commented = $commented; Unsafe = $false })
        }
    }
    return @($out)
}

function ConvertTo-NRGDLCsvLine {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string[]] $Header, [Parameter(Mandatory)] $Record)
    $cells = foreach ($h in $Header) {
        $v = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Record -Key $h -Default '') -MaxLength 8000
        '"' + ((ConvertTo-NRGCsvCell $v) -replace '"', '""') + '"'
    }
    return ($cells -join ',')
}

function Publish-NRGDistributionListWorksheet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Metadata,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [AllowNull()] $RawData,
        [Parameter(Mandatory)] [string] $OutputDirectory,
        [Parameter(Mandatory)] [string] $BaseName,
        [switch] $NoMembers
    )

    if ($BaseName -match '[\\/]' -or $BaseName -match '\.\.') { throw "BaseName rejected: '$BaseName' must be a file name stem, not a path." }
    if (-not (Test-Path -LiteralPath $OutputDirectory)) { [void][System.IO.Directory]::CreateDirectory($OutputDirectory) }

    $model = Get-NRGDistributionListWorksheetModel -Findings $Findings -RawData $RawData
    $templates = @(Get-NRGDistributionListHardeningTemplates)
    $data = Get-NRGObjectField -Item $RawData -Key 'Data' -Default $null
    $stats = Get-NRGObjectField -Item $data -Key 'Stats' -Default $null
    $limits = Get-NRGObjectField -Item $data -Key 'Limits' -Default $null
    $scope = Get-NRGObjectField -Item $data -Key 'Scope' -Default $null
    $status = Get-NRGObjectField -Item $data -Key 'SectionStatus' -Default $null

    $tenant  = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Metadata -Key 'TenantDomain' -Default 'unknown tenant') -MaxLength 120
    $date    = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'yyyy-MM-dd HH:mm')) -MaxLength 60
    $version = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Metadata -Key 'ToolVersion' -Default 'unknown') -MaxLength 30
    $memberLimit = [int](Get-NRGObjectField -Item $limits -Key 'MemberLimit' -Default 0)

    $t = [System.Collections.Generic.List[string]]::new()
    $rule = '=' * 78
    $t.Add($rule)
    $t.Add('NRG-Assessment: distribution list worksheet')
    $t.Add($rule)
    $t.Add("Tenant:        $tenant")
    $t.Add("Generated:     $date")
    $t.Add("Tool version:  $version")
    $t.Add('')
    $t.Add('READ THIS FIRST')
    $t.Add('  * This scan only READ. It did not create, add, remove or change any list, member')
    $t.Add('    or setting. Every command below is text for an administrator to review and run')
    $t.Add('    by hand; this tool never runs them.')
    $t.Add('  * A line that starts with # is a note, or a command that needs a value from you or')
    $t.Add('    a decision before it is safe to use. Nothing in this file has been run.')
    $t.Add('  * INTERNAL USE. This file lists the tenant''s lists, owners and members (name and')
    $t.Add('    sign-in name only). It is written with restricted permissions; do not send it on')
    $t.Add('    without review.')
    $t.Add('')
    $t.Add('WHAT WAS AND WAS NOT ASSESSED')
    $t.Add("  Assessed:      $($model.ListCount) list(s) read from Exchange Online: " +
        "$([int](Get-NRGObjectField -Item $stats -Key 'DistributionGroups' -Default 0)) distribution list(s), " +
        "$([int](Get-NRGObjectField -Item $stats -Key 'MailEnabledSecurityGroups' -Default 0)) mail-enabled security group(s), " +
        "$([int](Get-NRGObjectField -Item $stats -Key 'DynamicGroups' -Default 0)) dynamic distribution list(s).")
    $limitText = if ($memberLimit -gt 0) { " Up to $memberLimit member(s) per list." } else { '' }
    $t.Add("  What was read: who can send to each list, its owners, who can join, and its members (display name and sign-in name).$limitText")
    $notCovered = Get-NRGRuleList -Item $scope -Key 'NotCovered'
    if ($null -ne $notCovered) { foreach ($n in @($notCovered)) { $t.Add("  Not assessed:  $(ConvertTo-NRGDLText -Value $n -MaxLength 300)") } }
    foreach ($n in @($model.TenantNotes)) {
        $t.Add("  NOT READ:      $($n.Detail) [$($n.ControlIds -join ', ')]")
    }
    $sectionLines = @()
    if ($null -ne $status -and $status -is [System.Collections.IDictionary]) {
        $sectionLines = @($status.Keys | Where-Object { [string]$status[$_] -ne 'Collected' } | Sort-Object | ForEach-Object { "$_ = $($status[$_])" })
    } elseif ($null -ne $status) {
        $sectionLines = @($status.PSObject.Properties | Where-Object { [string]$_.Value -ne 'Collected' } | ForEach-Object { "$($_.Name) = $($_.Value)" })
    }
    if ($sectionLines.Count -gt 0) { $t.Add('  Collection:    not every section completed (' + ($sectionLines -join ', ') + '); see the list notes below and the Exceptions in the results JSON.') }
    $unreadRows = @($model.Rows | Where-Object { $_.MembersStatus -ne 'Read' })
    if ($unreadRows.Count -gt 0) {
        $t.Add("  Member limits: $($unreadRows.Count) list(s) had members not read in full; each says why on its own entry.")
    }
    $t.Add('')
    $t.Add('SUMMARY')
    $t.Add("  Needs attention:       $($model.Counts['NeedsAttention'])")
    $t.Add("  Partly protected:      $($model.Counts['PartlyProtected'])")
    $t.Add("  Not fully assessed:    $($model.Counts['NotFullyAssessed'])")
    $t.Add("  OK in what was read:   $($model.Counts['OkInWhatWasRead'])   (this is not a statement that the list is secure)")
    if ($model.Counts['Error'] -gt 0) { $t.Add("  Error:                 $($model.Counts['Error'])") }
    $t.Add('')

    $writeRow = {
        param($Row, [int] $Number)
        $kv = { param([string] $Key, $Value) $t.Add(('   {0,-24}{1}' -f ($Key + ':'), $Value)) }
        $t.Add(('-' * 78))
        $t.Add(("{0}. {1}  <{2}>   [{3}{4}]" -f $Number, $Row.List, $Row.Address, $Row.Status, $(if ($Row.Severity) { " - $($Row.Severity)" } else { '' })))
        & $kv 'Type' $Row.Type
        & $kv 'Who can send to it' $Row.WhoCanSend
        & $kv 'Owners' $Row.Owners
        & $kv 'Members' $Row.MemberCount
        & $kv 'Outside members' $Row.ExternalMembers
        & $kv 'Listed in address book' $Row.ListedInAddressBook
        foreach ($line in @($Row.FindingLines)) { & $kv 'Finding' $line }
        & $kv 'Recommended setting' $Row.Recommended
        if ($Row.ReadLimit) { & $kv 'Read limit' $Row.ReadLimit }
        $cmds = @(Get-NRGDistributionListWorksheetCommands -Row $Row -Templates $templates)
        if ($cmds.Count -gt 0) {
            $t.Add('   To harden (TEXT ONLY: an administrator runs these after review; this tool did not):')
            foreach ($c in $cmds) {
                $t.Add("     # $($c.ControlId) $($c.Intent)")
                if ($c.Unsafe) {
                    $t.Add('     # (no command printed: this address has characters that are not safe to paste; find the list or member by hand)')
                } elseif ($c.Text) {
                    $prefix = if ($c.Commented) { '# ' } else { '' }
                    $t.Add("     $prefix$($c.Text)")
                    if ($c.Kind -eq 'Alternative') { $t.Add('     # (alternative: use this instead of the main change only if outside senders must keep writing to the list)') }
                    if ($c.Kind -eq 'ReviewFirst') { $t.Add('     # (review first: remove a member only if the list owner confirms it should not receive the list)') }
                    if ($c.Text.Contains("'<")) { $t.Add('     # (replace the quoted <placeholder> with a real address, then remove the leading #)') }
                }
                if ($c.Impact) { $t.Add("     #   What could break: $($c.Impact)") }
            }
        }
        $t.Add('   Admin decision:  [ ] fix    [ ] accept the risk    [ ] not needed        Done: ____  Date: ________')
    }

    $n = 0
    $fix = @($model.Rows | Where-Object { $_.State -in @('Error', 'Gap', 'Partial') })
    if ($fix.Count -gt 0) {
        $t.Add('LISTS TO FIX (worst first)')
        foreach ($r in $fix) { $n++; & $writeRow $r $n }
        $t.Add('')
    }
    $unsure = @($model.Rows | Where-Object { $_.State -eq 'NotApplicable' })
    if ($unsure.Count -gt 0) {
        $t.Add('LISTS NOT FULLY ASSESSED (something could not be read; do not treat these as clean)')
        foreach ($r in $unsure) { $n++; & $writeRow $r $n }
        $t.Add('')
    }
    $ok = @($model.Rows | Where-Object { $_.State -eq 'Satisfied' })
    if ($ok.Count -gt 0) {
        $t.Add('LISTS WITH NOTHING TO CHANGE IN WHAT WAS READ')
        $t.Add(('-' * 78))
        foreach ($r in $ok) {
            $n++
            $t.Add(('{0}. {1}  <{2}>' -f $n, $r.List, $r.Address))
            $t.Add("     Who can send: $($r.WhoCanSend)")
            $t.Add("     Owners: $($r.Owners)   Members: $($r.MemberCount)   Outside members: $($r.ExternalMembers)")
        }
        $t.Add('')
    }
    if ($model.ListCount -eq 0) {
        $t.Add('NO LISTS')
        $t.Add('  No distribution list was returned to this account. If a section is shown as not read above,')
        $t.Add('  that is the reason; otherwise a role-scoped administrator sees only the lists in that scope, so')
        $t.Add('  this does not prove none exist.')
        $t.Add('')
    }

    if (-not $NoMembers) {
        $t.Add($rule)
        $t.Add('MEMBERS BY LIST (display name and sign-in name only)')
        $t.Add($rule)
        foreach ($r in @($model.Rows | Sort-Object List)) {
            $t.Add('')
            $t.Add("$($r.List)  <$($r.Address)>   members: $($r.MemberCount)")
            if ($r.Members.Count -eq 0) {
                $t.Add('    (none listed)')
            } else {
                foreach ($m in @($r.Members)) {
                    $dn = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $m -Key 'DisplayName' -Default '') -MaxLength 120
                    $up = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $m -Key 'UserPrincipalName' -Default '') -MaxLength 320
                    $t.Add("    $up    $dn")
                }
            }
            if ($r.ReadLimit) { $t.Add("    ($($r.ReadLimit))") }
        }
        $t.Add('')
    }

    $textPath = Join-Path $OutputDirectory "$BaseName-distribution-lists.txt"
    $csvPath  = Join-Path $OutputDirectory "$BaseName-distribution-lists.csv"
    Set-NRGSensitiveFileContent -Path $textPath -Content ((@($t) -join "`n") + "`n")

    $header = @('List', 'Address', 'Type', 'WhoCanSendToIt', 'Owners', 'MemberCount', 'ExternalMembers', 'Status', 'Severity', 'Finding', 'RecommendedSetting', 'ReadLimit')
    $csv = [System.Collections.Generic.List[string]]::new()
    $csv.Add(($header | ForEach-Object { '"' + $_ + '"' }) -join ',')
    foreach ($r in @($model.Rows)) {
        $rec = [ordered]@{
            List = $r.List; Address = $r.Address; Type = $r.Type; WhoCanSendToIt = $r.WhoCanSend; Owners = $r.Owners
            MemberCount = $r.MemberCount; ExternalMembers = $r.ExternalMembers; Status = $r.Status; Severity = $r.Severity
            Finding = $r.Finding; RecommendedSetting = $r.Recommended; ReadLimit = $r.ReadLimit
        }
        $csv.Add((ConvertTo-NRGDLCsvLine -Header $header -Record $rec))
    }
    # A list the scan could not see still gets a row: a CSV that omits it reads as complete.
    foreach ($note in @($model.TenantNotes)) {
        $rec = [ordered]@{
            List = '(not read)'; Address = ''; Type = ''; WhoCanSendToIt = ''; Owners = ''; MemberCount = ''; ExternalMembers = ''
            Status = (Get-NRGDLStateLabel -State 'NotApplicable'); Severity = ''
            Finding = ("{0}: {1}" -f ($note.ControlIds -join ', '), $note.Detail)
            RecommendedSetting = 'Fix the cause and run the scan again'; ReadLimit = ''
        }
        $csv.Add((ConvertTo-NRGDLCsvLine -Header $header -Record $rec))
    }
    Set-NRGSensitiveFileContent -Path $csvPath -Content ((@($csv) -join "`r`n") + "`r`n") -Encoding ([System.Text.UTF8Encoding]::new($true))

    return [pscustomobject]@{ TextPath = $textPath; CsvPath = $csvPath; ListCount = $model.ListCount; Counts = $model.Counts }
}

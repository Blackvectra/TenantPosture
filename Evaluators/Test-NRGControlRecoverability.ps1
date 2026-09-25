#Requires -Version 7.0
#
# Test-NRGControlRecoverability.ps1
# Dependencies: Test-NRGSectionCollected, Get-NRGNestedProperty, Get-NRGObjectField,
#               Get-NRGControlById, Get-NRGFrameworkCitations, Add-NRGFinding
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Contingency planning — what survives a deletion.
#
#          800-53 CP was the thinnest evidenceable family in the tool: two
#          controls, one of them break-glass accounts. That is the family a
#          client asks about the morning after ransomware, and the tool had
#          almost nothing to say.
#
#          The gap matters because of an assumption clients make and nobody
#          corrects: Microsoft is hosting the mail, so the mail is backed up.
#          It is not. Exchange Online keeps deleted items for a configurable
#          window that defaults to 14 days, keeps a deleted mailbox for 30 days
#          and then destroys it, and keeps a departed user's OneDrive for a
#          configurable period after which it is gone. None of that is a
#          backup, and all three windows are shorter than the time it usually
#          takes to notice something is missing.
#
# Controls: EXO-9.1 (hold or retention coverage), EXO-9.2 (deleted item
#           window), SPO-4.1 (departed-user OneDrive retention).
#
# Consumes: EXO-Inventory and SharePoint raw data. No Graph, no direct EXO calls.
#

# ── EXO-9.1 Mailboxes Protected by Hold or Retention Policy ──────────────────
function Test-NRGControlEXOMailboxHoldCoverage {
    [CmdletBinding()] param()
    $cid = 'EXO-9.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO inventory not collected'
        return
    }
    if (-not (Test-NRGSectionCollected $inv 'MailboxRecoverability')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Mailbox recoverability was not collected; not assessed.'
        return
    }

    $rec   = Get-NRGNestedProperty -Object $inv -Path 'Data.MailboxRecoverability' -Default $null
    $total = [int](Get-NRGObjectField -Item $rec -Key 'TotalMailboxes' -Default 0)
    $none  = [int](Get-NRGObjectField -Item $rec -Key 'WithoutHold'    -Default 0)

    # A tenant with no mailboxes is not a pass — it is a query that returned
    # nothing useful, and there is no posture to report either way.
    if ($total -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No mailboxes were enumerated, so hold coverage could not be assessed.'
        return
    }

    # Without the organization's hold list, a mailbox with no hold of its own
    # may still be covered by an org-wide retention policy. Replayed JSON
    # predating the field keeps its previous reading.
    if ($none -gt 0 -and (Get-NRGObjectField -Item $rec -Key 'OrgHoldsRead' -Default $true) -eq $false) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "$none mailbox(es) carry no hold of their own, but the organization-wide retention policies (Get-OrganizationConfig InPlaceHolds) could not be read, so whether a tenant-wide policy covers them was not assessed."
        return
    }

    if ($none -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -CurrentValue "All $total mailboxes covered by a hold or retention policy" `
            -Detail "Every mailbox is covered by a litigation hold, a Purview retention policy or an eDiscovery hold (organization-wide policies applied unless the mailbox is excluded), so content survives deletion of the item, the mailbox and the account."
        return
    }

    $pct = [int][Math]::Round(100 * $none / $total)
    $sample = @(Get-NRGObjectField -Item $rec -Key 'WithoutHoldSample' -Default @())

    # Partial rather than Gap when it is a minority: a tenant part-way through
    # a retention rollout is in a materially better position than one with
    # nothing, and collapsing both to Gap tells the operator nothing about
    # which they are.
    #
    # Written as two branches with LITERAL state values rather than one call
    # taking -State $state. Get-NRGControlAutomationAudit proves a control can
    # discriminate by reading the literal -State arguments out of the syntax
    # tree; a variable is opaque to it and the control gets classified
    # SingleVerdict — indistinguishable from one that can only ever return one
    # answer.
    $current  = "$none of $total mailboxes ($pct%) have no hold and no retention policy"
    $required = 'Every mailbox covered by a retention policy or litigation hold'
    $detail   = "$none mailbox(es) are covered by no hold and no retention policy. If one of those accounts is deleted, Microsoft keeps the mailbox for 30 days and then destroys it permanently — there is no backup behind that. A tenant-wide Purview retention policy is the maintainable fix; per-mailbox litigation hold does not follow new starters."

    if ($pct -ge 50) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity $ctrl.Severity -FrameworkIds $cit `
            -CurrentValue $current -RequiredValue $required -Detail $detail `
            -Remediation $ctrl.Remediation -AffectedObjects $sample
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Medium' -FrameworkIds $cit `
            -CurrentValue $current -RequiredValue $required -Detail $detail `
            -Remediation $ctrl.Remediation -AffectedObjects $sample
    }
}

# ── EXO-9.2 Deleted Item Retention Window at Maximum ─────────────────────────
function Test-NRGControlEXODeletedItemRetention {
    [CmdletBinding()] param()
    $cid = 'EXO-9.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO inventory not collected'
        return
    }
    if (-not (Test-NRGSectionCollected $inv 'MailboxRecoverability')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Mailbox recoverability was not collected; not assessed.'
        return
    }

    $rec   = Get-NRGNestedProperty -Object $inv -Path 'Data.MailboxRecoverability' -Default $null
    $total = [int](Get-NRGObjectField -Item $rec -Key 'TotalMailboxes'      -Default 0)
    $short = [int](Get-NRGObjectField -Item $rec -Key 'ShortRetentionCount' -Default 0)
    $min   =      Get-NRGObjectField -Item $rec -Key 'MinRetentionDays'     -Default $null

    if ($total -eq 0 -or $null -eq $min) {
        # RetainDeletedItemsFor arrives in a shape that varies by EXO module
        # version. If nothing parsed, that is an unknown, not a pass.
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'The deleted-item retention window could not be read from any mailbox, so it was not assessed.'
        return
    }

    if ($short -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -CurrentValue "All $total mailboxes retain deleted items for 30 days" `
            -Detail 'Every mailbox retains deleted items for the full 30-day maximum, so an item deleted by a user or an attacker stays recoverable for as long as Exchange Online allows without a hold.'
        return
    }

    $sample = @(Get-NRGObjectField -Item $rec -Key 'ShortRetentionSample' -Default @())
    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
        -Severity $ctrl.Severity -FrameworkIds $cit `
        -CurrentValue "$short of $total mailboxes retain deleted items for under 30 days (lowest: $min)" `
        -RequiredValue 'RetainDeletedItemsFor = 30 on every mailbox' `
        -Detail "$short mailbox(es) keep deleted items for fewer than 30 days, the lowest being $min. Business email compromise and ransomware are routinely discovered later than that, and mail an attacker deleted to cover their tracks is unrecoverable once the window closes — including the evidence of what they did. 30 days is the maximum without a hold." `
        -Remediation $ctrl.Remediation -AffectedObjects $sample
}

# ── SPO-4.1 Departed-User OneDrive Retention Configured ──────────────────────
function Test-NRGControlSPODepartedUserRetention {
    [CmdletBinding()] param()
    $cid = 'SPO-4.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SharePoint data not collected'
        return
    }
    if (-not (Test-NRGSectionCollected $spo 'TenantSettings')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'TenantSettings was not collected; not assessed.'
        return
    }

    $days = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.DeletedUserPersonalSiteRetentionPeriodInDays' -Default $null
    if ($null -eq $days) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'DeletedUserPersonalSiteRetentionPeriodInDays was not returned by the tenant, so departed-user OneDrive retention was not assessed.'
        return
    }

    $d = [int]$days
    # 30 is the Microsoft default and the value that bites: it is routinely
    # shorter than the time it takes anyone to discover that a leaver held the
    # only copy of something.
    if ($d -ge 365) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -CurrentValue "$d days" `
            -Detail "A departed user's OneDrive is retained for $d days, which leaves a realistic window to discover and retrieve content only that person held."
    } elseif ($d -gt 30) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Low' -FrameworkIds $cit `
            -CurrentValue "$d days" -RequiredValue 'At least 365 days' `
            -Detail "A departed user's OneDrive is retained for $d days — longer than the 30-day default, but still short of a full business cycle. Content nobody realises is missing until year-end is already gone." `
            -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity $ctrl.Severity -FrameworkIds $cit `
            -CurrentValue "$d days (Microsoft default is 30)" -RequiredValue 'At least 365 days' `
            -Detail "A departed user's OneDrive is destroyed after $d days. That is frequently shorter than the time it takes anyone to realise the leaver held the only copy of a document, and once the period elapses the content is unrecoverable — there is no backup behind it." `
            -Remediation $ctrl.Remediation
    }
}

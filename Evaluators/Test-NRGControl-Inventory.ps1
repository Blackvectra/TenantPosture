#Requires -Version 7.0
#
# Test-NRGControl-Inventory.ps1  (v4.5.5)
# Named/per-object inventory evaluators — these produce findings with
# AffectedObjects arrays so the HTML report can show specific named users,
# mailboxes, and apps rather than just counts.
#
# These are the "blood test" findings — they name EXACTLY who and what is at risk.
#

# Returns $true only when the named collector section was actually collected.
# Used for both EXO-Inventory and AAD-Inventory, which share this shape.
#
# Every such list defaults to @() and each query has its own
# try/catch, so the collector reports Success = $true even when an individual
# query failed (throttling and transient 403s are routine on real tenants).
# That makes an empty list ambiguous — "scanned, found nothing" or "never
# scanned" — and reading it as compliance produces a false clean bill of health
# on exactly the checks a client is paying for. Any evaluator about to conclude
# Satisfied from an EMPTY list must gate on this first.
#
# Absent SectionStatus (data captured before this map existed) is treated as
# collected so a replayed older JSON keeps its previous behaviour rather than
# silently turning every inventory finding into NotApplicable.
function Test-NRGInventorySectionCollected {
    [CmdletBinding()]
    param(
        [AllowNull()] $Inventory,
        [Parameter(Mandatory)] [string] $Section
    )
    $status = Get-NRGNestedProperty -Object $Inventory -Path "Data.SectionStatus.$Section" -Default $null
    if ($null -eq $status) { return $true }
    return ($status -eq 'Collected')
}

# ── INV-1.1 Users Without MFA — Named List ────────────────────────────────────
function Test-NRGControlInventoryMFAUsers {
    [CmdletBinding()] param()
    $cid = 'AAD-12.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $users = Get-NRGRawData -Key 'AAD-Users'
    if (-not $users -or -not $users.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'User data not collected'; return
    }
    $regDetails = @(Get-NRGNestedProperty -Object $users -Path 'Data.MFARegistration.RegistrationDetails' -Default @())
    if ($regDetails.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'MFA registration details not available (requires Reports.Read.All)'; return
    }

    $enabled   = @($regDetails | Where-Object { $_.IsEnabled -eq $true })
    $withMFA   = @($enabled    | Where-Object { $_.IsMfaRegistered -eq $true })
    $noMFA     = @($enabled    | Where-Object { $_.IsMfaRegistered -eq $false })
    $total     = $enabled.Count
    $pct       = if ($total -gt 0) { [int][Math]::Round($withMFA.Count * 100 / $total) } else { 0 }

    if ($noMFA.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($withMFA.Count) of $total enabled users ($pct%) have MFA registered. No gaps found."
    } else {
        $objects = @($noMFA | Select-Object -First 100 | ForEach-Object {
            "$($_.UserDisplayName) ($($_.UserPrincipalName))"
        })
        $remaining = if ($noMFA.Count -gt 100) { " ($($noMFA.Count - 100) additional users in full results)" } else { '' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($withMFA.Count) of $total enabled users ($pct%) have MFA registered. The $($noMFA.Count) user(s) listed below have no MFA method — each is one stolen password away from a full mailbox compromise.$remaining" `
            -CurrentValue "$($withMFA.Count)/$total users with MFA ($pct%)" `
            -RequiredValue '100% of enabled users registered for MFA' `
            -Remediation $ctrl.Remediation -AffectedObjects $objects
    }
}

# ── INV-1.2 Stale Guest Accounts ─────────────────────────────────────────────
function Test-NRGControlInventoryStaleGuests {
    [CmdletBinding()] param()
    $cid = 'AAD-12.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'AAD-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Inventory data not collected'; return
    }
    $staleGuests = @($inv.Data['GuestUsers'] | Where-Object { $_.IsStale -eq $true })
    $allGuests   = @($inv.Data['GuestUsers']).Count
    if ($allGuests -eq 0 -and -not (Test-NRGInventorySectionCollected -Inventory $inv -Section 'GuestUsers')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'Guest account enumeration did not complete (see Exceptions) — stale guest access could not be assessed.'
        return
    }
    if ($staleGuests.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$allGuests guest account(s) found — all have signed in within the past 90 days. No stale guest access detected."
    } else {
        $objects = @($staleGuests | Sort-Object DaysSinceSignIn -Descending | Select-Object -First 50 | ForEach-Object {
            $days = if ($_.DaysSinceSignIn -eq 9999) { "Never signed in" } else { "$($_.DaysSinceSignIn) days ago" }
            "$($_.DisplayName) ($($_.UPN)) — Last sign-in: $days"
        })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($staleGuests.Count) guest account(s) with no sign-in activity in 90+ days. These are likely ex-vendors, ex-contractors, or test accounts that retain access to SharePoint, Teams, and shared resources." `
            -CurrentValue "$($staleGuests.Count) stale guests of $allGuests total" -RequiredValue 'All guests active within 90 days or removed' `
            -Remediation $ctrl.Remediation -AffectedObjects $objects
    }
}

# ── INV-1.3 Stale Licensed Member Accounts ───────────────────────────────────
function Test-NRGControlInventoryStaleMembers {
    [CmdletBinding()] param()
    $cid = 'AAD-12.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'AAD-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Inventory data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $inv 'StaleMembers')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'StaleMembers was not collected; not assessed.'
        return
    }
    $stale = @($inv.Data['StaleMembers'] ?? @() | Where-Object { $_.HasLicense -eq $true })
    if (@($inv.Data['StaleMembers']).Count -eq 0 -and -not (Test-NRGInventorySectionCollected -Inventory $inv -Section 'StaleMembers')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'Dormant account enumeration did not complete (see Exceptions) — stale licensed accounts could not be assessed.'
        return
    }
    if ($stale.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'All licensed member accounts have been active within the past 90 days. No dormant employee accounts detected.'
    } else {
        $objects = @($stale | Sort-Object DaysSinceSignIn -Descending | Select-Object -First 50 | ForEach-Object {
            $days = if ($_.DaysSinceSignIn -eq 9999) { "Never signed in" } else { "$($_.DaysSinceSignIn) days ago" }
            "$($_.DisplayName) ($($_.UPN)) — $days"
        })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($stale.Count) licensed member account(s) have not signed in for 90+ days. These accounts are likely departed employees whose accounts were not offboarded — each is a dormant attack surface with an active license." `
            -CurrentValue "$($stale.Count) stale licensed accounts" -RequiredValue 'All accounts active or offboarded' `
            -Remediation $ctrl.Remediation -AffectedObjects $objects
    }
}

# ── INV-1.4 OAuth Apps with AllPrincipals Consent ────────────────────────────
function Test-NRGControlInventoryOAuthApps {
    [CmdletBinding()] param()
    $cid = 'AAD-12.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'AAD-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Inventory data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $inv 'OAuthGrantedApps')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'OAuthGrantedApps was not collected; not assessed.'
        return
    }
    $apps = @($inv.Data['OAuthGrantedApps'] ?? @())
    if ($apps.Count -eq 0 -and -not (Test-NRGInventorySectionCollected -Inventory $inv -Section 'OAuthGrantedApps')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'OAuth consent grant enumeration did not complete (see Exceptions) — tenant-wide app consent could not be assessed.'
        return
    }
    if ($apps.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'No tenant-wide (AllPrincipals) OAuth consent grants found. Third-party app access is properly scoped to consenting individuals only.'
    } else {
        # Flag apps with sensitive scopes
        $sensitive = @('Mail.Read','Mail.ReadWrite','Mail.Send','Files.Read.All','Files.ReadWrite.All',
                       'User.Read.All','Directory.Read.All','Calendars.Read','offline_access')
        $highRisk = @($apps | Where-Object {
            $scope = [string]($_.Scope ?? '')
            $sensitive | Where-Object { $scope -match $_ }
        })
        # v4.6.4 FIX: the prior `$highRisk | Where-Object { $_.AppName -eq $_.AppName }`
        # was a self-comparison (always-true) — every app got the [HIGH RISK SCOPE]
        # label whenever any high-risk app existed. Build a lookup set keyed on
        # AppName so we test "is THIS app (outer) in the high-risk list?" correctly.
        $highRiskNames = @{}
        foreach ($hr in $highRisk) {
            if ($hr -and $hr.AppName) { $highRiskNames[[string]$hr.AppName] = $true }
        }
        $objects = @($apps | Select-Object -First 30 | ForEach-Object {
            $appName   = [string]$_.AppName
            $riskLabel = if ($highRiskNames.ContainsKey($appName)) { ' [HIGH RISK SCOPE]' } else { '' }
            "$appName$riskLabel — Scopes: $($_.Scope -replace ' ',' | ')"
        })
        $sev = if ($highRisk.Count -gt 0) { 'High' } else { 'Medium' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $sev -FrameworkIds $cit `
            -Detail "$($apps.Count) application(s) have been granted OAuth permissions across ALL users in this tenant. $($highRisk.Count) have sensitive scopes (Mail, Files, Directory access). Each of these apps can access data for every user — if any app is compromised or malicious, the impact is tenant-wide." `
            -CurrentValue "$($apps.Count) apps with AllPrincipals consent" -RequiredValue 'All tenant-wide grants reviewed and justified' `
            -Remediation $ctrl.Remediation -AffectedObjects $objects
    }
}

# ── INV-2.1 Mailboxes with External Forwarding Rules ─────────────────────────
function Test-NRGControlInventoryExternalForwarding {
    [CmdletBinding()] param()
    $cid = 'EXO-6.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO inventory not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $inv 'ForwardingMailboxes')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'ForwardingMailboxes was not collected; not assessed.'
        return
    }
    $allFwd = @($inv.Data['ForwardingMailboxes'] ?? @())
    if ($allFwd.Count -eq 0 -and -not (Test-NRGInventorySectionCollected -Inventory $inv -Section 'ForwardingMailboxes')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'Forwarding mailbox enumeration did not complete (see Exceptions) — external forwarding could not be assessed. Re-run before relying on this control.'
        return
    }

    # Score the EXTERNAL subset only. The collector already classified every
    # row; counting all forwarding mailboxes reported internal forwarding —
    # a delegation pattern in normal use — as external exfiltration, which is
    # a false Critical on a correctly-configured tenant.
    # Via the helper: StrictMode throws on a missing property, and result JSON
    # from a run before this collector change carries no Classification field.
    $fwd        = @($allFwd | Where-Object { Get-NRGObjectField -Item $_ -Key 'IsExternal' -Default $false })
    $unresolved = @($allFwd | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Classification' -Default '') -eq 'Unresolved' })

    if ($fwd.Count -eq 0 -and $unresolved.Count -gt 0) {
        # A forwarding target we could not resolve is not evidence of internal
        # forwarding. Claiming clean here is the same mistake as reading an
        # empty list as compliance.
        $objects = @($unresolved | ForEach-Object {
            $mech = [string](Get-NRGObjectField -Item $_ -Key 'ForwardingMechanism' -Default 'ForwardingSmtpAddress')
            "$($_.DisplayName) ($($_.UPN)) → $($_.ForwardingAddress) [$mech]"
        })
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail "$($unresolved.Count) forwarding target(s) could not be resolved to an address, so they could not be classified as internal or external. Not assessed — resolve these manually before treating this control as clean." `
            -AffectedObjects $objects
        return
    }

    if ($fwd.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "No mailboxes forward to an external address. $($allFwd.Count) mailbox forwarding configuration(s) were found and all resolve to accepted domains in this tenant."
    } else {
        $mailboxCount = @($fwd | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'UPN' -Default '') } | Sort-Object -Unique).Count
        $objects = @($fwd | ForEach-Object {
            $deliver = if ($_.DeliverToMailboxAndForward) { ' [copy kept]' } else { ' [forward only — emails not in mailbox]' }
            $mech    = [string](Get-NRGObjectField -Item $_ -Key 'ForwardingMechanism' -Default 'ForwardingSmtpAddress')
            "$($_.DisplayName) ($($_.UPN)) → $($_.ForwardingAddress) [$mech]$deliver"
        })
        $unresolvedNote = if ($unresolved.Count -gt 0) { " A further $($unresolved.Count) forwarding target(s) could not be resolved and are not counted here." } else { '' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$mailboxCount mailbox(es) are configured to forward email to external addresses. This is the primary BEC data exfiltration technique — compromised accounts set forwarding rules to silently copy all incoming mail to attacker-controlled addresses. Each of these should be verified as intentional.$unresolvedNote" `
            -CurrentValue "$mailboxCount mailboxes forwarding externally" -RequiredValue 'All external forwarding rules reviewed and approved' `
            -Remediation $ctrl.Remediation -AffectedObjects $objects
    }
}

# ── INV-2.2 Shared Mailboxes with Direct Sign-In Enabled ─────────────────────
function Test-NRGControlInventorySharedMailboxSignIn {
    [CmdletBinding()] param()
    $cid = 'EXO-6.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO inventory not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $inv 'AllSharedMailboxes')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AllSharedMailboxes was not collected; not assessed.'
        return
    }
    $shared = @($inv.Data['AllSharedMailboxes'] ?? @())
    if ($shared.Count -eq 0 -and -not (Test-NRGInventorySectionCollected -Inventory $inv -Section 'SharedMailboxes')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'Shared mailbox enumeration did not complete (see Exceptions) — shared mailbox sign-in state could not be assessed.'
        return
    }
    if ($shared.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'No shared mailboxes found.'; return
    }
    # Cross-reference with AAD users to find which shared mailboxes have enabled accounts
    $users = Get-NRGRawData -Key 'AAD-Users'
    # The sign-in state of a shared mailbox is only knowable by joining against
    # AAD users. Without that data the join silently yields zero matches, and
    # the branch below would report "all have interactive sign-in blocked" —
    # a definitive compliance claim about a check that never ran.
    if (-not $users -or -not $users.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail "$($shared.Count) shared mailbox(es) found, but AAD user data was not collected — sign-in state could not be determined."
        return
    }
    $enabledShared = @()
    if ($users -and $users.Success) {
        $userIndex = @{}
        foreach ($u in @($users.Data['Users'])) { $userIndex[$u.UserPrincipalName.ToLower()] = $u }
        foreach ($mb in $shared) {
            $smtp = [string]($mb.PrimarySmtp ?? '').ToLower()
            if ($userIndex.ContainsKey($smtp) -and $userIndex[$smtp].AccountEnabled -eq $true) {
                $enabledShared += $mb
            }
        }
    }
    if ($enabledShared.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($shared.Count) shared mailbox(es) found — all have interactive sign-in blocked. Access is via Outlook delegation only, as intended."
    } else {
        $objects = @($enabledShared | ForEach-Object { "$($_.DisplayName) ($($_.PrimarySmtp))" })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($enabledShared.Count) of $($shared.Count) shared mailbox(es) have sign-in enabled. Shared mailboxes should have BlockCredential = true — they are accessed via delegation, not direct login. An enabled shared mailbox account can be compromised and is not subject to MFA." `
            -CurrentValue "$($enabledShared.Count) shared mailboxes with sign-in enabled" -RequiredValue 'All shared mailboxes: BlockCredential = $true' `
            -Remediation $ctrl.Remediation -AffectedObjects $objects
    }
}

# ── INV-2.3 Mailboxes with Audit Logging Disabled ────────────────────────────
function Test-NRGControlInventoryMailboxAuditDisabled {
    [CmdletBinding()] param()
    $cid = 'EXO-6.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO inventory not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $inv 'AuditDisabledMailboxes')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AuditDisabledMailboxes was not collected; not assessed.'
        return
    }
    $noAudit = @($inv.Data['AuditDisabledMailboxes'] ?? @())
    if ($noAudit.Count -eq 0 -and -not (Test-NRGInventorySectionCollected -Inventory $inv -Section 'AuditDisabledMailboxes')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'Mailbox audit enumeration did not complete (see Exceptions) — audit coverage could not be assessed.'
        return
    }
    if ($noAudit.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'All mailboxes have audit logging enabled. Mailbox access, inbox rules, and delegation changes are being recorded.'
    } else {
        $objects = @($noAudit | ForEach-Object { "$($_.DisplayName) ($($_.UPN)) [$($_.MailboxType)]" })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($noAudit.Count) mailbox(es) have audit logging explicitly disabled. A BEC incident affecting these accounts cannot be investigated — there is no record of what email was read, what rules were created, or who accessed the mailbox." `
            -CurrentValue "$($noAudit.Count) mailboxes unaudited" -RequiredValue 'Zero mailboxes with AuditEnabled = $false' `
            -Remediation $ctrl.Remediation -AffectedObjects $objects
    }
}

# ── INV-2.4 Per-User SMTP AUTH Override Enabled ───────────────────────────────
function Test-NRGControlInventorySMTPAuthUsers {
    [CmdletBinding()] param()
    $cid = 'EXO-6.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO inventory not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $inv 'SmtpAuthEnabledPerUser')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SmtpAuthEnabledPerUser was not collected; not assessed.'
        return
    }
    $smtp = @($inv.Data['SmtpAuthEnabledPerUser'] ?? @())
    if ($smtp.Count -eq 0 -and -not (Test-NRGInventorySectionCollected -Inventory $inv -Section 'SmtpAuthEnabledPerUser')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'Per-user SMTP AUTH enumeration did not complete (see Exceptions) — legacy authentication overrides could not be assessed.'
        return
    }
    if ($smtp.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'No per-user SMTP AUTH overrides. The org-level SMTP AUTH disable is enforced across all users — legacy client authentication is blocked.'
    } else {
        $objects = @($smtp | ForEach-Object { "$($_.DisplayName) ($($_.UPN))" })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($smtp.Count) user(s) have SMTP AUTH individually re-enabled, bypassing the org-level disable. These users can authenticate via legacy SMTP, which does not support MFA and is a known credential stuffing target." `
            -CurrentValue "$($smtp.Count) users with SMTP AUTH enabled" -RequiredValue 'Zero per-user SMTP AUTH overrides' `
            -Remediation $ctrl.Remediation -AffectedObjects $objects
    }
}

# ── INV-3.1 Microsoft Secure Score ────────────────────────────────────────────
function Test-NRGControlInventorySecureScore {
    [CmdletBinding()] param()
    $cid = 'AAD-13.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'AAD-Inventory'
    if (-not $inv -or -not $inv.Success -or -not $inv.Data['SecureScore']) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Secure Score data not collected (requires SecurityEvents.Read.All)'; return
    }
    $ss  = $inv.Data['SecureScore']
    $pct = [int](Get-NRGObjectField -Item $ss -Key 'Percentage' -Default 0)
    $cur = [int](Get-NRGObjectField -Item $ss -Key 'CurrentScore' -Default 0)
    $max = [int](Get-NRGObjectField -Item $ss -Key 'MaxScore' -Default 0)

    # Prefer Microsoft's OWN peer benchmark (averageComparativeScores) over an
    # arbitrary percentage: are you at/above the average tenant of your size?
    # AllTenants is the broadest, most stable basis; fall back to TotalSeats.
    $benchScore = $null
    $benchBasis = ''
    $comps = @(Get-NRGObjectField -Item $ss -Key 'AverageComparativeScores' -Default @())
    foreach ($basis in @('AllTenants', 'TotalSeats', 'IndustryTypes')) {
        $hit = @($comps | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Basis') -eq $basis }) | Select-Object -First 1
        if ($hit) {
            $benchScore = [double](Get-NRGObjectField -Item $hit -Key 'AverageScore' -Default 0)
            $benchBasis = $basis
            break
        }
    }

    if ($null -ne $benchScore -and $max -gt 0 -and $benchScore -gt 0) {
        # Benchmark available — judge against Microsoft's peer average.
        $benchPct = [int](($benchScore / $max) * 100)
        $basisLabel = switch ($benchBasis) { 'AllTenants' {'all Microsoft 365 tenants'} 'TotalSeats' {'tenants of similar size'} default {'tenants in your industry'} }
        if ($pct -ge $benchPct) {
            Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
                -Severity 'Informational' -FrameworkIds $cit `
                -Detail "Microsoft Secure Score $cur / $max ($pct%) is at or above the $benchPct% average for $basisLabel. Configuration posture across identity, data, apps, and devices meets or beats the peer benchmark. Score as of $($ss.CreatedDate)." `
                -CurrentValue "$pct% (peer average $benchPct%)"
        } else {
            Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
                -Severity $ctrl.Severity -FrameworkIds $cit `
                -Detail "Microsoft Secure Score $cur / $max ($pct%) is BELOW the $benchPct% average for $basisLabel. Microsoft's own assessment rates this tenant behind comparable organizations — work the ranked improvement actions to close the gap." `
                -CurrentValue "$pct% (peer average $benchPct%)" `
                -RequiredValue "At or above the peer benchmark ($benchPct%)" `
                -Remediation $ctrl.Remediation
        }
    } else {
        # No comparative benchmark returned — fall back to an absolute posture band.
        $posture = if ($pct -ge 70) { 'Strong' } elseif ($pct -ge 50) { 'Moderate' } elseif ($pct -ge 30) { 'At Risk' } else { 'Critical' }
        Add-NRGFinding -ControlId $cid -State $(if ($pct -ge 70) {'Satisfied'} elseif ($pct -ge 50) {'Partial'} else {'Gap'}) `
            -Category $ctrl.Category -Title $ctrl.Title -Severity $(if ($pct -lt 30) {'High'} elseif ($pct -lt 50) {'Medium'} else {'Low'}) `
            -FrameworkIds $cit `
            -Detail "Microsoft Secure Score: $cur / $max ($pct%) — $posture. Microsoft's own assessment of your tenant configuration across identity, data, apps, and devices (peer benchmark unavailable in this run). Score as of $($ss.CreatedDate)." `
            -CurrentValue "Score: $cur/$max ($pct%)" -RequiredValue 'Target: 70%+ (Strong posture)' -Remediation $ctrl.Remediation
    }
}

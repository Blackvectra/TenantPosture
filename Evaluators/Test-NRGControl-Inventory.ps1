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
# collected so a replayed older JSON keeps its previous behavior rather than
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

    # Population = enabled MEMBER accounts, the same one AAD-1.2 uses. The
    # registration report also lists guests and disabled accounts, and the
    # collector marks every row enabled — on a live tenant that made this
    # control say "185 users have no MFA" (mostly guests, who authenticate
    # in their home tenant) while AAD-1.2 in the same report said 49.5% of
    # 103 members. Fall back to the raw report only if the user list is absent.
    $memberAll = @(Get-NRGNestedProperty -Object $users -Path 'Data.Users' -Default @() | Where-Object {
        (Get-NRGObjectField -Item $_ -Key 'AccountEnabled' -Default $false) -eq $true -and
        [string](Get-NRGObjectField -Item $_ -Key 'UserType' -Default '') -eq 'Member'
    })
    # The directory-sync service account is left out here as in AAD-1.2, or the
    # two controls report different populations for the same tenant.
    $memberList = @($memberAll | Where-Object { -not (Test-NRGDirectorySyncAccount $_) })
    $syncNote = if ($memberAll.Count -gt $memberList.Count) { " ($($memberAll.Count - $memberList.Count) Entra Connect sync service account(s) excluded; they cannot register MFA.)" } else { '' }
    if ($memberList.Count -gt 0) {
        $byUpn = @{}
        foreach ($r in $regDetails) { $u = [string](Get-NRGObjectField -Item $r -Key 'UserPrincipalName' -Default ''); if ($u) { $byUpn[$u.ToLowerInvariant()] = $r } }
        $enabled = @($memberList | ForEach-Object {
            $upn = [string](Get-NRGObjectField -Item $_ -Key 'UserPrincipalName' -Default '')
            $rec = $byUpn[$upn.ToLowerInvariant()]
            @{ UserPrincipalName = $upn
               UserDisplayName   = [string](Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default $upn)
               # No registration record = no registered method (as AAD-1.2 treats it).
               IsMfaRegistered   = [bool]($rec -and (Get-NRGObjectField -Item $rec -Key 'IsMfaRegistered' -Default $false)) }
        })
    } else {
        $enabled = @($regDetails | Where-Object { $_.IsEnabled -eq $true })
    }
    $popLabel  = if ($memberList.Count -gt 0) { 'enabled member accounts (guests excluded)' } else { 'enabled users' }
    $withMFA   = @($enabled    | Where-Object { $_.IsMfaRegistered -eq $true })
    $noMFA     = @($enabled    | Where-Object { $_.IsMfaRegistered -eq $false })
    $total     = $enabled.Count
    $pct       = if ($total -gt 0) { [Math]::Round($withMFA.Count * 100 / $total, 1) } else { 0 }

    if ($noMFA.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($withMFA.Count) of $total $popLabel ($pct%) have MFA registered.$syncNote"
    } else {
        $objects = @($noMFA | Select-Object -First 100 | ForEach-Object {
            "$($_.UserDisplayName) ($($_.UserPrincipalName))"
        })
        $remaining = if ($noMFA.Count -gt 100) { " ($($noMFA.Count - 100) additional users in full results)" } else { '' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($withMFA.Count) of $total $popLabel ($pct%) have MFA registered. The $($noMFA.Count) user(s) listed below have no MFA method — each is one stolen password away from a full mailbox compromise.$remaining$syncNote" `
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
            $days = if ($_.DaysSinceSignIn -eq 9999) { "Never signed in" } else { "$($_.DaysSinceSignIn) days since $([string](Get-NRGObjectField -Item $_ -Key 'LastSignInBasis' -Default 'last sign-in'))" }
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
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Every licensed member account older than 90 days has signed in successfully within the past 90 days. No dormant employee accounts detected.'
    } else {
        $objects = @($stale | Sort-Object DaysSinceSignIn -Descending | Select-Object -First 50 | ForEach-Object {
            $days = if ($_.DaysSinceSignIn -eq 9999) { "Never signed in" } else { "$($_.DaysSinceSignIn) days since $([string](Get-NRGObjectField -Item $_ -Key 'LastSignInBasis' -Default 'last sign-in'))" }
            "$($_.DisplayName) ($($_.UPN)) — $days"
        })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($stale.Count) licensed member account(s) older than 90 days have not successfully signed in for 90+ days. These accounts are likely departed employees whose accounts were not offboarded — each is a dormant attack surface with an active license." `
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
        # Scopes that only sign the user in (OpenID Connect plus reading the
        # signed-in user's own profile) are what every "Sign in with
        # Microsoft" app needs; granting them tenant-wide exposes nobody's
        # data. offline_access keeps the token refreshable and grants no data.
        $signInOnly = @('openid','profile','email','offline_access','User.Read')
        $sensitive  = @('Mail.Read','Mail.ReadBasic','Mail.ReadWrite','Mail.Send','Mail.Read.Shared','Mail.ReadWrite.Shared','Mail.Send.Shared',
                        'Files.Read','Files.ReadWrite','Files.Read.All','Files.ReadWrite.All','Sites.Read.All','Sites.ReadWrite.All','Sites.FullControl.All',
                        'User.Read.All','User.ReadWrite.All','Directory.Read.All','Directory.ReadWrite.All','Directory.AccessAsUser.All',
                        'Calendars.Read','Calendars.ReadWrite','Contacts.Read','Contacts.ReadWrite','Notes.Read.All','Notes.ReadWrite.All',
                        'Chat.Read','Chat.ReadWrite','ChannelMessage.Read.All','EWS.AccessAsUser.All','full_access_as_user',
                        'RoleManagement.ReadWrite.Directory','Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All')
        $tokens = { param($a) @(([string](Get-NRGObjectField -Item $a -Key 'Scope' -Default '')) -split '\s+' | Where-Object { $_ }) }
        $name   = { param($a) $n = [string](Get-NRGObjectField -Item $a -Key 'AppName' -Default ''); if ($n) { $n } else { [string](Get-NRGObjectField -Item $a -Key 'ClientId' -Default '?') } }
        $dataApps = @($apps | Where-Object { @(& $tokens $_ | Where-Object { $_ -notin $signInOnly }).Count -gt 0 })
        if ($dataApps.Count -eq 0) {
            Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
                -Detail "$($apps.Count) tenant-wide consent grant(s) exist, and each carries only sign-in permissions ($($signInOnly -join ', ')), which read nothing beyond the signed-in user's own basic profile: $((@($apps | ForEach-Object { & $name $_ } | Sort-Object -Unique)) -join ', ')."
            return
        }
        $highRisk = @($dataApps | Where-Object { @(& $tokens $_ | Where-Object { $_ -in $sensitive }).Count -gt 0 })
        $objects = @($dataApps | Select-Object -First 30 | ForEach-Object {
            $risky = @(& $tokens $_ | Where-Object { $_ -in $sensitive })
            $riskLabel = if ($risky.Count) { ' [HIGH RISK SCOPE]' } else { '' }
            "$(& $name $_)$riskLabel — Scopes: $((& $tokens $_) -join ' | ')"
        })
        $sev = if ($highRisk.Count -gt 0) { 'High' } else { 'Medium' }
        $signInNote = if ($apps.Count -gt $dataApps.Count) { " A further $($apps.Count - $dataApps.Count) grant(s) carry sign-in permissions only and are not counted." } else { '' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $sev -FrameworkIds $cit `
            -Detail "$($dataApps.Count) application(s) have been granted data permissions across ALL users in this tenant; $($highRisk.Count) include sensitive scopes (mail, files, directory, chat). Each can act on data for every user — if the app or its publisher is compromised, the impact is tenant-wide.$signInNote" `
            -CurrentValue "$($dataApps.Count) apps with tenant-wide data consent" -RequiredValue 'All tenant-wide grants reviewed and justified' `
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
    # Join on the mailbox's UPN first — a shared mailbox's UPN routinely
    # differs from its primary SMTP address, and joining on SMTP alone missed
    # 6 of 18 sign-in-enabled mailboxes on a live tenant (EXO-2.6 in the same
    # report found all 18). A mailbox that matches no account is UNKNOWN,
    # never "blocked".
    $enabledShared = @()
    $unmatched     = @()
    $userIndex = @{}
    foreach ($u in @($users.Data['Users'])) {
        $k = [string](Get-NRGObjectField -Item $u -Key 'UserPrincipalName' -Default '')
        if ($k) { $userIndex[$k.ToLowerInvariant()] = $u }
    }
    foreach ($mb in $shared) {
        $acct = $null
        foreach ($key in @((Get-NRGObjectField -Item $mb -Key 'UPN' -Default ''), (Get-NRGObjectField -Item $mb -Key 'PrimarySmtp' -Default ''))) {
            $k = ([string]$key).ToLowerInvariant()
            if ($k -and $userIndex.ContainsKey($k)) { $acct = $userIndex[$k]; break }
        }
        if (-not $acct) { $unmatched += $mb }
        elseif ((Get-NRGObjectField -Item $acct -Key 'AccountEnabled' -Default $false) -eq $true) { $enabledShared += $mb }
    }
    if ($enabledShared.Count -eq 0 -and $unmatched.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "$($unmatched.Count) of $($shared.Count) shared mailbox(es) could not be matched to an Entra account, so their sign-in state is unknown; not assessed."
        return
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
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO inventory not collected'; return
    }
    $st = Get-NRGMailboxAuditBypassState -Inventory $inv
    if ($st.Kind -eq 'Bypass') {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($st.Names.Count) account(s) have a mailbox audit bypass: nothing they do in any mailbox — their own, a shared mailbox, or one they administer — is recorded. A BEC incident involving these accounts cannot be investigated." `
            -CurrentValue "$($st.Names.Count) account(s) with AuditBypassEnabled = True" -RequiredValue 'No mailbox audit bypass associations' `
            -Remediation 'For each account: Set-MailboxAuditBypassAssociation -Identity <account> -AuditBypassEnabled $false. Bypass is only appropriate for high-volume service accounts whose actions are logged elsewhere.' -AffectedObjects $st.Names
    } elseif ($st.Kind -eq 'Clean') {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail $st.Detail
    } else {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $st.Detail
    }
}

# ── INV-2.4 Per-User SMTP AUTH Override Enabled ───────────────────────────────
function Test-NRGControlInventorySMTPAuthUsers {
    [CmdletBinding()] param()
    $cid = 'EXO-6.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO inventory not collected'; return
    }
    if (-not (Test-NRGSectionCollected $inv 'SmtpAuthEnabledPerUser')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'SmtpAuthEnabledPerUser was not collected; not assessed.'
        return
    }
    $st = Get-NRGSmtpAuthOverrideState -Inventory $inv
    if ($st.OrgDisabled -eq $false) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'SMTP AUTH is enabled for the whole organization, so every mailbox can use it whether or not it has a per-user override. Scored under EXO-1.2.'
        return
    }
    $orgNote = if ($st.OrgDisabled -eq $true) { 'The organization-level SMTP AUTH disable applies to every other mailbox.' } else { 'The organization-level SMTP AUTH setting was not read.' }
    if ($st.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "No mailbox re-enables SMTP AUTH individually. $orgNote"
    } else {
        $objects = @($st.List | ForEach-Object { "$([string](Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '')) ($([string](Get-NRGObjectField -Item $_ -Key 'UPN' -Default '')))" })
        $capNote = if ($st.Count -gt $objects.Count) { " The first $($objects.Count) are listed." } else { '' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($st.Count) mailbox(es) have SMTP AUTH individually re-enabled. $orgNote These accounts can submit mail over SMTP AUTH, a password-spray target that bypasses MFA wherever basic authentication is still accepted.$capNote" `
            -CurrentValue "$($st.Count) users with SMTP AUTH enabled" -RequiredValue 'Zero per-user SMTP AUTH overrides' `
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
        # averageScore arrives on a 0-100 scale (a live tenant scoring 807 of
        # 1165 reported 53.99 for AllTenants). Dividing it by the tenant's
        # maxScore printed "the 5% average for all Microsoft 365 tenants".
        # A value above 100 can only be points, and is converted.
        $benchPct = if ($benchScore -le 100) { [int][math]::Round($benchScore) } else { [int](($benchScore / $max) * 100) }
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

# Shared reading for EXO-6.3 / EXO-7.3. With mailbox auditing on by default,
# Exchange IGNORES a mailbox's AuditEnabled = False and Get-Mailbox reports
# True regardless (Microsoft, "Manage mailbox auditing"), so the old
# AuditEnabled -eq $false sweep could neither find a gap nor prove its
# absence. Per-user audit is switched off only by an audit bypass
# association; org-wide, by OrganizationConfig.AuditDisabled (EXO-5.1).
function Get-NRGMailboxAuditBypassState {
    [CmdletBinding()] param([Parameter(Mandatory)] $Inventory)
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    $orgOff = $null
    if ($exo -and $exo.Success -and (Test-NRGSectionCollected $exo 'OrganizationConfig')) {
        $orgOff = Get-NRGNestedProperty -Object $exo -Path 'Data.OrganizationConfig.AuditDisabled' -Default $null
    }
    if ($orgOff -eq $true) {
        return @{ Kind = 'OrgOff'; Names = @(); Detail = 'Mailbox auditing is turned off for the whole organization (AuditDisabled = True), so no mailbox is audited and per-user settings are ignored. Scored under EXO-5.1.' }
    }
    $status = Get-NRGNestedProperty -Object $Inventory -Path 'Data.SectionStatus.AuditBypassAccounts' -Default $null
    if ($status -ne 'Collected') {
        return @{ Kind = 'NotRead'; Names = @(); Detail = 'Mailbox audit bypass associations (Get-MailboxAuditBypassAssociation) were not read, so whether any account is exempt from mailbox auditing was not assessed. (A mailbox''s AuditEnabled flag is ignored while organization auditing is on and cannot answer this.)' }
    }
    $names = @(@(Get-NRGObjectField -Item $Inventory.Data -Key 'AuditBypassAccounts' -Default @()) | ForEach-Object {
        $n = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
        if (-not $n) { $n = [string](Get-NRGObjectField -Item $_ -Key 'Identity' -Default '') }
        $n } | Where-Object { $_ })
    if ($names.Count -gt 0) { return @{ Kind = 'Bypass'; Names = $names; Detail = '' } }
    if ($null -eq $orgOff) {
        return @{ Kind = 'OrgUnknown'; Names = @(); Detail = 'No account has a mailbox audit bypass, but whether mailbox auditing is on for the organization (Get-OrganizationConfig AuditDisabled) was not read; not assessed.' }
    }
    return @{ Kind = 'Clean'; Names = @(); Detail = 'Mailbox auditing is on for the organization and no account has an audit bypass association, so every mailbox action is recorded. (Per-mailbox AuditEnabled flags are ignored by Exchange while organization auditing is on.)' }
}

# Shared reading for EXO-6.4 / EXO-7.4: per-user SMTP AUTH overrides only
# mean something while the organization disables SMTP AUTH.
function Get-NRGSmtpAuthOverrideState {
    [CmdletBinding()] param([Parameter(Mandatory)] $Inventory)
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    $orgDisabled = $null
    if ($exo -and $exo.Success) {
        $orgDisabled = Get-NRGNestedProperty -Object $exo -Path 'Data.TransportConfig.SmtpClientAuthenticationDisabled' -Default $null
    }
    $list  = @(Get-NRGObjectField -Item $Inventory.Data -Key 'SmtpAuthEnabledPerUser' -Default @())
    # The list is capped at 100 names; the count is the full total.
    $count = [int](Get-NRGObjectField -Item $Inventory.Data -Key 'SmtpAuthEnabledPerUserCount' -Default $list.Count)
    return @{ OrgDisabled = $orgDisabled; List = $list; Count = $count }
}

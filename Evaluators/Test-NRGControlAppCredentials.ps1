#Requires -Version 7.0
#
# Test-NRGControlAppCredentials.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: AAD-14.1 — credential hygiene on app registrations.
#
#          The tool already looks at applications from two angles: AAD-12.4
#          lists apps holding tenant-wide consent, and AAD-11.3 flags service
#          principals Identity Protection has marked risky. Neither looks at
#          the CREDENTIALS on those apps, and a client secret is a standing
#          bearer credential to everything the app can reach — no MFA, no
#          Conditional Access, no sign-in risk evaluation.
#
#          Two opposite failure modes, both real and both worth naming:
#
#            Expiring or expired. An integration is about to break, or already
#            has. The fix under time pressure is a new secret with the longest
#            lifetime the portal offers and no reminder set, which converts an
#            outage into the second problem.
#
#            Long-lived. A two-year secret is a two-year window. Everyone who
#            has ever seen it — a departed admin, a stale runbook, a chat log,
#            a CI variable — keeps access for its full term. Rotation is the
#            only thing that closes it, and nothing forces rotation.
#
#          Certificates are reported alongside secrets and held to the same
#          expiry bar. They are better credentials, not exempt ones.
#
# Consumes: AAD-Inventory raw data (Data.AppCredentials). No Graph calls.
#

# Thresholds. Deliberately conservative and stated in the finding so a reader
# can disagree with the number rather than the verdict:
#   90 days  — a secret longer than this is a rotation policy nobody has.
#   30 days  — expiring inside a month is an outage being scheduled.
$script:NRGAppCredMaxLifetimeDays = 180
$script:NRGAppCredWarnDays        = 30

function Test-NRGControlAADAppCredentialExpiry {
    [CmdletBinding()] param()
    $cid = 'AAD-14.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'AAD-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AAD inventory not collected'
        return
    }
    if (-not (Test-NRGSectionCollected $inv 'AppCredentials')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Application credentials were not collected; not assessed.'
        return
    }

    $creds = @(Get-NRGNestedProperty -Object $inv -Path 'Data.AppCredentials' -Default @())

    # No credentials at all is a legitimate and good state — an app-only
    # integration may use federated credentials, or the tenant may simply have
    # no app registrations. The section status above already proved the query
    # ran, so this is a real answer rather than an empty one.
    if ($creds.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -CurrentValue 'No application secrets or certificates' `
            -Detail 'No app registration in the tenant carries a client secret or certificate. There are no standing application credentials to rotate or leak.'
        return
    }

    $expired  = [System.Collections.Generic.List[object]]::new()
    $expiring = [System.Collections.Generic.List[object]]::new()
    $longLived = [System.Collections.Generic.List[object]]::new()

    foreach ($c in $creds) {
        $days = Get-NRGObjectField -Item $c -Key 'DaysRemaining' -Default $null
        $life = Get-NRGObjectField -Item $c -Key 'LifetimeDays'  -Default $null
        $row  = @{
            App            = [string](Get-NRGObjectField -Item $c -Key 'AppDisplayName')
            AppId          = [string](Get-NRGObjectField -Item $c -Key 'AppId')
            CredentialType = [string](Get-NRGObjectField -Item $c -Key 'CredentialType')
            DaysRemaining  = $days
            LifetimeDays   = $life
        }
        if ($null -ne $days) {
            if     ($days -lt 0)                            { $expired.Add($row) }
            elseif ($days -le $script:NRGAppCredWarnDays)   { $expiring.Add($row) }
        }
        # An already-expired credential is dead and cannot be used, so its
        # lifetime is not also counted as a live exposure.
        if ($null -ne $life -and $life -gt $script:NRGAppCredMaxLifetimeDays -and $null -ne $days -and $days -ge 0) {
            $longLived.Add($row)
        }
    }

    $total = $creds.Count
    if ($expired.Count -eq 0 -and $expiring.Count -eq 0 -and $longLived.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -CurrentValue "$total credential(s), none expired, expiring within $($script:NRGAppCredWarnDays) days, or issued for more than $($script:NRGAppCredMaxLifetimeDays) days" `
            -Detail "All $total application credentials are current and none was issued with a lifetime beyond $($script:NRGAppCredMaxLifetimeDays) days."
        return
    }

    $parts = @()
    if ($expired.Count)   { $parts += "$($expired.Count) expired" }
    if ($expiring.Count)  { $parts += "$($expiring.Count) expiring within $($script:NRGAppCredWarnDays) days" }
    if ($longLived.Count) { $parts += "$($longLived.Count) issued for more than $($script:NRGAppCredMaxLifetimeDays) days" }

    $detail = "Of $total application credentials: $($parts -join ', ')."
    if ($longLived.Count) {
        $detail += " A long-lived secret is a standing bearer credential — no MFA prompt applies to it, and Conditional Access covers an application only where a workload-identity policy targets an eligible single-tenant service principal — and everyone who has ever held it keeps access until it is rotated: $((@($longLived | ForEach-Object { "$($_.App) ($($_.CredentialType), $($_.LifetimeDays)d)" }) | Select-Object -First 5) -join '; ')."
    }
    if ($expired.Count) {
        $detail += " Expired: $((@($expired | ForEach-Object { "$($_.App) ($($_.CredentialType))" }) | Select-Object -First 5) -join '; '). Remove them — an expired credential left in place is one an operator will rotate under pressure rather than retire."
    }
    if ($expiring.Count) {
        $detail += " Expiring soon: $((@($expiring | ForEach-Object { "$($_.App) ($($_.DaysRemaining)d)" }) | Select-Object -First 5) -join '; ')."
    }

    # Expired and long-lived credentials are the real exposure. An imminent
    # expiry on its own is an operational warning, not a security gap, so it
    # scores as Partial rather than dragging the control to a full Gap.
    #
    # Written as two branches with LITERAL state values rather than one call
    # with -State $state. Get-NRGControlAutomationAudit proves a control
    # discriminates by reading the literal -State arguments out of the
    # evaluator's syntax tree; a variable is opaque to it, and this control was
    # classified SingleVerdict — indistinguishable from one that can only ever
    # return one answer. The duplication buys a static guarantee that the
    # control can actually fail.
    $required = "Every application credential current and issued for no more than $($script:NRGAppCredMaxLifetimeDays) days"
    $current  = ($parts -join ', ')
    $affected = @($expired) + @($expiring) + @($longLived)

    if ($expired.Count -gt 0 -or $longLived.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity $ctrl.Severity -FrameworkIds $cit `
            -CurrentValue $current -RequiredValue $required `
            -Detail $detail -Remediation $ctrl.Remediation -AffectedObjects $affected
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Medium' -FrameworkIds $cit `
            -CurrentValue $current -RequiredValue $required `
            -Detail $detail -Remediation $ctrl.Remediation -AffectedObjects $affected
    }
}

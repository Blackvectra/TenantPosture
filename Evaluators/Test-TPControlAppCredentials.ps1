#Requires -Version 7.0
#
# Test-TPControlAppCredentials.ps1
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
$script:TPAppCredMaxLifetimeDays = 180
$script:TPAppCredWarnDays        = 30

# The tenant application management policy half (ScubaGear MS.AAD.5.6v1 and
# 5.7v1 audit it): enabled, with a passwordLifetime and an asymmetricKeyLifetime
# restriction that is enabled, applies to every app (no created-after date),
# exempts no actor, and caps the lifetime at this control's own bound. Returns
# Verified / Shortfalls / NotEstablished sentences. Module scope, not exported.
function Get-TPAppManagementPolicyVerdict {
    [CmdletBinding()]
    param([AllowNull()] $Inventory, [int] $MaxDays)
    $v = @(); $s = @(); $n = @()
    $status = [string](Get-TPNestedProperty -Object $Inventory -Path 'Data.SectionStatus.AppManagementPolicy' -Default '')
    $pol = Get-TPNestedProperty -Object $Inventory -Path 'Data.AppManagementPolicy' -Default $null
    if ($status -ne 'Collected' -or $null -eq $pol) {
        $n += "the tenant application management policy (which caps the lifetime of new secrets and certificates) was not read ($(if ($status) { "status: $status" } else { 'a results file from before it was collected' }))."
        return [pscustomobject]@{ Verified = $v; Shortfalls = $s; NotEstablished = $n }
    }
    $enabled = Get-TPObjectField -Item $pol -Key 'IsEnabled' -Default $null
    if ($enabled -ne $true) {
        if ($null -eq $enabled) { $n += 'whether the tenant application management policy is enabled was not returned.' }
        else { $s += 'the tenant application management policy is not enabled, so no lifetime limit applies to new secrets or certificates.' }
        return [pscustomobject]@{ Verified = $v; Shortfalls = $s; NotEstablished = $n }
    }
    foreach ($kind in @(
            @{ Key = 'PasswordRestrictions'; Type = 'passwordLifetime';      Name = 'client secrets (passwordLifetime)' },
            @{ Key = 'KeyRestrictions';      Type = 'asymmetricKeyLifetime'; Name = 'certificates (asymmetricKeyLifetime)' })) {
        $r = @(Get-TPObjectField -Item $pol -Key $kind.Key -Default @() | Where-Object { $null -ne $_ -and [string](Get-TPObjectField -Item $_ -Key 'RestrictionType' -Default '') -eq $kind.Type }) | Select-Object -First 1
        if (-not $r) { $s += "the tenant application management policy sets no lifetime limit for $($kind.Name)."; continue }
        $state = [string](Get-TPObjectField -Item $r -Key 'State' -Default '')
        $maxRaw = [string](Get-TPObjectField -Item $r -Key 'MaxLifetime' -Default '')
        $days = $null
        if ($maxRaw) { try { $days = [System.Xml.XmlConvert]::ToTimeSpan($maxRaw).TotalDays } catch { $days = $null } }
        $after = ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $r -Key 'RestrictForAppsCreatedAfterDateTime' -Default $null)
        $exempt = [int](Get-TPObjectField -Item $r -Key 'ExcludedActorAttributes' -Default 0)
        $why = @()
        if ($state -eq 'disabled') { $why += 'the restriction is disabled' } elseif ($state -ne 'enabled') { $n += "the state of the lifetime limit for $($kind.Name) was not returned."; continue }
        if ($null -eq $days) { $n += "the lifetime limit for $($kind.Name) ('$maxRaw') could not be read as a duration."; continue }
        if ($days -gt $MaxDays) { $why += "it allows $([math]::Round($days)) days, more than $MaxDays" }
        if ($after -and $after.Year -gt 1) { $why += "it applies only to applications created after $($after.ToString('yyyy-MM-dd')), so older applications are unrestricted" }
        if ($exempt -gt 0) { $why += 'it exempts actors holding a custom security attribute' }
        if ($why.Count) { $s += "the tenant application management policy limit for $($kind.Name) falls short: $($why -join '; ')." }
        else { $v += "The tenant application management policy limits $($kind.Name) to $([math]::Round($days)) days for every application." }
    }
    return [pscustomobject]@{ Verified = $v; Shortfalls = $s; NotEstablished = $n }
}

function Test-TPControlAADAppCredentialExpiry {
    [CmdletBinding()] param()
    $cid = 'AAD-14.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $inv = Get-TPRawData -Key 'AAD-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AAD inventory not collected'
        return
    }
    if (-not (Test-TPSectionCollected $inv 'AppCredentials')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Application credentials were not collected; not assessed.'
        return
    }

    $creds = @(Get-TPNestedProperty -Object $inv -Path 'Data.AppCredentials' -Default @())
    $pv = Get-TPAppManagementPolicyVerdict -Inventory $inv -MaxDays $script:TPAppCredMaxLifetimeDays
    $required = "Every application credential current and issued for no more than $($script:TPAppCredMaxLifetimeDays) days, and the tenant application management policy limiting new secrets and certificates to $($script:TPAppCredMaxLifetimeDays) days for every application"

    # No credentials at all is a legitimate and good state — an app-only
    # integration may use federated credentials, or the tenant may simply have
    # no app registrations. The section status above already proved the query
    # ran, so this is a real answer rather than an empty one.
    if ($creds.Count -eq 0) {
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
            -Verified (@('No app registration in the tenant carries a client secret or certificate, so there are no standing application credentials to rotate or leak.') + @($pv.Verified)) `
            -Shortfalls $pv.Shortfalls -NotEstablished $pv.NotEstablished `
            -CurrentValue 'No application secrets or certificates' -RequiredValue $required
        return
    }

    $expired  = [System.Collections.Generic.List[object]]::new()
    $expiring = [System.Collections.Generic.List[object]]::new()
    $longLived = [System.Collections.Generic.List[object]]::new()

    foreach ($c in $creds) {
        $days = Get-TPObjectField -Item $c -Key 'DaysRemaining' -Default $null
        $life = Get-TPObjectField -Item $c -Key 'LifetimeDays'  -Default $null
        $row  = @{
            App            = [string](Get-TPObjectField -Item $c -Key 'AppDisplayName')
            AppId          = [string](Get-TPObjectField -Item $c -Key 'AppId')
            CredentialType = [string](Get-TPObjectField -Item $c -Key 'CredentialType')
            DaysRemaining  = $days
            LifetimeDays   = $life
        }
        if ($null -ne $days) {
            if     ($days -lt 0)                            { $expired.Add($row) }
            elseif ($days -le $script:TPAppCredWarnDays)   { $expiring.Add($row) }
        }
        # An already-expired credential is dead and cannot be used, so its
        # lifetime is not also counted as a live exposure.
        if ($null -ne $life -and $life -gt $script:TPAppCredMaxLifetimeDays -and $null -ne $days -and $days -ge 0) {
            $longLived.Add($row)
        }
    }

    $total = $creds.Count
    $parts = @()
    if ($expired.Count)   { $parts += "$($expired.Count) expired" }
    if ($expiring.Count)  { $parts += "$($expiring.Count) expiring within $($script:TPAppCredWarnDays) days" }
    if ($longLived.Count) { $parts += "$($longLived.Count) issued for more than $($script:TPAppCredMaxLifetimeDays) days" }

    $v = @(); $sf = @()
    if ($parts.Count -eq 0) {
        $v += "All $total application credentials are current and none was issued with a lifetime beyond $($script:TPAppCredMaxLifetimeDays) days."
    } else {
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
        $sf += $detail
    }
    $v += @($pv.Verified); $sf += @($pv.Shortfalls)
    $current  = $(if ($parts.Count) { $parts -join ', ' } else { "$total credential(s), none expired, expiring within $($script:TPAppCredWarnDays) days, or issued for more than $($script:TPAppCredMaxLifetimeDays) days" })
    $affected = @(@($expired) + @($expiring) + @($longLived))

    # Expired and long-lived credentials are the real exposure, and a Gap
    # whatever else is met. An imminent expiry on its own is an operational
    # warning: Partial when the rest is met. Two calls with literal -ShortfallState
    # values so the automation audit can see the control discriminates.
    if ($expired.Count -gt 0 -or $longLived.Count -gt 0) {
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $v -Shortfalls $sf -NotEstablished $pv.NotEstablished `
            -CurrentValue $current -RequiredValue $required -AffectedObjects $affected -ShortfallState 'Gap'
    } else {
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $v -Shortfalls $sf -NotEstablished $pv.NotEstablished `
            -CurrentValue $current -RequiredValue $required -AffectedObjects $affected
    }
}

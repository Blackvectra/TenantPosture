#Requires -Version 7.0
#
# Test-NRGSignInControls.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Sign-in log IoC evaluators for the unified admin-scope IR
#          workflow. Each evaluator emits SIGNIN-* findings AND contributes
#          to a per-user IoC score the orchestrator uses to rank suspicious
#          users for the deep-dive step.
#
# Per-user score is accumulated in module-scope $script:NRGSignInUserScores
# (cleared by Clear-NRGSignInTriageState). Aggregator reads the scores
# at the end and emits SIGNIN-RANK-* findings + populates the triage
# ranked list that Publish-NRGSignInTriageReport renders.

if (-not (Get-Variable -Name NRGSignInUserScores -Scope Script -ErrorAction SilentlyContinue)) {
    $script:NRGSignInUserScores = @{}
}

function Clear-NRGSignInTriageState {
    [CmdletBinding()] param()
    $script:NRGSignInUserScores = @{}
}

# Internal helper: add to a user's IoC score with a reason tag
function script:Add-NRGSignInScore {
    param([string] $UserPrincipalName, [int] $Points, [string] $Reason)
    if (-not $UserPrincipalName) { return }
    $upn = $UserPrincipalName.ToLowerInvariant()
    if (-not $script:NRGSignInUserScores.ContainsKey($upn)) {
        $script:NRGSignInUserScores[$upn] = [ordered]@{
            UserPrincipalName = $upn
            Score             = 0
            Reasons           = @()
            DisplayName       = $null
        }
    }
    $script:NRGSignInUserScores[$upn].Score += $Points
    if ($Reason -and ($script:NRGSignInUserScores[$upn].Reasons -notcontains $Reason)) {
        $script:NRGSignInUserScores[$upn].Reasons += $Reason
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# SIGNIN-1.1 — Failed→Success correlation (a possible password attack)
# ─────────────────────────────────────────────────────────────────────────────
function Test-NRGSignInControlFailedToSuccess {
    [CmdletBinding()] param()
    $cid   = 'SIGNIN-1.1'
    $title = 'Failed-then-success sign-in correlations (possible password attack)'
    $cat   = 'Email'

    $bag = Get-NRGRawData -Key 'IR-SignIn-Recent'
    if (-not $bag -or -not $bag.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' -Detail 'Sign-in collection did not succeed.'
        return
    }

    $events = @($bag.Data.Events)
    if ($events.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'High' -Detail "No sign-in events in the last $($bag.Data.WindowDays) days."
        return
    }

    # Group by UPN and walk the timeline per user. A "cluster" is: at least 5
    # CREDENTIAL failures (wrong password, smart lockout) within a 30-minute
    # window followed by a success for the same account. It is a suspicious
    # CORRELATION, not proof the success was attacker-controlled: the source of
    # the success is compared with the sources of the failures and the finding
    # says how well they line up. Failures with no readable status, and failures
    # of another kind (MFA required, blocked by policy, expired password), are
    # not credential guesses and are not counted.
    $credentialFailureCodes = @(50126, 50053)
    $clusters = @()
    $byUser = $events | Group-Object userPrincipalName
    foreach ($g in $byUser) {
        $upn = $g.Name
        if (-not $upn) { continue }
        $userEvents = $g.Group | Sort-Object createdDateTime
        $failBuffer = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $userEvents) {
            $code = $null
            $statusObj = Get-NRGObjectField -Item $e -Key 'status' -Default $null
            if ($null -ne $statusObj) { $code = Get-NRGObjectField -Item $statusObj -Key 'errorCode' -Default $null }
            if ($null -eq $code) { continue }   # status unknown: neither a failure nor a success
            $isSuccess = ($code -eq 0)
            $ts = [datetime]::MinValue
            if (-not [datetime]::TryParse([string](Get-NRGObjectField -Item $e -Key 'createdDateTime' -Default ''), [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$ts)) { continue }
            # Drop failures older than 30 minutes from the buffer
            while ($failBuffer.Count -gt 0) {
                $oldestTs = $failBuffer[0].Ts
                if (($ts - $oldestTs).TotalMinutes -gt 30) {
                    $failBuffer.RemoveAt(0)
                } else { break }
            }
            if (-not $isSuccess) {
                if ($credentialFailureCodes -contains [int]$code) { $failBuffer.Add(@{ Ts = $ts; Ip = [string](Get-NRGObjectField -Item $e -Key 'ipAddress' -Default '') }) }
                continue
            }
            # Success: does the buffer hold >= 5 credential failures?
            if ($failBuffer.Count -ge 5) {
                $successIp = [string](Get-NRGObjectField -Item $e -Key 'ipAddress' -Default '')
                $failIps   = @($failBuffer | ForEach-Object { $_.Ip } | Where-Object { $_ } | Select-Object -Unique)
                $net24 = { param([string] $ip) if ($ip -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') { $Matches[1] } else { '' } }
                $relation = if (-not $successIp -or $failIps.Count -eq 0) { 'Unknown' }
                            elseif ($failIps -contains $successIp) { 'SameAddress' }
                            elseif ((& $net24 $successIp) -and (@($failIps | Where-Object { (& $net24 $_) -eq (& $net24 $successIp) }).Count -gt 0)) { 'SameNetwork' }
                            else { 'DifferentSource' }
                $confidence = switch ($relation) { 'SameAddress' { 'High' } 'SameNetwork' { 'Medium' } default { 'Low' } }
                $points = switch ($confidence) { 'High' { 60 } 'Medium' { 40 } default { 20 } }
                $clusters += [ordered]@{
                    UserPrincipalName = $upn
                    SuccessAt         = [string](Get-NRGObjectField -Item $e -Key 'createdDateTime' -Default '')
                    SuccessIp         = $successIp
                    FailureCount      = $failBuffer.Count
                    FailureIps        = $failIps
                    SourceRelation    = $relation
                    Confidence        = $confidence
                    Distributed       = ($failIps.Count -ge 3)
                }
                Add-NRGSignInScore -UserPrincipalName $upn -Points $points `
                    -Reason "failed-then-success correlation ($($failBuffer.Count) credential failures, then a success; source relation: $relation, confidence $confidence)"
                $failBuffer.Clear()
            } else {
                # Reset on success (assume legit)
                $failBuffer.Clear()
            }
        }
    }

    $completeness = Get-NRGSignInCollectionCompleteness -Keys 'IR-SignIn-Recent'
    if ($clusters.Count -eq 0) {
        if ($completeness.Complete) {
            Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
                -Title $title -Severity 'High' `
                -Detail "Reviewed $($events.Count) sign-in events across $($byUser.Count) users. No failed-then-success correlations detected (5 or more credential failures within 30 minutes followed by a success). This describes the events read, not the whole tenant."
        } else {
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
                -Title $title -Severity 'High' `
                -Detail "Not cleared: no failed-then-success correlation was found in the $($events.Count) events read, but the sign-in reads were incomplete ($($completeness.Reasons -join '; ')), so this is not evidence that none occurred."
        }
    } else {
        $worst = if (@($clusters | Where-Object { $_.Confidence -eq 'High' }).Count -gt 0) { 'Critical' } elseif (@($clusters | Where-Object { $_.Confidence -eq 'Medium' }).Count -gt 0) { 'High' } else { 'Medium' }
        $detail = "FOUND $($clusters.Count) failed-then-success correlation(s): 5 or more credential failures within 30 minutes, then a success for the same account. This is a suspicious pattern, not proof the success was attacker-controlled; confidence reflects how well the success source lines up with the failure sources.`n"
        foreach ($c in $clusters | Select-Object -First 10) {
            $rel = switch ($c.SourceRelation) {
                'SameAddress'     { 'success came from an address that also failed' }
                'SameNetwork'     { 'success came from the same /24 network as some failures' }
                'DifferentSource' { 'success came from a different source than the failures (a distributed attack, or an unrelated legitimate sign-in)' }
                default           { 'source addresses were not available to compare' }
            }
            $dist = if ($c.Distributed) { ' Failures came from 3 or more addresses.' } else { '' }
            $detail += "  - $($c.UserPrincipalName): $($c.FailureCount) credential failures, then a success at $($c.SuccessAt) from $($c.SuccessIp); confidence $($c.Confidence); $rel.$dist`n"
        }
        if (-not $completeness.Complete) { $detail += "Note: the sign-in reads were incomplete ($($completeness.Reasons -join '; ')); more correlations may exist.`n" }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
            -Title $title -Severity $worst -Detail $detail `
            -CurrentValue "$($clusters.Count) correlation(s) across $(@($clusters | ForEach-Object { $_.UserPrincipalName } | Select-Object -Unique).Count) user(s)" `
            -Remediation "Review each flagged account with its owner and revoke active sessions where the sign-in is not theirs. For deep-dive, issue a Temporary Access Pass (Entra > Users > Authentication methods > Add > Temporary Access Pass) and run Invoke-NRGEmailAssessment.ps1 as the user with the TAP. Compare the success source with the account's usual locations and with tenant Conditional Access named locations before treating it as attacker infrastructure."
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# SIGNIN-1.2 — Anonymous-IP / TOR sign-ins
# ─────────────────────────────────────────────────────────────────────────────
function Test-NRGSignInControlAnonymousIp {
    [CmdletBinding()] param()
    $cid   = 'SIGNIN-1.2'
    $title = 'Sign-ins from anonymous IP (TOR / anon-VPN)'
    $cat   = 'Email'

    $bag = Get-NRGRawData -Key 'IR-SignIn-AnonIp'
    if (-not $bag -or -not $bag.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' -Detail 'Anon-IP sign-in collection did not succeed.'
        return
    }

    $events = @($bag.Data.Events)
    if ($events.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'High' -Detail 'No anon-IP sign-ins flagged by Microsoft in the window.'
        return
    }

    # Score every user with an anon-IP sign-in. Successful anon-IP sign-in
    # is much worse than a failed one.
    $userHits = @{}
    foreach ($e in $events) {
        $upn = $e.userPrincipalName
        if (-not $upn) { continue }
        $isSuccess = ($e.status -and $e.status.errorCode -eq 0)
        $pts = if ($isSuccess) { 50 } else { 15 }
        Add-NRGSignInScore -UserPrincipalName $upn -Points $pts `
            -Reason ("anonymous-IP sign-in ({0})" -f $(if ($isSuccess) { 'SUCCESS' } else { 'failed' }))
        if (-not $userHits.ContainsKey($upn)) { $userHits[$upn] = @{ Success=0; Failed=0 } }
        if ($isSuccess) { $userHits[$upn].Success++ } else { $userHits[$upn].Failed++ }
    }

    $detail = "FOUND $($events.Count) anon-IP sign-in(s) across $($userHits.Keys.Count) user(s):`n"
    foreach ($k in ($userHits.Keys | Sort-Object { -$userHits[$_].Success } | Select-Object -First 10)) {
        $detail += "  - $k — SUCCESS: $($userHits[$k].Success), failed: $($userHits[$k].Failed)`n"
    }
    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
        -Title $title -Severity 'Critical' -Detail $detail `
        -CurrentValue "$($events.Count) anon-IP events, $($userHits.Keys.Count) users" `
        -Remediation "Successful sign-ins from anon-IP infrastructure are near-certain compromise. Revoke sessions + reset passwords for each flagged user. If the tenant has Conditional Access, block sign-ins from anonymous IP addresses tenant-wide."
}

# ─────────────────────────────────────────────────────────────────────────────
# SIGNIN-1.3 — Impossible travel / unfamiliar-features sign-ins
# ─────────────────────────────────────────────────────────────────────────────
function Test-NRGSignInControlImpossibleTravel {
    [CmdletBinding()] param()
    $cid   = 'SIGNIN-1.3'
    $title = 'Impossible travel or unfamiliar features (Microsoft IP heuristic)'
    $cat   = 'Email'

    $bag = Get-NRGRawData -Key 'IR-SignIn-Travel'
    if (-not $bag -or -not $bag.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' -Detail 'Impossible-travel collection did not succeed.'
        return
    }

    $events = @($bag.Data.Events)
    if ($events.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'High' -Detail 'No impossible-travel / unfamiliar-features events flagged in the window.'
        return
    }

    $byUser = $events | Group-Object userPrincipalName
    foreach ($g in $byUser) {
        if (-not $g.Name) { continue }
        # 40 points per flagged user — Microsoft's heuristic is noisy
        # (legitimate VPN use trips it) so lower than the anon-IP weight.
        Add-NRGSignInScore -UserPrincipalName $g.Name -Points 40 `
            -Reason "impossible-travel / unfamiliar-features ($($g.Group.Count) event(s))"
    }

    $detail = "FOUND $($events.Count) impossible-travel / unfamiliar-features event(s) across $($byUser.Count) user(s):`n"
    foreach ($g in ($byUser | Sort-Object Count -Descending | Select-Object -First 10)) {
        $sample = $g.Group | Select-Object -First 1
        $loc = if ($sample.location) { "$($sample.location.city), $($sample.location.countryOrRegion)" } else { '(unknown)' }
        $detail += "  - $($g.Name) — $($g.Group.Count) event(s), most recent IP $($sample.ipAddress), location $loc`n"
    }
    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
        -Title $title -Severity 'High' -Detail $detail `
        -Remediation "Cross-check each flagged user's recent travel + VPN use before treating as IoC. Microsoft's heuristic is noisy. Successful sign-ins paired with mailbox-level IoCs (inbox rules, outbound BEC) are the high-confidence subset."
}

# ─────────────────────────────────────────────────────────────────────────────
# SIGNIN-1.4 — Identity Protection risky users (Microsoft ML)
# ─────────────────────────────────────────────────────────────────────────────
function Test-NRGSignInControlRiskyUsers {
    [CmdletBinding()] param()
    $cid   = 'SIGNIN-1.4'
    $title = 'Microsoft Identity Protection risky users'
    $cat   = 'Email'

    $bag = Get-NRGRawData -Key 'IR-SignIn-RiskyUsers'
    if (-not $bag -or -not $bag.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Medium' `
            -Detail 'Identity Protection /riskyUsers endpoint not available (Entra ID P2 required) or collection failed.'
        return
    }

    $users = @($bag.Data.Users)
    if ($users.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'Medium' -Detail 'No active risky users flagged by Identity Protection.'
        return
    }

    foreach ($u in $users) {
        $upn = $u.userPrincipalName
        if (-not $upn) { continue }
        $level = [string]$u.riskLevel
        $pts = switch ($level.ToLowerInvariant()) {
            'high'   { 50 }
            'medium' { 25 }
            'low'    { 10 }
            default  { 15 }
        }
        Add-NRGSignInScore -UserPrincipalName $upn -Points $pts `
            -Reason "Identity Protection risk level: $level"
        # Also stash display name for the publisher
        if ($script:NRGSignInUserScores.ContainsKey($upn.ToLowerInvariant())) {
            $script:NRGSignInUserScores[$upn.ToLowerInvariant()].DisplayName = $u.userDisplayName
        }
    }

    $detail = "FOUND $($users.Count) risky user(s) flagged by Microsoft Identity Protection:`n"
    foreach ($u in ($users | Sort-Object { switch ($_.riskLevel) {'high'{3}'medium'{2}'low'{1}default{0}} } -Descending | Select-Object -First 10)) {
        $detail += "  - $($u.userPrincipalName) — risk level: $($u.riskLevel), state: $($u.riskState), last updated: $($u.riskLastUpdatedDateTime)`n"
    }
    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
        -Title $title -Severity 'High' -Detail $detail `
        -CurrentValue "$($users.Count) risky users" `
        -Remediation "Review each in Defender Portal > Identity Protection > Risky users. Confirm or dismiss the risk after triage. Use the per-user mailbox deep-dive (Email-IR) to confirm compromise before action."
}

# ─────────────────────────────────────────────────────────────────────────────
# SIGNIN-1.6 — Geo-anomaly: sign-ins from outside the home state / country
# ─────────────────────────────────────────────────────────────────────────────
# The primary BEC detection signal: a tenant's users almost always sign in
# from one home base (for the operator's clients, North Dakota). A successful
# sign-in from a DIFFERENT state — especially a different country — is the
# classic "your account was just accessed from somewhere it never is" IoC.
#
# Home baseline is AUTO-DETECTED as the modal (most-frequent) state across all
# SUCCESSFUL sign-ins in the window, so it works across every client without
# config. Operator can override with -HomeState / -HomeCountry on the
# orchestrator (passed through to this evaluator).
#
# Scoring (only SUCCESSFUL sign-ins count — a failed attempt from abroad is
# noise; a success is access):
#   foreign COUNTRY success  : 55   (account accessed from another country)
#   out-of-home-STATE success: 35   (same country, wrong state)
# Failed attempts from outside the home base are listed for context but not
# scored, to keep the ranking focused on actual access.
function Test-NRGSignInControlGeoAnomaly {
    [CmdletBinding()] param(
        # Explicit overrides. When omitted, HomeState is auto-detected as the
        # modal state of successful sign-ins; HomeCountry as the modal country.
        [string] $HomeState,
        [string] $HomeCountry
    )
    $cid   = 'SIGNIN-1.6'
    $title = 'Sign-ins from outside the home state / country (geo-anomaly)'
    $cat   = 'Email'

    $bag = Get-NRGRawData -Key 'IR-SignIn-Recent'
    if (-not $bag -or -not $bag.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' -Detail 'Sign-in collection did not succeed.'
        return
    }

    $events = @($bag.Data.Events)
    # Only events that carry a usable location can be geo-evaluated.
    $located = @($events | Where-Object { $_.location -and ($_.location.state -or $_.location.countryOrRegion) })
    if ($located.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail 'No sign-in events carry location data (sign-in logs may not include geo, or none in window).'
        return
    }

    # Helper to normalize a location value for comparison (case-insensitive,
    # trimmed). Entra returns full state names ("North Dakota") and 2-letter
    # ISO country codes ("US").
    $norm = { param($v) if ($v) { ([string]$v).Trim().ToLowerInvariant() } else { '' } }

    # Auto-detect home baseline from SUCCESSFUL sign-ins (modal state/country).
    $successful = @($located | Where-Object { $_.status -and $_.status.errorCode -eq 0 })
    if (-not $HomeState) {
        $stateCounts = @{}
        foreach ($e in $successful) {
            $st = & $norm $e.location.state
            if ($st) { if (-not $stateCounts.ContainsKey($st)) { $stateCounts[$st] = 0 }; $stateCounts[$st]++ }
        }
        if ($stateCounts.Keys.Count -gt 0) {
            $HomeState = ($stateCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
        }
    } else {
        $HomeState = & $norm $HomeState
    }
    if (-not $HomeCountry) {
        $countryCounts = @{}
        foreach ($e in $successful) {
            $c = & $norm $e.location.countryOrRegion
            if ($c) { if (-not $countryCounts.ContainsKey($c)) { $countryCounts[$c] = 0 }; $countryCounts[$c]++ }
        }
        if ($countryCounts.Keys.Count -gt 0) {
            $HomeCountry = ($countryCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
        }
    } else {
        $HomeCountry = & $norm $HomeCountry
    }

    if (-not $HomeState -and -not $HomeCountry) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail 'Could not establish a home-state/country baseline (no located successful sign-ins).'
        return
    }

    # Walk every located event; flag the ones outside the home baseline.
    $anomalies = @()
    foreach ($e in $located) {
        $st = & $norm $e.location.state
        $c  = & $norm $e.location.countryOrRegion
        $isSuccess = ($e.status -and $e.status.errorCode -eq 0)

        $foreignCountry = $HomeCountry -and $c -and ($c -ne $HomeCountry)
        $foreignState   = $HomeState -and $st -and ($st -ne $HomeState) -and -not $foreignCountry

        if (-not $foreignCountry -and -not $foreignState) { continue }

        $kind = if ($foreignCountry) { 'foreign-country' } else { 'out-of-state' }
        $anomalies += [ordered]@{
            UserPrincipalName = [string]$e.userPrincipalName
            When              = $e.createdDateTime
            IP                = [string]$e.ipAddress
            City              = if ($e.location.city) { [string]$e.location.city } else { '' }
            State             = if ($e.location.state) { [string]$e.location.state } else { '' }
            Country           = if ($e.location.countryOrRegion) { [string]$e.location.countryOrRegion } else { '' }
            Success           = $isSuccess
            Kind              = $kind
        }

        # Score successful anomalies only.
        if ($isSuccess -and $e.userPrincipalName) {
            $pts = if ($foreignCountry) { 55 } else { 35 }
            $loc = (@($e.location.city, $e.location.state, $e.location.countryOrRegion) | Where-Object { $_ }) -join ', '
            Add-NRGSignInScore -UserPrincipalName $e.userPrincipalName -Points $pts `
                -Reason "successful sign-in from $kind ($loc; home=$HomeState/$HomeCountry)"
        }
    }

    $homeLabel = (@($HomeState, $HomeCountry) | Where-Object { $_ }) -join ' / '
    if ($anomalies.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail "Home baseline: $homeLabel. All $($located.Count) located sign-in(s) are within the home state/country."
        return
    }

    $successAnoms = @($anomalies | Where-Object { $_.Success })
    $detail = "Home baseline (auto-detected unless overridden): $homeLabel`n"
    $detail += "FOUND $($anomalies.Count) sign-in(s) outside home ($($successAnoms.Count) SUCCESSFUL):`n"
    foreach ($a in ($anomalies | Sort-Object { -[int][bool]$_.Success } | Select-Object -First 20)) {
        $tag = if ($a.Success) { 'SUCCESS' } else { 'failed ' }
        $loc = (@($a.City, $a.State, $a.Country) | Where-Object { $_ }) -join ', '
        $detail += "  [$tag] $($a.UserPrincipalName) — $loc  ($($a.IP), $($a.When)) [$($a.Kind)]`n"
    }

    $state    = if ($successAnoms.Count -gt 0) { 'Gap' }     else { 'Gap' }
    $severity = if ($successAnoms.Count -gt 0) { 'Critical' } else { 'High' }
    Add-NRGFinding -ControlId $cid -State $state -Category $cat `
        -Title $title -Severity $severity -Detail $detail `
        -CurrentValue "$($anomalies.Count) out-of-home sign-in(s), $($successAnoms.Count) successful" `
        -Remediation "Confirm whether the flagged users actually traveled. Successful sign-ins from a foreign country or a state the user never works from are high-confidence account-takeover IoCs — deep-dive those mailboxes first. Set -HomeState / -HomeCountry to override the auto-detected baseline if the modal state is wrong for this tenant."
}

# ─────────────────────────────────────────────────────────────────────────────
# SIGNIN-1.5 — IP threat-intel enrichment of suspicious sign-in sources
# ─────────────────────────────────────────────────────────────────────────────
# Threat-hunt step: for every IP that produced an anonymous-IP or
# impossible-travel sign-in, look up geolocation + ASN owner via RDAP and
# cross-check the Tor exit-node list. Confirmed-bad infrastructure (Tor exit,
# hosting/datacenter ASN, known commercial VPN ASN) bumps the associated
# user's IoC score so attacker infra rises in the ranking. Stores the
# enrichment in IR-SignIn-IPIntel for the publisher to render.
#
# External calls: RDAP (rdap.org) only. Degrades gracefully when offline
# — emits NotApplicable rather than crashing.
function Test-NRGSignInControlIPIntel {
    [CmdletBinding()] param(
        # Cap the number of unique IPs enriched. RDAP is rate-limited and the
        # operator doesn't need 500 lookups — the suspicious set is small.
        [int] $MaxIPs = 25
    )
    $cid   = 'SIGNIN-1.5'
    $title = 'Threat-intel on suspicious sign-in source IPs'
    $cat   = 'Email'

    if (-not (Get-Command Get-NRGIPSignInIntel -ErrorAction SilentlyContinue)) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Medium' -Detail 'IP threat-intel helper (Get-NRGIPSignInIntel) not loaded.'
        return
    }

    # Gather suspicious IPs (+ the user that signed in from each) from the
    # anon-IP and travel bags. These are the events Microsoft already flagged.
    # ip -> @{ Users = every user seen from it; SuccessUsers = only the users whose
    # OWN sign-in from it succeeded }. Success is tracked per user: a shared
    # address (office NAT, a VPN exit) must not make one user's success count
    # against another user who only failed from it.
    $ipToUsers = @{}
    foreach ($bagKey in 'IR-SignIn-AnonIp','IR-SignIn-Travel') {
        $bag = Get-NRGRawData -Key $bagKey
        if (-not $bag -or -not $bag.Success) { continue }
        foreach ($e in @($bag.Data.Events)) {
            $ip = [string]$e.ipAddress
            if (-not $ip) { continue }
            if (-not $ipToUsers.ContainsKey($ip)) {
                $ipToUsers[$ip] = @{ Users = [System.Collections.Generic.HashSet[string]]::new(); SuccessUsers = [System.Collections.Generic.HashSet[string]]::new() }
            }
            if ($e.userPrincipalName) {
                [void]$ipToUsers[$ip].Users.Add([string]$e.userPrincipalName)
                if ($e.status -and $e.status.errorCode -eq 0) { [void]$ipToUsers[$ip].SuccessUsers.Add([string]$e.userPrincipalName) }
            }
        }
    }

    if ($ipToUsers.Keys.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'Medium' -Detail 'No suspicious source IPs to enrich (no anon-IP or impossible-travel events).'
        return
    }

    $targets = @($ipToUsers.Keys | Select-Object -First $MaxIPs)
    $enriched = @()
    $failed   = 0
    $badInfra = 0
    foreach ($ip in $targets) {
        $intel = $null
        try { $intel = Get-NRGIPSignInIntel -IPAddress $ip } catch { $failed++; continue }
        if (-not $intel) { $failed++; continue }
        $enriched += $intel
        if ((Get-NRGObjectField -Item $intel -Key 'LookupStatus' -Default '') -eq 'Failed') { $failed++; continue }

        # Bump score for flagged infra ONLY for the users whose own sign-in from
        # it succeeded (a failed attempt from Tor is noise), and only from a
        # lookup that actually returned registrant data. Never for another user
        # who merely appears on the same address.
        if ($ipToUsers[$ip].SuccessUsers.Count -gt 0 -and @($intel.Flags).Count -gt 0) {
            $badInfra++
            $flagStr = @($intel.Flags) -join '+'
            foreach ($u in $ipToUsers[$ip].SuccessUsers) {
                Add-NRGSignInScore -UserPrincipalName $u -Points 30 `
                    -Reason "successful sign-in from an address whose registrant name matches $flagStr ($ip): context, not proof of attacker infrastructure"
            }
        }
    }

    $resolved = @($enriched | Where-Object { (Get-NRGObjectField -Item $_ -Key 'LookupStatus' -Default '') -eq 'Resolved' })
    $noOwner  = @($enriched | Where-Object { (Get-NRGObjectField -Item $_ -Key 'LookupStatus' -Default '') -eq 'NoOwnerData' }).Count
    $capNote  = if ($ipToUsers.Keys.Count -gt $targets.Count) { " Only the first $($targets.Count) of $($ipToUsers.Keys.Count) suspicious addresses were looked up." } else { '' }
    $lookupNote = "Registrant data came back for $($resolved.Count) of $($targets.Count) address(es) looked up; $failed lookup(s) failed and $noOwner returned no owner.$capNote"

    # Stash enrichment for the publisher.
    Set-NRGRawData -Key 'IR-SignIn-IPIntel' -Data @{
        CollectorId = $cid
        CollectedAt = (Get-Date -Format 'o')
        Success     = $true
        Data        = [ordered]@{ Count = $enriched.Count; Resolved = $resolved.Count; Failed = $failed; NoOwnerData = $noOwner; Requested = $targets.Count; Items = $enriched }
    }

    if ($resolved.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Medium' `
            -Detail "Not assessed: no registrant lookup completed for the $($targets.Count) suspicious address(es), so nothing can be said about who holds them. RDAP may be unreachable from this host. $lookupNote"
        return
    }

    $flagged = @($resolved | Where-Object { @($_.Flags).Count -gt 0 })
    $detail = "$lookupNote`n"
    foreach ($i in ($resolved | Sort-Object { @($_.Flags).Count } -Descending | Select-Object -First 20)) {
        $line = "  - $($i.IPAddress)"
        if ($i.Country)  { $line += " [$($i.Country)]" }
        if ($i.ASNOwner) { $line += " $($i.ASNOwner)" }
        if (@($i.Flags).Count -gt 0) { $line += "  *** registrant name matches: $(@($i.Flags) -join ', ') ***" }
        $who = $ipToUsers[[string]$i.IPAddress]
        if ($who) { $line += "  (users seen: $($who.Users.Count), with a successful sign-in: $($who.SuccessUsers.Count)$(if ($who.Users.Count -gt 1) { '; shared address' }))" }
        $detail += "$line`n"
    }

    if ($flagged.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
            -Title $title -Severity 'High' -Detail $detail `
            -CurrentValue "$($flagged.Count) of $($resolved.Count) resolved IP(s) registered to a hosting or VPN provider name (context, not a malicious-IP verdict)" `
            -Remediation "A registrant name that matches a hosting or VPN provider is context, not a reputation verdict: legitimate users also sign in through commercial VPNs and hosted desktops, and a shared address (a corporate VPN exit, an office NAT) is possible. The detail shows how many users were seen from each address and how many succeeded. Confirm with those users before blocking, then prioritize the users who succeeded for deep-dive."
    } elseif ($resolved.Count -eq $ipToUsers.Keys.Count) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'Medium' -Detail $detail `
            -CurrentValue "$($resolved.Count) IP(s) resolved, none registered to a hosting or VPN provider name"
    } else {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
            -Title $title -Severity 'Medium' `
            -Detail "Not cleared: nothing among the addresses that resolved matched a hosting or VPN provider name, but not every suspicious address could be looked up, and an unresolved address is not a clean one. $detail" `
            -CurrentValue "$($resolved.Count) of $($ipToUsers.Keys.Count) suspicious IP(s) resolved, none flagged"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Completeness — what the "no indicators" conclusion actually rests on
# ─────────────────────────────────────────────────────────────────────────────
function Get-NRGSignInCollectionCompleteness {
    <#
    .SYNOPSIS
        Says whether the sign-in reads behind a conclusion completed. Recent,
        AnonIp and Travel are required; a Recent read that hit its event cap is
        incomplete because older events in the window were not read. RiskyUsers
        (Entra ID P2) is optional and only noted.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        # The reads the conclusion rests on. A detector that reads only the
        # recent-events bag is not made incomplete by a failed anon-IP read.
        [string[]] $Keys = @('IR-SignIn-Recent', 'IR-SignIn-AnonIp', 'IR-SignIn-Travel')
    )
    $reasons = [System.Collections.Generic.List[string]]::new()
    $events = 0; $window = 0
    foreach ($k in $Keys) {
        $bag = Get-NRGRawData -Key $k
        if (-not $bag -or -not (Get-NRGObjectField -Item $bag -Key 'Success' -Default $false)) { $reasons.Add("$k did not complete"); continue }
        if ($k -eq 'IR-SignIn-Recent') {
            $events = [int](Get-NRGNestedProperty -Object $bag -Path 'Data.Count' -Default 0)
            $window = [int](Get-NRGNestedProperty -Object $bag -Path 'Data.WindowDays' -Default 0)
            if ([bool](Get-NRGNestedProperty -Object $bag -Path 'Data.Truncated' -Default $false)) {
                $reasons.Add("the sign-in read stopped at $events events, so older events in the $window-day window were not read")
            }
        } elseif ([bool](Get-NRGNestedProperty -Object $bag -Path 'Data.Truncated' -Default $false)) {
            # AnonIp reads one server page; Travel is derived from the recent read.
            $reasons.Add("$k is partial: $(Get-NRGNestedProperty -Object $bag -Path 'Data.Source' -Default 'its source') did not cover every event in the window")
        }
    }
    return [ordered]@{ Complete = ($reasons.Count -eq 0); Reasons = @($reasons); EventsRead = $events; WindowDays = $window }
}

# ─────────────────────────────────────────────────────────────────────────────
# SIGNIN-RANK — Aggregate per-user scores and emit the prioritized list
# ─────────────────────────────────────────────────────────────────────────────
function Test-NRGSignInControlRankUsers {
    [CmdletBinding()] param()
    $cid   = 'SIGNIN-2.1'
    $title = 'Ranked list of users for IR deep-dive'
    $cat   = 'Email'

    if ($script:NRGSignInUserScores.Count -eq 0) {
        # A conclusion of "nothing found" needs the reads it rests on. Without them
        # the honest answer is "not cleared", never "clean".
        $comp = Get-NRGSignInCollectionCompleteness
        if (-not $comp.Complete) {
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $cat `
                -Title $title -Severity 'High' `
                -Detail "Not cleared: no user scored, but the evidence is incomplete ($($comp.Reasons -join '; ')). An absence of indicators here is not evidence that none occurred."
            return
        }
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $cat `
            -Title $title -Severity 'High' `
            -Detail "No user scored: no sign-in indicators in the $($comp.EventsRead) sign-in events read over the last $($comp.WindowDays) days. This describes the events read, not the whole tenant."
        return
    }

    # Stash the ranked list in raw data for the orchestrator to consume
    $ranked = @($script:NRGSignInUserScores.Values | Sort-Object { $_.Score } -Descending)
    Set-NRGRawData -Key 'IR-SignIn-Ranked' -Data @{
        CollectorId = $cid
        CollectedAt = (Get-Date -Format 'o')
        Success     = $true
        Data        = [ordered]@{
            Count = $ranked.Count
            Users = $ranked
        }
    }

    $detail = "RANKED USER LIST (highest IoC score first):`n"
    foreach ($u in ($ranked | Select-Object -First 15)) {
        $detail += "  $($u.Score.ToString().PadLeft(4))  $($u.UserPrincipalName)`n"
        $detail += "        $($u.Reasons -join '; ')`n"
    }
    $severity = if ($ranked[0].Score -ge 70) { 'Critical' } else { 'High' }
    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $cat `
        -Title $title -Severity $severity -Detail $detail `
        -CurrentValue "$($ranked.Count) users scored, top score: $($ranked[0].Score)" `
        -Remediation 'Run the per-user Email-IR deep-dive on each flagged user: issue a Temporary Access Pass in Microsoft Entra (Users > Authentication methods > Add > Temporary Access Pass), sign in as that user with the TAP, run Invoke-NRGEmailAssessment.ps1. Critical scores warrant immediate session revocation.'
}

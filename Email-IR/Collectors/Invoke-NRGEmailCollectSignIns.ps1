#Requires -Version 7.0
#
# Invoke-NRGEmailCollectSignIns.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Collect tenant-wide sign-in data for incident-response triage.
#          Admin scope (AuditLog.Read.All + IdentityRiskyUser.Read.All).
#
# Pulls four IoC sources, each into its own raw-data bag so evaluators can
# read them independently:
#
#   IR-SignIn-Recent       — last N days of /auditLogs/signIns (raw events)
#   IR-SignIn-AnonIp       — sign-ins flagged with riskEventType anonymousIpAddress
#   IR-SignIn-Travel       — sign-ins flagged with unfamiliarFeatures /
#                            impossibleTravel risk events
#   IR-SignIn-RiskyUsers   — /identityProtection/riskyUsers (Microsoft ML)
#
# We do the Failed→Success cluster analysis in the evaluator rather than
# the collector — it's a post-process on the raw signIns bag, and keeping
# the cluster heuristic with its tests in Test-NRGSignInControls makes the
# scoring auditable.

function Invoke-NRGEmailCollectSignIns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 90)]
        [int] $WindowDays = 7,

        # Cap the number of sign-in events pulled. The audit log can be
        # enormous on busy tenants (millions of events). 5000 is enough
        # for the heuristic and respects Graph throttling.
        [Parameter(Mandatory = $false)]
        [ValidateRange(100, 25000)]
        [int] $MaxEvents = 5000
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $cutoff      = (Get-Date).ToUniversalTime().AddDays(-$WindowDays).ToString('o')
    $collectorId = 'IR-SignIn'
    # Coverage is registered at the END from what actually completed. It used to
    # be 'Collected' here, before any query ran, so a run in which every Graph
    # read failed still reported complete coverage.

    # ── Recent sign-ins ──────────────────────────────────────────────────────
    $recentBag = [ordered]@{
        CollectorId = "$collectorId-Recent"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        $events = @()
        $select = 'id,createdDateTime,userPrincipalName,userId,userDisplayName,appDisplayName,ipAddress,clientAppUsed,deviceDetail,location,status,riskState,riskLevelAggregated,riskLevelDuringSignIn,riskEventTypes,riskEventTypes_v2,conditionalAccessStatus,authenticationDetails'
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=createdDateTime ge $cutoff&`$select=$select"
        $pageCap = [Math]::Ceiling($MaxEvents / 1000)
        $pages   = 0
        while ($uri -and $pages -lt $pageCap -and $events.Count -lt $MaxEvents) {
            $resp = Invoke-NRGGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if ($resp.value) { $events += $resp.value }
            $uri = if ($resp['@odata.nextLink']) { $resp['@odata.nextLink'] } else { $null }
            $pages++
        }
        # Trim to cap (defensive — pages can return slightly over)
        if ($events.Count -gt $MaxEvents) { $events = $events[0..($MaxEvents - 1)] }

        # More pages remained ($uri is still set) or the cap trimmed events: the
        # window was NOT fully read, so "no indicators" cannot mean "none happened".
        $wasTruncated = [bool]$uri -or ($events.Count -ge $MaxEvents)
        $recentBag.Data = [ordered]@{
            WindowDays = $WindowDays
            Cutoff     = $cutoff
            Count      = $events.Count
            MaxEvents  = $MaxEvents
            Truncated  = $wasTruncated
            Events     = @($events)
        }
        $recentBag.Success = $true
    } catch {
        Register-NRGException -Source "$collectorId-Recent" -Message $_.Exception.Message
    }
    Set-NRGRawData -Key 'IR-SignIn-Recent' -Data $recentBag

    # ── Anon-IP sign-ins (high-signal IoC) ───────────────────────────────────
    $anonBag = [ordered]@{
        CollectorId = "$collectorId-AnonIp"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        $anonEvents = @()
        # Filter on the indexed risk-event type. Graph's filter language is
        # picky here — using a substring match on riskEventTypes_v2 array
        # via 'any()' isn't always supported, so we fall back to client-side
        # filter of the Recent bag if the server-side filter rejects.
        $filter = "createdDateTime ge $cutoff and riskEventTypes_v2/any(t:t eq 'anonymizedIPAddress')"
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1000&`$filter=$filter"
        try {
            $resp = Invoke-NRGGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if ($resp.value) { $anonEvents = $resp.value }
        } catch {
            # Server-side filter rejected; fall back to client-side over the
            # Recent bag we already collected.
            if ($recentBag.Success -and $recentBag.Data.Events) {
                $anonEvents = $recentBag.Data.Events | Where-Object {
                    $_.riskEventTypes_v2 -contains 'anonymizedIPAddress' -or
                    $_.riskEventTypes    -contains 'anonymizedIPAddress'
                }
            }
        }
        $anonBag.Data = [ordered]@{
            Count  = @($anonEvents).Count
            Events = @($anonEvents)
        }
        $anonBag.Success = $true
    } catch {
        Register-NRGException -Source "$collectorId-AnonIp" -Message $_.Exception.Message
    }
    Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data $anonBag

    # ── Impossible travel + unfamiliar-features sign-ins ─────────────────────
    $travelBag = [ordered]@{
        CollectorId = "$collectorId-Travel"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        $travelEvents = @()
        # Client-side over Recent bag — Graph filter syntax for nested any()
        # on multiple event types is brittle across versions.
        if ($recentBag.Success -and $recentBag.Data.Events) {
            $travelTags = @('unfamiliarFeatures', 'impossibleTravel', 'newCountry', 'malwareInfectedIPAddress')
            $travelEvents = @($recentBag.Data.Events | Where-Object {
                $events_v2 = @($_.riskEventTypes_v2)
                $events_v1 = @($_.riskEventTypes)
                $combined = $events_v1 + $events_v2 | Where-Object { $_ }
                foreach ($t in $travelTags) {
                    if ($combined -contains $t) { return $true }
                }
                $false
            })
        }
        $travelBag.Data = [ordered]@{
            Count  = $travelEvents.Count
            Events = @($travelEvents)
        }
        $travelBag.Success = $true
    } catch {
        Register-NRGException -Source "$collectorId-Travel" -Message $_.Exception.Message
    }
    Set-NRGRawData -Key 'IR-SignIn-Travel' -Data $travelBag

    # ── Identity Protection risky users (Microsoft ML) ───────────────────────
    $riskyBag = [ordered]@{
        CollectorId = "$collectorId-RiskyUsers"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        $risky = @()
        $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$top=200&`$filter=riskState ne 'dismissed' and riskState ne 'remediated'"
        $pages = 0
        while ($uri -and $pages -lt 3) {
            $resp = Invoke-NRGGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if ($resp.value) { $risky += $resp.value }
            $uri = if ($resp['@odata.nextLink']) { $resp['@odata.nextLink'] } else { $null }
            $pages++
        }
        # A tenant with more at-risk users than the 3-page cap (600 users at
        # $top=200) has its risky-user list silently truncated. Success stays
        # $true because what WAS collected is real, but the triage ranking
        # never sees the remainder unless this says so.
        $truncated = [bool]$uri
        if ($truncated) {
            Register-NRGException -Source "$collectorId-RiskyUsers" `
                -Message "Risky-user pagination cap reached (3 pages / $($risky.Count) users). Additional risky users exist beyond this collection."
        }
        $riskyBag.Data = [ordered]@{
            Count     = $risky.Count
            Users     = @($risky)
            Truncated = $truncated
        }
        $riskyBag.Success = $true
    } catch {
        # Identity Protection requires Entra ID P2. Catch+log+continue —
        # this collector being unavailable is normal for B1/B2/E3 tenants.
        Register-NRGException -Source "$collectorId-RiskyUsers" -Message "Identity Protection not available (Entra ID P2 required?): $($_.Exception.Message)"
    }
    Set-NRGRawData -Key 'IR-SignIn-RiskyUsers' -Data $riskyBag

    # ── Coverage from what completed ─────────────────────────────────────────
    # Recent, AnonIp and Travel are the reads a "no indicators" conclusion rests
    # on. RiskyUsers needs Entra ID P2 and is reported, not required.
    $required = @($recentBag, $anonBag, $travelBag)
    $failed   = @($required | Where-Object { -not $_.Success } | ForEach-Object { $_.CollectorId })
    $truncNote = if ($recentBag.Success -and $recentBag.Data.Truncated) { " Sign-in read stopped at $MaxEvents events; older events in the window were not read." } else { '' }
    if ($failed.Count -eq $required.Count) {
        Register-NRGCoverage -Family 'Email-IR' -Status 'Failed' -Note "No sign-in read completed ($($failed -join ', '))."
    } elseif ($failed.Count -gt 0 -or $truncNote) {
        Register-NRGCoverage -Family 'Email-IR' -Status 'Partial' -Note "Did not complete: $($failed -join ', ').$truncNote"
    } else {
        Register-NRGCoverage -Family 'Email-IR' -Status 'Collected'
    }
}

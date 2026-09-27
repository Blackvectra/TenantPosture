#Requires -Version 7.0
#
# Get-NRGAssessmentScope.ps1
# Dependencies: Get-NRGControlDefinitions, Get-NRGCoverage, Get-NRGObjectField,
#               Test-NRGLicenseRequirementMet
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Answers the question every other section of the report assumes away: which
# of the tool's controls did this run NOT reach a verdict on, and why.
#
# Sets:     nothing (pure function)
# Consumes: findings (Get-NRGFindings), Config/controls.json, module coverage
#           state (Get-NRGCoverage), optionally a licence profile
# Cmdlets:  none — no Graph, no EXO, no network
#
# WHY THIS EXISTS
# ---------------
# `NotApplicable` is excluded from the compliance denominator. That is correct
# — a control the tenant cannot satisfy should not count against them — but it
# means a control that silently stops producing a verdict is INVISIBLE: the
# score does not move, no gap appears, and the report looks clean. Every
# high-consequence bug found in this tool has had that shape:
#
#   * Graph omits `signInActivity` for never-signed-in users, so a nested read
#     threw and the guest / stale-account controls reported NotApplicable on
#     every real tenant for months.
#   * `AAD-PIMSchedules` published no SectionStatus, so an empty list read as
#     "no PIM adoption" and a privilege-escalation control scored Partial.
#   * A failed DNS lookup was indistinguishable from an absent record.
#
# In each case the score looked fine and nothing in the deliverable said the
# control had gone quiet. This function is the surface that says it.
#
# It is a REPORTING VIEW ONLY. It reads findings and computes counts; it
# emits no findings, moves no score, and changes no verdict. A test pins that.
#
# THE FOUR REASONS A CONTROL HAS NO SCORED VERDICT
# ------------------------------------------------
#   LicenceBlocked        — the tenant is not licensed for it. Expected, and
#                           already surfaced in Upgrade Unlocks. Benign.
#   CollectionIncomplete  — the collector did not return the data. The
#                           dangerous one: the control COULD have been
#                           assessed and was not, and the reader cannot tell
#                           from the score.
#   NoProgrammaticCheck   — advisory control with no automated test, or one
#                           whose check ran and declared it needs manual
#                           verification. Honest by
#                           design (see "advisory controls never claim
#                           compliance"), but it must be visible, not implied.
#   NoResult              — the control is in controls.json and NOTHING was
#                           emitted for it. Worse than any of the above,
#                           because even the NotApplicable row is missing: the
#                           control vanishes from the report entirely.
#
# `Error` findings are counted separately. They are scored as gaps by the
# report (ErrorHandling 'Gap'), so they are not "unassessed" — but a run with
# many of them is a run to re-do, and the reader should see the count.

function Get-NRGAssessmentScope {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Findings,

        # Module coverage state. Defaults to Get-NRGCoverage so the publishers
        # need no new parameter, matching how the other Lib view functions
        # reach module state.
        [hashtable] $Coverage,

        # Optional. Used ONLY as positive evidence that a control is licence
        # gated, and only when it carries real SKU data — see the classifier.
        [AllowNull()]
        [object] $LicenseProfile,

        # Collected raw data, keyed the same way controls.json keys
        # CollectorDependency. Defaults to module state. This is the HARD
        # evidence for "the collector did not return the data", and it is the
        # same signal the evaluator itself gated on.
        [AllowNull()]
        [object] $RawData,

        # True when the run used -Quick, which deliberately drops evaluators.
        # Without it the controls those evaluators own emit nothing and get
        # reported as a tool fault, which is a lie about a mode the operator
        # chose on purpose.
        [switch] $QuickScan,

        # Optional: the EvaluatorFunction names actually executed this run
        # (e.g. under -Quick, only Critical/High-owning evaluators run). When
        # provided, a control with no finding is filed under NotEvaluatedThisMode
        # ONLY if its own EvaluatorFunction was excluded from this set;
        # otherwise it is filed under NoResult, because its evaluator DID run
        # and a genuine bug in it must not hide behind the quick-scan
        # explanation. When omitted, every no-finding control under -Quick is
        # filed under NotEvaluatedThisMode as before (unknown execution set).
        [AllowNull()]
        [string[]] $ExecutedEvaluators
    )

    Set-StrictMode -Version Latest

    $empty = [ordered]@{
        Available            = $false
        QuickScan            = [bool]$QuickScan
        TotalControls        = 0
        ScoredControls       = 0
        UnscoredControls     = 0
        ErrorControls        = 0
        LicenceBlocked       = @()
        CollectionIncomplete = @()
        NoProgrammaticCheck  = @()
        ThirdPartyAttested   = @()
        NotApplicableToTenant = @()
        NotEvaluatedThisMode = @()
        SkippedByOperator    = @()
        NoResult             = @()
        Errors               = @()
        CoverageIssues       = @()
        ByWorkload           = @()
        Limitations          = @()
    }

    $controls = $null
    try {
        if (Get-Command Get-NRGControlDefinitions -ErrorAction SilentlyContinue) {
            $controls = @(Get-NRGControlDefinitions)
        }
    } catch {
        Write-Verbose "Assessment scope: control definitions unavailable — $($_.Exception.Message)"
        return $empty
    }
    if (-not $controls -or $controls.Count -eq 0) { return $empty }

    # ── Index findings by control id ─────────────────────────────────────────
    # One finding per control is the norm, but per-instance controls (DNS, the
    # named-object inventory evaluators) emit one per domain / object. The
    # WORST state wins for scope purposes: a control that reached a verdict on
    # one domain and not another has been partly assessed, and "partly" is the
    # honest answer, not "assessed".
    # The same order the score uses (Get-NRGStateSeverityRank). With
    # NotApplicable ranked above Gap here and below Satisfied in the score, a
    # control passing on one domain and unread on another was a pass in the
    # score ring and "not assessed" in this section of the same report.
    $rank = Get-NRGStateSeverityRank
    $byId = @{}
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $cid = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
        if ([string]::IsNullOrWhiteSpace($cid)) { continue }
        $state = [string](Get-NRGObjectField -Item $f -Key 'State' -Default '')
        if (-not $byId.ContainsKey($cid)) {
            $byId[$cid] = $f
            continue
        }
        $prev = [string](Get-NRGObjectField -Item $byId[$cid] -Key 'State' -Default '')
        $prevRank = if ($rank.ContainsKey($prev)) { $rank[$prev] } else { -1 }
        $thisRank = if ($rank.ContainsKey($state)) { $rank[$state] } else { -1 }
        if ($thisRank -gt $prevRank) { $byId[$cid] = $f }
    }

    # ── Evidence available to the classifier ─────────────────────────────────
    #
    # THE RULE THAT GOVERNS ALL OF THIS: absence of evidence is never evidence.
    # The first version inverted Test-NRGLicenseRequirementMet, which returns
    # $false when there is NO SKU data (deliberately, so Upgrade Unlocks
    # over-reports rather than hides an upgrade need). Inverted, "we don't know
    # the licensing" became "licence gated, benign" — so on any run where the
    # licence profile did not populate, controls whose own Detail said "EXO
    # data not collected" were filed as benign. That is precisely the failure
    # this whole section exists to prevent. Every signal below is therefore
    # used only when it is POSITIVELY present.
    $rd = $RawData
    if ($null -eq $rd -and (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue)) {
        try { $rd = Get-NRGRawData } catch { $rd = $null }
    }
    # An empty raw-data map means we are replaying a results file and know
    # nothing about collection, NOT that every collector failed.
    $haveRawData = $false
    if ($null -ne $rd) {
        try { $haveRawData = (@($rd.Keys).Count -gt 0) } catch { $haveRawData = $false }
    }

    # Likewise: a licence profile with no SKU data cannot tell us a control is
    # licence gated.
    $haveSkuData = $false
    if ($null -ne $LicenseProfile) {
        # HasLicenseData when present: a Business Basic tenant has SKU data
        # yet satisfies no requirement, so an empty suppression set does not
        # mean "no data". Older profiles lack the flag; fall back to the set.
        $flag = Get-NRGObjectField -Item $LicenseProfile -Key 'HasLicenseData' -Default $null
        if ($null -ne $flag) {
            $haveSkuData = [bool]$flag
        } else {
            $sup = Get-NRGObjectField -Item $LicenseProfile -Key 'SuppressedLicenseRequirements' -Default $null
            if ($null -ne $sup) {
                try { $haveSkuData = (@($sup).Count -gt 0) } catch { $haveSkuData = $false }
            }
        }
    }

    # Coverage state, fetched early so the classifier can recognize a
    # collector the operator deliberately disabled (-SkipDNS / -SkipTeams /
    # etc.) and tell that apart from a collector that tried and failed. A
    # deliberate skip is an operator choice, not a collection fault, so it
    # must not read as "could not be assessed ... re-run once the cause is
    # resolved" — Register-NRGCoverage -Status 'Skipped' is how the entry
    # point records that choice for this classifier to see.
    $cov = $Coverage
    if ($null -eq $cov -and (Get-Command Get-NRGCoverage -ErrorAction SilentlyContinue)) {
        try { $cov = Get-NRGCoverage } catch { $cov = $null }
    }
    $skippedCollectors = [System.Collections.Generic.HashSet[string]]::new()
    if ($null -ne $cov) {
        foreach ($k in @($cov.Keys)) {
            $entry  = $cov[$k]
            $status = [string](Get-NRGObjectField -Item $entry -Key 'Status' -Default '')
            if ($status -eq 'Skipped') { $null = $skippedCollectors.Add([string]$k) }
        }
    }

    # Prose patterns, derived from what the evaluators ACTUALLY emit (every
    # evaluator was run against empty state and the distinct Detail strings
    # collected) rather than from what a classifier author imagines they say.
    # This is the weakest signal and is consulted last.
    $collectionRx = 'not collected|was not collected|did not complete|did not run|not assessed|' +
                    'unavailable|could not be retrieved|could not be determined|no data returned|' +
                    'produced data|not returned|not found in collected data|not available|' +
                    '403|Forbidden|consent'
    # An evaluator that declares itself advisory is authoritative about itself.
    $advisoryRx   = 'requires manual verification|manual review required|no programmatic check'

    # ── Classify every control in the catalogue ──────────────────────────────
    $licenceBlocked = [System.Collections.Generic.List[object]]::new()
    $collectionGap  = [System.Collections.Generic.List[object]]::new()
    $thirdParty     = [System.Collections.Generic.List[object]]::new()
    $advisory       = [System.Collections.Generic.List[object]]::new()
    $notForTenant   = [System.Collections.Generic.List[object]]::new()
    $notThisMode    = [System.Collections.Generic.List[object]]::new()
    $skippedByOp    = [System.Collections.Generic.List[object]]::new()
    $noResult       = [System.Collections.Generic.List[object]]::new()
    $errored        = [System.Collections.Generic.List[object]]::new()
    $workload       = [ordered]@{}
    $scored         = 0

    foreach ($c in $controls) {
        $cid = [string](Get-NRGObjectField -Item $c -Key 'ControlId' -Default '')
        if ([string]::IsNullOrWhiteSpace($cid)) { continue }

        $wl = [string](Get-NRGObjectField -Item $c -Key 'Workload' -Default 'Other')
        if (-not $workload.Contains($wl)) {
            $workload[$wl] = [ordered]@{ Workload = $wl; Total = 0; Scored = 0; Unscored = 0 }
        }
        $workload[$wl].Total++

        $row = [ordered]@{
            ControlId = $cid
            Title     = [string](Get-NRGObjectField -Item $c -Key 'Title' -Default '')
            Workload  = $wl
            Severity  = [string](Get-NRGObjectField -Item $c -Key 'Severity' -Default '')
            Collector = [string](Get-NRGObjectField -Item $c -Key 'CollectorDependency' -Default '')
            Licence   = [string](Get-NRGObjectField -Item $c -Key 'LicenseRequirement' -Default '')
            Reason    = ''
        }

        if (-not $byId.ContainsKey($cid)) {
            $workload[$wl].Unscored++
            $evalFn = [string](Get-NRGObjectField -Item $c -Key 'EvaluatorFunction' -Default '')
            # -Quick drops whole evaluators on purpose — but only the ones it
            # actually dropped. When we know which evaluators ran this pass,
            # a control whose OWN evaluator ran and still emitted nothing is a
            # tool fault, not a quick-scan omission; calling it the latter
            # would hide a real bug behind a mode the operator chose on
            # purpose. Without that knowledge, fall back to the old behavior.
            $skippedThisMode = $QuickScan -and (
                $null -eq $ExecutedEvaluators -or -not $evalFn -or ($ExecutedEvaluators -notcontains $evalFn)
            )
            if ($skippedThisMode) {
                $row.Reason = 'Not evaluated: this run used quick-scan mode, which skips this control''s evaluator.'
                $notThisMode.Add([pscustomobject]$row)
            } else {
                # Nothing was emitted at all. The control is absent from the
                # report, not merely unscored.
                $row.Reason = 'The evaluator produced no result this run.'
                $noResult.Add([pscustomobject]$row)
            }
            continue
        }

        $f     = $byId[$cid]
        $state = [string](Get-NRGObjectField -Item $f -Key 'State' -Default '')

        if ($state -eq 'Satisfied' -or $state -eq 'Partial' -or $state -eq 'Gap') {
            $scored++
            $workload[$wl].Scored++
            continue
        }

        if ($state -eq 'Error') {
            # Scored as a gap by the report, so it counts toward the
            # denominator — but the verdict is "we could not tell", and a run
            # with several is a run to repeat.
            $row.Reason = [string](Get-NRGObjectField -Item $f -Key 'Detail' -Default 'The evaluator raised an error.')
            $errored.Add([pscustomobject]$row)
            $scored++
            $workload[$wl].Scored++
            continue
        }

        # NotApplicable, or any state the report does not score.
        $workload[$wl].Unscored++
        $detail = [string](Get-NRGObjectField -Item $f -Key 'Detail' -Default '')
        $row.Reason = if ([string]::IsNullOrWhiteSpace($detail)) { 'Reported not applicable; no reason recorded.' } else { $detail }

        # ── Classification, strongest evidence first ─────────────────────────

        # 0. The assessor declared a third-party tool covers this check
        #    (Set-NRGThirdPartyEdr). Declared, not verified: its own bucket,
        #    never mixed into "no automated test" or "could not collect".
        if ($detail.StartsWith($script:NRGThirdPartyEdrMarker)) {
            $thirdParty.Add([pscustomobject]$row)
            continue
        }

        # 1. The evaluator declares itself advisory. It is authoritative about
        #    whether it has a programmatic check, and that is true whether or
        #    not the collector ran.
        if ($detail -match $advisoryRx) {
            $advisory.Add([pscustomobject]$row)
            continue
        }

        # 2. HARD evidence: the raw data this control depends on is absent or
        #    the collector reported failure. Same signal the evaluator gated
        #    on, so it cannot disagree with the finding. Only consulted when
        #    raw data is present in this run.
        #
        #    Security Defaults. A finding the evaluator reached because
        #    Security Defaults is on did not gate on the Conditional Access
        #    read (no CA policy can be on beside it), so a failed
        #    AAD-CAPolicies read is not its reason and naming it would
        #    contradict the finding's own detail (license gating's wrapper
        #    included); its remaining dependencies still count, and the
        #    license and prose steps classify it. A
        #    finding that says the Security Defaults state was not read is
        #    positive evidence of a collection gap (a re-run can read it), so
        #    it is filed there before the license step can call it gated.
        if ($detail.StartsWith($script:NRGSecurityDefaultsUnreadPrefix, [System.StringComparison]::Ordinal)) {
            $collectionGap.Add([pscustomobject]$row)
            continue
        }
        $sdVerdict = [bool](Test-NRGSecurityDefaultsVerdictDetail -Detail $detail)
        if ($row.Collector) {
            $failedDep  = $null
            $skippedDep = $null
            foreach ($depKey in @($row.Collector -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                if ($sdVerdict -and $depKey -eq 'AAD-CAPolicies') { continue }
                if ($skippedCollectors.Contains($depKey)) { $skippedDep = $depKey; break }
                if (-not $haveRawData) { continue }
                $entry = $null
                try { $entry = $rd[$depKey] } catch { $entry = $null }
                if ($null -eq $entry) { $failedDep = $depKey; break }
                $ok = Get-NRGObjectField -Item $entry -Key 'Success' -Default $null
                if ($null -ne $ok -and -not $ok) { $failedDep = $depKey; break }
            }
            if ($skippedDep) {
                # An operator choice (-Skip flag), not a collection fault and
                # not a quick-scan omission: its own bucket, worded as not
                # assessed.
                $row.Reason = "Not assessed: the '$skippedDep' collector was skipped for this run by the operator (a -Skip flag). Neither a pass nor a failure. $detail".Trim()
                $skippedByOp.Add([pscustomobject]$row)
                continue
            }
            if ($failedDep) {
                $row.Reason = "The '$failedDep' collector did not return data, so this control could not be assessed. $detail".Trim()
                $collectionGap.Add([pscustomobject]$row)
                continue
            }
        }

        # 3. License gated — POSITIVE evidence only. Either the evaluator said
        #    so explicitly, or we hold real SKU data and it says the tenant
        #    lacks the licence. "No SKU data" is not evidence of anything.
        #    A Security Defaults AAD-1.2 finding whose remaining fix needs no
        #    license (Test-NRGSecurityDefaultsLicenseFree) is not license
        #    gated, so its "registration not collected" is a collection gap.
        $isLicence = $false
        if ($detail -match 'upgrade opportunity') {
            $isLicence = $true
        } elseif ($haveSkuData -and $row.Licence -and $row.Licence -notmatch '^Included' -and
                  (Get-Command Test-NRGLicenseRequirementMet -ErrorAction SilentlyContinue)) {
            try {
                $isLicence = -not (Test-NRGLicenseRequirementMet -LicenseRequirement $row.Licence -LicenseProfile $LicenseProfile -ControlId $row.ControlId -Finding $f)
            } catch {
                $isLicence = $false
            }
        }
        if ($isLicence) {
            $licenceBlocked.Add([pscustomobject]$row)
            continue
        }

        # 4. Weakest signal: the evaluator's own prose. Kept because a section
        #    can fail inside a collector that otherwise succeeded, and because
        #    a replayed results file carries no raw data at all.
        if ($detail -match $collectionRx) {
            $collectionGap.Add([pscustomobject]$row)
            continue
        }

        # 5. Everything else: the evaluator reached a reasoned "does not apply"
        #    (sharing is off, no Copilot licenses, no certificates issued). It
        #    used to fall into "no automated test — manual review", which is
        #    false for a control that ran its test. Its own detail says why.
        $notForTenant.Add([pscustomobject]$row)
    }

    # ── Collector coverage that did not complete ─────────────────────────────
    # $cov was already fetched above so the classifier could see 'Skipped'
    # collectors. A deliberate skip is an operator choice, not an incomplete
    # run, so it is excluded here too — it must not appear as a coverage
    # issue alongside genuine failures.
    $covIssues = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $cov) {
        foreach ($k in @($cov.Keys | Sort-Object)) {
            $entry  = $cov[$k]
            $status = [string](Get-NRGObjectField -Item $entry -Key 'Status' -Default '')
            if ($status -eq 'Collected' -or $status -eq 'Skipped' -or [string]::IsNullOrWhiteSpace($status)) { continue }
            $covIssues.Add([pscustomobject][ordered]@{
                Family = [string]$k
                Status = $status
                Note   = [string](Get-NRGObjectField -Item $entry -Key 'Note' -Default '')
            })
        }
    }

    # ── Plain-language limitations ───────────────────────────────────────────
    # Deliberately written for the person who signs off on the report, not for
    # the operator. Each line states a fact about THIS run, never a reassurance.
    $limitations = [System.Collections.Generic.List[string]]::new()
    $limitations.Add('This assessment reads Microsoft 365 tenant configuration only. It does not test whether a control works in practice, does not inspect endpoints, network equipment, on-premises systems or third-party services, and is not a penetration test.')
    if ($collectionGap.Count -gt 0) {
        $limitations.Add("$($collectionGap.Count) control(s) could not be assessed because the underlying data did not collect. These are NOT passes. Re-run once the cause is resolved before treating them as anything.")
    }
    if ($skippedByOp.Count -gt 0) {
        $limitations.Add("$($skippedByOp.Count) control(s) were not assessed because the operator skipped their workload for this run (a -Skip flag such as -SkipPurview). They are neither passes nor failures. Run without the flag to assess them.")
    }
    if ($notThisMode.Count -gt 0) {
        $limitations.Add("$($notThisMode.Count) control(s) were not evaluated because this was a quick scan. They are neither passes nor failures. Run a full assessment to cover them.")
    }
    if ($noResult.Count -gt 0) {
        $limitations.Add("$($noResult.Count) control(s) produced no result at all this run and do not appear elsewhere in this report. Treat this as a tool fault to investigate, not as a tenant finding.")
    }
    if ($advisory.Count -gt 0) {
        # Two kinds land here: controls with no automated test, and controls
        # whose automated check ran but could not decide (e.g. AAD-7.2 beside
        # Security Defaults, which offers no exclusion to recognize emergency
        # access accounts by). "No automated test" alone is false for the
        # second kind.
        $limitations.Add("$($advisory.Count) control(s) have no automated test, or their automated check ran but could not reach a verdict, and were not scored. They require manual review; nothing in this report asserts whether they are met.")
    }
    if ($notForTenant.Count -gt 0) {
        $limitations.Add("$($notForTenant.Count) control(s) were checked and do not apply to this tenant as configured (for example, a feature that is turned off or not in use). Each finding states the reason. They are not scored; confirm the reason still holds before relying on it.")
    }
    # The declaration also rewrites endpoint (DEV-*) checks, which are not in
    # controls.json; count every declared finding so the sentence matches what
    # Set-NRGThirdPartyEdr actually did (it said 3 while 8 were rewritten).
    $declaredIds = @(@($Findings) | Where-Object { $null -ne $_ -and ([string](Get-NRGObjectField -Item $_ -Key 'Detail' -Default '')).StartsWith($script:NRGThirdPartyEdrMarker) } |
        ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'ControlId' -Default '') } | Where-Object { $_ } | Sort-Object -Unique)
    if ($declaredIds.Count -gt 0) {
        $limitations.Add("$($declaredIds.Count) Microsoft Defender endpoint check(s) were not scored because the assessor declared a third-party EDR provides endpoint protection for this client. Microsoft 365 cannot see that product, so this coverage is declared, not verified; confirm it in that product's console.")
    }
    if ($licenceBlocked.Count -gt 0) {
        $limitations.Add("$($licenceBlocked.Count) control(s) require licensing this tenant does not hold. They are excluded from the score rather than counted against it, and are itemized under licensing.")
    }
    if ($errored.Count -gt 0) {
        $limitations.Add("$($errored.Count) control(s) raised an error during evaluation and are counted as gaps. Their true state is unknown.")
    }
    if ($covIssues.Count -gt 0) {
        $limitations.Add("$($covIssues.Count) collector(s) did not complete. Any control depending on them is unassessed regardless of what the score shows.")
    }

    $total    = @($controls).Count
    $unscored = $total - $scored

    return [ordered]@{
        Available            = $true
        QuickScan            = [bool]$QuickScan
        TotalControls        = $total
        ScoredControls       = $scored
        UnscoredControls     = $unscored
        ErrorControls        = $errored.Count
        LicenceBlocked       = @($licenceBlocked)
        CollectionIncomplete = @($collectionGap)
        NoProgrammaticCheck  = @($advisory)
        ThirdPartyAttested   = @($thirdParty)
        NotApplicableToTenant = @($notForTenant)
        NotEvaluatedThisMode = @($notThisMode)
        SkippedByOperator    = @($skippedByOp)
        NoResult             = @($noResult)
        Errors               = @($errored)
        CoverageIssues       = @($covIssues)
        ByWorkload           = @($workload.Values | ForEach-Object { [pscustomobject]$_ })
        Limitations          = @($limitations)
    }
}

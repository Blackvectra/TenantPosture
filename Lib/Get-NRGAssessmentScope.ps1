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
#   NoProgrammaticCheck   — advisory control with no automated test. Honest by
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
        [switch] $QuickScan
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
        NotEvaluatedThisMode = @()
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
    $rank = @{ 'Satisfied' = 0; 'Partial' = 1; 'Gap' = 2; 'Error' = 3; 'NotApplicable' = 4 }
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
        $sup = Get-NRGObjectField -Item $LicenseProfile -Key 'SuppressedLicenseRequirements' -Default $null
        if ($null -ne $sup) {
            try { $haveSkuData = (@($sup).Count -gt 0) } catch { $haveSkuData = $false }
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
    $advisoryRx   = 'requires manual verification'

    # ── Classify every control in the catalogue ──────────────────────────────
    $licenceBlocked = [System.Collections.Generic.List[object]]::new()
    $collectionGap  = [System.Collections.Generic.List[object]]::new()
    $advisory       = [System.Collections.Generic.List[object]]::new()
    $notThisMode    = [System.Collections.Generic.List[object]]::new()
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
            if ($QuickScan) {
                # -Quick drops whole evaluators on purpose. Calling that a tool
                # fault would be a lie about a mode the operator chose.
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
        if ($haveRawData -and $row.Collector) {
            $failedDep = $null
            foreach ($depKey in @($row.Collector -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $entry = $null
                try { $entry = $rd[$depKey] } catch { $entry = $null }
                if ($null -eq $entry) { $failedDep = $depKey; break }
                $ok = Get-NRGObjectField -Item $entry -Key 'Success' -Default $null
                if ($null -ne $ok -and -not $ok) { $failedDep = $depKey; break }
            }
            if ($failedDep) {
                $row.Reason = "The '$failedDep' collector did not return data, so this control could not be assessed. $detail".Trim()
                $collectionGap.Add([pscustomobject]$row)
                continue
            }
        }

        # 3. Licence gated — POSITIVE evidence only. Either the evaluator said
        #    so explicitly, or we hold real SKU data and it says the tenant
        #    lacks the licence. "No SKU data" is not evidence of anything.
        $isLicence = $false
        if ($detail -match 'upgrade opportunity') {
            $isLicence = $true
        } elseif ($haveSkuData -and $row.Licence -and $row.Licence -notmatch '^Included' -and
                  (Get-Command Test-NRGLicenseRequirementMet -ErrorAction SilentlyContinue)) {
            try {
                $isLicence = -not (Test-NRGLicenseRequirementMet -LicenseRequirement $row.Licence -LicenseProfile $LicenseProfile)
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

        $advisory.Add([pscustomobject]$row)
    }

    # ── Collector coverage that did not complete ─────────────────────────────
    $covIssues = [System.Collections.Generic.List[object]]::new()
    $cov = $Coverage
    if ($null -eq $cov -and (Get-Command Get-NRGCoverage -ErrorAction SilentlyContinue)) {
        try { $cov = Get-NRGCoverage } catch { $cov = $null }
    }
    if ($null -ne $cov) {
        foreach ($k in @($cov.Keys | Sort-Object)) {
            $entry  = $cov[$k]
            $status = [string](Get-NRGObjectField -Item $entry -Key 'Status' -Default '')
            if ($status -eq 'Collected' -or [string]::IsNullOrWhiteSpace($status)) { continue }
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
    if ($notThisMode.Count -gt 0) {
        $limitations.Add("$($notThisMode.Count) control(s) were not evaluated because this was a quick scan. They are neither passes nor failures. Run a full assessment to cover them.")
    }
    if ($noResult.Count -gt 0) {
        $limitations.Add("$($noResult.Count) control(s) produced no result at all this run and do not appear elsewhere in this report. Treat this as a tool fault to investigate, not as a tenant finding.")
    }
    if ($advisory.Count -gt 0) {
        $limitations.Add("$($advisory.Count) control(s) have no automated test and were not scored. They require manual review; nothing in this report asserts whether they are met.")
    }
    if ($licenceBlocked.Count -gt 0) {
        $limitations.Add("$($licenceBlocked.Count) control(s) require licensing this tenant does not hold. They are excluded from the score rather than counted against it, and are itemised under licensing.")
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
        NotEvaluatedThisMode = @($notThisMode)
        NoResult             = @($noResult)
        Errors               = @($errored)
        CoverageIssues       = @($covIssues)
        ByWorkload           = @($workload.Values | ForEach-Object { [pscustomobject]$_ })
        Limitations          = @($limitations)
    }
}

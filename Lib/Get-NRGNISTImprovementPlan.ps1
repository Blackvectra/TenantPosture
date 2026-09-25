#Requires -Version 7.0
#
# Get-NRGNISTImprovementPlan.ps1
# Dependencies: Get-NRGCoverageScore, Get-NRGNISTFamilyCoverage,
#               Get-NRGNISTControlIdsFromFinding, Get-NRGControlOperationalImpact,
#               Get-NRGObjectField, Get-NRGControlDefinitions,
#               Test-NRGLicenseRequirementMet (all optional-guarded)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Turn a NIST 800-53 Rev 5 assessment into an ordered plan for getting
#          closer to it.
#
#          Every other deliverable here reports a POSITION — you are at 61%,
#          these families are weak, these controls failed. None of them answer
#          the only question that changes the number: what do we do next, in
#          what order, and what will it cost us to do it.
#
#          This does. It ranks the open gaps by how many points of NIST
#          coverage each one returns, states the exact projected coverage after
#          each step, names the 800-53 families each step moves, and attaches
#          what the change will break — so a plan can be approved by someone
#          who is accountable for the disruption, not just for the score.
#
#          THREE TRACKS, because that is how the work actually gets scheduled:
#
#            Do now      Licensed, and nothing a user will notice. These go in
#                        this week; there is nothing to plan around.
#            Schedule    Licensed, but somebody will feel it. Needs a window,
#                        a comms message, or a discovery pass first.
#            Buy first   Blocked on a license. Listed, never given a projected
#                        score — see below.
#
# WHY THE MATH IS EXACT, AND WHERE IT DELIBERATELY STOPS:
#
#   NIST coverage is round(100 * (Satisfied + 0.5*Partial) / Scored) over the
#   findings carrying a NIST citation — the same formula and the same
#   denominator rule as every other score in the tool. Fixing a Gap adds 1.0 to
#   the numerator; fixing a Partial adds 0.5. Neither changes the denominator,
#   because the control was already assessed and already counted. So the
#   projected coverage after a set of steps is recomputed from counts, not
#   accumulated from rounded per-step deltas, and there is no drift.
#
#   A license unlock gets NO projected score. Buying a license changes the
#   denominator, and a licensed-but-unconfigured control is a Gap rather than
#   an automatic pass, so any number attached there would be a guess dressed as
#   arithmetic. They are listed with what they would unlock and nothing more.
#
#   Per-family movement is reported as the family score before and after, which
#   is exact for the same reason. Families do not sum to the total — a finding
#   citing controls in two families is counted in both — and every surface that
#   renders this says so.
#
# WHAT THIS IS NOT: a completion plan. Finishing every step here does not make
#   an organization NIST compliant. It closes what a Microsoft 365 tenant scan
#   and an endpoint scan can see, which is a subset of 800-53 — 14 of the 20
#   families, and within those only the controls a cloud tenant evidences. The
#   remainder is policy, process, physical and personnel. The plan says its own
#   ceiling out loud rather than letting a reader infer 100% means done.
#
# Inputs:  -Findings        assessment findings (shape-agnostic).
#          -LicenseProfile  optional; resolved from module state when omitted.
#                           Null means "no SKU data", and a control with a real
#                           license requirement is then classified as blocked —
#                           conservative, never a false quick win.
#          -ImpactPath      optional override for operational-impact.json.
#
# Outputs: [ordered] hashtable — Baseline, Projected, Tracks, Families,
#          Ceiling, Available.
#
# Consumes: findings only. No raw data, no Graph, no EXO, no network.
#

function Get-NRGNISTImprovementPlan {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()] [AllowEmptyCollection()]
        [object[]] $Findings,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object] $LicenseProfile,

        [Parameter(Mandatory = $false)]
        [string] $ImpactPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $empty = [ordered]@{
        Baseline  = [ordered]@{ Score = 0; Satisfied = 0; Partial = 0; Gap = 0; Scored = 0 }
        Projected = [ordered]@{ Score = 0; PointGain = 0; StepCount = 0 }
        Tracks    = @()
        Families  = @()
        Blocked   = @()
        Ceiling   = [ordered]@{ Families = 0; TotalFamilies = 20; Note = '' }
        Available = $false
    }

    $live = @($Findings | Where-Object { $null -ne $_ })
    if ($live.Count -eq 0) { return $empty }

    # ── Baseline, from the same helper every other score uses ────────────────
    $base = Get-NRGCoverageScore -Findings $live -FrameworkId 'NIST' -ErrorHandling 'Gap'
    if ([int]$base.Scored -eq 0) { return $empty }

    $famBefore = Get-NRGNISTFamilyCoverage -Findings $live -ErrorHandling 'Gap'

    $impact = if ($ImpactPath) {
        Get-NRGOperationalImpactCatalog -ConfigPath $ImpactPath
    } else {
        Get-NRGOperationalImpactCatalog
    }

    # Control metadata, for the remediation text and the license requirement.
    $defs = @{}
    try { foreach ($c in (Get-NRGControlDefinitions)) { $defs[[string]$c.ControlId] = $c } } catch {
        Write-Verbose "controls.json unavailable to the improvement plan: $($_.Exception.Message)"
    }

    # ── Candidate steps ──────────────────────────────────────────────────────
    # Only Gap and Partial. A Satisfied control has nothing to do; a
    # NotApplicable one was excluded from the denominator and closing it would
    # not move the score; an Error produced no verdict, so there is nothing to
    # act on and guessing at one would put invented work in a plan.
    $steps = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $live) {
        $state = [string](Get-NRGObjectField -Item $f -Key 'State' -Default '')
        if ($state -notin @('Gap', 'Partial')) { continue }

        $nistIds = @(Get-NRGNISTControlIdsFromFinding -Finding $f)
        if ($nistIds.Count -eq 0) { continue }   # not a NIST control; out of scope for this plan

        $cid  = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
        $def  = if ($defs.ContainsKey($cid)) { $defs[$cid] } else { $null }

        # License classification. Conservative by construction: anything we
        # cannot prove the tenant is licensed for is treated as blocked rather
        # than promised as a quick win.
        $licReq = [string](Get-NRGObjectField -Item $def -Key 'LicenseRequirement' -Default '')
        $licensed = $true
        if ($licReq) {
            if (Get-Command Test-NRGLicenseRequirementMet -ErrorAction SilentlyContinue) {
                try {
                    $licensed = [bool](Test-NRGLicenseRequirementMet -LicenseRequirement $licReq -LicenseProfile $LicenseProfile -ControlId $cid)
                } catch { $licensed = $false }
            } else {
                $licensed = $false
            }
        }

        $im = Get-NRGControlOperationalImpact -ControlId $cid -Catalog $impact

        # Score lift: a Gap closed is worth 1.0, a Partial 0.5. Denominator
        # unchanged either way.
        $lift = if ($state -eq 'Gap') { 1.0 } else { 0.5 }

        $families = @($nistIds | ForEach-Object {
            $t = [string]$_
            if ($t -match '^([A-Z]{2})') { $Matches[1] }
        } | Where-Object { $_ } | Select-Object -Unique | Sort-Object)

        $steps.Add([ordered]@{
            ControlId    = $cid
            Title        = [string](Get-NRGObjectField -Item $f -Key 'Title' -Default '')
            State        = $state
            Severity     = [string](Get-NRGObjectField -Item $f -Key 'Severity' -Default '')
            Workload     = [string](Get-NRGObjectField -Item $def -Key 'Workload' -Default '')
            NistControls = $nistIds
            Families     = $families
            Remediation  = [string](Get-NRGObjectField -Item $f -Key 'Remediation' -Default (
                              [string](Get-NRGObjectField -Item $def -Key 'Remediation' -Default '')))
            CurrentValue = [string](Get-NRGObjectField -Item $f -Key 'CurrentValue' -Default '')
            Licensed     = $licensed
            LicenseReq   = $licReq
            Impact       = $im
            Lift         = $lift
        })
    }

    if ($steps.Count -eq 0) {
        $empty['Baseline'] = [ordered]@{
            Score = [int]$base.Score; Satisfied = [int]$base.Satisfied
            Partial = [int]$base.Partial; Gap = [int]$base.Gap; Scored = [int]$base.Scored
        }
        $empty['Available'] = $true
        return $empty
    }

    # ── Track assignment ─────────────────────────────────────────────────────
    # 'Do now' is deliberately narrow: licensed AND an impact archetype the
    # tool has actually documented AND that documentation says users notice
    # nothing. A control with NO impact entry never lands here — an
    # undocumented impact is not evidence of no impact, and putting one in the
    # "nothing to plan around" track is exactly the mistake that gets a change
    # approved without anyone checking.
    $silent = @('none-visible', 'admin-review-workload', 'monitoring-integration')
    foreach ($s in $steps) {
        $arch = if ($s['Impact']) { [string]$s['Impact']['Archetype'] } else { '' }
        $s['Track'] =
            if (-not $s['Licensed'])          { 'Buy first' }
            elseif ($arch -and $arch -in $silent) { 'Do now' }
            else                              { 'Schedule' }
        $s['Effort'] = if ($s['Impact']) { [string]$s['Impact']['Effort'] } else { 'Not documented' }
    }

    $sevRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Informational' = 4 }
    $rankOf  = { param($s) if ($sevRank.ContainsKey([string]$s['Severity'])) { $sevRank[[string]$s['Severity']] } else { 5 } }

    # Ordered by points returned, then by severity, then by control id so the
    # plan is stable between runs on an unchanged tenant — a plan whose order
    # shuffles every run cannot be worked down.
    $actionable = @($steps | Where-Object { $_['Track'] -ne 'Buy first' } |
        Sort-Object @{ Expression = { -$_['Lift'] } },
                    @{ Expression = { & $rankOf $_ } },
                    @{ Expression = { [string]$_['ControlId'] } })
    $blocked = @($steps | Where-Object { $_['Track'] -eq 'Buy first' } |
        Sort-Object @{ Expression = { & $rankOf $_ } }, @{ Expression = { [string]$_['ControlId'] } })

    # ── Cumulative projection ────────────────────────────────────────────────
    # Recomputed from counts at every step rather than summed from rounded
    # deltas. 'Do now' steps are applied first so the cumulative column reads
    # in the order the work is actually done.
    $ordered = @($actionable | Where-Object { $_['Track'] -eq 'Do now' }) +
               @($actionable | Where-Object { $_['Track'] -eq 'Schedule' })

    $numerator   = [double]$base.Satisfied + (0.5 * [double]$base.Partial)
    $denominator = [double]$base.Scored
    $running     = $numerator
    $rank        = 0
    foreach ($s in $ordered) {
        $rank++
        $before   = [int][Math]::Round(100 * $running / $denominator)
        $running += [double]$s['Lift']
        $after    = [int][Math]::Round(100 * $running / $denominator)
        $s['Rank']            = $rank
        $s['ScoreLift']       = [Math]::Round(100 * [double]$s['Lift'] / $denominator, 1)
        $s['CumulativeScore'] = $after
        $s['ScoreBefore']     = $before
    }

    $projected = [int][Math]::Round(100 * $running / $denominator)

    # ── Per-family movement ──────────────────────────────────────────────────
    # Computed by replaying the plan against the findings and re-running the
    # same family rollup, rather than by arithmetic on family counts. Replaying
    # is slower and is the only way to be right: a finding citing two families
    # moves both, and hand-rolled per-family arithmetic gets that wrong in a
    # way nobody notices until an auditor adds the column up.
    $fixed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $ordered) { $null = $fixed.Add([string]$s['ControlId']) }

    $after = foreach ($f in $live) {
        $cid = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
        if ($cid -and $fixed.Contains($cid)) {
            $clone = [ordered]@{}
            foreach ($k in @('ControlId', 'Title', 'Severity', 'FrameworkIds', 'Category')) {
                $clone[$k] = Get-NRGObjectField -Item $f -Key $k -Default $null
            }
            $clone['State'] = 'Satisfied'
            $clone
        } else { $f }
    }
    $famAfter = Get-NRGNISTFamilyCoverage -Findings @($after) -ErrorHandling 'Gap'

    $afterById = @{}
    foreach ($row in @($famAfter['Families'])) { $afterById[[string]$row['Family']] = $row }

    $families = [System.Collections.Generic.List[object]]::new()
    foreach ($row in @($famBefore['Families'])) {
        $fid = [string]$row['Family']
        $aft = if ($afterById.ContainsKey($fid)) { [int]$afterById[$fid]['Score'] } else { [int]$row['Score'] }
        $families.Add([ordered]@{
            Family      = $fid
            Name        = [string]$row['Name']
            Assessed    = [int]$row['Assessed']
            ScoreBefore = [int]$row['Score']
            ScoreAfter  = $aft
            Movement    = $aft - [int]$row['Score']
            Steps       = @($ordered | Where-Object { $fid -in @($_['Families']) } |
                            ForEach-Object { [string]$_['ControlId'] })
        })
    }

    $tracks = [System.Collections.Generic.List[object]]::new()
    foreach ($name in @('Do now', 'Schedule')) {
        $rows = @($ordered | Where-Object { $_['Track'] -eq $name })
        $tracks.Add([ordered]@{
            Name        = $name
            Description = if ($name -eq 'Do now') {
                'Licensed, and documented as changing nothing a user will notice. There is nothing to plan around — these go in this week.'
            } else {
                'Licensed, but somebody will feel it. Each needs a window, a message to users, or a discovery pass before it is enforced.'
            }
            Steps     = $rows
            Count     = $rows.Count
            PointGain = [Math]::Round((@($rows | ForEach-Object { $_['ScoreLift'] }) | Measure-Object -Sum).Sum, 1)
        })
    }

    [ordered]@{
        Baseline = [ordered]@{
            Score = [int]$base.Score; Satisfied = [int]$base.Satisfied
            Partial = [int]$base.Partial; Gap = [int]$base.Gap; Scored = [int]$base.Scored
        }
        Projected = [ordered]@{
            Score = $projected; PointGain = $projected - [int]$base.Score; StepCount = $ordered.Count
        }
        Tracks   = $tracks.ToArray()
        Families = $families.ToArray()
        Blocked  = $blocked
        Ceiling  = [ordered]@{
            Families      = [int]$famBefore['FamilyCount']
            TotalFamilies = 20
            NistControls  = [int]$famBefore['NistControlCount']
            Note          = 'Completing this plan closes what a Microsoft 365 tenant scan and an endpoint scan can observe. That is a subset of 800-53: the families below, and within them only the controls a cloud tenant evidences. Planning, Program Management, Risk Assessment, System and Services Acquisition, Supply Chain Risk Management and PII Processing are documents and processes that no scanner reaches. 100% here is not 800-53 compliance.'
        }
        Available = $true
    }
}

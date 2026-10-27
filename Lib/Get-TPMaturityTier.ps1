#Requires -Version 7.0
#
# Get-TPMaturityTier.ps1  (v4.10.1)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Derived classification of tenant security posture into a 5-tier
#          maturity model. Reads the finished findings stream from a run and
#          returns a single tier label, numeric level, and the score / gap
#          counts that fed the decision. Implements roadmap F1.
#
# Inputs:  Findings array (post-evaluation) — same shape Get-TPFindings emits.
#          Accepts an empty array (silent zero-score result, not a binding error).
# Outputs: [ordered] hashtable with Tier (1-5), Label, Score, CriticalGaps,
#          HighGaps, ScoredControls, ErrorFindings, UnknownStates, Description,
#          ObservedLabel, EvidenceComplete, UnverifiedFindings, Qualification,
#          plus per-state counts (Satisfied, Partial, Gap, NotApplicable, Total).
#          Safe to serialize as JSON.
#
# Tier rules (combination of coverage % across license-applicable controls
# and absolute critical/high gap count — captures both "wide" and "deep"):
#
#   5 Optimizing   Score >= 90 AND 0 Critical AND 0 High
#   4 Managed      Score >= 75 AND 0 Critical AND High <= 3
#   3 Defined      Score >= 60 AND 0 Critical
#   2 Developing   Score >= 40 AND Critical <= 5
#   1 Initial      Everything else (<40% coverage OR any critical gap with low score)
#
# Score derivation matches Get-TPCoverageScore's default (Error excluded):
#   score = round(100 * (Satisfied + 0.5*Partial) / ScoredControls)
#   ScoredControls = total findings - NotApplicable - Error - Unknown
#
# Why Error is excluded from the denominator: an `Error` finding means the
# evaluator threw (transient Graph throttling, missing scope, partial collection).
# Counting it as a gap punishes the operator for tool problems and turns
# `-FailOnScoreBelow` in CI into a false alarm on flaky tenants.
#
# Why the label is then QUALIFIED: excluding a finding from the denominator
# does not make it a pass. A run in which half the checks errored and the other
# half passed used to print an unqualified "Optimizing", which reads as a claim
# about the whole tenant. The tier and the score are still computed over the
# scored controls (that is what the number means), but whenever any finding
# produced no verdict (Error, or a state the formula does not know) or no
# control was scored at all, EvidenceComplete is $false, Label carries
# "(provisional: evidence incomplete)", ObservedLabel keeps the bare tier name
# and Qualification says how many findings produced no verdict. There is no
# threshold below which this is waived: one errored check is one control the
# label says nothing about, and the counts let the reader weigh it.
#
# v4.10.1: the coverage-score computation moved into Lib/Get-TPCoverageScore.ps1
# (one canonical formula across all publishers + this helper). The shape-agnostic
# field reader moved into Lib/Get-TPObjectField.ps1. This file now does only
# the tier classification — CriticalGaps/HighGaps still computed locally because
# they are severity-aware over Gap findings specifically (not coverage math).

function Get-TPMaturityTier {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Findings,

        # The run's control selection (Metadata.ControlSelection) when it was a
        # partial run (-ControlId / -ExcludeControlId). A partial run is never an
        # unqualified tier: the label and the qualification say how many controls
        # were selected, because a three-control run that passes is not a tenant
        # at "Optimizing".
        [AllowNull()]
        [object] $Selection
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $cov = Get-TPCoverageScore -Findings $Findings

    # Severity-of-gap counters — computed inline because they aren't coverage
    # math. One pass over findings; the coverage helper already validated and
    # skipped nulls but we re-iterate here to count by severity.
    $crit = 0; $high = 0
    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }
        $state = Get-TPObjectField -Item $f -Key 'State'
        if ($state -ne 'Gap') { continue }
        $severity = Get-TPObjectField -Item $f -Key 'Severity'
        if     ($severity -eq 'Critical') { $crit++ }
        elseif ($severity -eq 'High')     { $high++ }
    }

    $score = $cov.Score

    $tier  = 1
    $label = 'Initial'
    $desc  = 'Foundational gaps remain — establish identity hardening, MFA, and audit logging before deepening other workloads.'

    if ($score -ge 90 -and $crit -eq 0 -and $high -eq 0) {
        $tier = 5; $label = 'Optimizing'
        $desc = 'Posture is continuously measured and tuned. Focus on threat-hunting depth, regression alerting, and supply-chain governance.'
    }
    elseif ($score -ge 75 -and $crit -eq 0 -and $high -le 3) {
        $tier = 4; $label = 'Managed'
        $desc = 'Controls are tracked and enforced. Drive remaining High-severity gaps to closure and add proactive drift detection.'
    }
    elseif ($score -ge 60 -and $crit -eq 0) {
        $tier = 3; $label = 'Defined'
        $desc = 'Security baseline is in place across most workloads. Move toward measured operations — runbooks, change controls, evidence retention.'
    }
    elseif ($score -ge 40 -and $crit -le 5) {
        $tier = 2; $label = 'Developing'
        $desc = 'Core controls exist but coverage is uneven. Close remaining Critical gaps and standardize identity + email hardening first.'
    }

    # Evidence completeness. Error and unknown-state findings are outside the
    # denominator, so the score says nothing about them; a run with no scored
    # control has a score of 0 that is a default, not a measurement. Either
    # way the classification is provisional and says so in every surface that
    # prints the label (console, JSON metadata, downstream dashboards).
    $unverified = [int]$cov.Error + [int]$cov.Unknown
    $evidenceComplete = ($unverified -eq 0 -and [int]$cov.Scored -gt 0)
    $observedLabel = $label
    $qualification = ''
    $partialRun = $false; $selectedCount = 0; $totalControls = 0
    if ($null -ne $Selection -and [bool](Get-TPObjectField -Item $Selection -Key 'Partial' -Default $true)) {
        $partialRun    = $true
        $selectedCount = [int](Get-TPObjectField -Item $Selection -Key 'SelectedCount' -Default 0)
        $totalControls = [int](Get-TPObjectField -Item $Selection -Key 'TotalControls' -Default 0)
    }
    $partialSentence = if ($partialRun) {
        "Partial run: $selectedCount of $totalControls controls were selected. The score and the tier describe those controls only and claim nothing about the other $([math]::Max(0, $totalControls - $selectedCount))."
    } else { '' }
    if (-not $evidenceComplete -or $partialRun) {
        $evidenceIncomplete = -not $evidenceComplete
        $evidenceComplete = $false
        $counted = [int]$cov.Scored + $unverified
        $qualification = if ([int]$cov.Scored -eq 0) {
            if ($counted -eq 0) { 'No control was scored, so the tier is a default, not a measurement of this tenant.' }
            else { "None of the $counted finding(s) with a state the score formula counts produced a verdict ($($cov.Error) errored, $($cov.Unknown) with an unrecognized state), so the tier is a default, not a measurement of this tenant." }
        } else {
            "$unverified of $counted finding(s) produced no verdict ($($cov.Error) errored, $($cov.Unknown) with an unrecognized state). The score and the tier are computed over the $($cov.Scored) scored control(s) only and claim nothing about the rest; the Assessment Scope section names them. Not-applicable findings are excluded by design (license-gated, advisory, or not collected) and are listed there as well."
        }
        if (-not $evidenceIncomplete) { $qualification = '' }
        if ($partialRun) {
            $qualification = (@($partialSentence, $qualification) | Where-Object { $_ }) -join ' '
            $label = if ($evidenceIncomplete) { "$observedLabel (provisional: partial run, $selectedCount of $totalControls controls; evidence incomplete)" }
                     else { "$observedLabel (provisional: partial run, $selectedCount of $totalControls controls)" }
        } else {
            $label = "$observedLabel (provisional: evidence incomplete)"
        }
    }

    [ordered]@{
        Tier            = $tier
        Label           = $label
        Score           = $score
        CriticalGaps    = $crit
        HighGaps        = $high
        ScoredControls  = $cov.Scored
        ErrorFindings   = $cov.Error
        UnknownStates   = $cov.Unknown
        Description     = $desc
        # Evidence completeness (see the header): the bare tier name, whether every
        # counted finding produced a verdict, how many did not, and the sentence that
        # qualifies the label when they did not.
        ObservedLabel      = $observedLabel
        EvidenceComplete   = $evidenceComplete
        UnverifiedFindings = $unverified
        Qualification      = $qualification
        # A partial run (-ControlId): how many controls the tier covers.
        PartialRun         = $partialRun
        SelectedControls   = $selectedCount
        TotalControls      = $totalControls
        # v4.10.1 — per-state counts pulled through from the coverage helper
        # so the orchestrator's summary banner and any future caller reads
        # from one source instead of re-deriving with Where-Object.
        Satisfied       = $cov.Satisfied
        Partial         = $cov.Partial
        Gap             = $cov.Gap
        NotApplicable   = $cov.NA
        Total           = $cov.Total
    }
}

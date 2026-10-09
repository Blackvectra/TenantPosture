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
        [object[]] $Findings
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

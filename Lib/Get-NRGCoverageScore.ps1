#Requires -Version 7.0
#
# Get-NRGCoverageScore.ps1  (v4.10.1)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Canonical coverage-score helper. Returns the per-state count
#          breakdown plus a normalized 0-100 score derived from the standard
#          formula:
#
#              Score = round(100 * (Satisfied + 0.5 * Partial) / Scored)
#
#          Created to consolidate the four divergent inline copies that
#          previously existed in Get-NRGMaturityTier, Publish-NRGAssessmentHTML
#          (3 sites: tenant / per-workload / per-framework), Publish-NRGAssessmentSummary,
#          Publish-NRGDeltaReport (nested Get-Score function), and
#          Publish-NRGRemediationPlaybook. Each site had drifted to a slightly
#          different denominator rule — see -ErrorHandling parameter for the
#          two variants that are now selectable instead of duplicated.
#
# Inputs:  -Findings           array of finding objects (hashtable, ordered, or
#                              PSCustomObject — shape-agnostic via
#                              Get-NRGObjectField). $null entries are skipped.
#                              Empty/null array returns all zeros, no throw.
#          -Workload           optional ControlId prefix filter (e.g. 'AAD').
#                              Matches "$Workload-*" via the standard
#                              ControlId-prefix convention.
#          -FrameworkId        optional FrameworkIds prefix filter (e.g. 'CIS').
#                              Matches via regex "^$FrameworkId" against each
#                              entry in the finding's FrameworkIds collection.
#                              Findings without FrameworkIds are excluded when
#                              this filter is active.
#          -ErrorHandling      'Exclude' (default) drops Error findings from
#                              the denominator — matches Maturity-tier
#                              semantics and the rationale at the top of
#                              Get-NRGMaturityTier.ps1: a flaky Graph throttle
#                              shouldn't tank a CI gate.
#                              'Gap' counts Error in the denominator (treated
#                              as a soft gap). Preserved for the publishers
#                              that historically used this variant.
#
# Outputs: [ordered] hashtable:
#            @{
#                Satisfied      = <int>   count
#                Partial        = <int>
#                Gap            = <int>
#                NA             = <int>   NotApplicable
#                Error          = <int>
#                Unknown        = <int>   State values not in the known set
#                                          (e.g., typo'd 'Satisifed' or future
#                                           state). Always excluded from Scored.
#                Total          = <int>   non-null findings classified
#                Scored         = <int>   the denominator (per -ErrorHandling)
#                Score          = <int>   0..100, rounded; 0 when Scored == 0
#            }

function Get-NRGCoverageScore {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Findings,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $Workload,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $FrameworkId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Exclude','Gap')]
        [string] $ErrorHandling = 'Exclude'
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $total = 0
    $sat = 0; $part = 0; $gap = 0; $na = 0; $err = 0; $unknown = 0

    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }

        if ($Workload) {
            $cid = Get-NRGObjectField -Item $f -Key 'ControlId'
            if (-not $cid) { continue }
            $prefix = ($cid -replace '-.*$','')
            if ($prefix -ne $Workload) { continue }
        }

        if ($FrameworkId) {
            $fwIds = Get-NRGObjectField -Item $f -Key 'FrameworkIds'
            if (-not $fwIds) { continue }
            # v4.11.2 audit fix (L-3): regex-escape FrameworkId so a future
            # caller passing operator-supplied or controls.json-derived text
            # can't silently change matching semantics via regex metachars
            # (`.`, `+`, `*`, `[`). Today's callers all pass literals
            # (CIS / SCuBA / NIST / CMMC) — defense-in-depth.
            $fwPattern = '^' + [regex]::Escape($FrameworkId)
            $match = $false
            foreach ($id in @($fwIds)) {
                if ($id -match $fwPattern) { $match = $true; break }
            }
            if (-not $match) { continue }
        }

        $total++
        $state = Get-NRGObjectField -Item $f -Key 'State'
        switch ($state) {
            'Satisfied'     { $sat++ }
            'Partial'       { $part++ }
            'Gap'           { $gap++ }
            'NotApplicable' { $na++ }
            'Error'         { $err++ }
            default         { $unknown++ }
        }
    }

    # Denominator: always exclude NA + Unknown. Error follows -ErrorHandling.
    $scored = switch ($ErrorHandling) {
        'Exclude' { $total - $na - $err - $unknown }
        'Gap'     { $total - $na - $unknown }
    }

    $score = if ($scored -gt 0) {
        [int][Math]::Round(100 * ($sat + 0.5 * $part) / $scored)
    } else { 0 }

    [ordered]@{
        Satisfied = $sat
        Partial   = $part
        Gap       = $gap
        NA        = $na
        Error     = $err
        Unknown   = $unknown
        Total     = $total
        Scored    = $scored
        Score     = $score
    }
}

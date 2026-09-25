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

    foreach ($f in (Get-NRGScoringFindings -Findings $Findings)) {
        if ($null -eq $f) { continue }

        if ($Workload) {
            $cid = Get-NRGObjectField -Item $f -Key 'ControlId'
            if (-not $cid) { continue }
            $prefix = ($cid -replace '-.*$','')
            if ($prefix -ne $Workload) { continue }
        }

        if ($FrameworkId) {
            $fwIds = Get-NRGObjectField -Item $f -Key 'FrameworkIds'
            # Escape before use as a regex. Callers today pass literals
            # (CIS / SCuBA / NIST / CMMC), but an unescaped value lets a
            # future caller wiring this from operator input or a
            # controls.json field silently change matching semantics via
            # regex metacharacters (. + * [). Defense in depth.
            $fwPattern = '^' + [regex]::Escape($FrameworkId)
            if (-not $fwIds) { continue }
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

# One finding per control for SCORING. The DNS evaluators emit one finding per
# domain under the same ControlId, so per-finding scoring weighted each DNS
# control once per domain: the same configuration scored differently on a
# tenant with more domains, and a one-domain Gap could be outvoted by another
# domain's pass. Collapse instances to the WORST state (Gap > Error > Partial >
# Satisfied > NotApplicable), as Get-NRGAssessmentScope already does, keeping
# the worst instance's citations. Findings without a ControlId pass through.
function Get-NRGStateSeverityRank {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return @{ 'Gap' = 5; 'Error' = 4; 'Partial' = 3; 'NotApplicable' = 2; 'Satisfied' = 1 }
}

function Get-NRGScoringFindings {
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Findings)
    # ONE worst-state order, shared by the score, the scope section and the
    # SSP (they used three, so a control passing on one domain and unread on
    # another scored as a pass while the scope section called it "not
    # assessed"). Known shortfalls first; then unknown; a pass only when
    # every instance passed.
    #
    # Controls that read the same setting (Config/control-links.json) are one
    # entry: the worst state across the group, reported under the group's
    # primary ID where states tie, carrying the UNION of the members'
    # framework citations so no framework loses a row. Each member still has
    # its own finding in the report; only the counting is shared.
    $rank  = Get-NRGStateSeverityRank
    $links = if (Get-Command Get-NRGControlLinkMap -ErrorAction SilentlyContinue) { Get-NRGControlLinkMap } else { @{} }
    $byId  = [ordered]@{}
    $ids   = @{}
    $cites = @{}
    $loose = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $cid = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
        if (-not $cid) { $loose.Add($f); continue }
        $gid = if ($links.ContainsKey($cid)) { $links[$cid].Primary } else { $cid }
        if (-not $ids.ContainsKey($gid)) { $ids[$gid] = [System.Collections.Generic.List[string]]::new(); $cites[$gid] = [System.Collections.Generic.List[string]]::new() }
        if (-not $ids[$gid].Contains($cid)) { $ids[$gid].Add($cid) }
        foreach ($c in @(Get-NRGObjectField -Item $f -Key 'FrameworkIds' -Default @())) {
            if ($c -and -not $cites[$gid].Contains([string]$c)) { $cites[$gid].Add([string]$c) }
        }
        if (-not $byId.Contains($gid)) { $byId[$gid] = $f; continue }
        $new = [string](Get-NRGObjectField -Item $f -Key 'State' -Default '')
        $old = [string](Get-NRGObjectField -Item $byId[$gid] -Key 'State' -Default '')
        $oldCid = [string](Get-NRGObjectField -Item $byId[$gid] -Key 'ControlId' -Default '')
        if ((($rank[$new] ?? 0) -gt ($rank[$old] ?? 0)) -or
            (($rank[$new] ?? 0) -eq ($rank[$old] ?? 0) -and $cid -eq $gid -and $oldCid -ne $gid)) { $byId[$gid] = $f }
    }
    $out = foreach ($gid in @($byId.Keys)) {
        $rep = $byId[$gid]
        if ($ids[$gid].Count -le 1) { $rep; continue }
        # A copy, so the member's own finding is untouched in the report.
        $copy = if ($rep -is [System.Collections.IDictionary]) { $rep.Clone() } else { $rep.PSObject.Copy() }
        $union = [string[]]@($cites[$gid])
        $members = [string[]]@($ids[$gid])
        if ($copy -is [System.Collections.IDictionary]) {
            $copy['FrameworkIds'] = $union; $copy['LinkedControls'] = $members
        } else {
            $copy | Add-Member -NotePropertyName FrameworkIds -NotePropertyValue $union -Force
            $copy | Add-Member -NotePropertyName LinkedControls -NotePropertyValue $members -Force
        }
        $copy
    }
    return @(@($out) + @($loose))
}

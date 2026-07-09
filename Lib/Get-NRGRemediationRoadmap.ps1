#Requires -Version 7.0
#
# Get-NRGRemediationRoadmap.ps1
# Dependencies: Get-NRGCoverageScore, Get-NRGObjectField, Get-NRGControlDefinitions
#               (all optional-guarded), Get-NRGTenantLicenseProfile /
#               Test-NRGLicenseRequirementMet (for license classification)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Purpose: Turn the assessment from a GRADE into a GUIDE. Ranks the open
#   Gap/Partial findings by how many compliance-score points each fix returns,
#   separating zero-license "quick wins" (a configuration change the tenant is
#   already licensed for) from "license unlocks" (fixes that first require a
#   licensing upgrade). Produces an ordered roadmap with an exact projected
#   score after each step, so the report can say:
#
#     "Do these 5 first: +18 points, all zero-license configuration changes."
#
# WHY THE MATH IS EXACT (not a heuristic):
#   The tenant score is Score = round(100 * (Satisfied + 0.5*Partial) / Scored),
#   the same formula Get-NRGCoverageScore computes. Fixing a Gap -> Satisfied
#   adds 1.0 to the numerator; fixing a Partial -> Satisfied adds 0.5. For a
#   quick win the denominator (Scored) does not change — the control was already
#   counted — so the projected score after a set of quick wins is just
#   round(100 * (Satisfied + Σ delta) / Scored). No estimation, no rounding
#   drift (we recompute from counts, we don't sum rounded per-step deltas).
#
#   License unlocks are listed but NOT given a projected-score number: a licence
#   purchase changes the denominator and the post-upgrade state is speculative
#   (licensed-but-unconfigured is a Gap, not an automatic Satisfied), so
#   attaching a precise point value there would overclaim. They are the separate
#   "upgrade to unlock" track, consistent with the License Gap Analysis card.
#
# OUTPUT SCHEMA (all keys always present; empty collections, never $null):
#   @{
#     BaselineScore              = <int 0..100>
#     Scored                     = <int>            # denominator used
#     ProjectedScoreAllQuickWins = <int 0..100>
#     QuickWinPointGain          = <int>            # projected - baseline
#     QuickWinCount              = <int>
#     QuickWins                  = @( @{
#         Rank; ControlId; Title; Severity; State; Workload;
#         ScoreLift        # marginal points this single fix returns (1 dp)
#         CumulativeScore  # exact projected score after this + all prior wins
#         Remediation
#     } ... )                                        # ranked best-first
#     LicenseUnlocks             = @( @{ ControlId; Title; Severity; State;
#                                        LicenseRequirement; Remediation } ... )
#     LicenseUnlockCount         = <int>
#   }
#
# OWASP / ASVS: not in scope (reporting math, not a security control).
#

function Get-NRGRemediationRoadmap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Findings,

        # Optional — output of Get-NRGTenantLicenseProfile. If omitted, the
        # helper resolves it from module state. Passing null means "no SKU
        # data": a control with a real licence requirement is then classified
        # as a license unlock (conservative — never a false quick win).
        [Parameter()] [AllowNull()] [object] $LicenseProfile
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # ── Field reader — StrictMode-safe across hashtable / ordered / PSCustomObject
    $readField = {
        param($item, $key)
        if ($null -eq $item) { return $null }
        if (Get-Command Get-NRGObjectField -ErrorAction SilentlyContinue) {
            return Get-NRGObjectField -Item $item -Key $key
        }
        # Fallback if the helper isn't loaded (isolated unit test).
        if ($item -is [System.Collections.IDictionary]) {
            if ($item.Contains($key)) { return $item[$key] }
            return $null
        }
        $p = $item.PSObject.Properties[$key]
        if ($p) { return $p.Value }
        return $null
    }

    $emptyResult = [ordered]@{
        BaselineScore              = 0
        Scored                     = 0
        ProjectedScoreAllQuickWins = 0
        QuickWinPointGain          = 0
        QuickWinCount              = 0
        QuickWins                  = @()
        LicenseUnlocks             = @()
        LicenseUnlockCount         = 0
    }

    # ── Baseline via the canonical scorer (same 'Gap' error-handling the HTML
    #    executive score uses, so BaselineScore matches the report's ring). ──
    if (-not (Get-Command Get-NRGCoverageScore -ErrorAction SilentlyContinue)) {
        return $emptyResult
    }
    $cov    = Get-NRGCoverageScore -Findings $Findings -ErrorHandling 'Gap'
    $scored = [int]$cov.Scored
    $baseScore = [int]$cov.Score
    # Baseline numerator = Satisfied + 0.5*Partial — the SAME numerator the score
    # formula starts from. A Partial already contributes 0.5, so fixing it adds
    # only 0.5 (its delta below); the projected score must therefore build on
    # this full baseline numerator, not on the Satisfied count alone.
    $baseNum = [double]$cov.Satisfied + 0.5 * [double]$cov.Partial

    if ($scored -le 0 -or -not $Findings) {
        $emptyResult.BaselineScore              = $baseScore
        $emptyResult.Scored                     = $scored
        $emptyResult.ProjectedScoreAllQuickWins = $baseScore
        return $emptyResult
    }

    # ── Control-definition lookup (LicenseRequirement / Remediation / Title). ─
    $cdefs = @{}
    if (Get-Command Get-NRGControlDefinitions -ErrorAction SilentlyContinue) {
        try {
            foreach ($c in (Get-NRGControlDefinitions)) {
                $cid = [string](& $readField $c 'ControlId')
                if ($cid) { $cdefs[$cid] = $c }
            }
        } catch { }
    }

    # ── License profile (for quick-win vs unlock classification). ─────────────
    if (-not $PSBoundParameters.ContainsKey('LicenseProfile')) {
        $LicenseProfile = $null
        if (Get-Command Get-NRGTenantLicenseProfile -ErrorAction SilentlyContinue) {
            try { $LicenseProfile = Get-NRGTenantLicenseProfile } catch { $LicenseProfile = $null }
        }
    }
    $canTestLicense = [bool](Get-Command Test-NRGLicenseRequirementMet -ErrorAction SilentlyContinue)

    $sevRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Informational' = 4 }

    # ── Classify each actionable finding. ─────────────────────────────────────
    $quick    = [System.Collections.Generic.List[object]]::new()
    $unlocks  = [System.Collections.Generic.List[object]]::new()

    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }
        try {
            $state = [string](& $readField $f 'State')
            if ($state -notin @('Gap', 'Partial')) { continue }

            $cid  = [string](& $readField $f 'ControlId')
            $ctrl = if ($cid -and $cdefs.ContainsKey($cid)) { $cdefs[$cid] } else { $null }

            $title = [string](& $readField $f 'Title')
            if ([string]::IsNullOrWhiteSpace($title) -and $ctrl) { $title = [string](& $readField $ctrl 'Title') }

            $sev = [string](& $readField $f 'Severity')
            if ([string]::IsNullOrWhiteSpace($sev) -and $ctrl) { $sev = [string](& $readField $ctrl 'Severity') }
            if ([string]::IsNullOrWhiteSpace($sev)) { $sev = 'Medium' }

            $rem = [string](& $readField $f 'Remediation')
            if ([string]::IsNullOrWhiteSpace($rem) -and $ctrl) { $rem = [string](& $readField $ctrl 'Remediation') }

            $workload = if ($cid -match '^([A-Z]{2,4})-') { $matches[1] } else { '' }

            # Move-to-Satisfied numerator delta: Gap gains 1.0, Partial gains 0.5.
            $delta = if ($state -eq 'Gap') { 1.0 } else { 0.5 }

            # License classification.
            $licReq = if ($ctrl) { [string](& $readField $ctrl 'LicenseRequirement') } else { '' }
            $licMet = $true
            if (-not [string]::IsNullOrEmpty($licReq) -and $licReq -notmatch '^Included') {
                if ($canTestLicense) {
                    $licMet = [bool](Test-NRGLicenseRequirementMet -LicenseRequirement $licReq -LicenseProfile $LicenseProfile)
                } else {
                    $licMet = $false
                }
            }

            if ($licMet) {
                $quick.Add([pscustomobject]@{
                    ControlId   = $cid
                    Title       = $title
                    Severity    = $sev
                    State       = $state
                    Workload    = $workload
                    Delta       = $delta
                    SevRank     = if ($sevRank.ContainsKey($sev)) { $sevRank[$sev] } else { 5 }
                    Remediation = $rem
                })
            } else {
                $unlocks.Add([pscustomobject]@{
                    ControlId          = $cid
                    Title              = $title
                    Severity           = $sev
                    State              = $state
                    LicenseRequirement = $licReq
                    Remediation        = $rem
                })
            }
        } catch {
            Write-Warning "Get-NRGRemediationRoadmap: skipping malformed finding ($($_.Exception.Message))"
            continue
        }
    }

    # ── Rank quick wins: biggest single-fix lift first (Gap 1.0 before Partial
    #    0.5), then by severity, then ControlId for a stable deterministic order.
    $ranked = @($quick | Sort-Object `
        @{ Expression = 'Delta';     Descending = $true },
        @{ Expression = 'SevRank';   Descending = $false },
        @{ Expression = 'ControlId'; Descending = $false })

    # ── Cumulative exact projected score. Scored is constant for quick wins. ──
    $quickWins = [System.Collections.Generic.List[object]]::new()
    $cumDelta  = 0.0
    $rank      = 0
    foreach ($q in $ranked) {
        $rank++
        $cumDelta += [double]$q.Delta
        $projected = [int][Math]::Min(100, [Math]::Round(100 * ($baseNum + $cumDelta) / $scored))
        $marginal  = [Math]::Round(100 * ([double]$q.Delta) / $scored, 1)
        $quickWins.Add([ordered]@{
            Rank            = $rank
            ControlId       = $q.ControlId
            Title           = $q.Title
            Severity        = $q.Severity
            State           = $q.State
            Workload        = $q.Workload
            ScoreLift       = $marginal
            CumulativeScore = $projected
            Remediation     = $q.Remediation
        })
    }

    $projectedAll = if ($quickWins.Count -gt 0) {
        [int]$quickWins[$quickWins.Count - 1].CumulativeScore
    } else { $baseScore }

    [ordered]@{
        BaselineScore              = $baseScore
        Scored                     = $scored
        ProjectedScoreAllQuickWins = $projectedAll
        QuickWinPointGain          = $projectedAll - $baseScore
        QuickWinCount              = $quickWins.Count
        QuickWins                  = @($quickWins)
        LicenseUnlocks             = @($unlocks | ForEach-Object {
            [ordered]@{
                ControlId          = $_.ControlId
                Title              = $_.Title
                Severity           = $_.Severity
                State              = $_.State
                LicenseRequirement = $_.LicenseRequirement
                Remediation        = $_.Remediation
            }
        })
        LicenseUnlockCount         = $unlocks.Count
    }
}

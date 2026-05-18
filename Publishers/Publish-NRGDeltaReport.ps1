#Requires -Version 7.0
#
# Publish-NRGDeltaReport.ps1  (v4.5.5)
# Compares current assessment findings against a prior run baseline JSON.
# Produces a Markdown delta report showing:
#   - New gaps (Gap in current, not Gap in baseline)
#   - Resolved gaps (Gap in baseline, Satisfied in current)
#   - Regressed controls (Satisfied→Gap or any deterioration)
#   - Unchanged gaps
#   - Score delta
#
# Usage:
#   Publish-NRGDeltaReport -CurrentFindings $findings `
#     -BaselineResultsPath ".\prior-run-results.json" `
#     -Metadata $meta -OutputPath ".\delta.md"
#

function Publish-NRGDeltaReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]]  $CurrentFindings,
        [Parameter(Mandatory)]
        [ValidateScript({
            if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Baseline file not found: $_" }
            return $true
        })]
        [string]    $BaselineResultsPath,
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [string]    $OutputPath
    )

    # Load baseline
    $baselineRaw = Get-Content -LiteralPath $BaselineResultsPath -Encoding utf8 -Raw | ConvertFrom-Json
    $baseFindings = @($baselineRaw.Findings ?? $baselineRaw)

    # Build lookup by ControlId
    $base = @{}
    foreach ($f in $baseFindings) { $base[[string]$f.ControlId] = $f }
    $curr = @{}
    foreach ($f in $CurrentFindings) { $curr[[string]$f.ControlId] = $f }

    # Categorize changes
    $newGaps       = @()  # Was not Gap, now is Gap
    $resolved      = @()  # Was Gap, now Satisfied
    $regressed     = @()  # Was Satisfied/Partial, now worse
    $improved      = @()  # Was Gap, now Partial (partial progress)
    $unchangedGaps = @()  # Was Gap, still Gap

    foreach ($cid in ($curr.Keys | Sort-Object)) {
        $c = $curr[$cid]; $b = $base[$cid]
        if (-not $b) {
            # New control added since baseline
            if ($c.State -eq 'Gap') { $newGaps += $c }
            continue
        }
        $bState = [string]$b.State; $cState = [string]$c.State
        $sOrder = @{ 'Satisfied'=0; 'Partial'=1; 'Gap'=2; 'NotApplicable'=3 }
        $bOrd = if ($sOrder.ContainsKey($bState)) { $sOrder[$bState] } else { 3 }
        $cOrd = if ($sOrder.ContainsKey($cState)) { $sOrder[$cState] } else { 3 }

        if ($bState -eq 'Gap' -and $cState -eq 'Satisfied')  { $resolved   += $c } elseif ($bState -eq 'Gap' -and $cState -eq 'Partial') { $improved   += $c } elseif ($bState -eq 'Gap' -and $cState -eq 'Gap')    { $unchangedGaps += $c } elseif ($cOrd -gt $bOrd)                              { $regressed  += $c } elseif ($cState -eq 'Gap' -and $bState -ne 'Gap')    { $newGaps    += $c }
    }

    # Score calculation
    function Get-Score { param([object[]]$f)
        $sc = @($f | Where-Object State -ne 'NotApplicable').Count
        $sat = @($f | Where-Object State -eq 'Satisfied').Count
        $pt  = @($f | Where-Object State -eq 'Partial').Count
        if ($sc -gt 0) { [int][Math]::Round(100*($sat+0.5*$pt)/$sc) } else { 0 }
    }
    $currScore = Get-Score $CurrentFindings
    $baseScore = Get-Score $baseFindings
    $scoreDelta = $currScore - $baseScore
    $scoreArrow = if ($scoreDelta -gt 0) { "&#9650; +$scoreDelta" } elseif ($scoreDelta -lt 0) { "&#9660; $scoreDelta" } else { "&#9654; 0" }

    $baseDate = [string]($baselineRaw.Metadata.AssessmentDate ?? 'prior run')
    $currDate = [string]($Metadata.AssessmentDate ?? (Get-Date -Format 'MMMM dd, yyyy'))
    $client   = [string]($Metadata.TenantDomain ?? 'Client')

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# Assessment Delta Report")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Client:** $client  ")
    $null = $sb.AppendLine("**Current assessment:** $currDate  ")
    $null = $sb.AppendLine("**Baseline:** $baseDate  ")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("## Score Change")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| | Baseline | Current | Change |")
    $null = $sb.AppendLine("|---|---|---|---|")
    $null = $sb.AppendLine("| Security Score | $baseScore/100 | $currScore/100 | **$scoreArrow** |")
    $baseGaps = @($baseFindings | Where-Object State -eq 'Gap').Count
    $currGaps = @($CurrentFindings | Where-Object State -eq 'Gap').Count
    $null = $sb.AppendLine("| Total Gaps | $baseGaps | $currGaps | $(if($currGaps -lt $baseGaps){"&#9650; -$($baseGaps-$currGaps)"}elseif($currGaps -gt $baseGaps){"&#9660; +$($currGaps-$baseGaps)"}else{"&#9654; 0"}) |")
    $null = $sb.AppendLine()

    function Write-Section {
        param([string]$title, [object[]]$items, [string]$icon, [string]$emptyMsg)
        $null = $sb.AppendLine("## $icon $title ($($items.Count))")
        $null = $sb.AppendLine()
        if ($items.Count -eq 0) { $null = $sb.AppendLine("*$emptyMsg*"); $null = $sb.AppendLine(); return }
        $null = $sb.AppendLine("| Control | Title | Severity |")
        $null = $sb.AppendLine("|---|---|---|")
        foreach ($f in ($items | Sort-Object @{Expression={ switch($_.Severity){'Critical'{0};'High'{1};'Medium'{2};'Low'{3};default{4}} }},ControlId)) {
            $null = $sb.AppendLine("| $($f.ControlId) | $($f.Title) | $($f.Severity) |")
        }
        $null = $sb.AppendLine()
    }

    Write-Section '&#x1F534; New Gaps'         $newGaps       '🔴' 'No new gaps — good.'
    Write-Section '&#x1F7E0; Regressed'         $regressed     '🟠' 'No regressions.'
    Write-Section '&#x1F7E1; Unchanged Gaps'    $unchangedGaps '🟡' 'No unchanged gaps.'
    Write-Section '&#x1F7E2; Resolved'          $resolved      '🟢' 'No gaps resolved this period.'
    Write-Section '&#x1F535; Partially Improved' $improved     '🔵' 'No partial improvements.'

    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("## Trend Summary")
    $null = $sb.AppendLine()
    if ($resolved.Count -gt 0 -and $newGaps.Count -eq 0) {
        $null = $sb.AppendLine("> **Positive trend.** $($resolved.Count) gap(s) resolved with no new gaps introduced.")
    } elseif ($newGaps.Count -gt $resolved.Count) {
        $null = $sb.AppendLine("> **Negative trend.** $($newGaps.Count) new gap(s) exceed $($resolved.Count) resolved gap(s). Security posture deteriorated this period.")
    } elseif ($resolved.Count -gt 0) {
        $null = $sb.AppendLine("> **Mixed trend.** $($resolved.Count) gap(s) resolved, $($newGaps.Count) new gap(s) introduced.")
    } else {
        $null = $sb.AppendLine("> **No change.** Posture unchanged from baseline.")
    }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Recommended next action:**")
    if ($newGaps.Count -gt 0) {
        $topNew = $newGaps | Sort-Object @{Expression={switch($_.Severity){'Critical'{0};'High'{1};default{2}}}} | Select-Object -First 3
        $null = $sb.AppendLine("Address the $($newGaps.Count) new gap(s) first, prioritizing: $($topNew.Title -join ', ').")
    } elseif ($unchangedGaps.Count -gt 0) {
        $null = $sb.AppendLine("$($unchangedGaps.Count) gap(s) remain unresolved from prior assessment. Focus on completing Phase 1 remediation.")
    } else {
        $null = $sb.AppendLine("All prior gaps resolved. Schedule next full assessment in 90 days.")
    }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine("*NRG-Assessment v$($Metadata.ToolVersion ?? '4.5.5') · NRG Technology Services · $currDate*")

    $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
}
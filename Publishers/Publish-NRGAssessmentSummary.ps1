#Requires -Version 7.0
#
# Publish-NRGAssessmentSummary.ps1  (v4.5.5)
# Generates a Markdown assessment summary report from findings.
#
# SECURITY:
#   - All tenant-sourced values (domain, tenant name, finding details)
#     pass through ConvertTo-NRGHtmlSafe before inclusion.
#     Even in Markdown, escaping prevents injection into downstream processors
#     (Pandoc → HTML, MkDocs, GitHub rendering).
#   - OutputPath validated by orchestrator — LiteralPath used here.
#   - Out-File uses explicit -Encoding utf8 (ASVS V16.2.3)
#
# OWASP A03  — tenant data sanitized before output
# ASVS V16.2.3 — explicit output encoding
#

function Publish-NRGAssessmentSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]  $Metadata,
        [Parameter(Mandatory)] [object[]]   $Findings,
        [Parameter(Mandatory)] [hashtable]  $Connections,
        [Parameter(Mandatory)] [string]     $OutputPath,
        [AllowNull()] [object] $BaselineRegressions = $null,
        # The pre-run plan compared with this run (Compare-NRGBaselinePlan). Optional.
        [AllowNull()] [object] $BaselinePlanComparison = $null
    )

    # Fail closed — require security helpers
    if (-not (Get-Command ConvertTo-NRGHtmlSafe -ErrorAction SilentlyContinue)) {
        throw "ConvertTo-NRGHtmlSafe not loaded — refusing to generate report without XSS protection."
    }

    # Helper: escape for Markdown (prevents table/header injection).
    # Only escape characters that break markdown table/code-span structure
    # (pipe, backtick, raw newlines). Do NOT HTML-escape (>, ', &, etc.) —
    # those are valid markdown source and HTML escaping at this layer
    # produces visible `&gt;` and `&#39;` in the rendered output. XSS
    # protection belongs at the markdown→HTML render boundary, not here.
    function EscMd([object]$v) {
        if ($null -eq $v -or [string]::IsNullOrEmpty([string]$v)) { return '' }
        $safe = [string]$v
        $safe = $safe -replace '\|', '\|' -replace '`', '\`' -replace '[\r\n]+', ' '
        return $safe
    }

    $brand      = $script:NRGBrand
    $company    = EscMd ($brand.CompanyName ?? 'NRG Technology Services / NextLayerSec LLC')
    # Get-NRGObjectField, not dot-access-then-??: StrictMode throws on a
    # missing key before ?? can apply. These three happen to be present on
    # every metadata shape today, but the pattern is one absent key away from
    # silently suppressing this deliverable, as it did for the XLSX matrix.
    $tenant     = EscMd ([string](Get-NRGObjectField -Item $Metadata -Key 'TenantDomain'   -Default 'Unknown Tenant'))
    $assmtDate  = EscMd ([string](Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'MMMM dd, yyyy')))
    $version    = EscMd ([string](Get-NRGObjectField -Item $Metadata -Key 'ToolVersion'    -Default '4.5.5'))

    # License tier — added in v4.6.2. The Markdown report previously had no
    # tier indicator at all, which led operators to assume the tool had not
    # detected their license. The line is rendered just below the metadata
    # block. Degrades gracefully when the helper is not loaded.
    $tierLabel = if (Get-Command Get-NRGTenantLicenseProfile -ErrorAction SilentlyContinue) {
        try { (Get-NRGTenantLicenseProfile).TierLabel } catch { 'Unknown' }
    } else { 'Unknown' }
    $tierLabelMd = EscMd $tierLabel

    # Scoring summary — v4.10.1: pulled from the canonical helper instead of
    # re-rolling Where-Object passes. -ErrorHandling Gap preserves the
    # historical Summary semantics (Error findings counted in the denominator).
    $cov = Get-NRGCoverageScore -Findings $Findings -ErrorHandling 'Gap'
    $satisfied = $cov.Satisfied
    $partial   = $cov.Partial
    $gap       = $cov.Gap
    $na        = $cov.NA
    $total     = $cov.Total
    $scorePerc = $cov.Score

    # PowerShell `switch ($true)` evaluates EVERY matching scriptblock unless
    # each arm contains a `break`. The previous form fell through and joined
    # multiple buckets together ("Moderate At Risk" at 73%). Rewriting as
    # if/elseif/else makes the mutually-exclusive intent obvious and removes
    # the fallthrough hazard.
    $posture = if     ($scorePerc -ge 85) { 'Strong'   }
               elseif ($scorePerc -ge 65) { 'Moderate' }
               elseif ($scorePerc -ge 40) { 'At Risk'  }
               else                       { 'Critical' }

    # Build findings tables by severity
    $criticalGaps = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'Critical' })
    $highGaps     = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'High' })
    $otherGaps    = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -notin @('Critical','High') })

    $sb = [System.Text.StringBuilder]::new()

    $null = $sb.AppendLine("# M365 Security Assessment Report")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Prepared by:** $company")
    $null = $sb.AppendLine("**Tenant:** $tenant")
    $null = $sb.AppendLine("**License Tier:** $tierLabelMd")
    $null = $sb.AppendLine("**Assessment Date:** $assmtDate")
    $null = $sb.AppendLine("**Tool Version:** $version")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("## Executive Summary")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Overall Security Posture: $posture ($scorePerc%)**")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| Result | Count |")
    $null = $sb.AppendLine("|--------|-------|")
    $null = $sb.AppendLine("| ✅ Satisfied | $satisfied |")
    $null = $sb.AppendLine("| ⚠️ Partial | $partial |")
    $null = $sb.AppendLine("| ❌ Gap | $gap |")
    # Without this row the table did not add up to its total, and a reader
    # could not tell whether the missing rows were passes or failures.
    $null = $sb.AppendLine("| ⛔ Error (not evaluated; counted as a failure) | $($cov.Error) |")
    $null = $sb.AppendLine("| — Not Applicable | $na |")
    $null = $sb.AppendLine("| **Total Controls** | **$total** |")
    $null = $sb.AppendLine()

    # ── Risk Exposure (PR #8 — Get-NRGAggregateRisk) ─────────────────────────
    # Translates open Gap and Partial findings into annualized loss expectancy
    # using Verizon DBIR / IBM CoaDB anchored bands. Degrades gracefully when
    # the risk-quantification module is not loaded (older deployments without
    # PR #8 merged): the section is omitted and the rest of the report is
    # unaffected.
    if (Get-Command Get-NRGAggregateRisk -CommandType Function -Module NRG-Assessment -ErrorAction SilentlyContinue) {
        try {
            $risk = Get-NRGAggregateRisk -Findings $Findings
            if ($risk.OpenGapAndPartialCount -gt 0) {
                $null = $sb.AppendLine("## 💰 Estimated Annual Risk Exposure")
                $null = $sb.AppendLine()
                $null = $sb.AppendLine("**Open gaps and partials map to roughly $(EscMd $risk.TotalRangeFormatted) in expected annual loss.**")
                $null = $sb.AppendLine()
                $null = $sb.AppendLine("| Metric | Value |")
                $null = $sb.AppendLine("|---|---|")
                $null = $sb.AppendLine("| Findings included | $($risk.OpenGapAndPartialCount) (Gap + Partial) |")
                $null = $sb.AppendLine("| Exposure range | $(EscMd $risk.TotalRangeFormatted) |")
                $null = $sb.AppendLine("| Midpoint estimate | $(EscMd $risk.TotalMidpointFormatted) |")
                $null = $sb.AppendLine()

                if ($risk.BySeverity.Count -gt 0) {
                    $null = $sb.AppendLine("**By severity:**")
                    $null = $sb.AppendLine()
                    $null = $sb.AppendLine("| Severity | Open | Exposure range |")
                    $null = $sb.AppendLine("|---|---|---|")
                    foreach ($sev in @('Critical','High','Medium','Low')) {
                        if ($risk.BySeverity.ContainsKey($sev)) {
                            $b = $risk.BySeverity[$sev]
                            $range = '$' + ('{0:N0}' -f $b.Low) + ' – $' + ('{0:N0}' -f $b.High)
                            $null = $sb.AppendLine("| $sev | $($b.Count) | $(EscMd $range) |")
                        }
                    }
                    $null = $sb.AppendLine()
                }

                $null = $sb.AppendLine("> *Methodology: annualized loss expectancy = SLE × ARO. SLE from Verizon DBIR 2025 incident-cost medians and IBM Cost of a Data Breach 2024. Bands, not point estimates — assessment-grade.*")
                $null = $sb.AppendLine()
            }
        } catch {
            # Risk calc failure must not break the rest of the report
            $null = $sb.AppendLine("## 💰 Risk Exposure")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("*Risk exposure calculation failed: $(EscMd $_.Exception.Message). Report continues with the rest of the findings.*")
            $null = $sb.AppendLine()
        }
    }

    # ── Assessment scope and limitations ─────────────────────────────────────
    # Directly under the score and the risk figure, because both are read as
    # statements about the tenant and both are silent about controls the tool
    # never reached a verdict on. NotApplicable is excluded from the
    # denominator, so the score RISES when the tool goes blind.
    if (Get-Command Get-NRGAssessmentScope -ErrorAction SilentlyContinue) {
        $scope = $null
        # The licence profile and the quick-scan flag are passed here exactly
        # as the HTML publisher passes them. Omitting them made the same run's
        # two deliverables bucket the same control differently.
        $mdLicProfile = if (Get-Command Get-NRGTenantLicenseProfile -ErrorAction SilentlyContinue) {
            try { Get-NRGTenantLicenseProfile } catch { $null }
        } else { $null }
        try {
            $scope = Get-NRGAssessmentScope -Findings $Findings -LicenseProfile $mdLicProfile `
                        -QuickScan:([bool](Get-NRGObjectField -Item $Metadata -Key 'QuickScan' -Default $false))
        } catch {
            Write-Verbose "Assessment scope section skipped: $($_.Exception.Message)"
        }
        if ($scope -and $scope.Available) {
            $null = $sb.AppendLine("## Assessment Scope and Limitations")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("**$($scope.ScoredControls) of $($scope.TotalControls) controls produced a scored verdict.** The remaining $($scope.UnscoredControls) are itemized below and are excluded from the compliance score — they are neither passes nor failures.")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("| Outcome | Controls |")
            $null = $sb.AppendLine("|---------|----------|")
            $null = $sb.AppendLine("| Scored (Satisfied / Partial / Gap / Error) | $($scope.ScoredControls) |")
            $null = $sb.AppendLine("| Could not be assessed — data did not collect | $($scope.CollectionIncomplete.Count) |")
            $null = $sb.AppendLine("| Not evaluated — quick-scan mode | $($scope.NotEvaluatedThisMode.Count) |")
            $null = $sb.AppendLine("| Not assessed — workload skipped by the operator | $(@(Get-NRGObjectField -Item $scope -Key 'SkippedByOperator' -Default @()).Count) |")
            $null = $sb.AppendLine("| Produced no result at all | $($scope.NoResult.Count) |")
            $null = $sb.AppendLine("| Manual review required (no automated test, or no automated verdict) | $($scope.NoProgrammaticCheck.Count) |")
            $null = $sb.AppendLine("| Covered by a declared third-party EDR — not verified | $(@(Get-NRGObjectField -Item $scope -Key 'ThirdPartyAttested' -Default @()).Count) |")
            $null = $sb.AppendLine("| Checked, not applicable to this tenant (reason stated) | $(@(Get-NRGObjectField -Item $scope -Key 'NotApplicableToTenant' -Default @()).Count) |")
            $null = $sb.AppendLine("| License gated | $($scope.LicenceBlocked.Count) |")
            $null = $sb.AppendLine()

            foreach ($l in $scope.Limitations) {
                $null = $sb.AppendLine("- $(EscMd $l)")
            }
            $null = $sb.AppendLine()

            foreach ($grp in @(
                @{ Label = 'Could not be assessed — data did not collect'; Items = $scope.CollectionIncomplete }
                @{ Label = 'Not evaluated — quick-scan mode'; Items = $scope.NotEvaluatedThisMode }
                @{ Label = 'Not assessed — workload skipped by the operator (a -Skip flag)'; Items = @(Get-NRGObjectField -Item $scope -Key 'SkippedByOperator' -Default @()) }
                @{ Label = 'Produced no result at all'; Items = $scope.NoResult }
                @{ Label = 'Manual review required — no automated test, or no automated verdict'; Items = $scope.NoProgrammaticCheck }
                @{ Label = 'Covered by a declared third-party EDR — not verified'; Items = @(Get-NRGObjectField -Item $scope -Key 'ThirdPartyAttested' -Default @()) }
                @{ Label = 'Checked, not applicable to this tenant'; Items = @(Get-NRGObjectField -Item $scope -Key 'NotApplicableToTenant' -Default @()) }
            )) {
                $items = @($grp.Items)
                if ($items.Count -eq 0) { continue }
                $null = $sb.AppendLine("### $($grp.Label) ($($items.Count))")
                $null = $sb.AppendLine()
                $null = $sb.AppendLine("| Control | Title | Reason |")
                $null = $sb.AppendLine("|---------|-------|--------|")
                foreach ($it in $items) {
                    $null = $sb.AppendLine("| $(EscMd $it.ControlId) | $(EscMd $it.Title) | $(EscMd $it.Reason) |")
                }
                $null = $sb.AppendLine()
            }

            if (@($scope.CoverageIssues).Count -gt 0) {
                $null = $sb.AppendLine("### Collectors that did not complete ($(@($scope.CoverageIssues).Count))")
                $null = $sb.AppendLine()
                $null = $sb.AppendLine("| Collector | Status | Note |")
                $null = $sb.AppendLine("|-----------|--------|------|")
                foreach ($ci in $scope.CoverageIssues) {
                    $null = $sb.AppendLine("| $(EscMd $ci.Family) | $(EscMd $ci.Status) | $(EscMd $ci.Note) |")
                }
                $null = $sb.AppendLine()
            }
        }
    }

    # ── NRG Security Baseline (desired state; a view, never a score) ─────────
    if (Get-Command Get-NRGBaselineCompliance -ErrorAction SilentlyContinue) {
        $bl = $null
        try {
            $blTier = [string](Get-NRGObjectField -Item $Metadata -Key 'TargetTier' -Default 'Standard')
            if ($blTier -notin @('Minimum', 'Standard', 'Hardened')) { $blTier = 'Standard' }
            $bl = Get-NRGBaselineCompliance -Findings $Findings -TargetTier $blTier -LicenseProfile $mdLicProfile `
                    -TenantDomain ([string](Get-NRGObjectField -Item $Metadata -Key 'TenantDomain' -Default '')) `
                    -QuickScan:([bool](Get-NRGObjectField -Item $Metadata -Key 'QuickScan' -Default $false))
        } catch { Write-Verbose "NRG baseline section skipped: $($_.Exception.Message)" }
        if ($bl -and $bl.Available) {
            $bs = $bl.Summary
            $null = $sb.AppendLine("## NRG Security Baseline v$($bs.BaselineVersion) — $($bs.TargetTier) tier")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("Is this tenant configured the way NRG requires a managed client to be? This is desired state, separate from the framework scores. **$($bs.Satisfied) of $($bs.RequiredControls) required controls are satisfied.** Not verified means the run produced no usable evidence (no result, a collector that did not complete, a skipped workload, a manual check, or evidence older than its freshness window); it is never counted as satisfied.")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("### Configuration compliance")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("| Baseline state | Controls |")
            $null = $sb.AppendLine("|---|---|")
            $null = $sb.AppendLine("| Required at $($bs.TargetTier) | $($bs.RequiredControls) |")
            $null = $sb.AppendLine("| Satisfied | $($bs.Satisfied) |")
            $null = $sb.AppendLine("| Failed | $($bs.Failed) |")
            $null = $sb.AppendLine("| Not verified | $($bs.NotVerified) |")
            $null = $sb.AppendLine("| License blocked | $($bs.LicenseBlocked) |")
            $null = $sb.AppendLine("| Approved exceptions (observed state kept) | $($bs.ApprovedException) |")
            $null = $sb.AppendLine("| Not applicable to this tenant | $($bs.NotApplicable) |")
            $null = $sb.AppendLine("| Stale evidence (older than its freshness class) | $($bs.StaleEvidence) |")
            $null = $sb.AppendLine()
            $causes = Get-NRGObjectField -Item $bs -Key 'NotVerifiedByCause' -Default $null
            if ($null -ne $causes -and @($causes.Keys).Count -gt 0) {
                $null = $sb.AppendLine("| Not verified, by cause | Controls |")
                $null = $sb.AppendLine("|---|---|")
                foreach ($k in @($causes.Keys)) { $null = $sb.AppendLine("| $(EscMd $k) | $($causes[$k]) |") }
                $null = $sb.AppendLine()
            }
            $evc = Get-NRGObjectField -Item $bl -Key 'EvidenceCoverage' -Default $null
            if ($null -ne $evc) {
                $null = $sb.AppendLine("### Evidence coverage")
                $null = $sb.AppendLine()
                $null = $sb.AppendLine("**$($evc.Known) of $($evc.Applicable) applicable required controls have usable evidence ($($evc.Percent)%).**$(if ($evc.LicenseBlocked -gt 0) { " $($evc.LicenseBlocked) license blocked, counted in the denominator and shown separately." })$(if ($evc.NotApplicable -gt 0) { " $($evc.NotApplicable) not applicable, outside the denominator." }) Not a score: a tenant failing every control has 100% evidence coverage.")
                $null = $sb.AppendLine()
                if (@($evc.Gaps.Keys).Count -gt 0) {
                    $null = $sb.AppendLine("| Evidence gaps | Controls |")
                    $null = $sb.AppendLine("|---|---|")
                    foreach ($k in @($evc.Gaps.Keys)) { $null = $sb.AppendLine("| ``$k`` | $($evc.Gaps[$k]) |") }
                    $null = $sb.AppendLine()
                }
            }
            $null = $sb.AppendLine("### Effectiveness visibility")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("Configuration says a control is set; effectiveness says it is working. The assessment can read effectiveness evidence for only a few controls today; everywhere else it is reported as unknown, not assumed.")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("| Effectiveness | Controls |")
            $null = $sb.AppendLine("|---|---|")
            $null = $sb.AppendLine("| Known (effective or ineffective) | $([int]$bs.EffectivenessEffective + [int]$bs.EffectivenessIneffective) |")
            $null = $sb.AppendLine("| Effective | $($bs.EffectivenessEffective) |")
            $null = $sb.AppendLine("| Ineffective | $($bs.EffectivenessIneffective) |")
            $null = $sb.AppendLine("| Unknown (evidence not collected) | $($bs.EffectivenessUnknown) |")
            $null = $sb.AppendLine()
            $efc = Get-NRGObjectField -Item $bl -Key 'EffectivenessCoverage' -Default $null
            if ($null -ne $efc) {
                $null = $sb.AppendLine("**Effectiveness coverage: $($efc.Known) of $($efc.Required) required controls have effectiveness evidence ($($efc.Percent)%).** Configuration evidence never counts as effectiveness evidence; the tool can read effectiveness for $($efc.CapabilityCollected) of these today.")
                $null = $sb.AppendLine()
            }
            if ($null -ne $BaselinePlanComparison -and [bool](Get-NRGObjectField -Item $BaselinePlanComparison -Key 'Available' -Default $false)) {
                $pc = $BaselinePlanComparison
                $null = $sb.AppendLine("### Expected before the run vs observed")
                $null = $sb.AppendLine()
                $null = $sb.AppendLine((EscMd ([string](Get-NRGObjectField -Item $pc -Key 'Note' -Default ''))))
                $null = $sb.AppendLine()
                $null = $sb.AppendLine("| Plan vs run | Controls |")
                $null = $sb.AppendLine("|---|---|")
                $null = $sb.AppendLine("| Not verified, expected before the run | $([int](Get-NRGObjectField -Item $pc -Key 'ExpectedNotVerified' -Default 0)) |")
                $null = $sb.AppendLine("| Not verified, observed | $([int](Get-NRGObjectField -Item $pc -Key 'ObservedNotVerified' -Default 0)) |")
                $null = $sb.AppendLine("| Licensing unknown before the run | $([int](Get-NRGObjectField -Item $pc -Key 'LicensingUnknownBeforeRun' -Default 0)) |")
                $null = $sb.AppendLine()
                $unexp = @(Get-NRGObjectField -Item $pc -Key 'UnexpectedNotVerified' -Default @())
                if ($unexp.Count -gt 0) {
                    $null = $sb.AppendLine("| Not expected | Cause | Plan said |")
                    $null = $sb.AppendLine("|---|---|---|")
                    foreach ($u in $unexp) { $null = $sb.AppendLine("| $($u.ControlId) | $(EscMd ([string]$u.Cause)) | $(EscMd ([string]$u.Expected)) |") }
                    $null = $sb.AppendLine()
                }
            }
            if ($null -ne $BaselineRegressions) {
                $regs = @(Get-NRGObjectField -Item $BaselineRegressions -Key 'Regressions' -Default @())
                $note = [string](Get-NRGObjectField -Item $BaselineRegressions -Key 'Note' -Default '')
                $null = $sb.AppendLine("### Baseline regressions since the prior run ($($regs.Count))")
                $null = $sb.AppendLine()
                if ($note) { $null = $sb.AppendLine((EscMd $note)); $null = $sb.AppendLine() }
                if ($regs.Count -gt 0) {
                    $null = $sb.AppendLine("| Control | Tier | Previous | Current | Kind | Reason |")
                    $null = $sb.AppendLine("|---|---|---|---|---|---|")
                    foreach ($r in $regs) {
                        $kind = [string](Get-NRGObjectField -Item $r -Key 'Kind' -Default ''); $cause = [string](Get-NRGObjectField -Item $r -Key 'CurrentCause' -Default '')
                        $kindText = if ($kind -eq 'EvidenceLost') { "Evidence lost: $cause" } elseif ($kind -eq 'ConfigurationRegressed') { 'Configuration regressed' } else { $kind }
                        $null = $sb.AppendLine("| $(EscMd $r.ControlId) $(EscMd $r.Title) | $(EscMd $r.RequiredTier) | $(EscMd $r.Previous) | **$(EscMd $r.Current)** | $(EscMd $kindText) | $(EscMd $r.Reason) |")
                    }
                    $null = $sb.AppendLine()
                }
            }
            $order = @{ 'Failed' = 0; 'NotVerified' = 1; 'ApprovedException' = 2; 'LicenseBlocked' = 3; 'NotApplicable' = 4; 'Satisfied' = 5 }
            $null = $sb.AppendLine("### Required controls")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("| Control | Tier | Owner | Baseline | Observed | Evidence | Effectiveness | Dependencies | Reason |")
            $null = $sb.AppendLine("|---|---|---|---|---|---|---|---|---|")
            foreach ($c in ($bl.Controls | Sort-Object { $order[[string]$_.BaselineStatus] }, RequiredTier, ControlId)) {
                $reason = if ([string]$c.BaselineStatus -eq 'ApprovedException') { "$($c.ExceptionSummary) Observed: $($c.ObservedState). $($c.Reason)" } else { [string]$c.Reason }
                $null = $sb.AppendLine("| $(EscMd $c.ControlId) $(EscMd $c.Title) | $(EscMd $c.RequiredTier) | $(EscMd $c.Owner) | **$(EscMd $c.BaselineStatus)** | $(EscMd $c.ObservedState) | $(EscMd $c.EvidenceFreshness) | $(EscMd $c.EffectivenessState) | $(EscMd $c.DependencyState) | ``$(EscMd ([string](Get-NRGObjectField -Item $c -Key 'ReasonCode' -Default '')))`` $(EscMd $reason) |")
            }
            $null = $sb.AppendLine()
        }
    }

    # ── Conditional Access: every policy's real state, and Microsoft's own
    # recommended baseline. A view — no findings, no score change. Mirrors
    # the HTML report's Conditional Access section.
    if (Get-Command Get-NRGConditionalAccessView -ErrorAction SilentlyContinue) {
        $caView = $null
        try { $caView = Get-NRGConditionalAccessView -LicenseProfile $mdLicProfile } catch { $caView = $null }
        if ($caView -and $caView.Available -and $caView.ReadStatus -eq 'Collected') {
            $null = $sb.AppendLine("## Conditional Access")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("$($caView.Counts.Total) polic$(if ($caView.Counts.Total -eq 1) {'y'} else {'ies'}) &mdash; $($caView.Counts.On) On, $($caView.Counts.ReportOnly) Report-only (audit), $($caView.Counts.Off) Off.")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("| Policy | State | Description |")
            $null = $sb.AppendLine("|--------|-------|-------------|")
            foreach ($p in $caView.Policies) {
                $null = $sb.AppendLine("| $(EscMd $p.DisplayName) | $(EscMd $p.StateLabel) | $(EscMd $p.Description) |")
            }
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("### Recommended Conditional Access Baseline")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("Advisory only &mdash; nothing here is scored. A policy scoped to specific apps, groups or users is never credited against a broad template it does not implement.")
            if ($caView.SecurityDefaultsState -eq $true) {
                $null = $sb.AppendLine()
                $null = $sb.AppendLine("Security Defaults is enabled: Conditional Access policies can be created but not turned on, so most of this baseline reads *Not in place* until Security Defaults is replaced by Conditional Access.")
            }
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("| Template | Category | Status | Note |")
            $null = $sb.AppendLine("|----------|----------|--------|------|")
            foreach ($b in $caView.Baseline) {
                $lbl = switch ($b.Status) {
                    'Enforced'                  { 'Enforced' }
                    'Similar'                    { 'Partly in place' }
                    'CoveredBySecurityDefaults'  { 'Covered by Security Defaults' }
                    'NotLicensed'                { 'Needs a license' }
                    'NotRead'                    { 'Not read' }
                    default                      { 'Not in place' }
                }
                $null = $sb.AppendLine("| [$(EscMd $b.Name)]($($b.SourceUrl)) | $(EscMd $b.Category) | $lbl | $(EscMd $b.Note) |")
            }
            $null = $sb.AppendLine()
            if ($caView.Custom.Count -gt 0) {
                $null = $sb.AppendLine("**$($caView.Custom.Count) custom polic$(if ($caView.Custom.Count -eq 1) {'y'} else {'ies'})** &mdash; scoped to specific apps, groups or users and matched to no baseline template above: $(EscMd (($caView.Custom | ForEach-Object { $_.DisplayName }) -join ', ')).")
                $null = $sb.AppendLine()
            }
        }
    }

    # Service connection status
    $null = $sb.AppendLine("## Service Coverage")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| Service | Connected |")
    $null = $sb.AppendLine("|---------|-----------|")
    $null = $sb.AppendLine("| Microsoft Graph (Entra ID) | $(if ($Connections.Graph) { '✅' } else { '❌' }) |")
    $null = $sb.AppendLine("| Exchange Online | $(if ($Connections.EXO) { '✅' } else { '❌' }) |")
    $null = $sb.AppendLine("| Security & Compliance | $(if ($Connections.IPPSSession) { '✅' } else { '❌' }) |")
    $null = $sb.AppendLine("| Microsoft Teams | $(if ($Connections.Teams) { '✅' } else { '❌' }) |")
    $null = $sb.AppendLine("| SharePoint Online | $(if ($Connections.SharePoint) { '✅' } else { '❌' }) |")
    $null = $sb.AppendLine()

    # NIST SP 800-53 Rev 5 control-family coverage.
    # Sits ahead of the gap tables because a compliance reader working an
    # 800-53 / FedRAMP / CMMC assessment needs the family posture first —
    # every other section of this summary is organized by M365 workload, which
    # is the engineer's lens rather than the auditor's. Rendered only when the
    # findings actually carry NIST citations, so an Email-IR or partial run
    # does not emit an empty table.
    $nistCov = $null
    if (Get-Command Get-NRGNISTFamilyCoverage -ErrorAction SilentlyContinue) {
        try { $nistCov = Get-NRGNISTFamilyCoverage -Findings $Findings -ErrorHandling 'Gap' }
        catch { $nistCov = $null }
    }
    if ($nistCov -and $nistCov.FamilyCount -gt 0) {
        $null = $sb.AppendLine("## NIST SP 800-53 Rev 5 — Control Family Coverage")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("| Family | Name | Assessed | Met | Partial | Gap | Error | N/A | Coverage |")
        $null = $sb.AppendLine("|--------|------|---------:|----:|--------:|----:|------:|----:|---------:|")
        foreach ($fam in $nistCov.Families) {
            # Scored -eq 0 means every finding in the family was NotApplicable.
            # Printing 0% there would report a failing grade for a question the
            # tool never got to ask.
            $covTxt = if ($fam.Scored -gt 0) { "$([int]$fam.Score)%" } else { 'Not assessed' }
            $null = $sb.AppendLine("| $(EscMd $fam.Family) | $(EscMd $fam.Name) | $($fam.Assessed) | $($fam.Satisfied) | $($fam.Partial) | $($fam.Gap) | $($fam.Error) | $($fam.NA) | $covTxt |")
        }
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("_$($nistCov.NistControlCount) distinct 800-53 controls exercised. Met + Partial + Gap + Error + N/A sums to Assessed on every row. A control mapped to more than one family is counted in each, so family rows do not sum to the assessment total. N/A and Error are both excluded from Coverage — N/A means this assessment could not evaluate the control, Error means the evaluator threw before reaching a verdict. Neither is a control the tenant passed._")
        $null = $sb.AppendLine()
    }

    # NIST physical / media / device controls.
    # Deliberately placed after the family table it qualifies: the family table
    # is a score, and this section is the statement of what that score does and
    # does not cover. Nothing here is scored — Attestation-required rows were
    # never assessed and must not read as compliant.
    $physCov = $null
    if (Get-Command Get-NRGNISTPhysicalPosture -ErrorAction SilentlyContinue) {
        try { $physCov = Get-NRGNISTPhysicalPosture -Findings $Findings }
        catch { $physCov = $null }
    }
    if ($physCov -and $physCov.Available -and @($physCov.Groups).Count -gt 0) {
        $null = $sb.AppendLine("## NIST SP 800-53 — Physical, Media and Device Controls")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("A Microsoft 365 assessment can evidence endpoint posture — encryption, patch level, screen lock, endpoint protection, device identity — and it cannot see a locked server room, a certificate of destruction, or a returned badge. Those are still 800-53 controls, so they are listed here with implementation options and the evidence an assessor must collect directly.")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("**Nothing in this section is scored.** Rows marked _Attestation required_ were never assessed by this tool and are not claimed as compliant. $($physCov.TenantItems) items are evidenced from the tenant, $($physCov.HybridItems) partly, and $($physCov.AttestedItems) are not visible from Microsoft 365 at all.")
        $null = $sb.AppendLine()

        foreach ($grp in $physCov.Groups) {
            $null = $sb.AppendLine("### $(EscMd $grp.Title)")
            $null = $sb.AppendLine()
            if ($grp.Description) {
                $null = $sb.AppendLine("_$(EscMd $grp.Description)_")
                $null = $sb.AppendLine()
            }
            foreach ($it in $grp.Items) {
                $evTxt = if (@($it.Evidence).Count -gt 0) {
                    (@($it.Evidence) | ForEach-Object { "$($_.ControlId) ($($_.State))" }) -join ', '
                } else { '' }

                $null = $sb.AppendLine("**$(EscMd $it.NistControl) $(EscMd $it.NistTitle)** — _$(EscMd $it.Status)_")
                $null = $sb.AppendLine()
                if ($it.DeviceAspect)      { $null = $sb.AppendLine("$(EscMd $it.DeviceAspect)"); $null = $sb.AppendLine() }
                if ($evTxt)                { $null = $sb.AppendLine("- Evidence from this assessment: $(EscMd $evTxt)") }
                if ($it.OffTenantEvidence) { $null = $sb.AppendLine("- Evidence the assessor must collect: $(EscMd $it.OffTenantEvidence)") }
                foreach ($opt in @($it.Options)) {
                    $null = $sb.AppendLine("- Option: $(EscMd $opt)")
                }
                $null = $sb.AppendLine()
            }
        }
    }

    # Critical and High gaps
    if ($criticalGaps.Count -gt 0) {
        $null = $sb.AppendLine("## ⛔ Critical Gaps — Immediate Action Required")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("| Control | Finding | Remediation |")
        $null = $sb.AppendLine("|---------|---------|-------------|")
        foreach ($f in $criticalGaps) {
            $title = EscMd $f.Title
            $detail = EscMd ($f.Detail ?? '')
            $remedy = EscMd ($f.Remediation ?? '')
            $null = $sb.AppendLine("| $(EscMd $f.ControlId) | **$title** — $detail | $remedy |")
        }
        $null = $sb.AppendLine()
    }

    if ($highGaps.Count -gt 0) {
        $null = $sb.AppendLine("## 🔴 High Priority Gaps")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("| Control | Finding | Remediation |")
        $null = $sb.AppendLine("|---------|---------|-------------|")
        foreach ($f in $highGaps) {
            $null = $sb.AppendLine("| $(EscMd $f.ControlId) | **$(EscMd $f.Title)** — $(EscMd ($f.Detail ?? '')) | $(EscMd ($f.Remediation ?? '')) |")
        }
        $null = $sb.AppendLine()
    }

    if ($otherGaps.Count -gt 0) {
        $null = $sb.AppendLine("## 🟡 Other Gaps")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("| Control | Severity | Finding |")
        $null = $sb.AppendLine("|---------|----------|---------|")
        foreach ($f in $otherGaps) {
            $null = $sb.AppendLine("| $(EscMd $f.ControlId) | $(EscMd $f.Severity) | $(EscMd $f.Title) |")
        }
        $null = $sb.AppendLine()
    }

    # All findings — sorted Gap → Partial → Satisfied first so the actionable
    # rows are at the top. NotApplicable rows are collapsed into a count and
    # listed in a folded appendix at the end (most readers don't need to scan
    # 60+ rows of "not licensed for this control").
    $null = $sb.AppendLine("## All Findings")
    $null = $sb.AppendLine()

    $stateIcon = @{
        'Satisfied'     = '✅'
        'Partial'       = '⚠️'
        'Gap'           = '❌'
        'NotApplicable' = '—'
        'Error'         = '💥'
    }
    $stateOrder = @{ 'Gap' = 0; 'Partial' = 1; 'Satisfied' = 2; 'Error' = 3; 'NotApplicable' = 4 }
    $sevOrder   = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Informational' = 4 }

    $actionable = @($Findings | Where-Object { $_.State -ne 'NotApplicable' })
    $naFindings = @($Findings | Where-Object { $_.State -eq 'NotApplicable' })

    $null = $sb.AppendLine("| Control | Category | State | Severity | Title |")
    $null = $sb.AppendLine("|---------|----------|-------|----------|-------|")
    # `?? 99` coerces unknown State / Severity values to a sortable tail position
    # so a malformed finding (null or unexpected enum value) sorts last instead
    # of mixing $null into the comparison and producing unpredictable order.
    $sorted = $actionable | Sort-Object `
        @{Expression={($stateOrder[[string]$_.State])    ?? 99}}, `
        @{Expression={($sevOrder[[string]$_.Severity])   ?? 99}}, `
        Category, ControlId
    foreach ($f in $sorted) {
        $icon = $stateIcon[$f.State] ?? $f.State
        $null = $sb.AppendLine("| $(EscMd $f.ControlId) | $(EscMd $f.Category) | $icon $(EscMd $f.State) | $(EscMd $f.Severity) | $(EscMd $f.Title) |")
    }
    $null = $sb.AppendLine()

    if ($naFindings.Count -gt 0) {
        $null = $sb.AppendLine("### Not Applicable ($($naFindings.Count) controls)")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("These controls were not scored. Some do not apply to this tenant; others could not be assessed (the license is not present, the data could not be read, the check is manual, or the workload was skipped). Each finding says which. Not scored is not the same as compliant. Expand for full list.")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("<details><summary>Show $($naFindings.Count) Not Applicable controls</summary>")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("| Control | Category | Title |")
        $null = $sb.AppendLine("|---------|----------|-------|")
        foreach ($f in ($naFindings | Sort-Object Category, ControlId)) {
            $null = $sb.AppendLine("| $(EscMd $f.ControlId) | $(EscMd $f.Category) | $(EscMd $f.Title) |")
        }
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("</details>")
        $null = $sb.AppendLine()
    }

    $null = $sb.AppendLine()
    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine("*Generated by NRG-Assessment v$version | $company | $assmtDate*")

    # Write output — LiteralPath prevents wildcard expansion, utf8 explicit
    # Publisher self-hardens via Set-NRGSensitiveFileContent: the file is
    # pre-created and its ACL applied BEFORE tenant data lands. Writing with a
    # bare Out-File lets the file inherit the parent directory ACL for the
    # duration of the write, which on a shared MSP workstation or a synced
    # OneDrive folder is a window in which a co-resident process can read CA
    # policies, admin UPNs, OAuth grants and DMARC records. Hardening travels
    # with the terminal write so no caller can forget it. The Out-File fallback
    # preserves behavior if Lib/ has not been dot-sourced.
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $OutputPath -Content $sb.ToString()
    } else {
        $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8 -NoNewline:$false
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $OutputPath -ErrorAction SilentlyContinue
        }
    }
}

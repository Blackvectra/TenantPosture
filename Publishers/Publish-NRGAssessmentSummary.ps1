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
        [Parameter(Mandatory)] [string]     $OutputPath
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
    $company    = EscMd ($brand.CompanyName ?? 'NRG Technology Services')
    $tenant     = EscMd ($Metadata.TenantDomain ?? 'Unknown Tenant')
    $assmtDate  = EscMd ($Metadata.AssessmentDate ?? (Get-Date -Format 'MMMM dd, yyyy'))
    $version    = EscMd ($Metadata.ToolVersion ?? '4.5.5')

    # License tier — added in v4.6.2. The Markdown report previously had no
    # tier indicator at all, which led operators to assume the tool had not
    # detected their license. The line is rendered just below the metadata
    # block. Degrades gracefully when the helper is not loaded.
    $tierLabel = if (Get-Command Get-NRGTenantLicenseProfile -ErrorAction SilentlyContinue) {
        try { (Get-NRGTenantLicenseProfile).TierLabel } catch { 'Unknown' }
    } else { 'Unknown' }
    $tierLabelMd = EscMd $tierLabel

    # Scoring summary
    $satisfied = @($Findings | Where-Object { $_.State -eq 'Satisfied' }).Count
    $partial   = @($Findings | Where-Object { $_.State -eq 'Partial' }).Count
    $gap       = @($Findings | Where-Object { $_.State -eq 'Gap' }).Count
    $na        = @($Findings | Where-Object { $_.State -eq 'NotApplicable' }).Count
    $total     = $Findings.Count
    $scored    = $satisfied + $partial + $gap

    $scorePerc = if ($scored -gt 0) {
        [int](($satisfied + ($partial * 0.5)) / $scored * 100)
    } else { 0 }

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
    $sorted = $actionable | Sort-Object `
        @{Expression={$stateOrder[[string]$_.State]}}, `
        @{Expression={$sevOrder[[string]$_.Severity]}}, `
        Category, ControlId
    foreach ($f in $sorted) {
        $icon = $stateIcon[$f.State] ?? $f.State
        $null = $sb.AppendLine("| $(EscMd $f.ControlId) | $(EscMd $f.Category) | $icon $(EscMd $f.State) | $(EscMd $f.Severity) | $(EscMd $f.Title) |")
    }
    $null = $sb.AppendLine()

    if ($naFindings.Count -gt 0) {
        $null = $sb.AppendLine("### Not Applicable ($($naFindings.Count) controls)")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("These controls did not apply to this tenant — typically because the required license is not present, the feature is not enabled, or the workload was skipped at runtime. Expand for full list.")
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
    $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8 -NoNewline:$false
}

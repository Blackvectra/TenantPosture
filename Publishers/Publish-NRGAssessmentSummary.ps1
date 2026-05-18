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

    # Helper: escape for Markdown (prevents table/header injection)
    function EscMd([object]$v) {
        if ($null -eq $v -or [string]::IsNullOrEmpty([string]$v)) { return '' }
        $safe = ConvertTo-NRGHtmlSafe -Value ([string]$v)
        $safe = $safe -replace '\|', '\|' -replace '`', '\`'
        return $safe
    }

    $brand      = $script:NRGBrand
    $company    = EscMd ($brand.CompanyName ?? 'NRG Technology Services')
    $tenant     = EscMd ($Metadata.TenantDomain ?? 'Unknown Tenant')
    $assmtDate  = EscMd ($Metadata.AssessmentDate ?? (Get-Date -Format 'MMMM dd, yyyy'))
    $version    = EscMd ($Metadata.ToolVersion ?? '4.5.5')

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

    $posture = switch ($true) {
        { $scorePerc -ge 85 } { 'Strong' }
        { $scorePerc -ge 65 } { 'Moderate' }
        { $scorePerc -ge 40 } { 'At Risk' }
        default                { 'Critical' }
    }

    # Build findings tables by severity
    $criticalGaps = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'Critical' })
    $highGaps     = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'High' })
    $otherGaps    = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -notin @('Critical','High') })

    $sb = [System.Text.StringBuilder]::new()

    $null = $sb.AppendLine("# M365 Security Assessment Report")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Prepared by:** $company")
    $null = $sb.AppendLine("**Tenant:** $tenant")
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

    # All findings detail
    $null = $sb.AppendLine("## All Findings")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| Control | Category | State | Severity | Title |")
    $null = $sb.AppendLine("|---------|----------|-------|----------|-------|")

    $stateIcon = @{
        'Satisfied'     = '✅'
        'Partial'       = '⚠️'
        'Gap'           = '❌'
        'NotApplicable' = '—'
        'Error'         = '💥'
    }

    foreach ($f in ($Findings | Sort-Object Category, ControlId)) {
        $icon = $stateIcon[$f.State] ?? $f.State
        $null = $sb.AppendLine("| $(EscMd $f.ControlId) | $(EscMd $f.Category) | $icon $(EscMd $f.State) | $(EscMd $f.Severity) | $(EscMd $f.Title) |")
    }

    $null = $sb.AppendLine()
    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine("*Generated by NRG-Assessment v$version | $company | $assmtDate*")

    # Write output — LiteralPath prevents wildcard expansion, utf8 explicit
    $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8 -NoNewline:$false
}

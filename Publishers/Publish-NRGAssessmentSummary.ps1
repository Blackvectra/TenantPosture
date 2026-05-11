#
# Publish-NRGAssessmentSummary.ps1
# Generates a Markdown summary report from findings.
#
# This is the v4 baseline publisher - clean output, NRG-branded, suitable as a
# starting point for clients. Full HTML/Word publishers come in later sessions.
#

function Publish-NRGAssessmentSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]  $Metadata,
        [Parameter(Mandatory)] [object[]]   $Findings,
        [Parameter(Mandatory)] $Connections,
        [Parameter(Mandatory)] [string]     $OutputPath
    )

    $brand = $Metadata.Brand
    $sb = [System.Text.StringBuilder]::new()

    # Header
    [void]$sb.AppendLine("# Microsoft 365 Security Assessment")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("**Prepared for:** $($Metadata.TenantDomain)")
    [void]$sb.AppendLine("**Report Date:** $($Metadata.AssessmentDate)")
    [void]$sb.AppendLine("**Prepared by:** $($brand.CompanyName)")
    [void]$sb.AppendLine("**Tool Version:** NRG-Assessment v$($Metadata.ToolVersion)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("")

    # Summary counts
    $satisfied = @($Findings | Where-Object State -eq 'Satisfied').Count
    $partial   = @($Findings | Where-Object State -eq 'Partial').Count
    $gap       = @($Findings | Where-Object State -eq 'Gap').Count
    $na        = @($Findings | Where-Object State -eq 'NotApplicable').Count
    $total     = $Findings.Count

    $scoreNum  = if ($total - $na -gt 0) { [Math]::Round(100 * ($satisfied + 0.5 * $partial) / ($total - $na)) } else { 0 }

    $posture = if ($scoreNum -ge 85) { '🟢 Strong'
               } elseif ($scoreNum -ge 65) { '🟡 Moderate'
               } elseif ($scoreNum -ge 40) { '🟠 Weak'
               } else { '🔴 Critical' }

    [void]$sb.AppendLine("## 1. Executive Summary")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("### Overall Posture: $posture")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Metric | Value |")
    [void]$sb.AppendLine("|---|---|")
    [void]$sb.AppendLine("| NRG Composite Score | **$scoreNum / 100** |")
    [void]$sb.AppendLine("| Controls Satisfied | $satisfied |")
    [void]$sb.AppendLine("| Partial | $partial |")
    [void]$sb.AppendLine("| Gaps | $gap |")
    [void]$sb.AppendLine("| Not Applicable | $na |")
    [void]$sb.AppendLine("| Total | $total |")
    [void]$sb.AppendLine("")

    # Top actions
    $topGaps = @($Findings | Where-Object {
        $_.State -eq 'Gap' -and $_.Severity -in @('Critical','High')
    } | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical' { 0 }; 'High' { 1 }; default { 2 } }
    }} | Select-Object -First 5)

    if ($topGaps.Count -gt 0) {
        [void]$sb.AppendLine("### Top 5 Priority Actions")
        [void]$sb.AppendLine("")
        $i = 1
        foreach ($g in $topGaps) {
            $sevEmoji = if ($g.Severity -eq 'Critical') { '🔴' } else { '🟠' }
            [void]$sb.AppendLine("$i. $sevEmoji **$($g.Severity)** — $($g.Title)")
            $i++
        }
        [void]$sb.AppendLine("")
    }

    # Connection status
    [void]$sb.AppendLine("### Service Connections")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Service | Connected |")
    [void]$sb.AppendLine("|---|---|")
    foreach ($svc in @('Graph','EXO','IPPSSession','Teams','SharePoint')) {
        $status = if ($Connections.$svc) { '✓' } else { '✗' }
        [void]$sb.AppendLine("| $svc | $status |")
    }
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("")

    # Findings detail
    [void]$sb.AppendLine("## 2. Findings")
    [void]$sb.AppendLine("")

    $byCategory = $Findings | Group-Object Category | Sort-Object Name
    foreach ($cat in $byCategory) {
        [void]$sb.AppendLine("### $($cat.Name)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| State | Severity | Control | Detail |")
        [void]$sb.AppendLine("|---|---|---|---|")
        foreach ($f in ($cat.Group | Sort-Object @{Expression={
            switch ($_.State) { 'Gap' { 0 }; 'Partial' { 1 }; 'Satisfied' { 2 }; 'NotApplicable' { 3 } }
        }}, @{Expression='Title'})) {
            $stateEmoji = switch ($f.State) {
                'Satisfied'     { '🟢 Pass' }
                'Partial'       { '🟡 Partial' }
                'Gap'           { '🔴 Gap' }
                'NotApplicable' { '⬜ N/A' }
            }
            $detail = ($f.Detail -replace '\|','\\|' -replace '[\r\n]+',' ')
            [void]$sb.AppendLine("| $stateEmoji | $($f.Severity) | $($f.Title) | $detail |")
        }
        [void]$sb.AppendLine("")
    }

    # Footer
    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("*Prepared by $($brand.CompanyName) | $($brand.Phone) | $($brand.Website)*")
    [void]$sb.AppendLine("*Read-only assessment — no configuration changes were made*")

    $sb.ToString() | Out-File -FilePath $OutputPath -Encoding utf8
}

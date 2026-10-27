#Requires -Version 7.0
#
# Publish-TPFleetDashboard.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Render the fleet model (Get-TPFleetModel) as a self-contained HTML
#   dashboard, a Markdown summary and a CSV with one row per client. INTERNAL:
#   the default output names clients; an anonymized model labels them Client A,
#   B, ... everywhere. Uses the shared report theme (Lib/Get-TPReportTheme.ps1).
#
#   Touches nothing: no Graph, no Exchange Online, no network. It renders the
#   model it is handed and writes three files through Set-TPSensitiveFileContent.
#
# Rendering rules (pinned by TP.FleetDashboard.Tests.ps1):
#   - Every string is escaped for its format (HTML, Markdown through
#     ConvertTo-TPMarkdownSafe, CSV with a leading apostrophe on a cell a
#     spreadsheet would read as a formula).
#   - The page loads nothing and carries a policy that forbids it.
#   - A partial or quick re-check is shown beside the full-run score, never in
#     its place; "not recorded" is said where a run recorded nothing.
#   - Nothing says "compliant".
#
# Inputs:  -Model (Get-TPFleetModel), -OutputPath (folder, created if absent),
#          -GeneratedAt (tests). Returns the three paths.
# Data consumed: the model only. Graph scopes / cmdlets used: none.

function Publish-TPFleetDashboard {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [object] $Model,
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath,
        [AllowNull()] [object] $Brand,
        [string] $ToolVersion = '',
        [datetime] $GeneratedAt = [datetime]::UtcNow
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not (Get-Command ConvertTo-TPHtmlSafe -ErrorAction SilentlyContinue)) {
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the fleet dashboard without HTML escaping.'
    }
    if ((Get-TPObjectField -Item $Model -Key 'Available' -Default $false) -ne $true) {
        throw "Fleet dashboard not generated: $([string](Get-TPObjectField -Item $Model -Key 'Note' -Default 'no runs'))"
    }

    function EscMd { param([object] $v) ConvertTo-TPMarkdownSafe $v }   # one Markdown rule for the whole tool
    function Esc { param([object] $v) ConvertTo-TPHtmlSafe $v }
    function CsvSafe {
        param([object] $v)
        $t = [string]$v
        if ($t -match '^[=+\-@\t\r]') { return "'" + $t }
        return $t
    }

    if (-not $PSBoundParameters.ContainsKey('Brand')) {
        $Brand = if ((Get-Variable -Name TPBrand -Scope Script -ErrorAction SilentlyContinue)) { $script:TPBrand } else { $null }
    }
    if (-not $ToolVersion -and (Get-Variable -Name TPAssessmentVersion -Scope Script -ErrorAction SilentlyContinue)) { $ToolVersion = [string]$script:TPAssessmentVersion }
    $theme = Get-TPReportTheme -Brand $Brand
    $anon = [bool](Get-TPObjectField -Item $Model -Key 'Anonymized' -Default $false)
    $kpi = $Model.Kpis
    $fresh = $Model.Freshness
    $clientRows = @($Model.Clients)
    $neverRows = @($Model.NeverAssessed)

    if (Test-Path -LiteralPath $OutputPath -PathType Leaf) { throw "OutputPath is a file, not a folder: $OutputPath" }
    $null = [System.IO.Directory]::CreateDirectory($OutputPath)
    $stamp = $GeneratedAt.ToUniversalTime().ToString('yyyyMMdd-HHmmss', [cultureinfo]::InvariantCulture)
    $baseName = 'fleet-dashboard-' + $stamp + $(if ($anon) { '-anonymized' } else { '' })
    $htmlPath = Join-Path $OutputPath "$baseName.html"
    $mdPath   = Join-Path $OutputPath "$baseName.md"
    $csvPath  = Join-Path $OutputPath "$baseName.csv"

    # ── Shared wording ──
    $statusText = @{ Current = 'Current'; Aging = 'Aging'; Overdue = 'Overdue'; NoFullRun = 'No full run'; NeverAssessed = 'Never assessed' }
    $statusTone = @{ Current = 'Good'; Aging = 'Warn'; Overdue = 'Bad'; NoFullRun = 'Neutral'; NeverAssessed = 'Neutral' }
    $audience = if ($anon) { 'Anonymized: clients are labeled Client A, Client B and so on.' } else { 'Internal working document: it names clients. Re-run with -Anonymize for a version to share or screenshot.' }
    $howToRead = @(
        'Each client''s score and maturity label are the values its latest FULL run recorded. A partial (-ControlId) or quick (-Quick) re-check is shown beside them and never replaces them.',
        'Open Critical and High count controls whose worst finding was a Gap or Partial in that full run. A control that was not assessed is neither open nor passed.',
        'Change since the previous full run comes from the NRG Security Baseline view of the two runs (Get-TPBaselineRegressions). "Evidence lost" means a control was satisfied before and could not be verified this time; the configuration may be unchanged.',
        [string]$fresh.Basis,
        'Nothing here is a statement that a client meets a framework. The dashboard reads saved results files only and connects to nothing.'
    )
    $scoreText = {
        param($lf)
        if ($null -eq $lf) { return 'No full run' }
        if (-not $lf.MaturityRecorded -or $null -eq $lf.Score) { return 'Not recorded' }
        return "$($lf.Score)"
    }
    $changeText = {
        param($ch)
        if ($null -eq $ch) { return 'No earlier full run' }
        if (-not $ch.Available) { return 'Not compared: ' + $ch.Note }
        $parts = @()
        $parts += "$(@($ch.Regressed).Count) regressed$(if (@($ch.Regressed).Count) { ' (' + (@($ch.Regressed) -join ', ') + ')' })"
        $parts += "$(@($ch.Resolved).Count) resolved$(if (@($ch.Resolved).Count) { ' (' + (@($ch.Resolved) -join ', ') + ')' })"
        if (@($ch.EvidenceLost).Count) { $parts += "$(@($ch.EvidenceLost).Count) evidence lost (" + (@($ch.EvidenceLost) -join ', ') + ')' }
        $txt = ($parts -join '; ') + " since $($ch.PreviousRunDate)"
        if (-not $ch.Comparable) { $txt += '. The baseline version or tier changed; only controls required in both runs at the same tier were compared.' }
        return $txt
    }
    $recheckText = {
        param($rc)
        if ($null -eq $rc) { return '' }
        $what = if ($rc.Kind -eq 'Partial') { "Partial re-check $($rc.RunDate): $($rc.Selected) of $($rc.TotalControls) controls$(if (@($rc.Patterns).Count) { ' (' + (@($rc.Patterns) -join ', ') + ')' })" } else { "Quick scan $($rc.RunDate): $($rc.Selected) controls" }
        return "$what. $($rc.Satisfied) satisfied, $($rc.Open) open, $($rc.NoVerdict) without a verdict. Not scored; the full-run score stands."
    }
    $evidenceText = {
        param($lf)
        if ($null -eq $lf -or -not $lf.BaselineRecorded) { return 'Not recorded' }
        if ($null -eq $lf.EvidencePercent) { return 'Not recorded' }
        return "$($lf.EvidenceKnown) of $($lf.EvidenceApplicable) ($($lf.EvidencePercent)%)"
    }

    # ── HTML ──
    $sb = [System.Text.StringBuilder]::new()
    $chips = @("$($kpi.Clients) clients", "Generated $($GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)) UTC", $(if ($anon) { 'Anonymized' } else { 'Internal' }))
    $null = $sb.Append((New-TPThemeMasthead -CompanyName $theme.CompanyName -Title 'Fleet posture' -Subtitle 'Every client''s latest full assessment, what changed since the one before, and who is due. Built from saved results files.' -Chips $chips))
    $null = $sb.Append('<div class="tp-banner tp-banner--info">' + (Esc $audience) + '</div>')

    $kpiHtml = [System.Text.StringBuilder]::new('<div class="tp-kpis">')
    $null = $kpiHtml.Append((New-TPThemeKpi -Label 'Clients' -Value $kpi.Clients -Note "$($kpi.WithRuns) with runs, $($kpi.NeverAssessed) never assessed"))
    $null = $kpiHtml.Append((New-TPThemeKpi -Label 'Assessed in window' -Value $kpi.InWindow -Note "Full run within $($fresh.OverdueDays) days (Monthly class)" -PillHtml $(if ($kpi.InWindow -gt 0) { New-TPThemePill -Status Good -Text "$($kpi.Current) current" } else { '' })))
    $null = $kpiHtml.Append((New-TPThemeKpi -Label 'Overdue' -Value $kpi.Overdue -Note "No full run within $($fresh.OverdueDays) days" -PillHtml $(if ($kpi.Overdue -gt 0) { New-TPThemePill -Status Bad -Text 'Needs a run' } else { New-TPThemePill -Status Good -Text 'None' })))
    $null = $kpiHtml.Append((New-TPThemeKpi -Label 'Open Critical' -Value $kpi.OpenCritical -Note 'Across latest full runs' -PillHtml $(if ($kpi.OpenCritical -gt 0) { New-TPThemePill -Status Bad -Text 'Open' } else { New-TPThemePill -Status Good -Text 'None open' })))
    $null = $kpiHtml.Append((New-TPThemeKpi -Label 'Open High' -Value $kpi.OpenHigh -Note 'Across latest full runs' -PillHtml $(if ($kpi.OpenHigh -gt 0) { New-TPThemePill -Status Warn -Text 'Open' } else { New-TPThemePill -Status Good -Text 'None open' })))
    $null = $kpiHtml.Append('</div>')
    $null = $sb.Append($kpiHtml.ToString())
    foreach ($n in @($Model.Notes)) { $null = $sb.Append('<p class="tp-note">' + (Esc $n) + '</p>') }

    # Client cards
    $cards = [System.Text.StringBuilder]::new('<div class="tp-grid">')
    foreach ($c in $clientRows) {
        $lf = $c.LatestFull
        $tone = $statusTone[[string]$c.Status]
        $null = $cards.Append('<article class="tp-card"><div class="tp-card-head"><div><div class="tp-card-title">' + (Esc $c.Name) + '</div>')
        if (-not $anon -and $c.Domain -and $c.Domain -ne $c.Name) { $null = $cards.Append('<div class="tp-small tp-muted">' + (Esc $c.Domain) + '</div>') }
        $null = $cards.Append('</div>' + (New-TPThemePill -Status $tone -Text $statusText[[string]$c.Status]) + '</div>')
        if ($lf) {
            $trendVals = @($c.Trend | ForEach-Object { [double]$_.Score })
            $trendLabel = if ($trendVals.Count) { 'Score over full runs: ' + ((@($c.Trend | ForEach-Object { "$($_.Date) $($_.Score)" })) -join ', ') } else { 'No recorded scores' }
            $null = $cards.Append('<div class="tp-row"><div><span class="tp-big">' + (Esc (& $scoreText $lf)) + '</span>' + $(if ($null -ne $lf.Score) { '<span class="tp-muted"> / 100</span>' } else { '' }) + '<div class="tp-small tp-muted">' + (Esc $(if ($lf.MaturityLabel) { $lf.MaturityLabel } else { 'Maturity not recorded' })) + '</div></div>' + (New-TPThemeSparkline -Values $trendVals -Label $trendLabel) + '</div>')
            $null = $cards.Append('<div class="tp-row" style="margin-top:10px">' +
                (New-TPThemePill -Status $(if ($lf.OpenCritical -gt 0) { 'Bad' } else { 'Good' }) -Text "$($lf.OpenCritical) Critical open") +
                (New-TPThemePill -Status $(if ($lf.OpenHigh -gt 0) { 'Warn' } else { 'Good' }) -Text "$($lf.OpenHigh) High open") +
                $(if ($lf.NoVerdict -gt 0) { New-TPThemePill -Status Neutral -Text "$($lf.NoVerdict) without a verdict" } else { '' }) + '</div>')
            $null = $cards.Append('<dl class="tp-kv">')
            $null = $cards.Append('<dt>Last full run</dt><dd>' + (Esc "$($lf.RunDate) ($($lf.AgeDays) days old)") + '</dd>')
            $null = $cards.Append('<dt>Baseline</dt><dd>' + (Esc $(if ($lf.BaselineRecorded) { "$($lf.TargetTier), v$($lf.BaselineVersion)" } else { 'Not recorded' })) + '</dd>')
            $null = $cards.Append('<dt>Evidence coverage</dt><dd>' + (Esc (& $evidenceText $lf)))
            if ($null -ne $lf.EvidencePercent) { $null = $cards.Append((New-TPThemeBar -Value ([double]$lf.EvidencePercent) -Max 100 -Label "Evidence coverage $($lf.EvidencePercent) percent")) }
            $null = $cards.Append('</dd>')
            if ($lf.RequiredRows -gt 0) { $null = $cards.Append('<dt>Past freshness</dt><dd>' + (Esc "$($lf.PastWindow) of $($lf.RequiredRows) required controls") + '</dd>') }
            $null = $cards.Append('<dt>Since previous</dt><dd>' + (Esc (& $changeText $c.Change)) + '</dd>')
            $null = $cards.Append('<dt>Tool version</dt><dd>' + (Esc $(if ($lf.ToolVersion) { $lf.ToolVersion } else { 'Not recorded' })) + '</dd>')
            $null = $cards.Append('</dl>')
        }
        if ($c.Recheck) { $null = $cards.Append('<p class="tp-small">' + (New-TPThemePill -Status Info -Text $(if ($c.Recheck.Kind -eq 'Partial') { 'Partial re-check' } else { 'Quick scan' })) + ' ' + (Esc (& $recheckText $c.Recheck)) + '</p>') }
        if (@($c.Notes).Count) {
            $null = $cards.Append('<ul class="tp-list tp-small tp-muted">')
            foreach ($n in @($c.Notes)) { $null = $cards.Append('<li>' + (Esc $n) + '</li>') }
            $null = $cards.Append('</ul>')
        }
        $null = $cards.Append('</article>')
    }
    $null = $cards.Append('</div>')
    $null = $sb.Append((New-TPThemeSection -Id 'clients' -Title 'Clients' -Kicker 'Overdue and no-full-run first, then by open Critical and High' -BodyHtml $cards.ToString() -First))

    # Most common open gaps
    $top = @($Model.TopGaps)
    $gapHtml = if ($top.Count -eq 0) { '<p class="tp-note">No control is open in any latest full run.</p>' } else {
        $maxC = [math]::Max(1, [int]$kpi.WithRuns)
        $tb = [System.Text.StringBuilder]::new('<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Control</th><th>Title</th><th>Severity</th><th class="tp-num">Clients</th><th>Share of clients with runs</th></tr></thead><tbody>')
        foreach ($g in $top) {
            $null = $tb.Append('<tr><td class="tp-mono">' + (Esc $g.ControlId) + '</td><td>' + (Esc $g.Title) + '</td><td>' + (Esc $g.Severity) + '</td><td class="tp-num">' + (Esc $g.Clients) + '</td><td>' + (New-TPThemeBar -Value ([double]$g.Clients) -Max $maxC -Label "$($g.Clients) of $maxC clients") + '</td></tr>')
        }
        $null = $tb.Append('</tbody></table></div>')
        $tb.ToString()
    }
    $null = $sb.Append((New-TPThemeSection -Id 'top-gaps' -Title 'Most common open gaps' -Kicker 'Top 10 controls by number of clients with the control open' -BodyHtml $gapHtml))

    if ($neverRows.Count -gt 0) {
        $nv = [System.Text.StringBuilder]::new('<ul class="tp-list">')
        foreach ($n in $neverRows) { $null = $nv.Append('<li>' + (Esc $n.Name) + $(if (-not $anon -and $n.Domain -and $n.Domain -ne $n.Name) { ' <span class="tp-muted">' + (Esc $n.Domain) + '</span>' } else { '' }) + ' ' + (New-TPThemePill -Status Neutral -Text 'Never assessed') + '</li>') }
        $null = $nv.Append('</ul>')
        $null = $sb.Append((New-TPThemeSection -Id 'never-assessed' -Title 'Never assessed' -Kicker 'Active in the clients file, no results file found' -BodyHtml $nv.ToString()))
    }

    $how = '<ul class="tp-list tp-note">' + ((@($howToRead | ForEach-Object { '<li>' + (Esc $_) + '</li>' })) -join '') + '</ul>'
    $null = $sb.Append((New-TPThemeSection -Id 'how-to-read' -Title 'How to read this dashboard' -BodyHtml $how))
    $null = $sb.Append((New-TPThemeFooter -GeneratedAt $GeneratedAt -ToolVersion $ToolVersion -CompanyName $theme.CompanyName -Note $(if ($anon) { 'Anonymized' } else { 'Internal: names clients' })))
    $html = New-TPThemeDocument -Title 'Fleet posture' -Theme $theme -BodyHtml $sb.ToString()

    # ── Markdown ──
    $md = [System.Text.StringBuilder]::new()
    $null = $md.AppendLine("# $(EscMd $theme.CompanyName): fleet posture")
    $null = $md.AppendLine()
    $null = $md.AppendLine("> **$(EscMd $audience)**")
    $null = $md.AppendLine()
    $null = $md.AppendLine("Generated $($GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)) UTC from $($Model.RunsRead) saved run(s).")
    $null = $md.AppendLine()
    $null = $md.AppendLine('| Clients | Assessed in window | Current | Aging | Overdue | No full run | Never assessed | Open Critical | Open High |')
    $null = $md.AppendLine('|---|---|---|---|---|---|---|---|---|')
    $null = $md.AppendLine("| $($kpi.Clients) | $($kpi.InWindow) | $($kpi.Current) | $($kpi.Aging) | $($kpi.Overdue) | $($kpi.NoFullRun) | $($kpi.NeverAssessed) | $($kpi.OpenCritical) | $($kpi.OpenHigh) |")
    $null = $md.AppendLine()
    foreach ($n in @($Model.Notes)) { $null = $md.AppendLine("- $(EscMd $n)") }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Clients')
    $null = $md.AppendLine()
    $null = $md.AppendLine('| Client | Status | Last full run | Score | Maturity (recorded) | Critical open | High open | Baseline | Evidence coverage | Since previous full run | Re-check |')
    $null = $md.AppendLine('|---|---|---|---|---|---|---|---|---|---|---|')
    foreach ($c in $clientRows) {
        $lf = $c.LatestFull
        $last = if ($lf) { "$($lf.RunDate) ($($lf.AgeDays) days)" } else { 'None' }
        $mat = if ($lf -and $lf.MaturityLabel) { $lf.MaturityLabel } elseif ($lf) { 'Not recorded' } else { '' }
        $base = if ($lf -and $lf.BaselineRecorded) { "$($lf.TargetTier) v$($lf.BaselineVersion)" } elseif ($lf) { 'Not recorded' } else { '' }
        $null = $md.AppendLine("| $(EscMd $c.Name) | $(EscMd $statusText[[string]$c.Status]) | $(EscMd $last) | $(EscMd (& $scoreText $lf)) | $(EscMd $mat) | $(if ($lf) { $lf.OpenCritical }) | $(if ($lf) { $lf.OpenHigh }) | $(EscMd $base) | $(EscMd (& $evidenceText $lf)) | $(EscMd $(if ($lf) { & $changeText $c.Change } else { '' })) | $(EscMd (& $recheckText $c.Recheck)) |")
    }
    $null = $md.AppendLine()
    foreach ($c in $clientRows) {
        if (@($c.Notes).Count -eq 0) { continue }
        $null = $md.AppendLine("- **$(EscMd $c.Name)**: $(EscMd ((@($c.Notes)) -join ' '))")
    }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Most common open gaps')
    $null = $md.AppendLine()
    if ($top.Count -eq 0) { $null = $md.AppendLine('No control is open in any latest full run.') }
    else {
        $null = $md.AppendLine('| Control | Title | Severity | Clients |')
        $null = $md.AppendLine('|---|---|---|---|')
        foreach ($g in $top) { $null = $md.AppendLine("| ``$($g.ControlId)`` | $(EscMd $g.Title) | $(EscMd $g.Severity) | $($g.Clients) |") }
    }
    if ($neverRows.Count -gt 0) {
        $null = $md.AppendLine()
        $null = $md.AppendLine('## Never assessed')
        $null = $md.AppendLine()
        foreach ($n in $neverRows) { $null = $md.AppendLine("- $(EscMd $n.Name)") }
    }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## How to read this dashboard')
    $null = $md.AppendLine()
    foreach ($h in $howToRead) { $null = $md.AppendLine("- $(EscMd $h)") }
    $null = $md.AppendLine()
    $null = $md.AppendLine("_TenantPosture $(EscMd $ToolVersion)_")

    # ── CSV ──
    $csvRows = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $clientRows) {
        $lf = $c.LatestFull
        $csvRows.Add([pscustomobject][ordered]@{
            Client             = CsvSafe $c.Name
            Status             = $statusText[[string]$c.Status]
            LastFullRun        = $(if ($lf) { $lf.RunDate } else { '' })
            AgeDays            = $(if ($lf) { $lf.AgeDays } else { '' })
            Score              = CsvSafe (& $scoreText $lf)
            MaturityRecorded   = CsvSafe $(if ($lf) { $lf.MaturityLabel } else { '' })
            OpenCritical       = $(if ($lf) { $lf.OpenCritical } else { '' })
            OpenHigh           = $(if ($lf) { $lf.OpenHigh } else { '' })
            BaselineTier       = CsvSafe $(if ($lf) { $lf.TargetTier } else { '' })
            BaselineVersion    = CsvSafe $(if ($lf) { $lf.BaselineVersion } else { '' })
            EvidenceCoverage   = CsvSafe (& $evidenceText $lf)
            Regressed          = CsvSafe $(if ($c.Change) { @($c.Change.Regressed) -join ' ' } else { '' })
            Resolved           = CsvSafe $(if ($c.Change) { @($c.Change.Resolved) -join ' ' } else { '' })
            EvidenceLost       = CsvSafe $(if ($c.Change) { @($c.Change.EvidenceLost) -join ' ' } else { '' })
            Recheck            = CsvSafe (& $recheckText $c.Recheck)
            ToolVersion        = CsvSafe $(if ($lf) { $lf.ToolVersion } else { '' })
            Notes              = CsvSafe ((@($c.Notes)) -join ' ')
        })
    }
    foreach ($n in $neverRows) {
        $csvRows.Add([pscustomobject][ordered]@{
            Client = CsvSafe $n.Name; Status = 'Never assessed'; LastFullRun = ''; AgeDays = ''; Score = ''; MaturityRecorded = ''; OpenCritical = ''; OpenHigh = ''
            BaselineTier = ''; BaselineVersion = ''; EvidenceCoverage = ''; Regressed = ''; Resolved = ''; EvidenceLost = ''; Recheck = ''; ToolVersion = ''; Notes = ''
        })
    }
    $csvText = ($csvRows | ConvertTo-Csv -NoTypeInformation -UseQuotes Always) -join "`r`n"

    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    Set-TPSensitiveFileContent -Path $mdPath -Content $md.ToString()
    Set-TPSensitiveFileContent -Path $csvPath -Content $csvText
    return [ordered]@{ Html = $htmlPath; Markdown = $mdPath; Csv = $csvPath }
}

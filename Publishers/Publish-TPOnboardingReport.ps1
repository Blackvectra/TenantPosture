#Requires -Version 7.0
#
# Publish-TPOnboardingReport.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Render the onboarding model (Get-TPOnboardingModel) as a
#   client-facing first-look report: an executive one-pager, what is working,
#   what needs attention, a 30/60/90-day plan, the license decisions, and
#   (when Config/microsoft-changes.json exists) the coming Microsoft changes.
#   Self-contained HTML in the shared report theme, plus Markdown, written as
#   <base>-onboarding.html / .md.
#
# Rendering rules (pinned by TP.OnboardingReport.Tests.ps1):
#   - No hour, day or week effort figure: effort is the archetype's class and
#     a window says when work starts. The only day numbers are the window
#     labels.
#   - No pricing: the report makes no cost promise.
#   - Nothing says "compliant"; controls not assessed are neither open nor
#     passed, and the report says so.
#   - The coming-changes section is absent when the catalog file is absent;
#     a date is shown exactly as the file gives it.
#   - Every string is escaped for its format; the page loads nothing.
#
# Inputs:  -Model, -OutputPath (file path of the .html; the .md sits beside
#          it), -Brand (defaults to the loaded profile), -GeneratedAt (tests).
# Data consumed: the model only. Graph scopes / cmdlets used: none.

function Publish-TPOnboardingReport {
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
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the onboarding report without HTML escaping.'
    }
    if ((Get-TPObjectField -Item $Model -Key 'Available' -Default $false) -ne $true) {
        throw "Onboarding report not generated: $([string](Get-TPObjectField -Item $Model -Key 'Note' -Default 'not available'))"
    }

    function EscMd { param([object] $v) ConvertTo-TPMarkdownSafe $v }   # one Markdown rule for the whole tool
    function Esc { param([object] $v) ConvertTo-TPHtmlSafe $v }

    if (-not $PSBoundParameters.ContainsKey('Brand')) {
        $Brand = if ((Get-Variable -Name TPBrand -Scope Script -ErrorAction SilentlyContinue)) { $script:TPBrand } else { $null }
    }
    if (-not $ToolVersion) { $ToolVersion = [string]$Model.ToolVersion }
    $theme = Get-TPReportTheme -Brand $Brand

    $htmlPath = if ($OutputPath -match '\.html\z') { $OutputPath } else { "$OutputPath.html" }
    $mdPath = [System.IO.Path]::ChangeExtension($htmlPath, '.md')
    $dir = Split-Path -Parent $htmlPath
    if ($dir) { $null = [System.IO.Directory]::CreateDirectory($dir) }

    $tenantText = if ($Model.TenantDomain) { $Model.TenantDomain } else { 'your tenant' }
    $sevTone = @{ Critical = 'Bad'; High = 'Warn'; Medium = 'Info'; Low = 'Neutral'; Informational = 'Neutral' }
    $windows = [ordered]@{
        Days1to30  = @{ Label = 'Days 1-30';  Text = 'Critical and High items whose change is documented as invisible to users. Licensed, low friction, high value.' }
        Days31to60 = @{ Label = 'Days 31-60'; Text = 'The remaining Critical and High items, and changes that need a policy change or a staged rollout.' }
        Days61to90 = @{ Label = 'Days 61-90'; Text = 'Projects, changes that need discovery first, and Medium and Low items.' }
    }
    $scoreText = if ($Model.MaturityRecorded -and $null -ne $Model.Score) { [string]$Model.Score } else { 'Not recorded' }
    $open = $Model.OpenBySeverity
    $openTotal = [int]$open.Critical + [int]$open.High + [int]$open.Medium + [int]$open.Low
    $plan = $Model.Plan
    $changes = $Model.Changes

    $itemHtml = {
        param($it, [switch] $WithEffort)
        $html = '<li class="tp-card" style="list-style:none;margin:0 0 10px"><div class="tp-card-head"><div><span class="tp-mono">' + (Esc $it.ControlId) + '</span> <span class="tp-card-title">' + (Esc $it.Title) + '</span></div>' + (New-TPThemePill -Status $sevTone[[string]$it.Severity] -Text $it.Severity) + '</div>'
        if ($WithEffort) {
            $html += '<div class="tp-row tp-small"><span class="tp-chip">Effort: ' + (Esc $it.Effort) + '</span><span class="tp-chip">' + (Esc $it.State) + '</span></div>'
            $html += '<p class="tp-small">' + (Esc $it.ImpactSummary) + '</p>'
            if ($it.Contains('Note')) { $html += '<p class="tp-small tp-muted">' + (Esc $it.Note) + '</p>' }
        }
        if ($it.Remediation) { $html += '<details><summary>What to change</summary><p class="tp-small">' + (Esc $it.Remediation) + '</p></details>' }
        return $html + '</li>'
    }

    # ── HTML ──
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.Append((New-TPThemeMasthead -CompanyName $theme.CompanyName -Title 'Where you stand' -Subtitle "Onboarding report for ${tenantText}: your starting position and the first ninety days of work." -Chips @("Assessed $($Model.AssessedAt)", "License: $($Model.LicenseTier)")))

    $kpis = '<div class="tp-kpis">' +
        (New-TPThemeKpi -Label 'Score (recorded)' -Value $scoreText -Note $(if ($Model.MaturityLabel) { "Maturity: $($Model.MaturityLabel)" } else { 'Maturity not recorded' })) +
        (New-TPThemeKpi -Label 'Open items' -Value $openTotal -Note "$($open.Critical) Critical, $($open.High) High" -PillHtml $(if ([int]$open.Critical -gt 0) { New-TPThemePill -Status Bad -Text 'Critical open' } elseif ([int]$open.High -gt 0) { New-TPThemePill -Status Warn -Text 'High open' } else { '' })) +
        (New-TPThemeKpi -Label 'Working' -Value $Model.Counts.Satisfied -Note 'Controls satisfied') +
        (New-TPThemeKpi -Label 'Not assessed' -Value ([int]$Model.Counts.NotApplicable + [int]$Model.Counts.Error) -Note 'Neither open nor passed') +
        (New-TPThemeKpi -Label 'License decisions' -Value @($Model.LicenseDecision).Count -Note 'Need a license to fix') + '</div>'
    $summary = $kpis + '<div class="tp-banner tp-banner--info">' + (Esc $Model.Statement) + '</div>'
    if ($Model.Qualification) { $summary += '<p class="tp-note">' + (Esc $Model.Qualification) + '</p>' }
    $risks = @($Model.TopRisks)
    if ($risks.Count -gt 0) {
        $summary += '<h3 style="margin:18px 0 10px">Top risks</h3><div class="tp-grid">'
        foreach ($r in $risks) {
            $summary += '<div class="tp-card"><div class="tp-card-head"><div class="tp-card-title">' + (Esc $r.Title) + '</div>' + (New-TPThemePill -Status $sevTone[[string]$r.Severity] -Text $r.Severity) + '</div><p class="tp-small">' + (Esc $(if ($r.BusinessRisk) { $r.BusinessRisk } else { 'No business-risk statement is recorded for this control.' })) + '</p><div class="tp-small tp-muted tp-mono">' + (Esc $r.ControlId) + '</div></div>'
        }
        $summary += '</div>'
    } else {
        $summary += '<p class="tp-note">No Critical or High item is open in this run.</p>'
    }
    $null = $sb.Append((New-TPThemeSection -Id 'summary' -Title 'Executive summary' -Kicker "Assessed $($Model.AssessedAt)" -BodyHtml $summary -First))

    # What's working
    $work = @($Model.Working)
    $wHtml = if ($work.Count -eq 0) { '<p class="tp-note">No control was satisfied in this run.</p>' } else {
        $chipsHtml = '<div class="tp-row" style="margin-bottom:12px">' + ((@($Model.WorkingByWorkload.Keys | ForEach-Object { '<span class="tp-chip">' + (Esc "$_ $($Model.WorkingByWorkload[$_])") + '</span>' })) -join '') + '</div>'
        $listHtml = '<ul class="tp-list">' + ((@($work | Select-Object -First 15 | ForEach-Object { '<li>' + (New-TPThemePill -Status Good -Text 'Satisfied') + ' ' + (Esc $_.Title) + ' <span class="tp-muted tp-small tp-mono">' + (Esc $_.ControlId) + '</span></li>' })) -join '') + '</ul>'
        $more = if ($work.Count -gt 15) { '<p class="tp-note">' + (Esc "And $($work.Count - 15) more satisfied control(s); the assessment report lists them all.") + '</p>' } else { '' }
        $chipsHtml + $listHtml + $more
    }
    $null = $sb.Append((New-TPThemeSection -Id 'working' -Title 'What''s working' -Kicker "$($work.Count) control(s) satisfied" -BodyHtml $wHtml))

    # What needs attention
    $maxOpen = [math]::Max(1, $openTotal)
    $att = '<div class="tp-card"><dl class="tp-kv">'
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low') {
        $att += '<dt>' + (Esc $sev) + '</dt><dd>' + (Esc "$($open[$sev]) open") + (New-TPThemeBar -Value ([double]$open[$sev]) -Max $maxOpen -Label "$($open[$sev]) $sev items open" -Status $(switch ($sev) { 'Critical' { 'Bad' } 'High' { 'Warn' } default { '' } })) + '</dd>'
    }
    $att += '</dl><p class="tp-note">' + (Esc "Open means the control's worst finding is a Gap or Partial. $([int]$Model.Counts.NotApplicable + [int]$Model.Counts.Error) control(s) produced no verdict in this run and are not counted here.") + '</p></div>'
    $null = $sb.Append((New-TPThemeSection -Id 'attention' -Title 'What needs attention' -Kicker "$openTotal open item(s)" -BodyHtml $att))

    # 30/60/90 plan
    $planHtml = '<p class="tp-note">' + (Esc $Model.PlanNote) + '</p><div class="tp-grid">'
    foreach ($k in $windows.Keys) {
        $items = @($plan[$k])
        $planHtml += '<div><h3 style="margin:6px 0 4px">' + (Esc $windows[$k].Label) + '</h3><p class="tp-small tp-muted">' + (Esc $windows[$k].Text) + '</p>'
        $planHtml += if ($items.Count -eq 0) { '<p class="tp-note">Nothing in this window.</p>' } else { '<ul class="tp-list" style="padding:0">' + ((@($items | ForEach-Object { & $itemHtml $_ -WithEffort })) -join '') + '</ul>' }
        $planHtml += '</div>'
    }
    $planHtml += '</div>'
    $review = @($plan.PlanAfterReview)
    if ($review.Count -gt 0) {
        $planHtml += '<h3 style="margin:18px 0 4px">Plan after review</h3><p class="tp-small tp-muted">' + (Esc 'Open items whose operational impact is not documented. They are scheduled once someone has checked what the change will affect.') + '</p><ul class="tp-list" style="padding:0">' + ((@($review | ForEach-Object { & $itemHtml $_ })) -join '') + '</ul>'
    }
    $null = $sb.Append((New-TPThemeSection -Id 'plan' -Title '30/60/90-day plan' -Kicker 'When each piece of work starts' -BodyHtml $planHtml))

    # License decisions
    $lic = @($Model.LicenseDecision)
    $licHtml = if ($lic.Count -eq 0) { '<p class="tp-note">No open item needs a license decision.</p>' } else {
        $t = '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Control</th><th>Severity</th><th>Would be unlocked by</th><th>Why it is here</th></tr></thead><tbody>'
        foreach ($it in $lic) { $t += '<tr><td><span class="tp-mono">' + (Esc $it.ControlId) + '</span><div>' + (Esc $it.Title) + '</div></td><td>' + (New-TPThemePill -Status $sevTone[[string]$it.Severity] -Text $it.Severity) + '</td><td>' + (Esc $(if ($it.License) { $it.License } else { 'Not stated' })) + '</td><td class="tp-small">' + (Esc $it.Reason) + '</td></tr>' }
        $t + '</tbody></table></div>'
    }
    $null = $sb.Append((New-TPThemeSection -Id 'licensing' -Title 'Needs a license decision' -Kicker "$($lic.Count) item(s); license tier: $($Model.LicenseTier)" -BodyHtml $licHtml))

    # Coming Microsoft changes (only when the catalog file exists)
    if ($null -ne $changes) {
        $chg = @($changes.Changes)
        $cHtml = '<p class="tp-note">' + (Esc "From the Microsoft changes catalog$(if ($changes.SourceRetrieved) { ", sources retrieved $($changes.SourceRetrieved)" }). Dates are shown as the catalog gives them; only entries dated today or later are listed.") + '</p>'
        if ($chg.Count -eq 0) { $cHtml += '<p class="tp-note">No change in the catalog is dated today or later.</p>' }
        foreach ($c in $chg) {
            $cHtml += '<div class="tp-card" style="margin-bottom:12px"><div class="tp-card-head"><div class="tp-card-title">' + (Esc $c.Title) + '</div><span class="tp-chip">' + (Esc ((@($c.DateQualifier, $c.Date) | Where-Object { $_ }) -join ' ')) + '</span></div>'
            if ($c.Summary) { $cHtml += '<p class="tp-small">' + (Esc $c.Summary) + '</p>' }
            if ($c.Impact) { $cHtml += '<p class="tp-small"><strong>Impact:</strong> ' + (Esc $c.Impact) + '</p>' }
            if (@($c.Related).Count) { $cHtml += '<div class="tp-row tp-small">' + ((@($c.Related | ForEach-Object { '<span class="tp-chip">' + (Esc "$($_.ControlId): $($_.State)") + '</span>' })) -join '') + '</div>' }
            $url = ConvertTo-TPSafeUrl -Url $c.SourceUrl -AllowedSchemes @('https')
            if ($url) { $cHtml += '<p class="tp-small">Source: <a href="' + $url + '" rel="noopener noreferrer">' + (Esc $(if ($c.SourceTitle) { $c.SourceTitle } else { 'Microsoft' })) + '</a></p>' }
            $cHtml += '</div>'
        }
        $null = $sb.Append((New-TPThemeSection -Id 'microsoft-changes' -Title 'Coming Microsoft changes' -Kicker 'What Microsoft has announced that touches this tenant' -BodyHtml $cHtml))
    }

    $null = $sb.Append((New-TPThemeFooter -GeneratedAt $GeneratedAt -ToolVersion $ToolVersion -CompanyName $theme.CompanyName -Note 'What the tool observed at the time shown'))
    $html = New-TPThemeDocument -Title "Where you stand: $tenantText" -Theme $theme -BodyHtml $sb.ToString()

    # ── Markdown ──
    $md = [System.Text.StringBuilder]::new()
    $null = $md.AppendLine("# Where you stand: $(EscMd $tenantText)")
    $null = $md.AppendLine()
    $null = $md.AppendLine("$(EscMd $theme.CompanyName) &middot; assessed $(EscMd $Model.AssessedAt) &middot; license: $(EscMd $Model.LicenseTier)")
    $null = $md.AppendLine()
    $null = $md.AppendLine("> $(EscMd $Model.Statement)")
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Executive summary')
    $null = $md.AppendLine()
    $null = $md.AppendLine('| Score (recorded) | Maturity (recorded) | Open Critical | Open High | Satisfied | Not assessed | License decisions |')
    $null = $md.AppendLine('|---|---|---|---|---|---|---|')
    $null = $md.AppendLine("| $(EscMd $scoreText) | $(EscMd $(if ($Model.MaturityLabel) { $Model.MaturityLabel } else { 'Not recorded' })) | $($open.Critical) | $($open.High) | $($Model.Counts.Satisfied) | $([int]$Model.Counts.NotApplicable + [int]$Model.Counts.Error) | $(@($Model.LicenseDecision).Count) |")
    $null = $md.AppendLine()
    if ($Model.Qualification) { $null = $md.AppendLine((EscMd $Model.Qualification)); $null = $md.AppendLine() }
    $null = $md.AppendLine('### Top risks')
    $null = $md.AppendLine()
    if ($risks.Count -eq 0) { $null = $md.AppendLine('No Critical or High item is open in this run.') }
    foreach ($r in $risks) { $null = $md.AppendLine("- **$(EscMd $r.Title)** ($(EscMd $r.Severity), ``$($r.ControlId)``): $(EscMd $r.BusinessRisk)") }
    $null = $md.AppendLine()
    $null = $md.AppendLine("## What's working")
    $null = $md.AppendLine()
    if ($work.Count -eq 0) { $null = $md.AppendLine('No control was satisfied in this run.') }
    foreach ($w in @($work | Select-Object -First 15)) { $null = $md.AppendLine("- $(EscMd $w.Title) (``$($w.ControlId)``)") }
    if ($work.Count -gt 15) { $null = $md.AppendLine("- And $($work.Count - 15) more satisfied control(s).") }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## What needs attention')
    $null = $md.AppendLine()
    $null = $md.AppendLine("| Critical | High | Medium | Low |")
    $null = $md.AppendLine('|---|---|---|---|')
    $null = $md.AppendLine("| $($open.Critical) | $($open.High) | $($open.Medium) | $($open.Low) |")
    $null = $md.AppendLine()
    $null = $md.AppendLine('## 30/60/90-day plan')
    $null = $md.AppendLine()
    $null = $md.AppendLine((EscMd $Model.PlanNote))
    $mdItem = {
        param($it)
        $line = "- ``$($it.ControlId)`` **$(EscMd $it.Title)** ($(EscMd $it.Severity), $(EscMd $it.State))"
        if ($it.Contains('Effort')) { $line += ". Effort: $(EscMd $it.Effort). $(EscMd $it.ImpactSummary)" }
        if ($it.Contains('Note')) { $line += " $(EscMd $it.Note)" }
        return $line
    }
    foreach ($k in $windows.Keys) {
        $null = $md.AppendLine()
        $null = $md.AppendLine("### $(EscMd $windows[$k].Label)")
        $null = $md.AppendLine()
        $null = $md.AppendLine("_$(EscMd $windows[$k].Text)_")
        $null = $md.AppendLine()
        $items = @($plan[$k])
        if ($items.Count -eq 0) { $null = $md.AppendLine('Nothing in this window.') }
        foreach ($it in $items) { $null = $md.AppendLine((& $mdItem $it)) }
    }
    if ($review.Count -gt 0) {
        $null = $md.AppendLine()
        $null = $md.AppendLine('### Plan after review')
        $null = $md.AppendLine()
        $null = $md.AppendLine('Open items whose operational impact is not documented. They are scheduled once someone has checked what the change will affect.')
        $null = $md.AppendLine()
        foreach ($it in $review) { $null = $md.AppendLine((& $mdItem $it)) }
    }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Needs a license decision')
    $null = $md.AppendLine()
    if ($lic.Count -eq 0) { $null = $md.AppendLine('No open item needs a license decision.') }
    else {
        $null = $md.AppendLine('| Control | Title | Severity | Would be unlocked by | Why it is here |')
        $null = $md.AppendLine('|---|---|---|---|---|')
        foreach ($it in $lic) { $null = $md.AppendLine("| ``$($it.ControlId)`` | $(EscMd $it.Title) | $(EscMd $it.Severity) | $(EscMd $(if ($it.License) { $it.License } else { 'Not stated' })) | $(EscMd $it.Reason) |") }
    }
    if ($null -ne $changes) {
        $null = $md.AppendLine()
        $null = $md.AppendLine('## Coming Microsoft changes')
        $null = $md.AppendLine()
        $chg = @($changes.Changes)
        if ($chg.Count -eq 0) { $null = $md.AppendLine('No change in the catalog is dated today or later.') }
        foreach ($c in $chg) {
            $when = (@($c.DateQualifier, $c.Date) | Where-Object { $_ }) -join ' '
            $null = $md.AppendLine("- **$(EscMd $c.Title)** ($(EscMd $when)): $(EscMd $c.Summary)$(if ($c.Impact) { ' Impact: ' + (EscMd $c.Impact) })$(if (@($c.Related).Count) { ' Related: ' + (EscMd ((@($c.Related | ForEach-Object { "$($_.ControlId) $($_.State)" })) -join ', ')) })$(if ($c.SourceTitle) { ' Source: ' + (EscMd $c.SourceTitle) })")
        }
    }
    $null = $md.AppendLine()
    $null = $md.AppendLine("_Generated $($GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)) UTC by TenantPosture $(EscMd $ToolVersion)_")

    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    Set-TPSensitiveFileContent -Path $mdPath -Content $md.ToString()
    return [ordered]@{ Html = $htmlPath; Markdown = $mdPath }
}

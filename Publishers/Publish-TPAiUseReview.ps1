#Requires -Version 7.0
#
# Publish-TPAiUseReview.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Render the client-facing AI use readiness review
#   (Get-TPAiUseReview) as <base>-ai-use-review.html in the shared report
#   theme, printable, and as PDF when asked (-Pdf) and a browser is available
#   (ConvertTo-TPPdf). The PDF is optional: a failed print is reported and the
#   HTML stays.
#
# Rendering rules (pinned by TP.AiUseReview.Tests.ps1):
#   - Page one states what the review is and is not before any number; the
#     numbers are counts of catalog controls, never a score.
#   - Nothing says compliant, safe, approved or AI-ready.
#   - Every count is rendered with its status (complete, lower bound, not
#     established, not read); an incomplete read never prints as zero.
#   - Technical evidence, third-party declarations and unrecorded
#     organizational evidence are three different labels.
#   - No finding detail, account, object id, agent or application name, or
#     tenant identifier. Every string is escaped; the page loads and runs
#     nothing (default-src 'none').
#
# Inputs:  -Model, -OutputPath (file path of the .html; the .pdf sits beside
#          it), -Pdf, -Brand (defaults to the loaded profile), -GeneratedAt.
# Data consumed: the model only. Graph scopes / cmdlets used: none.

function Publish-TPAiUseReview {
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
        [switch] $Pdf,
        [AllowNull()] [object] $Brand,
        [string] $ToolVersion = '',
        [datetime] $GeneratedAt = [datetime]::UtcNow
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not (Get-Command ConvertTo-TPHtmlSafe -ErrorAction SilentlyContinue)) {
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the AI use review without HTML escaping.'
    }
    if ((Get-TPObjectField -Item $Model -Key 'Available' -Default $false) -ne $true) {
        throw "AI use readiness review not generated: $([string](Get-TPObjectField -Item $Model -Key 'Note' -Default 'not available'))"
    }
    function Esc { param([object] $value) ConvertTo-TPHtmlSafe $value }

    if (-not $PSBoundParameters.ContainsKey('Brand')) {
        $Brand = if ((Get-Variable -Name TPBrand -Scope Script -ErrorAction SilentlyContinue)) { $script:TPBrand } else { $null }
    }
    if (-not $ToolVersion) { $ToolVersion = [string]$Model.ToolVersion }
    $theme = Get-TPReportTheme -Brand $Brand
    $preparedBy = if ($Model.PreparedBy) { $Model.PreparedBy } else { $theme.CompanyName }

    $htmlPath = if ($OutputPath -match '\.html\z') { $OutputPath } else { "$OutputPath.html" }
    $pdfPath = [System.IO.Path]::ChangeExtension($htmlPath, '.pdf')
    $dir = Split-Path -Parent $htmlPath
    if ($dir) { $null = [System.IO.Directory]::CreateDirectory($dir) }

    $names = $Model.GroupNames
    $tone = [ordered]@{ Observed = 'Info'; Verified = 'Good'; Attention = 'Bad'; Attested = 'Warn'; NotVerified = 'Neutral' }
    $sevTone = @{ Critical = 'Bad'; High = 'Warn'; Medium = 'Info'; Low = 'Neutral'; Informational = 'Neutral' }
    $countTone = @{ Complete = 'Good'; LowerBound = 'Warn'; NotEstablished = 'Neutral'; NotRead = 'Neutral' }
    $countWord = @{ Complete = 'Complete'; LowerBound = 'Lower bound'; NotEstablished = 'Not established'; NotRead = 'Not read' }
    $relName = [ordered]@{ AiSpecific = 'AI-specific'; DirectAccess = 'Direct access'; SupportingGovernance = 'Supporting governance'; General = 'General' }

    $pill = { param([string] $status, [string] $textValue) New-TPThemePill -Status $status -Text $textValue }
    $countRow = {
        param($countItem)
        $st = [string]$countItem.Status
        return '<tr><td>' + (Esc $countItem.Label) + '<div class="tp-small tp-muted">' + (Esc $countItem.Note) + '</div></td><td class="tp-num">' + (Esc $countItem.Display) + '</td><td>' + (& $pill $countTone[$st] $countWord[$st]) + '</td></tr>'
    }
    $refHtml = {
        param($reference)
        if ($null -eq $reference) { return '' }
        $url = [string](Get-TPObjectField -Item $reference -Key 'Url' -Default '')
        $title = [string](Get-TPObjectField -Item $reference -Key 'Title' -Default '')
        $when = [string](Get-TPObjectField -Item $reference -Key 'Retrieved' -Default '')
        # The link opens nothing from this page: default-src 'none' blocks every
        # load, and the reader follows it in their own browser if they choose.
        return '<div class="tp-small tp-muted">Source: <a href="' + (Esc $url) + '" rel="noopener noreferrer">' + (Esc $title) + '</a>' + (Esc " (read $when)") + '</div>'
    }
    $controlCard = {
        param($it, [bool] $withImpact)
        $html = '<div class="tp-card tp-ai-item" style="margin:0 0 10px"><div class="tp-card-head"><div><span class="tp-card-title">' + (Esc $it.Title) + '</span> <span class="tp-muted tp-mono">' + (Esc $it.ControlId) + '</span></div><span class="tp-chip">' + (Esc $relName[[string]$it.Relationship]) + '</span></div>'
        $html += '<p class="tp-small"><strong>' + (Esc $it.Scope) + '.</strong> ' + (Esc $it.Explanation) + '</p>'
        $html += '<p class="tp-small">' + (Esc $it.ReasonText)
        if ($it.Severity -and [string]$it.Group -eq 'Attention') { $html += ' ' + (& $pill $sevTone[[string]$it.Severity] $it.Severity) }
        $html += '</p>'
        if ($withImpact) {
            $impact = $it.Impact
            if ($null -ne $impact) { $html += '<p class="tp-small tp-muted">' + (Esc "If changed: $($impact.Summary) Effort: $($impact.Effort).") + '</p>' }
            else { $html += '<p class="tp-small tp-muted">Operational impact not documented.</p>' }
        }
        $html += & $refHtml $it.Reference
        return $html + '</div>'
    }

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.Append((New-TPThemeMasthead -CompanyName $preparedBy -Title 'AI use readiness review' -Subtitle "Microsoft 365 configuration as it relates to AI use, for $($Model.ClientName)" -Chips @("Assessed $($Model.AssessedAt)", "Prepared by $preparedBy")))

    # ── About ────────────────────────────────────────────────────────────────
    $counts = $Model.Counts
    $kpis = '<div class="tp-kpis">'
    $short = [ordered]@{ Observed = 'Observed'; Verified = 'In place'; Attention = 'Act'; Attested = 'Declared'; NotVerified = 'Unverified' }
    foreach ($k in $names.Keys) { $kpis += New-TPThemeKpi -Label $names[$k] -Value $counts[$k] -Note "of $($Model.CatalogControls) reviewed controls" -PillHtml (& $pill $tone[$k] $short[$k]) }
    $kpis += '</div>'
    $about = '<div class="tp-banner tp-banner--info">' + (Esc $Model.Statements.Purpose) + '</div>' +
        '<p class="tp-small"><strong>What this is not.</strong> ' + (Esc $Model.Statements.NotThis) + '</p>' +
        '<p class="tp-small"><strong>Scope.</strong> ' + (Esc $Model.Statements.Scope) + '</p>' +
        '<p class="tp-small"><strong>Dates.</strong> ' + (Esc $Model.Statements.Dates) + '</p>'
    if ($Model.Statements.Hipaa) { $about += '<p class="tp-small"><strong>HIPAA wording.</strong> ' + (Esc $Model.Statements.Hipaa) + '</p>' }
    $about += '<p class="tp-note">' + (Esc "The counts below are how many of the $($Model.CatalogControls) reviewed controls fall in each group. They are not a score, and the $($Model.ControlsJsonTotal) controls of the full assessment are not all reviewed here.") + '</p>' + $kpis
    $null = $sb.Append((New-TPThemeSection -Id 'about' -Title 'About this review' -Kicker 'Read this first' -BodyHtml $about -First))

    # ── 1 Observed ───────────────────────────────────────────────────────────
    $obs = $Model.Observed
    $body = '<p class="tp-note">' + (Esc $obs.Statements.Usage) + '</p>'
    $body += '<h3 style="margin:14px 0 8px">Entitlement</h3><div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Product</th><th>Subscribed SKUs</th></tr></thead><tbody>'
    foreach ($e in @($obs.Entitlement)) { $body += '<tr><td>' + (Esc $e.Label) + '</td><td>' + (Esc $e.Display) + '</td></tr>' }
    $body += '</tbody></table></div>'
    $body += '<p class="tp-small">' + (Esc $obs.Statements.AddOn) + ' ' + (Esc $obs.Statements.Chat) + '</p>'
    $body += '<h3 style="margin:14px 0 8px">Microsoft Copilot seats</h3><p class="tp-small">' + (Esc $obs.Copilot.Summary) + '</p>'
    $body += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Measurement</th><th class="tp-num">Value</th><th>Status</th></tr></thead><tbody>'
    foreach ($countItem in @($obs.Copilot.Counts)) { $body += & $countRow $countItem }
    $body += '</tbody></table></div>'
    $body += '<p class="tp-small tp-muted">' + (Esc "Reads recorded by the collector: subscription list $($obs.Copilot.LicensingRead); user enumeration $($obs.Copilot.UsersRead). A lower bound is what a partial read established; it is not a total.") + '</p>'
    foreach ($it in @($Model.Groups.Observed)) {
        $body += '<div class="tp-card" style="margin:0 0 10px"><div class="tp-card-head"><div><span class="tp-card-title">' + (Esc $it.Title) + '</span> <span class="tp-muted tp-mono">' + (Esc $it.ControlId) + '</span></div><span class="tp-chip">Observation only</span></div><p class="tp-small">' + (Esc $it.ReasonText) + '</p><p class="tp-small tp-muted">' + (Esc $it.Explanation) + '</p></div>'
    }
    $cs = $obs.CopilotStudio
    $body += '<h3 style="margin:14px 0 8px">Copilot Studio agents</h3><p class="tp-small">' + (Esc $cs.Summary) + '</p>'
    if ($cs.Available) {
        $body += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Measurement</th><th class="tp-num">Value</th><th>Status</th></tr></thead><tbody>'
        $body += & $countRow $cs.Agents
        $body += & $countRow $cs.ManagedAgents
        $body += '<tr><td>Environments listed<div class="tp-small tp-muted">' + (Esc "Environment list: $($cs.ListStatus). Dataverse environments: $($cs.DataverseEnvironments).") + '</div></td><td class="tp-num">' + (Esc $cs.EnvironmentsListed) + '</td><td>' + (& $pill $(if ($cs.ListStatus -eq 'Collected') { 'Good' } else { 'Neutral' }) $cs.ListStatus) + '</td></tr>'
        $body += '<tr><td>Environments read in full / in part / not at all</td><td class="tp-num">' + (Esc "$($cs.EnvironmentsRead) / $($cs.EnvironmentsTruncated) / $($cs.EnvironmentsNotRead)") + '</td><td>' + (& $pill $(if ($cs.EnvironmentsTruncated -eq 0 -and $cs.EnvironmentsNotRead -eq 0) { 'Good' } else { 'Warn' }) $(if ($cs.EnvironmentsTruncated -eq 0 -and $cs.EnvironmentsNotRead -eq 0) { 'Complete' } else { 'Partial' })) + '</td></tr>'
        $body += '</tbody></table></div>'
    }
    $body += '<p class="tp-small tp-muted">' + (Esc $obs.Statements.Agents) + '</p>'
    $null = $sb.Append((New-TPThemeSection -Id 'observed' -Title '1. Observed AI-related configuration' -Kicker 'From the saved assessment' -BodyHtml $body))

    # ── 2 Safeguards ─────────────────────────────────────────────────────────
    $body = '<p class="tp-note">' + (Esc 'Controls recorded Satisfied when the assessment ran. Each one is labeled by how it relates to AI use: an AI-specific setting, a setting that decides what an account (and so Copilot acting as that account) can read, a setting that supports that governance, or a general application control. A setting can change after the date shown, and these are the settings this tool checks, not every setting that bears on AI use.') + '</p>'
    $items = @($Model.Groups.Verified)
    if ($items.Count -eq 0) { $body += '<p class="tp-note">None recorded in this review.</p>' }
    $aiItems = @($items | Where-Object { $_.Relationship -eq 'AiSpecific' })
    $relItems = @($items | Where-Object { $_.Relationship -ne 'AiSpecific' })
    if ($aiItems.Count) { $body += '<h3 style="margin:14px 0 8px">AI-specific safeguards</h3>'; foreach ($it in $aiItems) { $body += & $controlCard $it $false } }
    if ($relItems.Count) { $body += '<h3 style="margin:14px 0 8px">Related access and data-governance safeguards</h3>'; foreach ($it in $relItems) { $body += & $controlCard $it $false } }
    $null = $sb.Append((New-TPThemeSection -Id 'safeguards' -Title '2. Safeguards in place' -Kicker "$($items.Count) control(s) recorded Satisfied" -BodyHtml $body))

    # ── 3 Attention ──────────────────────────────────────────────────────────
    $body = '<p class="tp-note">' + (Esc 'Controls recorded as a gap or only partly in place. AI-specific shortfalls are listed first; the related access and data-governance shortfalls are weaknesses of the Microsoft 365 configuration itself, which also widen what an account, and so Copilot, can reach. Each card says what changing the setting does to users.') + '</p>'
    $items = @($Model.Groups.Attention)
    if ($items.Count -eq 0) { $body += '<p class="tp-note">None recorded in this review.</p>' }
    $aiItems = @($items | Where-Object { $_.Relationship -eq 'AiSpecific' })
    $relItems = @($items | Where-Object { $_.Relationship -ne 'AiSpecific' })
    if ($aiItems.Count) { $body += '<h3 style="margin:14px 0 8px">AI-specific</h3>'; foreach ($it in $aiItems) { $body += & $controlCard $it $true } }
    if ($relItems.Count) { $body += '<h3 style="margin:14px 0 8px">Related access and data governance</h3>'; foreach ($it in $relItems) { $body += & $controlCard $it $true } }
    $null = $sb.Append((New-TPThemeSection -Id 'attention' -Title '3. Items needing attention' -Kicker "$($items.Count) control(s) recorded Gap or Partial" -BodyHtml $body))

    # ── 4 Decisions and evidence gaps ────────────────────────────────────────
    $body = '<p class="tp-note">' + (Esc 'These are decisions and records only your organization can make. None of them is a technical finding, and "not recorded in this assessment" means exactly that: the assessment has no way to read them. The roles are suggestions; nobody has been appointed by this review.') + '</p>'
    $body += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Area</th><th>What to decide and record</th><th>Evidence type</th><th>Suggested roles</th><th>In this assessment</th></tr></thead><tbody>'
    foreach ($area in @($Model.Organizational)) {
        $body += '<tr><td>' + (Esc $area.Area) + '</td><td class="tp-small">' + (Esc $area.Wording) + '</td><td class="tp-small">' + (Esc $area.EvidenceType) + '</td><td class="tp-small">' + (Esc (@($area.SuggestedRoles) -join ', ')) + '</td><td>' + (& $pill 'Neutral' 'Not recorded') + '</td></tr>'
    }
    $body += '</tbody></table></div>'
    $attested = @($Model.Groups.Attested)
    if ($attested.Count) {
        $body += '<h3 style="margin:14px 0 8px">Declared by a third party, not verified here</h3><p class="tp-small">' + (Esc 'The assessor declared that a non-Microsoft product covers these controls. The declaration is recorded as such; this assessment did not verify the product.') + '</p>'
        foreach ($it in $attested) { $body += & $controlCard $it $false }
    }
    $nv = @($Model.Groups.NotVerified)
    $body += '<h3 style="margin:14px 0 8px">Not verified in this review</h3><p class="tp-small">' + (Esc 'Controls for which this assessment recorded no verdict. Nothing is claimed either way; each row says why.') + '</p>'
    if ($nv.Count -eq 0) { $body += '<p class="tp-note">Every reviewed control produced a verdict.</p>' }
    else {
        $body += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Control</th><th>Relationship</th><th>Why no verdict</th></tr></thead><tbody>'
        foreach ($it in $nv) { $body += '<tr><td>' + (Esc $it.Title) + ' <span class="tp-muted tp-mono">' + (Esc $it.ControlId) + '</span></td><td class="tp-small">' + (Esc $relName[[string]$it.Relationship]) + '</td><td class="tp-small">' + (Esc $it.ReasonText) + '</td></tr>' }
        $body += '</tbody></table></div>'
    }
    $null = $sb.Append((New-TPThemeSection -Id 'decisions' -Title '4. Organizational decisions and evidence gaps' -Kicker "$(@($Model.Organizational).Count) review areas; $($attested.Count) declared; $($nv.Count) not verified" -BodyHtml $body))

    # ── 5 Next steps ─────────────────────────────────────────────────────────
    $stepTable = {
        param([object[]] $steps, [string] $empty)
        $list = @($steps | Where-Object { $null -ne $_ })
        if ($list.Count -eq 0) { return '<p class="tp-note">' + (Esc $empty) + '</p>' }
        $html = '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Step</th><th>Evidence basis</th><th>Suggested role</th><th>Dependency</th><th>Operational impact</th><th>Verification</th></tr></thead><tbody>'
        foreach ($s in $list) {
            $label = (Esc $s.Title) + $(if ($s.ControlId) { ' <span class="tp-muted tp-mono">' + (Esc $s.ControlId) + '</span>' } else { '' }) + $(if ($s.Severity) { ' ' + (& $pill $sevTone[[string]$s.Severity] $s.Severity) } else { '' })
            $html += '<tr><td>' + $label + '</td><td class="tp-small">' + (Esc $s.EvidenceBasis) + '</td><td class="tp-small">' + (Esc $s.ResponsibleRole) + '</td><td class="tp-small">' + (Esc $s.Dependency) + '</td><td class="tp-small">' + (Esc $s.OperationalImpact) + (Esc " Effort: $($s.Effort).") + '</td><td class="tp-small">' + (Esc $s.Verification) + '</td></tr>'
        }
        return $html + '</tbody></table></div>'
    }
    $ns = $Model.NextSteps
    $body = '<p class="tp-note">' + (Esc 'Steps are grouped by what each one needs. Effort is a class, never an hour figure. Roles are suggestions.') + '</p>'
    $body += '<h3 style="margin:14px 0 8px">Improvements with current capabilities</h3>' + (& $stepTable $ns.CurrentCapabilities 'None: every reviewed control with a verdict is in place, or needs a license first.')
    $body += '<h3 style="margin:14px 0 8px">Decisions or documentation requiring the client</h3>' + (& $stepTable $ns.ClientDecisions 'None.')
    $body += '<h3 style="margin:14px 0 8px">Additional collection or review needed</h3>' + (& $stepTable $ns.AdditionalCollection 'None: every reviewed control produced a verdict.')
    $body += '<h3 style="margin:14px 0 8px">Licensing or separately scoped projects</h3>' + (& $stepTable $ns.LicensingOrProjects 'None.')
    $null = $sb.Append((New-TPThemeSection -Id 'next-steps' -Title '5. Prioritized next steps' -Kicker 'By what each step needs' -BodyHtml $body))

    # ── Sources and provenance ───────────────────────────────────────────────
    $body = '<dl class="tp-kv">'
    foreach ($fact in @($Model.VendorFacts)) { $body += '<dt>' + (Esc $fact.Source.Title) + '</dt><dd>' + (Esc $fact.Statement) + (& $refHtml $fact.Source) + '</dd>' }
    $body += '<dt>Assessment</dt><dd>' + (Esc "Results recorded $($Model.AssessedAt) by TenantPosture $($Model.ToolVersion).") + '</dd>'
    $body += '<dt>Control mapping</dt><dd>' + (Esc "AI use review catalog version $($Model.CatalogVersion): $($Model.CatalogControls) of the assessment's $($Model.ControlsJsonTotal) controls, applied by the installed tool when this page was generated.") + '</dd>'
    $body += '<dt>Vendor statements</dt><dd>' + (Esc "Read from Microsoft Learn on $($Model.VendorFactsRetrieved). That is the date they were checked, not a publication or product-change date.") + '</dd></dl>'
    $null = $sb.Append((New-TPThemeSection -Id 'sources' -Title 'Sources and dates' -Kicker 'Provenance' -BodyHtml $body))

    $null = $sb.Append((New-TPThemeFooter -GeneratedAt $GeneratedAt -ToolVersion $ToolVersion -CompanyName $preparedBy -Note "Microsoft 365 configuration as read on $($Model.AssessedAt); not a risk assessment and not a compliance determination"))
    $null = $sb.Append('<style>@media print{.tp-ai-item{break-inside:auto}}</style>')
    $html = New-TPThemeDocument -Title "AI use readiness review: $($Model.ClientName)" -Theme $theme -BodyHtml $sb.ToString()

    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    $out = [ordered]@{ Html = $htmlPath; Pdf = ''; PdfNote = '' }
    if ($Pdf) {
        $r = ConvertTo-TPPdf -HtmlPath $htmlPath -PdfPath $pdfPath
        if ($r.Written) { $out.Pdf = $pdfPath } else { $out.PdfNote = "HTML generated; PDF unavailable: $($r.Reason) Open the HTML in a browser and print it to PDF." }
    }
    return $out
}

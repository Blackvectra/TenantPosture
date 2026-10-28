#Requires -Version 7.0
#
# Publish-TPSecurityReviewReport.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Render the client security review (Get-TPSecurityReviewReport) as
#   <base>-security-review.html in the shared report theme and, with -Pdf, a
#   PDF of it printed by the Edge or Chrome already on the workstation
#   (ConvertTo-TPPdf). The internal checklists (Publish-TPCAChecklist,
#   Publish-TPIntuneChecklist) are the technician's versions.
#
# Rendering rules (pinned by TP.SecurityReview.Tests.ps1): page one says what
#   the report is and is not before any number; nothing says compliant or
#   secure; every string is escaped; the page loads nothing.
#
# Inputs:  -Model, -OutputPath (the .html; the PDF sits beside it), -Pdf,
#          -Brand (defaults to the loaded profile), -ToolVersion, -GeneratedAt.
# Data consumed: the model only. Graph scopes / cmdlets used: none.

function Publish-TPSecurityReviewReport {
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
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the security review without HTML escaping.'
    }
    if ((Get-TPObjectField -Item $Model -Key 'Available' -Default $false) -ne $true) {
        throw "Security review not generated: $([string](Get-TPObjectField -Item $Model -Key 'Note' -Default 'not available'))"
    }
    function Esc { param([object] $v) ConvertTo-TPHtmlSafe $v }

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
    $tone = [ordered]@{ NextSteps = 'Bad'; TurnOn = 'Warn'; InPlace = 'Good'; NotChecked = 'Neutral' }
    $short = [ordered]@{ NextSteps = 'Act'; TurnOn = 'Turn on'; InPlace = 'In place'; NotChecked = 'Unchecked' }
    $sevTone = @{ High = 'Bad'; Medium = 'Warn'; Low = 'Neutral' }
    $groupText = [ordered]@{
        NextSteps  = 'Settings that are missing or set below the recommended value, most important first, each with what to change.'
        TurnOn     = 'A policy that would meet the check already exists in report-only mode, which records what it would do and enforces nothing.'
        InPlace    = 'Settings that were in place when this review read them.'
        NotChecked = 'Checks whose settings could not be read in this review, or that need a license this tenant does not have. Nothing is claimed either way.'
    }

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.Append((New-TPThemeMasthead -CompanyName $preparedBy -Title 'Security configuration review' -Subtitle "Sign-in protection and device security for $($Model.ClientName)" -Chips @("Reviewed $($Model.AssessedAt)", "Prepared by $preparedBy")))

    $c = $Model.Counts
    $kpis = '<div class="tp-kpis">'
    foreach ($k in $names.Keys) { $kpis += New-TPThemeKpi -Label $names[$k] -Value $c[$k] -Note "of $($Model.Total) checks" -PillHtml (New-TPThemePill -Status $tone[$k] -Text $short[$k]) }
    $kpis += '</div>'
    $about = '<div class="tp-banner tp-banner--info">' + (Esc $Model.Statements.Purpose) + '</div>' +
        '<p class="tp-small"><strong>What this is not.</strong> ' + (Esc $Model.Statements.NotThis) + '</p>' +
        '<p class="tp-small"><strong>Scope.</strong> ' + (Esc $Model.Statements.Scope) + '</p>'
    if ($Model.Statements.SecurityDefaults) { $about += '<p class="tp-small"><strong>Security Defaults.</strong> ' + (Esc $Model.Statements.SecurityDefaults) + '</p>' }
    $about += $kpis
    $tHtml = '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Area</th>'
    foreach ($k in $names.Keys) { $tHtml += '<th class="tp-num">' + (Esc $names[$k]) + '</th>' }
    $tHtml += '</tr></thead><tbody>'
    foreach ($t in @($Model.Topics.Values)) {
        $tHtml += '<tr><td>' + (Esc $t.Title) + $(if (-not $t.Read) { '<div class="tp-small tp-muted">Not reviewed in this run</div>' } else { '' }) + '</td>'
        foreach ($k in $names.Keys) { $tHtml += '<td class="tp-num">' + (Esc $t[$k]) + '</td>' }
        $tHtml += '</tr>'
    }
    $tHtml += '</tbody></table></div>'
    $about += '<h3 style="margin:18px 0 8px">By area</h3>' + $tHtml
    if ($Model.NotApplicable -gt 0) { $about += '<p class="tp-note">' + (Esc "$($Model.NotApplicable) further check(s) did not apply to this tenant (for example, a device platform you do not use).") + '</p>' }
    $pri = @($Model.Priorities)
    if ($pri.Count) {
        $about += '<h3 style="margin:18px 0 8px">Most important next steps</h3><ol class="tp-list">'
        foreach ($p in $pri) { $about += '<li><strong>' + (Esc $p.Title) + '</strong><div class="tp-small">' + (Esc $p.Action) + '</div></li>' }
        $about += '</ol>'
    }
    $about += '<p class="tp-small"><strong>Before any change.</strong> ' + (Esc $Model.Statements.Changes) + '</p>'
    $null = $sb.Append((New-TPThemeSection -Id 'summary' -Title 'Summary' -Kicker "$($Model.Total) checks" -BodyHtml $about -First))

    foreach ($k in $names.Keys) {
        $items = @($Model.Groups[$k] | Where-Object { $null -ne $_ })
        $body = '<p class="tp-note">' + (Esc $groupText[$k]) + '</p>'
        if ($items.Count -eq 0) { $body += '<p class="tp-note">None in this review.</p>' }
        elseif ($k -eq 'InPlace') {
            $body += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Area</th><th>Check</th></tr></thead><tbody>'
            foreach ($it in $items) { $body += '<tr><td class="tp-small">' + (Esc $it.TopicTitle) + '</td><td>' + (Esc $it.Title) + ' <span class="tp-muted tp-mono tp-small">' + (Esc $it.Reference) + '</span></td></tr>' }
            $body += '</tbody></table></div>'
        } else {
            $body += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Check</th><th>Why it matters</th><th>' + (Esc $(if ($k -eq 'NotChecked') { 'Why it was not checked' } else { 'What to do' })) + '</th></tr></thead><tbody>'
            foreach ($it in $items) {
                $sev = if ($it.Severity -and $k -eq 'NextSteps') { ' ' + (New-TPThemePill -Status $sevTone[[string]$it.Severity] -Text $it.Severity) } else { '' }
                $body += '<tr class="tp-review-row"><td>' + (Esc $it.Title) + $sev + '<div class="tp-small tp-muted">' + (Esc "$($it.TopicTitle) · $($it.Reference)") + '</div></td><td class="tp-small">' + (Esc $it.Why) + '</td><td class="tp-small">' + (Esc $it.Action) + '</td></tr>'
            }
            $body += '</tbody></table></div>'
        }
        $null = $sb.Append((New-TPThemeSection -Id ('group-' + $k.ToLowerInvariant()) -Title $names[$k] -Kicker "$($items.Count) check(s)" -BodyHtml $body))
    }

    $terms = '<dl class="tp-kv"><dt>Conditional Access</dt><dd>' + (Esc 'Microsoft Entra rules that decide who can sign in, from where and with what proof (for example multifactor authentication).') + '</dd>' +
        '<dt>Report-only mode</dt><dd>' + (Esc 'A Conditional Access policy that records what it would have done without enforcing it; the safe way to test a change.') + '</dd>' +
        '<dt>Compliance policy</dt><dd>' + (Esc "Intune's list of conditions a device must meet (passcode, encryption, OS version); a device that falls short can be kept out of company data.") + '</dd>' +
        '<dt>Attack surface reduction</dt><dd>' + (Esc 'Microsoft Defender rules that stop techniques attackers commonly use on Windows devices.') + '</dd>' +
        '<dt>Reference</dt><dd>' + (Esc 'Each check carries the id of the matching Maester test (maester.dev), so a technician can trace it.') + '</dd></dl>'
    $null = $sb.Append((New-TPThemeSection -Id 'terms' -Title 'How to read this report' -Kicker 'Terms' -BodyHtml $terms))
    $null = $sb.Append((New-TPThemeFooter -GeneratedAt $GeneratedAt -ToolVersion $ToolVersion -CompanyName $preparedBy -Note "Configuration as read on $($Model.AssessedAt); not an audit or a compliance determination"))
    $null = $sb.Append('<style>@media print{.tp-review-row{break-inside:avoid}}</style>')
    $html = New-TPThemeDocument -Title "Security configuration review: $($Model.ClientName)" -Theme $theme -BodyHtml $sb.ToString()

    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    $out = [ordered]@{ Html = $htmlPath; Pdf = ''; PdfNote = '' }
    if ($Pdf) {
        $r = ConvertTo-TPPdf -HtmlPath $htmlPath -PdfPath $pdfPath
        if ($r.Written) { $out.Pdf = $pdfPath } else { $out.PdfNote = "PDF not written: $($r.Reason) Open the HTML in a browser and print it to PDF." }
    }
    return $out
}

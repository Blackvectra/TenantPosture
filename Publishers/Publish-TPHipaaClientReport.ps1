#Requires -Version 7.0
#
# Publish-TPHipaaClientReport.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Render the client-facing HIPAA Security Rule report
#   (Get-TPHipaaClientReport) as <base>-hipaa-report.html in the shared report
#   theme, printable, and as PDF when a browser is available
#   (ConvertTo-TPPdf). The internal readiness view (Publish-TPHipaaReadiness)
#   is unchanged; this is the version a client keeps.
#
# Rendering rules (pinned by TP.HipaaClientReport.Tests.ps1):
#   - Page one states what the report is and is not before any number.
#   - Nothing says compliant; the five group names state technical results.
#   - No finding detail, remediation command, account name or tenant id.
#   - Every string is escaped; the page loads nothing and runs nothing.
#
# Inputs:  -Model, -OutputPath (file path of the .html; the .pdf sits beside
#          it), -Pdf, -Brand (defaults to the loaded profile), -GeneratedAt.
# Data consumed: the model only. Graph scopes / cmdlets used: none.

function Publish-TPHipaaClientReport {
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
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the HIPAA report without HTML escaping.'
    }
    if ((Get-TPObjectField -Item $Model -Key 'Available' -Default $false) -ne $true) {
        throw "HIPAA client report not generated: $([string](Get-TPObjectField -Item $Model -Key 'Note' -Default 'not available'))"
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
    $tone = [ordered]@{ Verified = 'Good'; Partly = 'Info'; Attention = 'Bad'; NotVerified = 'Neutral'; Documentation = 'Warn' }
    $sevTone = @{ Critical = 'Bad'; High = 'Warn'; Medium = 'Info'; Low = 'Neutral'; Informational = 'Neutral' }
    $groupText = [ordered]@{
        Verified      = 'Requirements whose supporting Microsoft 365 settings were all in place.'
        Partly        = 'Standards whose own checks passed while some of their implementation specifications are not yet verified.'
        Attention     = 'Requirements where a supporting Microsoft 365 setting is missing or only partly in place. These are the recommended next steps.'
        NotVerified   = 'Requirements whose supporting settings could not be read in this review. Nothing is claimed either way.'
        Documentation = 'Requirements Microsoft 365 configuration cannot show: they are met by your policies, procedures, agreements, training and records.'
    }

    # What fell short is listed in full; what is in place is a sample with the
    # count of the rest (one standard can rest on thirty settings, and a client
    # needs the shortfalls, not the inventory).
    $checkList = {
        param([object[]] $checks, [string] $label, [int] $Max = 0)
        $c = @($checks | Where-Object { $null -ne $_ })
        if ($c.Count -eq 0) { return '' }
        $shown = if ($Max -gt 0) { @($c | Select-Object -First $Max) } else { $c }
        $html = '<div class="tp-small"><strong>' + (Esc $(if ($Max -gt 0 -and $c.Count -gt $Max) { "$label ($($c.Count))" } else { $label })) + '</strong><ul class="tp-list">'
        foreach ($x in $shown) {
            $html += '<li>' + (Esc $x.Title)
            if ($label -eq 'Fell short' -and $x.Severity) { $html += ' ' + (New-TPThemePill -Status $sevTone[[string]$x.Severity] -Text $x.Severity) }
            $html += ' <span class="tp-muted tp-mono">' + (Esc $x.ControlId) + '</span></li>'
        }
        if ($c.Count -gt $shown.Count) { $html += '<li class="tp-muted">' + (Esc "and $($c.Count - $shown.Count) more") + '</li>' }
        return $html + '</ul></div>'
    }
    $itemCard = {
        param($it)
        $html = '<div class="tp-card tp-hipaa-item" style="margin:0 0 10px"><div class="tp-card-head"><div><span class="tp-mono">' + (Esc "§$($it.Citation)") + '</span> <span class="tp-card-title">' + (Esc $it.Name) + '</span></div><span class="tp-chip">' + (Esc "$($it.Safeguard) · $($it.Requirement)") + '</span></div>'
        $html += '<p class="tp-small">' + (Esc $it.Why) + '</p>'
        $html += & $checkList $it.Failed 'Fell short'
        $html += & $checkList $it.Passed 'In place' -Max 5
        $html += & $checkList $it.NoResult 'Could not be checked'
        return $html + '</div>'
    }

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.Append((New-TPThemeMasthead -CompanyName $preparedBy -Title 'HIPAA Security Rule review' -Subtitle "Microsoft 365 technical safeguards for $($Model.ClientName)" -Chips @("Reviewed $($Model.AssessedAt)", "Prepared by $preparedBy")))

    $c = $Model.Counts
    $kpis = '<div class="tp-kpis">'
    # A short word in the pill: the card's label already names the group, and a
    # long pill overflows a narrow card on a printed page.
    $short = [ordered]@{ Verified = 'Verified'; Partly = 'Partly'; Attention = 'Act'; NotVerified = 'Unchecked'; Documentation = 'Document' }
    foreach ($k in $names.Keys) { $kpis += New-TPThemeKpi -Label $names[$k] -Value $c[$k] -Note "of $($Model.Total) requirements" -PillHtml (New-TPThemePill -Status $tone[$k] -Text $short[$k]) }
    $kpis += '</div>'
    $about = '<div class="tp-banner tp-banner--info">' + (Esc $Model.Statements.Purpose) + '</div>' +
        '<p class="tp-small"><strong>What this is not.</strong> ' + (Esc $Model.Statements.NotThis) + '</p>' +
        '<p class="tp-small"><strong>Scope.</strong> ' + (Esc $Model.Statements.Scope) + '</p>' + $kpis
    $sgHtml = '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Safeguard</th>'
    foreach ($k in $names.Keys) { $sgHtml += '<th class="tp-num">' + (Esc $names[$k]) + '</th>' }
    $sgHtml += '<th class="tp-num">Total</th></tr></thead><tbody>'
    foreach ($row in @($Model.BySafeguard)) {
        $sgHtml += '<tr><td>' + (Esc "$($row.Safeguard) safeguards") + '</td>'
        foreach ($k in $names.Keys) { $sgHtml += '<td class="tp-num">' + (Esc $row[$k]) + '</td>' }
        $sgHtml += '<td class="tp-num">' + (Esc $row.Total) + '</td></tr>'
    }
    $sgHtml += '</tbody></table></div>'
    $about += '<h3 style="margin:18px 0 8px">By safeguard</h3>' + $sgHtml
    $pri = @($Model.Priorities)
    if ($pri.Count) {
        $about += '<h3 style="margin:18px 0 8px">Recommended next steps</h3><ol class="tp-list">'
        foreach ($p in $pri) { $about += '<li>' + (Esc $p.Title) + ' ' + (New-TPThemePill -Status $sevTone[[string]$p.Severity] -Text $p.Severity) + $(if ($p.BusinessRisk) { '<div class="tp-small tp-muted">' + (Esc $p.BusinessRisk) + '</div>' } else { '' }) + '</li>' }
        $about += '</ol>'
    }
    $null = $sb.Append((New-TPThemeSection -Id 'summary' -Title 'Summary' -Kicker "$($Model.Rule)" -BodyHtml $about -First))

    $order = @('Attention', 'Verified', 'Partly', 'NotVerified', 'Documentation')
    foreach ($k in $order) {
        $items = @($Model.Groups[$k] | Where-Object { $null -ne $_ })
        $body = '<p class="tp-note">' + (Esc $groupText[$k]) + '</p>'
        if ($k -eq 'Verified') { $body += '<p class="tp-note">' + (Esc $Model.Statements.Verified) + '</p>' }
        if ($items.Count -eq 0) { $body += '<p class="tp-note">None in this review.</p>' }
        elseif ($k -eq 'Documentation') {
            # A checklist the client can work through: one row each, in the rule's order.
            $body += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Citation</th><th>Requirement</th><th>Type</th><th>What shows it</th><th>Documented</th></tr></thead><tbody>'
            foreach ($it in $items) {
                $body += '<tr><td class="tp-mono tp-small">' + (Esc "§$($it.Citation)") + '</td><td>' + (Esc $it.Name) + '<div class="tp-small tp-muted">' + (Esc "$($it.Safeguard) safeguard") + '</div></td><td class="tp-small">' + (Esc $it.Requirement) + '</td><td class="tp-small">' + (Esc $it.Why) + '</td><td style="font-size:1.2rem">&#9744;</td></tr>'
            }
            $body += '</tbody></table></div>'
        }
        else { foreach ($it in $items) { $body += & $itemCard $it } }
        $null = $sb.Append((New-TPThemeSection -Id ("group-" + $k.ToLowerInvariant()) -Title $names[$k] -Kicker "$($items.Count) requirement(s)" -BodyHtml $body))
    }

    $terms = '<dl class="tp-kv"><dt>Standard</dt><dd>' + (Esc 'A requirement of the rule; most have implementation specifications under them.') + '</dd>' +
        '<dt>Required / Addressable</dt><dd>' + (Esc $Model.Statements.Addressable) + '</dd>' +
        '<dt>Source</dt><dd>' + (Esc "$($Model.Rule), as published in the eCFR $(if ($Model.RuleSnapshot) { "($($Model.RuleSnapshot))" }).") + '</dd></dl>'
    $null = $sb.Append((New-TPThemeSection -Id 'terms' -Title 'How to read this report' -Kicker 'Terms' -BodyHtml $terms))
    $null = $sb.Append((New-TPThemeFooter -GeneratedAt $GeneratedAt -ToolVersion $ToolVersion -CompanyName $preparedBy -Note "Microsoft 365 configuration as read on $($Model.AssessedAt); not a compliance determination"))
    # A requirement card may break across printed pages (the theme keeps cards
    # whole, which leaves a blank page before any card taller than what is left).
    $null = $sb.Append('<style>@media print{.tp-hipaa-item{break-inside:auto}}</style>')
    $html = New-TPThemeDocument -Title "HIPAA Security Rule review: $($Model.ClientName)" -Theme $theme -BodyHtml $sb.ToString()

    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    $out = [ordered]@{ Html = $htmlPath; Pdf = ''; PdfNote = '' }
    if ($Pdf) {
        $r = ConvertTo-TPPdf -HtmlPath $htmlPath -PdfPath $pdfPath
        if ($r.Written) { $out.Pdf = $pdfPath } else { $out.PdfNote = "PDF not written: $($r.Reason) Open the HTML in a browser and print it to PDF." }
    }
    return $out
}

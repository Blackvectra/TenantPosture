#Requires -Version 7.0
#
# Publish-TPScapView.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Render the SCAP results view (Get-TPScapView) as <base>-scap.html /
#   .md in the shared report theme: per benchmark, the hosts in the files and
#   each rule with how many hosts passed or failed it and which failed.
#
# Rendering rules (pinned by TP.ScapView.Tests.ps1): page one says the results
#   were imported and not verified, cover only the hosts in the files, and are
#   not a compliance determination, before any number; nothing says compliant;
#   every string from the files is escaped; the page loads nothing.
#
# Inputs:  -Model, -OutputPath (file path of the .html), -Brand, -ToolVersion,
#          -GeneratedAt (tests).
# Data consumed: the model only. Graph scopes / cmdlets used: none.

function Publish-TPScapView {
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
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the SCAP view without HTML escaping.'
    }
    if ((Get-TPObjectField -Item $Model -Key 'Available' -Default $false) -ne $true) {
        throw "SCAP view not generated: $([string](Get-TPObjectField -Item $Model -Key 'Note' -Default 'not available'))"
    }
    function EscMd { param([object] $v) ConvertTo-TPMarkdownSafe $v }   # one Markdown rule for the whole tool
    function Esc { param([object] $v) ConvertTo-TPHtmlSafe $v }

    if (-not $PSBoundParameters.ContainsKey('Brand')) {
        $Brand = if ((Get-Variable -Name TPBrand -Scope Script -ErrorAction SilentlyContinue)) { $script:TPBrand } else { $null }
    }
    $theme = Get-TPReportTheme -Brand $Brand
    $htmlPath = if ($OutputPath -match '\.html\z') { $OutputPath } else { "$OutputPath.html" }
    $mdPath = [System.IO.Path]::ChangeExtension($htmlPath, '.md')
    $dir = Split-Path -Parent $htmlPath
    if ($dir) { $null = [System.IO.Directory]::CreateDirectory($dir) }

    $names = $Model.StatusNames
    $tone = @{ Failing = 'Bad'; NotEstablished = 'Warn'; Manual = 'Info'; Met = 'Good'; NotApplicable = 'Neutral' }
    $benches = @($Model.Benchmarks | Where-Object { $null -ne $_ })
    $st = $Model.Statements
    $hostWord = { param($n) if ($n -eq 1) { 'host' } else { 'hosts' } }

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.Append((New-TPThemeMasthead -CompanyName $theme.CompanyName -Title 'Endpoint baseline results (SCAP)' -Subtitle 'STIG and CIS benchmark results imported from SCAP scans, shown beside the Microsoft 365 assessment' -Chips @("$($benches.Count) benchmark(s)", "$($Model.FilesRead) file(s) read")))
    $intro = '<div class="tp-banner tp-banner--info">' + (Esc $st.Source) + '</div>' +
        '<p class="tp-small"><strong>Coverage.</strong> ' + (Esc $st.Coverage) + '</p>' +
        '<p class="tp-small"><strong>What this is not.</strong> ' + (Esc $st.NotThis) + '</p>' +
        '<p class="tp-small"><strong>Age.</strong> ' + (Esc $st.Age) + '</p>'
    $skipped = @($Model.FilesSkipped | Where-Object { $null -ne $_ })
    if ($skipped.Count -or $Model.FilesNotRead) {
        $intro += '<p class="tp-note">' + (Esc "$($skipped.Count) file(s) could not be used$(if ($Model.FilesNotRead) { " and $($Model.FilesNotRead) more were not read (file limit)" }):") + '</p><ul class="tp-small">'
        foreach ($s in ($skipped | Select-Object -First 50)) { $intro += '<li>' + (Esc "$($s.File): $($s.Reason)") + '</li>' }
        $intro += '</ul>'
    }
    $tbl = '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Benchmark</th><th class="tp-num">Hosts (current)</th>'
    foreach ($k in $names.Keys) { $tbl += '<th class="tp-num">' + (Esc $names[$k]) + '</th>' }
    $tbl += '</tr></thead><tbody>'
    foreach ($b in $benches) {
        $tbl += '<tr><td>' + (Esc $b.Title) + $(if ($b.Version) { ' <span class="tp-muted tp-small">' + (Esc $b.Version) + '</span>' } else { '' }) + '</td><td class="tp-num">' + (Esc "$($b.HostsCurrent) of $($b.HostsTotal)") + '</td>'
        foreach ($k in $names.Keys) { $tbl += '<td class="tp-num">' + (Esc $b.Counts[$k]) + '</td>' }
        $tbl += '</tr>'
    }
    $tbl += '</tbody></table></div>'
    $null = $sb.Append((New-TPThemeSection -Id 'summary' -Title 'Summary' -Kicker "$($benches.Count) benchmark(s)" -BodyHtml ($intro + $tbl) -First))

    $i = 0
    foreach ($b in $benches) {
        $i++
        $body = '<p class="tp-small">' + (Esc "Benchmark $($b.BenchmarkId)$(if ($b.Version) { ", version $($b.Version)" })$(if (@($b.Profiles).Count) { "; profile $(@($b.Profiles) -join ', ')" }).") + '</p>'
        $body += '<div class="tp-kpis">'
        foreach ($k in $names.Keys) { $body += New-TPThemeKpi -Label $names[$k] -Value $b.Counts[$k] -PillHtml (New-TPThemePill -Status $tone[$k] -Text $names[$k]) }
        $body += '</div>'
        $fs = $b.FailingBySeverity
        $body += '<p class="tp-small">' + (Esc "Failing rules by severity: CAT I (high) $($fs.high), CAT II (medium) $($fs.medium), CAT III (low) $($fs.low).") + '</p>'
        $body += '<details><summary>' + (Esc "$($b.HostsTotal) $(& $hostWord $b.HostsTotal) in the files, $($b.HostsCurrent) current") + '</summary><div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Host</th><th>Scanned</th><th>Current</th><th>Score</th><th>File</th></tr></thead><tbody>'
        foreach ($h in @($b.Hosts)) {
            $sup = if (@($h.Superseded).Count) { '<div class="tp-small tp-muted">' + (Esc "Superseded: $(@($h.Superseded) -join ', ')") + '</div>' } else { '' }
            $body += '<tr><td>' + (Esc $h.Host) + $(if ($h.Fqdn) { '<div class="tp-small tp-muted">' + (Esc $h.Fqdn) + '</div>' } else { '' }) + '</td><td>' + (Esc $h.Scanned) + '</td><td>' + $(if ($h.Current) { (New-TPThemePill -Status Good -Text 'Current') } else { (New-TPThemePill -Status Warn -Text 'Not current') }) + '</td><td class="tp-num">' + (Esc $h.Score) + '</td><td class="tp-small">' + (Esc $h.File) + $sup + '</td></tr>'
        }
        $body += '</tbody></table></div></details>'
        $body += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Rule</th><th>Result</th><th class="tp-num">Pass</th><th class="tp-num">Fail</th><th class="tp-num">Other</th><th>Failing hosts</th></tr></thead><tbody>'
        foreach ($r in @($b.Rules)) {
            if ($r.Status -eq 'NotApplicable') { continue }
            $other = $r.NotEstablished + $r.Manual
            $fail = if (@($r.FailingHosts).Count) { (Esc (@($r.FailingHosts) -join ', ')) + $(if ($r.FailingHostsNotShown) { ' ' + (Esc "and $($r.FailingHostsNotShown) more") } else { '' }) } else { '<span class="tp-muted">&#8211;</span>' }
            $sev = if ($r.Category) { ' ' + (New-TPThemePill -Status $(if ($r.Severity -eq 'high') { 'Bad' } elseif ($r.Severity -eq 'medium') { 'Warn' } else { 'Neutral' }) -Text $r.Category) } else { '' }
            $body += '<tr><td><span class="tp-mono">' + (Esc $r.Reference) + '</span>' + $sev + '<div>' + (Esc $r.Title) + '</div></td><td>' + (New-TPThemePill -Status $tone[$r.Status] -Text $r.StatusLabel) + '</td><td class="tp-num">' + (Esc $r.Pass) + '</td><td class="tp-num">' + (Esc $r.Fail) + '</td><td class="tp-num">' + (Esc $other) + '</td><td class="tp-small">' + $fail + '</td></tr>'
        }
        $body += '</tbody></table></div>'
        $na = @($b.Rules | Where-Object { $_.Status -eq 'NotApplicable' }).Count
        if ($na) { $body += '<p class="tp-note">' + (Esc "$na rule(s) did not apply to any current host and are not listed.") + '</p>' }
        $null = $sb.Append((New-TPThemeSection -Id "benchmark-$i" -Title $b.Title -Kicker "$($b.HostsCurrent) current $(& $hostWord $b.HostsCurrent)" -BodyHtml $body))
    }
    $null = $sb.Append((New-TPThemeFooter -GeneratedAt $GeneratedAt -ToolVersion $ToolVersion -CompanyName $theme.CompanyName -Note 'Imported SCAP results; not verified by TenantPosture and not a compliance determination'))
    $html = New-TPThemeDocument -Title 'Endpoint baseline results (SCAP)' -Theme $theme -BodyHtml $sb.ToString()

    $md = [System.Text.StringBuilder]::new()
    $null = $md.AppendLine('# Endpoint baseline results (SCAP)')
    $null = $md.AppendLine()
    foreach ($k in 'Source', 'Coverage', 'NotThis', 'Age') { $null = $md.AppendLine("> $(EscMd $st[$k])"); $null = $md.AppendLine('>') }
    $null = $md.AppendLine()
    if ($skipped.Count) {
        $null = $md.AppendLine("## Files not used ($($skipped.Count))")
        $null = $md.AppendLine()
        foreach ($s in ($skipped | Select-Object -First 50)) { $null = $md.AppendLine("- $(EscMd $s.File): $(EscMd $s.Reason)") }
        $null = $md.AppendLine()
    }
    foreach ($b in $benches) {
        $null = $md.AppendLine("## $(EscMd $b.Title)$(if ($b.Version) { " ($(EscMd $b.Version))" })")
        $null = $md.AppendLine()
        $null = $md.AppendLine("Hosts in the files: $($b.HostsTotal); current: $($b.HostsCurrent).")
        $null = $md.AppendLine()
        $null = $md.AppendLine('| ' + (@($names.Keys | ForEach-Object { EscMd $names[$_] }) -join ' | ') + ' |')
        $null = $md.AppendLine('|' + (@($names.Keys | ForEach-Object { '---' }) -join '|') + '|')
        $null = $md.AppendLine('| ' + (@($names.Keys | ForEach-Object { $b.Counts[$_] }) -join ' | ') + ' |')
        $null = $md.AppendLine()
        $null = $md.AppendLine('| Rule | Severity | Title | Result | Pass | Fail | Other | Failing hosts |')
        $null = $md.AppendLine('|---|---|---|---|---|---|---|---|')
        foreach ($r in @($b.Rules | Where-Object { $_.Status -ne 'NotApplicable' })) {
            $fh = (@($r.FailingHosts) -join ', ') + $(if ($r.FailingHostsNotShown) { " and $($r.FailingHostsNotShown) more" } else { '' })
            $null = $md.AppendLine("| $(EscMd $r.Reference) | $(EscMd $r.Category) | $(EscMd $r.Title) | $(EscMd $r.StatusLabel) | $($r.Pass) | $($r.Fail) | $($r.NotEstablished + $r.Manual) | $(EscMd $fh) |")
        }
        $null = $md.AppendLine()
    }
    $null = $md.AppendLine("_Generated $($GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)) UTC by TenantPosture $(EscMd $ToolVersion)._")

    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    Set-TPSensitiveFileContent -Path $mdPath -Content $md.ToString()
    return [ordered]@{ Html = $htmlPath; Markdown = $mdPath }
}

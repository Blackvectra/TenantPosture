#Requires -Version 7.0
#
# Publish-TPIntuneChecklist.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Render the Intune and endpoint checklist (Get-TPIntuneChecklist) as
#   <base>-intune-checklist.html / .md: tenant settings, iOS / Android / macOS
#   compliance policies, ASR, LAPS and Defender Antivirus, each row with what
#   the run found and, when it is not met, what to set in the Intune admin
#   center.
#
# Rendering rules (pinned by TP.IntuneChecklist.Tests.ps1): every row shows
#   its status in words and the Maester test it follows; nothing says the
#   tenant is compliant; every string is escaped; the page loads nothing.
#
# Inputs:  -Model, -OutputPath (file path of the .html), -TenantDomain,
#          -Brand, -ToolVersion, -GeneratedAt (tests).
# Data consumed: the model only. Graph scopes / cmdlets used: none.

function Publish-TPIntuneChecklist {
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
        [AllowEmptyString()] [string] $TenantDomain = '',
        [AllowNull()] [object] $Brand,
        [string] $ToolVersion = '',
        [datetime] $GeneratedAt = [datetime]::UtcNow
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not (Get-Command ConvertTo-TPHtmlSafe -ErrorAction SilentlyContinue)) {
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the Intune checklist without HTML escaping.'
    }
    if ((Get-TPObjectField -Item $Model -Key 'Available' -Default $false) -ne $true) {
        throw "Intune checklist not generated: $([string](Get-TPObjectField -Item $Model -Key 'Note' -Default 'not available'))"
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

    $tenantText = if ($TenantDomain) { $TenantDomain } else { 'this tenant' }
    $tone = @{ Pass = 'Good'; Fail = 'Bad'; Staged = 'Warn'; NotAssessed = 'Neutral'; NotApplicable = 'Neutral'; NeedsLicense = 'Info' }
    $areaTitle = [ordered]@{
        Tenant    = @{ Title = 'Intune tenant settings'; Id = 'tenant' }
        iOS       = @{ Title = 'iOS and iPadOS compliance'; Id = 'ios' }
        Android   = @{ Title = 'Android compliance'; Id = 'android' }
        macOS     = @{ Title = 'macOS compliance'; Id = 'macos' }
        ASR       = @{ Title = 'Attack surface reduction'; Id = 'asr' }
        LAPS      = @{ Title = 'Windows LAPS'; Id = 'laps' }
        Antivirus = @{ Title = 'Microsoft Defender Antivirus'; Id = 'antivirus' }
    }
    $names = $Model.StatusNames
    $rows = @($Model.Rows | Where-Object { $null -ne $_ })
    $c = $Model.Counts

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.Append((New-TPThemeMasthead -CompanyName $theme.CompanyName -Title 'Intune and endpoint checklist' -Subtitle "How ${tenantText}'s Intune compliance policies, attack surface reduction, LAPS and antivirus compare with what Maester checks." -Chips @("$($rows.Count) checks")))
    $kpis = '<div class="tp-kpis">' +
        (New-TPThemeKpi -Label $names.Pass -Value $c.Pass -PillHtml (New-TPThemePill -Status Good -Text 'In place')) +
        (New-TPThemeKpi -Label $names.Fail -Value $c.Fail -PillHtml (New-TPThemePill -Status Bad -Text 'Fix')) +
        (New-TPThemeKpi -Label $names.NotAssessed -Value $c.NotAssessed -Note 'Data not read') +
        (New-TPThemeKpi -Label $names.NotApplicable -Value $c.NotApplicable -Note 'No policy and no device of that platform') + '</div>'
    $intro = '<div class="tp-banner tp-banner--info">' + (Esc 'Each row follows a Maester test (the id is shown). A policy counts only when it is assigned to someone. Where a row is not met, the last column says what to set in the Intune admin center; the tool changes nothing.') + '</div>'
    foreach ($n in @($Model.Notes)) { $intro += '<p class="tp-note">' + (Esc $n) + '</p>' }
    $null = $sb.Append((New-TPThemeSection -Id 'summary' -Title 'Summary' -Kicker "$($rows.Count) checks" -BodyHtml ($kpis + $intro) -First))

    foreach ($k in $areaTitle.Keys) {
        $set = @($rows | Where-Object { $_.Area -eq $k })
        if ($set.Count -eq 0) { continue }
        $body = '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Check</th><th>Result</th><th>What the run found</th><th>What to set</th></tr></thead><tbody>'
        foreach ($r in $set) {
            $found = '<div class="tp-small">' + (Esc $r.Detail) + '</div>'
            $items = @($r.Items | Where-Object { $null -ne $_ })
            if ($items.Count) {
                $found += '<details><summary>' + (Esc "$($items.Count) policy(ies)") + '</summary><ul class="tp-small">'
                foreach ($it in ($items | Select-Object -First 50)) { $found += '<li>' + (Esc ([string](Get-TPObjectField -Item $it -Key 'Name' -Default ''))) + ' &#8212; ' + (Esc ([string](Get-TPObjectField -Item $it -Key 'Note' -Default ''))) + '</li>' }
                $found += '</ul></details>'
            }
            $fix = if ($r.Status -eq 'Fail') { (Esc $r.Recommended) } else { '<span class="tp-muted">&#8211;</span>' }
            $body += '<tr><td><span class="tp-mono">' + (Esc $r.Id) + '</span><div>' + (Esc $r.Title) + '</div><div class="tp-small tp-muted">' + (Esc $r.Why) + '</div></td><td>' + (New-TPThemePill -Status $tone[[string]$r.Status] -Text $r.StatusLabel) + '</td><td>' + $found + '</td><td class="tp-small">' + $fix + '</td></tr>'
        }
        $body += '</tbody></table></div>'
        $null = $sb.Append((New-TPThemeSection -Id $areaTitle[$k].Id -Title $areaTitle[$k].Title -Kicker "$($set.Count) check(s)" -BodyHtml $body))
    }
    $null = $sb.Append((New-TPThemeFooter -GeneratedAt $GeneratedAt -ToolVersion $ToolVersion -CompanyName $theme.CompanyName -Note "Checks follow Maester ($($Model.MaesterReference))"))
    $html = New-TPThemeDocument -Title "Intune checklist: $tenantText" -Theme $theme -BodyHtml $sb.ToString()

    $md = [System.Text.StringBuilder]::new()
    $null = $md.AppendLine("# Intune and endpoint checklist: $(EscMd $tenantText)")
    $null = $md.AppendLine()
    $null = $md.AppendLine('> Each row follows a Maester test (the id is shown). A policy counts only when it is assigned to someone. Where a row is not met, "What to set" says what to change in the Intune admin center; the tool changes nothing.')
    $null = $md.AppendLine()
    foreach ($n in @($Model.Notes)) { $null = $md.AppendLine("- $(EscMd $n)") }
    $null = $md.AppendLine()
    $null = $md.AppendLine("| $($names.Pass) | $($names.Fail) | $($names.NotAssessed) | $($names.NotApplicable) |")
    $null = $md.AppendLine('|---|---|---|---|')
    $null = $md.AppendLine("| $($c.Pass) | $($c.Fail) | $($c.NotAssessed) | $($c.NotApplicable) |")
    foreach ($k in $areaTitle.Keys) {
        $set = @($rows | Where-Object { $_.Area -eq $k })
        if ($set.Count -eq 0) { continue }
        $null = $md.AppendLine()
        $null = $md.AppendLine("## $($areaTitle[$k].Title)")
        $null = $md.AppendLine()
        $null = $md.AppendLine('| Check | Title | Result | What the run found | What to set |')
        $null = $md.AppendLine('|---|---|---|---|---|')
        foreach ($r in $set) {
            $found = [string]$r.Detail
            $items = @($r.Items | Where-Object { $null -ne $_ })
            if ($items.Count) { $found += ' ' + (@($items | Select-Object -First 10 | ForEach-Object { "$([string](Get-TPObjectField -Item $_ -Key 'Name' -Default '')): $([string](Get-TPObjectField -Item $_ -Key 'Note' -Default ''))" }) -join '; ') }
            $fix = if ($r.Status -eq 'Fail') { [string]$r.Recommended } else { '' }
            $null = $md.AppendLine("| ``$($r.Id)`` | $(EscMd $r.Title) | $(EscMd $r.StatusLabel) | $(EscMd $found) | $(EscMd $fix) |")
        }
    }
    $null = $md.AppendLine()
    $null = $md.AppendLine("_Generated $($GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)) UTC by TenantPosture $(EscMd $ToolVersion). Checks follow Maester ($(EscMd $Model.MaesterReference))._")

    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    Set-TPSensitiveFileContent -Path $mdPath -Content $md.ToString()
    return [ordered]@{ Html = $htmlPath; Markdown = $mdPath }
}

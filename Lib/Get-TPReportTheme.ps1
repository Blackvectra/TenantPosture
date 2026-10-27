#Requires -Version 7.0
#
# Get-TPReportTheme.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: One look for the MSP deliverables (the fleet dashboard, the proof of
#   fix and the onboarding report): the stylesheet and the small HTML builders
#   they share (status pill, KPI card, inline-SVG sparkline and bar, section
#   header, footer, document shell). Nothing else uses it yet; the assessment
#   report keeps its own styling.
#
# Rules (pinned by TP.ReportTheme.Tests.ps1):
#   - Self-contained. No font, stylesheet, script or image is loaded from
#     anywhere; charts are inline SVG and the system font stack is used. The
#     document shell carries a Content-Security-Policy that forbids all of it.
#   - Light and dark (prefers-color-scheme), and a print stylesheet that always
#     prints the light palette on white, with a page break between sections.
#   - WCAG AA. Every text/background pair the theme defines is listed in
#     ContrastPairs and meets 4.5:1 (3:1 for non-text marks). The brand color
#     from the loaded profile is an ACCENT only, and it is darkened (light
#     scheme) or lightened (dark scheme) until it meets 4.5:1 against the
#     surfaces it is drawn on; a color that is not #rrggbb falls back to a safe
#     default rather than reaching the stylesheet.
#   - Status is never color alone: a pill carries an icon glyph and a word.
#   - No year is written into the theme. The footer prints the generation date
#     it is handed (UTC) and the tool version.
#   - Every value that reaches markup through these builders is HTML-encoded
#     (ConvertTo-TPHtmlSafe); numbers are formatted with the invariant culture.
#
# Data consumed: the loaded profile ($script:TPBrand: CompanyName,
#   PrimaryColor). Data set: none. Graph scopes / cmdlets used: none.

# A color the stylesheet may use: '#rrggbb', lower-case, or the fallback.
function ConvertTo-TPThemeHexColor {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Value,
        [Parameter(Mandatory)] [string] $Fallback
    )
    if ($Value -cmatch '\A#[0-9A-Fa-f]{6}\z') { return $Value.ToLowerInvariant() }
    return $Fallback.ToLowerInvariant()
}

# WCAG 2.x relative luminance of '#rrggbb'.
function Get-TPThemeLuminance {
    [CmdletBinding()]
    [OutputType([double])]
    param([Parameter(Mandatory)] [string] $Color)
    $hex = $Color.TrimStart('#')
    $channels = foreach ($i in 0, 2, 4) {
        $c = [Convert]::ToInt32($hex.Substring($i, 2), 16) / 255.0
        if ($c -le 0.03928) { $c / 12.92 } else { [math]::Pow(($c + 0.055) / 1.055, 2.4) }
    }
    return (0.2126 * $channels[0]) + (0.7152 * $channels[1]) + (0.0722 * $channels[2])
}

# WCAG 2.x contrast ratio between two '#rrggbb' colors (1 to 21).
function Get-TPThemeContrastRatio {
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory)] [string] $Foreground,
        [Parameter(Mandatory)] [string] $Background
    )
    $l1 = Get-TPThemeLuminance -Color $Foreground
    $l2 = Get-TPThemeLuminance -Color $Background
    $hi = [math]::Max($l1, $l2); $lo = [math]::Min($l1, $l2)
    return ($hi + 0.05) / ($lo + 0.05)
}

# Moves a color toward black or white in small steps until it meets the
# minimum contrast against every background given. Toward black on a light
# scheme, toward white on a dark one; a color that already passes is kept.
function Resolve-TPThemeAccent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Color,
        [Parameter(Mandatory)] [string[]] $Backgrounds,
        [Parameter(Mandatory)] [ValidateSet('Darken', 'Lighten')] [string] $Direction,
        [double] $Minimum = 4.5
    )
    $target = if ($Direction -eq 'Darken') { @(0, 0, 0) } else { @(255, 255, 255) }
    $hex = $Color.TrimStart('#')
    $rgb = @(foreach ($i in 0, 2, 4) { [Convert]::ToInt32($hex.Substring($i, 2), 16) })
    for ($step = 0; $step -le 20; $step++) {
        $t = $step / 20.0
        $mix = @(for ($k = 0; $k -lt 3; $k++) { [int][math]::Round($rgb[$k] + (($target[$k] - $rgb[$k]) * $t)) })
        $candidate = '#{0:x2}{1:x2}{2:x2}' -f $mix[0], $mix[1], $mix[2]
        $ok = $true
        foreach ($bg in $Backgrounds) { if ((Get-TPThemeContrastRatio -Foreground $candidate -Background $bg) -lt $Minimum) { $ok = $false; break } }
        if ($ok) { return $candidate }
    }
    return $(if ($Direction -eq 'Darken') { '#000000' } else { '#ffffff' })
}

function Get-TPReportTheme {
    <#
    .SYNOPSIS
        The shared stylesheet and palette for the MSP deliverables.
    .DESCRIPTION
        Returns an ordered dictionary: Css (the whole stylesheet), CompanyName
        (from the profile, or 'TenantPosture'), Light and Dark (the palette per
        scheme, accent included) and ContrastPairs (every foreground/background
        pair the theme draws, with the minimum ratio it must meet). The brand
        color comes from -Brand, or the loaded profile when -Brand is omitted.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] [object] $Brand)

    Set-StrictMode -Version Latest

    if (-not $PSBoundParameters.ContainsKey('Brand')) {
        $Brand = if ((Get-Variable -Name TPBrand -Scope Script -ErrorAction SilentlyContinue)) { $script:TPBrand } else { $null }
    }
    $company = ([string](Get-TPObjectField -Item $Brand -Key 'CompanyName' -Default '')).Trim()
    if (-not $company) { $company = 'TenantPosture' }
    $brandColor = ConvertTo-TPThemeHexColor -Value ([string](Get-TPObjectField -Item $Brand -Key 'PrimaryColor' -Default '')) -Fallback '#1f4e8c'

    $light = [ordered]@{
        Bg = '#f6f8fb'; Card = '#ffffff'; Text = '#18202b'; Muted = '#4b5565'; Border = '#d5dbe3'; Track = '#e3e8ef'
        GoodFg = '#0f5c2e'; GoodBg = '#dcf5e4'; WarnFg = '#6e4500'; WarnBg = '#fff0c7'
        BadFg = '#9a1028'; BadBg = '#ffe1e5'; NeutralFg = '#3a4452'; NeutralBg = '#eceff4'
        InfoFg = '#0b4a99'; InfoBg = '#e0ecff'
    }
    $dark = [ordered]@{
        Bg = '#0e1319'; Card = '#161d27'; Text = '#e7ebf1'; Muted = '#a9b4c3'; Border = '#2c3644'; Track = '#253040'
        GoodFg = '#86e0a9'; GoodBg = '#123323'; WarnFg = '#ffd27a'; WarnBg = '#3a2b07'
        BadFg = '#ffa3ad'; BadBg = '#3e121b'; NeutralFg = '#c5ceda'; NeutralBg = '#252f3b'
        InfoFg = '#a4c8ff'; InfoBg = '#112a4d'
    }
    $light['Accent'] = Resolve-TPThemeAccent -Color $brandColor -Backgrounds @($light.Bg, $light.Card) -Direction Darken
    $dark['Accent']  = Resolve-TPThemeAccent -Color $brandColor -Backgrounds @($dark.Bg, $dark.Card) -Direction Lighten

    $pairs = [System.Collections.Generic.List[object]]::new()
    foreach ($scheme in @(@{ Name = 'light'; P = $light }, @{ Name = 'dark'; P = $dark })) {
        $pal = $scheme.P
        foreach ($bg in 'Bg', 'Card') {
            foreach ($fg in 'Text', 'Muted', 'Accent') {
                $pairs.Add([ordered]@{ Scheme = $scheme.Name; Foreground = $pal[$fg]; Background = $pal[$bg]; Use = "$fg on $bg"; Minimum = 4.5 })
            }
        }
        foreach ($s in 'Good', 'Warn', 'Bad', 'Neutral', 'Info') {
            $pairs.Add([ordered]@{ Scheme = $scheme.Name; Foreground = $pal["${s}Fg"]; Background = $pal["${s}Bg"]; Use = "$s status text on its pill"; Minimum = 4.5 })
            # The same color is used for the bar and sparkline marks on a card.
            $pairs.Add([ordered]@{ Scheme = $scheme.Name; Foreground = $pal["${s}Fg"]; Background = $pal.Card; Use = "$s status mark on a card"; Minimum = 3.0 })
        }
    }

    $vars = {
        param($pal)
        return ("--tp-bg:{0};--tp-card:{1};--tp-text:{2};--tp-muted:{3};--tp-border:{4};--tp-track:{5};--tp-accent:{6};" -f $pal.Bg, $pal.Card, $pal.Text, $pal.Muted, $pal.Border, $pal.Track, $pal.Accent) +
               ("--tp-good-fg:{0};--tp-good-bg:{1};--tp-warn-fg:{2};--tp-warn-bg:{3};--tp-bad-fg:{4};--tp-bad-bg:{5};--tp-neutral-fg:{6};--tp-neutral-bg:{7};--tp-info-fg:{8};--tp-info-bg:{9};" -f $pal.GoodFg, $pal.GoodBg, $pal.WarnFg, $pal.WarnBg, $pal.BadFg, $pal.BadBg, $pal.NeutralFg, $pal.NeutralBg, $pal.InfoFg, $pal.InfoBg)
    }
    $lightVars = & $vars $light
    $darkVars  = & $vars $dark

    $css = @'
:root{color-scheme:light dark;{{LIGHT}}--tp-radius:14px;--tp-radius-sm:9px;--tp-gap:20px;--tp-font:system-ui,-apple-system,"Segoe UI Variable Text","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;--tp-mono:ui-monospace,"Cascadia Code","SF Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{{{DARK}}}}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--tp-bg);color:var(--tp-text);font:16px/1.55 var(--tp-font);font-variant-numeric:tabular-nums}
.tp-page{max-width:1180px;margin:0 auto;padding:32px 20px 48px}
a{color:var(--tp-accent);text-underline-offset:3px}
a:focus-visible,summary:focus-visible{outline:3px solid var(--tp-accent);outline-offset:2px;border-radius:4px}
h1,h2,h3{line-height:1.2;margin:0;font-weight:650;letter-spacing:-.01em}
h1{font-size:2rem}
h2{font-size:1.35rem}
h3{font-size:1.05rem}
p{margin:.5em 0}
code,.tp-mono{font-family:var(--tp-mono);font-size:.9em}
.tp-masthead{display:flex;flex-wrap:wrap;gap:12px 32px;align-items:flex-end;justify-content:space-between;padding:22px 24px;margin-bottom:var(--tp-gap);background:var(--tp-card);border:1px solid var(--tp-border);border-left:6px solid var(--tp-accent);border-radius:var(--tp-radius)}
.tp-brand{font-size:.8rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--tp-accent);margin-bottom:6px}
.tp-subtitle{color:var(--tp-muted);margin-top:6px;max-width:68ch}
.tp-meta{display:flex;flex-wrap:wrap;gap:8px}
.tp-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border:1px solid var(--tp-border);border-radius:999px;font-size:.82rem;color:var(--tp-muted);background:var(--tp-bg)}
.tp-banner{padding:14px 18px;margin:0 0 var(--tp-gap);border-radius:var(--tp-radius-sm);border:1px solid var(--tp-border);background:var(--tp-card)}
.tp-banner--warn{background:var(--tp-warn-bg);color:var(--tp-warn-fg);border-color:transparent}
.tp-banner--info{background:var(--tp-info-bg);color:var(--tp-info-fg);border-color:transparent}
.tp-banner--bad{background:var(--tp-bad-bg);color:var(--tp-bad-fg);border-color:transparent}
.tp-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:var(--tp-gap)}
.tp-kpi{background:var(--tp-card);border:1px solid var(--tp-border);border-radius:var(--tp-radius);padding:16px 18px;display:flex;flex-direction:column;gap:4px;min-width:0}
.tp-kpi-label{font-size:.8rem;font-weight:600;color:var(--tp-muted);text-transform:uppercase;letter-spacing:.05em}
.tp-kpi-value{font-size:2rem;font-weight:700;line-height:1.1}
.tp-kpi-note{font-size:.85rem;color:var(--tp-muted)}
.tp-section{margin:0 0 calc(var(--tp-gap)*1.6)}
.tp-section-head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:6px 16px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--tp-border)}
.tp-kicker{font-size:.85rem;color:var(--tp-muted)}
.tp-card{background:var(--tp-card);border:1px solid var(--tp-border);border-radius:var(--tp-radius);padding:18px 20px;min-width:0}
.tp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px}
.tp-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px}
.tp-card-title{font-weight:650;font-size:1.05rem;overflow-wrap:anywhere}
.tp-row{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px}
.tp-big{font-size:2.1rem;font-weight:700;line-height:1}
.tp-muted{color:var(--tp-muted)}
.tp-small{font-size:.86rem}
.tp-kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:10px 0 0;font-size:.9rem}
.tp-kv dt{color:var(--tp-muted)}
.tp-kv dd{margin:0;overflow-wrap:anywhere}
.tp-pill{display:inline-flex;align-items:center;gap:5px;padding:2px 10px 2px 8px;border-radius:999px;font-size:.8rem;font-weight:650;white-space:nowrap;line-height:1.6}
.tp-pill-icon{font-weight:800}
.tp-pill--good{background:var(--tp-good-bg);color:var(--tp-good-fg)}
.tp-pill--warn{background:var(--tp-warn-bg);color:var(--tp-warn-fg)}
.tp-pill--bad{background:var(--tp-bad-bg);color:var(--tp-bad-fg)}
.tp-pill--neutral{background:var(--tp-neutral-bg);color:var(--tp-neutral-fg)}
.tp-pill--info{background:var(--tp-info-bg);color:var(--tp-info-fg)}
.tp-spark{display:block;width:120px;height:34px;color:var(--tp-accent);overflow:visible}
.tp-spark polyline{fill:none;stroke:currentColor;stroke-width:2;stroke-linejoin:round;stroke-linecap:round;vector-effect:non-scaling-stroke}
.tp-spark circle{fill:currentColor}
.tp-bar{display:block;width:100%;height:10px}
.tp-bar .tp-bar-track{fill:var(--tp-track)}
.tp-bar .tp-bar-fill{fill:var(--tp-accent)}
.tp-bar--good .tp-bar-fill{fill:var(--tp-good-fg)}
.tp-bar--warn .tp-bar-fill{fill:var(--tp-warn-fg)}
.tp-bar--bad .tp-bar-fill{fill:var(--tp-bad-fg)}
.tp-table-wrap{overflow-x:auto;border:1px solid var(--tp-border);border-radius:var(--tp-radius);background:var(--tp-card)}
table.tp-table{width:100%;border-collapse:collapse;font-size:.92rem}
.tp-table th,.tp-table td{padding:10px 14px;text-align:left;vertical-align:top;border-bottom:1px solid var(--tp-border)}
.tp-table th{font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;color:var(--tp-muted);font-weight:650;background:var(--tp-card)}
.tp-table tr:last-child td{border-bottom:0}
.tp-table td.tp-num,.tp-table th.tp-num{text-align:right}
.tp-list{margin:.4em 0;padding-left:1.2em}
.tp-list li{margin:.25em 0}
details{margin:.4em 0}
summary{cursor:pointer;color:var(--tp-accent);font-weight:600}
.tp-note{font-size:.88rem;color:var(--tp-muted);max-width:90ch}
.tp-footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--tp-border);font-size:.82rem;color:var(--tp-muted);display:flex;flex-wrap:wrap;gap:6px 18px;justify-content:space-between}
@media (max-width:640px){.tp-page{padding:20px 16px 36px}h1{font-size:1.6rem}.tp-kpi-value{font-size:1.6rem}.tp-big{font-size:1.7rem}}
@media print{
:root{{{LIGHT}}}
body{background:#ffffff;font-size:11pt}
.tp-page{max-width:none;padding:0}
.tp-masthead,.tp-card,.tp-kpi,.tp-table-wrap{background:#ffffff}
.tp-section{break-before:page}
.tp-section.tp-section--first,.tp-masthead+.tp-section{break-before:auto}
.tp-card,.tp-kpi,tr,.tp-banner{break-inside:avoid}
h2,h3{break-after:avoid}
.tp-table-wrap{overflow:visible}
a{color:var(--tp-text);text-decoration:none}
.tp-noprint{display:none}
details>*{display:block}
@page{margin:14mm}
}
'@
    $css = $css.Replace('{{LIGHT}}', $lightVars).Replace('{{DARK}}', $darkVars)

    return [ordered]@{
        Css           = $css
        CompanyName   = $company
        BrandColor    = $brandColor
        Light         = $light
        Dark          = $dark
        ContrastPairs = $pairs.ToArray()
    }
}

# A status pill: an icon glyph and a word, never color alone.
function New-TPThemePill {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidateSet('Good', 'Warn', 'Bad', 'Neutral', 'Info')] [string] $Status,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text
    )
    $icon = switch ($Status) {
        'Good'    { '&#10003;' }
        'Warn'    { '!' }
        'Bad'     { '&#10005;' }
        'Neutral' { '&#8211;' }
        'Info'    { 'i' }
    }
    return ('<span class="tp-pill tp-pill--{0}"><span class="tp-pill-icon" aria-hidden="true">{1}</span>{2}</span>' -f $Status.ToLowerInvariant(), $icon, (ConvertTo-TPHtmlSafe $Text))
}

# A KPI card: label, value, optional note and pill. -ValueHtml is for a value
# the caller already built from these helpers; plain text goes in -Value.
function New-TPThemeKpi {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Label,
        [AllowNull()] [object] $Value,
        [AllowEmptyString()] [string] $Note = '',
        [AllowEmptyString()] [string] $PillHtml = ''
    )
    $v = if ($null -eq $Value) { '&#8211;' } elseif ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) { ConvertTo-TPHtmlSafe ([string]::Format([cultureinfo]::InvariantCulture, '{0}', $Value)) } else { ConvertTo-TPHtmlSafe ([string]$Value) }
    $noteHtml = if ($Note) { '<div class="tp-kpi-note">' + (ConvertTo-TPHtmlSafe $Note) + '</div>' } else { '' }
    return ('<div class="tp-kpi"><div class="tp-kpi-label">{0}</div><div class="tp-kpi-value">{1}</div>{2}{3}</div>' -f (ConvertTo-TPHtmlSafe $Label), $v, $noteHtml, $PillHtml)
}

# An inline-SVG sparkline over 0..-Max (a score is 0..100). One value draws a
# dot; none draws nothing. -Label is the accessible description, and it is the
# text a reader without the chart gets, so it must carry the values.
function New-TPThemeSparkline {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [AllowEmptyCollection()] [double[]] $Values,
        [Parameter(Mandatory)] [string] $Label,
        [double] $Max = 100
    )
    $vals = @($Values | Where-Object { $null -ne $_ })
    if ($vals.Count -eq 0 -or $Max -le 0) { return '' }
    $w = 120.0; $h = 34.0; $pad = 3.0
    $inv = [cultureinfo]::InvariantCulture
    $pts = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $vals.Count; $i++) {
        $x = if ($vals.Count -eq 1) { $w / 2 } else { $pad + (($w - 2 * $pad) * $i / ($vals.Count - 1)) }
        $v = [math]::Min([math]::Max([double]$vals[$i], 0), $Max)
        $y = $h - $pad - (($h - 2 * $pad) * $v / $Max)
        $pts.Add(([string]::Format($inv, '{0:0.##},{1:0.##}', $x, $y)))
    }
    $last = $pts[$pts.Count - 1].Split(',')
    $line = if ($pts.Count -gt 1) { '<polyline points="' + ($pts -join ' ') + '"/>' } else { '' }
    return ('<svg class="tp-spark" viewBox="0 0 120 34" role="img" aria-label="{0}"><title>{0}</title>{1}<circle cx="{2}" cy="{3}" r="3"/></svg>' -f (ConvertTo-TPHtmlSafe $Label), $line, $last[0], $last[1])
}

# An inline-SVG horizontal bar for Value out of Max.
function New-TPThemeBar {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [double] $Value,
        [Parameter(Mandatory)] [double] $Max,
        [Parameter(Mandatory)] [string] $Label,
        [ValidateSet('', 'Good', 'Warn', 'Bad')] [string] $Status = ''
    )
    $pct = if ($Max -gt 0) { [math]::Min([math]::Max($Value / $Max, 0), 1) * 100 } else { 0 }
    $cls = if ($Status) { ' tp-bar--' + $Status.ToLowerInvariant() } else { '' }
    $width = [string]::Format([cultureinfo]::InvariantCulture, '{0:0.##}', $pct)
    return ('<svg class="tp-bar{0}" viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label="{1}"><title>{1}</title><rect class="tp-bar-track" x="0" y="0" width="100" height="10" rx="5"/><rect class="tp-bar-fill" x="0" y="0" width="{2}" height="10" rx="5"/></svg>' -f $cls, (ConvertTo-TPHtmlSafe $Label), $width)
}

# A section: header (title, optional kicker) and the body the caller built.
function New-TPThemeSection {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidatePattern('\A[a-z][a-z0-9-]{0,40}\z')] [string] $Id,
        [Parameter(Mandatory)] [string] $Title,
        [AllowEmptyString()] [string] $Kicker = '',
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $BodyHtml,
        [switch] $First
    )
    $k = if ($Kicker) { '<div class="tp-kicker">' + (ConvertTo-TPHtmlSafe $Kicker) + '</div>' } else { '' }
    $cls = if ($First) { 'tp-section tp-section--first' } else { 'tp-section' }
    return ('<section class="{0}" id="{1}" aria-labelledby="{1}-h"><div class="tp-section-head"><h2 id="{1}-h">{2}</h2>{3}</div>{4}</section>' -f $cls, $Id, (ConvertTo-TPHtmlSafe $Title), $k, $BodyHtml)
}

# The footer: generation time (UTC) and tool version, never a fixed year.
function New-TPThemeFooter {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [datetime] $GeneratedAt,
        [AllowEmptyString()] [string] $ToolVersion = '',
        [AllowEmptyString()] [string] $Note = '',
        [AllowEmptyString()] [string] $CompanyName = ''
    )
    $when = $GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) + ' UTC'
    $ver = if ($ToolVersion) { 'TenantPosture ' + $ToolVersion } else { 'TenantPosture' }
    $left = 'Generated ' + $when + ' &#183; ' + (ConvertTo-TPHtmlSafe $ver)
    if ($CompanyName) { $left += ' &#183; ' + (ConvertTo-TPHtmlSafe $CompanyName) }
    $right = if ($Note) { '<span>' + (ConvertTo-TPHtmlSafe $Note) + '</span>' } else { '' }
    return ('<footer class="tp-footer"><span>{0}</span>{1}</footer>' -f $left, $right)
}

# The masthead: brand name, title, subtitle and metadata chips.
function New-TPThemeMasthead {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $CompanyName,
        [Parameter(Mandatory)] [string] $Title,
        [AllowEmptyString()] [string] $Subtitle = '',
        [AllowNull()] [AllowEmptyCollection()] [string[]] $Chips = @()
    )
    $sub = if ($Subtitle) { '<p class="tp-subtitle">' + (ConvertTo-TPHtmlSafe $Subtitle) + '</p>' } else { '' }
    $chipHtml = (@($Chips | Where-Object { $_ } | ForEach-Object { '<span class="tp-chip">' + (ConvertTo-TPHtmlSafe $_) + '</span>' }) -join '')
    return ('<header class="tp-masthead"><div><div class="tp-brand">{0}</div><h1>{1}</h1>{2}</div><div class="tp-meta">{3}</div></header>' -f (ConvertTo-TPHtmlSafe $CompanyName), (ConvertTo-TPHtmlSafe $Title), $sub, $chipHtml)
}

# The document shell. Self-contained: the policy forbids every external load
# (no script at all, inline styles only, images only as data: URIs).
function New-TPThemeDocument {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [object] $Theme,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $BodyHtml
    )
    $css = [string](Get-TPObjectField -Item $Theme -Key 'Css' -Default '')
    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>$(ConvertTo-TPHtmlSafe $Title)</title>
<style>$css</style>
</head>
<body>
<main class="tp-page">
$BodyHtml
</main>
</body>
</html>
"@
}

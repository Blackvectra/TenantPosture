#Requires -Version 7.0
#
# TP.ReportTheme.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards Lib/Get-TPReportTheme.ps1, the one look shared by the fleet
# dashboard, the proof of fix and the onboarding report:
#   - light, dark and print stylesheets are all present, and print is light
#     on white with a page break between sections
#   - every text/background pair the theme draws passes WCAG AA, checked by a
#     contrast computation written here, independently of the theme's own,
#     for the default brand and for brand colors chosen to be awkward
#   - a brand color that is not #rrggbb never reaches the stylesheet
#   - nothing the theme renders loads an external asset or a script
#   - no year is written into the theme; the footer prints the date it is given
#   - status pills carry an icon and a word, and every builder escapes
#   - the existing assessment report is not restyled by this change
# Data keys consumed: none. Graph scopes / cmdlets: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Mod = Get-Module TenantPosture
    $script:InMod = { param([scriptblock] $Sb, [object[]] $ArgList = @()) & $script:Mod $Sb @ArgList }

    # WCAG 2.x, written here so the theme is not checked against itself.
    $script:Ratio = {
        param([string] $A, [string] $B)
        $lum = {
            param([string] $hex)
            $h = $hex.TrimStart('#')
            $vals = foreach ($i in 0, 2, 4) {
                $c = [Convert]::ToInt32($h.Substring($i, 2), 16) / 255.0
                if ($c -le 0.03928) { $c / 12.92 } else { [math]::Pow(($c + 0.055) / 1.055, 2.4) }
            }
            0.2126 * $vals[0] + 0.7152 * $vals[1] + 0.0722 * $vals[2]
        }
        $la = & $lum $A; $lb = & $lum $B
        ([math]::Max($la, $lb) + 0.05) / ([math]::Min($la, $lb) + 0.05)
    }
    $script:Theme = { param($brand) & $script:Mod { param($b) Get-TPReportTheme -Brand $b } $brand }
    $script:RenderAll = {
        param([datetime] $When)
        & $script:Mod {
            param($When)
            $t = Get-TPReportTheme -Brand @{ CompanyName = 'Contoso Managed IT'; PrimaryColor = '#2563eb' }
            $body = (New-TPThemeMasthead -CompanyName $t.CompanyName -Title 'T' -Subtitle 'S' -Chips @('a', 'b')) +
                    (New-TPThemeKpi -Label 'K' -Value 5 -Note 'n' -PillHtml (New-TPThemePill -Status Good -Text 'ok')) +
                    (New-TPThemeSection -Id 'one' -Title 'One' -Kicker 'k' -BodyHtml ((New-TPThemeSparkline -Values 10, 50, 90 -Label 'trend') + (New-TPThemeBar -Value 3 -Max 10 -Label 'bar' -Status Warn)) -First) +
                    (New-TPThemeFooter -GeneratedAt $When -ToolVersion '9.9.9' -CompanyName $t.CompanyName -Note 'note')
            New-TPThemeDocument -Title 'Doc' -Theme $t -BodyHtml $body
        } $When
    }
}

AfterAll {
    Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue
}

Describe 'Report theme: light, dark and print' {
    It 'defines the palette for light, overrides it for dark, and prints light on white' {
        $t = & $script:Theme @{ PrimaryColor = '#1a3a6b' }
        $t.Css | Should -Match '@media \(prefers-color-scheme:dark\)\{:root\{--tp-bg:#0e1319'
        $t.Css | Should -Match ':root\{color-scheme:light dark;--tp-bg:#f6f8fb'
        $print = [regex]::Match($t.Css, '(?s)@media print\{(.*)\}\s*\z').Groups[1].Value
        $print | Should -Not -BeNullOrEmpty
        $print | Should -Match ':root\{--tp-bg:#f6f8fb;--tp-card:#ffffff'
        $print | Should -Match 'body\{background:#ffffff'
        $print | Should -Match '\.tp-section\{break-before:page\}'
        $print | Should -Match '@page\{margin:14mm\}'
        $print | Should -Not -Match '#0e1319|#161d27' -Because 'a dark background never prints'
    }
    It 'uses the system font stack and loads no font' {
        $t = & $script:Theme $null
        $t.Css | Should -Match '--tp-font:system-ui'
        $t.Css | Should -Not -Match '@font-face|@import|url\('
    }
}

Describe 'Report theme: contrast (WCAG AA)' {
    It 'every pair passes for brand color <Color>' -ForEach @(
        @{ Color = '#1a3a6b' }, @{ Color = '#ffcc00' }, @{ Color = '#ffffff' }, @{ Color = '#000000' },
        @{ Color = '#e87722' }, @{ Color = '#7fffd4' }, @{ Color = '#2563eb' }, @{ Color = 'not-a-color' }
    ) {
        $t = & $script:Theme @{ PrimaryColor = $Color }
        @($t.ContrastPairs).Count | Should -BeGreaterThan 30
        foreach ($p in $t.ContrastPairs) {
            $r = & $script:Ratio $p.Foreground $p.Background
            $r | Should -BeGreaterOrEqual $p.Minimum -Because "$($p.Scheme) $($p.Use): $($p.Foreground) on $($p.Background) is $([math]::Round($r, 2)):1"
        }
        # Text on a surface needs 4.5:1, not the 3:1 allowed for a mark.
        @($t.ContrastPairs | Where-Object { $_.Use -match ' on (Bg|Card)$|pill$' -and $_.Minimum -lt 4.5 }).Count | Should -Be 0
    }
    It 'the accent the stylesheet uses is the one that was checked, in both schemes' {
        $t = & $script:Theme @{ PrimaryColor = '#ffcc00' }
        $t.Css | Should -Match ([regex]::Escape("--tp-accent:$($t.Light.Accent);"))
        $t.Css | Should -Match ([regex]::Escape("--tp-accent:$($t.Dark.Accent);"))
        $t.Light.Accent | Should -Not -Be '#ffcc00' -Because 'yellow on white fails 4.5:1 and is darkened'
    }
    It 'a brand color that is not #rrggbb never reaches the stylesheet' {
        $t = & $script:Theme @{ PrimaryColor = '#123456;}body{visibility:collapse' }
        $t.Css | Should -Not -Match 'visibility:collapse'
        $t.BrandColor | Should -Be '#1f4e8c'
    }
}

Describe 'Report theme: self-contained output' {
    It 'renders a document that loads nothing and runs nothing' {
        $html = & $script:RenderAll ([datetime]::new(2041, 3, 4, 5, 6, 0, [DateTimeKind]::Utc))
        $html | Should -Match "Content-Security-Policy"
        $html | Should -Match "default-src 'none'"
        $html | Should -Not -Match '(?i)<script|<link|<img|<iframe|@import|url\('
        $html | Should -Not -Match '(?i)(https?:)?//[a-z0-9]' -Because 'no external URL, not even the SVG namespace'
        $html | Should -Match '<meta name="color-scheme" content="light dark">'
    }
    It 'writes no year: the source holds none, and the footer prints the date it is given' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Get-TPReportTheme.ps1') -Raw
        $src | Should -Not -Match '\b(19|20)\d{2}\b'
        $html = & $script:RenderAll ([datetime]::new(2041, 3, 4, 5, 6, 0, [DateTimeKind]::Utc))
        $html | Should -Match 'Generated 2041-03-04 05:06 UTC'
        $html | Should -Match 'TenantPosture 9\.9\.9'
        ([regex]::Matches($html, '\b20\d{2}\b') | ForEach-Object { $_.Value } | Sort-Object -Unique) | Should -Be @('2041')
    }
}

Describe 'Report theme: builders' {
    It 'a pill carries an icon and the word, so status is never color alone' {
        foreach ($s in 'Good', 'Warn', 'Bad', 'Neutral', 'Info') {
            $p = & $script:Mod { param($s) New-TPThemePill -Status $s -Text "$s word" } $s
            $p | Should -Match 'class="tp-pill-icon" aria-hidden="true">[^<]+</span>'
            $p | Should -Match "$s word"
        }
    }
    It 'every builder escapes what it is given' {
        $evil = '<script>alert(1)</script>"&'
        $out = & $script:Mod {
            param($e)
            (New-TPThemePill -Status Bad -Text $e) + (New-TPThemeKpi -Label $e -Value $e -Note $e) +
            (New-TPThemeSparkline -Values 1, 2 -Label $e) + (New-TPThemeBar -Value 1 -Max 2 -Label $e) +
            (New-TPThemeSection -Id 'x' -Title $e -Kicker $e -BodyHtml '') + (New-TPThemeFooter -GeneratedAt (Get-Date) -ToolVersion $e -Note $e -CompanyName $e) +
            (New-TPThemeMasthead -CompanyName $e -Title $e -Subtitle $e -Chips @($e))
        } $evil
        $out | Should -Not -Match '<script'
        $out | Should -Match '&lt;script&gt;'
    }
    It 'a section id is a plain token' {
        { & $script:Mod { New-TPThemeSection -Id 'x" onload="y' -Title 't' -BodyHtml '' } } | Should -Throw
    }
    It 'a sparkline of no values is empty, of one value a note (one point is not a trend), and clamps out-of-range values' {
        (& $script:Mod { New-TPThemeSparkline -Values @() -Label 'x' }) | Should -BeNullOrEmpty
        $one = & $script:Mod { New-TPThemeSparkline -Values 50 -Label 'x' }
        $one | Should -Not -Match '<svg'
        $one | Should -Match 'Trend after the next full run'
        $clamped = & $script:Mod { New-TPThemeSparkline -Values -20, 400 -Label 'x' }
        $clamped | Should -Match 'points="3,31 117,3"'
    }
    It 'numbers are formatted with the invariant culture' {
        $prev = [cultureinfo]::CurrentCulture
        try {
            [cultureinfo]::CurrentCulture = [cultureinfo]::GetCultureInfo('de-DE')
            (& $script:Mod { New-TPThemeBar -Value 1 -Max 3 -Label 'x' }) | Should -Match 'width="33\.33"'
        } finally { [cultureinfo]::CurrentCulture = $prev }
    }
}

Describe 'Report theme: scope of this change' {
    It 'the existing assessment report is not restyled' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Publishers/Publish-TPAssessmentHTML.ps1') -Raw
        $src | Should -Not -Match 'Get-TPReportTheme|New-TPTheme'
    }
    It 'the three MSP deliverables use it' {
        foreach ($f in 'Publish-TPFleetDashboard.ps1', 'Publish-TPRemediationProof.ps1', 'Publish-TPOnboardingReport.ps1') {
            (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Publishers' $f) -Raw) | Should -Match 'Get-TPReportTheme'
        }
    }
}

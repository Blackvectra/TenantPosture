#Requires -Version 7.0
#
# NRG.MonthlyReport.Tests.ps1
#
# Pins behavior of Publishers/Publish-NRGMonthlyReport.ps1 — the v4.11.0
# monthly compliance report publisher. Confirms the publisher emits HTML
# + JSON state, handles missing prior-month gracefully (baseline note),
# renders trend deltas when prior present, and falls back when the
# delta file is malformed.

Describe 'Publish-NRGMonthlyReport' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGCoverageScore.ps1')
        . (Join-Path $script:RepoRoot 'Publishers' 'Publish-NRGMonthlyReport.ps1')

        $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-monthly-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Force -LiteralPath $script:tmp | Out-Null

        # Minimal delta fixture
        $script:deltaPath = Join-Path $script:tmp 'delta.psd1'
        @"
@{
    Period      = 'May 2026'
    EntityType  = 'Behavioral Health · HIPAA Covered Entity'
    TLP         = 'AMBER'
    NewlyCompleted = @(
        @{ Service = 'Baseline assessment delivered';                    ControlId = '' }
        @{ Service = 'HIPAA mapping completed';                          ControlId = '' }
    )
    MovedToProgress = @(
        @{ Service = 'Phishing-resistant MFA for administrators';        ControlId = 'AAD-1.3' }
        @{ Service = 'Conditional Access policy deployment';             ControlId = 'AAD-2.1' }
    )
    AddedToQueue = @(
        @{ Service = 'Managed Detection & Response deployment';          ControlId = 'INT-2.1' }
    )
}
"@ | Out-File -LiteralPath $script:deltaPath -Encoding utf8

        # Findings fixture — small but covers the score formula + counts
        $script:findings = @(
            @{ State='Satisfied'; Severity='Medium'; ControlId='AAD-1.1' }
            @{ State='Satisfied'; Severity='Medium'; ControlId='EXO-1.1' }
            @{ State='Gap';       Severity='Critical'; ControlId='AAD-1.3' }
            @{ State='Gap';       Severity='High';     ControlId='EXO-6.1' }
            @{ State='Partial';   Severity='High';     ControlId='AAD-2.1' }
            @{ State='NotApplicable'; Severity='Low'; ControlId='SPO-1.1' }
        )

        $script:metadata = @{
            TenantDomain   = 'cornerpostcounseling.com'
            ClientName     = 'Cornerpost Counseling'
            AssessmentDate = 'May 31, 2026'
            ToolVersion    = '4.11.0'
            Brand          = @{ CompanyName = 'NRG Technology Services / NextLayerSec LLC' }
            Maturity       = @{
                Tier=2; Score=50; CriticalGaps=1; HighGaps=1; ScoredControls=5
                Satisfied=2; Partial=1; Gap=2; NotApplicable=1; ErrorFindings=0
            }
        }
    }

    AfterAll {
        if ($script:tmp -and (Test-Path -LiteralPath $script:tmp)) {
            Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'First-month (baseline period) — no prior' {
        It 'Emits HTML + JSON outputs and returns a result object' {
            $out = Join-Path $script:tmp 'monthly-may.html'
            $r = Publish-NRGMonthlyReport `
                -Findings $script:findings `
                -Metadata $script:metadata `
                -DeltaPath $script:deltaPath `
                -OutputPath $out
            $r.HtmlPath | Should -Be $out
            $r.JsonPath | Should -Be ($out -replace '\.html$', '.json')
            Test-Path -LiteralPath $r.HtmlPath | Should -BeTrue
            Test-Path -LiteralPath $r.JsonPath | Should -BeTrue
        }

        It 'Renders the score from Get-NRGCoverageScore (-ErrorHandling Gap)' {
            $out = Join-Path $script:tmp 'monthly-score.html'
            $r = Publish-NRGMonthlyReport `
                -Findings $script:findings `
                -Metadata $script:metadata `
                -DeltaPath $script:deltaPath `
                -OutputPath $out
            # Expected: 2 Sat + 1 Partial → 2.5 ÷ 5 (Gap mode) × 100 = 50
            $r.Score | Should -Be 50
        }

        It 'Shows the baseline-period note when no PriorMonth is given' {
            $out = Join-Path $script:tmp 'monthly-baseline.html'
            Publish-NRGMonthlyReport `
                -Findings $script:findings `
                -Metadata $script:metadata `
                -DeltaPath $script:deltaPath `
                -OutputPath $out | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'Baseline period'
        }

        It 'JSON state file has the documented shape (next month''s input)' {
            $out = Join-Path $script:tmp 'monthly-json.html'
            Publish-NRGMonthlyReport `
                -Findings $script:findings `
                -Metadata $script:metadata `
                -DeltaPath $script:deltaPath `
                -OutputPath $out | Out-Null
            $json = Get-Content -LiteralPath ($out -replace '\.html$', '.json') -Raw | ConvertFrom-Json -AsHashtable
            $json.Period       | Should -Be 'May 2026'
            $json.TLP          | Should -Be 'AMBER'
            $json.Score        | Should -Be 50
            $json.Counts.Gap   | Should -Be 2
            $json.Counts.CriticalOpen | Should -Be 1
            $json.WorkCompleted.Count | Should -Be 2
            $json.InProgress.Count    | Should -Be 2
            $json.Queued.Count        | Should -Be 1
        }
    }

    Context 'Subsequent month — prior present' {
        It 'Renders a trend note instead of baseline-period note when prior given' {
            # Create a prior-month JSON
            $priorPath = Join-Path $script:tmp 'prior.json'
            @{
                Period = 'April 2026'; Score = 42; EntityType='Behavioral Health'
                Counts = @{ Gap=5; CriticalOpen=2; HighOpen=3 }
            } | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $priorPath -Encoding utf8

            $out = Join-Path $script:tmp 'monthly-trend.html'
            Publish-NRGMonthlyReport `
                -Findings $script:findings `
                -Metadata $script:metadata `
                -DeltaPath $script:deltaPath `
                -PriorMonthPath $priorPath `
                -OutputPath $out | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'Trend vs April 2026'
            # Current score 50 vs prior 42 = +8
            $html | Should -Match '\+8'
            $html | Should -Not -Match 'Baseline period'
        }
    }

    Context 'Defensive input handling' {
        It 'Throws if -DeltaPath references a missing file' {
            $out = Join-Path $script:tmp 'monthly-missing.html'
            { Publish-NRGMonthlyReport `
                -Findings $script:findings `
                -Metadata $script:metadata `
                -DeltaPath (Join-Path $script:tmp 'does-not-exist.psd1') `
                -OutputPath $out } | Should -Throw
        }

        It 'Throws if -DeltaPath attempts path traversal' {
            $out = Join-Path $script:tmp 'monthly-traversal.html'
            { Publish-NRGMonthlyReport `
                -Findings $script:findings `
                -Metadata $script:metadata `
                -DeltaPath '../../etc/passwd' `
                -OutputPath $out } | Should -Throw
        }

        It 'Throws if the delta file is missing required keys' {
            $badDelta = Join-Path $script:tmp 'bad-delta.psd1'
            "@{ NewlyCompleted = @() }" | Out-File -LiteralPath $badDelta -Encoding utf8
            $out = Join-Path $script:tmp 'monthly-bad.html'
            { Publish-NRGMonthlyReport `
                -Findings $script:findings `
                -Metadata $script:metadata `
                -DeltaPath $badDelta `
                -OutputPath $out } | Should -Throw -ExpectedMessage '*missing required key*'
        }

        It 'Renders gracefully with empty findings (no crash, score=0)' {
            $emptyMeta = @{
                TenantDomain='x.com'; ClientName='X'; AssessmentDate='May 31, 2026'
                ToolVersion='4.11.0'; Brand=@{ CompanyName='NRG' }
            }
            $out = Join-Path $script:tmp 'monthly-empty.html'
            $r = Publish-NRGMonthlyReport `
                -Findings @() `
                -Metadata $emptyMeta `
                -DeltaPath $script:deltaPath `
                -OutputPath $out
            $r.Score | Should -Be 0
        }

        It 'Renders gracefully when delta arrays are empty (shows "No items" rows)' {
            $emptyDelta = Join-Path $script:tmp 'empty-delta.psd1'
            "@{ Period='May 2026'; EntityType='X'; TLP='WHITE'; NewlyCompleted=@(); MovedToProgress=@(); AddedToQueue=@() }" `
                | Out-File -LiteralPath $emptyDelta -Encoding utf8
            $out = Join-Path $script:tmp 'monthly-emptydelta.html'
            Publish-NRGMonthlyReport `
                -Findings $script:findings `
                -Metadata $script:metadata `
                -DeltaPath $emptyDelta `
                -OutputPath $out | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            $html | Should -Match 'No items completed this period'
            $html | Should -Match 'No items in progress'
            $html | Should -Match 'No items queued'
        }
    }

    Context 'XSS guard' {
        It 'Escapes HTML in delta Service text to prevent injection' {
            $xssDelta = Join-Path $script:tmp 'xss-delta.psd1'
            @'
@{
    Period='May 2026'; EntityType='HIPAA'; TLP='AMBER'
    NewlyCompleted = @( @{ Service='<script>alert(1)</script>'; ControlId='' } )
    MovedToProgress = @(); AddedToQueue = @()
}
'@ | Out-File -LiteralPath $xssDelta -Encoding utf8
            $out = Join-Path $script:tmp 'monthly-xss.html'
            Publish-NRGMonthlyReport `
                -Findings $script:findings `
                -Metadata $script:metadata `
                -DeltaPath $xssDelta `
                -OutputPath $out | Out-Null
            $html = Get-Content -LiteralPath $out -Raw
            # Raw <script> must not appear unescaped in the table row content
            $html | Should -Not -Match '<script>alert\(1\)</script>'
            # Escaped form must appear
            $html | Should -Match '&lt;script&gt;'
        }
    }
}

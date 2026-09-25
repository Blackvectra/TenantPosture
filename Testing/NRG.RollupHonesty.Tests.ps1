#Requires -Version 7.0
#
# NRG.RollupHonesty.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Numbers derived FROM findings must agree with the score. Found by audit:
#   - the remediation roadmap and the NIST improvement plan made each
#     per-domain DNS finding its own fix (12 steps "worth +38" for a true +19,
#     projected NIST coverage of 119-170%);
#   - the score, the scope section and the SSP each ranked worst-state
#     differently, so one control was a pass in the ring and "not assessed"
#     in the scope section of the same report;
#   - the Executive Overview counted the 35 endpoint checks that report "no
#     endpoint results supplied" as assessed controls;
#   - "All assessed controls are satisfied" printed on a 12/100 report;
#   - reasoned "does not apply" findings were filed as "no automated test".

Describe 'Rollups agree with the score' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        function script:F([string] $Cid, [string] $State, [string] $Instance = '', [string] $Detail = 'x', [string] $Severity = 'Medium') {
            [pscustomobject]@{ ControlId = $Cid; State = $State; Title = $Cid; Severity = $Severity; Category = 'Email'; Instance = $Instance
                               Detail = $Detail; CurrentValue = ''; RequiredValue = ''; Remediation = "fix $Cid"; AffectedObjects = @()
                               FrameworkIds = @(Get-NRGFrameworkCitations -ControlId $Cid) }
        }
        # Three domains missing MTA-STS and TLS-RPT, one control passing.
        $script:Multi = @(
            (F 'DNS-1.4' 'Gap' 'a.test'), (F 'DNS-1.4' 'Gap' 'b.test'), (F 'DNS-1.4' 'Gap' 'c.test'),
            (F 'DNS-1.5' 'Gap' 'a.test'), (F 'DNS-1.5' 'Gap' 'b.test'), (F 'DNS-1.5' 'Gap' 'c.test'),
            (F 'DNS-1.1' 'Satisfied' 'a.test'))
    }

    It 'the roadmap has one step per control and projects the true score' {
        $r = Get-NRGRemediationRoadmap -Findings $script:Multi -LicenseProfile $null
        @($r.QuickWins + $r.LicenseUnlocks).Count | Should -Be 2
        $r.ProjectedScoreAllQuickWins | Should -BeLessOrEqual 100
    }

    It 'the improvement plan has one step per control and never projects above 100%' {
        $p = Get-NRGNISTImprovementPlan -Findings $script:Multi -LicenseProfile $null
        $steps = @($p['Tracks'] | ForEach-Object { @($_['Steps']) })
        $steps.Count | Should -Be 2 -Because 'two controls, however many domains'
        foreach ($s in $steps) { [int]$s['CumulativeScore'] | Should -BeLessOrEqual 100 }
        [int]$p['Projected']['Score'] | Should -BeLessOrEqual 100
    }

    It 'a control passing on one domain and unread on another is not a pass anywhere' {
        $f = @((F 'DNS-1.3' 'Satisfied' 'a.test'), (F 'DNS-1.3' 'NotApplicable' 'b.test' 'The DMARC lookup did not complete.'), (F 'DNS-1.1' 'Gap' 'a.test'))
        (Get-NRGCoverageScore -Findings $f).Satisfied | Should -Be 0
        $s = Get-NRGAssessmentScope -Findings $f
        @($s.CollectionIncomplete | ForEach-Object ControlId) | Should -Contain 'DNS-1.3'
    }

    It 'a reasoned "does not apply" is not filed as "no automated test"' {
        $s = Get-NRGAssessmentScope -Findings @(F 'SPO-2.2' 'NotApplicable' '' 'External sharing is disabled, so Anyone links cannot exist.')
        @($s.NotApplicableToTenant | ForEach-Object ControlId) | Should -Contain 'SPO-2.2'
        @($s.NoProgrammaticCheck | ForEach-Object ControlId) | Should -Not -Contain 'SPO-2.2'
    }

    Context 'report text' {
        BeforeAll {
            function script:Html([object[]] $Findings) {
                Clear-NRGState
                $out = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-roll-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.html')
                Publish-NRGAssessmentHTML -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; Operator = 't'; ToolVersion = 'test' } `
                    -Findings $Findings -Connections @{ Graph = $true } -OutputPath $out -ClientName 'Test Co' | Out-Null
                $h = Get-Content -Raw $out; Remove-Item $out -ErrorAction SilentlyContinue; $h
            }
        }
        It 'the overview does not count endpoint checks with no device data as assessed controls' {
            $dev = @(1..35 | ForEach-Object { F "DEV-9.$_" 'NotApplicable' '' 'No endpoint results supplied.' })
            $h = Html (@((F 'EXO-1.1' 'Satisfied'), (F 'EXO-1.2' 'Gap')) + $dev)
            $h | Should -Match '2 controls assessed &middot; 2 scored &middot; 0 not scored'
            $h | Should -Match 'endpoint checks: 0 of 35 scored'
        }
        It 'does not say "all satisfied" when partial or errored controls remain' {
            $h = Html @((F 'EXO-1.1' 'Partial'), (F 'EXO-1.2' 'Error'))
            $h | Should -Not -Match 'All assessed controls are satisfied'
            $h | Should -Match 'partially configured'
        }
        It 'the Markdown summary table has an Error row, so it adds up to its total' {
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-roll-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.md')
            Publish-NRGAssessmentSummary -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; ToolVersion = 'test' } `
                -Findings @((F 'EXO-1.1' 'Satisfied'), (F 'EXO-1.2' 'Error')) -Connections @{ Graph = $true; EXO = $true; IPPSSession = $false; Teams = $false; SharePoint = $false } -OutputPath $out | Out-Null
            $md = Get-Content -Raw $out; Remove-Item $out -ErrorAction SilentlyContinue
            $md | Should -Match '\| ⛔ Error \(not evaluated; counted as a failure\) \| 1 \|'
        }
    }
}

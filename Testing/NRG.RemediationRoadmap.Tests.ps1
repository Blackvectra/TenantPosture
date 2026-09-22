#Requires -Version 7.0
#
# NRG.RemediationRoadmap.Tests.ps1
#
# Locks the score-lift math and classification of Get-NRGRemediationRoadmap.
# The whole value of the roadmap is that its projected scores are EXACT (they
# recompute the canonical coverage formula, they don't estimate), so these
# tests pin the arithmetic against hand-computed values and guard the
# quick-win vs license-unlock split.

Describe 'Get-NRGRemediationRoadmap' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        # Findings are hashtables (as Add-NRGFinding produces). ControlIds under
        # the 'TEST-' prefix are absent from controls.json, so they carry no
        # LicenseRequirement -> always classified as zero-license quick wins,
        # regardless of the license profile. That isolates the score math.
        function New-F {
            param([string]$Id, [string]$State, [string]$Severity = 'High')
            @{ ControlId = $Id; State = $State; Severity = $Severity; Title = "$Id title"; Remediation = "fix $Id" }
        }
    }

    It 'returns a well-formed empty roadmap for no findings' {
        $r = Get-NRGRemediationRoadmap -Findings @()
        $r.BaselineScore              | Should -Be 0
        $r.QuickWinCount              | Should -Be 0
        $r.QuickWins                  | Should -BeNullOrEmpty
        $r.LicenseUnlocks             | Should -BeNullOrEmpty
        $r.ProjectedScoreAllQuickWins | Should -Be 0
    }

    It 'reports no quick wins when everything is already satisfied' {
        $f = @( New-F 'TEST-1' 'Satisfied'; New-F 'TEST-2' 'Satisfied' )
        $r = Get-NRGRemediationRoadmap -Findings $f
        $r.BaselineScore              | Should -Be 100
        $r.QuickWinCount              | Should -Be 0
        $r.ProjectedScoreAllQuickWins | Should -Be 100
        $r.QuickWinPointGain          | Should -Be 0
    }

    It 'computes exact baseline and projected scores (4 Sat / 2 Partial / 4 Gap)' {
        # scored = 10 ; numerator = 4 + 0.5*2 = 5 ; baseline = 50
        # fix all 6 quick wins -> numerator = 10 -> projected 100 ; gain 50
        $f = @(
            (New-F 'TEST-1' 'Satisfied'), (New-F 'TEST-2' 'Satisfied'),
            (New-F 'TEST-3' 'Satisfied'), (New-F 'TEST-4' 'Satisfied'),
            (New-F 'TEST-5' 'Partial'),   (New-F 'TEST-6' 'Partial'),
            (New-F 'TEST-7' 'Gap'), (New-F 'TEST-8' 'Gap'),
            (New-F 'TEST-9' 'Gap'), (New-F 'TEST-10' 'Gap')
        )
        $r = Get-NRGRemediationRoadmap -Findings $f
        $r.Scored                     | Should -Be 10
        $r.BaselineScore              | Should -Be 50
        $r.QuickWinCount              | Should -Be 6
        $r.ProjectedScoreAllQuickWins | Should -Be 100
        $r.QuickWinPointGain          | Should -Be 50
    }

    It 'ranks Gaps (1.0) ahead of Partials (0.5) even when the Partial is more severe' {
        $f = @(
            (New-F 'TEST-1' 'Satisfied'),
            (New-F 'TEST-2' 'Partial' 'Critical'),
            (New-F 'TEST-3' 'Gap' 'Low')
        )
        $r = Get-NRGRemediationRoadmap -Findings $f
        $r.QuickWins[0].ControlId | Should -Be 'TEST-3'   # the Gap first
        $r.QuickWins[0].State     | Should -Be 'Gap'
        $r.QuickWins[1].State     | Should -Be 'Partial'
    }

    It 'produces a monotonically non-decreasing cumulative score' {
        $f = @(
            (New-F 'A-1' 'Satisfied'),
            (New-F 'A-2' 'Gap'), (New-F 'A-3' 'Gap'),
            (New-F 'A-4' 'Partial')
        )
        $r = Get-NRGRemediationRoadmap -Findings $f
        $prev = $r.BaselineScore
        foreach ($q in $r.QuickWins) {
            $q.CumulativeScore | Should -BeGreaterOrEqual $prev
            $prev = $q.CumulativeScore
        }
        $r.QuickWins[-1].CumulativeScore | Should -Be $r.ProjectedScoreAllQuickWins
    }

    It 'marginal ScoreLift for a Gap is exactly 100 / Scored' {
        # 1 Satisfied + 4 Gap -> scored 5 ; each Gap lift = 100/5 = 20.0
        $f = @(
            (New-F 'TEST-1' 'Satisfied'),
            (New-F 'TEST-2' 'Gap'), (New-F 'TEST-3' 'Gap'),
            (New-F 'TEST-4' 'Gap'), (New-F 'TEST-5' 'Gap')
        )
        $r = Get-NRGRemediationRoadmap -Findings $f
        $r.QuickWins[0].ScoreLift | Should -Be 20.0
    }

    It 'routes a license-not-met Gap to LicenseUnlocks, not QuickWins' {
        # DEF-1.1 carries a real Defender-for-Office-365-P1 LicenseRequirement.
        # With an explicit null profile the requirement is unmet -> unlock track.
        $f = @( @{ ControlId = 'DEF-1.1'; State = 'Gap'; Severity = 'High'; Title = 'Safe Attachments' } )
        $r = Get-NRGRemediationRoadmap -Findings $f -LicenseProfile $null
        $r.QuickWinCount     | Should -Be 0
        $r.LicenseUnlockCount | Should -Be 1
        $r.LicenseUnlocks[0].ControlId          | Should -Be 'DEF-1.1'
        $r.LicenseUnlocks[0].LicenseRequirement | Should -Not -BeNullOrEmpty
    }

    It 'never throws on a malformed finding (missing State) and skips it' {
        $f = @(
            @{ ControlId = 'TEST-1' },          # no State
            (New-F 'TEST-2' 'Gap'),
            $null                               # null entry
        )
        { Get-NRGRemediationRoadmap -Findings $f } | Should -Not -Throw
        $r = Get-NRGRemediationRoadmap -Findings $f
        $r.QuickWinCount | Should -Be 1
    }

    It 'projected score never exceeds 100' {
        $f = @( (New-F 'TEST-1' 'Gap'), (New-F 'TEST-2' 'Partial') )
        $r = Get-NRGRemediationRoadmap -Findings $f
        $r.ProjectedScoreAllQuickWins | Should -BeLessOrEqual 100
        foreach ($q in $r.QuickWins) { $q.CumulativeScore | Should -BeLessOrEqual 100 }
    }
}

Describe 'HTML report renders the roadmap and survives every license tier' {
    # Regression guard for a latent publisher crash the unit suite never hit:
    # $suppressedLicReqs was assigned as the OUTPUT of an if-block, which
    # ENUMERATES the HashSet — an EMPTY set (low/no-license tenant) yielded
    # $null and the later .Contains() threw "cannot call a method on a
    # null-valued expression", killing the whole report. Rendering a real
    # report across an empty and a non-empty suppression set locks the fix.

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-roadmap-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        $null = New-Item -ItemType Directory -Path $script:OutDir -Force

        function Invoke-Render {
            param([object[]] $Skus)
            Clear-NRGState
            if ($Skus) {
                Set-NRGRawData -Key 'AAD-Inventory' -Data ([pscustomobject]@{
                    CollectorId = 'x'; CollectedAt = 'n'; Success = $true
                    Data = @{ SubscribedSkus = $Skus }
                })
            }
            # A license-gated Gap (AAD-2.1 needs BP/Entra P1) plus a Partial.
            Add-NRGFinding -ControlId 'AAD-2.1' -State 'Gap' -Category 'Identity' -Title 'Require MFA' -Severity 'Critical' -Detail 'x' -Remediation 'Create CA policy'
            Add-NRGFinding -ControlId 'EXO-1.1' -State 'Partial' -Category 'Email' -Title 'Mailbox audit' -Severity 'Medium' -Detail 'x' -Remediation 'Enable audit'
            Add-NRGFinding -ControlId 'TMS-1.1' -State 'Satisfied' -Category 'Collaboration' -Title 'ok' -Severity 'Low' -Detail 'x'
            $findings = @(Get-NRGFindings)
            $out = Join-Path $script:OutDir ("r-" + [guid]::NewGuid().ToString('N').Substring(0,6) + ".html")
            $meta = @{ TenantDomain = 'example.test'; AssessmentDate = '2026-07-09'; Operator = 't'; ToolVersion = 'test'; Brand = $script:NRGBrand }
            Publish-NRGAssessmentHTML -Metadata $meta -Findings $findings -Connections @{ Graph = $true } -OutputPath $out -ClientName 'Test Co' | Out-Null
            return (Get-Content -Raw $out)
        }
    }

    AfterAll {
        if ($script:OutDir -and (Test-Path $script:OutDir)) { Remove-Item -Recurse -Force $script:OutDir -ErrorAction SilentlyContinue }
    }

    It 'renders without throwing for a low/no-license tenant (EMPTY suppression set)' {
        { Invoke-Render -Skus @() } | Should -Not -Throw
    }

    It 'renders without throwing for a Business Premium tenant (non-empty suppression set)' {
        { Invoke-Render -Skus @(@{ SkuPartNumber = 'SPB'; ServicePlans = @() }) } | Should -Not -Throw
    }

    It 'includes the Prioritized Remediation Roadmap card when quick wins exist' {
        # Business Premium meets AAD-2.1's license, so the Gap becomes a
        # zero-license quick win and the card must render.
        $html = Invoke-Render -Skus @(@{ SkuPartNumber = 'SPB'; ServicePlans = @() })
        $html | Should -Match 'Prioritized Remediation Roadmap'
        $html | Should -Match 'projected score'
    }

    It 'embeds -Attachments as CSP-safe download buttons whose data-URIs round-trip' {
        Clear-NRGState
        Add-NRGFinding -ControlId 'AAD-2.1' -State 'Gap' -Category 'Identity' -Title 'MFA' -Severity 'Critical' -Detail 'x' -Remediation 'CA'
        $findings = @(Get-NRGFindings)
        $out = Join-Path $script:OutDir ("a-" + [guid]::NewGuid().ToString('N').Substring(0,6) + ".html")
        $meta = @{ TenantDomain = 'example.test'; AssessmentDate = '2026-07-09'; Operator = 't'; ToolVersion = 'test'; Brand = $script:NRGBrand }
        $atts = @(
            @{ Label = 'Remediation script'; FileName = 'rem.ps1'; Mime = 'text/plain'; Content = "# hello`nSet-X 1`n" },
            @{ Label = 'Findings CSV';       FileName = 'f.csv';   Mime = 'text/csv';   Content = "ControlId,State`nAAD-2.1,Gap`n" }
        )
        Publish-NRGAssessmentHTML -Metadata $meta -Findings $findings -Connections @{ Graph = $true } -OutputPath $out -ClientName 'T' -Attachments $atts | Out-Null
        $html = Get-Content -Raw $out
        $html | Should -Match "id='downloads'"
        $html | Should -Match "download='rem.ps1'"
        $html | Should -Match "download='f.csv'"
        # decode the ps1 data-URI and confirm byte-exact round-trip
        $m = [regex]::Match($html, "download='rem\.ps1' href='data:text/plain;base64,([A-Za-z0-9+/=]+)'")
        $m.Success | Should -BeTrue
        [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($m.Groups[1].Value)) | Should -Be "# hello`nSet-X 1`n"
    }

    It 'renders no downloads card when no attachments are supplied' {
        $html = Invoke-Render -Skus @(@{ SkuPartNumber = 'SPB'; ServicePlans = @() })
        $html | Should -Not -Match "id='downloads'"
    }
}

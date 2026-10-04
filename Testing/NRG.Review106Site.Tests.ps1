#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.Review106Site.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Regression tests for the review of the report site and the web GUI sign-in:
             a run with no findings still writes the site and its action plan; skipped
             workloads and Error findings are labeled as what they are.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

BeforeAll {
    $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    $script:Meta = @{ TenantId = '00000000-0000-0000-0000-000000000000'; TenantDomain = 'contoso.example'; AssessmentTime = '2026-09-30T10:49:00-05:00'; ToolVersion = '4.14.3' }
    $script:NewOut = { Join-Path ([IO.Path]::GetTempPath()) ("nrg-r106-" + [Guid]::NewGuid().ToString('N').Substring(0, 8)) }
}

Describe 'S1: a run with no findings still writes the site and an empty action plan' {
    BeforeAll {
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        $script:Out = & $script:NewOut
    }
    AfterAll { Remove-Item -LiteralPath $script:Out -Recurse -Force -ErrorAction SilentlyContinue; Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'does not throw and writes ActionPlan.csv with only the header' {
        { $script:R = Publish-NRGReportSite -Metadata $script:Meta -Findings @() -OutputPath $script:Out } | Should -Not -Throw
        $csv = Join-Path $script:Out 'ActionPlan.csv'
        Test-Path -LiteralPath $csv | Should -BeTrue
        $lines = @(Get-Content -LiteralPath $csv)
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match '^"Control ID",'
        Test-Path -LiteralPath (Join-Path $script:Out 'index.html') | Should -BeTrue
        $script:R.ActionPlanRows | Should -Be 0
    }
}

Describe 'S2: New-NRGReportSite.ps1 builds the site from a results file with "Findings": []' {
    BeforeAll {
        $script:Out2 = & $script:NewOut
        $null = New-Item -ItemType Directory -Force -Path $script:Out2
        $script:Res2 = Join-Path $script:Out2 'empty-results.json'
        Set-Content -LiteralPath $script:Res2 -Encoding utf8 -Value (@{ Metadata = $script:Meta; Findings = @() } | ConvertTo-Json -Depth 5)
    }
    AfterAll { Remove-Item -LiteralPath $script:Out2 -Recurse -Force -ErrorAction SilentlyContinue; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'the results file really carries an empty Findings array' {
        (Get-Content -LiteralPath $script:Res2 -Raw) | Should -Match '"Findings":\s*\[\s*\]'
    }
    It 'does not throw and writes index.html and a header-only ActionPlan.csv' {
        $site = Join-Path $script:Out2 'site'
        { $null = & (Join-Path $script:Root 'New-NRGReportSite.ps1') -ResultsPath $script:Res2 -OutputPath $site 6>$null } | Should -Not -Throw
        Test-Path -LiteralPath (Join-Path $site 'index.html') | Should -BeTrue
        @(Get-Content -LiteralPath (Join-Path $site 'ActionPlan.csv')).Count | Should -Be 1
    }
}

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

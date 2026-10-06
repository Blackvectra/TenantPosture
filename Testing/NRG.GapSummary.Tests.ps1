#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.GapSummary.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: 69 Gap controls are not 69 separate exposures. Get-NRGGapSummary separates the distinct
             requirements from controls that restate another control's shortfall (Config/control-links.json
             "Views") and reports the controls already counted once because they read the same setting.
             The identity Total = Distinct + Views must always hold, and a view of a control with no
             shortfall must stay a distinct requirement.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Gap summary: total Gap controls versus distinct deficiencies' {
    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:F = { param($id, $state) [pscustomobject]@{ ControlId = $id; State = $state; Severity = 'High'; Category = 'X'; Title = $id; FrameworkIds = @() } }
        $script:Sum = { param($f) & (Get-Module NRG-Assessment) { param($x) Get-NRGGapSummary -Findings $x } $f }
    }

    It 'a named-object view of a Gap control is one deficiency, not two' {
        $s = & $script:Sum @((& $script:F 'EXO-1.2' 'Gap'), (& $script:F 'EXO-6.4' 'Gap'), (& $script:F 'AAD-3.5' 'Gap'))
        $s.GapControls | Should -Be 3
        @($s.NamedViews).Count | Should -Be 1
        $s.NamedViews[0].Control | Should -Be 'EXO-6.4'
        $s.DistinctDeficiencies | Should -Be 2
    }
    It 'a view of a Partial control (the shortfall is the same) also folds in' {
        $s = & $script:Sum @((& $script:F 'AAD-1.2' 'Partial'), (& $script:F 'AAD-12.1' 'Gap'))
        $s.GapControls | Should -Be 1; @($s.NamedViews).Count | Should -Be 1; $s.DistinctDeficiencies | Should -Be 0
    }
    It 'a view whose parent is Satisfied or not assessed stays a distinct requirement' {
        $s = & $script:Sum @((& $script:F 'AAD-1.2' 'Satisfied'), (& $script:F 'AAD-12.1' 'Gap'))
        @($s.NamedViews).Count | Should -Be 0; $s.DistinctDeficiencies | Should -Be 1
        $s = & $script:Sum @((& $script:F 'AAD-1.2' 'NotApplicable'), (& $script:F 'AAD-12.1' 'Gap'))
        @($s.NamedViews).Count | Should -Be 0
    }
    It 'controls that read the same setting are counted once and reported as folded, not as extra Gaps' {
        $s = & $script:Sum @((& $script:F 'SPO-1.4' 'Gap'), (& $script:F 'SPO-3.4' 'Gap'), (& $script:F 'SPO-2.6' 'Gap'), (& $script:F 'SPO-2.7' 'Gap'))
        $s.GapControls | Should -Be 2
        $s.FoldedControls | Should -Be 2
        @($s.FoldedSameSetting | ForEach-Object { $_.AlsoCounted } | Sort-Object) | Should -Be @('SPO-2.7', 'SPO-3.4')
    }
    It 'Total = Distinct + Views for any mix' {
        $f = @(
            (& $script:F 'EXO-1.2' 'Gap'), (& $script:F 'EXO-6.4' 'Gap'), (& $script:F 'EXO-7.4' 'Gap'),
            (& $script:F 'AAD-1.2' 'Partial'), (& $script:F 'AAD-12.1' 'Gap'), (& $script:F 'TMS-1.3' 'Gap'), (& $script:F 'DEF-2.1' 'Partial'))
        $s = & $script:Sum $f
        ($s.DistinctDeficiencies + @($s.NamedViews).Count) | Should -Be $s.GapControls
    }
    It 'no findings and no Gaps are a clean zero, not an error' {
        $s = & $script:Sum @()
        $s.GapControls | Should -Be 0; $s.DistinctDeficiencies | Should -Be 0
    }
    It 'the sentence states the counts and never assumes distinct requirements have separate root causes' {
        $s = & $script:Sum @((& $script:F 'EXO-1.2' 'Gap'), (& $script:F 'EXO-6.4' 'Gap'))
        $t = & (Get-Module NRG-Assessment) { param($x) Format-NRGGapSummary -Summary $x } $s
        $t | Should -Match '^2 Gap control\(s\): 1 distinct requirement\(s\) and 1 named-object view'
        $t | Should -Match 'does not assume they do'
    }
    It 'the SharePoint guest-expiration and email-attestation pairs read one setting each and are linked for scoring' {
        $links = & (Get-Module NRG-Assessment) { Get-NRGControlLinkMap }
        $links['SPO-3.4'].Primary | Should -Be 'SPO-1.4'
        $links['SPO-2.7'].Primary | Should -Be 'SPO-2.6'
    }
    It 'every recorded view names two real controls and a reason' {
        $ids = @((Get-Content -LiteralPath (Join-Path $script:Root 'Config/controls.json') -Raw | ConvertFrom-Json).controls | ForEach-Object { $_.ControlId })
        $cfg = Get-Content -LiteralPath (Join-Path $script:Root 'Config/control-links.json') -Raw | ConvertFrom-Json
        @($cfg.Views).Count | Should -BeGreaterThan 0
        foreach ($v in @($cfg.Views)) {
            $ids | Should -Contain $v.Control; $ids | Should -Contain $v.Of
            $v.Control | Should -Not -Be $v.Of
            [string]$v.Reason | Should -Not -BeNullOrEmpty
        }
    }
}

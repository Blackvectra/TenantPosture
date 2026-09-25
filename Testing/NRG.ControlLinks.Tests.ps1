#Requires -Version 7.0
#
# NRG.ControlLinks.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Controls that read the same tenant setting (Config/control-links.json) are
# each assessed and reported, but count once. On a live tenant (2026-09-25)
# EXO-2.6 and EXO-6.2 both reported "18 of 28 shared mailboxes have sign-in
# enabled", docking the tenant twice for one setting; nine more pairs did the
# same. The owner's rule: assess both, add them together, one fix satisfies
# both.
#
# Data keys: none (findings only).

Describe 'Linked controls count once' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        $script:Cfg = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/control-links.json') -Raw | ConvertFrom-Json
        $script:Controls = @{}
        foreach ($c in (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw | ConvertFrom-Json).controls) { $script:Controls[$c.ControlId] = $c }
        function script:F { param([string] $Id, [string] $State, [string[]] $Cites)
            [pscustomobject]@{ ControlId = $Id; State = $State; Title = $Id; Severity = 'High'; Detail = 'x'; FrameworkIds = $Cites; Instance = '' } }
        function script:Score { param([object[]] $Findings) & $script:Mod { param($f) @(Get-NRGScoringFindings -Findings $f) } $Findings }
    }
    BeforeEach { Clear-NRGState }

    It 'every linked ID is a real control, appears in one group only, and shares a collector with its primary' {
        $seen = @{}
        foreach ($g in $script:Cfg.groups) {
            $members = @(@($g.Primary) + @($g.Linked))
            $members.Count | Should -BeGreaterThan 1
            $g.Reason | Should -Not -BeNullOrEmpty
            foreach ($m in $members) {
                $script:Controls.ContainsKey($m) | Should -BeTrue -Because "$m must exist in controls.json"
                $seen.ContainsKey($m) | Should -BeFalse -Because "$m is in two groups"
                $seen[$m] = $true
            }
            $pDeps = @($script:Controls[$g.Primary].CollectorDependency -split ',' | ForEach-Object Trim)
            foreach ($l in $g.Linked) {
                $lDeps = @($script:Controls[$l].CollectorDependency -split ',' | ForEach-Object Trim)
                @($lDeps | Where-Object { $_ -in $pDeps }).Count | Should -BeGreaterThan 0 -Because "$l and $($g.Primary) must read the same collector's data"
            }
        }
    }

    It 'a pair failing on the same setting is one Gap in the score, reported under the primary, with both citations' {
        $s = @(Score @((F 'EXO-2.6' 'Gap' @('NIST:AC-2', 'CIS:6.2.1')), (F 'EXO-6.2' 'Gap' @('NIST:AC-2', 'CIS:1.2.2'))))
        $s.Count | Should -Be 1
        $s[0].ControlId | Should -Be 'EXO-2.6'
        @($s[0].LinkedControls) | Should -Be @('EXO-2.6', 'EXO-6.2')
        @($s[0].FrameworkIds | Sort-Object) | Should -Be @('CIS:1.2.2', 'CIS:6.2.1', 'NIST:AC-2')
        $cov = & $script:Mod { param($f) Get-NRGCoverageScore -Findings $f } @((F 'EXO-2.6' 'Gap' @()), (F 'EXO-6.2' 'Gap' @()), (F 'EXO-1.2' 'Satisfied' @()))
        $cov.Gap | Should -Be 1
        $cov.Satisfied | Should -Be 1
    }

    It 'the worst state across the pair wins, so one pass cannot hide the other''s gap' {
        $s = @(Score @((F 'EXO-2.6' 'Satisfied' @()), (F 'EXO-6.2' 'Gap' @())))
        $s.Count | Should -Be 1
        $s[0].State | Should -Be 'Gap'
    }

    It 'each control keeps its own finding in the report, untouched by the merge' {
        $a = F 'EXO-2.6' 'Gap' @('NIST:AC-2')
        $null = Score @($a, (F 'EXO-6.2' 'Gap' @('CIS:1.2.2')))
        @($a.FrameworkIds) | Should -Be @('NIST:AC-2')
        $a.PSObject.Properties['LinkedControls'] | Should -BeNullOrEmpty
    }

    It 'merges replayed findings (hashtables from -FromResults) the same way' {
        $s = @(Score @(@{ ControlId = 'TMS-2.3'; State = 'Gap'; FrameworkIds = @('NIST:SC-7') }, @{ ControlId = 'SPO-2.5'; State = 'Gap'; FrameworkIds = @('NIST:AC-20') }))
        $s.Count | Should -Be 1
        $s[0]['ControlId'] | Should -Be 'TMS-2.3'
        @($s[0]['FrameworkIds'] | Sort-Object) | Should -Be @('NIST:AC-20', 'NIST:SC-7')
    }

    It 'the finding says it is scored together, and with which control' {
        Add-NRGFinding -ControlId 'EXO-6.2' -State 'Gap' -Category 'Email' -Title 't' -Detail '18 of 28 shared mailboxes have sign-in enabled.'
        @(Get-NRGFindings)[0].Detail | Should -Match 'Scored together with EXO-2\.6 \(both read whether shared mailboxes can sign in directly\); the setting counts once in the score\.$'
    }

    It 'an unlinked control is scored alone, exactly as before' {
        $s = @(Score @((F 'EXO-1.2' 'Gap' @('NIST:IA-2')), (F 'EXO-1.2' 'Satisfied' @('NIST:IA-2'))))
        $s.Count | Should -Be 1
        $s[0].PSObject.Properties['LinkedControls'] | Should -BeNullOrEmpty
    }
}

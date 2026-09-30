#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.ControlStatus.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Get-NRGControlStatus answers "has this ticket's control been
             fixed?" from a results file. Only Satisfied is "In place";
             NotApplicable and a missing finding are never a fix; several
             findings for one control resolve to the worst; a workload prefix
             expands to the catalog; the script connects to nothing.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Get-NRGControlStatus' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Cat = @(
            [pscustomobject]@{ ControlId = 'TMS-1.1'; Title = 'One';   Severity = 'High' }
            [pscustomobject]@{ ControlId = 'TMS-1.2'; Title = 'Two';   Severity = 'High' }
            [pscustomobject]@{ ControlId = 'TMS-1.10'; Title = 'Ten';  Severity = 'Low' }
            [pscustomobject]@{ ControlId = 'AAD-1.1'; Title = 'Aad';   Severity = 'High' }
        )
        $script:F = @(
            @{ ControlId = 'TMS-1.1'; State = 'Satisfied'; Detail = 'ok' }
            @{ ControlId = 'TMS-1.2'; State = 'Gap';       Detail = 'off' }
            @{ ControlId = 'AAD-1.1'; State = 'NotApplicable'; Detail = 'Requires Entra ID P1 (upgrade opportunity).' }
        )
        $script:Get = { param($ids, $f = $script:F) , @(Get-NRGControlStatus -Findings $f -ControlId $ids -ControlCatalog $script:Cat) }
    }

    It 'calls only Satisfied "In place"' {
        $r = & $script:Get 'TMS-1.1'
        $r[0].Status | Should -Be 'In place'
    }

    It 'reports a Gap as Open and never as fixed' {
        (& $script:Get 'TMS-1.2')[0].Status | Should -Be 'Open'
    }

    It 'does not treat NotApplicable as a fix, and names the license reason' {
        $r = (& $script:Get 'AAD-1.1')[0]
        $r.Status | Should -Be 'Not assessed'
        $r.Reason | Should -Match 'license'
    }

    It 'reports an Error finding as Not assessed, never Open: a failed check has not shown the control is unconfigured' {
        $f = @(@{ ControlId = 'TMS-1.1'; State = 'Error'; Detail = 'query failed' })
        (& $script:Get 'TMS-1.1' $f)[0].Status | Should -Be 'Not assessed'
    }

    It 'reports a control with no finding as No result, never a pass' {
        (& $script:Get 'TMS-1.10')[0].Status | Should -Be 'No result'
    }

    It 'reports an ID that is neither in the catalog nor in the findings as unknown' {
        (& $script:Get 'ZZZ-9.9')[0].Status | Should -Be 'Unknown control ID'
    }

    It 'resolves several findings for one control to the worst state' {
        $f = @(
            @{ ControlId = 'TMS-1.1'; State = 'Satisfied'; Detail = 'a.com ok' }
            @{ ControlId = 'TMS-1.1'; State = 'Gap';       Detail = 'b.com missing' }
        )
        (& $script:Get 'TMS-1.1' $f)[0].Status | Should -Be 'Open'
    }

    It 'expands a workload prefix to its catalog controls, numerically ordered' {
        $r = & $script:Get 'tms'
        ($r | ForEach-Object { $_.ControlId }) -join ',' | Should -Be 'TMS-1.1,TMS-1.2,TMS-1.10'
    }

    It 'accepts comma-separated input and drops duplicates' {
        (& $script:Get 'TMS-1.1, TMS-1.1,AAD-1.1').Count | Should -Be 2
    }

    It 'still answers when the findings list is empty' {
        (& $script:Get 'TMS-1.1' @())[0].Status | Should -Be 'No result'
    }

    It 'resolves every control in the real catalog without throwing' {
        $cat = @((Get-Content -LiteralPath (Join-Path $script:Root 'Config/controls.json') -Raw | ConvertFrom-Json -Depth 10).controls)
        $r = @(Get-NRGControlStatus -Findings @() -ControlId @('AAD', 'EXO', 'DEF', 'TMS', 'SPO', 'PVW', 'INT', 'PPL', 'DNS') -ControlCatalog $cat)
        $r.Count | Should -Be $cat.Count
    }
}

Describe 'Get-NRGControlStatus.ps1 (entry point)' {
    BeforeAll { $script:Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Get-NRGControlStatus.ps1' }

    It 'connects to nothing' {
        $text = Get-Content -LiteralPath $script:Path -Raw
        foreach ($bad in 'Connect-MgGraph', 'Connect-ExchangeOnline', 'Invoke-NRGGraphRequest', 'Invoke-RestMethod', 'Invoke-WebRequest') {
            $text | Should -Not -Match ([regex]::Escape($bad))
        }
    }

    It 'reads a results file and prints the honest statuses' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-cs-{0}.json" -f [guid]::NewGuid())
        try {
            @{ Metadata = @{ TenantDomain = 'x.onmicrosoft.com' }
               Findings = @(@{ ControlId = 'TMS-1.1'; State = 'Gap'; Detail = 'off' }) } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding utf8
            $rows = @(& $script:Path -ResultsPath $tmp -ControlId 'TMS-1.1' -PassThru 6>$null)
            $rows[0].Status | Should -Be 'Open'
        } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
    }
}

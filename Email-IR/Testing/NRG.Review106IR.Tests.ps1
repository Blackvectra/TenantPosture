#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.Review106IR.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Regression tests for the review-106 incident-response defects. The
             rule they pin: a failed read, truncated evidence or a missing
             required input never produces a clean conclusion, and a Critical
             is reserved for what the evidence actually supports.
    Data keys consumed: IR-SignIn-*, IR-UserConsents, IR-UserAuthMethods,
    IR-MailboxSentItems, IR-MailboxProfile (all synthetic, raw API shapes).
    Graph scopes / cmdlets: none (the Graph boundary is mocked).
#>

Describe 'Review 106 — incident-response honesty' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Ok = { param([string] $Key, $Data) Set-NRGRawData -Key $Key -Data ([ordered]@{ CollectorId = $Key; CollectedAt = (Get-Date).ToString('o'); Success = $true; Data = $Data }) }
        $script:Finding = { param([string] $Cid) @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
    }
    AfterAll { Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-NRGState; Clear-NRGSignInTriageState }

    Context 'B1: a sign-in bag derived from a failed read is not a successful read' {

        It 'every Graph read throwing (429): the anonymous-IP and travel bags are not successful, completeness says so, and SIGNIN-1.2 / 1.3 are not Satisfied' {
            Mock -ModuleName 'NRG-Assessment' Invoke-NRGGraphRequest { throw 'Response status code does not indicate success: TooManyRequests (Too Many Requests).' }
            Invoke-NRGEmailCollectSignIns -WindowDays 7 -MaxEvents 100
            (Get-NRGRawData -Key 'IR-SignIn-Recent').Success | Should -BeFalse
            (Get-NRGRawData -Key 'IR-SignIn-AnonIp').Success | Should -BeFalse -Because 'its server-side read failed and the recent read it falls back to failed too'
            (Get-NRGRawData -Key 'IR-SignIn-Travel').Success | Should -BeFalse -Because 'it is derived only from the recent read, which failed'
            (Get-NRGSignInCollectionCompleteness -Keys 'IR-SignIn-AnonIp').Complete | Should -BeFalse
            (Get-NRGSignInCollectionCompleteness -Keys 'IR-SignIn-Travel').Complete | Should -BeFalse
            Test-NRGSignInControlAnonymousIp
            Test-NRGSignInControlImpossibleTravel
            (& $script:Finding 'SIGNIN-1.2').State | Should -Not -Be 'Satisfied'
            (& $script:Finding 'SIGNIN-1.3').State | Should -Not -Be 'Satisfied'
            ((Get-NRGExceptions | ForEach-Object { $_.Message }) -join ' ') | Should -Match 'TooManyRequests'
        }

        It 'the server-side anonymous-IP filter failing over a complete recent read falls back, and says it did' {
            Mock -ModuleName 'NRG-Assessment' Invoke-NRGGraphRequest {
                if ($Uri -match 'anonymizedIPAddress') { throw 'Response status code does not indicate success: BadRequest (Bad Request).' }
                [ordered]@{ value = @() }
            }
            Invoke-NRGEmailCollectSignIns -WindowDays 7 -MaxEvents 100
            $anon = Get-NRGRawData -Key 'IR-SignIn-AnonIp'
            $anon.Success | Should -BeTrue
            $anon.Data.Source | Should -Match 'client-side over the recent read'
            $anon.Data.Truncated | Should -BeFalse
        }
    }
}

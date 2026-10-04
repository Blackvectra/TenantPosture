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

    Context 'B2: a truncated read cannot support "nothing found"' {

        It 'SIGNIN-1.2: an anonymous-IP read that stopped at its first page with nothing in it is not cleared, never Satisfied' {
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 0; Source = 'server-side filter, first page (1000 events)'; Truncated = $true; Events = @() })
            Test-NRGSignInControlAnonymousIp
            $f = & $script:Finding 'SIGNIN-1.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Not cleared'
        }

        It 'SIGNIN-1.2: the client-side fallback over a truncated recent read is not cleared either' {
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 0; Source = 'client-side over the recent read'; Truncated = $true; Events = @() })
            Test-NRGSignInControlAnonymousIp
            (& $script:Finding 'SIGNIN-1.2').State | Should -Be 'NotApplicable'
        }

        It 'SIGNIN-1.3: a travel bag derived from a truncated recent read is not cleared, never Satisfied' {
            & $script:Ok 'IR-SignIn-Travel' ([ordered]@{ Count = 0; Source = 'client-side over the recent read'; Truncated = $true; Events = @() })
            Test-NRGSignInControlImpossibleTravel
            $f = & $script:Finding 'SIGNIN-1.3'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Not cleared'
        }

        It 'SIGNIN-1.6: every located sign-in at home in a truncated recent read is not cleared, never Satisfied' {
            $ev = @(1..3 | ForEach-Object { @{ id = "e$_"; userPrincipalName = 'a@corp.example'; createdDateTime = (Get-Date).ToUniversalTime().AddHours(-$_).ToString('o'); ipAddress = '198.51.100.1'
                status = @{ errorCode = 0 }; location = @{ city = 'Fargo'; state = 'North Dakota'; countryOrRegion = 'US' } } })
            & $script:Ok 'IR-SignIn-Recent' ([ordered]@{ WindowDays = 7; Count = 100; MaxEvents = 100; Truncated = $true; Events = $ev })
            Test-NRGSignInControlGeoAnomaly
            $f = & $script:Finding 'SIGNIN-1.6'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Not cleared'
            $f.Detail | Should -Match 'stopped at 100 events'
        }

        It 'what a truncated read DID find is still reported, with the truncation stated beside it' {
            $ev = @(@{ id = 'x'; userPrincipalName = 'a@corp.example'; createdDateTime = (Get-Date).ToUniversalTime().ToString('o'); ipAddress = '203.0.113.9'; status = @{ errorCode = 0 }; riskEventTypes_v2 = @('anonymizedIPAddress') })
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 1; Source = 'server-side filter, first page (1000 events)'; Truncated = $true; Events = $ev })
            Test-NRGSignInControlAnonymousIp
            $f = & $script:Finding 'SIGNIN-1.2'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'incomplete'
        }
    }
}

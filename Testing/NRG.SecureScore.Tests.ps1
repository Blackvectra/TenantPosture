#Requires -Version 7.0
#
# NRG.SecureScore.Tests.ps1
#
# Proves AAD-13.1 (Microsoft Secure Score) discriminates against Microsoft's OWN
# peer benchmark (averageComparativeScores) — at/above the peer average is
# Satisfied, below is Gap — with a threshold fallback when no benchmark is
# returned, and NotApplicable when Secure Score wasn't collected.

Describe 'AAD-13.1 Secure Score control discriminates on the peer benchmark' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function Set-SS {
            param($SecureScore)
            Clear-NRGState
            $data = @{ SubscribedSkus = @() }
            if ($null -ne $SecureScore) { $data['SecureScore'] = $SecureScore }
            Set-NRGRawData -Key 'AAD-Inventory' -Data ([pscustomobject]@{
                CollectorId = 'x'; CollectedAt = 'n'; Success = $true; Data = $data
            })
        }
        function State { (Get-NRGFindings | Where-Object { $_.ControlId -eq 'AAD-13.1' } | Select-Object -First 1).State }
    }

    It 'Satisfied when the tenant is AT/ABOVE the AllTenants peer average' {
        # tenant 60/100 = 60%, peer average 45/100 = 45% -> at/above -> Satisfied
        Set-SS -SecureScore @{
            CurrentScore = 60; MaxScore = 100; Percentage = 60; CreatedDate = '2026-07-10'
            AverageComparativeScores = @(@{ Basis = 'AllTenants'; AverageScore = 45 })
        }
        Test-NRGControlInventorySecureScore
        State | Should -Be 'Satisfied'
    }

    It 'Gap when the tenant is BELOW the peer average' {
        # tenant 30%, peer average 45% -> below -> Gap
        Set-SS -SecureScore @{
            CurrentScore = 30; MaxScore = 100; Percentage = 30; CreatedDate = '2026-07-10'
            AverageComparativeScores = @(@{ Basis = 'AllTenants'; AverageScore = 45 })
        }
        Test-NRGControlInventorySecureScore
        State | Should -Be 'Gap'
    }

    It 'falls back to the absolute band when NO benchmark is returned' {
        # No AverageComparativeScores -> 75% -> Satisfied on the >=70 band
        Set-SS -SecureScore @{ CurrentScore = 75; MaxScore = 100; Percentage = 75; CreatedDate = '2026-07-10'; AverageComparativeScores = @() }
        Test-NRGControlInventorySecureScore
        State | Should -Be 'Satisfied'
        # 40% -> Gap on the <50 band
        Set-SS -SecureScore @{ CurrentScore = 40; MaxScore = 100; Percentage = 40; CreatedDate = '2026-07-10'; AverageComparativeScores = @() }
        Test-NRGControlInventorySecureScore
        State | Should -Be 'Gap'
    }

    It 'NotApplicable when Secure Score was not collected' {
        Set-SS -SecureScore $null
        Test-NRGControlInventorySecureScore
        State | Should -Be 'NotApplicable'
    }
}

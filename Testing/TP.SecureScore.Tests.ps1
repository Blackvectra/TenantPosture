#Requires -Version 7.0
#
# TP.SecureScore.Tests.ps1
#
# Proves AAD-13.1 (Microsoft Secure Score) discriminates against Microsoft's OWN
# peer benchmark (averageComparativeScores) — at/above the peer average is
# Satisfied, below is Gap — with a threshold fallback when no benchmark is
# returned, and NotApplicable when Secure Score wasn't collected or carries no
# maximum score.

Describe 'AAD-13.1 Secure Score control discriminates on the peer benchmark' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        function Set-SS {
            param($SecureScore)
            Clear-TPState
            $data = @{ SubscribedSkus = @() }
            if ($null -ne $SecureScore) { $data['SecureScore'] = $SecureScore }
            Set-TPRawData -Key 'AAD-Inventory' -Data ([pscustomobject]@{
                CollectorId = 'x'; CollectedAt = 'n'; Success = $true; Data = $data
            })
        }
        function State { (Get-TPFindings | Where-Object { $_.ControlId -eq 'AAD-13.1' } | Select-Object -First 1).State }
    }

    It 'Satisfied when the tenant is AT/ABOVE the AllTenants peer average' {
        # tenant 60/100 = 60%, peer average 45/100 = 45% -> at/above -> Satisfied
        Set-SS -SecureScore @{
            CurrentScore = 60; MaxScore = 100; Percentage = 60; CreatedDate = '2026-07-10'
            AverageComparativeScores = @(@{ Basis = 'AllTenants'; AverageScore = 45 })
        }
        Test-TPControlInventorySecureScore
        State | Should -Be 'Satisfied'
    }

    It 'Gap when the tenant is BELOW the peer average' {
        # tenant 30%, peer average 45% -> below -> Gap
        Set-SS -SecureScore @{
            CurrentScore = 30; MaxScore = 100; Percentage = 30; CreatedDate = '2026-07-10'
            AverageComparativeScores = @(@{ Basis = 'AllTenants'; AverageScore = 45 })
        }
        Test-TPControlInventorySecureScore
        State | Should -Be 'Gap'
    }

    It 'reads the peer average as a percentage, not points (live shape: max 1165, AllTenants 53.99)' {
        # The fixtures above use MaxScore = 100, where points and percent are
        # the same number, which hid the bug: dividing 53.99 by 1165 printed a
        # "5% average" and passed a tenant sitting at 40%.
        Set-SS -SecureScore @{
            CurrentScore = 466; MaxScore = 1165; Percentage = 40; CreatedDate = '2026-09-25'
            AverageComparativeScores = @(@{ Basis = 'AllTenants'; AverageScore = 53.99 })
        }
        Test-TPControlInventorySecureScore
        State | Should -Be 'Gap'
        Clear-TPState
        Set-SS -SecureScore @{
            CurrentScore = 807; MaxScore = 1165; Percentage = 69; CreatedDate = '2026-09-25'
            AverageComparativeScores = @(@{ Basis = 'AllTenants'; AverageScore = 53.99 })
        }
        Test-TPControlInventorySecureScore
        $f = Get-TPFindings | Where-Object { $_.ControlId -eq 'AAD-13.1' } | Select-Object -First 1
        $f.State  | Should -Be 'Satisfied'
        $f.Detail | Should -Match '54% average'
    }

    It 'falls back to the absolute band when NO benchmark is returned' {
        # No AverageComparativeScores -> 75% -> Satisfied on the >=70 band
        Set-SS -SecureScore @{ CurrentScore = 75; MaxScore = 100; Percentage = 75; CreatedDate = '2026-07-10'; AverageComparativeScores = @() }
        Test-TPControlInventorySecureScore
        State | Should -Be 'Satisfied'
        # 40% -> Gap on the <50 band
        Set-SS -SecureScore @{ CurrentScore = 40; MaxScore = 100; Percentage = 40; CreatedDate = '2026-07-10'; AverageComparativeScores = @() }
        Test-TPControlInventorySecureScore
        State | Should -Be 'Gap'
    }

    It 'NotApplicable when Secure Score was not collected' {
        Set-SS -SecureScore $null
        Test-TPControlInventorySecureScore
        State | Should -Be 'NotApplicable'
    }

    It 'names the benchmark it compared against, never "comparable organizations" for the all-tenants average' {
        # AllTenants is every Microsoft 365 tenant, not a peer group of similar ones.
        Set-SS -SecureScore @{
            CurrentScore = 30; MaxScore = 100; Percentage = 30; CreatedDate = '2026-07-10'
            AverageComparativeScores = @(@{ Basis = 'AllTenants'; AverageScore = 45 })
        }
        Test-TPControlInventorySecureScore
        $f = Get-TPFindings | Where-Object { $_.ControlId -eq 'AAD-13.1' } | Select-Object -First 1
        $f.State  | Should -Be 'Gap'
        $f.Detail | Should -Match 'average for all Microsoft 365 tenants'
        $f.Detail | Should -Not -Match 'comparable'
    }

    It 'NotApplicable, never "0% - Critical", when Microsoft returned no maximum score' {
        # The collector writes Percentage 0 when maxScore is absent or 0.
        Set-SS -SecureScore @{ CurrentScore = 0; MaxScore = 0; Percentage = 0; CreatedDate = ''; AverageComparativeScores = @() }
        Test-TPControlInventorySecureScore
        $f = Get-TPFindings | Where-Object { $_.ControlId -eq 'AAD-13.1' } | Select-Object -First 1
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Not -Match 'Critical'
    }
}

#Requires -Version 7.0
#
# NRG.AccessReviews.Tests.ps1
#
# Proves AAD-8.2 (Access Reviews for Privileged Roles) discriminates on the real
# access-review definitions collected via Graph identityGovernance/accessReviews
# (AccessReview.Read.All re-consent scope): an active review targeting privileged
# directory roles => Satisfied; reviews that don't target roles => Partial; no
# reviews => Gap; scope not consented => NotApplicable; no PIM => NotApplicable.

Describe 'AAD-8.2 Access Reviews control discriminates' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function Set-PIM {
            param([bool]$PIMAvailable = $true, [bool]$Collected = $true, $Reviews = @())
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-PIMSchedules' -Data @{
                Success = $true
                PIMAvailable = $PIMAvailable
                AccessReviewsCollected = $Collected
                Data = @{ EligibleSchedules = @(); ActiveSchedules = @(); RolePolicies = @(); AccessReviews = @($Reviews) }
            }
        }
        function State { (Get-NRGFindings | Where-Object { $_.ControlId -eq 'AAD-8.2' } | Select-Object -First 1).State }
    }

    It 'Satisfied when an active review targets privileged directory roles' {
        Set-PIM -Reviews @(@{ Id = '1'; DisplayName = 'Global Admin review'; Status = 'InProgress'; TargetsRoles = $true; IsRecurring = $true })
        Test-NRGControlAADAccessReviews
        State | Should -Be 'Satisfied'
    }

    It 'Partial when reviews exist but none target privileged roles' {
        Set-PIM -Reviews @(@{ Id = '2'; DisplayName = 'Group X review'; Status = 'InProgress'; TargetsRoles = $false; IsRecurring = $true })
        Test-NRGControlAADAccessReviews
        State | Should -Be 'Partial'
    }

    It 'Gap when no access reviews are configured' {
        Set-PIM -Reviews @()
        Test-NRGControlAADAccessReviews
        State | Should -Be 'Gap'
    }

    It 'NotApplicable when the AccessReview.Read.All scope was not consented' {
        Set-PIM -Collected $false -Reviews @()
        Test-NRGControlAADAccessReviews
        State | Should -Be 'NotApplicable'
    }

    It 'NotApplicable when PIM is not available (no Entra P2)' {
        Set-PIM -PIMAvailable $false
        Test-NRGControlAADAccessReviews
        State | Should -Be 'NotApplicable'
    }
}

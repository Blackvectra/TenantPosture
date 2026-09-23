#Requires -Version 7.0
#
# NRG.AccessReviews.Tests.ps1
#
# Proves AAD-8.2 (Access Reviews for Privileged Roles) discriminates on the real
# access-review definitions collected via Graph identityGovernance/accessReviews
# (AccessReview.Read.All re-consent scope): an active review targeting privileged
# directory roles => Satisfied; reviews that don't target roles => Partial; no
# reviews => Gap; scope not consented => NotApplicable; no PIM => NotApplicable.
#
# v4.13.1: previously fed the evaluator pre-computed TargetsRoles/IsRecurring
# fields and AccessReviewsCollected=$true directly, so the COLLECTOR was never
# exercised — the scope.query regex that derives TargetsRoles, the recurrence
# pattern parse, the accessReviews/definitions paging loop, and the 403-vs-other
# catch that sets AccessReviewsCollected all shipped unverified. That is how a
# StrictMode nextLink throw disabling AAD-8.2 on PS 7.4 got past this suite.
# Now the Graph layer is stubbed with real accessReviewScheduleDefinition shapes
# and the real collector (Invoke-NRGCollectAADPIM) runs before the evaluator.
#
# The Graph mock is injected into MODULE scope (Set-Item function:script:), the
# same pattern NRG.AppPermissions.Tests.ps1 uses, because the collector's call
# to Invoke-NRGGraphRequest resolves inside the module and a test-scope Mock
# would never be seen.

Describe 'AAD-8.2 Access Reviews control discriminates' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        # Scenario knobs read by the mock below — set per test.
        $script:PIMForbidden           = $false   # 403 on the P2-availability probe
        $script:AccessReviewsForbidden = $false   # 403 on accessReviews/definitions (not re-consented)
        $script:AccessReviewDefs       = @()      # raw accessReviewScheduleDefinition rows

        & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } 'Invoke-NRGGraphRequest' @'
[CmdletBinding()]
param([string] $Uri, [string] $Method = 'GET', $Body, $Headers, [string] $OutputType = 'HashTable')

if ($Uri -like '*roleEligibilitySchedules?$top=1*') {
    if ($script:PIMForbidden) { throw '403 Forbidden' }
    return @{ value = @() }
}
if ($Uri -like '*roleEligibilitySchedules?$expand*') { return @{ value = @() } }
if ($Uri -like '*roleAssignmentSchedules?$expand*')  { return @{ value = @() } }
if ($Uri -like '*policies/roleManagementPolicies*')  { return @{ value = @() } }
if ($Uri -like '*identityGovernance/accessReviews/definitions*') {
    if ($script:AccessReviewsForbidden) { throw 'Graph 403 Forbidden — Authorization_RequestDenied' }
    return @{ value = @($script:AccessReviewDefs) }
}
return @{ value = @() }
'@

        function Set-AccessReviewScenario {
            param(
                [bool] $PIMForbidden = $false,
                [bool] $AccessReviewsForbidden = $false,
                [object[]] $Definitions = @()
            )
            Clear-NRGState
            $script:PIMForbidden           = $PIMForbidden
            $script:AccessReviewsForbidden = $AccessReviewsForbidden
            $script:AccessReviewDefs       = $Definitions
            $null = Invoke-NRGCollectAADPIM
        }

        # Real accessReviewScheduleDefinition shape: a review scoped to
        # privileged directory roles queries roleAssignmentScheduleInstances
        # under roleManagement/directory (the PIM role-assignment surface),
        # not a group or app membership.
        function New-RoleReviewDef {
            param([string]$Id = '1', [string]$Status = 'InProgress', [string]$Recurrence = 'weekly')
            @{
                id          = $Id
                displayName = 'Global Admin review'
                status      = $Status
                scope       = @{
                    query     = '/roleManagement/directory/roleAssignmentScheduleInstances'
                    queryType = 'MicrosoftGraph'
                }
                settings    = @{ recurrence = @{ pattern = @{ type = $Recurrence } } }
            }
        }

        function New-GroupReviewDef {
            param([string]$Id = '2', [string]$Status = 'InProgress')
            @{
                id          = $Id
                displayName = 'Group X review'
                status      = $Status
                scope       = @{
                    query     = "/groups/$([guid]::Empty)/transitiveMembers"
                    queryType = 'MicrosoftGraph'
                }
                settings    = @{ recurrence = @{ pattern = @{ type = 'weekly' } } }
            }
        }

        function State { (Get-NRGFindings | Where-Object { $_.ControlId -eq 'AAD-8.2' } | Select-Object -First 1).State }
    }

    It 'Satisfied when an active review targets privileged directory roles' {
        Set-AccessReviewScenario -Definitions @( (New-RoleReviewDef) )
        Test-NRGControlAADAccessReviews
        State | Should -Be 'Satisfied'
    }

    It 'Partial when reviews exist but none target privileged roles' {
        Set-AccessReviewScenario -Definitions @( (New-GroupReviewDef) )
        Test-NRGControlAADAccessReviews
        State | Should -Be 'Partial'
    }

    It 'Gap when no access reviews are configured' {
        Set-AccessReviewScenario -Definitions @()
        Test-NRGControlAADAccessReviews
        State | Should -Be 'Gap'
    }

    It 'NotApplicable when the AccessReview.Read.All scope was not consented' {
        Set-AccessReviewScenario -AccessReviewsForbidden $true
        Test-NRGControlAADAccessReviews
        State | Should -Be 'NotApplicable'
    }

    It 'NotApplicable when PIM is not available (no Entra P2)' {
        Set-AccessReviewScenario -PIMForbidden $true
        Test-NRGControlAADAccessReviews
        State | Should -Be 'NotApplicable'
    }

    It 'a review whose recurrence is noRecurrence is still counted if it targets privileged roles' {
        # IsRecurring only affects framing in the Detail text, not the
        # Satisfied/Partial/Gap branch — a one-time role review still counts.
        Set-AccessReviewScenario -Definitions @( (New-RoleReviewDef -Recurrence 'noRecurrence') )
        Test-NRGControlAADAccessReviews
        State | Should -Be 'Satisfied'
    }

    It 'a completed (non-active) role review does not count toward Satisfied' {
        Set-AccessReviewScenario -Definitions @( (New-RoleReviewDef -Status 'Completed') )
        Test-NRGControlAADAccessReviews
        State | Should -Be 'Partial' -Because 'the review exists but is not in an active status, so it does not recertify anything right now'
    }
}

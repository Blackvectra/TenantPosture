<#
.SYNOPSIS
    Collects PIM eligible and active role assignment schedules.
.DESCRIPTION
    Retrieves both eligible (not yet activated) and active (currently activated)
    PIM role assignment schedules. Requires Entra ID P2.

    Graceful skip pattern: Result.Success = $true even when P2 is unavailable.
    PIMAvailable = $false signals evaluator to generate a Skip finding with context
    rather than treating it as a collection failure.
.NOTES
    NIST SP 800-53: AC-2(7), AC-6(2), AC-6(5)
    MITRE ATT&CK:   T1078.004 (Cloud Accounts)
    Required Graph scopes: RoleManagement.Read.All
    License required:      Entra ID P2 (included in M365 Business Premium)
    Version: 1.0.0 (Session 2 — Identity Layer)
#>
function Get-NRGCollector-AAD-PIM {
    [CmdletBinding()]
    param(
        [string]$LogPath = 'C:\ProgramData\NRG\Logs\NRGAssessment.log'
    )

    Write-NRGLog -Message '[AAD-PIM] Collector starting' -Path $LogPath

    $result = [PSCustomObject]@{
        CollectorId         = 'AAD-PIM'
        CollectedAt         = (Get-Date -Format 'o')
        PIMAvailable        = $false
        EligibleAssignments = @()
        ActiveSchedules     = @()
        Success             = $false
        Error               = $null
    }

    try {
        # AC-2(7) — Eligible assignments: JIT access model, not yet activated
        $eligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
            -All -ExpandProperty 'Principal,RoleDefinition' -ErrorAction Stop

        $result.EligibleAssignments = $eligible | Select-Object -Property @(
            'Id', 'PrincipalId', 'RoleDefinitionId',
            @{ N = 'PrincipalUPN'; E = { $_.Principal.AdditionalProperties['userPrincipalName'] } },
            @{ N = 'RoleName';     E = { $_.RoleDefinition.DisplayName } },
            'ScheduleInfo', 'Status', 'MemberType'
        )

        # AC-6(2) — Active PIM schedules: currently activated, time-bounded
        # These are not permanent — distinguishes JIT activations from standing access
        $active = Get-MgRoleManagementDirectoryRoleAssignmentSchedule `
            -All -ExpandProperty 'Principal,RoleDefinition' -ErrorAction Stop

        $result.ActiveSchedules = $active | Select-Object -Property @(
            'Id', 'PrincipalId', 'RoleDefinitionId',
            @{ N = 'PrincipalUPN'; E = { $_.Principal.AdditionalProperties['userPrincipalName'] } },
            @{ N = 'RoleName';     E = { $_.RoleDefinition.DisplayName } },
            'AssignmentType', 'ScheduleInfo', 'Status', 'MemberType'
        )

        $result.PIMAvailable = $true
        $result.Success = $true
        Write-NRGLog -Message "[AAD-PIM] Complete. Eligible: $($result.EligibleAssignments.Count), Active schedules: $($result.ActiveSchedules.Count)" -Path $LogPath
    }
    catch {
        # P2 not licensed or RoleManagement schedule endpoints not provisioned
        # Set Success = $true intentionally: absence of PIM is a finding (AAD-4.4 Skip),
        # not a script failure. Evaluator checks PIMAvailable flag.
        $result.Error   = $_.Exception.Message
        $result.Success = $true
        Write-NRGLog -Message "[AAD-PIM] PIM unavailable (P2 not licensed or insufficient permissions): $($_.Exception.Message)" -Path $LogPath -Level 'WARN'
    }

    return $result
}

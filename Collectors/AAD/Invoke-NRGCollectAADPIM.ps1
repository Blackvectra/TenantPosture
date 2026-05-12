#
# Invoke-NRGCollectAADPIM.ps1
# Collects PIM eligible and active role assignment schedules.
# Requires Entra ID P2. Graceful skip if not licensed.
# COLLECTION ONLY - no scoring.
#
# Graceful skip pattern:
#   result.Success = $true even when P2 unavailable.
#   result.Data['PIMAvailable'] = $false signals evaluator
#   to produce NotApplicable finding with licensing context.
#
# NIST SP 800-53: AC-2(7), AC-6(2), AC-6(5)
# MITRE ATT&CK:   T1078.004 (Cloud Accounts)
#
# Required Graph scopes: RoleManagement.Read.All
# Required license:      Entra ID P2 (included in M365 Business Premium)
#

function Invoke-NRGCollectAADPIM {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'AAD-PIM'
        Timestamp  = [DateTime]::UtcNow.ToString('o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    try {
        # AC-2(7) — Eligible assignments: not yet activated, JIT access model
        $eligible = @(
            Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
                -All -ExpandProperty 'Principal,RoleDefinition' -ErrorAction Stop
        )

        $result.Data['EligibleAssignments'] = $eligible | Select-Object -Property @(
            'Id', 'PrincipalId', 'RoleDefinitionId',
            @{ N = 'PrincipalUPN'; E = { $_.Principal.AdditionalProperties['userPrincipalName'] } },
            @{ N = 'RoleName';     E = { $_.RoleDefinition.DisplayName } },
            'ScheduleInfo', 'Status', 'MemberType'
        )

        # AC-6(2) — Active PIM schedules: currently activated, time-bounded
        $active = @(
            Get-MgRoleManagementDirectoryRoleAssignmentSchedule `
                -All -ExpandProperty 'Principal,RoleDefinition' -ErrorAction Stop
        )

        $result.Data['ActiveSchedules'] = $active | Select-Object -Property @(
            'Id', 'PrincipalId', 'RoleDefinitionId',
            @{ N = 'PrincipalUPN'; E = { $_.Principal.AdditionalProperties['userPrincipalName'] } },
            @{ N = 'RoleName';     E = { $_.RoleDefinition.DisplayName } },
            'AssignmentType', 'ScheduleInfo', 'Status', 'MemberType'
        )

        $result.Data['PIMAvailable']          = $true
        $result.Data['EligibleCount']         = $eligible.Count
        $result.Data['ActiveScheduleCount']   = $active.Count
        $result.Data['EligibleGACount']       = @($result.Data['EligibleAssignments'] | Where-Object { $_.RoleName -eq 'Global Administrator' }).Count

        $result.Success = $true
        Register-NRGCoverage -Family 'AAD-PIM' -Status 'Collected'
    }
    catch {
        # P2 not licensed or endpoint not provisioned — not a script failure
        # Evaluator checks PIMAvailable flag and produces NotApplicable with licensing context
        $result.Data['PIMAvailable'] = $false
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'AAD-PIM' -Message $_.Exception.Message -Severity 'Warning'
        Register-NRGCoverage -Family 'AAD-PIM' -Status 'NotCollected' -Note 'Entra ID P2 not licensed or RoleManagement schedule endpoints not provisioned'

        # Mark Success = $true intentionally: P2 absence is a finding, not a crash
        $result.Success = $true
    }

    Set-NRGRawData -Key 'AAD-PIM' -Data $result
    return $result
}

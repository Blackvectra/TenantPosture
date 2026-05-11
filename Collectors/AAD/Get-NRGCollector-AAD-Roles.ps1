<#
.SYNOPSIS
    Collects permanent (non-PIM) Entra ID directory role assignments.
.DESCRIPTION
    Enumerates all active role assignments with principal and role definition
    expanded inline to avoid N+1 lookup calls. Captures on-prem sync state
    for hybrid identity kill chain detection (AAD-4.2).
.NOTES
    NIST SP 800-53: AC-2(7), AC-6(5)
    MITRE ATT&CK:   T1078.004 (Valid Accounts: Cloud Accounts)
    Required Graph scopes: RoleManagement.Read.All
    Version: 1.0.0 (Session 2 — Identity Layer)
#>
function Get-NRGCollector-AAD-Roles {
    [CmdletBinding()]
    param(
        [string]$LogPath = 'C:\ProgramData\NRG\Logs\NRGAssessment.log'
    )

    Write-NRGLog -Message '[AAD-Roles] Collector starting' -Path $LogPath

    $result = [PSCustomObject]@{
        CollectorId          = 'AAD-Roles'
        CollectedAt          = (Get-Date -Format 'o')
        PermanentAssignments = @()
        RoleDefinitions      = @()
        Success              = $false
        Error                = $null
    }

    try {
        # AC-2(7), AC-6(5) — All permanent (non-PIM) role assignments
        # ExpandProperty inline: Principal (for UPN, sync state, object type)
        #                        RoleDefinition (for display name, built-in flag)
        $assignments = Get-MgRoleManagementDirectoryRoleAssignment `
            -All -ExpandProperty 'Principal,RoleDefinition' -ErrorAction Stop

        $result.PermanentAssignments = $assignments | Select-Object -Property @(
            'Id', 'PrincipalId', 'RoleDefinitionId', 'DirectoryScopeId',
            @{ N = 'PrincipalUPN';  E = { $_.Principal.AdditionalProperties['userPrincipalName'] } },
            @{ N = 'PrincipalType'; E = { $_.Principal.AdditionalProperties['@odata.type'] } },
            @{ N = 'OnPremSynced';  E = { $_.Principal.AdditionalProperties['onPremisesSyncEnabled'] } },
            @{ N = 'RoleName';      E = { $_.RoleDefinition.DisplayName } },
            @{ N = 'IsBuiltInRole'; E = { $_.RoleDefinition.IsBuiltIn } }
        )

        # Pull role definitions for ID-to-name mapping in evaluators
        $result.RoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop |
            Select-Object Id, DisplayName, IsBuiltIn, IsEnabled

        $result.Success = $true
        Write-NRGLog -Message "[AAD-Roles] Complete. Assignments: $($result.PermanentAssignments.Count)" -Path $LogPath
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-NRGLog -Message "[AAD-Roles] Error: $($_.Exception.Message)" -Path $LogPath -Level 'ERROR'
    }

    return $result
}

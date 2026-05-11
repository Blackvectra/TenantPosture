#
# Invoke-NRGCollectAADRoles.ps1
# Collects permanent (non-PIM) Entra ID directory role assignments.
# Expands Principal and RoleDefinition inline to avoid N+1 lookups.
# COLLECTION ONLY - no scoring.
#
# NIST SP 800-53: AC-2(7), AC-6(5)
# MITRE ATT&CK:   T1078.004 (Cloud Accounts)
#
# Required Graph scopes: RoleManagement.Read.All
#

function Invoke-NRGCollectAADRoles {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'AAD-Roles'
        Timestamp  = [DateTime]::UtcNow.ToString('o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    try {
        # AC-2(7), AC-6(5) — All permanent role assignments
        # ExpandProperty inline: avoids separate principal/role lookups per assignment
        $assignments = @(
            Get-MgRoleManagementDirectoryRoleAssignment `
                -All -ExpandProperty 'Principal,RoleDefinition' -ErrorAction Stop
        )

        $result.Data['PermanentAssignments'] = $assignments | Select-Object -Property @(
            'Id', 'PrincipalId', 'RoleDefinitionId', 'DirectoryScopeId',
            @{ N = 'PrincipalUPN';  E = { $_.Principal.AdditionalProperties['userPrincipalName'] } },
            @{ N = 'PrincipalType'; E = { $_.Principal.AdditionalProperties['@odata.type'] } },
            @{ N = 'OnPremSynced';  E = { $_.Principal.AdditionalProperties['onPremisesSyncEnabled'] } },
            @{ N = 'RoleName';      E = { $_.RoleDefinition.DisplayName } },
            @{ N = 'IsBuiltIn';     E = { $_.RoleDefinition.IsBuiltIn } }
        )

        $result.Data['RoleDefinitions'] = @(
            Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop |
            Select-Object Id, DisplayName, IsBuiltIn, IsEnabled
        )

        # Pre-aggregate counts for common evaluator queries
        $GA_ROLE_ID = '62e90394-69f5-4237-9190-012177145e10'
        $result.Data['TotalAssignmentCount']  = $assignments.Count
        $result.Data['GlobalAdminCount']      = @($result.Data['PermanentAssignments'] | Where-Object { $_.RoleDefinitionId -eq $GA_ROLE_ID }).Count
        $result.Data['SyncedAdminCount']      = @($result.Data['PermanentAssignments'] | Where-Object { $_.OnPremSynced -eq $true }).Count

        $result.Success = $true
        Register-NRGCoverage -Family 'AAD-Roles' -Status 'Collected'
    }
    catch {
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'AAD-Roles' -Message $_.Exception.Message
        Register-NRGCoverage -Family 'AAD-Roles' -Status 'Failed' -Note $_.Exception.Message
    }

    Set-NRGRawData -Key 'AAD-Roles' -Data $result
    return $result
}

#Requires -Version 7.0
#
# Invoke-NRGCollectAADRoles.ps1  (v4.5.5)
# Collects directory role assignments (active, permanent, and service principals).
# READ-ONLY.
#
# Required Graph scopes: RoleManagement.Read.All, Directory.Read.All
#
# NIST SP 800-53: AC-6 (least privilege), AC-6(5) (privileged accounts)
# MITRE ATT&CK:   T1078.004 (Cloud Accounts), T1098 (Account Manipulation)
#

function Invoke-NRGCollectAADRoles {
    [CmdletBinding()] param()

    $result = @{
        Success = $false
        Data    = @{
            RoleDefinitions  = @()
            RoleAssignments  = @()
            PrivRoles        = @()
        }
    }

    try {
        # High-privilege roles to focus evaluation on
        $privRoleNames = @(
            'Global Administrator', 'Privileged Role Administrator',
            'Security Administrator', 'Exchange Administrator',
            'SharePoint Administrator', 'User Administrator',
            'Application Administrator', 'Cloud Application Administrator',
            'Authentication Administrator', 'Privileged Authentication Administrator',
            'Helpdesk Administrator', 'Compliance Administrator',
            'Billing Administrator', 'Teams Administrator',
            'Azure AD Joined Device Local Administrator', 'Intune Administrator',
            'Conditional Access Administrator'
        )

        # Get all role definitions (we need names to match)
        try {
            $roleDefResp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,isEnabled&$top=200' `
                -ErrorAction Stop
            $result.Data.RoleDefinitions = @($roleDefResp.value ?? @() | ForEach-Object {
                @{
                    Id          = [string]$_.id
                    DisplayName = [string]$_.displayName
                    IsBuiltIn   = [bool]$_.isBuiltIn
                    IsEnabled   = [bool]$_.isEnabled
                    IsPriv      = ($privRoleNames -contains $_.displayName)
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-RoleDefinitions' -Message $_.Exception.Message
            }
        }

        # Build role ID → name lookup
        $roleMap = @{}
        foreach ($rd in @($result.Data.RoleDefinitions)) {
            $roleMap[$rd.Id] = $rd.DisplayName
        }

        # Get active (permanent) role assignments — expanded to get principal details
        try {
            $assignResp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$top=500' `
                -ErrorAction Stop

            $assignments = [System.Collections.Generic.List[object]]::new()
            $nextLink = $assignResp.'@odata.nextLink'

            foreach ($a in @($assignResp.value ?? @())) {
                $roleName = $roleMap[$a.roleDefinitionId] ?? $a.roleDefinitionId
                $assignments.Add(@{
                    Id                   = [string]$a.id
                    RoleDefinitionId     = [string]$a.roleDefinitionId
                    RoleDefinitionName   = $roleName
                    PrincipalId          = [string]$a.principalId
                    PrincipalType        = [string]($a.principal.'@odata.type' ?? 'unknown')
                    PrincipalDisplayName = [string]($a.principal.displayName ?? 'unknown')
                    PrincipalUPN         = [string]($a.principal.userPrincipalName ?? '')
                    DirectoryScopeId     = [string]($a.directoryScopeId ?? '/')
                    IsPriv               = ($privRoleNames -contains $roleName)
                    OnPremisesSyncEnabled = $a.principal.onPremisesSyncEnabled
                })
            }

            # Page through remaining assignments.
            # Pagination cap (v4.6.3 P2): a misbehaving proxy or service that
            # echoes back the same nextLink would create an infinite loop. Cap
            # at 200 pages — at default Graph $top this is ~20k assignments,
            # which exceeds any realistic tenant role assignment count.
            $maxPages   = 200
            $pageCount  = 0
            while ($nextLink -and $pageCount -lt $maxPages) {
                $pageResp = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
                foreach ($a in @($pageResp.value ?? @())) {
                    $roleName = $roleMap[$a.roleDefinitionId] ?? $a.roleDefinitionId
                    $assignments.Add(@{
                        Id                   = [string]$a.id
                        RoleDefinitionId     = [string]$a.roleDefinitionId
                        RoleDefinitionName   = $roleName
                        PrincipalId          = [string]$a.principalId
                        PrincipalType        = [string]($a.principal.'@odata.type' ?? 'unknown')
                        PrincipalDisplayName = [string]($a.principal.displayName ?? 'unknown')
                        PrincipalUPN         = [string]($a.principal.userPrincipalName ?? '')
                        DirectoryScopeId     = [string]($a.directoryScopeId ?? '/')
                        IsPriv               = ($privRoleNames -contains $roleName)
                        OnPremisesSyncEnabled = $a.principal.onPremisesSyncEnabled
                    })
                }
                $nextLink = $pageResp.'@odata.nextLink'
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $nextLink) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'AAD-Roles' `
                        -Message "Pagination cap reached ($maxPages pages). Possible nextLink loop or very large dataset; role assignments may be truncated."
                }
            }

            $result.Data.RoleAssignments = $assignments.ToArray()
            $result.Data.PrivRoles       = @($assignments | Where-Object { $_.IsPriv })

        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-RoleAssignments' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-Roles' -Status 'Collected' `
                -Note "$($result.Data.RoleAssignments.Count) assignments"
        }

    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'AAD-Roles' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-Roles' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data $result
    }
    return $result
}

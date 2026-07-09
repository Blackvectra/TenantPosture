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
            RoleDefinitions          = @()
            RoleAssignments          = @()
            PrivRoles                = @()
            # v4.6.4 EMERGENCY FIX (High #7): permanent assignments alone
            # under-report privileged access on PIM-managed tenants because
            # every role assignment there is an eligibilitySchedule rather
            # than a permanent assignment. AllPrivilegedAssignments merges
            # both surfaces with a Source flag so AAD-4.x evaluators have a
            # correct combined view.
            RoleEligibilitySchedules = @()
            AllPrivilegedAssignments = @()
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
            $roleDefResp = Invoke-NRGGraphRequest -Method GET `
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
            $assignResp = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$top=500' `
                -ErrorAction Stop

            $assignments = [System.Collections.Generic.List[object]]::new()
            $nextLink = $assignResp['@odata.nextLink']

            foreach ($a in @($assignResp.value ?? @())) {
                $roleName = $roleMap[$a.roleDefinitionId] ?? $a.roleDefinitionId
                $assignments.Add(@{
                    Id                   = [string]$a.id
                    RoleDefinitionId     = [string]$a.roleDefinitionId
                    RoleDefinitionName   = $roleName
                    PrincipalId          = [string]$a.principalId
                    PrincipalType        = [string]($a.principal['@odata.type'] ?? 'unknown')
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
                $pageResp = Invoke-NRGGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
                foreach ($a in @($pageResp.value ?? @())) {
                    $roleName = $roleMap[$a.roleDefinitionId] ?? $a.roleDefinitionId
                    $assignments.Add(@{
                        Id                   = [string]$a.id
                        RoleDefinitionId     = [string]$a.roleDefinitionId
                        RoleDefinitionName   = $roleName
                        PrincipalId          = [string]$a.principalId
                        PrincipalType        = [string]($a.principal['@odata.type'] ?? 'unknown')
                        PrincipalDisplayName = [string]($a.principal.displayName ?? 'unknown')
                        PrincipalUPN         = [string]($a.principal.userPrincipalName ?? '')
                        DirectoryScopeId     = [string]($a.directoryScopeId ?? '/')
                        IsPriv               = ($privRoleNames -contains $roleName)
                        OnPremisesSyncEnabled = $a.principal.onPremisesSyncEnabled
                    })
                }
                $nextLink = $pageResp['@odata.nextLink']
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

        # ── PIM eligibility schedules (v4.6.4 EMERGENCY FIX High #7) ─────────
        # PIM-managed tenants have ZERO permanent role assignments. If we only
        # read /roleAssignments above, AAD-3.x and AAD-4.x evaluators report
        # 0 GAs and misroute findings to NotApplicable. Pull eligibility
        # schedules separately and merge into AllPrivilegedAssignments with a
        # Source flag so evaluators can either union or filter as needed.
        $eligibility = [System.Collections.Generic.List[object]]::new()
        try {
            $eligResp = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal&$top=500' `
                -ErrorAction Stop
            $eligNext = $eligResp['@odata.nextLink']

            foreach ($e in @($eligResp.value ?? @())) {
                $roleName = $roleMap[$e.roleDefinitionId] ?? $e.roleDefinitionId
                $eligibility.Add(@{
                    Id                   = [string]$e.id
                    RoleDefinitionId     = [string]$e.roleDefinitionId
                    RoleDefinitionName   = $roleName
                    PrincipalId          = [string]$e.principalId
                    PrincipalType        = [string]($e.principal['@odata.type'] ?? 'unknown')
                    PrincipalDisplayName = [string]($e.principal.displayName ?? 'unknown')
                    PrincipalUPN         = [string]($e.principal.userPrincipalName ?? '')
                    DirectoryScopeId     = [string]($e.directoryScopeId ?? '/')
                    IsPriv               = ($privRoleNames -contains $roleName)
                    OnPremisesSyncEnabled= $e.principal.onPremisesSyncEnabled
                    StartDateTime        = [string]($e.scheduleInfo.startDateTime ?? '')
                    EndDateTime          = [string]($e.scheduleInfo.expiration.endDateTime ?? '')
                    MemberType           = [string]($e.memberType ?? 'Direct')
                })
            }
            $maxPages  = 200
            $pageCount = 0
            while ($eligNext -and $pageCount -lt $maxPages) {
                $pageResp = Invoke-NRGGraphRequest -Method GET -Uri $eligNext -ErrorAction Stop
                foreach ($e in @($pageResp.value ?? @())) {
                    $roleName = $roleMap[$e.roleDefinitionId] ?? $e.roleDefinitionId
                    $eligibility.Add(@{
                        Id                   = [string]$e.id
                        RoleDefinitionId     = [string]$e.roleDefinitionId
                        RoleDefinitionName   = $roleName
                        PrincipalId          = [string]$e.principalId
                        PrincipalType        = [string]($e.principal['@odata.type'] ?? 'unknown')
                        PrincipalDisplayName = [string]($e.principal.displayName ?? 'unknown')
                        PrincipalUPN         = [string]($e.principal.userPrincipalName ?? '')
                        DirectoryScopeId     = [string]($e.directoryScopeId ?? '/')
                        IsPriv               = ($privRoleNames -contains $roleName)
                        OnPremisesSyncEnabled= $e.principal.onPremisesSyncEnabled
                        StartDateTime        = [string]($e.scheduleInfo.startDateTime ?? '')
                        EndDateTime          = [string]($e.scheduleInfo.expiration.endDateTime ?? '')
                        MemberType           = [string]($e.memberType ?? 'Direct')
                    })
                }
                $eligNext = $pageResp['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $eligNext) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'AAD-RoleEligibility' `
                        -Message "Pagination cap reached ($maxPages pages); eligibility schedule list may be truncated."
                }
            }
            $result.Data.RoleEligibilitySchedules = $eligibility.ToArray()
        } catch {
            # PIM not licensed (Entra P1+) — non-fatal. Note also covered by
            # the dedicated PIM collector wrapper, but reading it here lets
            # AAD-Roles consumers see a unified view without cross-collector
            # ordering dependencies.
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-RoleEligibility' -Message $_.Exception.Message
            }
        }

        # Build combined view: permanent + eligible, with Source flag.
        $combined = [System.Collections.Generic.List[object]]::new()
        foreach ($a in @($result.Data.RoleAssignments)) {
            $copy = @{} + $a
            $copy.Source = 'permanent'
            $combined.Add($copy)
        }
        foreach ($e in @($result.Data.RoleEligibilitySchedules)) {
            $copy = @{} + $e
            $copy.Source = 'eligible'
            $combined.Add($copy)
        }
        $result.Data.AllPrivilegedAssignments = @($combined.ToArray() | Where-Object { $_.IsPriv })

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

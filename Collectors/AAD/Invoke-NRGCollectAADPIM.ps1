#Requires -Version 7.0
#
# Invoke-NRGCollectAADPIM.ps1  (v4.5.5)
# Collects PIM eligible/active role schedules and activation policies.
# Requires Entra ID P2 license. Gracefully skips if PIM not available.
# READ-ONLY.
#
# Required Graph scopes: RoleManagement.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup
#
# NIST SP 800-53: AC-6 (least privilege), AC-6(5) (privileged accounts)
# MITRE ATT&CK:   T1548 (Abuse Elevation Control Mechanism)
#

function Invoke-NRGCollectAADPIM {
    [CmdletBinding()] param()

    $result = @{
        Success  = $false
        PIMAvailable = $false
        Data     = @{
            EligibleSchedules = @()
            ActiveSchedules   = @()
            RolePolicies      = @()
        }
    }

    try {
        # Probe whether PIM is available (P2 license check)
        try {
            $testResp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$top=1' `
                -ErrorAction Stop
            $result.PIMAvailable = $true
        } catch {
            # 403 = no P2 license, 404 = not applicable — both are non-fatal
            if ($_.Exception.Message -match '403|Forbidden|Unauthorized|NotFound') {
                if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
                    Register-NRGCoverage -Family 'AAD-PIM' -Status 'NotCollected' `
                        -Note 'PIM not available (requires Entra P2 license)'
                }
                $result.Success = $true  # Not a failure — expected on E3 tenants
                if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
                    Set-NRGRawData -Key 'AAD-PIMSchedules' -Data $result
                }
                return $result
            }
            throw  # Re-throw unexpected errors
        }

        # Eligible schedules (PIM configured but not active)
        try {
            $eligLink = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition&$top=200'
            $eligList = [System.Collections.Generic.List[object]]::new()

            while ($eligLink) {
                $resp = Invoke-MgGraphRequest -Method GET -Uri $eligLink -ErrorAction Stop
                foreach ($s in @($resp.value ?? @())) {
                    $eligList.Add(@{
                        Id                 = [string]$s.id
                        RoleDefinitionId   = [string]$s.roleDefinitionId
                        RoleDisplayName    = [string]($s.roleDefinition.displayName ?? '')
                        PrincipalId        = [string]$s.principalId
                        PrincipalUPN       = [string]($s.principal.userPrincipalName ?? '')
                        PrincipalType      = [string]($s.principal.'@odata.type' ?? '')
                        Status             = [string]$s.status
                        MemberType         = [string]$s.memberType
                        StartDateTime      = [string]($s.scheduleInfo.startDateTime ?? '')
                        Expiration         = [string]($s.scheduleInfo.expiration.type ?? 'noExpiration')
                        DirectoryScopeId   = [string]$s.directoryScopeId
                    })
                }
                $eligLink = $resp.'@odata.nextLink'
            }
            $result.Data.EligibleSchedules = $eligList.ToArray()
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-PIM-Eligible' -Message $_.Exception.Message
            }
        }

        # Active schedules (PIM-activated roles currently active)
        try {
            $activeLink = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?$expand=principal,roleDefinition&$top=200'
            $activeList = [System.Collections.Generic.List[object]]::new()

            while ($activeLink) {
                $resp = Invoke-MgGraphRequest -Method GET -Uri $activeLink -ErrorAction Stop
                foreach ($s in @($resp.value ?? @())) {
                    $activeList.Add(@{
                        Id               = [string]$s.id
                        RoleDefinitionId = [string]$s.roleDefinitionId
                        RoleDisplayName  = [string]($s.roleDefinition.displayName ?? '')
                        PrincipalId      = [string]$s.principalId
                        PrincipalUPN     = [string]($s.principal.userPrincipalName ?? '')
                        PrincipalType    = [string]($s.principal.'@odata.type' ?? '')
                        AssignmentType   = [string]$s.assignmentType
                        MemberType       = [string]$s.memberType
                        Status           = [string]$s.status
                        StartDateTime    = [string]($s.scheduleInfo.startDateTime ?? '')
                        Expiration       = [string]($s.scheduleInfo.expiration.type ?? 'noExpiration')
                    })
                }
                $activeLink = $resp.'@odata.nextLink'
            }
            $result.Data.ActiveSchedules = $activeList.ToArray()
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-PIM-Active' -Message $_.Exception.Message
            }
        }

        # PIM role management policies (activation settings per role)
        try {
            $policyResp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?$top=50&$filter=scopeType eq ''DirectoryRole''' `
                -ErrorAction Stop
            $result.Data.RolePolicies = @($policyResp.value ?? @() | ForEach-Object {
                @{
                    Id                  = [string]$_.id
                    DisplayName         = [string]$_.displayName
                    IsOrganizationDefault = [bool]($_.isOrganizationDefault ?? $false)
                    LastModifiedDateTime  = [string]($_.lastModifiedDateTime ?? '')
                    ScopeId             = [string]$_.scopeId
                    ScopeType           = [string]$_.scopeType
                    # Rules are complex nested objects — collect as raw for evaluator inspection
                    Rules               = @($_.rules ?? @())
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-PIM-Policies' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-PIM' -Status 'Collected' `
                -Note "Eligible=$($result.Data.EligibleSchedules.Count) Active=$($result.Data.ActiveSchedules.Count)"
        }

    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'AAD-PIM' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-PIM' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'AAD-PIMSchedules' -Data $result
    }
    return $result
}

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
        # AAD-8.2: set $true only when the access-review definitions were actually
        # read. Stays $false when AccessReview.Read.All hasn't been consented, so
        # the evaluator reports NotApplicable rather than a false "no reviews" gap.
        AccessReviewsCollected = $false
        Data     = @{
            EligibleSchedules = @()
            ActiveSchedules   = @()
            RolePolicies      = @()
            AccessReviews     = @()
            # Every section above is pre-initialised to @() and every query below
            # has its own try/catch, so presence alone cannot distinguish "queried,
            # this tenant has none" from "the query failed". Test-NRGSectionCollected
            # reads a present-but-empty array as collected, so without this map a
            # failed PIM query looked like a tenant with no PIM adoption.
            SectionStatus = @{
                EligibleSchedules = 'NotRun'
                ActiveSchedules   = 'NotRun'
                RolePolicies      = 'NotRun'
                AccessReviews     = 'NotRun'
            }
        }
    }

    try {
        # Probe whether PIM is available (P2 license check). The response body
        # is intentionally discarded — only the fact that the call didn't
        # throw matters (P2 licensing gates this endpoint with a 403).
        try {
            $null = Invoke-NRGGraphRequest -Method GET `
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
            # Pagination cap (v4.6.3 P2): see AADRoles for rationale.
            $maxPages  = 200
            $pageCount = 0

            while ($eligLink -and $pageCount -lt $maxPages) {
                $resp = Invoke-NRGGraphRequest -Method GET -Uri $eligLink -ErrorAction Stop
                foreach ($s in @($resp.value ?? @())) {
                    # The expanded 'principal' is a directoryObject that may be a
                    # user, GROUP, or SERVICE PRINCIPAL (group-based / workload PIM
                    # eligibility). Groups/SPs have no userPrincipalName, so a bare
                    # $s.principal.userPrincipalName THROWS on those rows and aborts
                    # the whole enumeration. Same shape-safe read as AADRoles.ps1.
                    $pr = Get-NRGObjectField -Item $s -Key 'principal' -Default @{}
                    $eligList.Add(@{
                        Id                 = [string]$s.id
                        RoleDefinitionId   = [string]$s.roleDefinitionId
                        # $expand=roleDefinition can come back absent (e.g. a
                        # deleted or inaccessible role definition), and a bare
                        # $s.roleDefinition.displayName throws at that point
                        # under StrictMode.
                        RoleDisplayName    = [string](Get-NRGNestedProperty -Object $s -Path 'roleDefinition.displayName' -Default '')
                        PrincipalId        = [string]$s.principalId
                        PrincipalUPN       = [string](Get-NRGObjectField -Item $pr -Key 'userPrincipalName' -Default '')
                        PrincipalType      = [string](Get-NRGObjectField -Item $pr -Key '@odata.type' -Default '')
                        Status             = [string]$s.status
                        MemberType         = [string]$s.memberType
                        StartDateTime      = [string](Get-NRGNestedProperty -Object $s -Path 'scheduleInfo.startDateTime' -Default '')
                        Expiration         = [string](Get-NRGNestedProperty -Object $s -Path 'scheduleInfo.expiration.type' -Default 'noExpiration')
                        DirectoryScopeId   = [string]$s.directoryScopeId
                    })
                }
                $eligLink = $resp['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $eligLink) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'AAD-PIM-Eligible' `
                        -Message "Pagination cap reached ($maxPages pages); eligible schedule list may be truncated."
                }
            }
            $result.Data.EligibleSchedules = $eligList.ToArray()
            $result.Data.SectionStatus.EligibleSchedules = 'Collected'
        } catch {
            $result.Data.SectionStatus.EligibleSchedules = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-PIM-Eligible' -Message $_.Exception.Message
            }
        }

        # Active schedules (PIM-activated roles currently active)
        try {
            $activeLink = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?$expand=principal,roleDefinition&$top=200'
            $activeList = [System.Collections.Generic.List[object]]::new()
            # Pagination cap (v4.6.3 P2)
            $maxPages   = 200
            $pageCount2 = 0

            while ($activeLink -and $pageCount2 -lt $maxPages) {
                $resp = Invoke-NRGGraphRequest -Method GET -Uri $activeLink -ErrorAction Stop
                foreach ($s in @($resp.value ?? @())) {
                    # Same shape-safe principal read as the eligible-schedules block
                    # above — the expanded principal may be a group or service
                    # principal with no userPrincipalName.
                    $pr = Get-NRGObjectField -Item $s -Key 'principal' -Default @{}
                    $activeList.Add(@{
                        Id               = [string]$s.id
                        RoleDefinitionId = [string]$s.roleDefinitionId
                        # See rationale above (eligible-schedules block) —
                        # $expand=roleDefinition can come back absent.
                        RoleDisplayName  = [string](Get-NRGNestedProperty -Object $s -Path 'roleDefinition.displayName' -Default '')
                        PrincipalId      = [string]$s.principalId
                        PrincipalUPN     = [string](Get-NRGObjectField -Item $pr -Key 'userPrincipalName' -Default '')
                        PrincipalType    = [string](Get-NRGObjectField -Item $pr -Key '@odata.type' -Default '')
                        AssignmentType   = [string]$s.assignmentType
                        MemberType       = [string]$s.memberType
                        Status           = [string]$s.status
                        StartDateTime    = [string](Get-NRGNestedProperty -Object $s -Path 'scheduleInfo.startDateTime' -Default '')
                        Expiration       = [string](Get-NRGNestedProperty -Object $s -Path 'scheduleInfo.expiration.type' -Default 'noExpiration')
                    })
                }
                $activeLink = $resp['@odata.nextLink']
                $pageCount2++
            }
            if ($pageCount2 -ge $maxPages -and $activeLink) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'AAD-PIM-Active' `
                        -Message "Pagination cap reached ($maxPages pages); active schedule list may be truncated."
                }
            }
            $result.Data.ActiveSchedules = $activeList.ToArray()
            $result.Data.SectionStatus.ActiveSchedules = 'Collected'
        } catch {
            $result.Data.SectionStatus.ActiveSchedules = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-PIM-Active' -Message $_.Exception.Message
            }
        }

        # PIM role management policies (activation settings per role)
        try {
            $policyResp = Invoke-NRGGraphRequest -Method GET `
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
            $result.Data.SectionStatus.RolePolicies = 'Collected'
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-PIM-Policies' -Message $_.Exception.Message
            }
        }

        # Access review definitions for privileged roles (AAD-8.2). Requires the
        # AccessReview.Read.All scope — a re-consent scope. On 403 (scope not yet
        # consented) leave AccessReviewsCollected = $false so the evaluator reports
        # NotApplicable, not a false gap. Read-only GET.
        try {
            $arList  = [System.Collections.Generic.List[object]]::new()
            $arLink  = 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?$top=100'
            $arPages = 0
            while ($arLink -and $arPages -lt 50) {
                $arResp = Invoke-NRGGraphRequest -Method GET -Uri $arLink -ErrorAction Stop
                foreach ($d in @($arResp.value ?? @())) {
                    $scopeQuery = [string](Get-NRGNestedProperty -Object $d -Path 'scope.query' -Default '')
                    $recurType  = [string](Get-NRGNestedProperty -Object $d -Path 'settings.recurrence.pattern.type' -Default 'noRecurrence')
                    $arList.Add(@{
                        Id           = [string]$d.id
                        DisplayName  = [string]($d.displayName ?? '')
                        Status       = [string]($d.status ?? '')
                        ScopeQuery   = $scopeQuery
                        IsRecurring  = [bool]($recurType -and $recurType -ne 'noRecurrence')
                        # A review targets privileged directory roles when its scope
                        # queries roleManagement/directory (the PIM role-assignment
                        # instances) rather than a group or app.
                        TargetsRoles = [bool]($scopeQuery -match 'roleManagement/directory|roleAssignmentScheduleInstances|directoryRole')
                    })
                }
                $arLink = [string](Get-NRGObjectField -Item $arResp -Key '@odata.nextLink' -Default '')
                $arPages++
            }
            $result.Data.AccessReviews = @($arList)
            $result.Data.SectionStatus.AccessReviews = 'Collected'
            $result.AccessReviewsCollected = $true
        } catch {
            if ($_.Exception.Message -match '403|Forbidden|Unauthorized|Authorization_RequestDenied|Accepted') {
                if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
                    Register-NRGCoverage -Family 'AAD-AccessReviews' -Status 'NotCollected' `
                        -Note 'AccessReview.Read.All not consented (re-consent required for AAD-8.2)'
                }
            } else {
                $result.Data.SectionStatus.AccessReviews = 'Failed'
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'AAD-AccessReviews' -Message $_.Exception.Message
                }
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

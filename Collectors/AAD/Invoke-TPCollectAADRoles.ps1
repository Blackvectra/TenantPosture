#Requires -Version 7.0
#
# Invoke-TPCollectAADRoles.ps1  (v4.5.5)
# Collects directory role assignments (active, permanent, and service principals).
# READ-ONLY.
#
# Required Graph scopes: RoleManagement.Read.All, Directory.Read.All
#
# NIST SP 800-53: AC-6 (least privilege), AC-6(5) (privileged accounts)
# MITRE ATT&CK:   T1078.004 (Cloud Accounts), T1098 (Account Manipulation)
#

function Invoke-TPCollectAADRoles {
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
            # Per-source collection outcome. Success below is
            # (assignments -OR- eligibility), so a tenant where the permanent
            # -assignment call failed but eligibility succeeded still reports
            # Success = $true with RoleAssignments / PrivRoles empty. Evaluators
            # that read those lists must not treat empty as "nothing found":
            # every real tenant has at least one privileged assignment, so an
            # empty list is a failed read, not a clean tenant.
            SectionStatus = @{
                RoleAssignments          = 'NotRun'
                RoleEligibilitySchedules = 'NotRun'
            }
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
        # Built-in role TEMPLATE ids (Microsoft Entra built-in roles reference;
        # a built-in role's roleDefinitionId equals its template id in every
        # tenant). With the roleDefinitions read failed, names fell back to the
        # GUID, every assignment scored IsPriv=$false, and AAD-3.2 reported
        # "No permanent privileged role assignments" beside a permanent GA.
        $privRoleTemplates = @{
            '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
            'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
            '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
            '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
            'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
            'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
            '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
            '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
            'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
            '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
            '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
            '17315797-102d-40b4-93e0-432062caca18' = 'Compliance Administrator'
            'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
            '69091246-20e8-4a56-aa4d-066075b2a7a8' = 'Teams Administrator'
            '9f06204d-73c1-4d4c-880a-6edb90606fd8' = 'Azure AD Joined Device Local Administrator'
            '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
            'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
        }

        # Get all role definitions (we need names to match). A tenant's
        # built-in plus custom role definitions can exceed a single $top=200
        # page; a role definition missing from a truncated result falls back
        # to its GUID as the name below, is scored IsPriv=$false, and any
        # assignment to it is silently excluded from PrivRoles /
        # AllPrivilegedAssignments — a privileged-assignment undercount with
        # no signal that anything was missed. Page through nextLink exactly
        # as the role assignments query below already does.
        try {
            $mkRoleDef = {
                param($rd)
                $dn = [string](Get-TPObjectField -Item $rd -Key 'displayName' -Default '')
                @{
                    Id          = [string](Get-TPObjectField -Item $rd -Key 'id' -Default '')
                    DisplayName = $dn
                    IsBuiltIn   = [bool](Get-TPObjectField -Item $rd -Key 'isBuiltIn' -Default $false)
                    IsEnabled   = [bool](Get-TPObjectField -Item $rd -Key 'isEnabled' -Default $true)
                    IsPriv      = ($privRoleNames -contains $dn)
                }
            }

            $roleDefResp = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,isEnabled&$top=200' `
                -ErrorAction Stop
            # Shape-safe: a role definition missing any $select'd field (isBuiltIn,
            # isEnabled) would otherwise throw and empty the whole map, so every
            # assignment falls back to a GUID name and the GA-by-name filter finds
            # nothing — another path to a false "0 Global Administrators".
            $roleDefs = [System.Collections.Generic.List[object]]::new()
            foreach ($rd in @($roleDefResp.value ?? @())) { $roleDefs.Add((& $mkRoleDef $rd)) }

            $rdNextLink  = $roleDefResp['@odata.nextLink']
            $rdMaxPages  = 200
            $rdPageCount = 0
            while ($rdNextLink -and $rdPageCount -lt $rdMaxPages) {
                $rdPageResp = Invoke-TPGraphRequest -Method GET -Uri $rdNextLink -ErrorAction Stop
                foreach ($rd in @($rdPageResp.value ?? @())) { $roleDefs.Add((& $mkRoleDef $rd)) }
                $rdNextLink = $rdPageResp['@odata.nextLink']
                $rdPageCount++
            }
            if ($rdPageCount -ge $rdMaxPages -and $rdNextLink) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'AAD-RoleDefinitions' `
                        -Message "Pagination cap reached ($rdMaxPages pages). Possible nextLink loop or very large dataset; role definitions may be truncated."
                }
            }

            $result.Data.RoleDefinitions = $roleDefs.ToArray()
        } catch {
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-RoleDefinitions' -Message $_.Exception.Message
            }
        }

        # Build role ID → name lookup
        $roleMap = @{}
        foreach ($rd in @($result.Data.RoleDefinitions)) {
            $roleMap[$rd.Id] = $rd.DisplayName
        }

        # Honest-success flags: at least one privileged-assignment SOURCE must
        # actually collect, or the collector reports Success=$false so GA-count /
        # privileged-role evaluators route to NotApplicable instead of a false
        # "0 Global Administrators". PIM tenants have 0 permanent + N eligible;
        # non-PIM tenants have N permanent + 0 eligible — either alone is valid.
        $assignmentsOk = $false
        $eligibilityOk = $false

        # Get active (permanent) role assignments — expanded to get principal details
        try {
            $assignResp = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$top=500' `
                -ErrorAction Stop

            $assignments = [System.Collections.Generic.List[object]]::new()
            $nextLink = $assignResp['@odata.nextLink']

            # Safe per-assignment projection. The expanded 'principal' is a
            # directoryObject that may be a user, GROUP, or SERVICE PRINCIPAL.
            # Groups/SPs have NO userPrincipalName, so a bare
            # $a.principal.userPrincipalName THROWS on those rows (PS 7.4 missing
            # key; PS 7.5+ / PSCustomObject on $null.leaf) and aborted the whole
            # enumeration — the root cause of a tenant with real Global Admins
            # reporting "Permanent Global Administrator count: 0". Read every
            # principal field through the shape-safe helper.
            $mkAssignment = {
                param($a)
                $pr = Get-TPObjectField -Item $a -Key 'principal' -Default @{}
                $roleName = $roleMap[(Get-TPObjectField -Item $a -Key 'roleDefinitionId')] ?? $privRoleTemplates[[string](Get-TPObjectField -Item $a -Key 'roleDefinitionId' -Default '')] ?? (Get-TPObjectField -Item $a -Key 'roleDefinitionId' -Default '')
                @{
                    Id                   = [string](Get-TPObjectField -Item $a -Key 'id' -Default '')
                    RoleDefinitionId     = [string](Get-TPObjectField -Item $a -Key 'roleDefinitionId' -Default '')
                    RoleDefinitionName   = $roleName
                    PrincipalId          = [string](Get-TPObjectField -Item $a -Key 'principalId' -Default '')
                    PrincipalType        = [string](Get-TPObjectField -Item $pr -Key '@odata.type' -Default 'unknown')
                    PrincipalDisplayName = [string](Get-TPObjectField -Item $pr -Key 'displayName' -Default 'unknown')
                    PrincipalUPN         = [string](Get-TPObjectField -Item $pr -Key 'userPrincipalName' -Default '')
                    DirectoryScopeId     = [string](Get-TPObjectField -Item $a -Key 'directoryScopeId' -Default '/')
                    IsPriv               = ($privRoleNames -contains $roleName)
                    OnPremisesSyncEnabled = (Get-TPObjectField -Item $pr -Key 'onPremisesSyncEnabled' -Default $null)
                }
            }

            foreach ($a in @($assignResp.value ?? @())) {
                $assignments.Add((& $mkAssignment $a))
            }

            # Page through remaining assignments.
            # Pagination cap (v4.6.3 P2): a misbehaving proxy or service that
            # echoes back the same nextLink would create an infinite loop. Cap
            # at 200 pages — at default Graph $top this is ~20k assignments,
            # which exceeds any realistic tenant role assignment count.
            $maxPages   = 200
            $pageCount  = 0
            while ($nextLink -and $pageCount -lt $maxPages) {
                $pageResp = Invoke-TPGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
                foreach ($a in @($pageResp.value ?? @())) {
                    $assignments.Add((& $mkAssignment $a))
                }
                $nextLink = $pageResp['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $nextLink) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'AAD-Roles' `
                        -Message "Pagination cap reached ($maxPages pages). Possible nextLink loop or very large dataset; role assignments may be truncated."
                }
            }

            $result.Data.RoleAssignments = $assignments.ToArray()
            $result.Data.PrivRoles       = @($assignments | Where-Object { $_.IsPriv })
            $assignmentsOk = $true
            $result.Data.SectionStatus.RoleAssignments = 'Collected'

        } catch {
            $result.Data.SectionStatus.RoleAssignments = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-RoleAssignments' -Message $_.Exception.Message
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
            $eligResp = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal&$top=500' `
                -ErrorAction Stop
            $eligNext = $eligResp['@odata.nextLink']

            # Same shape-safe projection as permanent assignments, plus the
            # PIM schedule window (scheduleInfo.expiration.endDateTime is also a
            # deep chain that throws when absent).
            $mkEligible = {
                param($e)
                $pr = Get-TPObjectField -Item $e -Key 'principal' -Default @{}
                $roleName = $roleMap[(Get-TPObjectField -Item $e -Key 'roleDefinitionId')] ?? $privRoleTemplates[[string](Get-TPObjectField -Item $e -Key 'roleDefinitionId' -Default '')] ?? (Get-TPObjectField -Item $e -Key 'roleDefinitionId' -Default '')
                @{
                    Id                   = [string](Get-TPObjectField -Item $e -Key 'id' -Default '')
                    RoleDefinitionId     = [string](Get-TPObjectField -Item $e -Key 'roleDefinitionId' -Default '')
                    RoleDefinitionName   = $roleName
                    PrincipalId          = [string](Get-TPObjectField -Item $e -Key 'principalId' -Default '')
                    PrincipalType        = [string](Get-TPObjectField -Item $pr -Key '@odata.type' -Default 'unknown')
                    PrincipalDisplayName = [string](Get-TPObjectField -Item $pr -Key 'displayName' -Default 'unknown')
                    PrincipalUPN         = [string](Get-TPObjectField -Item $pr -Key 'userPrincipalName' -Default '')
                    DirectoryScopeId     = [string](Get-TPObjectField -Item $e -Key 'directoryScopeId' -Default '/')
                    IsPriv               = ($privRoleNames -contains $roleName)
                    OnPremisesSyncEnabled= (Get-TPObjectField -Item $pr -Key 'onPremisesSyncEnabled' -Default $null)
                    StartDateTime        = [string](Get-TPNestedProperty -Object $e -Path 'scheduleInfo.startDateTime' -Default '')
                    EndDateTime          = [string](Get-TPNestedProperty -Object $e -Path 'scheduleInfo.expiration.endDateTime' -Default '')
                    MemberType           = [string](Get-TPObjectField -Item $e -Key 'memberType' -Default 'Direct')
                }
            }

            foreach ($e in @($eligResp.value ?? @())) {
                $eligibility.Add((& $mkEligible $e))
            }
            $maxPages  = 200
            $pageCount = 0
            while ($eligNext -and $pageCount -lt $maxPages) {
                $pageResp = Invoke-TPGraphRequest -Method GET -Uri $eligNext -ErrorAction Stop
                foreach ($e in @($pageResp.value ?? @())) {
                    $eligibility.Add((& $mkEligible $e))
                }
                $eligNext = $pageResp['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $eligNext) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'AAD-RoleEligibility' `
                        -Message "Pagination cap reached ($maxPages pages); eligibility schedule list may be truncated."
                }
            }
            $result.Data.RoleEligibilitySchedules = $eligibility.ToArray()
            $eligibilityOk = $true
            $result.Data.SectionStatus.RoleEligibilitySchedules = 'Collected'
        } catch {
            $result.Data.SectionStatus.RoleEligibilitySchedules = 'Failed'
            # PIM not licensed (Entra P1+) — non-fatal. Note also covered by
            # the dedicated PIM collector wrapper, but reading it here lets
            # AAD-Roles consumers see a unified view without cross-collector
            # ordering dependencies.
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-RoleEligibility' -Message $_.Exception.Message
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

        # Success only if at least one privileged-assignment source collected.
        $result.Success = ($assignmentsOk -or $eligibilityOk)
        if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
            if ($result.Success) {
                Register-TPCoverage -Family 'AAD-Roles' -Status 'Collected' `
                    -Note "$($result.Data.RoleAssignments.Count) permanent, $($result.Data.RoleEligibilitySchedules.Count) eligible"
            } else {
                Register-TPCoverage -Family 'AAD-Roles' -Status 'Failed' -Note 'role assignments + eligibility both failed — see exceptions'
            }
        }

    } catch {
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'AAD-Roles' -Message $_.Exception.Message
        }
        if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
            Register-TPCoverage -Family 'AAD-Roles' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'AAD-DirectoryRoles' -Data $result
    }
    return $result
}

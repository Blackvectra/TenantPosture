#Requires -Version 7.0
#
# Invoke-TPCollectAADAppPermissions.ps1
# Dependencies: Invoke-TPGraphRequest, Set-TPRawData, Get-TPNestedProperty,
#               Register-TPException, Register-TPCoverage
# TenantPosture
# Author: Matthew Levorson
#
# Sets:     AAD-AppPermissions (Data.Grants, Data.Principals, Data.SectionStatus)
# Consumes: nothing
# Scopes:   Application.Read.All, Directory.Read.All, Organization.Read.All
#           — all three are already in the tool's scope list. NO RE-CONSENT.
#
# WHY THIS EXISTS
# ---------------
# AAD-12.4 reads `oauth2PermissionGrants` with consentType 'AllPrincipals'.
# That is the DELEGATED consent table: an app acting AS A SIGNED-IN USER. It
# is a real risk and the control is right to check it.
#
# It is also only half the picture, and the quieter half is the dangerous one.
# APPLICATION permissions — app-only, granted as appRoleAssignments — let an
# app act with NO user at all. No MFA prompt. No Conditional Access evaluation,
# because there is no sign-in to apply a policy to. A sign-in log entry that
# does not look like a person. An app holding `Mail.ReadWrite` as an
# application permission reads every mailbox in the tenant; one holding
# `RoleManagement.ReadWrite.Directory` can make itself Global Administrator.
#
# None of that appears in `oauth2PermissionGrants`. A malicious app-only grant
# returns ZERO rows from the endpoint AAD-12.4 queries, so the control reports
# "No tenant-wide OAuth consent grants found" and the report says the tenant is
# clean. This collector closes that hole.
#
# HOW IT COLLECTS
# ---------------
# Rather than asking every service principal what it holds (one call each,
# hundreds of calls), it asks each high-value RESOURCE who has been granted a
# role on it: `GET /servicePrincipals/{resourceSpId}/appRoleAssignedTo`. Three
# resources cover the ground that matters — Microsoft Graph, Exchange Online
# and SharePoint — so the whole collection is a handful of paged queries.
#
# `appRoleId` is a GUID. Translating it to a permission name needs the resource
# SP's own `appRoles` collection, which the same lookup already returns.
#
# EMPTY IS NOT CLEAN
# ------------------
# Each resource is queried independently so one failure does not abort the
# rest, which makes an empty Grants list ambiguous exactly the way the
# collector doctrine describes. `SectionStatus` is published per resource, and
# the evaluators refuse to conclude "no dangerous app permissions" from an
# empty list unless the section actually completed. A tenant-takeover control
# that reports Satisfied because the query 403'd is the worst output this tool
# could produce.

function Invoke-TPCollectAADAppPermissions {
    [CmdletBinding()] param()

    $result = @{
        Success = $false
        Data    = [ordered]@{
            # Per-resource collection outcome: NotRun / Collected / Failed.
            SectionStatus  = [ordered]@{}
            # One row per app-role assignment on a watched resource.
            Grants         = @()
            # Service principals seen, keyed by object id, for owner lookup.
            Principals     = [ordered]@{}
            TenantId       = ''
            ResourcesFound = @()
            Errors         = @()
        }
    }

    # Well-known resource appIds. Hardcoding these is safe and deliberate:
    # they are Microsoft's fixed first-party application identifiers, identical
    # in every tenant on earth, and are not tenant data.
    $watched = [ordered]@{
        'Microsoft Graph'            = '00000003-0000-0000-c000-000000000000'
        'Office 365 Exchange Online' = '00000002-0000-0ff1-ce00-000000000000'
        'SharePoint Online'          = '00000003-0000-0ff1-ce00-000000000000'
    }
    foreach ($n in $watched.Keys) { $result.Data.SectionStatus[$n] = 'NotRun' }

    $maxPages = 25

    try {
        # ── Tenant id, so a home-tenant app registration can be told apart
        #    from a genuinely external multi-tenant one ─────────────────────
        try {
            $org = Invoke-TPGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id' -ErrorAction Stop
            $orgRows = @(Get-TPNestedProperty -Object $org -Path 'value' -Default @())
            if ($orgRows.Count -gt 0) {
                $result.Data.TenantId = [string](Get-TPNestedProperty -Object $orgRows[0] -Path 'id' -Default '')
            }
        } catch {
            # Not fatal: without it, a tenant-owned app is reported as external,
            # which is the conservative direction (more scrutiny, not less).
            $result.Data.Errors += "TenantId: $($_.Exception.Message)"
        }

        # ── Service principal directory, for owner attribution ─────────────
        # One paged query with $select rather than a lookup per grantee.
        $principals = [ordered]@{}
        try {
            $next = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled&$top=999'
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($sp in @(Get-TPNestedProperty -Object $page -Path 'value' -Default @())) {
                    $spId = [string](Get-TPNestedProperty -Object $sp -Path 'id' -Default '')
                    if (-not $spId) { continue }
                    $principals[$spId] = [ordered]@{
                        Id            = $spId
                        AppId         = [string](Get-TPNestedProperty -Object $sp -Path 'appId' -Default '')
                        DisplayName   = [string](Get-TPNestedProperty -Object $sp -Path 'displayName' -Default '')
                        OwnerOrgId    = [string](Get-TPNestedProperty -Object $sp -Path 'appOwnerOrganizationId' -Default '')
                        Type          = [string](Get-TPNestedProperty -Object $sp -Path 'servicePrincipalType' -Default '')
                        Enabled       = [bool](Get-TPNestedProperty -Object $sp -Path 'accountEnabled' -Default $true)
                    }
                }
                # NOT Get-TPNestedProperty: it splits the path on '.', so
                # '@odata.nextLink' becomes @odata -> nextLink, never resolves,
                # and paging silently stops after the first page. A tenant with
                # more than one page of assignments would then be reported as
                # fully enumerated off a partial list. Get-TPObjectField is a
                # flat key lookup and handles the dotted key correctly.
                $next = [string](Get-TPObjectField -Item $page -Key '@odata.nextLink' -Default '')
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                $result.Data.Errors += 'ServicePrincipals: page cap reached; owner attribution may be incomplete.'
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'AAD-AppPermissions' -Message 'Service principal enumeration hit the page cap; some grantees may be reported with an unknown owner.'
                }
            }
        } catch {
            $result.Data.Errors += "ServicePrincipals: $($_.Exception.Message)"
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-AppPermissions' -Message "Service principal enumeration failed: $($_.Exception.Message)"
            }
        }
        $result.Data.Principals = $principals

        # ── Per-resource app role assignments ──────────────────────────────
        $grants = [System.Collections.Generic.List[object]]::new()
        foreach ($resName in @($watched.Keys)) {
            $resAppId = $watched[$resName]
            try {
                # Resolve the resource SP and its appRoles (id -> permission value).
                $spResp = Invoke-TPGraphRequest -Method GET -ErrorAction Stop `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$resAppId'&`$select=id,displayName,appRoles"
                $spRows = @(Get-TPNestedProperty -Object $spResp -Path 'value' -Default @())
                if ($spRows.Count -eq 0) {
                    # The resource has no service principal in this tenant,
                    # which is a real answer: nothing can hold a role on it.
                    $result.Data.SectionStatus[$resName] = 'Collected'
                    continue
                }
                $resSp   = $spRows[0]
                $resSpId = [string](Get-TPNestedProperty -Object $resSp -Path 'id' -Default '')
                if (-not $resSpId) { throw "resource service principal for $resName returned no id" }
                $result.Data.ResourcesFound += $resName

                $roleMap = @{}
                foreach ($role in @(Get-TPNestedProperty -Object $resSp -Path 'appRoles' -Default @())) {
                    $rid = [string](Get-TPNestedProperty -Object $role -Path 'id' -Default '')
                    if ($rid) {
                        $roleMap[$rid] = [string](Get-TPNestedProperty -Object $role -Path 'value' -Default '')
                    }
                }

                $next = "https://graph.microsoft.com/v1.0/servicePrincipals/$resSpId/appRoleAssignedTo?`$top=999"
                $pageCount = 0
                while ($next -and $pageCount -lt $maxPages) {
                    $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                    foreach ($a in @(Get-TPNestedProperty -Object $page -Path 'value' -Default @())) {
                        $roleId = [string](Get-TPNestedProperty -Object $a -Path 'appRoleId' -Default '')
                        $permission = if ($roleMap.ContainsKey($roleId)) { $roleMap[$roleId] } else { '' }
                        $principalId = [string](Get-TPNestedProperty -Object $a -Path 'principalId' -Default '')

                        $ownerOrg = ''
                        $appId    = ''
                        $enabled  = $true
                        if ($principalId -and $principals.Contains($principalId)) {
                            $p        = $principals[$principalId]
                            $ownerOrg = [string]$p.OwnerOrgId
                            $appId    = [string]$p.AppId
                            $enabled  = [bool]$p.Enabled
                        }

                        $grants.Add([ordered]@{
                            Resource        = $resName
                            Permission      = $permission
                            AppRoleId       = $roleId
                            PrincipalId     = $principalId
                            PrincipalName   = [string](Get-TPNestedProperty -Object $a -Path 'principalDisplayName' -Default '')
                            PrincipalType   = [string](Get-TPNestedProperty -Object $a -Path 'principalType' -Default '')
                            AppId           = $appId
                            OwnerOrgId      = $ownerOrg
                            AccountEnabled  = $enabled
                            GrantedOn       = [string](Get-TPNestedProperty -Object $a -Path 'createdDateTime' -Default '')
                        })
                    }
                    # Flat key lookup — Get-TPNestedProperty would split on the dot.
                    $next = [string](Get-TPObjectField -Item $page -Key '@odata.nextLink' -Default '')
                    $pageCount++
                }
                if ($pageCount -ge $maxPages -and $next) {
                    # A truncated enumeration is NOT a completed one. Marking it
                    # Collected would let an evaluator read the partial list as
                    # the whole picture.
                    $result.Data.SectionStatus[$resName] = 'Failed'
                    $result.Data.Errors += "${resName}: page cap reached before the assignment list ended."
                    if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                        Register-TPException -Source 'AAD-AppPermissions' -Message "$resName app role assignments hit the page cap; the list is incomplete and is reported as not collected."
                    }
                } else {
                    $result.Data.SectionStatus[$resName] = 'Collected'
                }
            } catch {
                $result.Data.SectionStatus[$resName] = 'Failed'
                $result.Data.Errors += "${resName}: $($_.Exception.Message)"
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'AAD-AppPermissions' -Message "$resName app role assignment enumeration failed: $($_.Exception.Message)"
                }
            }
        }
        $result.Data.Grants = @($grants)
        $result.Success = $true

    } catch {
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'AAD-AppPermissions' -Message $_.Exception.Message
        }
    }

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'AAD-AppPermissions' -Data $result
    }
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        $statuses = @($result.Data.SectionStatus.Values)
        $failed   = @($statuses | Where-Object { $_ -ne 'Collected' }).Count
        $status   = if (-not $result.Success -or $failed -eq $statuses.Count) { 'Failed' }
                    elseif ($failed -gt 0) { 'Partial' }
                    else { 'Collected' }
        $note     = "$(@($result.Data.Grants).Count) application-permission grants across $(@($result.Data.ResourcesFound).Count) resource(s)"
        if ($failed -gt 0) { $note += "; $failed resource(s) did not complete — see Exceptions" }
        Register-TPCoverage -Family 'AAD-AppPermissions' -Status $status -Note $note
    }
    return $result
}

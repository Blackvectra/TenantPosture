#Requires -Version 7.0
#
# Invoke-NRGCollectAADIdentityGovernance.ps1  (v4.5.5)
# Collects SSPR config, guest access settings, app registration/consent policies,
# OAuth consent grants, and identifies break-glass account patterns.
# READ-ONLY.
#
# Required Graph scopes: Policy.Read.All, Directory.Read.All,
#                        Application.Read.All, RoleManagement.Read.All
#
# NIST SP 800-53: AC-2, AC-3, IA-5, AC-6
# MITRE ATT&CK:   T1078, T1098, T1528
#

function Invoke-NRGCollectAADIdentityGovernance {
    [CmdletBinding()] param()

    $result = @{
        Success = $false
        Data    = @{
            SSPRPolicy           = $null
            ExternalCollab       = $null
            AppRegistrationPolicy= $null
            ConsentPolicy        = $null
            OAuthHighRiskGrants  = @()
            BreakGlassIndicators = @()
            PasswordProtection   = $null
            PIMRolePolicies      = @()
            # Empty is not clean: each sub-query below is independently
            # try/catch'd and Success stays $true regardless, so a failed
            # query and "queried, found nothing" are otherwise indistinguishable.
            # Downstream evaluators must consult this before trusting an
            # empty/default section (Test-NRGSectionCollected).
            SectionStatus = @{
                SSPRPolicy           = 'NotRun'
                ExternalCollab       = 'NotRun'
                ConsentPolicy        = 'NotRun'
                OAuthHighRiskGrants  = 'NotRun'
                BreakGlassIndicators = 'NotRun'
                PIMRolePolicies      = 'NotRun'
            }
        }
    }

    try {
        # SSPR / Combined registration policy
        try {
            $sspr = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' `
                -ErrorAction Stop
            # registrationEnforcement (and its nested campaign block) is an
            # OPTIONAL sub-object on authenticationMethodsPolicy, omitted
            # entirely on a tenant that has never touched registration
            # campaign settings — a bare chained read throws at the first
            # absent intermediate under StrictMode.
            $result.Data.SSPRPolicy = @{
                RegistrationEnforcementState = [string](Get-NRGNestedProperty -Object $sspr -Path 'registrationEnforcement.authenticationMethodsRegistrationCampaign.state' -Default 'unknown')
                SnoozeDays                   = [int](Get-NRGNestedProperty -Object $sspr -Path 'registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays' -Default 0)
                MethodsConfigured            = @($sspr.authenticationMethodConfigurations ?? @() | ForEach-Object {
                    @{ Id = [string]$_.id; State = [string]$_.state }
                })
            }
            $result.Data.SectionStatus.SSPRPolicy = 'Collected'
        } catch {
            $result.Data.SectionStatus.SSPRPolicy = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-SSPR' -Message $_.Exception.Message
            }
        }

        # External collaboration / guest invite settings
        try {
            $extCollab = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
                -ErrorAction Stop
            # Graph returns permissionGrantPoliciesAssigned INSIDE
            # defaultUserRolePermissions. Read at the top level it was always
            # empty, so every tenant — including ones where users can consent
            # to ANY app — scored "consent restricted" (AAD-6.2). Two
            # statements, never an if-expression: an empty list (no user
            # consent at all, the best setting) would unroll to $null.
            # $null means "not returned", which is not "none".
            # Read by key presence: the property helpers return an empty
            # array as $null (pipeline unrolling), and empty is the answer
            # that matters most here.
            $permGrant = $null
            foreach ($holder in @((Get-NRGNestedProperty -Object $extCollab -Path 'defaultUserRolePermissions' -Default $null), $extCollab)) {
                if ($null -eq $holder) { continue }
                if ($holder -is [System.Collections.IDictionary]) {
                    if ($holder.Contains('permissionGrantPoliciesAssigned')) { $permGrant = [string[]]@($holder['permissionGrantPoliciesAssigned'] | Where-Object { $_ }); break }
                } elseif ($holder.PSObject.Properties['permissionGrantPoliciesAssigned']) {
                    $permGrant = [string[]]@($holder.permissionGrantPoliciesAssigned | Where-Object { $_ }); break
                }
            }
            # defaultUserRolePermissions is an OPTIONAL nested object on
            # authorizationPolicy — a tenant relying entirely on defaults can
            # omit it, so a bare $extCollab.defaultUserRolePermissions.* read
            # throws under StrictMode at the first absent intermediate.
            $result.Data.ExternalCollab = @{
                # Not returned is unknown, never "everyone" (that default scored
                # a Gap on tenants whose read simply lacked the field).
                AllowInvitesFrom             = [string](Get-NRGObjectField -Item $extCollab -Key 'allowInvitesFrom' -Default '')
                AllowedToSignUpEmailBased    = [bool]($extCollab.allowedToSignUpEmailBasedSubscriptions ?? $true)
                GuestUserRoleId              = [string]($extCollab.guestUserRoleId ?? '')
                DefaultUserRolePermissions   = @{
                    AllowedToCreateApps      = [bool](Get-NRGNestedProperty -Object $extCollab -Path 'defaultUserRolePermissions.allowedToCreateApps' -Default $true)
                    AllowedToCreateGroups    = [bool](Get-NRGNestedProperty -Object $extCollab -Path 'defaultUserRolePermissions.allowedToCreateGroups' -Default $true)
                    AllowedToCreateTenants   = [bool](Get-NRGNestedProperty -Object $extCollab -Path 'defaultUserRolePermissions.allowedToCreateTenants' -Default $true)
                }
                PermissionGrantPolicies      = $permGrant
                BlockMsolPowerShell          = $extCollab.blockMsolPowerShell
            }
            $result.Data.SectionStatus.ExternalCollab = 'Collected'
        } catch {
            $result.Data.SectionStatus.ExternalCollab = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-ExternalCollab' -Message $_.Exception.Message
            }
        }

        # Admin consent request policy
        try {
            $consentPol = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' `
                -ErrorAction Stop
            $result.Data.ConsentPolicy = @{
                IsEnabled = [bool]($consentPol.isEnabled ?? $false)
                Version   = [int]($consentPol.version ?? 0)
                Reviewers = @($consentPol.reviewers ?? @())
            }
            $result.Data.SectionStatus.ConsentPolicy = 'Collected'
        } catch {
            $result.Data.SectionStatus.ConsentPolicy = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-ConsentPolicy' -Message $_.Exception.Message
            }
        }

        # High-risk OAuth consent grants — app-only grants to all users
        try {
            $grants = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=200&$filter=consentType eq ''AllPrincipals''' `
                -ErrorAction Stop
            $result.Data.OAuthHighRiskGrants = @($grants.value ?? @() | ForEach-Object {
                @{
                    ClientId   = [string]$_.clientId
                    ResourceId = [string]$_.resourceId
                    Scope      = [string]$_.scope
                    Type       = [string]$_.consentType
                }
            })
            $result.Data.SectionStatus.OAuthHighRiskGrants = 'Collected'
        } catch {
            $result.Data.SectionStatus.OAuthHighRiskGrants = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-OAuthGrants' -Message $_.Exception.Message
            }
        }

        # Break-glass indicator: look for GA accounts excluded from all CA policies
        # A properly configured break-glass account is a GA with CA exclusions documented
        try {
            $rawRoles = if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) {
                Get-NRGRawData -Key 'AAD-DirectoryRoles'
            } else { $null }

            $caPolicies = if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) {
                Get-NRGRawData -Key 'AAD-CAPolicies'
            } else { $null }

            $breakGlass = @()
            # v4.6.4 EMERGENCY FIX (High #8): the old logic compared
            # $ga.PrincipalId against ExcludeGroups which holds GROUP IDs —
            # group IDs do not match user IDs, so the check always returned
            # false-negative on group-based exclusions. That produced a
            # false-positive "GA missing CA exclusion" finding on every tenant
            # with the documented break-glass pattern of "Global Admin in
            # CA-Exclude group".
            #
            # Fix: when a policy excludes a group, resolve the group's
            # transitive members from Graph and check if $ga.PrincipalId
            # is in the resolved set. Memberships are cached at the
            # per-collector run level — repeated checks across many CA
            # policies and many GAs do not re-fetch the same group.
            $groupMemberCache = @{}
            $resolveGroupMembers = {
                param([string]$groupId)
                if ([string]::IsNullOrWhiteSpace($groupId)) { return @() }
                if ($groupMemberCache.ContainsKey($groupId)) {
                    return $groupMemberCache[$groupId]
                }
                $members = @()
                try {
                    # transitiveMembers expands nested groups; default Graph
                    # uses paginated 100-per-page responses.
                    $next = "https://graph.microsoft.com/v1.0/groups/$groupId/transitiveMembers?`$select=id&`$top=999"
                    $pageCount = 0
                    while ($next -and $pageCount -lt 50) {
                        $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                        foreach ($m in @($page.value ?? @())) {
                            if ($m.id) { $members += [string]$m.id }
                        }
                        $next = $page['@odata.nextLink']
                        $pageCount++
                    }
                } catch {
                    # An unreadable group is UNKNOWN membership, not "no
                    # members": returning an empty set called every
                    # group-excluded break-glass account "not excluded" and
                    # scored AAD-7.2 a Gap. $null marks it unresolved.
                    $members = $null
                    if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                        Register-NRGException -Source 'AAD-BreakGlass-GroupResolve' `
                            -Message "transitiveMembers for $groupId failed: $($_.Exception.Message)"
                    }
                }
                $groupMemberCache[$groupId] = $members
                return $members
            }

            if ($rawRoles -and $rawRoles.Success) {
                # Use AllPrivilegedAssignments where available (covers both
                # permanent and PIM-eligible GAs from the Roles collector
                # v4.6.4 fix), falling back to legacy RoleAssignments for
                # backward compat with older raw-data shapes.
                $candidatePool = if ($rawRoles.Data.AllPrivilegedAssignments) {
                    @($rawRoles.Data.AllPrivilegedAssignments)
                } else {
                    @($rawRoles.Data.RoleAssignments)
                }
                $gaAccounts = @($candidatePool | Where-Object {
                    $_.RoleDefinitionName -eq 'Global Administrator' -and
                    $_.PrincipalType -notmatch 'servicePrincipal'
                })

                # A break-glass account must be excluded from every enabled
                # policy that would otherwise reach it — the all-users and
                # Global Administrator policies. Excluded from ANY one policy
                # used to count, so an admin excluded from a single pilot
                # policy was reported as an emergency access path.
                $gaRoleId = '62e90394-69f5-4237-9190-012177145e10'
                $reaching = @()
                if ($caPolicies -and $caPolicies.Success) {
                    $reaching = @(@($caPolicies.Data.Policies) | Where-Object {
                        $_.State -eq 'enabled' -and (
                            @(Get-NRGNestedProperty -Object $_ -Path 'Conditions.Users.IncludeUsers' -Default @()) -contains 'All' -or
                            @(Get-NRGNestedProperty -Object $_ -Path 'Conditions.Users.IncludeRoles' -Default @()) -contains $gaRoleId)
                    })
                }
                foreach ($ga in $gaAccounts) {
                    $isExcluded = $false
                    if ($caPolicies -and $caPolicies.Success) {
                        $allExcluded = $true; $unknown = $false
                        foreach ($policy in $reaching) {
                            $excludeUsers  = @($policy.Conditions.Users.ExcludeUsers  ?? @())
                            $excludeGroups = @($policy.Conditions.Users.ExcludeGroups ?? @())
                            if ($excludeUsers -contains $ga.PrincipalId) { continue }
                            $matched = $false
                            foreach ($gid in $excludeGroups) {
                                $members = & $resolveGroupMembers $gid
                                if ($null -eq $members) { $unknown = $true; continue }
                                if ($members -contains $ga.PrincipalId) { $matched = $true; break }
                            }
                            if (-not $matched) { $allExcluded = $false; break }
                        }
                        # $null = could not tell (a group membership was unreadable).
                        $isExcluded = if ($allExcluded -and $reaching.Count -gt 0) { $true } elseif ($unknown) { $null } else { $false }
                    }
                    $breakGlass += @{
                        PrincipalId  = [string]$ga.PrincipalId
                        DisplayName  = [string]$ga.PrincipalDisplayName
                        UPN          = [string]$ga.PrincipalUPN
                        CAExcluded   = $isExcluded
                        Synced       = $ga.OnPremisesSyncEnabled -eq $true
                        Source       = [string]($ga.Source ?? 'permanent')
                    }
                }
            }
            $result.Data.BreakGlassIndicators = $breakGlass

            # Section status reflects what CAExcluded actually means. Without
            # role data there is no GA list to check at all — Failed, not an
            # empty "clean" list. With roles but no CA data, every CAExcluded
            # defaulted to $false above and cannot be trusted as "not
            # excluded" — NotRun, since the exclusion check itself never ran.
            if (-not ($rawRoles -and $rawRoles.Success)) {
                $result.Data.SectionStatus.BreakGlassIndicators = 'Failed'
            } elseif (-not ($caPolicies -and $caPolicies.Success)) {
                $result.Data.SectionStatus.BreakGlassIndicators = 'NotRun'
            } else {
                $result.Data.SectionStatus.BreakGlassIndicators = 'Collected'
            }
        } catch {
            $result.Data.SectionStatus.BreakGlassIndicators = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-BreakGlass' -Message $_.Exception.Message
            }
        }

        # PIM role management policy details (activation rules)
        try {
            # List roleManagementPolicies REQUIRES $filter on both scopeId and
            # scopeType (Microsoft Learn) — scopeType alone is rejected by
            # Graph, so every tenant's PIM policies previously came back empty.
            $pimNext   = 'https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?$filter=scopeId eq ''/'' and scopeType eq ''DirectoryRole''&$expand=rules&$top=50'
            $pimRaw    = [System.Collections.Generic.List[object]]::new()
            $pimPages  = 0
            $maxPimPages = 20
            while ($pimNext -and $pimPages -lt $maxPimPages) {
                $pimResp = Invoke-NRGGraphRequest -Method GET -Uri $pimNext -ErrorAction Stop
                foreach ($p in @($pimResp.value ?? @())) { $pimRaw.Add($p) }
                $pimNext = [string](Get-NRGObjectField -Item $pimResp -Key '@odata.nextLink' -Default '')
                $pimPages++
            }
            if ($pimPages -ge $maxPimPages -and $pimNext) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'AAD-PIMPolicies' `
                        -Message "Pagination cap reached ($maxPimPages pages); role management policy list may be truncated."
                }
            }

            $result.Data.PIMRolePolicies = @($pimRaw | ForEach-Object {
                $policy = $_
                # Extract key rules. Enablement_EndUser_Assignment is a
                # unifiedRoleManagementPolicyEnablementRule — it carries an
                # 'enabledRules' array (e.g. 'MultiFactorAuthentication',
                # 'Justification'), not 'isEnabled'; reading isEnabled off it
                # threw under StrictMode and emptied PIMRolePolicies on every
                # tenant. Graph also never emits a rule id of
                # 'Justification_EndUser_Assignment', so that lookup always
                # missed — justification is read from enabledRules too.
                $enablementRule  = @($policy.rules ?? @()) | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' } | Select-Object -First 1
                $authContextRule = @($policy.rules ?? @()) | Where-Object { $_['@odata.type'] -match 'authenticationContext' } | Select-Object -First 1
                $approvalRule    = @($policy.rules ?? @()) | Where-Object { $_['@odata.type'] -match 'approvalSetting' -or $_.id -eq 'Approval_EndUser_Assignment' } | Select-Object -First 1
                $expiryRule      = @($policy.rules ?? @()) | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' } | Select-Object -First 1
                $enabledRuleNames = @(Get-NRGObjectField -Item $enablementRule -Key 'enabledRules' -Default @())

                # PIM offers MFA on activation two ways — "Azure MFA" (an entry in
                # the enablement rule's enabledRules) or a Conditional Access
                # authentication context (its own rule, isEnabled). Either one
                # satisfies the requirement; the enablement rule is always present,
                # so checking the context rule only in its absence never ran.
                $mfaViaEnablement = [bool]($enabledRuleNames -contains 'MultiFactorAuthentication')
                $mfaViaAuthCtx    = [bool](Get-NRGObjectField -Item $authContextRule -Key 'isEnabled' -Default $false)
                @{
                    PolicyId              = [string]$policy.id
                    DisplayName           = [string]$policy.displayName
                    ScopeId               = [string]$policy.scopeId
                    RequiresMFA           = if ($enablementRule -or $authContextRule) { $mfaViaEnablement -or $mfaViaAuthCtx } else { $null }
                    RequiresJustification = if ($enablementRule) { [bool]($enabledRuleNames -contains 'Justification') } else { $null }
                    RequiresApproval      = if ($approvalRule) { [bool](Get-NRGNestedProperty -Object $approvalRule -Path 'setting.isApprovalRequired' -Default $false) } else { $null }
                    MaxDurationHours      = if ($expiryRule -and $expiryRule.maximumDuration) {
                        # Parse ISO 8601 duration e.g. PT8H
                        $dur = [string]$expiryRule.maximumDuration
                        if ($dur -match 'PT(\d+)H') { [int]$matches[1] } else { $null }
                    } else { $null }
                }
            })
            $result.Data.SectionStatus.PIMRolePolicies = 'Collected'

            # Graph names every directory-role PIM policy "DirectoryRole"; which
            # role a policy governs lives only in roleManagementPolicyAssignments.
            # Without this map AAD-3.5 could never find the Global Administrator
            # policy and AAD-3.3/3.4/3.6 weighed every role equally. Its own
            # try/catch: a failure here leaves RoleDefinitionId absent and the
            # evaluators fall back to all-policy scoring, saying so.
            try {
                $asgNext  = 'https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq ''/'' and scopeType eq ''DirectoryRole'''
                $policyToRole = @{}
                $asgPages = 0
                while ($asgNext -and $asgPages -lt 20) {
                    $asgResp = Invoke-NRGGraphRequest -Method GET -Uri $asgNext -ErrorAction Stop
                    foreach ($a in @(Get-NRGObjectField -Item $asgResp -Key 'value' -Default @())) {
                        $pid_ = [string](Get-NRGObjectField -Item $a -Key 'policyId' -Default '')
                        $rid  = [string](Get-NRGObjectField -Item $a -Key 'roleDefinitionId' -Default '')
                        if ($pid_ -and $rid) { $policyToRole[$pid_] = $rid }
                    }
                    $asgNext = [string](Get-NRGObjectField -Item $asgResp -Key '@odata.nextLink' -Default '')
                    $asgPages++
                }
                foreach ($row in @($result.Data.PIMRolePolicies)) {
                    if ($policyToRole.ContainsKey($row.PolicyId)) { $row['RoleDefinitionId'] = $policyToRole[$row.PolicyId] }
                }
                $result.Data.SectionStatus.PIMPolicyAssignments = 'Collected'
            } catch {
                $result.Data.SectionStatus.PIMPolicyAssignments = 'Failed'
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'AAD-PIMPolicyAssignments' -Message $_.Exception.Message
                }
            }
        } catch {
            # PIM not licensed — non-fatal
            $result.Data.SectionStatus.PIMRolePolicies = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-PIMPolicies' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-IdentityGovernance' -Status 'Collected'
        }

    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'AAD-IdentityGovernance' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-IdentityGovernance' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data $result
    }
    return $result
}

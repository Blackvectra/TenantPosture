#Requires -Version 7.0
#
# Invoke-TPCollectAADIdentityGovernance.ps1  (v4.5.5)
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

function Invoke-TPCollectAADIdentityGovernance {
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
            # empty/default section (Test-TPSectionCollected).
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
            $sspr = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' `
                -ErrorAction Stop
            # registrationEnforcement (and its nested campaign block) is an
            # OPTIONAL sub-object on authenticationMethodsPolicy, omitted
            # entirely on a tenant that has never touched registration
            # campaign settings — a bare chained read throws at the first
            # absent intermediate under StrictMode.
            $result.Data.SSPRPolicy = @{
                RegistrationEnforcementState = [string](Get-TPNestedProperty -Object $sspr -Path 'registrationEnforcement.authenticationMethodsRegistrationCampaign.state' -Default 'unknown')
                SnoozeDays                   = [int](Get-TPNestedProperty -Object $sspr -Path 'registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays' -Default 0)
                MethodsConfigured            = @(@(Get-TPObjectField -Item $sspr -Key 'authenticationMethodConfigurations' -Default @()) | ForEach-Object {
                    @{ Id = [string](Get-TPObjectField -Item $_ -Key 'id' -Default ''); State = [string](Get-TPObjectField -Item $_ -Key 'state' -Default '') }
                })
            }
            $result.Data.SectionStatus.SSPRPolicy = 'Collected'
        } catch {
            $result.Data.SectionStatus.SSPRPolicy = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-SSPR' -Message $_.Exception.Message
            }
        }

        # External collaboration / guest invite settings
        try {
            $extCollab = Invoke-TPGraphRequest -Method GET `
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
            foreach ($holder in @((Get-TPNestedProperty -Object $extCollab -Path 'defaultUserRolePermissions' -Default $null), $extCollab)) {
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
                AllowInvitesFrom             = [string](Get-TPObjectField -Item $extCollab -Key 'allowInvitesFrom' -Default '')
                AllowedToSignUpEmailBased    = [bool](Get-TPObjectField -Item $extCollab -Key 'allowedToSignUpEmailBasedSubscriptions' -Default $true)
                GuestUserRoleId              = [string](Get-TPObjectField -Item $extCollab -Key 'guestUserRoleId' -Default '')
                DefaultUserRolePermissions   = @{
                    AllowedToCreateApps      = [bool](Get-TPNestedProperty -Object $extCollab -Path 'defaultUserRolePermissions.allowedToCreateApps' -Default $true)
                    AllowedToCreateGroups    = [bool](Get-TPNestedProperty -Object $extCollab -Path 'defaultUserRolePermissions.allowedToCreateGroups' -Default $true)
                    AllowedToCreateTenants   = [bool](Get-TPNestedProperty -Object $extCollab -Path 'defaultUserRolePermissions.allowedToCreateTenants' -Default $true)
                }
                PermissionGrantPolicies      = $permGrant
                BlockMsolPowerShell          = (Get-TPObjectField -Item $extCollab -Key 'blockMsolPowerShell' -Default $null)
            }
            $result.Data.SectionStatus.ExternalCollab = 'Collected'
        } catch {
            $result.Data.SectionStatus.ExternalCollab = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-ExternalCollab' -Message $_.Exception.Message
            }
        }

        # Admin consent request policy
        try {
            $consentPol = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' `
                -ErrorAction Stop
            $result.Data.ConsentPolicy = @{
                IsEnabled = [bool](Get-TPObjectField -Item $consentPol -Key 'isEnabled' -Default $false)
                Version   = [int](Get-TPObjectField -Item $consentPol -Key 'version' -Default 0)
                Reviewers = @(Get-TPObjectField -Item $consentPol -Key 'reviewers' -Default @())
            }
            $result.Data.SectionStatus.ConsentPolicy = 'Collected'
        } catch {
            $result.Data.SectionStatus.ConsentPolicy = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-ConsentPolicy' -Message $_.Exception.Message
            }
        }

        # High-risk OAuth consent grants — app-only grants to all users
        try {
            $grants = Invoke-TPGraphRequest -Method GET `
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
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-OAuthGrants' -Message $_.Exception.Message
            }
        }

        # Break-glass indicator: look for GA accounts excluded from all CA policies
        # A properly configured break-glass account is a GA with CA exclusions documented
        try {
            $rawRoles = if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) {
                Get-TPRawData -Key 'AAD-DirectoryRoles'
            } else { $null }

            $caPolicies = if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) {
                Get-TPRawData -Key 'AAD-CAPolicies'
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
                        $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
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
                    if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                        Register-TPException -Source 'AAD-BreakGlass-GroupResolve' `
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
                # Microsoft: exclude emergency access accounts from policies
                # that block OR RESTRICT sign-in; report-only policies need no
                # exclusion. So the requirement is every ENABLED policy that
                # reaches the account, whatever its controls (CAExcluded,
                # NotExcludedFrom). A session-only policy can still restrict
                # (sign-in frequency, token protection, app control), so it is
                # never assumed harmless. Separately, an account excluded from
                # every policy with a GRANT control (block, MFA, device,
                # strength, terms of use) is recorded as a candidate
                # (BlockingExcluded) so the finding can say "this looks like
                # the break-glass account; these session policies still reach
                # it" instead of "no emergency access path".
                $hasGrant = {
                    param($p)
                    $n = @(@(Get-TPNestedProperty -Object $p -Path 'GrantControls.BuiltInControls' -Default @()) | Where-Object { $_ }).Count
                    $n += @(@(Get-TPNestedProperty -Object $p -Path 'GrantControls.TermsOfUse' -Default @()) | Where-Object { $_ }).Count
                    $n += @(@(Get-TPNestedProperty -Object $p -Path 'GrantControls.CustomControls' -Default @()) | Where-Object { $_ }).Count
                    ($n -gt 0) -or [bool][string](Get-TPNestedProperty -Object $p -Path 'GrantControls.AuthStrengthId' -Default '')
                }
                $reaching = @()
                if ($caPolicies -and $caPolicies.Success) {
                    $reaching = @(@($caPolicies.Data.Policies) | Where-Object {
                        $_.State -eq 'enabled' -and (
                            @(Get-TPNestedProperty -Object $_ -Path 'Conditions.Users.IncludeUsers' -Default @()) -contains 'All' -or
                            @(Get-TPNestedProperty -Object $_ -Path 'Conditions.Users.IncludeRoles' -Default @()) -contains $gaRoleId)
                    })
                }
                $reachingGrant = @($reaching | Where-Object { & $hasGrant $_ })
                foreach ($ga in $gaAccounts) {
                    $isExcluded = $false
                    $blockingExcluded = $false
                    # Every enabled policy that reaches this account and does
                    # not exclude it, and the subset with a grant control.
                    $notExcludedFrom  = [System.Collections.Generic.List[string]]::new()
                    $grantNotExcluded = [System.Collections.Generic.List[string]]::new()
                    if ($caPolicies -and $caPolicies.Success) {
                        $unknown = $false; $grantUnknown = $false
                        foreach ($policy in $reaching) {
                            $excludeUsers  = @(Get-TPNestedProperty -Object $policy -Path 'Conditions.Users.ExcludeUsers'  -Default @())
                            $excludeGroups = @(Get-TPNestedProperty -Object $policy -Path 'Conditions.Users.ExcludeGroups' -Default @())
                            if ($excludeUsers -contains $ga.PrincipalId) { continue }
                            $matched = $false; $groupUnknown = $false
                            foreach ($gid in $excludeGroups) {
                                $members = & $resolveGroupMembers $gid
                                if ($null -eq $members) { $groupUnknown = $true; continue }
                                if ($members -contains $ga.PrincipalId) { $matched = $true; break }
                            }
                            if ($matched) { continue }
                            $isGrant = & $hasGrant $policy
                            if ($groupUnknown) { $unknown = $true; if ($isGrant) { $grantUnknown = $true }; continue }
                            $name = [string](Get-TPObjectField -Item $policy -Key 'DisplayName' -Default '(unnamed policy)')
                            $notExcludedFrom.Add($name)
                            if ($isGrant) { $grantNotExcluded.Add($name) }
                        }
                        # $null = could not tell (a group membership was unreadable).
                        $isExcluded = if ($notExcludedFrom.Count -gt 0) { $false } elseif ($unknown) { $null } elseif ($reaching.Count -gt 0) { $true } else { $false }
                        $blockingExcluded = if ($grantNotExcluded.Count -gt 0) { $false } elseif ($grantUnknown) { $null } elseif ($reachingGrant.Count -gt 0) { $true } else { $false }
                    }
                    $breakGlass += @{
                        PrincipalId  = [string]$ga.PrincipalId
                        DisplayName  = [string]$ga.PrincipalDisplayName
                        UPN          = [string]$ga.PrincipalUPN
                        CAExcluded   = $isExcluded
                        Synced       = $ga.OnPremisesSyncEnabled -eq $true
                        Source       = [string]($ga.Source ?? 'permanent')
                        NotExcludedFrom  = [string[]]@($notExcludedFrom)
                        BlockingExcluded = $blockingExcluded
                        GrantNotExcludedFrom = [string[]]@($grantNotExcluded)
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
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-BreakGlass' -Message $_.Exception.Message
            }
        }

        # PIM role management policy details (activation rules)
        try {
            # List roleManagementPolicies REQUIRES $filter on both scopeId and
            # scopeType (Microsoft Learn) — scopeType alone is rejected by
            # Graph, so every tenant's PIM policies previously came back empty.
            # No $top: the endpoint does not document it, and with $top=50 Graph
            # returned 50 policies and no nextLink, so a tenant's ~130 role
            # policies were cut to 50 and the Global Administrator policy was
            # missing (AAD-3.5 not assessed; AAD-3.3/3.4/3.6 judged 4 roles).
            $pimNext   = 'https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?$filter=scopeId eq ''/'' and scopeType eq ''DirectoryRole''&$expand=rules'
            $pimRaw    = [System.Collections.Generic.List[object]]::new()
            $pimPages  = 0
            $maxPimPages = 20
            while ($pimNext -and $pimPages -lt $maxPimPages) {
                $pimResp = Invoke-TPGraphRequest -Method GET -Uri $pimNext -ErrorAction Stop
                foreach ($p in @($pimResp.value ?? @())) { $pimRaw.Add($p) }
                $pimNext = [string](Get-TPObjectField -Item $pimResp -Key '@odata.nextLink' -Default '')
                $pimPages++
            }
            if ($pimPages -ge $maxPimPages -and $pimNext) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'AAD-PIMPolicies' `
                        -Message "Pagination cap reached ($maxPimPages pages); role management policy list may be truncated."
                }
            }

            $projectPolicy = {
                param($policy)
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
                $enabledRuleNames = @(Get-TPObjectField -Item $enablementRule -Key 'enabledRules' -Default @())

                # PIM offers MFA on activation two ways — "Azure MFA" (an entry in
                # the enablement rule's enabledRules) or a Conditional Access
                # authentication context (its own rule, isEnabled). Either one
                # satisfies the requirement; the enablement rule is always present,
                # so checking the context rule only in its absence never ran.
                $mfaViaEnablement = [bool]($enabledRuleNames -contains 'MultiFactorAuthentication')
                $mfaViaAuthCtx    = [bool](Get-TPObjectField -Item $authContextRule -Key 'isEnabled' -Default $false)
                @{
                    PolicyId              = [string]$policy.id
                    DisplayName           = [string]$policy.displayName
                    ScopeId               = [string]$policy.scopeId
                    RequiresMFA           = if ($enablementRule -or $authContextRule) { $mfaViaEnablement -or $mfaViaAuthCtx } else { $null }
                    RequiresJustification = if ($enablementRule) { [bool]($enabledRuleNames -contains 'Justification') } else { $null }
                    RequiresApproval      = if ($approvalRule) { [bool](Get-TPNestedProperty -Object $approvalRule -Path 'setting.isApprovalRequired' -Default $false) } else { $null }
                    MaxDurationHours      = if ($expiryRule -and $expiryRule.maximumDuration) {
                        # Parse ISO 8601 duration e.g. PT8H
                        $dur = [string]$expiryRule.maximumDuration
                        if ($dur -match 'PT(\d+)H') { [int]$matches[1] } else { $null }
                    } else { $null }
                }
            }
            $result.Data.PIMRolePolicies = @($pimRaw | ForEach-Object { & $projectPolicy $_ })
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
                    $asgResp = Invoke-TPGraphRequest -Method GET -Uri $asgNext -ErrorAction Stop
                    foreach ($a in @(Get-TPObjectField -Item $asgResp -Key 'value' -Default @())) {
                        $pid_ = [string](Get-TPObjectField -Item $a -Key 'policyId' -Default '')
                        $rid  = [string](Get-TPObjectField -Item $a -Key 'roleDefinitionId' -Default '')
                        if ($pid_ -and $rid) { $policyToRole[$pid_] = $rid }
                    }
                    $asgNext = [string](Get-TPObjectField -Item $asgResp -Key '@odata.nextLink' -Default '')
                    $asgPages++
                }
                # Any assigned policy the list did not return is read by ID,
                # so a short list never leaves a role unassessed.
                $have = [System.Collections.Generic.HashSet[string]]::new([string[]]@($result.Data.PIMRolePolicies | ForEach-Object { [string]$_.PolicyId }))
                $missingIds = @($policyToRole.Keys | Where-Object { -not $have.Contains($_) })
                $extra = [System.Collections.Generic.List[object]]::new()
                foreach ($mid in ($missingIds | Select-Object -First 300)) {
                    try {
                        $one = Invoke-TPGraphRequest -Method GET -ErrorAction Stop `
                            -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$([uri]::EscapeDataString($mid))?`$expand=rules"
                        $extra.Add((& $projectPolicy $one))
                    } catch {
                        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                            Register-TPException -Source 'AAD-PIMPolicies' -Message "Role management policy $mid could not be read: $($_.Exception.Message)"
                        }
                    }
                }
                if ($extra.Count -gt 0) { $result.Data.PIMRolePolicies = @($result.Data.PIMRolePolicies) + @($extra) }
                foreach ($row in @($result.Data.PIMRolePolicies)) {
                    if ($policyToRole.ContainsKey($row.PolicyId)) { $row['RoleDefinitionId'] = $policyToRole[$row.PolicyId] }
                }
                $result.Data.SectionStatus.PIMPolicyAssignments = 'Collected'
            } catch {
                $result.Data.SectionStatus.PIMPolicyAssignments = 'Failed'
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'AAD-PIMPolicyAssignments' -Message $_.Exception.Message
                }
            }
        } catch {
            # PIM not licensed — non-fatal
            $result.Data.SectionStatus.PIMRolePolicies = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-PIMPolicies' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
            Register-TPCoverage -Family 'AAD-IdentityGovernance' -Status 'Collected'
        }

    } catch {
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'AAD-IdentityGovernance' -Message $_.Exception.Message
        }
        if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
            Register-TPCoverage -Family 'AAD-IdentityGovernance' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'AAD-IdentityGovernance' -Data $result
    }
    return $result
}

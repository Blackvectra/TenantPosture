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
        }
    }

    try {
        # SSPR / Combined registration policy
        try {
            $sspr = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' `
                -ErrorAction Stop
            $regEnforcement = $sspr.registrationEnforcement
            $result.Data.SSPRPolicy = @{
                RegistrationEnforcementState = [string]($regEnforcement.authenticationMethodsRegistrationCampaign.state ?? 'unknown')
                SnoozeDays                   = [int]($regEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays ?? 0)
                MethodsConfigured            = @($sspr.authenticationMethodConfigurations ?? @() | ForEach-Object {
                    @{ Id = [string]$_.id; State = [string]$_.state }
                })
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-SSPR' -Message $_.Exception.Message
            }
        }

        # External collaboration / guest invite settings
        try {
            $extCollab = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
                -ErrorAction Stop
            $result.Data.ExternalCollab = @{
                AllowInvitesFrom             = [string]($extCollab.allowInvitesFrom ?? 'everyone')
                AllowedToSignUpEmailBased    = [bool]($extCollab.allowedToSignUpEmailBasedSubscriptions ?? $true)
                GuestUserRoleId              = [string]($extCollab.guestUserRoleId ?? '')
                DefaultUserRolePermissions   = @{
                    AllowedToCreateApps      = [bool]($extCollab.defaultUserRolePermissions.allowedToCreateApps ?? $true)
                    AllowedToCreateGroups    = [bool]($extCollab.defaultUserRolePermissions.allowedToCreateGroups ?? $true)
                    AllowedToCreateTenants   = [bool]($extCollab.defaultUserRolePermissions.allowedToCreateTenants ?? $true)
                }
                PermissionGrantPolicies      = @($extCollab.permissionGrantPoliciesAssigned ?? @())
                BlockMsolPowerShell          = $extCollab.blockMsolPowerShell
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-ExternalCollab' -Message $_.Exception.Message
            }
        }

        # Admin consent request policy
        try {
            $consentPol = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' `
                -ErrorAction Stop
            $result.Data.ConsentPolicy = @{
                IsEnabled = [bool]($consentPol.isEnabled ?? $false)
                Version   = [int]($consentPol.version ?? 0)
                Reviewers = @($consentPol.reviewers ?? @())
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-ConsentPolicy' -Message $_.Exception.Message
            }
        }

        # High-risk OAuth consent grants — app-only grants to all users
        try {
            $grants = Invoke-MgGraphRequest -Method GET `
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
        } catch {
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
                        $page = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
                        foreach ($m in @($page.value ?? @())) {
                            if ($m.id) { $members += [string]$m.id }
                        }
                        $next = $page.'@odata.nextLink'
                        $pageCount++
                    }
                } catch {
                    # Group may be deleted, hidden, or inaccessible — return
                    # an empty set so the CA check just treats it as a
                    # non-match. Logging happens once per failed group below.
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

                foreach ($ga in $gaAccounts) {
                    $isExcluded = $false
                    if ($caPolicies -and $caPolicies.Success) {
                        foreach ($policy in @($caPolicies.Data.Policies)) {
                            $excludeUsers  = @($policy.Conditions.Users.ExcludeUsers  ?? @())
                            $excludeGroups = @($policy.Conditions.Users.ExcludeGroups ?? @())

                            # Direct user-id exclusion: unchanged.
                            if ($excludeUsers -contains $ga.PrincipalId) {
                                $isExcluded = $true
                                break
                            }
                            # Group exclusion: resolve membership and check.
                            $matched = $false
                            foreach ($gid in $excludeGroups) {
                                $members = & $resolveGroupMembers $gid
                                if ($members -contains $ga.PrincipalId) {
                                    $matched = $true
                                    break
                                }
                            }
                            if ($matched) {
                                $isExcluded = $true
                                break
                            }
                        }
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
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-BreakGlass' -Message $_.Exception.Message
            }
        }

        # PIM role management policy details (activation rules)
        try {
            $pimPolicies = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?$filter=scopeType eq ''DirectoryRole''&$expand=rules&$top=50' `
                -ErrorAction Stop

            $result.Data.PIMRolePolicies = @($pimPolicies.value ?? @() | ForEach-Object {
                $policy = $_
                # Extract key rules
                $mfaRule           = @($policy.rules ?? @()) | Where-Object { $_.'@odata.type' -match 'authenticationContext' -or $_.id -eq 'Enablement_EndUser_Assignment' } | Select-Object -First 1
                $justRule          = @($policy.rules ?? @()) | Where-Object { $_.id -eq 'Justification_EndUser_Assignment' } | Select-Object -First 1
                $approvalRule      = @($policy.rules ?? @()) | Where-Object { $_.'@odata.type' -match 'approvalSetting' -or $_.id -eq 'Approval_EndUser_Assignment' } | Select-Object -First 1
                $expiryRule        = @($policy.rules ?? @()) | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' } | Select-Object -First 1

                @{
                    PolicyId              = [string]$policy.id
                    DisplayName           = [string]$policy.displayName
                    ScopeId               = [string]$policy.scopeId
                    RequiresMFA           = if ($mfaRule) { [bool]($mfaRule.isEnabled ?? $false) } else { $null }
                    RequiresJustification = if ($justRule) { [bool]($justRule.isEnabled ?? $false) } else { $null }
                    RequiresApproval      = if ($approvalRule) { [bool]($approvalRule.setting.isApprovalRequired ?? $false) } else { $null }
                    MaxDurationHours      = if ($expiryRule -and $expiryRule.maximumDuration) {
                        # Parse ISO 8601 duration e.g. PT8H
                        $dur = [string]$expiryRule.maximumDuration
                        if ($dur -match 'PT(\d+)H') { [int]$matches[1] } else { $null }
                    } else { $null }
                }
            })
        } catch {
            # PIM not licensed — non-fatal
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

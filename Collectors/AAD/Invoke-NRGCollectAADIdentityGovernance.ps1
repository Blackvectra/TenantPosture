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
            if ($rawRoles -and $rawRoles.Success) {
                $gaAccounts = @($rawRoles.Data.RoleAssignments | Where-Object {
                    $_.RoleDefinitionName -eq 'Global Administrator' -and
                    $_.PrincipalType -notmatch 'servicePrincipal'
                })

                foreach ($ga in $gaAccounts) {
                    $isExcluded = $false
                    if ($caPolicies -and $caPolicies.Success) {
                        # Check if this GA principal is explicitly excluded from any CA policy
                        $isExcluded = @($caPolicies.Data.Policies | Where-Object {
                            $_.Conditions.Users.ExcludeUsers -contains $ga.PrincipalId -or
                            $_.Conditions.Users.ExcludeGroups -contains $ga.PrincipalId
                        }).Count -gt 0
                    }
                    $breakGlass += @{
                        PrincipalId  = [string]$ga.PrincipalId
                        DisplayName  = [string]$ga.PrincipalDisplayName
                        UPN          = [string]$ga.PrincipalUPN
                        CAExcluded   = $isExcluded
                        Synced       = $ga.OnPremisesSyncEnabled -eq $true
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

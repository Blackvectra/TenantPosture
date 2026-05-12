#
# Invoke-NRGCollectAADAuthPolicies.ps1
# Collects Entra ID Authorization Policy + Auth Method Policy + Authentication Methods config.
# COLLECTION ONLY - no scoring.
#
# Returns standard collector schema:
#   @{ Source; Timestamp; Success; Data; Exceptions }
#

function Invoke-NRGCollectAADAuthPolicies {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'AAD-AuthPolicies'
        Timestamp  = [DateTime]::UtcNow.ToString('o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    try {
        # Authorization Policy - tenant-wide app reg + user consent settings
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $result.Data['AuthorizationPolicy'] = @{
            DefaultUserRolePermissions = @{
                AllowedToCreateApps              = $authPolicy.DefaultUserRolePermissions.AllowedToCreateApps
                AllowedToCreateSecurityGroups    = $authPolicy.DefaultUserRolePermissions.AllowedToCreateSecurityGroups
                AllowedToCreateTenants           = $authPolicy.DefaultUserRolePermissions.AllowedToCreateTenants
                AllowedToReadOtherUsers          = $authPolicy.DefaultUserRolePermissions.AllowedToReadOtherUsers
            }
            AllowedToSignUpEmailBasedSubscriptions = $authPolicy.AllowedToSignUpEmailBasedSubscriptions
            AllowedToUseSSPR                       = $authPolicy.AllowedToUseSSPR
            AllowedEmailVerifiedUsersToJoinOrganization = $authPolicy.AllowedEmailVerifiedUsersToJoinOrganization
            BlockMsolPowerShell                    = $authPolicy.BlockMsolPowerShell
            GuestUserRoleId                        = $authPolicy.GuestUserRoleId
        }

        # Authentication Methods Policy - which methods are enabled
        try {
            $authMethodsPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
            $result.Data['AuthMethodsPolicy'] = @{
                PolicyVersion = $authMethodsPolicy.PolicyVersion
                Description   = $authMethodsPolicy.Description
            }

            # Per-method config
            $methods = @{}
            foreach ($cfg in $authMethodsPolicy.AuthenticationMethodConfigurations) {
                $methodId = if ($cfg.Id) { $cfg.Id } else { 'unknown' }
                $methods[$methodId] = @{
                    State        = $cfg.State
                    AdditionalProperties = $cfg.AdditionalProperties
                }
            }
            $result.Data['AuthMethods'] = $methods
        } catch {
            $result.Exceptions += "AuthMethodsPolicy failed: $($_.Exception.Message)"
        }

        # Cross-tenant access policy
        try {
            $crossTenant = Get-MgPolicyCrossTenantAccessPolicy -ErrorAction Stop
            $result.Data['CrossTenantAccess'] = @{
                DisplayName = $crossTenant.DisplayName
                Description = $crossTenant.Description
            }
        } catch {
            $result.Exceptions += "CrossTenantAccess failed: $($_.Exception.Message)"
        }

        $result.Success = $true
        Register-NRGCoverage -Family 'AAD-AuthPolicies' -Status 'Collected'
    }
    catch {
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'AAD-AuthPolicies' -Message $_.Exception.Message
        Register-NRGCoverage -Family 'AAD-AuthPolicies' -Status 'Failed' -Note $_.Exception.Message
    }

    Set-NRGRawData -Key 'AAD-AuthPolicies' -Data $result
    return $result
}

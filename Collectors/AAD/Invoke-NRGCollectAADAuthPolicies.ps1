#Requires -Version 7.0
#
# Invoke-NRGCollectAADAuthPolicies.ps1  (v4.5.5)
# Collects Entra ID authentication and authorization policy data.
# READ-ONLY. No write operations.
#
# Collects: Authentication Methods Policy, Authorization Policy (consent settings,
# guest invite permissions, SSPR), Password Protection Policy, Security Defaults.
#
# Required Graph scopes: Policy.Read.All, Directory.Read.All
#
# NIST SP 800-53: IA-2 (MFA), IA-5 (authenticator management), AC-3 (access enforcement)
# MITRE ATT&CK:   T1078 (Valid Accounts), T1110 (Brute Force), T1621 (MFA Request Gen)
#

function Invoke-NRGCollectAADAuthPolicies {
    [CmdletBinding()] param()

    $result = @{
        Success = $false
        Data    = @{
            AuthMethodsPolicy       = $null
            AuthorizationPolicy     = $null
            PasswordProtection      = $null
            SecurityDefaults        = $null
            AdminConsentPolicy      = $null
            ConsentPolicies         = $null
            CrossTenantAccess       = $null
        }
    }

    try {
        # Authentication Methods Policy (MFA methods, FIDO2, Authenticator settings)
        try {
            $amp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' `
                -ErrorAction Stop
            if ($amp) {
                $result.Data.AuthMethodsPolicy = @{
                    Id                            = [string]$amp.id
                    Description                   = [string]$amp.description
                    PolicyVersion                 = [string]$amp.policyVersion
                    AuthenticationMethodConfigs   = @($amp.authenticationMethodConfigurations | ForEach-Object {
                        @{
                            Id      = [string]$_.id
                            State   = [string]$_.state
                            OdataType = [string]$_.'@odata.type'
                            IncludeTargets = @($_.includeTargets ?? @())
                            ExcludeTargets = @($_.excludeTargets ?? @())
                            FeatureSettings = if ($_.featureSettings) {
                                @{
                                    NumberMatchingRequiredState    = [string]($_.featureSettings.numberMatchingRequiredState ?? '')
                                    AdditionalContextFeatureState  = [string]($_.featureSettings.additionalContextFeatureState ?? '')
                                }
                            } else { $null }
                        }
                    })
                    RegistrationEnforcement = if ($amp.registrationEnforcement) {
                        @{
                            AuthenticationMethodsRegistrationCampaign = @{
                                State          = [string]($amp.registrationEnforcement.authenticationMethodsRegistrationCampaign.state ?? 'unknown')
                                SnoozeDuration = [int]($amp.registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays ?? 0)
                            }
                        }
                    } else { $null }
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-AuthMethodsPolicy' -Message $_.Exception.Message
            }
        }

        # Authorization Policy (consent settings, guest permissions, Security Defaults)
        try {
            $authPol = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
                -ErrorAction Stop
            if ($authPol) {
                $result.Data.AuthorizationPolicy = @{
                    Id                           = [string]$authPol.id
                    AllowInvitesFrom             = [string]($authPol.allowInvitesFrom ?? 'unknown')
                    AllowedToSignUpEmailBasedSubscriptions = [bool]($authPol.allowedToSignUpEmailBasedSubscriptions ?? $true)
                    AllowedToUseSSPR             = [bool]($authPol.allowedToUseSSPR ?? $true)
                    BlockMsolPowerShell           = $authPol.blockMsolPowerShell
                    DefaultUserRolePermissions    = @{
                        AllowedToCreateApps        = [bool]($authPol.defaultUserRolePermissions.allowedToCreateApps ?? $true)
                        AllowedToCreateGroups      = [bool]($authPol.defaultUserRolePermissions.allowedToCreateGroups ?? $true)
                        AllowedToCreateTenants     = [bool]($authPol.defaultUserRolePermissions.allowedToCreateTenants ?? $true)
                        AllowedToReadBitlockerKeys = [bool]($authPol.defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice ?? $true)
                    }
                    GuestUserRoleId              = [string]($authPol.guestUserRoleId ?? '')
                    PermissionGrantPoliciesAssigned = @($authPol.permissionGrantPoliciesAssigned ?? @())
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-AuthorizationPolicy' -Message $_.Exception.Message
            }
        }

        # Security Defaults
        try {
            $secDef = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' `
                -ErrorAction Stop
            if ($secDef) {
                $result.Data.SecurityDefaults = @{
                    IsEnabled = [bool]$secDef.isEnabled
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-SecurityDefaults' -Message $_.Exception.Message
            }
        }

        # Admin Consent Request Policy
        try {
            $consentPol = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' `
                -ErrorAction Stop
            if ($consentPol) {
                $result.Data.AdminConsentPolicy = @{
                    IsEnabled = [bool]($consentPol.isEnabled ?? $false)
                    Reviewers = @($consentPol.reviewers ?? @())
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-AdminConsentPolicy' -Message $_.Exception.Message
            }
        }

        # Password Protection Policy
        try {
            $pwdProt = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/beta/settings' `
                -ErrorAction Stop
            $ppSetting = ($pwdProt.value ?? @()) |
                Where-Object { $_.displayName -eq 'Password Rule Settings' } |
                Select-Object -First 1
            if ($ppSetting) {
                $values = @{}
                foreach ($v in @($ppSetting.values ?? @())) {
                    $values[$v.name] = $v.value
                }
                $result.Data.PasswordProtection = @{
                    LockoutThreshold       = [int]($values['LockoutThreshold'] ?? 10)
                    LockoutDurationSeconds = [int]($values['LockoutDurationInSeconds'] ?? 60)
                    EnableBannedPasswordCheck = [bool]($values['EnableBannedPasswordCheck'] ?? $false)
                    BannedPasswordListPresent = (-not [string]::IsNullOrWhiteSpace($values['BannedPasswordList']))
                }
            }
        } catch {
            # Beta endpoint may not be accessible in all tenants — non-fatal
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-PasswordProtection' -Message $_.Exception.Message
            }
        }

        # Cross-Tenant Access Policy
        try {
            $ctap = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default' `
                -ErrorAction Stop
            if ($ctap) {
                $result.Data.CrossTenantAccess = @{
                    InboundB2B  = @{
                        Applications = [string]($ctap.inboundTrust.applicationsFromExternalOrganizationsEnabled ?? 'unknown')
                        UsersGroups  = [string]($ctap.b2bCollaborationInbound.usersAndGroups.accessType ?? 'unknown')
                    }
                    OutboundB2B = @{
                        UsersGroups = [string]($ctap.b2bCollaborationOutbound.usersAndGroups.accessType ?? 'unknown')
                    }
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-CrossTenantAccess' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-AuthPolicies' -Status 'Collected'
        }

    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'AAD-AuthPolicies' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-AuthPolicies' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'AAD-AuthPolicies' -Data $result
    }
    return $result
}

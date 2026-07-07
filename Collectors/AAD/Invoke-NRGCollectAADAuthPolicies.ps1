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
            $amp = Invoke-NRGGraphRequest -Method GET `
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
            $authPol = Invoke-NRGGraphRequest -Method GET `
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
            $secDef = Invoke-NRGGraphRequest -Method GET `
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
            $consentPol = Invoke-NRGGraphRequest -Method GET `
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
        # v4.6.4 EMERGENCY FIX (High #6): previously called
        # https://graph.microsoft.com/beta/settings which is NOT the Entra
        # Password Protection endpoint and always returned empty. The
        # authoritative surface is /v1.0/groupSettings (or /beta/directorySettings)
        # filtered by templateId. The 'Password Rule Settings' template GUID
        # is well-known: 5cf42378-d67d-4f36-ba46-e8b86229381d.
        # Reference: https://learn.microsoft.com/graph/api/group-list-settings
        # and https://learn.microsoft.com/graph/group-directory-settings
        # If the tenant has never customized password protection, the template
        # may not yet be instantiated and the list will be empty — that itself
        # is a valid finding (default lockout threshold of 10 in effect).
        try {
            $PWD_RULE_TEMPLATE_ID = '5cf42378-d67d-4f36-ba46-e8b86229381d'
            $gsResp = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/groupSettings' `
                -ErrorAction Stop
            $ppSetting = @($gsResp.value ?? @()) |
                Where-Object { [string]$_.templateId -eq $PWD_RULE_TEMPLATE_ID } |
                Select-Object -First 1
            if ($ppSetting) {
                $values = @{}
                foreach ($v in @($ppSetting.values ?? @())) {
                    $values[$v.name] = $v.value
                }
                $result.Data.PasswordProtection = @{
                    Instantiated             = $true
                    TemplateId               = $PWD_RULE_TEMPLATE_ID
                    LockoutThreshold         = [int]($values['LockoutThreshold'] ?? 10)
                    LockoutDurationSeconds   = [int]($values['LockoutDurationInSeconds'] ?? 60)
                    EnableBannedPasswordCheckOnPremises = [bool]($values['EnableBannedPasswordCheckOnPremises'] ?? $false)
                    BannedPasswordCheckOnPremisesMode   = [string]($values['BannedPasswordCheckOnPremisesMode'] ?? 'Audit')
                    EnableBannedPasswordCheck = [bool]($values['EnableBannedPasswordCheck'] ?? $false)
                    BannedPasswordList       = [string]($values['BannedPasswordList'] ?? '')
                    BannedPasswordListPresent= (-not [string]::IsNullOrWhiteSpace($values['BannedPasswordList']))
                }
            } else {
                # Template not instantiated — Entra defaults apply (lockout=10).
                # Surface this as a structured "uninstantiated" state so the
                # evaluator can flag it instead of returning null.
                $result.Data.PasswordProtection = @{
                    Instantiated              = $false
                    TemplateId                = $PWD_RULE_TEMPLATE_ID
                    LockoutThreshold          = 10
                    LockoutDurationSeconds    = 60
                    EnableBannedPasswordCheck = $false
                    BannedPasswordListPresent = $false
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-PasswordProtection' -Message $_.Exception.Message
            }
        }

        # Cross-Tenant Access Policy
        # v4.6.4 EMERGENCY FIX (High #5): previously read
        # $ctap.inboundTrust.applicationsFromExternalOrganizationsEnabled
        # which does NOT exist on crossTenantAccessPolicyConfigurationDefault —
        # returned 'unknown' on every tenant. Correct schema lives under
        # b2bCollaborationInbound (and outbound) per
        # https://learn.microsoft.com/graph/api/resources/crosstenantaccesspolicyconfigurationdefault
        # Each B2B object has .applications and .usersAndGroups, both
        # crossTenantAccessPolicyTargetConfiguration with .accessType
        # ('allowed' | 'blocked') and a .targets array.
        try {
            $ctap = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default' `
                -ErrorAction Stop
            if ($ctap) {
                $result.Data.CrossTenantAccess = @{
                    IsServiceDefault = [bool]($ctap.isServiceDefault ?? $true)
                    InboundB2B  = @{
                        ApplicationsAccessType  = [string]($ctap.b2bCollaborationInbound.applications.accessType ?? 'unknown')
                        ApplicationsTargets     = @($ctap.b2bCollaborationInbound.applications.targets ?? @())
                        UsersGroupsAccessType   = [string]($ctap.b2bCollaborationInbound.usersAndGroups.accessType ?? 'unknown')
                        UsersGroupsTargets      = @($ctap.b2bCollaborationInbound.usersAndGroups.targets ?? @())
                    }
                    OutboundB2B = @{
                        ApplicationsAccessType  = [string]($ctap.b2bCollaborationOutbound.applications.accessType ?? 'unknown')
                        ApplicationsTargets     = @($ctap.b2bCollaborationOutbound.applications.targets ?? @())
                        UsersGroupsAccessType   = [string]($ctap.b2bCollaborationOutbound.usersAndGroups.accessType ?? 'unknown')
                        UsersGroupsTargets      = @($ctap.b2bCollaborationOutbound.usersAndGroups.targets ?? @())
                    }
                    B2BDirectConnectInbound = @{
                        ApplicationsAccessType = [string]($ctap.b2bDirectConnectInbound.applications.accessType ?? 'unknown')
                        UsersGroupsAccessType  = [string]($ctap.b2bDirectConnectInbound.usersAndGroups.accessType ?? 'unknown')
                    }
                    InboundTrust = @{
                        IsMfaAccepted               = [bool]($ctap.inboundTrust.isMfaAccepted ?? $false)
                        IsCompliantDeviceAccepted   = [bool]($ctap.inboundTrust.isCompliantDeviceAccepted ?? $false)
                        IsHybridAzureADJoinedDeviceAccepted = [bool]($ctap.inboundTrust.isHybridAzureADJoinedDeviceAccepted ?? $false)
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

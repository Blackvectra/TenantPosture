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
            RiskyServicePrincipals  = $null
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
                    # preMigration / migrationInProgress: SSPR methods are still
                    # governed by the legacy SSPR policy, not this one (AAD-5.2).
                    PolicyMigrationState          = [string](Get-NRGObjectField -Item $amp -Key 'policyMigrationState' -Default '')
                    AuthenticationMethodConfigs   = @($amp.authenticationMethodConfigurations | ForEach-Object {
                        # featureSettings is absent on most method configs; a bare
                        # $_.featureSettings then throws and empties this whole list.
                        $cfg = $_
                        $fs  = Get-NRGObjectField -Item $cfg -Key 'featureSettings'
                        @{
                            Id      = [string](Get-NRGObjectField -Item $cfg -Key 'id' -Default '')
                            State   = [string](Get-NRGObjectField -Item $cfg -Key 'state' -Default '')
                            OdataType = [string](Get-NRGObjectField -Item $cfg -Key '@odata.type' -Default '')
                            IncludeTargets = @(Get-NRGObjectField -Item $cfg -Key 'includeTargets' -Default @())
                            ExcludeTargets = @(Get-NRGObjectField -Item $cfg -Key 'excludeTargets' -Default @())
                            # Microsoft Authenticator: 'any' or 'deviceBasedPush' allows
                            # passwordless phone sign-in (AAD-9.2); 'push' does not.
                            AuthenticationModes = @(@(Get-NRGObjectField -Item $cfg -Key 'includeTargets' -Default @()) | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'authenticationMode' -Default '') } | Where-Object { $_ })
                            FeatureSettings = if ($fs) {
                                @{
                                    # Each feature setting is an OBJECT {state, includeTarget,
                                    # excludeTarget}; stringifying it stored
                                    # "System.Collections.Hashtable" and AAD-9.1 scored a Gap.
                                    NumberMatchingRequiredState    = [string](Get-NRGNestedProperty -Object $cfg -Path 'featureSettings.numberMatchingRequiredState.state' -Default '')
                                    AdditionalContextFeatureState  = [string](Get-NRGNestedProperty -Object $cfg -Path 'featureSettings.displayAppInformationRequiredState.state' -Default '')
                                }
                            } else { $null }
                        }
                    })
                    RegistrationEnforcement = if (Get-NRGObjectField -Item $amp -Key 'registrationEnforcement') {
                        @{
                            AuthenticationMethodsRegistrationCampaign = @{
                                State          = [string](Get-NRGNestedProperty -Object $amp -Path 'registrationEnforcement.authenticationMethodsRegistrationCampaign.state' -Default 'unknown')
                                SnoozeDuration = [int](Get-NRGNestedProperty -Object $amp -Path 'registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays' -Default 0)
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
            foreach ($holder in @((Get-NRGNestedProperty -Object $authPol -Path 'defaultUserRolePermissions' -Default $null), $authPol)) {
                if ($null -eq $holder) { continue }
                if ($holder -is [System.Collections.IDictionary]) {
                    if ($holder.Contains('permissionGrantPoliciesAssigned')) { $permGrant = [string[]]@($holder['permissionGrantPoliciesAssigned'] | Where-Object { $_ }); break }
                } elseif ($holder.PSObject.Properties['permissionGrantPoliciesAssigned']) {
                    $permGrant = [string[]]@($holder.permissionGrantPoliciesAssigned | Where-Object { $_ }); break
                }
            }
            if ($authPol) {
                $result.Data.AuthorizationPolicy = @{
                    Id                           = [string](Get-NRGObjectField -Item $authPol -Key 'id' -Default '')
                    AllowInvitesFrom             = [string](Get-NRGObjectField -Item $authPol -Key 'allowInvitesFrom' -Default 'unknown')
                    AllowedToSignUpEmailBasedSubscriptions = [bool](Get-NRGObjectField -Item $authPol -Key 'allowedToSignUpEmailBasedSubscriptions' -Default $true)
                    AllowedToUseSSPR             = [bool](Get-NRGObjectField -Item $authPol -Key 'allowedToUseSSPR' -Default $true)
                    BlockMsolPowerShell           = (Get-NRGObjectField -Item $authPol -Key 'blockMsolPowerShell' -Default $null)
                    DefaultUserRolePermissions    = @{
                        AllowedToCreateApps        = [bool](Get-NRGNestedProperty -Object $authPol -Path 'defaultUserRolePermissions.allowedToCreateApps' -Default $true)
                        AllowedToCreateGroups      = [bool](Get-NRGNestedProperty -Object $authPol -Path 'defaultUserRolePermissions.allowedToCreateGroups' -Default $true)
                        AllowedToCreateTenants     = [bool](Get-NRGNestedProperty -Object $authPol -Path 'defaultUserRolePermissions.allowedToCreateTenants' -Default $true)
                        AllowedToReadBitlockerKeys = [bool](Get-NRGNestedProperty -Object $authPol -Path 'defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice' -Default $true)
                    }
                    GuestUserRoleId              = [string](Get-NRGObjectField -Item $authPol -Key 'guestUserRoleId' -Default '')
                    PermissionGrantPoliciesAssigned = $permGrant
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
            # $null means "not read", never "disabled". A present isEnabled
            # whose value is null used to cast to $false and read as
            # "Security Defaults disabled". Get-NRGSecurityDefaultsState treats
            # a non-boolean IsEnabled as not read.
            if ($secDef) {
                $on = Get-NRGObjectField -Item $secDef -Key 'isEnabled' -Default $null
                $result.Data.SecurityDefaults = @{ IsEnabled = $(if ($on -is [bool]) { $on } else { $null }) }
                if ($on -isnot [bool] -and (Get-Command Register-NRGException -ErrorAction SilentlyContinue)) {
                    Register-NRGException -Source 'AAD-SecurityDefaults' -Message 'identitySecurityDefaultsEnforcementPolicy returned no boolean isEnabled; Security Defaults state not read.'
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
                # b2bCollaborationInbound/Outbound and b2bDirectConnectInbound
                # are OPTIONAL nested objects on crossTenantAccessPolicy — a
                # tenant that never customized them omits the block entirely
                # rather than returning it empty, so a bare
                # $ctap.b2bCollaborationInbound.applications.accessType throws
                # under StrictMode at the first absent intermediate. Every
                # nested read below goes through Get-NRGNestedProperty.
                $result.Data.CrossTenantAccess = @{
                    IsServiceDefault = [bool](Get-NRGNestedProperty -Object $ctap -Path 'isServiceDefault' -Default $true)
                    InboundB2B  = @{
                        ApplicationsAccessType  = [string](Get-NRGNestedProperty -Object $ctap -Path 'b2bCollaborationInbound.applications.accessType' -Default 'unknown')
                        ApplicationsTargets     = @(Get-NRGNestedProperty -Object $ctap -Path 'b2bCollaborationInbound.applications.targets' -Default @())
                        UsersGroupsAccessType   = [string](Get-NRGNestedProperty -Object $ctap -Path 'b2bCollaborationInbound.usersAndGroups.accessType' -Default 'unknown')
                        UsersGroupsTargets      = @(Get-NRGNestedProperty -Object $ctap -Path 'b2bCollaborationInbound.usersAndGroups.targets' -Default @())
                    }
                    OutboundB2B = @{
                        ApplicationsAccessType  = [string](Get-NRGNestedProperty -Object $ctap -Path 'b2bCollaborationOutbound.applications.accessType' -Default 'unknown')
                        ApplicationsTargets     = @(Get-NRGNestedProperty -Object $ctap -Path 'b2bCollaborationOutbound.applications.targets' -Default @())
                        UsersGroupsAccessType   = [string](Get-NRGNestedProperty -Object $ctap -Path 'b2bCollaborationOutbound.usersAndGroups.accessType' -Default 'unknown')
                        UsersGroupsTargets      = @(Get-NRGNestedProperty -Object $ctap -Path 'b2bCollaborationOutbound.usersAndGroups.targets' -Default @())
                    }
                    B2BDirectConnectInbound = @{
                        ApplicationsAccessType = [string](Get-NRGNestedProperty -Object $ctap -Path 'b2bDirectConnectInbound.applications.accessType' -Default 'unknown')
                        UsersGroupsAccessType  = [string](Get-NRGNestedProperty -Object $ctap -Path 'b2bDirectConnectInbound.usersAndGroups.accessType' -Default 'unknown')
                    }
                    InboundTrust = @{
                        IsMfaAccepted               = [bool](Get-NRGNestedProperty -Object $ctap -Path 'inboundTrust.isMfaAccepted' -Default $false)
                        IsCompliantDeviceAccepted   = [bool](Get-NRGNestedProperty -Object $ctap -Path 'inboundTrust.isCompliantDeviceAccepted' -Default $false)
                        IsHybridAzureADJoinedDeviceAccepted = [bool](Get-NRGNestedProperty -Object $ctap -Path 'inboundTrust.isHybridAzureADJoinedDeviceAccepted' -Default $false)
                    }
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-CrossTenantAccess' -Message $_.Exception.Message
            }
        }

        # ── Risky service principals (workload identity risk) — AAD-11.3 ──────
        # Needs IdentityRiskyServicePrincipal.Read.All (v4.13 re-consent) AND
        # Entra ID P2 + Workload Identities Premium for detections to populate.
        # Absent either, this 403s / returns empty; caught so RiskyServicePrincipals
        # stays $null and the evaluator routes to NotApplicable, never a false pass.
        try {
            $rsp = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals?$top=200' `
                -ErrorAction Stop
            if ($rsp -and $null -ne $rsp.value) {
                $result.Data.RiskyServicePrincipals = @(@($rsp.value) | ForEach-Object {
                    @{
                        Id                   = [string]($_.id ?? '')
                        AppId                = [string]($_.appId ?? '')
                        DisplayName          = [string]($_.displayName ?? '')
                        IsEnabled            = [bool]($_.isEnabled ?? $false)
                        RiskLevel            = [string]($_.riskLevel ?? 'none')
                        RiskState            = [string]($_.riskState ?? 'none')
                        RiskDetail           = [string]($_.riskDetail ?? 'none')
                        ServicePrincipalType = [string]($_.servicePrincipalType ?? '')
                    }
                })
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-RiskyServicePrincipals' -Message $_.Exception.Message
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

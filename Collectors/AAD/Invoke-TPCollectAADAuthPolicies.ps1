#Requires -Version 7.0
#
# Invoke-TPCollectAADAuthPolicies.ps1  (v4.5.5)
# Collects Entra ID authentication and authorization policy data.
# READ-ONLY. No write operations.
#
# Collects: Authentication Methods Policy, Authorization Policy (consent settings,
# guest invite permissions, SSPR), Password Protection Policy, Security Defaults,
# domain password validity periods (AAD-7.5), beta Authentication Methods Policy
# (system-preferred MFA and Authenticator on companion apps, AAD-17.4 / AAD-17.6).
#
# Required Graph scopes: Policy.Read.All, Directory.Read.All
#
# NIST SP 800-53: IA-2 (MFA), IA-5 (authenticator management), AC-3 (access enforcement)
# MITRE ATT&CK:   T1078 (Valid Accounts), T1110 (Brute Force), T1621 (MFA Request Gen)
#

function Invoke-TPCollectAADAuthPolicies {
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
            Domains                 = @()
            AgentBlueprintCreation  = $null
            AuthMethodsPolicyBeta   = $null
            SectionStatus           = @{ Domains = 'NotRun'; AgentBlueprintCreation = 'NotRun'; AuthMethodsPolicyBeta = 'NotRun' }
        }
    }

    try {
        # Authentication Methods Policy (MFA methods, FIDO2, Authenticator settings)
        try {
            $amp = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' `
                -ErrorAction Stop
            if ($amp) {
                $result.Data.AuthMethodsPolicy = @{
                    Id                            = [string](Get-TPObjectField -Item $amp -Key 'id' -Default '')
                    Description                   = [string](Get-TPObjectField -Item $amp -Key 'description' -Default '')
                    PolicyVersion                 = [string](Get-TPObjectField -Item $amp -Key 'policyVersion' -Default '')
                    # preMigration / migrationInProgress: SSPR methods are still
                    # governed by the legacy SSPR policy, not this one (AAD-5.2).
                    PolicyMigrationState          = [string](Get-TPObjectField -Item $amp -Key 'policyMigrationState' -Default '')
                    AuthenticationMethodConfigs   = @(@(Get-TPObjectField -Item $amp -Key 'authenticationMethodConfigurations' -Default @()) | ForEach-Object {
                        # featureSettings is absent on most method configs; a bare
                        # $_.featureSettings then throws and empties this whole list.
                        $cfg = $_
                        $fs  = Get-TPObjectField -Item $cfg -Key 'featureSettings'
                        @{
                            Id      = [string](Get-TPObjectField -Item $cfg -Key 'id' -Default '')
                            State   = [string](Get-TPObjectField -Item $cfg -Key 'state' -Default '')
                            OdataType = [string](Get-TPObjectField -Item $cfg -Key '@odata.type' -Default '')
                            IncludeTargets = @(Get-TPObjectField -Item $cfg -Key 'includeTargets' -Default @())
                            ExcludeTargets = @(Get-TPObjectField -Item $cfg -Key 'excludeTargets' -Default @())
                            # Microsoft Authenticator: 'any' or 'deviceBasedPush' allows
                            # passwordless phone sign-in (AAD-9.2); 'push' does not.
                            AuthenticationModes = @(@(Get-TPObjectField -Item $cfg -Key 'includeTargets' -Default @()) | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'authenticationMode' -Default '') } | Where-Object { $_ })
                            FeatureSettings = if ($fs) {
                                @{
                                    # Each feature setting is an OBJECT {state, includeTarget,
                                    # excludeTarget}; stringifying it stored
                                    # "System.Collections.Hashtable" and AAD-9.1 scored a Gap.
                                    NumberMatchingRequiredState    = [string](Get-TPNestedProperty -Object $cfg -Path 'featureSettings.numberMatchingRequiredState.state' -Default '')
                                    AdditionalContextFeatureState  = [string](Get-TPNestedProperty -Object $cfg -Path 'featureSettings.displayAppInformationRequiredState.state' -Default '')
                                }
                            } else { $null }
                        }
                    })
                    RegistrationEnforcement = if (Get-TPObjectField -Item $amp -Key 'registrationEnforcement') {
                        @{
                            AuthenticationMethodsRegistrationCampaign = @{
                                State          = [string](Get-TPNestedProperty -Object $amp -Path 'registrationEnforcement.authenticationMethodsRegistrationCampaign.state' -Default 'unknown')
                                SnoozeDuration = [int](Get-TPNestedProperty -Object $amp -Path 'registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays' -Default 0)
                            }
                        }
                    } else { $null }
                }
            }
        } catch {
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-AuthMethodsPolicy' -Message $_.Exception.Message
            }
        }

        # Authorization Policy (consent settings, guest permissions, Security Defaults)
        try {
            $authPol = Invoke-TPGraphRequest -Method GET `
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
            foreach ($holder in @((Get-TPNestedProperty -Object $authPol -Path 'defaultUserRolePermissions' -Default $null), $authPol)) {
                if ($null -eq $holder) { continue }
                if ($holder -is [System.Collections.IDictionary]) {
                    if ($holder.Contains('permissionGrantPoliciesAssigned')) { $permGrant = [string[]]@($holder['permissionGrantPoliciesAssigned'] | Where-Object { $_ }); break }
                } elseif ($holder.PSObject.Properties['permissionGrantPoliciesAssigned']) {
                    $permGrant = [string[]]@($holder.permissionGrantPoliciesAssigned | Where-Object { $_ }); break
                }
            }
            if ($authPol) {
                $result.Data.AuthorizationPolicy = @{
                    Id                           = [string](Get-TPObjectField -Item $authPol -Key 'id' -Default '')
                    AllowInvitesFrom             = [string](Get-TPObjectField -Item $authPol -Key 'allowInvitesFrom' -Default 'unknown')
                    AllowedToSignUpEmailBasedSubscriptions = [bool](Get-TPObjectField -Item $authPol -Key 'allowedToSignUpEmailBasedSubscriptions' -Default $true)
                    AllowedToUseSSPR             = [bool](Get-TPObjectField -Item $authPol -Key 'allowedToUseSSPR' -Default $true)
                    BlockMsolPowerShell           = (Get-TPObjectField -Item $authPol -Key 'blockMsolPowerShell' -Default $null)
                    DefaultUserRolePermissions    = @{
                        AllowedToCreateApps        = [bool](Get-TPNestedProperty -Object $authPol -Path 'defaultUserRolePermissions.allowedToCreateApps' -Default $true)
                        AllowedToCreateGroups      = [bool](Get-TPNestedProperty -Object $authPol -Path 'defaultUserRolePermissions.allowedToCreateGroups' -Default $true)
                        AllowedToCreateTenants     = [bool](Get-TPNestedProperty -Object $authPol -Path 'defaultUserRolePermissions.allowedToCreateTenants' -Default $true)
                        AllowedToReadBitlockerKeys = [bool](Get-TPNestedProperty -Object $authPol -Path 'defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice' -Default $true)
                    }
                    GuestUserRoleId              = [string](Get-TPObjectField -Item $authPol -Key 'guestUserRoleId' -Default '')
                    PermissionGrantPoliciesAssigned = $permGrant
                }
            }
        } catch {
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-AuthorizationPolicy' -Message $_.Exception.Message
            }
        }

        # Whether ordinary users can create agent identity blueprints (AAD-6.4). The
        # setting ("Users can create agent blueprints", Entra ID > Users > User settings)
        # is defaultUserRolePermissions.allowedToCreateAgentIdentityBlueprints, returned
        # only by the beta authorization policy and on by default from Microsoft's
        # November 2026 rollout. A tenant that does not return it yet is $null, never a
        # value: the evaluator reports it not assessed. Same scope (Policy.Read.All).
        # https://learn.microsoft.com/entra/identity/role-based-access-control/delegate-app-roles#restrict-who-can-create-applications-and-agents
        try {
            $authPolBeta = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/beta/policies/authorizationPolicy' `
                -ErrorAction Stop
            $durp = Get-TPObjectField -Item $authPolBeta -Key 'defaultUserRolePermissions' -Default $null
            $abp  = if ($null -ne $durp) { Get-TPObjectField -Item $durp -Key 'allowedToCreateAgentIdentityBlueprints' -Default $null } else { $null }
            $result.Data.AgentBlueprintCreation = $(if ($abp -is [bool]) { $abp } elseif ([string]$abp -eq 'True') { $true } elseif ([string]$abp -eq 'False') { $false } else { $null })
            $result.Data.SectionStatus.AgentBlueprintCreation = 'Collected'
        } catch {
            $result.Data.SectionStatus.AgentBlueprintCreation = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-AgentBlueprintCreation' -Message $_.Exception.Message
            }
        }

        # The two authentication methods settings Graph v1.0 does not define
        # (AAD-17.4, AAD-17.6): systemCredentialPreferences (system-preferred MFA)
        # on the policy, and featureSettings.companionAppAllowedState on the
        # Microsoft Authenticator method (Authenticator on companion apps). Both
        # exist on the beta resource only. Same scope (Policy.Read.All); its own
        # section, so a failure leaves only these two settings unread. A property
        # the response omits is stored as $null, never as a value.
        # https://learn.microsoft.com/graph/api/resources/systemcredentialpreferences?view=graph-rest-beta
        # https://learn.microsoft.com/graph/api/resources/microsoftauthenticatorfeaturesettings?view=graph-rest-beta
        try {
            $ampBeta = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy' `
                -ErrorAction Stop
            $targetIds = { param($list) @(@($list) | Where-Object { $null -ne $_ } | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'id' -Default '') } | Where-Object { $_ }) }
            $scp = Get-TPObjectField -Item $ampBeta -Key 'systemCredentialPreferences' -Default $null
            $scpOut = $null
            if ($null -ne $scp) {
                $scpOut = [ordered]@{
                    State            = [string](Get-TPObjectField -Item $scp -Key 'state' -Default '')
                    IncludeTargetIds = [string[]]@(& $targetIds (Get-TPObjectField -Item $scp -Key 'includeTargets' -Default @()))
                    ExcludeTargetIds = [string[]]@(& $targetIds (Get-TPObjectField -Item $scp -Key 'excludeTargets' -Default @()))
                }
            }
            $authr = @(@(Get-TPObjectField -Item $ampBeta -Key 'authenticationMethodConfigurations' -Default @()) | Where-Object { $null -ne $_ -and [string](Get-TPObjectField -Item $_ -Key 'id' -Default '') -eq 'MicrosoftAuthenticator' }) | Select-Object -First 1
            $companion = $null
            if ($null -ne $authr) {
                $cas = Get-TPNestedProperty -Object $authr -Path 'featureSettings.companionAppAllowedState' -Default $null
                if ($null -ne $cas) {
                    $companion = [ordered]@{
                        State           = [string](Get-TPObjectField -Item $cas -Key 'state' -Default '')
                        IncludeTargetId = [string](Get-TPNestedProperty -Object $cas -Path 'includeTarget.id' -Default '')
                        ExcludeTargetId = [string](Get-TPNestedProperty -Object $cas -Path 'excludeTarget.id' -Default '')
                    }
                }
            }
            $result.Data.AuthMethodsPolicyBeta = [ordered]@{
                SystemCredentialPreferences  = $scpOut
                AuthenticatorConfigReturned  = ($null -ne $authr)
                AuthenticatorState           = $(if ($null -ne $authr) { [string](Get-TPObjectField -Item $authr -Key 'state' -Default '') } else { '' })
                CompanionAppAllowedState     = $companion
            }
            $result.Data.SectionStatus.AuthMethodsPolicyBeta = 'Collected'
        } catch {
            $result.Data.SectionStatus.AuthMethodsPolicyBeta = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-AuthMethodsPolicyBeta' -Message $_.Exception.Message
            }
        }

        # Security Defaults
        try {
            $secDef = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' `
                -ErrorAction Stop
            # $null means "not read", never "disabled". A present isEnabled
            # whose value is null used to cast to $false and read as
            # "Security Defaults disabled". Get-TPSecurityDefaultsState treats
            # a non-boolean IsEnabled as not read.
            if ($secDef) {
                $on = Get-TPObjectField -Item $secDef -Key 'isEnabled' -Default $null
                $result.Data.SecurityDefaults = @{ IsEnabled = $(if ($on -is [bool]) { $on } else { $null }) }
                if ($on -isnot [bool] -and (Get-Command Register-TPException -ErrorAction SilentlyContinue)) {
                    Register-TPException -Source 'AAD-SecurityDefaults' -Message 'identitySecurityDefaultsEnforcementPolicy returned no boolean isEnabled; Security Defaults state not read.'
                }
            }
        } catch {
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-SecurityDefaults' -Message $_.Exception.Message
            }
        }

        # Admin Consent Request Policy
        try {
            $consentPol = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' `
                -ErrorAction Stop
            if ($consentPol) {
                $result.Data.AdminConsentPolicy = @{
                    IsEnabled = [bool](Get-TPObjectField -Item $consentPol -Key 'isEnabled' -Default $false)
                    Reviewers = @(Get-TPObjectField -Item $consentPol -Key 'reviewers' -Default @())
                }
            }
        } catch {
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-AdminConsentPolicy' -Message $_.Exception.Message
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
            $gsResp = Invoke-TPGraphRequest -Method GET `
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
                # Setting values are strings ("True"/"False"), and [bool] of any
                # non-empty string is $true, so a cast read "False" as enabled.
                # Anything but a literal True/False is $null (not read).
                $settingBool = { param($s) switch ([string]$s) { 'True' { $true } 'False' { $false } default { $null } } }
                # Numeric values are strings too ("10", "60"). An absent value
                # is the template default (Microsoft: lockout threshold 10,
                # lockout duration 60 seconds); a value that is not a whole
                # number of ASCII digits is $null (not read), never a cast
                # that throws away the whole Password Rule Settings block.
                $settingInt = { param($v, [int] $Default)
                    if ($null -eq $v) { return $Default }
                    $t = ([string]$v).Trim()
                    $n = 0
                    if ($t -cmatch '\A[0-9]{1,9}\z' -and [int]::TryParse($t, [System.Globalization.NumberStyles]::None, [cultureinfo]::InvariantCulture, [ref]$n)) { return $n }
                    return $null }
                $result.Data.PasswordProtection = @{
                    Instantiated             = $true
                    TemplateId               = $PWD_RULE_TEMPLATE_ID
                    LockoutThreshold         = (& $settingInt $values['LockoutThreshold'] 10)
                    LockoutDurationSeconds   = (& $settingInt $values['LockoutDurationInSeconds'] 60)
                    EnableBannedPasswordCheckOnPremises = (& $settingBool $values['EnableBannedPasswordCheckOnPremises'])
                    BannedPasswordCheckOnPremisesMode   = [string]($values['BannedPasswordCheckOnPremisesMode'] ?? 'Audit')
                    EnableBannedPasswordCheck = (& $settingBool $values['EnableBannedPasswordCheck'])
                    # Only whether a custom list exists and how many entries it
                    # holds: the entries themselves are the tenant's chosen
                    # weak passwords and never leave this function. Microsoft
                    # stores the list as one tab-separated string.
                    BannedPasswordCount      = @(([string]($values['BannedPasswordList'] ?? '')) -split "`t" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
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
                    BannedPasswordCount       = 0
                    BannedPasswordListPresent = $false
                }
            }
        } catch {
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-PasswordProtection' -Message $_.Exception.Message
            }
        }

        # Domains: each verified domain's password validity period (CIS
        # 1.3.1 audits passwordValidityPeriodInDays from
        # Get-MgDomain). Microsoft: "If the property isn't set, a default value
        # of 90 days is used", and 2147483647 is "never expire". Directory.Read.All
        # already covers /domains, so no new scope.
        # https://learn.microsoft.com/graph/api/resources/domain
        try {
            $domRows = @(Get-TPGraphAllPages -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,isVerified,authenticationType,passwordValidityPeriodInDays')
            $result.Data.Domains = @($domRows | Where-Object { $null -ne $_ } | ForEach-Object {
                $pv = Get-TPObjectField -Item $_ -Key 'passwordValidityPeriodInDays' -Default $null
                $pvn = $null
                if ($pv -is [int] -or $pv -is [long]) { $pvn = [long]$pv }
                elseif ($null -ne $pv) { $tmp = [long]0; if (([string]$pv) -cmatch '\A[0-9]{1,10}\z' -and [long]::TryParse([string]$pv, [ref]$tmp)) { $pvn = $tmp } }
                [ordered]@{
                    Id                           = [string](Get-TPObjectField -Item $_ -Key 'id' -Default '')
                    IsVerified                   = (Get-TPObjectField -Item $_ -Key 'isVerified' -Default $null)
                    AuthenticationType           = [string](Get-TPObjectField -Item $_ -Key 'authenticationType' -Default '')
                    PasswordValidityPeriodInDays = $pvn
                    PasswordValiditySet          = ($null -ne $pv)
                }
            })
            $result.Data.SectionStatus.Domains = 'Collected'
        } catch {
            $result.Data.SectionStatus.Domains = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-Domains' -Message $_.Exception.Message
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
            $ctap = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default' `
                -ErrorAction Stop
            if ($ctap) {
                # b2bCollaborationInbound/Outbound and b2bDirectConnectInbound
                # are OPTIONAL nested objects on crossTenantAccessPolicy — a
                # tenant that never customized them omits the block entirely
                # rather than returning it empty, so a bare
                # $ctap.b2bCollaborationInbound.applications.accessType throws
                # under StrictMode at the first absent intermediate. Every
                # nested read below goes through Get-TPNestedProperty.
                $result.Data.CrossTenantAccess = @{
                    IsServiceDefault = [bool](Get-TPNestedProperty -Object $ctap -Path 'isServiceDefault' -Default $true)
                    InboundB2B  = @{
                        ApplicationsAccessType  = [string](Get-TPNestedProperty -Object $ctap -Path 'b2bCollaborationInbound.applications.accessType' -Default 'unknown')
                        ApplicationsTargets     = @(Get-TPNestedProperty -Object $ctap -Path 'b2bCollaborationInbound.applications.targets' -Default @())
                        UsersGroupsAccessType   = [string](Get-TPNestedProperty -Object $ctap -Path 'b2bCollaborationInbound.usersAndGroups.accessType' -Default 'unknown')
                        UsersGroupsTargets      = @(Get-TPNestedProperty -Object $ctap -Path 'b2bCollaborationInbound.usersAndGroups.targets' -Default @())
                    }
                    OutboundB2B = @{
                        ApplicationsAccessType  = [string](Get-TPNestedProperty -Object $ctap -Path 'b2bCollaborationOutbound.applications.accessType' -Default 'unknown')
                        ApplicationsTargets     = @(Get-TPNestedProperty -Object $ctap -Path 'b2bCollaborationOutbound.applications.targets' -Default @())
                        UsersGroupsAccessType   = [string](Get-TPNestedProperty -Object $ctap -Path 'b2bCollaborationOutbound.usersAndGroups.accessType' -Default 'unknown')
                        UsersGroupsTargets      = @(Get-TPNestedProperty -Object $ctap -Path 'b2bCollaborationOutbound.usersAndGroups.targets' -Default @())
                    }
                    B2BDirectConnectInbound = @{
                        ApplicationsAccessType = [string](Get-TPNestedProperty -Object $ctap -Path 'b2bDirectConnectInbound.applications.accessType' -Default 'unknown')
                        UsersGroupsAccessType  = [string](Get-TPNestedProperty -Object $ctap -Path 'b2bDirectConnectInbound.usersAndGroups.accessType' -Default 'unknown')
                    }
                    InboundTrust = @{
                        IsMfaAccepted               = [bool](Get-TPNestedProperty -Object $ctap -Path 'inboundTrust.isMfaAccepted' -Default $false)
                        IsCompliantDeviceAccepted   = [bool](Get-TPNestedProperty -Object $ctap -Path 'inboundTrust.isCompliantDeviceAccepted' -Default $false)
                        IsHybridAzureADJoinedDeviceAccepted = [bool](Get-TPNestedProperty -Object $ctap -Path 'inboundTrust.isHybridAzureADJoinedDeviceAccepted' -Default $false)
                    }
                }
            }
        } catch {
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-CrossTenantAccess' -Message $_.Exception.Message
            }
        }

        # ── Risky service principals (workload identity risk) — AAD-11.3 ──────
        # Needs IdentityRiskyServicePrincipal.Read.All (v4.13 re-consent) AND
        # Entra ID P2 + Workload Identities Premium for detections to populate.
        # Absent either, this 403s / returns empty; caught so RiskyServicePrincipals
        # stays $null and the evaluator routes to NotApplicable, never a false pass.
        try {
            $rspRows = @(Get-TPGraphAllPages `
                -Uri 'https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals?$top=200')
            $result.Data.RiskyServicePrincipals = @($rspRows | ForEach-Object {
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
        } catch {
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-RiskyServicePrincipals' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
            Register-TPCoverage -Family 'AAD-AuthPolicies' -Status 'Collected'
        }

    } catch {
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'AAD-AuthPolicies' -Message $_.Exception.Message
        }
        if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
            Register-TPCoverage -Family 'AAD-AuthPolicies' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'AAD-AuthPolicies' -Data $result
    }
    return $result
}

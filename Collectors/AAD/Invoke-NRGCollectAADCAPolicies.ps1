#Requires -Version 7.0
#
# Invoke-NRGCollectAADCAPolicies.ps1  (v4.5.5)
# Collects Conditional Access policies and named locations.
# READ-ONLY.
#
# Required Graph scopes: Policy.Read.All
# Sets: AAD-CAPolicies
# Consumes: AAD-AuthPolicies (Security Defaults, for the coverage note only)
#
# NIST SP 800-53: AC-17 (remote access), IA-2 (MFA)
# MITRE ATT&CK:   T1078.004 (Cloud Accounts), T1110 (Brute Force)
#

function Invoke-NRGCollectAADCAPolicies {
    [CmdletBinding()] param()

    $result = @{
        Success = $false
        Data    = @{
            Policies       = @()
            NamedLocations = @()
            AuthStrengths  = @()
            # NamedLocations and AuthStrengths are independent sub-queries with
            # their own try/catch below, and Success only tracks the primary
            # Policies fetch. An empty NamedLocations is therefore ambiguous —
            # "no named locations defined" vs. "the query throttled/failed" —
            # and AAD-2.2 must not read the former from the latter. See
            # Test-NRGSectionCollected.
            SectionStatus  = @{
                NamedLocations = 'NotRun'
                AuthStrengths  = 'NotRun'
            }
        }
    }

    # Tracks whether the PRIMARY section (CA policies) actually collected. If it
    # throws, the tool must NOT report Success — otherwise every CA-derived
    # evaluator reads an empty-but-"successful" policy list and emits confident
    # false gaps (0 CA policies, legacy auth open, device code open, ...). A
    # genuinely empty tenant still sets this $true (the fetch succeeded, returned
    # nothing); only an EXCEPTION leaves it $false.
    $policiesCollected = $false

    try {
        # Conditional Access Policies
        try {
            $policyRows = @(Get-NRGGraphAllPages `
                -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=250' `
                -Headers @{ Prefer = 'include-unknown-enum-members' })
            # Prefer header: 'riskRemediation' (require risk remediation, the
            # control Microsoft's user-risk template uses) is an evolvable enum
            # member. Without the header Graph returns it as
            # 'unknownFutureValue', and AAD-1.5 could not see the policy.
            # Shape-safe projection. A CA policy's optional condition blocks
            # (platforms, locations, applications, grantControls, sessionControls)
            # are frequently ABSENT. A bare deep read like
            # $_.conditions.platforms.includePlatforms then THROWS — on PS 7.4 at
            # the missing '.platforms' key, on 7.5+ at '$null.includePlatforms',
            # and on PSCustomObject responses on every version. One such policy
            # aborted this whole ForEach-Object, leaving Policies empty while
            # Success stayed $true — the root cause of false "0 CA policies" +
            # every derived AAD gap. Get-NRGNestedProperty walks each hop with a
            # null guard and is safe on all supported versions.
            # One projection for both endpoints: the v1.0 list below, and any policy only the beta list returns.
            $projectPolicy = { param($p)
                $g = { param($path, $def = @()) Get-NRGNestedProperty -Object $p -Path $path -Default $def }
                $sif = & $g 'sessionControls.signInFrequency' $null
                $pb  = & $g 'sessionControls.persistentBrowser' $null
                @{
                    Id               = [string](& $g 'id' '')
                    DisplayName      = [string](& $g 'displayName' '')
                    State            = [string](& $g 'state' '')
                    CreatedDateTime  = [string](& $g 'createdDateTime' '')
                    ModifiedDateTime = [string](& $g 'modifiedDateTime' '')
                    Conditions       = @{
                        ClientAppTypes    = @(& $g 'conditions.clientAppTypes')
                        SignInRiskLevels  = @(& $g 'conditions.signInRiskLevels')
                        UserRiskLevels    = @(& $g 'conditions.userRiskLevels')
                        AuthFlows         = @(& $g 'conditions.authenticationFlows')
                        Platforms         = @(& $g 'conditions.platforms.includePlatforms')
                        # 'All' in Platforms is "Any device"; only an exclusion
                        # beside it narrows the policy (Get-NRGCANarrowing).
                        ExcludePlatforms  = @(& $g 'conditions.platforms.excludePlatforms')
                        Locations         = @{
                            Include = @(& $g 'conditions.locations.includeLocations')
                            Exclude = @(& $g 'conditions.locations.excludeLocations')
                        }
                        Users             = @{
                            IncludeUsers  = @(& $g 'conditions.users.includeUsers')
                            ExcludeUsers  = @(& $g 'conditions.users.excludeUsers')
                            IncludeGroups = @(& $g 'conditions.users.includeGroups')
                            ExcludeGroups = @(& $g 'conditions.users.excludeGroups')
                            IncludeRoles  = @(& $g 'conditions.users.includeRoles')
                            ExcludeRoles  = @(& $g 'conditions.users.excludeRoles')
                        }
                        Applications      = @{
                            Include = @(& $g 'conditions.applications.includeApplications')
                            Exclude = @(& $g 'conditions.applications.excludeApplications')
                            UserActions = @(& $g 'conditions.applications.includeUserActions')
                        }
                        # Read by AAD-11.7 (device filter for admins) and
                        # AAD-11.9 (workload identities); never projected before,
                        # so both reported "None" on tenants that had them.
                        Devices           = @{
                            FilterMode = [string](& $g 'conditions.devices.deviceFilter.mode' '')
                            FilterRule = [string](& $g 'conditions.devices.deviceFilter.rule' '')
                        }
                        ClientApplications = @{
                            IncludeServicePrincipals = @(& $g 'conditions.clientApplications.includeServicePrincipals')
                            ExcludeServicePrincipals = @(& $g 'conditions.clientApplications.excludeServicePrincipals')
                        }
                    }
                    GrantControls    = @{
                        Operator             = [string](& $g 'grantControls.operator' '')
                        BuiltInControls      = @(& $g 'grantControls.builtInControls')
                        CustomControls       = @(& $g 'grantControls.customAuthenticationFactors')
                        AuthStrengthId       = [string](& $g 'grantControls.authenticationStrength.id' '')
                        AuthStrengthName     = [string](& $g 'grantControls.authenticationStrength.displayName' '')
                        # Returned inline on the CA policy — so AAD-1.3 can tell a
                        # phishing-resistant strength from a custom one that allows
                        # SMS/voice without depending on the separate
                        # authenticationStrengthPolicies call (which can fail).
                        AuthStrengthCombinations = @(& $g 'grantControls.authenticationStrength.allowedCombinations')
                        TermsOfUse           = @(& $g 'grantControls.termsOfUse')
                    }
                    SessionControls  = @{
                        SignInFrequency  = if ($sif) {
                            @{
                                IsEnabled         = [bool](& $g 'sessionControls.signInFrequency.isEnabled' $false)
                                Value             = (& $g 'sessionControls.signInFrequency.value' $null)
                                Type              = [string](& $g 'sessionControls.signInFrequency.type' '')
                                FrequencyInterval = [string](& $g 'sessionControls.signInFrequency.frequencyInterval' '')
                                AuthenticationType = [string](& $g 'sessionControls.signInFrequency.authenticationType' '')
                            }
                        } else { $null }
                        ContinuousAccessEvaluation = [string](& $g 'sessionControls.continuousAccessEvaluation.mode' '')
                        # Token protection lives only in the beta shape; filled below.
                        SecureSignInSession = $null
                        PersistentBrowser = if ($pb) {
                            @{ IsEnabled = [bool](& $g 'sessionControls.persistentBrowser.isEnabled' $false); Mode = [string](& $g 'sessionControls.persistentBrowser.mode' '') }
                        } else { $null }
                    }
                }
            }
            $result.Data.Policies = @($policyRows | ForEach-Object { & $projectPolicy $_ })
            $policiesCollected = $true

            # Token protection (sessionControls.secureSignInSession) is not in
            # the v1.0 shape, so AAD-11.4 said "None" on every tenant. Read it
            # from beta per policy; a failure leaves the section unread and the
            # control reports not assessed instead of a gap.
            $result.Data.SectionStatus['TokenProtection'] = 'NotRun'
            $result.Data.SectionStatus['PolicyCompleteness'] = 'NotRun'
            try {
                # The v1.0 list withholds some policies. On the first full run it returned 15 policies where
                # ScubaGear's beta read returned 17: the two missing were user-risk (risk remediation) policies,
                # so the policy list, "every policy's true state" and the risk controls were incomplete. The
                # beta list is read in full; a policy only it returns is projected the same way and kept.
                $betaRows = @(Get-NRGGraphAllPages `
                    -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies?$top=250' `
                    -Headers @{ Prefer = 'include-unknown-enum-members' })
                $byId = @{}
                $knownIds = @{}
                foreach ($pol in $result.Data.Policies) { $knownIds[[string]$pol['Id']] = $true }
                $betaOnly = [System.Collections.Generic.List[string]]::new()
                foreach ($bp in $betaRows) {
                    $id  = [string](Get-NRGObjectField -Item $bp -Key 'id' -Default '')
                    $ssi = Get-NRGNestedProperty -Object $bp -Path 'sessionControls.secureSignInSession.isEnabled' -Default $null
                    if ($id) { $byId[$id] = $ssi }
                    if ($id -and -not $knownIds.ContainsKey($id)) {
                        $extra = & $projectPolicy $bp
                        $extra['Source'] = 'beta'
                        $result.Data.Policies = @($result.Data.Policies) + @($extra)
                        $knownIds[$id] = $true
                        $betaOnly.Add([string]$extra['DisplayName'])
                    }
                }
                $result.Data.PoliciesOnlyInBeta = @($betaOnly)
                $result.Data.SectionStatus['PolicyCompleteness'] = 'Collected'
                foreach ($pol in $result.Data.Policies) {
                    $polId = [string]$pol['Id']
                    if ($byId.ContainsKey($polId) -and $null -ne $byId[$polId]) { $pol['SessionControls']['SecureSignInSession'] = [bool]$byId[$polId] }
                }
                $result.Data.SectionStatus['TokenProtection'] = 'Collected'
            } catch {
                $result.Data.SectionStatus['TokenProtection'] = 'Failed'
                $result.Data.SectionStatus['PolicyCompleteness'] = 'Failed'
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'AAD-CAPolicies-TokenProtection' -Message $_.Exception.Message
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-CAPolicies' -Message $_.Exception.Message
            }
        }

        # Named Locations
        try {
            # Paged: a tenant may hold up to 195 named locations, and a single
            # $top=100 read dropped the rest, so a trusted location on page two
            # could make AAD-2.2 report none marked as trusted.
            $locRows = @(Get-NRGGraphAllPages `
                -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations?$top=100')
            # Shape-safe projection. namedLocations is polymorphic: an
            # ipNamedLocation row has no countriesAndRegions, and a
            # countryNamedLocation row has no ipRanges/isTrusted. A bare dot
            # read of the type-specific keys THROWS under StrictMode on the
            # first row of the other subtype — aborting this whole
            # ForEach-Object and leaving NamedLocations empty while Success
            # (tracked only off the Policies fetch) stays $true, the root
            # cause of a false AAD-2.2 "No named locations defined" on a
            # tenant that has them. Get-NRGObjectField never throws on an
            # absent key.
            $result.Data.NamedLocations = @($locRows | ForEach-Object {
                @{
                    Id          = [string](Get-NRGObjectField -Item $_ -Key 'id' -Default '')
                    DisplayName = [string](Get-NRGObjectField -Item $_ -Key 'displayName' -Default '')
                    OdataType   = [string](Get-NRGObjectField -Item $_ -Key '@odata.type' -Default '')
                    IsTrusted   = [bool](Get-NRGObjectField -Item $_ -Key 'isTrusted' -Default $false)
                    IpRanges    = @(Get-NRGObjectField -Item $_ -Key 'ipRanges' -Default @() | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'cidrAddress' -Default '') })
                    CountriesAndRegions = @(Get-NRGObjectField -Item $_ -Key 'countriesAndRegions' -Default @())
                }
            })
            $result.Data.SectionStatus.NamedLocations = 'Collected'
        } catch {
            $result.Data.SectionStatus.NamedLocations = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-NamedLocations' -Message $_.Exception.Message
            }
        }

        # Authentication Strength Policies. No $top — the collection is always a
        # handful of built-in policies plus whatever custom ones the tenant has
        # defined, never large enough to need paging, and a live BadRequest was
        # observed against this endpoint with $top=50 on it (root cause not yet
        # confirmed against a live tenant; dropped as the safe simplification).
        try {
            $strengthResp = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies' `
                -ErrorAction Stop
            # $strengthResp is a Hashtable (Invoke-NRGGraphRequest pins -OutputType
            # HashTable) — a bare dot-read on an absent key throws under StrictMode
            # identically to a PSObject; only index access / Get-NRGObjectField is safe.
            $result.Data.AuthStrengths = @(Get-NRGObjectField -Item $strengthResp -Key 'value' -Default @() | ForEach-Object {
                @{
                    Id                  = [string](Get-NRGObjectField -Item $_ -Key 'id' -Default '')
                    DisplayName         = [string](Get-NRGObjectField -Item $_ -Key 'displayName' -Default '')
                    PolicyType          = [string](Get-NRGObjectField -Item $_ -Key 'policyType' -Default '')
                    AllowedCombinations = @(Get-NRGObjectField -Item $_ -Key 'allowedCombinations' -Default @())
                }
            })
            $result.Data.SectionStatus.AuthStrengths = 'Collected'
        } catch {
            $result.Data.SectionStatus.AuthStrengths = 'Failed'
            # ErrorDetails.Message carries the actual Graph error body (a JSON
            # object with a real reason) when present; $_.Exception.Message alone
            # is just the generic "Response status code does not indicate success"
            # text and gives no way to diagnose a BadRequest after the fact.
            $detail = $_.Exception.Message
            $errBody = [string](Get-NRGNestedProperty -Object $_ -Path 'ErrorDetails.Message' -Default '')
            if ($errBody) {
                $detail = "$detail | $errBody"
            }
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-AuthStrengths' -Message $detail
            }
        }

        # Honest success: only if the CA-policies fetch itself succeeded. A
        # failed policies fetch -> Success=$false -> evaluators route CA controls
        # to NotApplicable ("couldn't assess"), never to a false Gap.
        $result.Success = $policiesCollected
        # While Security Defaults is on, CA policies can be created but not
        # turned on, so the console line says so instead of reading as an
        # unprotected tenant. The AuthPolicies step runs just before this one;
        # a state that was not read ($null) leaves the notes as they were.
        # Data is unchanged: AAD-AuthPolicies stays the single source of truth.
        $sd = if (Get-Command Get-NRGSecurityDefaultsState -ErrorAction SilentlyContinue) { Get-NRGSecurityDefaultsState } else { $null }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            if ($policiesCollected) {
                if ($sd -eq $true) {
                    Register-NRGCoverage -Family 'AAD-CAPolicies' -Status 'Collected' -Note "Security Defaults on: CA policies cannot be turned on ($(@($result.Data.Policies).Count) found)"
                } else {
                    Register-NRGCoverage -Family 'AAD-CAPolicies' -Status 'Collected'
                }
            } elseif ($sd -eq $true) {
                Register-NRGCoverage -Family 'AAD-CAPolicies' -Status 'Failed' -Note 'CA read failed; Security Defaults is on (see Exceptions)'
            } else {
                Register-NRGCoverage -Family 'AAD-CAPolicies' -Status 'Failed' -Note 'CA policies fetch/parse failed — see exceptions'
            }
        }

    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'AAD-CAPolicies' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-CAPolicies' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data $result
    }
    return $result
}

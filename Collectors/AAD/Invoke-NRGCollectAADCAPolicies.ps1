#Requires -Version 7.0
#
# Invoke-NRGCollectAADCAPolicies.ps1  (v4.5.5)
# Collects Conditional Access policies and named locations.
# READ-ONLY.
#
# Required Graph scopes: Policy.Read.All
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
            $response = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=250' `
                -ErrorAction Stop
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
            $result.Data.Policies = @($response.value ?? @() | ForEach-Object {
                $p = $_
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
                        }
                    }
                    GrantControls    = @{
                        Operator             = [string](& $g 'grantControls.operator' '')
                        BuiltInControls      = @(& $g 'grantControls.builtInControls')
                        CustomControls       = @(& $g 'grantControls.customAuthenticationFactors')
                        AuthStrengthId       = [string](& $g 'grantControls.authenticationStrength.id' '')
                        AuthStrengthName     = [string](& $g 'grantControls.authenticationStrength.displayName' '')
                    }
                    SessionControls  = @{
                        SignInFrequency  = if ($sif) {
                            @{
                                IsEnabled         = [bool](& $g 'sessionControls.signInFrequency.isEnabled' $false)
                                Value             = (& $g 'sessionControls.signInFrequency.value' $null)
                                Type              = [string](& $g 'sessionControls.signInFrequency.type' '')
                                FrequencyInterval = [string](& $g 'sessionControls.signInFrequency.frequencyInterval' '')
                            }
                        } else { $null }
                        PersistentBrowser = if ($pb) {
                            @{ IsEnabled = [bool](& $g 'sessionControls.persistentBrowser.isEnabled' $false); Mode = [string](& $g 'sessionControls.persistentBrowser.mode' '') }
                        } else { $null }
                    }
                }
            })
            $policiesCollected = $true
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-CAPolicies' -Message $_.Exception.Message
            }
        }

        # Named Locations
        try {
            $locResp = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations?$top=100' `
                -ErrorAction Stop
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
            $result.Data.NamedLocations = @($locResp.value ?? @() | ForEach-Object {
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
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            if ($policiesCollected) {
                Register-NRGCoverage -Family 'AAD-CAPolicies' -Status 'Collected'
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

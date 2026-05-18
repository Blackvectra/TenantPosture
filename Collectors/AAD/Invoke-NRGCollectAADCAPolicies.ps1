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
        }
    }

    try {
        # Conditional Access Policies
        try {
            $response = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=250' `
                -ErrorAction Stop
            $result.Data.Policies = @($response.value ?? @() | ForEach-Object {
                @{
                    Id               = [string]$_.id
                    DisplayName      = [string]$_.displayName
                    State            = [string]$_.state
                    CreatedDateTime  = [string]($_.createdDateTime ?? '')
                    ModifiedDateTime = [string]($_.modifiedDateTime ?? '')
                    Conditions       = @{
                        ClientAppTypes    = @($_.conditions.clientAppTypes ?? @())
                        SignInRiskLevels  = @($_.conditions.signInRiskLevels ?? @())
                        UserRiskLevels    = @($_.conditions.userRiskLevels ?? @())
                        AuthFlows         = @($_.conditions.authenticationFlows ?? @())
                        Platforms         = @($_.conditions.platforms.includePlatforms ?? @())
                        Locations         = @{
                            Include = @($_.conditions.locations.includeLocations ?? @())
                            Exclude = @($_.conditions.locations.excludeLocations ?? @())
                        }
                        Users             = @{
                            IncludeUsers  = @($_.conditions.users.includeUsers ?? @())
                            ExcludeUsers  = @($_.conditions.users.excludeUsers ?? @())
                            IncludeGroups = @($_.conditions.users.includeGroups ?? @())
                            ExcludeGroups = @($_.conditions.users.excludeGroups ?? @())
                            IncludeRoles  = @($_.conditions.users.includeRoles ?? @())
                            ExcludeRoles  = @($_.conditions.users.excludeRoles ?? @())
                        }
                        Applications      = @{
                            Include = @($_.conditions.applications.includeApplications ?? @())
                            Exclude = @($_.conditions.applications.excludeApplications ?? @())
                        }
                    }
                    GrantControls    = @{
                        Operator             = [string]($_.grantControls.operator ?? '')
                        BuiltInControls      = @($_.grantControls.builtInControls ?? @())
                        CustomControls       = @($_.grantControls.customAuthenticationFactors ?? @())
                        AuthStrengthId       = [string]($_.grantControls.authenticationStrength.id ?? '')
                        AuthStrengthName     = [string]($_.grantControls.authenticationStrength.displayName ?? '')
                    }
                    SessionControls  = @{
                        SignInFrequency  = if ($_.sessionControls.signInFrequency) {
                            @{
                                IsEnabled       = [bool]$_.sessionControls.signInFrequency.isEnabled
                                Value           = $_.sessionControls.signInFrequency.value
                                Type            = [string]($_.sessionControls.signInFrequency.type ?? '')
                                FrequencyInterval = [string]($_.sessionControls.signInFrequency.frequencyInterval ?? '')
                            }
                        } else { $null }
                        PersistentBrowser = if ($_.sessionControls.persistentBrowser) {
                            @{ IsEnabled = [bool]$_.sessionControls.persistentBrowser.isEnabled; Mode = [string]$_.sessionControls.persistentBrowser.mode }
                        } else { $null }
                    }
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-CAPolicies' -Message $_.Exception.Message
            }
        }

        # Named Locations
        try {
            $locResp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations?$top=100' `
                -ErrorAction Stop
            $result.Data.NamedLocations = @($locResp.value ?? @() | ForEach-Object {
                @{
                    Id          = [string]$_.id
                    DisplayName = [string]$_.displayName
                    OdataType   = [string]($_.'@odata.type' ?? '')
                    IsTrusted   = [bool]($_.isTrusted ?? $false)
                    IpRanges    = @($_.ipRanges ?? @() | ForEach-Object { [string]($_.cidrAddress ?? '') })
                    CountriesAndRegions = @($_.countriesAndRegions ?? @())
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-NamedLocations' -Message $_.Exception.Message
            }
        }

        # Authentication Strength Policies
        try {
            $strengthResp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies?$top=50' `
                -ErrorAction Stop
            $result.Data.AuthStrengths = @($strengthResp.value ?? @() | ForEach-Object {
                @{
                    Id                  = [string]$_.id
                    DisplayName         = [string]$_.displayName
                    PolicyType          = [string]($_.policyType ?? '')
                    AllowedCombinations = @($_.allowedCombinations ?? @())
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-AuthStrengths' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-CAPolicies' -Status 'Collected'
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

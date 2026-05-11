#
# Get-NRGCollector-AAD-CAPolicies.ps1
# Collects all Conditional Access policies + their configurations.
# COLLECTION ONLY - no scoring.
#

function Get-NRGCollector-AAD-CAPolicies {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'AAD-CAPolicies'
        Timestamp  = [DateTime]::UtcNow.ToString('o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    try {
        $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)

        $policyDetails = foreach ($p in $policies) {
            [PSCustomObject]@{
                Id                = $p.Id
                DisplayName       = $p.DisplayName
                State             = $p.State
                CreatedDateTime   = $p.CreatedDateTime
                ModifiedDateTime  = $p.ModifiedDateTime
                Conditions = @{
                    Users = @{
                        IncludeUsers  = @($p.Conditions.Users.IncludeUsers)
                        ExcludeUsers  = @($p.Conditions.Users.ExcludeUsers)
                        IncludeGroups = @($p.Conditions.Users.IncludeGroups)
                        ExcludeGroups = @($p.Conditions.Users.ExcludeGroups)
                        IncludeRoles  = @($p.Conditions.Users.IncludeRoles)
                        ExcludeRoles  = @($p.Conditions.Users.ExcludeRoles)
                    }
                    Applications = @{
                        IncludeApplications = @($p.Conditions.Applications.IncludeApplications)
                        ExcludeApplications = @($p.Conditions.Applications.ExcludeApplications)
                        IncludeUserActions  = @($p.Conditions.Applications.IncludeUserActions)
                    }
                    ClientAppTypes    = @($p.Conditions.ClientAppTypes)
                    Locations = @{
                        IncludeLocations = @($p.Conditions.Locations.IncludeLocations)
                        ExcludeLocations = @($p.Conditions.Locations.ExcludeLocations)
                    }
                    Platforms = @{
                        IncludePlatforms = @($p.Conditions.Platforms.IncludePlatforms)
                        ExcludePlatforms = @($p.Conditions.Platforms.ExcludePlatforms)
                    }
                    UserRiskLevels   = @($p.Conditions.UserRiskLevels)
                    SignInRiskLevels = @($p.Conditions.SignInRiskLevels)
                }
                GrantControls = @{
                    Operator        = $p.GrantControls.Operator
                    BuiltInControls = @($p.GrantControls.BuiltInControls)
                    AuthenticationStrength = if ($p.GrantControls.AuthenticationStrength) {
                        @{ DisplayName = $p.GrantControls.AuthenticationStrength.DisplayName; Id = $p.GrantControls.AuthenticationStrength.Id }
                    } else { $null }
                }
                SessionControls = @{
                    ApplicationEnforcedRestrictions = if ($p.SessionControls.ApplicationEnforcedRestrictions) { $p.SessionControls.ApplicationEnforcedRestrictions.IsEnabled } else { $false }
                    PersistentBrowser = if ($p.SessionControls.PersistentBrowser) { @{ IsEnabled = $p.SessionControls.PersistentBrowser.IsEnabled; Mode = $p.SessionControls.PersistentBrowser.Mode } } else { $null }
                    SignInFrequency   = if ($p.SessionControls.SignInFrequency)   { @{ IsEnabled = $p.SessionControls.SignInFrequency.IsEnabled; Type = $p.SessionControls.SignInFrequency.Type; Value = $p.SessionControls.SignInFrequency.Value } } else { $null }
                }
            }
        }

        $result.Data['Policies']      = $policyDetails
        $result.Data['TotalCount']    = $policies.Count
        $result.Data['EnabledCount']  = @($policies | Where-Object State -eq 'enabled').Count
        $result.Data['ReportOnlyCount'] = @($policies | Where-Object State -eq 'enabledForReportingButNotEnforced').Count
        $result.Data['DisabledCount'] = @($policies | Where-Object State -eq 'disabled').Count

        $result.Success = $true
        Register-NRGCoverage -Family 'AAD-CAPolicies' -Status 'Collected'
    }
    catch {
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'AAD-CAPolicies' -Message $_.Exception.Message
        Register-NRGCoverage -Family 'AAD-CAPolicies' -Status 'Failed' -Note $_.Exception.Message
    }

    Set-NRGRawData -Key 'AAD-CAPolicies' -Data $result
    return $result
}

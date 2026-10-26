#Requires -Version 7.0
#
# Get-TPRetentionCoverage.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Judge which workloads ENABLED retention policies cover from the policies' location
#          properties, never from Workload. Microsoft documents that Get-RetentionCompliancePolicy's
#          Workload "shows all workloads (Exchange, SharePoint, OneDriveForBusiness, Skype,
#          ModernGroup). It doesn't show the actual workload on which the policy is applied", and
#          that -DistributionDetail returns "accurate values for the ... *Location properties".
#
# Data consumed: Purview (RetentionPolicies: Enabled, LocationsRead, Locations, AdaptiveScopes).
# Graph scopes / cmdlets: none (Get-RetentionCompliancePolicy is read by the Purview collector).

function Get-TPRetentionPolicyLocations {
    <#
    .SYNOPSIS
        The location properties of one Get-RetentionCompliancePolicy row, as name lists per
        location (empty list = the location is not in the policy), plus its adaptive scopes.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] $Policy)
    $asNames = { param($v) @(@($v) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { $n = Get-TPObjectField -Item $_ -Key 'Name' -Default $null; if ($n) { [string]$n } else { [string]$_ } }) }
    $map = [ordered]@{}
    $fields = [ordered]@{
        Exchange = 'ExchangeLocation'; SharePoint = 'SharePointLocation'; OneDriveForBusiness = 'OneDriveLocation'
        TeamsChannel = 'TeamsChannelLocation'; TeamsChat = 'TeamsChatLocation'; AdaptiveScopes = 'AdaptiveScopeLocation'
    }
    foreach ($k in $fields.Keys) { $map[$k] = @(& $asNames (Get-TPObjectField -Item $Policy -Key $fields[$k] -Default $null)) }
    return $map
}

function Get-TPRetentionCoverage {
    <#
    .SYNOPSIS
        Which of Exchange, SharePoint, OneDrive and Teams the enabled retention policies cover.
        Returns LocationsRead = $false when any policy's locations were not read with
        -DistributionDetail (an older results file), since Workload cannot answer the question.
        An enabled policy scoped by adaptive scopes covers workloads its static locations do not
        show, so a workload no static location covers is then not established, never missing.
    #>
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Policies)
    $all = @($Policies | Where-Object { $null -ne $_ })
    $read = @($all | Where-Object { (Get-TPObjectField -Item $_ -Key 'LocationsRead' -Default $false) -ne $true }).Count -eq 0
    $enabled = @($all | Where-Object { (Get-TPObjectField -Item $_ -Key 'Enabled' -Default $null) -eq $true })
    $enabledUnknown = @($all | Where-Object { $null -eq (Get-TPObjectField -Item $_ -Key 'Enabled' -Default $null) })
    $loc = { param($p, $k) @(@(Get-TPNestedProperty -Object $p -Path "Locations.$k" -Default @()) | Where-Object { $null -ne $_ -and "$_" -ne '' }) }
    $workloads = [ordered]@{ Exchange = @('Exchange'); SharePoint = @('SharePoint'); OneDriveForBusiness = @('OneDriveForBusiness'); Teams = @('TeamsChannel', 'TeamsChat') }
    $covered = [ordered]@{}
    foreach ($w in $workloads.Keys) {
        $covered[$w] = @($enabled | Where-Object { $p = $_; @($workloads[$w] | Where-Object { @(& $loc $p $_).Count -gt 0 }).Count -gt 0 } |
            ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '') })
    }
    [pscustomobject]@{
        LocationsRead   = $read
        PolicyCount     = $all.Count
        EnabledCount    = $enabled.Count
        DisabledNames   = @($all | Where-Object { (Get-TPObjectField -Item $_ -Key 'Enabled' -Default $null) -eq $false } | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '') })
        EnabledUnknown  = $enabledUnknown.Count
        Adaptive        = @($enabled | Where-Object { @(& $loc $_ 'AdaptiveScopes').Count -gt 0 } | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '') })
        Covered         = $covered
    }
}

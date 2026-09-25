#Requires -Version 7.0
#
# Get-NRGGraphConsent.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Record which Microsoft Graph permissions the connected token was
#   actually granted, so a control that could not read its data can say
#   "this tenant has not consented to X" instead of a generic "not collected".
#
# Data keys: sets 'Graph-Consent' (Data.Mode, Data.GrantedScopes,
#   Data.MissingScopes). Written by Connect-NRGServices after Graph connects;
#   read by the AAD-8.2 / AAD-11.3 / DEF-4.6 evaluators.
# Graph: none — reads Get-MgContext only.
#
# A scope counts as missing only when the token's scope list was actually
# read and does not contain it. No record, or an empty scope list, means
# "unknown" and callers fall back to their generic message: absence of
# evidence is never evidence.

# Scopes that need a one-time admin consent in each client tenant, and the
# controls that go unassessed without them.
$script:NRGConsentScopes = [ordered]@{
    'AccessReview.Read.All'                  = 'AAD-8.2'
    'IdentityRiskyServicePrincipal.Read.All' = 'AAD-11.3'
    'AttackSimulation.Read.All'              = 'DEF-4.6'
}

function Get-NRGConsentScopeMap {
    [CmdletBinding()] param()
    foreach ($k in $script:NRGConsentScopes.Keys) {
        [pscustomobject]@{ Scope = $k; ControlId = $script:NRGConsentScopes[$k] }
    }
}

function Set-NRGGraphConsentState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Delegated', 'AppOnly')] [string] $Mode,
        [AllowNull()] [string[]] $GrantedScopes,
        [AllowNull()] [string[]] $RequestedScopes
    )
    $granted = @(@($GrantedScopes) | Where-Object { $_ })
    # Only the consent-sensitive scopes are compared in app-only mode: the app
    # registration grants application permissions whose names differ from the
    # delegated list (RoleManagement.Read.Directory vs RoleManagement.Read.All).
    $compare = if ($Mode -eq 'AppOnly') { @($script:NRGConsentScopes.Keys) } else { @(@($RequestedScopes) | Where-Object { $_ }) }
    $missing = @()
    if ($granted.Count -gt 0) { $missing = @($compare | Where-Object { $granted -notcontains $_ }) }
    Set-NRGRawData -Key 'Graph-Consent' -Data ([ordered]@{
        CollectorId = 'Graph-Consent'
        CollectedAt = (Get-Date).ToString('o')
        Success     = ($granted.Count -gt 0)
        Data        = [ordered]@{
            Mode          = $Mode
            GrantedScopes = $granted
            MissingScopes = $missing
        }
    })
    return $missing
}

function Test-NRGGraphScopeMissing {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Scope)
    $rec = Get-NRGRawData -Key 'Graph-Consent'
    if (-not $rec -or -not (Get-NRGObjectField -Item $rec -Key 'Success' -Default $false)) { return $false }
    $granted = @(Get-NRGNestedProperty -Object $rec -Path 'Data.GrantedScopes' -Default @())
    if ($granted.Count -eq 0) { return $false }
    return ($granted -notcontains $Scope)
}

# The finding text for a control whose read was refused for lack of consent.
function Get-NRGConsentMissingDetail {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Scope)
    $rec  = Get-NRGRawData -Key 'Graph-Consent'
    $mode = [string](Get-NRGNestedProperty -Object $rec -Path 'Data.Mode' -Default 'Delegated')
    $fix  = if ($mode -eq 'AppOnly') {
        "In the tenant's Entra admin center, open App registrations > the NRG assessment app > API permissions, add the Microsoft Graph APPLICATION permission $Scope, then Grant admin consent."
    } else {
        "A Global Administrator of the tenant runs .\Grant-NRGGraphConsent.ps1 -TenantDomain <tenant> once and accepts the consent prompt for the organization."
    }
    "Not assessed: this tenant has not granted admin consent for the $Scope Graph permission, so the data could not be read. This is not a pass. One-time fix: $fix The control is assessed on the next run."
}

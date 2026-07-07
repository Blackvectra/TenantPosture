#Requires -Version 7.0
#
# Invoke-NRGGraphRequest.ps1  (v4.12.2)
#
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Thin, shape-pinning proxy over Invoke-MgGraphRequest. Forces
#          -OutputType HashTable so every collector reads a stable, StrictMode-
#          safe object shape regardless of the installed Microsoft.Graph SDK
#          version. Newer SDK builds return PSCustomObject by default, on which
#          a bare `$resp.'@odata.nextLink'` (or `$resp.value`) THROWS under
#          Set-StrictMode -Version Latest when the property is absent — which
#          it is on any single-page (small-tenant) response. Hashtables return
#          $null on absent keys instead, so the existing `?? $default` guards
#          throughout the collectors behave as originally written.
#
#          Root-cause fix for the clienta.org 2026-07-07 mass-false-gap run,
#          where ~20 Graph collectors bailed with empty data and the evaluators
#          scored empty as "Gap" (e.g. reported 0 Global Admins when 4 existed).
#
# Consumes: nothing (stateless).
# Sets:     nothing.
# Graph:    proxies GET requests only (all current call sites are GET).
# Cmdlets:  Invoke-MgGraphRequest (Microsoft.Graph.Authentication).

function Invoke-NRGGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Uri,

        [Parameter(Position = 1)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string] $Method = 'GET',

        [Parameter()]
        [AllowNull()]
        [object] $Body,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary] $Headers,

        # Pinned to HashTable by default. Exposed so a caller that genuinely
        # needs a raw HttpResponseMessage / Json string can opt out, but the
        # tool's collectors must never pass PSObject — that reintroduces the
        # StrictMode property-access bug this proxy exists to prevent.
        [Parameter()]
        [ValidateSet('HashTable', 'PSObject', 'HttpResponseMessage', 'Json')]
        [string] $OutputType = 'HashTable'
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $splat = @{
        Uri        = $Uri
        Method     = $Method
        OutputType = $OutputType
    }
    if ($PSBoundParameters.ContainsKey('Body'))    { $splat['Body']    = $Body }
    if ($PSBoundParameters.ContainsKey('Headers')) { $splat['Headers'] = $Headers }

    return Invoke-MgGraphRequest @splat
}

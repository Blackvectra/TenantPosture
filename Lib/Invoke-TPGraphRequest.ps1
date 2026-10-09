#Requires -Version 7.0
#
# Invoke-TPGraphRequest.ps1  (v4.12.2)
#
# Dependencies: Microsoft.Graph.Authentication (Invoke-MgGraphRequest)
#
# TenantPosture
# Author: Matthew Levorson
# Purpose: Thin, shape-pinning proxy over Invoke-MgGraphRequest. Forces
#          -OutputType HashTable so every collector reads a stable, StrictMode-
#          safe object shape regardless of the installed Microsoft.Graph SDK
#          version. Newer SDK builds return PSCustomObject by default, on which
#          a bare `$resp['@odata.nextLink']` (or `$resp.value`) THROWS under
#          Set-StrictMode -Version Latest when the property is absent — which
#          it is on any single-page (small-tenant) response. Hashtables only
#          return $null on absent keys via INDEX access ($resp['key']) or
#          Get-TPObjectField; a bare dot-read ($resp.key) on a hashtable
#          throws under StrictMode identically to a PSObject, so the existing
#          `?? $default` guards throughout the collectors are StrictMode-safe
#          only when they use index access, never dot-access.
#
#          Root-cause fix for a July-2026 client mass-false-gap run,
#          where ~20 Graph collectors bailed with empty data and the evaluators
#          scored empty as "Gap" (e.g. reported 0 Global Admins when 4 existed).
#          Get-TPGraphAllPages reads a whole paged collection through it.
#
# Consumes: nothing (stateless).
# Sets:     nothing.
# Graph:    proxies GET requests only (all current call sites are GET).
# Cmdlets:  Invoke-MgGraphRequest (Microsoft.Graph.Authentication).

function Invoke-TPGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Uri,

        [Parameter(Position = 1)]
        [ValidateSet('GET')]
        [string] $Method = 'GET',

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
    if ($PSBoundParameters.ContainsKey('Headers')) { $splat['Headers'] = $Headers }

    return Invoke-MgGraphRequest @splat
}

# Returns every item of a Graph collection, following @odata.nextLink. A list
# read from its first page alone is reported as a full enumeration, so this
# throws instead of returning a partial list: when a response carries no
# 'value' collection, or when the page cap is reached with pages still pending.
# The caller's catch then marks its section unread.
function Get-TPGraphAllPages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Uri,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary] $Headers,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int] $MaxPages = 100
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $items = [System.Collections.Generic.List[object]]::new()
    $next  = $Uri
    $pages = 0
    while ($next) {
        if ($pages -ge $MaxPages) {
            throw "Graph paging stopped at the $MaxPages-page cap with pages still pending for $Uri; the list is incomplete."
        }
        $splat = @{ Uri = $next; Method = 'GET'; ErrorAction = 'Stop' }
        if ($Headers) { $splat['Headers'] = $Headers }
        $resp = Invoke-TPGraphRequest @splat
        # Read 'value' by index, not through Get-TPObjectField: its return
        # unrolls an empty array to $null, which would read as "absent".
        $raw = $null
        if ($resp -is [System.Collections.IDictionary]) {
            if ($resp.Contains('value')) { $raw = $resp['value'] }
        } elseif ($null -ne $resp -and $null -ne $resp.PSObject.Properties['value']) {
            $raw = $resp.PSObject.Properties['value'].Value
        }
        if ($null -eq $raw) { throw "Graph returned no 'value' collection for $next." }
        foreach ($v in @($raw)) { if ($null -ne $v) { $items.Add($v) } }
        # Never Get-TPNestedProperty here: it splits on '.' and reads
        # '@odata' -> 'nextLink', so paging would stop after page one.
        $next = [string](Get-TPObjectField -Item $resp -Key '@odata.nextLink' -Default '')
        $pages++
    }
    return $items.ToArray()
}

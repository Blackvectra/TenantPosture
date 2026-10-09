#Requires -Version 7.0
#
# Resolve-TPTenantId.ps1
# TenantPosture
# Author: Matthew Levorson
# Purpose: Resolve a tenant's GUID from one of its domains via the public
#          OpenID metadata endpoint, so a scan can be pinned to the tenant the
#          operator asked for instead of whichever tenant they signed in to.
#
# Sets:     nothing (pure lookup)
# Consumes: nothing
# Network:  GET https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration
#           (anonymous, read-only; the same lookup CLAUDE.md documents for clients.json TenantId)

function Resolve-TPTenantId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61})+$')]
        [string] $Domain,

        [int] $TimeoutSeconds = 10
    )
    try {
        $meta = Invoke-RestMethod -Method Get -TimeoutSec $TimeoutSeconds -ErrorAction Stop `
            -Uri "https://login.microsoftonline.com/$Domain/v2.0/.well-known/openid-configuration"
        $issuer = [string](Get-TPObjectField -Item $meta -Key 'issuer' -Default '')
        if ($issuer -match '/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/') {
            return $Matches[1].ToLowerInvariant()
        }
    } catch {
        Write-Verbose "Resolve-TPTenantId: $Domain -> $($_.Exception.Message)"
    }
    return $null
}

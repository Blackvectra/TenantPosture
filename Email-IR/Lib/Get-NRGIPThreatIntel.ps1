#Requires -Version 7.0
#
# Get-NRGIPThreatIntel.ps1  (v4.12.x)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: IP-level threat intelligence helpers for the sign-in triage:
#          geolocation + ASN owner lookup via RDAP, plus hosting/VPN-ASN
#          tagging from that same lookup.
#
# Privacy: every IP queried via RDAP is submitted to the regional RIR
#          (ARIN / RIPE / APNIC / LACNIC / AFRINIC). Operator's
#          responsibility to confirm client data-handling policy
#          permits this. RDAP queries do NOT include identifying info
#          about the operator's tenant — just the IP being looked up.
#
# Outbound: rdap.org only. An earlier version also fetched
#           https://check.torproject.org/torbulkexitlist for standalone
#           Tor-exit detection; that hostname is flagged by several EDRs
#           (Palo Alto Cortex XDR, Microsoft Defender for Endpoint,
#           CrowdStrike) as "Tor infrastructure contact", and a later
#           version replaced it with an operator-supplied local exit-list
#           file to drop the live fetch. Tor-exit detection has since been
#           REMOVED from this helper entirely — no local-file lookup, no
#           TOR_EXIT flag. Tor sign-ins for tenants with Entra ID P2 are
#           still caught upstream: Microsoft Identity Protection labels
#           them server-side via 'anonymizedIPAddress' in riskEventTypes_v2,
#           and the sign-in scorer already reads that signal unchanged —
#           this file was never that signal's only source.
#
# Caching: per-process cache keyed by IP.

if (-not (Get-Variable -Name NRGIPCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:NRGIPCache = [System.Collections.Generic.Dictionary[string,object]]::new()
}

function Get-NRGIPGeolocation {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            $parsed = [System.Net.IPAddress]::None
            if (-not [System.Net.IPAddress]::TryParse($_, [ref]$parsed)) {
                throw "Not a valid IPv4/IPv6 address: '$_'"
            }
            $true
        })]
        [string] $IPAddress,

        [int] $TimeoutSeconds = 6
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $cacheKey = "geo:$IPAddress"
    if ($script:NRGIPCache.ContainsKey($cacheKey)) {
        return $script:NRGIPCache[$cacheKey]
    }

    $result = [ordered]@{
        IPAddress = $IPAddress
        Country   = $null
        Region    = $null
        City      = $null
        ASN       = $null
        ASNOwner  = $null
        CIDR      = $null
        Source    = 'rdap.org'
        Error     = $null
    }
    try {
        try {
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        } catch {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        # rdap.org auto-routes to the responsible RIR (ARIN/RIPE/APNIC/etc.)
        $url = "https://rdap.org/ip/$IPAddress"
        $resp = Invoke-RestMethod -Uri $url -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop

        # Country comes from the top-level "country" field on most RIRs.
        if ($resp.country) { $result.Country = [string]$resp.country }
        # CIDR network range
        if ($resp.handle) { $result.CIDR = [string]$resp.handle }
        elseif ($resp.cidr0_cidrs -and $resp.cidr0_cidrs.Count -gt 0) {
            $result.CIDR = "$($resp.cidr0_cidrs[0].v4prefix)/$($resp.cidr0_cidrs[0].length)"
        }

        # ASN owner is the entity with role 'registrant' or 'administrative'
        if ($resp.entities) {
            $owner = $resp.entities | Where-Object {
                $_.roles -contains 'registrant' -or
                $_.roles -contains 'administrative' -or
                $_.roles -contains 'technical'
            } | Select-Object -First 1
            if ($owner) {
                # vcardArray is the standard contact format
                if ($owner.vcardArray -and $owner.vcardArray.Count -ge 2) {
                    foreach ($v in $owner.vcardArray[1]) {
                        if ($v -is [array] -and $v.Count -ge 4 -and $v[0] -eq 'fn') {
                            $result.ASNOwner = [string]$v[3]; break
                        }
                    }
                }
                if (-not $result.ASNOwner -and $owner.handle) { $result.ASNOwner = [string]$owner.handle }
            }
        }

        # Some RIRs expose ASN via the "remarks" field; not standardized
        # — best-effort.
    } catch {
        $result.Error = $_.Exception.Message.Split([char]10)[0]
    }

    # A failed lookup is not cached: a timeout must not become the permanent
    # answer for this address for the rest of the process.
    if (-not $result.Error) { $script:NRGIPCache[$cacheKey] = $result }
    return $result
}

function Clear-NRGIPThreatIntelCache {
    [CmdletBinding()] param()
    $script:NRGIPCache.Clear()
}

# ─────────────────────────────────────────────────────────────────────────────
# Combined enrichment: takes a sign-in event, returns enriched IoC metadata
# ─────────────────────────────────────────────────────────────────────────────
function Get-NRGIPSignInIntel {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $IPAddress
    )
    Set-StrictMode -Version Latest
    $geo = Get-NRGIPGeolocation -IPAddress $IPAddress
    $err = [string](Get-NRGObjectField -Item $geo -Key 'Error' -Default '')
    # LookupStatus keeps three outcomes apart, because "nothing flagged" means
    # different things for each: Resolved (registrant data came back and was
    # judged), NoOwnerData (the lookup answered but named no owner, so nothing
    # could be judged), Failed (the lookup did not complete). Only Resolved may
    # support a negative.
    $status = if ($err) { 'Failed' } elseif ($geo.ASNOwner) { 'Resolved' } else { 'NoOwnerData' }
    # The flags come from pattern matches on the registrant NAME. They are
    # context about who holds the address, not a verdict that it is hostile.
    [ordered]@{
        IPAddress    = $IPAddress
        Country      = $geo.Country
        ASNOwner     = $geo.ASNOwner
        CIDR         = $geo.CIDR
        LookupStatus = $status
        Error        = $err
        Flags        = @(
            if ($status -eq 'Resolved' -and ($geo.ASNOwner -match '(?i)hosting|datacenter|server|cloud|colo|VPS')) { 'HOSTING_ASN' }
            if ($status -eq 'Resolved' -and ($geo.ASNOwner -match '(?i)NordVPN|Mullvad|Surfshark|ExpressVPN|ProtonVPN|PIA|Private Internet'))     { 'KNOWN_VPN_ASN' }
        ) | Where-Object { $_ }
        Source       = 'rdap.org (registrant name match, not a reputation verdict)'
    }
}

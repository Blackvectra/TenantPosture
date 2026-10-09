#Requires -Version 7.0
#
# Get-TPIPThreatIntel.ps1  (v4.12.x)
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
# Outbound: rdap.org only. This helper makes no other network call and
#           does no Tor-exit detection (an earlier version did; it was
#           removed). Tor sign-ins for tenants with Entra ID P2 are caught
#           upstream: Microsoft Identity Protection labels them server-side
#           via 'anonymizedIPAddress' in riskEventTypes_v2, which the
#           sign-in scorer reads unchanged.
#
# Caching: per-process cache keyed by IP.

if (-not (Get-Variable -Name TPIPCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:TPIPCache = [System.Collections.Generic.Dictionary[string,object]]::new()
}

function Get-TPIPGeolocation {
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
    if ($script:TPIPCache.ContainsKey($cacheKey)) {
        return $script:TPIPCache[$cacheKey]
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

        # Every field is optional in RDAP (RFC 9083) and the RIRs differ: ARIN
        # sends no top-level "country", so a dot-read threw under StrictMode and
        # every North American address came back Failed. Read each field through
        # Get-TPObjectField.
        $country = [string](Get-TPObjectField -Item $resp -Key 'country' -Default '')
        if ($country) { $result.Country = $country }
        # CIDR network range
        $handle = [string](Get-TPObjectField -Item $resp -Key 'handle' -Default '')
        $cidrs = @(@(Get-TPObjectField -Item $resp -Key 'cidr0_cidrs' -Default @()) | Where-Object { $_ })
        if ($handle) { $result.CIDR = $handle }
        elseif ($cidrs.Count -gt 0) {
            $prefix = Get-TPObjectField -Item $cidrs[0] -Key 'v4prefix' -Default (Get-TPObjectField -Item $cidrs[0] -Key 'v6prefix' -Default '')
            $result.CIDR = "$prefix/$(Get-TPObjectField -Item $cidrs[0] -Key 'length' -Default '')"
        }

        # The holder of the address is the entity with the 'registrant' role
        # (RFC 9083 section 10.2.4). Administrative, technical and abuse
        # entities are CONTACTS: RIPE lists its "Managing Director" contact
        # first, and judging a contact's name as the owner is wrong. With no
        # registrant the owner stays unknown (NoOwnerData). RIPE also tags its
        # maintainer object 'registrant' (vCard kind 'individual'), so an
        # organization registrant is preferred when there is one.
        $vcardValue = {
            param($Entity, [string] $Property)
            $vc = @(Get-TPObjectField -Item $Entity -Key 'vcardArray' -Default @())
            if ($vc.Count -lt 2) { return $null }
            foreach ($v in @($vc[1])) {
                if ($v -is [array] -and $v.Count -ge 4 -and $v[0] -eq $Property) { return [string]$v[3] }
            }
            return $null
        }
        $entities = @(@(Get-TPObjectField -Item $resp -Key 'entities' -Default @()) | Where-Object { $_ })
        $registrants = @($entities | Where-Object { @(Get-TPObjectField -Item $_ -Key 'roles' -Default @()) -contains 'registrant' })
        $owner = $registrants | Where-Object { (& $vcardValue $_ 'kind') -eq 'org' } | Select-Object -First 1
        if (-not $owner -and $registrants.Count -gt 0) { $owner = $registrants[0] }
        if ($owner) {
            $result.ASNOwner = & $vcardValue $owner 'fn'
            if (-not $result.ASNOwner) {
                $ownerHandle = [string](Get-TPObjectField -Item $owner -Key 'handle' -Default '')
                if ($ownerHandle) { $result.ASNOwner = $ownerHandle }
            }
        }

        # Some RIRs expose ASN via the "remarks" field; not standardized
        # — best-effort.
    } catch {
        $result.Error = $_.Exception.Message.Split([char]10)[0]
    }

    # A failed lookup is not cached: a timeout must not become the permanent
    # answer for this address for the rest of the process.
    if (-not $result.Error) { $script:TPIPCache[$cacheKey] = $result }
    return $result
}

function Clear-TPIPThreatIntelCache {
    [CmdletBinding()] param()
    $script:TPIPCache.Clear()
}

# ─────────────────────────────────────────────────────────────────────────────
# Combined enrichment: takes a sign-in event, returns enriched IoC metadata
# ─────────────────────────────────────────────────────────────────────────────
function Get-TPIPSignInIntel {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $IPAddress
    )
    Set-StrictMode -Version Latest
    $geo = Get-TPIPGeolocation -IPAddress $IPAddress
    $err = [string](Get-TPObjectField -Item $geo -Key 'Error' -Default '')
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

#Requires -Version 7.0
#
# Get-NRGIPThreatIntel.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: IP-level threat intelligence helpers for the sign-in triage:
#          geolocation + ASN owner lookup via RDAP, and Tor-exit-node
#          cross-check against the Tor Project's published list. All
#          free, unauthenticated sources. No VirusTotal / API keys.
#
# Privacy: every IP queried via RDAP is submitted to the regional RIR
#          (ARIN / RIPE / APNIC / LACNIC / AFRINIC). Operator's
#          responsibility to confirm client data-handling policy
#          permits this. RDAP queries do NOT include identifying info
#          about the operator's tenant — just the IP being looked up.
#
# Caching: per-process cache keyed by IP. Tor exit-list cached once per
#          run with a 6-hour staleness window — refreshed if the on-disk
#          file is older.

if (-not (Get-Variable -Name NRGIPCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:NRGIPCache = [System.Collections.Generic.Dictionary[string,object]]::new()
}
if (-not (Get-Variable -Name NRGTorExitSet -Scope Script -ErrorAction SilentlyContinue)) {
    $script:NRGTorExitSet = $null
    $script:NRGTorLoadedAt = $null
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

    $script:NRGIPCache[$cacheKey] = $result
    return $result
}

# Tor Project's published bulk exit list — text, one IP per line, public,
# no auth. The script downloads once per session (6h cache) and treats
# memberships as O(1) HashSet lookups so a few hundred sign-in IPs
# don't burst into a few hundred HTTP calls.
function Test-NRGIPIsTorExit {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $IPAddress,

        # Force a refresh of the local Tor exit list even if cached.
        [switch] $ForceRefresh
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # (Re)load the Tor exit list if needed
    $stale = (-not $script:NRGTorExitSet) -or
             $ForceRefresh -or
             ($script:NRGTorLoadedAt -and ((Get-Date) - $script:NRGTorLoadedAt).TotalHours -gt 6)
    if ($stale) {
        try {
            try {
                [Net.ServicePointManager]::SecurityProtocol =
                    [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
            } catch {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            }
            $body = Invoke-RestMethod -Uri 'https://check.torproject.org/torbulkexitlist' `
                -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            $script:NRGTorExitSet = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase)
            foreach ($line in ($body -split "`n")) {
                $ip = $line.Trim()
                if ($ip -and -not $ip.StartsWith('#')) {
                    [void]$script:NRGTorExitSet.Add($ip)
                }
            }
            $script:NRGTorLoadedAt = Get-Date
        } catch {
            # Network or cert error — fall through with an empty set.
            # Returning $false for unknown IPs is the safe default.
            if (-not $script:NRGTorExitSet) {
                $script:NRGTorExitSet = [System.Collections.Generic.HashSet[string]]::new()
            }
            Write-Warning "Tor exit list fetch failed; results may underestimate Tor IPs: $($_.Exception.Message.Split([char]10)[0])"
        }
    }
    return $script:NRGTorExitSet.Contains($IPAddress)
}

function Clear-NRGIPThreatIntelCache {
    [CmdletBinding()] param()
    $script:NRGIPCache.Clear()
    $script:NRGTorExitSet  = $null
    $script:NRGTorLoadedAt = $null
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
    $isTor = Test-NRGIPIsTorExit -IPAddress $IPAddress
    [ordered]@{
        IPAddress = $IPAddress
        Country   = $geo.Country
        ASNOwner  = $geo.ASNOwner
        CIDR      = $geo.CIDR
        IsTorExit = $isTor
        Flags     = @(
            if ($isTor)                    { 'TOR_EXIT' }
            if ($geo.ASNOwner -and ($geo.ASNOwner -match '(?i)hosting|datacenter|server|cloud|colo|VPS')) { 'HOSTING_ASN' }
            if ($geo.ASNOwner -and ($geo.ASNOwner -match '(?i)NordVPN|Mullvad|Surfshark|ExpressVPN|ProtonVPN|PIA|Private Internet'))     { 'KNOWN_VPN_ASN' }
        ) | Where-Object { $_ }
        Source    = "rdap.org+torproject"
    }
}

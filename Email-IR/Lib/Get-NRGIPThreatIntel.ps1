#Requires -Version 7.0
#
# Get-NRGIPThreatIntel.ps1  (v4.12.x)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: IP-level threat intelligence helpers for the sign-in triage:
#          geolocation + ASN owner lookup via RDAP. Tor-exit-node detection
#          is gated on an operator-supplied LOCAL file (no outbound to
#          check.torproject.org) — see Test-NRGIPIsTorExit notes.
#
# Privacy: every IP queried via RDAP is submitted to the regional RIR
#          (ARIN / RIPE / APNIC / LACNIC / AFRINIC). Operator's
#          responsibility to confirm client data-handling policy
#          permits this. RDAP queries do NOT include identifying info
#          about the operator's tenant — just the IP being looked up.
#
# Outbound: rdap.org only. The previous version also fetched
#           https://check.torproject.org/torbulkexitlist — that hostname
#           is flagged by several EDRs (Palo Alto Cortex XDR, Microsoft
#           Defender for Endpoint, CrowdStrike) as "Tor infrastructure
#           contact" which generates noise in the MSP's own SIEM even
#           though the fetch is a legitimate enrichment. The fetch has
#           been REMOVED. Two paths still cover Tor:
#             1) Microsoft Identity Protection labels Tor sign-ins
#                server-side via 'anonymizedIPAddress' in
#                riskEventTypes_v2 (Entra ID P2). The scorer already
#                picks this up unchanged.
#             2) Operators who need standalone Tor detection on
#                P1 / no-P2 tenants can curate a local file (one IP per
#                line, # comments allowed) and pass -TorExitListPath.
#
# Caching: per-process cache keyed by IP. Tor exit-list (when a local
#          file is provided) is read once per session and treated as
#          O(1) HashSet lookups.

if (-not (Get-Variable -Name NRGIPCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:NRGIPCache = [System.Collections.Generic.Dictionary[string,object]]::new()
}
if (-not (Get-Variable -Name NRGTorExitSet -Scope Script -ErrorAction SilentlyContinue)) {
    $script:NRGTorExitSet     = $null
    $script:NRGTorLoadedFrom  = $null
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

# Tor-exit lookup against an OPERATOR-SUPPLIED LOCAL FILE.
#
# The previous version of this helper fetched the bulk exit list from
# https://check.torproject.org/torbulkexitlist on first use. That hostname
# is on Palo Alto Cortex XDR, Microsoft Defender for Endpoint, and several
# other EDRs' "suspicious infrastructure" lists, generating noise in the
# MSP's own SIEM. The fetch has been removed; this helper now only loads
# from a local file the operator points at.
#
# File format: newline-delimited IPv4/IPv6 addresses. Lines starting with
# '#' are treated as comments. Blank lines ignored.
#
# Refresh strategy is left to the operator — most Tor exit IPs persist
# for weeks/months, so a snapshot pulled from any trusted internal source
# (your SIEM, MISP, your own mirror of the Tor list, etc.) and committed
# to a SharePoint share is sufficient.
#
# If -TorExitListPath is not supplied (or the file is missing), this
# function returns $false unconditionally. Tor signals are still picked
# up via Microsoft Identity Protection's 'anonymizedIPAddress' risk-event
# type for tenants with Entra ID P2 — that signal flows through
# riskEventTypes_v2 in the sign-in event and is scored by the existing
# anonymous-IP detector. No EDR noise either way.
function Test-NRGIPIsTorExit {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $IPAddress,

        # Operator-controlled local file of Tor exit IPs. Newline-delimited,
        # # comments allowed. When omitted, this helper returns $false.
        [string] $TorExitListPath,

        # Reload the local file even if cached (e.g., operator refreshed
        # the file mid-run).
        [switch] $ForceRefresh
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # No local file → no standalone Tor detection. Microsoft IdP still
    # catches Tor for P2 tenants via anonymizedIPAddress.
    if (-not $TorExitListPath) { return $false }

    if (-not (Test-Path -LiteralPath $TorExitListPath -PathType Leaf)) {
        Write-Warning "Tor exit list file not found: $TorExitListPath — returning `$false (no Tor flag from local list this run)"
        return $false
    }

    # (Re)load the local file if cached set is missing, came from a
    # different path, or operator forced refresh.
    $stale = (-not $script:NRGTorExitSet) -or
             $ForceRefresh -or
             ($script:NRGTorLoadedFrom -ne $TorExitListPath)
    if ($stale) {
        try {
            $script:NRGTorExitSet = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase)
            $lines = Get-Content -LiteralPath $TorExitListPath -ErrorAction Stop
            foreach ($line in $lines) {
                $ip = ([string]$line).Trim()
                if ($ip -and -not $ip.StartsWith('#')) {
                    [void]$script:NRGTorExitSet.Add($ip)
                }
            }
            $script:NRGTorLoadedFrom = $TorExitListPath
        } catch {
            # Read error — safe default is $false rather than throw.
            if (-not $script:NRGTorExitSet) {
                $script:NRGTorExitSet = [System.Collections.Generic.HashSet[string]]::new()
            }
            Write-Warning "Tor exit list read failed; returning `$false: $($_.Exception.Message.Split([char]10)[0])"
        }
    }
    return $script:NRGTorExitSet.Contains($IPAddress)
}

function Clear-NRGIPThreatIntelCache {
    [CmdletBinding()] param()
    $script:NRGIPCache.Clear()
    $script:NRGTorExitSet    = $null
    $script:NRGTorLoadedFrom = $null
}

# ─────────────────────────────────────────────────────────────────────────────
# Combined enrichment: takes a sign-in event, returns enriched IoC metadata
# ─────────────────────────────────────────────────────────────────────────────
function Get-NRGIPSignInIntel {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $IPAddress,

        # Operator-supplied local Tor exit list (see Test-NRGIPIsTorExit).
        # When omitted, Tor detection from this helper is disabled; rely on
        # Microsoft Identity Protection's anonymizedIPAddress risk event.
        [string] $TorExitListPath
    )
    Set-StrictMode -Version Latest
    $geo = Get-NRGIPGeolocation -IPAddress $IPAddress
    $isTor = Test-NRGIPIsTorExit -IPAddress $IPAddress -TorExitListPath $TorExitListPath
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
        Source    = 'rdap.org'
    }
}

#Requires -Version 7.0
#
# Get-NRGThreatIntel.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Lightweight threat-intelligence helpers for NRG-IR. No API keys
#          required for the MVP — uses public, unauthenticated endpoints:
#
#            - rdap.org / rdap.iana.org for WHOIS-via-RDAP (domain age,
#              registrar). RDAP is the modern JSON replacement for WHOIS
#              and is rate-limited but unauthenticated.
#            - Resolve-DnsName (PowerShell built-in) for MX/NS/A lookups
#              to test if a sender domain is even resolvable.
#
#          Privacy note: every domain queried here is SUBMITTED to the
#          public RDAP service. For incident-response use this is
#          generally acceptable (the operator is the user, looking up
#          sender domains of suspicious mail). Operator should be aware
#          their queries are visible to the RDAP provider.
#
# Inputs:  Get-NRGDomainAge -Domain <fqdn>            -> ordered hashtable
#          Test-NRGDomainResolves -Domain <fqdn>      -> ordered hashtable
#
# Caching: each call caches the result in module-scope $script:NRGTIDomainCache
#          to keep TI lookups bounded when scanning hundreds of inbox
#          messages all citing the same sender domain. Cache TTL is the
#          duration of the process — no on-disk persistence.

if (-not (Get-Variable -Name NRGTIDomainCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:NRGTIDomainCache = [System.Collections.Generic.Dictionary[string,object]]::new()
}

function Get-NRGDomainAge {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')]
        [string] $Domain,

        [int] $TimeoutSeconds = 6
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $cacheKey = "age:$Domain".ToLowerInvariant()
    if ($script:NRGTIDomainCache.ContainsKey($cacheKey)) {
        return $script:NRGTIDomainCache[$cacheKey]
    }

    $result = [ordered]@{
        Domain        = $Domain
        Registered    = $null
        AgeDays       = $null
        Registrar     = $null
        Status        = 'unknown'
        Source        = 'rdap.org'
        Error         = $null
    }
    try {
        $url = "https://rdap.org/domain/$Domain"
        # TLS 1.2 minimum on the runtime — assessment orchestrator pins
        # this; we re-pin here in case IR is invoked standalone.
        try {
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        } catch {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        $resp = Invoke-RestMethod -Uri $url -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop

        # RDAP "events" array carries lifecycle: registration / expiration / etc.
        if ($resp.events) {
            $regEvent = $resp.events | Where-Object { $_.eventAction -eq 'registration' } | Select-Object -First 1
            if ($regEvent -and $regEvent.eventDate) {
                $result.Registered = $regEvent.eventDate
                try {
                    $regDate = [datetime]::Parse($regEvent.eventDate, [Globalization.CultureInfo]::InvariantCulture)
                    $result.AgeDays = [int]((Get-Date).ToUniversalTime() - $regDate.ToUniversalTime()).TotalDays
                } catch { }
            }
        }
        # Registrar comes from the "entities" array, role = 'registrar'.
        if ($resp.entities) {
            $reg = $resp.entities | Where-Object { $_.roles -contains 'registrar' } | Select-Object -First 1
            if ($reg) {
                $name = $null
                if ($reg.vcardArray -and $reg.vcardArray.Count -ge 2) {
                    foreach ($v in $reg.vcardArray[1]) {
                        if ($v -is [array] -and $v.Count -ge 4 -and $v[0] -eq 'fn') {
                            $name = $v[3]; break
                        }
                    }
                }
                $result.Registrar = $name
            }
        }
        $result.Status = 'ok'
    } catch {
        $result.Status = 'error'
        $result.Error  = $_.Exception.Message.Split([char]10)[0]
    }

    $script:NRGTIDomainCache[$cacheKey] = $result
    return $result
}

function Test-NRGDomainResolves {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')]
        [string] $Domain
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $cacheKey = "dns:$Domain".ToLowerInvariant()
    if ($script:NRGTIDomainCache.ContainsKey($cacheKey)) {
        return $script:NRGTIDomainCache[$cacheKey]
    }

    $result = [ordered]@{
        Domain   = $Domain
        HasA     = $false
        HasMX    = $false
        HasNS    = $false
        MXRecords = @()
        NSRecords = @()
        Error    = $null
    }
    try {
        try {
            $a = Resolve-DnsName -Name $Domain -Type A -DnsOnly -ErrorAction Stop
            $result.HasA = ($a | Where-Object Type -eq 'A').Count -gt 0
        } catch { }
        try {
            $mx = Resolve-DnsName -Name $Domain -Type MX -DnsOnly -ErrorAction Stop
            $mxRecs = @($mx | Where-Object Type -eq 'MX' | Select-Object -ExpandProperty NameExchange)
            $result.HasMX = $mxRecs.Count -gt 0
            $result.MXRecords = $mxRecs
        } catch { }
        try {
            $ns = Resolve-DnsName -Name $Domain -Type NS -DnsOnly -ErrorAction Stop
            $nsRecs = @($ns | Where-Object Type -eq 'NS' | Select-Object -ExpandProperty NameHost)
            $result.HasNS = $nsRecs.Count -gt 0
            $result.NSRecords = $nsRecs
        } catch { }
    } catch {
        $result.Error = $_.Exception.Message.Split([char]10)[0]
    }

    $script:NRGTIDomainCache[$cacheKey] = $result
    return $result
}

function Clear-NRGThreatIntelCache {
    [CmdletBinding()] param()
    $script:NRGTIDomainCache.Clear()
}

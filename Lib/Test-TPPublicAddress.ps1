#Requires -Version 7.0
#
# Test-TPPublicAddress.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The positive rule for an address the tool may open a connection to,
#   a bounded HTTP text read, and a linear parser for DNS TXT data. All three
#   exist because the DNS collector acts on answers an attacker can publish:
#   an MX host, an AAAA record, an MTA-STS policy body. The rule is "globally
#   routable unicast only", never a list of what to refuse, because an
#   IPv4-mapped, NAT64 or 6to4 address carries a private IPv4 address inside
#   an IPv6 one and a deny-list that looked only at the family let it through.
# Data keys: none. Graph / cmdlets: none (one HttpClient).

function Test-TPGloballyRoutableAddress {
    <#
    .SYNOPSIS
        Returns @{ Allowed; Reason; Address } for an IP address. Address is the
        unwrapped form the caller must connect to (an IPv4-mapped or translated
        IPv6 address becomes its IPv4). Allowed only for a globally routable
        unicast address; every special-purpose range in the IANA registries is
        refused by name.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [System.Net.IPAddress] $Address)
    $a = $Address
    $ip = $a.ToString()
    if ($a.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        $b = $a.GetAddressBytes()
        if ($a.IsIPv4MappedToIPv6) { $a = $a.MapToIPv4() }
        elseif ($b[0] -eq 0 -and $b[1] -eq 0x64 -and $b[2] -eq 0xff -and $b[3] -eq 0x9b -and (($b[4..11] | Measure-Object -Sum).Sum -eq 0)) {
            $a = [System.Net.IPAddress]::new($b[12..15])   # NAT64 64:ff9b::/96 carries an IPv4 address
        }
        elseif ($b[0] -eq 0x20 -and $b[1] -eq 0x02) { $a = [System.Net.IPAddress]::new($b[2..5]) }   # 6to4 2002::/16 carries an IPv4 address
        elseif ($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -eq 0 -and $b[3] -eq 0) { return @{ Allowed = $false; Reason = "address $ip is Teredo (2001::/32)"; Address = $Address } }
    }
    if ($a.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        $b = $a.GetAddressBytes()
        if ([System.Net.IPAddress]::IsLoopback($a))         { return @{ Allowed = $false; Reason = "address $ip is IPv6 loopback"; Address = $a } }
        if ($a.Equals([System.Net.IPAddress]::IPv6Any))     { return @{ Allowed = $false; Reason = "address $ip is unspecified (::)"; Address = $a } }
        if ($a.IsIPv6LinkLocal)                             { return @{ Allowed = $false; Reason = "address $ip is IPv6 link-local (fe80::/10)"; Address = $a } }
        if ($a.IsIPv6SiteLocal)                             { return @{ Allowed = $false; Reason = "address $ip is IPv6 site-local (fec0::/10)"; Address = $a } }
        if ($a.IsIPv6Multicast -or $b[0] -eq 0xff)          { return @{ Allowed = $false; Reason = "address $ip is IPv6 multicast (ff00::/8)"; Address = $a } }
        if (($b[0] -band 0xFE) -eq 0xFC)                    { return @{ Allowed = $false; Reason = "address $ip is IPv6 unique local (fc00::/7)"; Address = $a } }
        if ($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -eq 0x0d -and $b[3] -eq 0xb8) { return @{ Allowed = $false; Reason = "address $ip is documentation (2001:db8::/32)"; Address = $a } }
        if (($b[0] -band 0xE0) -ne 0x20)                    { return @{ Allowed = $false; Reason = "address $ip is outside global unicast (2000::/3)"; Address = $a } }
        return @{ Allowed = $true; Reason = ''; Address = $a }
    }
    $b = $a.GetAddressBytes(); $b0 = $b[0]; $b1 = $b[1]; $b2 = $b[2]
    $why = $null
    if ($b0 -eq 0)                                              { $why = 'this network (0/8)' }
    elseif ($b0 -eq 10)                                         { $why = 'RFC 1918 10/8' }
    elseif ($b0 -eq 100 -and $b1 -ge 64 -and $b1 -le 127)       { $why = 'carrier-grade NAT 100.64/10' }
    elseif ($b0 -eq 127)                                        { $why = 'loopback 127/8' }
    elseif ($b0 -eq 169 -and $b1 -eq 254)                       { $why = 'link-local 169.254/16' }
    elseif ($b0 -eq 172 -and $b1 -ge 16 -and $b1 -le 31)        { $why = 'RFC 1918 172.16/12' }
    elseif ($b0 -eq 192 -and $b1 -eq 0 -and $b2 -eq 0)          { $why = 'IETF protocol assignments 192.0.0/24' }
    elseif ($b0 -eq 192 -and $b1 -eq 0 -and $b2 -eq 2)          { $why = 'documentation 192.0.2/24' }
    elseif ($b0 -eq 192 -and $b1 -eq 168)                       { $why = 'RFC 1918 192.168/16' }
    elseif ($b0 -eq 198 -and ($b1 -eq 18 -or $b1 -eq 19))       { $why = 'benchmarking 198.18/15' }
    elseif ($b0 -eq 198 -and $b1 -eq 51 -and $b2 -eq 100)       { $why = 'documentation 198.51.100/24' }
    elseif ($b0 -eq 203 -and $b1 -eq 0 -and $b2 -eq 113)        { $why = 'documentation 203.0.113/24' }
    elseif ($b0 -ge 224)                                        { $why = 'multicast or reserved (224/4, 240/4)' }
    if ($why) { return @{ Allowed = $false; Reason = "address $ip is $why"; Address = $a } }
    return @{ Allowed = $true; Reason = ''; Address = $a }
}

function Get-TPBoundedHttpText {
    <#
    .SYNOPSIS
        Reads a text body over HTTPS with the whole transfer under one timeout,
        no redirect followed, and a hard byte cap. Invoke-WebRequest's
        -TimeoutSec covers only the headers, so a server that trickles its
        body could hold a collector open for as long as it liked, and its
        default follows five redirects to any host.
    .OUTPUTS
        The body as a string. Throws with a named reason on a non-2xx status,
        a redirect, a timeout, or a body larger than -MaxBytes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^https://')] [string] $Uri,
        [ValidateRange(1, 300)] [int] $TimeoutSeconds = 10,
        [ValidateRange(1024, 67108864)] [int] $MaxBytes = 65536
    )
    $handler = [System.Net.Http.SocketsHttpHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $cts = [System.Threading.CancellationTokenSource]::new([timespan]::FromSeconds($TimeoutSeconds))
    try {
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('TenantPosture/1.0')
        $resp = $client.GetAsync($Uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token).GetAwaiter().GetResult()
        try {
            $code = [int]$resp.StatusCode
            if ($code -ge 300 -and $code -lt 400) { throw "redirect ($code) not followed" }
            if ($code -lt 200 -or $code -ge 300) { throw "HTTP $code" }
            $stream = $resp.Content.ReadAsStreamAsync($cts.Token).GetAwaiter().GetResult()
            $ms = [System.IO.MemoryStream]::new()
            $buf = [byte[]]::new(8192)
            while ($true) {
                $n = $stream.ReadAsync($buf, 0, $buf.Length, $cts.Token).GetAwaiter().GetResult()
                if ($n -le 0) { break }
                if ($ms.Length + $n -gt $MaxBytes) { throw "body exceeds $MaxBytes bytes" }
                $ms.Write($buf, 0, $n)
            }
            return [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
        } finally { $resp.Dispose() }
    } catch [System.OperationCanceledException] {
        throw "timed out after $TimeoutSeconds s"
    } finally {
        $cts.Dispose(); $client.Dispose(); $handler.Dispose()
    }
}

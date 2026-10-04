#Requires -Version 7.0
#
# Test-NRGWebRequestAllowed.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# The request policy for the local web GUI (Start-NRGWebServer), as one pure
# function so it is tested without a server. The server binds 127.0.0.1 only,
# which keeps the network out but not the operator's own browser: any web page
# they have open can talk to a loopback port. Two attacks follow, and this is the
# whole defense against both.
#
#   DNS rebinding. A page on evil.example makes its name resolve to 127.0.0.1;
#   the browser then treats the GUI as same-origin with evil.example and lets the
#   page READ it (reports, run list, the report site). The request still names
#   its own host, so the server refuses every request whose Host header is not
#   one it is meant to be reached as. This is the check that closes it.
#
#   Cross-site request forgery. A page can make the browser POST a form to the
#   scan route on 127.0.0.1:<port> with a perfectly good Host. It cannot send
#   a JSON body, set a custom content type, or pass a CORS preflight (the server
#   sends no CORS headers). So anything but GET/HEAD must carry
#   application/json, must come from this server's own origin when the browser
#   says where it came from, and must not be marked cross-site by Fetch Metadata.
#
# The verdict carries a Reason for tests and logs; the Message is fixed text and
# never echoes the request. Both rejections are 403.
#
# Consumed:  nothing. Reads no file, makes no call.
# Graph scopes / cmdlets used: none.

function Test-NRGWebRequestAllowed {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The HTTP method, as received.
        [Parameter(Mandatory)] [string] $Method,

        # The Host header, exactly as received. Missing is not allowed.
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $HostHeader,

        # Origin / Content-Type / Sec-Fetch-Site headers, when sent.
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Origin,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ContentType,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $SecFetchSite,

        # The port the server listens on, and the scheme it serves (the server,
        # which chooses its protocol, says which; the policy hard-codes neither).
        [Parameter(Mandatory)] [ValidateRange(1, 65535)] [int] $Port,
        [Parameter()] [ValidateSet('http', 'https')] [string] $Scheme = 'http',

        # Further names the GUI may be reached as, for a port forward or tunnel
        # (host or host:port; a bare host is taken to use $Port). Empty by default.
        [Parameter()] [AllowNull()] [string[]] $AllowedHost = @()
    )

    Set-StrictMode -Version Latest

    $deny = {
        param($Reason)
        [pscustomobject]@{ Allowed = $false; HttpStatus = 403; Reason = $Reason; Message = 'Forbidden.' }
    }

    # The names this server answers to. Exact match, case-insensitive: no
    # wildcards, no suffix match, no trailing-dot variants.
    $hosts = [System.Collections.Generic.List[string]]::new()
    $hosts.Add("127.0.0.1:$Port")
    $hosts.Add("localhost:$Port")
    foreach ($extra in @($AllowedHost)) {
        if ([string]::IsNullOrWhiteSpace($extra)) { continue }
        $hosts.Add($(if ($extra -match ':\d+\z') { $extra } else { "${extra}:$Port" }))
    }

    if ([string]::IsNullOrEmpty($HostHeader) -or $HostHeader -notin $hosts) { return (& $deny 'HostNotAllowed') }

    # Safe methods read; they cannot change anything, and a page that reads them
    # cross-origin is stopped by the Host check above and by the response headers.
    if ($Method -in @('GET', 'HEAD')) {
        return [pscustomobject]@{ Allowed = $true; HttpStatus = 200; Reason = ''; Message = '' }
    }

    # Anything else changes state. JSON only: a cross-site form cannot send it
    # without a preflight, and no preflight is ever answered.
    $mediaType = if ($ContentType) { ($ContentType -split ';', 2)[0].Trim() } else { '' }
    if ($mediaType -ne 'application/json') { return (& $deny 'ContentTypeNotJson') }

    # A browser says where a request came from. Present, it must be this server.
    # Absent means a client that is not a browser, which is not a CSRF vector.
    # "null" (a sandboxed frame, a file: page) is never this server.
    if ($Origin) {
        $origins = @($hosts | ForEach-Object { "${Scheme}://$_" })
        if ($Origin -notin $origins) { return (& $deny 'OriginNotAllowed') }
    }

    # Fetch Metadata, where the browser sends it: only a request from this
    # origin, or one the user started by hand (none), may change state.
    if ($SecFetchSite -and $SecFetchSite -notin @('same-origin', 'none')) { return (& $deny 'FetchSiteNotSameOrigin') }

    return [pscustomobject]@{ Allowed = $true; HttpStatus = 200; Reason = ''; Message = '' }
}

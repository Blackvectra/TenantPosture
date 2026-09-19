#Requires -Version 7.0
#
# Resolve-NRGDns.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: resolve public DNS records reliably from any host, for the DNS
#   email-auth controls (SPF/DKIM/DMARC/MTA-STS/TLS-RPT/CAA/DNSSEC).
#
# Why not Resolve-DnsName: three real defects observed on a client run —
#   1) it queries the MACHINE'S LOCAL resolver, which on a corporate / split-DNS
#      network returns NXDOMAIN for external _dmarc / _domainkey records that
#      resolve fine on public DNS (false "no DMARC / no DKIM");
#   2) TXT answers can arrive as objects without a .Strings property, throwing
#      "The property 'Strings' cannot be found" and losing a record that WAS
#      returned (false "no SPF");
#   3) older Windows DnsClient modules don't know the CAA record type and throw
#      "Cannot convert value 'CAA' to type RecordType".
#   It is also Windows-only, so DNS silently produced nothing off-Windows.
#
# This helper uses DNS-over-HTTPS against PUBLIC resolvers (Cloudflare, then
# Google) so the answer is independent of the client's resolver, works on every
# OS, supports every record type, and returns a stable string shape. If both DoH
# providers are unreachable it falls back to Resolve-DnsName pinned to a public
# server (1.1.1.1) where that cmdlet exists.
#
# Dependencies: (none — self-contained; optional Resolve-DnsName fallback)
#
# Outbound: https://cloudflare-dns.com , https://dns.google (DoH JSON API).

function Resolve-NRGDns {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)]
        [ValidateSet('A','AAAA','TXT','CNAME','MX','CAA','DS','NS','SOA')]
        [string] $Type,
        [int] $TimeoutSeconds = 6,

        # Receives 'Answered' / 'NoRecord' / 'LookupFailed'.
        #
        # An empty return is ambiguous exactly the way an empty collector
        # section is: it can mean "the name genuinely has no record of this
        # type" or "every resolver we asked failed". For DNS that difference
        # decides a client-facing verdict — an absent SPF/DMARC record is a
        # Gap, so a failed lookup reported as absent tells a client their
        # email authentication is missing when it is not.
        #
        # Optional, so every existing caller keeps its current behaviour.
        [ref] $Outcome,

        # Receives a short diagnostic when the outcome is LookupFailed: each
        # provider tried and why it could not answer. Without it the evaluator's
        # "every resolver failed" was undiagnosable from the results JSON — the
        # Exceptions array and the per-domain Errors list were both empty,
        # because the failures were swallowed here and this function never
        # throws. Optional, like -Outcome.
        [ref] $Reason
    )

    Set-StrictMode -Version Latest

    $failures   = [System.Collections.Generic.List[string]]::new()
    $setOutcome = { param([string] $State) if ($null -ne $Outcome) { $Outcome.Value = $State } }
    $setReason  = { if ($null -ne $Reason) { $Reason.Value = ($failures -join '; ') } }
    & $setOutcome 'LookupFailed'
    & $setReason

    # DoH Status codes we treat as an AUTHORITATIVE "no such record":
    #   0 NoError  — name resolves; an absent Answer means NODATA for this type
    #   3 NXDOMAIN — name does not exist
    # Anything else (2 SERVFAIL, 5 REFUSED, …) means the resolver could not
    # answer, which is not evidence of absence — fall through to the next
    # provider rather than reporting "no record".
    $authoritativeNoRecord = @(0, 3)

    # DoH numeric type codes (RFC 1035 / 6844).
    $typeCode = @{ A = 1; NS = 2; SOA = 6; CNAME = 5; MX = 15; TXT = 16; AAAA = 28; DS = 43; CAA = 257 }[$Type]

    # ── DoH against public resolvers (inline; no inner scriptblock so variable
    #    scoping is unambiguous). Cloudflare first, then Google. ───────────────
    foreach ($baseUrl in @('https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve')) {
        $provider = ([uri]$baseUrl).Host
        try {
            $uri  = "${baseUrl}?name=$([uri]::EscapeDataString($Name))&type=$Type"
            $resp = Invoke-RestMethod -Uri $uri -Headers @{ accept = 'application/dns-json' } `
                        -TimeoutSec $TimeoutSeconds -ErrorAction Stop
            if ($null -eq $resp) { $failures.Add("${provider}: empty response"); continue }

            # A DoH answer is a JSON object carrying a Status. Anything else
            # arrives as HTTP 200 too — an HTML block page from a TLS-inspecting
            # egress proxy, a captive portal, a JSON error object — and the
            # first version of this check let a body with NO Status fall
            # straight through to the "no Answer" branch, where it became a
            # confident NoRecord that never asked the next provider. On a
            # network that intercepts cloudflare-dns.com, every domain's SPF,
            # DMARC, MTA-STS, TLS-RPT, DS and CAA would have scored Gap. A
            # response we cannot read is a failure, not an answer.
            #
            # Status is accepted ONLY as a whole number: an [int]-family value
            # or a digit string. `-as [int]` alone is far too generous —
            # `$null`, `''` and `$false` all cast to 0, and 2.6 rounds to 3 —
            # each of which would have turned an unreadable body into an
            # authoritative NoRecord. An XmlDocument (an HTML block page that
            # happened to parse) exposes its root element as a property, so
            # it is rejected with the plain-string case.
            $statusProp = if ($resp -is [string] -or $resp -is [System.Xml.XmlNode]) { $null } else { $resp.PSObject.Properties['Status'] }
            $status     = $null
            if ($statusProp) {
                $raw = $statusProp.Value
                if ($raw -is [string]) {
                    if ($raw -match '^\s*\d+\s*$') { $status = [int]$raw }
                } elseif ($null -ne $raw -and $raw -isnot [bool] -and $raw -is [ValueType]) {
                    $i = $raw -as [int]
                    if ($null -ne $i -and ([double]$raw) -eq $i) { $status = $i }
                }
            }
            if ($null -eq $status) { $failures.Add("${provider}: response carried no readable Status (not a DoH answer)"); continue }
            if ($status -notin $authoritativeNoRecord) { $failures.Add("${provider}: Status $status"); continue }

            # Status 0 with no Answer (absent, null or empty) is NODATA; Status
            # 3 is NXDOMAIN. Both are real answers meaning "no record of this
            # type". Rows are read through PSObject.Properties, never
            # dot-access: a row lacking `type` or `data` is skipped, not
            # allowed to throw and fail the whole provider — under StrictMode
            # a direct `$_.type` on such a row did exactly that, discarding a
            # valid SPF row in the same Answer.
            $answerProp = $resp.PSObject.Properties['Answer']
            $rows = if ($answerProp -and $null -ne $answerProp.Value) { @($answerProp.Value) } else { @() }
            $out = @($rows | ForEach-Object {
                if ($null -eq $_ -or $_ -is [string]) { return }
                $tp = $_.PSObject.Properties['type']
                $dp = $_.PSObject.Properties['data']
                if (-not $tp -or -not $dp -or $null -eq $tp.Value -or $null -eq $dp.Value) { return }
                if (($tp.Value -as [int]) -ne $typeCode) { return }
                $data = [string]$dp.Value
                if ($Type -eq 'TXT') {
                    # TXT data arrives either as one or more quoted
                    # character-strings — "v=spf1 ..." or "part1" "part2"
                    # (Cloudflare) — or already unquoted and pre-joined
                    # (Google). Only a value that STARTS with a quote is
                    # segment-parsed; a bare value is taken whole, so an
                    # embedded quoted token in Google's form is not mistaken
                    # for the only segment. Inside a quoted segment, \" and \\
                    # are RFC 1035 escapes and are unescaped.
                    if ($data -match '^\s*"') {
                        $segs = [regex]::Matches($data, '"((?:[^"\\]|\\.)*)"')
                        -join ($segs | ForEach-Object { $_.Groups[1].Value -replace '\\(["\\])', '$1' })
                    } else {
                        $data
                    }
                } else {
                    $data
                }
            })
            # An Answer that contained no record of the requested type (e.g. a
            # CNAME-only chain) is still a real answer: no record of this type.
            & $setOutcome $(if (@($out).Count -gt 0) { 'Answered' } else { 'NoRecord' }); & $setReason
            return @($out)
        } catch {
            $failures.Add("${provider}: $($_.Exception.Message)")
            continue   # try the next provider
        }
    }

    # ── Fallback: Resolve-DnsName pinned to a PUBLIC resolver (never the local
    #    one). Only where the cmdlet exists; CAA is skipped if the module's enum
    #    doesn't know it. ─────────────────────────────────────────────────────
    if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        try {
            $recs = @(Resolve-DnsName -Name $Name -Type $Type -Server '1.1.1.1' -DnsOnly -ErrorAction Stop)

            # Resolve-DnsName returns every record on the wire, not only the
            # Answer section. A NODATA response carries the zone's SOA in the
            # Authority section (RFC 2308 §3), and a CNAME chain carries rows of
            # other types. Without this filter the `[string]$_` branch below
            # turned that SOA row into a truthy value and reported Answered —
            # a false pass on DNS-1.6 (DS present) and DNS-1.2 (DKIM CNAME) on
            # exactly the DoH-blocked workstation this fallback exists for.
            # Only rows in the Answer section of the requested type count; the
            # DoH path applies the same type filter. Rows that carry neither
            # property (older DnsClient shapes) are kept as before.
            $recs = @($recs | Where-Object {
                $sec = $_.PSObject.Properties['Section']
                $typ = $_.PSObject.Properties['Type']
                (-not $sec -or $null -eq $sec.Value -or [string]$sec.Value -eq 'Answer') -and
                (-not $typ -or $null -eq $typ.Value -or [string]$typ.Value -eq $Type)
            })
            # Render each row in the SAME text shape the DoH path returns, so
            # the collector's parsers see one format whichever path answered.
            # The previous `else { [string]$_ }` produced PSObject text
            # ("@{Section=Answer; Type=CAA; ...}") for CAA and DS rows: a
            # present CAA record could never match the collector's
            # `FLAGS TAG "VALUE"` parse, so CAA.Present stayed $false and
            # DNS-2.2 reported "No CAA record published" — a false Gap on
            # exactly the DoH-blocked workstation this fallback exists for.
            # A row whose type this fallback cannot render is a FAILURE for
            # the lookup, never an "Answered" with unusable data.
            $unrenderable = [System.Collections.Generic.List[string]]::new()   # a List so the pipeline block can mark it
            $fallback = @($recs | ForEach-Object {
                $p = $_.PSObject.Properties
                switch ($Type) {
                    'TXT'   { if ($p['Strings']) { -join @($p['Strings'].Value) } }
                    'CNAME' { if ($p['NameHost']) { [string]$p['NameHost'].Value } }
                    'NS'    { if ($p['NameHost']) { [string]$p['NameHost'].Value } }
                    'MX'    {
                        # DoH shape: 'PREF exchange.'
                        if ($p['NameExchange']) {
                            $pref = if ($p['Preference']) { [string]$p['Preference'].Value } else { '0' }
                            "$pref $([string]$p['NameExchange'].Value)"
                        }
                    }
                    'A'     { if ($p['IPAddress']) { [string]$p['IPAddress'].Value } }
                    'AAAA'  { if ($p['IPAddress']) { [string]$p['IPAddress'].Value } }
                    'CAA'   {
                        # DoH shape: 'FLAGS TAG "VALUE"'. Only a DnsClient
                        # build that exposes the CAA fields can render it.
                        if ($p['Flags'] -and $p['Tag'] -and $p['Value']) {
                            "$([string]$p['Flags'].Value) $([string]$p['Tag'].Value) `"$([string]$p['Value'].Value)`""
                        } else { $unrenderable.Add('CAA') }
                    }
                    'DS'    {
                        # DoH shape: 'KEYTAG ALG DIGESTTYPE DIGEST'. The
                        # collector only tests presence, but render the
                        # rdata when the fields are there.
                        if ($p['KeyTag'] -and $p['Algorithm'] -and $p['DigestType'] -and $p['Digest']) {
                            "$([string]$p['KeyTag'].Value) $([string]$p['Algorithm'].Value) $([string]$p['DigestType'].Value) $([string]$p['Digest'].Value)"
                        } elseif ($p['KeyTag']) { "$([string]$p['KeyTag'].Value)" }
                        else { $unrenderable.Add('DS') }
                    }
                    'SOA'   { if ($p['PrimaryServer']) { [string]$p['PrimaryServer'].Value } else { $unrenderable.Add('SOA') } }
                }
            } | Where-Object { $_ })
            if ($unrenderable.Count -gt 0 -and $fallback.Count -eq 0) {
                $failures.Add("Resolve-DnsName: returned $Type rows this fallback cannot render in the DoH text shape")
            } else {
                & $setOutcome $(if ($fallback.Count -gt 0) { 'Answered' } else { 'NoRecord' }); & $setReason
                return @($fallback)
            }
        } catch {
            # Resolve-DnsName reports NXDOMAIN and NODATA in one of two
            # shapes: by THROWING, the same way it reports a real failure, or
            # (NODATA) by returning only the Authority-section SOA, which the
            # Section filter above reduces to an empty answer. The throw has
            # to be read rather than treated uniformly. The Win32 DNS codes
            # distinguish absence from failure: 9003 DNS_ERROR_RCODE_NAME_ERROR
            # (NXDOMAIN), 9501 DNS_INFO_NO_RECORDS (NODATA) and 9701
            # DNS_ERROR_RECORD_DOES_NOT_EXIST ("DNS record does not exist",
            # which the cmdlet emits as RECORD_DOES_NOT_EXIST) are
            # authoritative "no record"; 9002 SERVFAIL, 1460 timeout and
            # anything else are not.
            #
            # The first version of this change mapped every throw to
            # LookupFailed. On a workstation where DoH is blocked — which the
            # header of this file says is common — that meant no DNS control
            # could ever report a Gap: every genuine absence became
            # NotApplicable, excluded from the denominator, and a tenant's
            # missing DMARC was never surfaced. Silently non-functional, which
            # is worse than the false Gap it replaced.
            $code = $null
            $ex   = $_.Exception
            while ($null -ne $ex -and $null -eq $code) {
                $ncp = $ex.PSObject.Properties['NativeErrorCode']
                if ($ncp -and $null -ne $ncp.Value) { $code = $ncp.Value -as [int] }
                $ex = $ex.InnerException
            }
            if ($null -eq $code) {
                $text = "$($_.FullyQualifiedErrorId) $($_.Exception.Message)"
                if     ($text -match 'DNS_ERROR_RCODE_NAME_ERROR') { $code = 9003 }
                elseif ($text -match 'DNS_INFO_NO_RECORDS')        { $code = 9501 }
                elseif ($text -match 'RECORD_DOES_NOT_EXIST')      { $code = 9701 }
            }
            if ($code -in @(9003, 9501, 9701)) {
                & $setOutcome 'NoRecord'; & $setReason
                return @()
            }
            $codeNote = if ($null -ne $code) { " (Win32 $code)" } else { '' }
            $failures.Add("Resolve-DnsName: $($_.Exception.Message)$codeNote")
        }
    } else {
        $failures.Add('Resolve-DnsName: cmdlet not available on this platform')
    }

    # Every provider failed.
    & $setOutcome 'LookupFailed'; & $setReason
    return @()
}

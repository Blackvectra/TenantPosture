#Requires -Version 7.0
#
# Invoke-NRGCollectDNSEmailRecords.ps1  (v4.5.6)
# Collects DNS email authentication and PKI hygiene data for each accepted domain:
#   - SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC, MX  (Phase 1)
#   - DKIM key rotation age via EXO Get-DkimSigningConfig.KeyCreationTime
#   - CAA records (RFC 8659) — controls which CAs may issue certs for the domain
#   - TLS certificate expiry on autodiscover + MX hostnames (port 443 HTTPS)
#   - crt.sh certificate transparency log lookup (RFC 6962)
#
# READ-ONLY. External DNS / HTTPS queries only — no tenant writes.
#
# IMPORTANT: Domain names are validated before any DNS call (OWASP A03 / ASVS V5.1.3).
# DNS responses are treated as hostile data and sanitized before storing.
#
# NIST SP 800-53: SI-8 (spam), SC-8 (transmission), SC-12 (key management),
#                 SC-17 (PKI certificates)
# MITRE ATT&CK:   T1566 (Phishing), T1036.005 (Domain Spoofing),
#                 T1583.001 (Acquire Infrastructure — Domains)
#

# Validated FQDN pattern — reused for all domain validation in this file
$script:DomainPattern = '^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

# SSRF guard for hostnames returned by DNS (MX records, etc.).
# Returns a hashtable describing the probe target:
#   @{ Refused = $true; Reason = '<why>' }                 -- unsafe, do not connect
#   @{ Refused = $false; Address = [IPAddress]; HostName = '<original>' } -- safe to probe by IP
#
# A malicious DNS response could direct a TCP/TLS probe at internal RFC1918 names,
# `localhost`, cloud-metadata-adjacent names, or link-local addresses. We re-validate
# the FQDN shape, block explicit internal-only suffixes, then resolve to IPs and
# refuse to connect to RFC1918 / loopback / link-local / IPv6 ULA / IPv6 link-local.
#
# DNS rebinding fix (v4.6.3 P2): the function previously only returned a refusal
# string. Callers then called e.g. `TcpClient.Connect($hostname, 443)` which did a
# SECOND DNS lookup. A short-TTL DNS rebinder could return a public IP at validate-time
# and an RFC1918 IP at connect-time. We now resolve ONCE and return the IP for the
# caller to connect by literal address (with SNI = original hostname).
function Test-NRGSafeProbeTarget {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $HostName)

    if ([string]::IsNullOrWhiteSpace($HostName)) {
        return @{ Refused = $true; Reason = 'empty hostname' }
    }

    # 1. Must match the same FQDN pattern we use for tenant domains.
    #    This excludes IPv4 literals (TLD is letters only) and any bare hostname.
    if ($HostName -notmatch $script:DomainPattern) {
        return @{ Refused = $true; Reason = "hostname '$HostName' failed FQDN validation" }
    }

    # 2. Explicit deny-list of internal-only hostnames and suffixes.
    $lower = $HostName.ToLowerInvariant()
    if ($lower -eq 'localhost' -or $lower -eq 'localhost.localdomain') {
        return @{ Refused = $true; Reason = "hostname '$HostName' is a loopback alias" }
    }
    if ($lower -like '*.local' -or $lower -like '*.internal') {
        return @{ Refused = $true; Reason = "hostname '$HostName' uses an internal-only suffix" }
    }
    if ($lower -eq 'metadata.google.internal') {
        return @{ Refused = $true; Reason = "hostname '$HostName' is a cloud metadata endpoint" }
    }
    # Belt-and-suspenders — the FQDN regex above should already exclude IPv4 literals,
    # but if somehow a 169.254.x.x dotted-quad slipped through we want to catch it.
    if ($HostName -match '^169\.254\.') {
        return @{ Refused = $true; Reason = "hostname '$HostName' is link-local" }
    }

    # 3. Resolve and inspect every returned address. Resolution happens ONCE
    #    and the returned address is the one the caller must connect to —
    #    closing the DNS-rebinding window between validate and connect.
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($HostName)
    } catch {
        return @{ Refused = $true; Reason = "DNS resolution failed: $($_.Exception.Message)" }
    }
    if (-not $addresses -or $addresses.Count -eq 0) {
        return @{ Refused = $true; Reason = "no addresses returned for '$HostName'" }
    }

    foreach ($addr in $addresses) {
        $ipStr = $addr.ToString()
        if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            # IPv4: block RFC1918, loopback, link-local
            $bytes = $addr.GetAddressBytes()
            $b0 = $bytes[0]; $b1 = $bytes[1]
            if ($b0 -eq 10)                                  { return @{ Refused = $true; Reason = "address $ipStr is RFC1918 10/8" } }
            if ($b0 -eq 172 -and $b1 -ge 16 -and $b1 -le 31) { return @{ Refused = $true; Reason = "address $ipStr is RFC1918 172.16/12" } }
            if ($b0 -eq 192 -and $b1 -eq 168)                { return @{ Refused = $true; Reason = "address $ipStr is RFC1918 192.168/16" } }
            if ($b0 -eq 127)                                 { return @{ Refused = $true; Reason = "address $ipStr is loopback 127/8" } }
            if ($b0 -eq 169 -and $b1 -eq 254)                { return @{ Refused = $true; Reason = "address $ipStr is link-local 169.254/16" } }
        } elseif ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            # IPv6: block loopback (::1), link-local (fe80::/10), ULA (fc00::/7)
            if ([System.Net.IPAddress]::IsLoopback($addr)) { return @{ Refused = $true; Reason = "address $ipStr is IPv6 loopback" } }
            if ($addr.IsIPv6LinkLocal)                     { return @{ Refused = $true; Reason = "address $ipStr is IPv6 link-local (fe80::/10)" } }
            $b0 = $addr.GetAddressBytes()[0]
            # fc00::/7 — high 7 bits are 1111110 (0xFC or 0xFD)
            if (($b0 -band 0xFE) -eq 0xFC)                 { return @{ Refused = $true; Reason = "address $ipStr is IPv6 ULA (fc00::/7)" } }
        }
    }

    # Pick the first IPv4 (preferred) or fall back to first IPv6. Callers must
    # connect to this IP literal — second resolution would re-open the rebinding race.
    $picked = $addresses | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
    if (-not $picked) { $picked = $addresses | Select-Object -First 1 }
    return @{ Refused = $false; Address = $picked; HostName = $HostName }
}

function Invoke-NRGCollectDNSEmailRecords {
    [CmdletBinding()]
    param(
        # Explicit domain list — if not provided, reads from EXO accepted domains
        [ValidateScript({
            foreach ($d in $_) {
                if ($d -notmatch '^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$') {
                    throw "Invalid domain name: '$d'"
                }
            }
            return $true
        })]
        [string[]] $Domains,

        # Per-domain time budget (seconds) for DNS + TLS + crt.sh probes.
        # Prevents one slow tenant from stretching collection into the minute range.
        [ValidateRange(10, 600)]
        [int] $TimeoutSec = 60
    )

    $result = @{
        Success     = $false
        Data        = @{ Domains = @{}; DomainCount = 0 }
    }

    try {
        # Determine domain list
        if (-not $Domains -or $Domains.Count -eq 0) {
            $exoData = if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) {
                Get-NRGRawData -Key 'EXO-MailboxConfig'
            } else { $null }

            if ($exoData -and $exoData.Success -and $exoData.Data.AcceptedDomains) {
                $Domains = @($exoData.Data.AcceptedDomains |
                    Where-Object { $_.DomainName -notmatch '\.onmicrosoft\.com$' } |
                    ForEach-Object { $_.DomainName } |
                    Where-Object { $_ -match $script:DomainPattern })
            }
        }

        # Graph fallback: SPF/DMARC/DNSSEC/MTA-STS are public DNS lookups that do
        # NOT require EXO. When EXO failed to connect (assembly conflict) the
        # AcceptedDomains fallback above yields nothing — so derive the domain
        # list from Graph verifiedDomains instead, so DNS still collects. Only
        # the DKIM check genuinely needs EXO. (ndaco.org 2026-07-07: EXO was down
        # and no -Domains was passed, so DNS silently collected nothing.)
        if ((-not $Domains -or $Domains.Count -eq 0) -and
            (Get-Command Invoke-NRGGraphRequest -ErrorAction SilentlyContinue)) {
            try {
                $org = Invoke-NRGGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization'
                $verified = @($org.value ?? @()) |
                    ForEach-Object { @($_.verifiedDomains ?? @()) } |
                    Where-Object { $_ }
                $Domains = @($verified |
                    ForEach-Object { [string]($_.name ?? '') } |
                    Where-Object { $_ -notmatch '\.onmicrosoft\.com$' -and $_ -match $script:DomainPattern } |
                    Select-Object -Unique)
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'DNS-DomainDiscovery' `
                        -Message "Graph verifiedDomains fallback failed: $($_.Exception.Message)"
                }
            }
        }

        if (-not $Domains -or $Domains.Count -eq 0) {
            if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
                Register-NRGCoverage -Family 'DNS-EmailRecords' -Status 'NotCollected' -Note 'No domains to check'
            }
            $result.Success = $true
            if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
                Set-NRGRawData -Key 'DNS-EmailRecords' -Data $result
            }
            return $result
        }

        $domainResults = @{}

        foreach ($domain in $Domains) {
            # Final validation — belt-and-suspenders even though we validated above
            if ($domain -notmatch $script:DomainPattern) {
                Write-Warning "Skipping invalid domain: $domain"
                continue
            }

            # Per-domain time budget — a hung TLS probe (5s), 30s crt.sh fetch,
            # plus multiple DNS lookups can compound into the minute range. With
            # many tenants this adds up, so we cap the total at $TimeoutSec and
            # skip the long-tail sub-steps (TLS probe, crt.sh) once exceeded.
            $sw = [System.Diagnostics.Stopwatch]::StartNew()

            $d = @{
                Domain  = $domain
                SPF     = $null
                DKIM    = @{
                    Selector1       = $null
                    Selector2       = $null
                    CustomSelectors = @()
                    KeySize         = $null
                    KeyCreationTime = $null
                    RotateOnDate    = $null
                    KeyAgeDays      = $null
                    RotationStatus  = $null  # 'OK' | 'Due' | 'Overdue' | 'Unknown'
                }
                DMARC   = $null
                MTASTS  = @{ DNSRecord = $null; Policy = $null; Mode = $null }
                TLSRPT  = $null
                DNSSEC  = $false
                MX      = @()
                CAA     = @{
                    Present         = $false
                    Records         = @()
                    IssuanceAllowed = @()  # 'issue' tag values
                    WildcardAllowed = @()  # 'issuewild' tag values
                    IodefContact    = @()  # 'iodef' tag values
                }
                TLSCerts = @{
                    Autodiscover = $null
                    MailHost     = $null
                }
                CTLog   = @{
                    TotalCerts      = 0
                    Last30Days      = 0
                    Issuers         = @()
                    UnexpectedSANs  = @()
                    QueryError      = $null
                }
                Errors  = @()
            }

            # SPF
            try {
                $txtRecords = @(Resolve-DnsName -Name $domain -Type TXT -ErrorAction Stop -ErrorVariable dnsErr)
                $spfRecord  = $txtRecords |
                    Where-Object { ($_.Strings -join '') -like 'v=spf1*' } |
                    Select-Object -First 1
                if ($spfRecord) { $d.SPF = ($spfRecord.Strings -join '') }
            } catch {
                $d.Errors += "SPF: $($_.Exception.Message)"
            }

            # DKIM — standard selectors + check if EXO DKIM data has custom selectors
            $dkimSelectors = @('selector1', 'selector2')

            # Pull any custom DKIM selectors from EXO collector data
            $exoRaw = if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) {
                Get-NRGRawData -Key 'EXO-MailboxConfig'
            } else { $null }

            if ($exoRaw -and $exoRaw.Success) {
                $dkimConfig = @($exoRaw.Data.DkimSigningConfigs ?? @()) |
                    Where-Object { $_.Domain -eq $domain } | Select-Object -First 1
                if ($dkimConfig) {
                    if ($dkimConfig.Selector1) { $dkimSelectors += $dkimConfig.Selector1 }
                    if ($dkimConfig.Selector2) { $dkimSelectors += $dkimConfig.Selector2 }
                    $dkimSelectors = @($dkimSelectors | Select-Object -Unique)

                    # DKIM rotation age — NIST 800-53 SC-12 expects cryptographic
                    # material to be rotated on a documented cadence. Microsoft
                    # rotates DKIM only when the customer opts in; many tenants
                    # have keys older than two years which weakens DKIM's value.
                    $d.DKIM.KeySize         = $dkimConfig.KeySize
                    $d.DKIM.KeyCreationTime = [string]$dkimConfig.KeyCreationTime
                    $d.DKIM.RotateOnDate    = [string]$dkimConfig.RotateOnDate
                    if ($dkimConfig.KeyCreationTime) {
                        try {
                            # InvariantCulture: Exchange returns timestamps in a fixed
                            # format; relying on current culture's parser allows weird
                            # parses on non-en-US hosts (e.g. dd/MM/yyyy). v4.6.3 P2 fix.
                            $kct = [datetime]::Parse([string]$dkimConfig.KeyCreationTime, [cultureinfo]::InvariantCulture)
                            $age = [int]([datetime]::UtcNow - $kct.ToUniversalTime()).TotalDays
                            $d.DKIM.KeyAgeDays = $age
                            # Industry guidance: rotate at most every 365 days,
                            # alert at 270 ("Due"), fail at 365+ ("Overdue").
                            $d.DKIM.RotationStatus = if ($age -lt 270) { 'OK' }
                                                     elseif ($age -lt 365) { 'Due' }
                                                     else { 'Overdue' }
                        } catch {
                            $d.DKIM.RotationStatus = 'Unknown'
                        }
                    } else {
                        $d.DKIM.RotationStatus = 'Unknown'
                    }
                }
            }

            foreach ($sel in $dkimSelectors) {
                try {
                    $dkimFqdn    = "${sel}._domainkey.${domain}"
                    $dkimRecords = @(Resolve-DnsName -Name $dkimFqdn -Type TXT -ErrorAction Stop)
                    $dkimMatch   = $dkimRecords |
                        Where-Object { ($_.Strings -join '') -like 'v=DKIM1*' } |
                        Select-Object -First 1
                    if ($dkimMatch) {
                        if ($sel -eq 'selector1') { $d.DKIM.Selector1 = ($dkimMatch.Strings -join '') } elseif ($sel -eq 'selector2') { $d.DKIM.Selector2 = ($dkimMatch.Strings -join '') } else { $d.DKIM.CustomSelectors += @{ Selector = $sel; Record = ($dkimMatch.Strings -join '') } }
                    }
                } catch { }  # DKIM not found on this selector — non-fatal
            }

            # DMARC
            try {
                $dmarcFqdn    = "_dmarc.$domain"
                $dmarcRecords = @(Resolve-DnsName -Name $dmarcFqdn -Type TXT -ErrorAction Stop)
                $dmarcMatch   = $dmarcRecords |
                    Where-Object { ($_.Strings -join '') -like 'v=DMARC1*' } |
                    Select-Object -First 1
                if ($dmarcMatch) {
                    $dmarcStr     = ($dmarcMatch.Strings -join '')
                    $d.DMARC      = $dmarcStr

                    # Parse policy value — safe extraction, no eval
                    $policyMatch = [regex]::Match($dmarcStr, '(?:^|;)\s*p=([^;]+)')
                    $subPolicyMatch = [regex]::Match($dmarcStr, '(?:^|;)\s*sp=([^;]+)')
                    $pctMatch    = [regex]::Match($dmarcStr, '(?:^|;)\s*pct=(\d+)')
                    $d.DMARCPolicy       = if ($policyMatch.Success) { $policyMatch.Groups[1].Value.Trim() } else { 'none' }
                    $d.DMARCSubPolicy    = if ($subPolicyMatch.Success) { $subPolicyMatch.Groups[1].Value.Trim() } else { $null }
                    $d.DMARCPct          = if ($pctMatch.Success) { [int]$pctMatch.Groups[1].Value } else { 100 }
                }
            } catch {
                $d.Errors += "DMARC: $($_.Exception.Message)"
            }

            # MTA-STS DNS record
            try {
                $mtaStsFqdn    = "_mta-sts.$domain"
                $mtaStsRecords = @(Resolve-DnsName -Name $mtaStsFqdn -Type TXT -ErrorAction Stop)
                $mtaStsMatch   = $mtaStsRecords |
                    Where-Object { ($_.Strings -join '') -like 'v=STSv1*' } |
                    Select-Object -First 1
                if ($mtaStsMatch) {
                    $d.MTASTS.DNSRecord = ($mtaStsMatch.Strings -join '')
                }
            } catch { }

            # MTA-STS policy file (HTTPS fetch — validate URL before opening)
            if ($d.MTASTS.DNSRecord) {
                # SSRF guard (v4.6.x audit MED #3): the mta-sts.<domain> hostname
                # is constructed from tenant DNS data. Even though $domain is
                # FQDN-validated above, the resolved hostname could point at
                # an RFC1918 / loopback / link-local address (DNS rebinding).
                # Refuse to fetch the policy file in those cases — same pattern
                # used for the MX hostname TLS probe below.
                $mtaStsHost  = "mta-sts.$domain"
                $mtaStsProbe = Test-NRGSafeProbeTarget -HostName $mtaStsHost
                if ($mtaStsProbe.Refused) {
                    $d.Errors += "MTASTS.Policy: refused '$mtaStsHost' — $($mtaStsProbe.Reason)"
                } else {
                    # DNS rebinding fix (v4.6.3 P2): Invoke-WebRequest would re-resolve
                    # the hostname; we cannot easily pin the resolved IP through it.
                    # We accept Invoke-WebRequest's resolution here because the MTA-STS
                    # policy file is a tenant-published-DNS record — risk is bounded
                    # to the .well-known/ HTTP fetch and we still gate on the validate-
                    # time resolution being public. A stricter pin would require a
                    # custom HttpClient with a SocketsHttpHandler.ConnectCallback. The
                    # validate-time resolution still rules out the worst case (the
                    # bare hostname pointing at an internal address at validate time).
                    try {
                        # Validate the domain before constructing URL — already validated above
                        $stsUrl     = "https://$mtaStsHost/.well-known/mta-sts.txt"
                        $stsContent = Invoke-WebRequest -Uri $stsUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                        $stsText    = $stsContent.Content
                        $d.MTASTS.Policy = $stsText

                        $modeMatch = [regex]::Match($stsText, '^\s*mode:\s*(\S+)', [System.Text.RegularExpressions.RegexOptions]::Multiline)
                        $d.MTASTS.Mode = if ($modeMatch.Success) { $modeMatch.Groups[1].Value.Trim() } else { 'unknown' }
                    } catch { }
                }
            }

            # TLS-RPT
            try {
                $tlsRptFqdn    = "_smtp._tls.$domain"
                $tlsRptRecords = @(Resolve-DnsName -Name $tlsRptFqdn -Type TXT -ErrorAction Stop)
                $tlsRptMatch   = $tlsRptRecords |
                    Where-Object { ($_.Strings -join '') -like 'v=TLSRPTv1*' } |
                    Select-Object -First 1
                if ($tlsRptMatch) { $d.TLSRPT = ($tlsRptMatch.Strings -join '') }
            } catch { }

            # DNSSEC (DS record presence at parent zone)
            try {
                $dsRecords = @(Resolve-DnsName -Name $domain -Type DS -ErrorAction SilentlyContinue)
                if ($dsRecords.Count -gt 0) { $d.DNSSEC = $true }
            } catch { }

            # MX
            try {
                $mxRecords = @(Resolve-DnsName -Name $domain -Type MX -ErrorAction Stop)
                $d.MX = @($mxRecords |
                    Where-Object { $_.Type -eq 'MX' } |
                    ForEach-Object { @{ Exchange = [string]$_.NameExchange; Preference = [int]$_.Preference } })
            } catch { }

            # ── CAA records (RFC 8659) ────────────────────────────────────────
            # Controls which CAs may issue certs for the domain. Absence means
            # any CA may issue, which is fine but means there's no defense
            # against an attacker who phishes a domain admin into approving
            # a cert from a CA the org doesn't use.
            try {
                $caaRecords = @(Resolve-DnsName -Name $domain -Type CAA -ErrorAction Stop |
                                Where-Object { $_.Type -eq 'CAA' })
                if ($caaRecords.Count -gt 0) {
                    $d.CAA.Present = $true
                    $d.CAA.Records = @($caaRecords | ForEach-Object {
                        @{
                            Flags = [int]($_.Flags ?? 0)
                            Tag   = [string]$_.Tag
                            Value = [string]$_.Value
                        }
                    })
                    $d.CAA.IssuanceAllowed = @($caaRecords | Where-Object { $_.Tag -eq 'issue' }     | ForEach-Object { [string]$_.Value })
                    $d.CAA.WildcardAllowed = @($caaRecords | Where-Object { $_.Tag -eq 'issuewild' } | ForEach-Object { [string]$_.Value })
                    $d.CAA.IodefContact    = @($caaRecords | Where-Object { $_.Tag -eq 'iodef' }     | ForEach-Object { [string]$_.Value })
                }
            } catch {
                $d.Errors += "CAA: $($_.Exception.Message)"
            }

            # Budget check after the DNS section — if we've already burned the
            # budget on slow lookups, skip the long-tail probes (TLS + crt.sh).
            if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) {
                $d.Errors += "TimeBudget: exceeded ${TimeoutSec}s before TLS probe; skipping TLS probe and crt.sh"
                $domainResults[$domain] = $d
                continue
            }

            # ── TLS certificate inspection (autodiscover + MX hostname) ──────
            # NIST 800-53 SC-17 — verify certs haven't expired and are issued by
            # a trusted CA. We probe port 443 on autodiscover.<domain> and on
            # the first MX hostname. STARTTLS on port 25 is a future enhancement;
            # current scope is the HTTPS endpoints the help desk routinely uses.
            # DNS rebinding fix (v4.6.3 P2): tlsTargets now stores
            # @{ HostName=<original-fqdn>; Address=[IPAddress] } per role.
            # We resolve ONCE in Test-NRGSafeProbeTarget and connect by IP,
            # passing the original hostname as SNI to AuthenticateAsClient.
            # This closes the rebinding race that existed when the validate-
            # time GetHostAddresses() and the connect-time TcpClient name
            # resolution disagreed (short-TTL DNS rebinder).
            $tlsTargets = [ordered]@{}
            # SSRF guard (v4.6.x audit MED #3): autodiscover.<domain> resolved
            # over DNS could point at RFC1918 / loopback / link-local IPs in
            # a misconfigured or hostile tenant. Same gate the MX target gets.
            $autoDiscHost  = "autodiscover.$domain"
            $autoDiscProbe = Test-NRGSafeProbeTarget -HostName $autoDiscHost
            if ($autoDiscProbe.Refused) {
                $d.Errors += "TLSCerts.Autodiscover: refused '$autoDiscHost' — $($autoDiscProbe.Reason)"
                $d.TLSCerts['Autodiscover'] = @{ Hostname = $autoDiscHost; Error = "Refused: $($autoDiscProbe.Reason)" }
            } else {
                $tlsTargets['Autodiscover'] = $autoDiscProbe
            }
            if ($d.MX.Count -gt 0) {
                $firstMx = [string]$d.MX[0].Exchange
                # MX hostnames sometimes end with a trailing dot — strip it
                $firstMx = $firstMx.TrimEnd('.')
                # SSRF guard — MX values are attacker-influenced DNS data. Re-validate
                # the FQDN, deny internal-only suffixes, and refuse to connect to
                # RFC1918 / loopback / link-local / IPv6 ULA addresses.
                if ($firstMx) {
                    $mxProbe = Test-NRGSafeProbeTarget -HostName $firstMx
                    if ($mxProbe.Refused) {
                        $d.Errors += "TLSCerts.MailHost: refused MX target '$firstMx' — $($mxProbe.Reason)"
                        $d.TLSCerts['MailHost'] = @{ Hostname = $firstMx; Error = "Refused: $($mxProbe.Reason)" }
                    } else {
                        $tlsTargets['MailHost'] = $mxProbe
                    }
                }
            }

            foreach ($role in $tlsTargets.Keys) {
                $probe = $tlsTargets[$role]
                if (-not $probe) { continue }
                $hostname = $probe.HostName
                $ipAddr   = $probe.Address
                if (-not $hostname -or -not $ipAddr) { continue }

                # Resource-leak fix: wrap the entire TLS-inspection block in
                # try/finally and dispose tcpClient + sslStream in the finally
                # block. Previously, an exception in AuthenticateAsClient left
                # the sockets dangling until GC.
                $tcpClient = $null
                $sslStream = $null
                try {
                    $tcpClient = [System.Net.Sockets.TcpClient]::new()
                    # 5-second connect timeout — many MX hosts block 443.
                    # Connect to the resolved IP (closes the DNS rebinding race
                    # against the connect-time name resolution).
                    $iar = $tcpClient.BeginConnect($ipAddr, 443, $null, $null)
                    if (-not $iar.AsyncWaitHandle.WaitOne(5000, $false)) {
                        $d.TLSCerts[$role] = @{ Hostname = $hostname; Address = $ipAddr.ToString(); Error = 'Connect timeout' }
                        continue
                    }
                    $tcpClient.EndConnect($iar)
                    # Don't validate the chain — we're inspecting, not consuming.
                    # SNI = original hostname (so the server returns the right cert),
                    # but the TCP destination is the validated IP.
                    $sslStream = [System.Net.Security.SslStream]::new(
                        $tcpClient.GetStream(), $false, { param($s,$c,$ch,$e) $true })
                    $sslStream.AuthenticateAsClient($hostname)
                    $cert  = $sslStream.RemoteCertificate
                    $x509  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
                    $now   = [datetime]::UtcNow
                    $days  = [int]($x509.NotAfter.ToUniversalTime() - $now).TotalDays
                    $d.TLSCerts[$role] = @{
                        Hostname        = $hostname
                        Address         = $ipAddr.ToString()
                        Subject         = [string]$x509.Subject
                        Issuer          = [string]$x509.Issuer
                        NotBefore       = $x509.NotBefore.ToString('o')
                        NotAfter        = $x509.NotAfter.ToString('o')
                        DaysUntilExpiry = $days
                        Thumbprint      = [string]$x509.Thumbprint
                        Status          = if ($days -lt 0) { 'Expired' }
                                          elseif ($days -lt 14) { 'ExpiringSoon' }
                                          elseif ($days -lt 30) { 'ExpiringWithin30' }
                                          else { 'OK' }
                    }
                } catch {
                    $d.TLSCerts[$role] = @{ Hostname = $hostname; Address = $ipAddr.ToString(); Error = $_.Exception.Message }
                } finally {
                    if ($sslStream) { try { $sslStream.Dispose() } catch {} }
                    if ($tcpClient) { try { $tcpClient.Dispose() } catch {} }
                }
            }

            # Budget check after TLS — skip crt.sh if we've exceeded the budget.
            if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) {
                $d.Errors += "TimeBudget: exceeded ${TimeoutSec}s after TLS probe; skipping crt.sh"
                $domainResults[$domain] = $d
                continue
            }

            # ── Certificate Transparency log lookup via crt.sh (RFC 6962) ────
            # Surfaces ALL certs ever issued for the domain — useful to catch
            # certs issued by CAs the org doesn't authorize, or recent issuance
            # spikes that may indicate an attacker who acquired the domain.
            try {
                # URL-encode the domain literal; crt.sh expects %25 (URL-encoded %)
                # around the domain for wildcard match.
                $ctUrl = ('https://crt.sh/?q=%25.{0}&output=json' -f [uri]::EscapeDataString($domain))
                $ctResp = Invoke-WebRequest -Uri $ctUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
                # CWE-502 — crt.sh is a public service; a hostile response (MITM
                # downgrade, BGP hijack, compromise) could include a recursive
                # JSON bomb. -Depth caps deserialization at realistic CT-log
                # entry nesting (10 is generous).
                $ctList = $ctResp.Content | ConvertFrom-Json -Depth 10 -ErrorAction Stop
                if ($ctList) {
                    $arr = @($ctList)
                    $d.CTLog.TotalCerts = $arr.Count
                    $thirtyDaysAgo = (Get-Date).AddDays(-30)
                    $recent = @($arr | Where-Object {
                        # InvariantCulture: crt.sh emits ISO 8601 timestamps; the local
                        # culture must not steer interpretation. v4.6.3 P2 fix.
                        try { [datetime]::Parse([string]$_.entry_timestamp, [cultureinfo]::InvariantCulture) -gt $thirtyDaysAgo }
                        catch { $false }
                    })
                    $d.CTLog.Last30Days = $recent.Count
                    $d.CTLog.Issuers = @($arr | ForEach-Object { [string]$_.issuer_name } |
                                         Sort-Object -Unique | Select-Object -First 20)

                    # Cross-check: are recent issuers consistent with the CAA
                    # allowlist? If CAA names letsencrypt.org but recent issuers
                    # include 'CN=Sectigo RSA Domain Validation', that's a finding.
                    if ($d.CAA.IssuanceAllowed.Count -gt 0) {
                        $allowed = @($d.CAA.IssuanceAllowed | ForEach-Object { $_.ToLowerInvariant() })
                        $d.CTLog.UnexpectedSANs = @($recent | Where-Object {
                            $issuer = [string]$_.issuer_name
                            $allowedHit = $false
                            foreach ($a in $allowed) {
                                if ($issuer.ToLowerInvariant() -match [regex]::Escape($a)) {
                                    $allowedHit = $true; break
                                }
                            }
                            -not $allowedHit
                        } | Select-Object -First 10 | ForEach-Object {
                            @{
                                CommonName   = [string]$_.common_name
                                Issuer       = [string]$_.issuer_name
                                NotBefore    = [string]$_.not_before
                                EntryDate    = [string]$_.entry_timestamp
                            }
                        })
                    }
                }
            } catch {
                $d.CTLog.QueryError = $_.Exception.Message
            }

            # Final budget check — log overrun so operators can see which domains
            # are pushing past the per-domain budget even after all sub-steps ran.
            if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) {
                $d.Errors += "TimeBudget: total time $([int]$sw.Elapsed.TotalSeconds)s exceeded ${TimeoutSec}s budget"
            }

            $domainResults[$domain] = $d
        }

        $result.Data.Domains    = $domainResults
        $result.Data.DomainCount = $domainResults.Count
        $result.Success         = $true

        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'DNS-EmailRecords' -Status 'Collected' `
                -Note "$($domainResults.Count) domains checked"
        }

    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'DNS-EmailRecords' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'DNS-EmailRecords' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'DNS-EmailRecords' -Data $result
    }
    return $result
}
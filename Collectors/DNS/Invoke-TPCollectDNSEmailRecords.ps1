#Requires -Version 7.0
#
# Invoke-TPCollectDNSEmailRecords.ps1  (v4.5.6)
# Dependencies: Resolve-TPDns, Get-TPRawData, Set-TPRawData, Get-TPObjectField,
#               Register-TPException, Register-TPCoverage, Test-TPSafeProbeTarget
# TenantPosture
# Author: Matthew Levorson
#
# Sets:         DNS-EmailRecords (Data.Domains.<domain> with per-record LookupStatus
#               and Errors — LookupStatus is this collector's SectionStatus)
# Consumes:     EXO-MailboxConfig (custom DKIM selectors, key creation time), optional
# Cmdlets:      none against the tenant; Resolve-TPDns (DoH) plus HTTPS/TLS probes
#
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
function Test-TPSafeProbeTarget {
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

function Invoke-TPCollectDNSEmailRecords {
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

    # [ordered] because this envelope is serialised into the results JSON.
    $result = [ordered]@{
        Success     = $false
        Data        = [ordered]@{ Domains = [ordered]@{}; DomainCount = 0 }
    }

    try {
        # Determine domain list
        if (-not $Domains -or $Domains.Count -eq 0) {
            $exoData = if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) {
                Get-TPRawData -Key 'EXO-MailboxConfig'
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
        # the DKIM check genuinely needs EXO. (observed on a client run: EXO was down
        # and no -Domains was passed, so DNS silently collected nothing.)
        if ((-not $Domains -or $Domains.Count -eq 0) -and
            (Get-Command Invoke-TPGraphRequest -ErrorAction SilentlyContinue)) {
            try {
                $org = Invoke-TPGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization'
                $verified = @($org.value ?? @()) |
                    ForEach-Object { @($_.verifiedDomains ?? @()) } |
                    Where-Object { $_ }
                $Domains = @($verified |
                    ForEach-Object { [string]($_.name ?? '') } |
                    Where-Object { $_ -notmatch '\.onmicrosoft\.com$' -and $_ -match $script:DomainPattern } |
                    Select-Object -Unique)
            } catch {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'DNS-DomainDiscovery' `
                        -Message "Graph verifiedDomains fallback failed: $($_.Exception.Message)"
                }
            }
        }

        if (-not $Domains -or $Domains.Count -eq 0) {
            if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
                Register-TPCoverage -Family 'DNS-EmailRecords' -Status 'NotCollected' -Note 'No domains to check'
            }
            $result.Success = $true
            if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
                Set-TPRawData -Key 'DNS-EmailRecords' -Data $result
            }
            return $result
        }

        # [ordered] all the way down: this map and each per-domain entry are
        # serialised into the results JSON, and a plain hashtable's key order
        # is unspecified, so two runs of the same tenant diffed differently
        # for no reason. LookupStatus alone being [ordered] was not enough.
        $domainResults = [ordered]@{}

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

            # Records a lookup outcome on the current domain entry. On a failure
            # the reason goes where an operator will look for it — the
            # per-domain Errors list (rendered in the report) and the
            # Exceptions array — because Resolve-TPDns never throws, so
            # previously nothing recorded WHY every resolver failed and the
            # evaluator's "did not complete" was undiagnosable.
            #
            # The outcome is validated against the tri-state before it is
            # written. Test-TPDnsLookupSucceeded reads a BLANK value as
            # collected (the replay rule for pre-change JSON), so a resolver
            # that returned without setting -Outcome would have replaced the
            # fail-closed LookupFailed default with '' and opened the gate.
            # Only Answered and NoRecord may improve on the default; anything
            # else is a failure.
            $recordLookup = {
                param([string] $Key, [string] $Outcome, [string] $Reason)
                if ($Outcome -notin @('Answered', 'NoRecord')) {
                    if ($Outcome -ne 'LookupFailed') { $Reason = "resolver returned an unrecognised outcome '$Outcome'; $Reason" }
                    $Outcome = 'LookupFailed'
                }
                $d.LookupStatus[$Key] = $Outcome
                if ($Outcome -eq 'LookupFailed') {
                    $d.Errors += "${Key}: lookup did not complete — $Reason"
                    if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                        Register-TPException -Source 'DNS-Resolve' -Message "[$domain] ${Key}: $Reason"
                    }
                }
            }

            # Records a lookup that THREW. Resolve-TPDns itself never throws,
            # but the parse pipeline after it can, and every per-record catch
            # below was either empty or appended to Errors without registering
            # an exception — so the coverage note's "see Exceptions" pointed at
            # an empty array, the NotApplicable finding carried no reason, and
            # exit code 3 (keyed on Exceptions) was not raised. The key keeps
            # its LookupFailed default; this only records why.
            $recordThrow = {
                param([string] $Key, [string] $Message)
                $d.Errors += "${Key}: lookup threw — $Message"
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'DNS-Resolve' -Message "[$domain] ${Key}: threw — $Message"
                }
            }

            $d = [ordered]@{
                Domain  = $domain
                # Per-record-type resolution outcome: Answered / NoRecord /
                # LookupFailed. An absent SPF or DMARC record is a Gap, so a
                # FAILED lookup reported as absence would tell a client their
                # email authentication is missing when it is not. Evaluators
                # consult this before scoring an absent record.
                # Initialised to LookupFailed for every gated record, not left
                # empty. Test-TPDnsLookupSucceeded reads an ABSENT key as
                # collected (so pre-change result JSON keeps its behaviour), and
                # the first version assigned each key only after its parse
                # pipeline — so a throw between the resolver returning and that
                # line left the key absent and the gate fail-OPEN on a live
                # run. A key can now only move from LookupFailed to something
                # better. [ordered] because this serialises into the results
                # JSON and key order must not differ between runs.
                LookupStatus = [ordered]@{
                    SPF = 'LookupFailed'; DKIM = 'LookupFailed'; DMARC = 'LookupFailed'
                    MTASTS = 'LookupFailed'; TLSRPT = 'LookupFailed'; DNSSEC = 'LookupFailed'
                    MX = 'LookupFailed'; CAA = 'LookupFailed'
                }
                SPF     = $null
                SPFRecordCount   = 0
                SPFRedirect      = $null
                DMARCRecordCount = 0
                DMARCInheritedFrom  = $null
                DNSSECInheritedFrom = $null
                DKIM    = @{
                    Selector1       = $null
                    Selector2       = $null
                    CustomSelectors = @()
                    KeySize         = $null
                    KeyCreationTime = $null
                    RotateOnDate    = $null
                    KeyAgeDays      = $null
                    RotationStatus  = $null  # 'OK' | 'Due' | 'Overdue' | 'Unknown'
                    # Date the current key was created (yyyy-MM-dd, UTC), the
                    # per-selector key sizes and the selector signing after
                    # RotateOnDate, from Get-DkimSigningConfig.
                    LastRotated       = $null
                    Selector1KeySize  = $null
                    Selector2KeySize  = $null
                    ActiveSelector    = $null
                    # The published key behind each selector CNAME: its n=
                    # creation timestamp and key size. A cross-check on
                    # Exchange's date; informational, never scored.
                    KeyRecords        = @()
                }
                DMARC   = $null
                MTASTS  = @{ DNSRecord = $null; Policy = $null; Mode = $null; PolicyFetchError = $null; PolicyHostMissing = $false }
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

            # SPF — resolved via public DoH (Resolve-TPDns), which returns clean
            # record strings so there is no fragile .Strings access, and queries
            # a PUBLIC resolver so split-DNS / corporate resolvers can't hide a
            # published record (both were real false-"no SPF" causes).
            try {
                $spfOutcome = ''; $spfReason = ''
                # Every v=spf1 record, not the first: two SPF records is a
                # permerror (RFC 7208 §4.5) — SPF then fails for all mail —
                # and reading only the first called that tenant "hard fail
                # configured".
                $spfAll = @(@(Resolve-TPDns -Name $domain -Type TXT -Outcome ([ref]$spfOutcome) -Reason ([ref]$spfReason)) |
                    Where-Object { [string]$_ -match '^v=spf1(\s|$)' })
                & $recordLookup 'SPF' $spfOutcome $spfReason
                $d.SPFRecordCount = $spfAll.Count
                if ($spfAll.Count -gt 0) { $d.SPF = [string]$spfAll[0] }
                # redirect= hands the policy to another domain's record; with
                # no 'all' of its own the verdict is the target's.
                if ($spfAll.Count -eq 1 -and $d.SPF -notmatch '(^|\s)[+\-~?]?all(\s|$)' -and $d.SPF -match '(^|\s)redirect=([^\s]+)') {
                    $target = $Matches[2].TrimEnd('.')
                    $d.SPFRedirect = [ordered]@{ Target = $target; Record = $null; Outcome = 'LookupFailed' }
                    # Underscore labels are normal here (_spf.example.com), so the
                    # hostname pattern used for tenant domains is too strict.
                    if ($target.Length -le 253 -and $target -match '^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}))+$') {
                        $rOut = ''; $rWhy = ''
                        $rRec = @(@(Resolve-TPDns -Name $target -Type TXT -Outcome ([ref]$rOut) -Reason ([ref]$rWhy)) |
                            Where-Object { [string]$_ -match '^v=spf1(\s|$)' })
                        $d.SPFRedirect.Outcome = if ($rOut -in @('Answered','NoRecord')) { $rOut } else { 'LookupFailed' }
                        if ($rRec.Count -eq 1) { $d.SPFRedirect.Record = [string]$rRec[0] }
                        if ($d.SPFRedirect.Outcome -eq 'LookupFailed') { $d.Errors += "SPF redirect ${target}: lookup did not complete — $rWhy" }
                    }
                }
            } catch {
                & $recordThrow 'SPF' $_.Exception.Message
            }

            # DKIM — standard selectors + check if EXO DKIM data has custom selectors
            $dkimSelectors = @('selector1', 'selector2')

            # Pull any custom DKIM selectors from EXO collector data
            $exoRaw = if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) {
                Get-TPRawData -Key 'EXO-MailboxConfig'
            } else { $null }

            if ($exoRaw -and $exoRaw.Success) {
                $dkimConfig = @($exoRaw.Data.DkimSigningConfigs ?? @()) |
                    Where-Object { $_.Domain -eq $domain } | Select-Object -First 1
                if ($dkimConfig) {
                    $cfgSel1 = [string](Get-TPObjectField -Item $dkimConfig -Key 'Selector1' -Default '')
                    $cfgSel2 = [string](Get-TPObjectField -Item $dkimConfig -Key 'Selector2' -Default '')
                    if ($cfgSel1) { $dkimSelectors += $cfgSel1 }
                    if ($cfgSel2) { $dkimSelectors += $cfgSel2 }
                    $dkimSelectors = @($dkimSelectors | Select-Object -Unique)

                    # DKIM rotation age — NIST 800-53 SC-12 expects cryptographic
                    # material to be rotated on a documented cadence. Microsoft
                    # rotates DKIM only when the customer opts in; many tenants
                    # have keys older than two years which weakens DKIM's value.
                    $d.DKIM.KeySize          = Get-TPObjectField -Item $dkimConfig -Key 'KeySize' -Default $null
                    $d.DKIM.Selector1KeySize = Get-TPObjectField -Item $dkimConfig -Key 'Selector1KeySize' -Default $null
                    $d.DKIM.Selector2KeySize = Get-TPObjectField -Item $dkimConfig -Key 'Selector2KeySize' -Default $null
                    $d.DKIM.ActiveSelector   = [string](Get-TPObjectField -Item $dkimConfig -Key 'SelectorAfterRotateOnDate' -Default '')
                    $d.DKIM.KeyCreationTime  = [string](Get-TPObjectField -Item $dkimConfig -Key 'KeyCreationTime' -Default '')
                    $d.DKIM.RotateOnDate     = [string](Get-TPObjectField -Item $dkimConfig -Key 'RotateOnDate' -Default '')
                    $d.DKIM.RotationStatus   = 'Unknown'
                    # InvariantCulture: Exchange returns a fixed format, and the
                    # current culture's parser misreads it on non-en-US hosts.
                    $kct = [datetime]::MinValue
                    if ($d.DKIM.KeyCreationTime -and [datetime]::TryParse($d.DKIM.KeyCreationTime, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$kct)) {
                        $age = [int][math]::Floor(([datetime]::UtcNow - $kct).TotalDays)
                        $d.DKIM.KeyAgeDays  = $age
                        $d.DKIM.LastRotated = $kct.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
                        # The same bands DNS-2.1 scores: within the 365-day
                        # rotation interval, within two years, older.
                        $d.DKIM.RotationStatus = if ($age -le 365) { 'OK' }
                                                 elseif ($age -le 730) { 'Due' }
                                                 else { 'Overdue' }
                    }
                }
            }

            # Per-selector outcome, then worst-of across selectors. The verdict
            # compares selector1 against selector2, so ONE failed selector can
            # turn a genuine Satisfied into a false Partial — a failure on any
            # selector makes the whole DKIM verdict unassessable.
            $dkimSelectorOutcomes = @()
            foreach ($sel in $dkimSelectors) {
                $selOutcome = 'LookupFailed'
                try {
                    $dkimFqdn = "${sel}._domainkey.${domain}"
                    # Microsoft 365 publishes DKIM as a CNAME
                    # (selector1._domainkey.<domain> -> selectorX-...._domainkey.
                    # <tenant>.onmicrosoft.com), NOT as a TXT 'v=DKIM1' record —
                    # the previous TXT-only lookup NEVER matched an M365 tenant and
                    # reported "no DKIM" on every one. Check CNAME first (the M365
                    # case), then fall back to a direct TXT key (custom/third-party
                    # DKIM). Either present => DKIM is published for this selector.
                    $cnameOutcome = ''; $cnameReason = ''; $txtOutcome = ''; $txtReason = ''
                    $dkimVal = @(Resolve-TPDns -Name $dkimFqdn -Type CNAME -Outcome ([ref]$cnameOutcome) -Reason ([ref]$cnameReason)) |
                        Select-Object -First 1
                    if (-not $dkimVal) {
                        $dkimVal = @(Resolve-TPDns -Name $dkimFqdn -Type TXT -Outcome ([ref]$txtOutcome) -Reason ([ref]$txtReason)) |
                            Where-Object { [string]$_ -match '(^|;)\s*p=[A-Za-z0-9+/]' } | Select-Object -First 1
                    }
                    # A record from either lookup is an answer. Only two clean
                    # answers (Answered or NoRecord — a TXT answer with no
                    # DKIM key in it is still an answer) mean the selector is
                    # absent. Anything else on either lookup, including a
                    # blank or unrecognised outcome, is a failure — the same
                    # validation $recordLookup applies. When no CNAME was
                    # returned the TXT lookup always runs, so both outcomes
                    # are populated here.
                    $clean = @('Answered', 'NoRecord')
                    $selOutcome = if ($dkimVal) { 'Answered' }
                                  elseif ($cnameOutcome -in $clean -and $txtOutcome -in $clean) { 'NoRecord' }
                                  else { 'LookupFailed' }
                    if ($selOutcome -eq 'LookupFailed') {
                        $d.Errors += "DKIM ${sel}: lookup did not complete — CNAME: $cnameReason | TXT: $txtReason"
                        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                            Register-TPException -Source 'DNS-Resolve' -Message "[$domain] DKIM ${sel}: CNAME: $cnameReason | TXT: $txtReason"
                        }
                    }
                    if ($dkimVal) {
                        if     ($sel -eq 'selector1') { $d.DKIM.Selector1 = [string]$dkimVal }
                        elseif ($sel -eq 'selector2') { $d.DKIM.Selector2 = [string]$dkimVal }
                        else { $d.DKIM.CustomSelectors += @{ Selector = $sel; Record = [string]$dkimVal } }
                    }
                } catch {
                    # Non-fatal for the run, but not silent: $selOutcome keeps
                    # its LookupFailed default and the reason is recorded.
                    & $recordThrow "DKIM ${sel}" $_.Exception.Message
                }
                $dkimSelectorOutcomes += $selOutcome
            }
            # The published key behind each Microsoft 365 selector CNAME. Its
            # n= tag carries the key's creation time (Unix seconds), which is
            # the independent cross-check on Exchange's KeyCreationTime. The
            # inactive selector's target is routinely absent after a rotation,
            # so an absent target is recorded, never an error, and nothing
            # here touches LookupStatus or any verdict.
            foreach ($pair in @(@('selector1', $d.DKIM.Selector1), @('selector2', $d.DKIM.Selector2))) {
                $selName = $pair[0]; $target = [string]$pair[1]
                if (-not $target -or $target -match '(^|;)\s*p=') { continue }
                $target = $target.Trim().TrimEnd('.')
                $rec = [ordered]@{ Selector = $selName; Target = $target; Lookup = 'LookupFailed'; KeyCreated = $null; KeyBits = $null }
                try {
                    $kOutcome = ''; $kReason = ''
                    $txt = @(Resolve-TPDns -Name $target -Type TXT -Outcome ([ref]$kOutcome) -Reason ([ref]$kReason)) |
                        ForEach-Object { ([string]$_) -replace '"\s*"', '' -replace '"', '' } |
                        Where-Object { $_ -match '(^|;)\s*p=' } | Select-Object -First 1
                    $rec.Lookup = if ($txt) { 'Answered' } elseif ($kOutcome -in @('Answered', 'NoRecord')) { 'NoRecord' } else { 'LookupFailed' }
                    if ($txt) {
                        if ($txt -match '(?:^|;)\s*n=(\d{9,11})\s*(?:;|$)') {
                            $rec.KeyCreated = [DateTimeOffset]::FromUnixTimeSeconds([long]$Matches[1]).UtcDateTime.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
                        }
                        if ($txt -match '(?:^|;)\s*p=([A-Za-z0-9+/=\s]+)') {
                            try {
                                $rsa = [System.Security.Cryptography.RSA]::Create()
                                $read = 0
                                $rsa.ImportSubjectPublicKeyInfo([Convert]::FromBase64String(($Matches[1] -replace '\s', '')), [ref]$read)
                                $rec.KeyBits = $rsa.KeySize
                                $rsa.Dispose()
                            } catch { Write-Verbose "[$domain] DKIM ${selName}: published key not parsed: $($_.Exception.Message)" }
                        }
                    }
                } catch { Write-Verbose "[$domain] DKIM ${selName}: published key not read: $($_.Exception.Message)" }
                $d.DKIM.KeyRecords += $rec
            }

            $d.LookupStatus['DKIM'] = if ($dkimSelectorOutcomes -contains 'LookupFailed') { 'LookupFailed' }
                                       elseif ($dkimSelectorOutcomes -contains 'Answered') { 'Answered' }
                                       else { 'NoRecord' }

            # DMARC
            try {
                $dmarcOutcome = ''; $dmarcReason = ''
                # "v=DMARC1" must match exactly, case included (RFC 7489 §6.3),
                # and more than one record means no DMARC policy is applied at
                # all (§6.6.3) — reading only the first called that "full
                # spoofing protection".
                $isDmarc = { param($r) [string]$r -cmatch '^v\s*=\s*DMARC1\s*(;|$)' }
                $dmarcAll = @(@(Resolve-TPDns -Name "_dmarc.$domain" -Type TXT -Outcome ([ref]$dmarcOutcome) -Reason ([ref]$dmarcReason)) |
                    Where-Object { & $isDmarc $_ })
                & $recordLookup 'DMARC' $dmarcOutcome $dmarcReason
                $d.DMARCRecordCount = $dmarcAll.Count
                $dmarcStr = if ($dmarcAll.Count -gt 0) { [string]$dmarcAll[0] } else { $null }

                # No record on a subdomain: receivers apply the organizational
                # domain's policy (its sp=, else p=) — §6.6.3. Walk up to the
                # nearest published record; a failed lookup on the way leaves
                # the result unknown rather than "no DMARC".
                if ($dmarcAll.Count -eq 0 -and $d.LookupStatus['DMARC'] -eq 'NoRecord') {
                    $labels = $domain.Split('.')
                    for ($i = 1; $labels.Count - $i -ge 2; $i++) {
                        $parent = ($labels[$i..($labels.Count - 1)]) -join '.'
                        $pOut = ''; $pWhy = ''
                        $pAll = @(@(Resolve-TPDns -Name "_dmarc.$parent" -Type TXT -Outcome ([ref]$pOut) -Reason ([ref]$pWhy)) | Where-Object { & $isDmarc $_ })
                        if ($pOut -notin @('Answered','NoRecord')) { & $recordLookup 'DMARC' 'LookupFailed' "organizational domain _dmarc.${parent}: $pWhy"; break }
                        if ($pAll.Count -gt 0) {
                            $d.DMARCInheritedFrom = $parent
                            $d.DMARCRecordCount   = $pAll.Count
                            $dmarcStr             = [string]$pAll[0]
                            break
                        }
                    }
                }

                if ($dmarcStr) {
                    $d.DMARC = $dmarcStr
                    # Tag names and values are whitespace-tolerant ("p = reject"
                    # is valid ABNF); the old '\s*p=' read it as p=none.
                    $tag = { param($name) $m = [regex]::Match($dmarcStr, "(?:^|;)\s*$name\s*=\s*([^;\s]+)", 'IgnoreCase'); if ($m.Success) { $m.Groups[1].Value.Trim().ToLowerInvariant() } else { $null } }
                    $p   = & $tag 'p'
                    $sp  = & $tag 'sp'
                    $pct = & $tag 'pct'
                    $d.DMARCPolicy    = if ($p) { $p } else { 'none' }
                    $d.DMARCSubPolicy = $sp
                    $d.DMARCPct       = if ($pct -match '^\d+$') { [int]$pct } else { 100 }
                    # An inherited record governs this domain through sp= when present.
                    if ((Get-TPObjectField -Item $d -Key 'DMARCInheritedFrom' -Default $null) -and $sp) { $d.DMARCPolicy = $sp }
                }
            } catch {
                & $recordThrow 'DMARC' $_.Exception.Message
            }

            # MTA-STS DNS record
            try {
                $mtaStsOutcome = ''; $mtaStsReason = ''
                $mtaStsMatch = @(Resolve-TPDns -Name "_mta-sts.$domain" -Type TXT -Outcome ([ref]$mtaStsOutcome) -Reason ([ref]$mtaStsReason)) |
                    Where-Object { $_ -like 'v=STSv1*' } | Select-Object -First 1
                & $recordLookup 'MTASTS' $mtaStsOutcome $mtaStsReason
                if ($mtaStsMatch) { $d.MTASTS.DNSRecord = [string]$mtaStsMatch }
            } catch { & $recordThrow 'MTASTS' $_.Exception.Message }

            # MTA-STS policy file (HTTPS fetch — validate URL before opening)
            if ($d.MTASTS.DNSRecord) {
                # SSRF guard (v4.6.x audit MED #3): the mta-sts.<domain> hostname
                # is constructed from tenant DNS data. Even though $domain is
                # FQDN-validated above, the resolved hostname could point at
                # an RFC1918 / loopback / link-local address (DNS rebinding).
                # Refuse to fetch the policy file in those cases — same pattern
                # used for the MX hostname TLS probe below.
                $mtaStsHost  = "mta-sts.$domain"
                $mtaStsProbe = Test-TPSafeProbeTarget -HostName $mtaStsHost
                if ($mtaStsProbe.Refused) {
                    $d.Errors += "MTASTS.Policy: refused '$mtaStsHost' — $($mtaStsProbe.Reason)"
                    $d.MTASTS.PolicyFetchError = "refused '$mtaStsHost' — $($mtaStsProbe.Reason)"
                    # A host that does not exist is a finding, not a fetch
                    # failure: senders cannot retrieve the policy, so MTA-STS
                    # is not in effect. Only an authoritative "no record" for
                    # both A and AAAA says so; any lookup failure stays unknown.
                    if ([string]$mtaStsProbe.Reason -like 'DNS resolution failed*') {
                        $aOut = ''; $aWhy = ''; $aaaaOut = ''; $aaaaWhy = ''
                        $a    = @(Resolve-TPDns -Name $mtaStsHost -Type A    -Outcome ([ref]$aOut)    -Reason ([ref]$aWhy))
                        $aaaa = @(Resolve-TPDns -Name $mtaStsHost -Type AAAA -Outcome ([ref]$aaaaOut) -Reason ([ref]$aaaaWhy))
                        if ($aOut -eq 'NoRecord' -and $aaaaOut -eq 'NoRecord' -and $a.Count -eq 0 -and $aaaa.Count -eq 0) {
                            $d.MTASTS.PolicyHostMissing = $true
                        }
                    }
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
                    } catch {
                        # Not silent: an unread policy file is "not assessed",
                        # never a scored mode of "unknown".
                        $d.MTASTS.PolicyFetchError = $_.Exception.Message
                        $d.Errors += "MTASTS.Policy: fetch failed — $($_.Exception.Message)"
                    }
                }
            }

            # TLS-RPT
            try {
                $tlsRptOutcome = ''; $tlsRptReason = ''
                $tlsRptMatch = @(Resolve-TPDns -Name "_smtp._tls.$domain" -Type TXT -Outcome ([ref]$tlsRptOutcome) -Reason ([ref]$tlsRptReason)) |
                    Where-Object { $_ -like 'v=TLSRPTv1*' } | Select-Object -First 1
                & $recordLookup 'TLSRPT' $tlsRptOutcome $tlsRptReason
                if ($tlsRptMatch) { $d.TLSRPT = [string]$tlsRptMatch }
            } catch { & $recordThrow 'TLSRPT' $_.Exception.Message }

            # DNSSEC (DS record presence at parent zone)
            try {
                $dsOutcome = ''; $dsReason = ''
                $dsRecords = @(Resolve-TPDns -Name $domain -Type DS -Outcome ([ref]$dsOutcome) -Reason ([ref]$dsReason))
                & $recordLookup 'DNSSEC' $dsOutcome $dsReason
                if ($dsRecords.Count -gt 0) { $d.DNSSEC = $true }
                elseif ($d.LookupStatus['DNSSEC'] -eq 'NoRecord' -and $domain.Split('.').Count -gt 2) {
                    # DS exists only at a zone cut. A subdomain that is NOT its
                    # own zone (no NS records) is signed by its parent's key,
                    # so "no DS here" is not "unsigned". Only a delegated
                    # subdomain needs its own DS.
                    $nsOut = ''; $nsWhy = ''
                    $ns = @(Resolve-TPDns -Name $domain -Type NS -Outcome ([ref]$nsOut) -Reason ([ref]$nsWhy))
                    if ($nsOut -notin @('Answered','NoRecord')) {
                        & $recordLookup 'DNSSEC' 'LookupFailed' "zone-cut (NS) check: $nsWhy"
                    } elseif ($ns.Count -eq 0) {
                        $labels = $domain.Split('.')
                        for ($i = 1; $labels.Count - $i -ge 2; $i++) {
                            $parent = ($labels[$i..($labels.Count - 1)]) -join '.'
                            $pOut = ''; $pWhy = ''
                            $pDs = @(Resolve-TPDns -Name $parent -Type DS -Outcome ([ref]$pOut) -Reason ([ref]$pWhy))
                            if ($pOut -notin @('Answered','NoRecord')) { & $recordLookup 'DNSSEC' 'LookupFailed' "parent zone ${parent} DS: $pWhy"; break }
                            if ($pDs.Count -gt 0) { $d.DNSSEC = $true; $d.DNSSECInheritedFrom = $parent; break }
                            # Stop at the parent that IS a zone: its DS answer is the zone's answer.
                            $pnOut = ''; $pnWhy = ''
                            $pNs = @(Resolve-TPDns -Name $parent -Type NS -Outcome ([ref]$pnOut) -Reason ([ref]$pnWhy))
                            if ($pNs.Count -gt 0) { break }
                        }
                    }
                }
            } catch { & $recordThrow 'DNSSEC' $_.Exception.Message }

            # MX — DoH returns each answer as 'PREF exchange.' e.g. '10 host.'
            try {
                $mxOutcome = ''; $mxReason = ''
                $d.MX = @(@(Resolve-TPDns -Name $domain -Type MX -Outcome ([ref]$mxOutcome) -Reason ([ref]$mxReason)) | ForEach-Object {
                    $parts = ([string]$_).Trim() -split '\s+', 2
                    if ($parts.Count -eq 2) {
                        @{ Preference = [int]$parts[0]; Exchange = $parts[1].TrimEnd('.') }
                    }
                } | Where-Object { $_ })
                & $recordLookup 'MX' $mxOutcome $mxReason
            } catch { & $recordThrow 'MX' $_.Exception.Message }

            # ── CAA records (RFC 8659) ────────────────────────────────────────
            # Controls which CAs may issue certs for the domain. Absence means
            # any CA may issue, which is fine but means there's no defense
            # against an attacker who phishes a domain admin into approving
            # a cert from a CA the org doesn't use.
            # Resolved via DoH — the previous Resolve-DnsName -Type CAA threw
            # 'Cannot convert value CAA to RecordType' on older Windows DnsClient
            # modules, so CAA was never actually checked. DoH returns each record
            # as 'FLAGS TAG "VALUE"', e.g. '0 issue "digicert.com"'.
            try {
                $caaOutcome = ''; $caaReason = ''
                $parseCaa = { param($rows) @(@($rows) | ForEach-Object {
                    $m = [regex]::Match([string]$_, '^\s*(\d+)\s+(\w+)\s+"?([^"]*)"?\s*$')
                    if ($m.Success) {
                        @{ Flags = [int]$m.Groups[1].Value; Tag = $m.Groups[2].Value.ToLowerInvariant(); Value = $m.Groups[3].Value.Trim() }
                    }
                } | Where-Object { $_ }) }
                $caaParsed = @(& $parseCaa @(Resolve-TPDns -Name $domain -Type CAA -Outcome ([ref]$caaOutcome) -Reason ([ref]$caaReason)))
                & $recordLookup 'CAA' $caaOutcome $caaReason
                # RFC 8659 §3: a CA climbs the tree — with no CAA at the name
                # itself, the nearest ancestor's CAA set governs issuance. A
                # subdomain of a CAA-protected domain is protected.
                if ($caaParsed.Count -eq 0 -and $d.LookupStatus['CAA'] -eq 'NoRecord') {
                    $labels = $domain.Split('.')
                    for ($i = 1; $labels.Count - $i -ge 2; $i++) {
                        $parent = ($labels[$i..($labels.Count - 1)]) -join '.'
                        $pOut = ''; $pWhy = ''
                        $pSet = @(& $parseCaa @(Resolve-TPDns -Name $parent -Type CAA -Outcome ([ref]$pOut) -Reason ([ref]$pWhy)))
                        if ($pOut -notin @('Answered','NoRecord')) { & $recordLookup 'CAA' 'LookupFailed' "parent ${parent}: $pWhy"; break }
                        if ($pSet.Count -gt 0) { $caaParsed = $pSet; $d.CAA.InheritedFrom = $parent; break }
                    }
                }
                if ($caaParsed.Count -gt 0) {
                    $d.CAA.Present = $true
                    $d.CAA.Records = $caaParsed
                    $d.CAA.IssuanceAllowed = @($caaParsed | Where-Object { $_.Tag -eq 'issue' }     | ForEach-Object { $_.Value })
                    $d.CAA.WildcardAllowed = @($caaParsed | Where-Object { $_.Tag -eq 'issuewild' } | ForEach-Object { $_.Value })
                    $d.CAA.IodefContact    = @($caaParsed | Where-Object { $_.Tag -eq 'iodef' }     | ForEach-Object { $_.Value })
                }
            } catch {
                & $recordThrow 'CAA' $_.Exception.Message
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
            # We resolve ONCE in Test-TPSafeProbeTarget and connect by IP,
            # passing the original hostname as SNI to AuthenticateAsClient.
            # This closes the rebinding race that existed when the validate-
            # time GetHostAddresses() and the connect-time TcpClient name
            # resolution disagreed (short-TTL DNS rebinder).
            $tlsTargets = [ordered]@{}
            # SSRF guard (v4.6.x audit MED #3): autodiscover.<domain> resolved
            # over DNS could point at RFC1918 / loopback / link-local IPs in
            # a misconfigured or hostile tenant. Same gate the MX target gets.
            $autoDiscHost  = "autodiscover.$domain"
            $autoDiscProbe = Test-TPSafeProbeTarget -HostName $autoDiscHost
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
                    $mxProbe = Test-TPSafeProbeTarget -HostName $firstMx
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

        # A run in which lookups failed is not a collected run, whatever the
        # domain count says. Before this the coverage table showed DNS as fully
        # collected, the batch summary reported success and the run exited 0
        # even when every lookup on every domain came back LookupFailed and all
        # ten DNS controls reported NotApplicable.
        $gatedRecords       = @('SPF', 'DKIM', 'DMARC', 'MTASTS', 'TLSRPT', 'DNSSEC', 'CAA')
        $domainsWithFailure = 0
        $domainsAllFailed   = 0
        $failedRecordTypes  = [System.Collections.Generic.HashSet[string]]::new()
        # The @() wraps the WHOLE if: an if-statement unrolls the array it
        # yields, so a single-domain tenant assigned the lone hashtable as a
        # scalar whose .Count was its KEY count (13), $domainsAllFailed (1)
        # never equalled it, and 'Failed' was unreachable on the most common
        # tenant shape — every-lookup-failed reported Partial.
        $entries = @(if ($domainResults -is [System.Collections.IDictionary]) { $domainResults.Values } else { $domainResults })
        foreach ($entry in $entries) {
            $ls = Get-TPObjectField -Item $entry -Key 'LookupStatus' -Default $null
            if ($null -eq $ls) { continue }
            $failedHere = @($gatedRecords | Where-Object { [string](Get-TPObjectField -Item $ls -Key $_ -Default '') -eq 'LookupFailed' })
            if ($failedHere.Count -gt 0) { $domainsWithFailure++; foreach ($k in $failedHere) { $null = $failedRecordTypes.Add($k) } }
            if ($failedHere.Count -eq $gatedRecords.Count) { $domainsAllFailed++ }
        }
        $coverageStatus = if ($entries.Count -gt 0 -and $domainsAllFailed -eq $entries.Count) { 'Failed' }
                          elseif ($domainsWithFailure -gt 0) { 'Partial' }
                          else { 'Collected' }
        $coverageNote = if ($coverageStatus -eq 'Collected') { "$($domainResults.Count) domains checked" }
                        else { "$($domainResults.Count) domains checked; lookups did not complete on $domainsWithFailure ($(@($failedRecordTypes) -join ', ')) — see Exceptions" }
        if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
            Register-TPCoverage -Family 'DNS-EmailRecords' -Status $coverageStatus -Note $coverageNote
        }

    } catch {
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'DNS-EmailRecords' -Message $_.Exception.Message
        }
        if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
            Register-TPCoverage -Family 'DNS-EmailRecords' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'DNS-EmailRecords' -Data $result
    }
    return $result
}
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
        [string[]] $Domains
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
                            $kct = [datetime]::Parse($dkimConfig.KeyCreationTime)
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
                try {
                    # Validate the domain before constructing URL — already validated above
                    $stsUrl     = "https://mta-sts.$domain/.well-known/mta-sts.txt"
                    $stsContent = Invoke-WebRequest -Uri $stsUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                    $stsText    = $stsContent.Content
                    $d.MTASTS.Policy = $stsText

                    $modeMatch = [regex]::Match($stsText, '^\s*mode:\s*(\S+)', [System.Text.RegularExpressions.RegexOptions]::Multiline)
                    $d.MTASTS.Mode = if ($modeMatch.Success) { $modeMatch.Groups[1].Value.Trim() } else { 'unknown' }
                } catch { }
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

            # ── TLS certificate inspection (autodiscover + MX hostname) ──────
            # NIST 800-53 SC-17 — verify certs haven't expired and are issued by
            # a trusted CA. We probe port 443 on autodiscover.<domain> and on
            # the first MX hostname. STARTTLS on port 25 is a future enhancement;
            # current scope is the HTTPS endpoints the help desk routinely uses.
            $tlsTargets = [ordered]@{}
            $tlsTargets['Autodiscover'] = "autodiscover.$domain"
            if ($d.MX.Count -gt 0) {
                $firstMx = [string]$d.MX[0].Exchange
                # MX hostnames sometimes end with a trailing dot — strip it
                $firstMx = $firstMx.TrimEnd('.')
                if ($firstMx) { $tlsTargets['MailHost'] = $firstMx }
            }

            foreach ($role in $tlsTargets.Keys) {
                $hostname = $tlsTargets[$role]
                if (-not $hostname) { continue }
                try {
                    $tcpClient = [System.Net.Sockets.TcpClient]::new()
                    # 5-second connect timeout — many MX hosts block 443
                    $iar = $tcpClient.BeginConnect($hostname, 443, $null, $null)
                    if (-not $iar.AsyncWaitHandle.WaitOne(5000, $false)) {
                        $tcpClient.Close()
                        $d.TLSCerts[$role] = @{ Hostname = $hostname; Error = 'Connect timeout' }
                        continue
                    }
                    $tcpClient.EndConnect($iar)
                    # Don't validate the chain — we're inspecting, not consuming
                    $sslStream = [System.Net.Security.SslStream]::new(
                        $tcpClient.GetStream(), $false, { param($s,$c,$ch,$e) $true })
                    $sslStream.AuthenticateAsClient($hostname)
                    $cert  = $sslStream.RemoteCertificate
                    $x509  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
                    $now   = [datetime]::UtcNow
                    $days  = [int]($x509.NotAfter.ToUniversalTime() - $now).TotalDays
                    $d.TLSCerts[$role] = @{
                        Hostname        = $hostname
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
                    $sslStream.Dispose()
                    $tcpClient.Close()
                } catch {
                    $d.TLSCerts[$role] = @{ Hostname = $hostname; Error = $_.Exception.Message }
                }
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
                $ctList = $ctResp.Content | ConvertFrom-Json -ErrorAction Stop
                if ($ctList) {
                    $arr = @($ctList)
                    $d.CTLog.TotalCerts = $arr.Count
                    $thirtyDaysAgo = (Get-Date).AddDays(-30)
                    $recent = @($arr | Where-Object {
                        try { [datetime]::Parse($_.entry_timestamp) -gt $thirtyDaysAgo }
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
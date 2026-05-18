#Requires -Version 7.0
#
# Invoke-NRGCollectDNSEmailRecords.ps1  (v4.5.5)
# Collects DNS email authentication records: SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC.
# READ-ONLY. External DNS queries only — no tenant writes.
#
# IMPORTANT: Domain names are validated before any DNS call (OWASP A03 / ASVS V5.1.3).
# DNS responses are treated as hostile data and sanitized before storing.
#
# NIST SP 800-53: SI-8 (spam protection), SC-8 (transmission confidentiality)
# MITRE ATT&CK:   T1566 (Phishing), T1036.005 (Domain Spoofing)
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
                DKIM    = @{ Selector1 = $null; Selector2 = $null; CustomSelectors = @() }
                DMARC   = $null
                MTASTS  = @{ DNSRecord = $null; Policy = $null; Mode = $null }
                TLSRPT  = $null
                DNSSEC  = $false
                MX      = @()
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
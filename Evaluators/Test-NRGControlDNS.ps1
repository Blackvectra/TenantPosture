#Requires -Version 7.0
#
# Test-NRGControlDNS.ps1  (v4.6.1)
# Evaluates DNS email authentication + PKI hygiene controls.
# SCORING ONLY — no DNS / HTTPS queries, reads from module state set by
# Invoke-NRGCollectDNSEmailRecords.
#
# NIST SP 800-53: SI-8, SC-8, SC-12, SC-13, SC-17, AU-6, CM-7
# MITRE ATT&CK:   T1566, T1036.005, T1557, T1600.001, T1583.001
#

# ── DNS-1.1 SPF Published and Valid ─────────────────────────────────────────
function Test-NRGControlDNSSPF {
    [CmdletBinding()] param()

    $controlId = 'DNS-1.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    $dnsDomainCount = [int](Get-NRGNestedProperty -Object $dnsData -Path 'Data.DomainCount' -Default 0)
    if (-not $dnsData -or -not $dnsData.Success -or $dnsDomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    $dnsDomainMap = Get-NRGNestedProperty -Object $dnsData -Path 'Data.Domains' -Default @{}
    foreach ($domain in @($dnsDomainMap.Keys)) {
        $d = $dnsDomainMap[$domain]

        if (-not $d.SPF) {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "Domain '$domain' has no SPF record. Anyone can send email claiming to be from this domain." `
                -CurrentValue 'No SPF record' -RequiredValue "v=spf1 include:spf.protection.outlook.com -all" `
                -Remediation $control.Remediation
        } elseif ($d.SPF -match '\-all\s*$') {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain SPF with hard fail (-all) configured." `
                -CurrentValue $d.SPF
        } elseif ($d.SPF -match '~all\s*$') {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Low' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain SPF uses soft fail (~all). Acceptable for compatibility, but -all provides stronger protection." `
                -CurrentValue $d.SPF -RequiredValue 'SPF ending in -all'
        } elseif ($d.SPF -match '\?all\s*$') {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'High' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain SPF uses neutral (?all) — provides no spam protection. Change to -all." `
                -CurrentValue $d.SPF -RequiredValue 'SPF ending in -all' `
                -Remediation $control.Remediation
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain SPF record present but does not end with -all, ~all, or ?all — likely misconfigured." `
                -CurrentValue $d.SPF -RequiredValue 'SPF ending in -all'
        }
    }
}

# ── DNS-1.2 DKIM Signed ──────────────────────────────────────────────────────
function Test-NRGControlDNSDKIM {
    [CmdletBinding()] param()

    $controlId = 'DNS-1.2'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    $dnsDomainCount = [int](Get-NRGNestedProperty -Object $dnsData -Path 'Data.DomainCount' -Default 0)
    if (-not $dnsData -or -not $dnsData.Success -or $dnsDomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    $dnsDomainMap = Get-NRGNestedProperty -Object $dnsData -Path 'Data.Domains' -Default @{}
    foreach ($domain in @($dnsDomainMap.Keys)) {
        $d = $dnsDomainMap[$domain]

        $hasSelector1 = -not [string]::IsNullOrEmpty($d.DKIM.Selector1)
        $hasSelector2 = -not [string]::IsNullOrEmpty($d.DKIM.Selector2)
        $hasCustom    = @($d.DKIM.CustomSelectors ?? @()).Count -gt 0

        if ($hasSelector1 -and $hasSelector2) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain DKIM configured with both selector1 and selector2."
        } elseif ($hasSelector1 -or $hasCustom) {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Low' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain DKIM partially configured (selector1 present, selector2 missing or custom)." `
                -CurrentValue 'Partial DKIM' -RequiredValue 'Both selector1 and selector2 configured'
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain has no DKIM records for selector1 or selector2. Email can be modified in transit without detection." `
                -CurrentValue 'No DKIM records' -RequiredValue 'DKIM selector1 + selector2 CNAMEs published' `
                -Remediation $control.Remediation
        }
    }
}

# ── DNS-1.3 DMARC Policy at Quarantine or Reject ────────────────────────────
function Test-NRGControlDNSDMARC {
    [CmdletBinding()] param()

    $controlId = 'DNS-1.3'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    $dnsDomainCount = [int](Get-NRGNestedProperty -Object $dnsData -Path 'Data.DomainCount' -Default 0)
    if (-not $dnsData -or -not $dnsData.Success -or $dnsDomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    $dnsDomainMap = Get-NRGNestedProperty -Object $dnsData -Path 'Data.Domains' -Default @{}
    foreach ($domain in @($dnsDomainMap.Keys)) {
        $d = $dnsDomainMap[$domain]

        if (-not $d.DMARC) {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain has no DMARC record. Without DMARC, domain spoofing is possible even with SPF and DKIM." `
                -CurrentValue 'No DMARC record' -RequiredValue 'v=DMARC1; p=reject; rua=mailto:dmarc@domain' `
                -Remediation $control.Remediation
        } else {
            $policy = $d.DMARCPolicy ?? 'none'
            $pct    = $d.DMARCPct ?? 100

            switch ($policy) {
                'reject' {
                    $state    = if ($pct -eq 100) { 'Satisfied' } else { 'Partial' }
                    $severity = if ($pct -eq 100) { 'Informational' } else { 'Low' }
                    $detail   = if ($pct -eq 100) { "$domain DMARC p=reject (100%). Full spoofing protection." } else { "$domain DMARC p=reject but pct=$pct — not fully enforced. Set pct=100." }
                    Add-NRGFinding -ControlId $controlId -State $state -Category $control.Category `
                        -Title "$($control.Title): $domain" -Severity $severity -Instance $domain `
                        -FrameworkIds $citations -Detail $detail -CurrentValue $d.DMARC
                }
                'quarantine' {
                    Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                        -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                        -FrameworkIds $citations `
                        -Detail "$domain DMARC p=quarantine. Spoofed email goes to spam, not rejected. Advance to p=reject." `
                        -CurrentValue $d.DMARC -RequiredValue 'p=reject'
                }
                'none' {
                    Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                        -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                        -FrameworkIds $citations `
                        -Detail "$domain DMARC p=none — reporting only, NO protection. This is not a security control." `
                        -CurrentValue $d.DMARC -RequiredValue 'p=quarantine or p=reject' `
                        -Remediation $control.Remediation
                }
                default {
                    Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                        -Title "$($control.Title): $domain" -Severity 'High' -Instance $domain `
                        -FrameworkIds $citations `
                        -Detail "$domain DMARC record present but policy is unrecognized: '$policy'" `
                        -CurrentValue $d.DMARC
                }
            }
        }
    }
}

# ── DNS-1.4 MTA-STS in Enforce Mode ─────────────────────────────────────────
function Test-NRGControlDNSMTASTS {
    [CmdletBinding()] param()

    $controlId = 'DNS-1.4'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    $dnsDomainCount = [int](Get-NRGNestedProperty -Object $dnsData -Path 'Data.DomainCount' -Default 0)
    if (-not $dnsData -or -not $dnsData.Success -or $dnsDomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    $dnsDomainMap = Get-NRGNestedProperty -Object $dnsData -Path 'Data.Domains' -Default @{}
    foreach ($domain in @($dnsDomainMap.Keys)) {
        $d = $dnsDomainMap[$domain]

        if (-not $d.MTASTS.DNSRecord) {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain has no MTA-STS DNS record. SMTP connections to this domain can be TLS-downgraded." `
                -CurrentValue 'No MTA-STS record' -RequiredValue 'MTA-STS DNS record + policy file in enforce mode'
        } elseif ($d.MTASTS.Mode -eq 'enforce') {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain MTA-STS in enforce mode — TLS required for all inbound SMTP."
        } elseif ($d.MTASTS.Mode -eq 'testing') {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Low' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain MTA-STS in testing mode — reporting only, no enforcement. Advance to enforce after monitoring." `
                -CurrentValue 'mode: testing' -RequiredValue 'mode: enforce'
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain MTA-STS record present but policy mode is '$($d.MTASTS.Mode ?? 'unknown')'" `
                -CurrentValue "mode: $($d.MTASTS.Mode ?? 'unknown')" -RequiredValue 'mode: enforce'
        }
    }
}

# ── DNS-1.5 TLS-RPT Configured ───────────────────────────────────────────────
function Test-NRGControlDNSTLSRPT {
    [CmdletBinding()] param()

    $controlId = 'DNS-1.5'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    $dnsDomainCount = [int](Get-NRGNestedProperty -Object $dnsData -Path 'Data.DomainCount' -Default 0)
    if (-not $dnsData -or -not $dnsData.Success -or $dnsDomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    $dnsDomainMap = Get-NRGNestedProperty -Object $dnsData -Path 'Data.Domains' -Default @{}
    foreach ($domain in @($dnsDomainMap.Keys)) {
        $d = $dnsDomainMap[$domain]

        if ($d.TLSRPT) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations -Detail "$domain TLS-RPT configured."
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Low' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain has no TLS-RPT record. TLS failures on inbound SMTP will not be reported." `
                -CurrentValue 'No TLS-RPT record' `
                -RequiredValue 'v=TLSRPTv1; rua=mailto:tlsrpt@domain' `
                -Remediation $control.Remediation
        }
    }
}

# ── DNS-1.6 DNSSEC Enabled ───────────────────────────────────────────────────
function Test-NRGControlDNSDNSSEC {
    [CmdletBinding()] param()

    $controlId = 'DNS-1.6'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    $dnsDomainCount = [int](Get-NRGNestedProperty -Object $dnsData -Path 'Data.DomainCount' -Default 0)
    if (-not $dnsData -or -not $dnsData.Success -or $dnsDomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    $dnsDomainMap = Get-NRGNestedProperty -Object $dnsData -Path 'Data.Domains' -Default @{}
    foreach ($domain in @($dnsDomainMap.Keys)) {
        $d = $dnsDomainMap[$domain]

        if ($d.DNSSEC -eq $true) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations -Detail "$domain DNSSEC enabled (DS record found at parent zone)."
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Low' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain does not have DNSSEC enabled. DNS records can be spoofed (cache poisoning, on-path attacks)." `
                -CurrentValue 'DNSSEC not configured' `
                -RequiredValue 'DNSSEC enabled at registrar (DS record published)' `
                -Remediation $control.Remediation
        }
    }
}

# ── DNS-2.1 DKIM Key Rotation Cadence ───────────────────────────────────────
# Reads $d.DKIM.KeyAgeDays populated by the collector from
# Get-DkimSigningConfig.KeyCreationTime. Microsoft does not auto-rotate DKIM
# keys for customer-managed domains, so many tenants run 2+ year old keys.
# NIST SP 800-57 Part 1 §5.3.6 recommends a documented cryptoperiod for
# signing keys; 1y is industry standard, 2y is the outer bound.
function Test-NRGControlDNSDkimRotation {
    [CmdletBinding()] param()

    $controlId = 'DNS-2.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    $dnsDomainCount = [int](Get-NRGNestedProperty -Object $dnsData -Path 'Data.DomainCount' -Default 0)
    if (-not $dnsData -or -not $dnsData.Success -or $dnsDomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    $dnsDomainMap = Get-NRGNestedProperty -Object $dnsData -Path 'Data.Domains' -Default @{}
    foreach ($domain in @($dnsDomainMap.Keys)) {
        $d = $dnsDomainMap[$domain]

        # Defensive: DKIM block may be missing on older collector data
        $age = $null
        if ($d.PSObject.Properties['DKIM'] -or ($d -is [hashtable] -and $d.ContainsKey('DKIM'))) {
            $dkim = $d.DKIM
            if ($dkim) {
                if ($dkim -is [hashtable] -and $dkim.ContainsKey('KeyAgeDays')) {
                    $age = $dkim['KeyAgeDays']
                } elseif ($dkim.PSObject.Properties['KeyAgeDays']) {
                    $age = $dkim.KeyAgeDays
                }
            }
        }

        if ($null -eq $age) {
            Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain DKIM rotation age unknown — selector not found or M365 default key (no customer-managed KeyCreationTime)." `
                -CurrentValue 'KeyAgeDays: unknown'
            continue
        }

        $ageInt = [int]$age
        if ($ageInt -le 365) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain DKIM key age is $ageInt days — within the 365-day cryptoperiod recommended by NIST SP 800-57." `
                -CurrentValue "KeyAgeDays: $ageInt"
        } elseif ($ageInt -le 730) {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain DKIM key is $ageInt days old — over 1 year, rotation recommended (NIST SP 800-57 cryptoperiod guidance)." `
                -CurrentValue "KeyAgeDays: $ageInt" -RequiredValue 'KeyAgeDays <= 365' `
                -Remediation $control.Remediation
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain DKIM key is $ageInt days old — over 2 years, significant rotation gap. Long-lived signing keys increase the impact of a key-compromise event." `
                -CurrentValue "KeyAgeDays: $ageInt" -RequiredValue 'KeyAgeDays <= 365' `
                -Remediation $control.Remediation
        }
    }
}

# ── DNS-2.2 CAA Record Restricts Cert Issuance ──────────────────────────────
# Reads $d.CAA populated by the collector from Resolve-DnsName -Type CAA.
# Absence of CAA means any publicly trusted CA may issue certs for the domain.
# RFC 8659 — DNS Certification Authority Authorization.
function Test-NRGControlDNSCAA {
    [CmdletBinding()] param()

    $controlId = 'DNS-2.2'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    $dnsDomainCount = [int](Get-NRGNestedProperty -Object $dnsData -Path 'Data.DomainCount' -Default 0)
    if (-not $dnsData -or -not $dnsData.Success -or $dnsDomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    $dnsDomainMap = Get-NRGNestedProperty -Object $dnsData -Path 'Data.Domains' -Default @{}
    foreach ($domain in @($dnsDomainMap.Keys)) {
        $d = $dnsDomainMap[$domain]

        $caa = $null
        if ($d -is [hashtable] -and $d.ContainsKey('CAA')) { $caa = $d['CAA'] }
        elseif ($d.PSObject.Properties['CAA'])             { $caa = $d.CAA }

        if (-not $caa -or -not $caa.Present) {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "No CAA record published for $domain — any publicly trusted CA may issue certs for this domain. Phishing-driven mis-issuance has no DNS-level brake." `
                -CurrentValue 'No CAA record' `
                -RequiredValue 'CAA issue/issuewild record naming approved CA(s) per RFC 8659' `
                -Remediation $control.Remediation
            continue
        }

        $issuance = @($caa.IssuanceAllowed ?? @())
        $wildcard = @($caa.WildcardAllowed ?? @())

        # Treat ";" as RFC 8659 deny-all. If issuance is empty, or all entries are
        # the literal deny token, and no wildcard override is present, it is a
        # deny-all configuration — usually a misconfig, occasionally intentional.
        $issuanceTrim = @($issuance | ForEach-Object { ([string]$_).Trim() })
        $allDenyIssue = ($issuanceTrim.Count -eq 0) -or
                        (-not ($issuanceTrim | Where-Object { $_ -and $_ -ne ';' }))
        $hasWildcardOverride = ($wildcard.Count -gt 0)

        if ($allDenyIssue -and -not $hasWildcardOverride) {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain CAA is deny-all (no 'issue' or 'issuewild' values present) and no wildcard exception is set. Cert renewal from the org's actual CA will fail. Verify this is intentional." `
                -CurrentValue ("issue: [" + ($issuanceTrim -join ',') + "], issuewild: [" + (($wildcard -join ',')) + "]") `
                -RequiredValue 'At least one approved CA listed in issue= or issuewild='
        } else {
            $allowedList = @($issuance + $wildcard | Where-Object { $_ -and $_ -ne ';' } | Sort-Object -Unique)
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain has a restrictive CAA allowlist ($($allowedList.Count) CA entry/entries) — RFC 8659 compliant." `
                -CurrentValue ('Allowed CAs: ' + ($allowedList -join ', '))
        }
    }
}

# ── DNS-2.3 TLS Certificate Expiry on Mail Hostnames ────────────────────────
# Reads $d.TLSCerts.Autodiscover and $d.TLSCerts.MailHost populated by the
# collector from a port-443 SslStream probe. Surfaces the soonest expiry per
# domain so help desk can plan renewals.
function Test-NRGControlDNSTLSCertExpiry {
    [CmdletBinding()] param()

    $controlId = 'DNS-2.3'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    $dnsDomainCount = [int](Get-NRGNestedProperty -Object $dnsData -Path 'Data.DomainCount' -Default 0)
    if (-not $dnsData -or -not $dnsData.Success -or $dnsDomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    $dnsDomainMap = Get-NRGNestedProperty -Object $dnsData -Path 'Data.Domains' -Default @{}
    foreach ($domain in @($dnsDomainMap.Keys)) {
        $d = $dnsDomainMap[$domain]

        $tls = $null
        if ($d -is [hashtable] -and $d.ContainsKey('TLSCerts')) { $tls = $d['TLSCerts'] }
        elseif ($d.PSObject.Properties['TLSCerts'])             { $tls = $d.TLSCerts }

        # Pull collector-side per-domain errors (TimeBudget, refused SSRF
        # targets, etc.) so NotApplicable findings explain WHY no TLS data
        # exists. Differentiates "domain has no HTTPS endpoint" from "we
        # ran out of time budget before probing this domain".
        $domainErrs = @()
        if ($d -is [hashtable] -and $d.ContainsKey('Errors')) { $domainErrs = @($d['Errors']) }
        elseif ($d.PSObject.Properties['Errors'])             { $domainErrs = @($d.Errors) }
        $budgetSkipped = @($domainErrs | Where-Object { $_ -like 'TimeBudget:*TLS probe*' -or $_ -like '*before TLS probe*' })

        if (-not $tls) {
            $reason = if ($budgetSkipped.Count -gt 0) {
                'per-domain time budget exceeded before TLS probe ran — TLS expiry could not be assessed this run'
            } else {
                "$domain has no TLS cert data collected"
            }
            Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail $reason -CurrentValue 'No TLS probe results'
            continue
        }

        # Walk every TLSCerts.* sub-key (Autodiscover, MailHost, plus any
        # future additions). Track the soonest valid expiry.
        $soonestDays  = $null
        $soonestHost  = $null
        $probedCount  = 0
        $errorCount   = 0
        $allErrors    = @()

        $tlsKeys = if ($tls -is [hashtable]) { @($tls.Keys) }
                   else { @($tls.PSObject.Properties.Name) }

        foreach ($role in $tlsKeys) {
            $cert = if ($tls -is [hashtable]) { $tls[$role] } else { $tls.$role }
            if (-not $cert) { continue }
            $probedCount++

            $certHasError = $false
            $certError    = $null
            $certDays     = $null
            $certHost     = $null

            if ($cert -is [hashtable]) {
                if ($cert.ContainsKey('Error')) { $certError = $cert['Error']; $certHasError = [bool]$certError }
                if ($cert.ContainsKey('DaysUntilExpiry')) { $certDays = $cert['DaysUntilExpiry'] }
                if ($cert.ContainsKey('Hostname'))        { $certHost = $cert['Hostname'] }
            } else {
                if ($cert.PSObject.Properties['Error'])           { $certError = $cert.Error; $certHasError = [bool]$certError }
                if ($cert.PSObject.Properties['DaysUntilExpiry']) { $certDays = $cert.DaysUntilExpiry }
                if ($cert.PSObject.Properties['Hostname'])        { $certHost = $cert.Hostname }
            }

            if ($certHasError) {
                $errorCount++
                $allErrors += "${role}: $certError"
                continue
            }
            if ($null -eq $certDays) { continue }

            $certDaysInt = [int]$certDays
            if ($null -eq $soonestDays -or $certDaysInt -lt $soonestDays) {
                $soonestDays = $certDaysInt
                $soonestHost = "$role ($certHost)"
            }
        }

        if ($null -eq $soonestDays) {
            $errSummary = if ($errorCount -gt 0) { ' Probe errors: ' + ($allErrors -join '; ') } else { '' }
            $budgetSummary = if ($budgetSkipped.Count -gt 0) {
                ' Note: per-domain time budget exceeded before some probes ran.'
            } else { '' }
            Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain has no TLS cert collected for autodiscover or mail hostnames — endpoints may not run HTTPS on 443 or are blocked.${errSummary}${budgetSummary}" `
                -CurrentValue 'No TLS cert collected'
            continue
        }

        $hostLabel = $soonestHost
        if ($soonestDays -lt 7) {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "CRITICAL: $hostLabel TLS cert expires in $soonestDays day(s). HTTPS will fail for users and break autodiscover within the week." `
                -CurrentValue "DaysUntilExpiry: $soonestDays on $hostLabel" `
                -RequiredValue 'DaysUntilExpiry >= 90' `
                -Remediation $control.Remediation
        } elseif ($soonestDays -lt 30) {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$hostLabel TLS cert expires in $soonestDays days — renewal window is closing. NIST SC-17 requires PKI lifecycle management." `
                -CurrentValue "DaysUntilExpiry: $soonestDays on $hostLabel" `
                -RequiredValue 'DaysUntilExpiry >= 90' `
                -Remediation $control.Remediation
        } elseif ($soonestDays -lt 90) {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$hostLabel TLS cert expires in $soonestDays days — schedule renewal." `
                -CurrentValue "DaysUntilExpiry: $soonestDays on $hostLabel" `
                -RequiredValue 'DaysUntilExpiry >= 90'
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain TLS certs valid; soonest expiry is $hostLabel at $soonestDays days." `
                -CurrentValue "DaysUntilExpiry: $soonestDays on $hostLabel"
        }
    }
}

# ── DNS-2.4 Certificate Transparency Log Hygiene ────────────────────────────
# Reads $d.CTLog populated by the collector from a crt.sh JSON query.
# Surfaces certs issued for the domain by unknown CAs — possible mis-issuance.
# RFC 6962 — Certificate Transparency.
function Test-NRGControlDNSCertTransparency {
    [CmdletBinding()] param()

    $controlId = 'DNS-2.4'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    # Known-good CA fragments. Matched case-insensitively against the full
    # crt.sh issuer_name string ("C=US, O=Let's Encrypt, CN=R3" etc.).
    $knownGoodCAs = @(
        'DigiCert', "Let's Encrypt", 'Lets Encrypt', 'Sectigo',
        'GlobalSign', 'GoDaddy', 'Starfield', 'Microsoft',
        'Comodo', 'Amazon', 'Entrust', 'Buypass', 'IdenTrust'
    )

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    $dnsDomainCount = [int](Get-NRGNestedProperty -Object $dnsData -Path 'Data.DomainCount' -Default 0)
    if (-not $dnsData -or -not $dnsData.Success -or $dnsDomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    $dnsDomainMap = Get-NRGNestedProperty -Object $dnsData -Path 'Data.Domains' -Default @{}
    foreach ($domain in @($dnsDomainMap.Keys)) {
        $d = $dnsDomainMap[$domain]

        $ct = $null
        if ($d -is [hashtable] -and $d.ContainsKey('CTLog')) { $ct = $d['CTLog'] }
        elseif ($d.PSObject.Properties['CTLog'])             { $ct = $d.CTLog }

        # Pull collector-side per-domain errors so we can distinguish
        # "crt.sh actually returned zero certs" (genuine finding) from
        # "we skipped crt.sh because the time budget expired" (clarity).
        $domainErrs = @()
        if ($d -is [hashtable] -and $d.ContainsKey('Errors')) { $domainErrs = @($d['Errors']) }
        elseif ($d.PSObject.Properties['Errors'])             { $domainErrs = @($d.Errors) }
        $ctSkipped = @($domainErrs | Where-Object { $_ -like '*crt.sh*' -or $_ -like '*after TLS probe*' })

        if (-not $ct) {
            $reason = if ($ctSkipped.Count -gt 0) {
                'per-domain time budget exceeded before crt.sh query ran — CT log hygiene could not be evaluated this run'
            } else {
                "$domain has no CT log data collected"
            }
            Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail $reason -CurrentValue 'No CTLog block'
            continue
        }

        $queryError = $null
        $totalCerts = 0
        $issuers    = @()
        if ($ct -is [hashtable]) {
            if ($ct.ContainsKey('QueryError')) { $queryError = $ct['QueryError'] }
            if ($ct.ContainsKey('TotalCerts')) { $totalCerts = [int]($ct['TotalCerts'] ?? 0) }
            if ($ct.ContainsKey('Issuers'))    { $issuers    = @($ct['Issuers'] ?? @()) }
        } else {
            if ($ct.PSObject.Properties['QueryError']) { $queryError = $ct.QueryError }
            if ($ct.PSObject.Properties['TotalCerts']) { $totalCerts = [int]($ct.TotalCerts ?? 0) }
            if ($ct.PSObject.Properties['Issuers'])    { $issuers    = @($ct.Issuers ?? @()) }
        }

        if ($queryError) {
            # Detect rate-limit responses (HTTP 429 / "Too Many Requests" /
            # explicit rate-limit text) so the operator sees the real reason
            # the second/third domain returned no CT data on the same run.
            $isRateLimited = $queryError -match '(?i)429|rate.?limit|too many'
            $reasonHint    = if ($isRateLimited) {
                "crt.sh rate-limited the query (HTTP 429 / rate-limit response). Re-run with a longer per-domain budget or stagger DNS collection."
            } else {
                "crt.sh query failed for ${domain}: $queryError"
            }
            Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$reasonHint. CT log hygiene cannot be evaluated this run." `
                -CurrentValue "QueryError: $queryError"
            continue
        }

        if ($totalCerts -eq 0) {
            # If the time budget cut off crt.sh and TotalCerts stayed at the
            # initialized zero, demote to NotApplicable so we don't blame the
            # tenant for the collector's truncation. The collector signals
            # this in $d.Errors with a 'TimeBudget:' message.
            if ($ctSkipped.Count -gt 0) {
                Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                    -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                    -FrameworkIds $citations `
                    -Detail "$domain CT log query was skipped: per-domain time budget exceeded before crt.sh ran." `
                    -CurrentValue 'TotalCerts: 0 (collector truncated)'
                continue
            }
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain has zero certs in CT logs — either the domain is unused for HTTPS, or CT monitoring is a blind spot for detecting mis-issuance against this domain." `
                -CurrentValue 'TotalCerts: 0' `
                -RequiredValue 'At least one cert in CT logs from an approved CA' `
                -Remediation $control.Remediation
            continue
        }

        # Classify issuers — anything not matching the known-good fragment list
        # is flagged as suspicious. We allow either an exact substring match or
        # a regex-escaped match to keep this resilient to issuer string variants.
        $suspicious = @()
        foreach ($issuer in $issuers) {
            $iLower  = ([string]$issuer).ToLowerInvariant()
            $matched = $false
            foreach ($ca in $knownGoodCAs) {
                if ($iLower.Contains($ca.ToLowerInvariant())) { $matched = $true; break }
            }
            if (-not $matched) { $suspicious += [string]$issuer }
        }

        if ($suspicious.Count -eq 0) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain has $totalCerts cert(s) in CT logs, all from recognized CAs ($($issuers.Count) issuer(s))." `
                -CurrentValue ("TotalCerts: $totalCerts; Issuers: " + (($issuers | Select-Object -First 5) -join '; '))
        } else {
            $top = ($suspicious | Select-Object -First 3) -join '; '
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain CT logs include $($suspicious.Count) cert(s) from issuer(s) not on the known-good CA list. Investigate possible mis-issuance: $top" `
                -CurrentValue "Suspicious issuers: $top" `
                -RequiredValue 'All CT-log issuers match the org-approved CA allowlist' `
                -Remediation $control.Remediation
        }
    }
}
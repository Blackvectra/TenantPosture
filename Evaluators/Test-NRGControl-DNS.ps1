#Requires -Version 7.0
#
# Test-NRGControl-DNS.ps1  (v4.5.5)
# Evaluates DNS email authentication controls.
# SCORING ONLY — no DNS queries, reads from module state.
#
# NIST SP 800-53: SI-8, SC-8, SC-13
# MITRE ATT&CK:   T1566, T1036.005, T1557, T1600.001
#

# ── DNS-1.1 SPF Published and Valid ─────────────────────────────────────────
function Test-NRGControlDNSSPF {
    [CmdletBinding()] param()

    $controlId = 'DNS-1.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if (-not $dnsData -or -not $dnsData.Success -or $dnsData.Data.DomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d = $dnsData.Data.Domains[$domain]

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
    if (-not $dnsData -or -not $dnsData.Success -or $dnsData.Data.DomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d = $dnsData.Data.Domains[$domain]

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
    if (-not $dnsData -or -not $dnsData.Success -or $dnsData.Data.DomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d = $dnsData.Data.Domains[$domain]

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
    if (-not $dnsData -or -not $dnsData.Success -or $dnsData.Data.DomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d = $dnsData.Data.Domains[$domain]

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
    if (-not $dnsData -or -not $dnsData.Success -or $dnsData.Data.DomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d = $dnsData.Data.Domains[$domain]

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
    if (-not $dnsData -or -not $dnsData.Success -or $dnsData.Data.DomainCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d = $dnsData.Data.Domains[$domain]

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
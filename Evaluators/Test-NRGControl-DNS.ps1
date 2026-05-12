#
# Test-NRGControl-DNS.ps1
# Evaluates DNS email security controls (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC).
#
# Functions:
#   Test-NRGControlDNSSPF     DNS-1.1
#   Test-NRGControlDNSDKIM    DNS-1.2
#   Test-NRGControlDNSDMARC   EXO-2.1
#   Test-NRGControlDNSMTASTS  DNS-2.1
#   Test-NRGControlDNSTLSRPT  DNS-2.2
#   Test-NRGControlDNSDNSSEC  DNS-2.3
#

function Test-NRGControlDNSSPF {
    [CmdletBinding()] param()

    $controlId = 'DNS-1.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if (-not $dnsData -or -not $dnsData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d         = $dnsData.Data.Domains[$domain]
        $citations = Get-NRGFrameworkCitations -ControlId $controlId

        if (-not $d.SPF) {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity `
                -Instance $domain `
                -Detail "Domain '$domain' has no SPF record." `
                -CurrentValue 'No SPF record' -RequiredValue 'SPF with -all or ~all' `
                -FrameworkIds $citations -Remediation $control.Remediation
        } elseif ($d.SPF -match '\-all\s*$') {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -Detail "$domain has SPF with hard fail (-all)." `
                -CurrentValue $d.SPF -RequiredValue 'SPF -all' -FrameworkIds $citations
        } elseif ($d.SPF -match '~all\s*$') {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Low' -Instance $domain `
                -Detail "$domain SPF uses soft fail (~all). Acceptable but -all is preferred." `
                -CurrentValue $d.SPF -RequiredValue 'SPF -all' -FrameworkIds $citations
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -Detail "$domain SPF present but does not end with -all or ~all." `
                -CurrentValue $d.SPF -RequiredValue 'SPF -all' -FrameworkIds $citations
        }
    }
}

function Test-NRGControlDNSDKIM {
    [CmdletBinding()] param()

    $controlId = 'DNS-1.2'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if (-not $dnsData -or -not $dnsData.Success) { return }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d         = $dnsData.Data.Domains[$domain]
        $citations = Get-NRGFrameworkCitations -ControlId $controlId

        $hasSelector1 = -not [string]::IsNullOrWhiteSpace($d.DKIM.Selector1)
        $hasSelector2 = -not [string]::IsNullOrWhiteSpace($d.DKIM.Selector2)

        if ($hasSelector1 -and $hasSelector2) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -Detail "Both DKIM selectors published for $domain." `
                -CurrentValue "selector1: $($d.DKIM.Selector1); selector2: $($d.DKIM.Selector2)" `
                -RequiredValue 'selector1 + selector2 CNAMEs' -FrameworkIds $citations
        } elseif ($hasSelector1 -or $hasSelector2) {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -Detail "Only one DKIM selector found for $domain. Both selector1 and selector2 should be published." `
                -CurrentValue 'Partial DKIM' -RequiredValue 'Both selectors' -FrameworkIds $citations
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain has no DKIM selectors published. Email cannot achieve DKIM-aligned DMARC pass." `
                -CurrentValue 'No DKIM' -RequiredValue 'selector1 + selector2 CNAMEs' `
                -FrameworkIds $citations -Remediation $control.Remediation
        }
    }
}

function Test-NRGControlDNSDMARC {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if (-not $dnsData -or -not $dnsData.Success) { return }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d         = $dnsData.Data.Domains[$domain]
        $citations = Get-NRGFrameworkCitations -ControlId $controlId

        if (-not $d.DMARC) {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Critical' -Instance $domain `
                -Detail "$domain has no DMARC record. Domain can be spoofed with impunity." `
                -CurrentValue 'No DMARC' -RequiredValue 'p=reject' `
                -FrameworkIds $citations -Remediation $control.Remediation
        } elseif ($d.DMARC -match 'p=reject') {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -Detail "$domain DMARC at p=reject - exact-domain spoofing prevented." `
                -CurrentValue $d.DMARC -RequiredValue 'p=reject' -FrameworkIds $citations
        } elseif ($d.DMARC -match 'p=quarantine') {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -Detail "$domain DMARC at p=quarantine. Move to p=reject after verifying clean mail stream." `
                -CurrentValue $d.DMARC -RequiredValue 'p=reject' -FrameworkIds $citations
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'High' -Instance $domain `
                -Detail "$domain DMARC at p=none provides monitoring only - zero protection against spoofing." `
                -CurrentValue $d.DMARC -RequiredValue 'p=reject' `
                -FrameworkIds $citations -Remediation $control.Remediation
        }
    }
}

function Test-NRGControlDNSMTASTS {
    [CmdletBinding()] param()

    $controlId = 'DNS-2.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if (-not $dnsData -or -not $dnsData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d         = $dnsData.Data.Domains[$domain]
        $citations = Get-NRGFrameworkCitations -ControlId $controlId
        $mtasts    = $d.MTASTS

        if (-not $mtasts) {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain has no MTA-STS policy. Inbound email can be downgraded to plaintext by a MITM attack." `
                -CurrentValue 'No MTA-STS' -RequiredValue 'MTA-STS enforce mode' `
                -FrameworkIds $citations -Remediation $control.Remediation
        } elseif ($mtasts -eq 'enforce') {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -Detail "$domain MTA-STS in enforce mode. Sending servers must use TLS." `
                -CurrentValue 'enforce' -RequiredValue 'enforce' -FrameworkIds $citations
        } elseif ($mtasts -eq 'testing') {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -Detail "$domain MTA-STS in testing mode. Policy is not enforced — still vulnerable to TLS downgrade." `
                -CurrentValue 'testing' -RequiredValue 'enforce' -FrameworkIds $citations `
                -Remediation 'Update MTA-STS policy file: mode: enforce'
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -Detail "$domain MTA-STS policy state: $mtasts" `
                -CurrentValue $mtasts -RequiredValue 'enforce' -FrameworkIds $citations
        }
    }
}

function Test-NRGControlDNSTLSRPT {
    [CmdletBinding()] param()

    $controlId = 'DNS-2.2'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if (-not $dnsData -or -not $dnsData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d         = $dnsData.Data.Domains[$domain]
        $citations = Get-NRGFrameworkCitations -ControlId $controlId
        $tlsrpt    = $d.TLSRPT

        if ($tlsrpt) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -Detail "$domain TLS-RPT configured. TLS delivery failure reports will be received." `
                -CurrentValue $tlsrpt -RequiredValue 'TLS-RPT record present' -FrameworkIds $citations
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain has no TLS-RPT record. MTA-STS and STARTTLS failure reports will not be received." `
                -CurrentValue 'No TLS-RPT' -RequiredValue '_smtp._tls TXT record with rua= destination' `
                -FrameworkIds $citations -Remediation $control.Remediation
        }
    }
}

function Test-NRGControlDNSDNSSEC {
    [CmdletBinding()] param()

    $controlId = 'DNS-2.3'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if (-not $dnsData -or -not $dnsData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'DNS data not collected'
        return
    }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d         = $dnsData.Data.Domains[$domain]
        $citations = Get-NRGFrameworkCitations -ControlId $controlId
        $dnssec    = $d.DNSSEC

        if ($dnssec -eq $true -or $dnssec -eq 'Enabled' -or $dnssec -eq 'signed') {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -Detail "$domain has DNSSEC enabled (DS records present). DNS records are cryptographically signed." `
                -CurrentValue 'DNSSEC: Enabled' -RequiredValue 'DNSSEC signed' -FrameworkIds $citations
        } elseif ($dnssec -eq $false -or $dnssec -eq 'Disabled' -or $dnssec -eq 'unsigned') {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain has no DNSSEC. DNS records can be spoofed via cache poisoning attacks, redirecting email to attacker-controlled servers." `
                -CurrentValue 'DNSSEC: Disabled' -RequiredValue 'DNSSEC signed at registrar' `
                -FrameworkIds $citations -Remediation $control.Remediation
        } else {
            Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                -Title "$($control.Title): $domain" -Instance $domain `
                -Detail "DNSSEC status for $domain could not be determined."
        }
    }
}

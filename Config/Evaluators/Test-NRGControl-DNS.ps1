#
# Test-NRGControl-DNS.ps1
# Evaluates DNS email security controls.
#
# Controls:
#   DNS-1.1  SPF record published
#   DNS-1.2  DKIM signing enabled
#   EXO-2.1  DMARC enforcement policy  (uses EXO control ID - DMARC lives in DNS but is email security)
#   DNS-2.1  MTA-STS policy enforced
#   DNS-2.2  TLS-RPT configured
#   DNS-2.3  DNSSEC enabled
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
        $d = $dnsData.Data.Domains[$domain]
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
        $d = $dnsData.Data.Domains[$domain]
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
        $d = $dnsData.Data.Domains[$domain]
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
        $d       = $dnsData.Data.Domains[$domain]
        $mta     = $d.MTASTS
        $policyUrl = "https://mta-sts.$domain/.well-known/mta-sts.txt"

        if (-not $mta -or -not $mta.TxtRecord) {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain has no MTA-STS TXT record (_mta-sts.$domain). SMTP TLS downgrade attacks are possible." `
                -CurrentValue 'No MTA-STS' -RequiredValue 'MTA-STS mode: enforce' `
                -Remediation $control.Remediation -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
        }
        elseif ($mta.Mode -eq 'enforce') {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -Detail "$domain MTA-STS in enforce mode. Sending servers must use TLS." `
                -CurrentValue "Mode: enforce | TXT: $($mta.TxtRecord) | Policy URL: $policyUrl" `
                -RequiredValue 'Mode: enforce' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
        }
        elseif ($mta.Mode -eq 'testing') {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain MTA-STS in testing mode — reports TLS failures but does not enforce. Zero enforcement protection." `
                -CurrentValue "Mode: testing | Policy URL: $policyUrl" `
                -RequiredValue 'Mode: enforce' `
                -Remediation 'Change mode: testing to mode: enforce in policy file at https://mta-sts.[domain]/.well-known/mta-sts.txt. Update the TXT record id timestamp to force policy refresh.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
        }
        elseif ($mta.Mode -eq 'none') {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain MTA-STS mode=none explicitly disables enforcement. Equivalent to no MTA-STS." `
                -CurrentValue "Mode: none | Policy URL: $policyUrl" `
                -RequiredValue 'Mode: enforce' `
                -Remediation 'Update policy file mode from none to enforce. Stage via testing first to verify no TLS failures.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
        }
        else {
            # TXT record exists but policy file couldn't be fetched or mode not parsed
            $modeDisplay = if ($mta.Mode) { $mta.Mode } else { 'unreadable' }
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain has MTA-STS TXT record but policy file mode could not be determined (mode: $modeDisplay). Policy file may be unreachable." `
                -CurrentValue "TXT record present | Mode: $modeDisplay | Policy URL: $policyUrl" `
                -RequiredValue 'Mode: enforce' `
                -Remediation "Verify policy file is reachable at $policyUrl and contains 'mode: enforce'." `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
        }
    }
}

function Test-NRGControlDNSTLSRPT {
    [CmdletBinding()] param()

    $controlId = 'DNS-2.2'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if (-not $dnsData -or -not $dnsData.Success) { return }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d = $dnsData.Data.Domains[$domain]

        if ($d.TLSRPT) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -Detail "$domain TLS-RPT configured. TLS delivery failure reports will be received." `
                -CurrentValue $d.TLSRPT -RequiredValue 'v=TLSRPTv1 record present' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
        }
        else {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain has no TLS-RPT record (_smtp._tls.$domain). MTA-STS enforcement failures will be silent." `
                -CurrentValue 'No TLS-RPT' -RequiredValue 'v=TLSRPTv1 record at _smtp._tls.[domain]' `
                -Remediation $control.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
        }
    }
}

function Test-NRGControlDNSDNSSEC {
    [CmdletBinding()] param()

    $controlId = 'DNS-2.3'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if (-not $dnsData -or -not $dnsData.Success) { return }

    foreach ($domain in $dnsData.Data.Domains.Keys) {
        $d = $dnsData.Data.Domains[$domain]

        if ($d.DNSSEC -eq $true) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -Detail "$domain has DNSSEC enabled (DS records present). DNS records are cryptographically signed." `
                -CurrentValue 'DNSSEC: enabled' -RequiredValue 'DS records published' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
        }
        else {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain does not have DNSSEC enabled. DNS cache poisoning could redirect SPF/DMARC/MTA-STS lookups." `
                -CurrentValue 'DNSSEC: not detected' -RequiredValue 'DS records published at registrar' `
                -Remediation $control.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
        }
    }
}

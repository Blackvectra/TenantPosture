#
# Test-NRGControl-DNS.ps1
# Evaluates DNS email security controls (SPF, DKIM, DMARC).
#

function Test-NRGControl-DNS-SPF {
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

function Test-NRGControl-DNS-DKIM {
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
                -CurrentValue "Partial DKIM" -RequiredValue 'Both selectors' -FrameworkIds $citations
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity $control.Severity -Instance $domain `
                -Detail "$domain has no DKIM selectors published. Email cannot achieve DKIM-aligned DMARC pass." `
                -CurrentValue 'No DKIM' -RequiredValue 'selector1 + selector2 CNAMEs' `
                -FrameworkIds $citations -Remediation $control.Remediation
        }
    }
}

function Test-NRGControl-DNS-DMARC {
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

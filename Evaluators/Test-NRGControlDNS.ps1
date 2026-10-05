#Requires -Version 7.0
#
# Test-NRGControlDNS.ps1  (v4.6.1)
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Evaluates DNS email authentication + PKI hygiene controls.
# SCORING ONLY — no DNS / HTTPS queries, reads from module state set by
# Invoke-NRGCollectDNSEmailRecords.
#
# Consumes:     DNS-EmailRecords (Data.Domains.<domain>, incl. LookupStatus, Errors)
# Sets:         findings only (Add-NRGFinding)
# Cmdlets:      none (no Graph / EXO)
# Dependencies: Get-NRGRawData, Get-NRGControlDefinitions, Get-NRGFrameworkCitations,
#               Get-NRGObjectField, Test-NRGDnsLookupSucceeded, Add-NRGFinding
#
# NIST SP 800-53: SI-8, SC-8, SC-12, SC-13, SC-17, AU-6, CM-7
# MITRE ATT&CK:   T1566, T1036.005, T1557, T1600.001, T1583.001
#

# ── Shared guard: a failed lookup is not an absent record ────────────────────
# Emits the NotApplicable finding for a record whose lookup did not complete and
# returns $true so the caller can `continue` past the domain. One implementation
# because the first version of this guard was pasted six times — which is how
# the DKIM evaluator was missed, and how an omitted -FrameworkIds propagated to
# all six. That omission mattered: a NotApplicable finding with no NIST
# citation is dropped by the 800-53 family rollup as unmapped, so it never
# reached the NIST matrix's "Not Assessed" sheet, the one surface that exists
# to say "this control could not be assessed". The reader of the NIST-only
# deliverable saw neither a verdict nor a not-assessed row. Every finding this
# helper emits carries the control's citations, matching the per-domain
# NotApplicable findings DNS-2.1 / 2.3 / 2.4 already emit.
function Add-NRGDnsLookupFailedFinding {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [object]   $Control,
        [Parameter(Mandatory)] [string]   $ControlId,
        # [AllowNull()] because Get-NRGFrameworkCitations yields $null, not
        # @(), for a control with no References — a binding error here would
        # replace the finding with a crash.
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [string[]] $Citations,
        [Parameter(Mandatory)] [string]   $Domain,
        [Parameter(Mandatory)] [AllowNull()] [object] $DomainEntry,
        # Key in the collector's LookupStatus map.
        [Parameter(Mandatory)] [string]   $Record,
        # Human name for the Detail text; defaults to the key.
        [string] $Label
    )
    if (Test-NRGDnsLookupSucceeded -Domain $DomainEntry -Record $Record) { return $false }
    if (-not $Label) { $Label = $Record }

    # Surface the collector's reason when it recorded one, so the operator
    # reading the finding does not have to open the results JSON to learn
    # whether it was SERVFAIL, a proxy, or a timeout.
    $why  = ''
    $errs = @(Get-NRGObjectField -Item $DomainEntry -Key 'Errors' -Default @())
    $hit  = @($errs | Where-Object { [string]$_ -like "${Record}:*" -or [string]$_ -like "${Label} *" }) | Select-Object -First 1
    if ($hit) { $why = " Reason: $hit" }

    Add-NRGFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category `
        -Title "$($Control.Title): $Domain" -Severity 'Informational' -Instance $Domain `
        -FrameworkIds $Citations `
        -Detail "The $Label lookup for '$Domain' did not complete (every resolver failed). Not assessed — re-run before treating this domain as lacking $Label.$why"
    return $true
}

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

        if (Add-NRGDnsLookupFailedFinding -Control $control -ControlId $controlId -Citations $citations `
                -Domain $domain -DomainEntry $d -Record 'SPF' -Label 'SPF') { continue }

        $spfCount = [int](Get-NRGObjectField -Item $d -Key 'SPFRecordCount' -Default 1)
        $redirect = Get-NRGObjectField -Item $d -Key 'SPFRedirect' -Default $null
        $common   = @{ Category = $control.Category; Title = "$($control.Title): $domain"; Instance = $domain; FrameworkIds = $citations }

        if (-not $d.SPF) {
            Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity $control.Severity `
                -Detail "Domain '$domain' has no SPF record. Anyone can send email claiming to be from this domain." `
                -CurrentValue 'No SPF record' -RequiredValue "v=spf1 include:spf.protection.outlook.com -all" `
                -Remediation $control.Remediation
            continue
        }
        if ($spfCount -gt 1) {
            # RFC 7208 §4.5: more than one v=spf1 record is a permerror — SPF
            # fails for every message, whatever each record says.
            Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity 'High' `
                -Detail "$domain publishes $spfCount SPF records. More than one is a permanent error (RFC 7208 §4.5): receivers treat SPF as failed for all mail. Merge them into one record." `
                -CurrentValue "$spfCount v=spf1 records" -RequiredValue 'Exactly one SPF record ending in -all' -Remediation $control.Remediation
            continue
        }

        # Top-level DNS-lookup terms (RFC 7208 §4.6.4 limit is 10, counted
        # recursively; only this record's own terms are counted here, so
        # more than 10 is certain, 10 or fewer is not proof).
        $terms   = @(([string]$d.SPF) -split '\s+' | Where-Object { $_ })
        $lookups = @($terms | Where-Object { $_ -match '^[+\-~?]?(include:|a$|a:|a/|mx$|mx:|mx/|ptr|exists:)' -or $_ -match '^redirect=' }).Count
        if ($lookups -gt 10) {
            Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity 'High' `
                -Detail "$domain SPF has $lookups DNS-lookup terms in its own record; the limit is 10 (RFC 7208 §4.6.4), so SPF evaluation ends in a permanent error and fails." `
                -CurrentValue $d.SPF -RequiredValue 'At most 10 DNS lookups including nested includes' -Remediation $control.Remediation
            continue
        }

        $record = [string]$d.SPF
        $via    = ''
        $allTerm = @($terms | Where-Object { $_ -match '^[+\-~?]?all$' }) | Select-Object -First 1
        if (-not $allTerm -and $redirect) {
            $rRec = Get-NRGObjectField -Item $redirect -Key 'Record' -Default $null
            $rOut = [string](Get-NRGObjectField -Item $redirect -Key 'Outcome' -Default 'LookupFailed')
            $rTgt = [string](Get-NRGObjectField -Item $redirect -Key 'Target' -Default '?')
            if (-not $rRec) {
                if ($rOut -eq 'NoRecord') {
                    Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity 'High' `
                        -Detail "$domain SPF redirects to $rTgt, which publishes no single SPF record — a permanent error (RFC 7208 §6.1)." `
                        -CurrentValue $record -RequiredValue 'redirect= target with one valid SPF record' -Remediation $control.Remediation
                } else {
                    Add-NRGFinding -ControlId $controlId @common -State 'NotApplicable' -Severity 'Informational' `
                        -Detail "$domain SPF redirects to $rTgt, and that record could not be read, so the policy was not assessed." `
                        -CurrentValue $record
                }
                continue
            }
            $allTerm = @(([string]$rRec) -split '\s+' | Where-Object { $_ -match '^[+\-~?]?all$' }) | Select-Object -First 1
            $via = " (via redirect to $rTgt)"
        }

        $qualifier = if ($allTerm) { if ($allTerm -match '^([+\-~?])') { $Matches[1] } else { '+' } } else { $null }
        switch ($qualifier) {
            '-' {
                Add-NRGFinding -ControlId $controlId @common -State 'Satisfied' -Severity 'Informational' `
                    -Detail "$domain SPF with hard fail (-all) configured$via." -CurrentValue $record
            }
            '~' {
                Add-NRGFinding -ControlId $controlId @common -State 'Partial' -Severity 'Low' `
                    -Detail "$domain SPF uses soft fail (~all)$via. Acceptable for compatibility, but -all provides stronger protection." `
                    -CurrentValue $record -RequiredValue 'SPF ending in -all'
            }
            '+' {
                # "+all" (or a bare "all") AUTHORIZES every sender on the
                # internet — worse than having no SPF at all.
                Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity 'High' `
                    -Detail "$domain SPF ends in '$allTerm'$via, which authorizes EVERY server on the internet to send as this domain. Change to -all." `
                    -CurrentValue $record -RequiredValue 'SPF ending in -all' -Remediation $control.Remediation
            }
            default {
                # '?all', or no 'all' and no redirect: both evaluate to neutral
                # (RFC 7208 §4.7), which gives no protection.
                $what = if ($qualifier -eq '?') { "uses neutral (?all)$via" } else { "has no 'all' mechanism and no redirect, so unlisted senders evaluate to neutral" }
                Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity 'High' `
                    -Detail "$domain SPF $what — provides no spoofing protection. End the record with -all." `
                    -CurrentValue $record -RequiredValue 'SPF ending in -all' -Remediation $control.Remediation
            }
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

        if (Add-NRGDnsLookupFailedFinding -Control $control -ControlId $controlId -Citations $citations `
                -Domain $domain -DomainEntry $d -Record 'DKIM' -Label 'DKIM') { continue }

        $hasSelector1 = -not [string]::IsNullOrEmpty($d.DKIM.Selector1)
        $hasSelector2 = -not [string]::IsNullOrEmpty($d.DKIM.Selector2)
        $hasCustom    = @($d.DKIM.CustomSelectors ?? @()).Count -gt 0

        if ($hasSelector1 -and $hasSelector2) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain DKIM configured with both selector1 and selector2."
        } elseif ($hasSelector1 -or $hasSelector2 -or $hasCustom) {
            $which = if ($hasSelector1) { 'selector1 is published, selector2 is not' } elseif ($hasSelector2) { 'selector2 is published, selector1 is not' } else { 'only a custom selector is published' }
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Low' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain DKIM partially configured: $which. Microsoft 365 needs both CNAMEs to rotate keys." `
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

# rua addresses of a DMARC record, lower-case, mailto: and !size stripped.
function Get-NRGDmarcReportAddresses {
    [CmdletBinding()] [OutputType([string[]])]
    param([AllowNull()] [string] $Record)
    if ([string]::IsNullOrWhiteSpace($Record)) { return @() }
    $m = [regex]::Match($Record, '(?i)(?:^|;)\s*rua\s*=\s*([^;]*)')
    if (-not $m.Success) { return @() }
    return @($m.Groups[1].Value -split ',' | ForEach-Object { ($_.Trim() -replace '(?i)^mailto:', '' -replace '!\d+[kmgt]?$', '').Trim().ToLowerInvariant() } | Where-Object { $_ })
}

# $Wanted is an address or an @domain.
function Test-NRGDmarcReportAddress {
    [CmdletBinding()] [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Wanted, [AllowNull()] [string[]] $Present)
    $w = $Wanted.Trim().ToLowerInvariant()
    foreach ($a in @($Present)) {
        if ($w.StartsWith('@')) { if ($a.EndsWith($w)) { return $true } }
        elseif ($a -eq $w) { return $true }
    }
    return $false
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

        if (Add-NRGDnsLookupFailedFinding -Control $control -ControlId $controlId -Citations $citations `
                -Domain $domain -DomainEntry $d -Record 'DMARC' -Label 'DMARC') { continue }

        $common   = @{ Category = $control.Category; Title = "$($control.Title): $domain"; Instance = $domain; FrameworkIds = $citations }
        $count    = [int](Get-NRGObjectField -Item $d -Key 'DMARCRecordCount' -Default 1)
        $from     = Get-NRGObjectField -Item $d -Key 'DMARCInheritedFrom' -Default $null
        $origin   = if ($from) { " (no record of its own; the organizational domain $from's policy applies)" } else { '' }

        if (-not $d.DMARC) {
            Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity $control.Severity `
                -Detail "$domain has no DMARC record. Without DMARC, domain spoofing is possible even with SPF and DKIM." `
                -CurrentValue 'No DMARC record' -RequiredValue 'v=DMARC1; p=reject; rua=mailto:dmarc@domain' `
                -Remediation $control.Remediation
            continue
        }
        if ($count -gt 1) {
            Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity $control.Severity `
                -Detail "$domain publishes $count DMARC records$origin. With more than one, receivers apply no DMARC policy at all (RFC 7489 §6.6.3). Keep one." `
                -CurrentValue "$count v=DMARC1 records" -RequiredValue 'Exactly one DMARC record' -Remediation $control.Remediation
            continue
        }

        $policy = [string](Get-NRGObjectField -Item $d -Key 'DMARCPolicy' -Default 'none')
        $pct    = [int](Get-NRGObjectField -Item $d -Key 'DMARCPct' -Default 100)
        $sp     = [string](Get-NRGObjectField -Item $d -Key 'DMARCSubPolicy' -Default '')

        switch ($policy) {
            { $_ -in @('reject','quarantine') } {
                $action = if ($policy -eq 'reject') { 'rejected' } else { 'sent to quarantine' }
                if ($pct -lt 100) {
                    Add-NRGFinding -ControlId $controlId @common -State 'Partial' -Severity 'Low' `
                        -Detail "$domain DMARC p=$policy but pct=${pct}${origin}: only $pct% of failing mail is $action. Set pct=100." `
                        -CurrentValue $d.DMARC -RequiredValue "p=$policy with pct=100"
                } elseif (-not $from -and $sp -eq 'none') {
                    Add-NRGFinding -ControlId $controlId @common -State 'Partial' -Severity 'Medium' `
                        -Detail "$domain DMARC p=$policy, but sp=none leaves every subdomain unprotected: mail spoofing a subdomain is delivered." `
                        -CurrentValue $d.DMARC -RequiredValue 'sp=quarantine or sp=reject (or omit sp)'
                } else {
                    $advice = if ($policy -eq 'quarantine') { ' p=reject is stronger: quarantined mail still reaches the user''s junk folder.' } else { '' }
                    # The expected state also names the NRG reporting address (DMARCian) in rua.
                    $ruaList = @(Get-NRGDmarcReportAddresses -Record ([string]$d.DMARC))
                    $wanted  = @((Get-NRGStandards).DmarcReportingAddresses)
                    $short = @(); $unknown = @()
                    if ($wanted.Count -eq 0) {
                        $unknown += 'whether rua names the NRG reporting address, because none is approved (Config/nrg-standards.json DmarcReportingAddresses is empty).'
                    } else {
                        $absent = @($wanted | Where-Object { -not (Test-NRGDmarcReportAddress -Wanted $_ -Present $ruaList) })
                        if ($absent.Count) { $short += "rua $(if ($ruaList.Count) { "($($ruaList -join ', ')) " })does not include the NRG reporting address: $($absent -join ', ')." }
                    }
                    Add-NRGExpectedStateFinding -ControlId $controlId -Control $control -FrameworkIds $citations -Instance $domain -TitleSuffix ": $domain" `
                        -Verified @("$domain DMARC p=$policy (100%)$origin. Spoofed mail failing authentication is $action.$advice") `
                        -Shortfalls $short -NotEstablished $unknown -CurrentValue ([string]$d.DMARC) -RequiredValue "p=$policy with pct=100 and the approved reporting address in rua"
                }
            }
            'none' {
                Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity $control.Severity `
                    -Detail "$domain DMARC p=none$origin — reporting only, NO protection. This is not a security control." `
                    -CurrentValue $d.DMARC -RequiredValue 'p=quarantine or p=reject' `
                    -Remediation $control.Remediation
            }
            default {
                Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity 'High' `
                    -Detail "$domain DMARC record present but policy is unrecognized: '$policy'$origin" `
                    -CurrentValue $d.DMARC
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

        if (Add-NRGDnsLookupFailedFinding -Control $control -ControlId $controlId -Citations $citations `
                -Domain $domain -DomainEntry $d -Record 'MTASTS' -Label 'MTA-STS') { continue }

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
        } elseif (-not $d.MTASTS.Mode -and (Get-NRGObjectField -Item $d.MTASTS -Key 'PolicyHostMissing' -Default $false) -eq $true) {
            # The TXT record is published but mta-sts.<domain> does not exist
            # (authoritative no A / AAAA record), so no sender can fetch the
            # policy and MTA-STS is not in effect.
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain publishes an MTA-STS record, but mta-sts.$domain does not exist in DNS, so no sending server can fetch the policy and MTA-STS is not in effect. Inbound TLS is not enforced." `
                -CurrentValue "_mta-sts TXT published; mta-sts.$domain has no A/AAAA record" `
                -RequiredValue "https://mta-sts.$domain/.well-known/mta-sts.txt serving mode: enforce" -Remediation $control.Remediation
        } elseif (-not $d.MTASTS.Mode -and (Get-NRGObjectField -Item $d.MTASTS -Key 'PolicyFetchError' -Default $null)) {
            # The DNS record exists but the policy file could not be read
            # (network, TLS or refused probe). That is not a mode — it is not
            # assessed.
            Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain publishes an MTA-STS record, but the policy file could not be fetched ($($d.MTASTS.PolicyFetchError)), so the mode was not assessed. Check https://mta-sts.$domain/.well-known/mta-sts.txt."
        } elseif ($d.MTASTS.Mode -eq 'testing') {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Low' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain MTA-STS in testing mode — reporting only, no enforcement. Advance to enforce after monitoring." `
                -CurrentValue 'mode: testing' -RequiredValue 'mode: enforce'
        } else {
            # mode: none (policy withdrawn) or a policy file with no valid
            # mode — either way senders do not enforce TLS: not configured.
            Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Medium' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain MTA-STS record present but the policy mode is '$($d.MTASTS.Mode ?? 'unknown')', which enforces nothing." `
                -CurrentValue "mode: $($d.MTASTS.Mode ?? 'unknown')" -RequiredValue 'mode: enforce' -Remediation $control.Remediation
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

        if (Add-NRGDnsLookupFailedFinding -Control $control -ControlId $controlId -Citations $citations `
                -Domain $domain -DomainEntry $d -Record 'TLSRPT' -Label 'TLS-RPT') { continue }

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

        if (Add-NRGDnsLookupFailedFinding -Control $control -ControlId $controlId -Citations $citations `
                -Domain $domain -DomainEntry $d -Record 'DNSSEC' -Label 'DS') { continue }

        if ($d.DNSSEC -eq $true) {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations -Detail $(if (Get-NRGObjectField -Item $d -Key 'DNSSECInheritedFrom' -Default $null) { "$domain is signed as part of the DNSSEC-signed zone $($d.DNSSECInheritedFrom) (it is not a separately delegated zone)." } else { "$domain DNSSEC enabled (DS record found at parent zone)." })
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
        if ($d.PSObject.Properties['DKIM'] -or ($d -is [System.Collections.IDictionary] -and $d.Contains('DKIM'))) {
            $dkim = $d.DKIM
            if ($dkim) {
                if ($dkim -is [System.Collections.IDictionary] -and $dkim.Contains('KeyAgeDays')) {
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
        if ($d -is [System.Collections.IDictionary] -and $d.Contains('CAA')) { $caa = $d['CAA'] }
        elseif ($d.PSObject.Properties['CAA'])             { $caa = $d.CAA }

        if (Add-NRGDnsLookupFailedFinding -Control $control -ControlId $controlId -Citations $citations `
                -Domain $domain -DomainEntry $d -Record 'CAA' -Label 'CAA') { continue }

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

        $issuance = @(@(Get-NRGObjectField -Item $caa -Key 'IssuanceAllowed' -Default @()) | ForEach-Object { ([string]$_).Trim() })
        $wildcard = @(@(Get-NRGObjectField -Item $caa -Key 'WildcardAllowed' -Default @()) | ForEach-Object { ([string]$_).Trim() })
        $from     = Get-NRGObjectField -Item $caa -Key 'InheritedFrom' -Default $null
        $origin   = if ($from) { " (inherited from $from, RFC 8659 §3)" } else { '' }
        $current  = "issue: [" + ($issuance -join ',') + "], issuewild: [" + ($wildcard -join ',') + "]$origin"
        $common   = @{ Category = $control.Category; Title = "$($control.Title): $domain"; Instance = $domain; FrameworkIds = $citations }

        # RFC 8659 §4.2/§4.3: ordinary certificates are governed ONLY by
        # 'issue'; 'issuewild' governs wildcards; a set with no 'issue' tag
        # (only iodef, or only issuewild) does not restrict ordinary issuance.
        if ($issuance.Count -eq 0) {
            if ($wildcard.Count -gt 0) {
                Add-NRGFinding -ControlId $controlId @common -State 'Partial' -Severity 'Medium' `
                    -Detail "$domain CAA restricts only WILDCARD certificates$origin (issuewild, no issue tag): any CA may still issue ordinary certificates for this domain." `
                    -CurrentValue $current -RequiredValue 'An issue= record naming approved CA(s)' -Remediation $control.Remediation
            } else {
                Add-NRGFinding -ControlId $controlId @common -State 'Gap' -Severity $control.Severity `
                    -Detail "$domain has a CAA record$origin with no issue or issuewild tag (for example iodef only), which does not restrict issuance (RFC 8659 §4.2): any publicly trusted CA may issue." `
                    -CurrentValue $current -RequiredValue 'CAA issue record naming approved CA(s)' -Remediation $control.Remediation
            }
            continue
        }

        $allowed = @($issuance + $wildcard | Where-Object { $_ -and $_ -ne ';' } | Sort-Object -Unique)
        if ($allowed.Count -eq 0) {
            # issue ";" with no CA anywhere: nothing can be issued. Restrictive,
            # but a domain that serves any certificate will fail renewal.
            Add-NRGFinding -ControlId $controlId @common -State 'Partial' -Severity $control.Severity `
                -Detail "$domain CAA forbids issuance by every CA$origin (issue "";""). No certificate for this domain can be issued or renewed. Verify this is intentional." `
                -CurrentValue $current -RequiredValue 'At least one approved CA listed in issue='
        } else {
            Add-NRGFinding -ControlId $controlId @common -State 'Satisfied' -Severity 'Informational' `
                -Detail "$domain has a restrictive CAA allowlist$origin ($($allowed.Count) CA entry/entries) — RFC 8659 compliant." `
                -CurrentValue ('Allowed CAs: ' + ($allowed -join ', ') + $origin)
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
        if ($d -is [System.Collections.IDictionary] -and $d.Contains('TLSCerts')) { $tls = $d['TLSCerts'] }
        elseif ($d.PSObject.Properties['TLSCerts'])             { $tls = $d.TLSCerts }

        # Pull collector-side per-domain errors (TimeBudget, refused SSRF
        # targets, etc.) so NotApplicable findings explain WHY no TLS data
        # exists. Differentiates "domain has no HTTPS endpoint" from "we
        # ran out of time budget before probing this domain".
        $domainErrs = @()
        if ($d -is [System.Collections.IDictionary] -and $d.Contains('Errors')) { $domainErrs = @($d['Errors']) }
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

        $tlsKeys = if ($tls -is [System.Collections.IDictionary]) { @($tls.Keys) }
                   else { @($tls.PSObject.Properties.Name) }

        foreach ($role in $tlsKeys) {
            $cert = if ($tls -is [System.Collections.IDictionary]) { $tls[$role] } else { $tls.$role }
            if (-not $cert) { continue }
            $probedCount++

            $certHasError = $false
            $certError    = $null
            $certDays     = $null
            $certHost     = $null

            if ($cert -is [System.Collections.IDictionary]) {
                if ($cert.Contains('Error')) { $certError = $cert['Error']; $certHasError = [bool]$certError }
                if ($cert.Contains('DaysUntilExpiry')) { $certDays = $cert['DaysUntilExpiry'] }
                if ($cert.Contains('Hostname'))        { $certHost = $cert['Hostname'] }
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
        'Comodo', 'Amazon', 'Entrust', 'Buypass', 'IdenTrust',
        # Large public CAs that issue for common hosting (Google-fronted and
        # Cloudflare sites use Google Trust Services); flagging them read a
        # normal certificate as possible mis-issuance.
        'Google Trust Services', 'ZeroSSL', 'SSL.com', 'Certum', 'Cloudflare', 'Actalis', 'HARICA'
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
        if ($d -is [System.Collections.IDictionary] -and $d.Contains('CTLog')) { $ct = $d['CTLog'] }
        elseif ($d.PSObject.Properties['CTLog'])             { $ct = $d.CTLog }

        # Pull collector-side per-domain errors so we can distinguish
        # "crt.sh actually returned zero certs" (genuine finding) from
        # "we skipped crt.sh because the time budget expired" (clarity).
        $domainErrs = @()
        if ($d -is [System.Collections.IDictionary] -and $d.Contains('Errors')) { $domainErrs = @($d['Errors']) }
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
        if ($ct -is [System.Collections.IDictionary]) {
            if ($ct.Contains('QueryError')) { $queryError = $ct['QueryError'] }
            if ($ct.Contains('TotalCerts')) { $totalCerts = [int]($ct['TotalCerts'] ?? 0) }
            if ($ct.Contains('Issuers'))    { $issuers    = @($ct['Issuers'] ?? @()) }
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
            # No certificate has ever been logged for this name: there is
            # nothing mis-issued to review. That is not a weakness to score.
            Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                -Title "$($control.Title): $domain" -Severity 'Informational' -Instance $domain `
                -FrameworkIds $citations `
                -Detail "$domain has no certificates in CT logs, so there is no issuance to review. Set up CT monitoring (e.g. a crt.sh or vendor alert) so a future mis-issued certificate is noticed." `
                -CurrentValue 'TotalCerts: 0'
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
                -Detail "$domain has certificates in CT logs from $($suspicious.Count) issuer(s) not on the known-good CA list. Confirm the organization requested them; otherwise investigate possible mis-issuance: $top" `
                -CurrentValue "Suspicious issuers: $top" `
                -RequiredValue 'All CT-log issuers match the org-approved CA allowlist' `
                -Remediation $control.Remediation
        }
    }
}
#Requires -Version 7.0
#
# Test-NRGControlEXO.ps1  (v4.5.6)
# Evaluates Exchange Online security controls.
# SCORING ONLY — no API calls.
#
# NIST SP 800-53: AU-2, SI-8, SC-7, SC-8
# MITRE ATT&CK:   T1114, T1114.003, T1078, T1566
#

# ── EXO-1.1 Mailbox Audit Logging ────────────────────────────────────────────
function Test-NRGControlEXOMailboxAudit {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    $orgDisabled = Get-NRGNestedProperty -Object $exoData -Path 'Data.OrganizationConfig.AuditDisabled' -Default $null
    $sample      = Get-NRGNestedProperty -Object $exoData -Path 'Data.MailboxAuditSummary.SampleMailboxAudit' -Default $null

    if ($orgDisabled -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'Mailbox audit logging is DISABLED at the organization level. No mailbox activity will be logged.' `
            -CurrentValue 'AuditDisabled = $true' -RequiredValue 'AuditDisabled = $false' `
            -Remediation $control.Remediation
    } elseif ($sample -and -not $sample.AllEnabled) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "Organization-level audit is enabled but some mailboxes have audit disabled (sample of $($sample.SampleCount) mailboxes)." `
            -CurrentValue 'Some mailboxes audit-disabled' -RequiredValue 'All mailboxes audit-enabled'
    } elseif ($orgDisabled -eq $false -or ($sample -and $sample.AllEnabled)) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail 'Mailbox audit logging enabled at organization level.'
    } else {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Audit status could not be determined'
    }
}

# ── EXO-1.2 SMTP Client Authentication Disabled ──────────────────────────────
function Test-NRGControlEXOSmtpAuth {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.2'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    $smtpAuth = $exoData.Data.SmtpAuthConfig
    if (-not $smtpAuth) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'SMTP auth configuration not collected'
        return
    }

    $tenantDisabled  = $smtpAuth.TenantDisabled
    $perMailboxCount = $smtpAuth.PerMailboxEnabledCount ?? 0

    if ($tenantDisabled -eq $true -and $perMailboxCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail 'SMTP AUTH disabled at tenant level with no per-mailbox exceptions.'
    } elseif ($tenantDisabled -eq $true -and $perMailboxCount -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "SMTP AUTH disabled tenant-wide but $perMailboxCount mailbox(es) have it re-enabled: $($smtpAuth.SampleEnabled -join ', ')." `
            -CurrentValue "$perMailboxCount mailboxes with SMTP AUTH enabled" `
            -RequiredValue 'Zero per-mailbox SMTP AUTH exceptions'
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'SMTP AUTH is enabled at the tenant level. This allows basic authentication bypassing MFA and CA policies.' `
            -CurrentValue 'SmtpClientAuthenticationDisabled = $false' `
            -RequiredValue 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true' `
            -Remediation $control.Remediation
    }
}

# ── EXO-1.3 External Auto-Forwarding Blocked ─────────────────────────────────
function Test-NRGControlEXOAutoForward {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.3'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    $defaultPolicy = @($exoData.Data.OutboundSpamPolicies ?? @()) |
        Where-Object { $_.IsDefault } | Select-Object -First 1

    $wildcardRemote = @($exoData.Data.RemoteDomains ?? @()) |
        Where-Object { $_.IsDefault } | Select-Object -First 1

    $policyBlocked  = $defaultPolicy -and $defaultPolicy.AutoForwardingMode -eq 'Off'
    $remoteBlocked  = $wildcardRemote -and (-not $wildcardRemote.AutoForwardEnabled)

    if ($policyBlocked -and $remoteBlocked) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail 'External auto-forwarding blocked in both outbound spam policy and remote domain settings.'
    } elseif ($policyBlocked) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Low' -FrameworkIds $citations `
            -Detail 'Outbound spam policy blocks auto-forward, but remote domain wildcard (*) still allows it. Set-RemoteDomain * -AutoForwardEnabled $false.' `
            -CurrentValue 'Remote domain AutoForwardEnabled = $true' `
            -RequiredValue 'Remote domain AutoForwardEnabled = $false'
    } elseif ($remoteBlocked) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail 'Remote domain wildcard blocks auto-forward, but outbound spam policy is not set to Off.' `
            -CurrentValue "AutoForwardingMode = $($defaultPolicy.AutoForwardingMode ?? 'unknown')" `
            -RequiredValue 'AutoForwardingMode = Off'
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'External auto-forwarding is NOT blocked. Users or compromised accounts can silently exfiltrate all email to external addresses.' `
            -CurrentValue "AutoForwardingMode = $($defaultPolicy.AutoForwardingMode ?? 'Automatic')" `
            -RequiredValue 'AutoForwardingMode = Off in outbound spam policy AND Remote domain AutoForwardEnabled = $false' `
            -Remediation $control.Remediation
    }
}

# ── EXO-1.4 DKIM Signing Enabled ─────────────────────────────────────────────
function Test-NRGControlEXODKIM {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.4'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    $dkimConfigs = @($exoData.Data.DkimSigningConfigs ?? @())
    if ($dkimConfigs.Count -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'No DKIM signing configuration found'
        return
    }

    $disabled = @($dkimConfigs | Where-Object { -not $_.Enabled })
    $enabled  = @($dkimConfigs | Where-Object { $_.Enabled })
    $weakKey  = @($dkimConfigs | Where-Object { $_.Enabled -and $_.KeySize -and $_.KeySize -lt 2048 })

    if ($disabled.Count -eq 0 -and $weakKey.Count -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail "DKIM enabled for all $($dkimConfigs.Count) domain(s): $($enabled.Domain -join ', ')"
    } elseif ($disabled.Count -gt 0 -and $enabled.Count -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'High' -FrameworkIds $citations `
            -Detail "DKIM enabled for $($enabled.Count) domain(s) but disabled for $($disabled.Count): $($disabled.Domain -join ', ')" `
            -CurrentValue "DKIM disabled: $($disabled.Domain -join ', ')" -RequiredValue 'DKIM enabled for all domains'
    } elseif ($weakKey.Count -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "DKIM enabled but $($weakKey.Count) domain(s) use <2048-bit keys: $($weakKey.Domain -join ', ')" `
            -CurrentValue "Key size < 2048 bits" -RequiredValue '≥2048-bit DKIM keys'
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail "DKIM is disabled for all $($disabled.Count) domain(s): $($disabled.Domain -join ', ')" `
            -CurrentValue 'DKIM disabled for all domains' -RequiredValue 'DKIM enabled for all domains' `
            -Remediation $control.Remediation
    }
}

# ── EXO-1.5 Anti-Phishing Impersonation Protection ───────────────────────────
function Test-NRGControlEXOAntiPhish {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.5'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    $defaultPolicy = @($exoData.Data.AntiPhishPolicies ?? @()) |
        Where-Object { $_.IsDefault } | Select-Object -First 1

    if (-not $defaultPolicy) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'No default anti-phishing policy found'
        return
    }

    $gaps = @()
    if (-not $defaultPolicy.EnableTargetedUserProtection) { $gaps += 'User impersonation protection disabled' }
    if (-not $defaultPolicy.EnableOrganizationDomainsProtection) { $gaps += 'Organization domain impersonation disabled' }
    if (-not $defaultPolicy.EnableMailboxIntelligence) { $gaps += 'Mailbox intelligence disabled' }
    if (-not $defaultPolicy.EnableExternalSenderTag) { $gaps += 'External sender tag disabled' }

    if ($gaps.Count -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail 'Anti-phishing policy has user impersonation, org domain protection, mailbox intelligence, and external sender tag all enabled.'
    } elseif ($gaps.Count -le 2) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "Anti-phishing partially configured. Gaps: $($gaps -join '; ')" `
            -CurrentValue "Missing: $($gaps -join ', ')" -RequiredValue 'All impersonation protections enabled'
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail "Anti-phishing impersonation protection has multiple gaps: $($gaps -join '; ')" `
            -CurrentValue "Missing: $($gaps -join ', ')" -RequiredValue 'All impersonation protections enabled' `
            -Remediation $control.Remediation
    }
}

# ── EXO-1.6 Modern Auth (OAuth2) Enabled ─────────────────────────────────────
function Test-NRGControlEXOModernAuth {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.6'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    $modernAuth = Get-NRGNestedProperty -Object $exoData -Path 'Data.OrganizationConfig.OAuth2ClientProfileEnabled' -Default $null

    if ($modernAuth -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail 'Modern authentication (OAuth2) is enabled for Exchange Online.'
    } elseif ($modernAuth -eq $false) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'Modern authentication is DISABLED. This forces clients to use basic authentication, bypassing MFA.' `
            -CurrentValue 'OAuth2ClientProfileEnabled = $false' `
            -RequiredValue 'Set-OrganizationConfig -OAuth2ClientProfileEnabled $true' `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Modern auth state could not be determined'
    }
}

# ── EXO-1.7 Honor DMARC Policy (Anti-phish) ──────────────────────────────────
function Test-NRGControlEXOHonorDMARC {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.7'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    $defaultPolicy = @($exoData.Data.AntiPhishPolicies ?? @()) |
        Where-Object { $_.IsDefault } | Select-Object -First 1

    if ($defaultPolicy -and $defaultPolicy.HonorDmarcPolicy -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail 'Anti-phishing policy honors incoming DMARC policy (p=reject/quarantine applied by EXO).'
    } elseif ($defaultPolicy) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity 'High' -FrameworkIds $citations `
            -Detail 'Anti-phishing policy does NOT honor DMARC. Inbound p=reject messages from senders may still be delivered.' `
            -CurrentValue 'HonorDmarcPolicy = $false' -RequiredValue 'HonorDmarcPolicy = $true' `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'No default anti-phishing policy found'
    }
}

# ── EXO-2.3 POP3 Access Disabled ─────────────────────────────────────────────
function Test-NRGControlEXOPop3 {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.3'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }
    # v4.6.4 ADVISORY MARK: no programmatic check, manual review required.
    Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
        -Title "$($control.Title) (Manual review required)" -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). POP3 state requires Get-CASMailboxPlan — not collected in current run. Verify manually: Get-CASMailboxPlan | Select PopEnabled'
}

# ── EXO-2.4 IMAP Access Disabled ─────────────────────────────────────────────
# v4.6.4 ADVISORY MARK: no programmatic check, manual review required.
function Test-NRGControlEXOImap {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.4'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
        -Title "$($control.Title) (Manual review required)" -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). IMAP state requires Get-CASMailboxPlan — not collected in current run. Verify manually: Get-CASMailboxPlan | Select ImapEnabled'
}

# ── EXO-2.5 Customer Lockbox Enabled ─────────────────────────────────────────
function Test-NRGControlEXOCustomerLockbox {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.5'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    # Customer Lockbox state is in org config — pull it from the collector
    # output. Prior versions referenced $orgConfig without ever assigning it
    # (lost in PR conflict resolution) — under StrictMode this silently
    # killed the evaluator via the loader's try/catch.
    $orgConfig = $exoData.Data.OrganizationConfig
    if (-not $orgConfig) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Organization config not collected'
        return
    }

    # CustomerLockBoxEnabled may not be present if E5 not licensed.
    # The collector stores OrganizationConfig as a hashtable, so use
    # ContainsKey rather than PSObject.Properties (which works on both but
    # is the wrong idiom for a hashtable).
    $lockboxEnabled = if ($orgConfig -is [System.Collections.IDictionary]) {
        if ($orgConfig.Contains('CustomerLockBoxEnabled')) { $orgConfig['CustomerLockBoxEnabled'] } else { $null }
    } elseif ($orgConfig.PSObject.Properties['CustomerLockBoxEnabled']) {
        $orgConfig.PSObject.Properties['CustomerLockBoxEnabled'].Value
    } else { $null }
    if ($lockboxEnabled -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail 'Customer Lockbox is enabled. Microsoft support requires explicit admin approval to access tenant data.'
    } elseif ($lockboxEnabled -eq $false) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'Customer Lockbox is disabled. Microsoft support can access tenant data during support cases without approval.' `
            -CurrentValue 'CustomerLockBoxEnabled = $false' -RequiredValue 'CustomerLockBoxEnabled = $true' `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Customer Lockbox state not available — requires E5 or E5 Compliance license'
    }
}

# ── EXO-2.6 Shared Mailboxes Block Direct Sign-In ────────────────────────────
function Test-NRGControlEXOSharedMailbox {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.6'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    # Shared mailbox sign-in state requires Graph User.Read.All to check AccountEnabled
    # This data is in AAD-Users if collected
    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'

    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    # v4.6.4 ADVISORY MARK: no programmatic check, manual review required.
    # Shared mailbox sign-in state requires cross-referencing AAD Users with EXO shared mailboxes
    Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
        -Title "$($control.Title) (Manual review required)" -Severity 'High' -FrameworkIds $citations `
        -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). Shared mailbox direct sign-in status requires manual verification. Run: Get-Mailbox -RecipientTypeDetails SharedMailbox | ForEach-Object { Get-MgUser -UserId $_.ExternalDirectoryObjectId | Select DisplayName,AccountEnabled }' `
        -CurrentValue 'Manual review required' -RequiredValue 'All shared mailbox accounts have AccountEnabled = $false' `
        -Remediation $control.Remediation
}

# ── EXO-3.1 Connection Filter No Safe List Bypass ────────────────────────────
function Test-NRGControlEXOConnectionFilter {
    [CmdletBinding()] param()
    $cid = 'EXO-3.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $cf = Get-NRGRawData -Key 'EXO-ConnectionFilter'
    if (-not $cf -or -not $cf.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Connection filter data not collected'; return
    }
    $defaultCF = @($cf.Data.ConnectionFilter | Where-Object { $_.IsDefault }) | Select-Object -First 1
    if (-not $defaultCF) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No default connection filter found'; return }
    $safeListEnabled = [bool]($defaultCF.EnableSafeList ?? $false)
    if (-not $safeListEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Microsoft safe list bypass is disabled on connection filter.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Safe list bypass is enabled — Microsoft-maintained IP list bypasses spam filtering entirely. Third-party senders on that list skip all EOP filtering.' -CurrentValue 'EnableSafeList = $true' -RequiredValue 'Set-HostedConnectionFilterPolicy -EnableSafeList $false' -Remediation $ctrl.Remediation
    }
}

# ── EXO-3.2 Outbound Spam User Sending Limits ────────────────────────────────
function Test-NRGControlEXOOutboundLimits {
    [CmdletBinding()] param()
    $cid = 'EXO-3.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    $defaultOutbound = @($exo.Data.OutboundSpamPolicies | Where-Object { $_.IsDefault }) | Select-Object -First 1
    if (-not $defaultOutbound) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No default outbound policy found'; return }
    # v4.6.4 ADVISORY MARK: hardcoded Satisfied without inspecting any threshold —
    # tag as manual review required pending v4.7.0 cleanup. AutoForwardingMode
    # already checked in EXO-1.3 — here check action on limit breach.
    Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual review required)" -Severity 'Informational' -FrameworkIds $cit -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). Outbound spam policy exists. EXO enforces sending limits by default — verify ActionWhenThresholdReached is set to alert an admin.'
}

# ── EXO-3.3 Alert Policy — Forwarding Rules ──────────────────────────────────
function Test-NRGControlEXOAlertForwarding {
    [CmdletBinding()] param()
    $cid = 'EXO-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $cf = Get-NRGRawData -Key 'EXO-ConnectionFilter'
    $alertPolicies = Get-NRGNestedProperty -Object $cf -Path 'Data.AlertPolicies' -Default $null
    if (-not $cf -or -not $cf.Success -or -not $alertPolicies) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Alert policy data not collected'; return
    }
    $activeAlerts = Get-NRGNestedProperty -Object $alertPolicies -Path 'ActiveAlerts' -Default @()
    $fwdAlerts = @($activeAlerts | Where-Object { $_.Title -match 'forward|redirect' })
    if ($fwdAlerts.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Forwarding rule alert policy is active.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'No active alert for new forwarding/redirect rules detected. Verify alert policies are configured in Defender portal: Email forwarding activities.' -Remediation $ctrl.Remediation
    }
}

# ── EXO-3.4 Alert Policy — Unusual Mail Volume ───────────────────────────────
# v4.6.4 ADVISORY MARK: no programmatic check, manual review required.
function Test-NRGControlEXOAlertVolume {
    [CmdletBinding()] param()
    $cid = 'EXO-3.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual review required)" -Severity 'Low' -FrameworkIds $cit -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). Unusual mail volume alert requires manual verification in Defender portal: Alerts > Alert policies > Unusual increase in email reported as phish.' -Remediation $ctrl.Remediation
}

# ── EXO-3.5 Transport Rules Audit Enabled ────────────────────────────────────
function Test-NRGControlEXOTransportAudit {
    [CmdletBinding()] param()
    $cid = 'EXO-3.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    $auditDisabled = Get-NRGNestedProperty -Object $exo -Path 'Data.OrganizationConfig.AuditDisabled' -Default $null
    if ($auditDisabled -ne $true) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Organization-level audit logging is enabled, covering transport rule changes.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Audit logging disabled — transport rule creation and modification is not audited.' -Remediation $ctrl.Remediation
    }
}

# ── EXO-4.1 Mailbox Audit Log Age Limit ──────────────────────────────────────
function Test-NRGControlEXOAuditAgeLimit {
    [CmdletBinding()] param()
    $cid = 'EXO-4.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    $sample = Get-NRGNestedProperty -Object $exo -Path 'Data.MailboxAuditSummary.SampleMailboxAudit' -Default $null
    if (-not $sample) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Sample mailbox audit data not collected'; return
    }
    $ageLimit = [string]($sample.AuditLogAgeLimit ?? '90.00:00:00')
    $days = 90
    if ($ageLimit -match '^(\d+)\.') { $days = [int]$matches[1] }
    if ($days -ge 180) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Mailbox audit log age limit: $days days (meets recommended 180+ days)."
    } elseif ($days -ge 90) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail "Audit log age limit is $days days. 90 days is the minimum — 180 days recommended for adequate IR investigation window." `
            -CurrentValue "$days days" -RequiredValue '180 days'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "Mailbox audit log age limit is only $days days — insufficient for most IR investigations." `
            -CurrentValue "$days days" -RequiredValue '≥90 days (180 recommended)' -Remediation $ctrl.Remediation
    }
}

# ── EXO-4.2 Admin Audit Log Enabled ─────────────────────────────────────────
function Test-NRGControlEXOAdminAudit {
    [CmdletBinding()] param()
    $cid = 'EXO-4.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    $orgAudit = Get-NRGNestedProperty -Object $exo -Path 'Data.OrganizationConfig.AuditDisabled' -Default $null
    if ($orgAudit -ne $true) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Admin audit logging is enabled — cmdlet execution by admins is tracked.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Organization audit logging is disabled. All admin cmdlet execution goes unlogged.' `
            -Remediation $ctrl.Remediation
    }
}

# ── EXO-4.3 Safe Attachments for SharePoint OneDrive Teams ───────────────────
function Test-NRGControlEXOSafeAttachmentsSPO {
    [CmdletBinding()] param()
    $cid = 'EXO-4.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    $sa = $def.Data['SafeAttachments']
    if (-not $sa -or -not $sa.Available) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Safe Attachments not available — Defender for Office 365 Plan 1 required for SPO/OD/Teams file scanning.' `
            -Remediation $ctrl.Remediation; return
    }
    # Safe Attachments for SPO/OD/Teams is a separate tenant-level setting
    # Proxied by checking if any policy covers it — CIS 2.3.4 requires global ATP for files
    $spoEnabled = @($sa.Policies | Where-Object { $_.Enable -and $_.Action -ne 'Allow' }).Count -gt 0
    if ($spoEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Safe Attachments active policies cover file scanning. Verify SharePoint/OneDrive/Teams file ATP is enabled in Defender portal > Global settings.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail 'Safe Attachments for SharePoint/OneDrive/Teams requires manual verification: Defender portal > Policies > Safe Attachments > Global settings > enable for SPO/OD/Teams.' `
            -Remediation $ctrl.Remediation
    }
}

# ── EXO-4.4 Anti-Spam Inbound Policy Configured ─────────────────────────────
function Test-NRGControlEXOAntiSpamInbound {
    [CmdletBinding()] param()
    $cid = 'EXO-4.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    $policies = @($exo.Data.AntiSpamPolicies ?? @())
    $default  = $policies | Where-Object { $_.IsDefault } | Select-Object -First 1
    if (-not $default) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'No default anti-spam policy found'; return
    }
    $gaps = @()
    if ($default.SpamAction     -ne 'MoveToJmf' -and $default.SpamAction -ne 'Quarantine') { $gaps += "SpamAction=$($default.SpamAction)" }
    if ($default.BulkThreshold  -gt 7)  { $gaps += "BulkThreshold=$($default.BulkThreshold)" }
    if ($default.ZapEnabled -ne $true)  { $gaps += 'ZapEnabled=False' }
    if ($gaps.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Default inbound anti-spam policy is properly configured.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "Anti-spam policy has sub-optimal settings: $($gaps -join ', ')" `
            -CurrentValue ($gaps -join ', ') -RequiredValue 'SpamAction=MoveToJmf/Quarantine, BulkThreshold≤7, ZapEnabled=True' `
            -Remediation $ctrl.Remediation
    }
}

# ── EXO-5.1 Per-User Mailbox Audit Logging Enabled ────────────────────────────
function Test-NRGControlEXOPerUserAudit {
    [CmdletBinding()] param()
    $cid = 'EXO-5.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    $auditSummary = $exo.Data.MailboxAuditSummary
    $auditDisabledCount = [int]($auditSummary.AuditDisabledCount ?? 0)
    $totalMailboxes     = [int]($auditSummary.TotalMailboxes ?? 0)
    if ($auditDisabledCount -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Mailbox audit logging enabled on all $totalMailboxes mailbox(es)."
    } elseif ($auditDisabledCount -gt 0 -and $totalMailboxes -gt 0) {
        $pct = [int]($auditDisabledCount * 100 / $totalMailboxes)
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$auditDisabledCount of $totalMailboxes mailboxes ($pct%) have audit logging disabled. Actions in those mailboxes are not logged — inbox rules, delegation, and access cannot be investigated." -CurrentValue "$auditDisabledCount mailboxes unaudited" -RequiredValue 'Zero mailboxes with audit disabled' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'Mailbox audit summary data incomplete. Verify all mailboxes have auditing enabled: Get-Mailbox -ResultSize Unlimited | Where-Object { $_.AuditEnabled -eq $false }' -Remediation $ctrl.Remediation
    }
}

# ── EXO-5.2 Priority Account Email Protection Configured ─────────────────────
function Test-NRGControlEXOPriorityAccountProtection {
    [CmdletBinding()] param()
    $cid = 'EXO-5.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    $priorityAccounts = @($def.Data.PriorityAccounts ?? @())
    $ap = $def.Data['AntiPhishing']
    $hasPriorityPolicy = $false
    if ($ap -and $ap.Available -and $priorityAccounts.Count -gt 0) {
        $hasPriorityPolicy = @($ap.Policies | Where-Object {
            $_.TargetedUsersToProtect -and @($_.TargetedUsersToProtect).Count -gt 0
        }).Count -gt 0
    }
    if ($hasPriorityPolicy -and $priorityAccounts.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Priority accounts are tagged and protected by targeted user impersonation protection in anti-phishing policy."
    } elseif ($priorityAccounts.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No priority accounts tagged. Executives and admins are not enrolled in enhanced threat protection or differentiated incident prioritization.' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'Priority accounts tagged but targeted impersonation protection not confirmed in anti-phishing policy. Ensure anti-phishing policy explicitly protects tagged accounts.' -Remediation $ctrl.Remediation
    }
}

# ── EXO-5.3 Exchange Online Protection Safe Senders Not Overriding ────────────
function Test-NRGControlEXOSafeSenderOverride {
    [CmdletBinding()] param()
    $cid = 'EXO-5.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    $defaultPolicy = @($exo.Data.AntiSpamPolicies | Where-Object { $_.IsDefault }) | Select-Object -First 1
    if (-not $defaultPolicy) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No default policy'; return }
    $allowListBypass = $defaultPolicy.AllowedSenderDomains -and @($defaultPolicy.AllowedSenderDomains).Count -gt 0
    if (-not $allowListBypass) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'No allowed sender domains in anti-spam policy — all inbound mail is filtered equally.'
    } else {
        $count = @($defaultPolicy.AllowedSenderDomains).Count
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$count allowed sender domain(s) in anti-spam policy bypass all EOP filtering. Allowed domains are a common attacker target — if a domain is compromised, all mail from it reaches inboxes unfiltered." -CurrentValue "$count bypass domains configured" -RequiredValue 'Zero allowed sender domains in anti-spam policy' -Remediation $ctrl.Remediation
    }
}

# ── EXO-7.1 Mailbox Forwarding to External Addresses ─────────────────────────
# Consumes EXO-Inventory.ForwardingMailboxes. ForwardingSmtpAddress is a
# server-side persistent exfil channel — common BEC TTP (MITRE T1114.003).
function Test-NRGControlEXOMailboxForwarding {
    [CmdletBinding()] param()
    $cid = 'EXO-7.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'EXO inventory data not collected'
        return
    }

    $fwd = @($inv.Data.ForwardingMailboxes ?? @())
    $count = $fwd.Count

    if ($count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'No mailboxes have a ForwardingSmtpAddress configured.'
        return
    }

    $affected = @($fwd | ForEach-Object {
        [ordered]@{
            DisplayName  = [string]$_.UPN
            ForwardingTo = [string]$_.ForwardingAddress
        }
    })

    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
        -Detail "$count mailbox(es) auto-forward to external addresses — common BEC persistence (MITRE T1114.003)." `
        -CurrentValue "$count mailbox(es) forwarding externally" `
        -RequiredValue 'Zero mailboxes with ForwardingSmtpAddress to external recipients' `
        -Remediation 'EAC > Recipients > Mailboxes > select mailbox > Manage email forwarding > clear "Forward all email sent to this mailbox". Or: Set-Mailbox -Identity <UPN> -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false. Also recommend an EXO transport rule blocking auto-forward to external recipients (Set-RemoteDomain Default -AutoForwardEnabled $false; mail flow rule: if sender is internal and recipient is external and message type is auto-forward, then reject).' `
        -AffectedObjects $affected
}

# ── EXO-7.2 Inbox Rules Forwarding Externally ────────────────────────────────
# Consumes EXO-Inventory.InboxRulesForwarding. Outlook rules that ForwardTo /
# RedirectTo / ForwardAsAttachmentTo external recipients — classic
# post-credential-compromise persistence (MITRE T1114.003) or insider exfil.
function Test-NRGControlEXOInboxRulesForwarding {
    [CmdletBinding()] param()
    $cid = 'EXO-7.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'EXO inventory data not collected'
        return
    }

    # Only count rules that actually forward externally — the collector also
    # tracks disabled-rule fingerprints, but for this control we score on the
    # active exfil surface.
    $rules = @(@($inv.Data.InboxRulesForwarding ?? @()) | Where-Object { $_.IsExternal })
    $count = $rules.Count

    if ($count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'No inbox rules forward mail externally.'
        return
    }

    $affected = @($rules | ForEach-Object {
        [ordered]@{
            DisplayName = [string]$_.Mailbox
            RuleName    = [string]$_.RuleName
            Recipients  = (@($_.ExternalRecipients) -join ', ')
        }
    })

    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
        -Detail "$count inbox rule(s) forward externally — attacker persistence (T1114.003) or insider data exfil." `
        -CurrentValue "$count inbox rule(s) forwarding externally" `
        -RequiredValue 'Zero inbox rules forwarding to external recipients' `
        -Remediation 'Find: foreach ($m in Get-Mailbox -ResultSize Unlimited) { Get-InboxRule -Mailbox $m.UserPrincipalName | Where-Object { $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo } | Select-Object @{n=''Mailbox'';e={$m.UserPrincipalName}}, Name, ForwardTo, RedirectTo, ForwardAsAttachmentTo }. Disable: Disable-InboxRule -Mailbox <UPN> -Identity <RuleName>. Block at transport layer: Set-RemoteDomain Default -AutoForwardEnabled $false plus a mail flow rule rejecting auto-forwarded mail to external recipients.' `
        -AffectedObjects $affected
}

# ── EXO-7.3 Per-User Audit Explicitly Disabled ───────────────────────────────
# Consumes EXO-Inventory.AuditDisabledMailboxes. Since Jan 2019, mailbox
# auditing is ON by default org-wide; an explicit AuditEnabled = $false is a
# deliberate override that creates an IR blind spot.
function Test-NRGControlEXOAuditDisabledMailboxes {
    [CmdletBinding()] param()
    $cid = 'EXO-7.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'EXO inventory data not collected'
        return
    }

    $disabled = @($inv.Data.AuditDisabledMailboxes ?? @())
    $count = $disabled.Count

    if ($count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'No mailboxes have per-user audit explicitly disabled.'
        return
    }

    $affected = @($disabled | ForEach-Object {
        [ordered]@{
            DisplayName = [string]$_.UPN
            MailboxType = [string]$_.MailboxType
        }
    })

    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
        -Detail "$count mailbox(es) with per-user audit explicitly disabled — incident-response blind spot." `
        -CurrentValue "$count mailbox(es) AuditEnabled = `$false" `
        -RequiredValue 'AuditEnabled = $true on every mailbox' `
        -Remediation 'As of Jan 2019, mailbox audit is enabled by default org-wide. Any AuditEnabled = $false is a deliberate override and almost always wrong. Re-enable: Get-Mailbox -ResultSize Unlimited | Where-Object { $_.AuditEnabled -eq $false } | Set-Mailbox -AuditEnabled $true. For a single mailbox: Set-Mailbox -Identity <UPN> -AuditEnabled $true.' `
        -AffectedObjects $affected
}

# ── EXO-7.4 Per-User SMTP AUTH Override (Legacy Auth) ────────────────────────
# Consumes EXO-Inventory.SmtpAuthEnabledPerUser. A per-mailbox
# SmtpClientAuthenticationDisabled = $false overrides the tenant-level disable
# and re-enables basic-auth SMTP — bypasses MFA and CA. Common attack surface
# for password spray against legacy mail clients and copiers/scanners.
function Test-NRGControlEXOSmtpAuthExceptions {
    [CmdletBinding()] param()
    $cid = 'EXO-7.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'EXO inventory data not collected'
        return
    }

    $exceptions = @($inv.Data.SmtpAuthEnabledPerUser ?? @())
    $count = $exceptions.Count

    if ($count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'No mailboxes override the tenant-level SMTP AUTH disable.'
        return
    }

    # v4.6.4 PII FIX: prior code interpolated the full UPN list into Detail,
    # which renders verbatim in the HTML client report → PII leak. Move UPNs to
    # the structured AffectedObjects (rendered into a named-findings card with
    # proper escaping) and keep Detail as a count-only one-liner.
    $affected = @($exceptions | ForEach-Object {
        [ordered]@{
            DisplayName  = [string]$_.UPN
            OverrideType = 'SmtpAuth'
        }
    })

    $detail  = "$count mailbox(es) override the tenant-level SMTP AUTH disable — legacy auth blast radius. See AffectedObjects for the per-user list."
    $remediation = 'For each affected mailbox: Set-CASMailbox -Identity <UPN> -SmtpClientAuthenticationDisabled $true. Recommend migrating senders to OAuth-based SMTP (Microsoft Graph sendMail API) or App Passwords with MFA. For multifunction devices/scanners, prefer SMTP relay via on-prem connector with IP allowlist or Direct Send (anonymous) — neither requires basic auth.'

    if ($count -le 5) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail $detail `
            -CurrentValue "$count per-user SMTP AUTH exception(s)" `
            -RequiredValue 'Zero per-user SMTP AUTH exceptions' `
            -Remediation $remediation `
            -AffectedObjects $affected
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail $detail `
            -CurrentValue "$count per-user SMTP AUTH exception(s)" `
            -RequiredValue 'Zero per-user SMTP AUTH exceptions' `
            -Remediation $remediation `
            -AffectedObjects $affected
    }
}
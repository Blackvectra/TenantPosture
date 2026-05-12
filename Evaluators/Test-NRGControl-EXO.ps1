#
# Test-NRGControl-EXO.ps1
# Evaluates Exchange Online controls against collected raw data.
#
# Functions:
#   Test-NRGControlEXOMailboxAudit     EXO-1.1
#   Test-NRGControlEXOSmtpAuth         EXO-1.2
#   Test-NRGControlEXOPop3             EXO-2.2
#   Test-NRGControlEXOImap             EXO-2.3
#   Test-NRGControlEXOCustomerLockbox  EXO-2.4
#   Test-NRGControlEXOSharedMailbox    EXO-2.5
#   Test-NRGControlEXOModernAuth       EXO-3.1
#
# Data key: 'EXO-MailboxConfig'
# Collector property map (verified against Invoke-NRGCollectEXOMailboxConfig.ps1):
#   MailboxProtocols.PopEnabled           — POP3 enabled count    (NOT Pop3Enabled)
#   MailboxProtocols.ImapEnabled          — IMAP enabled count
#   MailboxProtocols.TotalMailboxes       — total mailbox count
#   MailboxProtocols.SmtpClientAuthDisabled
#   OrganizationConfig.AuditDisabled
#   OrganizationConfig.CustomerLockBoxEnabled  (NOT IsCustomerLockBoxEnabled)
#   OrganizationConfig.OAuth2ClientProfileEnabled
#   SharedMailboxes.Count                 — total shared mailbox count
#   SharedMailboxes.SignInEnabled         — count with sign-in enabled (NOT array of objects)
#   AuditBypass.BypassedCount
#   TransportConfig.SmtpClientAuthenticationDisabled
#

function Test-NRGControlEXOMailboxAudit {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    $auditDisabled = $exoData.Data.OrganizationConfig.AuditDisabled
    $bypassedCount = if ($exoData.Data.ContainsKey('AuditBypass')) { $exoData.Data.AuditBypass.BypassedCount } else { 0 }

    if ($auditDisabled -eq $false -and $bypassedCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail 'Tenant audit enabled. No mailboxes have AuditBypassEnabled.' `
            -CurrentValue 'Enabled, no bypass' -RequiredValue 'Enabled, no bypass' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } elseif ($auditDisabled -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail 'Tenant-wide mailbox audit is disabled. No forensic trail of mailbox actions.' `
            -CurrentValue 'AuditDisabled = True' -RequiredValue 'AuditDisabled = False' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail "$bypassedCount mailbox(es) have AuditBypassEnabled=True. These users leave no audit trail." `
            -CurrentValue "$bypassedCount mailboxes bypassed" -RequiredValue 'No bypass' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation
    }
}

function Test-NRGControlEXOSmtpAuth {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.2'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    $tenantSmtpDisabled = $exoData.Data.TransportConfig.SmtpClientAuthenticationDisabled
    $totalMbx           = $exoData.Data.MailboxProtocols.TotalMailboxes
    $smtpDisabledMbx    = $exoData.Data.MailboxProtocols.SmtpClientAuthDisabled

    if ($tenantSmtpDisabled -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail 'SMTP client authentication disabled tenant-wide.' `
            -CurrentValue 'Tenant: Disabled' -RequiredValue 'Disabled' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } else {
        $enabledMbx = $totalMbx - $smtpDisabledMbx
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail "SMTP AUTH enabled tenant-wide. Approximately $enabledMbx of $totalMbx mailboxes accept SMTP basic auth, bypassing MFA." `
            -CurrentValue "Tenant SMTP AUTH enabled; $enabledMbx mailboxes affected" `
            -RequiredValue 'Tenant SmtpClientAuthenticationDisabled = True' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation
    }
}

function Test-NRGControlEXOPop3 {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.2'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    # Collector stores PopEnabled (not Pop3Enabled)
    $popEnabled = $exoData.Data.MailboxProtocols.PopEnabled
    $totalMbx   = $exoData.Data.MailboxProtocols.TotalMailboxes

    if ($popEnabled -eq 0 -or -not $popEnabled) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail 'POP3 disabled on all mailboxes.' `
            -CurrentValue '0 mailboxes with POP3 enabled' -RequiredValue '0 mailboxes' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail "POP3 enabled on $popEnabled of $totalMbx mailboxes. POP3 uses basic authentication and cannot enforce MFA." `
            -CurrentValue "$popEnabled mailboxes with POP3 enabled" -RequiredValue '0 mailboxes' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation
    }
}

function Test-NRGControlEXOImap {
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

    $imapEnabled = $exoData.Data.MailboxProtocols.ImapEnabled
    $totalMbx    = $exoData.Data.MailboxProtocols.TotalMailboxes

    if ($imapEnabled -eq 0 -or -not $imapEnabled) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail 'IMAP disabled on all mailboxes.' `
            -CurrentValue '0 mailboxes with IMAP enabled' -RequiredValue '0 mailboxes' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail "IMAP enabled on $imapEnabled of $totalMbx mailboxes. IMAP uses basic authentication and cannot enforce MFA." `
            -CurrentValue "$imapEnabled mailboxes with IMAP enabled" -RequiredValue '0 mailboxes' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation
    }
}

function Test-NRGControlEXOCustomerLockbox {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.4'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    # Collector stores CustomerLockBoxEnabled (not IsCustomerLockBoxEnabled)
    $lockboxEnabled = $exoData.Data.OrganizationConfig.CustomerLockBoxEnabled

    if ($lockboxEnabled -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail 'Customer Lockbox enabled. Microsoft support access requires explicit approval.' `
            -CurrentValue 'Enabled' -RequiredValue 'Enabled' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } elseif ($lockboxEnabled -eq $false) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail 'Customer Lockbox disabled. Microsoft support engineers can access tenant data without explicit approval.' `
            -CurrentValue 'Disabled' -RequiredValue 'Enabled' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title `
            -Detail 'Customer Lockbox data not available. Requires Microsoft 365 E5 or Customer Lockbox add-on license.'
    }
}

function Test-NRGControlEXOSharedMailbox {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.5'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    if (-not $exoData.Data.ContainsKey('SharedMailboxes')) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Shared mailbox data not collected.'
        return
    }

    # Collector stores SharedMailboxes as a hashtable of counts, not an array of objects
    $shared       = $exoData.Data.SharedMailboxes
    $total        = $shared.Count
    $signInEnabled = $shared.SignInEnabled

    if ($total -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail 'No shared mailboxes found in this tenant.' `
            -CurrentValue '0 shared mailboxes' -RequiredValue 'All shared mailboxes sign-in disabled'
    } elseif ($signInEnabled -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail "All $total shared mailbox(es) have sign-in disabled." `
            -CurrentValue "$total shared mailboxes, 0 with sign-in enabled" `
            -RequiredValue 'All shared mailboxes sign-in disabled' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail "$signInEnabled of $total shared mailbox(es) have sign-in enabled. Shared mailboxes with sign-in enabled can be used as persistent backdoor accounts." `
            -CurrentValue "$signInEnabled of $total shared mailboxes with sign-in enabled" `
            -RequiredValue 'All shared mailboxes: sign-in disabled (AccountDisabled = true)' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation
    }
}

function Test-NRGControlEXOModernAuth {
    [CmdletBinding()] param()

    $controlId = 'EXO-3.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'EXO data not collected'
        return
    }

    $modernAuthEnabled = $exoData.Data.OrganizationConfig.OAuth2ClientProfileEnabled

    if ($modernAuthEnabled -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail 'Modern authentication (OAuth2) enabled for Exchange Online. Outlook and mail clients can use MFA.' `
            -CurrentValue 'OAuth2ClientProfileEnabled = True' -RequiredValue 'Enabled' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } elseif ($modernAuthEnabled -eq $false) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail 'Modern authentication disabled for Exchange Online. Mail clients fall back to basic auth, bypassing MFA entirely.' `
            -CurrentValue 'OAuth2ClientProfileEnabled = False' -RequiredValue 'Enabled' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Modern auth state could not be determined from collected data.'
    }
}
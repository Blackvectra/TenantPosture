#
# Test-NRGControl-EXO.ps1
# Evaluates Exchange Online controls against collected raw data.
#
# Controls:
#   EXO-1.1  Mailbox audit enabled tenant-wide
#   EXO-1.2  SMTP client authentication disabled
#   EXO-2.2  POP3 disabled for all mailboxes
#   EXO-2.3  IMAP disabled for all mailboxes
#   EXO-2.4  Customer Lockbox enabled
#   EXO-2.5  Shared mailbox sign-in disabled
#   EXO-3.1  Modern authentication enabled
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

    $popEnabled = $exoData.Data.MailboxProtocols.PopEnabled
    $totalMbx   = $exoData.Data.MailboxProtocols.TotalMailboxes

    if ($popEnabled -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail 'POP3 disabled on all mailboxes.' `
            -CurrentValue "POP3 enabled: 0 of $totalMbx mailboxes" -RequiredValue '0 mailboxes with POP3 enabled' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail "POP3 enabled on $popEnabled of $totalMbx mailboxes. POP3 uses basic auth, bypassing MFA and Conditional Access." `
            -CurrentValue "POP3 enabled: $popEnabled of $totalMbx mailboxes" `
            -RequiredValue '0 mailboxes with POP3 enabled' `
            -Remediation $control.Remediation `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
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

    if ($imapEnabled -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail 'IMAP disabled on all mailboxes.' `
            -CurrentValue "IMAP enabled: 0 of $totalMbx mailboxes" -RequiredValue '0 mailboxes with IMAP enabled' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail "IMAP enabled on $imapEnabled of $totalMbx mailboxes. IMAP uses basic auth, bypassing MFA and Conditional Access." `
            -CurrentValue "IMAP enabled: $imapEnabled of $totalMbx mailboxes" `
            -RequiredValue '0 mailboxes with IMAP enabled' `
            -Remediation $control.Remediation `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
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

    $lockboxEnabled = $exoData.Data.OrganizationConfig.CustomerLockBoxEnabled

    if ($lockboxEnabled -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail 'Customer Lockbox enabled. Microsoft support access requires explicit approval.' `
            -CurrentValue 'CustomerLockBoxEnabled: True' -RequiredValue 'CustomerLockBoxEnabled: True' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } elseif ($null -eq $lockboxEnabled) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail 'Customer Lockbox state could not be determined. May not be supported on this license tier (requires M365 E3/E5 or equivalent).' `
            -CurrentValue 'Unknown' -RequiredValue 'CustomerLockBoxEnabled: True'
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail 'Customer Lockbox is disabled. Microsoft support can access tenant data during support incidents without explicit approval.' `
            -CurrentValue 'CustomerLockBoxEnabled: False' -RequiredValue 'CustomerLockBoxEnabled: True' `
            -Remediation $control.Remediation `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
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

    $sharedData     = $exoData.Data.SharedMailboxes
    $totalShared    = $sharedData.Count
    $signInEnabled  = $sharedData.SignInEnabled

    if ($totalShared -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'No shared mailboxes found in tenant.' `
            -CurrentValue '0 shared mailboxes' -RequiredValue 'N/A'
        return
    }

    if ($signInEnabled -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail "All $totalShared shared mailboxes have direct sign-in disabled." `
            -CurrentValue "Sign-in enabled: 0 of $totalShared shared mailboxes" `
            -RequiredValue 'All shared mailboxes: AccountEnabled = False' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail "$signInEnabled of $totalShared shared mailboxes have direct sign-in enabled. Shared mailboxes with sign-in are service accounts vulnerable to credential attacks." `
            -CurrentValue "Sign-in enabled: $signInEnabled of $totalShared shared mailboxes" `
            -RequiredValue 'All shared mailboxes: AccountEnabled = False' `
            -Remediation $control.Remediation `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
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
            -CurrentValue 'OAuth2ClientProfileEnabled: True' -RequiredValue 'OAuth2ClientProfileEnabled: True' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } elseif ($null -eq $modernAuthEnabled) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Modern auth state could not be determined from collected data.' `
            -CurrentValue 'Unknown' -RequiredValue 'OAuth2ClientProfileEnabled: True'
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail 'Modern authentication is disabled. Outlook and mail clients use basic authentication — MFA cannot be enforced on mail client connections.' `
            -CurrentValue 'OAuth2ClientProfileEnabled: False' -RequiredValue 'OAuth2ClientProfileEnabled: True' `
            -Remediation $control.Remediation `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    }
}

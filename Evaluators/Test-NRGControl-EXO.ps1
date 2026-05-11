#
# Test-NRGControl-EXO.ps1
# Evaluates Exchange Online controls against collected raw data.
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

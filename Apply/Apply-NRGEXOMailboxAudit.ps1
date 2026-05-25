#Requires -Version 7.0
#
# Apply-NRGEXOMailboxAudit.ps1  (v4.6.1)
# Remediates EXO-1.1: Enable mailbox audit logging org-wide.
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# CONSUMES : Finding object for ControlId 'EXO-1.1'
# REQUIRES : ExchangeOnlineManagement (Connect-ExchangeOnline must be established).
# CMDLETS  : Get-OrganizationConfig, Set-OrganizationConfig
# SAFETY   : ShouldProcess gate, idempotency re-read.
#
# CHANGE   : Set-OrganizationConfig -AuditDisabled $false
#

function Apply-NRGEXOMailboxAudit {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [object] $Finding
    )

    $controlId = 'EXO-1.1'
    $result = [ordered]@{
        ControlId = $controlId
        Action    = 'Set-OrganizationConfig -AuditDisabled $false'
        Status    = 'Pending'
        Before    = $null
        After     = $null
        Error     = $null
        Timestamp = (Get-Date).ToString('o')
    }

    try {
        $current = $null
        try {
            $current = Get-OrganizationConfig -ErrorAction Stop
        } catch {
            $result.Status = 'Failed'
            $result.Error  = "Failed to read OrganizationConfig: $($_.Exception.Message)"
            return [PSCustomObject]$result
        }

        $result.Before = [PSCustomObject]@{
            AuditDisabled = $current.AuditDisabled
            Identity      = $current.Identity
        }

        if ($current.AuditDisabled -eq $false) {
            $result.Status = 'AlreadyCompliant'
            $result.After  = $result.Before
            return [PSCustomObject]$result
        }

        $target = "OrganizationConfig (tenant: $($current.Identity))"
        $action = 'Set AuditDisabled = $false (enables mailbox audit logging org-wide)'
        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            $result.Status = 'Skipped'
            return [PSCustomObject]$result
        }

        Set-OrganizationConfig -AuditDisabled $false -ErrorAction Stop

        $verify = Get-OrganizationConfig -ErrorAction Stop
        $result.After = [PSCustomObject]@{
            AuditDisabled = $verify.AuditDisabled
            Identity      = $verify.Identity
        }
        $result.Status = if ($verify.AuditDisabled -eq $false) { 'Applied' } else { 'Failed' }
        if ($result.Status -eq 'Failed') {
            $result.Error = 'Set succeeded but verification re-read shows AuditDisabled still true.'
        }
    } catch {
        $result.Status = 'Failed'
        $result.Error  = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

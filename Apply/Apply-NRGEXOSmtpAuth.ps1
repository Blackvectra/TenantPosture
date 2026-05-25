#Requires -Version 7.0
#
# Apply-NRGEXOSmtpAuth.ps1  (v4.6.1)
# Remediates EXO-1.2: Disable SMTP client authentication org-wide.
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# CONSUMES : Finding object for ControlId 'EXO-1.2'
# REQUIRES : ExchangeOnlineManagement.
# CMDLETS  : Get-TransportConfig, Set-TransportConfig
# SAFETY   : ShouldProcess gate, idempotency re-read.
#
# CHANGE   : Set-TransportConfig -SmtpClientAuthenticationDisabled $true
#
# NOTE: This disables SMTP AUTH at the tenant level only. Per-mailbox overrides
#       (Set-CASMailbox -SmtpClientAuthenticationDisabled $false) are NOT changed
#       by this remediation. Operator must audit per-mailbox exceptions separately.
#

function Apply-NRGEXOSmtpAuth {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [object] $Finding
    )

    $controlId = 'EXO-1.2'
    $result = [ordered]@{
        ControlId = $controlId
        Action    = 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
        Status    = 'Pending'
        Before    = $null
        After     = $null
        Error     = $null
        Timestamp = (Get-Date).ToString('o')
    }

    try {
        $current = $null
        try {
            $current = Get-TransportConfig -ErrorAction Stop
        } catch {
            $result.Status = 'Failed'
            $result.Error  = "Failed to read TransportConfig: $($_.Exception.Message)"
            return [PSCustomObject]$result
        }

        $result.Before = [PSCustomObject]@{
            SmtpClientAuthenticationDisabled = $current.SmtpClientAuthenticationDisabled
            Identity = $current.Identity
        }

        if ($current.SmtpClientAuthenticationDisabled -eq $true) {
            $result.Status = 'AlreadyCompliant'
            $result.After  = $result.Before
            return [PSCustomObject]$result
        }

        $target = "TransportConfig (tenant: $($current.Identity))"
        $action = 'Set SmtpClientAuthenticationDisabled = $true (disables SMTP AUTH tenant-wide; per-mailbox overrides preserved)'
        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            $result.Status = 'Skipped'
            return [PSCustomObject]$result
        }

        Set-TransportConfig -SmtpClientAuthenticationDisabled $true -ErrorAction Stop

        $verify = Get-TransportConfig -ErrorAction Stop
        $result.After = [PSCustomObject]@{
            SmtpClientAuthenticationDisabled = $verify.SmtpClientAuthenticationDisabled
            Identity = $verify.Identity
        }
        $result.Status = if ($verify.SmtpClientAuthenticationDisabled -eq $true) { 'Applied' } else { 'Failed' }
        if ($result.Status -eq 'Failed') {
            $result.Error = 'Set succeeded but verification re-read shows SmtpClientAuthenticationDisabled still false.'
        }
    } catch {
        $result.Status = 'Failed'
        $result.Error  = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

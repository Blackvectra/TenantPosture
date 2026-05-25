#Requires -Version 7.0
#
# Apply-NRGEXOAutoForward.ps1  (v4.6.1)
# Remediates EXO-1.3: Block external auto-forwarding via the Default remote domain.
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# CONSUMES : Finding object for ControlId 'EXO-1.3'
# REQUIRES : ExchangeOnlineManagement.
# CMDLETS  : Get-RemoteDomain, Set-RemoteDomain
# SAFETY   : ShouldProcess gate, idempotency re-read.
#
# CHANGE   : Set-RemoteDomain Default -AutoForwardEnabled $false
#
# SCOPE    : Modifies ONLY the Default (*) remote domain. Custom remote domains
#            for federated partners are not touched — operator must review those
#            separately if BEC tooling needs to forward to specific external orgs.
#

function Apply-NRGEXOAutoForward {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [object] $Finding
    )

    $controlId = 'EXO-1.3'
    $result = [ordered]@{
        ControlId = $controlId
        Action    = 'Set-RemoteDomain Default -AutoForwardEnabled $false'
        Status    = 'Pending'
        Before    = $null
        After     = $null
        Error     = $null
        Timestamp = (Get-Date).ToString('o')
    }

    try {
        $default = $null
        try {
            $default = Get-RemoteDomain -Identity 'Default' -ErrorAction Stop
        } catch {
            $result.Status = 'Failed'
            $result.Error  = "Failed to read Default remote domain: $($_.Exception.Message)"
            return [PSCustomObject]$result
        }

        $result.Before = [PSCustomObject]@{
            Identity            = $default.Identity
            DomainName          = $default.DomainName
            AutoForwardEnabled  = $default.AutoForwardEnabled
        }

        if ($default.AutoForwardEnabled -eq $false) {
            $result.Status = 'AlreadyCompliant'
            $result.After  = $result.Before
            return [PSCustomObject]$result
        }

        $target = "RemoteDomain 'Default' (DomainName: $($default.DomainName))"
        $action = 'Set AutoForwardEnabled = $false (blocks external auto-forwarding via the wildcard remote domain)'
        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            $result.Status = 'Skipped'
            return [PSCustomObject]$result
        }

        Set-RemoteDomain -Identity 'Default' -AutoForwardEnabled $false -ErrorAction Stop

        $verify = Get-RemoteDomain -Identity 'Default' -ErrorAction Stop
        $result.After = [PSCustomObject]@{
            Identity           = $verify.Identity
            DomainName         = $verify.DomainName
            AutoForwardEnabled = $verify.AutoForwardEnabled
        }
        $result.Status = if ($verify.AutoForwardEnabled -eq $false) { 'Applied' } else { 'Failed' }
        if ($result.Status -eq 'Failed') {
            $result.Error = 'Set succeeded but verification re-read shows AutoForwardEnabled still true.'
        }
    } catch {
        $result.Status = 'Failed'
        $result.Error  = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

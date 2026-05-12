#
# Invoke-NRGCollectPowerPlatform.ps1
# Collects Power Platform governance settings via Microsoft Graph (beta) and
# Microsoft.PowerApps.Administration.PowerShell where available.
#
# Requires: Microsoft Graph connection
# Scopes:   Organization.Read.All (for tenant isolation check via Graph beta)
#
# NOTE: Full Power Platform DLP policy collection requires the
# Microsoft.PowerApps.Administration.PowerShell module with separate auth.
# This collector uses Graph beta endpoints where available and gracefully skips
# any data requiring the PowerApps admin module.
#
# Data keys stored:
#   PowerPlatform.Environments        — Graph beta environments list
#   PowerPlatform.TenantIsolation     — Graph beta tenant isolation settings
#   PowerPlatform.DLPPolicies         — PowerApps admin module (if available)
#   PowerPlatform.DLPAvailable        — bool: whether DLP data was collected
#
# NIST SP 800-53: AC-3, CM-7, AC-17
# MITRE ATT&CK:   T1567, T1530
#

function Invoke-NRGCollectPowerPlatform {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'PowerPlatform'
        Timestamp  = (Get-Date -Format 'o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    try {
        # ── Power Platform environments (Graph beta) ───────────────────────────
        try {
            $envs = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/beta/admin/powerPlatform/environments' `
                -ErrorAction Stop
            $result.Data['Environments'] = if ($envs.value) { @($envs.value) } else { @() }
        } catch {
            $result.Exceptions += "Environments: $($_.Exception.Message)"
            $result.Data['Environments'] = @()
        }

        # ── Tenant isolation settings (Graph beta) ─────────────────────────────
        try {
            $isolation = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/beta/admin/powerPlatform/tenantIsolationSettings' `
                -ErrorAction Stop
            $result.Data['TenantIsolation'] = $isolation
        } catch {
            $result.Exceptions += "TenantIsolation: $($_.Exception.Message)"
            $result.Data['TenantIsolation'] = $null
        }

        # ── DLP policies via PowerApps admin module (optional) ─────────────────
        $dlpAvailable = $false
        $dlpPolicies  = @()
        try {
            if (Get-Module -ListAvailable -Name 'Microsoft.PowerApps.Administration.PowerShell' -ErrorAction SilentlyContinue) {
                Import-Module 'Microsoft.PowerApps.Administration.PowerShell' -ErrorAction Stop -WarningAction SilentlyContinue
                # Add-PowerAppsAccount uses existing Graph token via -Endpoint
                $dlpPolicies  = @(Get-DlpPolicy -ErrorAction Stop)
                $dlpAvailable = $true
            }
        } catch {
            $result.Exceptions += "DLPPolicies: $($_.Exception.Message)"
        }
        $result.Data['DLPPolicies']  = $dlpPolicies
        $result.Data['DLPAvailable'] = $dlpAvailable

        $result.Success = $true

    } catch {
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'Invoke-NRGCollectPowerPlatform' -Message $_.Exception.Message
    }

    Set-NRGRawData -Key 'PowerPlatform' -Data $result
    return $result
}

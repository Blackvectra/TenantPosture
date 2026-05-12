#
# Invoke-NRGCollectSharePoint.ps1
# Collects SharePoint Online tenant settings via Microsoft Graph.
#
# Requires: Microsoft Graph connection (Connect-MgGraph)
# Scopes:   SharePointTenantSettings.Read.All, Sites.Read.All
#
# Data keys stored:
#   SharePoint.TenantSettings  — GET /v1.0/admin/sharepoint/settings
#
# NIST SP 800-53: AC-3, AC-17, AC-22, SC-8
# MITRE ATT&CK:   T1530 (Data from Cloud Storage), T1567 (Exfil to Cloud)
#

function Invoke-NRGCollectSharePoint {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'SharePoint'
        Timestamp  = (Get-Date -Format 'o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    try {
        # ── Tenant-level SharePoint settings ──────────────────────────────────
        try {
            $settings = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' `
                -ErrorAction Stop
            $result.Data['TenantSettings'] = $settings
        } catch {
            $msg = $_.Exception.Message
            $result.Exceptions += "TenantSettings: $msg"
            # API may not be available in all tenants / Graph SDK versions
            $result.Data['TenantSettings'] = $null
            Register-NRGException -Source 'SPO-TenantSettings' -Message $msg
        }

        $result.Success = $true

    } catch {
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'Invoke-NRGCollectSharePoint' -Message $_.Exception.Message
    }

    Set-NRGRawData -Key 'SharePoint' -Data $result
    return $result
}

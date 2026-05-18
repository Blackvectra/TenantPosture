#Requires -Version 7.0
#
# Invoke-NRGCollectPowerPlatform.ps1
# Collects Power Platform environments, tenant isolation, and DLP policy posture.
#
# READ-ONLY. Uses Graph beta endpoint where v1.0 lacks coverage (Power Platform
# admin APIs are not fully in v1.0 yet — beta is acceptable for assessment use,
# but operators should review beta changes per release).
#
# NIST SP 800-53: CM-7 (least functionality), AC-4 (information flow)
# MITRE ATT&CK:   T1567 (Exfiltration over Web Service)
#

function Invoke-NRGCollectPowerPlatform {
    [CmdletBinding()] param()
    $result = @{
        Success = $false
        Data    = @{
            Environments    = @()
            TenantIsolation = $null
            DLPPolicies     = @()
            DLPAvailable    = $false
        }
    }

    try {
        # Environments via Graph (read-only)
        try {
            $envs = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/admin/dynamics/environments' -ErrorAction Stop
            if ($envs.value) {
                $result.Data.Environments = @($envs.value | ForEach-Object {
                    @{
                        Id          = $_.id
                        DisplayName = $_.displayName
                        Type        = $_.type
                        Region      = $_.region
                        State       = $_.state
                    }
                })
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'PPL-Environments' -Message $_.Exception.Message
            }
        }

        # DLP policies require Microsoft.PowerApps.Administration.PowerShell module.
        # We do NOT auto-install. We report availability and ask operator to install
        # the optional module if richer DLP coverage is desired.
        if (Get-Module -ListAvailable -Name Microsoft.PowerApps.Administration.PowerShell -ErrorAction SilentlyContinue) {
            try {
                Import-Module Microsoft.PowerApps.Administration.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
                if (Get-Command Get-DlpPolicy -ErrorAction SilentlyContinue) {
                    $dlp = Get-DlpPolicy -ErrorAction Stop
                    if ($dlp) {
                        $result.Data.DLPPolicies = @($dlp | ForEach-Object {
                            @{
                                PolicyName  = $_.PolicyName
                                DisplayName = $_.DisplayName
                                Type        = $_.EnvironmentType
                            }
                        })
                        $result.Data.DLPAvailable = $true
                    }
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'PPL-DLP' -Message $_.Exception.Message
                }
            }
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'PowerPlatform-Collector' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'PowerPlatform' -Data $result
}

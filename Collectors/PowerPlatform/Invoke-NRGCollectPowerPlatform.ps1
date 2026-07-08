#Requires -Version 7.0
#
# Invoke-NRGCollectPowerPlatform.ps1  (v4.6.4)
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Collect Power Platform environments, tenant isolation, and DLP policy
# posture for assessment evaluation.
#
# READ-ONLY. No tenant configuration is ever modified.
#
# Sets raw data key: 'PowerPlatform'
#
# v4.6.4 EMERGENCY FIX (Critical #1): The previous implementation called
# https://graph.microsoft.com/beta/admin/dynamics/environments which is NOT a
# real Microsoft Graph endpoint — it always returned 404. As a result, every
# PPL evaluator returned NotApplicable on every tenant. Power Platform
# assessment had never produced real findings.
#
# CORRECT SURFACES (in order of preference):
#   (A) Microsoft.PowerApps.Administration.PowerShell cmdlets
#       (Get-AdminPowerAppEnvironment, Get-DlpPolicy, Get-TenantIsolationPolicy).
#       Operator must install the optional module; we do NOT auto-install.
#   (B) Power Platform admin API (BAP / Business Application Platform):
#       https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/...
#       Requires a token for audience 'https://service.powerapps.com/' which is
#       acquired via Get-MgGraphAccessToken -ResourceUrl '...' on supported
#       SDK versions. Many tenants (BP licensing only, no PPA admin role) do
#       not grant the PPA admin token at all.
#   (C) Graceful degradation: if neither (A) nor (B) is feasible, mark
#       Success=$false with a clear error so the evaluator routes downstream
#       findings to NotApplicable instead of incorrectly to Gap or Satisfied.
#
# NIST SP 800-53: CM-7 (least functionality), AC-4 (information flow)
# MITRE ATT&CK:   T1567 (Exfiltration over Web Service)
#

function Invoke-NRGCollectPowerPlatform {
    [CmdletBinding()] param()
    $result = [ordered]@{
        CollectorId = 'PowerPlatform'
        CollectedAt = (Get-Date).ToString('o')
        Success     = $false
        Errors      = @()
        Data        = [ordered]@{
            Environments    = @()
            TenantIsolation = $null
            DLPPolicies     = @()
            DLPAvailable    = $false
            Source          = 'none'   # 'module' | 'bap-api' | 'none'
        }
    }

    $haveModule = [bool](Get-Module -ListAvailable -Name Microsoft.PowerApps.Administration.PowerShell -ErrorAction SilentlyContinue)

    # ── Path A: Microsoft.PowerApps.Administration.PowerShell module ─────────
    if ($haveModule) {
        try {
            Import-Module Microsoft.PowerApps.Administration.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
            $result.Data.Source = 'module'

            # Environments
            if (Get-Command Get-AdminPowerAppEnvironment -ErrorAction SilentlyContinue) {
                try {
                    $envs = @(Get-AdminPowerAppEnvironment -ErrorAction Stop)
                    $result.Data.Environments = @($envs | ForEach-Object {
                        [ordered]@{
                            Id          = [string]$_.EnvironmentName
                            DisplayName = [string]$_.DisplayName
                            Type        = [string]$_.EnvironmentType
                            Region      = [string]$_.Location
                            State       = [string]$_.CommonDataServiceDatabaseProvisioningState
                        }
                    })
                } catch {
                    $msg = "Get-AdminPowerAppEnvironment failed: $($_.Exception.Message)"
                    $result.Errors += $msg
                    if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                        Register-NRGException -Source 'PPL-Environments' -Message $msg
                    }
                }
            }

            # DLP policies
            if (Get-Command Get-DlpPolicy -ErrorAction SilentlyContinue) {
                try {
                    $dlp = @(Get-DlpPolicy -ErrorAction Stop)
                    if ($dlp) {
                        $result.Data.DLPPolicies = @($dlp | ForEach-Object {
                            # PPL-2.1: capture connector classification so the
                            # evaluator can confirm connectors are actually grouped.
                            # Get-DlpPolicy classifications are Confidential (Business),
                            # General (Non-Business), Blocked — match both naming
                            # conventions to stay robust across module versions.
                            $cg = @($_.connectorGroups)
                            [ordered]@{
                                PolicyName  = [string]$_.PolicyName
                                DisplayName = [string]$_.DisplayName
                                Type        = [string]$_.EnvironmentType
                                BusinessConnectors = @($cg | Where-Object { "$($_.classification)" -match 'Confidential|Business' } | ForEach-Object { @($_.connectors) } | Where-Object { $_ })
                                BlockedConnectors  = @($cg | Where-Object { "$($_.classification)" -match 'Blocked' } | ForEach-Object { @($_.connectors) } | Where-Object { $_ })
                            }
                        })
                        $result.Data.DLPAvailable = $true
                    }
                } catch {
                    $msg = "Get-DlpPolicy failed: $($_.Exception.Message)"
                    $result.Errors += $msg
                    if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                        Register-NRGException -Source 'PPL-DLP' -Message $msg
                    }
                }
            }

            # Tenant isolation
            if (Get-Command Get-PowerAppTenantIsolationPolicy -ErrorAction SilentlyContinue) {
                try {
                    $iso = Get-PowerAppTenantIsolationPolicy -ErrorAction Stop
                    if ($iso) {
                        $result.Data.TenantIsolation = [ordered]@{
                            IsDisabled = [bool]($iso.properties.isDisabled ?? $true)
                            Rules      = @($iso.properties.rules ?? @())
                        }
                    }
                } catch {
                    $msg = "Get-PowerAppTenantIsolationPolicy failed: $($_.Exception.Message)"
                    $result.Errors += $msg
                }
            }

            $result.Success = ($result.Data.Environments.Count -gt 0 -or $result.Data.DLPPolicies.Count -gt 0 -or $null -ne $result.Data.TenantIsolation)
        } catch {
            $msg = "Microsoft.PowerApps.Administration.PowerShell import failed: $($_.Exception.Message)"
            $result.Errors += $msg
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'PowerPlatform-Collector' -Message $msg
            }
        }
    }

    # ── Path B: BAP API fallback (only if module path failed/unavailable) ────
    if (-not $result.Success) {
        $bapTokenAcquired = $false
        $bapToken = $null
        try {
            if (Get-Command Get-MgGraphAccessToken -ErrorAction SilentlyContinue) {
                # Get-MgGraphAccessToken in newer SDKs supports -ResourceUrl
                # for non-Graph audiences when the underlying MSAL token cache
                # has the right consent. Older SDK versions throw; we treat
                # any failure as "no token, fall through to degradation".
                $bapToken = Get-MgGraphAccessToken -ResourceUrl 'https://service.powerapps.com/' -ErrorAction Stop
                $bapTokenAcquired = [bool]$bapToken
            }
        } catch {
            $bapTokenAcquired = $false
        }

        if ($bapTokenAcquired) {
            try {
                $hdr = @{ Authorization = "Bearer $bapToken" }
                $bapUri = 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/environments?api-version=2020-10-01'
                $bapResp = Invoke-RestMethod -Method GET -Uri $bapUri -Headers $hdr -ErrorAction Stop
                if ($bapResp.value) {
                    $result.Data.Source = 'bap-api'
                    $result.Data.Environments = @($bapResp.value | ForEach-Object {
                        [ordered]@{
                            Id          = [string]$_.name
                            DisplayName = [string]($_.properties.displayName ?? '')
                            Type        = [string]($_.properties.environmentSku ?? '')
                            Region      = [string]($_.location ?? '')
                            State       = [string]($_.properties.states.management.id ?? '')
                        }
                    })
                    $result.Success = $true
                }
            } catch {
                $msg = "BAP environments API failed: $($_.Exception.Message)"
                $result.Errors += $msg
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'PPL-Environments-BAP' -Message $msg
                }
            }
        }
    }

    # ── Path C: graceful degradation ─────────────────────────────────────────
    if (-not $result.Success) {
        $why = 'Power Platform admin API requires Microsoft.PowerApps.Administration.PowerShell module or PPA admin token — neither available'
        $result.Errors += $why
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'PowerPlatform-Collector' -Message $why
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'PowerPlatform' -Data $result
    }
    if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
        if ($result.Success) {
            $note = "Source=$($result.Data.Source) Envs=$($result.Data.Environments.Count) DLP=$($result.Data.DLPPolicies.Count)"
            $status = if ($result.Errors.Count -gt 0) { 'Partial' } else { 'Collected' }
            Register-NRGCoverage -Family 'PowerPlatform' -Status $status -Note $note
        } else {
            Register-NRGCoverage -Family 'PowerPlatform' -Status 'Failed' -Note ($result.Errors -join '; ')
        }
    }
    return $result
}

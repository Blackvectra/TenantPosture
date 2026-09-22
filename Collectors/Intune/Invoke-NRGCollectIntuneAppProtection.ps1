#Requires -Version 7.0
#
# Invoke-NRGCollectIntuneAppProtection.ps1  (v4.6.4)
# Collects Intune app protection (MAM) and app configuration policies.
#
# READ-ONLY: GET-only Graph calls. Does not create, modify, or remove configuration.
#
# Returns: structured hashtable under key 'Intune-AppProtection' via Set-NRGRawData.
# Reads:   deviceAppManagement/managedAppPolicies, deviceAppManagement/mobileAppConfigurations,
#          deviceAppManagement/targetedManagedAppConfigurations.
#
# NIST SP 800-53: AC-19 (access control for mobile devices), SC-28 (protection of
#                 information at rest), CM-7 (least functionality)
# MITRE ATT&CK:   T1530 (Data from Cloud Storage), T1567 (Exfiltration over Web Service)
#
# v4.6.4 EMERGENCY FIX (Critical #3): Added @odata.nextLink pagination to all
# three Graph calls. Default Graph page size is 100 — tenants with >100 MAM
# policies, app configs, or targeted configs silently truncated the rest.
# Pagination cap 200 (same as AAD-Users / AAD-Roles).
#

function Invoke-NRGCollectIntuneAppProtection {
    [CmdletBinding()] param()
    $result = @{
        Success = $false
        Data    = @{
            AppProtectionPolicies = @()
            AppConfigPolicies     = @()
        }
    }

    # Empty is not clean: every section below initializes to @(), so an empty
    # list cannot be told apart from a query that failed. App config policies come from both the MDM and MAM endpoints.
    # A section is only 'Failed' when EVERY query feeding it failed —
    # one surviving feeder still yields real data.
    $mamFailed = $false
    $cfgMdmFailed = $false
    $cfgMamFailed = $false

    try {
        # ── App protection (MAM) policies ────────────────────────────────────
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceAppManagement/managedAppPolicies'
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($p in @($page.value)) {
                    # Conditional-launch settings (INT-3.3): the MAM app-protection
                    # object carries these access-gating fields directly (no new
                    # scope). Read via ?? so absent keys are $null (HashTable shape).
                    $condLaunch = @()
                    if (($p.deviceComplianceRequired ?? $false) -eq $true)      { $condLaunch += 'DeviceComplianceRequired' }
                    if ($p.minimumRequiredOsVersion)                            { $condLaunch += 'MinimumRequiredOsVersion' }
                    if ([int]($p.maximumPinRetries ?? 0) -gt 0)                 { $condLaunch += 'MaximumPinRetries' }
                    if ($p.periodOfflineBeforeWipeIsEnforced)                   { $condLaunch += 'PeriodOfflineBeforeWipe' }
                    $result.Data.AppProtectionPolicies += @{
                        Id          = $p.id
                        DisplayName = [string]$p.displayName
                        Description = [string]$p.description
                        Type        = [string]$p['@odata.type']
                        Version     = $p.version
                        # Fields backing the INT-3.3 conditional-launch evaluation.
                        DeviceComplianceRequired  = [bool]($p.deviceComplianceRequired ?? $false)
                        MinimumRequiredOsVersion  = [string]($p.minimumRequiredOsVersion ?? '')
                        MaximumPinRetries         = [int]($p.maximumPinRetries ?? 0)
                        ConditionalLaunchSettings = @($condLaunch)
                    }
                }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Intune-AppProtection-MAM' `
                        -Message "Pagination cap reached ($maxPages pages); managed app policy list may be truncated."
                }
            }
        } catch {
            $mamFailed = $true
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-AppProtection-MAM' -Message $_.Exception.Message
            }
        }

        # ── App configuration policies — device-managed (MDM-channel) ────────
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileAppConfigurations'
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($p in @($page.value)) {
                    $result.Data.AppConfigPolicies += @{
                        Id          = $p.id
                        DisplayName = [string]$p.displayName
                        Description = [string]$p.description
                        Type        = [string]$p['@odata.type']
                        Channel     = 'MDM'
                    }
                }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Intune-AppProtection-AppCfg-MDM' `
                        -Message "Pagination cap reached ($maxPages pages); MDM app configuration list may be truncated."
                }
            }
        } catch {
            $cfgMdmFailed = $true
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-AppProtection-AppCfg-MDM' -Message $_.Exception.Message
            }
        }

        # ── App configuration policies — MAM-channel (targeted, no device enrollment) ──
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceAppManagement/targetedManagedAppConfigurations'
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($p in @($page.value)) {
                    $result.Data.AppConfigPolicies += @{
                        Id          = $p.id
                        DisplayName = [string]$p.displayName
                        Description = [string]$p.description
                        Type        = [string]$p['@odata.type']
                        Channel     = 'MAM'
                    }
                }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Intune-AppProtection-AppCfg-MAM' `
                        -Message "Pagination cap reached ($maxPages pages); targeted MAM app configuration list may be truncated."
                }
            }
        } catch {
            $cfgMamFailed = $true
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-AppProtection-AppCfg-MAM' -Message $_.Exception.Message
            }
        }

        $result.Data.SectionStatus = @{
            AppProtectionPolicies     = $(if ($mamFailed) { 'Failed' } else { 'Collected' })
            AppConfigPolicies         = $(if ($cfgMdmFailed -and $cfgMamFailed) { 'Failed' } else { 'Collected' })
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Intune-AppProtection-Collector' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'Intune-AppProtection' -Data $result
    # v4.6.4 EMERGENCY FIX (Critical #3): added missing Register-NRGCoverage call
    # per CLAUDE.md collector contract.
    if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
        $status = if ($result.Success) { 'Collected' } else { 'Failed' }
        $note   = "MAM=$($result.Data.AppProtectionPolicies.Count) AppCfg=$($result.Data.AppConfigPolicies.Count)"
        Register-NRGCoverage -Family 'Intune-AppProtection' -Status $status -Note $note
    }
}

#Requires -Version 7.0
#
# Invoke-TPCollectIntuneAppProtection.ps1  (v4.6.4)
# Collects Intune app protection (MAM) and app configuration policies.
#
# READ-ONLY: GET-only Graph calls. Does not create, modify, or remove configuration.
#
# Returns: structured hashtable under key 'Intune-AppProtection' via Set-TPRawData.
# Reads:   deviceAppManagement/managedAppPolicies, deviceAppManagement/mobileAppConfigurations,
#          deviceAppManagement/targetedManagedAppConfigurations, and (beta, with
#          assignments) iosManagedAppProtections and androidManagedAppProtections
#          for the Intune checklist. Scope: DeviceManagementApps.Read.All.
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

function Invoke-TPCollectIntuneAppProtection {
    [CmdletBinding()] param()
    $result = @{
        Success = $false
        Data    = @{
            AppProtectionPolicies = @()
            AppConfigPolicies     = @()
            # The iOS and Android app protection policies with their settings and
            # assignments, for the Intune checklist (Maester MT.1238-1251).
            AppProtectionDetail   = @()
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
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($p in @($page.value)) {
                    # Conditional-launch settings (INT-3.3): the MAM app-protection
                    # object carries these access-gating fields directly (no new
                    # scope). managedAppPolicies is polymorphic — a row that is not
                    # a managedAppProtection (e.g. targetedManagedAppConfiguration,
                    # mdmWindowsInformationProtectionPolicy) simply lacks these keys,
                    # so they are read through Get-TPObjectField: a bare dot-read
                    # throws on an absent hashtable key under StrictMode even with
                    # a trailing '??' (see Invoke-TPGraphRequest.ps1 header).
                    # A property Graph did not return is stored as $null (not read),
                    # never as the value that would fail or pass the check.
                    $dcr                      = Get-TPObjectField -Item $p -Key 'deviceComplianceRequired' -Default $null
                    $deviceComplianceRequired = $(if ($null -eq $dcr) { $null } else { [bool]$dcr })
                    $minimumRequiredOsVersion = [string](Get-TPObjectField -Item $p -Key 'minimumRequiredOsVersion' -Default '')
                    $mpr                      = Get-TPObjectField -Item $p -Key 'maximumPinRetries' -Default $null
                    $maximumPinRetries        = $(if ($null -eq $mpr) { $null } else { [int]$mpr })
                    # ISO 8601 durations (Graph Duration), kept as returned:
                    # periodOfflineBeforeAccessCheck is the conditional launch
                    # "Offline grace period / Block access", periodOfflineBeforeWipeIsEnforced
                    # the "Offline grace period / Wipe data".
                    $periodOfflineBeforeAccess = Get-TPObjectField -Item $p -Key 'periodOfflineBeforeAccessCheck' -Default $null
                    $periodOfflineBeforeWipe   = Get-TPObjectField -Item $p -Key 'periodOfflineBeforeWipeIsEnforced' -Default $null
                    $condLaunch = @()
                    if ($deviceComplianceRequired -eq $true) { $condLaunch += 'DeviceComplianceRequired' }
                    if ($minimumRequiredOsVersion)           { $condLaunch += 'MinimumRequiredOsVersion' }
                    if ($null -ne $maximumPinRetries -and $maximumPinRetries -gt 0) { $condLaunch += 'MaximumPinRetries' }
                    if ($periodOfflineBeforeWipe)             { $condLaunch += 'PeriodOfflineBeforeWipe' }
                    # managedAppPolicies also returns app CONFIGURATION and WIP
                    # policies; only *ManagedAppProtection types protect data.
                    $ptype = [string](Get-TPObjectField -Item $p -Key '@odata.type' -Default '')
                    if ($ptype -notmatch 'ManagedAppProtection$') { continue }
                    $result.Data.AppProtectionPolicies += @{
                        Id          = (Get-TPObjectField -Item $p -Key 'id' -Default $null)
                        DisplayName = [string](Get-TPObjectField -Item $p -Key 'displayName' -Default '')
                        Description = [string](Get-TPObjectField -Item $p -Key 'description' -Default '')
                        Type        = [string](Get-TPObjectField -Item $p -Key '@odata.type' -Default '')
                        Version     = (Get-TPObjectField -Item $p -Key 'version' -Default $null)
                        # Fields backing the INT-3.3 conditional-launch evaluation.
                        DeviceComplianceRequired  = $deviceComplianceRequired
                        MinimumRequiredOsVersion  = $minimumRequiredOsVersion
                        MaximumPinRetries         = $maximumPinRetries
                        PeriodOfflineBeforeAccessCheck    = $(if ($null -eq $periodOfflineBeforeAccess) { $null } else { [string]$periodOfflineBeforeAccess })
                        PeriodOfflineBeforeWipeIsEnforced = $(if ($null -eq $periodOfflineBeforeWipe) { $null } else { [string]$periodOfflineBeforeWipe })
                        IsAssigned                = Get-TPObjectField -Item $p -Key 'isAssigned' -Default $null
                        ConditionalLaunchSettings = @($condLaunch)
                    }
                }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'Intune-AppProtection-MAM' `
                        -Message "Pagination cap reached ($maxPages pages); managed app policy list may be truncated."
                }
            }
        } catch {
            $mamFailed = $true
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Intune-AppProtection-MAM' -Message $_.Exception.Message
            }
        }

        # ── App configuration policies — device-managed (MDM-channel) ────────
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileAppConfigurations'
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($p in @($page.value)) {
                    $result.Data.AppConfigPolicies += @{
                        Id          = (Get-TPObjectField -Item $p -Key 'id' -Default $null)
                        DisplayName = [string](Get-TPObjectField -Item $p -Key 'displayName' -Default '')
                        Description = [string](Get-TPObjectField -Item $p -Key 'description' -Default '')
                        Type        = [string](Get-TPObjectField -Item $p -Key '@odata.type' -Default '')
                        Channel     = 'MDM'
                    }
                }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'Intune-AppProtection-AppCfg-MDM' `
                        -Message "Pagination cap reached ($maxPages pages); MDM app configuration list may be truncated."
                }
            }
        } catch {
            $cfgMdmFailed = $true
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Intune-AppProtection-AppCfg-MDM' -Message $_.Exception.Message
            }
        }

        # ── App configuration policies — MAM-channel (targeted, no device enrollment) ──
        try {
            $next = 'https://graph.microsoft.com/v1.0/deviceAppManagement/targetedManagedAppConfigurations'
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                foreach ($p in @($page.value)) {
                    $result.Data.AppConfigPolicies += @{
                        Id          = (Get-TPObjectField -Item $p -Key 'id' -Default $null)
                        DisplayName = [string](Get-TPObjectField -Item $p -Key 'displayName' -Default '')
                        Description = [string](Get-TPObjectField -Item $p -Key 'description' -Default '')
                        Type        = [string](Get-TPObjectField -Item $p -Key '@odata.type' -Default '')
                        Channel     = 'MAM'
                    }
                }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'Intune-AppProtection-AppCfg-MAM' `
                        -Message "Pagination cap reached ($maxPages pages); targeted MAM app configuration list may be truncated."
                }
            }
        } catch {
            $cfgMamFailed = $true
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Intune-AppProtection-AppCfg-MAM' -Message $_.Exception.Message
            }
        }

        # ── iOS and Android app protection, with settings and assignments ─────
        # The platform endpoints return each policy's own settings and expand its
        # assignments (managedAppPolicies does neither). Beta, as Maester reads
        # them; DeviceManagementApps.Read.All, already requested. Each platform is
        # its own section, so one failed read never reads as "no policy".
        $detailStatus = @{ IosAppProtection = 'NotRun'; AndroidAppProtection = 'NotRun' }
        foreach ($plat in @(@('IosAppProtection', 'iOS', 'iosManagedAppProtections'), @('AndroidAppProtection', 'Android', 'androidManagedAppProtections'))) {
            try {
                $rows = @(Get-TPGraphAllPages -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$($plat[2])?`$expand=assignments")
                foreach ($p in $rows) {
                    if ($null -eq $p) { continue }
                    $result.Data.AppProtectionDetail += [ordered]@{
                        Id                       = [string](Get-TPObjectField -Item $p -Key 'id' -Default '')
                        DisplayName              = [string](Get-TPObjectField -Item $p -Key 'displayName' -Default '')
                        Platform                 = $plat[1]
                        IsAssignedFlag           = ((Get-TPObjectField -Item $p -Key 'isAssigned' -Default $null) -eq $true)
                        InclusionAssignmentCount = (Get-TPAppProtectionInclusionCount -Policy $p)
                        Settings                 = (Get-TPAppProtectionSettingSnapshot -Policy $p)
                    }
                }
                $detailStatus[$plat[0]] = 'Collected'
            } catch {
                $detailStatus[$plat[0]] = 'Failed'
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source "Intune-AppProtection-$($plat[1])" -Message $_.Exception.Message
                }
            }
        }

        $result.Data.SectionStatus = @{
            AppProtectionPolicies     = $(if ($mamFailed) { 'Failed' } else { 'Collected' })
            AppConfigPolicies         = $(if ($cfgMdmFailed -and $cfgMamFailed) { 'Failed' } else { 'Collected' })
            IosAppProtection          = $detailStatus.IosAppProtection
            AndroidAppProtection      = $detailStatus.AndroidAppProtection
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'Intune-AppProtection-Collector' -Message $_.Exception.Message
        }
    }

    Set-TPRawData -Key 'Intune-AppProtection' -Data $result
    # v4.6.4 EMERGENCY FIX (Critical #3): added missing Register-TPCoverage call
    # per CLAUDE.md collector contract.
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        $status = if ($result.Success) { 'Collected' } else { 'Failed' }
        $note   = "MAM=$($result.Data.AppProtectionPolicies.Count) AppCfg=$($result.Data.AppConfigPolicies.Count)"
        Register-TPCoverage -Family 'Intune-AppProtection' -Status $status -Note $note
    }
}


# The app protection settings the Intune checklist judges, by Graph name. Only
# keys the policy returned are kept: absent is "not returned", never "off".
function Get-TPAppProtectionSettingSnapshot {
    [CmdletBinding()]
    param([AllowNull()] $Policy)
    $names = @(
        'pinRequired', 'minimumPinLength', 'maximumPinRetries', 'simplePinBlocked', 'disableAppPinIfDevicePinIsSet',
        'allowedOutboundDataTransferDestinations', 'allowedOutboundClipboardSharingLevel', 'saveAsBlocked', 'dataBackupBlocked',
        'minimumRequiredOsVersion', 'minimumRequiredAppVersion', 'minimumRequiredPatchVersion',
        'periodOfflineBeforeAccessCheck', 'periodOfflineBeforeWipeIsEnforced',
        'maximumAllowedDeviceThreatLevel', 'mobileThreatDefenseRemediationAction',
        'appDataEncryptionType', 'encryptAppData', 'disableAppEncryptionIfDeviceEncryptionIsEnabled', 'screenCaptureBlocked',
        'requiredAndroidSafetyNetDeviceAttestationType', 'appActionIfAndroidSafetyNetDeviceAttestationFailed'
    )
    $out = [ordered]@{}
    if ($null -eq $Policy) { return $out }
    foreach ($n in $names) {
        $present = if ($Policy -is [System.Collections.IDictionary]) { $Policy.Contains($n) } else { $null -ne $Policy.PSObject.Properties[$n] }
        if ($present) { $out[$n] = Get-TPObjectField -Item $Policy -Key $n -Default $null }
    }
    return $out
}

# Assignments that include someone (an exclusion target reaches nobody);
# $null when the assignments were not returned.
function Get-TPAppProtectionInclusionCount {
    [CmdletBinding()]
    param([AllowNull()] $Policy)
    if ($null -eq $Policy) { return $null }
    if ($Policy -is [System.Collections.IDictionary]) {
        if (-not $Policy.Contains('assignments')) { return $null }
        $list = $Policy['assignments']
    } else {
        $prop = $Policy.PSObject.Properties['assignments']
        if ($null -eq $prop) { return $null }
        $list = $prop.Value
    }
    return @(@($list) | Where-Object { $null -ne $_ } | Where-Object {
            $t = [string](Get-TPObjectField -Item (Get-TPObjectField -Item $_ -Key 'target' -Default $null) -Key '@odata.type' -Default '')
            $t -and $t -notmatch '(^|\.)exclusion'
        }).Count
}

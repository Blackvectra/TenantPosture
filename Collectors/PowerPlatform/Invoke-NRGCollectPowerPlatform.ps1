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
#   (A) Microsoft.PowerApps.Administration.PowerShell cmdlets in THIS session
#       (Get-AdminPowerAppEnvironment, Get-DlpPolicy,
#       Get-PowerAppTenantIsolationPolicy, Get-TenantSettings). Microsoft
#       documents the module as .NET Framework / Windows PowerShell 5.x only,
#       so under PowerShell 7 this usually fails to import or to sign in.
#   (B) The same module run in a Windows PowerShell 5.1 child process
#       (Invoke-NRGPowerPlatformBridge) — Microsoft's supported host for it.
#       Windows only; the module must be installed for Windows PowerShell
#       (Install-Module Microsoft.PowerApps.Administration.PowerShell from a
#       Windows PowerShell 5.1 prompt). Signs in with Add-PowerAppsAccount
#       pinned to the Graph tenant, so it cannot read another tenant. Output
#       comes back over stdout as JSON. The child's code is written to a
#       temp .ps1 for the length of the call (code only, no tenant data).
#   (C) Graceful degradation: if neither (A) nor (B) is feasible, mark
#       Success=$false with the specific reason so the evaluator routes
#       downstream findings to NotApplicable instead of Gap or Satisfied.
#
#   The previous path (B) called Get-MgGraphAccessToken, which is not a
#   Microsoft Graph PowerShell cmdlet, so it never ran.
#
# Tenant pinning: the child signs in with -TenantID = the Graph context
#   tenant; with no Graph context the bridge does not run.
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
            # Tenant governance flags (PPL-1.3). $null means "not read" — the
            # BAP-API fallback path below cannot retrieve these, so the
            # evaluator must not read absence as "creation is unrestricted".
            TenantGovernance = $null
            # Environments initializes to @(), so an empty list cannot be told
            # apart from a query that failed — and zero environments is a
            # legitimate compliant answer, which is exactly what made the
            # confusion dangerous. Tracked explicitly.
            SectionStatus    = @{ TenantGovernance = 'NotRun'; Environments = 'NotRun' }
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
                    $result.Data.SectionStatus.Environments = 'Collected'
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
                        # .properties is a nested object on the returned
                        # policy that is not guaranteed present on every
                        # module version/tenant shape — a bare chained read
                        # throws under StrictMode at the first absent
                        # intermediate.
                        $result.Data.TenantIsolation = [ordered]@{
                            IsDisabled = [bool](Get-NRGNestedProperty -Object $iso -Path 'properties.isDisabled' -Default $true)
                            Rules      = @(Get-NRGNestedProperty -Object $iso -Path 'properties.rules' -Default @())
                        }
                    }
                } catch {
                    $msg = "Get-PowerAppTenantIsolationPolicy failed: $($_.Exception.Message)"
                    $result.Errors += $msg
                }
            }

            # Tenant governance settings (PPL-1.3 environment creation).
            # Get-TenantSettings returns a nested object; the governance flag
            # documented by Microsoft is
            # powerPlatform.governance.disableEnvironmentCreationByNonAdminUsers.
            # Property casing has varied across module versions, so read it
            # defensively rather than assuming one spelling, and record whether
            # the call actually ran so the evaluator can tell "not restricted"
            # apart from "never read".
            if (Get-Command Get-TenantSettings -ErrorAction SilentlyContinue) {
                try {
                    $ts = Get-TenantSettings -ErrorAction Stop
                    $gov = $null
                    if ($ts) {
                        $pp  = if ($ts.PSObject.Properties['powerPlatform']) { $ts.powerPlatform } else { $null }
                        $gov = if ($pp -and $pp.PSObject.Properties['governance']) { $pp.governance } else { $null }
                    }
                    $flag = $null
                    foreach ($name in @('disableEnvironmentCreationByNonAdminUsers',
                                        'disableEnvironmentCreationByNonAdminusers')) {
                        if ($gov -and $gov.PSObject.Properties[$name]) { $flag = [bool]$gov.$name; break }
                        if ($null -eq $flag -and $ts -and $ts.PSObject.Properties[$name]) { $flag = [bool]$ts.$name; break }
                    }
                    $trial = $null
                    foreach ($name in @('disableTrialEnvironmentCreationByNonAdminUsers',
                                        'disableTrialEnvironmentCreationByNonAdminusers')) {
                        if ($gov -and $gov.PSObject.Properties[$name]) { $trial = [bool]$gov.$name; break }
                    }
                    $result.Data.TenantGovernance = [ordered]@{
                        EnvironmentCreationRestricted      = $flag
                        TrialEnvironmentCreationRestricted = $trial
                    }
                    $result.Data.SectionStatus.TenantGovernance = 'Collected'
                } catch {
                    $result.Data.SectionStatus.TenantGovernance = 'Failed'
                    $msg = "Get-TenantSettings failed: $($_.Exception.Message)"
                    $result.Errors += $msg
                    if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                        Register-NRGException -Source 'PPL-TenantSettings' -Message $msg
                    }
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

    # ── Path B: Windows PowerShell 5.1 bridge ─────────────────────────────────
    $bridgeWhy = $null
    if (-not $result.Success) {
        $tenantId = $null
        try { $ctx = Get-MgContext -ErrorAction Stop; if ($ctx) { $tenantId = [string]$ctx.TenantId } } catch { $tenantId = $null }
        if (-not $tenantId) {
            $bridgeWhy = 'no Graph tenant context to pin the Power Platform sign-in to'
        } else {
            $bridge = $null
            try { $bridge = Invoke-NRGPowerPlatformBridge -TenantId $tenantId } catch { $bridge = $null; $bridgeWhy = "Windows PowerShell bridge failed: $($_.Exception.Message)" }
            if ($bridge) {
                $state = [string](Get-NRGObjectField -Item $bridge -Key 'State' -Default '')
                if ($state -eq 'NotWindows') {
                    $bridgeWhy = 'the Power Platform admin module runs only in Windows PowerShell 5.1, which is not available on this platform'
                } elseif ($state -eq 'NoModule') {
                    $bridgeWhy = 'Microsoft.PowerApps.Administration.PowerShell is not installed for Windows PowerShell 5.1 (from a Windows PowerShell prompt: Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser)'
                } elseif ($state -eq 'SignInFailed') {
                    $bridgeWhy = "Power Platform sign-in failed: $([string](Get-NRGObjectField -Item $bridge -Key 'Error' -Default ''))"
                } elseif ($state -eq 'Ran') {
                    $result.Data.Source = 'module-winps'
                    foreach ($e in @(Get-NRGObjectField -Item $bridge -Key 'Errors' -Default @())) {
                        if (-not $e) { continue }
                        $result.Errors += "$e"
                        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                            Register-NRGException -Source 'PPL-WinPSBridge' -Message "$e"
                        }
                    }
                    $envs = Get-NRGObjectField -Item $bridge -Key 'Environments' -Default $null
                    if ($null -ne $envs) {
                        $result.Data.SectionStatus.Environments = 'Collected'
                        $result.Data.Environments = @(@($envs) | Where-Object { $_ } | ForEach-Object {
                            [ordered]@{
                                Id          = [string](Get-NRGObjectField -Item $_ -Key 'EnvironmentName' -Default '')
                                DisplayName = [string](Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '')
                                Type        = [string](Get-NRGObjectField -Item $_ -Key 'EnvironmentType' -Default '')
                                Region      = [string](Get-NRGObjectField -Item $_ -Key 'Location' -Default '')
                                State       = [string](Get-NRGObjectField -Item $_ -Key 'CommonDataServiceDatabaseProvisioningState' -Default '')
                            }
                        })
                    }
                    $dlp = @(Get-NRGObjectField -Item $bridge -Key 'DlpPolicies' -Default @()) | Where-Object { $_ }
                    if (@($dlp).Count -gt 0) {
                        $result.Data.DLPPolicies = @($dlp | ForEach-Object {
                            $cg = @(Get-NRGObjectField -Item $_ -Key 'connectorGroups' -Default @())
                            [ordered]@{
                                PolicyName  = [string](Get-NRGObjectField -Item $_ -Key 'PolicyName' -Default '')
                                DisplayName = [string](Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '')
                                Type        = [string](Get-NRGObjectField -Item $_ -Key 'EnvironmentType' -Default '')
                                BusinessConnectors = @($cg | Where-Object { "$(Get-NRGObjectField -Item $_ -Key 'classification' -Default '')" -match 'Confidential|Business' } | ForEach-Object { @(Get-NRGObjectField -Item $_ -Key 'connectors' -Default @()) } | Where-Object { $_ })
                                BlockedConnectors  = @($cg | Where-Object { "$(Get-NRGObjectField -Item $_ -Key 'classification' -Default '')" -match 'Blocked' } | ForEach-Object { @(Get-NRGObjectField -Item $_ -Key 'connectors' -Default @()) } | Where-Object { $_ })
                            }
                        })
                        $result.Data.DLPAvailable = $true
                    }
                    $iso = Get-NRGObjectField -Item $bridge -Key 'TenantIsolation' -Default $null
                    if ($null -ne $iso) {
                        $result.Data.TenantIsolation = [ordered]@{
                            IsDisabled = [bool](Get-NRGNestedProperty -Object $iso -Path 'properties.isDisabled' -Default $true)
                            Rules      = @(Get-NRGNestedProperty -Object $iso -Path 'properties.rules' -Default @())
                        }
                    }
                    $ts = Get-NRGObjectField -Item $bridge -Key 'TenantSettings' -Default $null
                    if ($null -ne $ts) {
                        $gov = Get-NRGNestedProperty -Object $ts -Path 'powerPlatform.governance' -Default $null
                        $flag = $null; $trial = $null
                        foreach ($name in @('disableEnvironmentCreationByNonAdminUsers', 'disableEnvironmentCreationByNonAdminusers')) {
                            $v = Get-NRGObjectField -Item $gov -Key $name -Default $null
                            if ($null -ne $v) { $flag = [bool]$v; break }
                        }
                        foreach ($name in @('disableTrialEnvironmentCreationByNonAdminUsers', 'disableTrialEnvironmentCreationByNonAdminusers')) {
                            $v = Get-NRGObjectField -Item $gov -Key $name -Default $null
                            if ($null -ne $v) { $trial = [bool]$v; break }
                        }
                        $result.Data.TenantGovernance = [ordered]@{
                            EnvironmentCreationRestricted      = $flag
                            TrialEnvironmentCreationRestricted = $trial
                        }
                        $result.Data.SectionStatus.TenantGovernance = 'Collected'
                    } elseif ([bool](Get-NRGObjectField -Item $bridge -Key 'TenantSettingsFailed' -Default $false)) {
                        $result.Data.SectionStatus.TenantGovernance = 'Failed'
                    }
                    $result.Success = ($result.Data.Environments.Count -gt 0 -or $result.Data.DLPPolicies.Count -gt 0 -or $null -ne $result.Data.TenantIsolation)
                    if (-not $result.Success) { $bridgeWhy = 'Windows PowerShell bridge ran but returned no Power Platform data (see Exceptions)' }
                } elseif (-not $bridgeWhy) {
                    $bridgeWhy = 'Windows PowerShell bridge returned an unreadable result'
                }
            } elseif (-not $bridgeWhy) {
                $bridgeWhy = 'Windows PowerShell 5.1 (powershell.exe) was not found'
            }
        }
    }

    # ── Path C: graceful degradation ─────────────────────────────────────────
    if (-not $result.Success) {
        $why = "Power Platform not collected: $(if ($bridgeWhy) { $bridgeWhy } else { 'admin module unavailable' })"
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

# Runs the Power Platform admin module in Windows PowerShell 5.1 and returns
# its output parsed from JSON, or $null when powershell.exe is not present.
# The child prints exactly one line between the markers; anything else it
# writes (banners, warnings) is ignored. Read-only: Get-* cmdlets only.
function Invoke-NRGPowerPlatformBridge {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $TenantId)

    if (-not $IsWindows) { return [pscustomobject]@{ State = 'NotWindows' } }
    $exe = Get-Command 'powershell.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $exe) { return $null }

    $child = @'
param([string] $TenantId)
$ErrorActionPreference = 'Stop'
$out = [ordered]@{ State = 'Ran'; Errors = @() }
function Emit { param($o) Write-Output ('<<NRG-PPL>>' + ($o | ConvertTo-Json -Depth 10 -Compress) + '<<NRG-PPL>>') }
if (-not (Get-Module -ListAvailable -Name Microsoft.PowerApps.Administration.PowerShell)) { Emit @{ State = 'NoModule' }; return }
try {
    Import-Module Microsoft.PowerApps.Administration.PowerShell -WarningAction SilentlyContinue
    Add-PowerAppsAccount -Endpoint prod -TenantID $TenantId | Out-Null
} catch { Emit @{ State = 'SignInFailed'; Error = "$($_.Exception.Message)" }; return }
try { $out.Environments = @(Get-AdminPowerAppEnvironment | Select-Object EnvironmentName, DisplayName, EnvironmentType, Location, CommonDataServiceDatabaseProvisioningState) }
catch { $out.Errors += "Get-AdminPowerAppEnvironment failed: $($_.Exception.Message)" }
try { $out.DlpPolicies = @(Get-DlpPolicy | ForEach-Object { if ($_.PSObject.Properties['value']) { $_.value } else { $_ } } | Select-Object PolicyName, DisplayName, EnvironmentType, connectorGroups) }
catch { $out.Errors += "Get-DlpPolicy failed: $($_.Exception.Message)" }
try { $out.TenantIsolation = Get-PowerAppTenantIsolationPolicy -TenantId $TenantId }
catch { $out.Errors += "Get-PowerAppTenantIsolationPolicy failed: $($_.Exception.Message)" }
try { $out.TenantSettings = Get-TenantSettings }
catch { $out.TenantSettingsFailed = $true; $out.Errors += "Get-TenantSettings failed: $($_.Exception.Message)" }
Emit $out
'@
    # A plain script file, not -EncodedCommand: base64-encoded PowerShell is
    # a stock EDR detection and this tool runs on MSP workstations under EDR.
    # The file holds only the code above (no tenant data) and is deleted
    # before this function returns.
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-ppl-" + [guid]::NewGuid().ToString('N') + '.ps1')
    try {
        [IO.File]::WriteAllText($tmp, $child, [Text.Encoding]::ASCII)
        $lines = @(& $exe.Source -NoProfile -ExecutionPolicy Bypass -File $tmp -TenantId $TenantId.ToLowerInvariant() 2>$null)
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    $text = ($lines | ForEach-Object { "$_" }) -join "`n"
    if ($text -notmatch '<<NRG-PPL>>(.+?)<<NRG-PPL>>') { throw 'no result marker in Windows PowerShell output' }
    return ($Matches[1] | ConvertFrom-Json -ErrorAction Stop)
}

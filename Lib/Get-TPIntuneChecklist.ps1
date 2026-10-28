#Requires -Version 7.0
#
# Get-TPIntuneChecklist.ps1
# Dependencies: Get-TPObjectField, Get-TPNestedProperty
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: The Intune and endpoint checklist, the way Maester checks it (owner,
#   2026-10-28: "follow the way Maester does it"): tenant settings (MT.1053,
#   MT.1054, MT.1105), iOS, Android and macOS compliance policies (MT.1214-1216,
#   MT.1228-1237), iOS and Android app protection (MT.1238-1251), the standard
#   protection ASR rules (MT.1178), Windows LAPS (MT.1177) and the Microsoft
#   Defender Antivirus values (MT.1148-1171), each
#   with what to set in the Intune admin center when it is not met.
#
# HOW A ROW IS JUDGED (Maester's rules, ported)
#   - Compliance rows: at least one ASSIGNED policy of the platform (assigned =
#     an inclusion target; an exclusion reaches nobody) sets the value Maester
#     requires. A matching policy that is not assigned is named, never a pass.
#   - ASR: the three standard protection rules in Block or Audit, across the
#     assigned ASR policies (the strongest mode wins, as Maester's union does).
#   - LAPS: one assigned LAPS policy backs up to Entra ID with four-class
#     complexity, length 14 or more and a post-authentication reset.
#   - Antivirus: EVERY assigned antivirus policy whose settings were read sets
#     the value (Maester's "AllPolicies"); a policy that does not set it counts
#     against the row, as in Maester.
#
# WHERE THIS DIFFERS FROM MAESTER (each stated in the output)
#   - No policy for a platform and no managed device of that platform is "Does
#     not apply"; Maester fails it.
#   - Android rows judge every Android policy type that returns the property
#     (device administrator, work profile, fully managed); Maester judges the
#     device administrator type only.
#   - Gatekeeper (MT.1215) judges the compliance policy only; a macOS
#     configuration profile is not read.
#   - ASR and LAPS count assigned policies only (Maester counts every policy),
#     and read endpoint-security ASR policies, not ASR rules set in a general
#     Settings Catalog policy.
#   - Sample submission (MT.1171) accepts the two values that send samples
#     automatically; Maester also accepts "never send".
#   - Data not read (a failed section, an older results file without the
#     setting snapshot) is "Not assessed", never passed or failed.
#
# A VIEW: no finding, no score. Nothing it writes says "compliant" about the
# tenant; "compliance policy" is Intune's own name for the object.
#
# Inputs:  -RawData (Get-TPRawData output), -ConfigPath, -Now (tests).
# Graph scopes / cmdlets used: none (it reads raw data already collected).

function Get-TPIntuneChecklistCatalog {
    [CmdletBinding()]
    param([AllowEmptyString()] [string] $Path = '')
    if (-not $Path) { $Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config/intune-checklist.json' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable)
}

function Get-TPIntuneChecklist {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [object] $RawData,
        [AllowEmptyString()] [string] $ConfigPath = '',
        [datetime] $Now = [datetime]::UtcNow
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not $PSBoundParameters.ContainsKey('RawData')) { $RawData = try { Get-TPRawData } catch { $null } }
    $catalog = Get-TPIntuneChecklistCatalog -Path $ConfigPath
    $names = Get-TPCAChecklistStatusNames
    if ($null -eq $catalog) {
        return [ordered]@{ Available = $false; Note = 'The Intune checklist catalog (Config/intune-checklist.json) was not found.'; Rows = @(); StatusNames = $names }
    }

    $raw = { param([string] $Key) if ($null -eq $RawData) { $null } else { Get-TPObjectField -Item $RawData -Key $Key -Default $null } }
    $ok = { param($Entry) $null -ne $Entry -and (Get-TPObjectField -Item $Entry -Key 'Success' -Default $false) -eq $true }
    $section = { param($Entry, [string] $Name) [string](Get-TPNestedProperty -Object $Entry -Path "Data.SectionStatus.$Name" -Default '') }
    $field = { param($Obj, [string] $Path, $Default = $null) Get-TPNestedProperty -Object $Obj -Path $Path -Default $Default }

    $dc = & $raw 'Intune-DeviceCompliance'
    $es = & $raw 'Intune-EndpointSecurity'
    $dcRead = & $ok $dc
    $esRead = & $ok $es
    $policiesRead = $dcRead -and (& $section $dc 'CompliancePolicies') -notin @('Failed', 'NotRun')
    $compliance = @()
    if ($policiesRead) { $compliance = @(& $field $dc 'Data.CompliancePolicies' @() | Where-Object { $null -ne $_ }) }
    $byPlatform = & $field $dc 'Data.OSComplianceSummary.ByPlatform' $null
    $devicesRead = $dcRead -and (& $section $dc 'OSComplianceSummary') -notin @('Failed', 'NotRun') -and $null -ne $byPlatform
    $deviceCount = { param([string[]] $Os)
        if (-not $devicesRead) { return $null }
        $n = 0
        foreach ($k in @(if ($byPlatform -is [System.Collections.IDictionary]) { $byPlatform.Keys } else { $byPlatform.PSObject.Properties.Name })) {
            if ([string]$k -in $Os) { $n += [int](Get-TPObjectField -Item $byPlatform -Key $k -Default 0) }
        }
        return $n
    }

    $platformTypes = @{
        iOS     = @('#microsoft.graph.iosCompliancePolicy')
        Android = @('#microsoft.graph.androidCompliancePolicy', '#microsoft.graph.androidWorkProfileCompliancePolicy', '#microsoft.graph.androidDeviceOwnerCompliancePolicy')
        macOS   = @('#microsoft.graph.macOSCompliancePolicy')
    }
    $platformOs = @{ iOS = @('iOS', 'iPadOS'); Android = @('Android'); macOS = @('macOS', 'MacMDM') }
    $assigned = { param($Pol)
        $inc = Get-TPObjectField -Item $Pol -Key 'InclusionAssignmentCount' -Default $null
        if ($null -ne $inc) { return ([int]$inc -gt 0) }
        return ((Get-TPObjectField -Item $Pol -Key 'IsAssigned' -Default $null) -eq $true)
    }
    $setting = { param($Pol, [string] $Name)
        $s = Get-TPObjectField -Item $Pol -Key 'Settings' -Default $null
        if ($null -eq $s) { return [pscustomobject]@{ Present = $false; Value = $null } }
        $present = if ($s -is [System.Collections.IDictionary]) { $s.Contains($Name) } else { $null -ne $s.PSObject.Properties[$Name] }
        return [pscustomobject]@{ Present = $present; Value = $(if ($present) { Get-TPObjectField -Item $s -Key $Name -Default $null } else { $null }) }
    }
    $num = { param($Value) $out = 0; if ($null -ne $Value -and [int]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Integer, [cultureinfo]::InvariantCulture, [ref]$out)) { return $out }; return $null }

    # Per-check tests over one policy: $true met, $false not met, $null not
    # returned by this policy type.
    $mobileRules = @{
        'MT.1228' = { param($Pol) $v = & $setting $Pol 'securityBlockJailbrokenDevices'; if (-not $v.Present) { $null } else { $v.Value -eq $true } }
        'MT.1229' = { param($Pol)
            $req = & $setting $Pol 'passcodeRequired'; $simple = & $setting $Pol 'passcodeBlockSimple'; $len = & $setting $Pol 'passcodeMinimumLength'; $lock = & $setting $Pol 'passcodeMinutesOfInactivityBeforeLock'
            if (-not $req.Present) { return $null }
            $l = & $num $len.Value; $m = & $num $lock.Value
            ($req.Value -eq $true) -and ($simple.Value -eq $true) -and ($null -ne $l -and $l -ge 6) -and ($null -ne $m -and $m -gt 0 -and $m -le 15)
        }
        'MT.1230' = { param($Pol) $v = & $setting $Pol 'osMinimumVersion'; if (-not $v.Present) { $null } else { -not [string]::IsNullOrWhiteSpace([string]$v.Value) } }
        'MT.1231' = { param($Pol) $v = & $setting $Pol 'advancedThreatProtectionRequiredSecurityLevel'; if (-not $v.Present) { $null } else { [string]$v.Value -in @('secured', 'low', 'medium') } }
        'MT.1232' = { param($Pol) $v = & $setting $Pol 'securityBlockJailbrokenDevices'; if (-not $v.Present) { $null } else { $v.Value -eq $true } }
        'MT.1233' = { param($Pol)
            $req = & $setting $Pol 'passwordRequired'; $len = & $setting $Pol 'passwordMinimumLength'; $lock = & $setting $Pol 'passwordMinutesOfInactivityBeforeLock'
            if (-not $req.Present) { return $null }
            $l = & $num $len.Value; $m = & $num $lock.Value
            ($req.Value -eq $true) -and ($null -ne $l -and $l -ge 6) -and ($null -ne $m -and $m -gt 0 -and $m -le 15)
        }
        'MT.1234' = { param($Pol)
            $v = & $setting $Pol 'minAndroidSecurityPatchLevel'
            if (-not $v.Present) { return $null }
            $d = [datetime]::MinValue
            if (-not [datetime]::TryParse([string]$v.Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) { return $false }
            $d -ge $Now.ToUniversalTime().Date.AddDays(-365)
        }
        'MT.1235' = { param($Pol) $v = & $setting $Pol 'deviceThreatProtectionEnabled'; if (-not $v.Present) { $null } else { $v.Value -eq $true } }
        'MT.1236' = { param($Pol) $v = & $setting $Pol 'securityDisableUsbDebugging'; if (-not $v.Present) { $null } else { $v.Value -eq $true } }
        'MT.1237' = { param($Pol) $v = & $setting $Pol 'securityBlockDeviceAdministratorManagedDevices'; if (-not $v.Present) { $null } else { $v.Value -eq $true } }
        'MT.1214' = { param($Pol) $v = & $setting $Pol 'systemIntegrityProtectionEnabled'; if (-not $v.Present) { $null } else { $v.Value -eq $true } }
        'MT.1215' = { param($Pol) $v = & $setting $Pol 'gatekeeperAllowedAppSource'; if (-not $v.Present) { $null } else { [string]$v.Value -in @('macAppStore', 'macAppStoreAndIdentifiedDevelopers') } }
        'MT.1216' = { param($Pol) $v = & $setting $Pol 'advancedThreatProtectionRequiredSecurityLevel'; if (-not $v.Present) { $null } else { [string]$v.Value -in @('secured', 'low', 'medium', 'high') } }
    }

    # App protection (Maester MT.1238-1251), over the platform reads with
    # settings and assignments. A policy counts when an inclusion assignment or
    # Graph's own isAssigned says it reaches someone (Maester's union).
    $ap = & $raw 'Intune-AppProtection'
    $apRead = & $ok $ap
    $apDetail = @()
    if ($apRead) { $apDetail = @(& $field $ap 'Data.AppProtectionDetail' @() | Where-Object { $null -ne $_ }) }
    $apAssigned = { param($Pol)
        $inc = & $num (Get-TPObjectField -Item $Pol -Key 'InclusionAssignmentCount' -Default $null)
        ($null -ne $inc -and $inc -gt 0) -or ((Get-TPObjectField -Item $Pol -Key 'IsAssignedFlag' -Default $false) -eq $true)
    }
    $hours = { param($Value)
        if ($null -eq $Value -or "$Value" -eq '') { return $null }
        try { return [System.Xml.XmlConvert]::ToTimeSpan([string]$Value) } catch { return $null }
    }
    $apRules = @{
        PIN = { param($Pol)
            $pin = & $setting $Pol 'pinRequired'; if (-not $pin.Present) { return $null }
            $len = & $num (& $setting $Pol 'minimumPinLength').Value; $retries = & $num (& $setting $Pol 'maximumPinRetries').Value
            ($pin.Value -eq $true) -and ((& $setting $Pol 'simplePinBlocked').Value -eq $true) -and ($null -ne $len -and $len -ge 6) -and ($null -ne $retries -and $retries -gt 0 -and $retries -le 5)
        }
        Data = { param($Pol)
            $out = & $setting $Pol 'allowedOutboundDataTransferDestinations'; if (-not $out.Present) { return $null }
            ([string]$out.Value -in @('managedApps', 'none')) -and ([string](& $setting $Pol 'allowedOutboundClipboardSharingLevel').Value -in @('managedApps', 'managedAppsWithPasteIn', 'blocked')) -and
            ((& $setting $Pol 'saveAsBlocked').Value -eq $true) -and ((& $setting $Pol 'dataBackupBlocked').Value -eq $true)
        }
        EncryptIos = { param($Pol) $v = & $setting $Pol 'appDataEncryptionType'; if (-not $v.Present) { $null } else { [string]$v.Value -in @('whenDeviceLocked', 'whenDeviceLockedExceptOpenFiles', 'afterDeviceRestart') } }
        EncryptAndroid = { param($Pol)
            $v = & $setting $Pol 'encryptAppData'; if (-not $v.Present) { return $null }
            ($v.Value -eq $true) -and ((& $setting $Pol 'disableAppEncryptionIfDeviceEncryptionIsEnabled').Value -ne $true)
        }
        Versions = { param($Pol)
            $os = & $setting $Pol 'minimumRequiredOsVersion'; if (-not $os.Present) { return $null }
            (-not [string]::IsNullOrWhiteSpace([string]$os.Value)) -and (-not [string]::IsNullOrWhiteSpace([string](& $setting $Pol 'minimumRequiredAppVersion').Value))
        }
        Offline = { param($Pol)
            $a = & $setting $Pol 'periodOfflineBeforeAccessCheck'; if (-not $a.Present) { return $null }
            $access = & $hours $a.Value; $wipe = & $hours (& $setting $Pol 'periodOfflineBeforeWipeIsEnforced').Value
            ($null -ne $access -and $access.TotalHours -gt 0 -and $access.TotalHours -le 12) -and ($null -ne $wipe -and $wipe.TotalDays -gt 0 -and $wipe.TotalDays -le 90)
        }
        Threat = { param($Pol)
            $lvl = & $setting $Pol 'maximumAllowedDeviceThreatLevel'; if (-not $lvl.Present) { return $null }
            ([string]$lvl.Value -in @('secured', 'low', 'medium')) -and ([string](& $setting $Pol 'mobileThreatDefenseRemediationAction').Value -in @('block', 'wipe'))
        }
        Screen = { param($Pol) $v = & $setting $Pol 'screenCaptureBlocked'; if (-not $v.Present) { $null } else { $v.Value -eq $true } }
        Attest = { param($Pol)
            $t = & $setting $Pol 'requiredAndroidSafetyNetDeviceAttestationType'; if (-not $t.Present) { return $null }
            ([string]$t.Value -in @('basicIntegrity', 'basicIntegrityAndDeviceCertification')) -and ([string](& $setting $Pol 'appActionIfAndroidSafetyNetDeviceAttestationFailed').Value -in @('block', 'wipe'))
        }
    }
    $apRuleOf = @{
        'MT.1238' = 'PIN'; 'MT.1239' = 'Data'; 'MT.1240' = 'EncryptIos'; 'MT.1241' = 'Versions'; 'MT.1242' = 'Offline'; 'MT.1243' = 'Threat'
        'MT.1244' = 'PIN'; 'MT.1245' = 'Data'; 'MT.1246' = 'EncryptAndroid'; 'MT.1247' = 'Versions'; 'MT.1248' = 'Offline'; 'MT.1249' = 'Threat'; 'MT.1250' = 'Screen'; 'MT.1251' = 'Attest'
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $newRow = { param($Check, [string] $Status, [string] $Detail, [object[]] $Items = @())
        [ordered]@{
            Id = [string]$Check.Id; Area = [string]$Check.Area; Title = [string]$Check.Title; Why = [string]$Check.Why
            Severity = [string]$Check.Severity; SourceUrl = [string]$Check.SourceUrl; Recommended = [string]$Check.Recommended
            Status = $Status; StatusLabel = $names[$Status]; Detail = $Detail; Items = @($Items)
        }
    }
    $pname = { param($Pol) [string](Get-TPObjectField -Item $Pol -Key 'DisplayName' -Default '') }

    foreach ($check in @($catalog.checks)) {
        $id = [string]$check.Id
        $area = [string]$check.Area
        switch ($area) {
            'Tenant' {
                if (-not $dcRead) { $rows.Add((& $newRow $check 'NotAssessed' 'The Intune collector did not run or failed.')); break }
                if ($id -eq 'MT.1054') {
                    if ((& $section $dc 'TenantSettings') -ne 'Collected') { $rows.Add((& $newRow $check 'NotAssessed' 'The Intune compliance settings were not read in this run.')); break }
                    $sbd = & $field $dc 'Data.TenantSettings.SecureByDefault' $null
                    if ($sbd -eq $true) { $rows.Add((& $newRow $check 'Pass' 'Devices with no compliance policy assigned are marked Not compliant.')) }
                    elseif ($sbd -eq $false) { $rows.Add((& $newRow $check 'Fail' 'Devices with no compliance policy assigned are marked Compliant, so a policy requiring a compliant device admits them.')) }
                    else { $rows.Add((& $newRow $check 'NotAssessed' 'The setting was not returned.')) }
                } elseif ($id -eq 'MT.1053') {
                    if ((& $section $dc 'CleanupRules') -ne 'Collected') { $rows.Add((& $newRow $check 'NotAssessed' 'The device clean-up rules were not read in this run.')); break }
                    $rules = @(& $field $dc 'Data.CleanupRules' @() | Where-Object { $null -ne $_ -and (& $num (Get-TPObjectField -Item $_ -Key 'InactiveDays' -Default $null)) -gt 0 })
                    if ($rules.Count) { $rows.Add((& $newRow $check 'Pass' ("Clean-up rule(s): " + (@($rules | ForEach-Object { "$((& $pname $_)) ($([string](Get-TPObjectField -Item $_ -Key 'Platform' -Default '')), $([string](Get-TPObjectField -Item $_ -Key 'InactiveDays' -Default '')) days)" }) -join '; ') + '.'))) }
                    else { $rows.Add((& $newRow $check 'Fail' 'No device clean-up rule is configured.')) }
                } else {
                    if ((& $section $dc 'MdmAuthority') -ne 'Collected') { $rows.Add((& $newRow $check 'NotAssessed' 'The MDM authority was not read in this run.')); break }
                    $auth = [string](& $field $dc 'Data.MdmAuthority' '')
                    if ($auth -eq 'intune') { $rows.Add((& $newRow $check 'Pass' 'The MDM authority is Intune.')) }
                    else { $rows.Add((& $newRow $check 'Fail' "The MDM authority is '$auth'.")) }
                }
            }
            { $_ -in @('iOS', 'Android', 'macOS') } {
                if (-not $policiesRead) { $rows.Add((& $newRow $check 'NotAssessed' 'The Intune compliance policies were not read in this run.')); break }
                $platformPolicies = @($compliance | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Platform' -Default '') -in $platformTypes[$area] })
                $devices = & $deviceCount $platformOs[$area]
                if ($platformPolicies.Count -eq 0) {
                    if ($devices -eq 0) { $rows.Add((& $newRow $check 'NotApplicable' "There is no $area compliance policy and no managed $area device. (Maester reports this as not met.)")) }
                    else { $rows.Add((& $newRow $check 'Fail' $(if ($null -eq $devices) { "There is no $area compliance policy." } else { "There is no $area compliance policy, and $devices managed $area device(s) are therefore held to nothing." }))) }
                    break
                }
                if (@($platformPolicies | Where-Object { $null -ne (Get-TPObjectField -Item $_ -Key 'Settings' -Default $null) }).Count -eq 0) {
                    $rows.Add((& $newRow $check 'NotAssessed' 'The compliance policy settings were not read (a results file from before this check).')); break
                }
                $rule = $mobileRules[$id]
                $met = [System.Collections.Generic.List[object]]::new(); $unassignedMet = [System.Collections.Generic.List[object]]::new(); $short = [System.Collections.Generic.List[object]]::new(); $unknown = 0
                foreach ($pol in $platformPolicies) {
                    $r = & $rule $pol
                    if ($null -eq $r) { $unknown++; continue }
                    if ($r -and (& $assigned $pol)) { $met.Add($pol) }
                    elseif ($r) { $unassignedMet.Add($pol) }
                    elseif (& $assigned $pol) { $short.Add($pol) }
                }
                $items = @($short | ForEach-Object { [ordered]@{ Name = (& $pname $_); Note = 'Assigned; does not set the required value' } }) + @($unassignedMet | ForEach-Object { [ordered]@{ Name = (& $pname $_); Note = 'Sets the value but is not assigned' } })
                if ($met.Count -gt 0) {
                    $text = "Met by: " + (@($met | ForEach-Object { & $pname $_ }) -join '; ') + '.'
                    if ($short.Count) { $text += " $($short.Count) other assigned policy(ies) do not set it, so devices only they reach are held to less." }
                    $rows.Add((& $newRow $check 'Pass' $text $items))
                } elseif ($unknown -eq $platformPolicies.Count) {
                    $rows.Add((& $newRow $check 'NotAssessed' "None of the $area policies returned this setting (the policy type does not carry it)."))
                } else {
                    $text = "No assigned $area compliance policy sets the required value."
                    if ($unassignedMet.Count) { $text += " $($unassignedMet.Count) policy(ies) set it but are not assigned to anyone." }
                    $rows.Add((& $newRow $check 'Fail' $text $items))
                }
            }
            { $_ -in @('iOS app protection', 'Android app protection') } {
                $plat = if ($area -like 'iOS*') { 'iOS' } else { 'Android' }
                $sectionName = if ($plat -eq 'iOS') { 'IosAppProtection' } else { 'AndroidAppProtection' }
                $sec = & $section $ap $sectionName
                if (-not $apRead -or $sec -ne 'Collected') {
                    $rows.Add((& $newRow $check 'NotAssessed' $(if ($apRead -and -not $sec) { 'The app protection settings were not read (a results file from before this check).' } else { "The $plat app protection policies were not read in this run." })))
                    break
                }
                $pols = @($apDetail | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Platform' -Default '') -eq $plat })
                if ($pols.Count -eq 0) { $rows.Add((& $newRow $check 'Fail' "There is no $plat app protection policy, so company data in Outlook, Teams and OneDrive on $plat is not protected on devices the organization does not manage.")); break }
                $rule = $apRules[$apRuleOf[$id]]
                $met = [System.Collections.Generic.List[object]]::new(); $unassignedMet = [System.Collections.Generic.List[object]]::new(); $short = [System.Collections.Generic.List[object]]::new(); $unknown = 0
                foreach ($pol in $pols) {
                    $r = & $rule $pol
                    if ($null -eq $r) { $unknown++; continue }
                    if ($r -and (& $apAssigned $pol)) { $met.Add($pol) } elseif ($r) { $unassignedMet.Add($pol) } elseif (& $apAssigned $pol) { $short.Add($pol) }
                }
                $items = @($short | ForEach-Object { [ordered]@{ Name = (& $pname $_); Note = 'Assigned; does not set the required values' } }) + @($unassignedMet | ForEach-Object { [ordered]@{ Name = (& $pname $_); Note = 'Sets the values but is not assigned' } })
                if ($met.Count -gt 0) {
                    $text = "Met by: " + (@($met | ForEach-Object { & $pname $_ }) -join '; ') + '.'
                    if ($short.Count) { $text += " $($short.Count) other assigned policy(ies) do not, so users only they reach are held to less." }
                    $rows.Add((& $newRow $check 'Pass' $text $items))
                } elseif ($unknown -eq $pols.Count) {
                    $rows.Add((& $newRow $check 'NotAssessed' "None of the $plat app protection policies returned these settings."))
                } else {
                    $text = "No assigned $plat app protection policy sets the required values."
                    if ($unassignedMet.Count) { $text += " $($unassignedMet.Count) policy(ies) set them but are not assigned to anyone." }
                    $rows.Add((& $newRow $check 'Fail' $text $items))
                }
            }
            'ASR' {
                if (-not $esRead) { $rows.Add((& $newRow $check 'NotAssessed' 'The Intune endpoint security policies were not read in this run.')); break }
                $asr = @(& $field $es 'Data.ASRPolicies' @() | Where-Object { $null -ne $_ -and (Get-TPObjectField -Item $_ -Key 'IsAssigned' -Default $null) -ne $false })
                $readAsr = @($asr | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'AsrSettingsStatus' -Default '') -in @('Read', 'Partial') })
                if ($asr.Count -eq 0) { $rows.Add((& $newRow $check 'Fail' 'No assigned attack surface reduction rules policy was found.')); break }
                if ($readAsr.Count -eq 0) { $rows.Add((& $newRow $check 'NotAssessed' 'The rules of the assigned ASR policies could not be read.')); break }
                $rank = @{ Block = 4; Audit = 3; Warn = 2; Off = 1 }
                $items = [System.Collections.Generic.List[object]]::new()
                $missing = 0
                foreach ($std in @($catalog.asrStandardRules)) {
                    $best = 'Not configured'; $bestRank = 0
                    foreach ($pol in $readAsr) {
                        $modes = Get-TPObjectField -Item $pol -Key 'AsrRuleModes' -Default $null
                        if ($null -eq $modes) { continue }
                        $mode = [string](Get-TPObjectField -Item $modes -Key ([string]$std.Key) -Default '')
                        $r = if ($rank.ContainsKey($mode)) { $rank[$mode] } else { 0 }
                        if ($r -gt $bestRank) { $bestRank = $r; $best = $mode }
                    }
                    if ($best -notin @('Block', 'Audit')) { $missing++ }
                    $items.Add([ordered]@{ Name = [string]$std.Name; Note = $best })
                }
                if ($missing -eq 0) {
                    $audit = @($items | Where-Object { $_.Note -eq 'Audit' }).Count
                    $rows.Add((& $newRow $check 'Pass' $(if ($audit) { "All three standard protection rules are on; $audit only in Audit mode, which logs and does not block." } else { 'All three standard protection rules are in Block mode.' }) $items.ToArray()))
                } else {
                    $rows.Add((& $newRow $check 'Fail' "$missing of the three standard protection rules are not in Block or Audit mode in any assigned ASR policy." $items.ToArray()))
                }
            }
            'LAPS' {
                if (-not $esRead) { $rows.Add((& $newRow $check 'NotAssessed' 'The Intune endpoint security policies were not read in this run.')); break }
                $laps = @(& $field $es 'Data.LAPSPolicies' @() | Where-Object { $null -ne $_ -and (Get-TPObjectField -Item $_ -Key 'IsAssigned' -Default $null) -ne $false })
                if ($laps.Count -eq 0) { $rows.Add((& $newRow $check 'Fail' 'No assigned Windows LAPS policy was found.')); break }
                $readLaps = @($laps | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'SettingsStatus' -Default '') -in @('Read', 'Partial') })
                if ($readLaps.Count -eq 0) { $rows.Add((& $newRow $check 'NotAssessed' 'The settings of the assigned LAPS policies could not be read.')); break }
                $items = [System.Collections.Generic.List[object]]::new(); $good = 0
                foreach ($pol in $readLaps) {
                    $vals = Get-TPObjectField -Item $pol -Key 'SettingValues' -Default $null
                    $get = { param([string] $Suffix) [string](Get-TPObjectField -Item $vals -Key "device_vendor_msft_laps_policies_$Suffix" -Default '') }
                    $backup = & $get 'backupdirectory'; $complex = & $get 'passwordcomplexity'; $len = & $num (& $get 'passwordlength'); $post = & $get 'postauthenticationactions'
                    $issues = @()
                    if ($backup -notmatch '_1\z') { $issues += 'backup directory is not Entra ID' }
                    if ($complex -notmatch '_(4|8)\z') { $issues += 'complexity below four classes' }
                    if ($null -eq $len -or $len -lt 14) { $issues += 'length below 14' }
                    if ($post -notmatch '_(1|3|5|11)\z') { $issues += 'no post-authentication reset' }
                    if ($issues.Count -eq 0) { $good++ }
                    $items.Add([ordered]@{ Name = (& $pname $pol); Note = $(if ($issues.Count) { $issues -join '; ' } else { 'Meets every value' }) })
                }
                if ($good -gt 0) { $rows.Add((& $newRow $check 'Pass' "$good assigned LAPS policy(ies) meet every value." $items.ToArray())) }
                else { $rows.Add((& $newRow $check 'Fail' 'No assigned LAPS policy meets every value Maester checks.' $items.ToArray())) }
            }
            'Antivirus' {
                if (-not $esRead) { $rows.Add((& $newRow $check 'NotAssessed' 'The Intune endpoint security policies were not read in this run.')); break }
                $avAll = @(& $field $es 'Data.AntivirusPolicies' @() | Where-Object { $null -ne $_ -and (Get-TPObjectField -Item $_ -Key 'IsAssigned' -Default $null) -ne $false })
                if ($avAll.Count -eq 0) { $rows.Add((& $newRow $check 'Fail' 'No assigned Microsoft Defender Antivirus policy was found.')); break }
                $av = @($avAll | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'AvSettingsStatus' -Default '') -in @('Read', 'Partial') -and $null -ne (Get-TPObjectField -Item $_ -Key 'AvSettingValues' -Default $null) })
                if ($av.Count -eq 0) { $rows.Add((& $newRow $check 'NotAssessed' 'The settings of the assigned antivirus policies were not read (or a results file from before the value read).')); break }
                $rule = $check.Rule
                $sid = [string]$rule.SettingId
                $items = [System.Collections.Generic.List[object]]::new(); $pass = 0
                foreach ($pol in $av) {
                    $vals = Get-TPObjectField -Item $pol -Key 'AvSettingValues' -Default $null
                    $value = [string](Get-TPObjectField -Item $vals -Key $sid -Default '')
                    $verdict = 'Not set'
                    if ($value) {
                        $token = if ($value -match '(_\d+)\z') { $Matches[1] } else { $value }
                        $okValue = switch ([string]$rule.Check) {
                            'Bool'  { $token -eq [string]$rule.Expected }
                            'Enum'  { $token -in @($rule.Expected) }
                            'Range' { $n = & $num $value; $null -ne $n -and $n -ge [int]$rule.Expected[0] -and $n -le [int]$rule.Expected[1] }
                            'Min'   { $n = & $num $value; $null -ne $n -and $n -ge [int]$rule.Expected }
                            'Level' { $lv = $rule.Expected; $lv.Contains($token) -and [int]$lv[$token] -ge 2 }
                            default { $false }
                        }
                        $verdict = if ($okValue) { 'Meets' } else { "Set to $token" }
                    }
                    if ($verdict -eq 'Meets') { $pass++ }
                    $items.Add([ordered]@{ Name = (& $pname $pol); Note = $verdict })
                }
                $skipped = $avAll.Count - $av.Count
                $note = if ($skipped) { " $skipped assigned antivirus policy(ies) could not be read and are not counted." } else { '' }
                if ($pass -eq $av.Count) { $rows.Add((& $newRow $check 'Pass' ("Every assigned antivirus policy read ($($av.Count)) sets the value." + $note) $items.ToArray())) }
                else { $rows.Add((& $newRow $check 'Fail' ("$($av.Count - $pass) of $($av.Count) assigned antivirus policy(ies) do not set the value Maester checks (a policy that leaves it unset counts, as in Maester)." + $note) $items.ToArray())) }
            }
        }
    }

    $counts = [ordered]@{}
    foreach ($k in $names.Keys) { $counts[$k] = @($rows | Where-Object { $_.Status -eq $k }).Count }
    $areas = [ordered]@{}
    foreach ($a in @($rows | ForEach-Object { $_.Area } | Select-Object -Unique)) { $areas[$a] = @($rows | Where-Object { $_.Area -eq $a }).Count }
    $notes = [System.Collections.Generic.List[string]]::new()
    if (-not $dcRead) { $notes.Add('The Intune compliance collector did not run or failed (Intune skipped, not licensed, or no access), so its rows are not assessed.') }
    if (-not $esRead) { $notes.Add('The Intune endpoint security collector did not run or failed, so the ASR, LAPS and antivirus rows are not assessed.') }
    if (-not $apRead) { $notes.Add('The Intune app protection collector did not run or failed, so the app protection rows are not assessed.') }
    return [ordered]@{
        Available        = $true
        Note             = ''
        Rows             = $rows.ToArray()
        Counts           = $counts
        Areas            = $areas
        Notes            = $notes.ToArray()
        StatusNames      = $names
        MaesterReference = [string]$catalog.maesterReference
        CatalogVersion   = [string]$catalog.version
    }
}

#Requires -Version 7.0
#
# TP.IntuneChecklist.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards the Intune and endpoint checklist (Lib/Get-TPIntuneChecklist.ps1,
# Publishers/Publish-TPIntuneChecklist.ps1, Config/intune-checklist.json) and
# the collector reads it needs (the compliance setting snapshot, inclusion
# assignments, tenant settings, clean-up rules, MDM authority):
#   - the catalog: unique Maester ids, a known area, Microsoft Learn sources,
#     a recommended setting for every row, a rule for every antivirus row
#   - compliance rows: an assigned policy that sets Maester's value passes; an
#     unassigned one is named, never a pass; no policy and no device of that
#     platform does not apply; settings not read is not assessed
#   - ASR: the three standard protection rules, strongest mode across the
#     assigned policies; LAPS: every value; antivirus: every assigned policy,
#     an unset value counting against the row
#   - not read is "Not assessed"; the report escapes, loads nothing and never
#     says the tenant is compliant
# Data keys consumed: synthetic raw data only. Graph scopes / cmdlets: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Mod = Get-Module 'TenantPosture'
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-ic-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = New-Item -ItemType Directory -Path $script:Tmp -Force
    $script:Catalog = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/intune-checklist.json') -Raw | ConvertFrom-Json -AsHashtable
    $script:Now = [datetime]'2026-10-28T00:00:00Z'

    $script:Cp = {
        param([string] $Type, [hashtable] $Settings, [int] $Included = 1, [string] $Name = 'Policy')
        @{ DisplayName = $Name; Platform = "#microsoft.graph.$Type"; IsAssigned = ($Included -gt 0); InclusionAssignmentCount = $Included; Settings = $Settings }
    }
    $script:Raw = {
        param([object[]] $Policies = @(), [hashtable] $ByPlatform = @{ iOS = 3; Android = 2; macOS = 1; Windows = 10 }, [hashtable] $Es = $null, [hashtable] $Extra = @{})
        $dc = @{ Success = $true; Data = @{
            CompliancePolicies = @($Policies)
            OSComplianceSummary = @{ ByPlatform = $ByPlatform }
            TenantSettings = @{ SecureByDefault = $true }
            CleanupRules = @(@{ DisplayName = 'Windows'; Platform = 'windows'; InactiveDays = 90 })
            MdmAuthority = 'intune'
            SectionStatus = @{ CompliancePolicies = 'Collected'; OSComplianceSummary = 'Collected'; TenantSettings = 'Collected'; CleanupRules = 'Collected'; MdmAuthority = 'Collected' }
        } }
        foreach ($k in $Extra.Keys) { $dc.Data[$k] = $Extra[$k] }
        $r = @{ 'Intune-DeviceCompliance' = $dc }
        if ($null -ne $Es) { $r['Intune-EndpointSecurity'] = @{ Success = $true; Data = $Es } }
        $r
    }
    $script:Row = { param($View, [string] $Id) @($View.Rows | Where-Object { $_.Id -eq $Id })[0] }
    $script:Check = { param($Raw, [string] $Id) & $script:Row (Get-TPIntuneChecklist -RawData $Raw -Now $script:Now) $Id }
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'The Intune checklist catalog' {
    It 'has unique Maester ids, a known area, a Microsoft Learn source and a recommended setting' {
        $ids = @($script:Catalog.checks | ForEach-Object { $_.Id })
        ($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
        foreach ($c in $script:Catalog.checks) {
            $c.Id | Should -Match '\AMT\.\d{4}\z'
            $c.Area | Should -BeIn @('Tenant', 'iOS', 'Android', 'macOS', 'iOS app protection', 'Android app protection', 'ASR', 'LAPS', 'Antivirus')
            $c.SourceUrl | Should -Match '\Ahttps://learn\.microsoft\.com/'
            $c.Recommended | Should -Not -BeNullOrEmpty
            if ($c.Area -eq 'Antivirus') {
                $c.Rule.SettingId | Should -Match '\Adevice_vendor_msft_'
                $c.Rule.Check | Should -BeIn @('Bool', 'Enum', 'Range', 'Min', 'Level')
            }
        }
        foreach ($want in 'MT.1238', 'MT.1243', 'MT.1244', 'MT.1251', 'MT.1053', 'MT.1054', 'MT.1105', 'MT.1177', 'MT.1178', 'MT.1214', 'MT.1228', 'MT.1229', 'MT.1232', 'MT.1237', 'MT.1148', 'MT.1171') { $ids | Should -Contain $want }
    }
    It 'names the three standard protection ASR rules' {
        @($script:Catalog.asrStandardRules).Count | Should -Be 3
    }
}

Describe 'Compliance rows' {
    It 'iOS passcode passes on an assigned policy with Maester''s values and names a weaker assigned one' {
        $strong = & $script:Cp 'iosCompliancePolicy' @{ passcodeRequired = $true; passcodeBlockSimple = $true; passcodeMinimumLength = 6; passcodeMinutesOfInactivityBeforeLock = 5 } 1 'Strong'
        $weak = & $script:Cp 'iosCompliancePolicy' @{ passcodeRequired = $true; passcodeBlockSimple = $false; passcodeMinimumLength = 4; passcodeMinutesOfInactivityBeforeLock = 60 } 1 'Weak'
        $row = & $script:Check (& $script:Raw @($strong, $weak)) 'MT.1229'
        $row.Status | Should -Be 'Pass'
        $row.Detail | Should -Match 'other assigned'
        (& $script:Check (& $script:Raw @($weak)) 'MT.1229').Status | Should -Be 'Fail'
    }
    It 'an unassigned policy is named, never a pass (an exclusion-only assignment reaches nobody)' {
        $unassigned = & $script:Cp 'iosCompliancePolicy' @{ securityBlockJailbrokenDevices = $true } 0 'Not assigned'
        $row = & $script:Check (& $script:Raw @($unassigned)) 'MT.1228'
        $row.Status | Should -Be 'Fail'
        $row.Detail | Should -Match 'not assigned'
    }
    It 'no policy and no device of the platform does not apply; no policy with devices fails' {
        (& $script:Check (& $script:Raw @() @{ Windows = 10 }) 'MT.1228').Status | Should -Be 'NotApplicable'
        $row = & $script:Check (& $script:Raw @() @{ iOS = 4 }) 'MT.1228'
        $row.Status | Should -Be 'Fail'
        $row.Detail | Should -Match '4 managed iOS'
    }
    It 'a results file without the setting snapshot is not assessed' {
        $old = @{ DisplayName = 'Old'; Platform = '#microsoft.graph.iosCompliancePolicy'; IsAssigned = $true }
        (& $script:Check (& $script:Raw @($old)) 'MT.1228').Status | Should -Be 'NotAssessed'
    }
    It 'Android rows judge work profile and fully managed policies that return the property' {
        $wp = & $script:Cp 'androidWorkProfileCompliancePolicy' @{ securityBlockJailbrokenDevices = $true; minAndroidSecurityPatchLevel = '2026-08-01' }
        (& $script:Check (& $script:Raw @($wp)) 'MT.1232').Status | Should -Be 'Pass'
        (& $script:Check (& $script:Raw @($wp)) 'MT.1234').Status | Should -Be 'Pass'
        $do = & $script:Cp 'androidDeviceOwnerCompliancePolicy' @{ passwordRequired = $true }
        (& $script:Check (& $script:Raw @($do)) 'MT.1232').Status | Should -Be 'NotAssessed'
    }
    It 'an Android patch level older than a year fails' {
        $wp = & $script:Cp 'androidWorkProfileCompliancePolicy' @{ minAndroidSecurityPatchLevel = '2025-01-01' }
        (& $script:Check (& $script:Raw @($wp)) 'MT.1234').Status | Should -Be 'Fail'
    }
    It 'macOS SIP, Gatekeeper and Defender risk read the documented values' {
        $mac = & $script:Cp 'macOSCompliancePolicy' @{ systemIntegrityProtectionEnabled = $true; gatekeeperAllowedAppSource = 'anywhere'; advancedThreatProtectionRequiredSecurityLevel = 'medium' }
        $raw = & $script:Raw @($mac)
        (& $script:Check $raw 'MT.1214').Status | Should -Be 'Pass'
        (& $script:Check $raw 'MT.1215').Status | Should -Be 'Fail'
        (& $script:Check $raw 'MT.1216').Status | Should -Be 'Pass'
    }
    It 'compliance rows are not assessed when the policies were not read' {
        $raw = & $script:Raw @()
        $raw['Intune-DeviceCompliance'].Data.SectionStatus.CompliancePolicies = 'Failed'
        (& $script:Check $raw 'MT.1229').Status | Should -Be 'NotAssessed'
    }
}

Describe 'Tenant rows' {
    It 'reads secure by default, clean-up rules and the MDM authority' {
        $raw = & $script:Raw @()
        (& $script:Check $raw 'MT.1054').Status | Should -Be 'Pass'
        (& $script:Check $raw 'MT.1053').Status | Should -Be 'Pass'
        (& $script:Check $raw 'MT.1105').Status | Should -Be 'Pass'
        $raw['Intune-DeviceCompliance'].Data.TenantSettings.SecureByDefault = $false
        $raw['Intune-DeviceCompliance'].Data.CleanupRules = @()
        $raw['Intune-DeviceCompliance'].Data.MdmAuthority = 'office365'
        (& $script:Check $raw 'MT.1054').Status | Should -Be 'Fail'
        (& $script:Check $raw 'MT.1053').Status | Should -Be 'Fail'
        (& $script:Check $raw 'MT.1105').Status | Should -Be 'Fail'
        $raw['Intune-DeviceCompliance'].Data.SectionStatus.TenantSettings = 'Failed'
        (& $script:Check $raw 'MT.1054').Status | Should -Be 'NotAssessed'
    }
}

Describe 'ASR, LAPS and antivirus rows' {
    It 'ASR passes when the three standard rules are Block or Audit across the assigned policies' {
        $es = @{ ASRPolicies = @(
            @{ DisplayName = 'ASR 1'; IsAssigned = $true; AsrSettingsStatus = 'Read'; AsrRuleModes = @{ blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem = 'Block'; blockabuseofexploitedvulnerablesigneddrivers = 'Audit' } },
            @{ DisplayName = 'ASR 2'; IsAssigned = $true; AsrSettingsStatus = 'Read'; AsrRuleModes = @{ blockpersistencethroughwmieventsubscription = 'Block' } }) }
        $row = & $script:Check (& $script:Raw @() -Es $es) 'MT.1178'
        $row.Status | Should -Be 'Pass'
        $row.Detail | Should -Match 'Audit'
        $es.ASRPolicies[1].AsrRuleModes.blockpersistencethroughwmieventsubscription = 'Off'
        (& $script:Check (& $script:Raw @() -Es $es) 'MT.1178').Status | Should -Be 'Fail'
        $es.ASRPolicies[0].IsAssigned = $false; $es.ASRPolicies[1].IsAssigned = $false
        (& $script:Check (& $script:Raw @() -Es $es) 'MT.1178').Status | Should -Be 'Fail'
    }
    It 'LAPS needs Entra ID backup, four-class complexity, length 14 and a post-authentication reset' {
        $vals = @{ device_vendor_msft_laps_policies_backupdirectory = 'device_vendor_msft_laps_policies_backupdirectory_1'; device_vendor_msft_laps_policies_passwordcomplexity = 'device_vendor_msft_laps_policies_passwordcomplexity_4'; device_vendor_msft_laps_policies_passwordlength = '14'; device_vendor_msft_laps_policies_postauthenticationactions = 'device_vendor_msft_laps_policies_postauthenticationactions_3' }
        $es = @{ LAPSPolicies = @(@{ DisplayName = 'LAPS'; IsAssigned = $true; SettingsStatus = 'Read'; SettingValues = $vals }) }
        (& $script:Check (& $script:Raw @() -Es $es) 'MT.1177').Status | Should -Be 'Pass'
        $vals.device_vendor_msft_laps_policies_passwordlength = '12'
        $row = & $script:Check (& $script:Raw @() -Es $es) 'MT.1177'
        $row.Status | Should -Be 'Fail'
        @($row.Items)[0].Note | Should -Match 'length below 14'
    }
    It 'antivirus needs every assigned policy to set the value; an unset value counts against it' {
        $a = @{ DisplayName = 'AV A'; IsAssigned = $true; AvSettingsStatus = 'Read'; AvSettingValues = @{ device_vendor_msft_policy_config_defender_allowarchivescanning = 'device_vendor_msft_policy_config_defender_allowarchivescanning_1'; device_vendor_msft_policy_config_defender_avgcpuloadfactor = '25'; device_vendor_msft_policy_config_defender_cloudblocklevel = 'device_vendor_msft_policy_config_defender_cloudblocklevel_2' } }
        $b = @{ DisplayName = 'AV B'; IsAssigned = $true; AvSettingsStatus = 'Read'; AvSettingValues = @{ device_vendor_msft_policy_config_defender_avgcpuloadfactor = '50' } }
        $raw = & $script:Raw @() -Es @{ AntivirusPolicies = @($a) }
        (& $script:Check $raw 'MT.1148').Status | Should -Be 'Pass'
        (& $script:Check $raw 'MT.1157').Status | Should -Be 'Pass'
        (& $script:Check $raw 'MT.1161').Status | Should -Be 'Pass'
        $both = & $script:Raw @() -Es @{ AntivirusPolicies = @($a, $b) }
        $row = & $script:Check $both 'MT.1148'
        $row.Status | Should -Be 'Fail'
        @($row.Items | Where-Object { $_.Name -eq 'AV B' })[0].Note | Should -Be 'Not set'
        (& $script:Check $both 'MT.1157').Status | Should -Be 'Fail'
    }
    It 'antivirus is not assessed when the values were not read, and fails with no policy' {
        (& $script:Check (& $script:Raw @() -Es @{ AntivirusPolicies = @(@{ DisplayName = 'Old'; IsAssigned = $true; AvSettingsStatus = 'Failed' }) }) 'MT.1148').Status | Should -Be 'NotAssessed'
        (& $script:Check (& $script:Raw @() -Es @{ AntivirusPolicies = @() }) 'MT.1148').Status | Should -Be 'Fail'
    }
    It 'with no endpoint security data the ASR, LAPS and antivirus rows are not assessed' {
        $view = Get-TPIntuneChecklist -RawData (& $script:Raw @()) -Now $script:Now
        foreach ($r in @($view.Rows | Where-Object { $_.Area -in @('ASR', 'LAPS', 'Antivirus') })) { $r.Status | Should -Be 'NotAssessed' }
    }
}

Describe 'App protection rows' {
    BeforeAll {
        $script:Ap = {
            param([object[]] $Detail, [string] $Ios = 'Collected', [string] $Android = 'Collected')
            $r = & $script:Raw @()
            $r['Intune-AppProtection'] = @{ Success = $true; Data = @{ AppProtectionDetail = @($Detail); SectionStatus = @{ IosAppProtection = $Ios; AndroidAppProtection = $Android } } }
            $r
        }
        $script:ApPol = { param([string] $Platform, [hashtable] $Settings, [int] $Included = 1, [bool] $Flag = $false, [string] $Name = 'APP')
            @{ DisplayName = $Name; Platform = $Platform; InclusionAssignmentCount = $Included; IsAssignedFlag = $Flag; Settings = $Settings } }
        $script:StrongPin = @{ pinRequired = $true; simplePinBlocked = $true; minimumPinLength = 6; maximumPinRetries = 5 }
    }
    It 'PIN passes on an assigned policy with Maester''s values and fails a weaker one' {
        (& $script:Check (& $script:Ap @((& $script:ApPol 'iOS' $script:StrongPin))) 'MT.1238').Status | Should -Be 'Pass'
        $weak = $script:StrongPin.Clone(); $weak.maximumPinRetries = 10
        (& $script:Check (& $script:Ap @((& $script:ApPol 'iOS' $weak))) 'MT.1238').Status | Should -Be 'Fail'
    }
    It 'isAssigned alone counts as assigned (Maester''s union); neither signal is unassigned' {
        (& $script:Check (& $script:Ap @((& $script:ApPol 'Android' $script:StrongPin 0 $true))) 'MT.1244').Status | Should -Be 'Pass'
        $row = & $script:Check (& $script:Ap @((& $script:ApPol 'Android' $script:StrongPin 0 $false))) 'MT.1244'
        $row.Status | Should -Be 'Fail'
        $row.Detail | Should -Match 'not assigned'
    }
    It 'data transfer, encryption, screen capture and attestation read the documented values' {
        $p = & $script:ApPol 'Android' @{ allowedOutboundDataTransferDestinations = 'managedApps'; allowedOutboundClipboardSharingLevel = 'managedAppsWithPasteIn'; saveAsBlocked = $true; dataBackupBlocked = $true
            encryptAppData = $true; disableAppEncryptionIfDeviceEncryptionIsEnabled = $true; screenCaptureBlocked = $true
            requiredAndroidSafetyNetDeviceAttestationType = 'basicIntegrity'; appActionIfAndroidSafetyNetDeviceAttestationFailed = 'warn' }
        $raw = & $script:Ap @($p)
        (& $script:Check $raw 'MT.1245').Status | Should -Be 'Pass'
        (& $script:Check $raw 'MT.1246').Status | Should -Be 'Fail'
        (& $script:Check $raw 'MT.1250').Status | Should -Be 'Pass'
        (& $script:Check $raw 'MT.1251').Status | Should -Be 'Fail'
        $ios = & $script:ApPol 'iOS' @{ appDataEncryptionType = 'useDeviceSettings' }
        (& $script:Check (& $script:Ap @($ios)) 'MT.1240').Status | Should -Be 'Fail'
    }
    It 'offline limits parse ISO 8601 durations, never compare them as text' {
        $ok = & $script:ApPol 'iOS' @{ periodOfflineBeforeAccessCheck = 'PT12H'; periodOfflineBeforeWipeIsEnforced = 'P90D' }
        (& $script:Check (& $script:Ap @($ok)) 'MT.1242').Status | Should -Be 'Pass'
        $long = & $script:ApPol 'iOS' @{ periodOfflineBeforeAccessCheck = 'P1D'; periodOfflineBeforeWipeIsEnforced = 'P90D' }
        (& $script:Check (& $script:Ap @($long)) 'MT.1242').Status | Should -Be 'Fail'
    }
    It 'no policy for the platform is not met; a failed or absent read is not assessed' {
        (& $script:Check (& $script:Ap @()) 'MT.1238').Status | Should -Be 'Fail'
        (& $script:Check (& $script:Ap @() 'Failed') 'MT.1238').Status | Should -Be 'NotAssessed'
        $old = & $script:Raw @()
        $old['Intune-AppProtection'] = @{ Success = $true; Data = @{ AppProtectionPolicies = @(); SectionStatus = @{ AppProtectionPolicies = 'Collected' } } }
        (& $script:Check $old 'MT.1244').Status | Should -Be 'NotAssessed'
    }
    It 'the collector keeps only returned settings and counts inclusion assignments' {
        & $script:Mod {
            $p = @{ pinRequired = $true; displayName = 'x'; assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget' } }, @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget' } }) }
            $s = Get-TPAppProtectionSettingSnapshot -Policy $p
            $s.Keys | Should -Contain 'pinRequired'
            $s.Keys | Should -Not -Contain 'screenCaptureBlocked'
            Get-TPAppProtectionInclusionCount -Policy $p | Should -Be 1
        }
    }
}

Describe 'Not read and output' {
    It 'with no Intune data every row is not assessed' {
        $view = Get-TPIntuneChecklist -RawData @{} -Now $script:Now
        foreach ($r in $view.Rows) { $r.Status | Should -Be 'NotAssessed' }
        $view.Rows.Count | Should -Be @($script:Catalog.checks).Count
    }
    It 'replays a results file to the same statuses' {
        $raw = & $script:Raw @((& $script:Cp 'iosCompliancePolicy' @{ securityBlockJailbrokenDevices = $true; osMinimumVersion = '17.0' }))
        $live = Get-TPIntuneChecklist -RawData $raw -Now $script:Now
        $replayed = Get-TPIntuneChecklist -RawData ($raw | ConvertTo-Json -Depth 20 | ConvertFrom-Json) -Now $script:Now
        foreach ($r in $live.Rows) { (& $script:Row $replayed $r.Id).Status | Should -Be $r.Status -Because $r.Id }
    }
    It 'publishes HTML and Markdown that load nothing, escape a hostile name and never call the tenant compliant' {
        $raw = & $script:Raw @((& $script:Cp 'iosCompliancePolicy' @{ securityBlockJailbrokenDevices = $false } 1 '<img src=x onerror=alert(1)>[x](http://evil)'))
        $view = Get-TPIntuneChecklist -RawData $raw -Now $script:Now
        $files = Publish-TPIntuneChecklist -Model $view -OutputPath (Join-Path $script:Tmp 'contoso-intune-checklist.html') -TenantDomain 'contoso.com' -GeneratedAt $script:Now
        $html = Get-Content -LiteralPath $files.Html -Raw
        $md = Get-Content -LiteralPath $files.Markdown -Raw
        $html | Should -Not -Match '<script|<link |src="http|<img src=x'
        $md | Should -Not -Match '\[x\]\(http'
        foreach ($t in $html, $md) { $t | Should -Not -Match '(?i)\btenant is compliant\b|\bfully compliant\b|\bis compliant\b' }
        $html | Should -Match 'Jailbroken devices = Block'
    }
}

Describe 'Collector reads' {
    It 'keeps only the settings the policy returned, and counts inclusion assignments' {
        & $script:Mod {
            $p = @{ securityBlockJailbrokenDevices = $true; passcodeRequired = $false; displayName = 'x'
                assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget' } }, @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget' } }) }
            $s = Get-TPComplianceSettingSnapshot -Policy $p
            $s.Keys | Should -Contain 'securityBlockJailbrokenDevices'
            $s.Keys | Should -Not -Contain 'systemIntegrityProtectionEnabled'
            $s.passcodeRequired | Should -BeFalse
            Get-TPComplianceInclusionCount -Policy $p | Should -Be 1
            Get-TPComplianceInclusionCount -Policy @{ assignments = @() } | Should -Be 0
            Get-TPComplianceInclusionCount -Policy @{ displayName = 'no expand' } | Should -BeNullOrEmpty
        }
    }
    It 'records the tenant settings, clean-up rules and MDM authority as their own sections' {
        & $script:Mod {
            Clear-TPState
            function script:Invoke-TPGraphRequest { param($Method, $Uri, $Headers, $OutputType)
                switch -Regex ($Uri) {
                    'deviceManagement/settings' { return @{ secureByDefault = $true } }
                    'managedDeviceCleanupRules' { return @{ value = @(@{ displayName = 'All'; deviceCleanupRulePlatformType = 'all'; deviceInactivityBeforeRetirementInDays = 90 }) } }
                    'organization' { throw 'denied' }
                    default { return @{ value = @() } }
                }
            }
            try {
                Invoke-TPCollectIntuneDeviceCompliance
                $d = (Get-TPRawData -Key 'Intune-DeviceCompliance').Data
                $d.SectionStatus.TenantSettings | Should -Be 'Collected'
                $d.TenantSettings.SecureByDefault | Should -BeTrue
                $d.SectionStatus.CleanupRules | Should -Be 'Collected'
                @($d.CleanupRules)[0].InactiveDays | Should -Be 90
                $d.SectionStatus.MdmAuthority | Should -Be 'Failed'
            } finally { Remove-Item function:Invoke-TPGraphRequest -ErrorAction SilentlyContinue; Clear-TPState }
        }
    }
    It 'reads the MDM authority from the organization with no $select, v1.0 first, then beta (2026-10-30 live run)' {
        & $script:Mod {
            Clear-TPState
            $script:TPTestUris = [System.Collections.Generic.List[string]]::new()
            function script:Invoke-TPGraphRequest { param($Method, $Uri, $Headers, $OutputType)
                $script:TPTestUris.Add($Uri)
                if ($Uri -match 'organization\?\$select') { throw 'Response status code does not indicate success: BadRequest (Bad Request).' }
                if ($Uri -match '/v1\.0/organization$') { return @{ value = @(@{ id = 'o1'; displayName = 'Contoso' }) } }
                if ($Uri -match '/beta/organization$') { return @{ value = @(@{ id = 'o1'; mobileDeviceManagementAuthority = 'intune' }) } }
                return @{ value = @() }
            }
            try {
                Invoke-TPCollectIntuneDeviceCompliance
                $d = (Get-TPRawData -Key 'Intune-DeviceCompliance').Data
                $d.SectionStatus.MdmAuthority | Should -Be 'Collected'
                $d.MdmAuthority | Should -Be 'intune'
                @($script:TPTestUris | Where-Object { $_ -match 'organization' -and $_ -match '\$select' }).Count | Should -Be 0
            } finally { Remove-Item function:Invoke-TPGraphRequest -ErrorAction SilentlyContinue; Clear-TPState }
        }
    }
}

Describe 'Entry point wiring' {
    It 'writes the view as IntuneChecklist under a name that shadows no parameter' {
        $text = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $text | Should -Match 'IntuneChecklist\s+=\s+\$intuneChecklistView'
        $text | Should -Match '\[switch\] \$IntuneChecklist'
        $text | Should -Not -Match '(?m)^\s*\$intuneChecklist\s*='
    }
}

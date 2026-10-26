#Requires -Version 7.0
#
# TP.IntuneAvBaseline.Tests.ps1
# NRG Technology Services / NextLayerSec LLC — Author: Matthew Levorson
# INT-1.5 judges an assigned Intune Defender Antivirus policy against the approved
# configuration standard: the CIS Microsoft Intune for Microsoft Defender Antivirus
# Benchmark v1.0.0, Level 1 - Workstation (Config/cis-intune-defender-av.json).
#
# Pinned here: the catalog accounts for every benchmark recommendation and takes its
# values from Microsoft's CSP reference; the standard applies only while approved; the
# parser reads the Settings Catalog shapes Microsoft documents (choice, integer, threat
# action group); every setting is judged across every assigned policy (not set and set
# below are shortfalls, an undocumented value is never compliant); the real collector
# stores the values; and a results file from before this read keeps the old judgment.
#
# Data keys: Intune-EndpointSecurity.
#

Describe 'INT-1.5 judges the antivirus policy against the approved CIS benchmark' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:CatPath = Join-Path $script:Root 'Config' 'cis-intune-defender-av.json'
        $script:Cat = Get-Content -LiteralPath $script:CatPath -Raw | ConvertFrom-Json -Depth 10
        $script:Baseline = & $script:Mod { Get-TPIntuneAvBaseline }

        # A Settings Catalog setting instance as Graph returns it.
        function script:DefId { param($S)
            $node = ([string]$S.Node).ToLowerInvariant()
            if ($S.Kind -eq 'ThreatAction') { return "device_vendor_msft_policy_config_defender_$node" }
            if ($S.Family -eq 'DefenderCsp') { return "device_vendor_msft_defender_configuration_$node" }
            return "device_vendor_msft_policy_config_defender_$node" }
        function script:Choice { param([string] $Id, [string] $Token)
            @{ settingInstance = @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'; settingDefinitionId = $Id
                choiceSettingValue = @{ value = "${Id}_$Token"; children = @() } } } }
        function script:Int { param([string] $Id, [int] $N)
            @{ settingInstance = @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = $Id
                simpleSettingValue = @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationIntegerSettingValue'; value = $N } } } }
        # A payload setting every catalog setting to its first accepted value, with overrides
        # (CIS id -> token, or $null to leave the setting out).
        function script:Payload { param([hashtable] $Override = @{})
            $threat = @()
            $out = @(foreach ($s in $script:Cat.Settings) {
                $token = switch ($s.Kind) { 'Integer' { [string]$s.Minimum } 'ThreatAction' { 'quarantine' } default { [string]@($s.Compliant)[0] } }
                if ($Override.ContainsKey($s.Cis)) { $token = $Override[$s.Cis]; if ($null -eq $token) { continue } }
                $id = DefId $s
                switch ($s.Kind) {
                    'Integer' { Int $id ([int]$token) }
                    'ThreatAction' { $threat += @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'; settingDefinitionId = $id
                                                   choiceSettingValue = @{ value = "${id}_$token"; children = @() } } }
                    default { Choice $id $token }
                }
            })
            if ($threat.Count) {
                $out += @{ settingInstance = @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
                    settingDefinitionId = 'device_vendor_msft_policy_config_defender_threatseveritydefaultaction'
                    groupSettingCollectionValue = @(@{ children = $threat }) } }
            }
            return $out }
        function script:Rows { param([object[]] $Payloads)
            & $script:Mod { param($p, $b) $maps = @($p | ForEach-Object { , (Get-TPAvSettingValues -Settings $_) }); Get-TPAvBaselineRows -SettingMaps $maps -Catalog $b } $Payloads $script:Baseline }
        function script:Row { param($Rows, [string] $Cis) @($Rows | Where-Object Cis -eq $Cis)[0] }

        # INT-1.5 from stored policies (the collector's entry shape).
        function script:AvPolicy { param($Payload, [string] $Name = 'AV', [string] $Status = 'Read')
            [pscustomobject]@{ DisplayName = $Name; TemplateType = 'Antivirus'; IsAssigned = $true; AvSettingsStatus = $Status
                AvSettings = (Get-TPAvSettings -Settings $Payload); AvSettingValues = (& $script:Mod { param($p) Get-TPAvSettingValues -Settings $p } $Payload) } }
        function script:Judge { param([object[]] $Policies)
            Clear-TPState
            Set-TPRawData -Key 'Intune-EndpointSecurity' -Data @{ CollectorId = 'Intune-EndpointSecurity'; CollectedAt = (Get-Date).ToString('o'); Success = $true
                Data = @{ SectionStatus = @{ EndpointSecurityPolicies = 'Collected' }; EndpointSecurityPolicies = @($Policies) } }
            Test-TPControlIntune | Out-Null
            @(Get-TPFindings | Where-Object ControlId -eq 'INT-1.5')[0] }
    }
    AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    Context 'The catalog' {
        It 'accounts for all 55 benchmark recommendations, each once: 30 judged, 25 out of scope with a reason' {
            @($script:Cat.Settings).Count | Should -Be 30
            $ids = @($script:Cat.Settings.Cis) + @($script:Cat.OutOfScope.Cis)
            $ids.Count | Should -Be ([int]$script:Cat.RecommendationCount)
            @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
            foreach ($o in $script:Cat.OutOfScope) { ([string]$o.Reason).Length | Should -BeGreaterThan 20 -Because "$($o.Cis) needs a reason" }
        }
        It 'judges only Level 1 settings and leaves every Level 2 one out' {
            @($script:Cat.OutOfScope | Where-Object Level -eq 2).Cis | Should -Be @('1.10.1', '2.31', '2.40')
            # Every out-of-scope Level 1 item is either an ASR rule (INT-2.2) or a recorded evidence limit.
            foreach ($o in @($script:Cat.OutOfScope | Where-Object Level -eq 1)) {
                ($o.EvidenceLimit -or $o.Reason -match 'INT-2\.2') | Should -BeTrue -Because $o.Cis
            }
        }
        It 'every setting is well formed and cites Microsoft''s CSP reference' {
            foreach ($s in $script:Cat.Settings) {
                $s.Kind | Should -BeIn @('Choice', 'Integer', 'ThreatAction')
                $s.Family | Should -BeIn @('PolicyCsp', 'DefenderCsp')
                [string]$s.Source | Should -Match '^https://learn\.microsoft\.com/windows/client-management/mdm/(policy-csp-defender|defender-csp)#'
                if ($s.Kind -eq 'Integer') { [int]$s.Minimum | Should -BeLessOrEqual ([int]$s.Maximum) }
                if ($s.Kind -eq 'Choice') {
                    # An accepted value is a documented one.
                    $documented = @($s.Values.PSObject.Properties.Name)
                    foreach ($v in @($s.Compliant)) { if ($documented.Count -gt 2) { $documented | Should -Contain ([string]$v) -Because "$($s.Cis) accepts $v" } }
                }
            }
        }
        It 'pins the values that are easy to get backwards (Microsoft CSP, not the benchmark''s registry form)' {
            $by = @{}; foreach ($s in $script:Cat.Settings) { $by[$s.Cis] = $s }
            @($by['2.1'].Compliant)  | Should -Be @('1')            # AllowArchiveScanning; the registry is DisableArchiveScanning = 0
            @($by['2.34'].Compliant) | Should -Be @('1')            # network protection block mode, not 2 (audit)
            @($by['2.37'].Compliant) | Should -Be @('1')            # PUA on, not 2 (audit)
            @($by['2.39'].Compliant) | Should -Be @('0')            # bi-directional
            @($by['2.28'].Compliant) | Should -Be @('2', '4', '6')  # High or above
            @($by['2.45'].Compliant) | Should -Not -Contain '8'     # 8 = no scheduled scan
            $by['2.46'].Minimum | Should -Be 1; $by['2.46'].Maximum | Should -Be 4
            $by['2.30'].Minimum | Should -Be 7; $by['2.30'].Maximum | Should -Be 7
        }
        It 'every Level 1 item it cannot read is named in INT-1.5''s evidence limit' {
            $lim = @((Get-Content -LiteralPath (Join-Path $script:Root 'Config/evidence-limits.json') -Raw | ConvertFrom-Json).Limits | Where-Object Control -eq 'INT-1.5')
            $lim.Count | Should -Be 1
            foreach ($o in @($script:Cat.OutOfScope | Where-Object EvidenceLimit)) { $lim[0].NotEstablished | Should -Match ([regex]::Escape($o.Cis)) }
        }
    }

    Context 'The approval' {
        It 'the shipped standards approve exactly the catalog''s benchmark and version' {
            $script:Baseline | Should -Not -BeNullOrEmpty
            $script:Baseline.Name | Should -Be 'CIS Microsoft Intune for Microsoft Defender Antivirus Benchmark v1.0.0'
            $script:Baseline.Profile | Should -Be 'Level 1 - Workstation'
        }
        It 'no approval, or an approval of another version, applies no standard' {
            $tmp = Join-Path $TestDrive 'std.json'
            Set-Content -LiteralPath $tmp -Encoding utf8 -Value '{ "IntuneAntivirusBaseline": { "Benchmark": "" } }'
            (& $script:Mod { param($p) Get-TPIntuneAvBaseline -StandardsPath $p } $tmp) | Should -BeNullOrEmpty
            Set-Content -LiteralPath $tmp -Encoding utf8 -Value '{ "IntuneAntivirusBaseline": { "Benchmark": "CIS Microsoft Intune for Microsoft Defender Antivirus Benchmark v2.0.0" } }'
            (& $script:Mod { param($p) Get-TPIntuneAvBaseline -StandardsPath $p } $tmp) | Should -BeNullOrEmpty
            Set-Content -LiteralPath $tmp -Encoding utf8 -Value '{}'
            (& $script:Mod { param($p) Get-TPIntuneAvBaseline -StandardsPath $p } $tmp) | Should -BeNullOrEmpty
        }
    }

    Context 'Reading the policy' {
        It 'reads choice, integer and threat-action values, from hashtables and from replayed JSON' {
            $p = Payload
            $m = & $script:Mod { param($x) Get-TPAvSettingValues -Settings $x } $p
            $m['device_vendor_msft_policy_config_defender_allowarchivescanning'] | Should -Be 'device_vendor_msft_policy_config_defender_allowarchivescanning_1'
            $m['device_vendor_msft_policy_config_defender_cloudextendedtimeout'] | Should -Be '1'
            $m['device_vendor_msft_policy_config_defender_threatseveritydefaultaction_severethreats'] | Should -Match '_quarantine$'
            $json = $p | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            $m2 = & $script:Mod { param($x) Get-TPAvSettingValues -Settings $x } $json
            $m2.Count | Should -Be $m.Count
        }
        It 'a fully compliant policy meets every setting' {
            $rows = Rows @(, (Payload))
            @($rows).Count | Should -Be 30
            @($rows | Where-Object Status -ne 'Met').Cis | Should -BeNullOrEmpty
        }
        It 'a setting no policy sets is NotSet and names the Windows default' {
            $r = Row (Rows @(, (Payload @{ '2.4' = $null }))) '2.4'
            $r.Status | Should -Be 'NotSet'; $r.WindowsDefault | Should -Be 'Not allowed'
        }
        It 'values outside the benchmark are Below, at the edges too' {
            $rows = Rows @(, (Payload @{ '2.29' = '0'; '2.46' = '8'; '2.45' = '8'; '2.34' = '2'; '2.49' = 'allow'; '2.30' = '6' }))
            foreach ($cis in '2.29', '2.46', '2.45', '2.34', '2.49', '2.30') { (Row $rows $cis).Status | Should -Be 'Below' -Because $cis }
            $ok = Rows @(, (Payload @{ '2.29' = '50'; '2.46' = '4'; '2.45' = '7'; '2.49' = 'remove' }))
            foreach ($cis in '2.29', '2.46', '2.45', '2.49') { (Row $ok $cis).Status | Should -Be 'Met' -Because $cis }
        }
        It 'one assigned policy setting a weaker value is Below even beside a compliant one' {
            $r = Row (Rows @((Payload), (Payload @{ '2.3' = '0' }))) '2.3'
            $r.Status | Should -Be 'Below'; @($r.Observed) | Should -Contain 'Not allowed'
        }
        It 'a value Microsoft does not document is Unrecognized, never Met' {
            (Row (Rows @(, (Payload @{ '2.7' = '9' }))) '2.7').Status | Should -Be 'Unrecognized'
        }
        It 'Schedule Scan Time is not read from Schedule Quick Scan Time' {
            (Row (Rows @(, (Payload @{ '2.44' = $null }))) '2.44').Status | Should -Be 'NotSet'
        }
    }

    Context 'The INT-1.5 verdict' {
        It 'every setting met: Satisfied' {
            $f = Judge @(AvPolicy (Payload))
            $f.State | Should -Be 'Satisfied'
            $f.CurrentValue | Should -Match '^30 of 30 benchmark settings met'
        }
        It 'a setting set below the benchmark: Partial, named with its value and the requirement' {
            $f = Judge @(AvPolicy (Payload @{ '2.4' = '0' }))
            $f.State | Should -Be 'Partial'
            $f.Detail | Should -Match '2\.4 Allow Email Scanning \(Not allowed; requires Allowed\)'
            @($f.AffectedObjects | ForEach-Object { $_.Cis }) | Should -Contain '2.4'
        }
        It 'an assigned policy that sets nothing: Partial (the not-configured rule), never not assessed' {
            $f = Judge @(AvPolicy @())
            $f.State | Should -Be 'Partial'
            $f.Detail | Should -Match 'Not set by any assigned policy, which the benchmark requires'
            $f.Detail | Should -Match 'Windows default'
        }
        It 'only an undocumented value: not assessed, never Satisfied' {
            $f = Judge @(AvPolicy (Payload @{ '2.7' = '9' }))
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Microsoft does not document'
        }
        It 'a policy whose settings were not read keeps the control from passing' {
            $f = Judge @((AvPolicy (Payload)), (AvPolicy (Payload) 'Second' 'Failed'))
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'could not be read'
        }
        It 'a results file from before the value read is not assessed while the standard is approved: three settings never stand for it' {
            $p = AvPolicy (Payload); $p.PSObject.Properties.Remove('AvSettingValues')
            $f = Judge @($p)
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'the approved standard'
            $f.RequiredValue | Should -Match 'real-time, cloud-delivered and PUA protection'
        }
        It 'a withdrawn approval keeps the three-setting judgment' {
            Mock -ModuleName TenantPosture Get-TPIntuneAvBaseline { $null }
            $f = Judge @(AvPolicy (Payload @{ '2.4' = '0' }))
            $f.State | Should -Be 'Satisfied' -Because 'email scanning is not one of the three settings judged without the standard'
            $f.RequiredValue | Should -Match 'real-time, cloud-delivered and PUA protection'
        }
    }

    Context 'The real collector stores the values' {
        It 'an assigned Antivirus policy carries every setting value it sets' {
            & $script:Mod { param($payload) Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value {
                param([string] $Uri, [string] $Method = 'GET', $Headers, $Body, [string] $OutputType = 'HashTable')
                if ($Uri -match 'configurationPolicies/av1/settings') { return @{ value = @($payload) } }
                if ($Uri -match 'configurationPolicies') {
                    return @{ value = @(@{ id = 'av1'; name = 'Defender AV'; platforms = 'windows10'
                        templateReference = @{ templateFamily = 'endpointSecurityAntivirus'; templateDisplayName = 'Microsoft Defender Antivirus' }
                        assignments = @(@{ id = 'a1'; target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }) }) }
                }
                return @{ value = @() } }.GetNewClosure() } (Payload @{ '2.4' = '0' })
            try {
                Clear-TPState
                Invoke-TPCollectIntuneEndpointSecurity | Out-Null
                $pol = @((Get-TPRawData -Key 'Intune-EndpointSecurity').Data.AntivirusPolicies)[0]
                $pol.AvSettingsStatus | Should -Be 'Read'
                $pol.AvSettingValues['device_vendor_msft_policy_config_defender_allowemailscanning'] | Should -Match '_0$'
                Test-TPControlIntune | Out-Null
                $f = @(Get-TPFindings | Where-Object ControlId -eq 'INT-1.5')[0]
                $f.State | Should -Be 'Partial'
                $f.Detail | Should -Match '2\.4 Allow Email Scanning'
            } finally { & $script:Mod { Remove-Item -Path 'function:script:Invoke-TPGraphRequest' -ErrorAction SilentlyContinue } }
        }
    }
}

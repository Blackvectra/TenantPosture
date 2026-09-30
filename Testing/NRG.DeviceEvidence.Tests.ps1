#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.DeviceEvidence.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: An all-pass endpoint result is not, by itself, evidence the control
             works. Stale results are not counted as passes; each endpoint
             finding records how much of the fleet it covers; and the baseline
             labels a control Effective only when that coverage is complete and
             current. A failing device is still Ineffective, and results with no
             recorded coverage cannot claim Effective.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Endpoint evidence: coverage and freshness gate the Effective label' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Now = (Get-Date).ToUniversalTime()
        $script:Dev = {
            param([string] $Host_, [string] $Result = 'Pass', [double] $AgeDays = 0, [bool] $Elevated = $true)
            [ordered]@{ Hostname = $Host_; Elevated = $Elevated; CollectedAt = $script:Now.AddDays(-$AgeDays).ToString('o')
                        Checks = @([ordered]@{ Id = 'DEV-2.8'; Result = $Result; Observed = 'o'; Detail = '' }) }
        }
        $script:Load = {
            param([object[]] $Devices, $WindowsFleet = $null)
            Clear-NRGState
            Set-NRGRawData -Key 'Device-Compliance' -Data @{ CollectorId = 'Device-Compliance'; CollectedAt = $script:Now.ToString('o'); Success = $true
                Data = @{ Devices = @($Devices); DeviceCount = @($Devices).Count; SectionStatus = @{ DeviceResults = 'Collected' } } }
            if ($null -ne $WindowsFleet) {
                Set-NRGRawData -Key 'Intune-DeviceCompliance' -Data @{ CollectorId = 'Intune-DeviceCompliance'; CollectedAt = $script:Now.ToString('o'); Success = $true
                    Data = @{ SectionStatus = @{ OSComplianceSummary = 'Collected' }; OSComplianceSummary = @{ ByPlatform = @{ Windows = $WindowsFleet; iOS = 4 } } } }
            }
            Test-NRGControlDevice
            @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'DEV-2.8' })[0]
        }
        $script:Effectiveness = {
            param([object] $Finding)
            $def = [ordered]@{ Version = '9.9'; TierOrder = @('Minimum', 'Standard', 'Hardened'); FreshnessWindowsDays = [ordered]@{ Daily = 2; Weekly = 8; Monthly = 35; PointInTime = 400; Realtime = 1 }
                Controls = [ordered]@{ 'INT-2.1' = [ordered]@{ ControlId = 'INT-2.1'; Title = 'EDR'; Tier = 'Minimum'; Owner = 'Endpoint'; RawDataKeys = @(); EvidenceSource = 'x'; ExpectedState = 'x'; SlaClass = 'High'; DependsOn = @(); FreshnessClass = 'Weekly'
                    EffectivenessCheck = 'x'; EffectivenessCapability = 'Collected'; EffectivenessEvidence = @{ Type = 'DeviceControls'; Controls = @('DEV-2.8') }; Automated = $true; Reason = ''; WhyNrgOwnsThis = ''; Notes = '' } } }
            $none = @{ Available = $false; Path = ''; Entries = @(); Approved = @{}; Rejected = @() }
            $fs = @($Finding)
            $c = Get-NRGBaselineCompliance -Findings $fs -TargetTier Minimum -Definition $def -Exceptions $none -RawData @{} -Coverage @{}
            @($c.Controls)[0]
        }
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    Context 'freshness' {
        It 'a result older than 8 days is not counted as a pass, and the finding says so' {
            $f = & $script:Load @((& $script:Dev 'A' 'Pass' 0), (& $script:Dev 'B' 'Pass' 30)) 2
            $f.State | Should -Be 'Satisfied'
            $f.CurrentValue | Should -Match '^1 of 1 assessed'
            $f.Detail | Should -Match '1 device\(s\) reported results older than 8 days'
            $f.Coverage.Stale | Should -Be 1
            $f.Coverage.Complete | Should -BeFalse
        }
        It 'a result with no readable date is treated as stale, not current' {
            $d = & $script:Dev 'A' 'Pass' 0; $d.CollectedAt = 'not a date'
            $f = & $script:Load @($d) 1
            $f.State | Should -Be 'NotApplicable' -Because 'the only result cannot be shown to be current'
            $f.Coverage.Stale | Should -Be 1
        }
        It 'a stale FAIL is not counted as a failure either: an old failure is not evidence about today' {
            $f = & $script:Load @((& $script:Dev 'A' 'Pass' 0), (& $script:Dev 'B' 'Fail' 40)) 2
            $f.State | Should -Be 'Satisfied'
        }
    }

    Context 'coverage on every endpoint finding' {
        It 'complete only when every device gave a verdict, none is stale, and the fleet is the expected size' {
            $f = & $script:Load @((& $script:Dev 'A'), (& $script:Dev 'B')) 2
            $f.Coverage.Complete | Should -BeTrue
            $f.Coverage.ExpectedFleet | Should -Be 2
            @($f.Coverage.Reasons).Count | Should -Be 0
        }
        It '3 of 38 managed Windows devices reporting is incomplete, however clean the 3 are' {
            $f = & $script:Load @((& $script:Dev 'A'), (& $script:Dev 'B'), (& $script:Dev 'C')) 38
            $f.State | Should -Be 'Satisfied'
            $f.Coverage.Complete | Should -BeFalse
            ($f.Coverage.Reasons -join ' ') | Should -Match '3 of 38 managed Windows devices reported'
        }
        It 'a device that could not run the check makes coverage incomplete' {
            $f = & $script:Load @((& $script:Dev 'A'), (& $script:Dev 'B' 'NotAssessed' 0 $false)) 2
            $f.Coverage.NotAssessed | Should -Be 1
            $f.Coverage.Complete | Should -BeFalse
        }
        It 'no Intune managed-device count means completeness cannot be shown' {
            $f = & $script:Load @((& $script:Dev 'A')) $null
            $f.Coverage.Complete | Should -BeFalse
            ($f.Coverage.Reasons -join ' ') | Should -Match 'expected fleet size is not known'
        }
    }

    Context 'the baseline label' {
        It 'complete and current: Effective' {
            $f = & $script:Load @((& $script:Dev 'A'), (& $script:Dev 'B')) 2
            $row = & $script:Effectiveness $f
            $row.EffectivenessState | Should -Be 'Effective'
            $row.EffectivenessDetail | Should -Match 'current results'
        }
        It '3 of 38 reporting is Unknown, with the reason, not Effective' {
            $f = & $script:Load @((& $script:Dev 'A'), (& $script:Dev 'B'), (& $script:Dev 'C')) 38
            $row = & $script:Effectiveness $f
            $row.EffectivenessState | Should -Be 'Unknown'
            $row.EffectivenessDetail | Should -Match '3 of 38 managed Windows devices reported'
        }
        It 'a stale device makes an otherwise all-pass result Unknown' {
            $f = & $script:Load @((& $script:Dev 'A'), (& $script:Dev 'B' 'Pass' 30)) 2
            (& $script:Effectiveness $f).EffectivenessState | Should -Be 'Unknown'
        }
        It 'a failing device is Ineffective whatever the coverage' {
            $f = & $script:Load @((& $script:Dev 'A' 'Fail'), (& $script:Dev 'B')) 38
            (& $script:Effectiveness $f).EffectivenessState | Should -Be 'Ineffective'
        }
        It 'a finding with no recorded coverage (older results) cannot claim Effective' {
            Clear-NRGState
            Add-NRGFinding -ControlId 'DEV-2.8' -State 'Satisfied' -Category 'Endpoint' -Title 't' -Severity 'Informational' -Detail 'All 5 assessed device(s) pass.'
            $f = @(Get-NRGFindings)[0]
            $f.PSObject.Properties['Coverage'] | Should -BeNullOrEmpty
            $row = & $script:Effectiveness $f
            $row.EffectivenessState | Should -Be 'Unknown'
            $row.EffectivenessDetail | Should -Match 'no recorded coverage'
        }
        It 'the observed state is untouched: effectiveness is a separate answer' {
            $f = & $script:Load @((& $script:Dev 'A')) 38
            $f.State | Should -Be 'Satisfied'
        }
    }
}

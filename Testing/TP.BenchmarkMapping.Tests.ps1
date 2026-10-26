#Requires -Version 7.0
#
# TP.BenchmarkMapping.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Every control is mapped to a configuration benchmark or says why it is not
# (Config/benchmark-mappings.json, Get-TPBenchmarkMapping). The file is a claim
# a client reads, so it is held to the citation rule: a known benchmark, a
# documented relation, a source, the reason, and for a Subset what is left
# unchecked. Also pinned: the evaluator changes made so the citations hold
# (SPO-1.5, SPO-3.3 in TP.SPOVersionHistory, TMS-3.4, TMS-4.1, INT-1.5 in
# TP.IntuneAvBaseline).

Describe 'Benchmark mapping' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Map = Get-Content (Join-Path $script:RepoRoot 'Config' 'benchmark-mappings.json') -Raw | ConvertFrom-Json -Depth 20
        $cj = Get-Content (Join-Path $script:RepoRoot 'Config' 'controls.json') -Raw | ConvertFrom-Json -Depth 20
        $script:Controls = @(if ($cj -is [array]) { $cj } else { $cj.controls })
        $script:Ids = @($script:Controls.ControlId)
        $script:View = Get-TPBenchmarkMapping
        # DISA Microsoft Entra ID STIG V1R1 group ids (2025-02-28).
        $script:StigIds = @('V-270200', 'V-270204', 'V-270208', 'V-270209', 'V-270227', 'V-270233', 'V-270239', 'V-270255', 'V-270335', 'V-270475')
        $script:Rows = @(foreach ($p in $script:Map.controls.PSObject.Properties) { foreach ($r in @($p.Value)) { [pscustomobject]@{ Control = $p.Name; Row = $r } } })
    }

    Context 'Coverage' {
        It 'puts every control in exactly one place: mapped or unmapped with a reason' {
            $script:View.Available | Should -BeTrue
            ($script:View.Summary.Mapped + $script:View.Summary.Unmapped) | Should -Be $script:Ids.Count
            foreach ($cid in $script:Ids) {
                ($script:View.Controls.Contains($cid) -xor $script:View.Unmapped.Contains($cid)) | Should -BeTrue -Because $cid
            }
            foreach ($cid in $script:View.Unmapped.Keys) {
                $script:View.Unmapped[$cid].Reason | Should -Not -BeNullOrEmpty -Because "$cid is unmapped and must say why"
            }
        }

        It 'names only real controls, and never lists a control as unmapped that is mapped' {
            foreach ($p in $script:Map.controls.PSObject.Properties) { $script:Ids | Should -Contain $p.Name }
            foreach ($p in $script:Map.unmapped.PSObject.Properties) {
                $script:Ids | Should -Contain $p.Name
                $script:View.Controls.Contains($p.Name) | Should -BeFalse -Because "$($p.Name) is listed unmapped but has a citation"
            }
        }

        It 'states the same counts in docs/TP-BENCHMARK-MAP.md' {
            $doc = Get-Content (Join-Path $script:RepoRoot 'docs' 'TP-BENCHMARK-MAP.md') -Raw
            $doc | Should -Match ([regex]::Escape("**$($script:View.Summary.Mapped) of $($script:Ids.Count) controls are mapped"))
            $doc | Should -Match ([regex]::Escape("; $($script:View.Summary.Unmapped) are not"))
            foreach ($cid in $script:Ids) { $doc | Should -Match ('\| ' + [regex]::Escape($cid) + ' \|') -Because "$cid must appear in the map" }
        }

        It 'keeps a reason on file for every control the view finds unmapped' {
            foreach ($cid in $script:View.Unmapped.Keys) {
                $script:Map.unmapped.PSObject.Properties.Name | Should -Contain $cid
            }
        }
    }

    Context 'Each citation' {
        It 'names a defined benchmark, a documented relation, a source and the reason' {
            $script:Rows.Count | Should -BeGreaterThan 0
            foreach ($x in $script:Rows) {
                $b = [string]$x.Row.Benchmark
                $script:Map.benchmarks.PSObject.Properties.Name | Should -Contain $b -Because "$($x.Control) cites $b"
                $x.Row.Relation | Should -BeIn @('Equivalent', 'Subset', 'Stricter') -Because $x.Control
                [string]$x.Row.ItemId | Should -Not -BeNullOrEmpty
                [string]$x.Row.Why | Should -Not -BeNullOrEmpty -Because "$($x.Control) $($x.Row.ItemId)"
                [string]$x.Row.Url | Should -Match '^https://' -Because "$($x.Control) $($x.Row.ItemId)"
            }
        }

        It 'says what a Subset leaves unchecked' {
            foreach ($x in @($script:Rows | Where-Object { $_.Row.Relation -eq 'Subset' })) {
                [string]$x.Row.Unchecked | Should -Not -BeNullOrEmpty -Because "$($x.Control) $($x.Row.ItemId) is a Subset"
            }
        }

        It 'cites only rules the DISA Entra ID STIG V1R1 contains' {
            foreach ($x in @($script:Rows | Where-Object { $_.Row.Benchmark -eq 'DISA-ENTRA-ID-STIG-V1R1' })) {
                $script:StigIds | Should -Contain ([string]$x.Row.ItemId)
            }
        }

        It 'cites only CIS Intune for Defender AV recommendations the repo encodes, and only where the control judges them' {
            $av  = @((Get-Content (Join-Path $script:RepoRoot 'Config' 'cis-intune-defender-av.json') -Raw | ConvertFrom-Json).Settings.Cis)
            $asr = @((Get-Content (Join-Path $script:RepoRoot 'Config' 'asr-required-rules.json') -Raw | ConvertFrom-Json).Rules.Cis)
            foreach ($x in @($script:Rows | Where-Object { $_.Row.Benchmark -eq 'CIS-INTUNE-DEFENDER-AV-1.0.0' })) {
                switch ($x.Control) {
                    'INT-1.5' { $av  | Should -Contain ([string]$x.Row.ItemId) }
                    'INT-2.2' { $asr | Should -Contain ([string]$x.Row.ItemId) }
                    default   { throw "$($x.Control) cites the CIS Defender AV benchmark, which only INT-1.5 and INT-2.2 judge" }
                }
            }
            @($script:Rows | Where-Object { $_.Control -eq 'INT-1.5' }).Count | Should -Be $av.Count
            @($script:Rows | Where-Object { $_.Control -eq 'INT-2.2' }).Count | Should -Be $asr.Count
        }

        It 'INT-1.5 cites the benchmark only while its approval is in force' {
            @($script:Rows | Where-Object { $_.Control -eq 'INT-1.5' -and -not $_.Row.Condition }).Count | Should -Be 0
            & (Get-Module TenantPosture) { Get-TPIntuneAvBaseline } | Should -Not -BeNullOrEmpty
        }

        It 'keeps CIS Microsoft 365 and ScubaGear citations in controls.json, not here' {
            $script:Map.benchmarks.PSObject.Properties.Name | Should -Not -Contain 'CIS-M365-7.0.0'
            $script:Map.benchmarks.PSObject.Properties.Name | Should -Not -Contain 'SCUBA-2.0.0'
        }

        It 'carries the ScubaGear relation from the alignment file into the view' {
            @($script:View.Controls['INT-1.2'] | Where-Object { $_.Benchmark -eq 'SCUBA-2.0.0' })[0].Relation | Should -Be 'Partial'
        }
    }

    Context 'Evaluator changes the citations rest on' {
        BeforeAll {
            function script:Teams([hashtable] $Meeting) {
                Clear-TPState
                Set-TPRawData -Key 'Teams' -Data ([ordered]@{ CollectorId = 'Teams'; CollectedAt = '2026-10-26T00:00:00Z'; Success = $true
                    Data = @{ MeetingPolicy = $Meeting; SectionStatus = @{ MeetingPolicy = 'Collected' } } })
                Test-TPControlTeamsMeetingRecordingScope | Out-Null
                @(Get-TPFindings | Where-Object ControlId -eq 'TMS-4.1')[0]
            }
            function script:TeamsDlp($Policies, $Rules, [string] $RuleStatus = 'Collected') {
                Clear-TPState
                Set-TPRawData -Key 'Purview' -Data ([ordered]@{ CollectorId = 'Purview'; CollectedAt = '2026-10-26T00:00:00Z'; Success = $true
                    Data = @{ DLPPolicies = @($Policies); DLPRules = @($Rules); SectionStatus = @{ DLPPolicies = 'Collected'; DLPRules = $RuleStatus } } })
                Test-TPControlTeamsChatCopy | Out-Null
                @(Get-TPFindings | Where-Object ControlId -eq 'TMS-3.4')[0]
            }
        }

        It 'TMS-4.1 passes within Microsoft''s 120-day default, is Partial beyond it, and a Gap when recordings never expire' {
            (Teams @{ NewMeetingRecordingExpirationDays = 120 }).State | Should -Be 'Satisfied'
            (Teams @{ NewMeetingRecordingExpirationDays = 60 }).State  | Should -Be 'Satisfied'
            (Teams @{ NewMeetingRecordingExpirationDays = 121 }).State | Should -Be 'Partial'
            (Teams @{ NewMeetingRecordingExpirationDays = 99999 }).State | Should -Be 'Partial'
            (Teams @{ NewMeetingRecordingExpirationDays = -1 }).State  | Should -Be 'Gap'
        }

        It 'TMS-3.4 credits a Teams DLP policy only with an enabled rule, and does not guess when rules were not read' {
            $pol = @{ Name = 'Teams PII'; Mode = 'Enable'; Enabled = $true; Workloads = @('Teams') }
            $live = @{ Name = 'R1'; ParentPolicyName = 'Teams PII'; Disabled = $false }
            $off  = @{ Name = 'R1'; ParentPolicyName = 'Teams PII'; Disabled = $true }
            (TeamsDlp @($pol) @($live)).State | Should -Be 'Satisfied'
            (TeamsDlp @($pol) @($off)).State  | Should -Be 'Gap'
            (TeamsDlp @($pol) @()).State      | Should -Be 'Gap'
            $f = TeamsDlp @($pol) @() 'Failed'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'DLP rules were not collected'
        }

        It 'SPO-1.5 does not credit an authentication-context setting whose Conditional Access policy is not read' {
            Clear-TPState
            $ts = @{ IsLegacyAuthProtocolsEnabled = $false; IsUnmanagedSyncAppForTenantRestricted = $false; SharingCapability = 'externalUserAndGuestSharing'; AllowedDomainGuidsForSyncApp = @(); DeletedUserPersonalSiteRetentionPeriodInDays = 365 }
            foreach ($case in @(@{ Cap = 'AuthenticationContext'; State = 'NotApplicable' }, @{ Cap = 'AllowLimitedAccess'; State = 'Satisfied' }, @{ Cap = 'BlockAccess'; State = 'Satisfied' })) {
                Clear-TPState
                Set-TPRawData -Key 'SharePoint' -Data ([ordered]@{ CollectorId = 'SharePoint'; CollectedAt = '2026-10-26T00:00:00Z'; Success = $true
                    Data = @{ TenantSettings = $ts; TenantSettingsSPO = @{ ConditionalAccessPolicy = $case.Cap }; ExternalSharing = $ts.SharingCapability } })
                Test-TPControlSharePoint | Out-Null
                @(Get-TPFindings | Where-Object ControlId -eq 'SPO-1.5')[0].State | Should -Be $case.State -Because $case.Cap
            }
        }
    }
}

#Requires -Version 7.0
#
# NRG.Baseline.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# The NRG Security Baseline is a desired-state view over the assessment.
# The acceptance test for the whole feature is one question: if a collector
# fails tomorrow, can the tool ever say the client still meets the baseline?
# Every test here is a way of answering "no". The view creates no findings,
# moves no framework score, and resolves NotVerified for a missing finding,
# a failed collector, stale evidence, a skipped workload or a manual
# control; an exception changes the disposition and never the observed
# state; effectiveness stays Unknown wherever the evidence is not read.

Describe 'NRG Security Baseline — definition and tiers' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Def  = Get-NRGBaselineDefinition -Force
        $script:Doc  = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'docs' 'NRG-SECURITY-BASELINE-CANDIDATES.md') -Raw
        $script:ControlIds = @((Get-NRGControlDefinitions) | ForEach-Object { $_.ControlId })
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'is versioned and orders its tiers Minimum, Standard, Hardened' {
        $script:Def.Version | Should -Match '^\d+\.\d+$'
        @($script:Def.TierOrder) | Should -Be @('Minimum', 'Standard', 'Hardened')
    }

    It 'every automated baseline control exists in controls.json; VM-VERIFY-01 is the one manual item' {
        foreach ($c in $script:Def.Controls.Values) {
            if ($c.Automated) { $script:ControlIds | Should -Contain $c.ControlId }
            else { $c.ControlId | Should -Be 'VM-VERIFY-01' }
        }
    }

    It 'carries the governance fields on every control' {
        foreach ($c in $script:Def.Controls.Values) {
            foreach ($k in @('Owner', 'ExpectedState', 'SlaClass', 'FreshnessClass', 'EffectivenessCheck', 'EffectivenessCapability')) {
                [string]$c[$k] | Should -Not -BeNullOrEmpty -Because "$($c.ControlId) must carry $k"
            }
            $c.EffectivenessCapability | Should -BeIn @('Collected', 'NotCollected')
        }
    }

    It 'has one central freshness window per class, and every control uses a defined class' {
        foreach ($cls in @('Daily', 'Weekly', 'Monthly', 'PointInTime')) { [int]$script:Def.FreshnessWindowsDays[$cls] | Should -BeGreaterThan 0 }
        foreach ($c in $script:Def.Controls.Values) { $script:Def.FreshnessWindowsDays.Contains($c.FreshnessClass) | Should -BeTrue }
    }

    It 'no control depends on a control in a higher tier, and every dependency is itself in the baseline' {
        $rank = @{ Minimum = 0; Standard = 1; Hardened = 2 }
        foreach ($c in $script:Def.Controls.Values) {
            foreach ($d in @($c.DependsOn)) {
                $script:Def.Controls.Contains($d) | Should -BeTrue -Because "$($c.ControlId) depends on $d, which must be a baseline control"
                $rank[$script:Def.Controls[$d].Tier] | Should -BeLessOrEqual $rank[$c.Tier] -Because "$($c.ControlId) ($($c.Tier)) cannot depend on $d ($($script:Def.Controls[$d].Tier))"
            }
        }
    }

    It 'matches the editorial document tier for tier (the document is the source; the JSON is its encoding)' {
        $docTiers = @{}
        foreach ($m in [regex]::Matches($script:Doc, '(?m)^\| ([A-Z]{2,4}-\d+\.\d+) \| [^|]+\| [^|]+\| [^|]+\| [^|]+\| \*\*(Minimum|Standard|Hardened|Assessment-only)\*\* \|')) {
            $docTiers[$m.Groups[1].Value] = $m.Groups[2].Value
        }
        $docTiers.Count | Should -Be $script:ControlIds.Count -Because 'the document lists every control once'
        foreach ($cid in $docTiers.Keys) {
            if ($docTiers[$cid] -eq 'Assessment-only') { $script:Def.Controls.Contains($cid) | Should -BeFalse -Because "$cid is assessment-only and must not be a requirement" }
            else { $script:Def.Controls[$cid].Tier | Should -Be $docTiers[$cid] -Because "$cid tier must match the document" }
        }
    }

    Context 'Tier inheritance' {
        It 'Minimum requires only Minimum controls' {
            $r = @(Get-NRGBaselineRequiredControls -TargetTier Minimum -Definition $script:Def)
            @($r | Where-Object { $_.Tier -ne 'Minimum' }).Count | Should -Be 0
            $r.Count | Should -Be @($script:Def.Controls.Values | Where-Object { $_.Tier -eq 'Minimum' }).Count
        }
        It 'Standard requires Minimum + Standard' {
            $r = @(Get-NRGBaselineRequiredControls -TargetTier Standard -Definition $script:Def)
            @($r | Where-Object { $_.Tier -eq 'Hardened' }).Count | Should -Be 0
            @($r | Where-Object { $_.Tier -eq 'Minimum' }).Count | Should -BeGreaterThan 0
            @($r | Where-Object { $_.Tier -eq 'Standard' }).Count | Should -BeGreaterThan 0
        }
        It 'Hardened requires all three' {
            $r = @(Get-NRGBaselineRequiredControls -TargetTier Hardened -Definition $script:Def)
            $r.Count | Should -Be $script:Def.Controls.Count
        }
        It 'an assessment-only control is never required at any tier' {
            $required = @(Get-NRGBaselineRequiredControls -TargetTier Hardened -Definition $script:Def | ForEach-Object { $_.ControlId })
            $required | Should -Not -Contain 'AAD-13.1'   # Secure Score, assessment-only by decision
            $required | Should -Not -Contain 'AAD-12.1'   # named-list twin of AAD-1.2
        }
        It 'rejects an unknown tier' {
            { Get-NRGBaselineRequiredControls -TargetTier 'Platinum' -Definition $script:Def } | Should -Throw
        }
    }
}

Describe 'NRG Security Baseline — compliance view honesty' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Def = Get-NRGBaselineDefinition -Force
        $script:Now = Get-Date

        # A small definition of our own so the tests do not depend on which
        # real controls carry which tier; keys are real controls.json IDs so
        # the scope classifier and license gating see them.
        $script:MiniDef = [ordered]@{
            Version = '9.9'; TierOrder = @('Minimum', 'Standard', 'Hardened')
            FreshnessWindowsDays = [ordered]@{ Realtime = 1; Daily = 2; Weekly = 8; Monthly = 35; PointInTime = 400 }
            Path = 'test'
            Controls = [ordered]@{
                'AAD-1.1' = [ordered]@{ ControlId = 'AAD-1.1'; Title = 'Legacy auth'; Tier = 'Minimum'; Owner = 'Identity'; RawDataKeys = @('AAD-CAPolicies'); EvidenceSource = 'ca'; ExpectedState = 'blocked'; SlaClass = 'Critical'; DependsOn = @(); FreshnessClass = 'Daily'; EffectivenessCheck = 'x'; EffectivenessCapability = 'NotCollected'; EffectivenessEvidence = $null; Automated = $true; Reason = '' }
                'AAD-1.2' = [ordered]@{ ControlId = 'AAD-1.2'; Title = 'MFA';         Tier = 'Minimum'; Owner = 'Identity'; RawDataKeys = @('AAD-CAPolicies'); EvidenceSource = 'ca'; ExpectedState = 'mfa';     SlaClass = 'Critical'; DependsOn = @('AAD-1.1'); FreshnessClass = 'Daily'; EffectivenessCheck = 'x'; EffectivenessCapability = 'NotCollected'; EffectivenessEvidence = $null; Automated = $true; Reason = '' }
                'AAD-1.4' = [ordered]@{ ControlId = 'AAD-1.4'; Title = 'Sign-in risk'; Tier = 'Hardened'; Owner = 'Identity'; RawDataKeys = @('AAD-CAPolicies'); EvidenceSource = 'ca'; ExpectedState = 'risk'; SlaClass = 'Standard'; DependsOn = @(); FreshnessClass = 'Weekly'; EffectivenessCheck = 'x'; EffectivenessCapability = 'NotCollected'; EffectivenessEvidence = $null; Automated = $true; Reason = '' }
                'INT-2.1' = [ordered]@{ ControlId = 'INT-2.1'; Title = 'EDR';         Tier = 'Minimum'; Owner = 'Endpoint'; RawDataKeys = @('Intune-EndpointSecurity'); EvidenceSource = 'intune'; ExpectedState = 'edr'; SlaClass = 'Critical'; DependsOn = @(); FreshnessClass = 'Daily'; EffectivenessCheck = 'onboarded'; EffectivenessCapability = 'Collected'; EffectivenessEvidence = [pscustomobject]@{ Type = 'DeviceControls'; Controls = @('DEV-2.8') }; Automated = $true; Reason = '' }
                'VM-VERIFY-01' = [ordered]@{ ControlId = 'VM-VERIFY-01'; Title = 'VM verify'; Tier = 'Minimum'; Owner = 'Vulnerability'; RawDataKeys = @(); EvidenceSource = 'manual'; ExpectedState = 'zero'; SlaClass = 'Immediate'; DependsOn = @(); FreshnessClass = 'Daily'; EffectivenessCheck = 'x'; EffectivenessCapability = 'NotCollected'; EffectivenessEvidence = $null; Automated = $false; Reason = '' }
            }
        }
        $script:NoExc = [ordered]@{ Available = $false; Path = ''; Entries = @(); Approved = @{}; Rejected = @() }
        $script:Finding = {
            param([string] $Id, [string] $State, [string] $Detail = 'observed', [datetime] $When = (Get-Date))
            [pscustomobject]@{ ControlId = $Id; State = $State; Category = 'Identity'; Title = $Id; Severity = 'High'; Detail = $Detail; CurrentValue = ''; RequiredValue = ''; Remediation = ''; AffectedObjects = @(); Instance = ''; FrameworkIds = @('NIST:IA-2'); Timestamp = $When.ToString('o') }
        }
        $script:Raw = {
            param([string] $Key, [bool] $Success = $true, [datetime] $When = (Get-Date))
            @{ CollectorId = $Key; CollectedAt = $When.ToString('o'); Success = $Success; Data = @{} }
        }
        $script:Row = { param($c, [string] $Id) @($c.Controls | Where-Object { $_.ControlId -eq $Id })[0] }
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-NRGState }

    It 'is a view: it adds no finding and changes no finding' {
        Add-NRGFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'x' -Severity 'Critical' -Detail 'ok'
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'x' -Severity 'Critical' -Detail 'gap'
        $before = @(Get-NRGFindings | ForEach-Object { "$($_.ControlId)=$($_.State)" })
        $null = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Hardened -Definition $script:MiniDef -Exceptions $script:NoExc
        @(Get-NRGFindings).Count | Should -Be 2
        @(Get-NRGFindings | ForEach-Object { "$($_.ControlId)=$($_.State)" }) | Should -Be $before
    }

    It 'does not move the framework scores' {
        Add-NRGFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'x' -Severity 'Critical' -Detail 'ok'
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'x' -Severity 'Critical' -Detail 'gap'
        Add-NRGFinding -ControlId 'EXO-1.3' -State 'Satisfied' -Category 'Email' -Title 'x' -Severity 'High' -Detail 'ok'
        $before = Get-NRGCoverageScore -Findings (Get-NRGFindings) | ConvertTo-Json -Depth 5 -Compress
        $null = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -Exceptions $script:NoExc
        $after = Get-NRGCoverageScore -Findings (Get-NRGFindings) | ConvertTo-Json -Depth 5 -Compress
        $after | Should -Be $before
    }

    It 'a missing finding is NotVerified, never Satisfied' {
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
        $c = Get-NRGBaselineCompliance -Findings @() -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
        (& $script:Row $c 'AAD-1.1').ObservedState | Should -Be 'NotVerified'
        $c.Summary.Satisfied | Should -Be 0
        $c.Summary.NotVerified | Should -Be $c.Summary.RequiredControls
    }

    It 'a failed collector does not preserve a Satisfied verdict (a replayed pass cannot outlive its data)' {
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies' $false)
        $f = @(& $script:Finding 'AAD-1.1' 'Satisfied' 'from an earlier run')
        $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
        $row = & $script:Row $c 'AAD-1.1'
        $row.ObservedState | Should -Be 'NotVerified'
        $row.ObservedFindingState | Should -Be 'Satisfied'
        $row.Reason | Should -Match 'did not succeed'
    }

    It 'a coverage entry of Failed or Skipped for the collector also resolves NotVerified' {
        Register-NRGCoverage -Family 'AAD-CAPolicies' -Status 'Skipped' -Note 'operator'
        $f = @(& $script:Finding 'AAD-1.1' 'Satisfied')
        $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc -RawData @{} -Coverage (Get-NRGCoverage)
        (& $script:Row $c 'AAD-1.1').ObservedState | Should -Be 'NotVerified'
    }

    It 'a Satisfied finding backed by a successful collector is Satisfied with current evidence' {
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
        $f = @(& $script:Finding 'AAD-1.1' 'Satisfied')
        $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
        $row = & $script:Row $c 'AAD-1.1'
        $row.ObservedState | Should -Be 'Satisfied'
        $row.EvidenceFreshness | Should -Be 'Current'
        $row.EvidenceTimestamp | Should -Not -BeNullOrEmpty
        $row.BaselineStatus | Should -Be 'Satisfied'
    }

    It 'Gap and Partial are Failed; Error is NotVerified' {
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
        $f = @((& $script:Finding 'AAD-1.1' 'Gap'), (& $script:Finding 'AAD-1.2' 'Partial'), (& $script:Finding 'AAD-1.4' 'Error' 'evaluator threw'))
        $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Hardened -Definition $script:MiniDef -Exceptions $script:NoExc
        (& $script:Row $c 'AAD-1.1').ObservedState | Should -Be 'Failed'
        (& $script:Row $c 'AAD-1.2').ObservedState | Should -Be 'Failed'
        (& $script:Row $c 'AAD-1.4').ObservedState | Should -Be 'NotVerified'
    }

    It 'the worst instance wins when a control has several findings' {
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
        $f = @((& $script:Finding 'AAD-1.1' 'Satisfied'), (& $script:Finding 'AAD-1.1' 'Gap' 'second domain'))
        $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
        (& $script:Row $c 'AAD-1.1').ObservedState | Should -Be 'Failed'
    }

    It 'license-blocked is a constraint, not a failure' {
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
        $marker = & (Get-Module NRG-Assessment) { $script:NRGUpgradeMarker }
        $f = @(& $script:Finding 'AAD-1.4' 'NotApplicable' "Not scored: this control requires Entra ID P2, which this tenant does not hold — $marker, not counted against the score. Result before the license check: Gap")
        $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Hardened -Definition $script:MiniDef -Exceptions $script:NoExc
        $row = & $script:Row $c 'AAD-1.4'
        $row.Constraint | Should -Be 'LicenseBlocked'
        $row.ObservedState | Should -Be 'NotApplicable'
        $row.BaselineStatus | Should -Be 'LicenseBlocked'
        $c.Summary.Failed | Should -Be 0
        $c.Summary.LicenseBlocked | Should -Be 1
    }

    It 'a NotApplicable with no classifiable reason is NotVerified, never a quiet pass' {
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
        $f = @(& $script:Finding 'AAD-1.1' 'NotApplicable' 'Conditional Access data not collected.')
        $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
        (& $script:Row $c 'AAD-1.1').ObservedState | Should -Be 'NotVerified'
    }

    It 'a third-party EDR declaration is NotApplicable with the declaration as the reason, not Satisfied' {
        Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (& $script:Raw 'Intune-EndpointSecurity')
        Add-NRGFinding -ControlId 'INT-2.1' -State 'Gap' -Category 'Endpoint' -Title 'EDR' -Severity 'Critical' -Detail 'No EDR policy'
        $null = Set-NRGThirdPartyEdr -Product 'Cortex XDR'
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
        $row = & $script:Row $c 'INT-2.1'
        $row.ObservedState | Should -Be 'NotApplicable'
        $row.Reason | Should -Match 'Third-party EDR'
        $row.BaselineStatus | Should -Not -Be 'Satisfied'
    }

    It 'the manual VM-VERIFY-01 requirement is always NotVerified and says why' {
        $c = Get-NRGBaselineCompliance -Findings @() -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
        $row = & $script:Row $c 'VM-VERIFY-01'
        $row.ObservedState | Should -Be 'NotVerified'
        $row.Reason | Should -Match 'manually'
        $row.EffectivenessState | Should -Be 'Unknown'
    }

    Context 'Evidence freshness' {
        It 'evidence older than its freshness window turns a Satisfied into NotVerified (a Daily control at 5 days)' {
            $old = (Get-Date).AddDays(-5)
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies' $true $old)
            $f = @(& $script:Finding 'AAD-1.1' 'Satisfied' 'ok' $old)
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
            $row = & $script:Row $c 'AAD-1.1'
            $row.EvidenceFreshness | Should -Be 'Stale'
            $row.ObservedState | Should -Be 'NotVerified'
            $row.Reason | Should -Match 'day\(s\) old'
            # AAD-1.2 has no finding but shares the stale collector, so its evidence is stale too.
            $c.Summary.StaleEvidence | Should -Be 2
        }
        It 'the same age is current for a Weekly control' {
            $old = (Get-Date).AddDays(-5)
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies' $true $old)
            $f = @(& $script:Finding 'AAD-1.4' 'Satisfied' 'ok' $old)
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Hardened -Definition $script:MiniDef -Exceptions $script:NoExc
            (& $script:Row $c 'AAD-1.4').EvidenceFreshness | Should -Be 'Current'
            (& $script:Row $c 'AAD-1.4').ObservedState | Should -Be 'Satisfied'
        }
        It 'stale evidence never hides a failure: a stale Gap stays Failed' {
            $old = (Get-Date).AddDays(-30)
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies' $true $old)
            $f = @(& $script:Finding 'AAD-1.1' 'Gap' 'gap' $old)
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
            (& $script:Row $c 'AAD-1.1').ObservedState | Should -Be 'Failed'
            (& $script:Row $c 'AAD-1.1').EvidenceFreshness | Should -Be 'Stale'
        }
        It 'the windows come from one central policy, not from the code' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib' 'Get-NRGBaseline.ps1') -Raw
            $src | Should -Match 'FreshnessWindowsDays'
            $src | Should -Not -Match "'Daily'\s*\{\s*\d+"
        }
    }

    Context 'Exceptions' {
        BeforeAll {
            $script:ExcDir = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-baseline-exc-" + [guid]::NewGuid().ToString('N'))
            $null = [System.IO.Directory]::CreateDirectory($script:ExcDir)
            $script:WriteExc = {
                param([string] $Name, [string] $Body)
                $p = Join-Path $script:ExcDir "$Name.psd1"
                Set-Content -LiteralPath $p -Value "@{ Exceptions = @( $Body ) }" -Encoding utf8
                $p
            }
            $script:Full = "@{ ControlId='AAD-1.1'; Reason='r'; CompensatingControl='c'; Approver='a@x'; ApprovedDate='2026-01-01'; ReviewDate='2999-01-01' }"
        }
        AfterAll { if ($script:ExcDir -and (Test-Path $script:ExcDir)) { Remove-Item $script:ExcDir -Recurse -Force -ErrorAction SilentlyContinue } }

        It 'the example file parses and its one exception is approved' {
            $e = Get-NRGBaselineExceptions -Path (Join-Path $script:RepoRoot 'Config' 'baseline-exceptions' 'example.psd1')
            $e.Available | Should -BeTrue
            $e.Approved.Keys | Should -Contain 'EXO-1.2'
        }
        It "'example' is never resolved as a tenant" {
            (Get-NRGBaselineExceptions -TenantDomain 'example').Available | Should -BeFalse
        }
        It 'an exception without ReviewDate is not approved' {
            $p = & $script:WriteExc 'noreview' "@{ ControlId='AAD-1.1'; Reason='r'; CompensatingControl='c'; Approver='a@x'; ApprovedDate='2026-01-01' }"
            $e = Get-NRGBaselineExceptions -Path $p
            $e.Approved.Count | Should -Be 0
            $e.Rejected[0].Verdict | Should -Match 'ReviewDate'
        }
        It 'an exception past its ReviewDate is not approved' {
            $p = & $script:WriteExc 'lapsed' "@{ ControlId='AAD-1.1'; Reason='r'; CompensatingControl='c'; Approver='a@x'; ApprovedDate='2025-01-01'; ReviewDate='2025-06-01' }"
            (Get-NRGBaselineExceptions -Path $p).Approved.Count | Should -Be 0
        }
        It 'an expired exception no longer suppresses the baseline gap' {
            $p = & $script:WriteExc 'expired' "@{ ControlId='AAD-1.1'; Reason='r'; CompensatingControl='c'; Approver='a@x'; ApprovedDate='2025-01-01'; ReviewDate='2999-01-01'; ExpiryDate='2025-12-31' }"
            $e = Get-NRGBaselineExceptions -Path $p
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
            $f = @(& $script:Finding 'AAD-1.1' 'Gap')
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $e
            $row = & $script:Row $c 'AAD-1.1'
            $row.Disposition | Should -Be 'Normal'
            $row.BaselineStatus | Should -Be 'Failed'
            $row.ExceptionSummary | Should -Match 'not in force'
        }
        It 'an approved exception keeps the underlying Failed state and only changes the disposition' {
            $p = & $script:WriteExc 'ok' $script:Full
            $e = Get-NRGBaselineExceptions -Path $p
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
            $f = @(& $script:Finding 'AAD-1.1' 'Gap')
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $e
            $row = & $script:Row $c 'AAD-1.1'
            $row.ObservedState | Should -Be 'Failed'
            $row.Disposition | Should -Be 'ApprovedException'
            $row.BaselineStatus | Should -Be 'ApprovedException'
            $c.Summary.Failed | Should -Be 0
            $c.Summary.ApprovedException | Should -Be 1
        }
        It 'an approved exception on an unverified control keeps NotVerified as the observed state' {
            $p = & $script:WriteExc 'nv' $script:Full
            $e = Get-NRGBaselineExceptions -Path $p
            $c = Get-NRGBaselineCompliance -Findings @() -TargetTier Minimum -Definition $script:MiniDef -Exceptions $e -RawData @{} -Coverage @{}
            (& $script:Row $c 'AAD-1.1').ObservedState | Should -Be 'NotVerified'
            (& $script:Row $c 'AAD-1.1').Disposition | Should -Be 'ApprovedException'
        }
    }

    Context 'Effectiveness' {
        It 'stays Unknown when the evidence is not collected, even for a Satisfied control' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
            $f = @(& $script:Finding 'AAD-1.1' 'Satisfied')
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
            (& $script:Row $c 'AAD-1.1').EffectivenessState | Should -Be 'Unknown'
        }
        It 'is Unknown for a collected-capability control when no endpoint results were ingested' {
            Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (& $script:Raw 'Intune-EndpointSecurity')
            $f = @(& $script:Finding 'INT-2.1' 'Satisfied')
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
            (& $script:Row $c 'INT-2.1').EffectivenessState | Should -Be 'Unknown'
            (& $script:Row $c 'INT-2.1').EffectivenessDetail | Should -Match 'DeviceResults'
        }
        It 'reads the endpoint check when it was ingested: Effective on pass, Ineffective on a failing device' {
            Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (& $script:Raw 'Intune-EndpointSecurity')
            $f = @((& $script:Finding 'INT-2.1' 'Satisfied'), (& $script:Finding 'DEV-2.8' 'Satisfied'))
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
            (& $script:Row $c 'INT-2.1').EffectivenessState | Should -Be 'Effective'
            $f = @((& $script:Finding 'INT-2.1' 'Satisfied'), (& $script:Finding 'DEV-2.8' 'Gap' 'two laptops not onboarded'))
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
            (& $script:Row $c 'INT-2.1').EffectivenessState | Should -Be 'Ineffective'
            (& $script:Row $c 'INT-2.1').ObservedState | Should -Be 'Satisfied' -Because 'effectiveness is a separate answer, not a rewrite of the observed state'
        }
        It 'every real baseline control marked NotCollected resolves Unknown, and the summary counts it' {
            $c = Get-NRGBaselineCompliance -Findings @() -TargetTier Hardened -Definition $script:Def -Exceptions $script:NoExc -RawData @{} -Coverage @{}
            @($c.Controls | Where-Object { $_.EffectivenessCapability -eq 'NotCollected' -and $_.EffectivenessState -ne 'Unknown' }).Count | Should -Be 0
            $c.Summary.EffectivenessUnknown | Should -Be $c.Summary.RequiredControls
        }
    }

    Context 'Dependencies' {
        It 'an unmet dependency is visible and does not change the dependent control''s own state' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
            $f = @((& $script:Finding 'AAD-1.1' 'Gap'), (& $script:Finding 'AAD-1.2' 'Satisfied'))
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
            $row = & $script:Row $c 'AAD-1.2'
            $row.ObservedState | Should -Be 'Satisfied'
            $row.DependencyState | Should -Match '^Unmet: AAD-1\.1=Failed'
        }
        It 'a satisfied dependency never makes an unverified dependent pass' {
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies')
            $f = @(& $script:Finding 'AAD-1.1' 'Satisfied')
            $c = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum -Definition $script:MiniDef -Exceptions $script:NoExc
            (& $script:Row $c 'AAD-1.2').ObservedState | Should -Be 'NotVerified'
            (& $script:Row $c 'AAD-1.2').DependencyState | Should -Be 'Met'
        }
    }

    Context 'Regressions' {
        BeforeAll {
            $script:Comp = {
                param([string] $Ver, [string] $Tier, [hashtable] $States)
                [ordered]@{ BaselineVersion = $Ver; TargetTier = $Tier; Controls = @(foreach ($k in $States.Keys) { [pscustomobject]@{ ControlId = $k; Title = $k; RequiredTier = 'Minimum'; Owner = 'Identity'; SlaClass = 'High'; BaselineStatus = $States[$k]; Reason = 'r'; ExpectedState = 'e' } }) }
            }
        }
        It 'reports Satisfied -> Failed and Satisfied -> NotVerified as regressions under the same context' {
            $prior = & $script:Comp '1.0' 'Standard' @{ 'AAD-1.1' = 'Satisfied'; 'AAD-1.2' = 'Satisfied'; 'AAD-1.4' = 'Failed' }
            $cur   = & $script:Comp '1.0' 'Standard' @{ 'AAD-1.1' = 'Failed'; 'AAD-1.2' = 'NotVerified'; 'AAD-1.4' = 'Satisfied' }
            $r = Get-NRGBaselineRegressions -Current $cur -Prior $prior
            $r.Comparable | Should -BeTrue
            @($r.Regressions | ForEach-Object { $_.ControlId } | Sort-Object) | Should -Be @('AAD-1.1', 'AAD-1.2')
            @($r.Improvements | ForEach-Object { $_.ControlId }) | Should -Be @('AAD-1.4')
        }
        It 'a baseline version change is stated, not read as decline, and only shared controls are compared' {
            $prior = & $script:Comp '1.0' 'Standard' @{ 'AAD-1.1' = 'Satisfied' }
            $cur   = & $script:Comp '1.1' 'Standard' @{ 'AAD-1.1' = 'Failed'; 'AAD-1.2' = 'Failed' }
            $r = Get-NRGBaselineRegressions -Current $cur -Prior $prior
            $r.Comparable | Should -BeFalse
            $r.BaselineVersionChanged | Should -BeTrue
            $r.Note | Should -Match 'does not mean the client got worse'
            @($r.Regressions | ForEach-Object { $_.ControlId }) | Should -Be @('AAD-1.1')
        }
        It 'a tier change is stated the same way' {
            $prior = & $script:Comp '1.0' 'Minimum' @{ 'AAD-1.1' = 'Satisfied' }
            $cur   = & $script:Comp '1.0' 'Standard' @{ 'AAD-1.1' = 'Satisfied' }
            $r = Get-NRGBaselineRegressions -Current $cur -Prior $prior
            $r.TargetTierChanged | Should -BeTrue
            @($r.Regressions).Count | Should -Be 0
        }
        It 'a prior run without baseline data yields nothing to compare, not a fabricated clean history' {
            $cur = & $script:Comp '1.0' 'Standard' @{ 'AAD-1.1' = 'Failed' }
            $r = Get-NRGBaselineRegressions -Current $cur -Prior $null
            $r.Available | Should -BeFalse
            @($r.Regressions).Count | Should -Be 0
        }
    }
}

Describe 'NRG Security Baseline — entry point and results contract' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Entry = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1') -Raw
        $script:Readme = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'README.md') -Raw
    }

    It 'takes -BaselineTier with the three tiers' {
        $script:Entry | Should -Match "\[ValidateSet\('', 'Minimum', 'Standard', 'Hardened'\)\]\s*\[string\] \`$BaselineTier"
    }
    It 'reads BaselineTier from clients.json and the prior metadata on -FromResults' {
        $script:Entry | Should -Match "clientRec\.PSObject\.Properties\['BaselineTier'\]"
        $script:Entry | Should -Match "Get-NRGObjectField -Item \`$reportMetadata -Key 'TargetTier'"
    }
    It 'records BaselineVersion and TargetTier in the metadata and writes BaselineCompliance and BaselineRegressions to the results JSON' {
        $script:Entry | Should -Match "\`$reportMetadata\['BaselineVersion'\]"
        $script:Entry | Should -Match "\`$reportMetadata\['TargetTier'\]"
        $script:Entry | Should -Match '(?m)^\s*BaselineCompliance\s*=\s*\$baselineCompliance'
        $script:Entry | Should -Match '(?m)^\s*BaselineRegressions\s*=\s*\$baselineRegressions'
    }
    It 'resolves the baseline after license gating and the EDR declaration (it must see the same findings the report does)' {
        $iGate = $script:Entry.LastIndexOf('Set-NRGLicenseGating')
        $iBase = $script:Entry.IndexOf('Get-NRGBaselineCompliance -Findings')
        $iBase | Should -BeGreaterThan $iGate
    }
    It 'the results JSON depth covers the baseline rows' {
        $script:Entry | Should -Match 'ConvertTo-Json -Depth 12'
    }
    It 'the README parameter table documents -BaselineTier' {
        $script:Readme | Should -Match '`-BaselineTier`'
    }
}

Describe 'NRG Security Baseline — report rendering' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        # AAD-1.2 reads both collectors; without the second it is (correctly) not verified.
        foreach ($k in @('AAD-CAPolicies', 'AAD-AuthPolicies')) { Set-NRGRawData -Key $k -Data @{ CollectorId = $k; CollectedAt = (Get-Date).ToString('o'); Success = $true; Data = @{} } }
        Add-NRGFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'Legacy Authentication Blocked' -Severity 'Critical' -Detail 'Blocked for all users.' -FrameworkIds @('NIST:IA-2')
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'MFA Required for All Users' -Severity 'Critical' -Detail 'No enforcing policy.' -FrameworkIds @('NIST:IA-2(1)')
        $script:findings = Get-NRGFindings
        $script:metadata = @{
            TenantDomain = 'contoso.onmicrosoft.com'; TenantId = '00000000-0000-0000-0000-000000000000'
            Operator = 'assessor@nrgtechservices.com'; AssessmentDate = 'September 29, 2026'
            AssessmentTime = '2026-09-29T00:00:00.0000000+00:00'; ToolVersion = '4.14.3'; QuickScan = $false
            BaselineVersion = '1.0'; TargetTier = 'Minimum'
        }
        $script:conn = @{ Graph = $true; EXO = $true; IPPSSession = $true; Teams = $true; SharePoint = $true }
        $script:regs = [ordered]@{
            Available = $true; Comparable = $false; BaselineVersionChanged = $true; TargetTierChanged = $false
            PriorBaselineVersion = '0.9'; PriorTargetTier = 'Minimum'; CurrentBaselineVersion = '1.0'; CurrentTargetTier = 'Minimum'
            Note = 'The baseline context changed (v0.9 Minimum -> v1.0 Minimum). A lower result does not mean the client got worse; only controls required in both runs at the same tier are compared.'
            Regressions = @([pscustomobject]@{ ControlId = 'AAD-1.2'; Title = 'MFA Required for All Users'; RequiredTier = 'Minimum'; Previous = 'Satisfied'; Current = 'Failed'; Reason = 'Gap: No enforcing policy.' })
            Improvements = @()
        }
        $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-baseline-render-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path $script:tmp | Out-Null
        $script:htmlPath = Join-Path $script:tmp 'report.html'
        $script:mdPath   = Join-Path $script:tmp 'summary.md'
        Publish-NRGAssessmentHTML -Metadata $script:metadata -Findings $script:findings -Connections $script:conn -OutputPath $script:htmlPath -BaselineRegressions $script:regs -ErrorAction Stop
        Publish-NRGAssessmentSummary -Metadata $script:metadata -Findings $script:findings -Connections $script:conn -OutputPath $script:mdPath -BaselineRegressions $script:regs -ErrorAction Stop
        $script:html = Get-Content -LiteralPath $script:htmlPath -Raw
        $script:md   = Get-Content -LiteralPath $script:mdPath -Raw
        $script:section = [regex]::Match($script:html, "(?s)<div class='card mt' id='nrg-baseline'>.*?</div>\s*</div>\s*</div>").Value
    }
    AfterAll {
        if ($script:tmp -and (Test-Path -LiteralPath $script:tmp)) { Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue }
        Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
    }

    It 'renders the section in both reports with the version and tier from the metadata' {
        $script:html | Should -Match "id='nrg-baseline'"
        $script:html | Should -Match 'NRG Security Baseline v1\.0 — Minimum tier'
        $script:md   | Should -Match '## NRG Security Baseline v1\.0 — Minimum tier'
    }
    It 'keeps configuration compliance and effectiveness visibility as separate blocks' {
        $script:html | Should -Match 'Configuration compliance'
        $script:html | Should -Match 'Effectiveness visibility'
        $script:md   | Should -Match '### Configuration compliance'
        $script:md   | Should -Match '### Effectiveness visibility'
    }
    It 'shows the failed control as Failed and the unassessed ones as not verified, never as satisfied' {
        $script:md | Should -Match '\| AAD-1\.2 [^|]*\| Minimum \| Identity \| \*\*Failed\*\*'
        $script:md | Should -Match '\| Satisfied \| 1 \|'
        $script:md | Should -Match '\| Not verified \| \d+ \|'
    }
    It 'reports the effectiveness of every control here as unknown, not assumed' {
        $script:md | Should -Match '\| Effective \| 0 \|'
        $script:md | Should -Match '\| Unknown \(evidence not collected\) \| \d+ \|'
    }
    It 'renders the regression and the version-change note' {
        $script:html | Should -Match 'Baseline regressions since the prior run \(1\)'
        $script:html | Should -Match 'does not mean the client got worse'
        $script:md   | Should -Match '### Baseline regressions since the prior run \(1\)'
    }
    It 'never says the tenant is compliant or secure' {
        $script:section | Should -Not -Match '(?i)\bis compliant\b|\bfully compliant\b|\bsecure\b|\bno issues\b'
    }
    It 'escapes finding text in the section' {
        $script:section | Should -Not -Match '<script'
    }
}

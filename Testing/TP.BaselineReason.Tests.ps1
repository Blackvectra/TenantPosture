#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.BaselineReason.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Pins the one explanation contract for baseline rows: a stable
             ReasonCode from an ordered catalog plus a short Reason, resolved by
             one function and carried by the compliance view, the plan, the
             comparison, the regression rows, the JSON and both reports. The
             precedence is deterministic: a skipped collector never reads as
             license-blocked, a third-party declaration never reads as manual,
             and a consumer never has to parse prose.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Baseline reason contract — catalog' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Codes = Get-TPBaselineReasonCodes
    }
    AfterAll { Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    It 'is ordered, unique, and every entry carries a scope and a meaning' {
        $keys = @($script:Codes.Keys)
        $keys.Count | Should -Be (@($keys | Select-Object -Unique).Count)
        $prev = 0
        foreach ($k in $keys) {
            $e = $script:Codes[$k]
            $e.Code | Should -Be $k
            $e.Precedence | Should -Be ($prev + 1); $prev = $e.Precedence
            $e.Scope | Should -BeIn @('Run', 'Plan', 'Both')
            $e.Meaning | Should -Not -BeNullOrEmpty
        }
    }

    It 'orders operator and declaration signals above licensing, licensing above evidence, evidence above verdicts' {
        $order = @($script:Codes.Keys)
        $idx = { param([string] $c) [array]::IndexOf($order, $c) }
        (& $idx 'SkippedByOperator')        | Should -BeLessThan (& $idx 'LicenseBlocked')
        (& $idx 'ThirdPartyHandled')        | Should -BeLessThan (& $idx 'LicenseBlocked')
        (& $idx 'ManualVerificationRequired') | Should -BeLessThan (& $idx 'ThirdPartyHandled')
        (& $idx 'OptionalCollectorRequired') | Should -BeLessThan (& $idx 'LicenseBlocked')
        (& $idx 'LicenseBlocked')           | Should -BeLessThan (& $idx 'CollectorUnavailable')
        (& $idx 'CollectorUnavailable')     | Should -BeLessThan (& $idx 'EvidenceStale')
        (& $idx 'EvidenceStale')            | Should -BeLessThan (& $idx 'EvidenceNotRead')
        (& $idx 'EvidenceNotRead')          | Should -BeLessThan (& $idx 'ControlFailed')
        (& $idx 'ControlFailed')            | Should -BeLessThan (& $idx 'Satisfied')
    }

    It 'every plan Expected bucket maps to a catalog code' {
        foreach ($e in 'Manual', 'SkippedByOperator', 'ThirdPartyHandled', 'OptionalCollectorRequired', 'LicenseBlockedExpected', 'LicensingUnknown', 'Automatic') {
            $script:Codes.Contains((ConvertTo-TPBaselineReasonCode -Expected $e)) | Should -BeTrue -Because "$e must map to a code"
        }
    }

    It 'the sentence helper keeps the first sentence, drops the not-assessed prefix and the cross-reference boilerplate' {
        Get-TPReasonSentence -Text 'Not assessed. 2 rule(s) forward to a recipient that could not be resolved. A rule the tool could not read is not clean.' | Should -Be '2 rule(s) forward to a recipient that could not be resolved.'
        Get-TPReasonSentence -Text '18 of 28 shared mailbox(es) have direct sign-in enabled. Scored together with EXO-6.2 (both read the same setting).' | Should -Be '18 of 28 shared mailbox(es) have direct sign-in enabled.'
        (Get-TPReasonSentence -Text ('x' * 400)).Length | Should -BeLessOrEqual 240
        Get-TPReasonSentence -Text '' | Should -Be ''
    }
}

Describe 'Baseline reason contract — resolution and precedence' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        Clear-TPState
        $script:Def = Get-TPBaselineDefinition -Force
        $script:Codes = Get-TPBaselineReasonCodes
        $script:Now = Get-Date
        $script:Raw = { param([string] $Key, [bool] $Ok = $true) @{ CollectorId = $Key; CollectedAt = $script:Now.ToString('o'); Success = $Ok; Data = @{} } }
        $script:Row = {
            param([string] $State, [string] $Cause = '', [string] $Constraint = 'None', [string] $Prose = '', [string] $FState = '', [string] $Cid = 'AAD-1.1')
            [ordered]@{ ControlId = $Cid; ObservedState = $State; Constraint = $Constraint; NotVerifiedCause = $Cause; Reason = $Prose; ObservedFindingState = $FState }
        }
    }
    AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-TPState }

    It 'a compliance view carries a catalog code and a non-empty reason on every row, and the codes sum to the required count' {
        Add-TPFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'Legacy auth' -Severity 'High' -Detail 'Blocked for all users.'
        Add-TPFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'MFA' -Severity 'High' -Detail '48 of 99 enabled members have no registered MFA method. A second sentence.'
        $c = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData @{ 'AAD-AuthPolicies' = (& $script:Raw 'AAD-AuthPolicies'); 'AAD-CAPolicies' = (& $script:Raw 'AAD-CAPolicies'); 'AAD-Users' = (& $script:Raw 'AAD-Users') } -Coverage @{}
        foreach ($r in $c.Controls) {
            $script:Codes.Contains([string]$r.ReasonCode) | Should -BeTrue -Because "$($r.ControlId) must carry a catalog code, got '$($r.ReasonCode)'"
            $script:Codes[[string]$r.ReasonCode].Scope | Should -Not -Be 'Plan' -Because "$($r.ControlId): a run row never carries a plan-only code"
            [string]$r.Reason | Should -Not -BeNullOrEmpty
            [string]$r.Detail | Should -Not -BeNullOrEmpty -Because 'the long prose is kept as Detail'
        }
        $sum = 0; foreach ($k in $c.Summary.ByReasonCode.Keys) { $sum += [int]$c.Summary.ByReasonCode[$k] }
        $sum | Should -Be $c.Summary.RequiredControls
        @($c.ReasonCodes | ForEach-Object { $_.Code }) | Should -Be @($script:Codes.Keys)
        $mfa = @($c.Controls | Where-Object { $_.ControlId -eq 'AAD-1.2' })[0]
        $mfa.ReasonCode | Should -Be 'ControlFailed'
        $mfa.Reason | Should -Be '48 of 99 enabled members have no registered MFA method.'
        $ok = @($c.Controls | Where-Object { $_.ControlId -eq 'AAD-1.1' })[0]
        $ok.ReasonCode | Should -Be 'Satisfied'
    }

    It 'a skipped collector resolves SkippedByOperator, not LicenseBlocked, even when the license is also unmet' {
        # Coverage says Purview was skipped; the finding (had it run) would be license-gated.
        Add-TPFinding -ControlId 'PVW-1.1' -State 'NotApplicable' -Category 'Compliance' -Title 'Audit' -Detail 'Not assessed: licensing upgrade opportunity.'
        $c = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData @{ 'Purview' = (& $script:Raw 'Purview') } -Coverage @{ 'Purview' = @{ Status = 'Skipped'; Note = 'Skipped for this run with -SkipPurview.' } }
        $row = @($c.Controls | Where-Object { $_.ControlId -eq 'PVW-1.1' })[0]
        $row.ObservedState | Should -Be 'NotVerified'
        $row.ReasonCode | Should -Be 'SkippedByOperator' -Because 'coverage Skipped is the operator''s choice, resolved before any license signal'
        $row.Reason | Should -Match 'skipped'
        $row.NotVerifiedCause | Should -Be 'Skipped by operator'
    }

    It 'a third-party declaration resolves ThirdPartyHandled, never ManualVerificationRequired or NotApplicable' {
        Add-TPFinding -ControlId 'INT-2.1' -State 'Gap' -Category 'Endpoint' -Title 'EDR' -Severity 'High' -Detail 'No EDR policy assigned.'
        $null = Set-TPThirdPartyEdr -Product 'Cortex XDR'
        $c = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData @{ 'Intune-EndpointSecurity' = (& $script:Raw 'Intune-EndpointSecurity') } -Coverage @{}
        $row = @($c.Controls | Where-Object { $_.ControlId -eq 'INT-2.1' })[0]
        $row.ObservedState | Should -Be 'NotApplicable'
        $row.ReasonCode | Should -Be 'ThirdPartyHandled'
        $row.Reason | Should -Match 'Cortex XDR'
        $row.Reason | Should -Match 'not verified'
    }

    It 'a passing Defender check keeps Satisfied beside a third-party declaration' {
        Add-TPFinding -ControlId 'INT-2.1' -State 'Satisfied' -Category 'Endpoint' -Title 'EDR' -Severity 'High' -Detail 'EDR policy assigned to all devices.'
        $null = Set-TPThirdPartyEdr -Product 'Cortex XDR'
        $c = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData @{ 'Intune-EndpointSecurity' = (& $script:Raw 'Intune-EndpointSecurity') } -Coverage @{}
        (@($c.Controls | Where-Object { $_.ControlId -eq 'INT-2.1' })[0]).ReasonCode | Should -Be 'Satisfied'
    }

    It 'an unread SharePoint shell value resolves OptionalCollectorRequired; other unread evidence resolves EvidenceNotRead' {
        Add-TPFinding -ControlId 'SPO-1.2' -State 'NotApplicable' -Category 'SharePoint' -Title 'Default link' -Detail 'Anyone links are enabled tenant-wide; the default link type was not read. Requires the SharePoint Online Management Shell (Get-SPOTenant); not connected. Re-run with -IncludeSharePointShell to read it.'
        Add-TPFinding -ControlId 'EXO-7.2' -State 'NotApplicable' -Category 'Email' -Title 'Forwarding rules' -Detail 'Not assessed. 2 rule(s) forward to a recipient that could not be resolved to an address; the recipient was not read.'
        $c = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData @{ 'SharePoint' = (& $script:Raw 'SharePoint'); 'EXO-Inventory' = (& $script:Raw 'EXO-Inventory') } -Coverage @{}
        $spo = @($c.Controls | Where-Object { $_.ControlId -eq 'SPO-1.2' })[0]
        $spo.ReasonCode | Should -Be 'OptionalCollectorRequired'
        $spo.Reason | Should -Match 'IncludeSharePointShell'
        $exo = @($c.Controls | Where-Object { $_.ControlId -eq 'EXO-7.2' })[0]
        $exo.ReasonCode | Should -Be 'EvidenceNotRead'
        $exo.Reason | Should -Match 'could not be resolved'
    }

    It 'a failed collector resolves CollectorUnavailable and names the collector' {
        Add-TPFinding -ControlId 'EXO-1.2' -State 'Satisfied' -Category 'Email' -Title 'SMTP AUTH' -Severity 'High' -Detail 'Disabled.'
        $c = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData @{ 'EXO-MailboxConfig' = (& $script:Raw 'EXO-MailboxConfig' $false) } -Coverage @{}
        $row = @($c.Controls | Where-Object { $_.ControlId -eq 'EXO-1.2' })[0]
        $row.ReasonCode | Should -Be 'CollectorUnavailable'
        $row.Reason | Should -Match 'EXO-MailboxConfig'
        $row.Reason | Should -Match 'did not succeed'
    }

    It 'stale evidence resolves EvidenceStale; the manual control resolves ManualVerificationRequired' {
        Add-TPFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'Legacy auth' -Severity 'High' -Detail 'Blocked.'
        $old = @{ CollectorId = 'AAD-AuthPolicies'; CollectedAt = $script:Now.AddDays(-400).ToString('o'); Success = $true; Data = @{} }
        $c = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData @{ 'AAD-AuthPolicies' = $old; 'AAD-CAPolicies' = $old } -Coverage @{} -AsOf $script:Now
        (@($c.Controls | Where-Object { $_.ControlId -eq 'AAD-1.1' })[0]).ReasonCode | Should -Be 'EvidenceStale'
        (@($c.Controls | Where-Object { $_.ControlId -eq 'VM-VERIFY-01' })[0]).ReasonCode | Should -Be 'ManualVerificationRequired'
    }

    It 'license gating resolves LicenseBlocked and names the requirement' {
        $row = & $script:Row 'NotApplicable' '' 'LicenseBlocked' 'licensing upgrade opportunity' 'Gap' 'AAD-1.4'
        $rr = Resolve-TPBaselineReason -Row $row -Detail 'Not scored: licensing upgrade opportunity.'
        $rr.ReasonCode | Should -Be 'LicenseBlocked'
        $rr.Reason | Should -Match 'Requires .*P2'
    }

    It 'an approved exception changes no code' {
        Add-TPFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'MFA' -Severity 'High' -Detail 'No enforcing policy.'
        $exc = @{ Available = $true; Path = 'x'; Approved = @{ 'AAD-1.2' = @{ ControlId = 'AAD-1.2'; Reason = 'r'; CompensatingControl = 'c'; Verdict = 'v' } }; Rejected = @() }
        $c = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData @{ 'AAD-AuthPolicies' = (& $script:Raw 'AAD-AuthPolicies'); 'AAD-CAPolicies' = (& $script:Raw 'AAD-CAPolicies'); 'AAD-Users' = (& $script:Raw 'AAD-Users') } -Coverage @{} -Exceptions $exc
        $row = @($c.Controls | Where-Object { $_.ControlId -eq 'AAD-1.2' })[0]
        $row.Disposition | Should -Be 'ApprovedException'
        $row.ReasonCode | Should -Be 'ControlFailed'
    }

    It 'the plan carries codes, and the comparison carries the run''s code and reason for an unexpected row' {
        $plan = Get-TPBaselinePlan -TargetTier Standard
        foreach ($r in $plan.Controls) { $script:Codes.Contains([string]$r.ReasonCode) | Should -BeTrue }
        @($plan.ReasonCodes | ForEach-Object { $_.Code }) | Should -Be @($script:Codes.Keys)
        Add-TPFinding -ControlId 'EXO-7.2' -State 'NotApplicable' -Category 'Email' -Title 'Forwarding rules' -Detail 'Not assessed. 2 rule(s) forward to a recipient that could not be resolved; not read.'
        $c = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData @{ 'EXO-Inventory' = (& $script:Raw 'EXO-Inventory') } -Coverage @{}
        $cmp = Compare-TPBaselinePlan -Plan $plan -Compliance $c
        $u = @($cmp.UnexpectedNotVerified | Where-Object { $_.ControlId -eq 'EXO-7.2' })[0]
        $u.ReasonCode | Should -Be 'EvidenceNotRead'
        $u.Reason | Should -Match 'could not be resolved'
    }

    It 'regression rows carry the current reason code' {
        Add-TPFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'Legacy auth' -Severity 'High' -Detail 'Blocked.'
        $raw = @{ 'AAD-AuthPolicies' = (& $script:Raw 'AAD-AuthPolicies'); 'AAD-CAPolicies' = (& $script:Raw 'AAD-CAPolicies') }
        $prior = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData $raw -Coverage @{}
        Clear-TPState
        Add-TPFinding -ControlId 'AAD-1.1' -State 'Gap' -Category 'Identity' -Title 'Legacy auth' -Severity 'High' -Detail 'Legacy authentication is allowed.'
        $cur = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData $raw -Coverage @{}
        $reg = Get-TPBaselineRegressions -Current $cur -Prior $prior -PriorRunTime 'x'
        $row = @($reg.Regressions | Where-Object { $_.ControlId -eq 'AAD-1.1' })[0]
        $row.Kind | Should -Be 'ConfigurationRegressed'
        $row.CurrentReasonCode | Should -Be 'ControlFailed'
    }
}

Describe 'Baseline reason contract — rendered' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        Clear-TPState
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-reason-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        Add-TPFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'MFA Required for All Users' -Severity 'Critical' -Detail '48 of 99 enabled members have no registered MFA method.' -FrameworkIds @('NIST:IA-2(1)')
        $script:Findings = @(Get-TPFindings)
        $script:Meta = @{
            TenantDomain = 'contoso.onmicrosoft.com'; TenantId = '00000000-0000-0000-0000-000000000000'
            Operator = 'assessor@nrgtechservices.com'; AssessmentDate = 'September 29, 2026'
            AssessmentTime = '2026-09-29T00:00:00.0000000+00:00'; ToolVersion = '4.14.3'; QuickScan = $false
            BaselineVersion = '1.0'; TargetTier = 'Standard'
        }
        $script:Conn = @{ Graph = $true; EXO = $false; Teams = $false; IPPSSession = $false; SharePoint = $false; TenantId = $script:Meta.TenantId }
    }
    AfterAll {
        Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue
        if ($script:Tmp -and (Test-Path $script:Tmp)) { Remove-Item $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'the Markdown required-controls table shows the code beside the reason' {
        $md = Join-Path $script:Tmp 'summary.md'
        Publish-TPAssessmentSummary -Metadata $script:Meta -Findings $script:Findings -Connections $script:Conn -OutputPath $md | Out-Null
        $text = Get-Content -LiteralPath $md -Raw
        $text | Should -Match '`ControlFailed` 48 of 99 enabled members have no registered MFA method\.'
        $text | Should -Match '`ManualVerificationRequired` Verified manually'
    }

    It 'the HTML required-controls table shows the code beside the reason' {
        $html = Join-Path $script:Tmp 'report.html'
        Publish-TPAssessmentHTML -Metadata $script:Meta -Findings $script:Findings -Connections $script:Conn -OutputPath $html | Out-Null
        $text = Get-Content -LiteralPath $html -Raw
        $text | Should -Match '<code>ControlFailed</code> 48 of 99 enabled members have no registered MFA method\.'
        $text | Should -Match '<code>ManualVerificationRequired</code> Verified manually'
    }
}

Describe 'Baseline coverage — evidence and effectiveness, apart from each other and from the score' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        Clear-TPState
        $script:Now = Get-Date
        $script:Raw = { param([string] $Key, [bool] $Ok = $true) @{ CollectorId = $Key; CollectedAt = $script:Now.ToString('o'); Success = $Ok; Data = @{} } }
        $script:AllRaw = @{}
        foreach ($c in (Get-TPBaselineDefinition -Force).Controls.Values) { foreach ($k in @($c.RawDataKeys)) { if ($k -and -not $script:AllRaw.ContainsKey($k)) { $script:AllRaw[$k] = & $script:Raw $k } } }
        $script:Row = { param([string] $Code, [string] $Eff = 'Unknown', [string] $Cap = 'NotCollected') [ordered]@{ ControlId = "X-$Code"; ReasonCode = $Code; EffectivenessState = $Eff; EffectivenessCapability = $Cap } }
    }
    AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-TPState }

    It 'Known + Unknown + LicenseBlocked = Applicable, and NotApplicable sits outside the denominator' {
        $rows = @((& $script:Row 'Satisfied'), (& $script:Row 'ControlFailed'), (& $script:Row 'ThirdPartyHandled'), (& $script:Row 'CollectorUnavailable'), (& $script:Row 'EvidenceNotRead'), (& $script:Row 'ManualVerificationRequired'), (& $script:Row 'LicenseBlocked'), (& $script:Row 'NotApplicable'))
        $cov = Get-TPBaselineCoverage -Rows $rows
        $cov.Evidence.Required | Should -Be 8
        $cov.Evidence.NotApplicable | Should -Be 1
        $cov.Evidence.Applicable | Should -Be 7
        $cov.Evidence.Known | Should -Be 3
        $cov.Evidence.Unknown | Should -Be 3
        $cov.Evidence.LicenseBlocked | Should -Be 1
        ($cov.Evidence.Known + $cov.Evidence.Unknown + $cov.Evidence.LicenseBlocked) | Should -Be $cov.Evidence.Applicable
        $cov.Evidence.Percent | Should -Be ([math]::Round(100.0 * 3 / 7, 1))
        @($cov.Evidence.Gaps.Keys) | Should -Be @('ManualVerificationRequired', 'CollectorUnavailable', 'EvidenceNotRead')
    }

    It 'a tenant failing every control has 100% evidence coverage and 0 satisfied: coverage is not the score' {
        foreach ($c in (Get-TPBaselineDefinition).Controls.Values) {
            if (-not $c.Automated) { continue }
            Add-TPFinding -ControlId $c.ControlId -State 'Gap' -Category 'Identity' -Title $c.Title -Severity 'High' -Detail 'Below the expected state.'
        }
        $comp = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData $script:AllRaw -Coverage @{}
        $comp.Summary.Satisfied | Should -Be 0
        $comp.EvidenceCoverage.Known | Should -Be ($comp.EvidenceCoverage.Applicable - 1) -Because 'only the manual control lacks evidence'
        $comp.EvidenceCoverage.Gaps['ManualVerificationRequired'] | Should -Be 1
        $comp.EvidenceCoverage.Percent | Should -BeGreaterThan 95
    }

    It 'perfect configuration evidence gives zero effectiveness coverage while nothing reads effectiveness' {
        foreach ($c in (Get-TPBaselineDefinition).Controls.Values) {
            if (-not $c.Automated) { continue }
            Add-TPFinding -ControlId $c.ControlId -State 'Satisfied' -Category 'Identity' -Title $c.Title -Severity 'High' -Detail 'At the expected state.'
        }
        $comp = Get-TPBaselineCompliance -Findings (Get-TPFindings) -TargetTier Standard -RawData $script:AllRaw -Coverage @{}
        $comp.EvidenceCoverage.Percent | Should -BeGreaterThan 95
        $comp.EffectivenessCoverage.Known | Should -Be 0
        $comp.EffectivenessCoverage.Percent | Should -Be 0
        $comp.EffectivenessCoverage.Unknown | Should -Be $comp.EffectivenessCoverage.Required
    }

    It 'effectiveness is known only from Effective or Ineffective, never from configuration' {
        $rows = @((& $script:Row 'Satisfied' 'Effective' 'Collected'), (& $script:Row 'Satisfied' 'Ineffective' 'Collected'), (& $script:Row 'Satisfied' 'Unknown' 'Collected'), (& $script:Row 'Satisfied' 'Unknown'))
        $cov = Get-TPBaselineCoverage -Rows $rows
        $cov.Effectiveness.Known | Should -Be 2
        $cov.Effectiveness.Effective | Should -Be 1
        $cov.Effectiveness.Ineffective | Should -Be 1
        $cov.Effectiveness.Unknown | Should -Be 2
        $cov.Effectiveness.CapabilityCollected | Should -Be 3
        $cov.Effectiveness.Percent | Should -Be 50
    }

    It 'both blocks render in the Markdown summary and the HTML report' {
        Add-TPFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'MFA' -Severity 'Critical' -Detail 'No enforcing policy.' -FrameworkIds @('NIST:IA-2(1)')
        $meta = @{ TenantDomain = 'contoso.onmicrosoft.com'; TenantId = '00000000-0000-0000-0000-000000000000'; Operator = 'a@b'; AssessmentDate = 'September 29, 2026'; AssessmentTime = '2026-09-29T00:00:00.0000000+00:00'; ToolVersion = '4.14.3'; QuickScan = $false; BaselineVersion = '1.0'; TargetTier = 'Standard' }
        $conn = @{ Graph = $true; EXO = $false; Teams = $false; IPPSSession = $false; SharePoint = $false; TenantId = $meta.TenantId }
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-cov-" + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        try {
            $md = Join-Path $tmp 's.md'; Publish-TPAssessmentSummary -Metadata $meta -Findings @(Get-TPFindings) -Connections $conn -OutputPath $md | Out-Null
            $t = Get-Content -LiteralPath $md -Raw
            $t | Should -Match '### Evidence coverage'
            $t | Should -Match 'applicable required controls have usable evidence \(\d+(\.\d+)?%\)'
            $t | Should -Match 'Effectiveness coverage: 0 of \d+ required controls have effectiveness evidence \(0%\)'
            $t | Should -Match '\| Evidence gaps \| Controls \|'
            $html = Join-Path $tmp 'r.html'; Publish-TPAssessmentHTML -Metadata $meta -Findings @(Get-TPFindings) -Connections $conn -OutputPath $html | Out-Null
            $h = Get-Content -LiteralPath $html -Raw
            $h | Should -Match 'Evidence coverage</h4>'
            $h | Should -Match 'Effectiveness coverage: 0 of \d+ required controls'
            $h | Should -Match '<th>Evidence gaps</th>'
        } finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

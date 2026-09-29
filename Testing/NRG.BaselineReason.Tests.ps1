#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.BaselineReason.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
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
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Codes = Get-NRGBaselineReasonCodes
    }
    AfterAll { Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

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
            $script:Codes.Contains((ConvertTo-NRGBaselineReasonCode -Expected $e)) | Should -BeTrue -Because "$e must map to a code"
        }
    }

    It 'the sentence helper keeps the first sentence, drops the not-assessed prefix and the cross-reference boilerplate' {
        Get-NRGReasonSentence -Text 'Not assessed. 2 rule(s) forward to a recipient that could not be resolved. A rule the tool could not read is not clean.' | Should -Be '2 rule(s) forward to a recipient that could not be resolved.'
        Get-NRGReasonSentence -Text '18 of 28 shared mailbox(es) have direct sign-in enabled. Scored together with EXO-6.2 (both read the same setting).' | Should -Be '18 of 28 shared mailbox(es) have direct sign-in enabled.'
        (Get-NRGReasonSentence -Text ('x' * 400)).Length | Should -BeLessOrEqual 240
        Get-NRGReasonSentence -Text '' | Should -Be ''
    }
}

Describe 'Baseline reason contract — resolution and precedence' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        $script:Def = Get-NRGBaselineDefinition -Force
        $script:Codes = Get-NRGBaselineReasonCodes
        $script:Now = Get-Date
        $script:Raw = { param([string] $Key, [bool] $Ok = $true) @{ CollectorId = $Key; CollectedAt = $script:Now.ToString('o'); Success = $Ok; Data = @{} } }
        $script:Row = {
            param([string] $State, [string] $Cause = '', [string] $Constraint = 'None', [string] $Prose = '', [string] $FState = '', [string] $Cid = 'AAD-1.1')
            [ordered]@{ ControlId = $Cid; ObservedState = $State; Constraint = $Constraint; NotVerifiedCause = $Cause; Reason = $Prose; ObservedFindingState = $FState }
        }
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-NRGState }

    It 'a compliance view carries a catalog code and a non-empty reason on every row, and the codes sum to the required count' {
        Add-NRGFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'Legacy auth' -Severity 'High' -Detail 'Blocked for all users.'
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'MFA' -Severity 'High' -Detail '48 of 99 enabled members have no registered MFA method. A second sentence.'
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData @{ 'AAD-AuthPolicies' = (& $script:Raw 'AAD-AuthPolicies'); 'AAD-CAPolicies' = (& $script:Raw 'AAD-CAPolicies'); 'AAD-Users' = (& $script:Raw 'AAD-Users') } -Coverage @{}
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
        Add-NRGFinding -ControlId 'PVW-1.1' -State 'NotApplicable' -Category 'Compliance' -Title 'Audit' -Detail 'Not assessed: licensing upgrade opportunity.'
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData @{ 'Purview' = (& $script:Raw 'Purview') } -Coverage @{ 'Purview' = @{ Status = 'Skipped'; Note = 'Skipped for this run with -SkipPurview.' } }
        $row = @($c.Controls | Where-Object { $_.ControlId -eq 'PVW-1.1' })[0]
        $row.ObservedState | Should -Be 'NotVerified'
        $row.ReasonCode | Should -Be 'SkippedByOperator' -Because 'coverage Skipped is the operator''s choice, resolved before any license signal'
        $row.Reason | Should -Match 'skipped'
        $row.NotVerifiedCause | Should -Be 'Skipped by operator'
    }

    It 'a third-party declaration resolves ThirdPartyHandled, never ManualVerificationRequired or NotApplicable' {
        Add-NRGFinding -ControlId 'INT-2.1' -State 'Gap' -Category 'Endpoint' -Title 'EDR' -Severity 'High' -Detail 'No EDR policy assigned.'
        $null = Set-NRGThirdPartyEdr -Product 'Cortex XDR'
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData @{ 'Intune-EndpointSecurity' = (& $script:Raw 'Intune-EndpointSecurity') } -Coverage @{}
        $row = @($c.Controls | Where-Object { $_.ControlId -eq 'INT-2.1' })[0]
        $row.ObservedState | Should -Be 'NotApplicable'
        $row.ReasonCode | Should -Be 'ThirdPartyHandled'
        $row.Reason | Should -Match 'Cortex XDR'
        $row.Reason | Should -Match 'not verified'
    }

    It 'a passing Defender check keeps Satisfied beside a third-party declaration' {
        Add-NRGFinding -ControlId 'INT-2.1' -State 'Satisfied' -Category 'Endpoint' -Title 'EDR' -Severity 'High' -Detail 'EDR policy assigned to all devices.'
        $null = Set-NRGThirdPartyEdr -Product 'Cortex XDR'
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData @{ 'Intune-EndpointSecurity' = (& $script:Raw 'Intune-EndpointSecurity') } -Coverage @{}
        (@($c.Controls | Where-Object { $_.ControlId -eq 'INT-2.1' })[0]).ReasonCode | Should -Be 'Satisfied'
    }

    It 'an unread SharePoint shell value resolves OptionalCollectorRequired; other unread evidence resolves EvidenceNotRead' {
        Add-NRGFinding -ControlId 'SPO-1.2' -State 'NotApplicable' -Category 'SharePoint' -Title 'Default link' -Detail 'Anyone links are enabled tenant-wide; the default link type was not read. Requires the SharePoint Online Management Shell (Get-SPOTenant); not connected. Re-run with -IncludeSharePointShell to read it.'
        Add-NRGFinding -ControlId 'EXO-7.2' -State 'NotApplicable' -Category 'Email' -Title 'Forwarding rules' -Detail 'Not assessed. 2 rule(s) forward to a recipient that could not be resolved to an address; the recipient was not read.'
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData @{ 'SharePoint' = (& $script:Raw 'SharePoint'); 'EXO-Inventory' = (& $script:Raw 'EXO-Inventory') } -Coverage @{}
        $spo = @($c.Controls | Where-Object { $_.ControlId -eq 'SPO-1.2' })[0]
        $spo.ReasonCode | Should -Be 'OptionalCollectorRequired'
        $spo.Reason | Should -Match 'IncludeSharePointShell'
        $exo = @($c.Controls | Where-Object { $_.ControlId -eq 'EXO-7.2' })[0]
        $exo.ReasonCode | Should -Be 'EvidenceNotRead'
        $exo.Reason | Should -Match 'could not be resolved'
    }

    It 'a failed collector resolves CollectorUnavailable and names the collector' {
        Add-NRGFinding -ControlId 'EXO-1.2' -State 'Satisfied' -Category 'Email' -Title 'SMTP AUTH' -Severity 'High' -Detail 'Disabled.'
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData @{ 'EXO-MailboxConfig' = (& $script:Raw 'EXO-MailboxConfig' $false) } -Coverage @{}
        $row = @($c.Controls | Where-Object { $_.ControlId -eq 'EXO-1.2' })[0]
        $row.ReasonCode | Should -Be 'CollectorUnavailable'
        $row.Reason | Should -Match 'EXO-MailboxConfig'
        $row.Reason | Should -Match 'did not succeed'
    }

    It 'stale evidence resolves EvidenceStale; the manual control resolves ManualVerificationRequired' {
        Add-NRGFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'Legacy auth' -Severity 'High' -Detail 'Blocked.'
        $old = @{ CollectorId = 'AAD-AuthPolicies'; CollectedAt = $script:Now.AddDays(-400).ToString('o'); Success = $true; Data = @{} }
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData @{ 'AAD-AuthPolicies' = $old; 'AAD-CAPolicies' = $old } -Coverage @{} -AsOf $script:Now
        (@($c.Controls | Where-Object { $_.ControlId -eq 'AAD-1.1' })[0]).ReasonCode | Should -Be 'EvidenceStale'
        (@($c.Controls | Where-Object { $_.ControlId -eq 'VM-VERIFY-01' })[0]).ReasonCode | Should -Be 'ManualVerificationRequired'
    }

    It 'license gating resolves LicenseBlocked and names the requirement' {
        $row = & $script:Row 'NotApplicable' '' 'LicenseBlocked' 'licensing upgrade opportunity' 'Gap' 'AAD-1.4'
        $rr = Resolve-NRGBaselineReason -Row $row -Detail 'Not scored: licensing upgrade opportunity.'
        $rr.ReasonCode | Should -Be 'LicenseBlocked'
        $rr.Reason | Should -Match 'Requires .*P2'
    }

    It 'an approved exception changes no code' {
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'MFA' -Severity 'High' -Detail 'No enforcing policy.'
        $exc = @{ Available = $true; Path = 'x'; Approved = @{ 'AAD-1.2' = @{ ControlId = 'AAD-1.2'; Reason = 'r'; CompensatingControl = 'c'; Verdict = 'v' } }; Rejected = @() }
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData @{ 'AAD-AuthPolicies' = (& $script:Raw 'AAD-AuthPolicies'); 'AAD-CAPolicies' = (& $script:Raw 'AAD-CAPolicies'); 'AAD-Users' = (& $script:Raw 'AAD-Users') } -Coverage @{} -Exceptions $exc
        $row = @($c.Controls | Where-Object { $_.ControlId -eq 'AAD-1.2' })[0]
        $row.Disposition | Should -Be 'ApprovedException'
        $row.ReasonCode | Should -Be 'ControlFailed'
    }

    It 'the plan carries codes, and the comparison carries the run''s code and reason for an unexpected row' {
        $plan = Get-NRGBaselinePlan -TargetTier Standard
        foreach ($r in $plan.Controls) { $script:Codes.Contains([string]$r.ReasonCode) | Should -BeTrue }
        @($plan.ReasonCodes | ForEach-Object { $_.Code }) | Should -Be @($script:Codes.Keys)
        Add-NRGFinding -ControlId 'EXO-7.2' -State 'NotApplicable' -Category 'Email' -Title 'Forwarding rules' -Detail 'Not assessed. 2 rule(s) forward to a recipient that could not be resolved; not read.'
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData @{ 'EXO-Inventory' = (& $script:Raw 'EXO-Inventory') } -Coverage @{}
        $cmp = Compare-NRGBaselinePlan -Plan $plan -Compliance $c
        $u = @($cmp.UnexpectedNotVerified | Where-Object { $_.ControlId -eq 'EXO-7.2' })[0]
        $u.ReasonCode | Should -Be 'EvidenceNotRead'
        $u.Reason | Should -Match 'could not be resolved'
    }

    It 'regression rows carry the current reason code' {
        Add-NRGFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'Legacy auth' -Severity 'High' -Detail 'Blocked.'
        $raw = @{ 'AAD-AuthPolicies' = (& $script:Raw 'AAD-AuthPolicies'); 'AAD-CAPolicies' = (& $script:Raw 'AAD-CAPolicies') }
        $prior = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData $raw -Coverage @{}
        Clear-NRGState
        Add-NRGFinding -ControlId 'AAD-1.1' -State 'Gap' -Category 'Identity' -Title 'Legacy auth' -Severity 'High' -Detail 'Legacy authentication is allowed.'
        $cur = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData $raw -Coverage @{}
        $reg = Get-NRGBaselineRegressions -Current $cur -Prior $prior -PriorRunTime 'x'
        $row = @($reg.Regressions | Where-Object { $_.ControlId -eq 'AAD-1.1' })[0]
        $row.Kind | Should -Be 'ConfigurationRegressed'
        $row.CurrentReasonCode | Should -Be 'ControlFailed'
    }
}

Describe 'Baseline reason contract — rendered' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-reason-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'MFA Required for All Users' -Severity 'Critical' -Detail '48 of 99 enabled members have no registered MFA method.' -FrameworkIds @('NIST:IA-2(1)')
        $script:Findings = @(Get-NRGFindings)
        $script:Meta = @{
            TenantDomain = 'contoso.onmicrosoft.com'; TenantId = '00000000-0000-0000-0000-000000000000'
            Operator = 'assessor@nrgtechservices.com'; AssessmentDate = 'September 29, 2026'
            AssessmentTime = '2026-09-29T00:00:00.0000000+00:00'; ToolVersion = '4.14.3'; QuickScan = $false
            BaselineVersion = '1.0'; TargetTier = 'Standard'
        }
        $script:Conn = @{ Graph = $true; EXO = $false; Teams = $false; IPPSSession = $false; SharePoint = $false; TenantId = $script:Meta.TenantId }
    }
    AfterAll {
        Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
        if ($script:Tmp -and (Test-Path $script:Tmp)) { Remove-Item $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'the Markdown required-controls table shows the code beside the reason' {
        $md = Join-Path $script:Tmp 'summary.md'
        Publish-NRGAssessmentSummary -Metadata $script:Meta -Findings $script:Findings -Connections $script:Conn -OutputPath $md | Out-Null
        $text = Get-Content -LiteralPath $md -Raw
        $text | Should -Match '`ControlFailed` 48 of 99 enabled members have no registered MFA method\.'
        $text | Should -Match '`ManualVerificationRequired` Verified manually'
    }

    It 'the HTML required-controls table shows the code beside the reason' {
        $html = Join-Path $script:Tmp 'report.html'
        Publish-NRGAssessmentHTML -Metadata $script:Meta -Findings $script:Findings -Connections $script:Conn -OutputPath $html | Out-Null
        $text = Get-Content -LiteralPath $html -Raw
        $text | Should -Match '<code>ControlFailed</code> 48 of 99 enabled members have no registered MFA method\.'
        $text | Should -Match '<code>ManualVerificationRequired</code> Verified manually'
    }
}

#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.EvidenceLimits.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Two things. INT-1.1 judges both halves of its expected state (coverage per enrolled
             platform, and each assigned policy's non-compliance actions) and says which half is
             missing: Satisfied only when every platform is covered and every assigned policy acts on
             a noncompliant device, Partial when a policy only notifies, not assessed when the actions
             were not read. And the evidence-limit mechanism (Config/evidence-limits.json, shown as
             "Not established: <component>." on every surface) still works, proven with a mocked
             limit: the catalog is empty since INT-1.1's boundary was lifted on 2026-10-14.
    Data keys consumed: Intune-DeviceCompliance, Intune-EndpointSecurity, Intune-AppProtection.
#>
Describe 'INT-1.1: platform coverage and non-compliance actions are both judged' {
    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        function script:Raw([string] $Id, [hashtable] $Data) { [ordered]@{ CollectorId = $Id; CollectedAt = '2026-10-01T00:00:00Z'; Success = $true; Data = $Data } }
        function script:Run([hashtable] $Dc) {
            Clear-TPState
            Set-TPRawData -Key 'Intune-DeviceCompliance' -Data (Raw 'Intune-DeviceCompliance' $Dc)
            Set-TPRawData -Key 'Intune-EndpointSecurity' -Data (Raw 'Intune-EndpointSecurity' @{ EndpointSecurityPolicies = @(); SectionStatus = @{ EndpointSecurityPolicies = 'Collected' } })
            Set-TPRawData -Key 'Intune-AppProtection' -Data (Raw 'Intune-AppProtection' @{ AppProtectionPolicies = @(); SectionStatus = @{ AppProtectionPolicies = 'Collected' } })
            & (Get-Module TenantPosture) { Test-TPControlIntune } 3>$null | Out-Null
            @(Get-TPFindings | Where-Object ControlId -eq 'INT-1.1')[-1]
        }
        # A policy as the collector stores it. $actions = $null leaves ActionsRead out, as an older results file does.
        $script:Pol = { param($platform, $assigned = $true, $actions = $null)
            $p = @{ Name = "$platform policy"; DisplayName = "$platform policy"; Platform = $platform; IsAssigned = $assigned }
            if ($null -ne $actions) { $p.ActionsRead = $true; $p.NonComplianceActions = @($actions) }
            $p }
        $script:Block  = @{ RuleName = 'PasswordRequired'; ActionType = 'block'; GracePeriodHours = 0; NotificationTemplateId = '' }
        $script:Notify = @{ RuleName = 'PasswordRequired'; ActionType = 'notification'; GracePeriodHours = 24; NotificationTemplateId = 't' }
        $script:Base = { param($policies, $platforms)
            $d = @{ SectionStatus = @{ CompliancePolicies = 'Collected'; ConfigurationProfiles = 'Collected'; EnrollmentConfig = 'Collected' }
                    ConfigurationProfiles = @(); EnrollmentConfig = @(); CompliancePolicies = @($policies) }
            if ($null -ne $platforms) { $d.OSComplianceSummary = @{ ByPlatform = $platforms }; $d.SectionStatus.OSComplianceSummary = 'Collected' }
            $d }
    }
    AfterAll { Clear-TPState }

    It 'returns the verdict each state of the evidence deserves' {
        $cases = @(
            @{ Name = 'no policy';                       Dc = (& $script:Base @() @{ Windows = 5 });                                                                     Expect = 'Gap' }
            @{ Name = 'unassigned only';                 Dc = (& $script:Base @((& $script:Pol 'windows10' $false)) @{ Windows = 5 });                                   Expect = 'Gap' }
            @{ Name = 'a platform has no policy';        Dc = (& $script:Base @((& $script:Pol 'windows10' $true @($script:Block))) @{ Windows = 5; Android = 2 });     Expect = 'Partial';       Detail = 'no assigned compliance policy for Android' }
            @{ Name = 'platform counts unread';          Dc = (& $script:Base @((& $script:Pol 'windows10')) $null);                                                     Expect = 'NotApplicable'; Detail = 'platform counts were not read; and the non-compliance actions of 1 policy(ies) were not read' }
            @{ Name = 'covered, actions not read (an older results file)'; Dc = (& $script:Base @((& $script:Pol 'windows10')) @{ Windows = 5 });                        Expect = 'NotApplicable'; Detail = 'the non-compliance actions of 1 policy(ies) were not read (windows10 policy)' }
            @{ Name = 'covered, every policy marks a device noncompliant'; Dc = (& $script:Base @((& $script:Pol 'windows10' $true @($script:Block))) @{ Windows = 5 }); Expect = 'Satisfied';     Detail = 'windows10 policy (mark noncompliant immediately)' }
            @{ Name = 'covered, a policy only notifies'; Dc = (& $script:Base @((& $script:Pol 'windows10' $true @($script:Notify))) @{ Windows = 5 });                  Expect = 'Partial';       Detail = 'take no action on a noncompliant device beyond a notification (windows10 policy)' }
            @{ Name = 'a grace period is stated';        Dc = (& $script:Base @((& $script:Pol 'windows10' $true @(@{ ActionType = 'block'; GracePeriodHours = 72 }))) @{ Windows = 5 }); Expect = 'Satisfied'; Detail = 'mark noncompliant after 72 h' }
            @{ Name = 'one policy read, one not: not assessed, never credited'; Dc = (& $script:Base @((& $script:Pol 'windows10' $true @($script:Block)), (& $script:Pol 'android')) @{ Windows = 5; Android = 1 }); Expect = 'NotApplicable'; Detail = 'were not read (android policy)' }
        )
        foreach ($c in $cases) {
            $f = Run $c.Dc
            $f | Should -Not -BeNullOrEmpty -Because $c.Name
            $f.State | Should -Be $c.Expect -Because $c.Name
            if ($c.Detail) { $f.Detail | Should -Match ([regex]::Escape($c.Detail)) -Because $c.Name }
        }
    }

    It 'the Satisfied finding says the actions are read from the policy, not that Intune applied them' {
        $f = Run (& $script:Base @((& $script:Pol 'windows10' $true @($script:Block))) @{ Windows = 5 })
        $f.State | Should -Be 'Satisfied'
        $f.Detail | Should -Match 'whether Intune applied them to a device is not'
    }

    It 'the lifted limit is gone: the catalog has no INT-1.1 entry and the note is empty' {
        (& (Get-Module TenantPosture) { Get-TPEvidenceLimitNote -ControlId 'INT-1.1' }) | Should -Be ''
        $cfg = Get-Content -LiteralPath (Join-Path $script:Root 'Config/evidence-limits.json') -Raw | ConvertFrom-Json
        @($cfg.Limits | Where-Object { $_.Control -eq 'INT-1.1' }).Count | Should -Be 0
    }
}

Describe 'Evidence limits: a recorded component is shown on every surface' {
    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Meta = @{ TenantDomain = 'contoso.example'; TenantId = '00000000-0000-0000-0000-000000000000'; Operator = 'a'; AssessmentDate = 'October 1, 2026'; AssessmentTime = '2026-10-01T00:00:00+00:00'; ToolVersion = '4.14.3'; QuickScan = $false }
        $script:Conn = @{ Graph = $true; EXO = $true; IPPSSession = $true; Teams = $true; SharePoint = $true }
        function script:Two {
            Clear-TPState
            Add-TPFinding -ControlId 'INT-1.1' -State 'Gap' -Severity 'High' -Category 'Endpoint' -Title 'Device Compliance Policies Configured' -Detail 'No device compliance policies configured.' -CurrentValue 'none' -RequiredValue 'one per platform'
            Add-TPFinding -ControlId 'INT-1.2' -State 'Gap' -Severity 'High' -Category 'Endpoint' -Title 'Non-Compliant Device Access Blocked via CA' -Detail 'No policy.' -CurrentValue 'none' -RequiredValue 'a policy'
        }
    }
    AfterAll { Clear-TPState }

    It 'the note is worded as asked and empty for a control without a limit' {
        Mock -ModuleName 'TenantPosture' -CommandName Get-TPEvidenceLimitMap -MockWith { @{ 'INT-1.1' = @{ NotEstablished = 'a synthetic component'; Reason = 'test' } } }
        (& (Get-Module TenantPosture) { Get-TPEvidenceLimitNote -ControlId 'INT-1.1' }) | Should -Be 'Not established: a synthetic component.'
        (& (Get-Module TenantPosture) { Get-TPEvidenceLimitNote -ControlId 'AAD-1.1' }) | Should -Be ''
        (& (Get-Module TenantPosture) { Get-TPEvidenceLimitMd -ControlId 'INT-1.1' }) | Should -Be ' *Not established: a synthetic component.*'
    }

    It 'the main HTML report shows it for the limited control and for no other' {
        Mock -ModuleName 'TenantPosture' -CommandName Get-TPEvidenceLimitMap -MockWith { @{ 'INT-1.1' = @{ NotEstablished = 'a synthetic component'; Reason = 'test' } } }
        Two
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('tp-lim-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Force -Path $dir | Out-Null
        try {
            Publish-TPAssessmentHTML -Metadata $script:Meta -Findings (Get-TPFindings) -Connections $script:Conn -OutputPath (Join-Path $dir 'r.html') -ClientName 'Contoso' -ErrorAction Stop | Out-Null
            $html = Get-Content -LiteralPath (Join-Path $dir 'r.html') -Raw
            ([regex]::Matches($html, 'Not established: a synthetic component\.')).Count | Should -BeGreaterThan 0
            $i = $html.IndexOf('Non-Compliant Device Access Blocked via CA')
            $i | Should -BeGreaterThan 0
            $html.Substring($i, [Math]::Min(400, $html.Length - $i)) | Should -Not -Match 'Not established: a synthetic component'
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; Clear-TPState }
    }

    It 'the report site shows it on the INT page' {
        Mock -ModuleName 'TenantPosture' -CommandName Get-TPEvidenceLimitMap -MockWith { @{ 'INT-1.1' = @{ NotEstablished = 'a synthetic component'; Reason = 'test' } } }
        $f = @{ ControlId = 'INT-1.1'; State = 'NotApplicable'; Severity = 'High'; Category = 'Endpoint'; Title = 'Device Compliance Policies Configured'
                Detail = 'Verified: 2 assigned. Not assessed: the non-compliance actions of 2 policy(ies) were not read.'; CurrentValue = ''; RequiredValue = ''; FrameworkIds = ''; Remediation = '' }
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('tp-lims-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        try {
            $null = Publish-TPReportSite -Metadata @{ TenantDomain = 'contoso.example'; ToolVersion = '4.14.3' } -Findings @($f) -OutputPath $dir
            (Get-Content -LiteralPath (Join-Path $dir 'INT.html') -Raw) | Should -Match 'Not established: a synthetic component\.'
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'the Markdown report and the remediation playbook show it in control detail and keep it out of the executive summary' {
        Mock -ModuleName 'TenantPosture' -CommandName Get-TPEvidenceLimitMap -MockWith { @{ 'INT-1.1' = @{ NotEstablished = 'a synthetic component'; Reason = 'test' } } }
        Two
        $f = @(Get-TPFindings)
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('tp-limm-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Force -Path $dir | Out-Null
        try {
            Publish-TPAssessmentSummary -Metadata $script:Meta -Findings $f -Connections $script:Conn -OutputPath (Join-Path $dir 'a.md') -ErrorAction Stop | Out-Null
            $md = Get-Content -LiteralPath (Join-Path $dir 'a.md') -Raw
            $md | Should -Match '\*Not established: a synthetic component\.\*'
            @($md -split "`n" | Where-Object { $_ -match 'Not established: a synthetic component' -and $_ -notmatch 'INT-1\.1' }).Count | Should -Be 0 -Because 'the note belongs to INT-1.1 rows only'
            Publish-TPRemediationPlaybook -Metadata $script:Meta -Findings $f -Connections $script:Conn -OutputPath (Join-Path $dir 'p.md') -ExecutivePath (Join-Path $dir 'e.md') -HtmlOutputPath (Join-Path $dir 'p.html') -ErrorAction Stop | Out-Null
            (Get-Content -LiteralPath (Join-Path $dir 'p.md') -Raw)   | Should -Match 'Evidence boundary:\*\* Not established: a synthetic component\.'
            (Get-Content -LiteralPath (Join-Path $dir 'p.html') -Raw) | Should -Match 'Evidence boundary</b> Not established: a synthetic component\.'
            (Get-Content -LiteralPath (Join-Path $dir 'e.md') -Raw)   | Should -Not -Match 'Not established' -Because 'the executive summary stays free of control-level limits'
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; Clear-TPState }
    }

    It 'the detection-limits document explains the lifted boundary and the data file' {
        $doc = Get-Content -LiteralPath (Join-Path $script:Root 'docs/TP-DETECTION-LIMITS.md') -Raw
        $doc | Should -Match 'INT-1\.1 — Device Compliance Policies Configured'
        $doc | Should -Match 'scheduledActionsForRule'
        $doc | Should -Match 'Config/evidence-limits\.json'
        $doc | Should -Not -Match 'INT-1\.1 does not return Satisfied'
    }

    It 'every recorded limit names a real control and a reason (the list may be empty)' {
        $ids = @((Get-Content -LiteralPath (Join-Path $script:Root 'Config/controls.json') -Raw | ConvertFrom-Json).controls | ForEach-Object { $_.ControlId })
        $cfg = Get-Content -LiteralPath (Join-Path $script:Root 'Config/evidence-limits.json') -Raw | ConvertFrom-Json
        $cfg.PSObject.Properties['Limits'] | Should -Not -BeNullOrEmpty
        foreach ($l in @($cfg.Limits)) { $ids | Should -Contain $l.Control; [string]$l.NotEstablished | Should -Not -BeNullOrEmpty; [string]$l.Reason | Should -Not -BeNullOrEmpty }
    }
}

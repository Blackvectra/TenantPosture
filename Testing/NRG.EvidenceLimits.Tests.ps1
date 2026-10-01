#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.EvidenceLimits.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: A control with a component the assessment never establishes (INT-1.1: configured
             non-compliance actions) must never return Satisfied, and every surface that shows
             it must say "Not established: ..." beside it. The documentation must match.
    Data keys consumed: Intune-DeviceCompliance, Intune-EndpointSecurity, Intune-AppProtection.
#>

Describe 'INT-1.1: configured non-compliance actions are not established' {
    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        function script:Raw([string] $Id, [hashtable] $Data) { [ordered]@{ CollectorId = $Id; CollectedAt = '2026-10-01T00:00:00Z'; Success = $true; Data = $Data } }
        function script:Run([hashtable] $Dc) {
            Clear-NRGState
            Set-NRGRawData -Key 'Intune-DeviceCompliance' -Data (Raw 'Intune-DeviceCompliance' $Dc)
            Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (Raw 'Intune-EndpointSecurity' @{ EndpointSecurityPolicies = @(); SectionStatus = @{ EndpointSecurityPolicies = 'Collected' } })
            Set-NRGRawData -Key 'Intune-AppProtection' -Data (Raw 'Intune-AppProtection' @{ AppProtectionPolicies = @(); SectionStatus = @{ AppProtectionPolicies = 'Collected' } })
            & (Get-Module NRG-Assessment) { Test-NRGControlIntune } 3>$null | Out-Null
            @(Get-NRGFindings | Where-Object ControlId -eq 'INT-1.1')[-1]
        }
        $script:Pol = { param($platform, $assigned = $true) @{ Name = "$platform policy"; Platform = $platform; IsAssigned = $assigned } }
    }
    AfterAll { Clear-NRGState }

    It 'is never Satisfied: no policy, unassigned, a platform with no policy, platforms unread, and every platform covered' {
        $base = { param($policies, $platforms)
            $d = @{ SectionStatus = @{ CompliancePolicies = 'Collected'; ConfigurationProfiles = 'Collected'; EnrollmentConfig = 'Collected' }
                    ConfigurationProfiles = @(); EnrollmentConfig = @(); CompliancePolicies = @($policies) }
            if ($null -ne $platforms) { $d.OSComplianceSummary = @{ ByPlatform = $platforms }; $d.SectionStatus.OSComplianceSummary = 'Collected' }
            $d }
        $cases = @(
            @{ Name = 'no policy';                   Dc = (& $base @() @{ Windows = 5 });                                              Expect = 'Gap' }
            @{ Name = 'unassigned only';             Dc = (& $base @((& $script:Pol 'windows10' $false)) @{ Windows = 5 });            Expect = 'Gap' }
            @{ Name = 'a platform has no policy';    Dc = (& $base @((& $script:Pol 'windows10')) @{ Windows = 5; Android = 2 });      Expect = 'Partial' }
            @{ Name = 'platform counts unread';      Dc = (& $base @((& $script:Pol 'windows10')) $null);                              Expect = 'NotApplicable' }
            @{ Name = 'every enrolled platform covered'; Dc = (& $base @((& $script:Pol 'windows10')) @{ Windows = 5 });             Expect = 'NotApplicable' }
        )
        foreach ($c in $cases) {
            $f = Run $c.Dc
            $f | Should -Not -BeNullOrEmpty -Because $c.Name
            $f.State | Should -Be $c.Expect -Because $c.Name
            $f.State | Should -Not -Be 'Satisfied' -Because 'the non-compliance actions are never read'
        }
    }

    It 'the limit is recorded and worded as asked' {
        $n = & (Get-Module NRG-Assessment) { Get-NRGEvidenceLimitNote -ControlId 'INT-1.1' }
        $n | Should -Be 'Not established: configured non-compliance actions.'
        (& (Get-Module NRG-Assessment) { Get-NRGEvidenceLimitNote -ControlId 'AAD-1.1' }) | Should -Be ''
    }

    It 'the main HTML report shows it for INT-1.1 and for no other control' {
        Clear-NRGState
        Add-NRGFinding -ControlId 'INT-1.1' -State 'Gap' -Severity 'High' -Category 'Endpoint' -Title 'Device Compliance Policies Configured' -Detail 'No device compliance policies configured.' -CurrentValue 'none' -RequiredValue 'one' -Remediation 'Create one.'
        Add-NRGFinding -ControlId 'INT-1.2' -State 'Gap' -Severity 'High' -Category 'Endpoint' -Title 'Non-Compliant Device Access Blocked via CA' -Detail 'No policy.' -CurrentValue 'none' -RequiredValue 'one' -Remediation 'Create one.'
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('nrg-lim-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Force -Path $dir | Out-Null
        try {
            Publish-NRGAssessmentHTML -Metadata @{ TenantDomain = 'contoso.example'; TenantId = '00000000-0000-0000-0000-000000000000'; Operator = 'a'; AssessmentDate = 'October 1, 2026'; AssessmentTime = '2026-10-01T00:00:00+00:00'; ToolVersion = '4.14.3'; QuickScan = $false } `
                -Findings (Get-NRGFindings) -Connections @{ Graph = $true; EXO = $true; IPPSSession = $true; Teams = $true; SharePoint = $true } -OutputPath (Join-Path $dir 'r.html') -ClientName 'Contoso' -ErrorAction Stop
            $html = Get-Content -LiteralPath (Join-Path $dir 'r.html') -Raw
            ([regex]::Matches($html, 'Not established: configured non-compliance actions\.')).Count | Should -BeGreaterThan 0
            # INT-1.2 is a different control and must not carry INT-1.1's limit.
            $i = $html.IndexOf('Non-Compliant Device Access Blocked via CA')
            $i | Should -BeGreaterThan 0
            $html.Substring($i, [Math]::Min(400, $html.Length - $i)) | Should -Not -Match 'Not established: configured non-compliance'
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; Clear-NRGState }
    }

    It 'the report site shows it on the INT page' {
        $f = @{ ControlId = 'INT-1.1'; State = 'NotApplicable'; Severity = 'High'; Category = 'Endpoint'; Title = 'Device Compliance Policies Configured'
                Detail = 'Verified: 2 assigned. Not assessed: each policy''s non-compliance action; it is not read.'; CurrentValue = ''; RequiredValue = ''; FrameworkIds = ''; Remediation = '' }
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('nrg-lims-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        try {
            $null = Publish-NRGReportSite -Metadata @{ TenantDomain = 'contoso.example'; ToolVersion = '4.14.3' } -Findings @($f) -OutputPath $dir
            (Get-Content -LiteralPath (Join-Path $dir 'INT.html') -Raw) | Should -Match 'Not established: configured non-compliance actions\.'
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'the detection-limits document carries the INT-1.1 boundary and the data file is documented' {
        $doc = Get-Content -LiteralPath (Join-Path $script:Root 'docs/NRG-DETECTION-LIMITS.md') -Raw
        $doc | Should -Match 'INT-1\.1 — Device Compliance Policies Configured'
        $doc | Should -Match 'does not return Satisfied'
        $doc | Should -Match 'Config/evidence-limits\.json'
    }

    It 'every recorded limit names a real control and a reason' {
        $ids = @((Get-Content -LiteralPath (Join-Path $script:Root 'Config/controls.json') -Raw | ConvertFrom-Json).controls | ForEach-Object { $_.ControlId })
        $cfg = Get-Content -LiteralPath (Join-Path $script:Root 'Config/evidence-limits.json') -Raw | ConvertFrom-Json
        @($cfg.Limits).Count | Should -BeGreaterThan 0
        foreach ($l in @($cfg.Limits)) { $ids | Should -Contain $l.Control; [string]$l.NotEstablished | Should -Not -BeNullOrEmpty; [string]$l.Reason | Should -Not -BeNullOrEmpty }
    }
}

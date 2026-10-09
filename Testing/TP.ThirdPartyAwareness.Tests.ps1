#Requires -Version 7.0
#
# TP.ThirdPartyAwareness.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# A client phishing-tested through a third-party platform (e.g. KnowBe4) read
# as "users are never phishing-tested" on DEF-4.6, or as a Defender for Office
# 365 Plan 2 upgrade it does not need, because Microsoft 365 cannot see the
# platform. -ThirdPartyAwareness / clients.json ThirdPartyAwareness takes the
# check out of the score. The declaration is the assessor's, not evidence, so
# these tests pin that it never becomes a pass.

Describe 'Third-party security awareness declaration' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:Checks = @(& $script:Mod { Get-TPAwarenessCheckIds })

        function script:Add-Finding([string]$Cid, [string]$State, [string]$Detail = 'Microsoft check result') {
            Add-TPFinding -ControlId $Cid -State $State -Category 'Email' -Title "$Cid title" -Severity 'Low' -Detail $Detail
        }
        function script:Get-One([string]$Cid) { @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
    }

    BeforeEach { Clear-TPState }

    It 'covers exactly DEF-4.6, and it is a real control' {
        $script:Checks | Should -Be @('DEF-4.6')
        $tenant = @((Get-Content (Join-Path $script:RepoRoot 'Config/controls.json') -Raw | ConvertFrom-Json).controls | ForEach-Object { $_.ControlId })
        $tenant | Should -Contain 'DEF-4.6'
    }

    It 'takes a failed check out of the score and says it is declared, not verified' {
        Add-Finding 'DEF-4.6' 'Gap' 'No Attack Simulation Training campaigns exist.'
        (Set-TPThirdPartyAwareness -Product 'KnowBe4') | Should -Be 1
        $f = Get-One 'DEF-4.6'
        $f.State        | Should -Be 'NotApplicable'
        $f.Severity     | Should -Be 'Informational'
        $f.Detail       | Should -Match '^Third-party security awareness declared:'
        $f.Detail       | Should -Match 'KnowBe4'
        $f.Detail       | Should -Match 'NOT verified'
        $f.Detail       | Should -Match 'before the declaration: Gap — No Attack Simulation Training campaigns exist\.'
        $f.CurrentValue | Should -Be 'Run on KnowBe4 (declared, not verified)'
        $f.Remediation  | Should -Match 'campaign reports'
    }

    It 'keeps a real pass as evidence and never turns a declaration into a pass' {
        Add-Finding 'DEF-4.6' 'Satisfied' 'Attack Simulation Training is in use.'
        (Set-TPThirdPartyAwareness -Product 'KnowBe4') | Should -Be 0
        (Get-One 'DEF-4.6').State | Should -Be 'Satisfied'
        Clear-TPState
        Add-Finding 'DEF-4.6' 'Partial'
        Set-TPThirdPartyAwareness -Product 'KnowBe4' | Out-Null
        (Get-One 'DEF-4.6').State | Should -Be 'NotApplicable'
        @(Get-TPFindings | Where-Object { $_.Detail -match '^Third-party security awareness declared:' -and $_.State -ne 'NotApplicable' }) | Should -BeNullOrEmpty
    }

    It 'touches only DEF-4.6' {
        Add-Finding 'DEF-4.6' 'Gap'
        Add-Finding 'DEF-4.4' 'Gap'
        Add-Finding 'INT-2.1' 'Gap'
        (Set-TPThirdPartyAwareness -Product 'KnowBe4') | Should -Be 1
        (Get-One 'DEF-4.4').State | Should -Be 'Gap'
        (Get-One 'INT-2.1').State | Should -Be 'Gap'
    }

    It 'is idempotent' {
        Add-Finding 'DEF-4.6' 'Gap' 'No campaigns.'
        Set-TPThirdPartyAwareness -Product 'KnowBe4' | Out-Null
        $once = (Get-One 'DEF-4.6').Detail
        (Set-TPThirdPartyAwareness -Product 'KnowBe4') | Should -Be 0
        (Get-One 'DEF-4.6').Detail | Should -Be $once
    }

    It 'unwraps a license-gated finding so the upgrade marker never survives (-FromResults of an older run)' {
        $gated = 'Not scored: this control requires Defender for Office 365 Plan 2 (M365 E5 or add-on), which this tenant does not hold — surfaced as a licensing upgrade opportunity, not counted against the score. Result before the license check: Gap — No Attack Simulation Training campaigns exist.'
        $loaded = @(@{ ControlId = 'DEF-4.6'; State = 'NotApplicable'; Detail = $gated; Severity = 'Low'; CurrentValue = ''; Remediation = '' })
        (Set-TPThirdPartyAwareness -Product 'KnowBe4' -Findings $loaded) | Should -Be 1
        $loaded[0].State  | Should -Be 'NotApplicable'
        $loaded[0].Detail | Should -Not -Match 'upgrade opportunity' -Because 'the license sections key on that marker and would still pitch Plan 2'
        $loaded[0].Detail | Should -Match 'before the declaration: Gap — No Attack Simulation Training campaigns exist\.$'
    }

    It 'runs before license gating on a live run, so gating leaves it alone' {
        $entry = Get-Content (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $live = $entry.LastIndexOf('Set-TPThirdPartyAwareness -Product $ThirdPartyAwareness')
        $live | Should -BeGreaterThan $entry.IndexOf('Invoke-TPEvaluatorSafe -EvaluatorFunction $ev')
        $live | Should -BeLessThan $entry.LastIndexOf('Set-TPLicenseGating')
        $replay = $entry.IndexOf('Set-TPThirdPartyAwareness -Product $ThirdPartyAwareness -Findings $findings')
        $replay | Should -BeGreaterThan 0
        $replay | Should -BeLessThan $entry.IndexOf('Set-TPLicenseGating -Findings $findings')
    }

    It 'the scope section files it as declared third-party coverage, not a pass, advisory or license gate' {
        Add-Finding 'DEF-4.6' 'Gap'
        Set-TPThirdPartyAwareness -Product 'KnowBe4' | Out-Null
        $s = Get-TPAssessmentScope -Findings @(Get-TPFindings)
        @($s.ThirdPartyAttested | ForEach-Object { $_.ControlId }) | Should -Contain 'DEF-4.6'
        @($s.NoProgrammaticCheck | ForEach-Object { $_.ControlId }) | Should -Not -Contain 'DEF-4.6'
        @($s.LicenceBlocked | ForEach-Object { $_.ControlId }) | Should -Not -Contain 'DEF-4.6'
        ($s.Limitations -join ' ') | Should -Match 'Attack Simulation Training check\(s\) were not scored'
        ($s.Limitations -join ' ') | Should -Match 'declared, not verified'
    }

    It 'leaves the score rather than counting as a pass' {
        Add-Finding 'DEF-4.6' 'Gap'
        Add-Finding 'AAD-1.1' 'Satisfied'
        $before = Get-TPCoverageScore -Findings @(Get-TPFindings)
        Set-TPThirdPartyAwareness -Product 'KnowBe4' | Out-Null
        $after = Get-TPCoverageScore -Findings @(Get-TPFindings)
        $after.Score | Should -BeGreaterThan $before.Score
        @(Get-TPFindings | Where-Object { $_.State -eq 'Satisfied' }).Count | Should -Be 1
    }

    It 'rejects a product name that could inject into the report' {
        { Set-TPThirdPartyAwareness -Product '<script>alert(1)</script>' } | Should -Throw
    }

    It 'the entry point reads it from clients.json and branding.psd1, and records it in the metadata' {
        $entry = Get-Content (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $entry | Should -Match "PSObject\.Properties\['ThirdPartyAwareness'\]"
        $entry | Should -Match "ContainsKey\('AwarenessStack'\)"
        $entry | Should -Match 'ThirdPartyAwareness = \[string\]\$ThirdPartyAwareness'
        (Import-PowerShellDataFile (Join-Path $script:RepoRoot 'Config/branding.psd1')).ContainsKey('AwarenessStack') | Should -BeTrue
        $schema = Get-Content (Join-Path $script:RepoRoot 'Config/schema/clients.schema.json') -Raw | ConvertFrom-Json
        $schema.definitions.client.properties.PSObject.Properties.Name | Should -Contain 'ThirdPartyAwareness'
    }
}

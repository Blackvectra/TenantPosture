#Requires -Version 7.0
#
# TP.ThirdPartyEdr.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# A client protected by a third-party EDR (e.g. Cortex XDR) read as "no
# antivirus policy, no EDR, no attack surface reduction" — a Gap on every
# Microsoft Defender endpoint check — because Microsoft 365 cannot see the
# third-party product. -ThirdPartyEDR / clients.json ThirdPartyEDR takes
# those checks out of the score. The declaration is the assessor's, not
# evidence, so these tests pin that it never becomes a pass.

Describe 'Third-party EDR declaration' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:Checks = @(& $script:Mod { Get-TPDefenderEndpointCheckIds })

        function script:Add-Finding([string]$Cid, [string]$State, [string]$Detail = 'Defender check result') {
            Add-TPFinding -ControlId $Cid -State $State -Category 'Endpoint' -Title "$Cid title" -Severity 'High' -Detail $Detail
        }
        function script:Get-One([string]$Cid) { @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
    }

    BeforeEach { Clear-TPState }

    It 'takes a failed Defender check out of the score and says it is declared, not verified' {
        Add-Finding 'INT-2.1' 'Gap' 'No EDR policy deployed.'
        (Set-TPThirdPartyEdr -Product 'Cortex XDR') | Should -Be 1
        $f = Get-One 'INT-2.1'
        $f.State        | Should -Be 'NotApplicable'
        $f.Detail       | Should -Match '^Third-party EDR declared:'
        $f.Detail       | Should -Match 'Cortex XDR'
        $f.Detail       | Should -Match 'NOT verified'
        $f.Detail       | Should -Match 'before the declaration: Gap — No EDR policy deployed\.'
        $f.CurrentValue | Should -Be 'Covered by Cortex XDR (declared, not verified)'
    }

    It 'never turns a declaration into a pass, and keeps a real pass as evidence' {
        Add-Finding 'INT-2.2' 'Satisfied' 'ASR rules in block mode.'
        Add-Finding 'INT-1.5' 'Partial'
        Add-Finding 'DEV-2.1' 'Error'
        Set-TPThirdPartyEdr -Product 'Cortex XDR' | Out-Null
        (Get-One 'INT-2.2').State | Should -Be 'Satisfied' -Because 'Defender really is configured — that is evidence'
        (Get-One 'INT-1.5').State | Should -Be 'NotApplicable'
        (Get-One 'DEV-2.1').State | Should -Be 'NotApplicable'
        @(Get-TPFindings | Where-Object { $_.Detail -match '^Third-party EDR declared:' -and $_.State -ne 'NotApplicable' }) | Should -BeNullOrEmpty
    }

    It 'does not excuse an assigned ASR policy read as falling short (INT-2.2 Shortfall)' {
        Add-Finding 'INT-2.2' 'Partial' 'Verified: 1 assigned Attack Surface Reduction Rules policy(ies). Shortfall: 1 of 3 required ASR rule(s) are not in Block mode: Block persistence through WMI event subscription (Audit).'
        Add-Finding 'INT-2.1' 'Gap' 'No EDR policy deployed.'
        (Set-TPThirdPartyEdr -Product 'Cortex XDR') | Should -Be 1 -Because 'only the INT-2.1 absence is rewritten'
        $f = Get-One 'INT-2.2'
        $f.State  | Should -Be 'Partial' -Because 'a deployed Defender policy read as misconfigured is evidence, not something a declaration explains'
        $f.Detail | Should -Match '^Verified: ' -Because 'the evaluator verdict leads; the note is appended'
        $f.Detail | Should -Match 'Not excused by the third-party EDR declaration'
        $f.Detail | Should -Match 'Cortex XDR'
        # Idempotent: a second application (for example -FromResults over a rewritten file) adds nothing.
        Set-TPThirdPartyEdr -Product 'Cortex XDR' | Out-Null
        ([regex]::Matches((Get-One 'INT-2.2').Detail, 'Not excused by')).Count | Should -Be 1
    }

    It 'still excuses INT-2.2 when no ASR policy is assigned or the rules were not read' {
        Add-Finding 'INT-2.2' 'Gap' 'No assigned Attack Surface Reduction Rules policy in Intune.'
        Set-TPThirdPartyEdr -Product 'Cortex XDR' | Out-Null
        (Get-One 'INT-2.2').State | Should -Be 'NotApplicable'
    }

    It 'touches only the Defender endpoint checks' {
        Add-Finding 'AAD-1.1' 'Gap'
        Add-Finding 'DEF-1.1' 'Gap' -Detail 'Safe Attachments off.'
        Set-TPThirdPartyEdr -Product 'Cortex XDR' | Out-Null
        (Get-One 'AAD-1.1').State | Should -Be 'Gap'
        (Get-One 'DEF-1.1').State | Should -Be 'Gap' -Because 'Defender for Office 365 protects mail; an endpoint EDR does not replace it'
    }

    It 'excluded checks leave the score and never appear as a license upgrade' {
        Add-Finding 'INT-2.1' 'Gap'
        Add-Finding 'AAD-1.1' 'Satisfied'
        $before = (Get-TPCoverageScore -Findings @(Get-TPFindings)).Score
        Set-TPThirdPartyEdr -Product 'Cortex XDR' | Out-Null
        $after = (Get-TPCoverageScore -Findings @(Get-TPFindings)).Score
        $after | Should -BeGreaterThan $before
        (Get-One 'INT-2.1').Detail | Should -Not -Match 'upgrade opportunity'
    }

    It 'the scope section files them as declared third-party coverage, not as passes or advisory' {
        Add-Finding 'INT-2.1' 'Gap'
        Set-TPThirdPartyEdr -Product 'Cortex XDR' | Out-Null
        $s = Get-TPAssessmentScope -Findings @(Get-TPFindings)
        @($s.ThirdPartyAttested | ForEach-Object { $_.ControlId }) | Should -Contain 'INT-2.1'
        @($s.NoProgrammaticCheck | ForEach-Object { $_.ControlId }) | Should -Not -Contain 'INT-2.1'
        ($s.Limitations -join ' ') | Should -Match 'declared, not verified'
    }

    It 'rewrites findings loaded by -FromResults (hashtables) as well' {
        $loaded = @(@{ ControlId = 'INT-2.1'; State = 'Gap'; Detail = 'x'; Severity = 'High'; CurrentValue = ''; Remediation = '' })
        (Set-TPThirdPartyEdr -Product 'Cortex XDR' -Findings $loaded) | Should -Be 1
        $loaded[0].State | Should -Be 'NotApplicable'
    }

    It 'every check it covers is a real control' {
        $tenant = @((Get-Content (Join-Path $script:RepoRoot 'Config/controls.json') -Raw | ConvertFrom-Json).controls | ForEach-Object { $_.ControlId })
        $devRaw = Get-Content (Join-Path $script:RepoRoot 'Config/device-controls.json') -Raw
        foreach ($id in $script:Checks) {
            (($tenant -contains $id) -or ($devRaw -match [regex]::Escape("`"$id`""))) | Should -BeTrue -Because "$id must exist"
        }
    }

    It 'rejects a product name that could inject into the report' {
        { Set-TPThirdPartyEdr -Product '<script>alert(1)</script>' } | Should -Throw
    }

    It 'the entry point reads ThirdPartyEDR from clients.json and applies it after evaluation' {
        $entry = Get-Content (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $entry | Should -Match "PSObject\.Properties\['ThirdPartyEDR'\]"
        $entry.LastIndexOf('Set-TPThirdPartyEdr -Product $ThirdPartyEDR') | Should -BeGreaterThan $entry.IndexOf('Invoke-TPEvaluatorSafe -EvaluatorFunction $ev')
    }
}

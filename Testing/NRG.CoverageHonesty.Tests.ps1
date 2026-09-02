#Requires -Version 7.0
#
# NRG.CoverageHonesty.Tests.ps1
#
# The coverage honesty-gate. Machine-verifies the tool's own automation claim:
# every control that says Automated = $true in controls.json must be PROVEN (by
# AST inspection, via Get-NRGControlAutomationAudit) to produce both a pass and a
# fail from tenant data — or be explicitly listed in Config/coverage-exceptions.psd1
# with a reason. This is what makes "202 automated controls" a defensible,
# self-maintaining claim instead of a marketing number. No other M365 assessment
# tool gates its own coverage this way.

Describe 'Coverage honesty gate' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        $script:Audit = @(Get-NRGControlAutomationAudit)

        $exPath = Join-Path $script:RepoRoot 'Config/coverage-exceptions.psd1'
        $script:ExceptionData = if (Test-Path -LiteralPath $exPath) { Import-PowerShellDataFile -LiteralPath $exPath } else { @{ Exceptions = @() } }
        $script:ExMap = @{}
        foreach ($e in @($script:ExceptionData.Exceptions)) { $script:ExMap[[string]$e.ControlId] = $e }
    }

    It 'audits all 202 controls' {
        $script:Audit.Count | Should -Be 202
    }

    It 'every Automated=true control either discriminates or is a documented exception' {
        $offenders = @($script:Audit | Where-Object {
            $_.Automated -and -not $_.Discriminates -and -not $script:ExMap.ContainsKey($_.ControlId)
        } | ForEach-Object { "$($_.ControlId) [$($_.Class)] via $($_.Evaluator)" })
        ($offenders -join "`n") | Should -BeNullOrEmpty -Because 'a control claiming Automated=true must be proven to discriminate pass/fail, or be listed in Config/coverage-exceptions.psd1 with a reason'
    }

    It 'has no stale exceptions (a listed control that now discriminates must be removed)' {
        $auditById = @{}
        foreach ($r in $script:Audit) { $auditById[$r.ControlId] = $r }
        $stale = @($script:ExMap.Keys | Where-Object {
            $auditById.ContainsKey($_) -and $auditById[$_].Discriminates
        })
        ($stale -join ', ') | Should -BeNullOrEmpty -Because 'once a control genuinely discriminates it must be deleted from coverage-exceptions.psd1 so the debt list stays honest'
    }

    It 'every exception has a valid Kind and a non-empty Reason' {
        $bad = @(@($script:ExceptionData.Exceptions) | Where-Object {
            [string]::IsNullOrWhiteSpace($_.ControlId) -or
            $_.Kind -notin @('Manual','ImplementationPending') -or
            [string]::IsNullOrWhiteSpace($_.Reason)
        } | ForEach-Object { [string]$_.ControlId })
        ($bad -join ', ') | Should -BeNullOrEmpty -Because 'every exception must document ControlId + Kind (Manual|ImplementationPending) + Reason'
    }

    It 'every exception ControlId is a real control' {
        $known = @{}
        foreach ($r in $script:Audit) { $known[$r.ControlId] = $true }
        $ghosts = @($script:ExMap.Keys | Where-Object { -not $known.ContainsKey($_) })
        ($ghosts -join ', ') | Should -BeNullOrEmpty -Because 'coverage-exceptions.psd1 must not reference control IDs that no longer exist'
    }

    It 'reports the genuinely-automated coverage ratio (informational)' {
        $disc = @($script:Audit | Where-Object Discriminates).Count
        Write-Host ("    Coverage: {0}/{1} controls genuinely discriminate pass/fail ({2}%)." -f $disc, $script:Audit.Count, [int]($disc * 100 / $script:Audit.Count))
        $disc | Should -BeGreaterThan 150
    }
}

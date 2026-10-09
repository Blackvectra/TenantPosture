#Requires -Version 7.0
#
# TP.EvaluatorResilience.Tests.ps1
#
# The ScubaGear-grade guarantee: an assessment ALWAYS emits a finding for every
# control, and no evaluator bug can crash the run or silently drop a control —
# even on the sparsest/most-partial tenant data.
#
# History: a fuzz sweep of all 172 evaluators against empty collector data
# surfaced 69 that threw 'The property X cannot be found on this object' on
# partial data. In a real run those throws were swallowed by the invocation
# wrapper and the affected controls just DISAPPEARED from the report — the
# operator saw fewer findings with no indication anything failed. This suite
# feeds every evaluator empty ("collected but no sub-data") and missing ("not
# collected at all") data through Invoke-TPEvaluatorSafe and asserts that
# EVERY control still receives a finding.

Describe 'Evaluator resilience — no control silently vanishes' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        $script:Controls  = @(Get-TPControlDefinitions)
        $script:AutomatedControlIds = @($script:Controls |
            Where-Object { $_.Automated -ne $false } |
            ForEach-Object { [string]$_.ControlId })
        $script:Evaluators = @(Get-Command -Name 'Test-TPControl*' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Name)
        # Every raw-data key any control depends on (CollectorDependency may be a
        # comma-separated list).
        $script:RawKeys = @($script:Controls |
            ForEach-Object { $_.CollectorDependency -split '[,\s]+' } |
            Where-Object { $_ -match '^[A-Z][A-Za-z0-9\-]+$' } |
            Sort-Object -Unique)

        function Invoke-AllEvaluators {
            param([ValidateSet('empty','missing')] [string] $Mode)
            Clear-TPState
            if ($Mode -eq 'empty') {
                foreach ($k in $script:RawKeys) {
                    Set-TPRawData -Key $k -Data @{ Success = $true; Data = @{} }
                }
            }
            foreach ($fn in $script:Evaluators) {
                Invoke-TPEvaluatorSafe -EvaluatorFunction $fn
            }
            @(Get-TPFindings)
        }
    }

    It 'the safe wrapper is exported and callable' {
        Get-Command Invoke-TPEvaluatorSafe -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'every automated control gets a finding when collectors returned EMPTY data' {
        $findings = Invoke-AllEvaluators -Mode 'empty'
        $covered  = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@($findings | ForEach-Object { [string]$_.ControlId }),
            [System.StringComparer]::OrdinalIgnoreCase)
        $missing  = @($script:AutomatedControlIds | Where-Object { -not $covered.Contains($_) })
        $missing -join ', ' | Should -BeNullOrEmpty -Because 'a control with no finding on empty data means an evaluator threw and the control silently vanished from the report'
    }

    It 'every automated control gets a finding when NOTHING was collected' {
        $findings = Invoke-AllEvaluators -Mode 'missing'
        $covered  = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@($findings | ForEach-Object { [string]$_.ControlId }),
            [System.StringComparer]::OrdinalIgnoreCase)
        $missing  = @($script:AutomatedControlIds | Where-Object { -not $covered.Contains($_) })
        $missing -join ', ' | Should -BeNullOrEmpty -Because 'even with zero collected data, every control must resolve to NotApplicable/Error — never disappear'
    }

    It 'no evaluator escapes the safe wrapper with an unhandled throw (empty data)' {
        # Invoke-TPEvaluatorSafe must swallow every evaluator error; if any
        # escapes, this whole test errors rather than fails — so assert the
        # invocation completes and produced findings.
        { Invoke-AllEvaluators -Mode 'empty' } | Should -Not -Throw
    }
}

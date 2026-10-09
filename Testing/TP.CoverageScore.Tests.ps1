#Requires -Version 7.0
#
# TP.CoverageScore.Tests.ps1
#
# Pins behavior of Lib/Get-TPCoverageScore.ps1 — the canonical
# coverage-score helper extracted in v4.10.1. Before extraction, this
# formula lived in 5+ places with 3 distinct denominator rules; the
# helper consolidates them via -ErrorHandling. These tests pin both
# variants plus the -Workload / -FrameworkId filters and the rounding
# rule at half-integer boundaries.

Describe 'Get-TPCoverageScore' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Get-TPObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-TPCoverageScore.ps1')
    }

    Context 'Basic state counting' {
        It 'Returns all zeros for empty array, no throw' {
            $cov = Get-TPCoverageScore -Findings @()
            $cov.Score     | Should -Be 0
            $cov.Scored    | Should -Be 0
            $cov.Total     | Should -Be 0
            $cov.Satisfied | Should -Be 0
        }

        It 'Returns all zeros for $null Findings, no throw' {
            $cov = Get-TPCoverageScore -Findings $null
            $cov.Score | Should -Be 0
            $cov.Total | Should -Be 0
        }

        It 'Counts Satisfied / Partial / Gap / NA / Error / Unknown' {
            $f = @(
                @{State='Satisfied'},
                @{State='Satisfied'},
                @{State='Partial'},
                @{State='Gap'},
                @{State='NotApplicable'},
                @{State='Error'},
                @{State='SomeWeirdState'}
            )
            $cov = Get-TPCoverageScore -Findings $f
            $cov.Satisfied | Should -Be 2
            $cov.Partial   | Should -Be 1
            $cov.Gap       | Should -Be 1
            $cov.NA        | Should -Be 1
            $cov.Error     | Should -Be 1
            $cov.Unknown   | Should -Be 1
            $cov.Total     | Should -Be 7
        }

        It 'Skips $null entries in the array' {
            [object[]] $f = @(
                @{State='Satisfied'}
                $null
                @{State='Satisfied'}
                $null
                @{State='Gap'}
            )
            $cov = Get-TPCoverageScore -Findings $f
            $cov.Total | Should -Be 3
            $cov.Scored | Should -Be 3
        }
    }

    Context '-ErrorHandling Exclude (default — Maturity semantics)' {
        It 'Excludes Error from the denominator' {
            $f = @(
                @{State='Satisfied'},
                @{State='Error'}
            )
            $cov = Get-TPCoverageScore -Findings $f
            $cov.Scored | Should -Be 1
            $cov.Score  | Should -Be 100
        }

        It 'Excludes Unknown from the denominator (typo-resistant)' {
            $f = @(
                @{State='Satisfied'},
                @{State='Satisifed'}    # typo
            )
            $cov = Get-TPCoverageScore -Findings $f
            $cov.Scored  | Should -Be 1
            $cov.Score   | Should -Be 100
            $cov.Unknown | Should -Be 1
        }

        It 'Excludes NotApplicable from the denominator' {
            $f = @(
                @{State='Satisfied'},
                @{State='NotApplicable'}
            )
            $cov = Get-TPCoverageScore -Findings $f
            $cov.Scored | Should -Be 1
            $cov.Score  | Should -Be 100
        }
    }

    Context '-ErrorHandling Gap (publisher semantics)' {
        It 'Counts Error in the denominator' {
            $f = @(
                @{State='Satisfied'},
                @{State='Error'}
            )
            $cov = Get-TPCoverageScore -Findings $f -ErrorHandling 'Gap'
            $cov.Scored | Should -Be 2
            $cov.Score  | Should -Be 50
        }

        It 'Still excludes Unknown from the denominator' {
            $f = @(
                @{State='Satisfied'},
                @{State='Error'},
                @{State='Garbage'}
            )
            $cov = Get-TPCoverageScore -Findings $f -ErrorHandling 'Gap'
            $cov.Scored  | Should -Be 2
            $cov.Unknown | Should -Be 1
        }
    }

    Context 'Score formula precision' {
        It 'Counts Partial as half' {
            $f = @(
                @{State='Partial'},
                @{State='Partial'}
            )
            $cov = Get-TPCoverageScore -Findings $f
            $cov.Score | Should -Be 50
        }

        It 'Returns 0 score when Scored is 0' {
            $f = @(@{State='NotApplicable'})
            $cov = Get-TPCoverageScore -Findings $f
            $cov.Score  | Should -Be 0
            $cov.Scored | Should -Be 0
        }

        It 'Uses Math.Round (banker''s rounding) — 1 Sat + 1 Partial out of 2 = 75' {
            # (1 + 0.5*1) / 2 * 100 = 75 exactly — Round of 75 = 75
            $f = @(
                @{State='Satisfied'},
                @{State='Partial'}
            )
            (Get-TPCoverageScore -Findings $f).Score | Should -Be 75
        }
    }

    Context '-Workload filter' {
        It 'Counts only findings whose ControlId begins with the workload prefix' {
            $f = @(
                @{ControlId='AAD-1.1'; State='Satisfied'},
                @{ControlId='AAD-2.1'; State='Gap'},
                @{ControlId='EXO-1.1'; State='Satisfied'}
            )
            $cov = Get-TPCoverageScore -Findings $f -Workload 'AAD'
            $cov.Total     | Should -Be 2
            $cov.Satisfied | Should -Be 1
            $cov.Gap       | Should -Be 1
            $cov.Score     | Should -Be 50
        }

        It 'Skips findings without ControlId (cannot prefix-match)' {
            $f = @(
                @{State='Satisfied'},               # no ControlId
                @{ControlId='AAD-1.1'; State='Satisfied'}
            )
            $cov = Get-TPCoverageScore -Findings $f -Workload 'AAD'
            $cov.Total | Should -Be 1
        }
    }

    Context '-FrameworkId filter' {
        It 'Counts only findings whose FrameworkIds match the framework prefix' {
            $f = @(
                @{State='Satisfied'; FrameworkIds=@('CIS-1.1.1','NIST-IA-2')},
                @{State='Gap';       FrameworkIds=@('CIS-1.2.3')},
                @{State='Satisfied'; FrameworkIds=@('SCuBA-AAD-1')}
            )
            $cov = Get-TPCoverageScore -Findings $f -FrameworkId 'CIS'
            $cov.Total     | Should -Be 2
            $cov.Satisfied | Should -Be 1
            $cov.Gap       | Should -Be 1
        }

        It 'Skips findings without FrameworkIds (cannot match) without throwing under StrictMode' {
            Set-StrictMode -Version Latest
            $f = @(
                @{State='Satisfied'},                                              # no FrameworkIds
                @{State='Satisfied'; FrameworkIds=@('CIS-1.1')}
            )
            { Get-TPCoverageScore -Findings $f -FrameworkId 'CIS' } | Should -Not -Throw
            (Get-TPCoverageScore -Findings $f -FrameworkId 'CIS').Total | Should -Be 1
        }
    }

    Context 'PSCustomObject inputs (-FromResults / Delta baseline shape)' {
        It 'Handles PSCustomObject findings (e.g., from ConvertFrom-Json)' {
            $f = @(
                [pscustomobject]@{ State='Satisfied'; Severity='Medium' },
                [pscustomobject]@{ State='Gap';       Severity='Critical' }
            )
            $cov = Get-TPCoverageScore -Findings $f
            $cov.Total | Should -Be 2
            $cov.Score | Should -Be 50
        }
    }

    Context 'Output shape' {
        It 'Returns all 9 documented keys' {
            $required = @('Satisfied','Partial','Gap','NA','Error','Unknown','Total','Scored','Score')
            $cov = Get-TPCoverageScore -Findings @()
            foreach ($k in $required) {
                $cov.Contains($k) | Should -BeTrue -Because "Get-TPCoverageScore must expose '$k'"
            }
        }

        It 'Returns an ordered dictionary' {
            $cov = Get-TPCoverageScore -Findings @()
            $cov | Should -BeOfType ([System.Collections.Specialized.OrderedDictionary])
        }
    }
}

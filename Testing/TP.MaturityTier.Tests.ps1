#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
<#
.SYNOPSIS
    Pester tests for Get-TPMaturityTier. Pins the 5-tier classification
    (Initial / Developing / Defined / Managed / Optimizing) and the score
    formula so the maturity badge can never disagree with the score ring
    in the HTML report.
#>

Describe 'TenantPosture Maturity Tier Classification' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }
        # v4.10.1: Get-TPMaturityTier now depends on Get-TPObjectField and
        # Get-TPCoverageScore (extracted helpers). Load order matters —
        # Maturity dot-sources the others at call time so they must be in
        # scope first.
        . (Join-Path $script:RepoRoot 'Lib' 'Get-TPObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-TPCoverageScore.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-TPMaturityTier.ps1')
    }

    Context 'Tier 5 — Optimizing' {

        It 'Returns Optimizing when score >= 90, no Critical, no High gaps' {
            $f = 1..10 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $m = Get-TPMaturityTier -Findings $f
            $m.Tier  | Should -Be 5
            $m.Label | Should -Be 'Optimizing'
            $m.Score | Should -BeGreaterOrEqual 90
        }

        It 'Falls out of Optimizing if even one High gap is present' {
            $f = @()
            $f += 1..9 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += @{ State = 'Gap'; Severity = 'High' }
            $m = Get-TPMaturityTier -Findings $f
            $m.Tier | Should -BeLessThan 5
        }
    }

    Context 'Tier 4 — Managed' {

        It 'Returns Managed when score >= 75, no Critical, <= 3 High gaps' {
            $f = @()
            $f += 1..8 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += 1..2 | ForEach-Object { @{ State = 'Gap';       Severity = 'High'   } }
            $m = Get-TPMaturityTier -Findings $f
            $m.Tier  | Should -Be 4
            $m.Label | Should -Be 'Managed'
        }
    }

    Context 'Tier 3 — Defined' {

        It 'Returns Defined when score >= 60 and no Critical gaps' {
            $f = @()
            $f += 1..7 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += 1..3 | ForEach-Object { @{ State = 'Gap';       Severity = 'High'   } }
            $m = Get-TPMaturityTier -Findings $f
            $m.Tier         | Should -Be 3
            $m.Label        | Should -Be 'Defined'
            $m.CriticalGaps | Should -Be 0
        }

        It 'Drops to Developing when a Critical gap appears at the same score' {
            $f = @()
            $f += 1..6 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += @{ State = 'Gap'; Severity = 'Critical' }
            $f += 1..3 | ForEach-Object { @{ State = 'Gap';       Severity = 'High'   } }
            $m = Get-TPMaturityTier -Findings $f
            $m.Tier  | Should -BeLessOrEqual 2
        }
    }

    Context 'Tier 2 — Developing' {

        It 'Returns Developing when score >= 40 and <= 5 Critical' {
            $f = @()
            $f += 1..4 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += @{ State = 'Gap'; Severity = 'Critical' }
            $f += 1..5 | ForEach-Object { @{ State = 'Gap';       Severity = 'High'   } }
            $m = Get-TPMaturityTier -Findings $f
            $m.Tier  | Should -Be 2
            $m.Label | Should -Be 'Developing'
        }
    }

    Context 'Tier 1 — Initial' {

        It 'Returns Initial for low coverage' {
            $f = @()
            $f += @{ State = 'Satisfied'; Severity = 'Medium' }
            $f += 1..9 | ForEach-Object { @{ State = 'Gap'; Severity = 'High' } }
            $m = Get-TPMaturityTier -Findings $f
            $m.Tier  | Should -Be 1
            $m.Label | Should -Be 'Initial'
        }

        It 'Returns Initial when many Critical gaps are present' {
            $f = @()
            $f += 1..3 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += 1..6 | ForEach-Object { @{ State = 'Gap';       Severity = 'Critical' } }
            $m = Get-TPMaturityTier -Findings $f
            $m.Tier  | Should -Be 1
        }
    }

    Context 'Score formula' {

        It 'Excludes NotApplicable from scored controls' {
            $f = @()
            $f += @{ State = 'Satisfied';     Severity = 'Medium' }
            $f += @{ State = 'NotApplicable'; Severity = 'Medium' }
            $f += @{ State = 'NotApplicable'; Severity = 'Medium' }
            $m = Get-TPMaturityTier -Findings $f
            $m.ScoredControls | Should -Be 1
            $m.Score          | Should -Be 100
        }

        It 'Counts Partial as half-credit (matches HTML publisher)' {
            $f = @()
            $f += @{ State = 'Satisfied'; Severity = 'Medium' }
            $f += @{ State = 'Partial';   Severity = 'Medium' }
            $m = Get-TPMaturityTier -Findings $f
            $m.Score | Should -Be 75
        }

        It 'Returns score 0 when every finding is NotApplicable' {
            $f = 1..3 | ForEach-Object { @{ State = 'NotApplicable'; Severity = 'Medium' } }
            $m = Get-TPMaturityTier -Findings $f
            $m.Score          | Should -Be 0
            $m.ScoredControls | Should -Be 0
        }
    }

    Context 'Output shape' {

        It 'Emits an ordered hashtable with all required keys' {
            $f = @(@{ State = 'Satisfied'; Severity = 'Medium' })
            $m = Get-TPMaturityTier -Findings $f
            $required = @('Tier','Label','Score','CriticalGaps','HighGaps','ScoredControls','ErrorFindings','UnknownStates','Description','Satisfied','Partial','Gap','NotApplicable','Total')
            foreach ($k in $required) {
                $m.Contains($k) | Should -BeTrue -Because "key '$k' must exist"
            }
        }

        It 'Tier is always between 1 and 5' {
            $f = @(@{ State = 'Satisfied'; Severity = 'Medium' })
            $m = Get-TPMaturityTier -Findings $f
            $m.Tier | Should -BeGreaterOrEqual 1
            $m.Tier | Should -BeLessOrEqual 5
        }

        It 'Includes ErrorFindings count in the result' {
            $f = @(@{ State = 'Error'; Severity = 'High' })
            $m = Get-TPMaturityTier -Findings $f
            $m.Contains('ErrorFindings') | Should -BeTrue
            $m.ErrorFindings              | Should -Be 1
        }
    }

    Context 'Defensive input handling (post-code-review hardening)' {

        It 'Accepts an empty findings array without throwing a binding error' {
            { Get-TPMaturityTier -Findings @() } | Should -Not -Throw
            $m = Get-TPMaturityTier -Findings @()
            $m.Score          | Should -Be 0
            $m.ScoredControls | Should -Be 0
            $m.Tier           | Should -Be 1
        }

        It 'Excludes State=Error from the score denominator (collector hiccups do not deflate score)' {
            $f = @()
            $f += 1..50 | ForEach-Object { @{ State = 'Satisfied'; Severity = 'Medium' } }
            $f += 1..50 | ForEach-Object { @{ State = 'Error';     Severity = 'High'   } }
            $m = Get-TPMaturityTier -Findings $f
            # Old behavior: scored=100, sat=50, score=50 — deflated to Developing.
            # New: Error excluded → scored=50, sat=50, score=100 → Optimizing.
            $m.Score          | Should -Be 100
            $m.ScoredControls | Should -Be 50
            $m.ErrorFindings  | Should -Be 50
            $m.Tier           | Should -Be 5
        }

        It 'Handles PSCustomObject findings (FromResults / ConvertFrom-Json shape)' {
            $f = @(
                [pscustomobject]@{ State = 'Satisfied'; Severity = 'Critical' }
                [pscustomobject]@{ State = 'Gap';       Severity = 'High'     }
            )
            { Get-TPMaturityTier -Findings $f } | Should -Not -Throw
            $m = Get-TPMaturityTier -Findings $f
            $m.HighGaps       | Should -Be 1
            $m.ScoredControls | Should -Be 2
        }

        It 'Survives findings missing State or Severity properties under StrictMode' {
            $f = @(
                @{ Foo = 'bar' }                                      # no State at all (hashtable)
                @{ State = 'Satisfied' }                              # no Severity
                [pscustomobject]@{ NotState = 'x' }                   # no State at all (PSCO)
                [pscustomobject]@{ State = 'Gap'; Severity = 'High' } # well-formed
            )
            { Get-TPMaturityTier -Findings $f } | Should -Not -Throw
            $m = Get-TPMaturityTier -Findings $f
            $m.HighGaps | Should -Be 1
        }

        It 'Skips $null entries in the findings array without throwing' {
            # The earlier version of this test contained no $null entries —
            # it would have passed even if the null-skip guard had been
            # deleted. This version uses a Where-Object workaround so the
            # literal $null actually lands in the array under PS7 (a bare
            # @($a, $null, $b) sometimes elides the null via parameter
            # binding rules — wrapping with [object[]] is the canonical fix).
            [object[]] $f = @(
                @{ State = 'Satisfied'; Severity = 'Medium' }
                $null
                @{ State = 'Satisfied'; Severity = 'Medium' }
                $null
                @{ State = 'Gap';       Severity = 'Critical' }
            )
            { Get-TPMaturityTier -Findings $f } | Should -Not -Throw
            $m = Get-TPMaturityTier -Findings $f
            # ScoredControls must reflect only the 3 non-null entries
            # (the prior $Findings.Count math would have given 5, deflating
            # the score by 40% silently on dirty -FromResults baselines).
            $m.ScoredControls | Should -Be 3
            $m.CriticalGaps   | Should -Be 1
        }

        It 'Excludes unknown State values from the denominator (typo-resistant)' {
            # If a future evaluator emits State='Satisifed' (typo) it must
            # NOT silently inflate the denominator the way the prior switch
            # did. The default arm tracks Unknown via UnknownStates.
            [object[]] $f = @(
                @{ State = 'Satisfied';  Severity = 'Medium' }
                @{ State = 'Satisifed';  Severity = 'Medium' }  # typo
                @{ State = 'Pending';    Severity = 'Medium' }  # future state
            )
            $m = Get-TPMaturityTier -Findings $f
            $m.ScoredControls | Should -Be 1
            $m.Score          | Should -Be 100
            $m.UnknownStates  | Should -Be 2
        }
    }
}

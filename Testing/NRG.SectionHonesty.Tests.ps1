#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
#
# NRG.SectionHonesty.Tests.ps1
#
# The second anti-false-PASS guard, and the one that was missing.
#
# NRG.EvaluatorHonesty.Tests.ps1 already proves no evaluator reports a pass when
# its collector NEVER RAN — raw data absent entirely. Every evaluator opens with
# `if (-not $x -or -not $x.Success) { NotApplicable; return }`, so that case was
# always covered.
#
# It is not the case that actually happens. A collector runs several independent
# queries, wraps each in its own try/catch so one failure does not abort the
# rest, and then sets Success = $true because the COLLECTOR completed. One
# throttled or unpermitted sub-query later, the envelope says Success and the
# section inside is empty — and Success cannot tell an evaluator which.
#
# That is the state this suite feeds in: every raw-data key present, every
# collector reporting success, every Data block empty. Nothing there is evidence
# of anything, so no control may claim compliance from it.
#
# It found 50 of 195 doing exactly that. A tenant where every collector returned
# empty-but-successful scored 51% overall and 49% NIST — a client handed a
# report showing half their controls green, backed by nothing. Among them:
# TMS-2.3 reporting third-party cloud storage disabled when the Teams client
# configuration query had failed, and the Intune controls reporting "1
# compliance policies active" because @($null).Count is 1, not 0.
#
# Two rules, both enforced below:
#   1. No Satisfied and no Partial on empty-but-successful data.
#   2. The resulting score is 0. Partial is worth 0.5, so a suite that only
#      checked for Satisfied would let 29 Partials quietly rebuild half a score.

Describe 'No control claims compliance from a section that was never collected' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        # Every raw-data key any collector sets, taken from the Set-NRGRawData
        # calls so the fixture cannot drift from the implementation.
        $script:Keys = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($f in (Get-ChildItem (Join-Path $script:RepoRoot 'Collectors') -Filter *.ps1 -Recurse -File)) {
            foreach ($m in [regex]::Matches((Get-Content -LiteralPath $f.FullName -Raw), "Set-NRGRawData\s+-Key\s+'([^']+)'")) {
                $null = $script:Keys.Add($m.Groups[1].Value)
            }
        }

        # Build the fixture from the REAL collectors with every Graph call
        # failing (issue #89): each collector leaves exactly the shape it leaves
        # in production when its sub-queries fail - pre-initialised sections,
        # SectionStatus = Failed - rather than a hand-made Data = @{} no
        # collector ever produces (47 evaluators threw on that shape, which hid
        # the two that genuinely mishandled the real one). EXO/Teams/SCC
        # cmdlets are simply absent here, so their sub-queries fail the same
        # way. Then force every envelope to Success = $true: the case this
        # suite exists for is "collector completed, sections empty".
        $mod = Get-Module 'NRG-Assessment'
        & $mod { Set-Item -Path 'function:script:Invoke-NRGGraphRequest' -Value {
            param([Parameter(ValueFromRemainingArguments)] $rest) throw 'Simulated: Graph 503 Service Unavailable' } }
        Clear-NRGState
        $collectors = @(Get-Command -Module 'NRG-Assessment' -Name 'Invoke-NRGCollect*' | Where-Object {
            -not ($_.Parameters.Values | Where-Object { $_.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory } })
        })
        foreach ($c in $collectors) { try { & $c.Name *>$null } catch { } }
        & $mod { Remove-Item -Path 'function:script:Invoke-NRGGraphRequest' -ErrorAction SilentlyContinue }
        foreach ($k in $script:Keys) {
            $raw = Get-NRGRawData -Key $k
            if (-not $raw) { $raw = @{ CollectorId = $k; CollectedAt = (Get-Date); Data = @{} } }
            # Keep a collector's own Success = $false: collectors whose Success
            # tracks their primary query (AAD-CAPolicies) report failure in
            # production too, and overriding that would fabricate a "zero
            # policies" tenant rather than a failed read. Everything else gets
            # the completed-but-empty envelope this suite is about.
            if ($raw -is [System.Collections.IDictionary] -and $raw.Contains('Success') -and $raw['Success'] -eq $false) { continue }
            $raw['Success'] = $true
            Set-NRGRawData -Key $k -Data $raw
        }

        $script:Controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 | ConvertFrom-Json).controls)
        # An evaluator that throws against this fixture produces no finding at
        # all and is silently absent from every assertion below - a swallowed
        # catch would let that masquerade as "nothing to assess". Record it
        # instead so the suite fails loudly on the mismatch.
        $script:EvaluatorErrors = [System.Collections.Generic.List[string]]::new()
        foreach ($c in $script:Controls) {
            if (Get-Command $c.EvaluatorFunction -ErrorAction SilentlyContinue) {
                try { & $c.EvaluatorFunction -ErrorAction SilentlyContinue *>$null }
                catch { $script:EvaluatorErrors.Add("$($c.ControlId) ($($c.EvaluatorFunction)): $($_.Exception.Message)") }
            }
        }
        $script:Findings = @(Get-NRGFindings)
        $script:Claims   = @($script:Findings | Where-Object { $_.State -in @('Satisfied', 'Partial') } |
                             Sort-Object ControlId -Unique)
    }

    AfterAll { Clear-NRGState }

    It 'seeded every collector key, so the fixture actually exercises the evaluators' {
        $script:Keys.Count  | Should -BeGreaterThan 15
        $script:Findings.Count | Should -BeGreaterThan 100
    }

    It 'runs every evaluator against the fixture without throwing' {
        # A thrown exception produces no finding, so it is invisible to every
        # other assertion in this Describe block - a swallowed throw would let
        # an evaluator that never actually ran against this fixture pass as
        # "claims nothing". Note this fixture's empty sections are Data = @{}
        # (absent keys), not the pre-initialised @() shape real collectors
        # leave behind, so an evaluator that throws here may still be honest
        # against the real collector output; that fixture-realism gap is
        # tracked separately and is not what this assertion checks.
        $names = $script:EvaluatorErrors -join '; '
        $script:EvaluatorErrors.Count | Should -Be 0 -Because "these evaluators threw instead of emitting a verdict: $names"
    }

    It 'has no control reporting Satisfied or Partial on empty-but-successful data' {
        $names = ($script:Claims | ForEach-Object { "$($_.ControlId) [$($_.State)]" }) -join ', '
        $script:Claims.Count | Should -Be 0 -Because "these controls claim compliance from nothing: $names"
    }

    It 'scores 0 on empty-but-successful data' {
        # Partial is worth 0.5. Checking only for Satisfied would let a wall of
        # Partials rebuild half a score out of no evidence at all.
        $uniq = $script:Findings | Sort-Object ControlId -Unique
        (Get-NRGCoverageScore -Findings $uniq -ErrorHandling 'Gap').Score | Should -Be 0
        (Get-NRGCoverageScore -Findings $uniq -FrameworkId 'NIST' -ErrorHandling 'Gap').Score | Should -Be 0
    }

    It 'answers NotApplicable rather than throwing' {
        # A throw produces no finding, so it cannot be a false pass — but it
        # aborts every remaining control in the same evaluator file, which
        # silently shrinks the assessment. NotApplicable is the honest verdict
        # and the one that keeps the run intact.
        @($script:Findings | Where-Object { $_.State -eq 'NotApplicable' }).Count |
            Should -BeGreaterThan 100
    }
}

Describe 'Test-NRGSectionCollected' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }

    It 'trusts an explicit Collected status' {
        Test-NRGSectionCollected @{ Success = $true; Data = @{ SectionStatus = @{ A = 'Collected' }; A = @() } } 'A' | Should -BeTrue
    }

    It 'refuses Failed and NotRun even when the section holds data' {
        # The status is the contract and it outranks whatever happens to be in
        # the section — a half-populated list from a query that then threw is
        # not evidence.
        Test-NRGSectionCollected @{ Success = $true; Data = @{ SectionStatus = @{ A = 'Failed' }; A = @(1,2) } } 'A' | Should -BeFalse
        Test-NRGSectionCollected @{ Success = $true; Data = @{ SectionStatus = @{ A = 'NotRun' }; A = @(1,2) } } 'A' | Should -BeFalse
    }

    It 'accepts an empty section that the collector says it collected' {
        # "Queried, this tenant has none" is a real and compliant answer. The
        # whole point of the status is to let that count.
        Test-NRGSectionCollected @{ Success = $true; Data = @{ SectionStatus = @{ A = 'Collected' }; A = @() } } 'A' | Should -BeTrue
    }

    It 'falls back to presence when the collector publishes no status' {
        Test-NRGSectionCollected @{ Success = $true; Data = @{ A = @(1) } }    'A' | Should -BeTrue
        Test-NRGSectionCollected @{ Success = $true; Data = @{ A = $null } }   'A' | Should -BeFalse
        Test-NRGSectionCollected @{ Success = $true; Data = @{} }              'A' | Should -BeFalse
    }

    It 'refuses a failed or absent envelope outright' {
        Test-NRGSectionCollected @{ Success = $false; Data = @{ A = @(1) } } 'A' | Should -BeFalse
        Test-NRGSectionCollected $null 'A' | Should -BeFalse
    }

    It 'never throws on a malformed envelope' {
        # Replayed result JSON from an older version is the normal source of
        # shapes this was not written for. Under StrictMode a bare dot-access
        # would throw and take the whole evaluator with it.
        { Test-NRGSectionCollected @{ Success = $true } 'A' }        | Should -Not -Throw
        { Test-NRGSectionCollected 'not-an-envelope' 'A' }           | Should -Not -Throw
        { Test-NRGSectionCollected ([pscustomobject]@{}) 'A' }       | Should -Not -Throw
    }
}

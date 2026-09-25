#Requires -Version 7.0
#
# NRG.ImprovementPlan.Tests.ps1
#
# Guards Lib/Get-NRGNISTImprovementPlan.ps1 and
# Publishers/Publish-NRGImprovementPlan.ps1 — the document that says what to do
# next and how much NIST coverage it returns.
#
# This one carries a number a client will hold us to. "Do these six things and
# you go from 61% to 78%" is a commitment, so the arithmetic behind it has to
# be exact rather than approximately right, and the things it will not commit
# to have to stay uncommitted:
#
#   1. The projection is recomputed from counts, never accumulated from
#      rounded per-step deltas. A test walks the plan and re-derives every
#      cumulative figure from the baseline independently.
#
#   2. A license-blocked control never gets a projected score, and never lands
#      in a track that implies it can be actioned. Buying a license changes the
#      denominator and a licensed-but-unconfigured control is still a gap.
#
#   3. "Do now" means the tool has DOCUMENTED that users notice nothing. A
#      control with no impact entry must never land there — an undocumented
#      impact is not evidence of no impact, and that is the mistake that gets a
#      change approved without anyone checking.
#
#   4. Single framework. The plan names NIST and nothing else. A leak is
#      invisible — the document still renders, still scores correctly, and just
#      quietly stops being the single-framework deliverable it was sold as.
#
#   5. The ceiling is stated. Completing every step does not make anyone 800-53
#      compliant; it closes what a tenant scan can see. A reader must not be
#      able to infer that 100% means done.

Describe 'NIST 800-53 improvement plan' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        $script:Controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 | ConvertFrom-Json).controls)
        $script:Impact   = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/operational-impact.json') -Raw -Encoding utf8 | ConvertFrom-Json

        # A mixed findings set: passes, gaps, partials, NotApplicable, and some
        # controls absent entirely.
        $script:Findings = @()
        $i = 0
        foreach ($c in $script:Controls) {
            $i++
            if ($i % 9 -eq 0) { continue }
            $state = switch ($i % 5) { 0 {'Satisfied'} 1 {'Gap'} 2 {'Partial'} 3 {'Satisfied'} 4 {'NotApplicable'} }
            $script:Findings += @{
                ControlId    = $c.ControlId
                State        = $state
                Title        = $c.Title
                Severity     = $c.Severity
                Remediation  = $c.Remediation
                FrameworkIds = @(Get-NRGFrameworkCitations -ControlId $c.ControlId)
            }
        }

        # LicenseProfile $null means "no SKU data" — conservative, so every
        # gated control lands in Buy first. That is the state the plan must be
        # safe in, so it is the state the tests use.
        $script:Plan = Get-NRGNISTImprovementPlan -Findings $script:Findings -LicenseProfile $null

        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-plan-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = [System.IO.Directory]::CreateDirectory($script:Tmp)
        $script:MdPath   = Join-Path $script:Tmp 'plan.md'
        $script:HtmlPath = [IO.Path]::ChangeExtension($script:MdPath, '.html')

        $script:PubError = $null
        try {
            Publish-NRGImprovementPlan -Plan $script:Plan -OutputPath $script:MdPath `
                -ClientName 'Example Client' `
                -Metadata @{ TenantDomain = 'example.com'; AssessmentDate = '2026-08-26'; ToolVersion = '4.12.1' } `
                -ErrorAction Stop
        } catch { $script:PubError = $_ }

        $script:Md   = if (Test-Path -LiteralPath $script:MdPath)   { Get-Content -LiteralPath $script:MdPath   -Raw } else { '' }
        $script:Html = if (Test-Path -LiteralPath $script:HtmlPath) { Get-Content -LiteralPath $script:HtmlPath -Raw } else { '' }

        $script:AllSteps = @(foreach ($t in $script:Plan['Tracks']) { foreach ($s in @($t['Steps'])) { $s } })
    }

    AfterAll {
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) {
            Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'The projection is arithmetic, not an estimate' {

        It 'reproduces the baseline the rest of the tool would compute' {
            $direct = Get-NRGCoverageScore -Findings $script:Findings -FrameworkId 'NIST' -ErrorHandling 'Gap'
            $script:Plan['Baseline']['Score']     | Should -Be ([int]$direct.Score)
            $script:Plan['Baseline']['Scored']    | Should -Be ([int]$direct.Scored)
            $script:Plan['Baseline']['Satisfied'] | Should -Be ([int]$direct.Satisfied)
            $script:Plan['Baseline']['Partial']   | Should -Be ([int]$direct.Partial)
        }

        It 'derives every cumulative figure from the baseline, with no rounding drift' {
            # Re-derived independently here. If the implementation ever starts
            # accumulating rounded per-step deltas instead of recomputing from
            # counts, the two diverge and this catches it.
            $num = [double]$script:Plan['Baseline']['Satisfied'] + (0.5 * [double]$script:Plan['Baseline']['Partial'])
            $den = [double]$script:Plan['Baseline']['Scored']
            foreach ($s in $script:AllSteps) {
                $num += if ($s['State'] -eq 'Gap') { 1.0 } else { 0.5 }
                $expected = [int][Math]::Round(100 * $num / $den)
                $s['CumulativeScore'] | Should -Be $expected -Because "step $($s['Rank']) ($($s['ControlId'])) must recompute from counts"
            }
        }

        It 'ends at the projected score it advertises' {
            if ($script:AllSteps.Count -gt 0) {
                $script:AllSteps[-1]['CumulativeScore'] | Should -Be $script:Plan['Projected']['Score']
            }
            $script:Plan['Projected']['PointGain'] | Should -Be ($script:Plan['Projected']['Score'] - $script:Plan['Baseline']['Score'])
            $script:Plan['Projected']['StepCount'] | Should -Be $script:AllSteps.Count
        }

        It 'values a partial at half a gap' {
            foreach ($s in $script:AllSteps) {
                $unit = 100.0 / [double]$script:Plan['Baseline']['Scored']
                $want = [Math]::Round($unit * $(if ($s['State'] -eq 'Gap') { 1.0 } else { 0.5 }), 1)
                $s['ScoreLift'] | Should -Be $want -Because "$($s['ControlId']) is $($s['State'])"
            }
        }

        It 'ranks steps contiguously from 1 and keeps a stable order between runs' {
            $ranks = @($script:AllSteps | ForEach-Object { $_['Rank'] })
            $ranks | Should -Be @(1..$script:AllSteps.Count)

            $again = Get-NRGNISTImprovementPlan -Findings $script:Findings -LicenseProfile $null
            $a = @(foreach ($t in $again['Tracks']) { foreach ($s in @($t['Steps'])) { [string]$s['ControlId'] } })
            $b = @($script:AllSteps | ForEach-Object { [string]$_['ControlId'] })
            $a | Should -Be $b -Because 'a plan whose order shuffles between runs cannot be worked down'
        }
    }

    Context 'What the plan refuses to claim' {

        It 'gives a license-blocked control no projected score and no rank' {
            foreach ($b in @($script:Plan['Blocked'])) {
                $b.Contains('CumulativeScore') | Should -BeFalse -Because "$($b['ControlId']) is license-blocked and must carry no projected coverage"
                $b.Contains('Rank')            | Should -BeFalse
                $b['Track'] | Should -Be 'Buy first'
            }
        }

        It 'keeps blocked controls out of the actionable tracks entirely' {
            $blockedIds = @($script:Plan['Blocked'] | ForEach-Object { [string]$_['ControlId'] })
            foreach ($s in $script:AllSteps) {
                $blockedIds | Should -Not -Contain ([string]$s['ControlId'])
            }
        }

        It 'treats absent license data as blocked rather than as a quick win' {
            # -LicenseProfile $null is "we do not know". A control with a
            # requirement we cannot verify must be blocked, never promised.
            #
            # "Included (EOP)" and the other Included* strings are the
            # exception, and a deliberate one: Test-NRGLicenseRequirementMet
            # treats them as met regardless of SKU data, because they are
            # capabilities every tenant has. So the invariant is not "no
            # requirement" — it is "the requirement is confirmed met by the
            # same helper the rest of the tool trusts".
            $gated = @($script:Plan['Blocked'] | ForEach-Object { [string]$_['ControlId'] })
            $gated.Count | Should -BeGreaterThan 0
            foreach ($s in $script:AllSteps) {
                $req = [string]$s['LicenseReq']
                if (-not $req) { continue }
                Test-NRGLicenseRequirementMet -LicenseRequirement $req -LicenseProfile $null |
                    Should -BeTrue -Because "$($s['ControlId']) sits in an actionable track requiring '$req', which we could not confirm the tenant holds"
            }
        }

        It 'never puts a control with an undocumented impact in the Do now track' {
            $now = @($script:Plan['Tracks'] | Where-Object { $_['Name'] -eq 'Do now' })
            foreach ($t in $now) {
                foreach ($s in @($t['Steps'])) {
                    $s['Impact'] | Should -Not -BeNullOrEmpty -Because "$($s['ControlId']) is in Do now, which asserts users notice nothing — that has to be documented, not assumed"
                    [string]$s['Impact']['Archetype'] | Should -BeIn @('none-visible', 'admin-review-workload', 'monitoring-integration')
                }
            }
        }

        It 'plans no work for a Satisfied, NotApplicable or Error finding' {
            foreach ($s in $script:AllSteps) { $s['State'] | Should -BeIn @('Gap', 'Partial') }
            $err = Get-NRGNISTImprovementPlan -Findings @(
                @{ ControlId = 'AAD-1.1'; State = 'Error'; Title = 'boom'; Severity = 'Critical'
                   FrameworkIds = @(Get-NRGFrameworkCitations -ControlId 'AAD-1.1') }
            ) -LicenseProfile $null
            @(foreach ($t in $err['Tracks']) { foreach ($s in @($t['Steps'])) { $s } }).Count |
                Should -Be 0 -Because 'a thrown evaluator produced no verdict, so there is nothing to act on'
        }

        It 'states its own ceiling and never implies 100% is compliance' {
            $script:Plan['Ceiling']['Families']      | Should -BeGreaterThan 0
            $script:Plan['Ceiling']['TotalFamilies'] | Should -Be 20
            $script:Plan['Ceiling']['Note']          | Should -Match 'not 800-53 compliance'
            $script:Md   | Should -Match 'What this plan does not do'
            $script:Html | Should -Match 'What this plan does not do'
            $script:Md   | Should -Match 'not 800-53 compliance'
        }

        It 'says family rows do not sum, on every surface that renders them' {
            $script:Md   | Should -Match 'do not sum'
            $script:Html | Should -Match 'do not sum'
        }
    }

    Context 'Family movement' {

        It 'matches a full replay of the plan through the same rollup' {
            # The implementation computes family movement by replaying. This
            # re-derives it the same way but independently, so a future
            # optimization to per-family arithmetic — which gets multi-family
            # controls wrong — fails here rather than in front of an auditor.
            # A step for a linked group fixes every control in it.
            $fixed = @($script:AllSteps | ForEach-Object { [string]$_['ControlId']; @($_['LinkedControls']) })
            $after = foreach ($f in $script:Findings) {
                if ([string]$f['ControlId'] -in $fixed) {
                    @{ ControlId = $f['ControlId']; State = 'Satisfied'; Title = $f['Title']
                       Severity = $f['Severity']; FrameworkIds = $f['FrameworkIds'] }
                } else { $f }
            }
            $expected = Get-NRGNISTFamilyCoverage -Findings @($after) -ErrorHandling 'Gap'
            $byId = @{}
            foreach ($row in @($expected['Families'])) { $byId[[string]$row['Family']] = [int]$row['Score'] }
            foreach ($f in @($script:Plan['Families'])) {
                $f['ScoreAfter'] | Should -Be $byId[[string]$f['Family']] -Because "family $($f['Family'])"
                $f['Movement']   | Should -Be ($f['ScoreAfter'] - $f['ScoreBefore'])
            }
        }

        It 'never reports a family going backwards' {
            foreach ($f in @($script:Plan['Families'])) {
                $f['Movement'] | Should -BeGreaterOrEqual 0 -Because "closing gaps cannot lower family $($f['Family'])"
            }
        }

        It 'lists every family it moved as touched by at least one step' {
            foreach ($f in @($script:Plan['Families'] | Where-Object { $_['Movement'] -gt 0 })) {
                @($f['Steps']).Count | Should -BeGreaterThan 0 -Because "family $($f['Family']) moved, so some step must be responsible"
            }
        }
    }

    Context 'Single framework, deliberately' {

        It 'names no framework other than NIST, on either surface' {
            # \b prefix matters: without it "precisely" and "decision" both
            # match CIS case-insensitively and the test fails on its own prose.
            foreach ($fw in 'CIS', 'SCuBA', 'CMMC', 'ISO 27001', 'SOC 2', 'HIPAA', 'PCI DSS', 'MITRE') {
                $script:Md   | Should -Not -Match ('\b' + [regex]::Escape($fw)) -Because "the Markdown plan leaked $fw"
                $script:Html | Should -Not -Match ('\b' + [regex]::Escape($fw)) -Because "the HTML plan leaked $fw"
            }
        }

        It 'renders NIST control identifiers, never the raw citation string' {
            # FrameworkIds carries every other framework the control cites.
            # Printing it verbatim is how a leak gets in.
            $script:Md | Should -Not -Match 'FrameworkIds'
            $script:Md | Should -Match 'AC-|AU-|IA-|SC-|SI-'
        }
    }

    Context 'The published plan' {

        It 'publishes without error and writes both files' {
            $script:PubError | Should -BeNullOrEmpty
            $script:Md   | Should -Not -BeNullOrEmpty
            $script:Html | Should -Not -BeNullOrEmpty
        }

        It 'renders every step with its remediation and its impact' {
            foreach ($s in $script:AllSteps) {
                $script:Md | Should -BeLike "*$($s['ControlId'])*"
            }
            $script:Md | Should -Match 'What it will affect'
            $script:Md | Should -Match 'Watch out for'
            $script:Md | Should -Match '\*\*How\.\*\*'
        }

        It 'shows both the current and the projected coverage in the headline' {
            $script:Md   | Should -BeLike "*$($script:Plan['Baseline']['Score'])%*"
            $script:Md   | Should -BeLike "*$($script:Plan['Projected']['Score'])%*"
            $script:Html | Should -BeLike "*$($script:Plan['Projected']['Score'])%*"
        }

        It 'produces self-contained HTML with no external asset' {
            $script:Html | Should -Not -Match '<script\s+[^>]*src='
            $script:Html | Should -Not -Match '<link\s+[^>]*href=[''"]http'
            $script:Html | Should -Not -Match '<img\s+[^>]*src=[''"]http'
        }

        It 'writes nothing and warns when there is nothing to plan against' {
            $md = Join-Path $script:Tmp 'none.md'
            $emptyPlan = Get-NRGNISTImprovementPlan -Findings @() -LicenseProfile $null
            $emptyPlan['Available'] | Should -BeFalse
            Publish-NRGImprovementPlan -Plan $emptyPlan -OutputPath $md -WarningAction SilentlyContinue
            Test-Path -LiteralPath $md | Should -BeFalse
        }

        It 'renders an honest empty plan when every NIST control already passes' {
            $allPass = @(foreach ($c in $script:Controls) {
                @{ ControlId = $c.ControlId; State = 'Satisfied'; Title = $c.Title; Severity = $c.Severity
                   FrameworkIds = @(Get-NRGFrameworkCitations -ControlId $c.ControlId) }
            })
            $p = Get-NRGNISTImprovementPlan -Findings $allPass -LicenseProfile $null
            $p['Available'] | Should -BeTrue
            $p['Projected']['StepCount'] | Should -Be 0
            $md = Join-Path $script:Tmp 'clean.md'
            Publish-NRGImprovementPlan -Plan $p -OutputPath $md
            (Get-Content -LiteralPath $md -Raw) | Should -Match 'There is nothing to do'
        }
    }

    Context 'Operational impact carries an effort class' {

        It 'gives every archetype an Effort' {
            foreach ($p in $script:Impact.archetypes.PSObject.Properties) {
                ([string]$p.Value.Effort).Trim() | Should -Not -BeNullOrEmpty -Because "archetype '$($p.Name)' needs an Effort"
            }
        }

        It 'uses only the documented effort classes, and never an hour figure' {
            # An invented hour count is a promise the tool cannot keep. Effort
            # describes the shape of the work and nothing more.
            $allowed = @('Single setting', 'Single setting, then ongoing', 'Policy change',
                         'Policy change, then tuning', 'Staged rollout', 'Discovery first',
                         'Project', 'License purchase', 'Review only')
            foreach ($p in $script:Impact.archetypes.PSObject.Properties) {
                [string]$p.Value.Effort | Should -BeIn $allowed -Because "archetype '$($p.Name)'"
                [string]$p.Value.Effort | Should -Not -Match '\d+\s*(h|hr|hour|day|week)'
            }
        }

        It 'surfaces the effort on every planned step' {
            foreach ($s in $script:AllSteps) {
                ([string]$s['Effort']).Trim() | Should -Not -BeNullOrEmpty -Because "$($s['ControlId']) has no effort class"
            }
        }
    }
}

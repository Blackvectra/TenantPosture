#Requires -Version 7.0
#
# NRG.AssessmentScope.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Pins Get-NRGAssessmentScope, the section that says which controls this run
# did NOT reach a verdict on.
#
# The bug class it exists to surface: NotApplicable is excluded from the
# compliance denominator, so a control that silently stops producing a verdict
# makes the score go UP. Every high-consequence defect found in this tool has
# had that shape — the omitted signInActivity property, the missing PIM
# SectionStatus, the DNS lookup failure read as an absent record. In each case
# nothing in the deliverable said the control had gone quiet.
#
# So the tests below are mostly about ARITHMETIC HONESTY: every control in the
# catalogue lands in exactly one bucket, the buckets sum to the totals, and a
# control that emitted nothing at all is reported rather than dropped. Plus the
# hard invariant that this is a reporting view and moves no score.

Describe 'Get-NRGAssessmentScope — what the assessment did not cover' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        $script:Controls = @(Get-NRGControlDefinitions)
        $script:Total    = $script:Controls.Count

        # Build a findings set from the real catalogue so the totals are the
        # product's real numbers, not a toy fixture.
        function script:Build {
            param(
                [int] $SkipFirst = 0,                 # controls that emit NOTHING
                [hashtable] $Override = @{}           # ControlId -> @{State;Detail}
            )
            $out = [System.Collections.Generic.List[object]]::new()
            $i = 0
            foreach ($c in $script:Controls) {
                $i++
                if ($i -le $SkipFirst) { continue }
                if ($Override.ContainsKey($c.ControlId)) {
                    $o = $Override[$c.ControlId]
                    $out.Add([pscustomobject]@{ ControlId = $c.ControlId; State = $o.State; Detail = $o.Detail })
                } else {
                    $out.Add([pscustomobject]@{ ControlId = $c.ControlId; State = 'Satisfied'; Detail = 'ok' })
                }
            }
            return $out.ToArray()
        }
    }

    AfterAll { Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    Context 'the arithmetic is honest' {

        It 'counts every control in the catalogue exactly once' {
            $s = Get-NRGAssessmentScope -Findings (script:Build)
            $s.Available     | Should -BeTrue
            $s.TotalControls | Should -Be $script:Total
            ($s.ScoredControls + $s.UnscoredControls) | Should -Be $s.TotalControls
        }

        It 'places every unscored control in exactly one bucket' {
            $ids = @($script:Controls | ForEach-Object { $_.ControlId })
            $ov  = @{
                $ids[5]  = @{ State = 'NotApplicable'; Detail = 'Teams data not collected; not assessed.' }
                $ids[6]  = @{ State = 'NotApplicable'; Detail = 'Requires Defender for Office 365 Plan 1 — surfaced as a licensing upgrade opportunity.' }
                $ids[7]  = @{ State = 'NotApplicable'; Detail = 'No programmatic check; manual review required.' }
            }
            $s = Get-NRGAssessmentScope -Findings (script:Build -SkipFirst 2 -Override $ov)

            $sum = $s.LicenceBlocked.Count + $s.CollectionIncomplete.Count +
                   $s.NoProgrammaticCheck.Count + $s.NotEvaluatedThisMode.Count + $s.NoResult.Count
            $sum | Should -Be $s.UnscoredControls -Because 'a control that is unscored and in no bucket is invisible, which is the whole failure mode'

            # And no control appears in two buckets.
            $all = @($s.LicenceBlocked) + @($s.CollectionIncomplete) + @($s.NoProgrammaticCheck) +
                   @($s.NotEvaluatedThisMode) + @($s.NoResult)
            @($all | ForEach-Object { $_.ControlId } | Group-Object | Where-Object Count -gt 1) | Should -BeNullOrEmpty
        }

        It 'reports a control that emitted NOTHING rather than dropping it' {
            # The worst case: the control is absent from the findings entirely,
            # so it appears nowhere else in the report at all.
            $s = Get-NRGAssessmentScope -Findings (script:Build -SkipFirst 3)
            $s.NoResult.Count | Should -Be 3
            @($s.NoResult | ForEach-Object { $_.ControlId }) | Should -Be @($script:Controls[0].ControlId, $script:Controls[1].ControlId, $script:Controls[2].ControlId)
        }

        It 'treats an empty findings set as nothing assessed, not as everything fine' {
            $s = Get-NRGAssessmentScope -Findings @()
            $s.ScoredControls   | Should -Be 0
            $s.NoResult.Count   | Should -Be $script:Total
            $s.UnscoredControls | Should -Be $script:Total
        }

        It 'tolerates a null findings argument' {
            { Get-NRGAssessmentScope -Findings $null } | Should -Not -Throw
        }
    }

    Context 'classification' {

        It 'separates a collection failure from a licence block' {
            # These two look identical in the report today — both NotApplicable,
            # both excluded from the score — but one is benign and one means
            # "we did not look".
            $ids = @($script:Controls | ForEach-Object { $_.ControlId })
            $ov  = @{
                $ids[0] = @{ State = 'NotApplicable'; Detail = 'Purview data not collected; not assessed.' }
                $ids[1] = @{ State = 'NotApplicable'; Detail = 'Requires Entra ID P2 — surfaced as a licensing upgrade opportunity.' }
            }
            $s = Get-NRGAssessmentScope -Findings (script:Build -Override $ov)
            @($s.CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Contain $ids[0]
            @($s.LicenceBlocked       | ForEach-Object { $_.ControlId }) | Should -Contain $ids[1]
            @($s.LicenceBlocked       | ForEach-Object { $_.ControlId }) | Should -Not -Contain $ids[0]
        }

        It 'classifies a 403 / consent failure as a collection failure, not as advisory' {
            $ids = @($script:Controls | ForEach-Object { $_.ControlId })
            $ov  = @{ $ids[0] = @{ State = 'NotApplicable'; Detail = 'Graph returned 403 Forbidden — scope requires admin consent.' } }
            $s = Get-NRGAssessmentScope -Findings (script:Build -Override $ov)
            @($s.CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Contain $ids[0]
        }

        It 'counts an Error finding as scored but names it, since its true state is unknown' {
            $ids = @($script:Controls | ForEach-Object { $_.ControlId })
            $ov  = @{ $ids[0] = @{ State = 'Error'; Detail = 'Graph returned 500.' } }
            $s = Get-NRGAssessmentScope -Findings (script:Build -Override $ov)
            $s.ErrorControls | Should -Be 1
            @($s.Errors | ForEach-Object { $_.ControlId }) | Should -Contain $ids[0]
            # The report scores Error as a gap, so it must not also be counted
            # as unassessed — that would double-count it.
            @($s.CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Not -Contain $ids[0]
        }

        It 'takes the WORST state for a control that emitted several instance findings' {
            # DNS and the named-object evaluators emit one finding per domain or
            # object. A control assessed on one domain and not another is partly
            # assessed, and "partly" is the honest answer.
            $cid = $script:Controls[0].ControlId
            $f = @(
                [pscustomobject]@{ ControlId = $cid; State = 'Satisfied';     Detail = 'ok' }
                [pscustomobject]@{ ControlId = $cid; State = 'NotApplicable'; Detail = 'The SPF lookup did not complete; not assessed.' }
            )
            $s = Get-NRGAssessmentScope -Findings $f
            @($s.CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Contain $cid
        }
    }

    Context 'classified against what the evaluators REALLY emit' {

        # The bug class this context exists for: the first version of the
        # classifier was tested against Detail strings the author invented to
        # match the author's own regex. Four misclassifications survived that,
        # because the evaluators say things like "Teams collector did not run."
        # and "Neither AAD-Users nor AAD-AuthPolicies collector produced data."
        # which the regex never matched. This is the same lesson as the
        # pre-computed IsExternal fixtures: test against the real shape.
        BeforeAll {
            Clear-NRGState
            $evs = @($script:Controls | ForEach-Object { $_.EvaluatorFunction } | Sort-Object -Unique)
            foreach ($ev in $evs) { try { Invoke-NRGEvaluatorSafe -EvaluatorFunction $ev } catch { } }
            $script:RealFindings = @(Get-NRGFindings)
            # No raw data, no licence profile — the state a totally failed
            # collection run leaves behind.
            $script:RealScope = Get-NRGAssessmentScope -Findings $script:RealFindings -Coverage @{}
        }

        It 'produces a finding for every control when every evaluator runs' {
            $script:RealFindings.Count | Should -Be $script:Total
            $script:RealScope.NoResult.Count | Should -Be 0
        }

        It 'classifies every totally-uncollected control as a collection failure or an advisory control' {
            # NOT as licence gated, and NOT as "no automated test" for a
            # control that simply had no data.
            $script:RealScope.LicenceBlocked.Count | Should -Be 0 -Because 'no SKU data was available, so nothing can be called licence gated'
            ($script:RealScope.CollectionIncomplete.Count + $script:RealScope.NoProgrammaticCheck.Count) |
                Should -Be $script:Total
        }

        It 'routes the overwhelming majority to the collection bucket, not to manual review' {
            # The three genuinely advisory controls say "requires manual
            # verification"; everything else lost its data.
            $script:RealScope.NoProgrammaticCheck.Count | Should -BeLessOrEqual 6
            $script:RealScope.CollectionIncomplete.Count | Should -BeGreaterThan 190
        }

        It 'puts only self-declared advisory controls in the manual-review bucket' {
            foreach ($row in $script:RealScope.NoProgrammaticCheck) {
                $row.Reason | Should -Match 'requires manual verification' -Because "$($row.ControlId) is in the advisory bucket"
            }
        }
    }

    Context 'absence of evidence is never evidence' {

        It 'never calls a control licence gated when the profile carries no SKU data' {
            # THE bug. Test-NRGLicenseRequirementMet returns $false when there
            # is no SKU data (deliberately — Upgrade Unlocks should over-report
            # an upgrade need). Inverting it turned "we don't know" into
            # "licence gated, benign", so a control whose own Detail said
            # "EXO data not collected" was filed as benign.
            $ids = @($script:Controls | ForEach-Object { $_.ControlId })
            $ov  = @{ $ids[0] = @{ State = 'NotApplicable'; Detail = 'EXO data not collected' } }
            $emptyProfile = [pscustomobject]@{
                SuppressedLicenseRequirements = [System.Collections.Generic.HashSet[string]]::new()
                TierLabel                     = 'Unknown'
            }
            $s = Get-NRGAssessmentScope -Findings (script:Build -Override $ov) -Coverage @{} -LicenseProfile $emptyProfile
            @($s.LicenceBlocked | ForEach-Object { $_.ControlId })       | Should -Not -Contain $ids[0]
            @($s.CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Contain $ids[0]
        }

        It 'still reports a licence block when the profile DOES carry SKU data' {
            $ids  = @($script:Controls | ForEach-Object { $_.ControlId })
            $lic  = @($script:Controls | Where-Object { $_.LicenseRequirement -and $_.LicenseRequirement -notmatch '^Included' } | Select-Object -First 1)
            $lic.Count | Should -BeGreaterThan 0 -Because 'the fixture needs a licence-gated control to exist'
            $target = $lic[0].ControlId
            $ov = @{ $target = @{ State = 'NotApplicable'; Detail = 'Feature not present in this tenant.' } }
            $realProfile = [pscustomobject]@{
                SuppressedLicenseRequirements = [System.Collections.Generic.HashSet[string]]::new([string[]]@('Included in all M365 plans'))
                TierLabel                     = 'Business Basic'
            }
            $s = Get-NRGAssessmentScope -Findings (script:Build -Override $ov) -Coverage @{} -LicenseProfile $realProfile
            @($s.LicenceBlocked | ForEach-Object { $_.ControlId }) | Should -Contain $target
        }

        It 'never calls every control a collection failure just because raw data is absent' {
            # The mirror of the same mistake: an empty raw-data map means we
            # are replaying and know nothing, not that every collector failed.
            $s = Get-NRGAssessmentScope -Findings (script:Build) -Coverage @{} -RawData @{}
            $s.CollectionIncomplete.Count | Should -Be 0
            $s.ScoredControls | Should -Be $script:Total
        }

        It 'uses raw data as hard evidence when it IS present' {
            $target = $script:Controls[0]
            $ov = @{ $target.ControlId = @{ State = 'NotApplicable'; Detail = 'Feature not present in this tenant.' } }
            $raw = @{ $target.CollectorDependency = [pscustomobject]@{ Success = $false; Data = $null } }
            $s = Get-NRGAssessmentScope -Findings (script:Build -Override $ov) -Coverage @{} -RawData $raw
            @($s.CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Contain $target.ControlId
            ($s.CollectionIncomplete | Where-Object { $_.ControlId -eq $target.ControlId }).Reason |
                Should -Match 'did not return data'
        }
    }

    Context 'quick-scan mode' {

        It 'reports skipped controls as not evaluated, never as a tool fault' {
            # -Quick drops whole evaluators on purpose; calling that a tool
            # fault is a lie about a mode the operator chose.
            $s = Get-NRGAssessmentScope -Findings (script:Build -SkipFirst 40) -Coverage @{} -QuickScan
            $s.QuickScan                    | Should -BeTrue
            $s.NotEvaluatedThisMode.Count   | Should -Be 40
            $s.NoResult.Count               | Should -Be 0
            ($s.Limitations -join ' ')      | Should -Match 'quick scan'
            ($s.Limitations -join ' ')      | Should -Not -Match 'tool fault'
        }

        It 'still calls a missing result a tool fault on a full run' {
            $s = Get-NRGAssessmentScope -Findings (script:Build -SkipFirst 2) -Coverage @{}
            $s.NoResult.Count             | Should -Be 2
            $s.NotEvaluatedThisMode.Count | Should -Be 0
            ($s.Limitations -join ' ')    | Should -Match 'tool fault'
        }
    }

    Context 'collector coverage' {

        It 'names collectors that did not complete and leaves the clean ones out' {
            $cov = @{
                'DNS-EmailRecords' = [pscustomobject]@{ Status = 'Partial';   Note = 'lookups did not complete on 1' }
                'Teams'            = [pscustomobject]@{ Status = 'Failed';    Note = 'not connected' }
                'AAD-Inventory'    = [pscustomobject]@{ Status = 'Collected'; Note = '500 users' }
            }
            $s = Get-NRGAssessmentScope -Findings (script:Build) -Coverage $cov
            @($s.CoverageIssues | ForEach-Object { $_.Family }) | Should -Be @('DNS-EmailRecords', 'Teams')
        }
    }

    Context 'the limitations text never reassures' {

        It 'always states the tenant-configuration-only limit, even on a perfect run' {
            $s = Get-NRGAssessmentScope -Findings (script:Build) -Coverage @{}
            ($s.Limitations -join ' ') | Should -Match 'does not test whether a control works in practice'
            ($s.Limitations -join ' ') | Should -Match 'not a penetration test'
        }

        It 'says unassessed controls are not passes' {
            $ids = @($script:Controls | ForEach-Object { $_.ControlId })
            $ov  = @{ $ids[0] = @{ State = 'NotApplicable'; Detail = 'Intune data not collected.' } }
            $s = Get-NRGAssessmentScope -Findings (script:Build -Override $ov) -Coverage @{}
            ($s.Limitations -join ' ') | Should -Match 'NOT passes'
        }

        It 'never claims anything is compliant, satisfied or secure' {
            $ids = @($script:Controls | ForEach-Object { $_.ControlId })
            $ov  = @{ $ids[0] = @{ State = 'NotApplicable'; Detail = 'Teams data not collected.' } }
            $s = Get-NRGAssessmentScope -Findings (script:Build -Override $ov) -Coverage @{}
            foreach ($l in $s.Limitations) {
                $l | Should -Not -Match '(?i)\b(is compliant|are compliant|fully covered|no issues found|all clear)\b'
            }
        }
    }

    Context 'it is a view, not a verdict' {

        It 'emits no findings' {
            Clear-NRGState
            $null = Get-NRGAssessmentScope -Findings (script:Build)
            @(Get-NRGFindings).Count | Should -Be 0 -Because 'this is a reporting view; it must never add to the findings set'
        }

        It 'does not move the compliance score' {
            $f = script:Build
            $before = Get-NRGCoverageScore -Findings $f -ErrorHandling 'Gap'
            $null   = Get-NRGAssessmentScope -Findings $f
            $after  = Get-NRGCoverageScore -Findings $f -ErrorHandling 'Gap'
            $after.Score | Should -Be $before.Score
            $after.Total | Should -Be $before.Total
        }

        It 'reads replayed result JSON (ConvertFrom-Json -AsHashtable) identically' {
            # The entry point replays prior runs through -AsHashtable, and a
            # field added later is absent there — the StrictMode trap this repo
            # has been bitten by repeatedly.
            $f      = script:Build -SkipFirst 2
            $live   = Get-NRGAssessmentScope -Findings $f
            $replay = Get-NRGAssessmentScope -Findings (($f | ConvertTo-Json -Depth 6) | ConvertFrom-Json -AsHashtable)
            $replay.ScoredControls   | Should -Be $live.ScoredControls
            $replay.UnscoredControls | Should -Be $live.UnscoredControls
            $replay.NoResult.Count   | Should -Be $live.NoResult.Count
        }

        It 'survives findings that carry no Detail field at all' {
            $f = @([pscustomobject]@{ ControlId = $script:Controls[0].ControlId; State = 'NotApplicable' })
            { Get-NRGAssessmentScope -Findings $f } | Should -Not -Throw
        }
    }
}

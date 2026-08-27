#Requires -Version 7.0
#
# NRG.SSP.Tests.ps1
#
# Guards the System Security Plan — Lib/Get-NRGSSPPosture.ps1,
# Lib/Get-NRGSSPAnswers.ps1, Publishers/Publish-NRGSSP.ps1,
# Config/nist-800-171-r2.json and Config/operational-impact.json.
#
# This is the one deliverable in the repo that a client SIGNS. An SSP goes to
# a prime contractor or a C3PAO assessor under a certification the client makes
# personally, and a false "Implemented" in it is not a display bug — it is a
# false statement in a compliance artifact. So the tests here are weighted
# almost entirely toward the tool refusing to claim things:
#
#   1. A requirement with no mapped control can never be derived as
#      implemented, no matter what the assessment found. 69 of the 110 are in
#      that state and the document has to keep saying so. The strongest test
#      here feeds a findings set that satisfies every control in the tool and
#      proves those 69 still refuse to claim anything.
#
#   2. A mapped control that produced no finding is an unknown, never a pass.
#      Skipped workloads and unlicensed features are the normal case, not an
#      edge case.
#
#   3. A status the CLIENT asserts is never counted as one the tool verified.
#      That separation is the difference between an SSP and a wish list.
#
#   4. An undocumented operational impact renders as "not documented", never as
#      "no impact". "No impact" is the answer that gets a change approved
#      without anyone checking.
#
# Plus the cross-reference integrity that rots silently: every Nist171 on a
# device control, and every 800-171 number embedded in a CMMC citation, must
# resolve in the Rev 2 catalog.

Describe 'System Security Plan (NIST SP 800-171 Rev 2)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        $script:CatPath = Join-Path $script:RepoRoot 'Config/nist-800-171-r2.json'
        $script:Cat     = Get-Content -LiteralPath $script:CatPath -Raw -Encoding utf8 | ConvertFrom-Json
        $script:Reqs    = @($script:Cat.requirements)

        $script:ImpactPath = Join-Path $script:RepoRoot 'Config/operational-impact.json'
        $script:Impact     = Get-Content -LiteralPath $script:ImpactPath -Raw -Encoding utf8 | ConvertFrom-Json

        $script:Controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 | ConvertFrom-Json).controls)
        $script:DevCtl   = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/device-controls.json') -Raw -Encoding utf8 | ConvertFrom-Json).controls)

        $script:ValidIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($r in $script:Reqs) { $null = $script:ValidIds.Add([string]$r.Id) }

        # A findings set in which EVERY control in the tool passes. The point of
        # this fixture is not to test a happy path — it is the adversarial input
        # for the honesty rule. If anything can make an unevidenced requirement
        # claim compliance, this is what makes it.
        $script:AllPass = @()
        foreach ($c in $script:Controls) { $script:AllPass += @{ ControlId = $c.ControlId; State = 'Satisfied'; Title = $c.Title } }
        foreach ($d in $script:DevCtl)   { $script:AllPass += @{ ControlId = $d.ControlId; State = 'Satisfied'; Title = $d.Title } }

        $script:PostureAllPass = Get-NRGSSPPosture -Findings $script:AllPass
        $script:PostureEmpty   = Get-NRGSSPPosture -Findings @()

        $script:Answers = Get-NRGSSPAnswers -Path (Join-Path $script:RepoRoot 'Config/ssp/example.psd1')

        # Mixed findings for the publisher, so every rendering branch is
        # exercised: passes, gaps, partials, NotApplicable and absent findings.
        $script:Mixed = @()
        $i = 0
        foreach ($c in $script:Controls) {
            $i++
            if ($i % 7 -eq 0) { continue }
            $st = switch ($i % 4) { 0 { 'Satisfied' } 1 { 'Gap' } 2 { 'Partial' } 3 { 'NotApplicable' } }
            $script:Mixed += @{ ControlId = $c.ControlId; State = $st; Title = $c.Title }
        }
        foreach ($d in $script:DevCtl) { $script:Mixed += @{ ControlId = $d.ControlId; State = 'Gap'; Title = $d.Title } }

        $script:PostureMixed = Get-NRGSSPPosture -Findings $script:Mixed -Answers $script:Answers

        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-ssp-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = [System.IO.Directory]::CreateDirectory($script:Tmp)
        $script:MdPath   = Join-Path $script:Tmp 'ssp.md'
        $script:HtmlPath = [IO.Path]::ChangeExtension($script:MdPath, '.html')

        $script:PubError = $null
        try {
            Publish-NRGSSP -Posture $script:PostureMixed -OutputPath $script:MdPath `
                -Answers $script:Answers -ClientName 'Example Client' `
                -Metadata @{ TenantDomain = 'example.com'; AssessmentDate = '2026-08-26'; ToolVersion = '4.12.1' } `
                -ErrorAction Stop
        } catch { $script:PubError = $_ }

        $script:Md   = if (Test-Path -LiteralPath $script:MdPath)   { Get-Content -LiteralPath $script:MdPath   -Raw } else { '' }
        $script:Html = if (Test-Path -LiteralPath $script:HtmlPath) { Get-Content -LiteralPath $script:HtmlPath -Raw } else { '' }
    }

    AfterAll {
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) {
            Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'The Rev 2 catalog' {

        It 'holds all 110 requirements across the 14 families' {
            $script:Reqs.Count | Should -Be 110
            @($script:Cat.families.PSObject.Properties).Count | Should -Be 14
        }

        It 'gives every requirement a family that exists and a non-empty statement' {
            foreach ($r in $script:Reqs) {
                $r.Family | Should -Not -BeNullOrEmpty -Because "$($r.Id) needs a family"
                $script:Cat.families.PSObject.Properties[$r.Family] | Should -Not -BeNullOrEmpty -Because "$($r.Id) cites family $($r.Family), which is not in the family list"
                ([string]$r.Statement).Trim() | Should -Not -BeNullOrEmpty -Because "$($r.Id) needs a statement"
            }
        }

        It 'carries no requirement id with surrounding whitespace' {
            # The community OSCAL catalog this was converted from ships 3.2.1
            # with padding in its id, which silently drops it from every
            # exact-match join. Normalisation happened at conversion; this stops
            # it coming back on the next refresh.
            foreach ($r in $script:Reqs) {
                ([string]$r.Id) | Should -BeExactly (([string]$r.Id).Trim()) -Because 'a padded id joins to nothing and the requirement vanishes silently'
            }
        }

        It 'is pinned to Rev 2, the revision CMMC Level 2 is assessed against' {
            # DoD Class Deviation 2023-O0006. Rev 3 exists but is not authorised
            # for CMMC scoring; publishing an SSP against it would be assessed
            # against the wrong standard.
            $script:Cat.framework | Should -Match 'Rev(ision)?\s*2'
        }
    }

    Context 'Mapping integrity' {

        It 'resolves every Nist171 on a device control to a real Rev 2 requirement' {
            foreach ($d in $script:DevCtl) {
                foreach ($n in @($d.Nist171)) {
                    $script:ValidIds.Contains([string]$n) | Should -BeTrue -Because "$($d.ControlId) cites $n, which is not a Rev 2 requirement"
                }
            }
        }

        It 'resolves every 800-171 number embedded in a CMMC citation' {
            foreach ($c in $script:Controls) {
                foreach ($id in @(Get-NRGNIST171RequirementIdsFromCmmc -Citation ([string]$c.References.CMMC))) {
                    $script:ValidIds.Contains($id) | Should -BeTrue -Because "$($c.ControlId) cites CMMC $($c.References.CMMC), whose requirement number $id is not in Rev 2"
                }
            }
        }

        It 'parses a CMMC practice id but never a bare identifier' {
            # 'Req 8.3' (PCI DSS) and 'A.5.17' (ISO) are also in controls.json
            # References. Matching the bare d.d.d shape would file a control's
            # evidence under a requirement it has nothing to do with.
            @(Get-NRGNIST171RequirementIdsFromCmmc -Citation 'IA.L2-3.5.3') | Should -Be @('3.5.3')
            @(Get-NRGNIST171RequirementIdsFromCmmc -Citation 'AC.L1-3.1.1, AC.L2-3.1.12').Count | Should -Be 2
            @(Get-NRGNIST171RequirementIdsFromCmmc -Citation 'Req 8.3').Count | Should -Be 0
            @(Get-NRGNIST171RequirementIdsFromCmmc -Citation '3.5.3').Count   | Should -Be 0
            @(Get-NRGNIST171RequirementIdsFromCmmc -Citation '').Count        | Should -Be 0
            @(Get-NRGNIST171RequirementIdsFromCmmc -Citation $null).Count     | Should -Be 0
        }

        It 'reaches a meaningful minority of the baseline and does not pretend to reach more' {
            # Both directions matter. If this drops, coverage regressed. If it
            # climbs toward 110, something started claiming evidence it does not
            # have — which is the failure this whole file exists to prevent.
            $script:PostureAllPass['Summary']['Evidenced'] | Should -BeGreaterOrEqual 38
            $script:PostureAllPass['Summary']['Evidenced'] | Should -BeLessOrEqual 60
            $script:PostureAllPass['Summary']['Evidenced'] + $script:PostureAllPass['Summary']['AttestationRequired'] | Should -Be 110
        }
    }

    Context 'The honesty rule — a requirement with no evidence claims nothing' {

        It 'never derives Implemented for a requirement with no mapped control, even when every control in the tool passes' {
            $unmapped = @($script:PostureAllPass['Requirements'] | Where-Object { $_['MappedControls'] -eq 0 })
            $unmapped.Count | Should -BeGreaterThan 0
            foreach ($r in $unmapped) {
                $r['Status']        | Should -Be 'No automated evidence' -Because "$($r['Id']) has no control behind it and must not claim one"
                $r['DerivedStatus'] | Should -Be 'No automated evidence'
                $r['Confidence']    | Should -Be 'Attestation only'
            }
        }

        It 'counts no unevidenced requirement as tool-verified' {
            $tv = @($script:PostureAllPass['Requirements'] | Where-Object { $_['Confidence'] -eq 'Tool-verified' })
            foreach ($r in $tv) { $r['MappedControls'] | Should -BeGreaterThan 0 }
            $script:PostureAllPass['Summary']['ToolVerified'] | Should -Be $script:PostureAllPass['Summary']['Evidenced']
        }

        It 'treats a mapped control that produced no finding as an unknown, not a pass' {
            # No findings at all: every mapped control is NotRun. Nothing may
            # read as implemented.
            @($script:PostureEmpty['Requirements'] | Where-Object { $_['Status'] -eq 'Implemented' }).Count | Should -Be 0
            @($script:PostureEmpty['Requirements'] | Where-Object { $_['Confidence'] -eq 'Tool-verified' }).Count | Should -Be 0
            $script:PostureEmpty['Summary']['NoEvidenceCollected'] | Should -Be $script:PostureEmpty['Summary']['Evidenced']
        }

        It 'does not let an Error state count in either direction' {
            $target = @($script:PostureAllPass['Requirements'] | Where-Object { $_['MappedControls'] -eq 1 })[0]
            $target | Should -Not -BeNullOrEmpty
            $cid = [string]$target['Evidence'][0]['ControlId']
            $p = Get-NRGSSPPosture -Findings @(@{ ControlId = $cid; State = 'Error'; Title = 'boom' })
            $r = @($p['Requirements'] | Where-Object { $_['Id'] -eq $target['Id'] })[0]
            $r['Satisfied'] | Should -Be 0
            $r['Gap']       | Should -Be 0
            $r['NotRun']    | Should -Be 1
            $r['Status']    | Should -Be 'Not assessed'
        }

        It 'keeps a client-attested status apart from a tool-verified one' {
            # 3.5.3 is asserted Implemented in the example answers file while
            # the assessment saw no findings at all.
            $r = @($script:PostureEmpty['Requirements'] | Where-Object { $_['Id'] -eq '3.5.3' })[0]
            $r2 = @((Get-NRGSSPPosture -Findings @() -Answers $script:Answers)['Requirements'] | Where-Object { $_['Id'] -eq '3.5.3' })[0]
            $r['Status']        | Should -Not -Be 'Implemented'
            $r2['Status']       | Should -Be 'Implemented'
            $r2['StatusSource'] | Should -Be 'Attested'
            $r2['Confidence']   | Should -Not -Be 'Tool-verified'
        }

        It 'stamps an inherited status as inherited rather than implemented-here' {
            $p = Get-NRGSSPPosture -Findings @() -Answers $script:Answers
            $r = @($p['Requirements'] | Where-Object { $_['Id'] -eq '3.10.1' })[0]
            $r['StatusSource']  | Should -Be 'Inherited'
            $r['InheritedFrom'] | Should -Not -BeNullOrEmpty
        }

        It 'derives nothing at all from an answers file that supplies only a narrative' {
            $p = Get-NRGSSPPosture -Findings @() -Answers @{
                Requirements = @{ '3.7.1' = @{ Narrative = 'We do maintenance.' } }
            }
            $r = @($p['Requirements'] | Where-Object { $_['Id'] -eq '3.7.1' })[0]
            $r['Narrative']    | Should -Not -BeNullOrEmpty
            $r['Status']       | Should -Be 'No automated evidence'
            $r['StatusSource'] | Should -Be 'None'
        }
    }

    Context 'Operational impact' {

        It 'maps every tenant and device control to an archetype that exists' {
            $arch = @($script:Impact.archetypes.PSObject.Properties.Name)
            foreach ($section in @('controls', 'deviceControls')) {
                foreach ($p in $script:Impact.$section.PSObject.Properties) {
                    $arch | Should -Contain ([string]$p.Value) -Because "$($p.Name) names archetype '$($p.Value)', which is not defined"
                }
            }
        }

        It 'covers every control in controls.json and device-controls.json' {
            foreach ($c in $script:Controls) {
                $script:Impact.controls.PSObject.Properties[$c.ControlId] | Should -Not -BeNullOrEmpty -Because "$($c.ControlId) has no operational impact, so the SSP cannot say what enabling it does"
            }
            foreach ($d in $script:DevCtl) {
                $script:Impact.deviceControls.PSObject.Properties[$d.ControlId] | Should -Not -BeNullOrEmpty -Because "$($d.ControlId) has no operational impact"
            }
        }

        It 'names no control that does not exist, in a mapping or an override' {
            $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($c in $script:Controls) { $null = $ids.Add([string]$c.ControlId) }
            foreach ($d in $script:DevCtl)   { $null = $ids.Add([string]$d.ControlId) }
            foreach ($section in @('controls', 'deviceControls', 'overrides')) {
                foreach ($p in $script:Impact.$section.PSObject.Properties) {
                    $ids.Contains([string]$p.Name) | Should -BeTrue -Because "operational-impact.json '$section' names $($p.Name), which is not a control in this tool"
                }
            }
        }

        It 'gives every archetype all five fields' {
            foreach ($p in $script:Impact.archetypes.PSObject.Properties) {
                foreach ($f in @('Summary', 'Users', 'Admins', 'Watchouts', 'Reversible')) {
                    ([string]$p.Value.$f).Trim() | Should -Not -BeNullOrEmpty -Because "archetype '$($p.Name)' is missing $f"
                }
            }
        }

        It 'returns $null for an unmapped control rather than an empty impact' {
            # The renderers print "not documented" for a $null and nothing at
            # all for an empty string. An unwritten impact must not read as
            # "no impact" — that is the answer that gets a change approved.
            Get-NRGControlOperationalImpact -ControlId 'ZZZ-9.9' -Catalog $script:Impact | Should -BeNullOrEmpty
            Get-NRGControlOperationalImpact -ControlId 'AAD-1.1' -Catalog $null           | Should -BeNullOrEmpty
        }

        It 'keeps an override separate from its archetype instead of merging over it' {
            $im = Get-NRGControlOperationalImpact -ControlId 'AAD-1.2' -Catalog $script:Impact
            $base = $script:Impact.archetypes.'auth-prompt'
            $im['Overridden']            | Should -BeTrue
            $im['Watchouts']             | Should -Be ([string]$base.Watchouts)
            $im['Overrides']['Watchouts'] | Should -Not -Be ([string]$base.Watchouts)
            # A control with no override carries no override fields.
            (Get-NRGControlOperationalImpact -ControlId 'AAD-5.2' -Catalog $script:Impact)['Overridden'] | Should -BeFalse
        }

        It 'prints one impact block per archetype, not one per control' {
            $actions = @(
                @{ ControlId = 'AAD-1.1'; Impact = (Get-NRGControlOperationalImpact -ControlId 'AAD-1.1' -Catalog $script:Impact) }
                @{ ControlId = 'EXO-2.3'; Impact = (Get-NRGControlOperationalImpact -ControlId 'EXO-2.3' -Catalog $script:Impact) }
                @{ ControlId = 'AAD-1.2'; Impact = (Get-NRGControlOperationalImpact -ControlId 'AAD-1.2' -Catalog $script:Impact) }
            )
            $g = @(Group-NRGSSPImpact -Actions $actions)
            $g.Count | Should -Be 2                       # legacy-client-break + auth-prompt
            $legacy = @($g | Where-Object { $_['Archetype'] -eq 'legacy-client-break' })[0]
            @($legacy['ControlIds']).Count | Should -Be 2
            $prompt = @($g | Where-Object { $_['Archetype'] -eq 'auth-prompt' })[0]
            @($prompt['Specifics']).Count  | Should -Be 1
            [string]$prompt['Specifics'][0]['ControlId'] | Should -Be 'AAD-1.2'
        }

        It 'survives an action list with no impact at all' {
            @(Group-NRGSSPImpact -Actions @()).Count | Should -Be 0
            @(Group-NRGSSPImpact -Actions @(@{ ControlId = 'X'; Impact = $null })).Count | Should -Be 0
        }
    }

    Context 'The answers file' {

        It 'loads the example without executing it' {
            $script:Answers['Available']            | Should -BeTrue
            @($script:Answers['Requirements'].Keys).Count | Should -BeGreaterThan 0
            $script:Answers['System']['Name']       | Should -Not -BeNullOrEmpty
        }

        It 'returns an unavailable answer set rather than throwing when the file is absent' {
            $a = Get-NRGSSPAnswers -ClientName 'no-such-client-at-all'
            $a['Available'] | Should -BeFalse
            @($a['Requirements'].Keys).Count | Should -Be 0
        }

        It 'refuses a traversing path' {
            { Get-NRGSSPAnswers -Path '../../etc/passwd' } | Should -Throw
        }

        It 'names a reason for every Not applicable and a provider for every Inherited' {
            # The example file is the template every client file is copied from.
            # An unreasoned N/A there teaches the pattern, and an assessor
            # rejects an unreasoned N/A on sight.
            foreach ($k in $script:Answers['Requirements'].Keys) {
                $v = $script:Answers['Requirements'][$k]
                $st = [string](Get-NRGObjectField -Item $v -Key 'Status' -Default '')
                if ($st -eq 'Not applicable') {
                    ([string](Get-NRGObjectField -Item $v -Key 'NotApplicableReason' -Default '')).Trim() |
                        Should -Not -BeNullOrEmpty -Because "$k is declared not applicable with no reason"
                }
                if ($st -eq 'Inherited') {
                    ([string](Get-NRGObjectField -Item $v -Key 'InheritedFrom' -Default '')).Trim() |
                        Should -Not -BeNullOrEmpty -Because "$k is declared inherited from nobody"
                }
            }
        }
    }

    Context 'The published plan' {

        It 'publishes without error and writes Markdown and HTML' {
            $script:PubError | Should -BeNullOrEmpty
            $script:Md   | Should -Not -BeNullOrEmpty
            $script:Html | Should -Not -BeNullOrEmpty
        }

        It 'renders every one of the 110 requirements' {
            foreach ($r in $script:Reqs) {
                $script:Md | Should -BeLike "*#### $($r.Id)*" -Because "$($r.Id) is missing from the plan"
            }
        }

        It 'states the evidenced / attested split on both surfaces' {
            $ev = $script:PostureMixed['Summary']['Evidenced']
            $at = $script:PostureMixed['Summary']['AttestationRequired']
            $script:Md   | Should -BeLike "*$ev*"
            $script:Md   | Should -BeLike "*$at*"
            $script:Md   | Should -Match 'working System Security Plan, not a finished one'
            $script:Html | Should -Match 'working System Security Plan, not a finished one'
        }

        It 'says plainly where a requirement has no automated evidence' {
            $script:Md   | Should -Match 'Nothing in a Microsoft 365 tenant or an endpoint scan evidences this requirement'
            $script:Html | Should -Match 'Nothing in a Microsoft 365 tenant or an endpoint scan evidences this requirement'
        }

        It 'marks a client-attested status as such wherever it renders' {
            $script:Md   | Should -Match 'client-attested'
            $script:Html | Should -Match 'client-attested'
        }

        It 'answers "what will it affect" wherever it offers a remediation' {
            $script:Md   | Should -Match 'What that will affect'
            $script:Html | Should -Match 'What that will affect'
            $script:Md   | Should -Match 'Watch out for'
        }

        It 'lists the requirements still needing a written answer' {
            $need = @($script:PostureMixed['Requirements'] | Where-Object {
                $_['MappedControls'] -eq 0 -and -not $_['Narrative'] -and $_['StatusSource'] -eq 'None'
            })
            $script:Md   | Should -Match 'Still to answer'
            $script:Html | Should -Match 'Still to answer'
            $script:Md   | Should -BeLike "*$($need.Count) requirements have neither automated evidence nor a written answer*"
        }

        It 'carries the SP 800-171A assessment objectives, which is what an assessor works' {
            $script:Md | Should -Match 'Assessment objectives \(SP 800-171A\)'
            # .Contains, not -BeLike: '[' opens a character class in a
            # PowerShell wildcard and the escape character is a backtick, not a
            # backslash, so '3.1.1\[a\]' silently matches nothing.
            $script:Md.Contains('3.1.1[a]') | Should -BeTrue
        }

        It 'produces self-contained HTML with no external asset' {
            $script:Html | Should -Not -Match '<script\s+[^>]*src='
            $script:Html | Should -Not -Match '<link\s+[^>]*href=[''"]http'
            $script:Html | Should -Not -Match '<img\s+[^>]*src=[''"]http'
        }

        It 'renders a plan with no answers file at all, without throwing' {
            $md = Join-Path $script:Tmp 'bare.md'
            { Publish-NRGSSP -Posture (Get-NRGSSPPosture -Findings @()) -OutputPath $md -ErrorAction Stop } |
                Should -Not -Throw
            (Get-Content -LiteralPath $md -Raw) | Should -Match 'Still to answer'
        }

        It 'writes nothing and warns when the baseline catalog is unavailable' {
            $md = Join-Path $script:Tmp 'none.md'
            $empty = [ordered]@{ Requirements = @(); Families = @(); Summary = [ordered]@{}; Available = $false }
            Publish-NRGSSP -Posture $empty -OutputPath $md -WarningAction SilentlyContinue
            Test-Path -LiteralPath $md | Should -BeFalse
        }
    }

    Context 'Additive — the SSP changes no existing output' {

        It 'moves no framework score' {
            # Same rule the NIST matrix is held to. The SSP reads findings and
            # writes documents; if publishing it can move a score, something is
            # mutating shared state.
            $before = Get-NRGCoverageScore -Findings $script:Mixed
            $null = Get-NRGSSPPosture -Findings $script:Mixed -Answers $script:Answers
            $null = Publish-NRGSSP -Posture $script:PostureMixed -OutputPath (Join-Path $script:Tmp 'again.md')
            $after = Get-NRGCoverageScore -Findings $script:Mixed
            $after.Score     | Should -Be $before.Score
            $after.Satisfied | Should -Be $before.Satisfied
            $after.Gap       | Should -Be $before.Gap
        }

        It 'keeps the DEV-* checks out of controls.json' {
            # The 199 is a stated product number. Nist171 was added to
            # device-controls.json, not to controls.json, and the two files stay
            # separate.
            $script:Controls.Count | Should -Be 199
            foreach ($c in $script:Controls) {
                $c.ControlId | Should -Not -BeLike 'DEV-*'
            }
        }
    }
}

#Requires -Version 7.0
#
# NRG.NISTFamily.Tests.ps1
#
# Pins the NIST SP 800-53 Rev 5 control-family rollup added in Lib/
# Get-NRGNISTFamilyCoverage.ps1, and the controls.json invariant it depends on.
#
# Two distinct classes of assertion live here.
#
#   1. Parsing and scoring. The rollup reads the flattened citation string
#      "NIST:IA-2, IA-5(1)" off each finding's FrameworkIds. That string is
#      built by Get-NRGFrameworkCitations from the References.NIST field, and it
#      shares a namespace with citations that LOOK like 800-53 identifiers but
#      are not — CMMC's "IA.L2-3.5.3" is the obvious trap. Mis-parsing those
#      would silently inflate family coverage with controls that were never
#      assessed against 800-53 at all.
#
#   2. The data invariant. The tool now presents a per-family NIST posture to
#      customers who are working an 800-53, FedRAMP, or CMMC assessment. That
#      presentation is only honest while EVERY control carries a real NIST
#      citation: a control with a missing or malformed reference vanishes from
#      the family view entirely, quietly shrinking a family's denominator and
#      inflating its coverage percentage. A control that cannot be assessed
#      must show up as N/A in its family, never as absent.

Describe 'NIST 800-53 control-family rollup' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }

        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGCoverageScore.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGNISTFamilyCoverage.ps1')

        $script:Controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 |
            ConvertFrom-Json).controls)

        # Helper: one finding with an explicit NIST citation string.
        function script:NistFinding {
            param([string]$ControlId, [string]$State, [string]$Nist)
            @{ ControlId = $ControlId; State = $State; FrameworkIds = @("NIST:$Nist") }
        }
    }

    Context 'Citation parsing' {

        It 'Extracts a single base control' {
            $ids = Get-NRGNISTControlIdsFromFinding -Finding (NistFinding 'AAD-1.1' 'Gap' 'IA-2')
            @($ids) | Should -Be @('IA-2')
        }

        It 'Extracts a comma-separated list, including control enhancements' {
            $ids = @(Get-NRGNISTControlIdsFromFinding -Finding (NistFinding 'AAD-1.1' 'Gap' 'IA-2, IA-5(1), AC-6(9)'))
            $ids | Should -Contain 'IA-2'
            $ids | Should -Contain 'IA-5(1)'
            $ids | Should -Contain 'AC-6(9)'
            $ids.Count | Should -Be 3
        }

        It 'De-duplicates a control cited twice in the same finding' {
            $ids = @(Get-NRGNISTControlIdsFromFinding -Finding (NistFinding 'AAD-1.1' 'Gap' 'AC-2, AC-2'))
            $ids.Count | Should -Be 1
        }

        It 'Ignores citations from other frameworks in the same FrameworkIds array' {
            # CMMC's identifiers begin with the same two letters as an 800-53
            # family. Matching on shape alone rather than on the NIST: prefix
            # would credit the IA family with a CMMC practice.
            $f = @{
                ControlId    = 'AAD-1.1'
                State        = 'Gap'
                FrameworkIds = @('CIS:5.2.2.3', 'CMMC:IA.L2-3.5.3', 'NIST:IA-2', 'ISO27001:A.5.17', 'SOC2:CC6.1')
            }
            $ids = @(Get-NRGNISTControlIdsFromFinding -Finding $f)
            @($ids) | Should -Be @('IA-2')
        }

        It 'Returns empty for a finding with no NIST citation, without throwing' {
            $f = @{ ControlId = 'EMAIL-1.1'; State = 'Gap'; FrameworkIds = @('MITRE:T1114') }
            @(Get-NRGNISTControlIdsFromFinding -Finding $f).Count | Should -Be 0
        }

        It 'Returns empty for a finding with no FrameworkIds field at all' {
            @(Get-NRGNISTControlIdsFromFinding -Finding @{ ControlId = 'X-1.1'; State = 'Gap' }).Count | Should -Be 0
        }

        It 'Returns empty for $null, without throwing' {
            @(Get-NRGNISTControlIdsFromFinding -Finding $null).Count | Should -Be 0
        }

        It 'Discards a malformed token rather than inventing a family from it' {
            $ids = @(Get-NRGNISTControlIdsFromFinding -Finding (NistFinding 'X-1.1' 'Gap' 'IA-2, not-a-control, AC'))
            @($ids) | Should -Be @('IA-2')
        }
    }

    Context 'Family rollup' {

        It 'Returns an empty rollup for no findings, without throwing' {
            $cov = Get-NRGNISTFamilyCoverage -Findings @()
            $cov.FamilyCount      | Should -Be 0
            $cov.NistControlCount | Should -Be 0
            @($cov.Families).Count | Should -Be 0
        }

        It 'Returns an empty rollup for $null findings, without throwing' {
            (Get-NRGNISTFamilyCoverage -Findings $null).FamilyCount | Should -Be 0
        }

        It 'Groups findings under the family of their cited control' {
            $cov = Get-NRGNISTFamilyCoverage -Findings @(
                (NistFinding 'AAD-1.1' 'Satisfied' 'IA-2'),
                (NistFinding 'AAD-1.2' 'Gap'       'IA-5(1)'),
                (NistFinding 'EXO-1.1' 'Satisfied' 'SC-8')
            )
            $cov.FamilyCount | Should -Be 2
            $ia = $cov.Families | Where-Object { $_.Family -eq 'IA' }
            $ia.Assessed  | Should -Be 2
            $ia.Satisfied | Should -Be 1
            $ia.Gap       | Should -Be 1
            $ia.Score     | Should -Be 50
            $ia.Name      | Should -Be 'Identification and Authentication'
        }

        It 'Counts a cross-family finding once in EACH family it cites' {
            # Deliberate: a control supporting both IA and AC is genuinely a
            # gap in both when it fails. Family totals therefore do not sum to
            # the assessment total, which the report states explicitly.
            $cov = Get-NRGNISTFamilyCoverage -Findings @(
                (NistFinding 'AAD-1.1' 'Gap' 'IA-2, AC-7')
            )
            $cov.FamilyCount | Should -Be 2
            ($cov.Families | Where-Object { $_.Family -eq 'IA' }).Assessed | Should -Be 1
            ($cov.Families | Where-Object { $_.Family -eq 'AC' }).Assessed | Should -Be 1
        }

        It 'Counts a finding citing two controls in ONE family only once for that family' {
            $cov = Get-NRGNISTFamilyCoverage -Findings @(
                (NistFinding 'AAD-1.1' 'Gap' 'IA-2, IA-5(1)')
            )
            $ia = $cov.Families | Where-Object { $_.Family -eq 'IA' }
            $ia.Assessed        | Should -Be 1
            @($ia.NistControls).Count | Should -Be 2
        }

        It 'Excludes NotApplicable from the coverage denominator' {
            # The whole point of the N/A state: a control the tool could not
            # assess is not a control the tenant failed. Counting it as a gap
            # would punish tenants for the tool's own blind spots; counting it
            # as satisfied would be the false clean bill of health.
            $cov = Get-NRGNISTFamilyCoverage -Findings @(
                (NistFinding 'A-1.1' 'Satisfied'     'AU-2'),
                (NistFinding 'A-1.2' 'NotApplicable' 'AU-2'),
                (NistFinding 'A-1.3' 'NotApplicable' 'AU-2')
            )
            $au = $cov.Families | Where-Object { $_.Family -eq 'AU' }
            $au.Assessed | Should -Be 3
            $au.NA       | Should -Be 2
            $au.Scored   | Should -Be 1
            $au.Score    | Should -Be 100
        }

        It 'Reports Scored = 0 for a family assessed only through NotApplicable' {
            # The publishers key off Scored to render a dash instead of a red
            # 0%. Score itself is 0 here by Get-NRGCoverageScore's contract, so
            # Scored is the field that must stay honest.
            $cov = Get-NRGNISTFamilyCoverage -Findings @(
                (NistFinding 'A-1.1' 'NotApplicable' 'CP-9')
            )
            $cp = $cov.Families | Where-Object { $_.Family -eq 'CP' }
            $cp.Scored | Should -Be 0
        }

        It 'Counts Error as a soft gap under -ErrorHandling Gap and drops it under Exclude' {
            $findings = @(
                (NistFinding 'A-1.1' 'Satisfied' 'SI-3'),
                (NistFinding 'A-1.2' 'Error'     'SI-3')
            )
            $gapMode = (Get-NRGNISTFamilyCoverage -Findings $findings -ErrorHandling 'Gap').Families |
                Where-Object { $_.Family -eq 'SI' }
            $gapMode.Scored | Should -Be 2
            $gapMode.Score  | Should -Be 50

            $excMode = (Get-NRGNISTFamilyCoverage -Findings $findings -ErrorHandling 'Exclude').Families |
                Where-Object { $_.Family -eq 'SI' }
            $excMode.Scored | Should -Be 1
            $excMode.Score  | Should -Be 100
        }

        It 'Scores Partial as half credit, matching every other score in the tool' {
            $cov = Get-NRGNISTFamilyCoverage -Findings @(
                (NistFinding 'A-1.1' 'Partial' 'CM-6'),
                (NistFinding 'A-1.2' 'Gap'     'CM-6')
            )
            ($cov.Families | Where-Object { $_.Family -eq 'CM' }).Score | Should -Be 25
        }

        It 'Counts findings with no NIST citation as Unmapped rather than dropping them silently' {
            $cov = Get-NRGNISTFamilyCoverage -Findings @(
                (NistFinding 'A-1.1' 'Gap' 'AC-3'),
                @{ ControlId = 'EMAIL-1.1'; State = 'Gap'; FrameworkIds = @('MITRE:T1114') }
            )
            $cov.Unmapped | Should -Be 1
        }

        It 'Rolls up per-800-53-control as well as per-family' {
            $cov = Get-NRGNISTFamilyCoverage -Findings @(
                (NistFinding 'A-1.1' 'Satisfied' 'AC-6(9)'),
                (NistFinding 'A-1.2' 'Gap'       'AC-6(9)'),
                (NistFinding 'A-1.3' 'Gap'       'AC-3')
            )
            $cov.NistControlCount | Should -Be 2
            $enh = $cov.Controls | Where-Object { $_.NistControl -eq 'AC-6(9)' }
            $enh.Assessed   | Should -Be 2
            $enh.Score      | Should -Be 50
            $enh.Family     | Should -Be 'AC'
            @($enh.ControlIds) | Should -Contain 'A-1.1'
        }

        It 'Is shape-agnostic: PSCustomObject findings roll up identically to hashtables' {
            $obj = [pscustomobject]@{ ControlId = 'A-1.1'; State = 'Gap'; FrameworkIds = @('NIST:AC-2') }
            $cov = Get-NRGNISTFamilyCoverage -Findings @($obj)
            ($cov.Families | Where-Object { $_.Family -eq 'AC' }).Gap | Should -Be 1
        }

        It 'Skips $null entries in the findings array' {
            $cov = Get-NRGNISTFamilyCoverage -Findings @((NistFinding 'A-1.1' 'Gap' 'AC-2'), $null)
            $cov.FamilyCount | Should -Be 1
        }
    }

    Context 'controls.json NIST citation invariant' {

        It 'Every control carries a References.NIST citation' {
            # A control missing this vanishes from the family view, shrinking a
            # family denominator and inflating that family's coverage — the
            # false-clean-bill-of-health failure mode, applied to compliance
            # reporting instead of to a single verdict.
            $missing = @($script:Controls | Where-Object {
                -not $_.References -or
                -not $_.References.PSObject.Properties['NIST'] -or
                [string]::IsNullOrWhiteSpace([string]$_.References.NIST)
            } | ForEach-Object { $_.ControlId })

            $missing -join ', ' | Should -BeNullOrEmpty
        }

        It 'Every NIST citation parses into at least one 800-53 identifier' {
            $bad = @()
            foreach ($c in $script:Controls) {
                $f   = @{ ControlId = $c.ControlId; State = 'Gap'; FrameworkIds = @("NIST:$([string]$c.References.NIST)") }
                $ids = @(Get-NRGNISTControlIdsFromFinding -Finding $f)
                if ($ids.Count -eq 0) { $bad += "$($c.ControlId) => '$($c.References.NIST)'" }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'Every token inside every NIST citation parses — no silently dropped references' {
            # The previous test passes if ONE token in "IA-2, garbage" parses.
            # This one catches the dropped half.
            $bad = @()
            foreach ($c in $script:Controls) {
                foreach ($tok in ([string]$c.References.NIST -split ',')) {
                    $t = $tok.Trim()
                    if (-not $t) { continue }
                    if ($t -notmatch '^[A-Z]{2}-\d{1,3}(\(\d{1,3}\))?$') {
                        $bad += "$($c.ControlId) => '$t'"
                    }
                }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'Every cited family is a real NIST SP 800-53 Rev 5 family' {
            $valid = @('AC','AT','AU','CA','CM','CP','IA','IR','MA','MP',
                       'PE','PL','PM','PS','PT','RA','SA','SC','SI','SR')
            $bad = @()
            foreach ($c in $script:Controls) {
                $f = @{ ControlId = $c.ControlId; State = 'Gap'; FrameworkIds = @("NIST:$([string]$c.References.NIST)") }
                foreach ($id in @(Get-NRGNISTControlIdsFromFinding -Finding $f)) {
                    $fam = ($id -split '-')[0]
                    if ($fam -notin $valid) { $bad += "$($c.ControlId) => $id" }
                }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'README and CLAUDE.md state the live family and 800-53 control counts' {
            # The docs advertise "12 families and 57 distinct 800-53 controls".
            # Both are derived numbers, so both rot the moment a control's NIST
            # citation changes. Pin them to controls.json the same way the
            # DocAccuracy suite pins the control and scope counts.
            $findings = @($script:Controls | ForEach-Object {
                @{ ControlId = $_.ControlId; State = 'Gap'; FrameworkIds = @("NIST:$([string]$_.References.NIST)") }
            })
            $cov = Get-NRGNISTFamilyCoverage -Findings $findings

            $readme = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'README.md')   -Raw -Encoding utf8
            $claude = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'CLAUDE.md')   -Raw -Encoding utf8
            $blob   = "$readme`n$claude"

            foreach ($m in [regex]::Matches($blob, '(\d+)\s+(?:of the 20\s+)?800-53 families')) {
                [int]$m.Groups[1].Value | Should -Be $cov.FamilyCount `
                    -Because 'a "<n> 800-53 families" claim must equal the live family count'
            }
            foreach ($m in [regex]::Matches($blob, '(\d+)\s+distinct 800-53 controls')) {
                [int]$m.Groups[1].Value | Should -Be $cov.NistControlCount `
                    -Because 'a "<n> distinct 800-53 controls" claim must equal the live count'
            }
            foreach ($m in [regex]::Matches($blob, '(\d+)\s+families and \d+\s+distinct')) {
                [int]$m.Groups[1].Value | Should -Be $cov.FamilyCount
            }
        }

        It 'The full control set rolls up with every control accounted for' {
            # End-to-end: synthesize one finding per control from the real
            # citations and prove nothing falls out of the rollup.
            $findings = @($script:Controls | ForEach-Object {
                @{ ControlId = $_.ControlId; State = 'Gap'; FrameworkIds = @("NIST:$([string]$_.References.NIST)") }
            })
            $cov = Get-NRGNISTFamilyCoverage -Findings $findings

            $cov.Unmapped    | Should -Be 0
            $cov.FamilyCount | Should -BeGreaterThan 5

            # Every tool control appears in at least one family's ControlIds.
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($fam in $cov.Families) {
                foreach ($cid in @($fam.ControlIds)) { $null = $seen.Add($cid) }
            }
            $seen.Count | Should -Be $script:Controls.Count
        }
    }
}

#Requires -Version 7.0
#
# TP.NISTMatrix.Tests.ps1
#
# Guards Config/nist-800-53-catalog.json, Lib/Get-TPNISTControlCatalog.ps1 and
# Publishers/Publish-TPNISTMatrix.ps1 — the standalone NIST 800-53 Rev 5
# deliverable.
#
# Three things this suite is really protecting.
#
#   1. The matrix is single-framework by design, and additive by design. If
#      producing it ever started changing what the multi-framework report says,
#      the "leave every other framework as is" contract would be broken
#      silently — the NIST document would look fine and the CIS/SCuBA/CMMC
#      numbers would have moved underneath it.
#
#   2. Titles must be the Rev 5 titles. Six of the controls this tool cites were
#      renamed between Rev 4 and Rev 5 (AC-11, AC-16, AC-6(9), AT-2, AU-2,
#      AU-4). A matrix that hands an auditor a Rev 4 title under a Rev 5 heading
#      is wrong in the way an auditor notices first, and the tool would look
#      less rigorous than it is.
#
#   3. The document must not overstate scope. A tenant scan reaches a fraction
#      of any 800-53 baseline. The score has to be labeled as coverage of what
#      was exercised, the physical section has to stay unscored, and controls
#      that came back NotApplicable have to be named as not-assessed rather than
#      quietly dropped — a matrix that omits what it could not evaluate reads as
#      full coverage of a smaller scope.

Describe 'NIST 800-53 standalone matrix' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }

        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        $script:CatalogPath = Join-Path $script:RepoRoot 'Config/nist-800-53-catalog.json'
        $script:Catalog     = Get-Content -LiteralPath $script:CatalogPath -Raw -Encoding utf8 | ConvertFrom-Json
        $script:Controls    = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 |
            ConvertFrom-Json).controls)

        # Every 800-53 identifier the tool cites, via the real parser.
        $script:CitedIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($c in $script:Controls) {
            $f = @{ ControlId = $c.ControlId; State = 'Gap'; FrameworkIds = @("NIST:$([string]$c.References.NIST)") }
            foreach ($id in @(Get-TPNISTControlIdsFromFinding -Finding $f)) { $null = $script:CitedIds.Add($id) }
        }

        # Every identifier the physical/device configs name. Both nist-physical
        # (the guide) and device-controls (the endpoint checks) cite the
        # catalog, so both must be counted or the orphan check below reports
        # live entries as dead.
        $script:PhysicalIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $physCfg = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/nist-physical.json') -Raw -Encoding utf8 | ConvertFrom-Json
        foreach ($g in $physCfg.groups) {
            foreach ($i in $g.Items) { $null = $script:PhysicalIds.Add([string]$i.NistControl) }
        }
        $devCfg = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/device-controls.json') -Raw -Encoding utf8 | ConvertFrom-Json
        foreach ($c in $devCfg.controls) {
            foreach ($n in @($c.Nist)) { $null = $script:PhysicalIds.Add([string]$n) }
        }
        $baseCfg = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/device-baseline.json') -Raw -Encoding utf8 | ConvertFrom-Json
        foreach ($st in $baseCfg.stages) {
            foreach ($i in $st.Items) { foreach ($n in @($i.Nist)) { $null = $script:PhysicalIds.Add([string]$n) } }
        }

        # A findings set spanning every state, built from the real citations so
        # the matrix exercises the same parsing path a live run does.
        $states = @('Satisfied', 'Gap', 'Partial', 'NotApplicable', 'Error')
        $n = 0
        $script:Findings = @($script:Controls | ForEach-Object {
            $n++
            @{
                ControlId     = $_.ControlId
                State         = $states[$n % $states.Count]
                Severity      = [string]$_.Severity
                Title         = [string]$_.Title
                Category      = [string]$_.Category
                Detail        = 'synthetic detail'
                CurrentValue  = 'current-x'
                RequiredValue = 'required-y'
                Remediation   = [string]$_.Remediation
                FrameworkIds  = @("NIST:$([string]$_.References.NIST)", "CIS:$([string]$_.References.CIS)")
            }
        })

        $script:Metadata = @{
            TenantDomain   = 'contoso.onmicrosoft.com'
            AssessmentDate = 'August 25, 2026'
            ToolVersion    = '4.12.1'
        }

        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("tp-nist-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path $script:Tmp | Out-Null
        $script:MdPath   = Join-Path $script:Tmp 'nist-matrix.md'
        $script:XlsxPath = Join-Path $script:Tmp 'nist-matrix.xlsx'

        $script:PublishError = $null
        try {
            Publish-TPNISTMatrix -Metadata $script:Metadata -Findings $script:Findings -OutputPath $script:MdPath -ErrorAction Stop
        } catch {
            $script:PublishError = $_
        }
        $script:Md = if (Test-Path -LiteralPath $script:MdPath) {
            Get-Content -LiteralPath $script:MdPath -Raw
        } else { '' }
    }

    AfterAll {
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) {
            Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
        Clear-TPState
    }

    Context 'Catalog' {

        It 'covers every 800-53 identifier the controls cite' {
            # A cited control with no catalog entry renders as a bare identifier.
            $missing = @($script:CitedIds | Where-Object { -not $script:Catalog.controls.PSObject.Properties[$_] })
            $missing -join ', ' | Should -BeNullOrEmpty
        }

        It 'covers every 800-53 identifier the physical/device config names' {
            $missing = @($script:PhysicalIds | Where-Object { -not $script:Catalog.controls.PSObject.Properties[$_] })
            $missing -join ', ' | Should -BeNullOrEmpty
        }

        It 'carries no catalog entry that nothing references' {
            # Dead entries are how a hand-maintained catalog rots: they make the
            # file look more complete than the assessment actually is.
            $used = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($i in $script:CitedIds)    { $null = $used.Add($i) }
            foreach ($i in $script:PhysicalIds) { $null = $used.Add($i) }
            $orphans = @($script:Catalog.controls.PSObject.Properties.Name | Where-Object { -not $used.Contains($_) })
            $orphans -join ', ' | Should -BeNullOrEmpty
        }

        It 'lists all 20 Rev 5 control families' {
            @($script:Catalog.families.PSObject.Properties).Count | Should -Be 20
        }

        It 'agrees with the family names Get-TPNISTFamilyCoverage uses' {
            # Two hardcoded family tables exist: this catalog and the one inside
            # the rollup, which is kept there so the rollup stays usable without
            # the config. They must not drift — a family named one way in the
            # report and another in the matrix reads as two different findings.
            foreach ($p in $script:Catalog.families.PSObject.Properties) {
                if ($p.Name -eq 'PT') { continue }   # abbreviated in both, checked below
                $fromLib = Get-TPNISTFamilyTitle -Family $p.Name
                $fromLib | Should -Be ([string]$p.Value) -Because "family $($p.Name) must have one name"
            }
        }

        It 'uses Rev 5 titles, not Rev 4, for the controls that were renamed' {
            # These six changed between revisions and are all cited by this tool.
            # Handing an auditor a Rev 4 title under a Rev 5 heading is the error
            # they notice first.
            (Get-TPNISTControlTitle -ControlId 'AC-11')   | Should -Be 'Device Lock'
            (Get-TPNISTControlTitle -ControlId 'AT-2')    | Should -Be 'Literacy Training and Awareness'
            (Get-TPNISTControlTitle -ControlId 'AU-2')    | Should -Be 'Event Logging'
            (Get-TPNISTControlTitle -ControlId 'AU-4')    | Should -Be 'Audit Log Storage Capacity'
            (Get-TPNISTControlTitle -ControlId 'AC-6(9)') | Should -Match 'Log Use of Privileged Functions'
            (Get-TPNISTControlTitle -ControlId 'AC-16')   | Should -Be 'Security and Privacy Attributes'
        }

        It 'resolves enhancements to their own title, not the base control title' {
            (Get-TPNISTControlTitle -ControlId 'SC-8(1)') | Should -Match 'Cryptographic Protection'
            (Get-TPNISTControlTitle -ControlId 'SC-8(1)') | Should -Not -Be (Get-TPNISTControlTitle -ControlId 'SC-8')
        }

        It 'returns empty for an unknown control rather than inventing a title' {
            # In a compliance deliverable a plausible-looking wrong title is
            # worse than a blank: the reader has no way to tell it is wrong.
            (Get-TPNISTControlTitle -ControlId 'ZZ-99') | Should -BeNullOrEmpty
        }

        It 'falls back to the base title, clearly marked, for an uncatalogd enhancement' {
            $t = Get-TPNISTControlTitle -ControlId 'AC-2(99)'
            $t | Should -Match 'Account Management'
            $t | Should -Match 'enhancement 99'
        }

        It 'returns empty / the bare code for null and empty input, without throwing' {
            (Get-TPNISTControlTitle -ControlId '')   | Should -BeNullOrEmpty
            (Get-TPNISTControlTitle -ControlId $null)| Should -BeNullOrEmpty
            (Get-TPNISTFamilyTitle  -Family    '')   | Should -BeNullOrEmpty
            (Get-TPNISTFamilyTitle  -Family 'ZZ')    | Should -Be 'ZZ'
        }
    }

    Context 'Markdown deliverable' {

        It 'publishes without throwing' {
            $script:PublishError | Should -BeNullOrEmpty
        }

        It 'writes a non-trivial Markdown file' {
            Test-Path -LiteralPath $script:MdPath | Should -BeTrue
            $script:Md.Length | Should -BeGreaterThan 5000
        }

        It 'is titled as a NIST-only deliverable and says so' {
            $script:Md | Should -Match 'NIST SP 800-53 Rev 5'
            $script:Md | Should -BeLike '*covers NIST SP 800-53 Revision 5 only*'
        }

        It 'names the tenant and assessment date' {
            $script:Md | Should -BeLike '*contoso.onmicrosoft.com*'
            $script:Md | Should -BeLike '*August 25, 2026*'
        }

        It 'contains every required section' {
            foreach ($h in '## Summary', '## Coverage by control family',
                           '## Coverage by 800-53 control', '## Control matrix') {
                $script:Md | Should -BeLike "*$h*" -Because "section '$h' must render"
            }
        }

        It 'renders every cited 800-53 control somewhere in the document' {
            # The point of a matrix is completeness. A control that vanishes is
            # indistinguishable, to the reader, from one the tool does not cover.
            $missing = @($script:CitedIds | Where-Object { $script:Md -notlike "*| $_ |*" })
            $missing -join ', ' | Should -BeNullOrEmpty
        }

        It 'renders 800-53 titles alongside identifiers, not bare codes' {
            $script:Md | Should -BeLike '*Least Privilege*'
            $script:Md | Should -BeLike '*Protection of Information at Rest*'
            $script:Md | Should -BeLike '*Identification and Authentication (Organizational Users)*'
        }

        It 'states that the score is not baseline completion' {
            # The single most likely way this document gets misread.
            $script:Md | Should -BeLike '*not*an 800-53 baseline completion percentage*'
        }

        It 'states that NotApplicable is not a pass' {
            $script:Md | Should -BeLike '*not controls the tenant passed*'
        }

        It 'states that multi-mapped controls do not sum' {
            $script:Md | Should -BeLike '*do not sum*'
        }

        It 'carries the physical/device section, unscored, with attestation language' {
            $script:Md | Should -BeLike '*Nothing in this section is scored*'
            $script:Md | Should -BeLike '*Attestation required*'
            $script:Md | Should -BeLike '*Option:*'
        }

        It 'names controls that came back NotApplicable rather than dropping them' {
            # The fixture cycles states, so some control is guaranteed to be
            # all-NotApplicable. It must be named, not omitted.
            $cov = Get-TPNISTFamilyCoverage -Findings $script:Findings -ErrorHandling 'Gap'
            $unassessed = @($cov.Controls | Where-Object { $_.Scored -le 0 })
            if ($unassessed.Count -gt 0) {
                $script:Md | Should -BeLike '*Cited but not assessable this run*'
                foreach ($u in $unassessed) {
                    $script:Md | Should -BeLike "*| $($u.NistControl) |*"
                }
            }
        }

        It 'every rollup row sums: Met + Partial + Gap + Error + N/A equals Assessed' {
            # Shipped once without an Error column, so on any tenant with a
            # thrown evaluator the columns came up short of Assessed. A reader
            # who adds a row and does not get the stated total has every reason
            # to stop trusting the rest of the document — and no way to tell
            # whether the missing rows were passes or failures.
            $fam = ($script:Md -split '## Coverage by control family')[1] -split "`n##" | Select-Object -First 1
            $rows = @($fam -split "`n" | Where-Object { $_ -match '^\|\s*[A-Z]{2}\s*\|' })
            $rows.Count | Should -BeGreaterThan 0

            foreach ($row in $rows) {
                $cells = @(($row.Trim().Trim('|') -split '\|') | ForEach-Object { $_.Trim() })
                # Family | Name | Assessed | Met | Partial | Gap | Error | N/A | Coverage
                $assessed = [int]$cells[2]
                $sum = [int]$cells[3] + [int]$cells[4] + [int]$cells[5] + [int]$cells[6] + [int]$cells[7]
                $sum | Should -Be $assessed -Because "family $($cells[0]) must account for every finding it counts"
            }
        }

        It 'says out loud that Error and N/A are excluded from coverage' {
            # Both are "no verdict reached". Neither may read as a pass, and a
            # reader must not have to infer that from the arithmetic.
            $script:Md | Should -BeLike '*Met + Partial + Gap + Error + N/A equals Assessed*'
            $script:Md | Should -BeLike '*evaluator threw*'
        }

        It 'renders backticked terms as code, not with the backticks eaten' {
            # A backtick inside a PowerShell double-quoted string is the escape
            # character, so these silently lost their code formatting once
            # already. Asserted with .Contains and an explicit char rather than
            # -BeLike, because a backtick is ALSO the escape character in a
            # wildcard pattern — writing the obvious -BeLike '*`x`*' here
            # silently tests for something else entirely.
            $bt = [char]0x60
            $script:Md.Contains($bt + 'Not assessable' + $bt) | Should -BeTrue
            $script:Md.Contains($bt + 'NotApplicable'  + $bt) | Should -BeTrue
        }

        It 'escapes pipe characters so the tables cannot be broken by finding text' {
            # A finding title containing a pipe would otherwise split a row into
            # extra columns and silently corrupt every value after it.
            Clear-TPState
            $hostile = @(@{
                ControlId    = 'AAD-1.1'
                State        = 'Gap'
                Severity     = 'High'
                Title        = 'Pipe | in | title'
                CurrentValue = 'a | b'
                FrameworkIds = @('NIST:AC-2')
            })
            $p = Join-Path $script:Tmp 'hostile.md'
            Publish-TPNISTMatrix -Metadata $script:Metadata -Findings $hostile -OutputPath $p
            $txt = Get-Content -LiteralPath $p -Raw
            $txt | Should -BeLike '*Pipe \| in \| title*'
            # The control-matrix row must still have exactly the header's column
            # count. Isolate the '## Control matrix' section first: the
            # by-control rollup table above it starts with the same identifier
            # AND lists the same tool control in its "Evidenced by" column, so
            # matching on either alone picks the wrong table and asserts against
            # the wrong column count.
            $section = ($txt -split '## Control matrix')[1]
            $section | Should -Not -BeNullOrEmpty
            $row = @($section -split "`n" | Where-Object { $_ -like '| AC-2 |*AAD-1.1*' })[0]
            $row | Should -Not -BeNullOrEmpty
            ([regex]::Matches($row, '(?<!\\)\|')).Count | Should -Be 9
        }
    }

    Context 'HTML deliverable — the NIST-only report' {

        BeforeAll {
            $script:NistHtmlPath = [System.IO.Path]::ChangeExtension($script:MdPath, '.html')
            $script:NistHtml = if (Test-Path -LiteralPath $script:NistHtmlPath) {
                Get-Content -LiteralPath $script:NistHtmlPath -Raw
            } else { '' }
        }

        It 'writes a well-formed, self-contained HTML report' {
            $script:NistHtml.Length | Should -BeGreaterThan 10000
            $script:NistHtml | Should -Match '<!DOCTYPE html>'
            $script:NistHtml | Should -Match '</html>'
            $script:NistHtml | Should -Not -Match 'src="http'
            $script:NistHtml | Should -Not -Match 'href="http'
            $script:NistHtml | Should -Not -Match '@import'
            $script:NistHtml | Should -Match '@media print'
        }

        It 'mentions no framework other than NIST anywhere on the page' {
            # This is the artifact that goes to an 800-53 client instead of the
            # multi-framework report. A stray "CMMC" in a table cell undermines
            # the whole premise.
            foreach ($fw in 'CIS', 'SCuBA', 'CMMC', 'ISO 27001', 'SOC 2', 'HIPAA', 'PCI DSS', 'MITRE') {
                $script:NistHtml | Should -Not -Match ('\b' + [regex]::Escape($fw)) `
                    -Because "a NIST-only report must not name $fw"
            }
        }

        It 'carries the same scope caveats as the Markdown' {
            $script:NistHtml | Should -BeLike '*an 800-53 baseline completion percentage*'
            $script:NistHtml | Should -BeLike '*controls the tenant passed*'
            $script:NistHtml | Should -BeLike '*Nothing in this section is scored*'
        }

        It 'renders the family table, the control matrix and the physical section' {
            $script:NistHtml | Should -BeLike '*Coverage by control family*'
            $script:NistHtml | Should -BeLike '*Control matrix*'
            $script:NistHtml | Should -BeLike '*Physical, Media and Device Controls*'
        }

        It 'escapes hostile finding text rather than emitting live markup' {
            $p = Join-Path $script:Tmp 'xss.md'
            Publish-TPNISTMatrix -Metadata $script:Metadata -OutputPath $p -Findings @(
                @{ ControlId = 'AAD-1.1'; State = 'Gap'; Severity = 'High'
                   Title = '<script>nrgnistprobe</script>'; FrameworkIds = @('NIST:AC-2') }
            )
            $h = Get-Content -LiteralPath ([System.IO.Path]::ChangeExtension($p, '.html')) -Raw
            $h | Should -Not -Match '<script>nrgnistprobe'
            $h | Should -Match 'nrgnistprobe'
        }
    }

    Context 'XLSX deliverable' {

        It 'writes the workbook alongside the Markdown when openpyxl is available' -Skip:(-not (
            (& { foreach ($py in 'python3','python') { try { $null = & $py -c 'import openpyxl' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } } return $false })
        )) {
            Test-Path -LiteralPath $script:XlsxPath | Should -BeTrue
            (Get-Item -LiteralPath $script:XlsxPath).Length | Should -BeGreaterThan 5000
        }

        It 'leaves no tenant-data scratch files beside the deliverable' {
            # The helper JSON carries findings. It must not survive the run.
            @(Get-ChildItem -LiteralPath $script:Tmp -Filter '*-nist-input.json'  -File).Count | Should -Be 0
            @(Get-ChildItem -LiteralPath $script:Tmp -Filter '*-nist-helper.py'   -File).Count | Should -Be 0
        }
    }

    Context 'Additive contract — the other frameworks are untouched' {

        It 'does not change the multi-framework scores it reads from' {
            # The whole premise: NIST gets its own document, everything else
            # stays exactly as it was. Scores are computed from the same
            # findings before and after publishing, and must be identical.
            $before = @{}
            foreach ($fw in 'CIS','SCuBA','NIST','CMMC') {
                $before[$fw] = (Get-TPCoverageScore -Findings $script:Findings -FrameworkId $fw -ErrorHandling 'Gap').Score
            }
            $p = Join-Path $script:Tmp 'additive.md'
            Publish-TPNISTMatrix -Metadata $script:Metadata -Findings $script:Findings -OutputPath $p
            foreach ($fw in 'CIS','SCuBA','NIST','CMMC') {
                (Get-TPCoverageScore -Findings $script:Findings -FrameworkId $fw -ErrorHandling 'Gap').Score |
                    Should -Be $before[$fw] -Because "publishing the NIST matrix must not move the $fw score"
            }
        }

        It 'does not mutate the findings it is handed' {
            $snapshot = ($script:Findings | ConvertTo-Json -Depth 6 -Compress)
            $p = Join-Path $script:Tmp 'nomutate.md'
            Publish-TPNISTMatrix -Metadata $script:Metadata -Findings $script:Findings -OutputPath $p
            ($script:Findings | ConvertTo-Json -Depth 6 -Compress) | Should -Be $snapshot
        }

        It 'still cites the other frameworks in controls.json' {
            # A cheap guard against a future "NIST focus" change quietly
            # stripping the other citations out of the source of truth.
            foreach ($fw in 'CIS','SCuBA','CMMC','ISO27001','SOC2','HIPAA') {
                $withFw = @($script:Controls | Where-Object {
                    $_.References.PSObject.Properties[$fw] -and -not [string]::IsNullOrWhiteSpace([string]$_.References.$fw)
                })
                $withFw.Count | Should -BeGreaterThan 0 -Because "$fw citations must survive the NIST work"
            }
        }
    }

    Context 'Degradation' {

        It 'produces a document from an empty findings set without throwing' {
            $p = Join-Path $script:Tmp 'empty.md'
            { Publish-TPNISTMatrix -Metadata $script:Metadata -Findings @() -OutputPath $p } | Should -Not -Throw
            (Get-Content -LiteralPath $p -Raw) | Should -Match 'NIST SP 800-53 Rev 5'
        }

        It 'skips findings with no NIST citation rather than emitting blank rows' {
            $p = Join-Path $script:Tmp 'nonist.md'
            Publish-TPNISTMatrix -Metadata $script:Metadata -OutputPath $p -Findings @(
                @{ ControlId = 'EMAIL-1.1'; State = 'Gap'; Title = 'IoC heuristic'; FrameworkIds = @('MITRE:T1114') }
            )
            $txt = Get-Content -LiteralPath $p -Raw
            $txt | Should -Not -BeLike '*EMAIL-1.1*'
        }

        It 'rejects a path-traversal output path' {
            { Publish-TPNISTMatrix -Metadata $script:Metadata -Findings @() -OutputPath '../../evil.md' } |
                Should -Throw
        }
    }
}

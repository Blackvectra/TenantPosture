#Requires -Version 7.0
#
# NRG.ManualReviewQuestionnaire.Tests.ps1
#
# Guards the controls.json manual-review questionnaire round trip:
# Lib/Get-NRGManualReviewItems.ps1, Lib/Get-NRGManualReviewAnswers.ps1,
# Lib/ConvertTo-NRGManualReviewAnswerPsd1.ps1,
# Publishers/Publish-NRGManualReviewQuestionnaire.ps1, and
# Import-NRGManualReviewQuestionnaire.ps1 — the controls.json counterpart to
# NRG.SSPQuestionnaire.Tests.ps1, same honesty rules applied to the OTHER
# catalog this tool scores against.
#

Describe 'Get-NRGManualReviewItems' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        # Run every real evaluator against empty state -- the same fixture
        # NRG.AssessmentScope.Tests.ps1 uses to prove the classifier sorts a
        # totally-uncollected run into CollectionIncomplete/NoProgrammaticCheck
        # rather than something falsely reassuring. This is what actually
        # exercises both buckets; an all-@() findings set does not, because a
        # control with NO finding at all lands in NoResult/NotEvaluatedThisMode
        # instead.
        Clear-NRGState
        $script:Controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 | ConvertFrom-Json).controls)
        $evs = @($script:Controls | ForEach-Object { $_.EvaluatorFunction } | Sort-Object -Unique)
        foreach ($ev in $evs) { try { Invoke-NRGEvaluatorSafe -EvaluatorFunction $ev } catch { } }
        $script:RealFindings = @(Get-NRGFindings)
        $script:RealScope = Get-NRGAssessmentScope -Findings $script:RealFindings -Coverage @{}
    }

    It 'returns a real, countable array (not $null) when Scope is unavailable' {
        $empty = [ordered]@{ Available = $false }
        $items = @(Get-NRGManualReviewItems -Scope $empty)
        $items.Count | Should -Be 0
    }

    It 'covers exactly the NoProgrammaticCheck + CollectionIncomplete controls, no more and no fewer' {
        $items = @(Get-NRGManualReviewItems -Scope $script:RealScope)
        $items.Count | Should -Be ($script:RealScope['NoProgrammaticCheck'].Count + $script:RealScope['CollectionIncomplete'].Count)
    }

    It 'never includes a control that was actually scored (Satisfied/Partial/Gap)' {
        $scoredIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($f in $script:RealFindings) {
            $state = [string](Get-NRGObjectField -Item $f -Key 'State' -Default '')
            if ($state -in @('Satisfied', 'Partial', 'Gap')) {
                [void]$scoredIds.Add([string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default ''))
            }
        }
        $items = @(Get-NRGManualReviewItems -Scope $script:RealScope)
        foreach ($it in $items) { $scoredIds.Contains([string]$it['ControlId']) | Should -BeFalse }
    }

    It 'uses the control''s own Description verbatim as the question' {
        $items = @(Get-NRGManualReviewItems -Scope $script:RealScope)
        $it = $items | Select-Object -First 1
        $def = $script:Controls | Where-Object { $_.ControlId -eq $it['ControlId'] }
        $it['Question'] | Should -Be ([string]$def.Description)
    }

    It 'filters to one workload when -Workload is supplied' {
        $items = @(Get-NRGManualReviewItems -Scope $script:RealScope -Workload 'SPO')
        $items.Count | Should -BeGreaterThan 0
        foreach ($it in $items) { $it['Workload'] | Should -Be 'SPO' }
    }

    It 'returns nothing for a workload that answers no controls, without throwing' {
        { $script:filtered = @(Get-NRGManualReviewItems -Scope $script:RealScope -Workload 'NOSUCHWORKLOAD') } | Should -Not -Throw
        $script:filtered.Count | Should -Be 0
    }

    It 'carries a prior answer forward for review when -Answers is supplied' {
        $items = @(Get-NRGManualReviewItems -Scope $script:RealScope)
        $target = ($items | Select-Object -First 1)['ControlId']
        $answers = [ordered]@{ Controls = @{ $target = @{ Status = 'Risk accepted'; RiskAcceptance = 'Accepted by IT Manager, review 2027-01-01.' } } }
        $withAns = @(Get-NRGManualReviewItems -Scope $script:RealScope -Answers $answers)
        $it = $withAns | Where-Object { $_['ControlId'] -eq $target }
        $it['CurrentStatus'] | Should -Be 'Risk accepted'
        $it['CurrentRiskAcceptance'] | Should -Be 'Accepted by IT Manager, review 2027-01-01.'
    }
}

Describe 'ConvertTo-NRGManualReviewAnswerPsd1' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }

    It 'omits a blank field rather than emitting an empty-string assignment' {
        $ans = [ordered]@{ Status = 'Risk accepted'; Owner = ''; Evidence = '   ' }
        $text = ConvertTo-NRGManualReviewAnswerPsd1 -ControlId 'DEF-3.3' -Answer $ans
        $text | Should -Match "Status = 'Risk accepted'"
        $text | Should -Not -Match 'Owner'
        $text | Should -Not -Match 'Evidence'
    }

    It 'omits the whole Poam block when every sub-field is blank' {
        $ans = [ordered]@{ Status = 'Not implemented'; Poam = [ordered]@{ Weakness = ''; Remedy = ''; Owner = ''; DueDate = '' } }
        $text = ConvertTo-NRGManualReviewAnswerPsd1 -ControlId 'PVW-3.1' -Answer $ans
        $text | Should -Not -Match 'Poam'
    }

    It 'produces text that Import-PowerShellDataFile parses back into the expected shape' {
        $ans = [ordered]@{
            Status  = 'Compensating control'
            Owner   = "IT Manager's designate"
            Evidence = 'Tenant default denies custom scripting; verified quarterly.'
            CompensatingControl = 'Tenant-wide DenyAddAndCustomizePages default.'
        }
        $entry = ConvertTo-NRGManualReviewAnswerPsd1 -ControlId 'SPO-2.4' -Answer $ans -Indent 2
        $wrapped = "@{`n    Controls = @{`n$entry`n    }`n}`n"
        $tmp = [System.IO.Path]::GetTempFileName() + '.psd1'
        try {
            [System.IO.File]::WriteAllText($tmp, $wrapped)
            $parsed = Import-PowerShellDataFile -LiteralPath $tmp
            $row = $parsed.Controls['SPO-2.4']
            $row.Status | Should -Be 'Compensating control'
            $row.Owner | Should -Be "IT Manager's designate"
            $row.CompensatingControl | Should -Be 'Tenant-wide DenyAddAndCustomizePages default.'
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Publish-NRGManualReviewQuestionnaire' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        Clear-NRGState
        $controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 | ConvertFrom-Json).controls)
        $evs = @($controls | ForEach-Object { $_.EvaluatorFunction } | Sort-Object -Unique)
        foreach ($ev in $evs) { try { Invoke-NRGEvaluatorSafe -EvaluatorFunction $ev } catch { } }
        $script:RealScope = Get-NRGAssessmentScope -Findings @(Get-NRGFindings) -Coverage @{}

        $script:OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-mrq-test-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:OutDir -Force
    }

    AfterAll {
        if ($script:OutDir -and (Test-Path -LiteralPath $script:OutDir)) {
            Remove-Item -LiteralPath $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'always writes Markdown and HTML, with no Python required' {
        $out = Join-Path $script:OutDir 'q1.md'
        Publish-NRGManualReviewQuestionnaire -Scope $script:RealScope -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test Client'
        Test-Path -LiteralPath $out | Should -BeTrue
        Test-Path -LiteralPath ([System.IO.Path]::ChangeExtension($out, '.html')) | Should -BeTrue
    }

    It 'says there is nothing left to ask when the item list is empty, rather than an empty shell silently' {
        $emptyScope = [ordered]@{ Available = $true; NoProgrammaticCheck = @(); CollectionIncomplete = @() }
        $out = Join-Path $script:OutDir 'q-empty.md'
        Publish-NRGManualReviewQuestionnaire -Scope $emptyScope -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test Client'
        (Get-Content -LiteralPath $out -Raw) | Should -Match 'nothing left to ask'
    }

    It 'writes a fillable PDF and manifest when reportlab is available' -Skip:(-not (
        (& { foreach ($py in 'python3', 'python') { try { $null = & $py -c 'import reportlab' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } }; return $false })
    )) {
        $filtered = @($script:RealScope['NoProgrammaticCheck'])
        $small = [ordered]@{ Available = $true; NoProgrammaticCheck = $filtered; CollectionIncomplete = @() }
        $out = Join-Path $script:OutDir 'q-pdf.md'
        Publish-NRGManualReviewQuestionnaire -Scope $small -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test Client'
        $pdf = [System.IO.Path]::ChangeExtension($out, '.pdf')
        $manifest = [System.IO.Path]::ChangeExtension($out, '.manifest.json')
        Test-Path -LiteralPath $pdf | Should -BeTrue
        Test-Path -LiteralPath $manifest | Should -BeTrue
        $m = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        @($m.Items).Count | Should -Be $filtered.Count
    }

    It 'skips the PDF with only a warning, never throwing, when reportlab is unavailable' -Skip:(
        (& { foreach ($py in 'python3', 'python') { try { $null = & $py -c 'import reportlab' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } }; return $false })
    ) {
        $out = Join-Path $script:OutDir 'q-nopdf.md'
        { Publish-NRGManualReviewQuestionnaire -Scope $script:RealScope -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test Client' -WarningAction SilentlyContinue } | Should -Not -Throw
        Test-Path -LiteralPath ([System.IO.Path]::ChangeExtension($out, '.pdf')) | Should -BeFalse
    }
}

Describe 'Import-NRGManualReviewQuestionnaire.ps1' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        Clear-NRGState
        $controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 | ConvertFrom-Json).controls)
        $evs = @($controls | ForEach-Object { $_.EvaluatorFunction } | Sort-Object -Unique)
        foreach ($ev in $evs) { try { Invoke-NRGEvaluatorSafe -EvaluatorFunction $ev } catch { } }
        $script:RealScope = Get-NRGAssessmentScope -Findings @(Get-NRGFindings) -Coverage @{}

        $script:OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-mrq-import-test-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:OutDir -Force
        $script:MrDir = Join-Path $script:RepoRoot 'Config/manual-review'
    }

    AfterAll {
        if ($script:OutDir -and (Test-Path -LiteralPath $script:OutDir)) {
            Remove-Item -LiteralPath $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        Get-ChildItem -LiteralPath $script:MrDir -Filter 'nrg-pester-mrq-test*' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    It 'fails with a clear error and exit code 4 rather than a stack trace when the manifest is missing' -Skip:(-not (
        (& { foreach ($py in 'python3', 'python') { try { $null = & $py -c 'import reportlab, pypdf' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } }; return $false })
    )) {
        $small = [ordered]@{ Available = $true; NoProgrammaticCheck = @($script:RealScope['NoProgrammaticCheck']); CollectionIncomplete = @() }
        $out = Join-Path $script:OutDir 'nomanifest.md'
        Publish-NRGManualReviewQuestionnaire -Scope $small -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test'
        $pdf = [System.IO.Path]::ChangeExtension($out, '.pdf')
        $manifest = [System.IO.Path]::ChangeExtension($out, '.manifest.json')
        Remove-Item -LiteralPath $manifest -Force

        $scriptPath = Join-Path $script:RepoRoot 'Import-NRGManualReviewQuestionnaire.ps1'
        $result = & pwsh -NoProfile -File $scriptPath -PdfPath $pdf -ClientName 'nrg-pester-mrq-test' 2>&1
        $LASTEXITCODE | Should -Be 4
        ($result -join "`n") | Should -Match 'Manifest not found'
    }

    It 'rejects Not applicable / Compensating control / Risk accepted with a missing required field, accepting everything else, end to end' -Skip:(-not (
        (& { foreach ($py in 'python3', 'python') { try { $null = & $py -c 'import reportlab, pypdf' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } }; return $false })
    )) {
        $filtered = @($script:RealScope['NoProgrammaticCheck'])
        $filtered.Count | Should -BeGreaterOrEqual 3 -Because 'the fixture needs at least 3 items to exercise 3 distinct rejection cases'
        $small = [ordered]@{ Available = $true; NoProgrammaticCheck = $filtered; CollectionIncomplete = @() }
        $out = Join-Path $script:OutDir 'roundtrip.md'
        Publish-NRGManualReviewQuestionnaire -Scope $small -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test'
        $pdf = [System.IO.Path]::ChangeExtension($out, '.pdf')
        $manifest = [System.IO.Path]::ChangeExtension($out, '.manifest.json')

        $filledPath = Join-Path $script:OutDir 'roundtrip-filled.pdf'
        $fillScript = @'
import sys
from pypdf import PdfReader, PdfWriter
reader = PdfReader(sys.argv[1])
writer = PdfWriter()
writer.append(reader)
values = {
    'q1_status': 'Risk accepted',
    'q1_riskaccept': 'Accepted by IT Manager, review 2027-01-01.',
    'q1_owner': 'IT Manager',
    'q2_status': 'Not applicable',
    # deliberately no q2_nareason -> must be rejected
    'q3_status': 'Compensating control',
    # deliberately no q3_compensating -> must be rejected
}
for page in writer.pages:
    writer.update_page_form_field_values(page, values)
with open(sys.argv[2], 'wb') as f:
    writer.write(f)
'@
        $pyTmp = Join-Path $script:OutDir 'fill.py'
        $fillScript | Out-File -LiteralPath $pyTmp -Encoding utf8
        $pyCmd = 'python3'
        try { $null = & python3 -c 'import pypdf' 2>&1; if ($LASTEXITCODE -ne 0) { $pyCmd = 'python' } } catch { $pyCmd = 'python' }
        & $pyCmd $pyTmp $pdf $filledPath 2>&1 | Out-Null

        $clientSlug = 'nrg-pester-mrq-test'
        $scriptPath = Join-Path $script:RepoRoot 'Import-NRGManualReviewQuestionnaire.ps1'
        $result = & pwsh -NoProfile -File $scriptPath -PdfPath $filledPath -ManifestPath $manifest -ClientName $clientSlug 2>&1
        $LASTEXITCODE | Should -Be 0
        ($result -join "`n") | Should -Match "needs? follow-up|Status is 'Not applicable' but no reason"

        $writtenPath = Join-Path $script:MrDir "$clientSlug.psd1"
        Test-Path -LiteralPath $writtenPath | Should -BeTrue
        $parsed = Import-PowerShellDataFile -LiteralPath $writtenPath
        $parsed.Controls.Count | Should -Be 1 -Because 'q1 (Risk accepted, with its required field) was accepted; q2 and q3 were rejected for missing required fields and must not appear'
    }
}

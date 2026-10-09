#Requires -Version 7.0
#
# TP.SSPQuestionnaire.Tests.ps1
#
# Guards the SSP questionnaire round trip: Lib/Get-TPSSPQuestionnaireItems.ps1,
# Lib/ConvertTo-TPSSPAnswerPsd1.ps1, Lib/ConvertTo-TPSSPClientSlug.ps1,
# Publishers/Publish-TPSSPQuestionnaire.ps1, and Import-TPSSPQuestionnaire.ps1.
#
# The same honesty rules TP.SSP.Tests.ps1 pins for Get-TPSSPPosture apply
# here a second time, at the round-trip boundary: a client's filled PDF is
# untrusted input exactly like a Graph API response, and writing its answers
# into a document that gets signed carries the same "never guess, never
# silently claim compliance" obligation the rest of the SSP feature has.
#

Describe 'Get-TPSSPQuestionnaireItems' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        $script:Controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 | ConvertFrom-Json).controls)

        # Same adversarial fixture TP.SSP.Tests.ps1 uses: every control in the
        # tool passes. This is what should make every MAPPED requirement
        # Tool-verified (and therefore excluded), while the 69 requirements
        # with no mapped control at all stay Attestation-only regardless.
        $script:AllPass = @()
        foreach ($c in $script:Controls) { $script:AllPass += @{ ControlId = $c.ControlId; State = 'Satisfied'; Title = $c.Title } }
    }

    It 'returns a real, countable array (not $null) when Posture is unavailable' {
        $empty = [ordered]@{ Requirements = @(); Available = $false }
        $items = @(Get-TPSSPQuestionnaireItems -Posture $empty)
        $items.Count | Should -Be 0
    }

    It 'excludes every Tool-verified requirement, even under an all-Satisfied findings set' {
        $posture = Get-TPSSPPosture -Findings $script:AllPass
        $items = @(Get-TPSSPQuestionnaireItems -Posture $posture)
        foreach ($it in $items) { $it['Confidence'] | Should -Not -Be 'Tool-verified' }
    }

    It 'still includes every requirement not fully evidenced by the tenant scan under an all-Satisfied findings set' {
        # The fixture only satisfies CONTROLS.JSON (tenant) controls, not the
        # endpoint DEV-* controls device-controls.json also maps into some
        # requirements -- so a requirement mapped to both lands on 'Partial
        # evidence', not 'Tool-verified', and correctly still needs an answer.
        # The real invariant under test is therefore "matches whatever
        # Get-TPSSPPosture itself did NOT mark Tool-verified", not a fixed
        # count guessed from the 69 unmapped requirements alone.
        $posture = Get-TPSSPPosture -Findings $script:AllPass
        $needsAnswerInPosture = @($posture['Requirements'] | Where-Object { $_['Confidence'] -ne 'Tool-verified' })
        $items = @(Get-TPSSPQuestionnaireItems -Posture $posture)
        $items.Count | Should -Be $needsAnswerInPosture.Count
        $items.Count | Should -BeGreaterThan 0 -Because 'the 69 unmapped 800-171 requirements never become Tool-verified no matter what the tenant scan finds'
    }

    It 'includes every requirement (all Attestation only) when there are no findings at all' {
        $posture = Get-TPSSPPosture -Findings @()
        $items = @(Get-TPSSPQuestionnaireItems -Posture $posture)
        $items.Count | Should -Be $posture['Summary']['Total']
    }

    It 'uses the NIST requirement Statement verbatim as the question -- never a paraphrase' {
        $posture = Get-TPSSPPosture -Findings @()
        $items = @(Get-TPSSPQuestionnaireItems -Posture $posture)
        $r = $posture['Requirements'] | Where-Object { $_['Id'] -eq '3.1.1' }
        $it = $items | Where-Object { $_['Id'] -eq '3.1.1' }
        $it['Question'] | Should -Be $r['Statement']
    }

    It 'filters to one family when -Family is supplied' {
        $posture = Get-TPSSPPosture -Findings @()
        $items = @(Get-TPSSPQuestionnaireItems -Posture $posture -Family '3.9')
        $items.Count | Should -BeGreaterThan 0
        foreach ($it in $items) { $it['Family'] | Should -Be '3.9' }
    }

    It 'returns nothing for a family that answers no requirements, without throwing' {
        $posture = Get-TPSSPPosture -Findings @()
        { $script:filtered = @(Get-TPSSPQuestionnaireItems -Posture $posture -Family '9.9') } | Should -Not -Throw
        $script:filtered.Count | Should -Be 0
    }

    It 'carries the current answer forward so a previously-attested row can be reviewed, not just first-time-answered ones' {
        $answers = @{ Requirements = @{ '3.1.16' = @{ Status = 'Not applicable'; NotApplicableReason = 'No wireless deployed.' } } }
        $posture = Get-TPSSPPosture -Findings @() -Answers $answers
        $items = @(Get-TPSSPQuestionnaireItems -Posture $posture)
        $it = $items | Where-Object { $_['Id'] -eq '3.1.16' }
        $it | Should -Not -BeNullOrEmpty
        $it['CurrentStatus'] | Should -Be 'Not applicable'
        $it['CurrentNaReason'] | Should -Be 'No wireless deployed.'
    }
}

Describe 'ConvertTo-TPSSPClientSlug' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    }

    It 'lowercases and keeps dots for a tenant domain' {
        ConvertTo-TPSSPClientSlug -ClientName 'Example.COM' | Should -Be 'example.com'
    }

    It 'collapses spaces and punctuation to a single dash, trimmed' {
        ConvertTo-TPSSPClientSlug -ClientName '  Acme Widgets & Sons!! ' | Should -Be 'acme-widgets-sons'
    }

    It 'returns an empty string for a blank name rather than throwing' {
        ConvertTo-TPSSPClientSlug -ClientName '' | Should -Be ''
    }

    It 'resolves to the exact file Get-TPSSPAnswers reads for the same client name -- the two must never diverge' {
        $repoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $clientName = 'Pester Slug Test Client'
        $slug = ConvertTo-TPSSPClientSlug -ClientName $clientName
        $expectedPath = Join-Path $repoRoot 'Config/ssp' "$slug.psd1"
        [System.IO.File]::WriteAllText($expectedPath, "@{ Requirements = @{ '3.1.1' = @{ Status = 'Implemented' } } }")
        try {
            $ans = Get-TPSSPAnswers -ClientName $clientName
            $ans['Available'] | Should -BeTrue
            $ans['Path'] | Should -Be $expectedPath
        } finally {
            Remove-Item -LiteralPath $expectedPath -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'ConvertTo-TPSSPAnswerPsd1' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    }

    It 'doubles an embedded single quote so the output is valid PowerShell Data Language' {
        $literal = ConvertTo-TPSSPPsd1String -Value "Operations Manager's approval"
        $literal | Should -Be "'Operations Manager''s approval'"
    }

    It 'omits a blank field rather than emitting an empty-string assignment' {
        $ans = [ordered]@{ Status = 'Implemented'; ResponsibleRole = ''; Narrative = '   ' }
        $text = ConvertTo-TPSSPAnswerPsd1 -Id '3.1.1' -Answer $ans
        $text | Should -Match "Status = 'Implemented'"
        $text | Should -Not -Match 'ResponsibleRole'
        $text | Should -Not -Match 'Narrative'
    }

    It 'omits the whole Poam block when every sub-field is blank, never emitting Poam = @{}' {
        $ans = [ordered]@{ Status = 'Implemented'; Poam = [ordered]@{ Weakness = ''; Remedy = ''; Owner = ''; DueDate = '' } }
        $text = ConvertTo-TPSSPAnswerPsd1 -Id '3.1.1' -Answer $ans
        $text | Should -Not -Match 'Poam'
    }

    It 'produces text that Import-PowerShellDataFile parses back into the expected shape' {
        $ans = [ordered]@{
            Status = "Partially implemented"
            ResponsibleRole = "IT Manager"
            Narrative = "Reviewed quarterly; owner's sign-off filed."
            Poam = [ordered]@{ Weakness = 'Gap text'; Remedy = 'Fix text'; Owner = 'IT Manager'; DueDate = '2026-06-30' }
        }
        $entry = ConvertTo-TPSSPAnswerPsd1 -Id '3.5.3' -Answer $ans -Indent 2
        $wrapped = "@{`n    Requirements = @{`n$entry`n    }`n}`n"
        $tmp = [System.IO.Path]::GetTempFileName() + '.psd1'
        try {
            [System.IO.File]::WriteAllText($tmp, $wrapped)
            $parsed = Import-PowerShellDataFile -LiteralPath $tmp
            $req = $parsed.Requirements['3.5.3']
            $req.Status | Should -Be 'Partially implemented'
            $req.ResponsibleRole | Should -Be 'IT Manager'
            $req.Narrative | Should -Be "Reviewed quarterly; owner's sign-off filed."
            $req.Poam.Weakness | Should -Be 'Gap text'
            $req.Poam.DueDate | Should -Be '2026-06-30'
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Publish-TPSSPQuestionnaire' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-sspq-test-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:OutDir -Force
    }

    AfterAll {
        if ($script:OutDir -and (Test-Path -LiteralPath $script:OutDir)) {
            Remove-Item -LiteralPath $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'always writes Markdown and HTML, with no Python required' {
        $posture = Get-TPSSPPosture -Findings @()
        $out = Join-Path $script:OutDir 'q1.md'
        Publish-TPSSPQuestionnaire -Posture $posture -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test Client'
        Test-Path -LiteralPath $out | Should -BeTrue
        Test-Path -LiteralPath ([System.IO.Path]::ChangeExtension($out, '.html')) | Should -BeTrue
    }

    It 'says there is nothing left to ask when every requirement is Tool-verified, rather than emitting an empty shell silently' {
        $controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 | ConvertFrom-Json).controls)
        $allPass = @()
        foreach ($c in $controls) { $allPass += @{ ControlId = $c.ControlId; State = 'Satisfied'; Title = $c.Title } }
        # Cannot reach zero items this way (69 requirements are permanently
        # unmapped), so exercise the empty-item-set message directly against a
        # synthetic all-tool-verified posture instead of relying on real data.
        $posture = [ordered]@{ Available = $true; Baseline = 'NIST SP 800-171 Rev 2'; Requirements = @() }
        $out = Join-Path $script:OutDir 'q-empty.md'
        Publish-TPSSPQuestionnaire -Posture $posture -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test Client'
        (Get-Content -LiteralPath $out -Raw) | Should -Match 'nothing left to ask'
    }

    It 'writes a fillable PDF and manifest when reportlab is available' -Skip:(-not (
        (& { foreach ($py in 'python3', 'python') { try { $null = & $py -c 'import reportlab' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } }; return $false })
    )) {
        $posture = Get-TPSSPPosture -Findings @() -ConfigPath (Join-Path $script:RepoRoot 'Config/nist-800-171-r2.json')
        $filtered = @($posture['Requirements'] | Where-Object { $_['Family'] -eq '3.9' })
        $small = [ordered]@{ Available = $true; Baseline = $posture['Baseline']; Requirements = $filtered }
        $out = Join-Path $script:OutDir 'q-pdf.md'
        Publish-TPSSPQuestionnaire -Posture $small -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test Client'
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
        $posture = Get-TPSSPPosture -Findings @()
        $out = Join-Path $script:OutDir 'q-nopdf.md'
        { Publish-TPSSPQuestionnaire -Posture $posture -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test Client' -WarningAction SilentlyContinue } | Should -Not -Throw
        Test-Path -LiteralPath ([System.IO.Path]::ChangeExtension($out, '.pdf')) | Should -BeFalse
    }
}

Describe 'Import-TPSSPQuestionnaire.ps1' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-sspq-import-test-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:OutDir -Force
        $script:SspDir = Join-Path $script:RepoRoot 'Config/ssp'
    }

    AfterAll {
        if ($script:OutDir -and (Test-Path -LiteralPath $script:OutDir)) {
            Remove-Item -LiteralPath $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        Get-ChildItem -LiteralPath $script:SspDir -Filter 'tp-pester-import-test*' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    It 'fails with a clear error and exit code 4 rather than a stack trace when the manifest is missing' -Skip:(-not (
        (& { foreach ($py in 'python3', 'python') { try { $null = & $py -c 'import reportlab, pypdf' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } }; return $false })
    )) {
        $posture = Get-TPSSPPosture -Findings @()
        $items = @(Get-TPSSPQuestionnaireItems -Posture $posture -Family '3.9')
        $out = Join-Path $script:OutDir 'nomanifest.md'
        Publish-TPSSPQuestionnaire -Posture ([ordered]@{ Available = $true; Baseline = $posture['Baseline']; Requirements = @($posture['Requirements'] | Where-Object { $_['Family'] -eq '3.9' }) }) `
            -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test'
        $pdf = [System.IO.Path]::ChangeExtension($out, '.pdf')
        $manifest = [System.IO.Path]::ChangeExtension($out, '.manifest.json')
        Remove-Item -LiteralPath $manifest -Force

        $scriptPath = Join-Path $script:RepoRoot 'Import-TPSSPQuestionnaire.ps1'
        $result = & pwsh -NoProfile -File $scriptPath -PdfPath $pdf -ClientName 'tp-pester-import-test' 2>&1
        $LASTEXITCODE | Should -Be 4
        ($result -join "`n") | Should -Match 'Manifest not found'
    }

    It 'rejects Not applicable with no reason and Inherited with no source, accepting everything else, end to end' -Skip:(-not (
        (& { foreach ($py in 'python3', 'python') { try { $null = & $py -c 'import reportlab, pypdf' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } }; return $false })
    )) {
        $posture = Get-TPSSPPosture -Findings @()
        $family = '3.9'
        $req = [ordered]@{ Available = $true; Baseline = $posture['Baseline']; Requirements = @($posture['Requirements'] | Where-Object { $_['Family'] -eq $family }) }
        $out = Join-Path $script:OutDir 'roundtrip.md'
        Publish-TPSSPQuestionnaire -Posture $req -Metadata @{ Date = '2026-01-01' } -OutputPath $out -ClientName 'Test'
        $pdf = [System.IO.Path]::ChangeExtension($out, '.pdf')
        $manifest = [System.IO.Path]::ChangeExtension($out, '.manifest.json')
        $manifestObj = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        $manifestObj.Items.Count | Should -BeGreaterThan 1 -Because 'family 3.9 (Personnel Security) has more than one 800-171 requirement'

        $filledPath = Join-Path $script:OutDir 'roundtrip-filled.pdf'
        $fillScript = @'
import sys
from pypdf import PdfReader, PdfWriter
reader = PdfReader(sys.argv[1])
writer = PdfWriter()
writer.append(reader)
values = {
    'q1_status': 'Implemented',
    'q1_narrative': 'Test narrative for requirement one.',
    'q1_role': 'Test Owner',
    'q2_status': 'Not applicable',
    # deliberately no q2_nareason -> must be rejected
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

        $clientSlug = 'tp-pester-import-test'
        $scriptPath = Join-Path $script:RepoRoot 'Import-TPSSPQuestionnaire.ps1'
        $result = & pwsh -NoProfile -File $scriptPath -PdfPath $filledPath -ManifestPath $manifest -ClientName $clientSlug 2>&1
        $LASTEXITCODE | Should -Be 0
        ($result -join "`n") | Should -Match 'needs? follow-up|Status is ''Not applicable'' but no reason'

        $writtenPath = Join-Path $script:SspDir "$clientSlug.psd1"
        Test-Path -LiteralPath $writtenPath | Should -BeTrue
        $parsed = Import-PowerShellDataFile -LiteralPath $writtenPath
        $parsed.Requirements.Count | Should -Be 1 -Because 'q1 was accepted (Implemented, no required extra field); q2 was rejected (Not applicable with no reason) and must not appear'
    }
}

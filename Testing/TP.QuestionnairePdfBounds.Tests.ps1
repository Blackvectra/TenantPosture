#Requires -Version 7.0
#
# TP.QuestionnairePdfBounds.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# A filled questionnaire PDF comes back from the client by email: untrusted input,
# handed to pypdf, which has shipped fixes for crafted files that loop or exhaust
# memory. Before this the two importers each parsed it with no size cap, no time
# limit and no version floor. These tests pin the one bounded reader: both
# importers use it and parse nothing themselves; a file above the cap, empty, or
# without a PDF header is refused before Python starts; the watchdog ends the
# interpreter at the limit; a pypdf below the floor is refused by version; and a
# real PDF still reads.

BeforeDiscovery {
    # -Skip is decided at discovery, before BeforeAll runs, so the probes live here.
    $script:Py = $null
    foreach ($py in 'python3', 'python') { if (Get-Command $py -ErrorAction SilentlyContinue) { $script:Py = $py; break } }
    $script:HavePypdf = $false
    if ($script:Py) { try { $null = & $script:Py -E -c 'import pypdf' 2>&1; $script:HavePypdf = ($LASTEXITCODE -eq 0) } catch { } }
}

Describe 'Questionnaire PDF import is bounded' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module TenantPosture
        $script:Py = $null
        foreach ($py in 'python3', 'python') { if (Get-Command $py -ErrorAction SilentlyContinue) { $script:Py = $py; break } }
        $script:Reader = & $script:Mod { $script:TPQuestionnairePythonReader }
        $script:Dir = Join-Path $TestDrive 'pdf'; New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
        # A minimal PDF with one page and no form. The cross-reference offsets are not
        # exact; pypdf rebuilds the table in its default non-strict mode, which is the
        # mode the reader uses.
        $script:MinimalPdf = "%PDF-1.4`n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj`n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj`n3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >> endobj`nxref`n0 4`n0000000000 65535 f `n0000000009 00000 n `n0000000058 00000 n `n0000000115 00000 n `ntrailer << /Size 4 /Root 1 0 R >>`nstartxref`n190`n%%EOF`n"
    }
    AfterAll { Remove-Module TenantPosture -Force -ErrorAction SilentlyContinue }

    It 'both importers read the PDF through Read-TPQuestionnaireFields and parse nothing themselves' {
        foreach ($name in 'Import-TPSSPQuestionnaire.ps1', 'Import-TPManualReviewQuestionnaire.ps1') {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot $name) -Raw
            $src | Should -Match 'Read-TPQuestionnaireFields -PdfPath \$PdfPath -Python \$pythonCmd' -Because "$name must use the one bounded reader"
            $src | Should -Not -Match 'PdfReader' -Because "$name must not parse the PDF itself"
            $src | Should -Not -Match 'from pypdf' -Because "$name must not parse the PDF itself"
        }
        (Get-Command Read-TPQuestionnaireFields -Module TenantPosture) | Should -Not -BeNullOrEmpty -Because 'the importers are scripts outside the module'
    }

    It 'the bounds are the stated ones' {
        (& $script:Mod { $script:TPQuestionnairePdfMaxBytes })   | Should -Be 32MB
        (& $script:Mod { $script:TPQuestionnairePdfTimeoutSec }) | Should -Be 60
        (& $script:Mod { $script:TPQuestionnairePypdfFloor })    | Should -Be '4.0.0'
    }

    It 'refuses a file above the size cap before Python starts' {
        # A Python that does not exist: if the cap were checked after Python ran, the
        # failure would be about the interpreter, not the size.
        $big = Join-Path $script:Dir 'big.pdf'
        [System.IO.File]::WriteAllBytes($big, [byte[]]::new(4096))
        { Read-TPQuestionnaireFields -PdfPath $big -Python 'tp-no-such-python' -MaxBytes 2048 } | Should -Throw '*above the*'
    }

    It 'refuses an empty file and a file without a PDF header before Python starts' {
        $empty = Join-Path $script:Dir 'empty.pdf'; [System.IO.File]::WriteAllBytes($empty, [byte[]]::new(0))
        { Read-TPQuestionnaireFields -PdfPath $empty -Python 'tp-no-such-python' } | Should -Throw '*is empty*'
        $text = Join-Path $script:Dir 'text.pdf'; Set-Content -LiteralPath $text -Value 'hello, not a pdf' -Encoding utf8
        { Read-TPQuestionnaireFields -PdfPath $text -Python 'tp-no-such-python' } | Should -Throw '*not a PDF*'
        { Read-TPQuestionnaireFields -PdfPath $script:Dir -Python 'tp-no-such-python' } | Should -Throw '*is a folder*'
    }

    It 'the Python helper takes its paths, limit and floor from argv, never from the source' {
        $script:Reader | Should -Match 'sys\.argv\[1\]'
        $script:Reader | Should -Match 'sys\.argv\[2\]'
        $script:Reader | Should -Match 'int\(sys\.argv\[3\]\)'
        $script:Reader | Should -Match 'sys\.argv\[4\]'
        $script:Reader | Should -Match 'get_fields\(\)' -Because 'only the AcroForm values are read'
        $script:Reader | Should -Not -Match 'extract_text|\.pages\b' -Because 'page content is never parsed'
        $script:Reader | Should -Match 'os\._exit\(124\)'
    }

    It 'the watchdog ends the interpreter at the limit, on this platform' -Skip:(-not $script:Py) {
        # The watchdog prologue (everything before the pypdf import) with a sleep in
        # place of the read: exit 124 well before the sleep would end.
        $prologue = ($script:Reader -split 'import pypdf')[0]
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = Invoke-TPPython -Python $script:Py -Script ($prologue + "import time`ntime.sleep(30)`n") -Arguments @('x', 'y', '1', '4.0.0')
        $sw.Stop()
        $LASTEXITCODE | Should -Be 124
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 15
    }

    It 'refuses a pypdf below the floor, naming its version' -Skip:(-not $script:Py) {
        # A stand-in pypdf on the path (the helper strips only the current directory).
        $fake = Join-Path $script:Dir 'fakepath'; New-Item -ItemType Directory -Path (Join-Path $fake 'pypdf') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $fake 'pypdf' '__init__.py') -Value "__version__ = '3.9.0'" -Encoding utf8
        $pathLiteral = ($fake | ConvertTo-Json -Compress)
        $out = Invoke-TPPython -Python $script:Py -Script ("import sys; sys.path.insert(0, $pathLiteral)`n" + $script:Reader) -Arguments @('x', 'y', '30', '4.0.0')
        $LASTEXITCODE | Should -Be 3
        (($out | ForEach-Object { [string]$_ }) -join "`n") | Should -Match 'pypdf 3\.9\.0 is older than the 4\.0\.0 floor'
    }

    It 'reads a real PDF with no form as an empty map' -Skip:(-not $script:HavePypdf) {
        $pdf = Join-Path $script:Dir 'minimal.pdf'
        [System.IO.File]::WriteAllBytes($pdf, [System.Text.Encoding]::ASCII.GetBytes($script:MinimalPdf))
        $map = Read-TPQuestionnaireFields -PdfPath $pdf -Python $script:Py
        $map | Should -BeOfType [hashtable]
        $map.Count | Should -Be 0
    }
}

#Requires -Version 7.0
#
# TP.PythonIsolation.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Every Python call goes through Invoke-TPPython / Test-TPPythonModule: the
# script goes in on stdin (no helper file is written) and the current directory
# is dropped from sys.path before anything is imported, so a planted openpyxl.py
# or json.py in the output folder or the operator's shell directory cannot be
# imported in place of the real library. The sensitive-file writer replaces a
# planted link instead of writing through it.

Describe 'Python runs through the helper; the sensitive writer never follows a link' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Py = (Get-Command python3, python -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        $script:HaveOpenpyxl = $false
        if ($script:Py) { $script:HaveOpenpyxl = Test-TPPythonModule -Python $script:Py -Module 'openpyxl' }
        $script:Sources = @(Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -Include '*.ps1' -File | Where-Object { $_.FullName -notmatch '[\\/](Testing|output|\.git)[\\/]' })
    }
    AfterAll { Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    It 'every Python invocation outside Lib/Invoke-TPPython.ps1 goes through the helper, and no helper .py file path is built' {
        $bad = foreach ($f in $script:Sources) {
            if ($f.Name -eq 'Invoke-TPPython.ps1') { continue }
            $t = Get-Content -LiteralPath $f.FullName -Raw
            foreach ($m in [regex]::Matches($t, '& \$(py|pythonCmd|Python)\b[^\r\n]*')) {
                if ($m.Value -notmatch '--version' -and $m.Value -notmatch '\s-I -m pip\b') { "$($f.Name): $($m.Value.Trim())" }
            }
            if ($t -match '\$pyTmp') { "$($f.Name): still builds a helper file path" }
        }
        @($bad) | Should -BeNullOrEmpty
    }

    It 'the helper drops the current directory from sys.path and keeps the user site' {
        if (-not $script:Py) { Set-ItResult -Skipped -Because 'python is not available'; return }
        $d = Join-Path $TestDrive 'cwd'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $d 'json.py') -Value "raise SystemExit('HIJACKED')`n" -Encoding utf8
        Push-Location $d
        try {
            $out = Invoke-TPPython -Python $script:Py -Script "import json, site; print('ok' if json.dumps(1) == '1' else 'bad'); print('site' if site.ENABLE_USER_SITE is not False else 'nosite')"
            ($out | Out-String) | Should -Match 'ok'
            ($out | Out-String) | Should -Not -Match 'HIJACKED'
            ($out | Out-String) | Should -Match 'site' -Because '-I is not used: a pip install --user library must stay importable'
            $env:PYTHONPATH = $d
            try { $out2 = Invoke-TPPython -Python $script:Py -Script "import json; print('ok2')" } finally { Remove-Item Env:\PYTHONPATH -ErrorAction SilentlyContinue }
            ($out2 | Out-String) | Should -Match 'ok2' -Because 'PYTHON* variables are ignored (-E)'
            Test-TPPythonModule -Python $script:Py -Module 'json' | Should -BeTrue
            Test-TPPythonModule -Python $script:Py -Module 'tp_no_such_module_x' | Should -BeFalse
        } finally { Pop-Location }
    }

    It 'a planted module in the output folder and the current directory is not imported' {
        if (-not $script:HaveOpenpyxl) { Set-ItResult -Skipped -Because 'python with openpyxl is not available'; return }
        $out = Join-Path $TestDrive 'out'; New-Item -ItemType Directory -Path $out -Force | Out-Null
        $planted = "raise SystemExit('HIJACKED')`n"
        foreach ($d in @($out, $TestDrive)) {
            foreach ($n in 'openpyxl.py', 'json.py', 'sys.py') { Set-Content -LiteralPath (Join-Path $d $n) -Value $planted -Encoding utf8 }
        }
        Push-Location $TestDrive
        try {
            $f = @(@{ ControlId = 'AAD-1.1'; State = 'Gap'; Severity = 'High'; Category = 'Identity'; Title = 't'; Detail = 'd'; CurrentValue = 'c'; RequiredValue = 'r'; Remediation = 'm'; FrameworkIds = 'NIST:IA-2'; AffectedObjects = @() })
            $xlsx = Join-Path $out 'm.xlsx'
            $r = Publish-TPComplianceMatrix -Metadata @{ TenantDomain = 'example.com'; AssessmentDate = 'October 11, 2026'; ToolVersion = '4.14.3'; Operator = 'o' } -Findings $f -OutputPath $xlsx 2>&1
            ($r | Out-String) | Should -Not -Match 'HIJACKED'
            Test-Path -LiteralPath $xlsx | Should -BeTrue -Because 'the real openpyxl was imported'
            @(Get-ChildItem -LiteralPath $out -Filter '*.py') | Where-Object { $_.Name -notin 'openpyxl.py', 'json.py', 'sys.py' } | Should -BeNullOrEmpty -Because 'no helper script is written'
        } finally { Pop-Location }
    }

    It 'Set-TPSensitiveFileContent replaces a planted symbolic link and never writes through it' {
        $d = Join-Path $TestDrive 'link'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $victim = Join-Path $d 'victim.txt'; Set-Content -LiteralPath $victim -Value 'ORIGINAL' -Encoding utf8
        $link = Join-Path $d 'planted-results.json'
        try { New-Item -ItemType SymbolicLink -Path $link -Target $victim -ErrorAction Stop | Out-Null }
        catch { Set-ItResult -Skipped -Because "symbolic links cannot be created here: $($_.Exception.Message)"; return }
        Set-TPSensitiveFileContent -Path $link -Content '{"tenant":"secret"}'
        (Get-Content -LiteralPath $victim -Raw).Trim() | Should -Be 'ORIGINAL' -Because 'the link target is never written'
        [string](Get-Item -LiteralPath $link -Force).LinkType | Should -BeNullOrEmpty -Because 'the output name is now an ordinary file'
        (Get-Content -LiteralPath $link -Raw) | Should -Be '{"tenant":"secret"}'
        @(Get-ChildItem -LiteralPath $d -Force -Filter '*.tmp') | Should -BeNullOrEmpty -Because 'no temp file is left behind'
    }

    It 'the installer loads the Python helper before probing' {
        (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Install-TPPrerequisites.ps1') -Raw) | Should -Match "\. \(Join-Path \`$PSScriptRoot 'Lib/Invoke-TPPython\.ps1'\)"
    }

    It 'Set-TPSensitiveFileContent still writes an ordinary new or existing file' {
        $d = Join-Path $TestDrive 'plain'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $p = Join-Path $d 'r.json'
        Set-TPSensitiveFileContent -Path $p -Content 'one'
        Set-TPSensitiveFileContent -Path $p -Content 'two'
        (Get-Content -LiteralPath $p -Raw) | Should -Be 'two'
        if (-not $IsWindows) { (& stat -c '%a' $p).Trim() | Should -Be '600' }
        { Set-TPSensitiveFileContent -Path $d -Content 'x' } | Should -Throw -ExpectedMessage '*is a directory*'
    }
}

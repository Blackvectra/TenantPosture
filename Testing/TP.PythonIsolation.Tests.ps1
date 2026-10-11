#Requires -Version 7.0
#
# TP.PythonIsolation.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Python helpers run isolated (-I) with the script on stdin: no helper file is
# written, and neither the output folder, the temp folder nor the current
# directory is on sys.path, so a planted openpyxl.py or json.py cannot be
# imported in place of the real library. The sensitive-file writer refuses to
# write through a link.

Describe 'Python helpers run isolated; the sensitive writer refuses links' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Py = (Get-Command python3, python -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        $script:HaveOpenpyxl = $false
        if ($script:Py) { & $script:Py -I -c 'import openpyxl' 2>$null; $script:HaveOpenpyxl = ($LASTEXITCODE -eq 0) }
        $script:Sources = @(Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -Include '*.ps1' -File | Where-Object { $_.FullName -notmatch '[\\/](Testing|output|\.git)[\\/]' })
    }
    AfterAll { Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    It 'every Python invocation in the tool passes -I and no helper .py file path is built' {
        $bad = foreach ($f in $script:Sources) {
            $t = Get-Content -LiteralPath $f.FullName -Raw
            foreach ($m in [regex]::Matches($t, '& \$(py|pythonCmd)\b[^\r\n]*')) {
                if ($m.Value -notmatch '\s-I\s' -and $m.Value -notmatch '--version' -and $m.Value -notmatch '-m pip') { "$($f.Name): $($m.Value.Trim())" }
            }
            if ($t -match '\$pyTmp') { "$($f.Name): still builds a helper file path" }
        }
        @($bad) | Should -BeNullOrEmpty
    }

    It 'a planted module in the output folder, the temp folder and the current directory is not imported' {
        if (-not $script:HaveOpenpyxl) { Set-ItResult -Skipped -Because 'python with openpyxl is not available'; return }
        $out = Join-Path $TestDrive 'out'; New-Item -ItemType Directory -Path $out -Force | Out-Null
        $planted = "raise SystemExit('HIJACKED')`n"
        foreach ($d in @($out, [System.IO.Path]::GetTempPath(), $TestDrive)) {
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
        } finally {
            Pop-Location
            foreach ($n in 'openpyxl.py', 'json.py', 'sys.py') { Remove-Item -LiteralPath (Join-Path ([System.IO.Path]::GetTempPath()) $n) -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'Set-TPSensitiveFileContent refuses to write through a symbolic link and leaves the target alone' {
        $d = Join-Path $TestDrive 'link'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $victim = Join-Path $d 'victim.txt'; Set-Content -LiteralPath $victim -Value 'ORIGINAL' -Encoding utf8
        $link = Join-Path $d 'planted-results.json'
        try { New-Item -ItemType SymbolicLink -Path $link -Target $victim -ErrorAction Stop | Out-Null }
        catch { Set-ItResult -Skipped -Because "symbolic links cannot be created here: $($_.Exception.Message)"; return }
        { Set-TPSensitiveFileContent -Path $link -Content '{"tenant":"secret"}' } | Should -Throw -ExpectedMessage '*will not be written through*'
        (Get-Content -LiteralPath $victim -Raw).Trim() | Should -Be 'ORIGINAL'
    }

    It 'Set-TPSensitiveFileContent still writes an ordinary new or existing file' {
        $d = Join-Path $TestDrive 'plain'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $p = Join-Path $d 'r.json'
        Set-TPSensitiveFileContent -Path $p -Content 'one'
        Set-TPSensitiveFileContent -Path $p -Content 'two'
        (Get-Content -LiteralPath $p -Raw) | Should -Be 'two'
    }
}

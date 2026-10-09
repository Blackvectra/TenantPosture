#Requires -Version 7.0
#
# TP.PsLiteral.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# One quoting rule for generated PowerShell: a curly quote (U+2018..U+201B) ends a
# single-quoted literal, so doubling the ASCII apostrophe alone is not enough. A
# generated SCRIPT withholds such a value; a DATA file keeps it as an apostrophe.
# Findings replayed from a results JSON are re-validated before any publisher
# sees them. The curly quotes are built from code points on purpose.

Describe 'PowerShell literal quoting and replay validation' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Rq = [string][char]0x2019   # right single quotation mark
        $script:Lq = [string][char]0x2018
        $script:Ast = {
            param([string] $Text)
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
            $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
            [pscustomobject]@{ Errors = @($errors).Count; Commands = $cmds }
        }
    }
    AfterAll { Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    Context 'ConvertTo-TPPsLiteral (generated scripts)' {
        It 'doubles the ASCII apostrophe and keeps ordinary text' {
            ConvertTo-TPPsLiteral -Value "O'Brien's list" | Should -Be "'O''Brien''s list'"
            ConvertTo-TPPsLiteral -Value '' | Should -Be "''"
        }
        It 'refuses every curly quote, line separator, line break, NUL and format character' {
            foreach ($cp in 0x2018, 0x2019, 0x201A, 0x201B, 0x0085, 0x2028, 0x2029, 0x000A, 0x000D, 0x0000, 0x200B, 0x202E, 0xFEFF) {
                ConvertTo-TPPsLiteral -Value ("a" + [string][char]$cp + "b") | Should -BeNullOrEmpty -Because ('U+{0:X4} must be refused' -f $cp)
            }
        }
        It 'a value it accepts round-trips as one string constant with no command' {
            $lit = ConvertTo-TPPsLiteral -Value 'x''; Write-Host PWNED; '''
            $r = & $script:Ast "Write-Output $lit"
            $r.Errors | Should -Be 0
            $r.Commands | Should -Be @('Write-Output')
        }
    }

    Context 'ConvertTo-TPPsd1String (data files)' {
        It 'keeps a curly apostrophe as data that Import-PowerShellDataFile reads back' {
            $lit = ConvertTo-TPPsd1String -Value ("it" + $script:Rq + "s done")
            $lit | Should -Be "'it''s done'"
            $tmp = Join-Path $TestDrive 'q.psd1'
            Set-Content -LiteralPath $tmp -Value "@{ Narrative = $lit }" -Encoding utf8
            (Import-PowerShellDataFile -LiteralPath $tmp).Narrative | Should -Be "it's done"
        }
        It 'a hostile narrative cannot add keys: the file re-reads with the one key written' {
            $hostile = "x" + $script:Rq + "; InheritedFrom = " + $script:Rq + "Injected" + $script:Rq + "; X = " + $script:Rq
            $tmp = Join-Path $TestDrive 'h.psd1'
            Set-Content -LiteralPath $tmp -Value "@{ Narrative = $(ConvertTo-TPPsd1String -Value $hostile) }" -Encoding utf8
            $d = Import-PowerShellDataFile -LiteralPath $tmp
            @($d.Keys) | Should -Be @('Narrative')
            $d.Narrative | Should -Be "x'; InheritedFrom = 'Injected'; X = '"
        }
        It 'the SSP answer writer and the profile writer use it' {
            $txt = ConvertTo-TPSSPAnswerPsd1 -Id '3.1.1' -Answer ([ordered]@{ Status = 'Planned'; Narrative = ("we" + $script:Rq + "ll") }) -Indent 2
            $txt | Should -Match "we''ll"
            $file = New-TPProfile -Name 'curly' -CompanyName ("O" + $script:Rq + "Brien IT") -Path (Join-Path $TestDrive 'p') -Confirm:$false
            (Import-PowerShellDataFile -LiteralPath $file).CompanyName | Should -Be "O'Brien IT"
        }
        It 'Test-TPPsd1EntriesRoundTrip throws on an entry set that re-reads differently' {
            $good = ConvertTo-TPSSPAnswerPsd1 -Id '3.1.1' -Answer ([ordered]@{ Status = 'Planned'; Narrative = 'ok' }) -Indent 2
            Test-TPPsd1EntriesRoundTrip -EntriesText $good -Block 'Requirements' -ExpectedIds @('3.1.1') | Should -BeTrue
            { Test-TPPsd1EntriesRoundTrip -EntriesText $good -Block 'Requirements' -ExpectedIds @('3.1.1', '3.1.2') } | Should -Throw -ExpectedMessage '*Missing: 3.1.2*'
            { Test-TPPsd1EntriesRoundTrip -EntriesText "        '3.1.1' = @{ Status = 'x" -Block 'Requirements' -ExpectedIds @('3.1.1') } | Should -Throw -ExpectedMessage '*do not parse*'
        }
    }

    Context 'Select-TPReplayedFinding' {
        It 'keeps valid findings and drops a bad ControlId, State or Severity, naming each' {
            $in = @(
                @{ ControlId = 'AAD-1.1'; State = 'Gap'; Severity = 'High'; Title = 'ok' },
                @{ ControlId = ("AAD-1.1" + $script:Rq + "; Set-Content x"); State = 'Gap'; Severity = 'High' },
                @{ ControlId = 'AAD-1.2'; State = 'Owned'; Severity = 'High' },
                @{ ControlId = 'AAD-1.3'; State = 'Gap'; Severity = 'Nuclear' }
            )
            $dropped = @()
            $kept = Select-TPReplayedFinding -Findings $in -Dropped ([ref]$dropped)
            @($kept).Count | Should -Be 1
            @($kept)[0].ControlId | Should -Be 'AAD-1.1'
            @($dropped).Count | Should -Be 3
            ($dropped -join ' ') | Should -Match 'not a control id'
            ($dropped -join ' ') | Should -Match "State 'Owned'"
            ($dropped -join ' ') | Should -Match "Severity 'Nuclear'"
            ($dropped -join ' ') | Should -Not -Match [regex]::Escape($script:Rq)
        }
        It 'returns an empty array for nothing' {
            @(Select-TPReplayedFinding -Findings @()).Count | Should -Be 0
        }
    }

    Context 'Publish-TPRemediationScript emits a script with only its own commands' {
        BeforeAll {
            $script:Meta = @{ TenantDomain = 'example.com'; AssessmentDate = 'October 9, 2026'; ToolVersion = '4.14.3' }
            $script:Hostile = @(
                @{ ControlId = 'AAD-1.1'; State = 'Gap'; Severity = 'High'; Category = 'Identity'
                   Title = ("Rule " + $script:Rq + "; Set-Content -Path x -Value y; Write-Host " + $script:Rq)
                   Detail = 'd'; CurrentValue = ("c" + $script:Lq + ";Remove-Item z;" + $script:Lq); RequiredValue = 'r'; Remediation = 'fix it' }
            )
        }
        It 'a curly-quoted finding field never becomes a command; a real apostrophe UPN still parses' {
            $out = Join-Path $TestDrive 'rem.ps1'
            $meta = $script:Meta.Clone(); $meta['Operator'] = "o'brien@msp.example"
            Publish-TPRemediationScript -Metadata $meta -Findings $script:Hostile -OutputPath $out | Out-Null
            $r = & $script:Ast (Get-Content -LiteralPath $out -Raw)
            $r.Errors | Should -Be 0
            $r.Commands | Should -Not -Contain 'Set-Content'
            $r.Commands | Should -Not -Contain 'Remove-Item'
            (Get-Content -LiteralPath $out -Raw) | Should -Match "UserPrincipalName 'o''brien@msp.example'"
        }
        It 'an operator value that cannot be quoted is replaced by Read-Host, not guessed' {
            $out = Join-Path $TestDrive 'rem2.ps1'
            $meta = $script:Meta.Clone(); $meta['Operator'] = ("x" + $script:Rq + "; Write-Host PWNED; " + $script:Rq)
            Publish-TPRemediationScript -Metadata $meta -Findings $script:Hostile -OutputPath $out | Out-Null
            $r = & $script:Ast (Get-Content -LiteralPath $out -Raw)
            $r.Errors | Should -Be 0
            $r.Commands | Should -Contain 'Read-Host'
            (Get-Content -LiteralPath $out -Raw) | Should -Match 'UserPrincipalName \(Read-Host'
            $tokens = $null; $errs = $null
            $null = [System.Management.Automation.Language.Parser]::ParseInput((Get-Content -LiteralPath $out -Raw), [ref]$tokens, [ref]$errs)
            $code = (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object Text) -join ' ')
            $code | Should -Not -Match 'PWNED' -Because 'the injected text may survive only inside a comment, never as code'
        }
    }

    Context 'Publish-TPAssessmentHTML workload id attribute' {
        It 'a ControlId prefix with markup cannot break out of the id attribute' {
            $out = Join-Path $TestDrive 'r.html'
            $f = @(@{ ControlId = "ZZ'><img src=x onerror=alert(1)><b x='-1.1"; State = 'Gap'; Severity = 'High'; Category = 'Identity'; Title = 't'; Detail = 'd'; CurrentValue = 'c'; RequiredValue = 'r'; Remediation = 'm'; FrameworkIds = ''; AffectedObjects = @() })
            Publish-TPAssessmentHTML -Metadata @{ TenantDomain = 'example.com'; AssessmentDate = 'October 9, 2026'; ToolVersion = '4.14.3'; Operator = 'admin@example.com' } -Findings $f -Connections @{} -OutputPath $out | Out-Null
            (Get-Content -LiteralPath $out -Raw) | Should -Not -Match "id='wl-ZZ'>"
            (Get-Content -LiteralPath $out -Raw) | Should -Not -Match '<img src=x onerror'
        }
    }
}

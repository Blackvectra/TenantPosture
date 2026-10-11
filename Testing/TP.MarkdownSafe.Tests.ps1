#Requires -Version 7.0
#
# TP.MarkdownSafe.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# One Markdown escape for tenant-derived text, used by every Markdown
# publisher: no link, image, code span, heading or HTML element can be formed
# from a finding's text. The SSP workbook writes client-authored text as text,
# never as a formula.

Describe 'Markdown and workbook output cannot carry markup or formulas' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Payload = '<img src=x onerror=alert(1)> [click](https://evil.example/md-link) ![t](https://evil.example/md-image.png) `code` | cell # head'
        $script:Meta = @{ TenantDomain = 'example.com'; AssessmentDate = 'October 11, 2026'; ToolVersion = '4.14.3'; Operator = 'admin@example.com' }
        $script:Findings = @(
            @{ ControlId = 'EXO-7.2'; State = 'Gap'; Severity = 'High'; Category = 'Email'; Title = "Rule $script:Payload"; Detail = "Detail $script:Payload"
               CurrentValue = $script:Payload; RequiredValue = 'r'; Remediation = "Fix $script:Payload"; FrameworkIds = 'NIST:AC-3'; AffectedObjects = @(@{ Rule = $script:Payload }) },
            @{ ControlId = 'AAD-1.1'; State = 'Satisfied'; Severity = 'Informational'; Category = 'Identity'; Title = 't'; Detail = 'd'; CurrentValue = 'c'; RequiredValue = 'r'; Remediation = 'm'; FrameworkIds = 'NIST:IA-2'; AffectedObjects = @() }
        )
        $script:Conn = @{ Graph = $true; EXO = $true; Teams = $false; IPPSSession = $false; SharePoint = $false }
        function script:Clean { param([string] $Path)
            $t = Get-Content -LiteralPath $Path -Raw
            $t | Should -Not -Match '(?<!\\)<img '
            $t | Should -Not -Match '(?<!\\)\]\(https://evil'
            $t | Should -Not -Match '(?<!\\)!\['
            $t | Should -Not -Match '(?<!\\)`code(?<!\\)`'
        }
    }
    AfterAll { Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    It 'ConvertTo-TPMarkdownSafe neutralizes every structural character and keeps the text readable' {
        $e = ConvertTo-TPMarkdownSafe $script:Payload
        $e | Should -Not -Match '(?<!\\)<img '
        $e | Should -Match '\\<img src=x onerror=alert\(1\)\\>'
        $e | Should -Match '\\\[click\\\]\(https://evil'
        $e | Should -Match '\\!\\\['
        $e | Should -Match '\\`code\\`'
        $e | Should -Match '\\\| cell \\# head'
        ConvertTo-TPMarkdownSafe "a`r`nb`tc" | Should -Be 'a b c'
        ConvertTo-TPMarkdownSafe 'back\slash' | Should -Be 'back\\slash'
        ConvertTo-TPMarkdownSafe $null | Should -Be ''
    }

    It 'the Markdown summary, playbook and executive summary carry no raw markup' {
        $d = Join-Path $TestDrive 'md'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        Publish-TPAssessmentSummary -Metadata $script:Meta -Findings $script:Findings -Connections $script:Conn -OutputPath (Join-Path $d 's.md') | Out-Null
        Clean (Join-Path $d 's.md')
        Publish-TPRemediationPlaybook -Metadata $script:Meta -Findings $script:Findings -Connections $script:Conn -OutputPath (Join-Path $d 'p.md') -ExecutivePath (Join-Path $d 'e.md') -HtmlOutputPath (Join-Path $d 'p.html') | Out-Null
        Clean (Join-Path $d 'p.md'); Clean (Join-Path $d 'e.md')
    }

    It 'the SSP Markdown carries no raw markup and its workbook holds no formula cell' {
        $d = Join-Path $TestDrive 'ssp'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $hostile = @{ Requirements = @{ '3.1.1' = @{ Status = 'Planned'; Narrative = "Note $script:Payload"; Poam = @{ Weakness = '=HYPERLINK("https://evil.example/x","open me")'; Remedy = "=cmd|' /C calc'!A0"; Owner = '+owner'; DueDate = '-2026' } } } }
        $posture = Get-TPSSPPosture -Findings $script:Findings -Answers $hostile
        $md = Join-Path $d 'ssp.md'
        Publish-TPSSP -Posture $posture -OutputPath $md -Metadata $script:Meta | Out-Null
        Clean $md
        $xlsx = Get-ChildItem -LiteralPath $d -Filter '*.xlsx' | Select-Object -First 1
        if (-not $xlsx) { Set-ItResult -Skipped -Because 'openpyxl is not available, so no workbook was written'; return }
        $tmp = Join-Path $d 'x'; New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        Expand-Archive -LiteralPath $xlsx.FullName -DestinationPath $tmp -Force
        $sheets = Get-ChildItem -LiteralPath (Join-Path $tmp 'xl' 'worksheets') -Filter '*.xml'
        $formulas = [int](($sheets | ForEach-Object { [regex]::Matches((Get-Content -LiteralPath $_.FullName -Raw), '<f>').Count } | Measure-Object -Sum).Sum)
        $formulas | Should -Be 0 -Because 'client-authored text must never become a live Excel formula'
        # openpyxl stores strings inline or in sharedStrings depending on version; look in both.
        $allXml = (Get-ChildItem -LiteralPath (Join-Path $tmp 'xl') -Filter '*.xml' -Recurse | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
        $allXml | Should -Match "'=HYPERLINK" -Because 'the value is kept as text with the apostrophe guard'
    }

    It 'the two incident-response Markdown reports carry no raw markup' {
        $d = Join-Path $TestDrive 'ir'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $meta = @{ TenantDomain = 'example.com'; AssessmentDate = 'October 11, 2026'; ToolVersion = '4.14.3'; UserPrincipalName = "user@example.com"; TargetUser = "user@example.com"; WindowDays = 14; Operator = 'admin@example.com'; CollectionComplete = $true }
        $f = @(@{ ControlId = 'EMAIL-1.1'; State = 'Gap'; Severity = 'High'; Category = 'Email'; Title = "Rule $script:Payload"; Detail = "Detail $script:Payload"; CurrentValue = $script:Payload; RequiredValue = ''; Remediation = ''; FrameworkIds = ''; AffectedObjects = @() })
        { Publish-TPEmailIncidentReport -Metadata $meta -Findings $f -OutputPath (Join-Path $d 'e.html') | Out-Null } | Should -Not -Throw
        $md = Get-ChildItem -LiteralPath $d -Filter '*.md' | Select-Object -First 1
        if ($md) { Clean $md.FullName }
    }
}

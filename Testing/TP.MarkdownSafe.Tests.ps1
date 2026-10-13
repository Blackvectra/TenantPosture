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
#
# "Every Markdown publisher" is pinned here, not assumed: four private escape
# chains had drifted from the one helper (the batch summary's let [text](url)
# through), and the outputs they wrote were not among those checked below. Every
# EscMd / EscMdStrict definition in the tool must call ConvertTo-TPMarkdownSafe,
# and the HIPAA, tenant-comparison, delta and batch-summary Markdown is driven
# with the same hostile payload as the rest.

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

    It 'every EscMd and EscMdStrict in the tool calls ConvertTo-TPMarkdownSafe' {
        # The rule is one function; a private replace chain beside it is how a
        # publisher drifts. Parsed, not grepped, so a comment naming the helper
        # does not count.
        $files = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'Publishers') -Filter '*.ps1') +
                 @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'Email-IR' 'Publishers') -Filter '*.ps1') +
                 @(Get-ChildItem -LiteralPath $script:RepoRoot -Filter '*.ps1' -File)
        $seen = 0
        foreach ($f in $files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($fn in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('EscMd', 'EscMdStrict') }, $true))) {
                $seen++
                $calls = @($fn.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'ConvertTo-TPMarkdownSafe' }, $true))
                $calls.Count | Should -BeGreaterThan 0 -Because "$($f.Name) defines $($fn.Name) without the one Markdown rule"
            }
        }
        $seen | Should -BeGreaterThan 8 -Because 'the publishers define these helpers; a count this low means the scan missed them'
    }

    It 'the HIPAA readiness Markdown carries no raw markup' {
        $d = Join-Path $TestDrive 'hipaa'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        # A hostile Gap on every control, so every mapped standard renders the Detail.
        $f = @(Get-TPControlDefinitions | ForEach-Object {
            @{ ControlId = $_.ControlId; State = 'Gap'; Severity = $_.Severity; Category = 'c'; Title = "$($_.Title) $script:Payload"; Detail = "Detail $script:Payload"
               CurrentValue = $script:Payload; RequiredValue = 'r'; Remediation = "Fix $script:Payload"; FrameworkIds = 'NIST:AC-3'; AffectedObjects = @() }
        })
        $p = Get-TPHipaaReadiness -Findings $f
        $md = Join-Path $d 'hipaa.md'
        Publish-TPHipaaReadiness -Posture $p -OutputPath $md -Metadata $script:Meta | Out-Null
        Clean $md
    }

    It 'the tenant comparison Markdown carries no raw markup' {
        $d = Join-Path $TestDrive 'cmp'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $mk = {
            param([string] $Domain, [string] $State, [string] $Code)
            $row = [ordered]@{ ControlId = 'AAD-1.1'; Title = "T $script:Payload"; RequiredTier = 'Minimum'; ExpectedState = 'on'
                               ObservedState = $State; ReasonCode = $Code; Reason = 'r'; Constraint = 'None'; Disposition = 'Normal'; EffectivenessState = 'Unknown' }
            $o = [pscustomobject]@{
                Metadata = [ordered]@{ TenantDomain = $Domain; AssessmentTime = '2026-10-01T10:00:00Z'; ToolVersion = '4.14.3'; TargetTier = 'Minimum'; BaselineVersion = '1.0' }
                Findings = @()
                BaselineCompliance = [ordered]@{ Available = $true; BaselineVersion = '1.0'; TargetTier = 'Minimum'; Controls = @($row) }
            }
            return ($o | ConvertTo-Json -Depth 12 | ConvertFrom-Json -Depth 20)
        }
        $cmp = Get-TPBaselineTenantComparison -ResultsA (& $mk 'a.example' 'Satisfied' 'Satisfied') -ResultsB (& $mk 'b.example' 'Failed' 'ControlFailed')
        $paths = Publish-TPBaselineTenantComparison -Comparison $cmp -OutputPath $d
        Clean $paths.Markdown
    }

    It 'the delta report Markdown carries no raw markup' {
        $d = Join-Path $TestDrive 'delta'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $baseline = Join-Path $d 'prior-results.json'
        # The delta refuses a baseline it cannot tie to the same tenant, so both carry one id.
        $tid = '11111111-2222-3333-4444-555555555555'
        $meta = $script:Meta.Clone(); $meta['TenantId'] = $tid
        $prior = @{
            Metadata = @{ TenantDomain = 'example.com'; TenantId = $tid; AssessmentDate = 'September 11, 2026'; ToolVersion = '4.14.3' }
            Findings = @(@{ ControlId = 'AAD-1.1'; State = 'Gap'; Severity = 'High'; Category = 'Identity'; Title = "Old $script:Payload"; Detail = "Detail $script:Payload"; CurrentValue = 'c'; RequiredValue = 'r'; Remediation = 'm'; FrameworkIds = 'NIST:IA-2'; AffectedObjects = @() })
        }
        $prior | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $baseline -Encoding utf8
        $md = Join-Path $d 'delta.md'
        Publish-TPDeltaReport -CurrentFindings $script:Findings -BaselineResultsPath $baseline -Metadata $meta -OutputPath $md | Out-Null
        Clean $md
    }

    It 'the batch summary escape neutralizes link, image and HTML syntax' {
        # The batch runner is a script, not a function; its EscMd is taken from the
        # parsed file and run here with the module loaded, as the runner has it.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:RepoRoot 'Invoke-TPBatchAssessment.ps1'), [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'EscMd' }, $true)
        $fn | Should -Not -BeNullOrEmpty
        $esc = & $fn.Body.GetScriptBlock() $script:Payload
        $esc | Should -Not -Match '(?<!\\)<img '
        $esc | Should -Not -Match '(?<!\\)\]\(https://evil'
        $esc | Should -Not -Match '(?<!\\)!\['
        $esc | Should -Not -Match '(?<!\\)`code(?<!\\)`'
        $esc | Should -Not -Match '(?<!\\)\|'
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

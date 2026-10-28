#Requires -Version 7.0
#
# TP.HipaaClientReport.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards the client-facing HIPAA Security Rule report and its PDF:
#   - every one of the 63 standards and specifications lands in exactly one
#     group, and the groups follow the readiness view's statuses
#   - a partial or quick run is refused; the model carries no finding detail
#   - page one says what the report is not before any number; nothing claims
#     compliance; tenant text is escaped; the page loads and runs nothing
#   - the documentation group is a checklist with a row per requirement
#   - the PDF: a missing browser is reported and the HTML is still written; a
#     non-browser named in TP_PDF_BROWSER is ignored; the browser runs with
#     its arguments as a list, a throwaway profile and no network; the PDF is
#     written byte for byte through the sensitive writer
#   - the entry point and the standalone script are wired
# Data keys consumed: synthetic findings only. Graph scopes / cmdlets: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Mod = Get-Module 'TenantPosture'
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-hcr-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = New-Item -ItemType Directory -Path $script:Tmp -Force
    $script:Meta = @{ TenantDomain = 'contoso-health.com'; AssessmentTime = '2026-10-28T15:00:00Z'; ToolVersion = '9.9.9' }
    $script:Marker = 'DETAIL-MARKER-91c4'
    $script:NewFindings = {
        param([hashtable] $Override = @{})
        foreach ($c in (Get-TPControlDefinitions)) {
            $st = if ($Override.ContainsKey($c.ControlId)) { $Override[$c.ControlId] } else { 'Satisfied' }
            @{ ControlId = $c.ControlId; State = $st; Severity = $c.Severity; Title = $c.Title; Detail = "$($script:Marker) $($c.ControlId)"; Category = 'c' }
        }
    }
    $script:Fails = @{ 'AAD-1.3' = 'Gap'; 'EXO-1.1' = 'Gap'; 'PVW-4.1' = 'NotApplicable' }
    $script:M = Get-TPHipaaClientReport -Findings @(& $script:NewFindings $script:Fails) -Metadata $script:Meta -ClientName 'Contoso <script>alert(1)</script> Health' -PreparedBy 'NextLayerSec, LLC'
}

# Which headless browser can print here, decided at discovery so -Skip can read it.
# Full Chrome cannot print headless in every container; Playwright's headless
# shell can. On Windows, Edge is found by Find-TPPdfBrowser in the product.
BeforeDiscovery {
    $script:Headless = @(
        $env:TP_PDF_BROWSER,
        '/opt/pw-browsers/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell'
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'HIPAA client report: the model' {
    It 'puts every one of the 63 requirements in exactly one group' {
        $script:M.Total | Should -Be 63
        ($script:M.Counts.Values | Measure-Object -Sum).Sum | Should -Be 63
        $all = @($script:M.Groups.Values | ForEach-Object { $_ } | ForEach-Object { $_.Citation })
        $all.Count | Should -Be 63
        @($all | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0
    }
    It 'follows the readiness view: a shortfall needs attention, an unread check is not verified, no check is documentation' {
        $st = & $script:Mod { Get-TPHipaaStatusNames }
        $ready = Get-TPHipaaReadiness -Findings @(& $script:NewFindings $script:Fails)
        $map = @{ $st.Satisfied = 'Verified'; $st.SpecsOpen = 'Partly'; $st.Shortfall = 'Attention'; $st.NotAssessed = 'NotVerified'; $st.Attestation = 'Documentation' }
        foreach ($r in $ready.Items) {
            $g = @($script:M.Groups.Keys | Where-Object { @($script:M.Groups[$_] | ForEach-Object { $_.Citation }) -contains $r.Citation })[0]
            $g | Should -Be $map[[string]$r.Status] -Because "$($r.Citation) is '$($r.Status)'"
        }
        @($script:M.Groups.Attention).Count | Should -BeGreaterThan 0
        @($script:M.Groups.Documentation | ForEach-Object { $_.Citation }) | Should -Contain '164.308(a)(1)(ii)(A)'
    }
    It 'with every check passing, nothing needs attention and documentation still does' {
        $m = Get-TPHipaaClientReport -Findings @(& $script:NewFindings @{}) -Metadata $script:Meta
        $m.Counts.Attention | Should -Be 0
        $m.Counts.Documentation | Should -BeGreaterThan 30
        $m.ClientName | Should -Be 'contoso-health.com'
    }
    It 'a failed check is named with its severity; the passed list is kept for the sample' {
        $it = @($script:M.Groups.Attention | Where-Object { @($_.Failed.ControlId) -contains 'AAD-1.3' })[0]
        $it | Should -Not -BeNullOrEmpty
        @($it.Failed)[0].Severity | Should -Be 'Critical'
        @($script:M.Priorities.ControlId) | Should -Contain 'AAD-1.3'
    }
    It 'refuses a partial or a quick run' {
        foreach ($meta in @(
            @{ TenantDomain = 'x.com'; ControlSelection = @{ Partial = $true; SelectedCount = 1; TotalControls = 253 } },
            @{ TenantDomain = 'x.com'; QuickScan = $true })) {
            $m = Get-TPHipaaClientReport -Findings @(& $script:NewFindings @{}) -Metadata $meta
            $m.Available | Should -BeFalse
            $m.Refused | Should -BeTrue
        }
    }
    It 'carries no finding detail' {
        ($script:M | ConvertTo-Json -Depth 12) | Should -Not -Match $script:Marker
    }
    It 'the documentation group is in the rule''s own order, not sorted as text' {
        $cits = @($script:M.Groups.Documentation | Where-Object Safeguard -eq 'Administrative' | ForEach-Object Citation)
        $cits.IndexOf('164.308(a)(7)(i)') | Should -BeLessThan $cits.IndexOf('164.308(a)(7)(ii)(C)')
        if ($cits -contains '164.308(b)(1)') { $cits.IndexOf('164.308(a)(7)(i)') | Should -BeLessThan $cits.IndexOf('164.308(b)(1)') }
    }
}

Describe 'HIPAA client report: the page' {
    BeforeAll {
        Mock -ModuleName 'TenantPosture' Find-TPPdfBrowser -MockWith { $null }
        $script:Files = Publish-TPHipaaClientReport -Model $script:M -OutputPath (Join-Path $script:Tmp 'contoso-hipaa-report.html') -Pdf -GeneratedAt ([datetime]::new(2041, 1, 2, 3, 4, 0, [DateTimeKind]::Utc))
        $script:Html = Get-Content -LiteralPath $script:Files.Html -Raw
    }
    It 'says what it is not before any number' {
        $not = $script:Html.IndexOf('What this is not.')
        $not | Should -BeGreaterThan 0
        $script:Html.IndexOf('class="tp-kpis"') | Should -BeGreaterThan $not
        $script:Html | Should -Match 'not a HIPAA risk analysis'
        $script:Html | Should -Match 'not a determination that your organization is or is not compliant'
        $script:Html | Should -Match 'Addressable does not mean optional'
    }
    It 'never claims compliance' {
        $script:Html | Should -Not -Match '(?i)\b(you are|organization is|tenant is|fully|now)\s+compliant\b|\bcompliant with\b|\bHIPAA[- ]compliant\b'
    }
    It 'escapes tenant text and loads and runs nothing' {
        $script:Html | Should -Match 'Contoso &lt;script&gt;'
        $script:Html | Should -Not -Match '(?i)<script|<link|<img|<iframe|@import'
        $script:Html | Should -Match "default-src 'none'"
    }
    It 'the documentation group is a checklist with a row per requirement' {
        $section = [regex]::Match($script:Html, '(?s)id="group-documentation".*?</table>').Value
        ([regex]::Matches($section, '&#9744;')).Count | Should -Be $script:M.Counts.Documentation
    }
    It 'with no browser, says the PDF was not written and keeps the HTML' {
        $script:Files.Pdf | Should -BeNullOrEmpty
        $script:Files.PdfNote | Should -Match 'No Microsoft Edge, Chrome or Chromium was found'
        $script:Files.PdfNote | Should -Match 'print it to PDF'
        Test-Path -LiteralPath $script:Files.Html | Should -BeTrue
    }
}

Describe 'PDF printing' {
    It 'ignores a TP_PDF_BROWSER that is not a Chromium browser' {
        $prev = $env:TP_PDF_BROWSER
        try {
            $env:TP_PDF_BROWSER = (Get-Command pwsh).Source
            $found = & $script:Mod { Find-TPPdfBrowser }
            $found | Should -Not -Be (Get-Command pwsh).Source
        } finally { $env:TP_PDF_BROWSER = $prev }
    }
    It 'runs the browser with an argument list, a throwaway profile and no network' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/ConvertTo-TPPdf.ps1') -Raw
        $src | Should -Match 'ArgumentList\.Add'
        $src | Should -Not -Match '(?i)Invoke-Expression|Start-Process|cmd(\.exe)? /c|\.Arguments\s*='
        $src | Should -Match ([regex]::Escape("'--host-resolver-rules=MAP * ~NOTFOUND'"))
        $src | Should -Match '--user-data-dir='
        $src | Should -Match "'%PDF-'"
        $src | Should -Match 'Set-TPSensitiveFileContent -Path \$PdfPath -Bytes'
    }
    It 'never throws: an HTML file that does not exist is a reason, not an error' {
        $r = ConvertTo-TPPdf -HtmlPath (Join-Path $script:Tmp 'missing.html') -PdfPath (Join-Path $script:Tmp 'x.pdf')
        $r.Written | Should -BeFalse
        $r.Reason | Should -Match 'not found'
    }
    It 'the sensitive writer writes bytes exactly' {
        $bytes = [byte[]](0..255) + [byte[]](37, 80, 68, 70)
        $p = Join-Path $script:Tmp 'bytes.bin'
        Set-TPSensitiveFileContent -Path $p -Bytes $bytes
        [System.IO.File]::ReadAllBytes($p) | Should -Be $bytes
        if (-not $IsWindows) { ((Get-Item -LiteralPath $p).UnixMode) | Should -Be '-rw-------' }
    }
    It 'prints a real PDF when a headless browser is available' -Skip:(-not $script:Headless) -ForEach @(@{ Browser = $script:Headless }) {
        Mock -ModuleName 'TenantPosture' Find-TPPdfBrowser -MockWith { $null }
        $html = Join-Path $script:Tmp 'print.html'
        $null = Publish-TPHipaaClientReport -Model $script:M -OutputPath $html
        $r = ConvertTo-TPPdf -HtmlPath $html -PdfPath (Join-Path $script:Tmp 'print.pdf') -Browser $Browser -TimeoutSeconds 60
        $r.Written | Should -BeTrue -Because $r.Reason
        $head = [System.IO.File]::ReadAllBytes($r.Path)[0..4]
        [System.Text.Encoding]::ASCII.GetString($head) | Should -Be '%PDF-'
    }
}

Describe 'HIPAA client report: wiring' {
    It 'the entry point writes it with -HIPAA, prints it with -Pdf and takes -ClientName' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $src | Should -Match '\[switch\] \$Pdf'
        $src | Should -Match '\[string\] \$ClientName'
        $src | Should -Match 'Publish-TPHipaaClientReport -Model \$hipaaModel .*-Pdf:\$Pdf'
    }
    It 'the standalone script refuses a partial run and connects to nothing' {
        $path = Join-Path $script:RepoRoot 'New-TPHipaaReport.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        foreach ($bad in 'Connect-TPServices', 'Connect-MgGraph', 'Invoke-TPGraphRequest', 'Invoke-RestMethod', 'Invoke-WebRequest', 'Connect-ExchangeOnline') { $cmds | Should -Not -Contain $bad }
        $cmds | Should -Contain 'Read-TPRunRecord'
        $cmds | Should -Contain 'Test-TPSensitiveOutputFolder'
    }
}

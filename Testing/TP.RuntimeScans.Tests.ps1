#Requires -Version 7.0
#
# TP.RuntimeScans.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The two scans that look at the tool RUNNING rather than at its code: the
# dynamic scan of the -Web GUI (.github/workflows/dast.yml, OWASP ZAP against
# the real server on loopback) and the image scan (.github/workflows/
# oss-scanner-image.yml, Trivy over the built OSS Scanner image and its
# Dockerfile). These tests pin what makes either scan worth trusting:
#
#   - the scanner runs from an image pinned by tag AND digest in a one-line
#     Dockerfile Dependabot tracks (.github/scanners/<tool>/Dockerfile), and the
#     job runs exactly what that file names;
#   - every alert fails the job unless reviewed into the exceptions file WITH a
#     reason a reviewer can check (.zap/rules.tsv, .trivyignore.yaml): a
#     silently ignored rule is a scan that no longer scans;
#   - the dynamic scan hits the real server, headless, over a fixture that gives
#     every route something to serve, and never waves warnings through (-I);
#   - the image scan fails on HIGH and CRITICAL, uploads SARIF, and the image
#     drops root before the scanner runs it.

Describe 'Runtime scans: the dynamic scan of the web GUI and the image scan' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $read = { param($rel) Get-Content -LiteralPath (Join-Path $script:RepoRoot $rel) -Raw }
        $script:Dast       = & $read '.github/workflows/dast.yml'
        $script:Image      = & $read '.github/workflows/oss-scanner-image.yml'
        $script:Dependabot = & $read '.github/dependabot.yml'
        $script:Docker     = & $read '.oss-scanner/Dockerfile'
        $script:Ignore     = & $read '.trivyignore.yaml'
        $script:RulesLines = @(Get-Content -LiteralPath (Join-Path $script:RepoRoot '.zap/rules.tsv'))
        $script:Fixture    = Join-Path $script:RepoRoot 'tools/New-TPWebScanFixture.ps1'
        $script:PinFiles = @(
            @{ Tool = 'zap';   Path = '.github/scanners/zap/Dockerfile';   Registry = 'ghcr\.io/zaproxy/zaproxy' }
            @{ Tool = 'trivy'; Path = '.github/scanners/trivy/Dockerfile'; Registry = 'docker\.io/aquasec/trivy' }
        )
    }

    Context 'Scanner images are pinned by digest in files Dependabot tracks' {

        It '<Tool>: the pin file is one FROM line naming the release tag and the digest together' -ForEach @(
            @{ Tool = 'zap';   Path = '.github/scanners/zap/Dockerfile';   Registry = 'ghcr\.io/zaproxy/zaproxy' }
            @{ Tool = 'trivy'; Path = '.github/scanners/trivy/Dockerfile'; Registry = 'docker\.io/aquasec/trivy' }
        ) {
            $text = Get-Content -LiteralPath (Join-Path $script:RepoRoot $Path) -Raw
            $instructions = @([regex]::Matches($text, '(?m)^[A-Z]+\b') | ForEach-Object { $_.Value })
            $instructions | Should -Be @('FROM') -Because 'nothing is built from the pin file; a second instruction would be dead or misleading'
            # Tag and digest: Dependabot moves both; a digest alone shows no version
            # and a tag alone can be re-pointed.
            $text | Should -Match "(?m)^FROM $Registry`:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}\s*$"
        }

        It 'Dependabot watches each pin directory weekly with the same cooldown as every other ecosystem' {
            foreach ($dir in '/.github/scanners/zap', '/.github/scanners/trivy') {
                $script:Dependabot | Should -Match ('package-ecosystem: "docker"\s+directory: "{0}"\s+schedule:\s+interval: "weekly"[\s\S]*?cooldown:\s+default-days: 7' -f [regex]::Escape($dir))
            }
        }

        It 'each job runs the image its pin file names, read from the FROM line, and no other image reference' {
            $script:Dast  | Should -Match "awk '/\^FROM /\{print \`$2\}' \.github/scanners/zap/Dockerfile"
            $script:Image | Should -Match "awk '/\^FROM /\{print \`$2\}' \.github/scanners/trivy/Dockerfile"
            # A second reference in the workflow would be a pin Dependabot cannot see.
            $script:Dast  | Should -Not -Match 'zaproxy/zaproxy[:@]'
            $script:Image | Should -Not -Match 'aquasec/trivy[:@]'
            $script:Dast  | Should -Not -Match 'docker://'
            $script:Image | Should -Not -Match 'docker://'
        }
    }

    Context 'The dynamic scan' {

        It 'runs ZAP against the real GUI on loopback, drives it with the AJAX spider, and reads the reviewed rules file' {
            $script:Dast | Should -Match 'zap-baseline\.py -t http://127\.0\.0\.1:8765 -j '
            $script:Dast | Should -Match '-c rules\.tsv'
            # Without -silent, zap-baseline.py downloads rule add-ons at start and the
            # rules that judge a pull request are whatever was published that day,
            # not what the pinned image ships.
            $script:Dast | Should -Match 'zap-baseline\.py[^\n]* -z "-silent"'
            $script:Dast | Should -Match 'cp \.zap/rules\.tsv zap-wrk/rules\.tsv'
            # The container must reach the loopback server and send the Host header
            # the request policy requires; only host networking gives it both.
            $script:Dast | Should -Match 'docker run --rm --network host '
        }

        It 'fails on any WARN or FAIL and never waves warnings through' {
            # -I makes zap-baseline exit 0 on warnings; -l raises the level shown;
            # either turns the scan into a report nobody reads.
            $script:Dast | Should -Not -Match 'zap-baseline\.py[^\n]*\s-I\b'
            $script:Dast | Should -Not -Match 'zap-baseline\.py[^\n]*\s-l\s'
            $script:Dast | Should -Match '(?m)^\s+0\) echo'
            $script:Dast | Should -Match '(?m)^\s+1\) [^\n]*exit 1'
            $script:Dast | Should -Match '(?m)^\s+2\) [^\n]*exit 1'
            $script:Dast | Should -Match '(?m)^\s+\*\) [^\n]*exit 1'
        }

        It 'starts the real server headless over the fixture and proves the run index lists it before scanning' {
            $script:Dast | Should -Match '\. \./Lib/Start-TPWebServer\.ps1; Start-TPWebServer -Port 8765 -ScriptDir \(Get-Location\)\.Path -OutputRoot \$env:TP_SCAN_OUTPUT -NoBrowser'
            $script:Dast | Should -Match '\./tools/New-TPWebScanFixture\.ps1 -Path'
            $script:Dast | Should -Match 'curl -fsS http://127\.0\.0\.1:8765/api/runs \| grep -q SCANTENANT'
            $script:Dast | Should -Match 'Install-TPPinnedModule\.ps1 -Name Pode'
        }

        It 'publishes the reports even when the scan fails, and runs on pull requests, main and a schedule' {
            $script:Dast | Should -Match "if: always\(\) && hashFiles\('zap-wrk/zap-report\.\*'\) != ''"
            $script:Dast | Should -Match 'name: zap-reports'
            $script:Dast | Should -Match '(?m)^  pull_request:'
            $script:Dast | Should -Match '(?m)^  push:'
            $script:Dast | Should -Match '(?m)^  schedule:'
        }

        It 'every exception in .zap/rules.tsv names a rule, an action and a reason a reviewer can check' {
            $rules = @($script:RulesLines | Where-Object { $_.Trim() -and -not $_.StartsWith('#') })
            $rules.Count | Should -BeGreaterThan 0
            $ids = @()
            foreach ($line in $rules) {
                $cols = $line -split "`t"
                $cols.Count | Should -Be 3 -Because "'$line' must be <id> TAB <action> TAB <reason>"
                $cols[0] | Should -Match '^\d+$'
                $cols[1] | Should -BeIn 'IGNORE', 'WARN', 'FAIL'
                $cols[2].Trim().Length | Should -BeGreaterThan 60 -Because "rule $($cols[0]) needs a reason that says what the alert is and why it is accepted"
                $ids += $cols[0]
            }
            @($ids | Select-Object -Unique).Count | Should -Be $ids.Count -Because 'one line per rule'
        }
    }

    Context 'The active scan' {

        BeforeAll {
            $script:Plan = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.zap/active-scan.yaml') -Raw
            $script:Judge = Join-Path $script:RepoRoot 'tools/Test-TPZapActiveScan.ps1'
        }

        It 'runs the plan in the pinned image on host networking, silently, and judges the report with the gate script' {
            $script:Dast | Should -Match '(?m)^  zap-active:'
            $script:Dast | Should -Match 'docker run --rm --network host -e TP_ZAP_OUT=/zap/wrk [^\n]*"\$\{image\}" \\\s+zap\.sh -cmd -silent -autorun /zap/wrk/active-scan\.yaml'
            $script:Dast | Should -Match '\./tools/Test-TPZapActiveScan\.ps1 -ReportPath zap-active/zap-active-report\.json'
            $script:Dast | Should -Match "if: always\(\) && hashFiles\('zap-active/zap-active-report\.\*'\) != ''"
        }

        It 'never scans POST /api/scan, which starts a real assessment, and still scans its status route' {
            $script:Plan | Should -Match "excludePaths:\s+- 'http://127\\\.0\\\.0\\\.1:8765/api/scan\(\\\?\.\*\)\?'"
            $exclude = 'http://127\.0\.0\.1:8765/api/scan(\?.*)?'
            # ZAP anchors an exclusion to the whole URL.
            'http://127.0.0.1:8765/api/scan' | Should -Match "^$exclude$"
            'http://127.0.0.1:8765/api/scan/000000000000/status' | Should -Not -Match "^$exclude$"
            $script:Plan | Should -Match 'requestor'
            $script:Plan | Should -Match '/api/scan/000000000000/status'
        }

        It 'records the output folder before the scan and fails if it gained anything' {
            $script:Dast | Should -Match 'find "\$TP_SCAN_OUTPUT" \| sort > "\$RUNNER_TEMP/output-before\.txt"'
            $script:Dast | Should -Match '-Before "\$env:RUNNER_TEMP/output-before\.txt"'
        }

        It 'the gate passes only reviewed IGNORE rules, and fails an unreviewed alert, a missing site, a missing report and a new file' {
            $root = Join-Path $TestDrive 'out'
            $null = New-Item -ItemType Directory -Force -Path $root
            $before = Join-Path $TestDrive 'before.txt'
            Set-Content -LiteralPath $before -Value ((Get-Item -LiteralPath $root).FullName)
            $rules = Join-Path $TestDrive 'rules.tsv'
            Set-Content -LiteralPath $rules -Value ("10027`tIGNORE`tReviewed reason long enough for the test, which only reads the action column.", "40012`tWARN`tListed but not accepted: a WARN line never passes a finding through the gate.")
            $target = 'http' + '://127.0.0.1:8765'
            $report = { param($Ids, [string] $Site = $target) $p = Join-Path $TestDrive 'r.json'; @{ site = @(@{ '@name' = $Site; alerts = @($Ids | ForEach-Object { @{ pluginid = $_; name = "Rule $_"; riskdesc = 'Medium (High)'; instances = @(@{ method = 'GET'; uri = "$target/" }) } }) }) } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $p; $p }
            $judge = { param($ReportPath) $null = & pwsh -NoProfile -File $script:Judge -ReportPath $ReportPath -RulesPath $rules -Target $target -OutputRoot $root -Before $before; $LASTEXITCODE }
            & $judge (& $report @('10027')) | Should -Be 0
            & $judge (& $report @('10027', '40012')) | Should -Be 1 -Because 'a WARN line is listed, not accepted'
            & $judge (& $report @('40018')) | Should -Be 1
            & $judge (& $report @() 'http://other:1') | Should -Be 1 -Because 'a scan that reached nothing is not clean'
            & $judge (Join-Path $TestDrive 'missing.json') | Should -Be 1
            $null = New-Item -ItemType Directory -Path (Join-Path $root 'evil.example')
            & $judge (& $report @('10027')) | Should -Be 1 -Because 'a new folder means a request started an assessment'
        }
    }

    Context 'The image scan' {

        It 'scans the built image from an archive for HIGH and CRITICAL vulnerabilities, fails on any, and uploads the SARIF' {
            $script:Image | Should -Match 'docker save tenantposture:ci -o '
            $script:Image | Should -Match 'image --input /scan/image\.tar --scanners vuln'
            $script:Image | Should -Match '--severity HIGH,CRITICAL --ignore-unfixed --ignorefile /scan/\.trivyignore\.yaml'
            $script:Image | Should -Match 'scan --format sarif --output /out/trivy-image\.sarif --exit-code 1'
            $script:Image | Should -Match 'category: trivy-image'
            $script:Image | Should -Match "if: always\(\) && hashFiles\('trivy-out/trivy-image\.sarif'\) != ''"
            # The archive mount means the scanner needs no Docker socket.
            $script:Image | Should -Not -Match 'docker\.sock'
        }

        It 'checks the Dockerfile at every severity in its own job and uploads that SARIF too' {
            $script:Image | Should -Match '(?m)^  dockerfile-config:'
            $script:Image | Should -Match 'config --severity LOW,MEDIUM,HIGH,CRITICAL'
            $script:Image | Should -Match 'scan --format sarif --output /out/trivy-config\.sarif --exit-code 1'
            $script:Image | Should -Match 'category: trivy-config'
        }

        It 'every .trivyignore.yaml entry carries a statement a reviewer can check' {
            $ids = @([regex]::Matches($script:Ignore, '(?m)^\s+- id:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value })
            $statements = @([regex]::Matches($script:Ignore, '(?m)^\s+statement:\s*"([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
            $statements.Count | Should -Be $ids.Count -Because 'an entry with no statement is an exception nobody can review'
            foreach ($st in $statements) { $st.Trim().Length | Should -BeGreaterThan 60 }
            # Only Trivy's own identifiers: a Dockerfile rule or a CVE.
            foreach ($id in $ids) { $id | Should -Match '^(DS-\d{4}|CVE-\d{4}-\d{4,}|GHSA-[0-9a-z-]+)$' }
        }

        It 'the OSS Scanner image drops root before the scanner runs it (Trivy DS-0002)' {
            $script:Docker | Should -Match '(?m)^RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin scanner'
            $users = @([regex]::Matches($script:Docker, '(?m)^USER\s+(\S+)') | ForEach-Object { $_.Groups[1].Value })
            $users.Count | Should -Be 1
            $users[0] | Should -Be 'scanner'
            # After the build and the test run, which stay root, and before CMD.
            $script:Docker.LastIndexOf('Invoke-TPTestGate.ps1') | Should -BeLessThan $script:Docker.IndexOf("`nUSER scanner")
            $script:Docker.IndexOf("`nUSER scanner") | Should -BeLessThan $script:Docker.IndexOf('CMD [')
        }

        It 'the image job scans on every change to its inputs, the ignore file and the scanner pin included' {
            foreach ($p in '.trivyignore.yaml', '.github/scanners/trivy/**') {
                ([regex]::Matches($script:Image, "- '$([regex]::Escape($p))'")).Count | Should -Be 2 -Because "$p is an input to the scan on push and on pull_request"
            }
        }
    }

    Context 'The scan fixture' {

        It 'connects to nothing and writes only under -Path' {
            # Judged on the commands the script CALLS (the AST), not on its text:
            # the header legitimately names Connect-TPServices in prose.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Fixture, [ref] $null, [ref] $null)
            $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
            $calls | Should -Not -BeNullOrEmpty
            foreach ($c in $calls) {
                $c | Should -Not -Match '^(Invoke-WebRequest|Invoke-RestMethod|Connect-|Import-Module|Start-Process|Start-Job|Resolve-DnsName|Invoke-Expression)' -Because 'the fixture is data only'
            }
            $allowed = 'Join-Path', 'Split-Path', 'Set-Content', 'Set-StrictMode', 'ConvertTo-Json', 'Write-Output'
            foreach ($c in $calls) { $c | Should -BeIn $allowed -Because "an unexpected command ($c) in the fixture builder is worth a look" }
            (Get-Content -LiteralPath $script:Fixture -Raw) | Should -Match '\$out = Join-Path \$Path ''output'''
        }

        It 'builds a flat run with its report and report site, a tenant-folder run, and a clients.json the index can join' {
            $work = Join-Path $TestDrive 'fx'
            $out = & $script:Fixture -Path $work
            $out | Should -Be (Join-Path $work 'output')
            foreach ($rel in 'SCANTENANT-20261016-110000-results.json', 'SCANTENANT-20261016-110000-assessment.html',
                             'SCANTENANT-20261016-110000-report/index.html', 'SCANTENANT-20261016-110000-report/AAD.html',
                             'SCANTENANT-20261016-110000-report/ActionPlan.csv',
                             'contoso.example/CONTOSO-20261016-100000-results.json', 'contoso.example/CONTOSO-20261016-100000-assessment.html') {
                Test-Path -LiteralPath (Join-Path $out $rel) | Should -BeTrue -Because $rel
            }
            $meta = (Get-Content -LiteralPath (Join-Path $out 'SCANTENANT-20261016-110000-results.json') -Raw | ConvertFrom-Json).Metadata
            $meta.TenantDomain | Should -Be 'scan-tenant.onmicrosoft.com'
            $meta.Brand.LogoUrl | Should -Be 'https://cdn.example.com/logo.png'
            $clients = (Get-Content -LiteralPath (Join-Path $work 'Config' 'clients.json') -Raw | ConvertFrom-Json).clients
            @($clients | Where-Object { $_.TenantId -eq $meta.TenantId }).Count | Should -Be 1
            # The report carries what the real publisher emits and the scanner checks:
            # an inline stylesheet and the recorded logo.
            $report = Get-Content -LiteralPath (Join-Path $out 'SCANTENANT-20261016-110000-assessment.html') -Raw
            $report | Should -Match '<style>'
            $report | Should -Match 'src="https://cdn\.example\.com/logo\.png"'
            # The action plan keeps the byte-order mark the publisher writes for Excel.
            $bytes = [System.IO.File]::ReadAllBytes((Join-Path $out 'SCANTENANT-20261016-110000-report/ActionPlan.csv'))
            ($bytes[0..2] -join ',') | Should -Be '239,187,191'
        }
    }
}

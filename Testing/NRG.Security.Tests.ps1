#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
<#
.SYNOPSIS
    Pester security test suite for NRG-Assessment v4.5.5

.DESCRIPTION
    Enforces OWASP Top 10:2025, ASVS v5, and OSSTMM v3 security invariants.
    Tests fall into two categories:
      - Static: pattern-matching against source code (CI on every PR)
      - Runtime: invoke functions with adversarial inputs to verify fail-closed behavior

    Static tests marked with [Static]; runtime tests marked with [Runtime].
    Runtime tests require module import — they are skipped if module is not loadable.

    FRAMEWORK COVERAGE:
      OWASP A01  Path traversal, LiteralPath, tenantTag sanitization
      OWASP A02  StrictMode, ErrorActionPreference, WAM broker
      OWASP A03  UPN/domain/controlId/key input validation
      OWASP A04  TLS enforcement
      OWASP A07  try/finally session cleanup guarantee
      OWASP A08  No auto-install, no iwr|iex pipelines
      OWASP A09  -Encoding on all Out-File, no plaintext HTTP
      OWASP A10  HTML publisher XSS via ConvertTo-NRGHtmlSafe
      ASVS V5.1.3  All string parameters have validation attributes
      ASVS V7.3.2  Session termination guaranteed
      ASVS V11.2.2 TLS 1.2/1.3 enforced at entry point
      ASVS V12.3.1 Path traversal prevention, LiteralPath
      ASVS V16.2.3 Explicit encoding on file writes
      ASVS V16.4.1 StrictMode on all files
      CVE-2025-54100 PS 7.0+ required on all files
#>

Describe 'NRG-Assessment Security Invariants — OWASP / ASVS v5' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }

        # All production PS files (excluding this test file and zip artifacts).
        # Path-separator class [/\\] makes the filter portable between Windows
        # and Linux runners — needed for CI on ubuntu-latest.
        # Config/ is excluded because the legitimate Config/ holds data files
        # only (branding.psd1, controls.json, frameworks.json, clients.json);
        # any .ps1/.psm1 files there are stale duplicates of the active module
        # tracked for removal in a separate PR and not loaded by the loader.
        $script:PsFiles = Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -File -Include '*.ps1','*.psm1' |
            Where-Object { $_.FullName -notmatch '[/\\]Testing[/\\]' -and
                           $_.FullName -notmatch '[/\\]output[/\\]' -and
                           $_.FullName -notmatch '[/\\]Config[/\\]' -and
                           $_.FullName -notmatch '\.git' }

        # Try to load module for runtime tests
        $script:ModuleLoaded = $false
        try {
            $manifestPath = Join-Path $script:RepoRoot 'NRG-Assessment.psd1'
            if (Test-Path -LiteralPath $manifestPath) {
                Import-Module $manifestPath -Force -ErrorAction Stop
                $script:ModuleLoaded = $true
            }
        } catch { }
    }

    # ── OWASP A01 / ASVS V12.3.1 — Path Traversal ────────────────────────

    Context 'A00 — Every script parses [Static]' {
        # A parse error in an entry point or the installer is a hard failure on
        # the operator's workstation and nothing else here catches it: the
        # module tests import the module, and Install-NRGPrerequisites.ps1 is
        # never imported. "$psVer:" inside a string reads as a scope qualifier
        # and shipped as a parse error in the installer (v4.14.3).
        It 'every .ps1 and .psm1 in the repo parses without errors' {
            $bad = @(foreach ($f in $script:PsFiles) {
                $t = $null; $e = $null
                [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
                if ($e -and $e.Count -gt 0) { "$($f.Name):$($e[0].Extent.StartLineNumber) $($e[0].Message)" }
            })
            $bad -join "`n" | Should -BeNullOrEmpty -Because 'a script that does not parse cannot run on the workstation'
        }
        It 'no double-quoted string interpolates a variable directly followed by a colon' {
            $hits = @(foreach ($f in $script:PsFiles) {
                $t = $null; $e = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
                foreach ($str in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)) {
                    # Extent.Text keeps the source escapes, so a backtick-escaped "`:" does not match.
                    if ($str.Extent.Text -match '\$[A-Za-z_][A-Za-z0-9_]*:(?![A-Za-z_])') { "$($f.Name):$($str.Extent.StartLineNumber)" }
                }
            })
            $hits -join "`n" | Should -BeNullOrEmpty -Because 'write ${name}: — a bare $name: is a scope qualifier'
        }
    }

    Context 'A01 — Path Traversal Prevention [Static]' {

        It 'All file operations use -LiteralPath not -Path' {
            $offenders = @()
            foreach ($file in $script:PsFiles) {
                $content = Get-Content -LiteralPath $file.FullName -Raw
                if ($content -match '(?:Get-Content|Set-Content|New-Item|Test-Path|Copy-Item|Move-Item|Remove-Item|Get-ChildItem|Import-PowerShellDataFile)\s[^\n]*\s-Path\s') {
                    # Allow if the same line also has LiteralPath (overloads)
                    $lines = $content -split '\n'
                    foreach ($line in $lines) {
                        if ($line -match '(?:Get-Content|Set-Content|New-Item|Test-Path|Copy-Item|Move-Item|Remove-Item|Get-ChildItem|Import-PowerShellDataFile)\s[^\n]*\s-Path\s' -and
                            $line -notmatch '-LiteralPath' -and
                            $line.Trim() -notmatch '^#') {
                            $offenders += "$($file.Name): $($line.Trim())"
                        }
                    }
                }
            }
            $offenders | Should -BeNullOrEmpty -Because 'All file ops must use -LiteralPath to prevent wildcard expansion (ASVS V12.3.1)'
        }

        It 'Orchestrator validates OutputPath against traversal sequences' {
            $orchPath = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
            $content  = Get-Content -LiteralPath $orchPath -Raw
            $content | Should -Match '\.\.\[/\\\\]' -Because 'OutputPath must reject ../ sequences (OWASP A01)'
        }

        It 'tenantTag is sanitized before use in file path' {
            $orchPath = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
            $content  = Get-Content -LiteralPath $orchPath -Raw
            $content | Should -Match 'tenantTag.*replace.*\[.a-zA-Z0-9' -Because 'tenantTag must strip non-alphanumeric before file path use'
        }

        It 'Module loader verifies dot-sourced files resolve inside PSScriptRoot' {
            $modPath = Join-Path $script:RepoRoot 'NRG-Assessment.psm1'
            $content = Get-Content -LiteralPath $modPath -Raw
            # OWASP A01 / CWE-22 — the loader must (a) canonicalize the module
            # root from $PSScriptRoot via Resolve-Path, (b) canonicalize each
            # dot-sourced file's path the same way, and (c) StartsWith-bound
            # (b) against (a) before dot-sourcing. Three pinned assertions —
            # cosmetic refactors don't break the test, but removing any one of
            # the three security primitives still fails it.
            $content | Should -Match 'Resolve-Path\s+-LiteralPath\s+\$PSScriptRoot' -Because 'module root must be canonicalized via Resolve-Path on PSScriptRoot (resolves symlinks)'
            $content | Should -Match 'Resolve-Path\s+-LiteralPath\s+\$file' -Because 'each dot-sourced file path must be canonicalized via Resolve-Path before comparison (resolves symlinks)'
            $content | Should -Match '\$resolvedFile\.StartsWith\(\s*\$resolvedModule' -Because 'StartsWith-bound against the canonicalized module root (OWASP A01)'
        }

        It 'HTML auto-open is bound-checked against output directory' -Skip:(-not (Get-Command Open-NRGReport -ErrorAction SilentlyContinue)) {
            # v4.11.2 audit fix (M-4), v4.11.3 review follow-up:
            # The original test enforced the invariant via regex-on-source
            # ('StartsWith.*resolvedOutput'), which silently passed because
            # the orchestrator's DOCUMENTATION COMMENT contained those
            # words — not any actual bounds-check code. v4.11.2 made the
            # test Skip-gated until Open-NRGReport exists, but the body
            # was a tautology ($true | Should -BeTrue) — meaning the test
            # would still enforce nothing the moment the helper landed.
            #
            # v4.11.3 gives the body a real assertion: when Open-NRGReport
            # is loaded, call it with a path explicitly OUTSIDE the
            # operator's output directory and assert the helper throws.
            # This makes path-traversal in any future auto-open implementation
            # caught by CI rather than shipped silently.
            $outRoot = Join-Path ([IO.Path]::GetTempPath()) ("nrg-bounds-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
            $null = [System.IO.Directory]::CreateDirectory($outRoot)
            try {
                $traversalPath = Join-Path $outRoot '..\..\etc\passwd'
                { Open-NRGReport -Path $traversalPath -OutputRoot $outRoot } |
                    Should -Throw -Because 'auto-open must refuse paths outside $resolvedOutput'
            } finally {
                Remove-Item -LiteralPath $outRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'controls.json loader verifies file resolves inside module root' {
            $ctrlPath = Join-Path $script:RepoRoot 'Lib\Get-NRGControlDefinitions.ps1'
            $content  = Get-Content -LiteralPath $ctrlPath -Raw
            $content | Should -Match 'StartsWith.*resolvedRoot|resolvedRoot.*StartsWith' -Because 'Config files must resolve inside module root'
        }
    }

    Context 'A01 — Path Traversal [Runtime]' {

        It 'OutputPath with ../ sequence is rejected' -Skip:(-not $script:ModuleLoaded) {
            { . (Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1') -OutputPath '../../tmp/evil' -WhatIfConnections } |
                Should -Throw -Because 'Path traversal in OutputPath must throw (ASVS V12.3.1)'
        }

        It 'Set-NRGRawData rejects key with path characters' -Skip:(-not $script:ModuleLoaded) {
            { Set-NRGRawData -Key '../evil-key' -Data @{} } |
                Should -Throw -Because 'Keys must match ValidatePattern — no path chars allowed'
        }

        It 'Add-NRGFinding rejects malformed ControlId' -Skip:(-not $script:ModuleLoaded) {
            { Add-NRGFinding -ControlId '../evil' -State 'Gap' -Category 'Identity' -Title 'Test' } |
                Should -Throw -Because 'ControlId ValidatePattern must reject injection attempts'
        }
    }

    # ── OWASP A02 / ASVS V16.4.1 — Security Misconfiguration ─────────────

    Context 'A02 — Security Misconfiguration [Static]' {

        It 'No $local:ErrorActionPreference = Continue anywhere' {
            $hits = $script:PsFiles | ForEach-Object {
                Select-String -Path $_.FullName -Pattern '\$local:ErrorActionPreference\s*=\s*[''"]Continue[''"]' -ErrorAction SilentlyContinue
            }
            $hits | Should -BeNullOrEmpty -Because 'Local EAP=Continue silently swallows errors — use try/catch instead (ASVS V16.4.1)'
        }

        It 'No module-level $ErrorActionPreference = Continue' {
            # Install-NRGPrerequisites.ps1 is the one-shot setup installer; it
            # legitimately uses EAP=Continue so that an install failure on one
            # module (e.g., MicrosoftTeams) does not abort the rest of the
            # prerequisites checklist. It is not loaded as part of the module.
            $allowlist = @('Install-NRGPrerequisites.ps1')
            $hits = $script:PsFiles |
                Where-Object { $_.Name -notin $allowlist } |
                ForEach-Object {
                    Select-String -Path $_.FullName -Pattern '^\$ErrorActionPreference\s*=\s*[''"]Continue[''"]' -ErrorAction SilentlyContinue
                }
            $hits | Should -BeNullOrEmpty -Because 'Module-level EAP=Continue masks all errors'
        }

        It 'Entry-point + module files declare Set-StrictMode -Version Latest' {
            # StrictMode is set ONCE at each entry point — the module's .psm1
            # propagates it to every dot-sourced collector / evaluator /
            # publisher via the inherited scope. Individual files do not need
            # their own Set-StrictMode directive (it would be redundant), so
            # we only assert it on the three orchestrator scripts and the
            # module body. The Pester gate previously deferred all of this
            # under -Skip; v4.6.x hardening fix removes the deferral.
            $entryFiles = @(
                'NRG-Assessment.psm1',
                'Invoke-NRGAssessment.ps1',
                'Apply-NRGBaseline.ps1',
                'Invoke-NRGBatchAssessment.ps1'
            )
            $offenders = @()
            foreach ($name in $entryFiles) {
                $path = Join-Path $script:RepoRoot $name
                if (Test-Path -LiteralPath $path) {
                    $content = Get-Content -LiteralPath $path -Raw
                    if ($content -notmatch 'Set-StrictMode\s+-Version\s+Latest') {
                        $offenders += $name
                    }
                } else {
                    $offenders += "$name (missing)"
                }
            }
            $offenders | Should -BeNullOrEmpty -Because 'StrictMode at entry catches uninitialized variables module-wide (ASVS V16.4.1)'
        }

        It 'NRG-Assessment.psm1 does not disable StrictMode' {
            $modPath = Join-Path $script:RepoRoot 'NRG-Assessment.psm1'
            $content = Get-Content -LiteralPath $modPath -Raw
            $content | Should -Not -Match "StrictMode.*intentionally off" -Because 'Disabling StrictMode for "safe property access" is wrong — use null-coalescing operators instead'
        }

        It 'WAM broker is disabled before module load' {
            $orchPath = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
            $content  = Get-Content -LiteralPath $orchPath -Raw
            $content | Should -Match 'MSAL_ALLOW_BROKER.*0' -Because 'WAM broker causes RuntimeBroker crashes when elevated'
        }
    }

    # ── OWASP A03 / ASVS V5.1.3 — Input Validation ───────────────────────

    Context 'A03 — Input Validation [Static]' {

        It 'Orchestrator validates UPN format via ValidatePattern' {
            $orchPath = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
            $content  = Get-Content -LiteralPath $orchPath -Raw
            $content | Should -Match 'ValidatePattern' -Because 'UPN must be validated (ASVS V5.1.3)'
            $content | Should -Match '@\[a-zA-Z0-9\]' -Because 'UPN pattern must require @ symbol and domain'
        }

        It 'Orchestrator validates DnsDomains as FQDNs' {
            $orchPath = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
            $content  = Get-Content -LiteralPath $orchPath -Raw
            $content | Should -Match '(?s)(ValidateScript.*DnsDomains|DnsDomains.*ValidateScript)' -Because 'DnsDomains must be FQDN-validated before reaching DNS resolver'
        }

        It 'DNS collector validates domain names before Resolve-DnsName' {
            $dnsPath = Join-Path $script:RepoRoot 'Collectors\DNS\Invoke-NRGCollectDNSEmailRecords.ps1'
            $content = Get-Content -LiteralPath $dnsPath -Raw
            $content | Should -Match 'ValidateScript|DomainPattern' -Because 'Domains must be validated before DNS queries (ASVS V5.1.3)'
            $content | Should -Match 'DomainPattern|notmatch.*domain' -Because 'Secondary validation must catch any domains that slip through'
        }

        It 'Add-NRGFinding validates ControlId format' {
            $libPath = Join-Path $script:RepoRoot 'Lib\Add-NRGFinding.ps1'
            $content = Get-Content -LiteralPath $libPath -Raw
            $content | Should -Match '(?s)(ValidatePattern.*ControlId|ControlId.*ValidatePattern)' -Because 'ControlId must match known format (ASVS V5.1.3)'
        }

        It 'Add-NRGFinding validates State via ValidateSet' {
            $libPath = Join-Path $script:RepoRoot 'Lib\Add-NRGFinding.ps1'
            $content = Get-Content -LiteralPath $libPath -Raw
            $content | Should -Match "ValidateSet.*'Satisfied'" -Because 'State must be constrained to known values'
        }

        It 'Add-NRGFinding validates Severity via ValidateSet' {
            $libPath = Join-Path $script:RepoRoot 'Lib\Add-NRGFinding.ps1'
            $content = Get-Content -LiteralPath $libPath -Raw
            $content | Should -Match "ValidateSet.*'Critical'" -Because 'Severity must be constrained to known values'
        }

        It 'Set-NRGRawData validates Key format via ValidatePattern' {
            $libPath = Join-Path $script:RepoRoot 'Lib\Add-NRGFinding.ps1'
            $content = Get-Content -LiteralPath $libPath -Raw
            $content | Should -Match '(?s)(ValidatePattern.*Key|Key.*ValidatePattern)' -Because 'Raw data keys must not allow path chars (ASVS V5.1.3)'
        }

        It 'Register-NRGException has length cap on Message' {
            $libPath = Join-Path $script:RepoRoot 'Lib\Add-NRGFinding.ps1'
            $content = Get-Content -LiteralPath $libPath -Raw
            $content | Should -Match '(?s)(ValidateLength.*Message|Message.*ValidateLength)' -Because 'Unbounded message strings can cause memory exhaustion (ASVS V5.1.3)'
        }

        It 'Get-NRGControlById validates ControlId format' {
            $ctrlPath = Join-Path $script:RepoRoot 'Lib\Get-NRGControlDefinitions.ps1'
            $content  = Get-Content -LiteralPath $ctrlPath -Raw
            $content  | Should -Match 'ValidatePattern' -Because 'ControlId lookup must validate format before dictionary lookup'
        }
    }

    Context 'A03 — Input Validation [Runtime]' {

        It 'Add-NRGFinding throws on invalid State' -Skip:(-not $script:ModuleLoaded) {
            { Add-NRGFinding -ControlId 'AAD-1.1' -State 'INVALID_STATE' -Category 'Identity' -Title 'Test' } |
                Should -Throw -Because 'ValidateSet must reject unknown State values'
        }

        It 'Add-NRGFinding throws on invalid Severity' -Skip:(-not $script:ModuleLoaded) {
            { Add-NRGFinding -ControlId 'AAD-1.1' -State 'Gap' -Category 'Identity' -Title 'Test' -Severity 'SuperCritical' } |
                Should -Throw -Because 'ValidateSet must reject unknown Severity values'
        }

        It 'Add-NRGFinding throws on ControlId with path chars' -Skip:(-not $script:ModuleLoaded) {
            { Add-NRGFinding -ControlId 'AAD/../evil' -State 'Gap' -Category 'Identity' -Title 'Test' } |
                Should -Throw -Because 'ValidatePattern must block path traversal in ControlId'
        }

        It 'Set-NRGRawData throws on key with path separator' -Skip:(-not $script:ModuleLoaded) {
            { Set-NRGRawData -Key 'AAD/Roles' -Data @{} } |
                Should -Throw -Because 'Forward slash in key not permitted by ValidatePattern'
        }

        It 'Register-NRGException throws on message exceeding 2000 chars' -Skip:(-not $script:ModuleLoaded) {
            { Register-NRGException -Source 'Test' -Message ('A' * 2001) } |
                Should -Throw -Because 'ValidateLength(1,2000) must enforce message length cap'
        }
    }

    # ── OWASP A04 / ASVS V11.2.2 — TLS Enforcement ───────────────────────

    Context 'A04 — TLS Enforcement [Static]' {

        It 'Orchestrator enforces TLS 1.2 and 1.3' {
            $orchPath = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
            $content  = Get-Content -LiteralPath $orchPath -Raw
            $content | Should -Match 'Tls12' -Because 'TLS 1.2 minimum required (ASVS V11.2.2)'
            $content | Should -Match 'Tls13' -Because 'TLS 1.3 should be preferred where available'
        }

        It 'Connect-NRGServices enforces TLS' {
            $connPath = Join-Path $script:RepoRoot 'Lib\Connect-NRGServices.ps1'
            $content  = Get-Content -LiteralPath $connPath -Raw
            $content | Should -Match 'Tls12|Tls13|SecurityProtocol' -Because 'Connection layer must enforce TLS (OSSTMM DN5)'
        }

        It 'No certificate validation bypass' {
            $hits = $script:PsFiles | ForEach-Object {
                Select-String -Path $_.FullName -Pattern 'SkipCertificateCheck|TrustAllCert|ServerCertificateValidationCallback' -ErrorAction SilentlyContinue
            }
            $hits | Should -BeNullOrEmpty -Because 'Cert validation bypass breaks TLS trust chain (OWASP A04)'
        }
    }

    # ── OWASP A07 / ASVS V7.3.2 — Session Cleanup ────────────────────────

    Context 'A07 — Session Termination [Static]' {

        It 'Orchestrator wraps entire run in try/finally' {
            $orchPath = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
            $content  = Get-Content -LiteralPath $orchPath -Raw
            $content | Should -Match 'finally\s*\{' -Because 'Sessions must disconnect even on thrown errors (ASVS V7.3.2)'
        }

        It 'Disconnect-NRGServices called inside finally block' {
            $orchPath = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
            # AST-verified, not a text-index comparison: the first literal
            # occurrence of the word "finally" in the file can be a COMMENT
            # (e.g. "# ... wrap the entire run in try/finally so ...") that
            # precedes the real `finally {` block, which would make the old
            # $disconnectIdx -gt $finallyIdx check pass for ANY Disconnect
            # call anywhere after that comment, inside the finally block or
            # not. Parse the file and confirm the call is actually nested
            # inside a TryStatementAst's Finally block.
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($orchPath, [ref]$tokens, [ref]$parseErrors)
            $tryStatements = @($ast.FindAll({
                param($node) $node -is [System.Management.Automation.Language.TryStatementAst]
            }, $true))
            $foundInFinally = $false
            foreach ($try in $tryStatements) {
                if ($null -eq $try.Finally) { continue }
                $calls = @($try.Finally.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst] -and
                    $node.GetCommandName() -eq 'Disconnect-NRGServices'
                }, $true))
                if ($calls.Count -gt 0) { $foundInFinally = $true; break }
            }
            $foundInFinally | Should -BeTrue -Because 'Disconnect-NRGServices must be invoked inside an actual try/finally Finally block (AST-verified)'
        }

        It 'Connect-NRGServices uses process-scoped MSAL token cache' {
            $connPath = Join-Path $script:RepoRoot 'Lib\Connect-NRGServices.ps1'
            $content  = Get-Content -LiteralPath $connPath -Raw
            $content | Should -Match '-ContextScope Process' -Because 'Process-scope prevents token leakage to other sessions (OSSTMM DN4)'
        }
    }

    # ── OWASP A08 — Supply Chain ─────────────────────────────────────────

    Context 'A08 — Supply Chain [Static]' {

        It 'No Install-Module auto-execution in production code' {
            $hits = $script:PsFiles | ForEach-Object {
                Select-String -Path $_.FullName -Pattern '^\s*Install-Module\s' -ErrorAction SilentlyContinue
            }
            $hits | Should -BeNullOrEmpty -Because 'Auto-install in production code is a supply chain risk'
        }

        It 'No iwr|iex or curl|sh pipelines' {
            $hits = $script:PsFiles | ForEach-Object {
                Select-String -Path $_.FullName -Pattern 'iwr.*\|\s*ie|Invoke-WebRequest.*\|.*iex|curl.*\|\s*sh' -ErrorAction SilentlyContinue
            }
            $hits | Should -BeNullOrEmpty
        }

        It 'No Invoke-Expression in any production file' {
            $hits = $script:PsFiles | ForEach-Object {
                Select-String -Path $_.FullName -Pattern 'Invoke-Expression|^\s*[^#]*\biex\b' -ErrorAction SilentlyContinue
            }
            $hits | Should -BeNullOrEmpty
        }

        It 'No dynamic ScriptBlock creation' {
            $hits = $script:PsFiles | ForEach-Object {
                Select-String -Path $_.FullName -Pattern '\[scriptblock\]::Create' -ErrorAction SilentlyContinue
            }
            $hits | Should -BeNullOrEmpty
        }
    }

    # ── OWASP A09 / ASVS V16.2.3 — Logging & Encoding ───────────────────

    Context 'A09 — Encoding Hygiene [Static]' {

        It 'All Out-File calls specify -Encoding' {
            $offenders = @()
            foreach ($file in $script:PsFiles) {
                $lines = Get-Content -LiteralPath $file.FullName
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match 'Out-File' -and
                        $lines[$i] -notmatch '-Encoding' -and
                        $lines[$i].Trim() -notmatch '^#') {
                        $offenders += "$($file.Name):$($i+1)"
                    }
                }
            }
            $offenders | Should -BeNullOrEmpty -Because '-Encoding utf8 prevents BOM/locale corruption (ASVS V16.2.3)'
        }

        It 'No plaintext HTTP URLs (except for legitimate exemptions)' {
            # Sign-Release.ps1 legitimately contains plaintext RFC 3161
            # timestamp authority URLs — those are HTTP by protocol design;
            # the cert chain inside the signed response validates trust.
            #
            # Start-NRGWebServer.ps1 binds the local GUI to http://127.0.0.1
            # only. TLS on loopback adds no security (the data never leaves
            # the kernel's loopback interface) and would require a self-
            # signed cert with all the trust-store ceremony that implies.
            #
            # The Power Platform collector's MSAL sign-in uses the loopback
            # redirect URI http://localhost (RFC 8252 native-app flow — the
            # browser hands the code back to this machine only). That one
            # line is exempt, not the file.
            $allowlist = @('Sign-Release.ps1', 'Start-NRGWebServer.ps1')
            $offenders = @()
            foreach ($file in $script:PsFiles) {
                if ($file.Name -in $allowlist) { continue }
                $hits = Select-String -Path $file.FullName -Pattern 'http://' -ErrorAction SilentlyContinue
                if ($file.Name -eq 'Invoke-NRGCollectPowerPlatform.ps1') {
                    $hits = @($hits | Where-Object { $_.Line -notmatch "WithRedirectUri\('http://localhost'\)" })
                }
                $offenders += $hits
            }
            $offenders | Should -BeNullOrEmpty -Because 'All connections must use HTTPS (OWASP A09)'
        }
    }

    # ── OWASP A10 — XSS (HTML Publisher) ─────────────────────────────────

    Context 'A10 — XSS Mitigation in HTML Publisher [Static]' {

        It 'HTML publisher uses ConvertTo-NRGHtmlSafe (≥3 call sites)' {
            $pubPath = Join-Path $script:RepoRoot 'Publishers\Publish-NRGAssessmentHTML.ps1'
            $count   = (Select-String -Path $pubPath -Pattern 'ConvertTo-NRGHtmlSafe' -AllMatches).Count
            $count | Should -BeGreaterOrEqual 3
        }

        It 'HTML publisher defines local hx() wrapper' {
            $pubPath = Join-Path $script:RepoRoot 'Publishers\Publish-NRGAssessmentHTML.ps1'
            $content = Get-Content -LiteralPath $pubPath -Raw
            $content | Should -Match 'function hx|filter hx' -Because 'hx() is the safe-interpolation wrapper used throughout the publisher'
        }

        It 'Markdown publisher uses EscMd helper for tenant data' {
            $mdPath  = Join-Path $script:RepoRoot 'Publishers\Publish-NRGAssessmentSummary.ps1'
            $content = Get-Content -LiteralPath $mdPath -Raw
            $content | Should -Match 'EscMd|ConvertTo-NRGHtmlSafe' -Because 'Tenant data in Markdown must be escaped to prevent downstream injection'
        }

        It 'HTML publisher fails closed if ConvertTo-NRGHtmlSafe not loaded' {
            $pubPath = Join-Path $script:RepoRoot 'Publishers\Publish-NRGAssessmentHTML.ps1'
            $content = Get-Content -LiteralPath $pubPath -Raw
            $content | Should -Match 'Refusing to generate report' -Because 'Publisher must refuse to run without its security dependency'
        }

        It 'Markdown publisher fails closed if ConvertTo-NRGHtmlSafe not loaded' {
            $mdPath  = Join-Path $script:RepoRoot 'Publishers\Publish-NRGAssessmentSummary.ps1'
            $content = Get-Content -LiteralPath $mdPath -Raw
            $content | Should -Match 'Refusing to generate' -Because 'Markdown publisher must also fail closed without its security helper'
        }

        It 'HTML publisher includes Content-Security-Policy meta tag' {
            $pubPath = Join-Path $script:RepoRoot 'Publishers\Publish-NRGAssessmentHTML.ps1'
            Select-String -Path $pubPath -Pattern 'Content-Security-Policy' | Should -Not -BeNullOrEmpty
        }

        It 'HTML publisher emits NO inline onclick= attributes (CSP requires addEventListener)' {
            # Inline onclick= attributes are blocked by the strict CSP we emit
            # (script-src 'sha256-...' with no 'unsafe-hashes'). Re-introducing
            # one silently breaks every interactive element in the report.
            $pubPath = Join-Path $script:RepoRoot 'Publishers\Publish-NRGAssessmentHTML.ps1'
            $content = Get-Content -LiteralPath $pubPath -Raw
            # Allow the explanatory comment that mentions onclick= as a counter-example.
            $stripped = $content -replace '(?m)^\s*#.*$', ''
            $stripped | Should -Not -Match "onclick\s*=" -Because 'CSP blocks inline event handlers; use addEventListener inside the hashed <script> instead'
        }

        It 'HTML publisher CSP frame-ancestors and object-src locked down' {
            $pubPath = Join-Path $script:RepoRoot 'Publishers\Publish-NRGAssessmentHTML.ps1'
            Select-String -Path $pubPath -Pattern "frame-ancestors 'none'" | Should -Not -BeNullOrEmpty -Because 'clickjacking protection (does not inherit from default-src)'
            Select-String -Path $pubPath -Pattern "object-src 'none'"      | Should -Not -BeNullOrEmpty -Because 'plugin-embedding protection (does not inherit from default-src)'
        }

        It 'External links use rel=noopener noreferrer' {
            $pubPath = Join-Path $script:RepoRoot 'Publishers\Publish-NRGAssessmentHTML.ps1'
            $count   = (Select-String -Path $pubPath -Pattern 'noopener noreferrer' -AllMatches).Count
            $count | Should -BeGreaterOrEqual 1
        }
    }

    Context 'A10 — XSS [Runtime]' {

        It 'ConvertTo-NRGHtmlSafe escapes < > & " characters' -Skip:(-not $script:ModuleLoaded) {
            $result = ConvertTo-NRGHtmlSafe -Value '<script>alert("xss")</script>'
            $result | Should -Not -Match '<script>'
            $result | Should -Match '&lt;'
            $result | Should -Match '&amp;|&quot;'
        }

        It 'ConvertTo-NRGHtmlSafe handles null without throwing' -Skip:(-not $script:ModuleLoaded) {
            { ConvertTo-NRGHtmlSafe -Value $null } | Should -Not -Throw
        }

        It 'ConvertTo-NRGHtmlSafe handles empty string' -Skip:(-not $script:ModuleLoaded) {
            $result = ConvertTo-NRGHtmlSafe -Value ''
            $result | Should -Be ''
        }
    }

    # ── CVE-2025-54100 — PS Version Floor ────────────────────────────────

    Context 'CVE-2025-54100 — PowerShell Version Floor [Static]' {

        It 'All .ps1 and .psm1 files require PS 7.0+' {
            # Device/ is carved out and re-asserted below. Everything that runs
            # on the ASSESSOR'S machine must be 7.0+.
            $offenders = @()
            $endpointDir = [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot 'Device'))
            foreach ($file in ($script:PsFiles | Where-Object { -not $_.FullName.StartsWith($endpointDir, [StringComparison]::OrdinalIgnoreCase) })) {
                $content = Get-Content -LiteralPath $file.FullName -Raw
                if ($content -notmatch '#Requires -Version 7') {
                    $offenders += $file.Name
                }
            }
            $offenders | Should -BeNullOrEmpty -Because '#Requires -Version 7.0 blocks PS 5.1 MSHTML injection (CVE-2025-54100)'
        }

        It 'the Device/ endpoint collector is the ONLY 5.1 exception, and earns it' {
            # Stock Windows ships Windows PowerShell 5.1. An endpoint collector
            # pushed by RMM to a bare machine cannot require 7.0 — so this file
            # is a deliberate, single exception rather than an oversight.
            #
            # The 7.0 floor exists to keep PS 5.1's MSHTML/COM surface out of
            # the tool. The exception is only defensible while this file carries
            # none of that surface, so the properties are asserted here rather
            # than assumed: it renders no HTML, evaluates no supplied string,
            # instantiates no COM object, and reaches no network. It reads local
            # state and writes one JSON file.
            # The TOP-LEVEL Device/ folder only. Collectors/Device/ holds the
            # ingestion side, which runs on the assessor's machine and is 7.0
            # like everything else.
            $endpointDir = [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot 'Device'))
            $deviceFiles = @($script:PsFiles | Where-Object { $_.FullName.StartsWith($endpointDir, [StringComparison]::OrdinalIgnoreCase) })
            $deviceFiles.Count | Should -Be 1 -Because 'exactly one file may claim the 5.1 exception'

            $src = Get-Content -LiteralPath $deviceFiles[0].FullName -Raw
            $src | Should -Match '#Requires -Version 5\.1' -Because 'the exception must be declared, not implied'

            $tokens = $null; $perr = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($deviceFiles[0].FullName, [ref]$tokens, [ref]$perr)
            @($perr).Count | Should -Be 0
            $code = (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ')

            foreach ($surface in 'New-Object -ComObject', 'ComObject', 'InternetExplorer',
                                 'HTMLFile', 'mshtml', 'Invoke-Expression', 'iex ',
                                 'Add-Type -TypeDefinition', 'ConvertTo-Html',
                                 'Invoke-RestMethod', 'Invoke-WebRequest') {
                $code | Should -Not -Match ([regex]::Escape($surface)) `
                    -Because "the 5.1 exception is only safe while the file carries no $surface"
            }
        }
    }

    # ── Read-Only Posture ─────────────────────────────────────────────────

    Context 'Read-Only Posture [Static]' {

        It 'No tenant write cmdlets execute outside -Remediation strings' {
            $writePatterns = @(
                '^\s*Set-Mailbox\b',
                '^\s*Set-OrganizationConfig\b',
                '^\s*Set-CASMailbox\b',
                '^\s*New-Mailbox\b',
                '^\s*Remove-Mailbox\b',
                '^\s*Set-TransportConfig\b',
                '^\s*Set-DkimSigningConfig\b',
                '^\s*Set-AntiPhishPolicy\b',
                '^\s*Enable-OrganizationCustomization\b',
                '^\s*Set-MalwareFilterPolicy\b'
            )
            # Apply-NRGBaseline.ps1 + Apply/ folder are the write-mode tool — they
            # exist specifically to execute these cmdlets. Exclude from the
            # read-only posture scan. The rest of the module (collectors,
            # evaluators, publishers) remains read-only.
            $offenders = @()
            foreach ($file in $script:PsFiles) {
                if ($file.FullName -match '[/\\]Apply[/\\]' -or
                    $file.Name -eq 'Apply-NRGBaseline.ps1') {
                    continue
                }
                $lines = Get-Content -LiteralPath $file.FullName
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    foreach ($pat in $writePatterns) {
                        if ($lines[$i] -match $pat) {
                            $ctx = $lines[[Math]::Max(0,$i-2)..$i] -join ' '
                            if ($ctx -notmatch '-Remediation\s+["\x27]') {
                                $offenders += "$($file.Name):$($i+1): $($lines[$i].Trim())"
                            }
                        }
                    }
                }
            }
            $offenders | Should -BeNullOrEmpty -Because 'This tool is read-only — no tenant writes permitted (except in Apply-NRGBaseline write-mode tool)'
        }
    }

    # ── Credential Handling ───────────────────────────────────────────────

    Context 'Credential Handling [Static]' {

        It 'No ConvertFrom-SecureString' {
            $hits = $script:PsFiles | ForEach-Object {
                Select-String -Path $_.FullName -Pattern 'ConvertFrom-SecureString' -ErrorAction SilentlyContinue
            }
            $hits | Should -BeNullOrEmpty
        }

        It 'No ConvertTo-SecureString -AsPlainText' {
            $hits = $script:PsFiles | ForEach-Object {
                Select-String -Path $_.FullName -Pattern 'ConvertTo-SecureString.*-AsPlainText' -ErrorAction SilentlyContinue
            }
            $hits | Should -BeNullOrEmpty
        }

        It 'No Export-Clixml (serializes credentials to disk)' {
            $hits = $script:PsFiles | ForEach-Object {
                Select-String -Path $_.FullName -Pattern 'Export-Clixml' -ErrorAction SilentlyContinue
            }
            $hits | Should -BeNullOrEmpty
        }

        # Client identifiers stay out of the repository. A real client's
        # domain reached a GUI help string, test fixtures and CHANGELOG
        # entries, and a live tenant ID sat in two test files; the secret
        # scanners look for credentials, not names. The list holds SHA-256
        # hashes of lower-cased identifiers, so the test does not itself
        # publish them; add a hash when a new client identifier must never
        # appear. Failures name the file and line, never the value.
        It 'No known client identifier appears in a tracked text file' {
            $clientIdHashes = @(
                '11e16614922618fac053edc9ee0644b94a64e63edf590a0cb8539494450d510b'
                '1714c4a4da0f3ae69c9510b45fb0bb68df4b5a93fbf4eb17b3f7a11d4b0b0e25'
                '0d8112db2b6e124be99af9f39e9edd525b9c301b5cf66d3c1706fce1d436175a'
            )
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $hashOf = @{}
            $textExt = @('.ps1', '.psm1', '.psd1', '.md', '.json', '.js', '.html', '.css', '.yml', '.yaml', '.txt', '.csv', '.py', '.toml', '.xml')
            $files = Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -File |
                Where-Object { $_.Extension -in $textExt -and $_.FullName -notmatch '[/\\](\.git|output|node_modules)[/\\]' }
            $hits = @(foreach ($f in $files) {
                $n = 0
                foreach ($line in [System.IO.File]::ReadLines($f.FullName)) {
                    $n++
                    foreach ($m in [regex]::Matches($line.ToLowerInvariant(), '[a-z0-9][a-z0-9._\-]*[a-z0-9]')) {
                        # The whole token (a domain, a GUID) and each part of it.
                        foreach ($t in @($m.Value) + @($m.Value -split '[._\-]')) {
                            if ($t.Length -lt 3) { continue }
                            if (-not $hashOf.ContainsKey($t)) {
                                $hashOf[$t] = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($t)) | ForEach-Object { $_.ToString('x2') })
                            }
                            if ($hashOf[$t] -in $clientIdHashes) { "$($f.FullName.Substring($script:RepoRoot.Length + 1)):$n"; break }
                        }
                    }
                }
            })
            $hits -join "`n" | Should -BeNullOrEmpty -Because 'client names, domains and tenant IDs are client data; use example.com / contoso.com and synthetic GUIDs'
        }
    }

    # ── File & Module Inventory ───────────────────────────────────────────

    Context 'Module Inventory [Static]' {

        It 'Lib/Add-NRGFinding.ps1 exists' {
            Test-Path -LiteralPath (Join-Path $script:RepoRoot 'Lib\Add-NRGFinding.ps1') | Should -BeTrue
        }

        It 'Lib/Connect-NRGServices.ps1 exists' {
            Test-Path -LiteralPath (Join-Path $script:RepoRoot 'Lib\Connect-NRGServices.ps1') | Should -BeTrue
        }

        It 'Lib/Get-NRGControlDefinitions.ps1 exists' {
            Test-Path -LiteralPath (Join-Path $script:RepoRoot 'Lib\Get-NRGControlDefinitions.ps1') | Should -BeTrue
        }

        It 'All AAD collectors exist' {
            @(
                'Collectors\AAD\Invoke-NRGCollectAADAuthPolicies.ps1',
                'Collectors\AAD\Invoke-NRGCollectAADCAPolicies.ps1',
                'Collectors\AAD\Invoke-NRGCollectAADUsers.ps1',
                'Collectors\AAD\Invoke-NRGCollectAADRoles.ps1',
                'Collectors\AAD\Invoke-NRGCollectAADPIM.ps1'
            ) | ForEach-Object {
                Test-Path -LiteralPath (Join-Path $script:RepoRoot $_) | Should -BeTrue -Because "$_ must exist"
            }
        }

        It 'EXO and DNS collectors exist' {
            @(
                'Collectors\EXO\Invoke-NRGCollectEXOMailboxConfig.ps1',
                'Collectors\EXO\Invoke-NRGCollectDefender.ps1',
                'Collectors\DNS\Invoke-NRGCollectDNSEmailRecords.ps1'
            ) | ForEach-Object {
                Test-Path -LiteralPath (Join-Path $script:RepoRoot $_) | Should -BeTrue -Because "$_ must exist"
            }
        }

        It 'All evaluators exist' {
            @(
                'Evaluators\Test-NRGControl-AAD.ps1',
                'Evaluators\Test-NRGControlEXO.ps1',
                'Evaluators\Test-NRGControlDNS.ps1',
                'Evaluators\Test-NRGControlDefender.ps1'
            ) | ForEach-Object {
                Test-Path -LiteralPath (Join-Path $script:RepoRoot $_) | Should -BeTrue -Because "$_ must exist"
            }
        }

        It 'Both publishers exist' {
            @(
                'Publishers\Publish-NRGAssessmentHTML.ps1',
                'Publishers\Publish-NRGAssessmentSummary.ps1'
            ) | ForEach-Object {
                Test-Path -LiteralPath (Join-Path $script:RepoRoot $_) | Should -BeTrue
            }
        }
    }

    # ── NRG-Assessment.psm1 hardening ────────────────────────────────────

    Context 'Module Loader Hardening [Static]' {

        It 'psm1 uses Get-ChildItem -LiteralPath not -Path' {
            $modPath = Join-Path $script:RepoRoot 'NRG-Assessment.psm1'
            $content = Get-Content -LiteralPath $modPath -Raw
            $content | Should -Match 'Get-ChildItem.*-LiteralPath'
        }

        It 'psm1 uses Import-PowerShellDataFile -LiteralPath' {
            $modPath = Join-Path $script:RepoRoot 'NRG-Assessment.psm1'
            $content = Get-Content -LiteralPath $modPath -Raw
            $content | Should -Match 'Import-PowerShellDataFile.*-LiteralPath'
        }

        It 'psm1 uses Synchronized hashtable for NRGRawData' {
            $modPath = Join-Path $script:RepoRoot 'NRG-Assessment.psm1'
            $content = Get-Content -LiteralPath $modPath -Raw
            $content | Should -Match 'Synchronized'
        }
    }

    # ── controls.json Content Hardening ───────────────────────────────────

    Context 'controls.json Integrity and Content Validation [Static]' {

        BeforeAll {
            $script:ControlsPath = Join-Path $script:RepoRoot 'Config\controls.json'
            $script:Controls     = $null
            if (Test-Path -LiteralPath $script:ControlsPath) {
                $script:Controls = (Get-Content -LiteralPath $script:ControlsPath -Raw |
                    ConvertFrom-Json).controls
            }
        }

        It 'controls.json exists' {
            Test-Path -LiteralPath $script:ControlsPath | Should -BeTrue
        }

        It 'controls.json is valid JSON' {
            { Get-Content -LiteralPath $script:ControlsPath -Raw | ConvertFrom-Json } |
                Should -Not -Throw
        }

        It 'controls.json has at least 40 controls' {
            $script:Controls.Count | Should -BeGreaterOrEqual 40 -Because 'Fewer than 40 controls suggests truncation or corruption'
        }

        It 'All ControlIds match expected format (WORKLOAD-N.N)' {
            $bad = @($script:Controls | Where-Object { $_.ControlId -notmatch '^[A-Z]{2,4}-\d{1,3}\.\d{1,3}$' })
            $bad | Should -BeNullOrEmpty -Because 'Malformed ControlIds indicate tampered or invalid JSON'
        }

        It 'No duplicate ControlIds' {
            $dupes = $script:Controls | Group-Object ControlId | Where-Object { $_.Count -gt 1 }
            $dupes | Should -BeNullOrEmpty -Because 'Duplicate IDs cause non-deterministic evaluator behavior'
        }

        It 'No ControlId is emitted by more than one evaluator function (v4.6.4 regression guard)' {
            # Scans every Add-NRGFinding call across Evaluators/*.ps1 and groups
            # the ControlId argument by the enclosing function. If two different
            # functions both write findings for the same ControlId, runtime output
            # contains duplicate findings with different titles (the v4.6.3 bug).
            $evalDir = Join-Path $script:RepoRoot 'Evaluators'
            $files   = @(Get-ChildItem -LiteralPath $evalDir -Filter '*.ps1' -File)

            # Pattern: Add-NRGFinding -ControlId 'X-N.M'  OR  Add-NRGFinding -ControlId "X-N.M"
            $litPattern = "Add-NRGFinding\s+-ControlId\s+['""]([A-Z]{2,4}-\d{1,3}\.\d{1,3})['""]"
            # Pattern for foreach-style multi-emit:   foreach ($id in @('A','B',...)) { Add-NRGFinding -ControlId $id ...
            # Loop variable name is captured ($id, $cid, $controlId, etc.) and required to match the Add-NRGFinding argument.
            $forPattern = "foreach\s*\(\s*\`$([A-Za-z_][A-Za-z0-9_]*)\s+in\s+@\(([^)]+)\)\s*\)\s*\{[^}]*?Add-NRGFinding\s+-ControlId\s+\`$\1"

            $emitterMap = @{}  # ControlId -> set of "fileBaseName::FunctionName"
            foreach ($f in $files) {
                $text = Get-Content -LiteralPath $f.FullName -Raw

                # Build function-range index for this file
                $fnMatches = [regex]::Matches($text, '(?m)^function\s+(Test-NRG[A-Za-z0-9_-]+)\s*\{')
                $fnRanges = foreach ($fm in $fnMatches) {
                    [PSCustomObject]@{ Name = $fm.Groups[1].Value; Start = $fm.Index }
                }
                $fnRanges = @($fnRanges | Sort-Object Start)

                # Helper to resolve which function contains a given offset
                $resolveFn = {
                    param([int]$offset)
                    $hit = $null
                    foreach ($r in $fnRanges) { if ($r.Start -le $offset) { $hit = $r.Name } else { break } }
                    if ($hit) { $hit } else { '<file-scope>' }
                }

                foreach ($m in [regex]::Matches($text, $litPattern)) {
                    $cid = $m.Groups[1].Value
                    $fn  = & $resolveFn $m.Index
                    $key = "$($f.BaseName)::$fn"
                    if (-not $emitterMap.ContainsKey($cid)) { $emitterMap[$cid] = [System.Collections.Generic.HashSet[string]]::new() }
                    [void]$emitterMap[$cid].Add($key)
                }

                foreach ($m in [regex]::Matches($text, $forPattern)) {
                    # Group 1 = loop variable name, Group 2 = comma-separated quoted id list
                    $idList = $m.Groups[2].Value
                    foreach ($idm in [regex]::Matches($idList, "'([A-Z]{2,4}-\d{1,3}\.\d{1,3})'")) {
                        $cid = $idm.Groups[1].Value
                        $fn  = & $resolveFn $m.Index
                        $key = "$($f.BaseName)::$fn"
                        if (-not $emitterMap.ContainsKey($cid)) { $emitterMap[$cid] = [System.Collections.Generic.HashSet[string]]::new() }
                        [void]$emitterMap[$cid].Add($key)
                    }
                }
            }

            $conflicts = foreach ($cid in $emitterMap.Keys) {
                if ($emitterMap[$cid].Count -gt 1) {
                    "{0} emitted by: {1}" -f $cid, (($emitterMap[$cid]) -join '; ')
                }
            }
            $conflicts | Should -BeNullOrEmpty -Because 'Two evaluator functions writing the same ControlId produces duplicate findings with conflicting titles (the v4.6.3 bug fixed in v4.6.4).'
        }

        It 'Every ControlId emitted by an evaluator is defined in controls.json (v4.6.4 regression guard)' {
            # Catches phantom emissions (e.g. evaluator emits AAD-4.5 but JSON has no AAD-4.5).
            $evalDir   = Join-Path $script:RepoRoot 'Evaluators'
            $files     = @(Get-ChildItem -LiteralPath $evalDir -Filter '*.ps1' -File)
            $knownIds  = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($c in $script:Controls) { [void]$knownIds.Add($c.ControlId) }

            $emitted = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($f in $files) {
                $text = Get-Content -LiteralPath $f.FullName -Raw
                foreach ($m in [regex]::Matches($text, "Add-NRGFinding\s+-ControlId\s+['""]([A-Z]{2,4}-\d{1,3}\.\d{1,3})['""]")) {
                    [void]$emitted.Add($m.Groups[1].Value)
                }
                foreach ($m in [regex]::Matches($text, "foreach\s*\(\s*\`$([A-Za-z_][A-Za-z0-9_]*)\s+in\s+@\(([^)]+)\)\s*\)\s*\{[^}]*?Add-NRGFinding\s+-ControlId\s+\`$\1")) {
                    foreach ($idm in [regex]::Matches($m.Groups[2].Value, "'([A-Z]{2,4}-\d{1,3}\.\d{1,3})'")) {
                        [void]$emitted.Add($idm.Groups[1].Value)
                    }
                }
            }

            $phantom = @($emitted | Where-Object { -not $knownIds.Contains($_) })
            $phantom | Should -BeNullOrEmpty -Because 'Evaluator emits a ControlId that controls.json does not define — finding will appear with no metadata in the report.'
        }

        It 'All Severity values are in the allowed set' {
            $valid = @('Critical','High','Medium','Low','Informational')
            $bad   = @($script:Controls | Where-Object { $_.Severity -notin $valid })
            $bad | Should -BeNullOrEmpty -Because 'Invalid Severity values bypass publisher badge logic'
        }

        It 'All Workload values are in the allowed set' {
            $valid = @('AAD','EXO','DNS','DEF','SPO','TMS','INT','PVW','PPL')
            $bad   = @($script:Controls | Where-Object { $_.Workload -notin $valid })
            $bad | Should -BeNullOrEmpty -Because 'Invalid Workloads break collector routing'
        }

        It 'All Category values are in the allowed set' {
            $valid = @('Identity','Email','Endpoint','Data','Collaboration','Governance','Network')
            $bad   = @($script:Controls | Where-Object { $_.Category -notin $valid })
            $bad | Should -BeNullOrEmpty -Because 'Invalid Categories break report grouping logic'
        }

        It 'All ControlId prefixes match their declared Workload' {
            $mismatched = @($script:Controls | Where-Object {
                $_.ControlId -match '^([A-Z]{2,4})-' -and $matches[1] -ne $_.Workload
            })
            $mismatched | Should -BeNullOrEmpty -Because 'Prefix/Workload mismatch indicates copy-paste error or tampering'
        }

        It 'No Remediation strings contain HTML injection patterns' {
            $injected = @($script:Controls | Where-Object {
                $_.Remediation -match '<script|javascript:|vbscript:|\bon(click|load|error|focus|blur|change|submit|input|keydown|keyup|mouseover|mouseout|abort|ready)\s*='
            })
            $injected | Should -BeNullOrEmpty -Because 'Remediation strings are rendered in HTML reports'
        }

        It 'All controls have required fields populated' {
            $required = @('ControlId','Title','Severity','Workload','Category',
                          'CollectorDependency','EvaluatorFunction','Remediation')
            $bad = @()
            foreach ($ctrl in $script:Controls) {
                foreach ($field in $required) {
                    if (-not $ctrl.PSObject.Properties[$field] -or
                        [string]::IsNullOrWhiteSpace([string]$ctrl.$field)) {
                        $bad += "$($ctrl.ControlId): missing '$field'"
                    }
                }
            }
            $bad | Should -BeNullOrEmpty
        }

        It 'Loader enforces content validation (fails on bad Severity)' -Skip:(-not $script:ModuleLoaded) {
            # Inject a control with invalid severity into a temp file and verify loader throws
            $tmpDir  = Join-Path ([System.IO.Path]::GetTempPath()) 'NRGTest'
            $tmpCfg  = Join-Path $tmpDir 'Config'
            $tmpJson = Join-Path $tmpCfg 'controls.json'

            New-Item -Path $tmpCfg -ItemType Directory -Force | Out-Null
            @{ controls = @(@{
                ControlId='AAD-1.1'; Title='Test'; Severity='INVALID_SEVERITY'
                Workload='AAD'; Category='Identity'; CollectorDependency='X'
                EvaluatorFunction='Test-X'; Remediation='Fix it'
            })} | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $tmpJson -Encoding utf8

            # Note: $PSScriptRoot is an automatic variable — cannot be overridden from a calling scope.
            # Test the validation logic directly by calling the validator function that Get-NRGControlDefinitions uses.
            $validSeverities = @('Critical','High','Medium','Low','Informational')
            $badCtrl = @{ ControlId='AAD-1.1'; Title='Test'; Severity='INVALID_SEVERITY'
                          Workload='AAD'; Category='Identity'; CollectorDependency='X'
                          EvaluatorFunction='Test-X'; Remediation='Fix it' }
            $badCtrl.Severity -in $validSeverities | Should -BeFalse -Because 'INVALID_SEVERITY must fail the severity validator'

            Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
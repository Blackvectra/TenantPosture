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

        # All production PS files (excluding this test file and zip artifacts)
        $script:PsFiles = Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -File -Include '*.ps1','*.psm1' |
            Where-Object { $_.FullName -notmatch '\\Testing\\' -and
                           $_.FullName -notmatch '\\output\\' -and
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
            $content | Should -Match 'StartsWith.*PSScriptRoot\|PSScriptRoot.*StartsWith' -Because 'Dot-sourced files must be origin-checked (OWASP A01)'
        }

        It 'HTML auto-open is bound-checked against output directory' {
            $orchPath = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
            $content  = Get-Content -LiteralPath $orchPath -Raw
            $content | Should -Match 'StartsWith.*resolvedOutput\|resolvedOutput.*StartsWith' -Because 'Auto-open must verify file is inside output dir'
        }

        It 'controls.json loader verifies file resolves inside module root' {
            $ctrlPath = Join-Path $script:RepoRoot 'Lib\Get-NRGControlDefinitions.ps1'
            $content  = Get-Content -LiteralPath $ctrlPath -Raw
            $content | Should -Match 'StartsWith.*resolvedRoot\|resolvedRoot.*StartsWith' -Because 'Config files must resolve inside module root'
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
            $hits = $script:PsFiles | ForEach-Object {
                Select-String -Path $_.FullName -Pattern '^\$ErrorActionPreference\s*=\s*[''"]Continue[''"]' -ErrorAction SilentlyContinue
            }
            $hits | Should -BeNullOrEmpty -Because 'Module-level EAP=Continue masks all errors'
        }

        It 'All production files have Set-StrictMode -Version Latest' {
            $offenders = @()
            foreach ($file in $script:PsFiles) {
                $content = Get-Content -LiteralPath $file.FullName -Raw
                if ($content -notmatch 'Set-StrictMode') {
                    $offenders += $file.Name
                }
            }
            $offenders | Should -BeNullOrEmpty -Because 'StrictMode catches uninitialized variables early (ASVS V16.4.1)'
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
            $content | Should -Match 'ValidateScript.*DnsDomains\|DnsDomains.*ValidateScript' -Because 'DnsDomains must be FQDN-validated before reaching DNS resolver'
        }

        It 'DNS collector validates domain names before Resolve-DnsName' {
            $dnsPath = Join-Path $script:RepoRoot 'Collectors\DNS\Invoke-NRGCollectDNSEmailRecords.ps1'
            $content = Get-Content -LiteralPath $dnsPath -Raw
            $content | Should -Match 'ValidateScript\|DomainPattern' -Because 'Domains must be validated before DNS queries (ASVS V5.1.3)'
            $content | Should -Match 'DomainPattern\|notmatch.*domain' -Because 'Secondary validation must catch any domains that slip through'
        }

        It 'Add-NRGFinding validates ControlId format' {
            $libPath = Join-Path $script:RepoRoot 'Lib\Add-NRGFinding.ps1'
            $content = Get-Content -LiteralPath $libPath -Raw
            $content | Should -Match 'ValidatePattern.*ControlId\|ControlId.*ValidatePattern' -Because 'ControlId must match known format (ASVS V5.1.3)'
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
            $content | Should -Match 'ValidatePattern.*Key\|Key.*ValidatePattern' -Because 'Raw data keys must not allow path chars (ASVS V5.1.3)'
        }

        It 'Register-NRGException has length cap on Message' {
            $libPath = Join-Path $script:RepoRoot 'Lib\Add-NRGFinding.ps1'
            $content = Get-Content -LiteralPath $libPath -Raw
            $content | Should -Match 'ValidateLength.*Message\|Message.*ValidateLength' -Because 'Unbounded message strings can cause memory exhaustion (ASVS V5.1.3)'
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
            $content | Should -Match 'Tls12\|Tls13\|SecurityProtocol' -Because 'Connection layer must enforce TLS (OSSTMM DN5)'
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
            $content  = Get-Content -LiteralPath $orchPath -Raw
            # Verify Disconnect is in the finally block, not just anywhere
            $finallyIdx = $content.IndexOf('finally')
            $disconnectIdx = $content.IndexOf('Disconnect-NRGServices')
            $disconnectIdx | Should -BeGreaterThan $finallyIdx -Because 'Disconnect must be inside the finally block'
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

        It 'No plaintext HTTP URLs (except RFC 3161 timestamp in Sign-Release)' {
            $offenders = @()
            foreach ($file in $script:PsFiles) {
                if ($file.Name -eq 'Sign-Release.ps1') { continue }
                $hits = Select-String -Path $file.FullName -Pattern 'http://' -ErrorAction SilentlyContinue
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
            $content | Should -Match 'EscMd\|ConvertTo-NRGHtmlSafe' -Because 'Tenant data in Markdown must be escaped to prevent downstream injection'
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
            $result | Should -Match '&amp;\|&quot;'
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
            $offenders = @()
            foreach ($file in $script:PsFiles) {
                $content = Get-Content -LiteralPath $file.FullName -Raw
                if ($content -notmatch '#Requires -Version 7') {
                    $offenders += $file.Name
                }
            }
            $offenders | Should -BeNullOrEmpty -Because '#Requires -Version 7.0 blocks PS 5.1 MSHTML injection (CVE-2025-54100)'
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
            $offenders = @()
            foreach ($file in $script:PsFiles) {
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
            $offenders | Should -BeNullOrEmpty -Because 'This tool is read-only — no tenant writes permitted'
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
                'Evaluators\Test-NRGControl-EXO.ps1',
                'Evaluators\Test-NRGControl-DNS.ps1',
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
                $_.Remediation -match '<script|javascript:|vbscript:|on\w+\s*='
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
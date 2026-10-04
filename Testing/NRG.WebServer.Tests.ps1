#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
<#
.SYNOPSIS
    Pester invariants for the local web GUI (Lib/Start-NRGWebServer.ps1 + Web/).

.DESCRIPTION
    The GUI is a thin Pode-backed loopback server. These tests pin its
    security posture so that future edits cannot regress:

      - The server binds to 127.0.0.1 only — never 0.0.0.0, never an external
        interface. Exposure to the network is the dominant risk for a tool
        that handles tenant data.
      - The server-side CSP middleware emits the strict directives the rest
        of the project enforces (default-src 'none', frame-ancestors 'none',
        object-src 'none').
      - The web HTML carries NO inline event handlers (onclick, etc.) — same
        invariant as the assessment-report publisher (CSP blocks them).
      - The web HTML carries NO inline <script> blocks (CSP allows only
        same-origin /static/app.js).
      - Pode is loaded as a SOFT dependency, not in RequiredModules; CLI
        users without Pode installed must not be broken by the module load.
      - The -Web flag exists on Invoke-NRGAssessment.ps1 and short-circuits
        to Start-NRGWebServer.

    Most of these are static (file-content checks) and run on every CI push.
    The 'Server actually starts' context is NOT static: it boots the real
    server on a loopback port and probes it. That context exists because every
    other test here passed while -Web was completely broken -- Pode rejects
    $using: inside its scriptblocks, so the server died on start and no
    file-content check could see it. It is skipped when Pode is unavailable.
#>

Describe 'NRG-Assessment Web GUI invariants — Lib/Start-NRGWebServer.ps1 + Web/' {

    BeforeAll {
        $script:RepoRoot   = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:ServerPath = Join-Path $script:RepoRoot 'Lib\Start-NRGWebServer.ps1'
        $script:WebRoot    = Join-Path $script:RepoRoot 'Web'
        $script:IndexHtml  = Join-Path $script:WebRoot  'index.html'
        $script:AppJs      = Join-Path $script:WebRoot  'static\app.js'
        $script:AppCss     = Join-Path $script:WebRoot  'static\app.css'
        $script:EntryScript = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
        $script:ManifestPsd1 = Join-Path $script:RepoRoot 'NRG-Assessment.psd1'
    }

    Context 'Files exist' {
        It 'Lib/Start-NRGWebServer.ps1 is present' {
            Test-Path -LiteralPath $script:ServerPath | Should -BeTrue
        }
        It 'Web/index.html is present' {
            Test-Path -LiteralPath $script:IndexHtml | Should -BeTrue
        }
        It 'Web/static/app.js is present' {
            Test-Path -LiteralPath $script:AppJs | Should -BeTrue
        }
        It 'Web/static/app.css is present' {
            Test-Path -LiteralPath $script:AppCss | Should -BeTrue
        }
    }

    Context 'Tenant input and run list' {
        It 'a user name typed in the tenant box is reduced to its domain, and the refusal message says what to enter' {
            $js = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Web' 'static' 'app.js') -Raw
            $js | Should -Match 'function normalizeDomain'
            $js | Should -Match "lastIndexOf\('@'\)"
            $js | Should -Match 'Enter the tenant domain, for example'
            $js | Should -Not -Match "setStatus\('Invalid domain format'\)"
        }
        It 'the run list excludes incident-response mailbox results' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib' 'Start-NRGWebServer.ps1') -Raw
            $src | Should -Match '-email-results'
        }
    }

    Context 'A scan started from the page signs in through the supported default path' {
        It 'the scan job sets no NRG_DISABLE_WAM and Connect-NRGServices writes no Graph options' {
            # Set-MgGraphOption -DisableLoginByWAM only takes effect with a custom ClientId (the tool
            # uses the default client) and writes a settings file to the operator's profile, so the
            # GUI must not use it. Sign-in from the GUI is a documented known limitation instead.
            $web = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib' 'Start-NRGWebServer.ps1') -Raw
            $web | Should -Not -Match 'NRG_DISABLE_WAM'
            $conn = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib' 'Connect-NRGServices.ps1') -Raw
            $conn | Should -Not -Match 'NRG_DISABLE_WAM'
            $conn | Should -Not -Match 'Set-MgGraphOption'
        }
    }

    Context 'Server bind + CSP posture' {
        BeforeAll {
            $script:ServerSrc = Get-Content -LiteralPath $script:ServerPath -Raw
        }

        It 'Binds to 127.0.0.1 only (never 0.0.0.0 or *)' {
            $script:ServerSrc | Should -Match "Add-PodeEndpoint -Address '127\.0\.0\.1'" `
                -Because 'Loopback binding is load-bearing — the GUI must never be reachable from the network'
            $script:ServerSrc | Should -Not -Match "Add-PodeEndpoint -Address '(0\.0\.0\.0|\*)'" `
                -Because 'Binding to all interfaces would expose the GUI to the LAN'
        }

        It "Emits CSP default-src 'none' on every response" {
            $script:ServerSrc | Should -Match "default-src 'none'"
        }

        It "Emits CSP frame-ancestors 'none' (clickjacking protection)" {
            $script:ServerSrc | Should -Match "frame-ancestors 'none'"
        }

        It "Emits CSP object-src 'none' (plugin-embedding protection)" {
            $script:ServerSrc | Should -Match "object-src 'none'"
        }

        It "Restricts script-src to 'self' (no inline, no remote)" {
            $script:ServerSrc | Should -Match "script-src 'self'"
        }
    }

    Context 'No path traversal in route handlers' {
        BeforeAll {
            $script:ServerSrc = Get-Content -LiteralPath $script:ServerPath -Raw
        }

        It ':tenant + :id route parameters are guarded against path separators' {
            # The /api/runs/:tenant/:id/report handler must reject anything
            # containing / or \ in either segment — otherwise an attacker
            # could escape the output directory.
            $script:ServerSrc | Should -Match "tenant -match '\[\\\\/\]'" `
                -Because 'Without this guard, ../ in :tenant could read arbitrary files'
            $script:ServerSrc | Should -Match "id -match '\[\\\\/\]'"
        }

        It 'POST /api/scan validates domain against an FQDN regex' {
            $script:ServerSrc | Should -Match 'domain -notmatch' `
                -Because 'Unvalidated domain input is fed to the child scan job; an attacker could inject shell-substitution-like chars'
        }
    }

    Context 'Web HTML and JS are CSP-friendly' {
        BeforeAll {
            $script:IndexSrc = Get-Content -LiteralPath $script:IndexHtml -Raw
            $script:AppJsSrc = Get-Content -LiteralPath $script:AppJs -Raw
        }

        It 'index.html has zero inline onclick / onload / onsubmit attributes' {
            # The CSP we emit (script-src 'self') blocks inline event handlers;
            # any onclick=, onload=, etc. attribute on an HTML element would be
            # silently dead. The assessment-report publisher already enforces
            # this invariant — same rule applies here.
            $script:IndexSrc | Should -Not -Match '\son[a-z]+\s*=\s*["'']' `
                -Because 'Inline event handlers are blocked by script-src self; use addEventListener in app.js instead'
        }

        It 'index.html has no inline <script> blocks (only external src)' {
            # An empty `<script src=...>` tag is fine. A `<script>...payload...</script>`
            # block would require either 'unsafe-inline' or a hashed CSP entry.
            $inlineScripts = [regex]::Matches($script:IndexSrc, '(?s)<script(?![^>]*\bsrc=)[^>]*>(.+?)</script>')
            $inlineScripts.Count | Should -Be 0 -Because 'script-src self forbids inline scripts'
        }

        It 'app.js does not use eval, new Function, or document.write' {
            $script:AppJsSrc | Should -Not -Match '\beval\s*\('
            $script:AppJsSrc | Should -Not -Match '\bnew\s+Function\s*\('
            $script:AppJsSrc | Should -Not -Match '\bdocument\s*\.\s*write\s*\('
        }

        It 'app.js wires DOM events via addEventListener (not by string handlers)' {
            $script:AppJsSrc | Should -Match 'addEventListener' `
                -Because 'addEventListener is the only CSP-friendly handler pattern'
        }

        It 'app.js escapes HTML output (no innerHTML on raw API values)' {
            $script:AppJsSrc | Should -Match 'escapeHtml|textContent' `
                -Because 'Tenant names / domains from the API must not flow into innerHTML unescaped'
        }
    }

    Context 'Module integration' {
        It '-Web flag exists on the entry script' {
            $entry = Get-Content -LiteralPath $script:EntryScript -Raw
            $entry | Should -Match '\[switch\]\s*\$Web' `
                -Because 'Operators invoke the GUI via Invoke-NRGAssessment.ps1 -Web'
        }

        It '-Web short-circuits to Start-NRGWebServer (no scan side-effects)' {
            $entry = Get-Content -LiteralPath $script:EntryScript -Raw
            $entry | Should -Match 'if \(\$Web\)\s*\{[\s\S]*Start-NRGWebServer'
        }

        It 'Start-NRGWebServer is in the manifest FunctionsToExport list' {
            $m = Import-PowerShellDataFile -LiteralPath $script:ManifestPsd1 -ErrorAction Stop
            $m.FunctionsToExport | Should -Contain 'Start-NRGWebServer'
        }

        It 'Pode is NOT in RequiredModules (soft dependency — CLI users unaffected)' {
            $m = Import-PowerShellDataFile -LiteralPath $script:ManifestPsd1 -ErrorAction Stop
            $required = if ($m.ContainsKey('RequiredModules')) {
                $m.RequiredModules | ForEach-Object {
                    if ($_ -is [hashtable]) { $_.ModuleName } else { [string]$_ }
                }
            } else { @() }
            $required | Should -Not -Contain 'Pode' `
                -Because 'Pode is only needed for -Web; CLI users should not be forced to install it'
        }
    }

    Context 'No $using: inside the Pode scriptblocks' {
        # Pode runs the server block and every route body through
        # Invoke-PodeScriptBlock in its own runspaces. A Using variable is
        # valid only with Invoke-Command / Start-Job / InlineScript, so Pode
        # fails the entire server start with "A Using variable cannot be
        # retrieved." This is a static guard that runs even without Pode
        # installed, because it is the cheapest possible catch for a bug that
        # otherwise only shows up at runtime.
        BeforeAll {
            $script:Src = Get-Content -LiteralPath $script:ServerPath -Raw

            # Isolate the Pode server block: from the $serverBlock assignment
            # to the Start-PodeServer call that consumes it. Start-Job above it
            # legitimately uses $using: and must not be caught.
            $m = [regex]::Match(
                $script:Src,
                '\$serverBlock\s*=\s*\{[\s\S]*?\}\.GetNewClosure\(\)',
                'IgnoreCase')
            $script:ServerBlockSrc = if ($m.Success) { $m.Value } else { '' }
        }

        It 'the Pode server block is present and closed with .GetNewClosure()' {
            # Start-PodeServer has no -ArgumentList, so the closure is the only
            # way registration-time values ($Port, $webRoot) reach the block.
            $script:ServerBlockSrc | Should -Not -BeNullOrEmpty `
                -Because 'without .GetNewClosure() the server block cannot see $Port or $webRoot'
        }

        It 'contains no $using: references anywhere inside it' {
            # Guard first: an unmatched block is the empty string, which has
            # zero $using: hits and would pass this vacuously -- exactly the
            # absence-of-evidence shape the rest of this tool refuses.
            $script:ServerBlockSrc | Should -Not -BeNullOrEmpty `
                -Because 'an unfound server block must fail this test, not pass it empty'
            $hits = [regex]::Matches($script:ServerBlockSrc, '\$using:') | ForEach-Object { $_.Value }
            $hits.Count | Should -Be 0 `
                -Because 'Pode rejects $using: and fails the whole server start'
        }

        It 'is consumed by Start-PodeServer' {
            $script:Src | Should -Match 'Start-PodeServer[^\r\n]*-ScriptBlock\s+\$serverBlock'
        }

        It 'reads clients.json as $raw.clients, not the wrapper object' {
            # clients.json is { "clients": [ ... ] }. Enumerating the wrapper
            # yielded one row whose ClientName/TenantDomain do not exist, so
            # the picker showed a single blank client.
            $script:Src | Should -Match '@\(\$raw\.clients\)'
        }
    }

    Context 'Server actually starts and serves' -Skip:(-not (Get-Module -ListAvailable -Name Pode | Where-Object { $_.Version -ge [version]'2.10.0' })) {
        # The test that would have caught the shipped bug. Everything else in
        # this file is a grep; a grep cannot tell you the server never came up.
        BeforeAll {
            $script:Port = Get-Random -Minimum 20000 -Maximum 29000
            $boot = Join-Path ([System.IO.Path]::GetTempPath()) ("nrgweb-{0}.ps1" -f ([Guid]::NewGuid().ToString('N')))
            $script:BootFile = $boot
            $script:LogFile  = "$boot.log"
            @"
`$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. '$($script:ServerPath)'
Start-NRGWebServer -Port $($script:Port) -ScriptDir '$($script:RepoRoot)' -NoBrowser
"@ | Set-Content -LiteralPath $boot -Encoding utf8

            # The server reads ./output relative to its working directory: seed one assessment run
            # and one incident-response run in a temp directory so the run list can be checked.
            $script:WebWork = Join-Path ([System.IO.Path]::GetTempPath()) ("nrgweb-work-{0}" -f ([Guid]::NewGuid().ToString('N')))
            $seed = Join-Path $script:WebWork 'output' 'ndaco.org'
            New-Item -ItemType Directory -Path $seed -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $seed 'NRGTS-20261002-114907-results.json') -Value '{}' -Encoding utf8
            Set-Content -LiteralPath (Join-Path $seed 'NRGTS-20261002-114907-assessment.html') -Value '<html></html>' -Encoding utf8
            $ir = Join-Path $script:WebWork 'output' 'Administrator_ndaco.org'
            New-Item -ItemType Directory -Path $ir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $ir '20261002-122037-email-results.json') -Value '{}' -Encoding utf8

            $pwshExe = (Get-Process -Id $PID).Path
            $script:Proc = Start-Process -FilePath $pwshExe `
                -WorkingDirectory $script:WebWork `
                -ArgumentList @('-NoProfile', '-File', $boot) `
                -RedirectStandardOutput $script:LogFile `
                -RedirectStandardError  "$($script:LogFile).err" `
                -PassThru
            # NOTE: no -WindowStyle. It throws NotSupportedException on
            # non-Windows editions, which fails the whole context in CI.

            # Poll until it answers rather than sleeping a fixed amount.
            $script:Up = $false
            foreach ($i in 1..40) {
                Start-Sleep -Milliseconds 750
                try {
                    $null = Invoke-WebRequest -Uri "http://127.0.0.1:$($script:Port)/" -TimeoutSec 3 -UseBasicParsing
                    $script:Up = $true
                    break
                } catch { }
            }
        }

        AfterAll {
            if ($script:Proc -and -not $script:Proc.HasExited) {
                Stop-Process -Id $script:Proc.Id -Force -ErrorAction SilentlyContinue
            }
            foreach ($f in @($script:BootFile, $script:LogFile, "$($script:LogFile).err")) {
                if ($f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
            }
            if ($script:WebWork) { Remove-Item -LiteralPath $script:WebWork -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'comes up and serves the index page' {
            $script:Up | Should -BeTrue -Because 'the server must actually start, not just parse'
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$($script:Port)/" -TimeoutSec 5 -UseBasicParsing
            $r.StatusCode | Should -Be 200
            $r.Content | Should -Match '<!DOCTYPE html>'
        }

        It 'serves /api/clients as a JSON array, never null' {
            # $clients is built by a pipeline; when it yields nothing the
            # variable is $null, which serializes as JSON null, and app.js
            # calls .forEach on it outside its try.
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$($script:Port)/api/clients" -TimeoutSec 5 -UseBasicParsing
            $r.StatusCode | Should -Be 200
            $r.Content.Trim() | Should -Not -Be 'null'
            { $r.Content | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        }

        It 'serves /api/runs as a JSON array' {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$($script:Port)/api/runs" -TimeoutSec 5 -UseBasicParsing
            $r.StatusCode | Should -Be 200
            $r.Content.Trim() | Should -Not -Be 'null'
        }

        It 'lists the assessment run and not the incident-response mailbox run' {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$($script:Port)/api/runs" -TimeoutSec 5 -UseBasicParsing
            $runs = @($r.Content | ConvertFrom-Json)
            $runs.Count | Should -Be 1
            $runs[0].tenant | Should -Be 'ndaco.org'
            $runs[0].hasReport | Should -BeTrue
        }

        It 'emits the strict CSP header on a real response' {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$($script:Port)/" -TimeoutSec 5 -UseBasicParsing
            ([string]$r.Headers['Content-Security-Policy']) | Should -Match "default-src 'none'"
        }

        It 'serves the static assets the page references' {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$($script:Port)/static/app.js" -TimeoutSec 5 -UseBasicParsing
            $r.StatusCode | Should -Be 200
        }
    }
}

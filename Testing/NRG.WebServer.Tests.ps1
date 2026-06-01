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

    These tests are static (file-content checks) and run on every CI push;
    no runtime server is started.
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
}

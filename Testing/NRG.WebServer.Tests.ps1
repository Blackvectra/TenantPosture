#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
<#
.SYNOPSIS
    Pester invariants for the local web GUI (Lib/Start-NRGWebServer.ps1 + Lib/Get-NRGWebRunIndex.ps1 + Web/).

.DESCRIPTION
    The GUI is a thin Pode-backed loopback server. These tests pin its
    security posture so that future edits cannot regress:

      - The server binds to 127.0.0.1 only — never 0.0.0.0, never an external
        interface. Exposure to the network is the dominant risk for a tool
        that handles tenant data.
      - The server-side CSP middleware emits the strict directives the rest
        of the project enforces (default-src 'none', frame-ancestors 'none',
        object-src 'none'), once, for every response, the report site included.
      - The web HTML carries NO inline event handlers (onclick, etc.) — same
        invariant as the assessment-report publisher (CSP blocks them).
      - The web HTML carries NO inline <script> blocks (CSP allows only
        same-origin /static/app.js).
      - Pode is loaded as a SOFT dependency, not in RequiredModules; CLI
        users without Pode installed must not be broken by the module load.
      - The -Web flag exists on Invoke-NRGAssessment.ps1 and short-circuits
        to Start-NRGWebServer.
      - Runs from both output layouts are listed once each (output\<domain>\
        from the GUI and batch runner, flat output\ from a command-line run),
        the multi-page report site is served only from a run's own -report
        folder (.html and .csv only), and no request can reach a file outside
        it. The guards are pure functions (Lib/Get-NRGWebRunIndex.ps1) so they
        are tested here WITHOUT a server and run in CI.
      - Calling Start-NRGWebServer without -ScriptDir resolves the repository
        root, not Lib.

    Most of these are static (file-content checks) or call the pure helpers,
    and run on every CI push. The 'Server actually starts' context is NOT
    static: it boots the real server on a loopback port and probes it. That
    context exists because every other test here passed while -Web was
    completely broken -- Pode rejects $using: inside its scriptblocks, so the
    server died on start and no file-content check could see it. It is skipped
    when Pode is unavailable, so CI skips it: run this file locally with Pode
    installed (Install-PSResource Pode -TrustRepository -Scope CurrentUser).
#>

Describe 'NRG-Assessment Web GUI invariants — Lib/Start-NRGWebServer.ps1 + Web/' {

    BeforeAll {
        $script:RepoRoot   = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:ServerPath = Join-Path $script:RepoRoot 'Lib\Start-NRGWebServer.ps1'
        $script:IndexLib   = Join-Path $script:RepoRoot 'Lib\Get-NRGWebRunIndex.ps1'
        $script:FieldLib   = Join-Path $script:RepoRoot 'Lib\Get-NRGObjectField.ps1'
        $script:WebRoot    = Join-Path $script:RepoRoot 'Web'
        $script:IndexHtml  = Join-Path $script:WebRoot  'index.html'
        $script:AppJs      = Join-Path $script:WebRoot  'static\app.js'
        $script:AppCss     = Join-Path $script:WebRoot  'static\app.css'
        $script:EntryScript = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
        $script:ManifestPsd1 = Join-Path $script:RepoRoot 'NRG-Assessment.psd1'

        # One fixture, used by the no-server tests and by the real-server
        # context. Returns where it was built and whether the filesystem let it
        # make symbolic links (Windows without developer mode does not).
        #
        #   output\
        #     CLITENANT-20261002-114907-results.json      flat CLI run; Metadata AFTER RawData
        #     CLITENANT-20261002-114907-assessment.html
        #     CLITENANT-20261002-114907-report\           index.html AAD.html ActionPlan.csv
        #                                                 + notes.txt raw.json (not servable)
        #     METAFIRST / NOMETA / BROKEN / HOSTILE / FLATNDACO   flat runs, other label cases
        #     ndaco.org\NDACO-20261002-100000-*           GUI-layout run
        #     Administrator_ndaco.org\...-email-results.json     IR run (never listed)
        #     *-signin-triage.json, *-signin-triage-results.json (never listed)
        #     _flat\RESERVED-*                            a real folder with the reserved name
        #     outside.html                                a file next to, not in, the report folder
        #   secret.html                                   a file above the output folder
        $script:NewFixture = {
            param([string] $Work)
            $out = Join-Path $Work 'output'
            $put = {
                param($Path, $Value)
                $null = New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force
                Set-Content -LiteralPath $Path -Value $Value -Encoding utf8
            }
            $stamp = { param($Path, [datetime] $When) [System.IO.File]::SetLastWriteTime($Path, $When) }

            $id = 'CLITENANT-20261002-114907'
            & $put (Join-Path $out "$id-results.json")    '{"RawData":{"k":[1,2,3]},"Findings":[],"Metadata":{"TenantDomain":"cli-tenant.example","ToolVersion":"4.14.3"}}'
            & $put (Join-Path $out "$id-assessment.html") '<!doctype html><html><body>FLAT-REPORT-MARKER</body></html>'
            $site = Join-Path $out "$id-report"
            & $put (Join-Path $site 'index.html')      '<!doctype html><html><head><meta charset="utf-8"><style>b{color:red}</style></head><body>SITE-INDEX-MARKER <a href="AAD.html">AAD</a> <a href="ActionPlan.csv">plan</a></body></html>'
            & $put (Join-Path $site 'AAD.html')        '<!doctype html><html><body>SITE-AAD-MARKER</body></html>'
            & $put (Join-Path $site 'ActionPlan.csv')  "Control,Owner`nSITE-CSV-MARKER,`n"
            & $put (Join-Path $site 'notes.txt')       'TXT-MARKER'
            & $put (Join-Path $site 'raw.json')        '{"m":"JSON-MARKER"}'
            & $put (Join-Path $out 'outside.html')     '<html>OUTSIDE-MARKER</html>'
            & $put (Join-Path $Work 'secret.html')     '<html>SECRET-MARKER</html>'
            # Real targets ABOVE the output folder, shaped like a report and a
            # report site, so a segment that moved the boundary up would find them.
            & $put (Join-Path $Work "$id-assessment.html") '<html>ABOVE-REPORT-MARKER</html>'
            & $put (Join-Path $Work 'secret-report\index.html') '<html>ABOVE-SITE-MARKER</html>'

            & $put (Join-Path $out 'METAFIRST-20261002-080000-results.json') '{"Metadata":{"TenantDomain":"meta-first.example"},"RawData":{}}'
            & $put (Join-Path $out 'NOMETA-20261001-090000-results.json')    '{}'
            & $put (Join-Path $out 'BROKEN-20261001-080000-results.json')    '{not json'
            & $put (Join-Path $out 'HOSTILE-20261001-070000-results.json')   '{"Metadata":{"TenantDomain":"<img src=x onerror=alert(1)>"}}'
            & $put (Join-Path $out 'FLATNDACO-20261002-090000-results.json') '{"Metadata":{"TenantDomain":"ndaco.org"}}'

            & $put (Join-Path $out 'ndaco.org\NDACO-20261002-100000-results.json')    '{}'
            & $put (Join-Path $out 'ndaco.org\NDACO-20261002-100000-assessment.html') '<html>FOLDER-REPORT-MARKER</html>'

            & $put (Join-Path $out 'Administrator_ndaco.org\20261002-122037-email-results.json') '{}'
            & $put (Join-Path $out '20261002-130000-signin-triage.json')         '{}'
            & $put (Join-Path $out '20261002-130001-signin-triage-results.json') '{}'
            & $put (Join-Path $out '_flat\RESERVED-20261002-110000-results.json')    '{}'
            & $put (Join-Path $out '_flat\RESERVED-20261002-110000-assessment.html') '<html>RESERVED-MARKER</html>'

            # Newest first: CLITENANT, then NDACO, FLATNDACO, METAFIRST, NOMETA, BROKEN, HOSTILE.
            $base = [datetime]'2026-10-02T12:00:00'
            $order = @(
                "$id-results.json", 'ndaco.org\NDACO-20261002-100000-results.json', 'FLATNDACO-20261002-090000-results.json',
                'METAFIRST-20261002-080000-results.json', 'NOMETA-20261001-090000-results.json',
                'BROKEN-20261001-080000-results.json', 'HOSTILE-20261001-070000-results.json')
            for ($i = 0; $i -lt $order.Count; $i++) { & $stamp (Join-Path $out $order[$i]) $base.AddHours(-$i) }

            # Links inside the report folder: a file link out, and a whole
            # report folder that is itself a link.
            $linksMade = $false
            try {
                $null = New-Item -ItemType SymbolicLink -Path (Join-Path $site 'linked.html') -Target (Join-Path $out 'outside.html') -ErrorAction Stop
                $elsewhere = Join-Path $Work 'elsewhere'
                & $put (Join-Path $elsewhere 'index.html') '<html>LINKDIR-MARKER</html>'
                & $put (Join-Path $out 'LINKDIR-20261002-070000-results.json')    '{}'
                & $put (Join-Path $out 'LINKDIR-20261002-070000-assessment.html') '<html>x</html>'
                $null = New-Item -ItemType SymbolicLink -Path (Join-Path $out 'LINKDIR-20261002-070000-report') -Target $elsewhere -ErrorAction Stop
                $linksMade = $true
            } catch { Write-Verbose "No symbolic links on this filesystem: $($_.Exception.Message)" }

            return @{ Out = $out; Work = $Work; Id = $id; LinksMade = $linksMade }
        }
    }

    Context 'Files exist' {
        It 'Lib/Start-NRGWebServer.ps1 is present' {
            Test-Path -LiteralPath $script:ServerPath | Should -BeTrue
        }
        It 'Lib/Get-NRGWebRunIndex.ps1 is present' {
            Test-Path -LiteralPath $script:IndexLib | Should -BeTrue
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

        It 'Sets the CSP header in exactly one place (a route cannot relax it for the report site)' {
            # The report site needs nothing beyond what the one policy already
            # allows (inline <style>; no script, no external asset), so no route
            # has a reason to set its own. A second Set-PodeHeader would be a
            # second, possibly weaker, policy.
            ([regex]::Matches($script:ServerSrc, 'Content-Security-Policy')).Count | Should -Be 1
        }
    }

    Context 'No path traversal in route handlers' {
        BeforeAll {
            $script:ServerSrc = Get-Content -LiteralPath $script:ServerPath -Raw
        }

        It 'the report and site routes take their path from Resolve-NRGWebRunPath, never from the client' {
            # The :tenant / :id / :page segments are only ever passed to the
            # resolver, which whitelists and contains them (tested below,
            # without a server). A route that built a path itself would bypass it.
            $script:ServerSrc | Should -Match "(?s)'/api/runs/:tenant/:id/report'.*?Resolve-NRGWebRunPath.*?-Kind Report"
            $script:ServerSrc | Should -Match "(?s)'/site/:tenant/:id/:page'.*?Resolve-NRGWebRunPath.*?-Kind SitePage"
            $script:ServerSrc | Should -Not -Match 'Join-Path[^\r\n]*\$WebEvent\.Parameters' `
                -Because 'a route that joins a request parameter onto a path skips the guards'
        }

        It 'the only static route is /static (the output folder is never served as a folder)' {
            $routes = [regex]::Matches($script:ServerSrc, "Add-PodeStaticRoute\s+-Path\s+'([^']+)'") | ForEach-Object { $_.Groups[1].Value }
            @($routes) | Should -Be @('/static')
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
            # Stronger than the pattern above: no raw-HTML sink anywhere, so a
            # field the API adds later cannot reach one by accident.
            $script:AppJsSrc | Should -Not -Match '\.(innerHTML|outerHTML)\s*[+]?=' `
                -Because 'every API field is rendered with textContent / setAttribute'
            $script:AppJsSrc | Should -Not -Match 'insertAdjacentHTML'
        }

        It 'the report-site link addresses the run by folder + id, encoded, and opens in a new tab without an opener' {
            $script:AppJsSrc | Should -Match "'/site/'\s*\+\s*encodeURIComponent\(run\.folder\)\s*\+\s*'/'\s*\+\s*encodeURIComponent\(run\.id\)" `
                -Because 'the address is the folder segment from /api/runs, never the display label'
            $script:AppJsSrc | Should -Match "\.target\s*=\s*'_blank'"
            $script:AppJsSrc | Should -Match "\.rel\s*=\s*'noopener'"
            $script:IndexSrc | Should -Match '<a id="link-report-site"[^>]*rel="noopener"' `
                -Because 'the server forbids framing (frame-ancestors none), so the site opens in its own tab'
        }

        It 'opening a report no longer builds its URL from the display label' {
            $script:AppJsSrc | Should -Not -Match 'openReport\(r\.tenant' `
                -Because 'for a command-line run the label is a domain from the results file, not a folder name'
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

        It 'loads the run-index helpers into the route runspaces with Use-PodeScript' {
            # Route bodies run in default-session-state runspaces: a module
            # function is not visible there unless Use-PodeScript brings it in.
            # The paths are computed outside the block and carried in by the
            # closure (no $using:).
            $script:ServerBlockSrc | Should -Match 'Use-PodeScript\s+-Path\s+\$podeScript'
            $script:Src | Should -Match "Lib\\Get-NRGObjectField\.ps1"
            $script:Src | Should -Match "Lib\\Get-NRGWebRunIndex\.ps1"
        }
    }

    Context 'Calling Start-NRGWebServer without -ScriptDir' {
        BeforeAll {
            $script:Src = Get-Content -LiteralPath $script:ServerPath -Raw
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ServerPath, [ref]$null, [ref]$null)
            $fn  = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Start-NRGWebServer' }, $true)
            $script:ScriptDirParam = $fn.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ScriptDir' }
        }

        It 'keeps the explicit -ScriptDir parameter (Invoke-NRGAssessment.ps1 -Web passes it)' {
            $script:ScriptDirParam | Should -Not -BeNullOrEmpty
            $entry = Get-Content -LiteralPath $script:EntryScript -Raw
            $entry | Should -Match 'Start-NRGWebServer\s+-Port\s+\$WebPort\s+-ScriptDir\s+\$scriptDir'
        }

        It 'does not default it from $PSCommandPath, which is Lib itself' {
            # Split-Path -Parent $PSCommandPath is Lib\, where Web\ does not
            # exist, so a direct call threw "Web asset directory not found".
            $script:ScriptDirParam.DefaultValue.Extent.Text | Should -Not -Match 'PSCommandPath'
            $script:ScriptDirParam.DefaultValue.Extent.Text | Should -Match 'Get-NRGWebDefaultScriptDir'
        }

        It 'the default resolves to the repository root, which holds Web and the helper scripts' {
            . $script:ServerPath
            $dir = Get-NRGWebDefaultScriptDir
            (Resolve-Path -LiteralPath $dir).Path | Should -Be (Resolve-Path -LiteralPath $script:RepoRoot).Path
            Test-Path -LiteralPath (Join-Path $dir 'Web' 'index.html') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $dir 'Lib' 'Get-NRGWebRunIndex.ps1') | Should -BeTrue
            (Split-Path -Leaf $dir) | Should -Not -Be 'Lib'
        }

        It 'resolves the same root when the function is loaded through the module' {
            # The module dot-sources every Lib file, so $PSScriptRoot there is
            # the file's folder, not the module's: pin it on the real load path.
            Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
            try {
                $viaModule = & (Get-Module NRG-Assessment) { Get-NRGWebDefaultScriptDir }
                (Resolve-Path -LiteralPath $viaModule).Path | Should -Be (Resolve-Path -LiteralPath $script:RepoRoot).Path
            } finally {
                Remove-Module NRG-Assessment -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Run listing and path guards (no server)' {
        BeforeAll {
            . $script:FieldLib
            . $script:IndexLib
            $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("nrgweb-unit-{0}" -f ([Guid]::NewGuid().ToString('N')))
            $script:Fx   = & $script:NewFixture $script:Work
            $script:Id   = $script:Fx.Id
            $script:Runs = @(Get-NRGWebRunList -OutputRoot $script:Fx.Out)
            $script:Resolve = {
                param($Folder, $Id, $Kind, $Page)
                Resolve-NRGWebRunPath -OutputRoot $script:Fx.Out -Folder $Folder -Id $Id -Kind $Kind -Page $Page
            }
        }
        AfterAll {
            if ($script:Work) { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue }
        }

        Context 'listing' {
            It 'lists a flat command-line run exactly once, labeled from its metadata' {
                $hit = @($script:Runs | Where-Object { $_.id -eq $script:Id })
                $hit.Count | Should -Be 1
                $hit[0].tenant | Should -Be 'cli-tenant.example'
                $hit[0].folder | Should -Be '_flat'
                $hit[0].layout | Should -Be 'flat'
                $hit[0].hasReport | Should -BeTrue
                $hit[0].hasSite | Should -BeTrue
            }

            It 'lists the GUI-layout run under its tenant folder' {
                $hit = @($script:Runs | Where-Object { $_.id -eq 'NDACO-20261002-100000' })
                $hit.Count | Should -Be 1
                $hit[0].tenant | Should -Be 'ndaco.org'
                $hit[0].folder | Should -Be 'ndaco.org'
                $hit[0].layout | Should -Be 'tenant-folder'
                $hit[0].hasReport | Should -BeTrue
                $hit[0].hasSite | Should -BeFalse -Because 'that run has no -report folder'
            }

            It 'lists exactly the assessment runs, newest first, and nothing else' {
                $ids = @($script:Runs | ForEach-Object { $_.id })
                $expected = @($script:Id, 'NDACO-20261002-100000', 'FLATNDACO-20261002-090000', 'METAFIRST-20261002-080000',
                    'NOMETA-20261001-090000', 'BROKEN-20261001-080000', 'HOSTILE-20261001-070000')
                if ($script:Fx.LinksMade) { $expected += 'LINKDIR-20261002-070000' }
                # LINKDIR was written last-but-stamped-by-creation; compare as a set plus the order of the stamped ones.
                @($ids | Sort-Object) | Should -Be @($expected | Sort-Object)
                @($ids | Where-Object { $_ -in $expected[0..6] }) | Should -Be $expected[0..6]
            }

            It 'never lists incident-response mailbox runs, sign-in triage results or a run inside a folder named like the reserved segment' {
                $ids = @($script:Runs | ForEach-Object { $_.id })
                $ids | Should -Not -Contain '20261002-122037-email'
                $ids | Should -Not -Contain '20261002-122037'
                @($ids | Where-Object { $_ -match 'signin-triage|email' }) | Should -BeNullOrEmpty
                $ids | Should -Not -Contain 'RESERVED-20261002-110000' `
                    -Because 'the reserved segment is never a tenant folder, so nothing can be addressed there'
            }

            It 'the same tenant from both layouts is two rows with two different addresses' {
                $rows = @($script:Runs | Where-Object { $_.tenant -eq 'ndaco.org' })
                $rows.Count | Should -Be 2
                @($rows | ForEach-Object { $_.folder } | Sort-Object) | Should -Be @('_flat', 'ndaco.org')
            }

            It 'reads the tenant label whatever the order of the keys in the results file' {
                ($script:Runs | Where-Object { $_.id -eq 'METAFIRST-20261002-080000' }).tenant | Should -Be 'meta-first.example'
                ($script:Runs | Where-Object { $_.id -eq $script:Id }).tenant | Should -Be 'cli-tenant.example' `
                    -Because 'Metadata comes after RawData in this file'
            }

            It 'falls back to the file-name tag when the file has no metadata, or is not valid JSON' {
                ($script:Runs | Where-Object { $_.id -eq 'NOMETA-20261001-090000' }).tenant | Should -Be 'NOMETA'
                ($script:Runs | Where-Object { $_.id -eq 'BROKEN-20261001-080000' }).tenant | Should -Be 'BROKEN'
            }

            It 'does not take a label that is not a domain, so a hand-edited file cannot put markup in the list' {
                $row = $script:Runs | Where-Object { $_.id -eq 'HOSTILE-20261001-070000' }
                $row.tenant | Should -Be 'HOSTILE'
                $row.tenant | Should -Not -Match '[<>]'
            }

            It 'a name that is only a timestamp gets an explicit unknown label, not an empty one' {
                $f = New-Item -ItemType File -Path (Join-Path $script:Work '20261001-070000-results.json') -Value '{}'
                Get-NRGWebRunLabel -File $f | Should -Be '(unknown tenant)'
            }

            It 'an empty or missing output folder yields no rows (not one null row)' {
                $empty = Join-Path $script:Work 'empty'
                $null = New-Item -ItemType Directory -Path $empty -Force
                @(Get-NRGWebRunList -OutputRoot $empty).Count | Should -Be 0
                @(Get-NRGWebRunList -OutputRoot (Join-Path $script:Work 'nope')).Count | Should -Be 0
                (ConvertTo-Json -InputObject @(Get-NRGWebRunList -OutputRoot $empty) -Compress) | Should -Be '[]'
            }

            It 'hasReport / hasSite agree with what the resolver would serve' {
                foreach ($r in $script:Runs) {
                    (Resolve-NRGWebRunPath -OutputRoot $script:Fx.Out -Folder $r.folder -Id $r.id -Kind Report).Status -eq 'Ok' | Should -Be $r.hasReport
                    (Resolve-NRGWebRunPath -OutputRoot $script:Fx.Out -Folder $r.folder -Id $r.id -Kind SitePage -Page 'index.html').Status -eq 'Ok' | Should -Be $r.hasSite
                }
            }

            It 'does not re-read an unchanged results file, and does when it changes' {
                $f = Get-Item -LiteralPath (Join-Path $script:Fx.Out "$($script:Id)-results.json")
                Mock Read-NRGWebRunTenantDomain { 'mocked.example' }
                $cache = [hashtable]::Synchronized(@{})
                Get-NRGWebRunLabel -File $f -Cache $cache | Should -Be 'mocked.example'
                Get-NRGWebRunLabel -File $f -Cache $cache | Should -Be 'mocked.example'
                Should -Invoke Read-NRGWebRunTenantDomain -Times 1 -Exactly
                Add-Content -LiteralPath $f.FullName -Value ' ' -NoNewline
                Get-NRGWebRunLabel -File (Get-Item -LiteralPath $f.FullName) -Cache $cache | Should -Be 'mocked.example'
                Should -Invoke Read-NRGWebRunTenantDomain -Times 2 -Exactly
            }
        }

        Context 'the segment whitelist' {
            It 'accepts a real tenant folder, run id and page name: <_>' -ForEach @(
                'CLITENANT-20261002-114907', 'ndaco.org', '_flat', 'Administrator_ndaco.org', 'a.b-c_d', 'ActionPlan.csv', 'index.html', '20261002-122037') {
                Test-NRGWebSegment -Value $_ | Should -BeTrue
            }

            # Each case carries a printable Label: the name of a test goes into the
            # NUnit XML report, and a literal NUL in it makes Pester's own export
            # throw ("hexadecimal value 0x00, is an invalid character") AFTER every
            # test has passed. The raw value stays in Value, where it is data.
            It 'rejects <Label>' -ForEach @(
                @{ Label = '..';                    Value = '..' }
                @{ Label = '.';                     Value = '.' }
                @{ Label = '../x';                  Value = '../x' }
                @{ Label = '..\x';                  Value = '..\x' }
                @{ Label = 'a/b';                   Value = 'a/b' }
                @{ Label = 'a\b';                   Value = 'a\b' }
                @{ Label = '/';                     Value = '/' }
                @{ Label = '\';                     Value = '\' }
                @{ Label = '.hidden';               Value = '.hidden' }
                @{ Label = '-x';                    Value = '-x' }
                @{ Label = 'a b (space)';           Value = 'a b' }
                @{ Label = 'a%2Fb';                 Value = 'a%2Fb' }
                @{ Label = 'a:b';                   Value = 'a:b' }
                @{ Label = 'a;b';                   Value = 'a;b' }
                @{ Label = 'a*b';                   Value = 'a*b' }
                @{ Label = 'a?b';                   Value = 'a?b' }
                @{ Label = 'a NUL b';               Value = "a`0b" }
                @{ Label = 'a LF b';                Value = "a`nb" }
                @{ Label = 'a TAB b';               Value = "a`tb" }
                @{ Label = 'a..b';                  Value = 'a..b' }
                @{ Label = '....';                  Value = '....' }
                @{ Label = 'index.html::$DATA';     Value = 'index.html::$DATA' }
                @{ Label = '256 characters (over the limit)'; Value = ('x' * 256) }) {
                Test-NRGWebSegment -Value $Value | Should -BeFalse
            }

            It 'rejects null and empty' {
                Test-NRGWebSegment -Value $null | Should -BeFalse
                Test-NRGWebSegment -Value '' | Should -BeFalse
            }

            It 'is an ASCII whitelist: a non-ASCII character that case-folds into [A-Za-z] (the Kelvin sign) is rejected' {
                Test-NRGWebSegment -Value ('a' + [char]0x212A + 'b') | Should -BeFalse
                Test-NRGWebSegment -Value ([string][char]0xFF0E + [char]0xFF0E) | Should -BeFalse -Because 'fullwidth full stops are not dots'
            }
        }

        Context 'resolving a file to serve' {
            It 'serves the report, the site pages and the action plan of a flat run' {
                foreach ($case in @(
                    @('Report', ''), @('SitePage', 'index.html'), @('SitePage', 'AAD.html'), @('SitePage', 'ActionPlan.csv'))) {
                    $r = & $script:Resolve '_flat' $script:Id $case[0] $case[1]
                    $r.Status | Should -Be 'Ok' -Because "$($case -join ' ')"
                    $r.HttpStatus | Should -Be 200
                    Test-Path -LiteralPath $r.Path -PathType Leaf | Should -BeTrue
                    $r.Path | Should -BeLike "$($script:Fx.Out)*"
                }
            }

            It 'serves a tenant-folder run only through its own folder' {
                (& $script:Resolve 'ndaco.org' 'NDACO-20261002-100000' 'Report' '').Status | Should -Be 'Ok'
                (& $script:Resolve '_flat' 'NDACO-20261002-100000' 'Report' '').Status | Should -Be 'NotFound' `
                    -Because 'the reserved segment is the output folder itself, not a way into a tenant folder'
                (& $script:Resolve 'ndaco.org' $script:Id 'Report' '').Status | Should -Be 'NotFound' `
                    -Because 'a flat run is not under a tenant folder'
            }

            It 'refuses a folder segment <Label>' -ForEach @(
                @{ Label = '..';             Value = '..' }
                @{ Label = '../x';           Value = '../x' }
                @{ Label = '..\x';           Value = '..\x' }
                @{ Label = 'a/b';            Value = 'a/b' }
                @{ Label = 'a\b';            Value = 'a\b' }
                @{ Label = '(empty)';        Value = '' }
                @{ Label = '.hidden';        Value = '.hidden' }
                @{ Label = '-x';             Value = '-x' }
                @{ Label = 'a b (space)';    Value = 'a b' }
                @{ Label = 'x%2Fy';          Value = 'x%2Fy' }
                @{ Label = '/etc';           Value = '/etc' }
                @{ Label = 'C:\x';           Value = 'C:\x' }
                @{ Label = 'C:';             Value = 'C:' }
                @{ Label = 'a NUL b';        Value = "a`0b" }
                @{ Label = '..%2F';          Value = '..%2F' }
                @{ Label = '....';           Value = '....' }
                @{ Label = 'a..b';           Value = 'a..b' }) {
                $r = & $script:Resolve $Value $script:Id 'Report' ''
                $r.Status | Should -BeIn @('BadRequest', 'NotFound')
                $r.Path | Should -BeNullOrEmpty
                $r.HttpStatus | Should -BeIn @(400, 404)
            }

            It 'refuses a run id <Label>' -ForEach @(
                @{ Label = '..';             Value = '..' }
                @{ Label = '../x';           Value = '../x' }
                @{ Label = '..\x';           Value = '..\x' }
                @{ Label = '../../secret';   Value = '../../secret' }
                @{ Label = 'a/b';            Value = 'a/b' }
                @{ Label = 'a\b';            Value = 'a\b' }
                @{ Label = '(empty)';        Value = '' }
                @{ Label = '.hidden';        Value = '.hidden' }
                @{ Label = 'a b (space)';    Value = 'a b' }
                @{ Label = 'x NUL y';        Value = "x`0y" }
                @{ Label = 'a..b';           Value = 'a..b' }) {
                $r = & $script:Resolve '_flat' $Value 'Report' ''
                $r.Status | Should -BeIn @('BadRequest', 'NotFound')
                $r.Path | Should -BeNullOrEmpty
            }

            It 'a null segment is refused, not an error' {
                (& $script:Resolve $null $script:Id 'Report' '').Status | Should -Be 'BadRequest'
                (& $script:Resolve '_flat' $null 'Report' '').Status | Should -Be 'BadRequest'
                (& $script:Resolve '_flat' $script:Id 'SitePage' $null).Status | Should -Be 'BadRequest'
            }

            It 'refuses a site page <_> (traversal, wrong type, odd name)' -ForEach @(
                '../outside.html', '..\outside.html', '..%2Foutside.html', '%2e%2e%2foutside.html', '../../secret.html',
                '../CLITENANT-20261002-114907-assessment.html', 'a/b.html', '/outside.html', 'C:\outside.html',
                'notes.txt', 'raw.json', 'index.html.txt', 'index', 'index.ps1', 'archive.html.zip',
                '.hidden.html', 'index.html::$DATA', 'index.html ', 'AAD.html/', '', '..', '.') {
                $r = & $script:Resolve '_flat' $script:Id 'SitePage' $_
                $r.Status | Should -BeIn @('BadRequest', 'NotFound')
                $r.Path | Should -BeNullOrEmpty
            }

            It 'a file that exists in the report folder but is not .html or .csv is refused for its type, not for being missing' {
                Test-Path -LiteralPath (Join-Path $script:Fx.Out "$($script:Id)-report" 'notes.txt') | Should -BeTrue
                Test-Path -LiteralPath (Join-Path $script:Fx.Out "$($script:Id)-report" 'raw.json') | Should -BeTrue
                (& $script:Resolve '_flat' $script:Id 'SitePage' 'notes.txt').Status | Should -Be 'BadRequest'
                (& $script:Resolve '_flat' $script:Id 'SitePage' 'raw.json').Status | Should -Be 'BadRequest'
            }

            It 'a file next to the report folder, or above the output folder, cannot be reached as a site page' {
                # Both exist and both are .html: the only thing refusing them is containment.
                Test-Path -LiteralPath (Join-Path $script:Fx.Out 'outside.html') | Should -BeTrue
                Test-Path -LiteralPath (Join-Path $script:Fx.Work 'secret.html') | Should -BeTrue
                (& $script:Resolve '_flat' $script:Id 'SitePage' 'outside.html').Status | Should -Be 'NotFound'
                (& $script:Resolve '_flat' $script:Id 'SitePage' "$($script:Id)-assessment.html").Status | Should -Be 'NotFound'
                (& $script:Resolve '_flat' $script:Id 'SitePage' '../outside.html').Path | Should -BeNullOrEmpty
                (& $script:Resolve '_flat' $script:Id 'SitePage' '../../secret.html').Path | Should -BeNullOrEmpty
            }

            It 'containment holds on its own: with the segment whitelist bypassed, traversal still never resolves' {
                # The two checks are independent layers. Force the first one open
                # and the second must still refuse, for the folder and id (which
                # build the boundary) as well as for the page.
                Mock Test-NRGWebSegment { $true }
                # These exist, so "not found" cannot be the reason they are refused.
                Test-Path -LiteralPath (Join-Path $script:Fx.Work "$($script:Id)-assessment.html") | Should -BeTrue
                Test-Path -LiteralPath (Join-Path $script:Fx.Work 'secret-report' 'index.html') | Should -BeTrue
                foreach ($c in @(
                    @('..', $script:Id, 'Report', ''),
                    @('../..', $script:Id, 'Report', ''),
                    @('..\..', $script:Id, 'Report', ''),
                    @('_flat', '../secret', 'Report', ''),
                    @('_flat', '../../secret', 'Report', ''),
                    @('_flat', '../secret', 'SitePage', 'index.html'),
                    @('_flat', $script:Id, 'SitePage', '../outside.html'),
                    @('_flat', $script:Id, 'SitePage', '../../secret.html'),
                    @('_flat', $script:Id, 'SitePage', "../$($script:Id)-assessment.html"),
                    @('_flat', "$($script:Id)-report/..", 'SitePage', 'outside.html'))) {
                    $r = & $script:Resolve $c[0] $c[1] $c[2] $c[3]
                    $r.Status | Should -Not -Be 'Ok' -Because ($c -join ' | ')
                    $r.Path | Should -BeNullOrEmpty -Because ($c -join ' | ')
                }
            }

            It 'an unknown run or page is not found' {
                (& $script:Resolve '_flat' 'NOSUCH-20261002-000000' 'Report' '').Status | Should -Be 'NotFound'
                (& $script:Resolve '_flat' $script:Id 'SitePage' 'missing.html').Status | Should -Be 'NotFound'
                (& $script:Resolve 'no-such-tenant' $script:Id 'SitePage' 'index.html').Status | Should -Be 'NotFound'
            }

            It 'never follows a symbolic link out of the report folder' {
                if (-not $script:Fx.LinksMade) { Set-ItResult -Skipped -Because 'this filesystem could not create symbolic links'; return }
                Test-Path -LiteralPath (Join-Path $script:Fx.Out "$($script:Id)-report" 'linked.html') -PathType Leaf | Should -BeTrue
                $r = & $script:Resolve '_flat' $script:Id 'SitePage' 'linked.html'
                $r.Status | Should -Be 'NotFound'
                $r.Path | Should -BeNullOrEmpty
            }

            It 'never serves a report folder that is itself a link, and does not list a site for it' {
                if (-not $script:Fx.LinksMade) { Set-ItResult -Skipped -Because 'this filesystem could not create symbolic links'; return }
                (& $script:Resolve '_flat' 'LINKDIR-20261002-070000' 'SitePage' 'index.html').Status | Should -Be 'NotFound'
                ($script:Runs | Where-Object { $_.id -eq 'LINKDIR-20261002-070000' }).hasSite | Should -BeFalse
            }
        }

        Context 'what the helpers may do' {
            BeforeAll {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:IndexLib, [ref]$null, [ref]$null)
                $script:Commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
                $script:Members = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) |
                    ForEach-Object { [string]$_.Member.Value })
            }

            It 'is read-only and makes no tenant or network call' {
                $script:Commands.Count | Should -BeGreaterThan 0
                $forbidden = '^(Connect-|Disconnect-|Invoke-(Mg|NRGGraph|RestMethod|WebRequest|Command)|.*-Mg[A-Z]|Start-(Process|Job)|Set-Content|Add-Content|Out-File|Remove-Item|New-Item|Move-Item|Copy-Item|Rename-Item|Clear-Content|Resolve-NRGDns|Resolve-DnsName|Get-NRGRawData)'
                @($script:Commands | Where-Object { $_ -match $forbidden }) | Should -BeNullOrEmpty
            }

            It 'reads the results file only through Get-NRGObjectField' {
                $script:Commands | Should -Contain 'Get-NRGObjectField'
                # No dotted access to a results field: a replayed older file does
                # not carry newer fields and StrictMode throws on the read.
                @($script:Members | Where-Object { $_ -in @('Metadata', 'TenantDomain', 'Findings', 'RawData') }) | Should -BeNullOrEmpty
            }

            It 'the server file makes no tenant call of its own (the scan is a child process of the entry script)' {
                # Parsed commands, not text: a comment may name Connect-MgGraph.
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ServerPath, [ref]$null, [ref]$null)
                $names = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
                $names.Count | Should -BeGreaterThan 0
                @($names | Where-Object { $_ -match '^(Connect-|Invoke-(Mg|NRGGraph)|.*-Mg[A-Z]|Get-NRGRawData|Resolve-NRGDns)' }) | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Server actually starts and serves' -Skip:(-not (Get-Module -ListAvailable -Name Pode | Where-Object { $_.Version -ge [version]'2.10.0' })) {
        # The test that would have caught the shipped bug. Everything else in
        # this file is a grep or a pure-function check; neither can tell you
        # the server never came up.
        BeforeAll {
            # Starts a server whose working directory is $Work (the server reads
            # ./output relative to it). $Explicit adds -ScriptDir; without it
            # the server must find the repository root by itself.
            $script:Boot = {
                param([string] $Work, [int] $Port, [bool] $Explicit)
                $boot = Join-Path ([System.IO.Path]::GetTempPath()) ("nrgweb-{0}.ps1" -f ([Guid]::NewGuid().ToString('N')))
                $dirArg = if ($Explicit) { " -ScriptDir '$($script:RepoRoot)'" } else { '' }
                @"
`$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. '$($script:ServerPath)'
Start-NRGWebServer -Port $Port$dirArg -NoBrowser
"@ | Set-Content -LiteralPath $boot -Encoding utf8

                $pwshExe = (Get-Process -Id $PID).Path
                $proc = Start-Process -FilePath $pwshExe `
                    -WorkingDirectory $Work `
                    -ArgumentList @('-NoProfile', '-File', $boot) `
                    -RedirectStandardOutput "$boot.log" `
                    -RedirectStandardError  "$boot.log.err" `
                    -PassThru
                # NOTE: no -WindowStyle. It throws NotSupportedException on
                # non-Windows editions, which fails the whole context in CI.

                # Poll until it answers rather than sleeping a fixed amount.
                $up = $false
                foreach ($i in 1..40) {
                    Start-Sleep -Milliseconds 750
                    try {
                        $null = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -TimeoutSec 3 -UseBasicParsing
                        $up = $true
                        break
                    } catch { }
                }
                return @{ Proc = $proc; Boot = $boot; Up = $up; Port = $Port }
            }

            # A raw HTTP/1.1 GET. Invoke-WebRequest runs the URL through
            # System.Uri, which collapses ../ and decodes %2e before anything is
            # sent, so a traversal test through it never reaches the server
            # as written. This sends the request line exactly as given.
            $script:Raw = {
                param([int] $Port, [string] $Target)
                $client = [System.Net.Sockets.TcpClient]::new()
                try {
                    $client.Connect('127.0.0.1', $Port)
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 8000
                    $req = [System.Text.Encoding]::ASCII.GetBytes("GET $Target HTTP/1.1`r`nHost: 127.0.0.1:$Port`r`nConnection: close`r`n`r`n")
                    $stream.Write($req, 0, $req.Length)
                    $ms = [System.IO.MemoryStream]::new()
                    $stream.CopyTo($ms)
                    $text = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
                    $head, $body = $text -split "`r`n`r`n", 2
                    $status = [int](($head -split "`r`n")[0] -split ' ')[1]
                    $headers = @{}
                    foreach ($line in ($head -split "`r`n" | Select-Object -Skip 1)) {
                        $k, $v = $line -split ':\s*', 2
                        if ($k) { $headers[$k.ToLowerInvariant()] = $v }
                    }
                    return [pscustomobject]@{ Status = $status; Headers = $headers; Body = [string]$body }
                } finally { $client.Dispose() }
            }

            $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("nrgweb-work-{0}" -f ([Guid]::NewGuid().ToString('N')))
            $script:Fx   = & $script:NewFixture $script:Work
            $script:Id   = $script:Fx.Id

            # Server A: no -ScriptDir at all. If the default were Lib (the old
            # behavior) this throws "Web asset directory not found" and never
            # comes up, so every test below fails.
            $script:Port = Get-Random -Minimum 20000 -Maximum 24000
            $script:A = & $script:Boot $script:Work $script:Port $false
            $script:Up = $script:A.Up

            # Server B: the explicit parameter still works. Its own empty
            # working directory, so it also starts with nothing in ./output.
            $script:WorkB = Join-Path ([System.IO.Path]::GetTempPath()) ("nrgweb-workb-{0}" -f ([Guid]::NewGuid().ToString('N')))
            $null = New-Item -ItemType Directory -Path $script:WorkB -Force
            $script:PortB = Get-Random -Minimum 24001 -Maximum 29000
            $script:B = & $script:Boot $script:WorkB $script:PortB $true

            $script:Base = "http://127.0.0.1:$($script:Port)"
            $script:Get = {
                param([string] $Path)
                Invoke-WebRequest -Uri "$($script:Base)$Path" -TimeoutSec 8 -UseBasicParsing -SkipHttpErrorCheck
            }
        }

        AfterAll {
            foreach ($s in @($script:A, $script:B)) {
                if ($s -and $s.Proc -and -not $s.Proc.HasExited) {
                    Stop-Process -Id $s.Proc.Id -Force -ErrorAction SilentlyContinue
                }
                if ($s -and $s.Boot) {
                    foreach ($f in @($s.Boot, "$($s.Boot).log", "$($s.Boot).log.err")) {
                        Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            foreach ($d in @($script:Work, $script:WorkB)) {
                if ($d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
            }
        }

        It 'comes up and serves the index page' {
            $script:Up | Should -BeTrue -Because 'the server must actually start, not just parse'
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$($script:Port)/" -TimeoutSec 5 -UseBasicParsing
            $r.StatusCode | Should -Be 200
            $r.Content | Should -Match '<!DOCTYPE html>'
        }

        It 'comes up with no -ScriptDir (the default is the repository root, not Lib)' {
            $script:A.Proc.HasExited | Should -BeFalse
            $err = Get-Content -LiteralPath "$($script:A.Boot).log.err" -Raw -ErrorAction SilentlyContinue
            [string]$err | Should -Not -Match 'Web asset directory not found'
        }

        It 'still comes up with an explicit -ScriptDir' {
            $script:B.Up | Should -BeTrue
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$($script:PortB)/static/app.js" -TimeoutSec 5 -UseBasicParsing
            $r.StatusCode | Should -Be 200
            $rows = Invoke-WebRequest -Uri "http://127.0.0.1:$($script:PortB)/api/runs" -TimeoutSec 5 -UseBasicParsing
            $rows.Content.Trim() | Should -Be '[]' -Because 'that server was started in an empty working directory'
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
            $r.Content.TrimStart() | Should -Match '^\['
        }

        Context 'both output layouts' {
            BeforeAll {
                $script:RunsResp = & $script:Get '/api/runs'
                $script:RunList  = @($script:RunsResp.Content | ConvertFrom-Json)
            }

            It 'lists the command-line run exactly once, labeled from its results file' {
                $hit = @($script:RunList | Where-Object { $_.id -eq $script:Id })
                $hit.Count | Should -Be 1
                $hit[0].tenant | Should -Be 'cli-tenant.example'
                $hit[0].folder | Should -Be '_flat'
                $hit[0].hasReport | Should -BeTrue
                $hit[0].hasSite | Should -BeTrue
            }

            It 'lists the GUI-layout run too, and not the incident-response or triage files' {
                @($script:RunList | Where-Object { $_.id -eq 'NDACO-20261002-100000' }).Count | Should -Be 1
                @($script:RunList | Where-Object { $_.id -match 'email|signin|^2026\d{4}-\d{6}$' }) | Should -BeNullOrEmpty
                $expected = if ($script:Fx.LinksMade) { 8 } else { 7 }
                $script:RunList.Count | Should -Be $expected
            }

            It 'serves the single-page report of a flat run and of a folder run' {
                $flat = & $script:Get "/api/runs/_flat/$($script:Id)/report"
                $flat.StatusCode | Should -Be 200
                $flat.Content | Should -Match 'FLAT-REPORT-MARKER'
                $folder = & $script:Get '/api/runs/ndaco.org/NDACO-20261002-100000/report'
                $folder.StatusCode | Should -Be 200
                $folder.Content | Should -Match 'FOLDER-REPORT-MARKER'
            }

            It 'a run is only reachable through its own layout' {
                (& $script:Get '/api/runs/ndaco.org/CLITENANT-20261002-114907/report').StatusCode | Should -Be 404
                (& $script:Get '/api/runs/_flat/NDACO-20261002-100000/report').StatusCode | Should -Be 404
            }
        }

        Context 'report site' {
            It 'serves the index and a workload page as HTML' {
                $i = & $script:Get "/site/_flat/$($script:Id)/index.html"
                $i.StatusCode | Should -Be 200
                $i.Headers['Content-Type'] | Should -Match 'text/html'
                $i.Content | Should -Match 'SITE-INDEX-MARKER'
                $p = & $script:Get "/site/_flat/$($script:Id)/AAD.html"
                $p.StatusCode | Should -Be 200
                $p.Content | Should -Match 'SITE-AAD-MARKER'
            }

            It 'the pages resolve their own relative links under the same prefix' {
                # index.html links "AAD.html" and "ActionPlan.csv" by relative
                # name: from /site/_flat/<id>/index.html they resolve to siblings.
                $base = [Uri]"http://127.0.0.1:$($script:Port)/site/_flat/$($script:Id)/index.html"
                foreach ($href in 'AAD.html', 'ActionPlan.csv') {
                    $u = [Uri]::new($base, $href)
                    $u.AbsolutePath | Should -Be "/site/_flat/$($script:Id)/$href"
                    (& $script:Get $u.AbsolutePath).StatusCode | Should -Be 200
                }
            }

            It 'serves the action plan as a CSV attachment' {
                $c = & $script:Get "/site/_flat/$($script:Id)/ActionPlan.csv"
                $c.StatusCode | Should -Be 200
                $c.Headers['Content-Type'] | Should -Match 'text/csv'
                [string]$c.Headers['Content-Disposition'] | Should -Match 'attachment; filename="ActionPlan.csv"'
                $c.Content | Should -Match 'SITE-CSV-MARKER'
            }

            It 'the site is served under the same strict CSP, not a relaxed one' {
                $idx  = (& $script:Get '/').Headers['Content-Security-Policy']
                $site = (& $script:Get "/site/_flat/$($script:Id)/index.html").Headers['Content-Security-Policy']
                [string]$site | Should -Be ([string]$idx)
                [string]$site | Should -Match "default-src 'none'"
                [string]$site | Should -Match "script-src 'self'(;|$)"
                [string]$site | Should -Match "frame-ancestors 'none'"
                [string]$site | Should -Not -Match "script-src[^;]*'unsafe-inline'"
                [string]$site | Should -Not -Match "script-src[^;]*'unsafe-eval'"
            }

            It 'refuses a file that is not .html or .csv, even though it is in the report folder' {
                foreach ($name in 'notes.txt', 'raw.json') {
                    $r = & $script:Raw $script:Port "/site/_flat/$($script:Id)/$name"
                    $r.Status | Should -Be 400
                    $r.Body | Should -Not -Match 'TXT-MARKER|JSON-MARKER'
                }
            }

            It 'refuses a request that tries to leave the report folder (<_>)' -ForEach @(
                "/site/_flat/CLITENANT-20261002-114907/..%2Foutside.html",
                "/site/_flat/CLITENANT-20261002-114907/%2e%2e%2foutside.html",
                "/site/_flat/CLITENANT-20261002-114907/..%5Coutside.html",
                "/site/_flat/CLITENANT-20261002-114907/../outside.html",
                "/site/_flat/CLITENANT-20261002-114907/../../secret.html",
                "/site/_flat/CLITENANT-20261002-114907/..%2F..%2F..%2Fsecret.html",
                "/site/_flat/CLITENANT-20261002-114907/..%2FCLITENANT-20261002-114907-assessment.html",
                "/site/_flat/..%2FCLITENANT-20261002-114907/index.html",
                "/site/..%2F/CLITENANT-20261002-114907/index.html",
                "/site/%2e%2e/CLITENANT-20261002-114907/index.html",
                "/api/runs/_flat/..%2Foutside/report",
                "/api/runs/..%2F/CLITENANT-20261002-114907/report",
                "/api/runs/_flat/CLITENANT-20261002-114907%00/report",
                "/site/_flat/CLITENANT-20261002-114907/index.html%00.txt",
                "/site/_flat/CLITENANT-20261002-114907/index.html%3A%3A%24DATA") {
                $r = & $script:Raw $script:Port $_
                $r.Status | Should -BeIn @(400, 404)
                $r.Body | Should -Not -Match 'OUTSIDE-MARKER|SECRET-MARKER|FLAT-REPORT-MARKER|SITE-INDEX-MARKER|TXT-MARKER'
            }

            It 'refuses a file that sits next to the report folder, asked for as a plain name' {
                # outside.html and the single-page report exist, are .html, and
                # are not inside <id>-report: nothing but containment refuses them.
                foreach ($name in 'outside.html', "$($script:Id)-assessment.html") {
                    $r = & $script:Raw $script:Port "/site/_flat/$($script:Id)/$name"
                    $r.Status | Should -BeIn @(400, 404)
                    $r.Body | Should -Not -Match 'OUTSIDE-MARKER|FLAT-REPORT-MARKER'
                }
            }

            It 'does not follow a symbolic link out of the report folder' {
                if (-not $script:Fx.LinksMade) { Set-ItResult -Skipped -Because 'this filesystem could not create symbolic links'; return }
                $r = & $script:Raw $script:Port "/site/_flat/$($script:Id)/linked.html"
                $r.Status | Should -Be 404
                $r.Body | Should -Not -Match 'OUTSIDE-MARKER'
                $d = & $script:Raw $script:Port '/site/_flat/LINKDIR-20261002-070000/index.html'
                $d.Status | Should -Be 404
                $d.Body | Should -Not -Match 'LINKDIR-MARKER'
            }

            It 'answers an unknown run with 404 and a plain-text body that says so' {
                $r = & $script:Raw $script:Port '/site/_flat/NOSUCH-20261002-000000/index.html'
                $r.Status | Should -Be 404
                $r.Body | Should -Be 'Not found.' -Because 'status and body are sent together'
                $r.Headers['content-type'] | Should -Match 'text/plain'
            }
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

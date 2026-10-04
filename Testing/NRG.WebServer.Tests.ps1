#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
<#
.SYNOPSIS
    Pester invariants for the local web GUI (Lib/Start-NRGWebServer.ps1, the three Lib/*NRGWeb* support files, and Web/).

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
        root, not Lib, and the runs are read from <ScriptDir>\output (where the
        command line writes), never from the current directory.
      - Only requests meant for this server are answered: a Host header that is
        not 127.0.0.1 / localhost on its own port is refused (DNS rebinding), and
        anything that changes state must be same-origin JSON (cross-site forms).
        The policy is a pure function, tested here without a server.

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
        $script:PathLib    = Join-Path $script:RepoRoot 'Lib\Resolve-NRGWebRunPath.ps1'
        $script:RequestLib = Join-Path $script:RepoRoot 'Lib\Test-NRGWebRequestAllowed.ps1'
        $script:DomainLib  = Join-Path $script:RepoRoot 'Lib\Test-NRGDomainName.ps1'
        $script:ApiErrorLib = Join-Path $script:RepoRoot 'Lib\Get-NRGWebApiError.ps1'
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
        #     JOINED / ORGONLY / HCLIENT                  flat runs whose label comes from clients.json
        #     joined.com\JOINEDGUI-*                      the same client's GUI-layout run
        #     ndaco.org\NDACO-20261002-100000-*           GUI-layout run
        #     Administrator_ndaco.org\...-email-results.json     IR run (never listed)
        #     *-signin-triage.json, *-signin-triage-results.json (never listed)
        #     _flat\RESERVED-*                            a real folder with the reserved name
        #     outside.html                                a file next to, not in, the report folder
        #   secret.html                                   a file above the output folder
        #   Config\clients.json                           the client registry the labels are joined to
        #
        # The results files record the tenant's INITIAL domain (.onmicrosoft.com),
        # as Connect-NRGServices does, while the GUI saves under the client's own
        # domain: a fixture that used one name for both hid exactly that.
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
            # The publisher writes the action plan with a UTF-8 BOM so Excel does
            # not read it as ANSI; non-ASCII text makes a dropped BOM visible.
            $null = New-Item -ItemType Directory -Path $site -Force
            [System.IO.File]::WriteAllLines((Join-Path $site 'ActionPlan.csv'), @('Control,Owner', "SITE-CSV-MARKER,Jos$([char]0xE9) $([char]0x2014) M$([char]0xFC)ller"), [System.Text.UTF8Encoding]::new($true))
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

            & $put (Join-Path $out 'JOINED-20261002-070500-results.json')    '{"Metadata":{"TenantDomain":"joined.onmicrosoft.com","TenantId":"11111111-2222-3333-4444-555555555555"}}'
            & $put (Join-Path $out 'ORGONLY-20261002-070400-results.json')   '{"Metadata":{"TenantDomain":"orgonly.onmicrosoft.com"}}'
            & $put (Join-Path $out 'HCLIENT-20261002-070300-results.json')   '{"Metadata":{"TenantDomain":"hostile.onmicrosoft.com","TenantId":"99999999-8888-7777-6666-555555555555"}}'
            # Graph could not answer /organization, so Connect-NRGServices fell back to
            # the SIGNED-IN ACCOUNT's domain: under GDAP that is the MSP's own, so the
            # file names the wrong tenant. Only the tenant id still identifies it.
            & $put (Join-Path $out 'UPNFALL-20261002-070100-results.json')   '{"Metadata":{"TenantDomain":"msp.example","TenantId":"aaaaaaaa-0000-0000-0000-000000000001"}}'
            & $put (Join-Path $out 'joined.com\JOINEDGUI-20261002-070200-results.json') '{}'
            & $put (Join-Path $Work 'Config\clients.json') (@{ clients = @(
                @{ ClientName = 'Joined Co'; TenantDomain = 'joined.com';  TenantId = '11111111-2222-3333-4444-555555555555'; DelegatedOrg = 'joined.onmicrosoft.com'; Active = $true }
                @{ ClientName = 'Org Only';  TenantDomain = 'orgonly.com'; TenantId = '';                                      DelegatedOrg = 'orgonly.onmicrosoft.com' }
                @{ ClientName = 'Upn Co';    TenantDomain = 'upn.com';     TenantId = 'AAAAAAAA-0000-0000-0000-000000000001'; DelegatedOrg = 'upn.onmicrosoft.com' }
                @{ ClientName = 'Hostile';   TenantDomain = '<b>x</b>';    TenantId = '99999999-8888-7777-6666-555555555555'; DelegatedOrg = 'hostile.onmicrosoft.com' }
            ) } | ConvertTo-Json -Depth 4)
            & $put (Join-Path $out 'ndaco.org\NDACO-20261002-100000-results.json')    '{}'
            & $put (Join-Path $out 'ndaco.org\NDACO-20261002-100000-assessment.html') '<html>FOLDER-REPORT-MARKER</html>'

            & $put (Join-Path $out 'Administrator_ndaco.org\20261002-122037-email-results.json') '{}'
            & $put (Join-Path $out '20261002-130000-signin-triage.json')         '{}'
            & $put (Join-Path $out '20261002-130001-signin-triage-results.json') '{}'
            & $put (Join-Path $out '_flat\RESERVED-20261002-110000-results.json')    '{}'
            & $put (Join-Path $out '_flat\RESERVED-20261002-110000-assessment.html') '<html>RESERVED-MARKER</html>'

            # Newest first: CLITENANT, NDACO, FLATNDACO, METAFIRST, NOMETA, BROKEN,
            # HOSTILE, JOINED, ORGONLY, HCLIENT, UPNFALL, JOINEDGUI.
            $base = [datetime]'2026-10-02T12:00:00'
            $order = @(
                "$id-results.json", 'ndaco.org\NDACO-20261002-100000-results.json', 'FLATNDACO-20261002-090000-results.json',
                'METAFIRST-20261002-080000-results.json', 'NOMETA-20261001-090000-results.json',
                'BROKEN-20261001-080000-results.json', 'HOSTILE-20261001-070000-results.json',
                'JOINED-20261002-070500-results.json', 'ORGONLY-20261002-070400-results.json',
                'HCLIENT-20261002-070300-results.json', 'UPNFALL-20261002-070100-results.json', 'joined.com\JOINEDGUI-20261002-070200-results.json')
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

            # A hard link is not a symbolic link: both names are the same file, and
            # the guard must not refuse it.
            $hardMade = $false
            try {
                $null = New-Item -ItemType HardLink -Path (Join-Path $site 'hard.html') -Target (Join-Path $site 'AAD.html') -ErrorAction Stop
                $hardMade = $true
            } catch { Write-Verbose "No hard links here: $($_.Exception.Message)" }

            return @{ Out = $out; Work = $Work; Id = $id; LinksMade = $linksMade; HardMade = $hardMade; Clients = (Join-Path $Work 'Config\clients.json') }
        }
    }

    Context 'Files exist' {
        It 'Lib/Start-NRGWebServer.ps1 is present' {
            Test-Path -LiteralPath $script:ServerPath | Should -BeTrue
        }
        It 'the support files are present: path guard, run index, request policy, domain-name rule, error table' {
            Test-Path -LiteralPath $script:PathLib     | Should -BeTrue
            Test-Path -LiteralPath $script:IndexLib    | Should -BeTrue
            Test-Path -LiteralPath $script:RequestLib  | Should -BeTrue
            Test-Path -LiteralPath $script:DomainLib   | Should -BeTrue
            Test-Path -LiteralPath $script:ApiErrorLib | Should -BeTrue
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

        It 'every response is no-store and refuses cross-origin embedding' {
            # Reports and the action plan are tenant data: no-store keeps them out
            # of the browser's on-disk cache, which the tool's own file ACLs do not
            # cover; CORP same-origin stops another origin embedding or reading a
            # response it managed to request.
            $script:ServerSrc | Should -Match "Set-PodeHeader -Name 'Cache-Control' -Value 'no-store'"
            $script:ServerSrc | Should -Match "Set-PodeHeader -Name 'Cross-Origin-Resource-Policy' -Value 'same-origin'"
        }

        It 'a RequestGuard middleware applies the request policy, after the headers so a refusal carries them' {
            $script:ServerSrc | Should -Match "Add-PodeMiddleware -Name 'RequestGuard'"
            $script:ServerSrc | Should -Match 'Test-NRGWebRequestAllowed'
            $script:ServerSrc.IndexOf("Add-PodeMiddleware -Name 'SecurityHeaders'") | Should -BeLessThan $script:ServerSrc.IndexOf("Add-PodeMiddleware -Name 'RequestGuard'")
            # The refusal is sent with its status in ONE call (Set-PodeResponseStatus
            # renders Pode's own error page and a later body is a slice of it) and
            # stops the pipeline before any route runs.
            # Under /api/ the refusal is the JSON contract, elsewhere text; either
            # way it is one call and it ends the pipeline.
            $script:ServerSrc | Should -Match '(?s)Add-PodeMiddleware -Name .RequestGuard.*?-not \$verdict\.Allowed.*?-clike ./api/\*.*?Get-NRGWebApiError -Code Forbidden\s+Write-PodeJsonResponse -Value \$apiError\.Body -StatusCode \$apiError\.HttpStatus.*?Write-PodeTextResponse -Value \$verdict\.Message -StatusCode \$verdict\.HttpStatus.*?return \$false'
        }

        It 'the policy reads every header it decides on, and the port it is told the server uses' {
            foreach ($h in 'Host', 'Origin', 'Content-Type', 'Sec-Fetch-Site') {
                $script:ServerSrc | Should -Match "Get-PodeHeader -Name '$h'"
            }
            $script:ServerSrc | Should -Match '-Port \$cfg\.Port'
            $script:ServerSrc | Should -Match '-Scheme \$cfg\.Scheme'
            $script:ServerSrc | Should -Match "Scheme\s+=\s+'http'" -Because 'the server chooses the protocol, so the server says which scheme'
            $script:ServerSrc | Should -Match '-AllowedHost \$cfg\.AllowedHost'
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

        It 'POST /api/scan validates the domain with the one domain-name rule, and keeps no pattern of its own' {
            # The domain is fed to the child scan job and becomes a folder name:
            # the rule that accepts it must be the rule the listing, the path
            # guard and the entry script agree with. The route had a regex of its
            # own, which accepted "a..b.com" and a trailing line feed.
            $script:ServerSrc | Should -Match '(?s)''/api/scan''.*?Test-NRGDomainName\s+-Value\s+\$domain'
            $script:ServerSrc | Should -Not -Match '\$domain\s+-(not)?c?match' `
                -Because 'a second definition of a valid domain is how the first drifted'
        }

        It 'no route uses Set-PodeResponseStatus (it renders Pode''s own error page and cuts the body written after it)' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ServerPath, [ref]$null, [ref]$null)
            $names = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
            $names.Count | Should -BeGreaterThan 0
            $names | Should -Not -Contain 'Set-PodeResponseStatus'
        }

        It 'a route under /api/ answers a refusal with the JSON contract, never with text' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ServerPath, [ref]$null, [ref]$null)
            $routes = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-PodeRoute' }, $true))
            $api = 0
            foreach ($route in $routes) {
                $path = $null; $block = $null
                $els = $route.CommandElements
                for ($i = 0; $i -lt $els.Count - 1; $i++) {
                    if ($els[$i] -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
                    if ($els[$i].ParameterName -eq 'Path')        { $path  = $els[$i + 1].Value }
                    if ($els[$i].ParameterName -eq 'ScriptBlock') { $block = $els[$i + 1] }
                }
                if ($path -cnotlike '/api/*') { continue }
                $api++
                $inner = @($block.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
                $inner | Should -Not -Contain 'Write-PodeTextResponse' -Because "route $path"
            }
            $api | Should -BeGreaterOrEqual 5 -Because 'a route list that did not parse would pass this vacuously'
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

        It 'app.js shows the API''s fixed sentence for a refused scan, not the raw response body' {
            # Every refusal under /api/ is { error, message }; printing the body
            # would show JSON, and printing text() of an error page would show markup.
            $script:AppJsSrc | Should -Match 'j\.message' -Because 'the GUI shows the message field'
            $script:AppJsSrc | Should -Not -Match 'new Error\(await r\.text\(\)\)'
        }

        It 'the report-site link addresses the run by folder + id, encoded, and opens in a new tab without an opener' {
            $script:AppJsSrc | Should -Match "'/site/'\s*\+\s*encodeURIComponent\(run\.folder\)\s*\+\s*'/'\s*\+\s*encodeURIComponent\(run\.id\)" `
                -Because 'the address is the folder segment from /api/runs, never the display label'
            $script:AppJsSrc | Should -Match "\.target\s*=\s*'_blank'"
            $script:AppJsSrc | Should -Match "\.rel\s*=\s*'noopener'"
            $script:IndexSrc | Should -Match '<a id="link-report-site"[^>]*rel="noopener"' `
                -Because 'the server forbids framing (frame-ancestors none), so the site opens in its own tab'
        }

        It 'a finished scan is found by its id and a case-insensitive folder, and opened under the folder name the server reports' {
            # NTFS ignores case: scanning Contoso.com into an existing contoso.com
            # folder reuses it, the server reports 'contoso.com', and a strict
            # comparison with what was typed missed the run, so the Report site
            # link was not shown for a run that had a site.
            $script:AppJsSrc | Should -Not -Match 'r\.folder\s*===\s*domain'
            $script:AppJsSrc | Should -Match 'String\(domain\)\.toLowerCase\(\)'
            $script:AppJsSrc | Should -Match 'String\(r\.folder\)\.toLowerCase\(\)\s*===\s*want'
            $script:AppJsSrc | Should -Match 'r\.id\s*===\s*s\.resultId'
            $script:AppJsSrc | Should -Match 'made\s*\?\s*toRun\(made\)' -Because 'the folder name on disk, not the typed one, addresses the run'
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
            foreach ($f in 'Get-NRGObjectField', 'Resolve-NRGWebRunPath', 'Get-NRGWebRunIndex', 'Test-NRGWebRequestAllowed', 'Test-NRGDomainName', 'Get-NRGWebApiError') {
                $script:Src | Should -Match ('Lib\\' + $f + '\.ps1')
            }
        }
    }

    Context 'Calling Start-NRGWebServer without -ScriptDir' {
        BeforeAll {
            $script:Src = Get-Content -LiteralPath $script:ServerPath -Raw
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ServerPath, [ref]$null, [ref]$null)
            $fn  = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Start-NRGWebServer' }, $true)
            $script:ScriptDirParam  = $fn.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ScriptDir' }
            $script:OutputRootParam = $fn.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputRoot' }
            $script:AllowedHostParam = $fn.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'AllowedHost' }
            . $script:ServerPath
        }

        It 'keeps the explicit -ScriptDir parameter, and the entry point passes both it and its output folder' {
            $script:ScriptDirParam | Should -Not -BeNullOrEmpty
            $entry = Get-Content -LiteralPath $script:EntryScript -Raw
            $entry | Should -Match 'Start-NRGWebServer\s+-Port\s+\$WebPort\s+-ScriptDir\s+\$scriptDir\s+-OutputRoot\s+\$OutputPath' `
                -Because 'Invoke-NRGAssessment.ps1 -OutputPath D:\reports -Web must show D:\reports'
        }

        It 'reads runs from the ScriptDir output folder, where the command line writes, never from the current directory' {
            # The command line and the batch runner default to <script dir>\output.
            # The server used (Get-Location)\output, so a GUI started from any
            # other folder listed none of what the command line had produced.
            $script:OutputRootParam | Should -Not -BeNullOrEmpty
            $script:OutputRootParam.DefaultValue.Extent.Text | Should -Match 'Join-Path \$ScriptDir ''output'''
            $script:OutputRootParam.DefaultValue.Extent.Text | Should -Not -Match 'Get-Location|\$PWD'
            $script:Src | Should -Not -Match 'Join-Path \(Get-Location\)'
            $entry = Get-Content -LiteralPath $script:EntryScript -Raw
            $entry | Should -Match '\[string\]\s*\$OutputPath'
            $entry | Should -Match 'if \(-not \$OutputPath\) \{ \$OutputPath = Join-Path \$scriptDir ''output'' \}' `
                -Because 'the two defaults must stay the same folder, or the history splits again'
        }

        It 'a relative -OutputRoot is resolved from the PowerShell location, not the process start folder' {
            $script:Src | Should -Match 'GetUnresolvedProviderPathFromPSPath\(\$OutputRoot\)'
        }

        It '-AllowedHost accepts a host or host:port and refuses anything else, before the server starts' {
            # Parameter validation runs at bind time, so these need no Pode.
            foreach ($bad in 'a b', 'a/b', '*', '*.example.com', 'http://evil', 'evil.com:99999x', 'evil.com:', ':8765', '-x.com', "evil.com`n", 'a@b.com') {
                $err = $null
                try { Start-NRGWebServer -AllowedHost $bad -NoBrowser } catch { $err = $_ }
                $err | Should -Not -BeNullOrEmpty -Because "'$bad' is not a host name"
                $err.FullyQualifiedErrorId | Should -Match 'ParameterArgumentValidationError' -Because 'refused by parameter validation, before any server code runs'
            }
            # And the names that are fine are accepted by the same validation.
            foreach ($good in 'localhost', 'tunnel.test:9000', 'a-b.example.com', '127.0.0.1:8765') {
                $attr = ($script:AllowedHostParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidatePattern' }).PositionalArguments[0].Value
                $good | Should -Match $attr -Because "'$good' is a host name"
            }
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
            . $script:PathLib
            . $script:IndexLib
            . $script:RequestLib
            . $script:DomainLib
            . $script:ApiErrorLib
            $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("nrgweb-unit-{0}" -f ([Guid]::NewGuid().ToString('N')))
            $script:Fx   = & $script:NewFixture $script:Work
            $script:Id   = $script:Fx.Id
            $script:Runs = @(Get-NRGWebRunList -OutputRoot $script:Fx.Out -ClientsFile $script:Fx.Clients)
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
                $stamped = @($script:Id, 'NDACO-20261002-100000', 'FLATNDACO-20261002-090000', 'METAFIRST-20261002-080000',
                    'NOMETA-20261001-090000', 'BROKEN-20261001-080000', 'HOSTILE-20261001-070000',
                    'JOINED-20261002-070500', 'ORGONLY-20261002-070400', 'HCLIENT-20261002-070300', 'UPNFALL-20261002-070100', 'JOINEDGUI-20261002-070200')
                $expected = @($stamped)
                if ($script:Fx.LinksMade) { $expected += 'LINKDIR-20261002-070000' }
                # LINKDIR is created after the stamps, so it carries the current time:
                # compare the set, then the order of the stamped runs alone.
                @($ids | Sort-Object) | Should -Be @($expected | Sort-Object)
                @($ids | Where-Object { $_ -in $stamped }) | Should -Be $stamped
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
                Resolve-NRGWebRunLabel -File $f -Metadata $null -ClientMap @{} | Should -Be '(unknown tenant)'
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
                Mock Read-NRGWebRunMetadata { [pscustomobject]@{ TenantDomain = 'mocked.example'; TenantId = '' } }
                $cache = [hashtable]::Synchronized(@{})
                (Get-NRGWebRunMetadata -File $f -Cache $cache).TenantDomain | Should -Be 'mocked.example'
                (Get-NRGWebRunMetadata -File $f -Cache $cache).TenantDomain | Should -Be 'mocked.example'
                Should -Invoke Read-NRGWebRunMetadata -Times 1 -Exactly
                Add-Content -LiteralPath $f.FullName -Value ' ' -NoNewline
                (Get-NRGWebRunMetadata -File (Get-Item -LiteralPath $f.FullName) -Cache $cache).TenantDomain | Should -Be 'mocked.example'
                Should -Invoke Read-NRGWebRunMetadata -Times 2 -Exactly
            }
        }

        Context 'naming a flat run the way its client is named' {
            # A results file records the tenant's INITIAL domain (.onmicrosoft.com);
            # the GUI and the batch runner file the same client under its own domain
            # from clients.json. Joined by tenant id, then by routing domain, so one
            # client is one name.
            It 'a run whose tenant id is in clients.json takes that client''s domain' {
                ($script:Runs | Where-Object { $_.id -eq 'JOINED-20261002-070500' }).tenant | Should -Be 'joined.com'
            }

            It 'with no tenant id, the routing domain (DelegatedOrg) finds the client' {
                ($script:Runs | Where-Object { $_.id -eq 'ORGONLY-20261002-070400' }).tenant | Should -Be 'orgonly.com'
            }

            It 'a run whose file names the WRONG domain (the account''s, under GDAP) is still found by its tenant id' {
                # The domain is the MSP's own and is in no client's record; only the
                # tenant id says whose run this is. Without the id join it would be
                # listed under the MSP's name, as if it were the MSP's own tenant.
                ($script:Runs | Where-Object { $_.id -eq 'UPNFALL-20261002-070100' }).tenant | Should -Be 'upn.com'
                $meta = Read-NRGWebRunMetadata -Path (Join-Path $script:Fx.Out 'UPNFALL-20261002-070100-results.json')
                $meta.TenantDomain | Should -Be 'msp.example'
            }

            It 'a command-line run and a GUI run of the same client are listed under the same name, at different addresses' {
                $rows = @($script:Runs | Where-Object { $_.tenant -eq 'joined.com' })
                $rows.Count | Should -Be 2
                @($rows | ForEach-Object { $_.folder } | Sort-Object) | Should -Be @('_flat', 'joined.com')
            }

            It 'a client whose domain in clients.json is not domain-shaped is ignored, and the results file''s own domain is used' {
                $row = $script:Runs | Where-Object { $_.id -eq 'HCLIENT-20261002-070300' }
                $row.tenant | Should -Be 'hostile.onmicrosoft.com'
                $row.tenant | Should -Not -Match '[<>]'
            }

            It 'without clients.json the label is what the results file says' {
                $rows = @(Get-NRGWebRunList -OutputRoot $script:Fx.Out)
                ($rows | Where-Object { $_.id -eq 'JOINED-20261002-070500' }).tenant | Should -Be 'joined.onmicrosoft.com'
                @(Get-NRGWebRunList -OutputRoot $script:Fx.Out -ClientsFile (Join-Path $script:Work 'no-such.json')).Count | Should -Be $rows.Count
            }

            It 'the client map: keys are lowercase, an unreadable or missing file is an empty map, a hostile entry is skipped' {
                $map = Get-NRGWebClientMap -ClientsFile $script:Fx.Clients
                $map['id:11111111-2222-3333-4444-555555555555'] | Should -Be 'joined.com'
                $map['org:joined.onmicrosoft.com'] | Should -Be 'joined.com'
                $map.ContainsKey('id:99999999-8888-7777-6666-555555555555') | Should -BeFalse
                (Get-NRGWebClientMap -ClientsFile (Join-Path $script:Work 'missing.json')).Count | Should -Be 0
                (Get-NRGWebClientMap -ClientsFile $null).Count | Should -Be 0
                $bad = Join-Path $script:Work 'bad-clients.json'
                Set-Content -LiteralPath $bad -Value '{not json' -Encoding utf8
                (Get-NRGWebClientMap -ClientsFile $bad).Count | Should -Be 0
                $upper = Join-Path $script:Work 'upper-clients.json'
                Set-Content -LiteralPath $upper -Value '{"clients":[{"TenantDomain":"Up.com","TenantId":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE","DelegatedOrg":"UP.onmicrosoft.com"}]}' -Encoding utf8
                $m = Get-NRGWebClientMap -ClientsFile $upper
                $m['id:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'] | Should -Be 'Up.com'
                $m['org:up.onmicrosoft.com'] | Should -Be 'Up.com'
            }

            It 'the metadata read returns the tenant id lowercased, and nothing for one that is not a GUID' {
                $f = Join-Path $script:Work 'META-20261002-000000-results.json'
                Set-Content -LiteralPath $f -Value '{"Metadata":{"TenantDomain":"m.example","TenantId":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"}}' -Encoding utf8
                (Read-NRGWebRunMetadata -Path $f).TenantId | Should -BeExactly 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -Because '-Be would ignore the case'
                Set-Content -LiteralPath $f -Value '{"Metadata":{"TenantDomain":"m.example","TenantId":"not-a-guid"}}' -Encoding utf8
                (Read-NRGWebRunMetadata -Path $f).TenantId | Should -Be ''
                # A JSON-escaped line feed: valid JSON whose value ends in a newline.
                Set-Content -LiteralPath $f -Value '{"Metadata":{"TenantDomain":"m.example\n"}}' -Encoding utf8
                (Read-NRGWebRunMetadata -Path $f).TenantDomain | Should -Be '' -Because 'a trailing newline is not part of a domain'
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

            # `$` also matches before a FINAL line feed in .NET, so a `$`-anchored
            # pattern accepts "abc`n". The anchor is \z, and each case below is a
            # value a `$` anchor lets through.
            It 'rejects a value that ends in a line break or other whitespace: <Label>' -ForEach @(
                @{ Label = 'trailing LF';            Value = "abc`n" }
                @{ Label = 'trailing CRLF';          Value = "abc`r`n" }
                @{ Label = 'trailing CR';            Value = "abc`r" }
                @{ Label = 'page ending in LF';      Value = "index.html`n" }
                @{ Label = 'trailing space';         Value = 'abc ' }
                @{ Label = 'trailing TAB';           Value = "abc`t" }
                @{ Label = 'leading LF';             Value = "`nabc" }) {
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

        Context 'the domain-name rule (one definition: the scan route, the listing and the entry script)' {
            # Discovery-time data: the same lists drive the per-case tests (-ForEach)
            # and the whole-list tests (a single case that carries the list), so each
            # is written once.
            BeforeDiscovery {
                $script:acceptedNames = @(
                    'contoso.com', 'a-b.example.com', 'ndaco.org', 'tenant.onmicrosoft.com', 'JOINED.COM', 'a.co',
                    '1.example.org', 'xn--bcher-kva.example', 'x.y.z.example.com', (('a' * 63) + '.com'),
                    ((('a' * 63) + '.') * 3 + ('d' * 57) + '.com'))
                $script:rejectedCases = @(
                    @{ Label = 'null';                         Value = $null }
                    @{ Label = 'empty';                        Value = '' }
                    @{ Label = 'one label';                    Value = 'localhost' }
                    @{ Label = 'empty label (a..b.com)';       Value = 'a..b.com' }
                    @{ Label = 'leading dot';                  Value = '.com' }
                    @{ Label = 'trailing dot';                 Value = 'a.com.' }
                    @{ Label = 'only dots';                    Value = '..' }
                    @{ Label = 'label starts with hyphen';     Value = '-x.com' }
                    @{ Label = 'label ends with hyphen';       Value = 'x-.com' }
                    @{ Label = 'inner label starts with hyphen'; Value = 'a.-b.com' }
                    @{ Label = 'underscore';                   Value = 'a_b.com' }
                    @{ Label = 'space';                        Value = 'a b.com' }
                    @{ Label = 'one-letter TLD';               Value = 'a.c' }
                    @{ Label = 'numeric TLD';                  Value = 'a.123' }
                    @{ Label = 'digit in TLD';                 Value = 'a.c0m' }
                    @{ Label = 'trailing LF';                  Value = "a.com`n" }
                    @{ Label = 'trailing CRLF';                Value = "a.com`r`n" }
                    @{ Label = 'leading space';                Value = ' a.com' }
                    @{ Label = 'NUL';                          Value = "a.com`0" }
                    @{ Label = 'Kelvin sign in the TLD';       Value = ('ndaco.or' + [char]0x212A) }
                    @{ Label = 'fullwidth full stop';          Value = ('a' + [char]0xFF0E + 'com') }
                    @{ Label = 'slash';                        Value = 'a/b.com' }
                    @{ Label = 'backslash';                    Value = 'a\b.com' }
                    @{ Label = 'path traversal';               Value = '../x.com' }
                    @{ Label = 'port';                         Value = 'a.com:443' }
                    @{ Label = 'userinfo';                     Value = 'user@a.com' }
                    @{ Label = 'wildcard';                     Value = '*.a.com' }
                    @{ Label = 'label of 64 characters';       Value = (('a' * 64) + '.com') }
                    @{ Label = 'top-level label of 64 letters'; Value = ('a.' + ('b' * 64)) }
                    @{ Label = '254 characters in all';        Value = ((('a' * 63) + '.') * 3 + ('d' * 58) + '.com') }
                    @{ Label = 'bad domain!';                  Value = 'bad domain!' })
            }

            It 'accepts a real domain name: <_>' -ForEach $script:acceptedNames {
                Test-NRGDomainName -Value $_ | Should -BeTrue
            }

            It 'accepts a 63-character label and a name of exactly 253 characters' {
                Test-NRGDomainName -Value (('a' * 63) + '.com') | Should -BeTrue
                $longest = ((('a' * 63) + '.') * 3 + ('d' * 57) + '.com')
                $longest.Length | Should -Be 253
                Test-NRGDomainName -Value $longest | Should -BeTrue
            }

            It 'rejects <Label>' -ForEach $script:rejectedCases {
                Test-NRGDomainName -Value $Value | Should -BeFalse
            }

            It 'every name it accepts is also a valid path segment, so a scan can never create a folder the GUI cannot open' -ForEach @(@{ Accepted = $script:acceptedNames }) {
                # Exhaustive over every string of up to six characters from an
                # alphabet that holds each character class that matters (letter,
                # digit, hyphen, dot, underscore).
                $alphabet = @('a', '1', '-', '.', '_')
                $level = @('')
                $accepted = 0
                $violations = [System.Collections.Generic.List[string]]::new()
                foreach ($length in 1..6) {
                    $next = [System.Collections.Generic.List[string]]::new()
                    foreach ($prefix in $level) {
                        foreach ($c in $alphabet) {
                            $candidate = $prefix + $c
                            $next.Add($candidate)
                            if (Test-NRGDomainName -Value $candidate) {
                                $accepted++
                                if (-not (Test-NRGWebSegment -Value $candidate)) { $violations.Add($candidate) }
                            }
                        }
                    }
                    $level = $next
                }
                $accepted | Should -BeGreaterThan 20 -Because 'a corpus that accepted nothing would pass this vacuously'
                @($violations) | Should -BeNullOrEmpty
                # The same, on the names that matter in practice.
                foreach ($name in $Accepted) { Test-NRGWebSegment -Value $name | Should -BeTrue -Because $name }
            }

            It 'the entry script''s -TenantDomain attribute is the same rule, case-sensitive, and behaves the same on every case above' -ForEach @(@{ Accepted = $script:acceptedNames; Rejected = $script:rejectedCases }) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:EntryScript, [ref]$null, [ref]$null)
                $param = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TenantDomain' }
                $attr = $param.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidatePattern' }
                @($attr).Count | Should -Be 1
                # The attribute binds before any module loads, so it carries a copy
                # of the pattern; the copy must be the rule, plus the empty value
                # (the parameter is optional).
                $attr.PositionalArguments[0].Value | Should -BeExactly ('\A\z|' + (Get-NRGDomainNamePattern))
                (@($attr.NamedArguments | Where-Object { $_.ArgumentName -eq 'Options' }).Argument.Value) | Should -Be 'None' `
                    -Because 'the default is IgnoreCase, which lets the Kelvin sign pass as a letter'
                # And it behaves like the function: bind the real attribute.
                $probe = [scriptblock]::Create("param($($attr.Extent.Text) [string] `$D) 'bound'")
                foreach ($name in $Accepted) {
                    (& $probe -D $name) | Should -Be 'bound' -Because $name
                }
                foreach ($case in $Rejected) {
                    if ([string]::IsNullOrEmpty($case.Value)) { continue }
                    { & $probe -D $case.Value } | Should -Throw -Because $case.Label
                }
                (& $probe -D '') | Should -Be 'bound' -Because 'the parameter is optional'
            }

            It 'a results file or clients.json entry that is not a domain name never becomes a label' {
                $f = Join-Path $script:Work 'label-probe.json'
                Set-Content -LiteralPath $f -Value '{"Metadata":{"TenantDomain":"a..b.com"}}' -Encoding utf8
                (Read-NRGWebRunMetadata -Path $f).TenantDomain | Should -Be ''
                Set-Content -LiteralPath $f -Value '{"Metadata":{"TenantDomain":"Unknown"}}' -Encoding utf8
                (Read-NRGWebRunMetadata -Path $f).TenantDomain | Should -Be ''
                Set-Content -LiteralPath $f -Value '{"Metadata":{"TenantDomain":"ok.example.com"}}' -Encoding utf8
                (Read-NRGWebRunMetadata -Path $f).TenantDomain | Should -Be 'ok.example.com'
            }
        }

        Context 'the API failure contract' {
            BeforeAll {
                # The statuses are written out here, independently of the table.
                $script:ExpectedApiErrors = @{
                    DomainRequired = 400; InvalidDomain = 400; UnknownRunId = 404
                    InvalidPath = 400; NotFound = 404; Forbidden = 403
                }
            }

            It 'has exactly the codes the routes use, each with its status: <Code>' -ForEach @(
                @{ Code = 'DomainRequired'; Status = 400 }, @{ Code = 'InvalidDomain'; Status = 400 }, @{ Code = 'UnknownRunId'; Status = 404 },
                @{ Code = 'InvalidPath';    Status = 400 }, @{ Code = 'NotFound';      Status = 404 }, @{ Code = 'Forbidden';    Status = 403 }) {
                $e = Get-NRGWebApiError -Code $Code
                $e.HttpStatus | Should -Be $Status
                @($e.Body.Keys) | Should -Be @('error', 'message') -Because 'the body is exactly { error, message }'
                $e.Body.error | Should -BeExactly $Code
                $e.Body.message | Should -Match '^[A-Z][^<>"''&]+\.$' -Because 'one fixed sentence, nothing that could carry markup'
                (($e.Body | ConvertTo-Json -Compress) | ConvertFrom-Json).error | Should -BeExactly $Code
            }

            It 'the set of codes is the one written down here (a new code needs a deliberate test)' {
                $valid = @((Get-Command Get-NRGWebApiError).Parameters['Code'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }).ValidValues
                @($valid | Sort-Object) | Should -Be @($script:ExpectedApiErrors.Keys | Sort-Object)
            }

            It 'every message is different, so a code can be told from its sentence' {
                $messages = foreach ($code in $script:ExpectedApiErrors.Keys) { (Get-NRGWebApiError -Code $code).Body.message }
                @($messages | Sort-Object -Unique).Count | Should -Be $script:ExpectedApiErrors.Count
            }

            It 'refuses a code that is not in the table' {
                { Get-NRGWebApiError -Code 'Whatever' } | Should -Throw
            }

            It 'the path guard''s own sentences are the table''s, so the two cannot drift apart' {
                $bad  = Resolve-NRGWebRunPath -OutputRoot $script:Fx.Out -Folder 'a b' -Id 'x' -Kind Report
                $none = Resolve-NRGWebRunPath -OutputRoot $script:Fx.Out -Folder '_flat' -Id 'NOSUCH-20261002-000000' -Kind Report
                $bad.Message  | Should -BeExactly (Get-NRGWebApiError -Code InvalidPath).Body.message
                $none.Message | Should -BeExactly (Get-NRGWebApiError -Code NotFound).Body.message
                $bad.HttpStatus  | Should -Be (Get-NRGWebApiError -Code InvalidPath).HttpStatus
                $none.HttpStatus | Should -Be (Get-NRGWebApiError -Code NotFound).HttpStatus
            }

            It 'the table is pure: it reads no file and makes no call' {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ApiErrorLib, [ref]$null, [ref]$null)
                $names = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
                @($names | Where-Object { $_ -match '^(Get-Content|Get-Item|Test-Path|Import-|Connect-|Invoke-|Start-|Set-|Out-File)' }) | Should -BeNullOrEmpty
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

            It 'a hard link is a normal file and is served (LinkType reports HardLink for BOTH names, so it cannot be told from the real file)' {
                if (-not $script:Fx.HardMade) { Set-ItResult -Skipped -Because 'this filesystem could not create a hard link'; return }
                (& $script:Resolve '_flat' $script:Id 'SitePage' 'hard.html').Status | Should -Be 'Ok'
                (& $script:Resolve '_flat' $script:Id 'SitePage' 'AAD.html').Status | Should -Be 'Ok'
            }

            It 'never serves a report folder that is itself a link, and does not list a site for it' {
                if (-not $script:Fx.LinksMade) { Set-ItResult -Skipped -Because 'this filesystem could not create symbolic links'; return }
                (& $script:Resolve '_flat' 'LINKDIR-20261002-070000' 'SitePage' 'index.html').Status | Should -Be 'NotFound'
                ($script:Runs | Where-Object { $_.id -eq 'LINKDIR-20261002-070000' }).hasSite | Should -BeFalse
            }
        }

        Context 'the link guard fails closed and does not depend on a newer runtime' {
            It 'a plain file and a plain folder are plain' {
                Test-NRGWebPathIsPlain -Path (Join-Path $script:Fx.Out "$($script:Id)-report" 'AAD.html') | Should -BeTrue
                Test-NRGWebPathIsPlain -Path (Join-Path $script:Fx.Out "$($script:Id)-report") | Should -BeTrue
            }

            It 'a path that cannot be inspected is NOT plain (fail closed)' {
                Test-NRGWebPathIsPlain -Path (Join-Path $script:Work 'no-such-file.html') | Should -BeFalse
            }

            It 'an item that exists but cannot be read is NOT plain (a race or an access error must not serve it)' {
                Mock Get-Item { $null }
                Test-NRGWebPathIsPlain -Path (Join-Path $script:Fx.Out "$($script:Id)-report" 'AAD.html') | Should -BeFalse
            }

            It 'a symbolic link is not plain, even where the runtime has no LinkTarget property' {
                if (-not $script:Fx.LinksMade) { Set-ItResult -Skipped -Because 'this filesystem could not create symbolic links'; return }
                $link = Join-Path $script:Fx.Out "$($script:Id)-report" 'linked.html'
                Test-NRGWebPathIsPlain -Path $link | Should -BeFalse
                # LinkTarget is .NET 6+. Hide it, as an older runtime would: LinkType
                # (PowerShell 6.0+) must still catch the link.
                Mock Get-NRGObjectField { '' } -ParameterFilter { $Key -eq 'LinkTarget' }
                Test-NRGWebPathIsPlain -Path $link | Should -BeFalse
            }

            It 'a hard link is plain' {
                if (-not $script:Fx.HardMade) { Set-ItResult -Skipped -Because 'this filesystem could not create a hard link'; return }
                Test-NRGWebPathIsPlain -Path (Join-Path $script:Fx.Out "$($script:Id)-report" 'hard.html') | Should -BeTrue
            }
        }

        Context 'what the helpers may do' {
            BeforeAll {
                $script:Parsed = @{}
                foreach ($entry in @(@('Index', $script:IndexLib), @('Path', $script:PathLib), @('Request', $script:RequestLib), @('Domain', $script:DomainLib), @('ApiError', $script:ApiErrorLib))) {
                    $ast = [System.Management.Automation.Language.Parser]::ParseFile($entry[1], [ref]$null, [ref]$null)
                    $script:Parsed[$entry[0]] = @{
                        Functions = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)).Count
                        Commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
                        Members  = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and $n -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) |
                            ForEach-Object { [string]$_.Member.Value })
                    }
                }
            }

            It 'is read-only and makes no tenant or network call, in any of the five files' {
                $forbidden = '^(Connect-|Disconnect-|Invoke-(Mg|NRGGraph|RestMethod|WebRequest|Command)|.*-Mg[A-Z]|Start-(Process|Job)|Set-Content|Add-Content|Out-File|Remove-Item|New-Item|Move-Item|Copy-Item|Rename-Item|Clear-Content|Resolve-NRGDns|Resolve-DnsName|Get-NRGRawData)'
                foreach ($k in $script:Parsed.Keys) {
                    $script:Parsed[$k].Functions | Should -BeGreaterThan 0 -Because "the $k file must have parsed"
                    @($script:Parsed[$k].Commands | Where-Object { $_ -match $forbidden }) | Should -BeNullOrEmpty -Because "the $k file"
                }
            }

            It 'reads the results file and clients.json only through Get-NRGObjectField' {
                $script:Parsed['Index'].Commands | Should -Contain 'Get-NRGObjectField'
                # No dotted access to a field of an input file: a replayed older file
                # does not carry newer fields and StrictMode throws on the read.
                foreach ($k in 'Index', 'Path') {
                    @($script:Parsed[$k].Members | Where-Object { $_ -in @('Metadata', 'TenantDomain', 'TenantId', 'DelegatedOrg', 'clients', 'Findings', 'RawData', 'LinkType', 'LinkTarget') }) |
                        Should -BeNullOrEmpty -Because "the $k file"
                }
            }

            It 'the request policy needs nothing from outside: no module function, no file, no state' {
                $script:Parsed['Request'].Commands | Should -Not -Contain 'Get-NRGObjectField'
                @($script:Parsed['Request'].Commands | Where-Object { $_ -match '^(Get-Content|Get-Item|Test-Path|Get-ChildItem|Import-)' }) | Should -BeNullOrEmpty
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

        Context 'the request policy (Host allow-list; same-origin JSON for anything that changes state)' {
            BeforeAll {
                $script:Policy = {
                    param([hashtable] $Req)
                    $a = @{ Method = 'GET'; Port = 8765 }
                    foreach ($k in $Req.Keys) { $a[$k] = $Req[$k] }
                    Test-NRGWebRequestAllowed @a
                }
                $script:Json = @{ Method = 'POST'; HostHeader = '127.0.0.1:8765'; ContentType = 'application/json' }
            }

            It 'allows a read on the names the server is meant to be reached as: <Label>' -ForEach @(
                @{ Label = '127.0.0.1 and its port';  HostName = '127.0.0.1:8765' }
                @{ Label = 'localhost and its port';  HostName = 'localhost:8765' }
                @{ Label = 'LOCALHOST (case)';        HostName = 'LOCALHOST:8765' }) {
                $v = & $script:Policy @{ HostHeader = $HostName }
                $v.Allowed | Should -BeTrue
            }

            It 'allows HEAD as a read' {
                (& $script:Policy @{ Method = 'HEAD'; HostHeader = '127.0.0.1:8765' }).Allowed | Should -BeTrue
            }

            It 'refuses a request whose Host header is not one of ours (DNS rebinding): <Label>' -ForEach @(
                @{ Label = 'a name the attacker owns';          HostName = 'evil.example.com:8765' }
                @{ Label = 'the attacker name, no port';        HostName = 'evil.example.com' }
                @{ Label = 'a LAN address';                     HostName = '192.168.1.50:8765' }
                @{ Label = '127.0.0.1 without the port';        HostName = '127.0.0.1' }
                @{ Label = 'localhost without the port';        HostName = 'localhost' }
                @{ Label = '127.0.0.1 on another port';         HostName = '127.0.0.1:8766' }
                @{ Label = 'localhost with a trailing dot';     HostName = 'localhost.:8765' }
                @{ Label = 'a subdomain of localhost';          HostName = 'x.localhost:8765' }
                @{ Label = 'a list of hosts';                   HostName = '127.0.0.1:8765, evil.example.com' }
                @{ Label = 'a trailing space';                  HostName = '127.0.0.1:8765 ' }
                @{ Label = 'a trailing line feed';              HostName = "127.0.0.1:8765`n" }
                @{ Label = 'userinfo before the real host';     HostName = 'evil.example.com@127.0.0.1:8765' }
                @{ Label = 'the real host as a userinfo';       HostName = '127.0.0.1:8765@evil.example.com' }
                @{ Label = 'IPv6 loopback (not bound)';         HostName = '[::1]:8765' }
                @{ Label = 'a decimal form of 127.0.0.1';       HostName = '2130706433:8765' }
                @{ Label = 'a different scheme in the header';  HostName = 'http://127.0.0.1:8765' }) {
                $v = & $script:Policy @{ HostHeader = $HostName }
                $v.Allowed | Should -BeFalse
                $v.HttpStatus | Should -Be 403
                $v.Reason | Should -Be 'HostNotAllowed'
            }

            It 'refuses a request with no Host header or an empty one' {
                (& $script:Policy @{ HostHeader = $null }).Reason | Should -Be 'HostNotAllowed'
                (& $script:Policy @{ HostHeader = '' }).Reason | Should -Be 'HostNotAllowed'
                (& $script:Policy @{}).Reason | Should -Be 'HostNotAllowed'
            }

            It 'the message is fixed text and never echoes the request' {
                $v = & $script:Policy @{ HostHeader = 'evil.example.com:8765'; Origin = 'http://attacker.test' }
                $v.Message | Should -Be 'Forbidden.'
                $v.Message | Should -Not -Match 'evil|attacker'
            }

            It 'allows a state-changing request that is same-origin JSON: <Label>' -ForEach @(
                @{ Label = 'a browser, same origin, Fetch Metadata same-origin'; Extra = @{ Origin = 'http://127.0.0.1:8765'; SecFetchSite = 'same-origin' } }
                @{ Label = 'a browser on localhost';                              Extra = @{ HostHeader = 'localhost:8765'; Origin = 'http://localhost:8765'; SecFetchSite = 'same-origin' } }
                @{ Label = 'JSON with a charset';                                 Extra = @{ ContentType = 'Application/JSON; charset=utf-8' } }
                @{ Label = 'a client that sends no Origin (not a browser)';       Extra = @{} }
                @{ Label = 'a request the user started by hand (Fetch Metadata none)'; Extra = @{ SecFetchSite = 'none' } }) {
                $req = @{} + $script:Json
                foreach ($k in $Extra.Keys) { $req[$k] = $Extra[$k] }
                (& $script:Policy $req).Allowed | Should -BeTrue
            }

            It 'refuses a state-changing request that is not JSON (a cross-site form cannot send JSON): <Label>' -ForEach @(
                @{ Label = 'a urlencoded form';       Type = 'application/x-www-form-urlencoded' }
                @{ Label = 'a multipart form';        Type = 'multipart/form-data; boundary=x' }
                @{ Label = 'text/plain';              Type = 'text/plain' }
                @{ Label = 'no content type';         Type = $null }
                @{ Label = 'an empty content type';   Type = '' }
                @{ Label = 'a look-alike media type'; Type = 'application/jsonp' }
                @{ Label = 'JSON-looking suffix';     Type = 'text/json' }
                @{ Label = 'JSON as a parameter only'; Type = 'text/plain; x=application/json' }) {
                $v = & $script:Policy @{ Method = 'POST'; HostHeader = '127.0.0.1:8765'; ContentType = $Type }
                $v.Allowed | Should -BeFalse
                $v.Reason | Should -Be 'ContentTypeNotJson'
                $v.HttpStatus | Should -Be 403
            }

            It 'refuses an Origin that is not this server, even with JSON: <Label>' -ForEach @(
                @{ Label = 'another site';              Origin = 'http://evil.example.com' }
                @{ Label = 'another site, same port';   Origin = 'http://evil.example.com:8765' }
                @{ Label = 'null (sandboxed frame)';    Origin = 'null' }
                @{ Label = 'https for the same host';   Origin = 'https://127.0.0.1:8765' }
                @{ Label = 'same host, another port';   Origin = 'http://127.0.0.1:8766' }
                @{ Label = 'a LAN address';             Origin = 'http://192.168.1.50:8765' }) {
                $v = & $script:Policy @{ Method = 'POST'; HostHeader = '127.0.0.1:8765'; ContentType = 'application/json'; Origin = $Origin }
                $v.Allowed | Should -BeFalse
                $v.Reason | Should -Be 'OriginNotAllowed'
            }

            It 'refuses a state-changing request the browser marks as cross-site: <Site>' -ForEach @(
                @{ Site = 'cross-site' }, @{ Site = 'same-site' }) {
                $v = & $script:Policy @{ Method = 'POST'; HostHeader = '127.0.0.1:8765'; ContentType = 'application/json'; SecFetchSite = $Site }
                $v.Allowed | Should -BeFalse
                $v.Reason | Should -Be 'FetchSiteNotSameOrigin'
            }

            It 'treats every method but GET and HEAD as state-changing: <Method>' -ForEach @(
                @{ Method = 'POST' }, @{ Method = 'PUT' }, @{ Method = 'PATCH' }, @{ Method = 'DELETE' }, @{ Method = 'OPTIONS' }, @{ Method = 'TRACE' }, @{ Method = 'post' }) {
                (& $script:Policy @{ Method = $Method; HostHeader = '127.0.0.1:8765' }).Reason | Should -Be 'ContentTypeNotJson'
            }

            It 'the Host check applies to a state-changing request too, and comes first' {
                (& $script:Policy @{ Method = 'POST'; HostHeader = 'evil.example.com:8765'; ContentType = 'application/json'; Origin = 'http://evil.example.com:8765' }).Reason | Should -Be 'HostNotAllowed'
            }

            It 'a read is not refused for its Fetch Metadata or Origin (a link from another page must still open the GUI)' {
                (& $script:Policy @{ HostHeader = '127.0.0.1:8765'; Origin = 'http://evil.example.com'; SecFetchSite = 'cross-site' }).Allowed | Should -BeTrue
            }

            It '-AllowedHost adds names for a tunnel: a bare host takes the server port, host:port is exact, anything else is still refused' {
                $extra = @('tunnel.test:9000', 'alias.test')
                (& $script:Policy @{ HostHeader = 'tunnel.test:9000'; AllowedHost = $extra }).Allowed | Should -BeTrue
                (& $script:Policy @{ HostHeader = 'alias.test:8765';  AllowedHost = $extra }).Allowed | Should -BeTrue
                (& $script:Policy @{ HostHeader = 'tunnel.test:9001'; AllowedHost = $extra }).Allowed | Should -BeFalse
                (& $script:Policy @{ HostHeader = 'tunnel.test';      AllowedHost = $extra }).Allowed | Should -BeFalse
                (& $script:Policy @{ HostHeader = 'alias.test:9000';  AllowedHost = $extra }).Allowed | Should -BeFalse
                (& $script:Policy @{ HostHeader = 'evil.example.com:8765'; AllowedHost = $extra }).Allowed | Should -BeFalse
                # And an allowed tunnel name is an allowed Origin for the JSON POST.
                (& $script:Policy @{ Method = 'POST'; HostHeader = 'tunnel.test:9000'; ContentType = 'application/json'; Origin = 'http://tunnel.test:9000'; AllowedHost = $extra }).Allowed | Should -BeTrue
                (& $script:Policy @{ Method = 'POST'; HostHeader = 'tunnel.test:9000'; ContentType = 'application/json'; Origin = 'http://127.0.0.1:8765'; AllowedHost = $extra }).Allowed | Should -BeTrue
            }

            It 'the scheme comes from the server, not the policy: https origins are accepted only when the server says https' {
                $post = @{ Method = 'POST'; HostHeader = '127.0.0.1:8765'; ContentType = 'application/json'; Origin = 'https://127.0.0.1:8765' }
                (& $script:Policy $post).Reason | Should -Be 'OriginNotAllowed'
                (& $script:Policy ($post + @{ Scheme = 'https' })).Allowed | Should -BeTrue
                (& $script:Policy ($post + @{ Scheme = 'http' })).Reason | Should -Be 'OriginNotAllowed'
                $http = @{ Method = 'POST'; HostHeader = '127.0.0.1:8765'; ContentType = 'application/json'; Origin = 'http://127.0.0.1:8765' }
                (& $script:Policy ($http + @{ Scheme = 'https' })).Reason | Should -Be 'OriginNotAllowed'
                { Test-NRGWebRequestAllowed -Method GET -HostHeader 'localhost:8765' -Port 8765 -Scheme 'ftp' } | Should -Throw
            }

            It 'a blank or null -AllowedHost entry adds nothing' {
                (& $script:Policy @{ HostHeader = ':8765'; AllowedHost = @('', '  ', $null) }).Allowed | Should -BeFalse
                (& $script:Policy @{ HostHeader = '127.0.0.1:8765'; AllowedHost = $null }).Allowed | Should -BeTrue
            }

            It 'the port must be a real port' {
                { Test-NRGWebRequestAllowed -Method GET -HostHeader 'localhost:0' -Port 0 } | Should -Throw
                { Test-NRGWebRequestAllowed -Method GET -HostHeader 'localhost:70000' -Port 70000 } | Should -Throw
            }
        }
    }

    Context 'Server actually starts and serves' -Skip:(-not (Get-Module -ListAvailable -Name Pode | Where-Object { $_.Version -ge [version]'2.10.0' })) {
        # The test that would have caught the shipped bug. Everything else in
        # this file is a grep or a pure-function check; neither can tell you
        # the server never came up.
        BeforeAll {
            # Starts a server and waits for it. $Opt: Cwd (where it runs: always a
            # neutral folder, so nothing can pass by reading the current directory),
            # Port, and optionally ScriptDir, OutputRoot and Extra (more arguments).
            $script:Boot = {
                param([hashtable] $Opt)
                $boot = Join-Path ([System.IO.Path]::GetTempPath()) ("nrgweb-{0}.ps1" -f ([Guid]::NewGuid().ToString('N')))
                $parts = @("-Port $($Opt.Port)")
                if ($Opt.ContainsKey('ScriptDir'))  { $parts += "-ScriptDir '$($Opt.ScriptDir)'" }
                if ($Opt.ContainsKey('OutputRoot')) { $parts += "-OutputRoot '$($Opt.OutputRoot)'" }
                if ($Opt.ContainsKey('Extra'))      { $parts += $Opt.Extra }
                @"
`$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. '$($script:ServerPath)'
Start-NRGWebServer $($parts -join ' ') -NoBrowser
"@ | Set-Content -LiteralPath $boot -Encoding utf8

                $pwshExe = (Get-Process -Id $PID).Path
                $proc = Start-Process -FilePath $pwshExe `
                    -WorkingDirectory $Opt.Cwd `
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
                        $null = Invoke-WebRequest -Uri "http://127.0.0.1:$($Opt.Port)/" -TimeoutSec 3 -UseBasicParsing
                        $up = $true
                        break
                    } catch { }
                }
                return @{ Proc = $proc; Boot = $boot; Up = $up; Port = $Opt.Port }
            }

            # A raw HTTP/1.1 request. Invoke-WebRequest runs the URL through
            # System.Uri, which collapses ../ and decodes %2e before anything is
            # sent, and it will not send an arbitrary Host or Origin: so a traversal,
            # DNS-rebinding or forged-origin test through it never reaches the
            # server as written. This sends the request exactly as given and returns
            # the body as bytes too (a byte-order mark does not survive a string).
            $script:Raw = {
                param([int] $Port, [string] $Target, [string] $Method = 'GET', [hashtable] $Headers = @{}, [string] $Body = '')
                $client = [System.Net.Sockets.TcpClient]::new()
                try {
                    $client.Connect('127.0.0.1', $Port)
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 8000
                    $hdr = [ordered]@{ Host = "127.0.0.1:$Port" }
                    foreach ($k in $Headers.Keys) { $hdr[$k] = $Headers[$k] }
                    $payload = [System.Text.Encoding]::UTF8.GetBytes($Body)
                    if ($payload.Length -gt 0) { $hdr['Content-Length'] = $payload.Length }
                    $lines = @("$Method $Target HTTP/1.1") + @($hdr.Keys | ForEach-Object { "${_}: $($hdr[$_])" }) + 'Connection: close'
                    $head = [System.Text.Encoding]::ASCII.GetBytes(($lines -join "`r`n") + "`r`n`r`n")
                    $stream.Write($head, 0, $head.Length)
                    if ($payload.Length -gt 0) { $stream.Write($payload, 0, $payload.Length) }
                    $ms = [System.IO.MemoryStream]::new()
                    $stream.CopyTo($ms)
                    $all = $ms.ToArray()
                    $split = -1
                    for ($i = 0; $i -le $all.Length - 4; $i++) {
                        if ($all[$i] -eq 13 -and $all[$i + 1] -eq 10 -and $all[$i + 2] -eq 13 -and $all[$i + 3] -eq 10) { $split = $i; break }
                    }
                    $headText = [System.Text.Encoding]::ASCII.GetString($all, 0, [Math]::Max($split, 0))
                    $bodyBytes = [byte[]]::new([Math]::Max($all.Length - $split - 4, 0))
                    if ($bodyBytes.Length -gt 0) { [Array]::Copy($all, $split + 4, $bodyBytes, 0, $bodyBytes.Length) }
                    $status = [int](($headText -split "`r`n")[0] -split ' ')[1]
                    $headers = @{}
                    foreach ($line in ($headText -split "`r`n" | Select-Object -Skip 1)) {
                        $k, $v = $line -split ':\s*', 2
                        if ($k) { $headers[$k.ToLowerInvariant()] = $v }
                    }
                    return [pscustomobject]@{ Status = $status; Headers = $headers; Body = [System.Text.Encoding]::UTF8.GetString($bodyBytes); BodyBytes = $bodyBytes }
                } finally { $client.Dispose() }
            }

            $tmp = [System.IO.Path]::GetTempPath()
            $script:Elsewhere = Join-Path $tmp ("nrgweb-cwd-{0}" -f ([Guid]::NewGuid().ToString('N')))
            $null = New-Item -ItemType Directory -Path $script:Elsewhere -Force

            $script:Work = Join-Path $tmp ("nrgweb-work-{0}" -f ([Guid]::NewGuid().ToString('N')))
            $script:Fx   = & $script:NewFixture $script:Work
            $script:Id   = $script:Fx.Id

            # Server A: no -ScriptDir at all (if the default were Lib, the old
            # behavior, this throws "Web asset directory not found" and never
            # comes up) and an explicit -OutputRoot, so it never reads the real
            # repository's output folder. Run from a neutral folder.
            $script:Port = Get-Random -Minimum 20000 -Maximum 23000
            $script:A = & $script:Boot @{ Cwd = $script:Elsewhere; Port = $script:Port; OutputRoot = $script:Fx.Out }
            $script:Up = $script:A.Up

            # Server B: an "installation" in its own folder, with the explicit
            # -ScriptDir and NO -OutputRoot: the runs must come from
            # <ScriptDir>\output, the clients from <ScriptDir>\Config\clients.json,
            # and the current directory (the neutral folder) must be left alone.
            $script:Install = Join-Path $tmp ("nrgweb-install-{0}" -f ([Guid]::NewGuid().ToString('N')))
            $script:FxB = & $script:NewFixture $script:Install
            Copy-Item -LiteralPath $script:WebRoot -Destination (Join-Path $script:Install 'Web') -Recurse
            $null = New-Item -ItemType Directory -Path (Join-Path $script:Install 'Lib') -Force
            foreach ($f in $script:FieldLib, $script:PathLib, $script:IndexLib, $script:RequestLib, $script:DomainLib, $script:ApiErrorLib) {
                Copy-Item -LiteralPath $f -Destination (Join-Path $script:Install 'Lib')
            }
            $script:PortB = Get-Random -Minimum 23001 -Maximum 26000
            $script:B = & $script:Boot @{ Cwd = $script:Elsewhere; Port = $script:PortB; ScriptDir = $script:Install }

            # Server C: extra names for a tunnel.
            $script:PortC = Get-Random -Minimum 26001 -Maximum 29000
            $script:C = & $script:Boot @{ Cwd = $script:Elsewhere; Port = $script:PortC; OutputRoot = $script:Fx.Out; Extra = "-AllowedHost 'tunnel.test:9000','alias.test'" }

            $script:Base = "http://127.0.0.1:$($script:Port)"
            $script:Get = {
                param([string] $Path)
                Invoke-WebRequest -Uri "$($script:Base)$Path" -TimeoutSec 8 -UseBasicParsing -SkipHttpErrorCheck
            }
        }

        AfterAll {
            foreach ($s in @($script:A, $script:B, $script:C)) {
                if ($s -and $s.Proc -and -not $s.Proc.HasExited) {
                    Stop-Process -Id $s.Proc.Id -Force -ErrorAction SilentlyContinue
                }
                if ($s -and $s.Boot) {
                    foreach ($f in @($s.Boot, "$($s.Boot).log", "$($s.Boot).log.err")) {
                        Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            foreach ($d in @($script:Work, $script:Install, $script:Elsewhere)) {
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

        Context 'the output folder is the ScriptDir output folder, not the current directory' {
            BeforeAll {
                $script:RunsB = @((Invoke-WebRequest -Uri "http://127.0.0.1:$($script:PortB)/api/runs" -TimeoutSec 8 -UseBasicParsing).Content | ConvertFrom-Json)
            }

            It 'a server started from another folder lists the runs the command line wrote into the ScriptDir output folder' {
                $script:B.Up | Should -BeTrue
                $expected = if ($script:FxB.LinksMade) { 13 } else { 12 }
                $script:RunsB.Count | Should -Be $expected `
                    -Because 'before, it read (Get-Location)\output and listed nothing unless it was started from the repository root'
                @($script:RunsB | Where-Object { $_.id -eq $script:FxB.Id }).Count | Should -Be 1
            }

            It 'it did not create or use an output folder in the current directory' {
                Test-Path -LiteralPath (Join-Path $script:Elsewhere 'output') | Should -BeFalse
            }

            It 'it read the ScriptDir Config\clients.json, so a command-line run carries its client''s name' {
                ($script:RunsB | Where-Object { $_.id -eq 'JOINED-20261002-070500' }).tenant | Should -Be 'joined.com'
                ($script:RunsB | Where-Object { $_.id -eq 'ORGONLY-20261002-070400' }).tenant | Should -Be 'orgonly.com'
                @($script:RunsB | Where-Object { $_.tenant -eq 'joined.com' }).Count | Should -Be 2 -Because 'the GUI-layout run of the same client has the same name'
            }

            It 'still serves its static assets and its reports' {
                (Invoke-WebRequest -Uri "http://127.0.0.1:$($script:PortB)/static/app.js" -TimeoutSec 5 -UseBasicParsing).StatusCode | Should -Be 200
                (& $script:Raw $script:PortB "/api/runs/_flat/$($script:FxB.Id)/report").Body | Should -Match 'FLAT-REPORT-MARKER'
            }
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
                $expected = if ($script:Fx.LinksMade) { 13 } else { 12 }
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

            It 'serves the action plan as a CSV attachment, once-charset media type' {
                $c = & $script:Get "/site/_flat/$($script:Id)/ActionPlan.csv"
                $c.StatusCode | Should -Be 200
                $c.Headers['Content-Type'] | Should -Match 'text/csv'
                [string]$c.Headers['Content-Type'] | Should -Not -Match 'charset=[^;]*;\s*charset=' -Because 'Pode adds the charset itself'
                [string]$c.Headers['Content-Disposition'] | Should -Match 'attachment; filename="ActionPlan.csv"'
                $c.Content | Should -Match 'SITE-CSV-MARKER'
            }

            It 'serves the action plan byte for byte, keeping the UTF-8 byte-order mark Excel needs' {
                # The publisher writes the file with a BOM so Excel reads UTF-8 and not
                # ANSI. Reading it as text and sending the string drops the BOM and the
                # non-ASCII text turns to mojibake in Excel.
                $disk = [System.IO.File]::ReadAllBytes((Join-Path $script:Fx.Out "$($script:Id)-report" 'ActionPlan.csv'))
                $disk[0..2] -join ',' | Should -Be '239,187,191' -Because 'the fixture carries a BOM'
                $r = & $script:Raw $script:Port "/site/_flat/$($script:Id)/ActionPlan.csv"
                $r.Status | Should -Be 200
                $r.BodyBytes.Length | Should -Be $disk.Length
                ($r.BodyBytes -join ',') | Should -Be ($disk -join ',')
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

        Context 'only requests meant for this server are answered' {
            # Every refused state-changing request below uses a domain that is
            # INVALID on purpose: the route would reject it with 400, so even a
            # request that got past the guard could not start a scan.

            It 'refuses a request whose Host header is not ours, on every route (DNS rebinding): <HostCase> <Path>' -ForEach @(
                @{ Path = '/';                                                     HostCase = 'evil.example.com' }
                @{ Path = '/static/app.js';                                        HostCase = 'evil.example.com' }
                @{ Path = '/api/clients';                                          HostCase = 'evil.example.com' }
                @{ Path = '/api/runs';                                             HostCase = 'evil.example.com' }
                @{ Path = '/api/runs/_flat/CLITENANT-20261002-114907/report';      HostCase = 'evil.example.com' }
                @{ Path = '/site/_flat/CLITENANT-20261002-114907/index.html';      HostCase = 'evil.example.com' }
                @{ Path = '/site/_flat/CLITENANT-20261002-114907/ActionPlan.csv';  HostCase = 'evil.example.com' }
                @{ Path = '/api/runs';                                             HostCase = 'lan' }
                @{ Path = '/api/runs';                                             HostCase = 'noport' }
                @{ Path = '/api/runs';                                             HostCase = 'localhost-noport' }
                @{ Path = '/api/runs';                                             HostCase = 'otherport' }) {
                $hostValue = switch ($HostCase) {
                    'evil.example.com' { "evil.example.com:$($script:Port)" }
                    'lan'              { "192.168.1.50:$($script:Port)" }
                    'noport'           { '127.0.0.1' }
                    'localhost-noport' { 'localhost' }
                    'otherport'        { "127.0.0.1:$($script:Port + 1)" }
                }
                $r = & $script:Raw $script:Port $Path 'GET' @{ Host = $hostValue }
                $r.Status | Should -Be 403
                if ($Path -clike '/api/*') {
                    $r.Headers['content-type'] | Should -Match '^application/json'
                    $j = $r.Body | ConvertFrom-Json
                    $j.error   | Should -BeExactly 'Forbidden'
                    $j.message | Should -BeExactly 'Forbidden.'
                } else {
                    $r.Body | Should -Be 'Forbidden.' -Because 'a page or document route refuses in plain text'
                }
                $r.Body | Should -Not -Match 'MARKER|"id"|<!DOCTYPE' -Because 'nothing of the page or the data may leave with a refusal'
            }

            It 'answers 127.0.0.1 and localhost on its own port' {
                (& $script:Raw $script:Port '/api/runs' 'GET' @{ Host = "127.0.0.1:$($script:Port)" }).Status | Should -Be 200
                (& $script:Raw $script:Port '/api/runs' 'GET' @{ Host = "localhost:$($script:Port)" }).Status | Should -Be 200
                (& $script:Raw $script:Port '/api/runs' 'GET' @{ Host = "LOCALHOST:$($script:Port)" }).Status | Should -Be 200
            }

            It 'a refusal carries the same security headers as an answer' {
                $r = & $script:Raw $script:Port '/' 'GET' @{ Host = 'evil.example.com' }
                $r.Status | Should -Be 403
                $r.Headers['content-security-policy'] | Should -Match "default-src 'none'"
                $r.Headers['cache-control'] | Should -Be 'no-store'
                $r.Headers['cross-origin-resource-policy'] | Should -Be 'same-origin'
                $r.Headers['x-content-type-options'] | Should -Be 'nosniff'
            }

            It 'every kind of answer is no-store and same-origin-only: <Path>' -ForEach @(
                @{ Path = '/' }
                @{ Path = '/static/app.js' }
                @{ Path = '/api/clients' }
                @{ Path = '/api/runs' }
                @{ Path = '/api/runs/_flat/CLITENANT-20261002-114907/report' }
                @{ Path = '/site/_flat/CLITENANT-20261002-114907/index.html' }
                @{ Path = '/site/_flat/CLITENANT-20261002-114907/ActionPlan.csv' }
                @{ Path = '/site/_flat/NOSUCH-20261002-000000/index.html' }) {
                $r = & $script:Raw $script:Port $Path
                $r.Headers['cache-control'] | Should -Be 'no-store'
                $r.Headers['cross-origin-resource-policy'] | Should -Be 'same-origin'
                $r.Headers.ContainsKey('access-control-allow-origin') | Should -BeFalse -Because 'the server never opts in to cross-origin reads'
            }

            It 'a page that makes the browser read us cross-origin still gets no CORS grant' {
                $r = & $script:Raw $script:Port '/api/runs' 'GET' @{ Origin = 'http://evil.example.com' }
                $r.Status | Should -Be 200 -Because 'the Host is ours: a read is allowed, but the browser may not hand it to the page'
                $r.Headers.ContainsKey('access-control-allow-origin') | Should -BeFalse
                $r.Headers['cross-origin-resource-policy'] | Should -Be 'same-origin'
            }

            It 'refuses a state-changing request that is not same-origin JSON: <Label>' -ForEach @(
                @{ Label = 'a cross-site form (urlencoded)'; Headers = @{ 'Content-Type' = 'application/x-www-form-urlencoded'; Origin = 'http://evil.example.com' }; Body = 'domain=bad domain!' }
                @{ Label = 'a form with no Origin';          Headers = @{ 'Content-Type' = 'application/x-www-form-urlencoded' };                                     Body = 'domain=bad domain!' }
                @{ Label = 'text/plain (the no-preflight trick)'; Headers = @{ 'Content-Type' = 'text/plain' };                                                       Body = '{"domain":"bad domain!"}' }
                @{ Label = 'JSON from another origin';       Headers = @{ 'Content-Type' = 'application/json'; Origin = 'http://evil.example.com' };                  Body = '{"domain":"bad domain!"}' }
                @{ Label = 'JSON from a null origin';        Headers = @{ 'Content-Type' = 'application/json'; Origin = 'null' };                                      Body = '{"domain":"bad domain!"}' }
                @{ Label = 'JSON marked cross-site';         Headers = @{ 'Content-Type' = 'application/json'; 'Sec-Fetch-Site' = 'cross-site' };                      Body = '{"domain":"bad domain!"}' }
                @{ Label = 'no content type at all';         Headers = @{};                                                                                           Body = '{"domain":"bad domain!"}' }) {
                $r = & $script:Raw $script:Port '/api/scan' 'POST' $Headers $Body
                $r.Status | Should -Be 403
                ($r.Body | ConvertFrom-Json).error | Should -BeExactly 'Forbidden'
            }

            It 'a state-changing request with a foreign Host is refused before its content is looked at' {
                $r = & $script:Raw $script:Port '/api/scan' 'POST' @{ Host = 'evil.example.com'; 'Content-Type' = 'application/json'; Origin = 'http://evil.example.com' } '{"domain":"bad domain!"}'
                $r.Status | Should -Be 403
                ($r.Body | ConvertFrom-Json).error | Should -BeExactly 'Forbidden'
            }

            It 'a preflight is never granted' {
                $r = & $script:Raw $script:Port '/api/scan' 'OPTIONS' @{ Origin = 'http://evil.example.com'; 'Access-Control-Request-Method' = 'POST'; 'Access-Control-Request-Headers' = 'content-type' }
                $r.Status | Should -BeIn @(403, 405)
                $r.Headers.ContainsKey('access-control-allow-origin') | Should -BeFalse
                $r.Headers.ContainsKey('access-control-allow-methods') | Should -BeFalse
            }

            It 'the GUI''s own request gets through to the route: same-origin JSON reaches the validator, which says 400 for the invalid domain' {
                # 400 is the ROUTE's answer to an invalid domain, so no scan was started.
                $own = @{ 'Content-Type' = 'application/json'; Origin = $script:Base; 'Sec-Fetch-Site' = 'same-origin' }
                (& $script:Raw $script:Port '/api/scan' 'POST' $own '{"domain":"bad domain!"}').Status | Should -Be 400
                # A client that is not a browser sends no Origin and is a normal caller.
                (& $script:Raw $script:Port '/api/scan' 'POST' @{ 'Content-Type' = 'application/json' } '{"domain":"bad domain!"}').Status | Should -Be 400
                # localhost is the same server.
                $viaName = @{ Host = "localhost:$($script:Port)"; 'Content-Type' = 'application/json'; Origin = "http://localhost:$($script:Port)" }
                (& $script:Raw $script:Port '/api/scan' 'POST' $viaName '{"domain":"bad domain!"}').Status | Should -Be 400
            }

            It 'refusing leaves no scan behind: the status route knows no run' {
                (& $script:Raw $script:Port '/api/scan/does-not-exist/status').Status | Should -Be 404
            }
        }

        Context 'a refusal under /api/ is JSON with a stable code; outside /api/ it is text' {
            # Server B is an installation folder with no entry script: if a domain
            # that must be refused were ever accepted, the scan it started would
            # fail at once instead of reaching a tenant. Server A, started from the
            # repository's own ScriptDir, is not used for a request that could start one.
            BeforeAll {
                $script:PostScan = {
                    param([string] $Body)
                    & $script:Raw $script:PortB '/api/scan' 'POST' @{ 'Content-Type' = 'application/json' } $Body
                }
            }

            It 'refuses a domain the one rule refuses with 400 InvalidDomain and a fixed sentence: <Label>' -ForEach @(
                @{ Label = 'a..b.com (the entry script accepted it)';       Body = '{"domain":"a..b.com"}';        Echo = 'a..b' }
                @{ Label = 'a trailing line feed (a $ anchor accepted it)'; Body = '{"domain":"ndaco.org\n"}';    Echo = 'ndaco' }
                @{ Label = 'a space and a bang';                           Body = '{"domain":"bad domain!"}';     Echo = 'bad domain' }
                @{ Label = 'one label';                                    Body = '{"domain":"localhost"}';       Echo = 'localhost' }
                @{ Label = 'a leading hyphen';                             Body = '{"domain":"-x.com"}';          Echo = '-x.com' }
                @{ Label = 'two dots';                                     Body = '{"domain":".."}';              Echo = '..' }
                @{ Label = 'a trailing dot';                               Body = '{"domain":"client.example.com."}'; Echo = 'client.example' }) {
                $r = & $script:PostScan $Body
                $r.Status | Should -Be 400
                $r.Headers['content-type'] | Should -Match '^application/json'
                $j = $r.Body | ConvertFrom-Json
                @($j.PSObject.Properties.Name) | Should -Be @('error', 'message')
                $j.error   | Should -BeExactly 'InvalidDomain'
                $j.message | Should -BeExactly 'The domain is not a valid domain name.'
                $r.Body | Should -Not -Match ([regex]::Escape($Echo)) -Because 'a refusal never echoes the request'
                $r.Body | Should -Not -Match '<html' -Because 'Pode''s own error page is not the answer'
            }

            It 'asks for a domain with 400 DomainRequired when there is none: <Label>' -ForEach @(
                @{ Label = 'an empty string'; Body = '{"domain":""}' }
                @{ Label = 'only spaces';     Body = '{"domain":"   "}' }
                @{ Label = 'no domain field'; Body = '{}' }) {
                $r = & $script:PostScan $Body
                $r.Status | Should -Be 400
                $j = $r.Body | ConvertFrom-Json
                $j.error   | Should -BeExactly 'DomainRequired'
                $j.message | Should -BeExactly 'A domain is required.'
            }

            It 'a valid domain is accepted: the route answers 200 with a run id, and the status route knows it' {
                $r = & $script:PostScan '{"domain":"Client-One.example.com"}'
                $r.Status | Should -Be 200
                $runId = ($r.Body | ConvertFrom-Json).runId
                $runId | Should -Match '^[0-9a-f]{12}$'
                $st = & $script:Raw $script:PortB "/api/scan/$runId/status"
                $st.Status | Should -Be 200
                $sj = $st.Body | ConvertFrom-Json
                $sj.domain | Should -BeExactly 'Client-One.example.com'
                $sj.status | Should -BeIn @('queued', 'running', 'failed', 'completed')
                @($sj.PSObject.Properties.Name) | Should -Not -Contain 'error'
                # The route creates nothing itself: the folder is the entry script's to make.
                Test-Path -LiteralPath (Join-Path $script:FxB.Out 'Client-One.example.com') | Should -BeFalse
            }

            It 'answers an unknown scan id with 404 UnknownRunId' {
                $r = & $script:Raw $script:Port '/api/scan/does-not-exist/status'
                $r.Status | Should -Be 404
                $r.Headers['content-type'] | Should -Match '^application/json'
                $j = $r.Body | ConvertFrom-Json
                $j.error   | Should -BeExactly 'UnknownRunId'
                $j.message | Should -BeExactly 'No scan with that run id.'
            }

            It 'answers the report route''s refusals in the same contract: <Path>' -ForEach @(
                @{ Path = '/api/runs/_flat/NOSUCH-20261002-000000/report'; Status = 404; Code = 'NotFound' }
                @{ Path = '/api/runs/nosuchfolder/NOSUCH-20261002-000000/report'; Status = 404; Code = 'NotFound' }
                @{ Path = '/api/runs/_flat/a%20b/report';                  Status = 400; Code = 'InvalidPath' }
                @{ Path = '/api/runs/a%20b/x/report';                      Status = 400; Code = 'InvalidPath' }) {
                $r = & $script:Raw $script:Port $Path
                $r.Status | Should -Be $Status
                $r.Headers['content-type'] | Should -Match '^application/json'
                ($r.Body | ConvertFrom-Json).error | Should -BeExactly $Code
            }

            It 'a document route (the report site) still refuses in plain text, and says the same thing' {
                $r = & $script:Raw $script:Port '/site/_flat/NOSUCH-20261002-000000/index.html'
                $r.Status | Should -Be 404
                $r.Headers['content-type'] | Should -Not -Match 'json'
                $r.Body | Should -BeExactly 'Not found.'
            }
        }

        Context '-AllowedHost (a tunnel or port forward)' {
            It 'answers the extra names, on the port they were given, and still refuses everything else' {
                $pc = $script:PortC
                (& $script:Raw $pc '/api/runs' 'GET' @{ Host = 'tunnel.test:9000' }).Status | Should -Be 200
                (& $script:Raw $pc '/api/runs' 'GET' @{ Host = "alias.test:$pc" }).Status | Should -Be 200
                (& $script:Raw $pc '/api/runs' 'GET' @{ Host = "127.0.0.1:$pc" }).Status | Should -Be 200
                (& $script:Raw $pc '/api/runs' 'GET' @{ Host = 'tunnel.test:9001' }).Status | Should -Be 403
                (& $script:Raw $pc '/api/runs' 'GET' @{ Host = 'tunnel.test' }).Status | Should -Be 403
                (& $script:Raw $pc '/api/runs' 'GET' @{ Host = "evil.example.com:$pc" }).Status | Should -Be 403
            }

            It 'an extra name is also an acceptable origin for the GUI''s own request, and a stranger still is not' {
                $pc = $script:PortC
                $ok  = @{ Host = 'tunnel.test:9000'; 'Content-Type' = 'application/json'; Origin = 'http://tunnel.test:9000' }
                $bad = @{ Host = 'tunnel.test:9000'; 'Content-Type' = 'application/json'; Origin = 'http://evil.example.com' }
                (& $script:Raw $pc '/api/scan' 'POST' $ok '{"domain":"bad domain!"}').Status | Should -Be 400
                (& $script:Raw $pc '/api/scan' 'POST' $bad '{"domain":"bad domain!"}').Status | Should -Be 403
            }

            It 'the default server (no -AllowedHost) does not answer those names' {
                (& $script:Raw $script:Port '/api/runs' 'GET' @{ Host = 'tunnel.test:9000' }).Status | Should -Be 403
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

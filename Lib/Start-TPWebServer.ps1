#Requires -Version 7.0
#
# Start-TPWebServer.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Local web GUI for the TenantPosture tool. Pode-backed loopback server on
# 127.0.0.1 (never exposed to the network) that lets the operator:
#   - Browse prior runs from ./output/ (both layouts: output\<domain>\ from the
#     batch runner, and the flat output\ a command-line run writes)
#   - Open the HTML report inline in the same browser window
#   - Open the multi-page report site (<base>-report\) in a new tab
#
# A viewer and nothing else. It starts no scan, signs in to nothing, starts no
# process on a request and accepts no request that changes anything: every
# route is a GET. An assessment is run from the command line
# (Invoke-TPAssessment.ps1, Invoke-TPBatchAssessment.ps1). The GUI used to
# launch one from a POST route; that was removed so that nothing a web page can
# reach on this socket can start a tenant sign-in.
#
# Tenant data never leaves the workstation.
#
# Consumed:
#   - Pode 2.10+ (PSGallery)  — soft import; user-installed
#   - Config/clients.json     — names for the run list (read only)
#   - <ScriptDir>/output/     — prior scan results, the same folder the command
#                               line writes to (read only; the server never
#                               writes here and makes no tenant call itself)
#   - Lib/Resolve-TPWebRunPath.ps1       — the path guard
#     Lib/Get-TPWebRunIndex.ps1          — run listing and labels
#     Lib/Test-TPWebRequestAllowed.ps1   — the request policy
#     Lib/Get-TPObjectField.ps1
#     loaded into Pode's runspaces with Use-PodeScript
#
# Graph scopes / cmdlets used: none.

# The repository root: this file is Lib\Start-TPWebServer.ps1 and Web\ sits
# beside Lib\. A default of Split-Path -Parent $PSCommandPath resolves to Lib\
# itself, so calling Start-TPWebServer directly failed with "Web asset
# directory not found"; only Invoke-TPAssessment.ps1 -Web, which passes the
# root explicitly, worked. A function (not an inline expression) so a test can
# ask what the default resolves to without starting a server.
function Get-TPWebDefaultScriptDir {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-TPWebLogoOrigin {
    <#
    .SYNOPSIS
        The origin (scheme and host) of the brand logo the assessment report embeds,
        read as data from the active profile (Config/profiles/<TP_PROFILE>.psd1) or
        Config/branding.psd1; '' when none is set or it is not an absolute https URL.
        The GUI and the report site carry no image of their own, so this is the one
        image origin the content-security policy has to allow beside 'self' and data:.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $ScriptDir)
    # The active profile, by the module's own rule (Resolve-TPProfilePath): the name the module
    # loaded when it is in scope, else TP_PROFILE. An unusable name gives no logo origin; the
    # entry point has already stopped on it.
    $file = Join-Path $ScriptDir 'Config' 'branding.psd1'
    $name = if (Get-Variable -Name TPProfileName -Scope Script -ErrorAction SilentlyContinue) { [string]$script:TPProfileName } else { [string]$env:TP_PROFILE }
    if ($name -and $name -ne 'branding') {
        $res = Resolve-TPProfilePath -Root $ScriptDir -Name $name
        if ($res.Status -eq 'Ok') { $file = $res.Path } else { return '' }
    }
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return '' }
    try { $data = Import-PowerShellDataFile -LiteralPath $file -ErrorAction Stop } catch { return '' }
    $logo = if ($data -is [System.Collections.IDictionary] -and $data.Contains('LogoUrl')) { [string]$data['LogoUrl'] } else { '' }
    # The same rule the run listing applies to a results file's Brand (an absolute https URL, or nothing).
    return (ConvertTo-TPWebImageOrigin -Url $logo)
}

function Start-TPWebServer {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1024, 65535)]
        [int] $Port = 8765,

        [Parameter()]
        [string] $ScriptDir = (Get-TPWebDefaultScriptDir),

        # Where the runs are. Defaults to <ScriptDir>\output, which is where
        # Invoke-TPAssessment.ps1 and the batch runner write by default. It used
        # to be the CURRENT directory's output folder, so a GUI started from
        # anywhere but the repository root listed nothing of what the command
        # line had produced. A relative path is relative to the PowerShell
        # location.
        [Parameter()]
        [string] $OutputRoot = (Join-Path $ScriptDir 'output'),

        # Skip the auto-open browser step. Useful for headless testing.
        [switch] $NoBrowser
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # ── Soft import Pode ──────────────────────────────────────────────────
    # Not in RequiredModules so CLI users aren't forced to install it. The
    # one-line install instruction below is the only friction.
    if (-not (Get-Module -ListAvailable -Name Pode | Where-Object { $_.Version -ge [version]'2.10.0' })) {
        Write-Host ''
        Write-Host '  [!] The Pode module is required for -Web mode and was not found.' -ForegroundColor Red
        Write-Host '      Install it once (free, MIT-licensed) with:'
        Write-Host ''
        Write-Host '          Install-Module Pode -MinimumVersion 2.10.0 -Scope CurrentUser' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '      Then re-run with -Web.' -ForegroundColor DarkGray
        return
    }
    Import-Module Pode -ErrorAction Stop

    # ── Locate static assets and config ───────────────────────────────────
    # Canonical before anything is built from it: Pode resolves a relative path
    # (its root, a Use-PodeScript file) against its own root, not the caller's
    # current directory, so a relative -ScriptDir would have passed the checks
    # here and had Pode look for Web\Lib\*.ps1.
    if (-not (Test-Path -LiteralPath $ScriptDir -PathType Container)) { throw "Script directory not found: $ScriptDir" }
    $ScriptDir = (Resolve-Path -LiteralPath $ScriptDir).ProviderPath
    $webRoot = Join-Path $ScriptDir 'Web'
    if (-not (Test-Path -LiteralPath $webRoot)) {
        throw "Web asset directory not found: $webRoot"
    }
    # Canonical, never relative: Pode resolves a relative -RootPath against its
    # own script location, not the caller's, so a relative -ScriptDir would have
    # passed this check here and pointed Pode at Lib\Web.
    $webRoot = (Resolve-Path -LiteralPath $webRoot).ProviderPath
    $clientsFile = Join-Path $ScriptDir 'Config\clients.json'
    # Relative means relative to where the operator is in PowerShell, not to the
    # process start folder that .NET would use.
    $outputRoot  = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot)
    [void][System.IO.Directory]::CreateDirectory($outputRoot)


    # The path guard, the run listing, the request policy, the domain-name rule
    # and the error table, loaded into Pode's runspaces below. Route bodies and middleware run in runspaces built
    # from a default session state, so a module function is not visible there
    # unless Use-PodeScript brings it in.
    $podeScripts = @(
        (Join-Path $ScriptDir 'Lib\Get-TPObjectField.ps1'),
        (Join-Path $ScriptDir 'Lib\Resolve-TPWebRunPath.ps1'),
        (Join-Path $ScriptDir 'Lib\Get-TPWebRunIndex.ps1'),
        (Join-Path $ScriptDir 'Lib\Test-TPWebRequestAllowed.ps1'),
        (Join-Path $ScriptDir 'Lib\Test-TPDomainName.ps1'),
        (Join-Path $ScriptDir 'Lib\Get-TPWebApiError.ps1')
    )
    foreach ($podeScript in $podeScripts) {
        if (-not (Test-Path -LiteralPath $podeScript -PathType Leaf)) {
            throw "Web server support script not found: $podeScript"
        }
    }
    # The same files in THIS scope too: registration-time code below (the logo
    # origin, through ConvertTo-TPWebImageOrigin) uses them, and this script
    # runs dot-sourced on its own as well as through the module.
    foreach ($podeScript in $podeScripts) { . $podeScript }
    # The profile resolver (the module's own rule for a profile name), for the logo origin below.
    . (Join-Path $ScriptDir 'Lib\Resolve-TPProfilePath.ps1')

    # Image sources the policy allows: the GUI and the report site have none, and
    # the assessment report embeds the brand logo only from the LogoUrl the active
    # profile sets, so that one origin is allowed, never every https host; a served
    # report adds the origin its own run recorded (Get-TPWebRunImageSources).
    $imgSrc = "'self' data:"
    $logoOrigin = Get-TPWebLogoOrigin -ScriptDir $ScriptDir
    if ($logoOrigin) { $imgSrc += " $logoOrigin" }

    # ── Auto-open browser after a small delay so the server is listening ─
    if (-not $NoBrowser) {
        $url = "http://127.0.0.1:$Port/"
        # $using:url is idiomatic for passing a closed-over variable into
        # Start-Job. Drops the PSUseUsingScopeModifierInNewRunspaces warning
        # vs the older param()/-ArgumentList pattern.
        Start-Job -ScriptBlock {
            Start-Sleep -Milliseconds 1500
            try { Start-Process $using:url } catch {
                Write-Verbose "Auto-launch of $using:url failed: $($_.Exception.Message)"
            }
        } | Out-Null
    }

    Write-Host ''
    Write-Host "  [+] TenantPosture GUI starting on http://127.0.0.1:$Port/" -ForegroundColor Green
    Write-Host "      Press Ctrl+C to stop." -ForegroundColor DarkGray
    Write-Host ''

    # ── Pode server ───────────────────────────────────────────────────────
    # $using: does NOT work anywhere below. Pode runs this block, and every
    # route body, through Invoke-PodeScriptBlock in its own runspaces, and a
    # Using variable is valid only with Invoke-Command / Start-Job /
    # InlineScript. Pode fails the whole server start with "A Using variable
    # cannot be retrieved", which is why -Web never came up. Two mechanisms
    # replace it, because the two places need different ones:
    #   - .GetNewClosure() carries $Port / $webRoot into the REGISTRATION-time
    #     expressions in this block. Start-PodeServer has no -ArgumentList
    #     (checked on 2.14.1), so a closure is the only way in.
    #   - Pode state carries config into the route BODIES, which run later in
    #     other runspaces that the closure does not reach.
    $serverBlock = {
        # Loopback only. Binding to 127.0.0.1 (not 0.0.0.0) is load-bearing —
        # this server is for the local operator, never the network.
        # The scheme is stated once more in the config state below (Scheme): the
        # request policy compares the Origin header with it and hard-codes neither.
        Add-PodeEndpoint -Address '127.0.0.1' -Port $Port -Protocol Http

        # Config for the route bodies. Pode's state machinery is synchronized
        # across the worker runspaces.
        Set-PodeState -Name 'cfg' -Value @{
            WebRoot     = $webRoot
            ClientsFile = $clientsFile
            OutputRoot  = $outputRoot
            ScriptDir   = $ScriptDir
            Port        = $Port
            Scheme      = 'http'
            ImgSrc      = $imgSrc
            # The one policy string; {0} is the img-src value, {1} the
            # frame-ancestors value and {2} the style-src value. The middleware
            # fills them with the server's sources, 'none' and 'self'; the report
            # route with that run's sources, 'self' (the GUI frames the report
            # through the iframe's src, so this response's own policy governs
            # the framed document) and 'self' 'unsafe-inline'; a site page with
            # the run's sources, 'none' (it opens in a tab) and the same
            # style-src. The GUI's own pages need no inline style: app.js styles
            # through the CSSOM, which CSP does not restrict, so a blanket
            # 'unsafe-inline' only widened what an injected style could do on
            # the page that lists tenants (the dynamic scan flagged it). The
            # report pages keep it because Publish-TPAssessmentHTML emits inline
            # style attributes, which no CSP hash can cover.
            CspTemplate = ("default-src 'none'; " +
                "script-src 'self'; " +
                "style-src {2}; " +
                "img-src {0}; " +
                "connect-src 'self'; " +
                "frame-src 'self' data:; " +
                "base-uri 'none'; " +
                "form-action 'none'; " +
                "frame-ancestors {1}; " +
                "object-src 'none'")
        } | Out-Null

        # What was read from each results file (keyed by file, valid until its
        # length or write time changes), so polling /api/runs does not re-read
        # every results JSON. Synchronized: four route runspaces write it.
        Set-PodeState -Name 'runMetadata' -Value ([hashtable]::Synchronized(@{})) | Out-Null

        # Bring the path guard, the run listing, the request policy, the
        # domain-name rule and the error table into the route runspaces.
        foreach ($podeScript in $podeScripts) { Use-PodeScript -Path $podeScript }

        # Security headers on every response. Same CSP family as the HTML
        # report publisher: deny everything by default, allow same-origin
        # script/style/data, no framing, no plugins, no form posts to off-host.
        Add-PodeMiddleware -Name 'SecurityHeaders' -ScriptBlock {
            $cfg = Get-PodeState -Name 'cfg'
            Set-PodeHeader -Name 'Content-Security-Policy' -Value ($cfg.CspTemplate -f $cfg.ImgSrc, "'none'", "'self'")
            Set-PodeHeader -Name 'X-Content-Type-Options' -Value 'nosniff'
            Set-PodeHeader -Name 'Referrer-Policy' -Value 'no-referrer'
            # The GUI uses no browser feature a permissions policy governs;
            # saying so closes them to any script that reached the page or a
            # framed report (the dynamic scan's first CI run flagged the absence).
            Set-PodeHeader -Name 'Permissions-Policy' -Value 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
            # Everything served here is tenant data. no-store keeps the browser
            # from writing reports and the action plan to its on-disk cache,
            # outside the access-restricted files the tool itself writes.
            Set-PodeHeader -Name 'Cache-Control' -Value 'no-store'
            # No other origin may embed or read a response (a script tag, an
            # image, a no-cors fetch), whatever it managed to request.
            Set-PodeHeader -Name 'Cross-Origin-Resource-Policy' -Value 'same-origin'
            return $true
        }

        # Who may talk to this server at all. Binding to 127.0.0.1 keeps the
        # network out, not the operator's own browser: DNS rebinding lets a web
        # page read the GUI. The policy (the Host allow-list; and, although no
        # route accepts one today, JSON same-origin requests only for anything
        # but GET and HEAD) is Test-TPWebRequestAllowed. It runs AFTER the headers
        # above so a refusal carries them too, and refuses before any route.
        Add-PodeMiddleware -Name 'RequestGuard' -ScriptBlock {
            $cfg = Get-PodeState -Name 'cfg'
            $verdict = Test-TPWebRequestAllowed `
                -Method $WebEvent.Method `
                -HostHeader (Get-PodeHeader -Name 'Host') `
                -Origin (Get-PodeHeader -Name 'Origin') `
                -ContentType (Get-PodeHeader -Name 'Content-Type') `
                -SecFetchSite (Get-PodeHeader -Name 'Sec-Fetch-Site') `
                -Port $cfg.Port `
                -Scheme $cfg.Scheme
            if (-not $verdict.Allowed) {
                # An API caller gets the same JSON contract as every other
                # refusal under /api/; a browser asking for a page gets text.
                if ($WebEvent.Path -clike '/api/*') {
                    $apiError = Get-TPWebApiError -Code Forbidden
                    Write-PodeJsonResponse -Value $apiError.Body -StatusCode $apiError.HttpStatus
                } else {
                    Write-PodeTextResponse -Value $verdict.Message -StatusCode $verdict.HttpStatus
                }
                return $false
            }
            return $true
        }

        # ── Static assets ────────────────────────────────────────────────
        # Two explicit routes, never a Pode static folder: a static route answers
        # every method, and for a path that resolves back to the folder itself
        # (/static/..%2F..%2Fx) Pode returned its browsable listing of it. Each
        # route names its own file; nothing from the request reaches the file system.
        Add-PodeRoute -Method Get -Path '/static/app.js' -ScriptBlock {
            $bytes = [System.IO.File]::ReadAllBytes((Join-Path (Get-PodeState -Name 'cfg').WebRoot 'static' 'app.js'))
            Write-PodeTextResponse -Bytes $bytes -ContentType 'text/javascript'
        }
        Add-PodeRoute -Method Get -Path '/static/app.css' -ScriptBlock {
            $bytes = [System.IO.File]::ReadAllBytes((Join-Path (Get-PodeState -Name 'cfg').WebRoot 'static' 'app.css'))
            Write-PodeTextResponse -Bytes $bytes -ContentType 'text/css'
        }

        # ── Routes ───────────────────────────────────────────────────────

        # Index — single-page UI shell.
        Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
            $cfg = Get-PodeState -Name 'cfg'
            $indexPath = Join-Path $cfg.WebRoot 'index.html'
            $html = Get-Content -LiteralPath $indexPath -Raw -Encoding utf8
            Write-PodeHtmlResponse -Value $html
        }

        # GET /api/runs — every prior assessment run under ./output/, newest
        # first. Both layouts: output\<domain>\*-results.json (a batch run, or
        # one an earlier GUI started) and output\*-results.json (a command-line run). The listing and
        # its exclusions (incident-response mailbox runs, sign-in triage) live
        # in Get-TPWebRunIndex.ps1. Each row carries `folder`, the address
        # segment the report and site routes take; `tenant` is only a label.
        Add-PodeRoute -Method Get -Path '/api/runs' -ScriptBlock {
            $cfg = Get-PodeState -Name 'cfg'
            $runs = Get-TPWebRunList -OutputRoot $cfg.OutputRoot -ClientsFile $cfg.ClientsFile `
                -MetadataCache (Get-PodeState -Name 'runMetadata')
            # @(...) so zero or one row still serializes as a JSON array.
            Write-PodeJsonResponse -Value @($runs)
        }

        # GET /api/runs/:tenant/:id/report — return the HTML report so the
        # frontend can inject it via iframe srcdoc. The HTML report carries
        # its own strict CSP; the iframe sandbox is the bound. :tenant is the
        # folder segment from /api/runs (the tenant folder, or the reserved
        # flat segment); a path is never taken from the client. The guards
        # (whitelisted segments, containment, no links) are in
        # Resolve-TPWebRunPath.
        Add-PodeRoute -Method Get -Path '/api/runs/:tenant/:id/report' -ScriptBlock {
            $found = Resolve-TPWebRunPath -OutputRoot (Get-PodeState -Name 'cfg').OutputRoot `
                -Folder $WebEvent.Parameters['tenant'] -Id $WebEvent.Parameters['id'] -Kind Report
            if ($found.Status -ne 'Ok') {
                # Under /api/, so a refusal is the JSON contract. Status and
                # body in one call: Set-PodeResponseStatus renders Pode's own
                # error page, and a body written after it is a slice of that
                # page cut to the new body's length.
                $apiError = Get-TPWebApiError -Code $(if ($found.Status -eq 'BadRequest') { 'InvalidPath' } else { 'NotFound' })
                Write-PodeJsonResponse -Value $apiError.Body -StatusCode $apiError.HttpStatus
                return
            }
            # The image policy for THIS run: its results file's Brand names the
            # logo the report embeds, which the active profile's may not be. The
            # GUI frames this response through the iframe's src, so this policy is
            # the framed document's, and frame-ancestors 'self' lets the GUI's own
            # origin, and nothing else, frame it.
            $cfg = Get-PodeState -Name 'cfg'
            $sources = Get-TPWebRunImageSources -ReportPath $found.Path -Id $WebEvent.Parameters['id'] `
                -ImgSrc $cfg.ImgSrc -Cache (Get-PodeState -Name 'runMetadata')
            Set-PodeHeader -Name 'Content-Security-Policy' -Value ($cfg.CspTemplate -f $sources, "'self'", "'self' 'unsafe-inline'")
            $html = Get-Content -LiteralPath $found.Path -Raw -Encoding utf8
            Write-PodeHtmlResponse -Value $html
        }

        # GET /site/:tenant/:id/:page — one file of the multi-page report site
        # (<base>-report\: index.html, one page per workload, ActionPlan.csv).
        # It is a route of its own, not a static folder, because the folder is
        # chosen per run. Only a .html or .csv directly inside that run's
        # -report folder is served (Resolve-TPWebRunPath -Kind SitePage); the
        # pages link each other by relative name, which resolves under this
        # same prefix. The strict CSP above applies unchanged: the site's pages
        # are self-contained (inline style, no script, no external asset), and
        # frame-ancestors 'none' means they open in their own tab, never framed.
        Add-PodeRoute -Method Get -Path '/site/:tenant/:id/:page' -ScriptBlock {
            $found = Resolve-TPWebRunPath -OutputRoot (Get-PodeState -Name 'cfg').OutputRoot `
                -Folder $WebEvent.Parameters['tenant'] -Id $WebEvent.Parameters['id'] `
                -Kind SitePage -Page $WebEvent.Parameters['page']
            if ($found.Status -ne 'Ok') {
                # Status and body in one call: Set-PodeResponseStatus renders
                # Pode's own error page, and a Write-PodeTextResponse after it
                # sends only a slice of that page cut to the new body's length.
                Write-PodeTextResponse -Value $found.Message -StatusCode $found.HttpStatus
                return
            }
            # The file's own bytes, not text read and re-encoded: the action plan
            # is written with a UTF-8 BOM so Excel does not read it as ANSI, and
            # re-encoding it as text drops the BOM. Pode adds the charset to the
            # media type itself (an explicit one comes out doubled).
            $bytes = [System.IO.File]::ReadAllBytes($found.Path)
            if ([System.IO.Path]::GetExtension($found.Path).ToLowerInvariant() -eq '.csv') {
                # The page name was whitelisted to letters, digits, dot,
                # underscore and hyphen, so it is safe inside the header.
                Set-PodeHeader -Name 'Content-Disposition' -Value ('attachment; filename="{0}"' -f [System.IO.Path]::GetFileName($found.Path))
                Write-PodeTextResponse -Bytes $bytes -ContentType 'text/csv'
            } else {
                # A site page may embed the run's brand logo too: the same per-run policy.
                $cfg = Get-PodeState -Name 'cfg'
                $sources = Get-TPWebRunImageSources -ReportPath $found.Path -Id $WebEvent.Parameters['id'] `
                    -ImgSrc $cfg.ImgSrc -Cache (Get-PodeState -Name 'runMetadata')
                Set-PodeHeader -Name 'Content-Security-Policy' -Value ($cfg.CspTemplate -f $sources, "'none'", "'self' 'unsafe-inline'")
                Write-PodeTextResponse -Bytes $bytes -ContentType 'text/html'
            }
        }

        # ── Everything else ──────────────────────────────────────────────
        # Registered last. Pode answered a path no route serves, or a method a
        # route does not allow, with its own error page BEFORE any middleware ran,
        # so that page carried no security headers and skipped the Host check. A
        # wildcard route on every method makes those requests ordinary ones: the
        # headers are set, the request policy applies, and the answer follows the
        # contract (JSON under /api/, a fixed sentence elsewhere, never the request).
        # Every method Pode routes (Connect, Merge and Trace included): a method
        # the list left out went back to Pode's own page, without the headers.
        Add-PodeRoute -Method Connect, Delete, Get, Head, Merge, Options, Patch, Post, Put, Trace -Path '/*' -ScriptBlock {
            if ($WebEvent.Path -clike '/api/*') {
                $apiError = Get-TPWebApiError -Code NotFound
                Write-PodeJsonResponse -Value $apiError.Body -StatusCode $apiError.HttpStatus
            } else {
                Write-PodeTextResponse -Value 'Not found.' -StatusCode 404
            }
        }
    }.GetNewClosure()

    # -RootPath pins Pode's own root to the Web folder: unpinned, Pode serves a
    # public\ folder found under its default root, which can be the operator's
    # current directory.
    Start-PodeServer -Threads 4 -ScriptBlock $serverBlock -RootPath $webRoot
}

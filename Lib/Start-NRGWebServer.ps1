#Requires -Version 7.0
#
# Start-NRGWebServer.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Local web GUI for the NRG-Assessment tool. Pode-backed loopback server on
# 127.0.0.1 (never exposed to the network) that lets the operator:
#   - Pick a tenant from clients.json or enter one ad-hoc
#   - Trigger a scan as a background job, with live progress
#   - Browse prior runs from ./output/ (both layouts: output\<domain>\ from the
#     GUI and the batch runner, and the flat output\ a command-line run writes)
#   - Open the HTML report inline in the same browser window
#   - Open the multi-page report site (<base>-report\) in a new tab
#
# Tenant data never leaves the workstation. The scan itself runs in a
# child pwsh job that does its own Microsoft Graph / EXO authentication via
# the same interactive browser flow the CLI uses. The server is the UI shell;
# scan logic is the existing module, unchanged.
#
# Consumed:
#   - Pode 2.10+ (PSGallery)  — soft import; user-installed
#   - Config/clients.json     — tenant list
#   - ./output/               — prior scan results (read only; the server never
#                               writes here and makes no tenant call itself)
#   - Lib/Get-NRGWebRunIndex.ps1, Lib/Get-NRGObjectField.ps1 — run listing and
#     the path guards, loaded into Pode's runspaces with Use-PodeScript
#
# Graph scopes / cmdlets used: none directly. The child scan job uses what
# Invoke-NRGAssessment.ps1 requests.

# The repository root: this file is Lib\Start-NRGWebServer.ps1 and Web\ sits
# beside Lib\. A default of Split-Path -Parent $PSCommandPath resolves to Lib\
# itself, so calling Start-NRGWebServer directly failed with "Web asset
# directory not found"; only Invoke-NRGAssessment.ps1 -Web, which passes the
# root explicitly, worked. A function (not an inline expression) so a test can
# ask what the default resolves to without starting a server.
function Get-NRGWebDefaultScriptDir {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Split-Path -Parent $PSScriptRoot)
}

function Start-NRGWebServer {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1024, 65535)]
        [int] $Port = 8765,

        [Parameter()]
        [string] $ScriptDir = (Get-NRGWebDefaultScriptDir),

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
    $webRoot = Join-Path $ScriptDir 'Web'
    if (-not (Test-Path -LiteralPath $webRoot)) {
        throw "Web asset directory not found: $webRoot"
    }
    $clientsFile = Join-Path $ScriptDir 'Config\clients.json'
    $outputRoot  = Join-Path (Get-Location) 'output'
    [void][System.IO.Directory]::CreateDirectory($outputRoot)

    # The run listing and the path guards, loaded into Pode's runspaces below.
    # Route bodies run in runspaces built from a default session state, so a
    # module function is not visible there unless Use-PodeScript brings it in.
    $podeScripts = @(
        (Join-Path $ScriptDir 'Lib\Get-NRGObjectField.ps1'),
        (Join-Path $ScriptDir 'Lib\Get-NRGWebRunIndex.ps1')
    )
    foreach ($podeScript in $podeScripts) {
        if (-not (Test-Path -LiteralPath $podeScript -PathType Leaf)) {
            throw "Web server support script not found: $podeScript"
        }
    }

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
    Write-Host "  [+] NRG-Assessment GUI starting on http://127.0.0.1:$Port/" -ForegroundColor Green
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
        Add-PodeEndpoint -Address '127.0.0.1' -Port $Port -Protocol Http

        # Config for the route bodies. Pode's state machinery is synchronized
        # across the worker runspaces, so a route body reads this the same way
        # the status handler reads what the scan handler writes.
        Set-PodeState -Name 'cfg' -Value @{
            WebRoot     = $webRoot
            ClientsFile = $clientsFile
            OutputRoot  = $outputRoot
            ScriptDir   = $ScriptDir
        } | Out-Null

        # Shared in-memory state — same machinery, so the status-poll handler
        # can read what the scan handler writes without locking ceremony in the
        # route bodies.
        Set-PodeState -Name 'scans' -Value @{} | Out-Null

        # Tenant labels already read from results files (keyed by file, valid
        # until its length or write time changes), so polling /api/runs does
        # not re-read every results JSON. Synchronized: four route runspaces
        # write it.
        Set-PodeState -Name 'runLabels' -Value ([hashtable]::Synchronized(@{})) | Out-Null

        # Bring the run listing and the path guards into the route runspaces.
        foreach ($podeScript in $podeScripts) { Use-PodeScript -Path $podeScript }

        # Security headers on every response. Same CSP family as the HTML
        # report publisher: deny everything by default, allow same-origin
        # script/style/data, no framing, no plugins, no form posts to off-host.
        Add-PodeMiddleware -Name 'SecurityHeaders' -ScriptBlock {
            Set-PodeHeader -Name 'Content-Security-Policy' -Value (
                "default-src 'none'; " +
                "script-src 'self'; " +
                "style-src 'self' 'unsafe-inline'; " +
                "img-src 'self' data: https:; " +
                "connect-src 'self'; " +
                "frame-src 'self' data:; " +
                "base-uri 'none'; " +
                "form-action 'none'; " +
                "frame-ancestors 'none'; " +
                "object-src 'none'"
            )
            Set-PodeHeader -Name 'X-Content-Type-Options' -Value 'nosniff'
            Set-PodeHeader -Name 'Referrer-Policy' -Value 'no-referrer'
            return $true
        }

        # ── Static assets ────────────────────────────────────────────────
        Add-PodeStaticRoute -Path '/static' -Source (Join-Path $webRoot 'static')

        # ── Routes ───────────────────────────────────────────────────────

        # Index — single-page UI shell.
        Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
            $indexPath = Join-Path (Get-PodeState -Name 'cfg').WebRoot 'index.html'
            $html = Get-Content -LiteralPath $indexPath -Raw -Encoding utf8
            Write-PodeHtmlResponse -Value $html
        }

        # GET /api/clients — list of clients from clients.json. Returns [] if
        # the file doesn't exist (operator can still trigger ad-hoc scans).
        Add-PodeRoute -Method Get -Path '/api/clients' -ScriptBlock {
            $cf = (Get-PodeState -Name 'cfg').ClientsFile
            if (-not (Test-Path -LiteralPath $cf)) {
                Write-PodeJsonResponse -Value @()
                return
            }
            try {
                $raw = Get-Content -LiteralPath $cf -Raw -Encoding utf8 | ConvertFrom-Json
            } catch {
                Write-PodeJsonResponse -Value @() -StatusCode 200
                return
            }
            # clients.json is { "clients": [ ... ] }, not a bare array — the
            # same shape Invoke-NRGBatchAssessment reads as $registry.clients.
            # Enumerating $raw itself yielded ONE row built from the wrapper
            # object, whose ClientName/TenantDomain do not exist, so the picker
            # showed a single blank client and never the real list.
            $clients = @($raw.clients) | Where-Object { $_.Active -ne $false } | ForEach-Object {
                [ordered]@{
                    name          = [string]$_.ClientName
                    domain        = [string]$_.TenantDomain
                    delegated     = [string]$_.DelegatedOrg
                    upn           = [string]$_.UserPrincipalName
                    clientType    = [string]$_.ClientType
                }
            }
            # @(...) or a pipeline that yields nothing assigns $null, which
            # serializes as JSON null, and app.js calls .forEach on it outside
            # its try — so a tenant list with no active rows killed the picker.
            Write-PodeJsonResponse -Value @($clients)
        }

        # GET /api/runs — every prior assessment run under ./output/, newest
        # first. Both layouts: output\<domain>\*-results.json (a GUI or batch
        # run) and output\*-results.json (a command-line run). The listing and
        # its exclusions (incident-response mailbox runs, sign-in triage) live
        # in Get-NRGWebRunIndex.ps1. Each row carries `folder`, the address
        # segment the report and site routes take; `tenant` is only a label.
        Add-PodeRoute -Method Get -Path '/api/runs' -ScriptBlock {
            $cfg = Get-PodeState -Name 'cfg'
            $runs = Get-NRGWebRunList -OutputRoot $cfg.OutputRoot -LabelCache (Get-PodeState -Name 'runLabels')
            # @(...) so zero or one row still serializes as a JSON array.
            Write-PodeJsonResponse -Value @($runs)
        }

        # GET /api/runs/:tenant/:id/report — return the HTML report so the
        # frontend can inject it via iframe srcdoc. The HTML report carries
        # its own strict CSP; the iframe sandbox is the bound. :tenant is the
        # folder segment from /api/runs (the tenant folder, or the reserved
        # flat segment); a path is never taken from the client. The guards
        # (whitelisted segments, containment, no links) are in
        # Resolve-NRGWebRunPath.
        Add-PodeRoute -Method Get -Path '/api/runs/:tenant/:id/report' -ScriptBlock {
            $found = Resolve-NRGWebRunPath -OutputRoot (Get-PodeState -Name 'cfg').OutputRoot `
                -Folder $WebEvent.Parameters['tenant'] -Id $WebEvent.Parameters['id'] -Kind Report
            if ($found.Status -ne 'Ok') {
                # Status and body in one call: Set-PodeResponseStatus renders
                # Pode's own error page, and a Write-PodeTextResponse after it
                # sends only a slice of that page cut to the new body's length.
                Write-PodeTextResponse -Value $found.Message -StatusCode $found.HttpStatus
                return
            }
            $html = Get-Content -LiteralPath $found.Path -Raw -Encoding utf8
            Write-PodeHtmlResponse -Value $html
        }

        # GET /site/:tenant/:id/:page — one file of the multi-page report site
        # (<base>-report\: index.html, one page per workload, ActionPlan.csv).
        # It is a route of its own, not a static folder, because the folder is
        # chosen per run. Only a .html or .csv directly inside that run's
        # -report folder is served (Resolve-NRGWebRunPath -Kind SitePage); the
        # pages link each other by relative name, which resolves under this
        # same prefix. The strict CSP above applies unchanged: the site's pages
        # are self-contained (inline style, no script, no external asset), and
        # frame-ancestors 'none' means they open in their own tab, never framed.
        Add-PodeRoute -Method Get -Path '/site/:tenant/:id/:page' -ScriptBlock {
            $found = Resolve-NRGWebRunPath -OutputRoot (Get-PodeState -Name 'cfg').OutputRoot `
                -Folder $WebEvent.Parameters['tenant'] -Id $WebEvent.Parameters['id'] `
                -Kind SitePage -Page $WebEvent.Parameters['page']
            if ($found.Status -ne 'Ok') {
                # Status and body in one call: Set-PodeResponseStatus renders
                # Pode's own error page, and a Write-PodeTextResponse after it
                # sends only a slice of that page cut to the new body's length.
                Write-PodeTextResponse -Value $found.Message -StatusCode $found.HttpStatus
                return
            }
            $text = Get-Content -LiteralPath $found.Path -Raw -Encoding utf8
            if ([System.IO.Path]::GetExtension($found.Path).ToLowerInvariant() -eq '.csv') {
                # The page name was whitelisted to letters, digits, dot,
                # underscore and hyphen, so it is safe inside the header.
                Set-PodeHeader -Name 'Content-Disposition' -Value ('attachment; filename="{0}"' -f [System.IO.Path]::GetFileName($found.Path))
                Write-PodeTextResponse -Value $text -ContentType 'text/csv'
            } else {
                Write-PodeHtmlResponse -Value $text
            }
        }

        # POST /api/scan — kick off a scan. Body: { clientId or domain }.
        # The scan runs in a child pwsh job so it has its own clean environment
        # for Microsoft Graph / EXO auth (Connect-MgGraph opens the browser
        # auth window in the child, which the operator authorizes once).
        Add-PodeRoute -Method Post -Path '/api/scan' -ScriptBlock {
            $body = $WebEvent.Data
            $domain = [string]$body.domain
            if ([string]::IsNullOrWhiteSpace($domain)) {
                Set-PodeResponseStatus -Code 400
                Write-PodeJsonResponse -Value @{ error = 'domain is required' }
                return
            }
            # Filename-safe and path-traversal-safe.
            if ($domain -notmatch '^[A-Za-z0-9.\-]{1,253}$') {
                Set-PodeResponseStatus -Code 400
                Write-PodeJsonResponse -Value @{ error = 'invalid domain format' }
                return
            }

            $runId = ([Guid]::NewGuid().ToString('N')).Substring(0, 12)
            $stateRow = [hashtable]::Synchronized(@{
                runId      = $runId
                domain     = $domain
                status     = 'queued'      # queued | running | completed | failed
                startedAt  = (Get-Date).ToString('o')
                lines      = New-Object System.Collections.ArrayList
                percent    = 0
                resultPath = $null
                # Read unconditionally by the status response below but only
                # assigned on completion. Pode's route runspaces do not inherit
                # this function's StrictMode, so the missing key read as $null
                # rather than throwing — declared here so the row's shape does
                # not depend on that staying true.
                runIdOnDisk = $null
                # Entry-script exit code, captured off the pipeline marker
                # object described below. $null until the marker arrives.
                exitCode    = $null
            })

            # Stash on shared state so the status endpoint can find it.
            $scans = (Get-PodeState -Name 'scans')
            $scans[$runId] = $stateRow
            Set-PodeState -Name 'scans' -Value $scans | Out-Null

            # Per-domain output directory, matching the batch runner's layout
            # (Invoke-NRGBatchAssessment writes to $clientOut = Join-Path
            # $resolvedOutput $safeDir with safeDir = TenantDomain). Without
            # -OutputPath the entry script defaults to a flat
            # <ScriptDir>/output/, which /api/runs and the status lookup
            # below never scan — a GUI scan's own report could never be
            # found by the GUI that ran it.
            $cfg = Get-PodeState -Name 'cfg'
            $scanOutputPath = Join-Path $cfg.OutputRoot $domain

            # Launch the scan in a child job. The job re-imports the module
            # and runs the entry script in -NonInteractive mode is NOT used —
            # the operator must be able to complete interactive auth in the
            # child's auth-popup browser window.
            $jobScript = {
                param($scriptDir, $domain, $outputPath)
                Set-Location $scriptDir
                $entryScript = Join-Path $scriptDir 'Invoke-NRGAssessment.ps1'
                # Run the entry script as its own CHILD PROCESS rather than
                # in-process via the call operator on the .ps1 file. Every
                # exit path in Invoke-NRGAssessment.ps1 ends in an explicit
                # `exit <code>` (0 success, 1 auth failure, 2 no findings, 3
                # partial collection, 4 fatal), and `exit` inside a script
                # invoked in THIS runspace terminates the whole job process
                # before any code below it can run — Start-Job { exit 1 }
                # lands on State=Completed with nothing after the exit ever
                # executing, so a failed auth was reported to the frontend as
                # a clean 100% run. Invoking the current pwsh executable
                # ((Get-Process -Id $PID).Path — portable across OSes) with
                # -File confines that exit to the nested process, so
                # $LASTEXITCODE survives here to report on the pipeline.
                $pwshPath = (Get-Process -Id $PID).Path
                # -TenantDomain, not a made-up "scan@<domain>" UPN: it pins the
                # scan to the chosen tenant (clients.json TenantId/DelegatedOrg,
                # else the domain's OpenID metadata) and aborts if the sign-in
                # lands anywhere else. The fake UPN only pre-filled the sign-in
                # prompt with an account that does not exist.
                & $pwshPath -NoLogo -File $entryScript -TenantDomain $domain -OutputPath $outputPath *>&1
                # *>&1 above (not 2>&1) merges the information stream too —
                # Write-Host output goes to the job's Information stream, not
                # the output stream the status handler iterates, so 2>&1
                # alone left the log always empty until the job ended.
                [pscustomobject]@{ NRGScanExitCode = $LASTEXITCODE }
            }
            $job = Start-Job -ScriptBlock $jobScript -ArgumentList $cfg.ScriptDir, $domain, $scanOutputPath
            $stateRow.jobId  = $job.Id
            $stateRow.status = 'running'

            Write-PodeJsonResponse -Value @{ runId = $runId }
        }

        # GET /api/scan/:id/status — poll for current scan state. Returns
        # status, percent, last N stdout lines. Frontend polls every 1 s.
        Add-PodeRoute -Method Get -Path '/api/scan/:id/status' -ScriptBlock {
            $id = $WebEvent.Parameters['id']
            $scans = (Get-PodeState -Name 'scans')
            if (-not $scans.ContainsKey($id)) {
                Set-PodeResponseStatus -Code 404
                Write-PodeJsonResponse -Value @{ error = 'unknown runId' }
                return
            }
            $row = $scans[$id]

            # If we have a job that's still running, harvest fresh stdout.
            if ($row.ContainsKey('jobId') -and $row.status -eq 'running') {
                $job = Get-Job -Id $row.jobId -ErrorAction SilentlyContinue
                if ($job) {
                    foreach ($chunk in Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue) {
                        # The job's last pipeline object is a marker carrying
                        # the entry script's real exit code (see jobScript in
                        # the /api/scan handler) — capture it, don't log it as
                        # a scan line. Property access on a plain string here
                        # is safe: this runspace does not inherit StrictMode.
                        if ($chunk -is [pscustomobject] -and $null -ne $chunk.NRGScanExitCode) {
                            $row.exitCode = $chunk.NRGScanExitCode
                            continue
                        }
                        $line = [string]$chunk
                        if ($line) {
                            $null = $row.lines.Add($line)
                            # Simple progress heuristic: count "[+]" success
                            # markers vs total controls. Caps at 95% so the
                            # bar moves but never falsely claims done.
                            if ($line -match '^\s*\[\+\]') {
                                $row.percent = [Math]::Min(95, $row.percent + 1)
                            }
                        }
                    }
                    if ($job.State -in @('Completed', 'Failed', 'Stopped')) {
                        # Drain any remaining output.
                        foreach ($chunk in Receive-Job -Job $job -ErrorAction SilentlyContinue) {
                            if ($chunk -is [pscustomobject] -and $null -ne $chunk.NRGScanExitCode) {
                                $row.exitCode = $chunk.NRGScanExitCode
                                continue
                            }
                            $line = [string]$chunk
                            if ($line) { $null = $row.lines.Add($line) }
                        }
                        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                        # State=Completed alone does not mean success — a
                        # non-zero exit (auth failure, module-load failure)
                        # also lands the job on Completed, so the exit-code
                        # marker is authoritative when it arrived; its
                        # absence (e.g. the child process was killed before
                        # emitting it) is treated as failure, not success.
                        $row.status  = if ($job.State -eq 'Completed' -and $row.exitCode -eq 0) { 'completed' } else { 'failed' }
                        $row.percent = if ($row.status -eq 'completed') { 100 } else { $row.percent }
                        # Look for the resulting -results.json the entry
                        # script wrote so the UI can link straight to it. Only
                        # a file written AFTER this scan started qualifies —
                        # otherwise a domain with a prior batch run hands the
                        # frontend that OLD report as "just now" even when
                        # this scan failed before writing anything.
                        $tenantDir = Join-Path (Get-PodeState -Name 'cfg').OutputRoot ($row.domain)
                        if ($row.status -eq 'completed' -and (Test-Path -LiteralPath $tenantDir)) {
                            $startedAt = [datetime]::MinValue
                            [void][datetime]::TryParse(
                                $row.startedAt, [cultureinfo]::InvariantCulture,
                                [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$startedAt)
                            $latest = Get-ChildItem -LiteralPath $tenantDir -Filter '*-results.json' -ErrorAction SilentlyContinue |
                                      Where-Object { $_.LastWriteTime -gt $startedAt } |
                                      Sort-Object LastWriteTime -Descending | Select-Object -First 1
                            if ($latest) {
                                $row.resultPath = $latest.Name
                                $row.runIdOnDisk = ($latest.BaseName -replace '-results$', '')
                            }
                        }
                    }
                }
            }

            # Trim the lines array to the most recent 200 to keep responses small.
            $tail = if ($row.lines.Count -le 200) { $row.lines } else {
                $row.lines.GetRange($row.lines.Count - 200, 200)
            }

            Write-PodeJsonResponse -Value @{
                runId       = $row.runId
                domain      = $row.domain
                status      = $row.status
                percent     = $row.percent
                lines       = @($tail)
                resultId    = $row.runIdOnDisk
            }
        }
    }.GetNewClosure()

    Start-PodeServer -Threads 4 -ScriptBlock $serverBlock
}

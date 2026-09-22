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
#   - Browse prior runs from ./output/
#   - Open the HTML report inline in the same browser window
#
# Tenant data never leaves the workstation. The scan itself runs in a
# child pwsh job that does its own Microsoft Graph / EXO authentication via
# the same interactive browser flow the CLI uses. The server is the UI shell;
# scan logic is the existing module, unchanged.
#
# Consumed:
#   - Pode 2.10+ (PSGallery)  — soft import; user-installed
#   - Config/clients.json     — tenant list
#   - ./output/               — prior scan results
#
# Graph scopes / cmdlets used: none directly. The child scan job uses what
# Invoke-NRGAssessment.ps1 requests.

function Start-NRGWebServer {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1024, 65535)]
        [int] $Port = 8765,

        [Parameter()]
        [string] $ScriptDir = (Split-Path -Parent $PSCommandPath),

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

        # GET /api/runs — list of prior runs by scanning the output directory.
        # Each subfolder under output/ is one tenant; each *-results.json is
        # one run.
        Add-PodeRoute -Method Get -Path '/api/runs' -ScriptBlock {
            $root = (Get-PodeState -Name 'cfg').OutputRoot
            if (-not (Test-Path -LiteralPath $root)) {
                Write-PodeJsonResponse -Value @()
                return
            }
            # Collect raw FileInfo + tenant first so we can sort by the real
            # DateTime, not the formatted display string. Sorting the formatted
            # string via `[datetime]$_.timestamp` uses CurrentCulture parsing,
            # which throws on non-en-US locales for the 'yyyy-MM-dd HH:mm:ss'
            # format we emit.
            $entries = @()
            foreach ($tenantDir in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
                foreach ($json in Get-ChildItem -LiteralPath $tenantDir.FullName -File -Filter '*-results.json' -ErrorAction SilentlyContinue) {
                    $entries += [pscustomobject]@{
                        File   = $json
                        Tenant = $tenantDir.Name
                    }
                }
            }
            $entries = @($entries | Sort-Object { $_.File.LastWriteTime } -Descending)

            $runs = foreach ($e in $entries) {
                $json = $e.File
                # Derive the matching .html sibling: strip `-results.json` and
                # append `-assessment.html`.
                $base          = $json.BaseName -replace '-results$', ''
                $htmlCandidate = Join-Path $json.Directory.FullName ($base + '-assessment.html')
                [ordered]@{
                    id        = $base
                    tenant    = $e.Tenant
                    timestamp = $json.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    sizeKb    = [int]($json.Length / 1KB)
                    hasReport = Test-Path -LiteralPath $htmlCandidate
                }
            }
            Write-PodeJsonResponse -Value @($runs)
        }

        # GET /api/runs/:tenant/:id/report — return the HTML report so the
        # frontend can inject it via iframe srcdoc. The HTML report carries
        # its own strict CSP; the iframe sandbox is the bound.
        Add-PodeRoute -Method Get -Path '/api/runs/:tenant/:id/report' -ScriptBlock {
            $tenant = $WebEvent.Parameters['tenant']
            $id     = $WebEvent.Parameters['id']
            # Guard against path traversal: both segments are filename-only.
            if ($tenant -match '[\\/]' -or $id -match '[\\/]') {
                Set-PodeResponseStatus -Code 400
                Write-PodeTextResponse -Value 'Invalid path segment.'
                return
            }
            $htmlPath = Join-Path (Get-PodeState -Name 'cfg').OutputRoot $tenant ($id + '-assessment.html')
            if (-not (Test-Path -LiteralPath $htmlPath)) {
                Set-PodeResponseStatus -Code 404
                Write-PodeTextResponse -Value 'Report not found.'
                return
            }
            $html = Get-Content -LiteralPath $htmlPath -Raw -Encoding utf8
            Write-PodeHtmlResponse -Value $html
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
            })

            # Stash on shared state so the status endpoint can find it.
            $scans = (Get-PodeState -Name 'scans')
            $scans[$runId] = $stateRow
            Set-PodeState -Name 'scans' -Value $scans | Out-Null

            # Launch the scan in a child job. The job re-imports the module
            # and runs the entry script in -NonInteractive mode is NOT used —
            # the operator must be able to complete interactive auth in the
            # child's auth-popup browser window.
            $jobScript = {
                param($scriptDir, $domain)
                Set-Location $scriptDir
                $entryScript = Join-Path $scriptDir 'Invoke-NRGAssessment.ps1'
                & $entryScript -UserPrincipalName "scan@$domain" 2>&1
            }
            $job = Start-Job -ScriptBlock $jobScript -ArgumentList (Get-PodeState -Name 'cfg').ScriptDir, $domain
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
                            $line = [string]$chunk
                            if ($line) { $null = $row.lines.Add($line) }
                        }
                        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                        $row.status  = if ($job.State -eq 'Completed') { 'completed' } else { 'failed' }
                        $row.percent = if ($row.status -eq 'completed') { 100 } else { $row.percent }
                        # Look for the resulting -results.json the entry
                        # script wrote so the UI can link straight to it.
                        $tenantDir = Join-Path (Get-PodeState -Name 'cfg').OutputRoot ($row.domain)
                        if (Test-Path -LiteralPath $tenantDir) {
                            $latest = Get-ChildItem -LiteralPath $tenantDir -Filter '*-results.json' -ErrorAction SilentlyContinue |
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

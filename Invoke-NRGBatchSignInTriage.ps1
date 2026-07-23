#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Microsoft.Graph.Authentication'; ModuleVersion='2.0.0' }

<#
.SYNOPSIS
    NRG Sign-In Triage Batch Runner — run the IR triage across every GDAP client.

.DESCRIPTION
    Thin wrapper over Invoke-NRGSignInTriage.ps1: loops every active client in
    Config\clients.json, runs the admin-scope sign-in IoC triage (plus mailbox
    deep-dive of flagged users) per tenant, and writes a batch summary ranking
    clients by what was found. The "morning sweep" — one command answers
    "did anyone in any client tenant get popped overnight?"

    Each per-tenant run is the existing triage orchestrator invoked as a child
    script, so it gets its own module load, state clear, connect/disconnect,
    and per-tenant output directory — the same isolation guarantees as the
    posture batch runner. The first tenant prompts a browser sign-in; later
    tenants typically SSO silently off the same MSAL session (GDAP).

    Per-client exit codes roll up into the batch summary:
      0 = clean    2 = no findings    10 = CRITICAL IoCs (likely compromise)

    Output per client: output\<tenantdomain>\IR-Triage\<timestamp>-signin-triage.html + .md + .json
    Batch summary:     output\triage-summary-<timestamp>.md

.PARAMETER ClientsFile
    Path to clients.json. Defaults to Config\clients.json.

.PARAMETER OutputRoot
    Root directory for all client triage output. Defaults to .\output\

.PARAMETER OnlyClient
    Run against a single client by TenantDomain. E.g. -OnlyClient example.com

.PARAMETER WindowDays
    Sign-in lookback window per tenant (default 7).

.PARAMETER DeepDive
    Deep-dive the top N flagged users per tenant (default 5; 0 = triage only).

.PARAMETER DeepDiveMinScore
    Minimum IoC score for a user to qualify for deep-dive (default 30).

.PARAMETER SkipMailDive
    Triage only — never request Mail.Read.All in any tenant.

.PARAMETER EnableThreatIntel
    IP threat-intel enrichment (rdap.org + Tor exit list). Default on.

.PARAMETER WhatIf
    Show which clients would be triaged without running.

.NOTES
    SECURITY:
    - Read-only — inherits the triage orchestrator's GET-only guarantee
    - TenantId validated as GUID format before use
    - Output paths sanitized — tenant domain stripped to safe chars
    - Per-tenant Graph session disconnected by the child script's finally
    - HomeState/HomeCountry auto-detect runs PER TENANT (each client's modal
      sign-in state is its own baseline — no cross-tenant assumption)
#>

[CmdletBinding()]
param(
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[/\\]' -or $_ -match '[/\\]\.\.' -or $_ -match '^\.\.' ) {
            throw "Path traversal not allowed in ClientsFile."
        }
        return $true
    })]
    [string] $ClientsFile,

    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[/\\]' -or $_ -match '[/\\]\.\.' -or $_ -match '^\.\.' ) {
            throw "Path traversal not allowed in OutputRoot."
        }
        return $true
    })]
    [string] $OutputRoot,

    [ValidatePattern('^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')]
    [string] $OnlyClient,

    [ValidateRange(1, 90)]
    [int] $WindowDays = 7,

    [ValidateRange(0, 50)]
    [int] $DeepDive = 5,

    [ValidateRange(0, 500)]
    [int] $DeepDiveMinScore = 30,

    [switch] $SkipMailDive,

    [bool] $EnableThreatIntel = $true,

    [switch] $WhatIf
)

Set-StrictMode -Version Latest

# ── Security baseline ─────────────────────────────────────────────────────────
$env:MSAL_ALLOW_BROKER = '0'
[System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.SecurityProtocolType]::Tls12 -bor
    [System.Net.SecurityProtocolType]::Tls13

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

if (-not $ClientsFile) { $ClientsFile = Join-Path $scriptDir 'Config' 'clients.json' }
if (-not $OutputRoot)  { $OutputRoot  = Join-Path $scriptDir 'output' }

$triagePath = Join-Path $scriptDir 'Invoke-NRGSignInTriage.ps1'
if (-not (Test-Path -LiteralPath $triagePath)) {
    Write-Host "[!] Invoke-NRGSignInTriage.ps1 not found next to this script." -ForegroundColor Red
    exit 1
}

# ── Load clients.json ─────────────────────────────────────────────────────────
$resolvedCfg = [System.IO.Path]::GetFullPath($ClientsFile)
if (-not (Test-Path -LiteralPath $resolvedCfg)) {
    Write-Host "[!] clients.json not found: $resolvedCfg" -ForegroundColor Red
    exit 1
}

try {
    $registry = Get-Content -LiteralPath $resolvedCfg -Raw -Encoding utf8 |
        ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Host "[!] clients.json parse failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$clients = @($registry.clients | Where-Object { $_.Active -eq $true })
if ($OnlyClient) {
    $clients = @($clients | Where-Object { $_.TenantDomain -eq $OnlyClient })
}

if ($clients.Count -eq 0) {
    Write-Host "[!] No active clients to triage." -ForegroundColor Yellow
    exit 0
}

# Validate TenantId on every client before any auth — same gate as the
# posture batch runner.
foreach ($c in $clients) {
    if ($c.TenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        Write-Host "[!] Invalid TenantId for $($c.ClientName): '$($c.TenantId)' — fix clients.json." -ForegroundColor Red
        exit 1
    }
}

Write-Host ''
Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ' NRG Batch Sign-In Triage — all GDAP clients'                -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host "  Clients      : $($clients.Count)"                           -ForegroundColor White
Write-Host "  Window       : $WindowDays day(s)"                          -ForegroundColor White
Write-Host "  Deep-dive    : top $DeepDive per tenant (>= score $DeepDiveMinScore)" -ForegroundColor White
Write-Host ''

if ($WhatIf) {
    Write-Host '  [WhatIf] Would triage:' -ForegroundColor Yellow
    foreach ($c in $clients) {
        Write-Host "    - $($c.ClientName) ($($c.TenantDomain) / $($c.TenantId))" -ForegroundColor Yellow
    }
    exit 0
}

# ── Batch loop ────────────────────────────────────────────────────────────────
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputRoot)
$timestamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$batchResults   = [System.Collections.Generic.List[object]]::new()

foreach ($client in $clients) {
    $clientStart = Get-Date

    # Sanitize domain for use in output path — OWASP A01
    $safeDir   = ($client.TenantDomain -replace '[^a-zA-Z0-9.\-]', '') -replace '^\.+|\.+$', ''
    if ([string]::IsNullOrEmpty($safeDir)) { $safeDir = 'unknown' }
    $clientOut = Join-Path (Join-Path $resolvedOutput $safeDir) 'IR-Triage'

    Write-Host ''
    Write-Host "━━━ $($client.ClientName) ($($client.TenantDomain)) ━━━" -ForegroundColor Cyan

    $status   = 'Clean'
    $errMsg   = ''
    $exitCode = $null

    try {
        # The child script owns connect/disconnect, module load, and state
        # clearing — one tenant cannot bleed into the next. -NonInteractive
        # suppresses the consent pause; the browser SSO picker may still
        # appear on the first tenant of the session.
        $params = @{
            TenantId          = $client.TenantId
            OutputPath        = $clientOut
            WindowDays        = $WindowDays
            DeepDive          = $DeepDive
            DeepDiveMinScore  = $DeepDiveMinScore
            EnableThreatIntel = $EnableThreatIntel
            NonInteractive    = $true
        }
        if ($SkipMailDive) { $params['SkipMailDive'] = $true }

        & $triagePath @params
        $exitCode = $LASTEXITCODE

        $status = switch ($exitCode) {
            0       { 'Clean' }
            2       { 'NoFindings' }
            10      { 'CRITICAL-IOCS' }
            default { "ExitCode-$exitCode" }
        }
    } catch {
        $status = 'Failed'
        $errMsg = $_.Exception.Message
        Write-Host "  [!] $errMsg" -ForegroundColor Red
    }

    $elapsed = [int](New-TimeSpan -Start $clientStart -End (Get-Date)).TotalMinutes
    $batchResults.Add([PSCustomObject]@{
        ClientName   = $client.ClientName
        TenantDomain = $client.TenantDomain
        Status       = $status
        ExitCode     = $exitCode
        Error        = $errMsg
        OutputPath   = $clientOut
        ElapsedMin   = $elapsed
    })
}

# ── Batch summary ─────────────────────────────────────────────────────────────
# CRITICAL-IOCS clients sort to the top — that's the call list.
$statusRank = @{ 'CRITICAL-IOCS' = 0; 'Failed' = 1; 'Clean' = 2; 'NoFindings' = 3 }
foreach ($r in $batchResults) {
    $rank = if ($statusRank.ContainsKey($r.Status)) { $statusRank[$r.Status] } else { 4 }
    $r | Add-Member -NotePropertyName SortRank -NotePropertyValue $rank -Force
}
$ordered = @($batchResults | Sort-Object -Property SortRank)

$md = "# NRG Batch Sign-In Triage Summary`n`n"
$md += "**Run:** $timestamp  `n"
$md += "**Clients:** $($batchResults.Count)  `n"
$md += "**Window:** $WindowDays day(s)  `n`n"
$md += "| Client | Tenant | Status | Minutes | Output |`n|---|---|---|---|---|`n"
foreach ($r in $ordered) {
    $statusCell = if ($r.Status -eq 'CRITICAL-IOCS') { "**$($r.Status)**" } else { $r.Status }
    $md += "| $($r.ClientName) | $($r.TenantDomain) | $statusCell | $($r.ElapsedMin) | ``$($r.OutputPath)`` |`n"
}
$failed = @($batchResults | Where-Object { $_.Status -eq 'Failed' })
if ($failed.Count -gt 0) {
    $md += "`n## Failures`n`n"
    foreach ($r in $failed) { $md += "- **$($r.ClientName)**: $($r.Error)`n" }
}

$summaryPath = Join-Path $resolvedOutput "triage-summary-$timestamp.md"
if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
    Set-NRGSensitiveFileContent -Path $summaryPath -Content $md
} else {
    $md | Out-File -LiteralPath $summaryPath -Encoding utf8
}

# ── Console rollup ────────────────────────────────────────────────────────────
$critClients = @($batchResults | Where-Object { $_.Status -eq 'CRITICAL-IOCS' })
Write-Host ''
Write-Host '════════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ' Batch Triage Summary' -ForegroundColor Cyan
Write-Host '════════════════════════════════════════════════════════════' -ForegroundColor Cyan
foreach ($r in $ordered) {
    $color = switch ($r.Status) {
        'CRITICAL-IOCS' { 'Red' } 'Failed' { 'Yellow' } default { 'Green' }
    }
    Write-Host ("  {0,-28} {1,-16} {2}" -f $r.ClientName, $r.Status, "$($r.ElapsedMin)m") -ForegroundColor $color
}
Write-Host ''
Write-Host "  Summary: $summaryPath" -ForegroundColor White
Write-Host ''

if ($critClients.Count -gt 0) {
    Write-Host "  [!] $($critClients.Count) client(s) with CRITICAL IoCs — review their triage reports first." -ForegroundColor Red
    exit 10
}
if ($failed.Count -gt 0) { exit 3 }
exit 0

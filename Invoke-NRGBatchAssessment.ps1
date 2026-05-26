#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Microsoft.Graph.Authentication'; ModuleVersion='2.0.0' }
#Requires -Modules @{ ModuleName='ExchangeOnlineManagement'; ModuleVersion='3.0.0' }
<#
.SYNOPSIS
    NRG-Assessment Batch Runner — GDAP multi-tenant mode.

.DESCRIPTION
    Authenticates ONCE using your NRG credentials via GDAP, then loops through
    every active client in Config\clients.json, switching tenant context per
    client via Connect-MgGraph -TenantId and
    Connect-ExchangeOnline -DelegatedOrganization.

    No per-client auth prompts. One browser login covers all tenants you have
    GDAP relationships with.

    Prerequisites:
    - Active GDAP relationships to all target tenants in Microsoft Partner Center
    - Graph scopes: Policy.Read.All, Directory.Read.All, Reports.Read.All,
                    RoleManagement.Read.All, User.Read.All, UserAuthenticationMethod.Read.All
    - Exchange Online: must hold an admin role in each client via GDAP

    Output per client: output\<tenantdomain>\<timestamp>-assessment.html + .md + .json
    Batch summary:     output\batch-summary-<timestamp>.md

.PARAMETER ClientsFile
    Path to clients.json. Defaults to Config\clients.json.

.PARAMETER OutputRoot
    Root directory for all client reports. Defaults to .\output\

.PARAMETER OnlyClient
    Run against a single client by TenantDomain. E.g. -OnlyClient ndaco.org

.PARAMETER JsonOnly
    Write JSON findings only — no HTML or Markdown.

.PARAMETER WhatIf
    Show which clients would be assessed without running.

.NOTES
    SECURITY:
    - Single auth session — no credentials stored or passed per client
    - TenantId validated as GUID format before use
    - DelegatedOrg validated as FQDN before use
    - Output paths sanitized — tenant domain stripped to safe chars
    - Sessions disconnected after each client (ASVS V7.3.2)
    - OWASP A01: path traversal prevention on all file paths
    - OWASP A03: TenantId and DelegatedOrg validated before any API call
    - OWASP A04: TLS 1.2/1.3 enforced at entry
#>

[CmdletBinding(SupportsShouldProcess)]
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

    # Single client filter — FQDN validated
    [ValidatePattern('^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')]
    [string] $OnlyClient,

    [switch] $JsonOnly,
    [switch] $WhatIf
)

# OWASP ASVS V16.4.1 — strict mode at entry, same as single-tenant orchestrator.
Set-StrictMode -Version Latest

# ── Security baseline ─────────────────────────────────────────────────────────
$env:MSAL_ALLOW_BROKER = '0'
[System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.SecurityProtocolType]::Tls12 -bor
    [System.Net.SecurityProtocolType]::Tls13

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

if (-not $ClientsFile) { $ClientsFile = Join-Path $scriptDir 'Config' 'clients.json' }
if (-not $OutputRoot)  { $OutputRoot  = Join-Path $scriptDir 'output' }

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
    Write-Host "[!] No active clients to assess." -ForegroundColor Yellow
    exit 0
}

# Validate TenantId and DelegatedOrg on every client before any auth
$GUID_PATTERN = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
$FQDN_PATTERN = '^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
foreach ($c in $clients) {
    if ($c.TenantId -notmatch $GUID_PATTERN) {
        Write-Host "[!] $($c.ClientName): TenantId '$($c.TenantId)' is not a valid GUID. Update clients.json." -ForegroundColor Red
        exit 1
    }
    if ($c.DelegatedOrg -notmatch $FQDN_PATTERN) {
        Write-Host "[!] $($c.ClientName): DelegatedOrg '$($c.DelegatedOrg)' is not a valid FQDN. Update clients.json." -ForegroundColor Red
        exit 1
    }
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host " NRG-Assessment Batch  —  $($clients.Count) tenant(s)" -ForegroundColor Cyan
Write-Host ' Auth: GDAP (one login covers all)' -ForegroundColor Cyan
Write-Host '================================================================' -ForegroundColor Cyan
foreach ($c in $clients) {
    Write-Host "  $($c.ClientName) — $($c.TenantDomain)" -ForegroundColor White
}
Write-Host ''

if ($WhatIf) {
    Write-Host "WhatIf — no assessments run." -ForegroundColor Yellow
    exit 0
}

# ── Initial Graph auth — one prompt for all tenants ───────────────────────────
# GDAP: authenticate against your own NRG tenant with the scopes needed
# Partner Center GDAP relationships grant the delegated access — no per-client auth needed
Write-Host '[-] Authenticating (one-time browser login)...' -ForegroundColor Cyan
try {
    Connect-MgGraph -Scopes @(
        'Policy.Read.All',
        'Directory.Read.All',
        'Reports.Read.All',
        'RoleManagement.Read.All',
        'User.Read.All',
        'UserAuthenticationMethod.Read.All',
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementApps.Read.All',
        'DeviceManagementManagedDevices.Read.All'
    ) -ContextScope Process -NoWelcome -ErrorAction Stop
    Write-Host '  [+] Graph authenticated' -ForegroundColor Green
} catch {
    Write-Host "  [!] Graph auth failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ── Load module ───────────────────────────────────────────────────────────────
$manifestPath = Join-Path $scriptDir 'NRG-Assessment.psd1'
try {
    Import-Module $manifestPath -Force -ErrorAction Stop
} catch {
    Write-Host "  [!] Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    exit 1
}

# ── Batch loop ────────────────────────────────────────────────────────────────
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputRoot)
$timestamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$batchResults   = [System.Collections.Generic.List[object]]::new()
$orchPath       = Join-Path $scriptDir 'Invoke-NRGAssessment.ps1'

foreach ($client in $clients) {
    $clientStart = Get-Date

    # Sanitize domain for use in output path — OWASP A01
    $safeDir   = ($client.TenantDomain -replace '[^a-zA-Z0-9.\-]', '') -replace '^\.+|\.+$', ''
    if ([string]::IsNullOrEmpty($safeDir)) { $safeDir = 'unknown' }
    $clientOut = Join-Path $resolvedOutput $safeDir

    Write-Host ''
    Write-Host "━━━ $($client.ClientName) ($($client.TenantDomain)) ━━━" -ForegroundColor Cyan

    $status = 'Success'
    $errMsg = ''

    try {
        # Clear-NRGState (not Clear-NRGFindings) to prevent raw-data bleed between tenants — CLAUDE.md mandates this.
        # Run BEFORE any tenant context switch so prior tenant's raw data, coverage,
        # and exception log cannot leak into the next client's evaluation pass.
        Clear-NRGState

        # Switch Graph context to this client tenant via GDAP
        # TenantId already validated as GUID above
        Write-Host "  [-] Switching Graph context → $($client.TenantId)..." -ForegroundColor DarkGray
        Connect-MgGraph -TenantId $client.TenantId -ContextScope Process -NoWelcome -ErrorAction Stop

        # Verify Graph context actually switched to the expected tenant.
        # Connect-MgGraph can return success while leaving a cached context
        # bound to a different tenant (token still valid for prior tenant,
        # GDAP relationship pending, etc.). Trusting the return value alone
        # risks running an assessment against the WRONG tenant and writing
        # findings to the wrong client's output directory.
        # NOTE: $tenantMismatch flag short-circuits to skip EXO connect and
        # orchestrator run while still flowing through finally + batch summary,
        # so the operator sees the skipped client in the run summary table.
        $tenantMismatch = $false
        $ctx = Get-MgContext
        if (-not $ctx -or $ctx.TenantId -ne $client.TenantId) {
            $actualTenant = if ($ctx) { $ctx.TenantId } else { '<no context>' }
            Write-Warning "Tenant context mismatch for $($client.ClientName): expected $($client.TenantId), got $actualTenant. Skipping."
            $status = 'TenantMismatch'
            $errMsg = "Graph context tenant $actualTenant != expected $($client.TenantId)"
            $tenantMismatch = $true
        }

        if (-not $tenantMismatch) {
            # Connect EXO via delegated org
            Write-Host "  [-] Connecting EXO → $($client.DelegatedOrg)..." -ForegroundColor DarkGray
            Connect-ExchangeOnline -DelegatedOrganization $client.DelegatedOrg `
                -ShowBanner:$false -ErrorAction Stop

            # Same defense-in-depth for EXO. Get-ConnectionInformation surfaces
            # the actual tenant of the established session — compare against
            # what we asked for. A mismatch means another tenant's mailbox
            # cmdlets would run, which is a categorical assessment failure.
            $exoCtx = Get-ConnectionInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq 'Connected' } |
                Select-Object -First 1
            if ($exoCtx -and $exoCtx.TenantId -and $exoCtx.TenantId -ne $client.TenantId) {
                Write-Warning "EXO context mismatch for $($client.ClientName): expected $($client.TenantId), got $($exoCtx.TenantId). Skipping."
                $status = 'TenantMismatch'
                $errMsg = "EXO context tenant $($exoCtx.TenantId) != expected $($client.TenantId)"
                $tenantMismatch = $true
            }
        }

        if (-not $tenantMismatch) {
            # Build params
            $params = @{ OutputPath = $clientOut }
            if ($client.UserPrincipalName) { $params['UserPrincipalName'] = $client.UserPrincipalName }
            if ($client.SkipPurview)       { $params['SkipPurview']       = $true }
            if ($client.SkipTeams)         { $params['SkipTeams']         = $true }
            if ($client.SkipSharePoint)    { $params['SkipSharePoint']    = $true }
            if ($client.SkipIntune)        { $params['SkipIntune']        = $true }
            if ($client.SkipPowerPlatform) { $params['SkipPowerPlatform'] = $true }
            if ($client.SkipDNS)           { $params['SkipDNS']           = $true }
            if ($JsonOnly)                 { $params['JsonOnly']           = $true }
            if ($client.DnsDomains -and @($client.DnsDomains).Count -gt 0) {
                $params['DnsDomains'] = @($client.DnsDomains)
            }

            # Run assessment — collectors + evaluators + publishers
            & $orchPath @params
        }

    } catch {
        $status = 'Failed'
        $errMsg = $_.Exception.Message
        Write-Host "  [!] $errMsg" -ForegroundColor Red
    } finally {
        # Always disconnect EXO before next client — ASVS V7.3.2
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }

    $elapsed = [int](New-TimeSpan -Start $clientStart -End (Get-Date)).TotalMinutes
    $batchResults.Add([PSCustomObject]@{
        ClientName   = $client.ClientName
        TenantDomain = $client.TenantDomain
        Status       = $status
        Error        = $errMsg
        OutputPath   = $clientOut
        ElapsedMin   = $elapsed
    })
}

# ── Disconnect Graph ─────────────────────────────────────────────────────────
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

# ── Batch summary ─────────────────────────────────────────────────────────────
if (-not (Test-Path -LiteralPath $resolvedOutput)) {
    New-Item -LiteralPath $resolvedOutput -ItemType Directory -Force | Out-Null
}

$summaryPath = Join-Path $resolvedOutput "batch-summary-$timestamp.md"

# Audit fix (v4.6.x MED #7): every tenant-sourced value gets escaped before
# Markdown interpolation. clients.json is operator-controlled today, but
# discipline + parity with Publish-NRGAssessmentSummary keeps the threat
# model consistent across publishers — and a future code path that loads
# clients from a partner-portal API would inherit the same protection.
function EscMd {
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)) { return '' }
    $s = [string]$Value
    # Strip the high-risk Markdown / HTML control characters. We deliberately
    # do not call ConvertTo-NRGHtmlSafe here because the module may not have
    # imported successfully — keep this helper standalone so the batch summary
    # is still produced even on partial load.
    $s = $s -replace '&', '&amp;'
    $s = $s -replace '<', '&lt;'
    $s = $s -replace '>', '&gt;'
    $s = $s -replace '\|', '\|'
    $s = $s -replace '`', '\`'
    # Trim newlines so a multi-line exception message doesn't smash the table.
    $s = $s -replace '[\r\n]+', ' '
    return $s
}

$sb = [System.Text.StringBuilder]::new()
$null = $sb.AppendLine("# NRG-Assessment Batch Summary")
$null = $sb.AppendLine()
$null = $sb.AppendLine("**Run:** $(Get-Date -Format 'MMMM dd, yyyy HH:mm')")
$null = $sb.AppendLine("**Clients:** $($batchResults.Count) assessed")
$null = $sb.AppendLine()
$null = $sb.AppendLine("| Client | Tenant | Status | Time | Report |")
$null = $sb.AppendLine("|--------|--------|--------|------|--------|")
foreach ($r in $batchResults) {
    $icon = if ($r.Status -eq 'Success') { '✅' } else { '❌' }
    $null = $sb.AppendLine("| $(EscMd $r.ClientName) | $(EscMd $r.TenantDomain) | $icon $(EscMd $r.Status) | $($r.ElapsedMin)m | $(EscMd $r.OutputPath) |")
}

$failed = @($batchResults | Where-Object { $_.Status -ne 'Success' })
if ($failed.Count -gt 0) {
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("## Failed Assessments")
    foreach ($f in $failed) {
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("**$(EscMd $f.ClientName):** $(EscMd $f.Error)")
    }
}

$sb.ToString() | Out-File -LiteralPath $summaryPath -Encoding utf8

# Audit-finding fix (HIGH #2): batch summary includes per-tenant status,
# tenant domains, and exception messages — same sensitivity tier as the
# per-client baseline JSON. Apply ACL hardening if helper is loaded
# (Set-NRGSensitiveFileAcl was exported by the module imported above).
if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
    Set-NRGSensitiveFileAcl -Path $summaryPath -ErrorAction SilentlyContinue
}

# ── Final ─────────────────────────────────────────────────────────────────────
$success = @($batchResults | Where-Object { $_.Status -eq 'Success' }).Count
Write-Host ''
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host " Done: $success/$($batchResults.Count) succeeded" -ForegroundColor $(if ($success -eq $batchResults.Count) { 'Green' } else { 'Yellow' })
Write-Host " Summary: $summaryPath" -ForegroundColor White
Write-Host ''

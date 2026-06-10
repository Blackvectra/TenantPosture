#Requires -Version 7.0
#
# Invoke-NRGEmailAssessment.ps1
# Email-focused incident-response variant of the NRG-Assessment tool.
# Assesses ONE user's email account during a suspected compromise instead
# of the full tenant.
#
# NRG Technology Services / NextLayerSec LLC — nrgtechservices.com
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Use when: a user's mailbox is suspected of being hacked (BEC, phish-stolen
# credentials, attacker-deleted inbox rules, mass outbound to external).
# Runs with the user's OWN credentials (delegated, no admin scope required).
#
# Usage:
#   .\Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@corp.com
#   .\Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@corp.com -WindowDays 14 -EnableThreatIntel
#
# Produces:
#   - .\output\<upn>\<timestamp>-email-results.json   (raw collected data)
#   - .\output\<upn>\<timestamp>-email-incident.html  (incident report)
#   - .\output\<upn>\<timestamp>-email-incident.md    (markdown summary)
#
# Exit codes:
#   0 success            2 no findings              4 fatal error
#   1 auth failure       3 partial collection      10 critical IoC found

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
    [string] $UserPrincipalName,

    [string] $OutputPath,

    # Optional explicit tenant — useful when the operator runs against
    # multiple tenants and the browser has a stale session for a different
    # one. Connect-NRGEmailServices will refuse a mismatched login.
    [string] $TenantId,

    # How far back to scan the SENT items. Inbox window is always 30 days
    # because the original phish often predates the first outbound IoC by
    # days or weeks.
    [ValidateRange(1, 90)]
    [int] $WindowDays = 7,

    # Opt-in threat-intel enrichment: looks up sender-domain registration
    # age via public RDAP. Submits the queried domains to a public service —
    # operator's data-handling policy may require this stay disabled.
    [switch] $EnableThreatIntel,

    # Exit non-zero when any Critical IoC is found. Useful for CI / SOAR
    # integrations that want to file a ticket on detection.
    [switch] $FailOnCriticalIoC,

    # Non-interactive mode: skip the "press enter to confirm" pause that
    # would otherwise interrupt cron / Task Scheduler runs.
    [switch] $NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:NRGEmailFatalExitCode     = $null
$script:NRGEmailSuccessExitCode   = $null
$script:NRGEmailThresholdExitCode = $null

try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ── Resolve paths + load module ─────────────────────────────────────────────
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
if (-not $OutputPath) {
    $sanitizedUser = $UserPrincipalName -replace '[^a-zA-Z0-9._-]', '_'
    $OutputPath = Join-Path $scriptDir (Join-Path 'output' $sanitizedUser)
}
$null = New-Item -ItemType Directory -Force -LiteralPath $OutputPath -ErrorAction SilentlyContinue
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$null = $resolvedOutput

Write-Host ''
Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ' NRG Email Account Assessment — Incident Response Mode'    -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Target user      : $UserPrincipalName" -ForegroundColor White
Write-Host "  Outbound window  : $WindowDays days"   -ForegroundColor White
Write-Host "  Inbox window     : 30 days (fixed)"    -ForegroundColor White
Write-Host "  Output           : $OutputPath"        -ForegroundColor White
Write-Host "  Threat intel     : $(if ($EnableThreatIntel) {'ENABLED (queries rdap.org for sender-domain age)'} else {'disabled'})" -ForegroundColor White
Write-Host ''

if (-not $NonInteractive) {
    Write-Host '  This tool will:' -ForegroundColor Yellow
    Write-Host '    1. Sign in as the COMPROMISED user (browser prompt)' -ForegroundColor Yellow
    Write-Host "    2. Read $UserPrincipalName's mailbox (sent items, inbox, rules, forwarding, deleted)" -ForegroundColor Yellow
    Write-Host '    3. Score IoCs, rank likely original phish, produce incident report' -ForegroundColor Yellow
    Write-Host '    4. NOT modify the mailbox — read-only Graph scopes only' -ForegroundColor Yellow
    if ($EnableThreatIntel) {
        Write-Host '    5. Submit external sender domains to rdap.org for registration-age lookup' -ForegroundColor Yellow
    }
    Write-Host ''
}

# Load module
$manifestPath = Join-Path $scriptDir 'NRG-Assessment.psd1'
Write-Host '[-] Loading NRG-Assessment module...' -ForegroundColor Cyan
try {
    Import-Module $manifestPath -Force -ErrorAction Stop
    Write-Host '  [+] Module loaded' -ForegroundColor Green
} catch {
    Write-Host "  [!] Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Clear state from any prior run in this session
if (Get-Command Clear-NRGState -ErrorAction SilentlyContinue) {
    Clear-NRGState
}

$reportMetadata = [ordered]@{
    AssessmentDate    = (Get-Date -Format 'MMMM dd, yyyy HH:mm UTC')
    AssessmentMode    = 'EmailIncidentResponse'
    UserPrincipalName = $UserPrincipalName
    WindowDays        = $WindowDays
    InboxWindowDays   = 30
    ToolVersion       = $script:NRGAssessmentVersion
    Brand             = $NRGBrand
    ThreatIntelEnabled = [bool]$EnableThreatIntel
}

# ── Connect ──────────────────────────────────────────────────────────────────
try {
    $ctx = Connect-NRGEmailServices -UserPrincipalName $UserPrincipalName -TenantId $TenantId
    $reportMetadata['ConnectedAccount'] = $ctx.Account
    $reportMetadata['TenantId']         = $ctx.TenantId
} catch {
    Write-Host "  [!] Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

try {
    # ── Collect ──────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '[-] Collecting mailbox data...' -ForegroundColor Cyan
    try {
        Invoke-NRGEmailCollectMailbox -WindowDays $WindowDays
        Write-Host '  [+] Mailbox data collected' -ForegroundColor Green
    } catch {
        Write-Warning "Mailbox collection failed: $($_.Exception.Message)"
    }

    # ── Evaluate ─────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '[-] Running incident response evaluators...' -ForegroundColor Cyan

    $evaluators = @(
        'Test-NRGEmailControl-InboxRules'
        'Test-NRGEmailControl-Forwarding'
        'Test-NRGEmailControl-OutboundActivity'
        'Test-NRGEmailControl-PhishOrigin'
    )
    if ($EnableThreatIntel) { $evaluators += 'Test-NRGEmailControl-ThreatIntel' }

    foreach ($fn in $evaluators) {
        if (Get-Command $fn -ErrorAction SilentlyContinue) {
            try {
                & $fn
                Write-Host "  [+] $fn" -ForegroundColor Green
            } catch {
                Write-Warning "$fn failed: $($_.Exception.Message)"
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source $fn -Message $_.Exception.Message
                }
            }
        } else {
            Write-Warning "Evaluator $fn not exported"
        }
    }

    $findings = @(Get-NRGFindings)
    $rawData  = Get-NRGRawData -AllKeys
    $reportMetadata['FindingCount'] = $findings.Count

    # ── Publish ──────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '[-] Generating incident report...' -ForegroundColor Cyan

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonPath  = Join-Path $OutputPath "$timestamp-email-results.json"
    $htmlPath  = Join-Path $OutputPath "$timestamp-email-incident.html"
    $mdPath    = Join-Path $OutputPath "$timestamp-email-incident.md"

    $jsonPayload = [ordered]@{
        Metadata   = $reportMetadata
        Findings   = $findings
        RawData    = $rawData
        Exceptions = @(Get-NRGExceptions)
    } | ConvertTo-Json -Depth 10
    Set-NRGSensitiveFileContent -Path $jsonPath -Content $jsonPayload
    Write-Host "  [+] JSON:     $jsonPath" -ForegroundColor Green

    if (Get-Command Publish-NRGEmailIncidentReport -ErrorAction SilentlyContinue) {
        try {
            Publish-NRGEmailIncidentReport `
                -Metadata $reportMetadata `
                -Findings $findings `
                -OutputPath $htmlPath `
                -MarkdownPath $mdPath
            Write-Host "  [+] HTML:     $htmlPath" -ForegroundColor Green
            Write-Host "  [+] Markdown: $mdPath"   -ForegroundColor Green
        } catch {
            Write-Warning "Report generation failed: $($_.Exception.Message)"
        }
    }

    # ── Summary banner ───────────────────────────────────────────────────────
    $crits = @($findings | Where-Object { $_.Severity -eq 'Critical' -and $_.State -eq 'Gap' })
    $highs = @($findings | Where-Object { $_.Severity -eq 'High'     -and $_.State -eq 'Gap' })

    Write-Host ''
    Write-Host '════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host ' Email IR Summary' -ForegroundColor Cyan
    Write-Host '════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host "  Total checks       : $($findings.Count)"   -ForegroundColor White
    Write-Host "  Critical IoCs      : $($crits.Count)" -ForegroundColor $(if ($crits.Count -gt 0) {'Red'} else {'Green'})
    Write-Host "  High IoCs          : $($highs.Count)" -ForegroundColor $(if ($highs.Count -gt 0) {'Yellow'} else {'Green'})
    Write-Host "  Output             : $OutputPath"   -ForegroundColor White
    Write-Host ''
    if ($crits.Count -gt 0) {
        Write-Host '  ╔══════════════════════════════════════════════════╗' -ForegroundColor Red
        Write-Host '  ║   CRITICAL IoCs found — likely compromise.       ║' -ForegroundColor Red
        Write-Host '  ║   Review the incident report and take action     ║' -ForegroundColor Red
        Write-Host '  ║   (revoke sessions, reset password, force MFA).  ║' -ForegroundColor Red
        Write-Host '  ╚══════════════════════════════════════════════════╝' -ForegroundColor Red
        Write-Host ''
    }

    if ($findings.Count -eq 0) {
        $script:NRGEmailSuccessExitCode = 2
    } elseif (@(Get-NRGExceptions).Count -gt 0) {
        $script:NRGEmailSuccessExitCode = 3
    } else {
        $script:NRGEmailSuccessExitCode = 0
    }
    if ($FailOnCriticalIoC -and $crits.Count -gt 0) {
        $script:NRGEmailThresholdExitCode = 10
        Write-Host "[!] Threshold breached: $($crits.Count) Critical IoC(s) — exiting 10" -ForegroundColor Red
    }
} catch {
    Write-Host "[!] Fatal error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    $script:NRGEmailFatalExitCode = 4
} finally {
    try { Disconnect-NRGEmailServices } catch { }
}

if ($script:NRGEmailFatalExitCode)     { exit $script:NRGEmailFatalExitCode }
if ($script:NRGEmailThresholdExitCode) { exit $script:NRGEmailThresholdExitCode }
if ($null -ne $script:NRGEmailSuccessExitCode) { exit $script:NRGEmailSuccessExitCode }
exit 0

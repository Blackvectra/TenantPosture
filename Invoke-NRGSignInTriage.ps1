#Requires -Version 7.0
#
# Invoke-NRGSignInTriage.ps1
# Admin-scope incident-response triage entry point. Pulls the tenant's
# sign-in logs, scores users for IoCs, and (optionally) deep-dives the
# top N suspicious users' mailboxes in the same admin session.
#
# NRG Technology Services / NextLayerSec LLC — nrgtechservices.com
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Workflow:
#   Phase 0 — Detection (this tool): admin signs in once, sign-in logs
#             triaged for failed→success clusters / anonymous-IP / impossible
#             travel / Identity Protection risky users, users ranked by
#             IoC score.
#   Phase 1 — Deep-dive (auto with -DeepDive): for each top-ranked user,
#             admin uses Mail.Read.All to pull mailbox data and run the
#             per-user Email-IR evaluators (Test-NRGEmailControl-*).
#   Phase 2 — Response: operator reviews the unified triage report and
#             takes containment + recovery action per finding.
#
# Use when: you SUSPECT compromise but don't yet know which users are
# affected. (Use Invoke-NRGEmailAssessment.ps1 when you ALREADY know
# which user — that's the user-credential per-user variant.)

[CmdletBinding()]
param(
    [string] $OutputPath,

    # Sign-in lookback window. Inbox window during deep-dive stays at 30 days
    # (the per-user collector's default — phish often predates outbound).
    [ValidateRange(1, 90)]
    [int] $WindowDays = 7,

    # Cap on raw sign-in events pulled from the audit log. Busy tenants can
    # blow past this on a long window — the IoC heuristics still work on
    # the most recent 5000 events.
    [ValidateRange(100, 25000)]
    [int] $MaxSignInEvents = 5000,

    # Triage only — skip the Mail.Read.All consent prompt and don't deep-dive
    # the top users' mailboxes. Useful when client BAA prohibits mailbox reads
    # by the assessment tool or when operator wants a quick triage pass.
    [switch] $SkipMailDive,

    # Auto-dive the top N users by IoC score. -DeepDive 5 = top 5; -DeepDive 0
    # = triage only (same as -SkipMailDive but still requests Mail.Read.All in
    # case the operator wants to dive interactively after). Default 5.
    [ValidateRange(0, 50)]
    [int] $DeepDive = 5,

    # Minimum IoC score required for a user to qualify for deep-dive. Caps
    # noise from low-confidence flags. Default 30.
    [ValidateRange(0, 500)]
    [int] $DeepDiveMinScore = 30,

    # Optional explicit tenant.
    [string] $TenantId,

    # Home-base geo for the out-of-state IoC (SIGNIN-1.6). When omitted, the
    # tool AUTO-DETECTS the home state + country as the modal (most-frequent)
    # location across successful sign-ins in the window — works across every
    # client with no config. Set these to override when the modal state is
    # wrong for a given tenant (e.g. -HomeState 'North Dakota' -HomeCountry 'US').
    [string] $HomeState,
    [string] $HomeCountry,

    # IP threat-intel enrichment of suspicious sign-in source IPs (RDAP
    # geolocation + ASN owner + Tor exit-node cross-check). Submits the
    # flagged IPs to public services (rdap.org, check.torproject.org) —
    # operator confirms client data-handling policy permits. On by default
    # for triage since identifying attacker infrastructure is the point;
    # pass -EnableThreatIntel:$false to skip the external calls.
    [bool] $EnableThreatIntel = $true,

    # Non-interactive mode skips the consent-disclosure pause.
    [switch] $NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:NRGSITriageFatalExitCode     = $null
$script:NRGSITriageSuccessExitCode   = $null
$script:NRGSITriageThresholdExitCode = $null

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
    $OutputPath = Join-Path $scriptDir (Join-Path 'output' 'IR-Triage')
}
$null = New-Item -ItemType Directory -Force -LiteralPath $OutputPath -ErrorAction SilentlyContinue
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$null = $resolvedOutput

Write-Host ''
Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ' NRG Sign-In Triage — Admin-Scope Incident Response'        -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Window                : $WindowDays day(s) of sign-ins"            -ForegroundColor White
Write-Host "  Max events pulled     : $MaxSignInEvents"                          -ForegroundColor White
Write-Host "  Output                : $OutputPath"                               -ForegroundColor White
if ($SkipMailDive) {
    Write-Host "  Mode                  : TRIAGE ONLY (-SkipMailDive)"           -ForegroundColor Yellow
} else {
    Write-Host "  Mode                  : Triage + deep-dive top $DeepDive (>= score $DeepDiveMinScore)" -ForegroundColor White
}
Write-Host ''

if (-not $NonInteractive) {
    Write-Host '  This tool will:' -ForegroundColor Yellow
    Write-Host '    1. Sign in as TENANT ADMIN (browser prompt).' -ForegroundColor Yellow
    Write-Host '    2. Request: AuditLog.Read.All, IdentityRiskyUser.Read.All,' -ForegroundColor Yellow
    Write-Host '       Directory.Read.All, User.Read.All' -ForegroundColor Yellow
    if (-not $SkipMailDive) {
        Write-Host '       + Mail.Read.All, MailboxSettings.Read.All (for the deep-dive).' -ForegroundColor Yellow
    }
    Write-Host '    3. Read sign-in logs, score users, rank by IoC.' -ForegroundColor Yellow
    if (-not $SkipMailDive -and $DeepDive -gt 0) {
        Write-Host "    4. For top $DeepDive flagged users (score >= $DeepDiveMinScore):" -ForegroundColor Yellow
        Write-Host '       read their mailbox + run Email-IR evaluators.' -ForegroundColor Yellow
    }
    Write-Host '    5. Produce a unified triage report (HTML + Markdown).' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '    NO writes to the tenant. Read-only Graph scopes only.' -ForegroundColor Green
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

if (Get-Command Clear-NRGState -ErrorAction SilentlyContinue) { Clear-NRGState }
if (Get-Command Clear-NRGSignInTriageState -ErrorAction SilentlyContinue) { Clear-NRGSignInTriageState }

$reportMetadata = [ordered]@{
    AssessmentDate    = (Get-Date -Format 'MMMM dd, yyyy HH:mm UTC')
    AssessmentMode    = 'SignInTriage'
    WindowDays        = $WindowDays
    MaxSignInEvents   = $MaxSignInEvents
    DeepDiveTop       = $DeepDive
    DeepDiveMinScore  = $DeepDiveMinScore
    SkipMailDive      = [bool]$SkipMailDive
    ThreatIntelEnabled = [bool]$EnableThreatIntel
    HomeState          = $HomeState
    HomeCountry        = $HomeCountry
    ToolVersion       = $script:NRGAssessmentVersion
    Brand             = $NRGBrand
}

# ── Connect ──────────────────────────────────────────────────────────────────
try {
    $ctx = Connect-NRGEmailAdminServices -TenantId $TenantId -SkipMailDive:$SkipMailDive
    $reportMetadata['ConnectedAdmin'] = $ctx.Account
    $reportMetadata['TenantId']       = $ctx.TenantId
} catch {
    Write-Host "  [!] Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

try {
    # ── Phase 0: Triage ──────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '[-] Phase 0 — Sign-in log triage...' -ForegroundColor Cyan

    try {
        Invoke-NRGEmailCollectSignIns -WindowDays $WindowDays -MaxEvents $MaxSignInEvents
        Write-Host '  [+] Sign-in events collected' -ForegroundColor Green
    } catch {
        Write-Warning "Sign-in collection failed: $($_.Exception.Message)"
    }

    # IP threat-intel enrichment runs BEFORE the rank aggregator so its
    # score bumps (successful sign-in from Tor/hosting/VPN infra) feed the
    # final ranking.
    $triageEvaluators = @(
        'Test-NRGSignInControl-FailedToSuccess'
        'Test-NRGSignInControl-AnonymousIp'
        'Test-NRGSignInControl-ImpossibleTravel'
        'Test-NRGSignInControl-RiskyUsers'
    )
    if ($EnableThreatIntel) { $triageEvaluators += 'Test-NRGSignInControl-IPIntel' }
    foreach ($fn in $triageEvaluators) {
        if (Get-Command $fn -ErrorAction SilentlyContinue) {
            try {
                & $fn
                Write-Host "  [+] $fn" -ForegroundColor Green
            } catch {
                Write-Warning "$fn failed: $($_.Exception.Message)"
            }
        }
    }

    # Geo-anomaly (out-of-home-state) runs with the operator's overrides — or
    # auto-detect when both omitted. Called explicitly because it takes
    # parameters. Runs before the rank aggregator so its score bumps count.
    if (Get-Command Test-NRGSignInControl-GeoAnomaly -ErrorAction SilentlyContinue) {
        try {
            Test-NRGSignInControl-GeoAnomaly -HomeState $HomeState -HomeCountry $HomeCountry
            Write-Host "  [+] Test-NRGSignInControl-GeoAnomaly" -ForegroundColor Green
        } catch {
            Write-Warning "Test-NRGSignInControl-GeoAnomaly failed: $($_.Exception.Message)"
        }
    }

    # Rank aggregator runs last so every score (incl. geo + IP-intel bumps) is in.
    if (Get-Command Test-NRGSignInControl-RankUsers -ErrorAction SilentlyContinue) {
        try {
            Test-NRGSignInControl-RankUsers
            Write-Host "  [+] Test-NRGSignInControl-RankUsers" -ForegroundColor Green
        } catch {
            Write-Warning "Test-NRGSignInControl-RankUsers failed: $($_.Exception.Message)"
        }
    }

    # ── Phase 1: Per-user deep-dives ─────────────────────────────────────────
    $rankedBag = Get-NRGRawData -Key 'IR-SignIn-Ranked'
    $rankedUsers = @()
    if ($rankedBag -and $rankedBag.Success -and $rankedBag.Data.Users) {
        $rankedUsers = @($rankedBag.Data.Users | Where-Object { $_.Score -ge $DeepDiveMinScore } | Select-Object -First $DeepDive)
    }

    if ($SkipMailDive -or $DeepDive -eq 0) {
        Write-Host ''
        Write-Host "[-] Phase 1 skipped (mode: triage only)" -ForegroundColor Yellow
        $reportMetadata['DeepDivedUsers'] = @()
    } elseif ($rankedUsers.Count -eq 0) {
        Write-Host ''
        Write-Host "[-] Phase 1 — no users met deep-dive threshold (score >= $DeepDiveMinScore)" -ForegroundColor Yellow
        $reportMetadata['DeepDivedUsers'] = @()
    } else {
        Write-Host ''
        Write-Host "[-] Phase 1 — deep-diving top $($rankedUsers.Count) user(s)..." -ForegroundColor Cyan
        $divedUsers = @()
        foreach ($u in $rankedUsers) {
            $upn = $u.UserPrincipalName
            Write-Host ''
            Write-Host "  >>> $upn (IoC score $($u.Score)): $($u.Reasons -join '; ')" -ForegroundColor Cyan
            # IMPORTANT: clear raw-data keys between users so each user's mailbox
            # data doesn't bleed into the next user's evaluation.
            foreach ($key in 'IR-MailboxProfile','IR-MailboxSentItems','IR-MailboxInbox','IR-MailboxRecoverable','IR-MailboxRules','IR-MailboxForwarding','IR-UserConsents','IR-UserAuthMethods') {
                Set-NRGRawData -Key $key -Data @{ CollectorId=$key; Success=$false; Data=$null }
            }
            try {
                Invoke-NRGEmailCollectMailbox -WindowDays $WindowDays -TargetUpn $upn
                # v4.12.1: OAuth consents + auth methods — the two persistence
                # surfaces a mailbox read can't see (illicit consent grants
                # survive password resets; attacker-added MFA methods survive
                # session revocation).
                try { Invoke-NRGEmailCollectUserSecurity -TargetUpn $upn } catch { Write-Warning "User-security collection for $upn failed: $($_.Exception.Message)" }
                foreach ($fn in @('Test-NRGEmailControl-InboxRules','Test-NRGEmailControl-Forwarding','Test-NRGEmailControl-OutboundActivity','Test-NRGEmailControl-PhishOrigin','Test-NRGEmailControl-OAuthConsents','Test-NRGEmailControl-AuthMethods')) {
                    try { & $fn } catch { Write-Warning "$fn for $upn failed: $($_.Exception.Message)" }
                }
                $divedUsers += $upn
                Write-Host "  [+] Deep-dive complete: $upn" -ForegroundColor Green
            } catch {
                Write-Warning "Deep-dive collection failed for ${upn}: $($_.Exception.Message)"
            }
        }
        $reportMetadata['DeepDivedUsers'] = $divedUsers
    }

    $findings = @(Get-NRGFindings)
    $rawData  = Get-NRGRawData -AllKeys

    # ── Publish ──────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '[-] Publishing triage report...' -ForegroundColor Cyan

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $jsonPath  = Join-Path $OutputPath "$timestamp-signin-triage.json"
    $htmlPath  = Join-Path $OutputPath "$timestamp-signin-triage.html"
    $mdPath    = Join-Path $OutputPath "$timestamp-signin-triage.md"

    $jsonPayload = [ordered]@{
        Metadata   = $reportMetadata
        Findings   = $findings
        RawData    = $rawData
        Exceptions = @(Get-NRGExceptions)
    } | ConvertTo-Json -Depth 10
    Set-NRGSensitiveFileContent -Path $jsonPath -Content $jsonPayload
    Write-Host "  [+] JSON:     $jsonPath" -ForegroundColor Green

    if (Get-Command Publish-NRGSignInTriageReport -ErrorAction SilentlyContinue) {
        try {
            Publish-NRGSignInTriageReport `
                -Metadata $reportMetadata `
                -Findings $findings `
                -RankedUsers $rankedUsers `
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
    Write-Host ' Triage Summary' -ForegroundColor Cyan
    Write-Host '════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host "  Findings           : $($findings.Count)"   -ForegroundColor White
    Write-Host "  Critical IoCs      : $($crits.Count)" -ForegroundColor $(if ($crits.Count -gt 0) {'Red'} else {'Green'})
    Write-Host "  High IoCs          : $($highs.Count)" -ForegroundColor $(if ($highs.Count -gt 0) {'Yellow'} else {'Green'})
    Write-Host "  Users deep-dived   : $(@($reportMetadata['DeepDivedUsers']).Count)" -ForegroundColor White
    Write-Host ''
    if ($crits.Count -gt 0) {
        Write-Host '  ╔══════════════════════════════════════════════════╗' -ForegroundColor Red
        Write-Host '  ║   CRITICAL IoCs found — likely compromise.       ║' -ForegroundColor Red
        Write-Host '  ║   Review the triage report and take action       ║' -ForegroundColor Red
        Write-Host '  ║   on each flagged user immediately.              ║' -ForegroundColor Red
        Write-Host '  ╚══════════════════════════════════════════════════╝' -ForegroundColor Red
        Write-Host ''
    }

    if ($findings.Count -eq 0) { $script:NRGSITriageSuccessExitCode = 2 }
    else { $script:NRGSITriageSuccessExitCode = 0 }
    if ($crits.Count -gt 0) { $script:NRGSITriageThresholdExitCode = 10 }
} catch {
    Write-Host "[!] Fatal error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    $script:NRGSITriageFatalExitCode = 4
} finally {
    try { Disconnect-NRGEmailAdminServices } catch { }
}

if ($script:NRGSITriageFatalExitCode)     { exit $script:NRGSITriageFatalExitCode }
if ($script:NRGSITriageThresholdExitCode) { exit $script:NRGSITriageThresholdExitCode }
if ($null -ne $script:NRGSITriageSuccessExitCode) { exit $script:NRGSITriageSuccessExitCode }
exit 0

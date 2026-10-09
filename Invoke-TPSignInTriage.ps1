#Requires -Version 7.0

<#
.SYNOPSIS
    Admin-scope sign-in triage — find likely-compromised users tenant-wide, then
    auto-deep-dive their mailboxes. The "who got popped?" tool.

.DESCRIPTION
    An incident-response triage entry point for when you SUSPECT compromise but
    don't yet know which user. The admin signs in once and the tool:

      Phase 0 (Detection): pulls the tenant sign-in logs and scores every user
        for indicators of compromise — failed->success bursts, anonymous-IP /
        Tor sign-ins, impossible travel, Entra Identity Protection risky users,
        and out-of-(home)-state logins — then ranks users by IoC score.
      Phase 1 (Deep-dive): for each top-ranked user, uses Mail.Read.All to pull
        the mailbox and run the per-user Email-IR checks (inbox rules,
        forwarding, outbound, phish origin). Skip with -SkipMailDive.
      Phase 2 (Response): produces one unified triage report to drive
        containment and recovery per finding.

    When you ALREADY know which mailbox is suspect, use the per-user variant
    Invoke-TPEmailAssessment.ps1 (which needs no admin scope). To sweep every
    GDAP client at once, use Invoke-TPBatchSignInTriage.ps1.

.PARAMETER OutputPath
    Output directory. Defaults to .\output\IR-Triage\.

.PARAMETER WindowDays
    Sign-in lookback window, in days (1-90, default 7). The inbox window during
    a deep-dive stays at 30 days (phish often predates outbound IoCs).

.PARAMETER MaxSignInEvents
    Cap on raw sign-in events pulled from the audit log (100-25000, default
    5000). The IoC heuristics still work on the most recent events.

.PARAMETER SkipMailDive
    Triage only — never request Mail.Read.All and never read a mailbox. Use when
    a client BAA prohibits mailbox reads or you just want a fast ranking pass.

.PARAMETER DeepDive
    Auto-dive the top N users by IoC score (0-50, default 5; 0 = triage only but
    still request Mail.Read.All so you can dive interactively afterwards).

.PARAMETER DeepDiveMinScore
    Minimum IoC score a user must reach to qualify for a deep-dive (0-500,
    default 30). Caps noise from low-confidence flags.

.PARAMETER TenantId
    Optional explicit tenant GUID (guards against a stale browser session for a
    different tenant).

.PARAMETER HomeState
    Home state/region for the out-of-state IoC. Omit to AUTO-DETECT it as the
    modal (most-frequent) location across successful sign-ins in the window.

.PARAMETER HomeCountry
    Home country for the out-of-state IoC. Omit to auto-detect (as with -HomeState).

.PARAMETER EnableThreatIntel
    IP threat-intel enrichment of suspicious source IPs (RDAP geolocation/ASN +
    Tor exit list). On by default; pass -EnableThreatIntel:$false to skip the
    external calls.

.PARAMETER NonInteractive
    Skip the consent-disclosure pause so the script runs unattended.

.EXAMPLE
    .\Invoke-TPSignInTriage.ps1

    Full triage: rank all users, then deep-dive the top 5 scoring at least 30.

.EXAMPLE
    .\Invoke-TPSignInTriage.ps1 -SkipMailDive

    Rank users only — no mailbox is read (e.g. a BAA restriction). Fast pass.

.EXAMPLE
    .\Invoke-TPSignInTriage.ps1 -DeepDive 10 -WindowDays 14 -HomeState 'North Dakota' -HomeCountry 'US'

    Widen the window to 14 days, deep-dive the top 10, and pin the home location
    for the out-of-state IoC instead of auto-detecting it.

.OUTPUTS
    .\output\IR-Triage\<timestamp>-signin-triage.html  unified triage report
    plus the per-user Email-IR reports for each deep-dived mailbox.

.NOTES
    NRG Technology Services / NextLayerSec LLC — nrgtechservices.com
    Read-only: all Graph and Exchange calls are GET/read-only.
    Required scopes: AuditLog.Read.All, IdentityRiskyUser.Read.All, and
    Mail.Read.All (only when a deep-dive runs).
    Exit codes: 0 clean | 1 auth failure | 2 no findings | 10 critical IoC found.
#>

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
    # geolocation + ASN owner). Submits the flagged IPs to rdap.org —
    # operator confirms client data-handling policy permits. On by default
    # for triage since identifying attacker infrastructure is the point;
    # pass -EnableThreatIntel:$false to skip the external calls.
    [bool] $EnableThreatIntel = $true,

    # Non-interactive mode skips the consent-disclosure pause.
    [switch] $NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TPSITriageFatalExitCode     = $null
$script:TPSITriageSuccessExitCode   = $null
$script:TPSITriageThresholdExitCode = $null

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
$null = [System.IO.Directory]::CreateDirectory($OutputPath)
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
$manifestPath = Join-Path $scriptDir 'TenantPosture.psd1'
Write-Host '[-] Loading TenantPosture module...' -ForegroundColor Cyan
try {
    Import-Module $manifestPath -Force -ErrorAction Stop
    Write-Host '  [+] Module loaded' -ForegroundColor Green
} catch {
    Write-Host "  [!] Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if (Get-Command Clear-TPState -ErrorAction SilentlyContinue) { Clear-TPState }
if (Get-Command Clear-TPSignInTriageState -ErrorAction SilentlyContinue) { Clear-TPSignInTriageState }

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
    ToolVersion       = $(if (Get-Variable -Name TPAssessmentVersion -ErrorAction SilentlyContinue) { [string]$TPAssessmentVersion } else { 'unknown' })
    Brand             = $TPBrand
}

# ── Connect ──────────────────────────────────────────────────────────────────
try {
    $ctx = Connect-TPEmailAdminServices -TenantId $TenantId -SkipMailDive:$SkipMailDive
    $reportMetadata['ConnectedAdmin'] = $ctx.Account
    $reportMetadata['TenantId']       = $ctx.TenantId
} catch {
    Write-Host "  [!] Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    # The first line is often all a credential error carries; the cause (a closed or hidden
    # sign-in window, a consent or Conditional Access refusal) sits in the inner exceptions.
    $inner = $_.Exception.InnerException
    while ($inner) {
        if ($inner.Message) { Write-Host ("      caused by: {0}" -f (($inner.Message -split "`r?`n")[0])) -ForegroundColor Red }
        $inner = $inner.InnerException
    }
    Write-Host '      If the window never appeared or closed, retry in a NEW PowerShell 7 window; the sign-in window can open behind other windows.' -ForegroundColor Yellow
    exit 1
}

try {
    # ── Phase 0: Triage ──────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '[-] Phase 0 — Sign-in log triage...' -ForegroundColor Cyan

    try {
        Invoke-TPEmailCollectSignIns -WindowDays $WindowDays -MaxEvents $MaxSignInEvents
        Write-Host '  [+] Sign-in events collected' -ForegroundColor Green
    } catch {
        Write-Warning "Sign-in collection failed: $($_.Exception.Message)"
    }

    # IP threat-intel enrichment runs BEFORE the rank aggregator so its
    # score bumps (successful sign-in from Tor/hosting/VPN infra) feed the
    # final ranking.
    $triageEvaluators = @(
        'Test-TPSignInControlFailedToSuccess'
        'Test-TPSignInControlAnonymousIp'
        'Test-TPSignInControlImpossibleTravel'
        'Test-TPSignInControlRiskyUsers'
    )
    if ($EnableThreatIntel) { $triageEvaluators += 'Test-TPSignInControlIPIntel' }
    # A detector that throws or is missing produced no verdict. It is recorded
    # as an assessment-health gap, never only a warning, so a missing detector
    # cannot look like a clean result.
    $evaluatorFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($fn in $triageEvaluators) {
        if (Get-Command $fn -ErrorAction SilentlyContinue) {
            try {
                & $fn
                Write-Host "  [+] $fn" -ForegroundColor Green
            } catch {
                Write-Warning "$fn failed: $($_.Exception.Message)"
                $evaluatorFailures.Add("$fn did not finish: $($_.Exception.Message)")
            }
        } else {
            $evaluatorFailures.Add("$fn was not available to run")
        }
    }

    # Geo-anomaly (out-of-home-state) runs with the operator's overrides — or
    # auto-detect when both omitted. Called explicitly because it takes
    # parameters. Runs before the rank aggregator so its score bumps count.
    if (Get-Command Test-TPSignInControlGeoAnomaly -ErrorAction SilentlyContinue) {
        try {
            Test-TPSignInControlGeoAnomaly -HomeState $HomeState -HomeCountry $HomeCountry
            Write-Host "  [+] Test-TPSignInControlGeoAnomaly" -ForegroundColor Green
        } catch {
            Write-Warning "Test-TPSignInControlGeoAnomaly failed: $($_.Exception.Message)"
            $evaluatorFailures.Add("Test-TPSignInControlGeoAnomaly did not finish: $($_.Exception.Message)")
        }
    }

    # Rank aggregator runs last so every score (incl. geo + IP-intel bumps) is in.
    if (Get-Command Test-TPSignInControlRankUsers -ErrorAction SilentlyContinue) {
        try {
            Test-TPSignInControlRankUsers
            Write-Host "  [+] Test-TPSignInControlRankUsers" -ForegroundColor Green
        } catch {
            Write-Warning "Test-TPSignInControlRankUsers failed: $($_.Exception.Message)"
            $evaluatorFailures.Add("Test-TPSignInControlRankUsers did not finish: $($_.Exception.Message)")
        }
    }

    # ── Phase 1: Per-user deep-dives ─────────────────────────────────────────
    $rankedBag = Get-TPRawData -Key 'IR-SignIn-Ranked'
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
        # One record per flagged user: the evidence that user's findings rest on
        # is kept HERE, because each dive overwrites the shared raw-data keys.
        $deepDives = [System.Collections.Generic.List[object]]::new()
        $deepDiveKeys = @('IR-MailboxProfile','IR-MailboxSentItems','IR-MailboxInbox','IR-MailboxRecoverable','IR-MailboxRules','IR-MailboxForwarding','IR-UserConsents','IR-UserAuthMethods')
        foreach ($u in $rankedUsers) {
            $upn = $u.UserPrincipalName
            $findingsBefore = @(Get-TPFindings).Count
            Write-Host ''
            Write-Host "  >>> $upn (IoC score $($u.Score)): $($u.Reasons -join '; ')" -ForegroundColor Cyan
            # IMPORTANT: clear raw-data keys between users so each user's mailbox
            # data doesn't bleed into the next user's evaluation.
            foreach ($key in $deepDiveKeys) {
                Set-TPRawData -Key $key -Data @{ CollectorId=$key; Success=$false; Data=$null }
            }
            # Steps of THIS dive that did not finish. A detector that threw produced
            # no verdict for this user, so the dive is Incomplete, not clean.
            $diveFailures = [System.Collections.Generic.List[string]]::new()
            try {
                Invoke-TPEmailCollectMailbox -WindowDays $WindowDays -TargetUpn $upn
                # v4.12.1: OAuth consents + auth methods — the two persistence
                # surfaces a mailbox read can't see (illicit consent grants
                # survive password resets; attacker-added MFA methods survive
                # session revocation).
                try { Invoke-TPEmailCollectUserSecurity -TargetUpn $upn } catch { Write-Warning "User-security collection for $upn failed: $($_.Exception.Message)"; $diveFailures.Add("user-security collection did not finish: $($_.Exception.Message)") }
                foreach ($fn in @('Test-TPEmailControlInboxRules','Test-TPEmailControlForwarding','Test-TPEmailControlOutboundActivity','Test-TPEmailControlPhishOrigin','Test-TPEmailControlOAuthConsents','Test-TPEmailControlAuthMethods')) {
                    try { & $fn } catch { Write-Warning "$fn for $upn failed: $($_.Exception.Message)"; $diveFailures.Add("$fn did not finish: $($_.Exception.Message)") }
                }
                # Say whose these findings are and what they rest on, BEFORE the
                # next user's dive replaces the raw data.
                $evidence = Get-TPDeepDiveEvidence
                $null = Set-TPFindingSubject -Since $findingsBefore -Subject $upn -Evidence $evidence
                $snapshot = [ordered]@{}
                foreach ($key in $deepDiveKeys) { $snapshot[$key] = Get-TPRawData -Key $key }
                $deepDives.Add([ordered]@{ UserPrincipalName = $upn; Score = $u.Score; Reasons = @($u.Reasons); Status = $(if ($evidence.Complete -and $diveFailures.Count -eq 0) { 'Completed' } else { 'Incomplete' }); Failures = @($diveFailures); Evidence = $evidence; RawData = $snapshot })
                $divedUsers += $upn
                # The same combined health decision as the recorded Status: a dive whose
                # evidence was read but whose detectors did not finish is not complete.
                $diveOk = ($evidence.Complete -and $diveFailures.Count -eq 0)
                $diveWhy = @(@($evidence.RequiredMissing | ForEach-Object { "missing $_" }) + @($evidence.RequiredPartial | ForEach-Object { "partial $_" }) + @($evidence.OptionalTruncated | ForEach-Object { "partial $_" }) + @($diveFailures))
                Write-Host "  [+] Deep-dive $(if ($diveOk) { 'complete' } else { "incomplete ($($diveWhy -join '; '))" }): $upn" -ForegroundColor $(if ($diveOk) { 'Green' } else { 'Yellow' })
            } catch {
                Write-Warning "Deep-dive collection failed for ${upn}: $($_.Exception.Message)"
                $deepDives.Add([ordered]@{ UserPrincipalName = $upn; Score = $u.Score; Reasons = @($u.Reasons); Status = 'Failed'; Error = $_.Exception.Message; Evidence = $null; RawData = $null })
            }
        }
        $reportMetadata['DeepDivedUsers'] = $divedUsers
        $reportMetadata['DeepDives'] = @($deepDives | ForEach-Object { [ordered]@{ UserPrincipalName = $_.UserPrincipalName; Status = $_.Status } })
    }

    $findings = @(Get-TPFindings)
    $rawData  = Get-TPRawData
    $rawDataOut = [ordered]@{}
    foreach ($k in @($rawData.Keys)) { if ($k -notmatch '^IR-(Mailbox|User)') { $rawDataOut[$k] = $rawData[$k] } }
    # What the verdict may claim depends on what was actually read.
    $comp = Get-TPSignInCollectionCompleteness
    $ddGaps = @()
    if ((Get-Variable -Name deepDives -ErrorAction SilentlyContinue) -and $deepDives) {
        $ddGaps = @($deepDives | Where-Object { $_.Status -ne 'Completed' } | ForEach-Object {
            $fl = @(Get-TPObjectField -Item $_ -Key 'Failures' -Default @())
            "deep-dive for $($_.UserPrincipalName) was $($_.Status.ToLowerInvariant())$(if ($fl.Count -gt 0) { ': ' + ($fl -join '; ') })" })
    }
    $evalGaps = @(if ((Get-Variable -Name evaluatorFailures -ErrorAction SilentlyContinue) -and $evaluatorFailures) { $evaluatorFailures })
    $reportMetadata['CollectionComplete'] = ([bool]$comp.Complete -and $ddGaps.Count -eq 0 -and $evalGaps.Count -eq 0)
    $reportMetadata['CollectionGaps']     = @(@($comp.Reasons) + $ddGaps + $evalGaps)
    $reportMetadata['EvaluatorFailures']  = @($evalGaps)
    $reportMetadata['EventsRead']         = [int]$comp.EventsRead

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
        # Per-mailbox keys are kept per user under DeepDives; left in RawData they
        # would hold only the LAST user's mailbox and read as nobody's.
        RawData    = $rawDataOut
        DeepDives  = @($(if ((Get-Variable -Name deepDives -ErrorAction SilentlyContinue) -and $deepDives) { $deepDives } else { @() }))
        Exceptions = @(Get-TPExceptions)
    } | ConvertTo-Json -Depth 10
    Set-TPSensitiveFileContent -Path $jsonPath -Content $jsonPayload
    Write-Host "  [+] JSON:     $jsonPath" -ForegroundColor Green

    if (Get-Command Publish-TPSignInTriageReport -ErrorAction SilentlyContinue) {
        try {
            Publish-TPSignInTriageReport `
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
    if (-not $reportMetadata['CollectionComplete']) {
        Write-Host '  NOT CLEARED: part of the evidence could not be read or checked:' -ForegroundColor Yellow
        foreach ($g in @($reportMetadata['CollectionGaps'])) { Write-Host "    - $g" -ForegroundColor Yellow }
    }
    Write-Host ''
    if ($crits.Count -gt 0) {
        Write-Host '  ╔══════════════════════════════════════════════════╗' -ForegroundColor Red
        Write-Host '  ║   CRITICAL indicators found — investigate.       ║' -ForegroundColor Red
        Write-Host '  ║   Review the triage report and take action       ║' -ForegroundColor Red
        Write-Host '  ║   on each flagged user immediately.              ║' -ForegroundColor Red
        Write-Host '  ╚══════════════════════════════════════════════════╝' -ForegroundColor Red
        Write-Host ''
    }

    # Exit-code precedence (highest first): 4 fatal error, 10 Critical indicator,
    # 3 evidence incomplete or a required check did not finish, 2 no findings,
    # 0 complete. Incomplete outranks "no findings": a run whose detectors failed
    # has no findings because nothing evaluated, not because nothing was wrong.
    # A Critical still exits 10, and the report and console say NOT CLEARED too.
    if (-not $reportMetadata['CollectionComplete']) { $script:TPSITriageSuccessExitCode = 3 }
    elseif ($findings.Count -eq 0) { $script:TPSITriageSuccessExitCode = 2 }
    else { $script:TPSITriageSuccessExitCode = 0 }
    if ($crits.Count -gt 0) { $script:TPSITriageThresholdExitCode = 10 }
} catch {
    Write-Host "[!] Fatal error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    $script:TPSITriageFatalExitCode = 4
} finally {
    try { Disconnect-TPEmailAdminServices } catch { }
}

if ($script:TPSITriageFatalExitCode)     { exit $script:TPSITriageFatalExitCode }
if ($script:TPSITriageThresholdExitCode) { exit $script:TPSITriageThresholdExitCode }
if ($null -ne $script:TPSITriageSuccessExitCode) { exit $script:TPSITriageSuccessExitCode }
exit 0

#Requires -Version 7.0
#
# Invoke-NRGAssessment.ps1
# Entry point for NRG-Assessment (version read from module manifest at runtime)
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# Flow:
#   1. Import module (loads Lib, Collectors, Evaluators, Publishers)
#   2. Connect to M365 services
#   3. Run collectors -> raw data stored in module state
#   4. Run evaluators -> findings registered via Add-NRGFinding
#   5. Run publishers -> HTML, Markdown, JSON, XLSX, Playbook, Remediation script
#
# Usage:
#   .\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com
#   .\Invoke-NRGAssessment.ps1 -AppId <guid> -TenantId <guid> -CertificateThumbprint <40hex> -OrganizationDomain contoso.onmicrosoft.com
#

[CmdletBinding()]
param(
    # OWASP ASVS V5.1.3 — UPN must match standard email format before reaching auth
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$|^$')]
    [string] $UserPrincipalName,
    [string] $OutputPath,

    # App-only / certificate authentication for unattended runs. ValidatePattern
    # at the entry point per OWASP ASVS V5.1.3 — defense-in-depth even though
    # Connect-NRGServices re-validates. Catches malformed input (newlines, null
    # bytes, command-injection metachars) before any logging or downstream use.
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $AppId,

    [ValidatePattern('^$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $TenantId,

    [ValidatePattern('^$|^[0-9a-fA-F]{40}$')]
    [string] $CertificateThumbprint,

    [ValidatePattern('^$|^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')]
    [string] $OrganizationDomain,

    # One-time tenant onboarding: register a read-only enterprise app + cert in
    # the customer tenant so future scans run app-only (no device codes, no
    # Conditional-Access flow blocks). Requires an operator who can create app
    # registrations; you'll be connected interactively with write scopes first.
    [switch] $RegisterApp,

    # Auto-grant admin consent during -RegisterApp (operator must be Global
    # Administrator). Omit to instead receive a consent URL for a Global Admin.
    [switch] $GrantConsent,

    # Convenience: look up a previously-onboarded tenant's ClientId + cert
    # thumbprint from Config/clients.json by domain, so unattended scans don't
    # need the GUIDs pasted every time. Also the target for -RegisterApp.
    [ValidatePattern('^$|^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
    [string] $TenantDomain,

    # The client's endpoint protection is a third-party EDR (e.g. 'Cortex XDR'),
    # not Microsoft Defender. The Defender endpoint checks (INT-1.5, INT-2.1,
    # INT-2.2, DEV-2.x) are then reported as covered by that product —
    # declared, not verified — and excluded from the score instead of scoring
    # as gaps. Also read from the client's ThirdPartyEDR field in
    # Config/clients.json when -TenantDomain is given.
    [ValidatePattern('^$|^[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}$')]
    [string] $ThirdPartyEDR,

    # The NRG monitoring address(es) alert policies should notify (an address,
    # or @domain for a whole domain). DEF-3.4 and EXO-3.3 compare each enabled
    # policy's recipients with this list; without one, "alerts reach NRG" is
    # not assessed (the recipients-exist half still is). Also read from the
    # client's MonitoringAddresses in Config/clients.json, then from
    # MonitoringAddresses in Config/branding.psd1.
    [string[]] $MonitoringAddress,

    # Cloud environment
    [ValidateSet('commercial','gcc','gcchigh','dod')]
    [string] $Environment = 'commercial',

    # Skip switches
    # Purview (Security & Compliance) is assessed by default; -SkipPurview
    # leaves it out and its controls report "not assessed". -IncludePurview
    # is the old opt-in switch, kept so existing commands still run; it no
    # longer changes anything.
    [switch] $SkipPurview,
    [switch] $IncludePurview,
    # Read the SharePoint tenant settings Graph does not expose (SPO-1.2, 1.4,
    # 1.5, 2.2, 2.6, 2.7, 3.2, 3.3, 3.4) through the SharePoint Online
    # Management Shell. In PowerShell 7 that module runs in a Windows
    # PowerShell CHILD PROCESS (Microsoft's documented -UseWindowsPowerShell),
    # which an Attack Surface Reduction rule blocking process creation will
    # stop; off by default, and a blocked start leaves those controls not
    # assessed with the reason logged. One extra sign-in.
    [switch] $IncludeSharePointShell,
    [switch] $SkipTeams,
    [switch] $SkipSharePoint,
    [switch] $SkipIntune,
    [switch] $SkipPowerPlatform,
    [switch] $SkipDNS,

    # Run modes
    [switch] $NonInteractive,
    # Audit fix (v4.6.x MED #6): validate that FromResults / BaselineResults
    # point at an existing file via -LiteralPath. This refuses wildcard input
    # ('*'), path-traversal sequences, and silently-missing files before any
    # downstream Get-Content / republish step touches the path.
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in FromResults." }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "FromResults file not found: $_" }
        return $true
    })]
    [string] $FromResults,
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in BaselineResults." }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "BaselineResults file not found: $_" }
        return $true
    })]
    [string] $BaselineResults,

    # Independent comparison: a ScubaGear ScubaResults.csv. The report site places each
    # mapped result beside the NRG control as a separate standard, never as a score.
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in ScubaResultsPath." }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "ScubaResultsPath file not found: $_" }
        return $true
    })]
    [string] $ScubaResultsPath,
    # The multi-page report site is written with every run that writes reports.
    # This switch turns that off.
    [switch] $SkipReportSite,

    # ── Monthly compliance report (v4.11.0) ─────────────────────────────────
    # When -MonthlyReport is set, Publish-NRGMonthlyReport emits a recurring
    # MSP deliverable (HTML + JSON state file) modeled on the user-supplied
    # template. Work-Completed / In-Progress / Queued state comes from
    # -MonthlyDeltaPath (operator-maintained .psd1, one per tenant per month).
    # -MonthlyPriorPath is the prior period's <name>.json output and drives
    # the trend note in the snapshot. Omit on first (baseline) report.
    # See Config/monthly-delta/EXAMPLE-example.com-2026-05.psd1
    # for the delta-file shape.
    [switch] $MonthlyReport,
    [ValidateScript({
        if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in MonthlyDeltaPath." }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Monthly delta file not found: $_" }
        return $true
    })]
    [string] $MonthlyDeltaPath,
    [ValidateScript({
        if ($null -eq $_ -or '' -eq $_) { return $true }
        if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in MonthlyPriorPath." }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Monthly prior-period file not found: $_" }
        return $true
    })]
    [string] $MonthlyPriorPath,
    # OWASP ASVS V5.1.3 — every DnsDomains entry must be an FQDN before DNS resolver sees it
    [ValidateScript({
        foreach ($d in $_) {
            if ($d -notmatch '^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$') {
                throw "Invalid DNS domain name: '$d'"
            }
        }
        return $true
    })]
    [string[]] $DnsDomains,
    [switch] $JsonOnly,

    # ── Output profile ───────────────────────────────────────────────────────
    # Default (neither switch): the CONSOLIDATED profile — just two files, the
    # self-contained interactive report (<name>-assessment.html, which embeds
    # the remediation script + findings CSV as in-report downloads) and the
    # machine/evidence record (<name>-results.json). This ends the old ~9-file
    # sprawl per run.
    # -AllFiles restores every sidecar deliverable as its own file (Markdown
    # summary, engineer playbook + executive summary, playbook HTML, standalone
    # remediation .ps1, XLSX matrix, delta). Batch mode passes this for parity.
    # -JsonOnly emits only the JSON (unchanged).
    [switch] $AllFiles,

    # Folder of endpoint results written by Device\Invoke-NRGDeviceCompliance.ps1
    # and collected by RMM. Supplying it adds the DEV-* endpoint controls to the
    # same report and the same NIST matrix. Omit it and every DEV control
    # reports NotApplicable with a prompt — never absent, so a forgotten
    # collection is visible rather than silently halving the assessment.
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        if (-not (Test-Path -LiteralPath $_)) { throw "Device results path not found: $_" }
        return $true
    })]
    [string] $DeviceResults,

    # Which framework(s) the REPORT presents. NRG assesses against NIST
    # SP 800-53 Rev 5, so that is the default here. This narrows the report,
    # never the assessment: every control still carries its CIS, SCuBA, CMMC,
    # ISO 27001, SOC 2, HIPAA, PCI DSS and MITRE citations, every framework is
    # still scored, and the results JSON and XLSX matrix are unchanged. Pass
    # -Framework All for the multi-framework report, or name one explicitly.
    [ValidateSet('NIST','CIS','SCuBA','CMMC','All')]
    [string] $Framework = 'NIST',

    # The NRG Security Baseline tier this client is held to
    # (Config/nrg-baseline.json). Tiers are cumulative: Standard requires
    # Minimum + Standard, Hardened all three. Read from the client's
    # BaselineTier in Config/clients.json when -TenantDomain is given, and
    # from the prior run's metadata on -FromResults; Standard otherwise. A
    # VIEW over the findings: it changes no verdict and no framework score.
    [ValidateSet('', 'Minimum', 'Standard', 'Hardened')]
    [string] $BaselineTier = '',

    # Standalone NIST SP 800-53 Rev 5 matrix (Markdown + XLSX), for clients
    # assessed against 800-53 who should not have to read their posture out of
    # a multi-framework report. Purely additive — every other framework the tool
    # cites is untouched, and this emits one extra document from the same run.
    # Implied by -AllFiles.
    [switch] $NISTMatrix,

    # System Security Plan against NIST SP 800-171 Rev 2 — the CMMC Level 2
    # baseline. All 110 requirements as a worked checklist: is it in place, what
    # proves it, how to close it, and what closing it will do to the business.
    # 41 requirements are evidenced from the tenant and endpoints; the other 69
    # are answered by the client in Config/ssp/<client>.psd1 and render as open
    # questions until they are. Markdown + HTML + XLSX. Implied by -AllFiles.
    [switch] $SSP,

    # Explicit path to the SSP answers file. Without it, -SSP looks for
    # Config/ssp/<tenant-domain>.psd1 and renders the plan with every narrative
    # blank if there is none — which is a truthful "not answered yet", not a
    # failure.
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed in -SSPAnswers.' }
        if (-not (Test-Path -LiteralPath $_)) { throw "SSP answers file not found: $_" }
        return $true
    })]
    [string] $SSPAnswers,

    # Fillable client questionnaire (Markdown + HTML + best-effort PDF) for
    # the SSP requirements this run could not evidence itself. NOT implied by
    # -AllFiles: it is a document meant to go OUT to a client and be filled
    # in and returned, not a routine run artifact regenerated on every
    # assessment. See Import-NRGSSPQuestionnaire.ps1 for the return half.
    [switch] $SSPQuestionnaire,

    # Restrict the questionnaire to one 800-171 family (e.g. '3.9' for
    # Personnel Security), so it can go to the person who actually owns that
    # domain instead of everyone getting all 110 requirements at once.
    [ValidateNotNullOrEmpty()]
    [string] $SSPQuestionnaireFamily,

    # Fillable client questionnaire for the controls.json controls this run
    # could not evaluate on its own — Get-NRGAssessmentScope's
    # NoProgrammaticCheck (no automated test exists, or the check could not
    # reach a verdict) and CollectionIncomplete (data did not collect this
    # run) buckets. The controls.json counterpart
    # to -SSPQuestionnaire; a separate document because a controls.json
    # ControlId and a NIST 800-171 requirement id are different catalogs.
    # NOT implied by -AllFiles, for the same reason -SSPQuestionnaire isn't.
    # See Import-NRGManualReviewQuestionnaire.ps1 for the return half.
    [switch] $ManualReviewQuestionnaire,

    # Restrict the manual-review questionnaire to one workload (e.g. 'SPO'),
    # so it can go to the person who actually owns that workload instead of
    # everyone getting every unassessed control across the tenant.
    [ValidateNotNullOrEmpty()]
    [string] $ManualReviewWorkload,

    # The NIST 800-53 Rev 5 improvement plan — what to do next, in what order,
    # and what it will cost. Ordered steps with the exact projected coverage
    # after each, the families each one moves, and what the change will break.
    # Single-framework by design: it names NIST and nothing else, because a
    # plan that hedges across four frameworks orders its steps for none of
    # them. Implied by -AllFiles.
    [switch] $ImprovementPlan,

    [switch] $WhatIfConnections,

    # GDAP batch mode establishes ONE Graph/EXO/Teams/IPPS session meant to be
    # reused across every client in Config/clients.json (see
    # Connect-NRGServices.ps1's reuseGraphContext / reuseExoSession logic).
    # This orchestrator's own finally block otherwise always calls
    # Disconnect-NRGServices, tearing the shared session down after EVERY
    # client — the next client's Connect-MgGraph then has to reconnect with
    # no -TenantId and can silently land back in the operator's home tenant.
    # Pass -KeepSession to skip the disconnect and leave the shared session
    # intact for the next client. Invoke-NRGBatchAssessment.ps1 passes it on
    # every client and disconnects the per-client Exchange, Security &
    # Compliance and Teams sessions itself; it closes Graph after the loop.
    [switch] $KeepSession,

    # Launch the local web GUI instead of running a scan in the terminal.
    # The GUI is a local Pode-backed server (loopback only, never exposed
    # to the network) that lets the operator pick a tenant, trigger scans,
    # watch progress, and view reports in a browser. See Lib/Start-NRGWebServer.ps1
    # and Web/. No tenant data leaves the workstation.
    [switch] $Web,

    # Port for the -Web GUI loopback server. Default avoids common collisions.
    [ValidateRange(1024, 65535)]
    [int] $WebPort = 8765,

    # ── Quick scan mode ──────────────────────────────────────────────────────
    # Only evaluate Critical + High controls. Skips Medium / Low / Informational
    # evaluators entirely. Designed for live demos and sanity checks; finishes
    # in under a minute on most tenants instead of ~10 min for the full sweep.
    [switch] $Quick,

    # ── Automation-friendly threshold exit codes ────────────────────────────
    # Non-zero exit on failure threshold. Default 0 = disabled (preserves the
    # existing exit-code spec). When any of these fires, the run still produces
    # all artifacts; the non-zero exit is purely a signal for cron / Task
    # Scheduler / CI integrations to take action (email IT, file a ticket).
    #   10 = critical-gap threshold breached
    #   11 = high-gap threshold breached
    #   12 = score below threshold
    [ValidateRange(0, 999)]
    [int] $FailOnCritical = 0,

    [ValidateRange(0, 999)]
    [int] $FailOnHigh     = 0,

    [ValidateRange(0, 100)]
    [int] $FailOnScoreBelow = 0
)

# OWASP ASVS V16.4.1 — strict mode at the entry point so the orchestrator
# uses the same semantics as the module body (uninitialized variable access,
# property access on $null, indexing past array end all throw).
Set-StrictMode -Version Latest

# v4.6.4 CRITICAL FIX: pre-initialize exit-code vars so StrictMode reads at end
# (lines 570 + 586) never throw VariableIsUndefined on the success path. Without
# this every successful run crashes with a stack trace AFTER the report is
# written but BEFORE `exit 0` lands → callers see exit code 1.
$script:NRGFatalExitCode     = $null
$script:NRGSuccessExitCode   = $null
$script:NRGThresholdExitCode = $null

# OWASP ASVS V11.2.2 / OSSTMM DN5 — enforce TLS 1.2 minimum (Microsoft endpoints
# already require this, but defense-in-depth catches dev/test environments where
# .NET defaults might drift back to older protocols)
[System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.SecurityProtocolType]::Tls12 -bor
    [System.Net.SecurityProtocolType]::Tls13

# Disable WAM broker before any module loads — prevents RuntimeBroker NullReferenceException
$env:MSAL_ALLOW_BROKER        = '0'
$env:MSAL_DISABLE_TOKENBROKER = '1'
$env:MSAL_DISABLE_WAM         = '1'

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ── Pre-banner version probe ─────────────────────────────────────────────────
# Read ModuleVersion from the manifest BEFORE the module is imported so the
# banner version stays in lockstep with the .psd1 / .psm1 single source of
# truth. Falls back to 'unknown' if the manifest can't be parsed — the import
# step below will then fail loudly and exit anyway.
$script:NRGAssessmentVersion = 'unknown'
try {
    $manifestData = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptDir 'NRG-Assessment.psd1') -ErrorAction Stop
    if ($manifestData.ModuleVersion) { $script:NRGAssessmentVersion = [string]$manifestData.ModuleVersion }
} catch { }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " NRG-Assessment v$($script:NRGAssessmentVersion) — Read-Only M365 Security Assessment" -ForegroundColor Cyan
Write-Host " NRG Technology Services | NextLayerSec LLC"                     -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ── Output path ───────────────────────────────────────────────────────────────
# OWASP A01 / ASVS V12.3.1 — reject ..[/\\] path-traversal sequences before any
# file operation. Also ensure the resolved path stays under the script directory
# unless an absolute path was explicitly provided by the operator.
if (-not $OutputPath) { $OutputPath = Join-Path $scriptDir 'output' }
if ($OutputPath -match '\.\.[\\/]') {
    throw "OutputPath rejected: contains '..[/\\]' traversal sequence."
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    [void][System.IO.Directory]::CreateDirectory($OutputPath)
}
# Resolve to absolute path. $resolvedOutput is intentionally retained as the
# forward-declaration anchor for the security invariant in
# Testing/NRG.Security.Tests.ps1:106-110, which enforces that any future
# auto-open / publish path-bounds check MUST take the form
# $path.StartsWith($resolvedOutput). v4.11.1 first tried to remove this as
# dead code; the security test caught that the variable IS a documented test
# anchor, not dead. Leaving the GetFullPath call (validates path format —
# throws on invalid syntax) and the variable for the test to match.
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
# Suppression: PSScriptAnalyzer flags this as unused. Documented above —
# it's a security-test anchor, not dead code. Remove when an actual
# StartsWith bounds check on $resolvedOutput exists at a use site.
$null = $resolvedOutput

# ── Import module ─────────────────────────────────────────────────────────────
Write-Host "[-] Loading NRG-Assessment module..." -ForegroundColor Cyan
$manifestPath = Join-Path $scriptDir 'NRG-Assessment.psd1'
try {
    Import-Module $manifestPath -Force -ErrorAction Stop
    Write-Host "  [+] Module loaded (v$($NRGAssessmentVersion))" -ForegroundColor Green
} catch {
    Write-Host "  [!] Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# -Web short-circuits the terminal flow: hand control to the local Pode-backed
# web GUI, which handles tenant selection, scan triggering, progress display,
# and report viewing in a browser. The server binds to 127.0.0.1 only —
# never exposed to the network — and exits cleanly on Ctrl+C.
if ($Web) {
    Start-NRGWebServer -Port $WebPort -ScriptDir $scriptDir
    exit 0
}

# -RegisterApp short-circuits into one-time tenant onboarding: connect
# interactively with WRITE scopes, then create the read-only enterprise app +
# cert in the customer tenant and record it in clients.json. After this, scans
# of that tenant run app-only. This is a privileged, deliberate operation — it
# never happens during a normal scan.
if ($RegisterApp) {
    if (-not $TenantDomain) {
        Write-Host "  [!] -RegisterApp requires -TenantDomain (the customer's domain)." -ForegroundColor Red
        exit 1
    }
    Write-Host ""
    Write-Host "[-] Connecting to Microsoft Graph with onboarding (write) scopes..." -ForegroundColor Cyan
    Write-Host "    A browser sign-in will open. Authorize as an admin of $TenantDomain." -ForegroundColor DarkGray
    try {
        Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.Read.All' `
                        -ContextScope Process -NoWelcome -ErrorAction Stop
    } catch {
        Write-Host "  [!] Graph connect failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    $regParams = @{ TenantDomain = $TenantDomain }
    if ($GrantConsent) { $regParams['GrantConsent'] = $true }
    # Onboarding writes to the tenant, so it is not in the read-only module:
    # load it only for this path.
    . (Join-Path $scriptDir 'Onboard' 'Register-NRGTenantApp.ps1')
    Register-NRGTenantApp @regParams
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    exit 0
}

# -TenantDomain convenience: if the operator gave a domain but no explicit
# app-only credentials, look up a previously-onboarded record in clients.json
# and populate AppId / TenantId / CertificateThumbprint so the scan runs
# app-only with zero typed GUIDs.
$targetTenantId      = $null
$targetDelegatedOrg  = $null
if ($TenantDomain -and -not ($AppId -and $TenantId -and $CertificateThumbprint)) {
    $clientsPath = Join-Path $scriptDir 'Config' 'clients.json'
    $clientRec = $null
    if (Test-Path -LiteralPath $clientsPath) {
        try {
            # clients.json is { "clients": [ ... ] } (what the batch runner
            # and the GUI read); a bare array is accepted too. Reading the
            # wrapper as the list meant this lookup could never match.
            $rawClients = Get-Content -LiteralPath $clientsPath -Raw -Encoding utf8 | ConvertFrom-Json
            $list = if ($rawClients.PSObject.Properties['clients']) { @($rawClients.clients) } else { @($rawClients) }
            $clientRec = $list | Where-Object { $_.PSObject.Properties['TenantDomain'] -and $_.TenantDomain -eq $TenantDomain } |
                         Select-Object -First 1
        } catch { $clientRec = $null }
    }
    # The tenant this run must assess. Interactive sign-in otherwise lands on
    # whatever tenant the account belongs to, and nothing checked that it was
    # the one asked for.
    if ($clientRec -and $clientRec.PSObject.Properties['TenantId'] -and "$($clientRec.TenantId)" -match '^[0-9a-fA-F-]{36}$') {
        $targetTenantId = "$($clientRec.TenantId)".ToLowerInvariant()
    } else {
        $targetTenantId = Resolve-NRGTenantId -Domain $TenantDomain
    }
    if ($clientRec -and $clientRec.PSObject.Properties['DelegatedOrg'] -and "$($clientRec.DelegatedOrg)" -match '\.onmicrosoft\.com$') {
        $targetDelegatedOrg = [string]$clientRec.DelegatedOrg
    }
    if (-not $ThirdPartyEDR -and $clientRec -and $clientRec.PSObject.Properties['ThirdPartyEDR'] -and "$($clientRec.ThirdPartyEDR)") {
        $ThirdPartyEDR = [string]$clientRec.ThirdPartyEDR
    }
    if (-not $MonitoringAddress -and $clientRec -and $clientRec.PSObject.Properties['MonitoringAddresses'] -and @($clientRec.MonitoringAddresses).Count -gt 0) {
        $MonitoringAddress = @($clientRec.MonitoringAddresses | ForEach-Object { [string]$_ })
        $monitoringSource = 'clients.json'
    }
    if (-not $BaselineTier -and $clientRec -and $clientRec.PSObject.Properties['BaselineTier'] -and "$($clientRec.BaselineTier)" -in @('Minimum', 'Standard', 'Hardened')) {
        $BaselineTier = [string]$clientRec.BaselineTier
    }
    # Opt-in collectors declared on the client record (Collectors block): an
    # operator expectation that turns the collector on, never proof it works.
    if ($clientRec -and (Get-Command Get-NRGClientCollectorFlags -ErrorAction SilentlyContinue)) {
        $clientCollectors = Get-NRGClientCollectorFlags -ClientRecord $clientRec
        if ($clientCollectors['SharePointShell'] -and -not $IncludeSharePointShell) {
            $IncludeSharePointShell = $true
            Write-Host "  [i] SharePoint Online Management Shell enabled from clients.json (Collectors.SharePointShell)." -ForegroundColor DarkGray
        }
    }
    $rec = if ($clientRec -and $clientRec.PSObject.Properties['ClientId'] -and $clientRec.ClientId) { $clientRec } else { $null }
    if ($rec) {
        $AppId                 = [string]$rec.ClientId
        $TenantId              = [string]$rec.TenantId
        $CertificateThumbprint = [string]$rec.CertThumbprint
        if (-not $OrganizationDomain -and $rec.PSObject.Properties['TenantDomain']) {
            $OrganizationDomain = [string]$rec.TenantDomain
        }
        Write-Host "  [+] Using app-only auth for $TenantDomain (ClientId $AppId)" -ForegroundColor Green
    } else {
        Write-Host "  [i] $TenantDomain is not onboarded for app-only auth. Falling back to interactive." -ForegroundColor DarkGray
        Write-Host "      Onboard it once with:  .\Invoke-NRGAssessment.ps1 -RegisterApp -TenantDomain $TenantDomain" -ForegroundColor DarkGray
    }
}

# MSP-wide default: EdrStack in Config/branding.psd1 declares the third-party
# EDR every client runs unless -ThirdPartyEDR or the client's clients.json
# ThirdPartyEDR says otherwise. Declared, never verified: the Defender
# endpoint checks go out of the score, they are not passed.
if (-not $ThirdPartyEDR) {
    $brandFile = Join-Path $scriptDir 'Config' 'branding.psd1'
    if (Test-Path -LiteralPath $brandFile) {
        try {
            $brandData = Import-PowerShellDataFile -LiteralPath $brandFile
            $edr = if ($brandData.ContainsKey('EdrStack')) { "$($brandData['EdrStack'])".Trim() } else { '' }
            if ($edr -match '^[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}$') { $ThirdPartyEDR = $edr }
            elseif ($edr) { Write-Warning "Ignoring EdrStack '$edr' in branding.psd1: use a plain product name such as 'Cortex XDR'." }
        } catch { Write-Verbose "branding.psd1 EdrStack not read: $($_.Exception.Message)" }
    }
}

# CWE-665 — full state reset between runs. Clear-NRGFindings only resets the
# findings list; raw collected data, coverage, and exceptions persist in module
# scope. Two back-to-back single-tenant runs in the same pwsh session would
# inherit the prior tenant's RawData — any collector that errors mid-way leaves
# the stale key intact, so the new tenant's evaluators read the prior tenant's
# data and emit cross-tenant findings labeled with the new tenant's metadata.
# Match the contract in CLAUDE.md ("Clear-NRGState must be called between batch
# clients") and the batch orchestrator (Invoke-NRGBatchAssessment.ps1:216).
Clear-NRGState

# The monitoring-address list, recorded as raw data AFTER the state reset so the
# alert-routing checks (DEF-3.4, EXO-3.3) can read it. Precedence: the parameter,
# the client's clients.json entry (already folded into $MonitoringAddress above),
# then the MSP-wide default in branding.psd1.
if (-not (Get-Variable -Name monitoringSource -ErrorAction SilentlyContinue)) { $monitoringSource = '' }
if ($MonitoringAddress -and -not $monitoringSource) { $monitoringSource = 'parameter' }
if (-not $MonitoringAddress) {
    $brandFileMon = Join-Path $scriptDir 'Config' 'branding.psd1'
    if (Test-Path -LiteralPath $brandFileMon) {
        try {
            $brandMon = Import-PowerShellDataFile -LiteralPath $brandFileMon
            if ($brandMon.ContainsKey('MonitoringAddresses') -and @($brandMon['MonitoringAddresses']).Count -gt 0) {
                $MonitoringAddress = @($brandMon['MonitoringAddresses'] | ForEach-Object { [string]$_ })
                $monitoringSource = 'branding.psd1'
            }
        } catch { Write-Verbose "branding.psd1 MonitoringAddresses not read: $($_.Exception.Message)" }
    }
}
$monitoringSet = @(Set-NRGMonitoringAddresses -Addresses $MonitoringAddress -Source $monitoringSource)

# OWASP ASVS V7.3.2 — wrap the entire run in try/finally so service sessions
# always disconnect, even if a collector / evaluator / publisher throws.
# $skipCollection is read by the finally block, so it must exist before any early
# exit (a failed prerequisite check) would otherwise run the finally with it unset.
$skipCollection = $false
try {

# ── Module prerequisite check ─────────────────────────────────────────────────
# ExchangeOnlineManagement 3.7.2 added -DisableWAM, the supported way around
# the WAM broker crash the old 3.2.0 pin worked around. The floor and ceiling
# follow the PowerShell in use (Get-NRGExoModuleFloor: 3.10.0+ on 7.6, 3.7.2
# to 3.9.x on 7.4/7.5) so the preflight, the installer and Get-NRGModuleHealth
# agree; a version outside that range fails inside the module at connect time.
$exoFloor = Get-NRGExoModuleFloor
if (-not $exoFloor.Supported) { Write-Host "  [!] $($exoFloor.Reason)" -ForegroundColor Red }
if ($exoFloor.StoreBuild) {
    Write-Host "  [!] Microsoft Store build of PowerShell detected (`$PSHOME is under WindowsApps); the Exchange Online module has failed to import from it. Install the MSI build: winget install --id Microsoft.PowerShell --source winget" -ForegroundColor Yellow
}
$moduleSpecs = @(
    @{ Name='Microsoft.Graph.Authentication'; MinVersion='2.0.0';       PinVersion=$null; MaxVersion=$null }
    @{ Name='ExchangeOnlineManagement';       MinVersion=$exoFloor.Min; PinVersion=$null; MaxVersion=$exoFloor.Max }
    @{ Name='MicrosoftTeams';                 MinVersion='5.0.0';       PinVersion=$null; MaxVersion=$null }
)
$needsAction = @()
foreach ($spec in $moduleSpecs) {
    $installed = Get-Module -ListAvailable -Name $spec.Name -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if ($installed -and $spec.MaxVersion -and $installed.Version -gt [version]$spec.MaxVersion) {
        Write-Host "  [!] $($spec.Name) $($installed.Version) is newer than PowerShell $($PSVersionTable.PSVersion) supports (up to $($spec.MaxVersion)); connecting will fail inside the module. Upgrade PowerShell or install a version in [$($spec.MinVersion),$($spec.MaxVersion)]." -ForegroundColor Yellow
    }
    if (-not $installed) {
        $needsAction += @{ Spec=$spec; Action='install'; Current=$null }
    } elseif ($spec.PinVersion -and $installed.Version -ne [version]$spec.PinVersion) {
        $needsAction += @{ Spec=$spec; Action='repin'; Current=$installed.Version }
    } elseif ($installed.Version -lt [version]$spec.MinVersion) {
        $needsAction += @{ Spec=$spec; Action='upgrade'; Current=$installed.Version }
    }
}

if ($needsAction.Count -gt 0) {
    Write-Host ""
    foreach ($n in $needsAction) {
        $name = $n.Spec.Name
        if ($n.Action -eq 'install') {
            Write-Host "  [!] Missing: $name" -ForegroundColor Yellow
        } elseif ($n.Action -eq 'repin') {
            Write-Host "  [!] $name $($n.Current) installed — recommended: $($n.Spec.PinVersion)" -ForegroundColor Yellow
            if ([version]$n.Current -gt [version]$n.Spec.PinVersion) {
                Write-Host "      Version $($n.Current) has known crash bugs in this tool's auth flow." -ForegroundColor DarkYellow
            }
        }
    }
    if ($NonInteractive) {
        Write-Host "  [!] NonInteractive — run .\Install-NRGPrerequisites.ps1 manually then retry." -ForegroundColor Red
        exit 1
    }
    $install = Read-Host "  Install/fix modules now? [Y/N]"
    if ($install -match '^[Yy]') {
        # A fresh install previously always used -Scope CurrentUser, which is
        # $HOME\Documents\PowerShell\Modules — the exact path OneDrive Known
        # Folder Move silently redirects on many managed machines, an org
        # policy the operator does not control. Answering Y here was the path
        # most operators actually took, so it was recreating the MSAL
        # assembly-conflict condition the rest of the tool warns about.
        # Get-NRGModuleInstallScope picks AllUsers instead when the session
        # is elevated; see Install-NRGPrerequisites.ps1 for the same decision.
        $scopeInfo    = Get-NRGModuleInstallScope
        $installScope = $scopeInfo.Scope
        if ($scopeInfo.StillSynced) {
            Write-Host "  [!] Your PowerShell module folder is inside OneDrive:" -ForegroundColor Yellow
            Write-Host "      $($scopeInfo.UserModuleDir)" -ForegroundColor DarkYellow
            Write-Host "      Installing here anyway — modules WILL land in OneDrive and may hit the" -ForegroundColor DarkYellow
            Write-Host "      same assembly-conflict bug this prompt exists to fix. To avoid it, re-run" -ForegroundColor DarkYellow
            Write-Host "      from an elevated window, or run .\Install-NRGPrerequisites.ps1 for full guidance." -ForegroundColor DarkYellow
        } elseif ($scopeInfo.UserPathIsSynced) {
            Write-Host "  [+] OneDrive-synced module path detected — installing to AllUsers instead ($env:ProgramFiles\PowerShell\Modules)." -ForegroundColor Green
        }
        foreach ($n in $needsAction) {
            $name = $n.Spec.Name
            $targetVer = $n.Spec.PinVersion
            try {
                if ($n.Action -eq 'repin' -and [version]$n.Current -gt [version]$n.Spec.PinVersion) {
                    # OneDrive-synced PowerShell module paths can't be removed (OneDrive holds
                    # file locks on every file in the synced tree). Detect that case up front
                    # and refuse with an actionable message rather than letting Uninstall-PSResource
                    # fail mid-sweep with a confusing 'Cannot remove package path' error.
                    $existing = Get-Module -Name $name -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
                    if ($existing -and $existing.ModuleBase -match '(?i)\bOneDrive\b') {
                        Write-Host "  [!] $name is installed in a OneDrive-synced path:" -ForegroundColor Red
                        Write-Host "      $($existing.ModuleBase)" -ForegroundColor DarkYellow
                        Write-Host "      OneDrive prevents PowerShell from removing this module." -ForegroundColor Yellow
                        Write-Host "      Fix: pause OneDrive sync on your Documents folder, OR move your" -ForegroundColor Yellow
                        Write-Host "      PowerShell modules out of OneDrive (Settings -> OneDrive -> Backup)." -ForegroundColor Yellow
                        Write-Host "      Then re-run this script." -ForegroundColor Yellow
                        continue
                    }
                    Write-Host "  [*] Downgrading $name $($n.Current) -> $targetVer..." -ForegroundColor Cyan
                    Uninstall-PSResource -Name $name -ErrorAction SilentlyContinue
                }
                if ($targetVer) {
                    Write-Host "  [*] Installing $name $targetVer..." -ForegroundColor Cyan
                    Install-PSResource -Name $name -Version $targetVer -TrustRepository -Scope $installScope -Reinstall -ErrorAction Stop
                } else {
                    Write-Host "  [*] Installing $name (latest)..." -ForegroundColor Cyan
                    Install-PSResource -Name $name -TrustRepository -Scope $installScope -ErrorAction Stop
                }
                Write-Host "  [+] $name ready" -ForegroundColor Green
            } catch {
                Write-Host "  [!] $name failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  [!] Skipping. Run .\Install-NRGPrerequisites.ps1 to set up manually." -ForegroundColor Yellow
    }
}

# ── FromResults mode — skip collection, just republish ───────────────────────
if ($FromResults -and (Test-Path -LiteralPath $FromResults)) {
    Write-Host "[-] FromResults mode — regenerating reports from $FromResults" -ForegroundColor Cyan
    # PS7 -AsHashtable gives us hashtables all the way down so downstream
    # `.Contains(key)` (Maturity badge, threshold exit codes) works. The prior
    # `@{} + $priorData.Metadata` form threw `A hash table can only be added
    # to another hash table` because ConvertFrom-Json returns PSCustomObject.
    $priorData = Get-Content -LiteralPath $FromResults -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
    $findings = [object[]]@($priorData.Findings)
    $conn = if ($priorData.Connections) { [hashtable]$priorData.Connections } else { @{} }
    $reportMetadata = if ($priorData.Metadata) { [hashtable]$priorData.Metadata } else {
        @{ TenantDomain='Unknown'; AssessmentDate=(Get-Date -Format 'MMMM dd, yyyy'); ToolVersion=$script:NRGAssessmentVersion }
    }
    if ($Quick) {
        Write-Warning "-Quick has no effect with -FromResults: findings are loaded from the baseline JSON, not re-evaluated. To produce a Quick scan, re-run against the live tenant."
    }

    # Restore the collection-side state the baseline carries. Without this a
    # republish silently loses it: Get-NRGCoverage returns empty, so the
    # "collectors that did not complete" block and its limitation line vanish
    # from the regenerated report even though the JSON records the failures,
    # and every scope check that reads raw data has nothing to read. Both are
    # report-only on this path — evaluators are not re-run — so restoring them
    # cannot change a verdict, only stop the republish from looking cleaner
    # than the original run.
    if ($priorData.Contains('Coverage') -and $priorData.Coverage) {
        $restored = 0
        foreach ($famKey in @($priorData.Coverage.Keys)) {
            $entry  = $priorData.Coverage[$famKey]
            $status = [string](Get-NRGObjectField -Item $entry -Key 'Status' -Default '')
            $note   = [string](Get-NRGObjectField -Item $entry -Key 'Note'   -Default '')
            # Register-NRGCoverage validates Status; a baseline written by a
            # future version could carry a value this build does not know, and
            # that must not abort the republish.
            if ($status -notin @('Collected','Partial','NotCollected','Failed')) { continue }
            try { Register-NRGCoverage -Family ([string]$famKey) -Status $status -Note $note; $restored++ } catch { }
        }
        if ($restored -gt 0) { Write-Host "  [+] Restored coverage for $restored collector(s)" -ForegroundColor Green }
    }
    if ($priorData.Contains('RawData') -and $priorData.RawData) {
        foreach ($rdKey in @($priorData.RawData.Keys)) {
            try { Set-NRGRawData -Key ([string]$rdKey) -Data $priorData.RawData[$rdKey] } catch { }
        }
    }
    $tenantTag = if ($reportMetadata.TenantDomain) { ($reportMetadata.TenantDomain -split '\.')[0] } else { 'tenant' }
    # OWASP A01 — strip any non-[a-zA-Z0-9-] before using tenantTag in a file path
    $tenantTag = $tenantTag -replace '[^a-zA-Z0-9-]', ''
    if (-not $tenantTag) { $tenantTag = 'tenant' }
    $baseName = "$tenantTag-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Host "  [+] Loaded $($findings.Count) findings" -ForegroundColor Green
    if ($ThirdPartyEDR) {
        $edrCount = Set-NRGThirdPartyEdr -Product $ThirdPartyEDR -Findings $findings
        $reportMetadata['ThirdPartyEDR'] = $ThirdPartyEDR
        Write-Host "  [i] $edrCount Defender endpoint check(s) reported as covered by $ThirdPartyEDR (declared, not verified; not scored)" -ForegroundColor DarkGray
    }
    # Same rule on republish (the license profile comes from the restored
    # AAD-Inventory raw data; without it nothing is moved).
    $licGated = Set-NRGLicenseGating -Findings $findings
    if ($licGated -gt 0) {
        Write-Host "  [i] $licGated control(s) need a license this tenant does not hold — listed as upgrade opportunities, not scored" -ForegroundColor DarkGray
    }
    $skipCollection = $true
} else {
    $skipCollection = $false
}

if (-not $skipCollection) {
    # ── Connect to services ──────────────────────────────────────────────────
    Write-Host ""
    # ── NRG baseline plan: what this run is expected to verify, before it runs ──
    # Predictive, never a verdict. Licensing is unknown here unless a prior
    # results JSON (-BaselineResults) supplies the SKUs read on that run.
    $baselinePlan = $null
    if (Get-Command Get-NRGBaselinePlan -ErrorAction SilentlyContinue) {
        try {
            $planTier = if ($BaselineTier) { $BaselineTier } else { 'Standard' }
            $planSkip = @(foreach ($sf in Get-NRGWorkloadSkipMap) { if ((Get-Variable -Name $sf.Flag -ValueOnly -ErrorAction SilentlyContinue)) { $sf.Keys } })
            $planLic = $null; $planLicSrc = ''
            if ($BaselineResults -and (Test-Path -LiteralPath $BaselineResults)) {
                try {
                    $planPrior = Get-Content -LiteralPath $BaselineResults -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
                    $planSkus  = @(Get-NRGNestedProperty -Object $planPrior -Path 'RawData.AAD-Inventory.Data.SubscribedSkus' -Default @())
                    if ($planSkus.Count -gt 0) {
                        $planLic    = Get-NRGTenantLicenseProfile -SubscribedSkus $planSkus
                        $planAt     = Get-NRGNestedProperty -Object $planPrior -Path 'Metadata.AssessmentTime' -Default '?'
                        $planLicSrc = "prior run $(if ($planAt -is [datetime]) { $planAt.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) } else { [string]$planAt })"
                    }
                } catch { Write-Verbose "Prior results could not supply licensing for the plan: $($_.Exception.Message)" }
            }
            $baselinePlan = Get-NRGBaselinePlan -TenantDomain $TenantDomain -TargetTier $planTier -ThirdPartyEDR $ThirdPartyEDR `
                -IncludeSharePointShell:($IncludeSharePointShell -and -not $SkipSharePoint) -SkipCollectors $planSkip `
                -LicenseProfile $planLic -LicenseSource $planLicSrc
            $ps = $baselinePlan.Summary
            Write-Host "[-] NRG baseline plan ($($ps.TargetTier)): $($ps.RequiredControls) required — expected $($ps.Automatic) automatic, $($ps.ThirdPartyHandled) third-party handled, $($ps.Manual) manual, $($ps.OptionalCollectorRequired) optional collector, $($ps.SkippedByOperator) skipped, $($ps.LicenseBlockedExpected) license blocked, $($ps.LicensingUnknown) licensing unknown until connection; potential not verified before run: $($ps.ExpectedNotVerified)" -ForegroundColor DarkGray
            Write-Host ""
        } catch { Write-Warning "Baseline plan unavailable: $($_.Exception.Message)" }
    }

    Write-Host "[-] Connecting to M365 services..." -ForegroundColor Cyan

    $connectParams = @{}
    if ($AppId -and $TenantId -and $CertificateThumbprint) {
        $connectParams['AppId']                  = $AppId
        $connectParams['TenantId']               = $TenantId
        $connectParams['CertificateThumbprint']  = $CertificateThumbprint
        if ($OrganizationDomain) { $connectParams['OrganizationDomain'] = $OrganizationDomain }
    } else {
        if ($UserPrincipalName)  { $connectParams['UserPrincipalName']     = $UserPrincipalName }
        if ($targetTenantId)     { $connectParams['ExpectedTenantId']      = $targetTenantId }
        if ($targetDelegatedOrg) { $connectParams['DelegatedOrganization'] = $targetDelegatedOrg }
    }
    if ($SkipPurview) { $connectParams['SkipPurview'] = $true }
    if ($SkipTeams)   { $connectParams['SkipTeams']   = $true }
    # SharePoint tenant settings come from Graph; the Management Shell (a
    # child process in PowerShell 7) only when asked for.
    if (-not $IncludeSharePointShell -or $SkipSharePoint) { $connectParams['SkipSharePoint'] = $true }

    $rawConn = @(Connect-NRGServices @connectParams)
    $conn = $rawConn | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1
    if (-not $conn) {
        $conn = @{ Graph=$false; EXO=$false; IPPSSession=$false; Teams=$false; SharePoint=$false }
    }
    # Exit-code spec (v4.6.3 P2): exit 1 on auth failure means no Graph/EXO
    # at all. The downstream collectors will skip silently but the result
    # would be useless — fail loudly here so batch runners can flag the
    # client as auth-broken in their summary.
    if (-not $conn.Graph -and -not $conn.EXO) {
        Write-Host "  [!] Connect-NRGServices returned no usable session (Graph and EXO both unavailable)." -ForegroundColor Red
        $script:NRGFatalExitCode = 1
        throw [System.InvalidOperationException]::new('Authentication failure: no Graph or EXO session available.')
    }
    if (-not $conn.ContainsKey('SharePoint')) { $conn['SharePoint'] = $false }
    # A run with Exchange but no Graph is valid and honest (every control that needs Graph
    # reads "not assessed"), but it is not the assessment the operator meant to run and it can
    # take half an hour to find that out. Say it now, before collection, not in the report.
    if (-not $conn.Graph) {
        Write-Host ""
        Write-Host "  [!] Microsoft Graph is NOT connected. Identity (Entra ID), Conditional Access, Intune, users, roles and" -ForegroundColor Red
        Write-Host "      application controls cannot be assessed in this run; they will read 'not assessed', not 'passed'." -ForegroundColor Red
        Write-Host "      Fix the Graph error shown above and re-run if you meant a full assessment (Ctrl+C to stop now)." -ForegroundColor Red
        Write-Host ""
    }

    # A -Skip flag is an operator choice. Recording it lets the scope section
    # file the workload's controls as "not assessed" instead of as data that
    # failed to collect. The keys are the CollectorDependency values the
    # skipped controls carry in controls.json.
    $skipFlags = @(
        @{ On = $SkipPurview;       Flag = '-SkipPurview';       Keys = @('Purview') }
        @{ On = $SkipTeams;         Flag = '-SkipTeams';         Keys = @('Teams') }
        @{ On = $SkipSharePoint;    Flag = '-SkipSharePoint';    Keys = @('SharePoint') }
        @{ On = $SkipIntune;        Flag = '-SkipIntune';        Keys = @('Intune-EndpointSecurity', 'Intune-DeviceCompliance', 'Intune-AppProtection') }
        @{ On = $SkipPowerPlatform; Flag = '-SkipPowerPlatform'; Keys = @('PowerPlatform') }
        @{ On = $SkipDNS;           Flag = '-SkipDNS';           Keys = @('DNS-EmailRecords') }
    )
    foreach ($sf in $skipFlags) {
        if (-not $sf.On) { continue }
        foreach ($k in $sf.Keys) { Register-NRGCoverage -Family $k -Status 'Skipped' -Note "Skipped for this run with $($sf.Flag)." }
    }

    # Never write a report for a tenant other than the one requested.
    if ($TenantDomain) {
        $mismatch = $null
        if ($targetTenantId -and $conn.TenantId -and "$($conn.TenantId)" -ne $targetTenantId) {
            $mismatch = "connected tenant $($conn.TenantId) is not $TenantDomain ($targetTenantId)"
        } elseif (-not $targetTenantId) {
            $mismatch = "could not resolve a tenant ID for $TenantDomain, so the connected tenant cannot be confirmed"
        }
        if ($mismatch) {
            Write-Host "  [!] Wrong tenant: $mismatch. Nothing was collected." -ForegroundColor Red
            Write-Host "      Sign in with an account in $TenantDomain (or with GDAP access to it and its DelegatedOrg in clients.json)." -ForegroundColor Red
            $script:NRGFatalExitCode = 1
            throw [System.InvalidOperationException]::new("Tenant mismatch: $mismatch.")
        }
    }

    if ($WhatIfConnections) {
        Write-Host ""
        Write-Host "Connections (WhatIf mode):" -ForegroundColor Yellow
        $conn | Format-Table -AutoSize
        return
    }

    # ── Run collectors ───────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "[-] Running collectors..." -ForegroundColor Cyan

    # One aligned line per collector: [+] collected, [!] collected with issues
    # logged, [x] failed, [-] not available in this tenant. The status comes
    # from what the collector itself recorded (coverage and the Exceptions
    # array), never from the fact that it returned. Third-party warnings are
    # captured and printed under the line rather than breaking into it.
    $script:NRGStepTally = [ordered]@{ Ok = 0; Issues = 0; Failed = 0; NotAvailable = 0 }
    function Write-NRGCollectorGroup { param([string] $Name) Write-Host "  $Name" -ForegroundColor Cyan }
    function Invoke-NRGCollectorStep {
        param([string] $Label, [string[]] $Function, [hashtable] $Params = @{})
        $fns = @($Function | Where-Object { Get-Command $_ -ErrorAction SilentlyContinue })
        if ($fns.Count -eq 0) { return }
        $covBefore = @{}
        foreach ($kv in (Get-NRGCoverage).GetEnumerator()) { $covBefore[$kv.Key] = "$($kv.Value.Status)|$($kv.Value.Note)" }
        $excBefore = @(Get-NRGExceptions).Count
        $line = '  [*] {0,-50}' -f $Label
        Write-Host $line -NoNewline -ForegroundColor DarkGray
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $threw = $null
        $warn = [System.Collections.Generic.List[object]]::new()
        foreach ($fn in $fns) {
            try {
                & $fn @Params -WarningAction SilentlyContinue -WarningVariable w | Out-Null
                foreach ($x in @($w)) { $warn.Add($x) }
            } catch { $threw = $_.Exception.Message.Split([char]10)[0].Trim() }
        }
        $sw.Stop()
        $changed = @((Get-NRGCoverage).GetEnumerator() | Where-Object { $covBefore[$_.Key] -ne "$($_.Value.Status)|$($_.Value.Note)" })
        $statuses = @($changed | ForEach-Object { $_.Value.Status })
        $newExc = @(Get-NRGExceptions).Count - $excBefore

        $failNote = @($changed | Where-Object { $_.Value.Status -eq 'Failed' } | ForEach-Object { $_.Value.Note } | Where-Object { $_ }) | Select-Object -First 1
        $okNote   = (@($changed | Where-Object { $_.Value.Status -in 'Collected', 'Partial' } | ForEach-Object { $_.Value.Note } | Where-Object { $_ }) -join '; ')
        $naNote   = @($changed | Where-Object { $_.Value.Status -eq 'NotCollected' } | ForEach-Object { $_.Value.Note } | Where-Object { $_ }) | Select-Object -First 1
        $okCount  = @($statuses | Where-Object { $_ -in 'Collected', 'Partial' }).Count

        if ($threw -or ('Failed' -in $statuses -and $okCount -eq 0)) {
            $mark = '[x]'; $color = 'Red'; $script:NRGStepTally.Failed++
            $detail = 'failed: ' + $(if ($threw) { $threw } elseif ($failNote) { $failNote } else { 'see Exceptions' })
        } elseif ('Failed' -in $statuses -or 'Partial' -in $statuses -or $newExc -gt 0) {
            $mark = '[!]'; $color = 'Yellow'; $script:NRGStepTally.Issues++
            $detail = "$(if ($okNote) { "$okNote; " })$newExc issue(s) logged"
        } elseif ($statuses.Count -gt 0 -and $okCount -eq 0 -and 'NotCollected' -in $statuses) {
            $mark = '[-]'; $color = 'DarkGray'; $script:NRGStepTally.NotAvailable++
            $detail = $(if ($naNote) { $naNote } else { 'not available' })
        } else {
            $mark = '[+]'; $color = 'Green'; $script:NRGStepTally.Ok++
            $detail = $okNote
        }
        if ($detail.Length -gt 70) { $detail = $detail.Substring(0, 67) + '...' }
        Write-Host ("`r  {0} {1,-50}{2,6:N1}s  {3}" -f $mark, $Label, $sw.Elapsed.TotalSeconds, $detail) -ForegroundColor $color
        foreach ($x in ($warn | Select-Object -Unique)) {
            $msg = "$x".Split([char]10)[0].Trim()
            if ($msg.Length -gt 100) { $msg = $msg.Substring(0, 97) + '...' }
            Write-Host "        warning: $msg" -ForegroundColor DarkYellow
        }
    }

    if ($conn.Graph) {
        Write-NRGCollectorGroup 'Identity (Entra ID)'
        Invoke-NRGCollectorStep 'Auth and authorization policies'        'Invoke-NRGCollectAADAuthPolicies'
        Invoke-NRGCollectorStep 'Conditional Access policies'            'Invoke-NRGCollectAADCAPolicies'
        Invoke-NRGCollectorStep 'Users and MFA registration'             'Invoke-NRGCollectAADUsers'
        Invoke-NRGCollectorStep 'Directory role assignments'             'Invoke-NRGCollectAADRoles'
        Invoke-NRGCollectorStep 'PIM schedules and access reviews'       'Invoke-NRGCollectAADPIM', 'Invoke-NRGCollectAADIdentityGovernance'
        Invoke-NRGCollectorStep 'Guests, stale accounts, OAuth, licenses' 'Invoke-NRGCollectAADInventory'
        Invoke-NRGCollectorStep 'Application (app-only) permissions'     'Invoke-NRGCollectAADAppPermissions'

        if (-not $SkipSharePoint) {
            Write-NRGCollectorGroup 'SharePoint and OneDrive'
            Invoke-NRGCollectorStep 'Tenant sharing settings'            'Invoke-NRGCollectSharePoint'
        }
        if (-not $SkipIntune) {
            Write-NRGCollectorGroup 'Intune'
            Invoke-NRGCollectorStep 'Endpoint security (LAPS, ASR, AV, EDR)' 'Invoke-NRGCollectIntuneEndpointSecurity'
            Invoke-NRGCollectorStep 'Compliance, enrollment, WHfB, updates'  'Invoke-NRGCollectIntuneDeviceCompliance'
            Invoke-NRGCollectorStep 'App protection and configuration'       'Invoke-NRGCollectIntuneAppProtection'
        }
        if (-not $SkipPowerPlatform) {
            Write-NRGCollectorGroup 'Power Platform'
            if (-not ($AppId -and $TenantId -and $CertificateThumbprint)) {
                Write-Host "      A browser sign-in may open (same account). Use -SkipPowerPlatform to skip." -ForegroundColor DarkGray
            }
            Invoke-NRGCollectorStep 'Environments, tenant isolation, DLP'    'Invoke-NRGCollectPowerPlatform'
        }
    }

    if ($conn.EXO) {
        Write-NRGCollectorGroup 'Exchange Online and Defender'
        Invoke-NRGCollectorStep 'Organization and transport settings'   'Invoke-NRGCollectEXOMailboxConfig', 'Invoke-NRGCollectEXOConnectionFilter'
        Invoke-NRGCollectorStep 'Mailboxes: forwarding, audit, SMTP AUTH' 'Invoke-NRGCollectEXOInventory'
        Invoke-NRGCollectorStep 'Defender for Office 365 policies'       'Invoke-NRGCollectDefender'
    }

    # DNS is public: it needs a domain list, not an Exchange session. The
    # collector takes accepted domains from Exchange when they were collected
    # and falls back to Graph verifiedDomains otherwise, so an Exchange
    # connection failure must not take the DNS controls with it (it did on
    # the first live run: three Minimum controls lost to a session error).
    if (-not $SkipDNS -and ($conn.Graph -or $conn.EXO)) {
        Write-NRGCollectorGroup 'DNS'
        $dnsParams = if ($DnsDomains) { @{ Domains = $DnsDomains } } else { @{} }
        Invoke-NRGCollectorStep 'SPF, DKIM, DMARC, MTA-STS, DNSSEC, CAA' 'Invoke-NRGCollectDNSEmailRecords' -Params $dnsParams
    }

    if ($conn.Teams -and -not $SkipTeams) {
        Write-NRGCollectorGroup 'Teams'
        Invoke-NRGCollectorStep 'Meetings, external access, messaging'   'Invoke-NRGCollectTeams'
    }

    if ($conn.IPPSSession -and -not $SkipPurview) {
        Write-NRGCollectorGroup 'Purview'
        Invoke-NRGCollectorStep 'Audit, DLP, retention, labels'          'Invoke-NRGCollectPurview'
    }

    # Copilot collector runs after Purview so it can reuse label/DLP/audit raw data
    if ($conn.Graph) {
        Write-NRGCollectorGroup 'Microsoft 365 Copilot'
        Invoke-NRGCollectorStep 'Licensing, labels, DLP, Copilot Studio' 'Invoke-NRGCollectM365Copilot'
    }

    # Endpoint compliance results. No connection required: the endpoints already
    # ran the collector and the RMM already gathered the output. This reads
    # files, nothing else.
    if ($DeviceResults) {
        Write-NRGCollectorGroup 'Endpoints'
        Invoke-NRGCollectorStep 'Device compliance results'              'Invoke-NRGCollectDeviceCompliance' -Params @{ ResultsPath = $DeviceResults }
        $devRaw = Get-NRGRawData -Key 'Device-Compliance'
        if ($devRaw -and $devRaw.Success) {
            $ne = [int]$devRaw.Data.DeviceCount - [int]$devRaw.Data.ElevatedCount
            if ($ne -gt 0) {
                Write-Host "        $ne device(s) ran without administrative rights — encryption, TPM, Secure Boot and audit-policy checks are unassessed on those, not passed." -ForegroundColor DarkYellow
            }
        }
    }

    $t = $script:NRGStepTally
    $tallyColor = if ($t.Failed -gt 0) { 'Red' } elseif ($t.Issues -gt 0) { 'Yellow' } else { 'Green' }
    $tallyText = "$($t.Ok) collected, $($t.Issues) with issues, $($t.Failed) failed"
    if ($t.NotAvailable -gt 0) { $tallyText += ", $($t.NotAvailable) not available" }
    if ($t.Issues + $t.Failed -gt 0) { $tallyText += '. Details: Exceptions array in the results JSON' }
    Write-Host ""
    Write-Host "  $tallyText" -ForegroundColor $tallyColor

    # ── Run evaluators ───────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "[-] Running evaluators..." -ForegroundColor Cyan

    # Evaluator invocation is delegated to the module's Invoke-NRGEvaluatorSafe,
    # which additionally back-fills an 'Error' finding for any control an
    # evaluator owns but fails to assess — so a single evaluator bug can never
    # silently drop a control from the report. See Lib/Invoke-NRGEvaluatorSafe.ps1.

    # All evaluators discovered by name from the loaded module
    $evaluators = @(Get-Command -Module NRG-Assessment -Name 'Test-NRGControl*' -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name)

    # ── -Quick: filter evaluators to those that handle Critical / High controls
    # NOTE: filter is by evaluator FUNCTION name, so any workload-level function
    # that handles BOTH Critical/High and Medium/Low controls (DEF-1.x, PVW-*,
    # SPO-*, etc) will still emit its Low/Medium findings. The maturity badge
    # and HTML score ring reflect the actual set, not the requested severity
    # range. Treat -Quick as "skip the workloads that ONLY have low-severity
    # checks" rather than "skip every Low/Medium finding."
    if ($Quick) {
        $highSevEvaluators = @{}
        # Fail-closed: a corrupt controls.json must not silently produce a
        # filter that excludes every evaluator and exits 2 ("no findings").
        # The outer try/catch already turns this into fatal=4 with a message.
        foreach ($ctrl in (Get-NRGControlDefinitions)) {
            if ($ctrl.Severity -in @('Critical','High') -and $ctrl.EvaluatorFunction) {
                $highSevEvaluators[$ctrl.EvaluatorFunction] = $true
            }
        }
        # Test-NRGControlDevice owns the 35 DEV-* endpoint checks (3 Critical,
        # 20 High) defined in Config/device-controls.json, NOT controls.json, so
        # the loop above never sees it and -Quick silently dropped every
        # endpoint finding even when -DeviceResults was supplied. Keep it in
        # the Quick set explicitly.
        $highSevEvaluators['Test-NRGControlDevice'] = $true
        $beforeCount = $evaluators.Count
        $evaluators  = @($evaluators | Where-Object { $highSevEvaluators.ContainsKey($_) })
        Write-Host "  [i] Quick mode: $($evaluators.Count) of $beforeCount evaluators (workloads with Critical+High only; lower-severity findings inside those workloads still surface)" -ForegroundColor Yellow
    }

    foreach ($ev in $evaluators) {
        Invoke-NRGEvaluatorSafe -EvaluatorFunction $ev
    }

    if ($ThirdPartyEDR) {
        $edrCount = Set-NRGThirdPartyEdr -Product $ThirdPartyEDR
        Write-Host "  [i] $edrCount Defender endpoint check(s) reported as covered by $ThirdPartyEDR (declared, not verified; not scored)" -ForegroundColor DarkGray
    }
    # After the EDR declaration, so a Cortex client is not pitched Defender
    # for Endpoint licenses for checks it does not need.
    $licGated = Set-NRGLicenseGating
    if ($licGated -gt 0) {
        Write-Host "  [i] $licGated control(s) need a license this tenant does not hold — listed as upgrade opportunities, not scored" -ForegroundColor DarkGray
    }

    $findings = Get-NRGFindings
    Write-Host "  [+] $($findings.Count) findings evaluated" -ForegroundColor Green

    # ── Build report metadata ────────────────────────────────────────────────
    $tenantTag = if ($conn.TenantDomain) { ($conn.TenantDomain -split '\.')[0] } else { 'tenant' }
    # OWASP A01 — strip any non-[a-zA-Z0-9-] before using tenantTag in a file path
    $tenantTag = $tenantTag -replace '[^a-zA-Z0-9-]', ''
    if (-not $tenantTag) { $tenantTag = 'tenant' }
    $baseName = "$tenantTag-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    $reportMetadata = @{
        TenantDomain   = $conn.TenantDomain
        TenantId       = $conn.TenantId
        # The account that actually signed in when no UPN was given (the GUI
        # and -TenantDomain runs), so the report never names nobody.
        Operator       = $(if ($UserPrincipalName) { $UserPrincipalName } elseif (Get-Command Get-MgContext -ErrorAction SilentlyContinue) { [string](Get-MgContext).Account } else { '' })
        AssessmentDate = (Get-Date).ToString('MMMM dd, yyyy')
        AssessmentTime = (Get-Date).ToString('o')
        ToolVersion    = $NRGAssessmentVersion
        Brand          = $NRGBrand
        QuickScan      = [bool]$Quick
        ThirdPartyEDR  = [string]$ThirdPartyEDR
    }
}

# ── Maturity tier (roadmap F1) ──────────────────────────────────────────────
# Derived from the final findings stream — recomputed every run including
# -FromResults so the badge always reflects the current findings, not whatever
# Maturity value (if any) the baseline JSON happened to carry. Result is
# embedded in the metadata so publishers (HTML, JSON, Markdown, Playbook,
# Delta) can render the same classification. Failure is logged + surfaced
# via the summary banner so a missing badge doesn't slip past the operator.
try {
    $reportMetadata['Maturity'] = Get-NRGMaturityTier -Findings $findings
} catch {
    Write-Warning "Maturity-tier classification failed: $($_.Exception.Message)"
    $reportMetadata['MaturityError'] = $_.Exception.Message
}

# ── NRG Security Baseline: a desired-state view over the findings ─────────────
# Resolved after every verdict-changing step (evaluation, third-party EDR,
# license gating) so it reads the same findings the report does. It creates
# no finding and moves no score; a control with no verdict, a failed
# collector, or stale evidence resolves NotVerified, never Satisfied.
$baselineCompliance  = $null
$baselineRegressions = $null
$baselinePlanComparison = $null
if (-not (Get-Variable -Name baselinePlan -ErrorAction SilentlyContinue)) { $baselinePlan = $null }
if (-not $BaselineTier) {
    $priorTier = [string](Get-NRGObjectField -Item $reportMetadata -Key 'TargetTier' -Default '')
    $BaselineTier = if ($skipCollection -and $priorTier -in @('Minimum', 'Standard', 'Hardened')) { $priorTier } else { 'Standard' }
}
if (Get-Command Get-NRGBaselineCompliance -ErrorAction SilentlyContinue) {
    try {
        $baselineCompliance = Get-NRGBaselineCompliance -Findings $findings -TargetTier $BaselineTier `
            -TenantDomain ([string](Get-NRGObjectField -Item $reportMetadata -Key 'TenantDomain' -Default '')) `
            -QuickScan:([bool](Get-NRGObjectField -Item $reportMetadata -Key 'QuickScan' -Default $false))
        $reportMetadata['BaselineVersion'] = $baselineCompliance.BaselineVersion
        $reportMetadata['TargetTier']      = $baselineCompliance.TargetTier
        # Regressions against the prior run, only under a comparable baseline
        # context; a version or tier change is stated, never read as decline.
        $priorBaseline = $null; $priorRunTime = ''
        if ($BaselineResults -and (Test-Path -LiteralPath $BaselineResults)) {
            try {
                $priorJson = Get-Content -LiteralPath $BaselineResults -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
                $priorBaseline = Get-NRGObjectField -Item $priorJson -Key 'BaselineCompliance' -Default $null
                $priorRunTime  = [string](Get-NRGNestedProperty -Object $priorJson -Path 'Metadata.AssessmentTime' -Default '')
            } catch { Write-Warning "Prior results could not be read for baseline regressions: $($_.Exception.Message)" }
        }
        $baselineRegressions = Get-NRGBaselineRegressions -Current $baselineCompliance -Prior $priorBaseline -PriorRunTime $priorRunTime
        if ($null -ne $baselinePlan -and (Get-Command Compare-NRGBaselinePlan -ErrorAction SilentlyContinue)) {
            $baselinePlanComparison = Compare-NRGBaselinePlan -Plan $baselinePlan -Compliance $baselineCompliance
        }
        $bs = $baselineCompliance.Summary
        Write-Host "  [i] NRG baseline v$($bs.BaselineVersion) ($($bs.TargetTier)): $($bs.RequiredControls) required — $($bs.Satisfied) satisfied, $($bs.Failed) failed, $($bs.NotVerified) not verified, $($bs.LicenseBlocked) license blocked, $($bs.ApprovedException) approved exception(s); effectiveness known for $($bs.EffectivenessEffective + $bs.EffectivenessIneffective) of $($bs.RequiredControls)" -ForegroundColor DarkGray
        $evc = Get-NRGObjectField -Item $baselineCompliance -Key 'EvidenceCoverage' -Default $null
        $efc = Get-NRGObjectField -Item $baselineCompliance -Key 'EffectivenessCoverage' -Default $null
        if ($null -ne $evc -and $null -ne $efc) {
            $gapText = (@($evc.Gaps.Keys | ForEach-Object { "$($evc.Gaps[$_]) $_" }) -join ', ')
            Write-Host "  [i] Evidence coverage: $($evc.Known) of $($evc.Applicable) applicable controls ($($evc.Percent)%)$(if ($evc.LicenseBlocked -gt 0) { ", $($evc.LicenseBlocked) license blocked" })$(if ($gapText) { "; gaps: $gapText" }). Effectiveness coverage: $($efc.Known) of $($efc.Required) ($($efc.Percent)%). Neither is the baseline score." -ForegroundColor DarkGray
        }
        if ($null -ne $baselinePlanComparison -and $baselinePlanComparison.Available) {
            $unexp = @($baselinePlanComparison.UnexpectedNotVerified)
            Write-Host "  [i] Plan vs run: $($baselinePlanComparison.Note)" -ForegroundColor DarkGray
            if ($unexp.Count -gt 0) { Write-Host "      Not expected: $(@($unexp | ForEach-Object { "$($_.ControlId) [$($_.Cause)]" }) -join ', ')" -ForegroundColor DarkYellow }
        }
        if ($baselineRegressions.Available -and @($baselineRegressions.Regressions).Count -gt 0) {
            $regCfg  = @($baselineRegressions.Regressions | Where-Object { $_.Kind -eq 'ConfigurationRegressed' })
            $regLost = @($baselineRegressions.Regressions | Where-Object { $_.Kind -eq 'EvidenceLost' })
            if ($regCfg.Count -gt 0)  { Write-Host "  [!] $($regCfg.Count) NRG baseline regression(s) since the prior run (configuration regressed): $(@($regCfg | ForEach-Object { $_.ControlId }) -join ', ')" -ForegroundColor Yellow }
            if ($regLost.Count -gt 0) { Write-Host "  [!] $($regLost.Count) required control(s) were satisfied last run and could not be verified this run (evidence lost, not necessarily drift): $(@($regLost | ForEach-Object { "$($_.ControlId) [$($_.CurrentCause)]" }) -join ', ')" -ForegroundColor DarkYellow }
        }
    } catch {
        Write-Warning "NRG baseline view failed: $($_.Exception.Message)"
        $reportMetadata['BaselineError'] = $_.Exception.Message
    }
}

# ── Publish reports ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Generating reports..." -ForegroundColor Cyan
# One aligned line per file, named by its leaf; the folder is printed once.
$script:NRGReportFolderShown = $false
function Write-NRGReportFile {
    param([string] $Label, [string] $Path)
    if (-not $script:NRGReportFolderShown) {
        Write-Host "  Folder: $(Split-Path -Path $Path -Parent)" -ForegroundColor DarkGray
        $script:NRGReportFolderShown = $true
    }
    Write-Host ('  [+] {0,-34} {1}' -f $Label, (Split-Path -Path $Path -Leaf)) -ForegroundColor Green
}

$jsonPath = Join-Path $OutputPath "$baseName-results.json"
# Capture the raw-data snapshot for drift detection on the NEXT run. The
# delta publisher compares this snapshot against a future run's snapshot to
# surface raw configuration changes (new CA policies, new admin assignments,
# new OAuth apps, DMARC policy regression) — not just finding state changes.
$rawDataSnapshot = if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) {
    Get-NRGRawData
} else { @{} }
# TOCTOU fix (v4.6.3 P2): Set-NRGSensitiveFileContent pre-creates the file
# and applies the ACL BEFORE any tenant data is written. Previously the
# file inherited the parent directory's permissions during Out-File and was
# only restricted afterwards via Set-Acl — on a shared MSP workstation a
# co-resident process polling the output dir could read tenant data in
# that small window.
$jsonPayload = @{
    Metadata    = $reportMetadata
    Findings    = $findings
    RawData     = $rawDataSnapshot
    Exceptions  = (Get-NRGExceptions)
    Coverage    = (Get-NRGCoverage)
    Connections = $conn
    # The NRG baseline is the integration contract for whatever consumes
    # these results later: per required control the observed state,
    # constraint, disposition, evidence timestamp and freshness, and
    # effectiveness, plus the regressions against the prior run.
    BaselineCompliance  = $baselineCompliance
    BaselineRegressions = $baselineRegressions
    BaselinePlan        = $baselinePlan
    BaselinePlanComparison = $baselinePlanComparison
} | ConvertTo-Json -Depth 12
Set-NRGSensitiveFileContent -Path $jsonPath -Content $jsonPayload
Write-NRGReportFile 'JSON' $jsonPath
Write-Host "      Holds sensitive tenant inventory (CA policies, admin assignments, OAuth apps); access restricted to you and administrators." -ForegroundColor Yellow

if (-not $JsonOnly) {
    # ── Audit-finding fix (HIGH #2): every secondary report file gets the same
    #    ACL hardening as the JSON baseline. They all contain the same tenant
    #    inventory data (CA policies, admin UPNs, OAuth grants, DMARC records)
    #    rendered into a different format. Inherited permissions on a shared
    #    MSP workstation or synced OneDrive would otherwise make these world-
    #    readable. Set-NRGSensitiveFileAcl is a no-op on non-Windows.
    # ── Build in-report downloads for the consolidated single-file report ────
    # The default profile writes only the HTML report + JSON. So the report
    # itself CARRIES the small text deliverables (remediation script, findings
    # CSV) as embedded <a download> data-URI buttons instead of scattering
    # sidecar files. Under -AllFiles these are ALSO written standalone.
    $reportAttachments = @()

    # Findings CSV — small, always embeddable.
    try {
        $csvText = @($findings | ForEach-Object {
            [pscustomobject][ordered]@{
                ControlId = $_.ControlId
                Severity  = $_.Severity
                State     = $_.State
                Category  = $_.Category
                Title     = $_.Title
            }
        }) | ConvertTo-Csv -NoTypeInformation | Out-String
        if (-not [string]::IsNullOrWhiteSpace($csvText)) {
            $reportAttachments += @{ Label = 'Findings (CSV)'; FileName = "$baseName-findings.csv"; Mime = 'text/csv'; Content = $csvText }
        }
    } catch { Write-Warning "Findings CSV build failed: $($_.Exception.Message)" }

    # Remediation script — generate once; embed its content, and (under
    # -AllFiles) also leave it as a standalone .ps1. In the default profile the
    # sidecar file is removed after its content is captured for embedding.
    if (Get-Command Publish-NRGRemediationScript -ErrorAction SilentlyContinue) {
        $rsPath = Join-Path $OutputPath "$baseName-remediation.ps1"
        try {
            Publish-NRGRemediationScript -Metadata $reportMetadata -Findings $findings -OutputPath $rsPath
            $remContent = Get-Content -Raw -LiteralPath $rsPath -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($remContent)) {
                $reportAttachments += @{ Label = 'Remediation script (PowerShell)'; FileName = "$baseName-remediation.ps1"; Mime = 'text/plain'; Content = $remContent }
            }
            if ($AllFiles) {
                Set-NRGSensitiveFileAcl -Path $rsPath -ErrorAction SilentlyContinue
                Write-NRGReportFile 'Remediation' $rsPath
            } else {
                # Consolidated profile: the content is embedded in the HTML —
                # don't leave the sidecar file (and don't leave tenant data on
                # disk unnecessarily).
                Remove-Item -LiteralPath $rsPath -Force -ErrorAction SilentlyContinue
            }
        } catch { Write-Warning "Remediation publish failed: $($_.Exception.Message)" }
    }

    # HTML report (always in a non-JsonOnly run) — carries the embedded downloads.
    if (Get-Command Publish-NRGAssessmentHTML -ErrorAction SilentlyContinue) {
        $htmlPath = Join-Path $OutputPath "$baseName-assessment.html"
        try {
            $fwSelection = if ($Framework -eq 'All') { @('CIS','SCuBA','NIST','CMMC') } else { @($Framework) }
            Publish-NRGAssessmentHTML -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $htmlPath -Attachments $reportAttachments -Frameworks $fwSelection -BaselineRegressions $baselineRegressions -BaselinePlanComparison $baselinePlanComparison
            Write-NRGReportFile 'HTML' $htmlPath
            Set-NRGSensitiveFileAcl -Path $htmlPath -ErrorAction SilentlyContinue
        } catch {
            $stack = $_.ScriptStackTrace
            Write-Warning "HTML failed: $($_.Exception.Message)"
            Write-Warning "Stack: $stack"
        }
    }

    # ── Standalone sidecar deliverables (only with -AllFiles) ────────────────
    # Every file below contains the same tenant inventory (CA policies, admin
    # UPNs, OAuth grants, DMARC records) in a different format, so each gets the
    # same ACL hardening as the JSON baseline. Set-NRGSensitiveFileAcl is a
    # no-op on non-Windows.
    if ($AllFiles) {
        # Markdown summary
        if (Get-Command Publish-NRGAssessmentSummary -ErrorAction SilentlyContinue) {
            $mdPath = Join-Path $OutputPath "$baseName-assessment.md"
            try {
                Publish-NRGAssessmentSummary -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $mdPath -BaselineRegressions $baselineRegressions -BaselinePlanComparison $baselinePlanComparison
                Write-NRGReportFile 'Markdown' $mdPath
                Set-NRGSensitiveFileAcl -Path $mdPath -ErrorAction SilentlyContinue
            } catch { Write-Warning "Markdown publish failed: $($_.Exception.Message)" }
        }

        # Remediation playbook + executive summary
        if (Get-Command Publish-NRGRemediationPlaybook -ErrorAction SilentlyContinue) {
            $pbPath     = Join-Path $OutputPath "$baseName-playbook.md"
            $execPath   = Join-Path $OutputPath "$baseName-executive.md"
            $pbHtmlPath = Join-Path $OutputPath "$baseName-playbook.html"
            try {
                Publish-NRGRemediationPlaybook `
                    -Metadata $reportMetadata `
                    -Findings $findings `
                    -Connections $conn `
                    -OutputPath $pbPath `
                    -ExecutivePath $execPath `
                    -HtmlOutputPath $pbHtmlPath
                Write-NRGReportFile 'Playbook (md)' $pbPath
                Write-NRGReportFile 'Playbook (html)' $pbHtmlPath
                Write-NRGReportFile 'Executive' $execPath
                Set-NRGSensitiveFileAcl -Path $pbPath     -ErrorAction SilentlyContinue
                Set-NRGSensitiveFileAcl -Path $execPath   -ErrorAction SilentlyContinue
                Set-NRGSensitiveFileAcl -Path $pbHtmlPath -ErrorAction SilentlyContinue
            } catch { Write-Warning "Playbook publish failed: $($_.Exception.Message)" }
        }

        # XLSX compliance matrix
        if (Get-Command Publish-NRGComplianceMatrix -ErrorAction SilentlyContinue) {
            $xlsxPath = Join-Path $OutputPath "$baseName-compliance-matrix.xlsx"
            try {
                Publish-NRGComplianceMatrix -Metadata $reportMetadata -Findings $findings -OutputPath $xlsxPath
                Write-NRGReportFile 'XLSX matrix' $xlsxPath
                Set-NRGSensitiveFileAcl -Path $xlsxPath -ErrorAction SilentlyContinue
            } catch { Write-Warning "XLSX publish failed: $($_.Exception.Message)" }
        }
    }

    # Standalone NIST 800-53 Rev 5 matrix. Separate from -AllFiles so an
    # 800-53 client can be served without generating every other sidecar, and
    # implied by -AllFiles so the consolidated profile stays a superset.
    if (($NISTMatrix -or $AllFiles) -and (Get-Command Publish-NRGNISTMatrix -ErrorAction SilentlyContinue)) {
        $nistPath = Join-Path $OutputPath "$baseName-nist-800-53-matrix.md"
        try {
            Publish-NRGNISTMatrix -Metadata $reportMetadata -Findings $findings -OutputPath $nistPath
            Write-NRGReportFile 'NIST matrix (md)' $nistPath
            Set-NRGSensitiveFileAcl -Path $nistPath -ErrorAction SilentlyContinue
            # The HTML and XLSX sidecars carry the same findings as the
            # Markdown and get the same file restriction.
            foreach ($ext in '.html', '.xlsx') {
                $side = [System.IO.Path]::ChangeExtension($nistPath, $ext)
                if (Test-Path -LiteralPath $side) {
                    Write-NRGReportFile "NIST matrix ($($ext.TrimStart('.')))" $side
                    Set-NRGSensitiveFileAcl -Path $side -ErrorAction SilentlyContinue
                }
            }
        } catch { Write-Warning "NIST matrix publish failed: $($_.Exception.Message)" }
    }

    # System Security Plan (NIST SP 800-171 Rev 2 / CMMC Level 2). Same shape as
    # the NIST matrix above: its own switch so a defense-contractor client can
    # be served without every other sidecar, and implied by -AllFiles.
    if (($SSP -or $AllFiles) -and (Get-Command Publish-NRGSSP -ErrorAction SilentlyContinue)) {
        $sspPath = Join-Path $OutputPath "$baseName-ssp-800-171.md"
        try {
            # Prefer the operator-supplied -TenantDomain when given. Under GDAP
            # batch mode, $reportMetadata.TenantDomain is derived by
            # Connect-NRGServices from the SIGNED-IN ACCOUNT's UPN, which is
            # the MSP's own domain, not the client's — looking the answers
            # file up by that value attaches the MSP's own SSP narratives to
            # every client. -TenantDomain is the client the operator actually
            # asked to assess and is unambiguous whenever it is supplied.
            # NOTE: Invoke-NRGBatchAssessment.ps1 does not yet pass
            # -TenantDomain through to this orchestrator for GDAP clients, so
            # this alone does not close the gap in batch mode — that
            # batch-runner wiring (and correcting how Connect-NRGServices
            # derives TenantDomain) is a separate follow-up.
            $sspClient = if ($TenantDomain) { $TenantDomain } else { [string]$reportMetadata.TenantDomain }
            $sspAnswerSet = if ($SSPAnswers) {
                Get-NRGSSPAnswers -Path $SSPAnswers
            } else {
                Get-NRGSSPAnswers -ClientName $sspClient
            }
            $sspPosture = Get-NRGSSPPosture -Findings $findings -Answers $sspAnswerSet
            Publish-NRGSSP -Posture $sspPosture -Metadata $reportMetadata -Answers $sspAnswerSet `
                -OutputPath $sspPath -ClientName $sspClient
            Write-NRGReportFile 'SSP (md)' $sspPath
            Set-NRGSensitiveFileAcl -Path $sspPath -ErrorAction SilentlyContinue
            foreach ($ext in @('.html', '.xlsx')) {
                $side = [System.IO.Path]::ChangeExtension($sspPath, $ext)
                if (Test-Path -LiteralPath $side) {
                    Write-NRGReportFile "SSP ($($ext.TrimStart('.')))" $side
                    Set-NRGSensitiveFileAcl -Path $side -ErrorAction SilentlyContinue
                }
            }
            # The count of unanswered requirements is the number that decides
            # whether this plan can be signed, so it is said at the console
            # rather than left for someone to find on page forty.
            $openCount = @($sspPosture['Requirements'] | Where-Object {
                $_['MappedControls'] -eq 0 -and -not $_['Narrative'] -and $_['StatusSource'] -eq 'None'
            }).Count
            if ($openCount -gt 0) {
                Write-Host "      $openCount of 110 requirements still need a written answer — see 'Still to answer'." -ForegroundColor Yellow
            }
        } catch { Write-Warning "SSP publish failed: $($_.Exception.Message)" }
    }

    # SSP questionnaire — the manual-evidence half of the SSP, as a document a
    # client fills in and sends back. Its own opt-in switch, deliberately NOT
    # implied by -AllFiles: unlike the SSP itself, this is a document meant to
    # leave the building, not a routine artifact to regenerate on every run.
    if ($SSPQuestionnaire -and (Get-Command Publish-NRGSSPQuestionnaire -ErrorAction SilentlyContinue)) {
        $sspqPath = Join-Path $OutputPath "$baseName-ssp-questionnaire.md"
        try {
            # Reuses the same posture/answers/client resolution as -SSP above
            # when that switch was also passed this run; computed fresh
            # otherwise so -SSPQuestionnaire works standalone.
            $sspqClient = if ($TenantDomain) { $TenantDomain } else { [string]$reportMetadata.TenantDomain }
            $sspqAnswerSet = if ($SSPAnswers) {
                Get-NRGSSPAnswers -Path $SSPAnswers
            } else {
                Get-NRGSSPAnswers -ClientName $sspqClient
            }
            $sspqPosture = Get-NRGSSPPosture -Findings $findings -Answers $sspqAnswerSet
            Publish-NRGSSPQuestionnaire -Posture $sspqPosture -Metadata $reportMetadata `
                -OutputPath $sspqPath -ClientName $sspqClient -Family $SSPQuestionnaireFamily
            Write-NRGReportFile 'SSP questionnaire (md)' $sspqPath
            Set-NRGSensitiveFileAcl -Path $sspqPath -ErrorAction SilentlyContinue
            foreach ($ext in @('.html', '.pdf', '.manifest.json')) {
                $side = [System.IO.Path]::ChangeExtension($sspqPath, $ext)
                if (Test-Path -LiteralPath $side) {
                    Write-NRGReportFile "SSP questionnaire ($($ext.TrimStart('.')))" $side
                    Set-NRGSensitiveFileAcl -Path $side -ErrorAction SilentlyContinue
                }
            }
        } catch { Write-Warning "SSP questionnaire publish failed: $($_.Exception.Message)" }
    }

    # Manual-review questionnaire — the controls.json counterpart to the SSP
    # questionnaire above, for the controls Get-NRGAssessmentScope classifies
    # as NoProgrammaticCheck or CollectionIncomplete. Same opt-in shape, same
    # reason it is not implied by -AllFiles.
    if ($ManualReviewQuestionnaire -and (Get-Command Publish-NRGManualReviewQuestionnaire -ErrorAction SilentlyContinue)) {
        $mrqPath = Join-Path $OutputPath "$baseName-manual-review.md"
        try {
            $mrqClient = if ($TenantDomain) { $TenantDomain } else { [string]$reportMetadata.TenantDomain }
            $mrqAnswerSet = Get-NRGManualReviewAnswers -ClientName $mrqClient
            $mrqScope = Get-NRGAssessmentScope -Findings $findings
            Publish-NRGManualReviewQuestionnaire -Scope $mrqScope -Answers $mrqAnswerSet -Metadata $reportMetadata `
                -OutputPath $mrqPath -ClientName $mrqClient -Workload $ManualReviewWorkload
            Write-NRGReportFile 'Manual review questionnaire (md)' $mrqPath
            Set-NRGSensitiveFileAcl -Path $mrqPath -ErrorAction SilentlyContinue
            foreach ($ext in @('.html', '.pdf', '.manifest.json')) {
                $side = [System.IO.Path]::ChangeExtension($mrqPath, $ext)
                if (Test-Path -LiteralPath $side) {
                    Write-NRGReportFile "Manual review questionnaire ($($ext.TrimStart('.')))" $side
                    Set-NRGSensitiveFileAcl -Path $side -ErrorAction SilentlyContinue
                }
            }
        } catch { Write-Warning "Manual review questionnaire publish failed: $($_.Exception.Message)" }
    }

    # NIST 800-53 improvement plan. Same shape as the two above: its own switch
    # so it can be produced without every other sidecar, implied by -AllFiles.
    if (($ImprovementPlan -or $AllFiles) -and (Get-Command Publish-NRGImprovementPlan -ErrorAction SilentlyContinue)) {
        $planPath = Join-Path $OutputPath "$baseName-nist-improvement-plan.md"
        try {
            # Resolved here rather than inside the plan so a tenant whose SKU
            # query failed is treated as "no license data" — every gated
            # control lands in Buy first rather than being promised as a quick
            # win the tenant cannot actually action.
            $planLicense = if (Get-Command Get-NRGTenantLicenseProfile -ErrorAction SilentlyContinue) {
                try { Get-NRGTenantLicenseProfile } catch { $null }
            } else { $null }

            $plan = Get-NRGNISTImprovementPlan -Findings $findings -LicenseProfile $planLicense
            if ($plan['Available']) {
                Publish-NRGImprovementPlan -Plan $plan -Metadata $reportMetadata `
                    -OutputPath $planPath -ClientName ([string]$reportMetadata.TenantDomain)
                Write-NRGReportFile 'NIST improvement plan (md)' $planPath
                Set-NRGSensitiveFileAcl -Path $planPath -ErrorAction SilentlyContinue
                $planHtml = [System.IO.Path]::ChangeExtension($planPath, '.html')
                if (Test-Path -LiteralPath $planHtml) {
                    Write-NRGReportFile 'NIST improvement plan (html)' $planHtml
                    Set-NRGSensitiveFileAcl -Path $planHtml -ErrorAction SilentlyContinue
                }
                Write-Host "      NIST coverage $($plan['Baseline']['Score'])% -> $($plan['Projected']['Score'])% across $($plan['Projected']['StepCount']) steps." -ForegroundColor Cyan
            } else {
                Write-Warning 'No NIST-cited findings to plan against — improvement plan skipped.'
            }
        } catch { Write-Warning "Improvement plan publish failed: $($_.Exception.Message)" }
    }

    # Multi-page report site (landing page, one page per workload, ActionPlan.csv):
    # observed configuration, the NRG baseline verdict and the independent comparison
    # kept apart. A VIEW over the findings: it changes no verdict. Written with every
    # run that writes reports, into its own folder beside the other files.
    if (-not $SkipReportSite -and (Get-Command Publish-NRGReportSite -ErrorAction SilentlyContinue)) {
        $siteDir = Join-Path $OutputPath "$baseName-report"
        try {
            $null = Publish-NRGReportSite -Metadata $reportMetadata -Findings $findings -OutputPath $siteDir `
                -BaselineCompliance $baselineCompliance -Coverage (Get-NRGCoverage) -ScubaResultsPath $ScubaResultsPath
            Write-NRGReportFile 'Report site (index.html)' (Join-Path $siteDir 'index.html')
            Write-NRGReportFile 'Action plan (csv)' (Join-Path $siteDir 'ActionPlan.csv')
            foreach ($f in @(Get-ChildItem -LiteralPath $siteDir -File -ErrorAction SilentlyContinue)) {
                Set-NRGSensitiveFileAcl -Path $f.FullName -ErrorAction SilentlyContinue
            }
        } catch { Write-Warning "Report site publish failed: $($_.Exception.Message)" }
    }

    # Delta report (if baseline provided)
    if ($BaselineResults -and (Test-Path -LiteralPath $BaselineResults) -and (Get-Command Publish-NRGDeltaReport -ErrorAction SilentlyContinue)) {
        $deltaPath = Join-Path $OutputPath "$baseName-delta.md"
        try {
            Publish-NRGDeltaReport -CurrentFindings $findings -CurrentRawData $rawDataSnapshot -BaselineResultsPath $BaselineResults `
                -Metadata $reportMetadata -OutputPath $deltaPath
            Write-NRGReportFile 'Delta' $deltaPath
            Set-NRGSensitiveFileAcl -Path $deltaPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "Delta publish failed: $($_.Exception.Message)" }
    }

    # Monthly compliance report (v4.11.0) — recurring MSP deliverable, HIPAA-framed.
    # Driven by an operator-maintained delta file (-MonthlyDeltaPath). The output
    # JSON file is intended to become the next month's -MonthlyPriorPath input.
    if ($MonthlyReport) {
        if (-not $MonthlyDeltaPath) {
            Write-Warning "-MonthlyReport requires -MonthlyDeltaPath <path-to-delta.psd1>; skipping monthly report."
        }
        elseif (Get-Command Publish-NRGMonthlyReport -ErrorAction SilentlyContinue) {
            $monthlyDir  = Join-Path $OutputPath 'monthly'
            $deltaBase   = [IO.Path]::GetFileNameWithoutExtension($MonthlyDeltaPath)
            $monthlyPath = Join-Path $monthlyDir "$deltaBase.html"
            try {
                Publish-NRGMonthlyReport `
                    -Findings $findings `
                    -Metadata $reportMetadata `
                    -DeltaPath $MonthlyDeltaPath `
                    -PriorMonthPath $MonthlyPriorPath `
                    -OutputPath $monthlyPath | Out-Null
                Set-NRGSensitiveFileAcl -Path $monthlyPath -ErrorAction SilentlyContinue
                Set-NRGSensitiveFileAcl -Path ($monthlyPath -replace '\.html$', '.json') -ErrorAction SilentlyContinue
            } catch { Write-Warning "Monthly report publish failed: $($_.Exception.Message)" }
        }
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────
# Error state is surfaced explicitly so an operator sees collector-failure
# counts as a distinct bucket from Gap (a real posture issue).
#
# v4.10.1: counts now pulled from $reportMetadata['Maturity'] when available
# (single source of truth with the maturity badge and CI thresholds). The
# Maturity helper computed Sat/Partial/Gap/NA/Error in one pass at line 583;
# re-deriving them here with 5x Where-Object was wasted work AND meant a
# future change to the counter rule (e.g., excluding Error from Gap counts)
# would silently split into two answers. Falls back to one canonical
# Get-NRGCoverageScore call when Maturity is unavailable (helper threw, or
# a -FromResults baseline pre-dating v4.10.1) — banner always renders.
$s = if ($reportMetadata.Contains('Maturity') -and $reportMetadata['Maturity']) {
    $m = $reportMetadata['Maturity']
    @{
        Satisfied = $m.Satisfied
        Partial   = $m.Partial
        Gap       = $m.Gap
        NA        = $m.NotApplicable
        Error     = $m.ErrorFindings
    }
} else {
    $cov = Get-NRGCoverageScore -Findings $findings -ErrorHandling 'Gap'
    @{
        Satisfied = $cov.Satisfied
        Partial   = $cov.Partial
        Gap       = $cov.Gap
        NA        = $cov.NA
        Error     = $cov.Error
    }
}

# Footer version + control count read at runtime so a stale hardcoded value
# never ships in the operator output. Falls back to the count of findings the
# evaluators actually emitted this run rather than guessing at "total controls
# defined in controls.json" which can drift from baseline coverage.
$footerVer    = if ($NRGAssessmentVersion)   { $NRGAssessmentVersion }   else { $script:NRGAssessmentVersion }
# Controls, not findings: DNS and the named-object checks report once per
# domain or object, so the finding count (249 on a live tenant) is larger than
# the per-control counts above (239), which never added up to "Total".
$footerCount  = [int]$s.Satisfied + [int]$s.Partial + [int]$s.Gap + [int]$s.NA + [int]$s.Error

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Assessment Complete (v$footerVer)"                                  -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Satisfied      $($s.Satisfied)"                                  -ForegroundColor Green
Write-Host "  Partial        $($s.Partial)"                                    -ForegroundColor Yellow
Write-Host "  Gap            $($s.Gap)"                                        -ForegroundColor Red
if ($s.Gap -gt 0) {
    try {
        $gs = Get-NRGGapSummary -Findings $findings
        Write-Host "                 = $($gs.DistinctDeficiencies) distinct requirement(s) + $(@($gs.NamedViews).Count) named-object view(s) of a control that already reports the shortfall; $($gs.FoldedControls) more control(s) share a setting and are already counted once" -ForegroundColor DarkGray
    } catch { Write-Verbose "Gap summary skipped: $($_.Exception.Message)" }
}
Write-Host "  Not Applicable $($s.NA)"                                         -ForegroundColor DarkGray
if ($s.Error -gt 0) {
    Write-Host "  Error          $($s.Error) (collector failures — excluded from score)" -ForegroundColor Magenta
}
# Controls that read the same setting count once (Config/control-links.json),
# so the scored total can be below the number of distinct controls reported.
$distinctControls = @($findings | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'ControlId' -Default '') } | Where-Object { $_ } | Sort-Object -Unique).Count
$notes = @()
if ($distinctControls -gt $footerCount) { $notes += "$distinctControls controls reported; controls that read the same setting count once" }
if ($findings.Count -gt $distinctControls) { $notes += "$($findings.Count) findings: some controls report once per domain or object" }
$perInstance = if ($notes.Count -gt 0) { " ($($notes -join '; '))" } else { '' }
Write-Host "  Total          $footerCount scored$perInstance"                  -ForegroundColor White
Write-Host "  Output         $OutputPath"                                      -ForegroundColor White
if ($reportMetadata.Contains('Maturity') -and $reportMetadata['Maturity']) {
    $m = $reportMetadata['Maturity']
    Write-Host "  Maturity       $($m.Label) (tier $($m.Tier)/5, score $($m.Score)/100)" -ForegroundColor Cyan
} elseif ($reportMetadata.Contains('MaturityError')) {
    Write-Host "  Maturity       unavailable ($($reportMetadata['MaturityError']))" -ForegroundColor Yellow
}
Write-Host ""

# ── Threshold exit codes (CI / automation) ────────────────────────────────────
# Opt-in policy gate (default 0 = disabled). Reads pre-computed counts from
# $reportMetadata['Maturity'] so the badge in the report and the threshold the
# CI fires on can never disagree — the older inline `Where-Object` re-derivation
# meant a future change to the maturity counter rule (e.g., excluding Error
# from Gap counts) would silently split into two answers.
#
# Threshold codes (10/11/12) land on $script:NRGThresholdExitCode — a separate
# channel from $script:NRGFatalExitCode (1=auth, 4=fatal). This preserves the
# disambiguation between "graceful policy breach, all reports on disk" and
# "orchestrator crashed mid-publish": the final exit-resolution block at the
# bottom of this script gives fatal precedence over threshold, threshold
# precedence over success.
#
# Fail-closed when Maturity is unavailable: ALL three FailOn flags emit the
# loud INOPERATIVE warning, not just FailOnScoreBelow. The earlier version
# silently defaulted gap counts to 0 when $mat was null, which silently let
# every FailOnCritical/FailOnHigh-gated tenant exit 0 if the Maturity helper
# ever threw. CI operators must get a loud signal when their gate is
# inoperative — silent fail-open is the worst possible failure mode for a
# policy enforcement check.
#
# Zero-findings runs (collection failed, all evaluators returned nothing) also
# skip the threshold check entirely — the run already exits 2 ("no findings"),
# and a derived "score=0" should not be re-interpreted as a posture failure.
# A baseline-tampered -FromResults with a "real" zero is still caught by the
# -FromResults + -FailOn* combination warning below.
if ($FailOnCritical -gt 0 -or $FailOnHigh -gt 0 -or $FailOnScoreBelow -gt 0) {

    # Warn loudly when -FromResults is combined with any -FailOn* — the gate
    # then evaluates against a baseline FILE, not the live tenant. A baseline
    # JSON with every State='Satisfied' would silently pass any CI gate. We
    # already reject -Quick + -FromResults the same way upstream.
    if ($skipCollection) {
        Write-Warning "-FailOnCritical / -FailOnHigh / -FailOnScoreBelow combined with -FromResults: CI gate is evaluated against the baseline JSON, not the live tenant. If the baseline file has been modified, the gate's verdict reflects the file — not current posture. Re-run against the live tenant for an authoritative gate."
    }

    $mat = if ($reportMetadata.Contains('Maturity')) { $reportMetadata['Maturity'] } else { $null }

    if ($findings.Count -eq 0) {
        Write-Warning "Threshold check skipped: 0 findings evaluated. The run will exit 2 ('no findings'); a zero-score derived from an empty findings stream would mislead a posture check."
    }
    elseif (-not $mat) {
        Write-Warning "Threshold check INOPERATIVE: Maturity classification unavailable, so CriticalGaps/HighGaps/Score cannot be read. Investigate the maturity warning above. The -FailOn* gate did NOT run for this assessment — do not treat a clean exit as policy compliance."
    }
    else {
        $critGaps = [int]$mat.CriticalGaps
        $highGaps = [int]$mat.HighGaps

        if ($FailOnCritical -gt 0 -and $critGaps -ge $FailOnCritical) {
            Write-Host "[!] Threshold breached: $critGaps Critical gaps (limit $FailOnCritical) — exiting 10" -ForegroundColor Red
            $script:NRGThresholdExitCode = 10
        }
        elseif ($FailOnHigh -gt 0 -and $highGaps -ge $FailOnHigh) {
            Write-Host "[!] Threshold breached: $highGaps High gaps (limit $FailOnHigh) — exiting 11" -ForegroundColor Red
            $script:NRGThresholdExitCode = 11
        }
        elseif ($FailOnScoreBelow -gt 0) {
            if ($mat.Contains('Score') -and $null -ne $mat.Score) {
                $maturityScore = [int]$mat.Score
                if ($maturityScore -lt $FailOnScoreBelow) {
                    Write-Host "[!] Threshold breached: score $maturityScore < $FailOnScoreBelow — exiting 12" -ForegroundColor Red
                    $script:NRGThresholdExitCode = 12
                }
            } else {
                Write-Warning "-FailOnScoreBelow $FailOnScoreBelow is set but Maturity.Score is missing/null — skipping. CI gate is INOPERATIVE for this run."
            }
        }
    }
}

# ── Exit-code spec (v4.6.3 P2) ────────────────────────────────────────────────
# CLAUDE.md declares: 0 success, 1 auth failure, 2 no findings, 3 partial
# collection, 4 fatal. Previously only exit 1 (module-load failure) was
# wired. This block computes the right code based on counters set above.
$collectorExceptions = @(Get-NRGExceptions)
if ($findings.Count -eq 0) {
    $script:NRGSuccessExitCode = 2
} elseif ($collectorExceptions.Count -gt 0) {
    # Partial collection: at least one collector raised, but some findings made it.
    $script:NRGSuccessExitCode = 3
} else {
    $script:NRGSuccessExitCode = 0
}

}
catch {
    # Outer fatal-error catch (v4.6.3 P2).
    # $script:NRGFatalExitCode may have been pre-set by an earlier explicit
    # condition (auth failure = 1); otherwise fall through to 4 (fatal).
    if (-not $script:NRGFatalExitCode) { $script:NRGFatalExitCode = 4 }
    Write-Host ""
    Write-Host "[!] Assessment failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ScriptStackTrace) {
        Write-Host "    Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    }
}
finally {
    # ── Disconnect on success or error ────────────────────────────────────────
    # -KeepSession (see param docs above) leaves a GDAP batch session intact
    # for the next client instead of tearing it down after every run.
    if (-not $skipCollection -and -not $KeepSession) {
        try { Disconnect-NRGServices } catch { }
    }
}

# Resolve and emit the exit code (must be done OUTSIDE the try/catch/finally
# so the exit happens after the disconnect runs).
# Precedence: fatal (auth/crash) > threshold (policy gate) > success.
# Threshold only applies when no fatal error occurred — a crash that happens
# to leave a threshold value set must not masquerade as a graceful breach.
if ($script:NRGFatalExitCode) {
    exit $script:NRGFatalExitCode
}
if ($script:NRGThresholdExitCode) {
    exit $script:NRGThresholdExitCode
}
if ($null -ne $script:NRGSuccessExitCode) {
    exit $script:NRGSuccessExitCode
}
exit 0
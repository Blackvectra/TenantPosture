#Requires -Version 7.0
#
# Invoke-TPAssessment.ps1
# Entry point for TenantPosture (version read from module manifest at runtime)
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# Flow:
#   1. Import module (loads Lib, Collectors, Evaluators, Publishers)
#   2. Connect to M365 services
#   3. Run collectors -> raw data stored in module state
#   4. Run evaluators -> findings registered via Add-TPFinding
#   5. Run publishers -> HTML, Markdown, JSON, XLSX, Playbook, Remediation script
#
# Usage:
#   .\Invoke-TPAssessment.ps1 -UserPrincipalName admin@client.com
#   .\Invoke-TPAssessment.ps1 -AppId <guid> -TenantId <guid> -CertificateThumbprint <40hex> -OrganizationDomain contoso.onmicrosoft.com
#

[CmdletBinding()]
param(
    # OWASP ASVS V5.1.3 — UPN must match standard email format before reaching auth
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$|^$')]
    [string] $UserPrincipalName,
    [string] $OutputPath,

    # App-only / certificate authentication for unattended runs. ValidatePattern
    # at the entry point per OWASP ASVS V5.1.3 — defense-in-depth even though
    # Connect-TPServices re-validates. Catches malformed input (newlines, null
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
    # The pattern is Get-TPDomainNamePattern (Lib/Test-TPDomainName.ps1), the
    # one definition of a domain name the web GUI's scan route and run listing
    # use too; a parameter attribute binds before any module loads, so it is a
    # copy and TP.WebServer.Tests.ps1 fails if the two differ. Options = None
    # makes it case-sensitive (the default admits the Kelvin sign as a letter).
    [ValidatePattern('\A\z|\A(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\z', Options = 'None')]
    [string] $TenantDomain,

    # The clients file this run reads the client's record from (declared EDR and awareness
    # products, monitoring addresses, baseline tier, opt-in collectors, routing domain, onboarding).
    # Default: Config/clients.json beside this script. The batch runner passes the file it was
    # given, so one file serves the whole batch. Read only together with -TenantDomain; a file that
    # is missing or is not valid JSON stops the run (exit 4) before anything connects, because a
    # run that quietly read no record would lose every declaration in it.
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[/\\]' -or $_ -match '[/\\]\.\.' -or $_ -match '^\.\.') {
            throw "Path traversal not allowed in ClientsFile."
        }
        return $true
    })]
    [string] $ClientsFile,

    # The client's endpoint protection is a third-party EDR (e.g. 'Cortex XDR'),
    # not Microsoft Defender. The Defender endpoint checks (INT-1.5, INT-2.1,
    # INT-2.2, DEV-2.x) are then reported as covered by that product —
    # declared, not verified — and excluded from the score instead of scoring
    # as gaps. Also read from the client's ThirdPartyEDR field in
    # Config/clients.json when -TenantDomain is given.
    [ValidatePattern('^$|^[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}$')]
    [string] $ThirdPartyEDR,

    # The client's phishing simulation and security awareness training run on
    # a third-party platform (e.g. 'KnowBe4'), not Microsoft Attack Simulation
    # Training. DEF-4.6 is then reported as run on that platform — declared,
    # not verified — and excluded from the score instead of scoring as a gap
    # or a license upgrade. Also read from the client's ThirdPartyAwareness
    # field in Config/clients.json, then AwarenessStack in the active profile.
    [ValidatePattern('^$|^[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}$')]
    [string] $ThirdPartyAwareness,

    # The NRG monitoring address(es) alert policies should notify (an address,
    # or @domain for a whole domain). DEF-3.4 and EXO-3.3 compare each enabled
    # policy's recipients with this list; without one, "alerts reach NRG" is
    # not assessed (the recipients-exist half still is). Also read from the
    # client's MonitoringAddresses in Config/clients.json, then from
    # MonitoringAddresses in the active profile.
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
    # mapped result beside the NRG control as a separate standard, never as a score,
    # and the -BOD2501 view shows it beside each required configuration.
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
    # When -MonthlyReport is set, Publish-TPMonthlyReport emits a recurring
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
    # remediation .ps1, XLSX matrix, delta, NIST matrix, SSP, HIPAA readiness,
    # BOD 25-01 view).
    # Batch mode passes this for parity.
    # -JsonOnly emits only the JSON (unchanged).
    [switch] $AllFiles,

    # Folder of endpoint results written by Device\Invoke-TPDeviceCompliance.ps1
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
    # No default here: the active profile's DefaultFramework decides (the NRG
    # profile says NIST, NLS and the neutral default say All). Resolved after
    # the module loads.
    [ValidateSet('NIST','CIS','SCuBA','CMMC','All')]
    [string] $Framework,

    # The profile to run with: Config/profiles/<name>.psd1 (company, colors,
    # default framework, DMARC reporting address, declared EDR and awareness
    # platforms). Without it, Config/branding.psd1. Same as TP_PROFILE in the
    # environment, which every entry point reads.
    [ValidatePattern('\A(?:|[a-z0-9][a-z0-9-]{0,31})\z', Options = 'None')]
    [string] $Profile,

    # The NRG Security Baseline tier this client is held to
    # (Config/tp-baseline.json). Tiers are cumulative: Standard requires
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

    # HIPAA Security Rule readiness (45 CFR 164 Subpart C): every standard and
    # implementation specification, Required or Addressable, with what this
    # assessment evidenced for it and what needs documents, interviews or a
    # walkthrough. Not a risk analysis and not a compliance determination; the
    # report says so on page one. Markdown + HTML. Implied by -AllFiles.
    # Also writes the client-facing HIPAA report (<base>-hipaa-report.html):
    # what was verified in Microsoft 365, what needs attention, what could not
    # be checked, and the documentation checklist; a PDF of it with -Pdf. Not
    # written from a partial or quick run.
    [switch] $HIPAA,

    # Also write a PDF of the client-facing HIPAA report, printed by the
    # Microsoft Edge (or Chrome) already on this computer, headless. When no
    # browser can print it, the run says so and the HTML prints to PDF from any
    # browser. Use with -HIPAA (or -AllFiles).
    [switch] $Pdf,

    # The client name printed on client-facing reports. Default: ClientName from
    # Config/clients.json for -TenantDomain, else the tenant domain.
    [ValidateLength(0, 120)]
    [string] $ClientName,

    # CISA BOD 25-01 required-configurations view: every Microsoft 365 policy
    # CISA lists as required (Config/bod-25-01-required.json), what this
    # assessment's checks found for it, what they do not check, and the
    # independent ScubaGear result beside it when -ScubaResultsPath is given.
    # A technical readiness view for government clients, not an attestation;
    # the report says so on page one. Markdown + HTML. Implied by -AllFiles.
    [switch] $BOD2501,

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
    # assessment. See Import-TPSSPQuestionnaire.ps1 for the return half.
    [switch] $SSPQuestionnaire,

    # Restrict the questionnaire to one 800-171 family (e.g. '3.9' for
    # Personnel Security), so it can go to the person who actually owns that
    # domain instead of everyone getting all 110 requirements at once.
    [ValidateNotNullOrEmpty()]
    [string] $SSPQuestionnaireFamily,

    # Fillable client questionnaire for the controls.json controls this run
    # could not evaluate on its own — Get-TPAssessmentScope's
    # NoProgrammaticCheck (no automated test exists, or the check could not
    # reach a verdict) and CollectionIncomplete (data did not collect this
    # run) buckets. The controls.json counterpart
    # to -SSPQuestionnaire; a separate document because a controls.json
    # ControlId and a NIST 800-171 requirement id are different catalogs.
    # NOT implied by -AllFiles, for the same reason -SSPQuestionnaire isn't.
    # See Import-TPManualReviewQuestionnaire.ps1 for the return half.
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

    # The new-client onboarding report: an executive one-pager, what is working,
    # what needs attention, a 30/60/90-day plan built from the operational-impact
    # effort classes and the license gate, and the coming Microsoft changes when
    # Config/microsoft-changes.json exists. HTML + Markdown. Covers the whole
    # tenant, so it is refused on a partial (-ControlId) run. Implied by -AllFiles
    # (and then skipped, with a note, on a partial or quick run).
    [switch] $OnboardingReport,

    # Change impact: the open findings sorted into what can be fixed now, what
    # needs planning, and what could break accounts, naming the accounts the
    # run's data shows each risky change would affect (legacy-client sign-ins,
    # accounts with no MFA method, admins without a phishing-resistant method,
    # forwarding and SMTP AUTH mailboxes, users of non-compliant devices) and
    # the emergency-access accounts to exclude. HTML + Markdown
    # (<base>-change-impact.*). The view itself is always in the results JSON.
    # Implied by -AllFiles.
    [switch] $ChangeImpact,

    # Conditional Access checklist, the way Maester checks it: is each policy
    # Microsoft recommends in place and turned on, are the existing policies set
    # up safely (break-glass exclusions, sync accounts, deleted objects, unprotected
    # groups, exclusions with no fallback), and what Entra's What If evaluation
    # says for a sample of real accounts. Writes <base>-ca-checklist.html / .md
    # and, for each recommended policy that is missing, a report-only policy file
    # in <base>-ca-policies\ for an administrator to review and import (the tool
    # creates nothing). The view itself is always in the results JSON. Implied by
    # -AllFiles.
    [switch] $CAChecklist,

    # Skip the Conditional Access What If simulation (Microsoft's evaluate
    # action, the tool's one POST; see Lib/Invoke-TPCAWhatIf.ps1). The checklist's
    # simulation rows then read "Not assessed".
    [switch] $SkipCAWhatIf,

    # Intune and endpoint checklist, the way Maester checks it: Intune tenant
    # settings, iOS / Android / macOS compliance policies, the standard
    # protection ASR rules, Windows LAPS and Defender Antivirus values, each with
    # what to set when it is not met. Writes <base>-intune-checklist.html / .md;
    # the view itself is always in the results JSON. Implied by -AllFiles.
    [switch] $IntuneChecklist,

    # Proof of fix: after this run, compare it with an earlier results file of the
    # SAME tenant and write a remediation certificate (<tenant>-proof-<time>.html
    # and .md) listing, for each control this run covered, the state before and
    # after and whether it was resolved. The natural pairing is a -ControlId
    # re-check after fixing. The file is checked before anything signs in; a
    # different tenant or an older run is refused. See New-TPRemediationProof.ps1
    # to build one from two saved files.
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in ProofAgainst." }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "ProofAgainst file not found: $_" }
        return $true
    })]
    [string] $ProofAgainst,

    # The distribution-list scan. Signs in to Exchange Online ONLY (no Graph, Purview, Teams or
    # SharePoint), lists every distribution list with its members, settings and who can reach it
    # (including the tenant-wide filtering bypasses that let mail past spam filtering), compares
    # each setting with a cited recommendation, and writes <tenant>-<time>-distribution-lists.txt
    # and .csv for an administrator to harden the lists. READ-ONLY: it never creates, adds,
    # removes or changes a user, group, rule or setting; the commands in the worksheet are text a
    # human runs. Every other area is not assessed and the worksheet says so. Reuses -UserPrincipalName,
    # -TenantDomain, and the app-only parameters; -OutputPath applies. Not implied by -AllFiles.
    [switch] $DistributionListsOnly,

    # Members read per list in the distribution-list scan. A larger list is reported as "more than N",
    # never as complete.
    [ValidateRange(1, 50000)]
    [int] $MaxMembersPerList = 500,

    # Lists read in one distribution-list scan; a tenant with more is reported as truncated.
    [ValidateRange(1, 100000)]
    [int] $MaxLists = 5000,

    [switch] $WhatIfConnections,

    # GDAP batch mode establishes ONE Graph/EXO/Teams/IPPS session meant to be
    # reused across every client in Config/clients.json (see
    # Connect-TPServices.ps1's reuseGraphContext / reuseExoSession logic).
    # This orchestrator's own finally block otherwise always calls
    # Disconnect-TPServices, tearing the shared session down after EVERY
    # client — the next client's Connect-MgGraph then has to reconnect with
    # no -TenantId and can silently land back in the operator's home tenant.
    # Pass -KeepSession to skip the disconnect and leave the shared session
    # intact for the next client. Invoke-TPBatchAssessment.ps1 passes it on
    # every client and disconnects the per-client Exchange, Security &
    # Compliance and Teams sessions itself; it closes Graph after the loop.
    [switch] $KeepSession,

    # Launch the local web GUI instead of running a scan in the terminal.
    # The GUI is a local Pode-backed server (loopback only, never exposed
    # to the network) that lets the operator pick a tenant, trigger scans,
    # watch progress, and view reports in a browser. See Lib/Start-TPWebServer.ps1
    # and Web/. No tenant data leaves the workstation.
    [switch] $Web,

    # Port for the -Web GUI loopback server. Default avoids common collisions.
    [ValidateRange(1024, 65535)]
    [int] $WebPort = 8765,

    # ── Control selection (a partial run) ───────────────────────────────────
    # Assess only the controls whose ControlId matches one of these wildcard
    # patterns (-like, case-insensitive), e.g. -ControlId EXO-1.6 to re-check
    # one fix, 'AAD-*' for a workload, or AAD-1.2,AAD-1.3,'SPO-5.*'. Only the
    # evaluators of those controls run, only the collectors they read, and only
    # the services those collectors need are signed in to (Graph always: the
    # license profile and tenant metadata come from it). A pattern that matches
    # nothing, or a selection left empty by -ExcludeControlId, stops the run
    # (exit 4) before any sign-in. Every report says the run was partial; the
    # controls not selected are "not assessed: not selected", never a pass.
    # The pattern rule is Get-TPControlIdPatternRule (Lib/Resolve-TPControlSelection.ps1);
    # a parameter attribute binds before any module loads, so this is a copy
    # TP.ControlSelection.Tests.ps1 pins equal. Options = None: case-sensitive,
    # so the Kelvin sign is not a letter.
    [ValidatePattern('\A[A-Za-z0-9.*?-]{1,40}\z', Options = 'None')]
    [string[]] $ControlId,

    # Controls to leave out of the run, by the same wildcard rule. With no
    # -ControlId, every control except these is assessed.
    [ValidatePattern('\A[A-Za-z0-9.*?-]{1,40}\z', Options = 'None')]
    [string[]] $ExcludeControlId,

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
$script:TPFatalExitCode     = $null
$script:TPSuccessExitCode   = $null
$script:TPThresholdExitCode = $null

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
$script:TPAssessmentVersion = 'unknown'
try {
    $manifestData = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptDir 'TenantPosture.psd1') -ErrorAction Stop
    if ($manifestData.ModuleVersion) { $script:TPAssessmentVersion = [string]$manifestData.ModuleVersion }
} catch { }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " TenantPosture v$($script:TPAssessmentVersion) — Read-Only M365 Security Assessment" -ForegroundColor Cyan
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
# Testing/TP.Security.Tests.ps1:106-110, which enforces that any future
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
Write-Host "[-] Loading TenantPosture module..." -ForegroundColor Cyan
$manifestPath = Join-Path $scriptDir 'TenantPosture.psd1'
# The profile name is resolved by the one resolver the module itself uses, BEFORE the
# import: a name that is not a profile is fatal (exit 4), never a quiet fallback to
# the neutral defaults, which would run a different practice than the one asked for.
. (Join-Path $scriptDir 'Lib' 'Resolve-TPProfilePath.ps1')
$wantedProfile = if ($Profile) { $Profile } else { [string]$env:TP_PROFILE }
$profileCheck = Resolve-TPProfilePath -Root $scriptDir -Name $wantedProfile
if ($profileCheck.Status -in @('BadName', 'NotFound')) {
    Write-Host "  [!] Profile '$wantedProfile': $($profileCheck.Message)" -ForegroundColor Red
    exit 4
}
# TP_PROFILE is the module's only way to learn the profile, and the import reads it once.
# It is set for the import and put back afterwards, so a later run in the same console
# without -Profile does not silently keep this run's practice.
# The clients file is checked here too, before anything connects. A file named with -ClientsFile that
# is missing or unreadable is fatal (exit 4); the default Config/clients.json is allowed to be absent
# (a first run has none), but one that exists and cannot be read is said so, not skipped.
. (Join-Path $scriptDir 'Lib' 'Get-TPClientRecord.ps1')
$clientsPath = if ($ClientsFile) { [System.IO.Path]::GetFullPath($ClientsFile) } else { Join-Path $scriptDir 'Config' 'clients.json' }
$clientLookup = $null
if ($ClientsFile -and -not $TenantDomain) {
    Write-Host "  [!] -ClientsFile is read together with -TenantDomain, which names the client; without it the file is not used." -ForegroundColor Yellow
}
if ($TenantDomain) {
    $clientLookup = Get-TPClientRecord -Path $clientsPath -TenantDomain $TenantDomain
    # -RegisterApp may name a file that does not exist yet (onboarding creates it); every other run needs the file to be there.
    if ($ClientsFile -and ($clientLookup.Status -eq 'Unreadable' -or ($clientLookup.Status -eq 'NoFile' -and -not $RegisterApp))) {
        Write-Host "  [!] $($clientLookup.Message) Nothing was run." -ForegroundColor Red
        exit 4
    }
    if (-not $ClientsFile -and $clientLookup.Status -eq 'Unreadable') {
        Write-Host "  [!] $($clientLookup.Message) It is ignored for this run, so no declared EDR, awareness product or other client setting in it applies." -ForegroundColor Yellow
    }
}
$profileEnvBefore = $env:TP_PROFILE
if ($Profile) { $env:TP_PROFILE = $Profile }
try {
    try {
        Import-Module $manifestPath -Force -ErrorAction Stop
    } finally {
        if ($Profile) {
            if ($null -eq $profileEnvBefore) { Remove-Item -LiteralPath Env:TP_PROFILE -ErrorAction SilentlyContinue }
            else { $env:TP_PROFILE = $profileEnvBefore }
        }
    }
    Write-Host "  [+] Module loaded (v$($TPAssessmentVersion); profile $($TPBrand['ProfileName']))" -ForegroundColor Green
    # The results JSON holds tenant data and is written only where the signed-in
    # user, SYSTEM and Administrators alone can read it. A folder that cannot hold
    # that protection (an exFAT or FAT32 drive, some shares) is refused HERE, before
    # any sign-in: the 2026-10-15 live run on such a drive ended at the results
    # write, after six minutes of collection, with nothing written.
    # -RegisterApp and -WhatIfConnections write nothing under -OutputPath, so an
    # unprotectable folder must not stop onboarding or a connection diagnosis.
    if (-not $RegisterApp -and -not $WhatIfConnections) {
        try { $null = Test-TPSensitiveOutputFolder -Path $OutputPath }
        catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red; exit 4 }
    }
    # The report's framework default comes from the profile; 'All' when it
    # sets none or an unknown value. Presentation only (see -Framework).
    if (-not $Framework) {
        $Framework = [string](Get-TPObjectField -Item $TPBrand -Key 'DefaultFramework' -Default 'All')
        if ($Framework -notin @('NIST','CIS','SCuBA','CMMC','All')) {
            Write-Warning "Profile DefaultFramework '$Framework' is not NIST, CIS, SCuBA, CMMC or All; using All."
            $Framework = 'All'
        }
    }
} catch {
    Write-Host "  [!] Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ── Control selection (-ControlId / -ExcludeControlId) ───────────────────────
# Resolved here, after the module loads and before anything signs in: a pattern
# that matches nothing, an empty selection or a combination that would hide
# results stops the run with exit 4 and nothing collected.
$controlSelection = $null
if ($ControlId -or $ExcludeControlId) {
    $selConflicts = @(
        @{ On = [bool]$Quick;                 Text = '-Quick drops evaluators by severity and -ControlId selects controls by ID; choose one.' }
        @{ On = [bool]$FromResults;           Text = '-FromResults republishes what an earlier run assessed; selecting controls there would hide results that run produced. Re-run against the tenant with -ControlId instead.' }
        @{ On = [bool]$Web;                   Text = '-Web starts the GUI, which launches its own runs; -ControlId applies to a command-line run.' }
        @{ On = [bool]$RegisterApp;           Text = '-RegisterApp onboards a tenant and assesses nothing.' }
        @{ On = [bool]$DistributionListsOnly; Text = '-DistributionListsOnly runs the distribution-list scan, which has its own DL-* checks.' }
        @{ On = [bool]$DeviceResults;         Text = '-DeviceResults adds the DEV-* endpoint checks, which are not in Config/controls.json and cannot be selected; run the endpoint checks in a full assessment.' }
        @{ On = [bool]$SSPQuestionnaire;      Text = '-SSPQuestionnaire would ask the client about requirements this partial run did not evidence only because their controls were not selected.' }
        @{ On = [bool]$MonthlyReport;         Text = '-MonthlyReport is a whole-tenant client deliverable; a partial run cannot feed it.' }
        @{ On = [bool]$OnboardingReport;      Text = '-OnboardingReport is a first look at the whole tenant; a partial run cannot feed it. Run it on a full assessment.' }
    )
    $selRefused = @($selConflicts | Where-Object { $_.On })
    if ($selRefused.Count -gt 0) {
        foreach ($c in $selRefused) { Write-Host "  [!] -ControlId / -ExcludeControlId: $($c.Text)" -ForegroundColor Red }
        Write-Host "      Nothing was run." -ForegroundColor Red
        exit 4
    }
    try {
        $controlSelection = Resolve-TPControlSelection -Include $ControlId -Exclude $ExcludeControlId -IncludeSharePointShell:$IncludeSharePointShell
    } catch {
        Write-Host "  [!] Control selection could not be resolved: $($_.Exception.Message) Nothing was run." -ForegroundColor Red
        exit 4
    }
    if (-not $controlSelection.Valid) {
        foreach ($e in @($controlSelection.Errors)) { Write-Host "  [!] $e" -ForegroundColor Red }
        Write-Host "      Nothing was run." -ForegroundColor Red
        exit 4
    }
    $selIds = @($controlSelection.SelectedControlIds)
    $selList = if ($selIds.Count -le 20) { $selIds -join ', ' } else { "$((@($controlSelection.Workloads.Keys | ForEach-Object { "$_ $($controlSelection.Workloads[$_])" })) -join ', ')" }
    Write-Host ""
    Write-Host "[-] Partial run: $($controlSelection.SelectedCount) of $($controlSelection.TotalControls) controls selected: $selList" -ForegroundColor Yellow
    $selSvc = @($controlSelection.Services.Keys | Where-Object { $controlSelection.Services[$_] })
    Write-Host "      Evaluators: $(@($controlSelection.EvaluatorFunctions).Count); collectors: $(@($controlSelection.Collectors).Count); services: $($selSvc -join ', ')" -ForegroundColor DarkGray
    if ($controlSelection.Fallback) {
        foreach ($u in @($controlSelection.Undetermined)) { Write-Host "      [!] $($u.Function): $($u.Reason)" -ForegroundColor Yellow }
        Write-Host "      The data a selected evaluator reads could not be determined from the code, so every collector runs (never under-collect)." -ForegroundColor Yellow
    }
    Write-Host "      The other $($controlSelection.TotalControls - $controlSelection.SelectedCount) control(s) are not assessed in this run; the reports say so." -ForegroundColor DarkGray
}

# ── Proof of fix (-ProofAgainst): the earlier results file is read and checked
# here, before anything signs in, so a file that cannot serve as the "before"
# run stops the run (exit 4) instead of being found unusable after collection.
$proofBefore = $null
if ($ProofAgainst) {
    try {
        $proofBefore = Read-TPRunRecord -Path $ProofAgainst -Hash
    } catch {
        Write-Host "  [!] -ProofAgainst could not be read: $($_.Exception.Message) Nothing was run." -ForegroundColor Red
        exit 4
    }
    $pbMeta = Get-TPObjectField -Item $proofBefore -Key 'Metadata' -Default $null
    $pbWhy = ''
    if ($proofBefore.IsIncidentResponse) { $pbWhy = 'it is an incident-response output, not an assessment run' }
    elseif (-not [string](Get-TPObjectField -Item $pbMeta -Key 'TenantId' -Default '')) { $pbWhy = 'it records no TenantId, so it cannot be shown to be this tenant' }
    elseif ($null -eq (Get-TPRunRecordTime -Record $proofBefore)) { $pbWhy = 'it records no readable assessment time' }
    if ($pbWhy) {
        Write-Host "  [!] -ProofAgainst cannot be used: $pbWhy. Nothing was run." -ForegroundColor Red
        exit 4
    }
}

# -Web short-circuits the terminal flow: hand control to the local Pode-backed
# web GUI, which handles tenant selection, scan triggering, progress display,
# and report viewing in a browser. The server binds to 127.0.0.1 only —
# never exposed to the network — and exits cleanly on Ctrl+C.
if ($Web) {
    Start-TPWebServer -Port $WebPort -ScriptDir $scriptDir -OutputRoot $OutputPath
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
    if ($ClientsFile) { $regParams['ClientsFile'] = $clientsPath }
    # Onboarding writes to the tenant, so it is not in the read-only module:
    # load it only for this path.
    . (Join-Path $scriptDir 'Onboard' 'Register-TPTenantApp.ps1')
    Register-TPTenantApp @regParams
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
    $clientRec = if ($clientLookup -and $clientLookup.Status -eq 'Found') { $clientLookup.Record } else { $null }
    # The tenant this run must assess. Interactive sign-in otherwise lands on
    # whatever tenant the account belongs to, and nothing checked that it was
    # the one asked for.
    if ($clientRec -and $clientRec.PSObject.Properties['TenantId'] -and "$($clientRec.TenantId)" -match '^[0-9a-fA-F-]{36}$') {
        $targetTenantId = "$($clientRec.TenantId)".ToLowerInvariant()
    } else {
        $targetTenantId = Resolve-TPTenantId -Domain $TenantDomain
    }
    if ($clientRec -and $clientRec.PSObject.Properties['DelegatedOrg'] -and "$($clientRec.DelegatedOrg)" -match '\.onmicrosoft\.com$') {
        $targetDelegatedOrg = [string]$clientRec.DelegatedOrg
    }
    if (-not $ThirdPartyEDR -and $clientRec -and $clientRec.PSObject.Properties['ThirdPartyEDR'] -and "$($clientRec.ThirdPartyEDR)") {
        $ThirdPartyEDR = [string]$clientRec.ThirdPartyEDR
    }
    if (-not $ThirdPartyAwareness -and $clientRec -and $clientRec.PSObject.Properties['ThirdPartyAwareness'] -and "$($clientRec.ThirdPartyAwareness)") {
        $ThirdPartyAwareness = [string]$clientRec.ThirdPartyAwareness
    }
    # A product name taken from the record is judged by the same rule as the parameter, now: Set-TPThirdPartyEdr
    # would otherwise reject it only after the whole assessment had run.
    foreach ($declared in @(@{ Name = 'ThirdPartyEDR'; Value = $ThirdPartyEDR }, @{ Name = 'ThirdPartyAwareness'; Value = $ThirdPartyAwareness })) {
        if ($declared.Value -and $declared.Value -cnotmatch (Get-TPProductNamePattern)) {
            Write-Host "  [!] $($declared.Name) '$($declared.Value)' in the client record for $TenantDomain is not a product name (letters, digits, spaces and . & ( ) + / - only, 2 to 60 characters). Nothing was run." -ForegroundColor Red
            exit 4
        }
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
    if ($clientRec -and (Get-Command Get-TPClientCollectorFlags -ErrorAction SilentlyContinue)) {
        $clientCollectors = Get-TPClientCollectorFlags -ClientRecord $clientRec
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
        Write-Host "      Onboard it once with:  .\Invoke-TPAssessment.ps1 -RegisterApp -TenantDomain $TenantDomain" -ForegroundColor DarkGray
    }
}

# -DistributionListsOnly short-circuits the full assessment, like -Web and -RegisterApp above: it needs
# Exchange Online and nothing else, so it skips the Graph / Teams / Purview prerequisite check and every
# collector, evaluator and publisher the full run uses. It is READ-ONLY (Get-* cmdlets only) and says in
# its output that every other area was not assessed.
if ($DistributionListsOnly) {
    # PowerShell's own support lifecycle (Get-TPPowerShellSupportStatus): a warning, never a stop.
    $psSupport = Get-TPPowerShellSupportStatus
    if ($psSupport.Level -eq 'Warning') { Write-Host "  [!] $($psSupport.Text)" -ForegroundColor Yellow }
    $exoFloor = Get-TPExoModuleFloor
    $exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    # One wording for the PowerShell floor, the Store build and the module's version range (Get-TPExoPreflightNotes), shared with
    # the full run. A version this PowerShell cannot run fails INSIDE Connect-ExchangeOnline, so an error-level note stops here.
    $exoNotes = @(Get-TPExoPreflightNotes -Floor $exoFloor -InstalledVersion $(if ($exoModule) { $exoModule.Version } else { $null }))
    foreach ($n in $exoNotes) { Write-Host "  [!] $($n.Text)" -ForegroundColor $(if ($n.Level -eq 'Error') { 'Red' } else { 'Yellow' }) }
    if (-not $exoModule) {
        Write-Host "  [!] ExchangeOnlineManagement is not installed. Run .\Install-TPPrerequisites.ps1, then retry." -ForegroundColor Red
        exit 1
    }
    if (@($exoNotes | Where-Object { $_.Level -eq 'Error' }).Count -gt 0) { exit 1 }
    $dlAppOnly = [bool]($AppId -and $TenantId -and $CertificateThumbprint)
    if (-not $TenantDomain) {
        Write-Host "  [i] No -TenantDomain given: the tool cannot confirm WHICH tenant you signed in to. The worksheet names the connected tenant; check it before you act on it." -ForegroundColor Yellow
    } elseif (-not $dlAppOnly -and -not $targetTenantId) {
        # The full run refuses here too. Without the tenant id nothing checks which tenant the interactive sign-in lands in, and the
        # worksheet would be labeled with the domain that was TYPED: a client's name on another tenant's members and settings.
        Write-Host "  [!] Could not resolve a tenant ID for $TenantDomain, so the tenant you sign in to cannot be confirmed. Nothing was collected." -ForegroundColor Red
        Write-Host "      Check the domain, or add the client to Config\clients.json (TenantId and DelegatedOrg)." -ForegroundColor Red
        exit 1
    }
    $dlParams = @{ OutputPath = $OutputPath; MaxMembersPerList = $MaxMembersPerList; MaxLists = $MaxLists }
    if ($TenantDomain) { $dlParams['TenantDomain'] = $TenantDomain }
    if ($AppId -and $TenantId -and $CertificateThumbprint) {
        $dlParams['AppId'] = $AppId; $dlParams['TenantId'] = $TenantId; $dlParams['CertificateThumbprint'] = $CertificateThumbprint
        # Exchange wants the .onmicrosoft.com routing domain. An onboarded client's TenantDomain is its primary domain, so use the
        # client's DelegatedOrg when the domain in hand is not a routing domain.
        $dlOrg = $OrganizationDomain
        if ($dlOrg -notmatch '\.onmicrosoft\.com$' -and $targetDelegatedOrg) { $dlOrg = $targetDelegatedOrg }
        if ($dlOrg) { $dlParams['OrganizationDomain'] = $dlOrg }
    } else {
        if ($UserPrincipalName)  { $dlParams['UserPrincipalName']  = $UserPrincipalName }
        if ($targetTenantId)     { $dlParams['ExpectedTenantId']   = $targetTenantId }
        if ($targetDelegatedOrg) { $dlParams['DelegatedOrganization'] = $targetDelegatedOrg }
    }
    if ($KeepSession) { $dlParams['KeepSession'] = $true }
    $dlResult = Invoke-TPDistributionListScan @dlParams
    exit ([int]$dlResult.ExitCode)
}

# MSP-wide default: EdrStack in the active profile (Config/profiles/<name>.psd1, else
# Config/branding.psd1) declares the third-party EDR every client runs unless
# -ThirdPartyEDR or the client's clients.json ThirdPartyEDR says otherwise. Declared,
# never verified: the Defender endpoint checks go out of the score, they are not passed.
# Read from $TPBrand, the profile the module loaded: a second read of branding.psd1 here
# ignored the profile and applied (or dropped) the wrong practice's declarations.
if (-not $ThirdPartyEDR) {
    $ThirdPartyEDR = Get-TPProfileDeclaration -Brand $TPBrand -Key EdrStack -Example 'Cortex XDR'
}
# Same rule for AwarenessStack: the phishing-simulation platform every client
# uses unless -ThirdPartyAwareness or clients.json ThirdPartyAwareness says
# otherwise. Declared, never verified: DEF-4.6 goes out of the score.
if (-not $ThirdPartyAwareness) {
    $ThirdPartyAwareness = Get-TPProfileDeclaration -Brand $TPBrand -Key AwarenessStack -Example 'KnowBe4'
}

# CWE-665 — full state reset between runs. Clear-TPFindings only resets the
# findings list; raw collected data, coverage, and exceptions persist in module
# scope. Two back-to-back single-tenant runs in the same pwsh session would
# inherit the prior tenant's RawData — any collector that errors mid-way leaves
# the stale key intact, so the new tenant's evaluators read the prior tenant's
# data and emit cross-tenant findings labeled with the new tenant's metadata.
# Match the contract in CLAUDE.md ("Clear-TPState must be called between batch
# clients") and the batch orchestrator (Invoke-TPBatchAssessment.ps1:216).
Clear-TPState

# The monitoring-address list, recorded as raw data AFTER the state reset so the
# alert-routing checks (DEF-3.4, EXO-3.3) can read it. Precedence: the parameter,
# the client's clients.json entry (already folded into $MonitoringAddress above),
# then the MSP-wide default in the active profile.
if (-not (Get-Variable -Name monitoringSource -ErrorAction SilentlyContinue)) { $monitoringSource = '' }
if ($MonitoringAddress -and -not $monitoringSource) { $monitoringSource = 'parameter' }
if (-not $MonitoringAddress) {
    $fromProfile = @(@(Get-TPObjectField -Item $TPBrand -Key 'MonitoringAddresses' -Default @()) |
        Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
    if ($fromProfile.Count -gt 0) {
        $MonitoringAddress = $fromProfile
        $monitoringSource = "profile $($TPBrand['ProfileName'])"
    }
}
$monitoringSet = @(Set-TPMonitoringAddresses -Addresses $MonitoringAddress -Source $monitoringSource)

# OWASP ASVS V7.3.2 — wrap the entire run in try/finally so service sessions
# always disconnect, even if a collector / evaluator / publisher throws.
# $skipCollection is read by the finally block, so it must exist before any early
# exit (a failed prerequisite check) would otherwise run the finally with it unset.
$skipCollection = $false
try {

# ── Module prerequisite check ─────────────────────────────────────────────────
# ExchangeOnlineManagement 3.7.2 added -DisableWAM, the supported way around
# the WAM broker crash the old 3.2.0 pin worked around. The floor and ceiling
# follow the PowerShell in use (Get-TPExoModuleFloor: 3.10.0+ on 7.6, 3.7.2
# to 3.9.x on 7.4/7.5) so the preflight, the installer and Get-TPModuleHealth
# agree; a version outside that range fails inside the module at connect time.
# PowerShell's own support lifecycle (Get-TPPowerShellSupportStatus, dates from
# Config/powershell-lifecycle.json): a warning, never a stop.
$psSupport = Get-TPPowerShellSupportStatus
if ($psSupport.Level -eq 'Warning') { Write-Host "  [!] $($psSupport.Text)" -ForegroundColor Yellow }
$exoFloor = Get-TPExoModuleFloor
# Floor and Store-build notes only (no installed version): the module range is checked per module below.
foreach ($n in @(Get-TPExoPreflightNotes -Floor $exoFloor -InstalledVersion $null)) { Write-Host "  [!] $($n.Text)" -ForegroundColor $(if ($n.Level -eq 'Error') { 'Red' } else { 'Yellow' }) }
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
        Write-Host "  [!] NonInteractive — run .\Install-TPPrerequisites.ps1 manually then retry." -ForegroundColor Red
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
        # Get-TPModuleInstallScope picks AllUsers instead when the session
        # is elevated; see Install-TPPrerequisites.ps1 for the same decision.
        $scopeInfo    = Get-TPModuleInstallScope
        $installScope = $scopeInfo.Scope
        if ($scopeInfo.StillSynced) {
            Write-Host "  [!] Your PowerShell module folder is inside OneDrive:" -ForegroundColor Yellow
            Write-Host "      $($scopeInfo.UserModuleDir)" -ForegroundColor DarkYellow
            Write-Host "      Installing here anyway — modules WILL land in OneDrive and may hit the" -ForegroundColor DarkYellow
            Write-Host "      same assembly-conflict bug this prompt exists to fix. To avoid it, re-run" -ForegroundColor DarkYellow
            Write-Host "      from an elevated window, or run .\Install-TPPrerequisites.ps1 for full guidance." -ForegroundColor DarkYellow
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
        Write-Host "  [!] Skipping. Run .\Install-TPPrerequisites.ps1 to set up manually." -ForegroundColor Yellow
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
    # A results file is input: fields Add-TPFinding validated on the live run are
    # re-validated here, and a finding that fails is dropped and named, never handed
    # to a publisher or the generated remediation script.
    $droppedReplay = @()
    $findings = Select-TPReplayedFinding -Findings @(Get-TPObjectField -Item $priorData -Key 'Findings' -Default @()) -Dropped ([ref]$droppedReplay)
    if (@($droppedReplay).Count -gt 0) {
        Write-Warning ("{0} finding(s) in {1} were dropped as malformed: {2}" -f @($droppedReplay).Count, $FromResults, (@($droppedReplay) -join '; '))
        Register-TPException -Source 'FromResults' -Message ("Dropped {0} malformed finding(s): {1}" -f @($droppedReplay).Count, (@($droppedReplay) -join '; '))
    }
    $priorConn = Get-TPObjectField -Item $priorData -Key 'Connections' -Default $null
    $priorMeta = Get-TPObjectField -Item $priorData -Key 'Metadata' -Default $null
    $conn = if ($priorConn) { [hashtable]$priorConn } else { @{} }
    $reportMetadata = if ($priorMeta) { [hashtable]$priorMeta } else {
        @{ TenantDomain='Unknown'; AssessmentDate=(Get-Date -Format 'MMMM dd, yyyy'); ToolVersion=$script:TPAssessmentVersion }
    }
    if ($Quick) {
        Write-Warning "-Quick has no effect with -FromResults: findings are loaded from the baseline JSON, not re-evaluated. To produce a Quick scan, re-run against the live tenant."
    }
    # A results file from a partial run (-ControlId) stays partial when it is
    # republished: the selection it recorded goes back into module state, so the
    # scope section, the baseline view and every report name the controls that
    # were not selected instead of reporting them as producing no result.
    $priorSelection = Get-TPObjectField -Item $reportMetadata -Key 'ControlSelection' -Default $null
    if ($null -ne $priorSelection) {
        Set-TPControlSelection -Selection $priorSelection
        $selNote = Format-TPControlSelectionNotice -Selection $priorSelection
        if ($selNote) { Write-Host "  [i] $selNote" -ForegroundColor Yellow }
    }

    # Restore the collection-side state the baseline carries. Without this a
    # republish silently loses it: Get-TPCoverage returns empty, so the
    # "collectors that did not complete" block and its limitation line vanish
    # from the regenerated report even though the JSON records the failures,
    # and every scope check that reads raw data has nothing to read. Both are
    # report-only on this path — evaluators are not re-run — so restoring them
    # cannot change a verdict, only stop the republish from looking cleaner
    # than the original run.
    if ($priorData.Contains('Coverage') -and $priorData.Coverage) {
        $restored = 0
        # Every status Register-TPCoverage accepts, read from its own ValidateSet so the two
        # cannot drift. 'Skipped' (a -Skip flag) must survive: dropping it filed every
        # operator-skipped control as a collection failure on the republish.
        $validCoverage = @((Get-Command Register-TPCoverage).Parameters['Status'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues })
        foreach ($famKey in @($priorData.Coverage.Keys)) {
            $entry  = $priorData.Coverage[$famKey]
            $status = [string](Get-TPObjectField -Item $entry -Key 'Status' -Default '')
            $note   = [string](Get-TPObjectField -Item $entry -Key 'Note'   -Default '')
            # Register-TPCoverage validates Status; a baseline written by a
            # future version could carry a value this build does not know, and
            # that must not abort the republish.
            if ($status -notin $validCoverage) { continue }
            try { Register-TPCoverage -Family ([string]$famKey) -Status $status -Note $note; $restored++ } catch { }
        }
        if ($restored -gt 0) { Write-Host "  [+] Restored coverage for $restored collector(s)" -ForegroundColor Green }
    }
    if ($priorData.Contains('RawData') -and $priorData.RawData) {
        foreach ($rdKey in @($priorData.RawData.Keys)) {
            try { Set-TPRawData -Key ([string]$rdKey) -Data $priorData.RawData[$rdKey] } catch { }
        }
    }
    $tenantTag = if ($reportMetadata.TenantDomain) { ($reportMetadata.TenantDomain -split '\.')[0] } else { 'tenant' }
    # OWASP A01 — strip any non-[a-zA-Z0-9-] before using tenantTag in a file path
    $tenantTag = $tenantTag -replace '[^a-zA-Z0-9-]', ''
    if (-not $tenantTag) { $tenantTag = 'tenant' }
    $baseName = "$tenantTag-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Host "  [+] Loaded $($findings.Count) findings" -ForegroundColor Green
    if ($ThirdPartyEDR) {
        $edrCount = Set-TPThirdPartyEdr -Product $ThirdPartyEDR -Findings $findings
        $reportMetadata['ThirdPartyEDR'] = $ThirdPartyEDR
        Write-Host "  [i] $edrCount Defender endpoint check(s) reported as covered by $ThirdPartyEDR (declared, not verified; not scored)" -ForegroundColor DarkGray
    }
    if ($ThirdPartyAwareness) {
        $satCount = Set-TPThirdPartyAwareness -Product $ThirdPartyAwareness -Findings $findings
        $reportMetadata['ThirdPartyAwareness'] = $ThirdPartyAwareness
        Write-Host "  [i] $satCount phishing-simulation check(s) reported as run on $ThirdPartyAwareness (declared, not verified; not scored)" -ForegroundColor DarkGray
    }
    # Approved emergency-access exclusions (Config/baseline-exceptions/<tenant>.psd1,
    # EmergencyAccess): a Conditional Access shortfall made only of principals on the
    # tenant's current approval record is a permitted deviation, named, never silent.
    # Before license gating, like the declarations.
    $eaCount = Set-TPEmergencyAccessApproval -TenantDomain ([string]$reportMetadata.TenantDomain) -Findings $findings
    if ($eaCount -gt 0) {
        Write-Host "  [i] $eaCount Conditional Access finding(s) carry approved emergency-access exceptions (named in the finding; the exclusion stays visible)" -ForegroundColor DarkGray
    }
    # Same rule on republish (the license profile comes from the restored
    # AAD-Inventory raw data; without it nothing is moved).
    $licGated = Set-TPLicenseGating -Findings $findings
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
    if (Get-Command Get-TPBaselinePlan -ErrorAction SilentlyContinue) {
        try {
            $planTier = if ($BaselineTier) { $BaselineTier } else { 'Standard' }
            $planSkip = @(foreach ($sf in Get-TPWorkloadSkipMap) { if ((Get-Variable -Name $sf.Flag -ValueOnly -ErrorAction SilentlyContinue)) { $sf.Keys } })
            $planLic = $null; $planLicSrc = ''
            if ($BaselineResults -and (Test-Path -LiteralPath $BaselineResults)) {
                try {
                    $planPrior = Get-Content -LiteralPath $BaselineResults -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
                    $planSkus  = @(Get-TPNestedProperty -Object $planPrior -Path 'RawData.AAD-Inventory.Data.SubscribedSkus' -Default @())
                    if ($planSkus.Count -gt 0) {
                        $planLic    = Get-TPTenantLicenseProfile -SubscribedSkus $planSkus
                        $planAt     = Get-TPNestedProperty -Object $planPrior -Path 'Metadata.AssessmentTime' -Default '?'
                        $planLicSrc = "prior run $(if ($planAt -is [datetime]) { $planAt.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) } else { [string]$planAt })"
                    }
                } catch { Write-Verbose "Prior results could not supply licensing for the plan: $($_.Exception.Message)" }
            }
            $baselinePlan = Get-TPBaselinePlan -TenantDomain $TenantDomain -TargetTier $planTier -ThirdPartyEDR $ThirdPartyEDR `
                -IncludeSharePointShell:($IncludeSharePointShell -and -not $SkipSharePoint) -SkipCollectors $planSkip `
                -LicenseProfile $planLic -LicenseSource $planLicSrc `
                -SelectedControls $(if ($null -ne $controlSelection -and $controlSelection.Partial) { @($controlSelection.SelectedControlIds) } else { $null })
            $ps = $baselinePlan.Summary
            Write-Host "[-] NRG baseline plan ($($ps.TargetTier)): $($ps.RequiredControls) required — expected $($ps.Automatic) automatic, $($ps.ThirdPartyHandled) third-party handled, $($ps.Manual) manual, $($ps.OptionalCollectorRequired) optional collector, $($ps.SkippedByOperator) skipped, $(if ([int](Get-TPObjectField -Item $ps -Key 'NotSelected' -Default 0) -gt 0) { "$($ps.NotSelected) not selected, " })$($ps.LicenseBlockedExpected) license blocked, $($ps.LicensingUnknown) licensing unknown until connection; potential not verified before run: $($ps.ExpectedNotVerified)" -ForegroundColor DarkGray
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
    # A partial run signs in only to what its selected controls read. These
    # are not -Skip flags: nothing is recorded as skipped by the operator, the
    # controls that would have needed the service were not selected.
    if ($null -ne $controlSelection) {
        if (-not $controlSelection.Services.Exchange) { $connectParams['SkipExchange'] = $true }
        if (-not $controlSelection.Services.Purview)  { $connectParams['SkipPurview']  = $true }
        if (-not $controlSelection.Services.Teams)    { $connectParams['SkipTeams']    = $true }
        if (@($controlSelection.RawDataKeys) -notcontains 'SharePoint') { $connectParams['SkipSharePoint'] = $true }
    }

    $rawConn = @(Connect-TPServices @connectParams)
    $conn = $rawConn | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1
    if (-not $conn) {
        $conn = @{ Graph=$false; EXO=$false; IPPSSession=$false; Teams=$false; SharePoint=$false }
    }
    # Exit-code spec (v4.6.3 P2): exit 1 on auth failure means no Graph/EXO
    # at all. The downstream collectors will skip silently but the result
    # would be useless — fail loudly here so batch runners can flag the
    # client as auth-broken in their summary.
    if (-not $conn.Graph -and -not $conn.EXO) {
        Write-Host "  [!] Connect-TPServices returned no usable session (Graph and EXO both unavailable)." -ForegroundColor Red
        $script:TPFatalExitCode = 1
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
        @{ On = $SkipPowerPlatform; Flag = '-SkipPowerPlatform'; Keys = @('PowerPlatform', 'CopilotStudio') }
        @{ On = $SkipDNS;           Flag = '-SkipDNS';           Keys = @('DNS-EmailRecords') }
    )
    foreach ($sf in $skipFlags) {
        if (-not $sf.On) { continue }
        foreach ($k in $sf.Keys) { Register-TPCoverage -Family $k -Status 'Skipped' -Note "Skipped for this run with $($sf.Flag)." }
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
            $script:TPFatalExitCode = 1
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
    $script:TPStepTally = [ordered]@{ Ok = 0; Issues = 0; Failed = 0; NotAvailable = 0 }
    # A partial run (-ControlId) runs only the collectors its selected controls
    # read (Resolve-TPControlSelection); $null runs every collector.
    $script:TPSelectedCollectors = if ($null -ne $controlSelection) {
        [System.Collections.Generic.HashSet[string]]::new([string[]]@($controlSelection.Collectors), [System.StringComparer]::OrdinalIgnoreCase)
    } else { $null }
    function Test-TPCollectorWanted {
        param([string[]] $Function)
        if ($null -eq $script:TPSelectedCollectors) { return $true }
        return (@($Function | Where-Object { $script:TPSelectedCollectors.Contains($_) }).Count -gt 0)
    }
    function Write-TPCollectorGroup {
        param([string] $Name, [string[]] $Function = @())
        if ($Function.Count -gt 0 -and -not (Test-TPCollectorWanted -Function $Function)) { return }
        Write-Host "  $Name" -ForegroundColor Cyan
    }
    function Invoke-TPCollectorStep {
        param([string] $Label, [string[]] $Function, [hashtable] $Params = @{})
        $fns = @($Function | Where-Object { (Test-TPCollectorWanted -Function $_) -and (Get-Command $_ -ErrorAction SilentlyContinue) })
        if ($fns.Count -eq 0) { return }
        $covBefore = @{}
        foreach ($kv in (Get-TPCoverage).GetEnumerator()) { $covBefore[$kv.Key] = "$($kv.Value.Status)|$($kv.Value.Note)" }
        $excBefore = @(Get-TPExceptions).Count
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
        $changed = @((Get-TPCoverage).GetEnumerator() | Where-Object { $covBefore[$_.Key] -ne "$($_.Value.Status)|$($_.Value.Note)" })
        $statuses = @($changed | ForEach-Object { $_.Value.Status })
        $newExc = @(Get-TPExceptions).Count - $excBefore

        $failNote = @($changed | Where-Object { $_.Value.Status -eq 'Failed' } | ForEach-Object { $_.Value.Note } | Where-Object { $_ }) | Select-Object -First 1
        $okNote   = (@($changed | Where-Object { $_.Value.Status -in 'Collected', 'Partial' } | ForEach-Object { $_.Value.Note } | Where-Object { $_ }) -join '; ')
        $naNote   = @($changed | Where-Object { $_.Value.Status -eq 'NotCollected' } | ForEach-Object { $_.Value.Note } | Where-Object { $_ }) | Select-Object -First 1
        $okCount  = @($statuses | Where-Object { $_ -in 'Collected', 'Partial' }).Count

        if ($threw -or ('Failed' -in $statuses -and $okCount -eq 0)) {
            $mark = '[x]'; $color = 'Red'; $script:TPStepTally.Failed++
            $detail = 'failed: ' + $(if ($threw) { $threw } elseif ($failNote) { $failNote } else { 'see Exceptions' })
        } elseif ('Failed' -in $statuses -or 'Partial' -in $statuses -or $newExc -gt 0) {
            $mark = '[!]'; $color = 'Yellow'; $script:TPStepTally.Issues++
            $detail = "$(if ($okNote) { "$okNote; " })$newExc issue(s) logged"
        } elseif ($statuses.Count -gt 0 -and $okCount -eq 0 -and 'NotCollected' -in $statuses) {
            $mark = '[-]'; $color = 'DarkGray'; $script:TPStepTally.NotAvailable++
            $detail = $(if ($naNote) { $naNote } else { 'not available' })
        } else {
            $mark = '[+]'; $color = 'Green'; $script:TPStepTally.Ok++
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
        Write-TPCollectorGroup 'Identity (Entra ID)' -Function 'Invoke-TPCollectAADAuthPolicies', 'Invoke-TPCollectAADCAPolicies', 'Invoke-TPCollectAADUsers', 'Invoke-TPCollectAADRoles', 'Invoke-TPCollectAADPIM', 'Invoke-TPCollectAADIdentityGovernance', 'Invoke-TPCollectAADInventory', 'Invoke-TPCollectAADAppPermissions', 'Invoke-TPCollectAADDirectorySettings', 'Invoke-TPCollectAADSignInEvidence', 'Invoke-TPCollectAADCAWhatIf'
        Invoke-TPCollectorStep 'Auth and authorization policies'        'Invoke-TPCollectAADAuthPolicies'
        Invoke-TPCollectorStep 'Conditional Access policies'            'Invoke-TPCollectAADCAPolicies'
        Invoke-TPCollectorStep 'Users and MFA registration'             'Invoke-TPCollectAADUsers'
        Invoke-TPCollectorStep 'Directory role assignments'             'Invoke-TPCollectAADRoles'
        Invoke-TPCollectorStep 'PIM schedules and access reviews'       'Invoke-TPCollectAADPIM', 'Invoke-TPCollectAADIdentityGovernance'
        Invoke-TPCollectorStep 'Guests, stale accounts, OAuth, licenses' 'Invoke-TPCollectAADInventory'
        Invoke-TPCollectorStep 'Application (app-only) permissions'     'Invoke-TPCollectAADAppPermissions'
        Invoke-TPCollectorStep 'Group creation and device settings'     'Invoke-TPCollectAADDirectorySettings'
        Invoke-TPCollectorStep 'Sign-in evidence (30 days)'             'Invoke-TPCollectAADSignInEvidence'
        if (-not $SkipCAWhatIf) {
            # Microsoft's What If evaluation for a sample of users and the approved
            # break-glass accounts (Maester MT.1033 / MT.1034). Read-only: the
            # evaluate action changes nothing; see Lib/Invoke-TPCAWhatIf.ps1.
            $whatIfEmergency = @()
            try {
                $eaRecord = Get-TPBaselineExceptions -TenantDomain ([string]$conn.TenantDomain)
                $eaMap = Get-TPObjectField -Item $eaRecord -Key 'EmergencyAccess' -Default $null
                if ($eaMap -is [System.Collections.IDictionary]) { $whatIfEmergency = @($eaMap.Keys | Where-Object { [string]$_ -like 'user:*' } | ForEach-Object { ([string]$_).Substring(5) }) }
            } catch { Write-Verbose "Emergency access record not read: $($_.Exception.Message)" }
            Invoke-TPCollectorStep 'Conditional Access What If (sample)'    'Invoke-TPCollectAADCAWhatIf' -Params @{ EmergencyAccessUserIds = $whatIfEmergency }
        }

        if (-not $SkipSharePoint) {
            Write-TPCollectorGroup 'SharePoint and OneDrive' -Function 'Invoke-TPCollectSharePoint'
            Invoke-TPCollectorStep 'Tenant sharing settings'            'Invoke-TPCollectSharePoint'
        }
        if (-not $SkipIntune) {
            Write-TPCollectorGroup 'Intune' -Function 'Invoke-TPCollectIntuneEndpointSecurity', 'Invoke-TPCollectIntuneDeviceCompliance', 'Invoke-TPCollectIntuneAppProtection'
            Invoke-TPCollectorStep 'Endpoint security (LAPS, ASR, AV, EDR)' 'Invoke-TPCollectIntuneEndpointSecurity'
            Invoke-TPCollectorStep 'Compliance, enrollment, WHfB, updates'  'Invoke-TPCollectIntuneDeviceCompliance'
            Invoke-TPCollectorStep 'App protection and configuration'       'Invoke-TPCollectIntuneAppProtection'
        }
        if (-not $SkipPowerPlatform -and (Test-TPCollectorWanted -Function 'Invoke-TPCollectPowerPlatform', 'Invoke-TPCollectCopilotStudio')) {
            Write-TPCollectorGroup 'Power Platform'
            if (-not ($AppId -and $TenantId -and $CertificateThumbprint)) {
                Write-Host "      A browser sign-in may open (same account). Use -SkipPowerPlatform to skip." -ForegroundColor DarkGray
            }
            Invoke-TPCollectorStep 'Environments, tenant isolation, DLP'    'Invoke-TPCollectPowerPlatform'
            # After the Power Platform collector: it reuses that environment list.
            Invoke-TPCollectorStep 'Copilot Studio agents (Dataverse)'      'Invoke-TPCollectCopilotStudio'
        }
    }

    if ($conn.EXO) {
        Write-TPCollectorGroup 'Exchange Online and Defender' -Function 'Invoke-TPCollectEXOMailboxConfig', 'Invoke-TPCollectEXOConnectionFilter', 'Invoke-TPCollectEXOInventory', 'Invoke-TPCollectDefender'
        Invoke-TPCollectorStep 'Organization and transport settings'   'Invoke-TPCollectEXOMailboxConfig', 'Invoke-TPCollectEXOConnectionFilter'
        Invoke-TPCollectorStep 'Mailboxes: forwarding, audit, SMTP AUTH' 'Invoke-TPCollectEXOInventory'
        Invoke-TPCollectorStep 'Defender for Office 365 policies'       'Invoke-TPCollectDefender'
    }

    # DNS is public: it needs a domain list, not an Exchange session. The
    # collector takes accepted domains from Exchange when they were collected
    # and falls back to Graph verifiedDomains otherwise, so an Exchange
    # connection failure must not take the DNS controls with it (it did on
    # the first live run: three Minimum controls lost to a session error).
    if (-not $SkipDNS -and ($conn.Graph -or $conn.EXO)) {
        Write-TPCollectorGroup 'DNS' -Function 'Invoke-TPCollectDNSEmailRecords'
        $dnsParams = if ($DnsDomains) { @{ Domains = $DnsDomains } } else { @{} }
        Invoke-TPCollectorStep 'SPF, DKIM, DMARC, MTA-STS, DNSSEC, CAA' 'Invoke-TPCollectDNSEmailRecords' -Params $dnsParams
    }

    if ($conn.Teams -and -not $SkipTeams) {
        Write-TPCollectorGroup 'Teams' -Function 'Invoke-TPCollectTeams'
        Invoke-TPCollectorStep 'Meetings, external access, messaging'   'Invoke-TPCollectTeams'
    }

    if ($conn.IPPSSession -and -not $SkipPurview) {
        Write-TPCollectorGroup 'Purview' -Function 'Invoke-TPCollectPurview'
        Invoke-TPCollectorStep 'Audit, DLP, retention, labels'          'Invoke-TPCollectPurview'
    }

    # Copilot collector runs after Purview so it can reuse label/DLP/audit raw data
    if ($conn.Graph) {
        Write-TPCollectorGroup 'Microsoft 365 Copilot' -Function 'Invoke-TPCollectM365Copilot'
        Invoke-TPCollectorStep 'Licensing, labels, DLP, Copilot Studio' 'Invoke-TPCollectM365Copilot'
    }

    # Endpoint compliance results. No connection required: the endpoints already
    # ran the collector and the RMM already gathered the output. This reads
    # files, nothing else.
    if ($DeviceResults) {
        Write-TPCollectorGroup 'Endpoints'
        Invoke-TPCollectorStep 'Device compliance results'              'Invoke-TPCollectDeviceCompliance' -Params @{ ResultsPath = $DeviceResults }
        $devRaw = Get-TPRawData -Key 'Device-Compliance'
        if ($devRaw -and $devRaw.Success) {
            $ne = [int]$devRaw.Data.DeviceCount - [int]$devRaw.Data.ElevatedCount
            if ($ne -gt 0) {
                Write-Host "        $ne device(s) ran without administrative rights — encryption, TPM, Secure Boot and audit-policy checks are unassessed on those, not passed." -ForegroundColor DarkYellow
            }
        }
    }

    $t = $script:TPStepTally
    $tallyColor = if ($t.Failed -gt 0) { 'Red' } elseif ($t.Issues -gt 0) { 'Yellow' } else { 'Green' }
    $tallyText = "$($t.Ok) collected, $($t.Issues) with issues, $($t.Failed) failed"
    if ($t.NotAvailable -gt 0) { $tallyText += ", $($t.NotAvailable) not available" }
    if ($t.Issues + $t.Failed -gt 0) { $tallyText += '. Details: Exceptions array in the results JSON' }
    Write-Host ""
    Write-Host "  $tallyText" -ForegroundColor $tallyColor

    # ── Run evaluators ───────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "[-] Running evaluators..." -ForegroundColor Cyan

    # Evaluator invocation is delegated to the module's Invoke-TPEvaluatorSafe,
    # which additionally back-fills an 'Error' finding for any control an
    # evaluator owns but fails to assess — so a single evaluator bug can never
    # silently drop a control from the report. See Lib/Invoke-TPEvaluatorSafe.ps1.

    # All evaluators discovered by name from the loaded module
    $evaluators = @(Get-Command -Module TenantPosture -Name 'Test-TPControl*' -ErrorAction SilentlyContinue |
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
        foreach ($ctrl in (Get-TPControlDefinitions)) {
            if ($ctrl.Severity -in @('Critical','High') -and $ctrl.EvaluatorFunction) {
                $highSevEvaluators[$ctrl.EvaluatorFunction] = $true
            }
        }
        # Test-TPControlDevice owns the 39 DEV-* endpoint checks (3 Critical,
        # 20 High) defined in Config/device-controls.json, NOT controls.json, so
        # the loop above never sees it and -Quick silently dropped every
        # endpoint finding even when -DeviceResults was supplied. Keep it in
        # the Quick set explicitly.
        $highSevEvaluators['Test-TPControlDevice'] = $true
        $beforeCount = $evaluators.Count
        $evaluators  = @($evaluators | Where-Object { $highSevEvaluators.ContainsKey($_) })
        Write-Host "  [i] Quick mode: $($evaluators.Count) of $beforeCount evaluators (workloads with Critical+High only; lower-severity findings inside those workloads still surface)" -ForegroundColor Yellow
    }

    # A partial run (-ControlId) runs only the evaluators of the selected controls.
    if ($null -ne $controlSelection) {
        $beforeCount = $evaluators.Count
        $evaluators  = @($evaluators | Where-Object { $_ -in @($controlSelection.EvaluatorFunctions) })
        Write-Host "  [i] Partial run: $($evaluators.Count) of $beforeCount evaluators (the evaluators of the $($controlSelection.SelectedCount) selected control(s))" -ForegroundColor Yellow
    }

    foreach ($ev in $evaluators) {
        Invoke-TPEvaluatorSafe -EvaluatorFunction $ev
    }

    if ($ThirdPartyEDR) {
        $edrCount = Set-TPThirdPartyEdr -Product $ThirdPartyEDR
        Write-Host "  [i] $edrCount Defender endpoint check(s) reported as covered by $ThirdPartyEDR (declared, not verified; not scored)" -ForegroundColor DarkGray
    }
    if ($ThirdPartyAwareness) {
        $satCount = Set-TPThirdPartyAwareness -Product $ThirdPartyAwareness
        Write-Host "  [i] $satCount phishing-simulation check(s) reported as run on $ThirdPartyAwareness (declared, not verified; not scored)" -ForegroundColor DarkGray
    }
    # Approved emergency-access exclusions, from the CONNECTED tenant's record
    # (Config/baseline-exceptions/<tenant>.psd1, EmergencyAccess): a Conditional
    # Access shortfall made only of principals on the current approval record is a
    # permitted deviation, named, never silent.
    $eaCount = Set-TPEmergencyAccessApproval -TenantDomain ([string]$conn.TenantDomain)
    if ($eaCount -gt 0) {
        Write-Host "  [i] $eaCount Conditional Access finding(s) carry approved emergency-access exceptions (named in the finding; the exclusion stays visible)" -ForegroundColor DarkGray
    }
    # After the EDR and awareness declarations, so a Cortex client is not pitched Defender
    # for Endpoint licenses for checks it does not need.
    $licGated = Set-TPLicenseGating
    if ($licGated -gt 0) {
        Write-Host "  [i] $licGated control(s) need a license this tenant does not hold — listed as upgrade opportunities, not scored" -ForegroundColor DarkGray
    }

    # An evaluator can own several controls (Test-TPControlDefender owns six).
    # Findings for controls the operator did not select are dropped here, after
    # every verdict-changing step, and recorded in the metadata: never scored,
    # never shown as a verdict.
    $selectionDropped = @()
    if ($null -ne $controlSelection) {
        $selectionDropped = @(Select-TPSelectedFindings -SelectedControlIds @($controlSelection.SelectedControlIds))
        if ($selectionDropped.Count -gt 0) {
            Write-Host "  [i] $($selectionDropped.Count) control(s) evaluated alongside the selection by a shared evaluator were not selected; their findings are dropped, not scored: $($selectionDropped -join ', ')" -ForegroundColor DarkGray
        }
    }

    $findings = Get-TPFindings
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
        ToolVersion    = $TPAssessmentVersion
        Brand          = $TPBrand
        QuickScan      = [bool]$Quick
        ThirdPartyEDR  = [string]$ThirdPartyEDR
        ThirdPartyAwareness = [string]$ThirdPartyAwareness
    }
    # The selection is part of the record: a partial run's results file says it
    # is partial, and a republish of it stays partial.
    if ($null -ne $controlSelection) {
        $reportMetadata['ControlSelection'] = ConvertTo-TPControlSelectionRecord -Selection $controlSelection -DroppedFindings $selectionDropped
        Set-TPControlSelection -Selection $reportMetadata['ControlSelection']
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
    $reportMetadata['Maturity'] = Get-TPMaturityTier -Findings $findings -Selection (Get-TPObjectField -Item $reportMetadata -Key 'ControlSelection' -Default $null)
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
    $priorTier = [string](Get-TPObjectField -Item $reportMetadata -Key 'TargetTier' -Default '')
    $BaselineTier = if ($skipCollection -and $priorTier -in @('Minimum', 'Standard', 'Hardened')) { $priorTier } else { 'Standard' }
}
if (Get-Command Get-TPBaselineCompliance -ErrorAction SilentlyContinue) {
    try {
        $baselineCompliance = Get-TPBaselineCompliance -Findings $findings -TargetTier $BaselineTier `
            -TenantDomain ([string](Get-TPObjectField -Item $reportMetadata -Key 'TenantDomain' -Default '')) `
            -QuickScan:([bool](Get-TPObjectField -Item $reportMetadata -Key 'QuickScan' -Default $false)) `
            -SelectedControls (Get-TPSelectedControlIds -Metadata $reportMetadata)
        $reportMetadata['BaselineVersion'] = $baselineCompliance.BaselineVersion
        $reportMetadata['TargetTier']      = $baselineCompliance.TargetTier
        # Regressions against the prior run, only under a comparable baseline
        # context; a version or tier change is stated, never read as decline.
        $priorBaseline = $null; $priorRunTime = ''
        if ($BaselineResults -and (Test-Path -LiteralPath $BaselineResults)) {
            try {
                $priorJson = Get-Content -LiteralPath $BaselineResults -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
                $priorBaseline = Get-TPObjectField -Item $priorJson -Key 'BaselineCompliance' -Default $null
                $priorRunTime  = [string](Get-TPNestedProperty -Object $priorJson -Path 'Metadata.AssessmentTime' -Default '')
            } catch { Write-Warning "Prior results could not be read for baseline regressions: $($_.Exception.Message)" }
        }
        $baselineRegressions = Get-TPBaselineRegressions -Current $baselineCompliance -Prior $priorBaseline -PriorRunTime $priorRunTime
        if ($null -ne $baselinePlan -and (Get-Command Compare-TPBaselinePlan -ErrorAction SilentlyContinue)) {
            $baselinePlanComparison = Compare-TPBaselinePlan -Plan $baselinePlan -Compliance $baselineCompliance
        }
        $bs = $baselineCompliance.Summary
        Write-Host "  [i] NRG baseline v$($bs.BaselineVersion) ($($bs.TargetTier)): $($bs.RequiredControls) required — $($bs.Satisfied) satisfied, $($bs.Failed) failed, $($bs.NotVerified) not verified, $($bs.LicenseBlocked) license blocked, $($bs.ApprovedException) approved exception(s); effectiveness known for $($bs.EffectivenessEffective + $bs.EffectivenessIneffective) of $($bs.RequiredControls)" -ForegroundColor DarkGray
        $evc = Get-TPObjectField -Item $baselineCompliance -Key 'EvidenceCoverage' -Default $null
        $efc = Get-TPObjectField -Item $baselineCompliance -Key 'EffectivenessCoverage' -Default $null
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

# ── Change impact: what fixing each open item would break, and for whom ──────
# A view over the findings and the raw data already read: Implement now / Needs
# planning / Could break accounts, naming the accounts the run's data shows would
# be affected. Computed on every run and written to the results JSON (the MCP
# server's get_change_impact reads it); the report files need -ChangeImpact or
# -AllFiles. It creates no finding and moves no score.
$changeImpactView = $null
if (Get-Command Get-TPChangeImpact -ErrorAction SilentlyContinue) {
    try {
        $changeImpactView = Get-TPChangeImpact -Findings $findings -Metadata $reportMetadata
        if ($changeImpactView.Available) {
            $ciSummary = $changeImpactView.Summary
            Write-Host "  [i] Change impact: $($ciSummary.ImplementNow) can go in now, $($ciSummary.NeedsPlanning) need planning, $($ciSummary.CouldBreakAccounts) could break accounts ($($ciSummary.AccountsNamed) account(s) named), $($ciSummary.LicenseDecision) need a license decision" -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "Change-impact view failed: $($_.Exception.Message)"
        $reportMetadata['ChangeImpactError'] = $_.Exception.Message
    }
}

# ── Conditional Access checklist (Maester's checks) ──────────────────────────
# A view over the Conditional Access data already read: recommended policies,
# policy hygiene and the What If simulation, with a report-only policy body for
# every recommended policy that is missing. Written to the results JSON on every
# run; the report files need -CAChecklist or -AllFiles. No finding, no score.
$caChecklistView = $null
if (Get-Command Get-TPCAChecklist -ErrorAction SilentlyContinue) {
    try {
        $eaForChecklist = try { Get-TPBaselineExceptions -TenantDomain ([string]$reportMetadata.TenantDomain) } catch { $null }
        $licForChecklist = try { Get-TPTenantLicenseProfile } catch { $null }
        $caChecklistView = Get-TPCAChecklist -EmergencyAccessRecord $eaForChecklist -LicenseProfile $licForChecklist
        if ($caChecklistView.Available) {
            $cc = $caChecklistView.Counts
            Write-Host "  [i] Conditional Access checklist: $($cc.Pass) passed, $($cc.Fail) not met, $($cc.Staged) report-only, $($cc.NotAssessed) not assessed; $(@($caChecklistView.Fixes).Count) report-only polic(ies) to import" -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "Conditional Access checklist failed: $($_.Exception.Message)"
        $reportMetadata['CAChecklistError'] = $_.Exception.Message
    }
}

# ── Intune and endpoint checklist (Maester's checks) ─────────────────────────
$intuneChecklistView = $null
if (Get-Command Get-TPIntuneChecklist -ErrorAction SilentlyContinue) {
    try {
        $intuneChecklistView = Get-TPIntuneChecklist
        if ($intuneChecklistView.Available) {
            $ic = $intuneChecklistView.Counts
            Write-Host "  [i] Intune checklist: $($ic.Pass) passed, $($ic.Fail) not met, $($ic.NotAssessed) not assessed, $($ic.NotApplicable) do not apply" -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "Intune checklist failed: $($_.Exception.Message)"
        $reportMetadata['IntuneChecklistError'] = $_.Exception.Message
    }
}

# ── Publish reports ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Generating reports..." -ForegroundColor Cyan
# One aligned line per file, named by its leaf; the folder is printed once.
$script:TPReportFolderShown = $false
function Write-TPReportFile {
    param([string] $Label, [string] $Path)
    if (-not $script:TPReportFolderShown) {
        Write-Host "  Folder: $(Split-Path -Path $Path -Parent)" -ForegroundColor DarkGray
        $script:TPReportFolderShown = $true
    }
    Write-Host ('  [+] {0,-34} {1}' -f $Label, (Split-Path -Path $Path -Leaf)) -ForegroundColor Green
}

$jsonPath = Join-Path $OutputPath "$baseName-results.json"
# Capture the raw-data snapshot for drift detection on the NEXT run. The
# delta publisher compares this snapshot against a future run's snapshot to
# surface raw configuration changes (new CA policies, new admin assignments,
# new OAuth apps, DMARC policy regression) — not just finding state changes.
$rawDataSnapshot = if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) {
    Get-TPRawData
} else { @{} }
# TOCTOU fix (v4.6.3 P2): Set-TPSensitiveFileContent pre-creates the file
# and applies the ACL BEFORE any tenant data is written. Previously the
# file inherited the parent directory's permissions during Out-File and was
# only restricted afterwards via Set-Acl — on a shared MSP workstation a
# co-resident process polling the output dir could read tenant data in
# that small window.
$jsonPayload = @{
    Metadata    = $reportMetadata
    Findings    = $findings
    RawData     = $rawDataSnapshot
    Exceptions  = (Get-TPExceptions)
    Coverage    = (Get-TPCoverage)
    Connections = $conn
    # The NRG baseline is the integration contract for whatever consumes
    # these results later: per required control the observed state,
    # constraint, disposition, evidence timestamp and freshness, and
    # effectiveness, plus the regressions against the prior run.
    BaselineCompliance  = $baselineCompliance
    BaselineRegressions = $baselineRegressions
    BaselinePlan        = $baselinePlan
    BaselinePlanComparison = $baselinePlanComparison
    # Open findings sorted by what fixing them disturbs, with the accounts the
    # run's data shows each risky change would affect (UPN and display name only).
    ChangeImpact        = $changeImpactView
    # Maester's Conditional Access checks and the report-only policy bodies.
    CAChecklist         = $caChecklistView
    # Maester's Intune and endpoint checks.
    IntuneChecklist     = $intuneChecklistView
} | ConvertTo-Json -Depth 12
Set-TPSensitiveFileContent -Path $jsonPath -Content $jsonPayload
Write-TPReportFile 'JSON' $jsonPath
Write-Host "      Holds sensitive tenant inventory (CA policies, admin assignments, OAuth apps); access restricted to you and administrators." -ForegroundColor Yellow

# Proof of fix: this run against the -ProofAgainst file, read back from the
# results file just written so the certificate's hash is of the file on disk.
if ($null -ne $proofBefore) {
    try {
        $proofAfter = Read-TPRunRecord -Path $jsonPath -Hash
        $proof = Get-TPRemediationProof -Before $proofBefore -After $proofAfter
        if ($proof.Available) {
            $proofFiles = Publish-TPRemediationProof -Proof $proof -OutputPath $OutputPath
            Write-TPReportFile 'Proof of fix (html)' $proofFiles.Html
            Write-TPReportFile 'Proof of fix (md)' $proofFiles.Markdown
            Write-Host "      $($proof.Headline)." -ForegroundColor Cyan
        } else {
            Write-Host "  [!] Proof of fix not written: $($proof.Note)" -ForegroundColor Yellow
        }
    } catch { Write-Warning "Proof of fix publish failed: $($_.Exception.Message)" }
}

if (-not $JsonOnly) {
    # ── Audit-finding fix (HIGH #2): every secondary report file gets the same
    #    ACL hardening as the JSON baseline. They all contain the same tenant
    #    inventory data (CA policies, admin UPNs, OAuth grants, DMARC records)
    #    rendered into a different format. Inherited permissions on a shared
    #    MSP workstation or synced OneDrive would otherwise make these world-
    #    readable. Set-TPSensitiveFileAcl is a no-op on non-Windows.
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
    if (Get-Command Publish-TPRemediationScript -ErrorAction SilentlyContinue) {
        $rsPath = Join-Path $OutputPath "$baseName-remediation.ps1"
        try {
            Publish-TPRemediationScript -Metadata $reportMetadata -Findings $findings -OutputPath $rsPath
            $remContent = Get-Content -Raw -LiteralPath $rsPath -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($remContent)) {
                $reportAttachments += @{ Label = 'Remediation script (PowerShell)'; FileName = "$baseName-remediation.ps1"; Mime = 'text/plain'; Content = $remContent }
            }
            if ($AllFiles) {
                Set-TPSensitiveFileAcl -Path $rsPath -ErrorAction SilentlyContinue
                Write-TPReportFile 'Remediation' $rsPath
            } else {
                # Consolidated profile: the content is embedded in the HTML —
                # don't leave the sidecar file (and don't leave tenant data on
                # disk unnecessarily).
                Remove-Item -LiteralPath $rsPath -Force -ErrorAction SilentlyContinue
            }
        } catch { Write-Warning "Remediation publish failed: $($_.Exception.Message)" }
    }

    # HTML report (always in a non-JsonOnly run) — carries the embedded downloads.
    if (Get-Command Publish-TPAssessmentHTML -ErrorAction SilentlyContinue) {
        $htmlPath = Join-Path $OutputPath "$baseName-assessment.html"
        try {
            $fwSelection = if ($Framework -eq 'All') { @('CIS','SCuBA','NIST','CMMC') } else { @($Framework) }
            Publish-TPAssessmentHTML -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $htmlPath -Attachments $reportAttachments -Frameworks $fwSelection -BaselineRegressions $baselineRegressions -BaselinePlanComparison $baselinePlanComparison
            Write-TPReportFile 'HTML' $htmlPath
            Set-TPSensitiveFileAcl -Path $htmlPath -ErrorAction SilentlyContinue
        } catch {
            $stack = $_.ScriptStackTrace
            Write-Warning "HTML failed: $($_.Exception.Message)"
            Write-Warning "Stack: $stack"
        }
    }

    # ── Standalone sidecar deliverables (only with -AllFiles) ────────────────
    # Every file below contains the same tenant inventory (CA policies, admin
    # UPNs, OAuth grants, DMARC records) in a different format, so each gets the
    # same ACL hardening as the JSON baseline. Set-TPSensitiveFileAcl is a
    # no-op on non-Windows.
    if ($AllFiles) {
        # Markdown summary
        if (Get-Command Publish-TPAssessmentSummary -ErrorAction SilentlyContinue) {
            $mdPath = Join-Path $OutputPath "$baseName-assessment.md"
            try {
                Publish-TPAssessmentSummary -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $mdPath -BaselineRegressions $baselineRegressions -BaselinePlanComparison $baselinePlanComparison
                Write-TPReportFile 'Markdown' $mdPath
                Set-TPSensitiveFileAcl -Path $mdPath -ErrorAction SilentlyContinue
            } catch { Write-Warning "Markdown publish failed: $($_.Exception.Message)" }
        }

        # Remediation playbook + executive summary
        if (Get-Command Publish-TPRemediationPlaybook -ErrorAction SilentlyContinue) {
            $pbPath     = Join-Path $OutputPath "$baseName-playbook.md"
            $execPath   = Join-Path $OutputPath "$baseName-executive.md"
            $pbHtmlPath = Join-Path $OutputPath "$baseName-playbook.html"
            try {
                Publish-TPRemediationPlaybook `
                    -Metadata $reportMetadata `
                    -Findings $findings `
                    -Connections $conn `
                    -OutputPath $pbPath `
                    -ExecutivePath $execPath `
                    -HtmlOutputPath $pbHtmlPath
                Write-TPReportFile 'Playbook (md)' $pbPath
                Write-TPReportFile 'Playbook (html)' $pbHtmlPath
                Write-TPReportFile 'Executive' $execPath
                Set-TPSensitiveFileAcl -Path $pbPath     -ErrorAction SilentlyContinue
                Set-TPSensitiveFileAcl -Path $execPath   -ErrorAction SilentlyContinue
                Set-TPSensitiveFileAcl -Path $pbHtmlPath -ErrorAction SilentlyContinue
            } catch { Write-Warning "Playbook publish failed: $($_.Exception.Message)" }
        }

        # XLSX compliance matrix
        if (Get-Command Publish-TPComplianceMatrix -ErrorAction SilentlyContinue) {
            $xlsxPath = Join-Path $OutputPath "$baseName-compliance-matrix.xlsx"
            try {
                Publish-TPComplianceMatrix -Metadata $reportMetadata -Findings $findings -OutputPath $xlsxPath
                Write-TPReportFile 'XLSX matrix' $xlsxPath
                Set-TPSensitiveFileAcl -Path $xlsxPath -ErrorAction SilentlyContinue
            } catch { Write-Warning "XLSX publish failed: $($_.Exception.Message)" }
        }
    }

    # Standalone NIST 800-53 Rev 5 matrix. Separate from -AllFiles so an
    # 800-53 client can be served without generating every other sidecar, and
    # implied by -AllFiles so the consolidated profile stays a superset.
    if (($NISTMatrix -or $AllFiles) -and (Get-Command Publish-TPNISTMatrix -ErrorAction SilentlyContinue)) {
        $nistPath = Join-Path $OutputPath "$baseName-nist-800-53-matrix.md"
        try {
            Publish-TPNISTMatrix -Metadata $reportMetadata -Findings $findings -OutputPath $nistPath
            Write-TPReportFile 'NIST matrix (md)' $nistPath
            Set-TPSensitiveFileAcl -Path $nistPath -ErrorAction SilentlyContinue
            # The HTML and XLSX sidecars carry the same findings as the
            # Markdown and get the same file restriction.
            foreach ($ext in '.html', '.xlsx') {
                $side = [System.IO.Path]::ChangeExtension($nistPath, $ext)
                if (Test-Path -LiteralPath $side) {
                    Write-TPReportFile "NIST matrix ($($ext.TrimStart('.')))" $side
                    Set-TPSensitiveFileAcl -Path $side -ErrorAction SilentlyContinue
                }
            }
        } catch { Write-Warning "NIST matrix publish failed: $($_.Exception.Message)" }
    }

    # System Security Plan (NIST SP 800-171 Rev 2 / CMMC Level 2). Same shape as
    # the NIST matrix above: its own switch so a defense-contractor client can
    # be served without every other sidecar, and implied by -AllFiles.
    if (($SSP -or $AllFiles) -and (Get-Command Publish-TPSSP -ErrorAction SilentlyContinue)) {
        $sspPath = Join-Path $OutputPath "$baseName-ssp-800-171.md"
        try {
            # Prefer the operator-supplied -TenantDomain when given. Under GDAP
            # batch mode, $reportMetadata.TenantDomain is derived by
            # Connect-TPServices from the SIGNED-IN ACCOUNT's UPN, which is
            # the MSP's own domain, not the client's — looking the answers
            # file up by that value attaches the MSP's own SSP narratives to
            # every client. -TenantDomain is the client the operator actually
            # asked to assess and is unambiguous whenever it is supplied.
            # NOTE: Invoke-TPBatchAssessment.ps1 does not yet pass
            # -TenantDomain through to this orchestrator for GDAP clients, so
            # this alone does not close the gap in batch mode — that
            # batch-runner wiring (and correcting how Connect-TPServices
            # derives TenantDomain) is a separate follow-up.
            $sspClient = if ($TenantDomain) { $TenantDomain } else { [string]$reportMetadata.TenantDomain }
            $sspAnswerSet = if ($SSPAnswers) {
                Get-TPSSPAnswers -Path $SSPAnswers
            } else {
                Get-TPSSPAnswers -ClientName $sspClient
            }
            $sspPosture = Get-TPSSPPosture -Findings $findings -Answers $sspAnswerSet
            Publish-TPSSP -Posture $sspPosture -Metadata $reportMetadata -Answers $sspAnswerSet `
                -OutputPath $sspPath -ClientName $sspClient
            Write-TPReportFile 'SSP (md)' $sspPath
            Set-TPSensitiveFileAcl -Path $sspPath -ErrorAction SilentlyContinue
            foreach ($ext in @('.html', '.xlsx')) {
                $side = [System.IO.Path]::ChangeExtension($sspPath, $ext)
                if (Test-Path -LiteralPath $side) {
                    Write-TPReportFile "SSP ($($ext.TrimStart('.')))" $side
                    Set-TPSensitiveFileAcl -Path $side -ErrorAction SilentlyContinue
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

    # HIPAA Security Rule readiness view. A view over the findings like the SSP:
    # it creates no finding and moves no score.
    if (($HIPAA -or $AllFiles) -and (Get-Command Publish-TPHipaaReadiness -ErrorAction SilentlyContinue)) {
        $hipaaPath = Join-Path $OutputPath "$baseName-hipaa-readiness.md"
        try {
            $hipaaPosture = Get-TPHipaaReadiness -Findings $findings
            Publish-TPHipaaReadiness -Posture $hipaaPosture -Metadata $reportMetadata -OutputPath $hipaaPath
            if (Test-Path -LiteralPath $hipaaPath) {
                Write-TPReportFile 'HIPAA readiness (md)' $hipaaPath
                Set-TPSensitiveFileAcl -Path $hipaaPath -ErrorAction SilentlyContinue
                $hipaaHtml = [System.IO.Path]::ChangeExtension($hipaaPath, '.html')
                if (Test-Path -LiteralPath $hipaaHtml) {
                    Write-TPReportFile 'HIPAA readiness (html)' $hipaaHtml
                    Set-TPSensitiveFileAcl -Path $hipaaHtml -ErrorAction SilentlyContinue
                }
                $hs = $hipaaPosture['Summary']
                Write-Host "      $($hs['Total'] - $hs['EvidenceCollected']) of $($hs['Total']) HIPAA Security Rule items have no evidence from this run: $($hs['AttestationRequired']) have no mapped tenant check and need documents, interviews or a walkthrough; $($hs['Mapped'] - $hs['EvidenceCollected']) have mapped checks that produced none." -ForegroundColor Yellow
            }
        } catch { Write-Warning "HIPAA readiness publish failed: $($_.Exception.Message)" }

        # The client-facing version: the same view regrouped into what a client
        # can act on, printable, and a PDF with -Pdf. A partial or quick run is
        # not written, with a note.
        if (Get-Command Publish-TPHipaaClientReport -ErrorAction SilentlyContinue) {
            try {
                $hipaaClient = if ($ClientName) { $ClientName }
                               else { [string](Get-TPObjectField -Item (Get-TPObjectField -Item $clientLookup -Key 'Record' -Default $null) -Key 'ClientName' -Default '') }
                $hipaaModel = Get-TPHipaaClientReport -Findings $findings -Metadata $reportMetadata -ClientName $hipaaClient
                if ($hipaaModel.Available) {
                    $hipaaFiles = Publish-TPHipaaClientReport -Model $hipaaModel -OutputPath (Join-Path $OutputPath "$baseName-hipaa-report.html") -Pdf:$Pdf
                    Write-TPReportFile 'HIPAA client report (html)' $hipaaFiles.Html
                    if ($hipaaFiles.Pdf) { Write-TPReportFile 'HIPAA client report (pdf)' $hipaaFiles.Pdf }
                    elseif ($hipaaFiles.PdfNote) { Write-Host "  [!] $($hipaaFiles.PdfNote)" -ForegroundColor Yellow }
                } else {
                    Write-Host "  [i] HIPAA client report not written: $($hipaaModel.Note)" -ForegroundColor DarkGray
                }
            } catch { Write-Warning "HIPAA client report publish failed: $($_.Exception.Message)" }
        }
    }

    if ($Pdf -and -not ($HIPAA -or $AllFiles)) {
        Write-Host "  [i] -Pdf prints the client-facing HIPAA report; add -HIPAA to write it." -ForegroundColor DarkGray
    }

    # BOD 25-01 required-configurations view. A view over the findings like the
    # HIPAA view: it creates no finding and moves no score.
    if (($BOD2501 -or $AllFiles) -and (Get-Command Publish-TPBod2501View -ErrorAction SilentlyContinue)) {
        $bodPath = Join-Path $OutputPath "$baseName-bod-25-01.md"
        try {
            $bodArgs = @{ Findings = $findings }
            if ($ScubaResultsPath) { $bodArgs.ScubaResultsPath = $ScubaResultsPath }
            $bodView = Get-TPBod2501View @bodArgs
            Publish-TPBod2501View -View $bodView -Metadata $reportMetadata -OutputPath $bodPath
            if (Test-Path -LiteralPath $bodPath) {
                Write-TPReportFile 'BOD 25-01 view (md)' $bodPath
                Set-TPSensitiveFileAcl -Path $bodPath -ErrorAction SilentlyContinue
                $bodHtml = [System.IO.Path]::ChangeExtension($bodPath, '.html')
                if (Test-Path -LiteralPath $bodHtml) {
                    Write-TPReportFile 'BOD 25-01 view (html)' $bodHtml
                    Set-TPSensitiveFileAcl -Path $bodHtml -ErrorAction SilentlyContinue
                }
                $bs = $bodView['Summary']
                $bn = Get-TPObjectField -Item $bs -Key 'ByStatus' -Default @{}
                $bodCounts = (@($bn.Keys) | ForEach-Object { "$($bn[$_]) $_" }) -join '; '
                Write-Host "      $($bs['Total']) BOD 25-01 required configurations: $bodCounts. A technical readiness view; ScubaGear's report is what CISA expects." -ForegroundColor Yellow
                if ($bodView['IndependentError']) { Write-Warning "BOD 25-01 view: $($bodView['IndependentError'])" }
            }
        } catch { Write-Warning "BOD 25-01 view publish failed: $($_.Exception.Message)" }
    }

    # SSP questionnaire — the manual-evidence half of the SSP, as a document a
    # client fills in and sends back. Its own opt-in switch, deliberately NOT
    # implied by -AllFiles: unlike the SSP itself, this is a document meant to
    # leave the building, not a routine artifact to regenerate on every run.
    if ($SSPQuestionnaire -and (Get-Command Publish-TPSSPQuestionnaire -ErrorAction SilentlyContinue)) {
        $sspqPath = Join-Path $OutputPath "$baseName-ssp-questionnaire.md"
        try {
            # Reuses the same posture/answers/client resolution as -SSP above
            # when that switch was also passed this run; computed fresh
            # otherwise so -SSPQuestionnaire works standalone.
            $sspqClient = if ($TenantDomain) { $TenantDomain } else { [string]$reportMetadata.TenantDomain }
            $sspqAnswerSet = if ($SSPAnswers) {
                Get-TPSSPAnswers -Path $SSPAnswers
            } else {
                Get-TPSSPAnswers -ClientName $sspqClient
            }
            $sspqPosture = Get-TPSSPPosture -Findings $findings -Answers $sspqAnswerSet
            Publish-TPSSPQuestionnaire -Posture $sspqPosture -Metadata $reportMetadata `
                -OutputPath $sspqPath -ClientName $sspqClient -Family $SSPQuestionnaireFamily
            Write-TPReportFile 'SSP questionnaire (md)' $sspqPath
            Set-TPSensitiveFileAcl -Path $sspqPath -ErrorAction SilentlyContinue
            foreach ($ext in @('.html', '.pdf', '.manifest.json')) {
                $side = [System.IO.Path]::ChangeExtension($sspqPath, $ext)
                if (Test-Path -LiteralPath $side) {
                    Write-TPReportFile "SSP questionnaire ($($ext.TrimStart('.')))" $side
                    Set-TPSensitiveFileAcl -Path $side -ErrorAction SilentlyContinue
                }
            }
        } catch { Write-Warning "SSP questionnaire publish failed: $($_.Exception.Message)" }
    }

    # Manual-review questionnaire — the controls.json counterpart to the SSP
    # questionnaire above, for the controls Get-TPAssessmentScope classifies
    # as NoProgrammaticCheck or CollectionIncomplete. Same opt-in shape, same
    # reason it is not implied by -AllFiles.
    if ($ManualReviewQuestionnaire -and (Get-Command Publish-TPManualReviewQuestionnaire -ErrorAction SilentlyContinue)) {
        $mrqPath = Join-Path $OutputPath "$baseName-manual-review.md"
        try {
            $mrqClient = if ($TenantDomain) { $TenantDomain } else { [string]$reportMetadata.TenantDomain }
            $mrqAnswerSet = Get-TPManualReviewAnswers -ClientName $mrqClient
            $mrqScope = Get-TPAssessmentScope -Findings $findings
            Publish-TPManualReviewQuestionnaire -Scope $mrqScope -Answers $mrqAnswerSet -Metadata $reportMetadata `
                -OutputPath $mrqPath -ClientName $mrqClient -Workload $ManualReviewWorkload
            Write-TPReportFile 'Manual review questionnaire (md)' $mrqPath
            Set-TPSensitiveFileAcl -Path $mrqPath -ErrorAction SilentlyContinue
            foreach ($ext in @('.html', '.pdf', '.manifest.json')) {
                $side = [System.IO.Path]::ChangeExtension($mrqPath, $ext)
                if (Test-Path -LiteralPath $side) {
                    Write-TPReportFile "Manual review questionnaire ($($ext.TrimStart('.')))" $side
                    Set-TPSensitiveFileAcl -Path $side -ErrorAction SilentlyContinue
                }
            }
        } catch { Write-Warning "Manual review questionnaire publish failed: $($_.Exception.Message)" }
    }

    # NIST 800-53 improvement plan. Same shape as the two above: its own switch
    # so it can be produced without every other sidecar, implied by -AllFiles.
    if (($ImprovementPlan -or $AllFiles) -and (Get-Command Publish-TPImprovementPlan -ErrorAction SilentlyContinue)) {
        $planPath = Join-Path $OutputPath "$baseName-nist-improvement-plan.md"
        try {
            # Resolved here rather than inside the plan so a tenant whose SKU
            # query failed is treated as "no license data" — every gated
            # control lands in Buy first rather than being promised as a quick
            # win the tenant cannot actually action.
            $planLicense = if (Get-Command Get-TPTenantLicenseProfile -ErrorAction SilentlyContinue) {
                try { Get-TPTenantLicenseProfile } catch { $null }
            } else { $null }

            $plan = Get-TPNISTImprovementPlan -Findings $findings -LicenseProfile $planLicense
            if ($plan['Available']) {
                Publish-TPImprovementPlan -Plan $plan -Metadata $reportMetadata `
                    -OutputPath $planPath -ClientName ([string]$reportMetadata.TenantDomain)
                Write-TPReportFile 'NIST improvement plan (md)' $planPath
                Set-TPSensitiveFileAcl -Path $planPath -ErrorAction SilentlyContinue
                $planHtml = [System.IO.Path]::ChangeExtension($planPath, '.html')
                if (Test-Path -LiteralPath $planHtml) {
                    Write-TPReportFile 'NIST improvement plan (html)' $planHtml
                    Set-TPSensitiveFileAcl -Path $planHtml -ErrorAction SilentlyContinue
                }
                Write-Host "      NIST coverage $($plan['Baseline']['Score'])% -> $($plan['Projected']['Score'])% across $($plan['Projected']['StepCount']) steps." -ForegroundColor Cyan
            } else {
                Write-Warning 'No NIST-cited findings to plan against — improvement plan skipped.'
            }
        } catch { Write-Warning "Improvement plan publish failed: $($_.Exception.Message)" }
    }

    # New-client onboarding report. Its own switch, implied by -AllFiles; it covers
    # the whole tenant, so a partial or quick run is skipped with a note (an
    # explicit -OnboardingReport with -ControlId already stopped the run).
    if (($OnboardingReport -or $AllFiles) -and (Get-Command Publish-TPOnboardingReport -ErrorAction SilentlyContinue)) {
        try {
            $obLicense = try { Get-TPTenantLicenseProfile } catch { $null }
            $obModel = Get-TPOnboardingModel -Findings $findings -Metadata $reportMetadata -LicenseProfile $obLicense
            if ($obModel.Available) {
                $obFiles = Publish-TPOnboardingReport -Model $obModel -OutputPath (Join-Path $OutputPath "$baseName-onboarding.html")
                Write-TPReportFile 'Onboarding report (html)' $obFiles.Html
                Write-TPReportFile 'Onboarding report (md)' $obFiles.Markdown
            } elseif ($OnboardingReport) {
                Write-Host "  [!] Onboarding report not written: $($obModel.Note)" -ForegroundColor Yellow
            } else {
                Write-Host "  [i] Onboarding report not written: $($obModel.Note)" -ForegroundColor DarkGray
            }
        } catch { Write-Warning "Onboarding report publish failed: $($_.Exception.Message)" }
    }

    # Change impact: Implement now / Needs planning / Could break accounts, with the
    # accounts named. Its own switch, implied by -AllFiles; a partial run is allowed
    # and says so on the page.
    if (($ChangeImpact -or $AllFiles) -and $null -ne $changeImpactView -and (Get-Command Publish-TPChangeImpact -ErrorAction SilentlyContinue)) {
        try {
            if ($changeImpactView.Available) {
                $ciFiles = Publish-TPChangeImpact -Model $changeImpactView -OutputPath (Join-Path $OutputPath "$baseName-change-impact.html")
                Write-TPReportFile 'Change impact (html)' $ciFiles.Html
                Write-TPReportFile 'Change impact (md)' $ciFiles.Markdown
            } else {
                Write-Host "  [!] Change-impact report not written: $($changeImpactView.Note)" -ForegroundColor Yellow
            }
        } catch { Write-Warning "Change-impact report publish failed: $($_.Exception.Message)" }
    }

    # Conditional Access checklist (Maester's checks) and the report-only policy
    # files for what is missing. Its own switch, implied by -AllFiles.
    if (($CAChecklist -or $AllFiles) -and $null -ne $caChecklistView -and (Get-Command Publish-TPCAChecklist -ErrorAction SilentlyContinue)) {
        try {
            if ($caChecklistView.Available) {
                $caFiles = Publish-TPCAChecklist -Model $caChecklistView -OutputPath (Join-Path $OutputPath "$baseName-ca-checklist.html") -TenantDomain ([string]$reportMetadata.TenantDomain) -ToolVersion ([string]$reportMetadata.ToolVersion)
                Write-TPReportFile 'CA checklist (html)' $caFiles.Html
                Write-TPReportFile 'CA checklist (md)' $caFiles.Markdown
                if ($caFiles.PolicyFolder) { Write-TPReportFile "CA report-only policies ($(@($caFiles.PolicyFiles).Count - 1))" $caFiles.PolicyFolder }
            } else {
                Write-Host "  [!] Conditional Access checklist not written: $($caChecklistView.Note)" -ForegroundColor Yellow
            }
        } catch { Write-Warning "Conditional Access checklist publish failed: $($_.Exception.Message)" }
    }

    # Intune and endpoint checklist (Maester's checks). Implied by -AllFiles.
    if (($IntuneChecklist -or $AllFiles) -and $null -ne $intuneChecklistView -and (Get-Command Publish-TPIntuneChecklist -ErrorAction SilentlyContinue)) {
        try {
            if ($intuneChecklistView.Available) {
                $icFiles = Publish-TPIntuneChecklist -Model $intuneChecklistView -OutputPath (Join-Path $OutputPath "$baseName-intune-checklist.html") -TenantDomain ([string]$reportMetadata.TenantDomain) -ToolVersion ([string]$reportMetadata.ToolVersion)
                Write-TPReportFile 'Intune checklist (html)' $icFiles.Html
                Write-TPReportFile 'Intune checklist (md)' $icFiles.Markdown
            } else {
                Write-Host "  [!] Intune checklist not written: $($intuneChecklistView.Note)" -ForegroundColor Yellow
            }
        } catch { Write-Warning "Intune checklist publish failed: $($_.Exception.Message)" }
    }

    # Multi-page report site (landing page, one page per workload, ActionPlan.csv):
    # observed configuration, the NRG baseline verdict and the independent comparison
    # kept apart. A VIEW over the findings: it changes no verdict. Written with every
    # run that writes reports, into its own folder beside the other files.
    if (-not $SkipReportSite -and (Get-Command Publish-TPReportSite -ErrorAction SilentlyContinue)) {
        $siteDir = Join-Path $OutputPath "$baseName-report"
        try {
            $null = Publish-TPReportSite -Metadata $reportMetadata -Findings $findings -OutputPath $siteDir `
                -BaselineCompliance $baselineCompliance -Coverage (Get-TPCoverage) -ScubaResultsPath $ScubaResultsPath
            Write-TPReportFile 'Report site (index.html)' (Join-Path $siteDir 'index.html')
            Write-TPReportFile 'Action plan (csv)' (Join-Path $siteDir 'ActionPlan.csv')
            foreach ($f in @(Get-ChildItem -LiteralPath $siteDir -File -ErrorAction SilentlyContinue)) {
                Set-TPSensitiveFileAcl -Path $f.FullName -ErrorAction SilentlyContinue
            }
        } catch { Write-Warning "Report site publish failed: $($_.Exception.Message)" }
    }

    # Delta report (if baseline provided)
    if ($BaselineResults -and (Test-Path -LiteralPath $BaselineResults) -and (Get-Command Publish-TPDeltaReport -ErrorAction SilentlyContinue)) {
        $deltaPath = Join-Path $OutputPath "$baseName-delta.md"
        try {
            Publish-TPDeltaReport -CurrentFindings $findings -CurrentRawData $rawDataSnapshot -BaselineResultsPath $BaselineResults `
                -Metadata $reportMetadata -OutputPath $deltaPath
            Write-TPReportFile 'Delta' $deltaPath
            Set-TPSensitiveFileAcl -Path $deltaPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "Delta publish failed: $($_.Exception.Message)" }
    }

    # Monthly compliance report (v4.11.0) — recurring MSP deliverable, HIPAA-framed.
    # Driven by an operator-maintained delta file (-MonthlyDeltaPath). The output
    # JSON file is intended to become the next month's -MonthlyPriorPath input.
    if ($MonthlyReport) {
        if (-not $MonthlyDeltaPath) {
            Write-Warning "-MonthlyReport requires -MonthlyDeltaPath <path-to-delta.psd1>; skipping monthly report."
        }
        elseif (Get-Command Publish-TPMonthlyReport -ErrorAction SilentlyContinue) {
            $monthlyDir  = Join-Path $OutputPath 'monthly'
            $deltaBase   = [IO.Path]::GetFileNameWithoutExtension($MonthlyDeltaPath)
            $monthlyPath = Join-Path $monthlyDir "$deltaBase.html"
            try {
                Publish-TPMonthlyReport `
                    -Findings $findings `
                    -Metadata $reportMetadata `
                    -DeltaPath $MonthlyDeltaPath `
                    -PriorMonthPath $MonthlyPriorPath `
                    -OutputPath $monthlyPath | Out-Null
                Set-TPSensitiveFileAcl -Path $monthlyPath -ErrorAction SilentlyContinue
                Set-TPSensitiveFileAcl -Path ($monthlyPath -replace '\.html$', '.json') -ErrorAction SilentlyContinue
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
# Get-TPCoverageScore call when Maturity is unavailable (helper threw, or
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
    $cov = Get-TPCoverageScore -Findings $findings -ErrorHandling 'Gap'
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
$footerVer    = if ($TPAssessmentVersion)   { $TPAssessmentVersion }   else { $script:TPAssessmentVersion }
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
        $gs = Get-TPGapSummary -Findings $findings
        Write-Host "                 = $($gs.DistinctDeficiencies) distinct requirement(s) + $(@($gs.NamedViews).Count) named-object view(s) of a control that already reports the shortfall; $($gs.FoldedControls) more control(s) share a setting and are already counted once" -ForegroundColor DarkGray
    } catch { Write-Verbose "Gap summary skipped: $($_.Exception.Message)" }
}
Write-Host "  Not Applicable $($s.NA)"                                         -ForegroundColor DarkGray
if ($s.Error -gt 0) {
    Write-Host "  Error          $($s.Error) (collector failures — excluded from score)" -ForegroundColor Magenta
}
# Controls that read the same setting count once (Config/control-links.json),
# so the scored total can be below the number of distinct controls reported.
$distinctControls = @($findings | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'ControlId' -Default '') } | Where-Object { $_ } | Sort-Object -Unique).Count
$notes = @()
if ($distinctControls -gt $footerCount) { $notes += "$distinctControls controls reported; controls that read the same setting count once" }
if ($findings.Count -gt $distinctControls) { $notes += "$($findings.Count) findings: some controls report once per domain or object" }
$perInstance = if ($notes.Count -gt 0) { " ($($notes -join '; '))" } else { '' }
Write-Host "  Total          $footerCount scored$perInstance"                  -ForegroundColor White
Write-Host "  Output         $OutputPath"                                      -ForegroundColor White
$selNotice = Format-TPControlSelectionNotice -Selection (Get-TPObjectField -Item $reportMetadata -Key 'ControlSelection' -Default $null)
if ($selNotice) { Write-Host "  $selNotice" -ForegroundColor Yellow }
if ($reportMetadata.Contains('Maturity') -and $reportMetadata['Maturity']) {
    $m = $reportMetadata['Maturity']
    Write-Host "  Maturity       $($m.Label) (tier $($m.Tier)/5, score $($m.Score)/100)" -ForegroundColor Cyan
    # A provisional label is one some checks produced no verdict for: the
    # reason prints beside it, never only in the JSON.
    if ((Get-TPObjectField -Item $m -Key 'EvidenceComplete' -Default $true) -ne $true) {
        Write-Host "                 $(Get-TPObjectField -Item $m -Key 'Qualification' -Default 'Evidence incomplete.')" -ForegroundColor Yellow
    }
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
# Threshold codes (10/11/12) land on $script:TPThresholdExitCode — a separate
# channel from $script:TPFatalExitCode (1=auth, 4=fatal). This preserves the
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
        # The gate reads counts and a score computed over the scored controls only.
        # When some checks produced no verdict a clean exit covers less than it
        # looks like, so say so; the exit code itself is unchanged.
        if ((Get-TPObjectField -Item $mat -Key 'EvidenceComplete' -Default $true) -ne $true) {
            Write-Warning "Threshold check ran on incomplete evidence: $(Get-TPObjectField -Item $mat -Key 'Qualification' -Default 'some findings produced no verdict.') A clean exit here is not a verdict on the controls that were not scored."
        }

        if ($FailOnCritical -gt 0 -and $critGaps -ge $FailOnCritical) {
            Write-Host "[!] Threshold breached: $critGaps Critical gaps (limit $FailOnCritical) — exiting 10" -ForegroundColor Red
            $script:TPThresholdExitCode = 10
        }
        elseif ($FailOnHigh -gt 0 -and $highGaps -ge $FailOnHigh) {
            Write-Host "[!] Threshold breached: $highGaps High gaps (limit $FailOnHigh) — exiting 11" -ForegroundColor Red
            $script:TPThresholdExitCode = 11
        }
        elseif ($FailOnScoreBelow -gt 0) {
            if ($mat.Contains('Score') -and $null -ne $mat.Score) {
                $maturityScore = [int]$mat.Score
                if ($maturityScore -lt $FailOnScoreBelow) {
                    Write-Host "[!] Threshold breached: score $maturityScore < $FailOnScoreBelow — exiting 12" -ForegroundColor Red
                    $script:TPThresholdExitCode = 12
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
$collectorExceptions = @(Get-TPExceptions)
if ($findings.Count -eq 0) {
    $script:TPSuccessExitCode = 2
} elseif ($collectorExceptions.Count -gt 0) {
    # Partial collection: at least one collector raised, but some findings made it.
    $script:TPSuccessExitCode = 3
} else {
    $script:TPSuccessExitCode = 0
}

}
catch {
    # Outer fatal-error catch (v4.6.3 P2).
    # $script:TPFatalExitCode may have been pre-set by an earlier explicit
    # condition (auth failure = 1); otherwise fall through to 4 (fatal).
    if (-not $script:TPFatalExitCode) { $script:TPFatalExitCode = 4 }
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
        try { Disconnect-TPServices } catch { }
    }
}

# Resolve and emit the exit code (must be done OUTSIDE the try/catch/finally
# so the exit happens after the disconnect runs).
# Precedence: fatal (auth/crash) > threshold (policy gate) > success.
# Threshold only applies when no fatal error occurred — a crash that happens
# to leave a threshold value set must not masquerade as a graceful breach.
if ($script:TPFatalExitCode) {
    exit $script:TPFatalExitCode
}
if ($script:TPThresholdExitCode) {
    exit $script:TPThresholdExitCode
}
if ($null -ne $script:TPSuccessExitCode) {
    exit $script:TPSuccessExitCode
}
exit 0
# NRG-Assessment

**Read-only M365 security assessment framework for managed service providers.**

Built by Matthew Levorson — NRG Technology Services / NextLayerSec LLC  
GitHub: [Blackvectra/NRG-Assessment-Tool](https://github.com/Blackvectra/NRG-Assessment-Tool)

[![CI](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/ci.yml)
[![Secret Scan](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/secret-scan.yml/badge.svg?branch=main)](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/secret-scan.yml)
[![Release](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/release.yml/badge.svg)](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/release.yml)
[![PowerShell 7](https://img.shields.io/badge/PowerShell-7.0%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
[![Controls](https://img.shields.io/badge/controls-204-0c7d8c)](Config/controls.json)

[![OpenSSF Best Practices](https://img.shields.io/badge/OpenSSF_Best_Practices-Passing_(self--assessed)-blue)](docs/OPENSSF-BEST-PRACTICES.md)
[![SSDF](https://img.shields.io/badge/NIST_SP_800--218-self--attested-green)](docs/SECURE-DEVELOPMENT.md)
[![CISA BOD 20-01](https://img.shields.io/badge/Vulnerability_Disclosure-CISA_BOD_20--01-orange)](docs/VULNERABILITY-DISCLOSURE-POLICY.md)
[![Security Policy](https://img.shields.io/badge/security-policy-red)](SECURITY.md)

<sub>Workflow badges render for signed-in users with repository access (this repo is private).</sub>

> **Security:** Report vulnerabilities privately via the [GitHub Security tab](https://github.com/Blackvectra/NRG-Assessment-Tool/security/advisories/new) or `security@nrgtechservices.com`. We follow a 7-day Critical / 30-day High fix SLA; see [`SECURITY.md`](SECURITY.md) for the full policy.

---

## What It Does

> **New here, or back after a while?** [`docs/WHAT-CAN-I-RUN.md`](docs/WHAT-CAN-I-RUN.md) lists every entry point, what it needs, and what it produces — including what this tool deliberately does *not* cover.

Connects to a Microsoft 365 tenant via delegated auth (or GDAP for MSP batch runs), collects raw configuration data across all M365 services, evaluates **204 security controls with license-aware scoring**, and produces client-ready HTML and Markdown reports with citations into six frameworks (CIS M365, CISA SCuBA, NIST 800-53r5, CMMC 2.0, ISO 27001, MITRE ATT&CK) plus CIS Controls v8.1.

**Zero writes to tenant. Read-only by design.**

Four entry points:

| Script | Purpose |
|---|---|
| `Invoke-NRGAssessment.ps1` | Single-tenant interactive assessment |
| `Invoke-NRGBatchAssessment.ps1` | All clients in `Config/clients.json` via GDAP, one login |
| `Invoke-NRGSignInTriage.ps1` (+ batch variant) | Admin-scope sign-in IoC triage — ranks likely-compromised users |
| `Invoke-NRGEmailAssessment.ps1` | Per-user mailbox incident-response deep-dive (Email-IR mode) |

---

## First-Time Setup

On a fresh machine, run this once:

```powershell
# After extracting the zip
cd C:\path\to\NRG-Assessment-Tool
.\Install-NRGPrerequisites.ps1
```

This installs/pins required PowerShell modules (with EOM at the known-good 3.2.0 version), sets execution policy, unblocks files, and installs Python+openpyxl if you want XLSX compliance matrices. Skip Python with `-SkipPython`.

## Quick Start

> **First time on Windows?** After extracting, unblock the files and set execution policy:
> ```powershell
> Get-ChildItem -Path . -Recurse | Unblock-File
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```



### Prerequisites

```powershell
# Install required modules. Versions match the manifest's pinned ranges —
# Graph.Authentication [2.20.0, <3.0) and ExchangeOnlineManagement [3.2.0, <4.0);
# major-version bumps are adopted deliberately, never by surprise.
Install-PSResource -Name Microsoft.Graph.Authentication -Version '[2.20.0,2.99.99]' -TrustRepository
Install-PSResource -Name ExchangeOnlineManagement       -Version '[3.2.0,3.99.99]'  -TrustRepository
Install-PSResource -Name MicrosoftTeams                 -TrustRepository   # optional — Teams collector
Install-PSResource -Name Microsoft.Online.SharePoint.PowerShell -TrustRepository   # optional — SPO-2.x/3.x tenant controls
Install-PSResource -Name Pester -Version '[5.5.0,5.99.99]' -TrustRepository        # tests only
```

### Single Tenant Run

```powershell
# Clone repo
git clone https://github.com/Blackvectra/NRG-Assessment-Tool
cd NRG-Assessment-Tool

# Run assessment
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com

# Output lands in .\output\<timestamp>\
```

### Quick Triage, Delta, and CI Exit Codes

For automation pipelines and fast triage:

```powershell
# Quick scan — only Critical + High controls (faster, lower noise)
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com -Quick

# Compare against a prior baseline JSON — emits a delta report
# (score delta, finding regressions, CA / role / OAuth / DMARC drift)
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com `
    -BaselineResults .\output\client\20260415-results.json

# CI / Task Scheduler thresholds — non-zero exit when posture drifts
# Exit 10 = critical threshold, 11 = high threshold, 12 = score threshold
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com `
    -FailOnCritical 1 -FailOnHigh 5 -FailOnScoreBelow 70
```

Every run now classifies the tenant into a **Tenant Security Maturity Tier** (Initial / Developing / Defined / Managed / Optimizing) — the label appears in the console summary and is embedded in the JSON metadata for downstream dashboards.

### MSP Batch Run (GDAP)

```powershell
# 1. Add your clients to Config\clients.json (TenantId + DelegatedOrg required)
# 2. One browser login covers all tenants via GDAP relationships
.\Invoke-NRGBatchAssessment.ps1

# Run a single client
.\Invoke-NRGBatchAssessment.ps1 -OnlyClient example.com

# Preview what would run
.\Invoke-NRGBatchAssessment.ps1 -WhatIf
```

### Incident Response — Email-IR (mailbox compromise)

Three separate entry points for a *suspected account compromise* (BEC, stolen
credentials, attacker inbox rules, mass outbound). These are distinct from the
posture assessment above — they focus on one or more **mailboxes during an
incident**, not the 204 tenant controls.

**1. You already know which user** — `Invoke-NRGEmailAssessment.ps1`
Runs with **the user's own credentials** (delegated sign-in, *no admin scope
needed*). Scans inbox rules, forwarding, outbound activity, phish origin, auth
methods, and OAuth consents for that one mailbox.

```powershell
# Assess one mailbox (browser sign-in as that user, or an admin who can read it)
.\Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@corp.com

# Wider sent-items window + public RDAP domain-age enrichment
.\Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@corp.com -WindowDays 14 -EnableThreatIntel

# Unattended / SOAR: no prompts, exit 10 if any Critical IoC is found
.\Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@corp.com -NonInteractive -FailOnCriticalIoC
```
Output: `.\output\<upn>\<timestamp>-email-incident.html` + `-email-incident.md` + `-email-results.json`.

**2. You suspect compromise but don't know which user** — `Invoke-NRGSignInTriage.ps1`
**Admin sign-in.** Pulls the tenant sign-in logs, scores every user for IoCs
(failed→success bursts, anonymous-IP / Tor, impossible travel, Identity
Protection risky users, out-of-state), ranks them, then auto deep-dives the top
users' mailboxes in the same session (`Mail.Read.All`).

```powershell
# Full triage: rank users, then deep-dive the top 5 scoring >= 30
.\Invoke-NRGSignInTriage.ps1

# Triage only — rank users, do NOT read any mailbox (e.g. BAA restriction)
.\Invoke-NRGSignInTriage.ps1 -SkipMailDive

# Dive deeper / widen the window
.\Invoke-NRGSignInTriage.ps1 -DeepDive 10 -WindowDays 14
```
Output goes to `.\output\IR-Triage\`. Required admin scopes: `AuditLog.Read.All`,
`IdentityRiskyUser.Read.All`, and `Mail.Read.All` (only when deep-diving).

**3. Morning sweep across every GDAP client** — `Invoke-NRGBatchSignInTriage.ps1`
Runs the sign-in triage across all active clients in `Config\clients.json`, one
login via GDAP — the same multi-tenant model as the batch assessment.

```powershell
.\Invoke-NRGBatchSignInTriage.ps1
```

> Tip: run `Get-Help .\Invoke-NRGSignInTriage.ps1 -Full` for every parameter, or
> open the script header — each lists its full switch set and exit codes
> (`0` ok, `1` auth, `10` critical IoC found).

### Local Web GUI

For operators who prefer clicking over typing, `-Web` boots a local browser
GUI instead of the terminal flow. The GUI is a Pode-backed loopback server
on `127.0.0.1:8765`; it never exposes itself to the network and never sends
tenant data anywhere. Pick a tenant, click "Run scan", watch progress live,
and view the existing HTML report inline.

```powershell
# One-time install (free, MIT-licensed PSGallery module)
Install-Module Pode -MinimumVersion 2.10.0 -Scope CurrentUser

# Launch the GUI (auto-opens your default browser)
.\Invoke-NRGAssessment.ps1 -Web

# Use a different port if 8765 is taken
.\Invoke-NRGAssessment.ps1 -Web -WebPort 9000
```

The GUI consumes the same `Config/clients.json` as the CLI, scans run via the
same module functions, and reports land in the same `./output/` directory —
so CLI and GUI workflows can be mixed freely.

---

## Architecture

```
Invoke-NRGAssessment.ps1          ← Entry point (validated params, try/finally)
Invoke-NRGBatchAssessment.ps1     ← GDAP batch runner (one auth, all tenants)
NRG-Assessment.psm1               ← Module loader (recursive dot-source, path traversal check)
NRG-Assessment.psd1               ← Module manifest (323 exports, dependency declarations)

Lib/                              ← Shared infrastructure
  Add-NRGFinding.ps1              State management (findings, exceptions, coverage, raw data)
  Connect-NRGServices.ps1         Auth (interactive browser MFA / app-only cert; process-scoped MSAL)
  ConvertTo-NRGHtmlSafe.ps1       XSS prevention (all tenant data escapes through here)
  Get-NRGControlDefinitions.ps1   controls.json loader + content validation

Collectors/                       READ-ONLY — raw data collection, no scoring
  AAD/    (7 files)               Auth policies, CA, users+MFA, roles, PIM, identity governance, inventory
  EXO/    (3 files)               Mailbox config, EXO inventory, Defender policies
  DNS/    (1 file)                SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC
  Intune/ (3 files)               Device compliance, app protection, endpoint security
  SharePoint/ Teams/ Purview/ PowerPlatform/ AI/   (1 file each)

Evaluators/                       SCORING ONLY — reads raw data, writes findings
  Test-NRGControl-AAD.ps1         46 controls
  Test-NRGControlAppPermissions.ps1  2 controls  (app-only Graph/EXO/SPO permissions)
  Test-NRGControlEXO.ps1          31 controls
  Test-NRGControlDefender.ps1     23 controls
  Test-NRGControlTeams.ps1        22 controls
  Test-NRGControlPurview.ps1      18 controls
  Test-NRGControlSharePoint.ps1   17 controls
  Test-NRGControlIntune.ps1       17 controls
  Test-NRGControlPowerPlatform.ps1 11 controls
  Test-NRGControlDNS.ps1          10 controls

Publishers/                       (7 files)
  Publish-NRGAssessmentHTML.ps1   Interactive HTML report with exec summary + findings
  Publish-NRGAssessmentSummary.ps1 Markdown report for OneNote / GitHub
  Publish-NRGComplianceMatrix.ps1 Framework compliance matrix (XLSX when openpyxl present)
  Publish-NRGDeltaReport.ps1      Baseline-vs-current drift report
  Publish-NRGMonthlyReport.ps1    Monthly maturity-tier trend report
  Publish-NRGRemediationPlaybook.ps1 / -RemediationScript.ps1  Remediation guidance

Config/
  controls.json                   204 control definitions + framework citations
  frameworks.json                 CIS, SCuBA, NIST, CMMC, MITRE metadata
  clients.json                    MSP client registry (TenantId + GDAP config)
  schema/                         JSON Schemas for controls.json + clients.json (CI-enforced)
  framework-baselines/            Authoritative SCuBA v1.8.0 + CIS Controls v8.1 ID lists (CI-enforced)

Testing/                          65 Pester suites — the FULL suite gates every PR
  NRG.Security.Tests.ps1          OWASP/ASVS static + runtime invariants
  NRG.FrameworkAccuracy.Tests.ps1 Framework citations vs authoritative baselines
  NRG.GraphRequest.Tests.ps1      Graph response shape (StrictMode paging regression guard)
  ...                             coverage-score, license, maturity-tier, report, helper suites

.github/workflows/                6 workflows: ci, secret-scan, codeql, dependency-review, scorecard, release
```

---

## Controls Coverage

**204 controls across 9 workloads** — every count below is generated from `Config/controls.json` and schema-validated in CI.

| Workload | Controls | Key Areas |
|---|---|---|
| Entra ID (AAD) | 46 | MFA, legacy auth, CA policies, PIM, guest access, app consent, risky users & workload identities, break-glass |
| Exchange Online | 31 | Mailbox audit, SMTP auth, auto-forward, DKIM, anti-phish, priority-account protection, DMARC |
| Defender for O365 | 23 | Safe Attachments/Links, spoof intel, ZAP, quarantine, attack-simulation training, preset policies |
| Teams | 22 | Federation allowlists, meeting lobby, PSTN bypass, recording expiry, live events, app governance |
| Purview | 18 | Unified audit log, DLP, sensitivity labels, retention, insider risk |
| SharePoint / OneDrive | 17 | External sharing, link expiration, email attestation, guest expiry, unmanaged sync |
| Intune | 17 | Device compliance, BitLocker, EDR, ASR rules, MAM conditional launch |
| Power Platform | 11 | Tenant isolation, DLP connector classification, maker governance |
| DNS Email Auth | 10 | External SPF, DKIM, DMARC enforcement, MTA-STS, TLS-RPT, DNSSEC — resolved from public DNS, not just tenant config |

**Severity distribution:** 11 Critical · 92 High · 65 Medium · 27 Low

**Framework citations per control:** CIS M365 Foundations v6.0.1 · CISA SCuBA (ScubaGear v1.8.0 policy IDs) · NIST SP 800-53 Rev 5 · CMMC 2.0 · ISO/IEC 27001:2022 · MITRE ATT&CK — plus CIS Controls v8.1 safeguards, SOC 2, HIPAA, and PCI DSS references. Controls whose license requirement the tenant doesn't meet are routed to an Upgrade Unlocks section instead of dragging the score down.

### NIST SP 800-53 Rev 5 — family rollup

All 204 controls carry an 800-53 citation, and the report rolls them up **by control family**, not only as a single aggregate percentage. Every other view in the report groups by M365 workload — the right lens for the engineer doing the remediation, the wrong one for a reader working an 800-53, FedRAMP, or CMMC assessment, whose own POA&M is organized by family.

The rollup covers 12 families and 59 distinct 800-53 controls, and appears in three places: a family table in the HTML report, the same table in the Markdown summary, and a dedicated `NIST Families` sheet in the XLSX matrix.

Two things it will not do. A control mapped to more than one family is counted in **each** family it cites, so family rows do not sum to the assessment total — the report says so on the page rather than leaving a reader to discover it. And `NotApplicable` rows stay out of the coverage percentage entirely: a control the tool could not evaluate is not a control the tenant passed, and a family with nothing assessable reads "Not assessed", never a red 0%.

### NIST-first reporting (NRG default)

NRG's practice is built on NIST SP 800-53, so **the report defaults to NIST only**:

```powershell
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com          # NIST only
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com -Framework All    # all four
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com -Framework CIS    # one other
```

**This narrows the report, never the assessment.** Every one of the 204 controls still carries its CIS, SCuBA, CMMC, ISO 27001, SOC 2, HIPAA, PCI DSS and MITRE citations; every framework is still scored; the results JSON and the XLSX matrix are byte-identical either way. `-Framework` decides what the HTML puts in front of the reader and nothing else — a test renders the report both ways and asserts no framework score moves.

`-NISTMatrix` additionally emits a **standalone NIST-only HTML report** alongside the Markdown and XLSX — a self-contained page with the family table, the full control matrix, the not-assessable list and the physical/device section, that names no other framework anywhere on it. That's the artifact for a client who is assessed against 800-53 and shouldn't have to read their posture out of a multi-framework document.

> **The NLS twin defaults to `All`.** That is the single deliberate behavioral difference between the two repos, and each pins its own default by test — it's exactly the setting a careless sync would silently flip, and the failure would be invisible because the report still renders and still scores correctly.

### Standalone NIST 800-53 matrix

Clients assessed against 800-53 should not have to read their posture out of a multi-framework report. `-NISTMatrix` emits a **single-framework deliverable** from the same run — Markdown always, XLSX when `openpyxl` is present:

```powershell
# Just the NIST matrix, no other sidecars
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com -NISTMatrix

# -AllFiles implies it, so the full profile stays a superset
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com -AllFiles
```

The workbook has six sheets: **Summary** (posture, scope, caveats), **Control Matrix** (one row per 800-53 control and the tenant control evidencing it — the matrix proper), **By Control**, **By Family**, **Physical & Device**, and **Not Assessed**. Every row carries the official Rev 5 control title from [`Config/nist-800-53-catalog.json`](Config/nist-800-53-catalog.json), because a row reading `AC-6(9)   Gap` is not something an auditor can work from.

This is **purely additive**. `Publish-NRGComplianceMatrix` keeps every framework it has today — CIS, SCuBA, CMMC, ISO 27001, SOC 2, HIPAA, PCI DSS, MITRE — and none of the existing report changes. Same findings, same scores, one extra document organized the way an 800-53 reader works. A test asserts that publishing the NIST matrix does not move the CIS, SCuBA or CMMC score by a single point.

Three things the document is careful not to claim:

- **The score is coverage of what was exercised, not baseline completion.** A tenant scan reaches 59 of the 800-53 controls. A Low, Moderate or High baseline contains many that no cloud scan can reach, and the Summary sheet says so in as many words.
- **Physical, media, maintenance and personnel controls stay unscored**, with the evidence an assessor has to collect directly and two or more implementation options each.
- **Controls that came back `NotApplicable` are named, not dropped.** They get their own sheet stating that a missing license or an unconnected service is neither a pass nor a gap. A matrix that omits what it could not evaluate reads as full coverage of a smaller scope.

### Improvement plan — the one that moves the number

Every other deliverable here reports a **position**: you are at 61%, these families are weak, these controls failed. `-ImprovementPlan` reports a **route**.

```powershell
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com -ImprovementPlan
```

Ordered steps against NIST 800-53 Rev 5. Each one carries the exact projected coverage after it, the 800-53 families it moves, and **what the change will break** — because a plan gets approved by someone accountable for the disruption, not just for the score.

Two tracks, because that is how the work actually splits:

- **Do now** — licensed, and documented as changing nothing a user will notice. There is nothing to plan around; these go in this week.
- **Schedule** — licensed, but somebody will feel it. Needs a window, a message to users, or a discovery pass first.

A control lands in *Do now* only if the tool has **documented** that users notice nothing. A control with no impact entry never lands there: an undocumented impact is not evidence of no impact, and that is exactly the mistake that gets a change approved without anyone checking.

**The projection is arithmetic, not an estimate.** Coverage is `round(100 * (Satisfied + 0.5*Partial) / Scored)` — the same formula and denominator rule as every other score in the tool. Closing a gap adds 1.0 to the numerator, closing a partial adds 0.5, and the denominator does not move because the control was already assessed. Every cumulative figure is recomputed from counts rather than accumulated from rounded per-step deltas, so there is no drift; a test re-derives all of them independently and fails if the implementation ever starts summing.

License-blocked controls are listed separately and get **no projected number**. Buying a license changes the denominator, and a licensed-but-unconfigured control is still a gap — a figure there would be a guess dressed as arithmetic.

Family movement is computed by replaying the plan through the same rollup, not by per-family arithmetic. A control supporting two families moves both, and hand-rolled arithmetic gets that wrong in a way nobody notices until an auditor adds the column up.

**Completing every step does not make an organization 800-53 compliant.** It closes what a Microsoft 365 tenant scan and an endpoint scan can observe — a subset of 800-53, and 14 of the 20 families. The plan states that ceiling on its first page rather than letting a reader infer that 100% means done.

Single framework on purpose: the document names NIST and nothing else. A plan that hedges across four frameworks orders its steps for none of them, and a test greps for the others and fails on any leak.

### System Security Plan — NIST 800-171 Rev 2 / CMMC Level 2

`-SSP` turns the same run into a **worked System Security Plan** against all 110 NIST SP 800-171 Rev 2 requirements — the baseline CMMC Level 2 is assessed against. Markdown, self-contained HTML, and an XLSX working copy:

```powershell
# The plan, from the same scan
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com -SSP

# With the client's written answers
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com -SSP `
    -SSPAnswers .\Config\ssp\example.com.psd1
```

Every requirement is a row that answers four questions in order: **is this in place**, **what proves it**, **how do we close it**, and **what will closing it do to the business**. The last one is the reason the document exists. Every other deliverable here answers "what is wrong"; a client reading a gap list asks "if we fix that, what breaks?" — and until now the tool had no answer, so remediation got scheduled on guesswork or not scheduled at all. [`Config/operational-impact.json`](Config/operational-impact.json) holds that answer for all 230 controls and it renders beside every action, with what users notice, what it costs administrators, what actually goes wrong, and whether it can be backed out.

The join needs no mapping table: a CMMC practice ID embeds its 800-171 requirement number (`IA.L2-3.5.3` → `3.5.3`), and every control already carries a CMMC citation. The endpoint checks use the explicit `Nist171` array in `device-controls.json`.

**41 of the 110 requirements have automated evidence here. The other 69 do not, and the document never pretends otherwise.** They are policy, process, physical security and personnel — no scan reaches them. They are answered by the client in `Config/ssp/<client>.psd1` (see [`Config/ssp/example.psd1`](Config/ssp/example.psd1)), read with `Import-PowerShellDataFile` so an answers file emailed between the MSP and the client can never execute. Requirements with neither evidence nor an answer are counted on the first page and listed on the last, because an SSP with 69 blanks is not a finished document and a reader must not be able to mistake it for one.

Four rules the generator enforces, tested adversarially in `NRG.SSP.Tests.ps1`:

- **A requirement with no mapped control is never derived as implemented.** A test feeds it a findings set in which every control in the tool passes and proves those 69 still refuse to claim anything.
- **A mapped control that produced no finding is an unknown, never a pass.** Skipped workloads and unlicensed features are the normal case.
- **A status the client asserts never counts as one the tool verified.** It renders stamped *client-attested* and stays out of the tool-verified total. That separation is the difference between an SSP and a wish list.
- **An undocumented operational impact renders as "not documented", never as "no impact."** "No impact" is the answer that gets a change approved without anyone checking.

Rev 2, not Rev 3 — DoD Class Deviation 2023-O0006 makes Rev 2 the standard CMMC Level 2 is scored against, and publishing against Rev 3 would have the client assessed on the wrong one.

### Device guide — reference material, no scanning

Not everything is a scan. `New-NRGDeviceGuide.ps1` renders a **printable NIST device and endpoint guide** and connects to nothing — no sign-in, no Graph, no Exchange Online, and no endpoint is touched:

```powershell
# Markdown + self-contained HTML, no tenant required
.\New-NRGDeviceGuide.ps1 -ClientName 'Example Client'

# Optionally annotate with what a prior run already evidenced
.\New-NRGDeviceGuide.ps1 -ResultsPath .\output\client\20260825-results.json
```

31 controls spanning five areas — Endpoint Protection, Device Identity and Access, Media Protection, Physical and Environmental, Maintenance and Personnel — with **98 implementation options**. Each control states what it covers, how to satisfy it, and (where the tenant cannot see it) the evidence to keep.

That independence is the point: the guide is usable before a tenant is connected, during a sales conversation, and on a site with nothing open. The HTML references no external asset and carries print styling, so it emails, opens offline, and prints.

Two properties the tests enforce, because both are easy to break by accident:

- **It touches nothing.** A static guard fails the build if `Invoke-NRGGraphRequest`, `Connect-MgGraph`, `Invoke-RestMethod` or friends ever appear in either file. Otherwise the guide quietly becomes something that needs an authenticated session, and you find out in front of a client.
- **Findings never change the advice.** `-ResultsPath` may change what the guide reports as *already done*; it may never change what it recommends you *do*. A test diffs the rendered options with and without findings and requires them identical — otherwise two clients with the same obligations get different advice because one happened to be scanned first.

Every control carries **two or more** options by design. A single option is a directive, and a client already standardized on a third-party endpoint suite or an existing badge system should be able to satisfy the control with what they have.

### Endpoint compliance — `DeviceCompliance` scanner

The tenant half of the assessment reads Intune **policy**. This reads device **state** — what the machine actually reports, not what a policy asked for.

`Device\Invoke-NRGDeviceCompliance.ps1` runs **on the endpoint**, pushed by ConnectWise RMM (or an Intune platform script) as SYSTEM. It writes one JSON file; the RMM collects it; the assessment ingests a folder of them:

```powershell
# On the endpoint, via RMM script task
.\Invoke-NRGDeviceCompliance.ps1          # -> C:\ProgramData\NRG\device-compliance.json

# On your workstation, same run as the tenant assessment
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com `
    -DeviceResults .\collected\clientname\ -NISTMatrix
```

**35 checks** across encryption and boot integrity, malware defense, network exposure, accounts and privilege, patch state, session lock, legacy surface and audit policy. Each maps to an 800-53 control, so device findings land in the same report, the same score, and the same NIST family rollup as everything else.

Three properties, all enforced by test:

- **Windows PowerShell 5.1.** Stock Windows ships 5.1, not 7. The endpoint script is the single carve-out from the repo-wide `#Requires -Version 7` floor, and the security suite asserts it *earns* that exception — no MSHTML, no COM, no `Invoke-Expression`, no network — rather than silently bypassing the rule.
- **Standalone.** No module import, no network, no credential. It has to run on a bare machine with nothing installed.
- **Read-only.** It reads local state and writes exactly one file. A static guard fails the build on `Set-ItemProperty`, `Enable-BitLocker`, `Set-MpPreference` and friends.

**Elevation is reported, never assumed.** BitLocker, TPM, Secure Boot and the audit policy return nothing without admin rights — which is indistinguishable from *"not configured"*. Those land as `NotAssessed` and are **excluded from the fleet denominator**, so a control reads *"2 of 5 compliant — 1 device could not run this check (the collector ran without administrative rights)"* rather than inventing a pass or a failure for a machine nobody measured.

Findings aggregate per control, not per device — one row saying *"41 of 60 failing"* with the hostnames in `AffectedObjects`, instead of 2,100 rows nobody reads.

### Device build standard

The guide above is organized by 800-53 control. The **build standard** is the same material sequenced the way the work happens — a technician images, enrolls, encrypts, hardens and hands over; they do not work AC-11 then SC-28. It is emitted by the same command:

```powershell
.\New-NRGDeviceGuide.ps1 -ClientName 'Example Client'
#   nist-device-guide.md / .html            control reference
#   nist-device-guide-baseline.md / .html   build standard
```

**27 requirements across 5 lifecycle stages, 23 of them mandatory** — procurement and intake, provisioning and enrollment, hardening, in service, offboarding and disposal. It leads with a printable checklist (one unchecked box per requirement) and puts the reasoning underneath, so the person doing the build gets the list and the person justifying an exception gets the argument.

Every requirement states **why** it exists, **how** to do it, the 800-53 control it satisfies, and whether the assessment can verify it. That last part is the honest one: roughly a third of the standard is build-time work no tenant scan can confirm — BIOS passwords, firmware settings, certificates of destruction — and those rows say *"not checkable from the tenant"* rather than letting a reader assume the assessment covers everything listed.

The mandatory set is deliberately small and non-negotiable: MDM enrollment, per-device local admin passwords, full-disk encryption with escrowed keys, EDR, patching within a window, and the Conditional Access enforcement that gives all of it teeth. A device that misses one is not a managed device; it is an unmanaged device with an asset tag.

### Physical, media and device controls

A tenant scan can evidence endpoint posture — encryption, patch level, screen lock, endpoint protection, device identity. It cannot see a locked server room, a certificate of destruction, or a returned badge. Those are still 800-53 controls a client working an 800-53 or CMMC assessment has to satisfy, and leaving them out silently is the dangerous option: a reader looking at a clean family table would reasonably infer the physical families were assessed and passed.

So the report carries a **Physical, Media and Device Controls** section covering 31 800-53 controls spanning AC, CM, IA, MA, MP, PE, PS, SC and SI, driven by [`Config/nist-physical.json`](Config/nist-physical.json). Every row states its scope:

| Scope | Meaning | Count |
|---|---|---:|
| **Tenant** | Fully evidenced by controls scored in this assessment — BitLocker/FileVault, ASR, LAPS, Windows Hello, update rings, device compliance, endpoint DLP | 10 |
| **Hybrid** | The tenant evidences part; the rest is off-tenant — remote access, external systems, nonlocal maintenance, asset inventory, personnel termination | 7 |
| **Attested** | Not observable from Microsoft 365 under any configuration — facility access, visitor records, fire and environmental controls, media storage/transport/sanitization, maintenance personnel, wireless | 14 |

Each row names the device aspect it covers, links back to the tool controls that evidence it, states the evidence an assessor must collect off-tenant, and lists **two or more implementation options** — so a client already standardized on a third-party EDR or an existing badge system sees alternatives rather than a single directive.

**Nothing in this section is scored.** Tenant and Hybrid rows reflect findings already scored under their own control IDs; counting them again would double-count. Attested rows were never assessed and read *Attestation required* — never Satisfied, never Partial. That is the same rule the tool applies to advisory controls, enforced here by `NRG.NISTPhysical.Tests.ps1`, which feeds the posture a findings set that satisfies every control in the tool and asserts the attested rows still refuse to claim anything.

---

## Security Hardening

This tool is hardened against the threats it assesses. Every production file has:

- `#Requires -Version 7.0` — blocks PS 5.1 MSHTML injection (CVE-2025-54100)
- `Set-StrictMode -Version Latest` — catches uninitialized variables at runtime
- `$ErrorActionPreference = 'Stop'` — no silent error swallowing
- `-LiteralPath` on all file operations — no wildcard expansion (OWASP A01)
- `-Encoding utf8` on all file writes — explicit encoding (ASVS V16.2.3)
- Input validation on every parameter — UPN, domain, path, controlId (ASVS V5.1.3)
- `try/finally` session cleanup — guaranteed disconnect on any error (ASVS V7.3.2)
- TLS 1.2/1.3 enforced at entry — no downgrade (ASVS V11.2.2)
- Process-scoped MSAL token cache — no cross-session token leakage
- XSS prevention — all tenant data passes through `ConvertTo-NRGHtmlSafe` before HTML output

**controls.json content validation** — before any evaluator runs, the loader validates every control against allowlists for Severity, Workload, Category, ControlId format, prefix/workload consistency, injection patterns in Remediation, and duplicate IDs. Fail-closed: any violation throws.

The full Pester suite — **65 suites** — covers all of the above plus framework-citation accuracy, docs-freshness enforcement, and an end-to-end HTML-report render, and gates every pull request in CI.

```powershell
# Run the full test suite (same thing CI runs)
Invoke-Pester ./Testing -Output Detailed
```

---

## Client Registry (MSP)

Edit `Config\clients.json` to add tenants:

```json
{
  "ClientName":        "Client Name",
  "TenantDomain":      "client.com",
  "TenantId":          "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "DelegatedOrg":      "client.onmicrosoft.com",
  "DnsDomains":        ["client.com"],
  "SkipPurview":       false,
  "SkipTeams":         false,
  "SkipSharePoint":    false,
  "SkipIntune":        false,
  "SkipPowerPlatform": true,
  "SkipDNS":           false,
  "ThirdPartyEDR":     "Cortex XDR",
  "Notes":             "Business Standard tenant — Purview and Power Platform skipped.",
  "Active":            true
}
```

Get TenantId from: **Entra ID > Overview > Tenant ID**  
Get DelegatedOrg from: **Partner Center > Customers > client > Domains** (find the `.onmicrosoft.com` domain)

GDAP relationships must be active in Partner Center before the batch runner can access client tenants.

`ThirdPartyEDR` is optional. Set it when the client's endpoint protection is not Microsoft Defender (the same as `-ThirdPartyEDR 'Cortex XDR'` on a single run, including a `-FromResults` republish). The Microsoft Defender endpoint checks (INT-1.5, INT-2.1, INT-2.2 and the DEV-2.x endpoint checks) are then reported as covered by that product, **declared, not verified**, and left out of the score instead of scoring as gaps. A Defender check that actually passed keeps its result.

**One-time per client tenant:** AAD-8.2, AAD-11.3 and DEF-4.6 need Graph permissions that each tenant must consent to. Until then they report exactly which one is missing. A Global Administrator runs `.\Grant-NRGGraphConsent.ps1 -TenantDomain client.com` once and accepts the prompt for the organization.

**Power Platform (PPL-\*)** needs no module. The assessment signs in to the Power Platform admin API inside the same PowerShell session (one extra browser sign-in, usually completed automatically by your existing session) and reads it over REST. No child process is started. The account needs the Power Platform Administrator (or Global Administrator) role; app-only runs skip it.

---

## CI/CD

Six GitHub Actions workflows cover the repository. All run automatically on push and pull request to `main` (plus the scheduled sweeps noted below), and each also accepts a manual `workflow_dispatch`. Every job carries a `timeout-minutes` bound so a hung job cannot run to the six-hour default and burn a month of Actions minutes:

| Workflow | What it does |
|---|---|
| **CI** | Full Pester suite (65 suites) · PSScriptAnalyzer with SARIF upload · Export List Sync (psd1 ↔ psm1) · module-manifest validation · JSON-Schema enforcement of `controls.json` + `clients.json` |
| **Secret Scan** | Gitleaks (full history) + TruffleHog (live-verified secrets) — both SHA-pinned; weekly scheduled sweep |
| **CodeQL** | Scans the Actions workflow YAML for supply-chain weaknesses (PowerShell isn't CodeQL-supported; PSSA covers it) |
| **Dependency Review** | Flags vulnerable dependency changes on PRs |
| **Scorecard** | OpenSSF Scorecard supply-chain posture, weekly |
| **Release** | On `v*` tags: CycloneDX SBOM generation + Authenticode signature/integrity verification |

The framework-accuracy suite validates every SCuBA citation against the bundled ScubaGear v1.8.0 policy list, every CIS Controls citation against the v8.1 safeguard list, CMMC domain/level correctness, and ISO 27001:2022 Annex-A ranges — a wrong citation fails the PR, not the client report.

---

## License

**Proprietary — all rights reserved.** Copyright (c) 2026 Matthew Levorson — NRG Technology Services / NextLayerSec LLC. See [LICENSE](LICENSE).

This is not open-source software. No right to use, copy, modify, redistribute or resell it is granted without prior written permission from the owner, and receiving a copy does not itself confer one. Assessment reports produced by running the tool belong to the customer they were produced for.

---

*NRG-Assessment v4.14.0 · 204 posture controls + EMAIL/SIGNIN IR heuristics · 323 exported functions · full Pester suite (65 suites) gating CI*

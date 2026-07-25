# NRG-Assessment

**Read-only M365 security assessment framework for managed service providers.**

Built by Matthew Levorson — NRG Technology Services / NextLayerSec LLC  
GitHub: [Blackvectra/NRG-Assessment-Tool](https://github.com/Blackvectra/NRG-Assessment-Tool)

[![CI](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/ci.yml)
[![Secret Scan](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/secret-scan.yml/badge.svg?branch=main)](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/secret-scan.yml)
[![Release](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/release.yml/badge.svg)](https://github.com/Blackvectra/NRG-Assessment-Tool/actions/workflows/release.yml)
[![PowerShell 7](https://img.shields.io/badge/PowerShell-7.0%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
[![Controls](https://img.shields.io/badge/controls-195-0c7d8c)](Config/controls.json)

[![OpenSSF Best Practices](https://img.shields.io/badge/OpenSSF_Best_Practices-Passing_(self--assessed)-blue)](docs/OPENSSF-BEST-PRACTICES.md)
[![SSDF](https://img.shields.io/badge/NIST_SP_800--218-self--attested-green)](docs/SECURE-DEVELOPMENT.md)
[![CISA BOD 20-01](https://img.shields.io/badge/Vulnerability_Disclosure-CISA_BOD_20--01-orange)](docs/VULNERABILITY-DISCLOSURE-POLICY.md)
[![Security Policy](https://img.shields.io/badge/security-policy-red)](SECURITY.md)

<sub>Workflow badges render for signed-in users with repository access (this repo is private).</sub>

> **Security:** Report vulnerabilities privately via the [GitHub Security tab](https://github.com/Blackvectra/NRG-Assessment-Tool/security/advisories/new) or `security@nrgtechservices.com`. We follow a 7-day Critical / 30-day High fix SLA; see [`SECURITY.md`](SECURITY.md) for the full policy.

---

## What It Does

Connects to a Microsoft 365 tenant via delegated auth (or GDAP for MSP batch runs), collects raw configuration data across all M365 services, evaluates **195 security controls with license-aware scoring**, and produces client-ready HTML and Markdown reports with citations into six frameworks (CIS M365, CISA SCuBA, NIST 800-53r5, CMMC 2.0, ISO 27001, MITRE ATT&CK) plus CIS Controls v8.1.

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
cd C:\path\to\NRG-Assessment-v4.6.5
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
incident**, not the 195 tenant controls.

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
NRG-Assessment.psd1               ← Module manifest (220 exports, dependency declarations)

Lib/                              ← Shared infrastructure
  Add-NRGFinding.ps1              State management (findings, exceptions, coverage, raw data)
  Connect-NRGServices.ps1         Auth (interactive browser MFA / app-only cert; process-scoped MSAL)
  ConvertTo-NRGHtmlSafe.ps1       XSS prevention (all tenant data escapes through here)
  Get-NRGControlDefinitions.ps1   controls.json loader + content validation

Collectors/                       READ-ONLY — raw data collection, no scoring
  AAD/    (6 files)               Auth policies, CA, users+MFA, roles, PIM, identity governance
  EXO/    (3 files)               Mailbox config + connection filter, Defender policies
  DNS/    (1 file)                SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC
  SharePoint/ Teams/ Purview/
  Intune/ PowerPlatform/          (5 files)

Evaluators/                       SCORING ONLY — reads raw data, writes findings
  Test-NRGControl-AAD.ps1         46 controls
  Test-NRGControlEXO.ps1          31 controls
  Test-NRGControlDefender.ps1     23 controls
  Test-NRGControlTeams.ps1        22 controls
  Test-NRGControlPurview.ps1      18 controls
  Test-NRGControlSharePoint.ps1   17 controls
  Test-NRGControlIntune.ps1       17 controls
  Test-NRGControlPowerPlatform.ps1 11 controls
  Test-NRGControlDNS.ps1          10 controls

Publishers/
  Publish-NRGAssessmentHTML.ps1   Interactive HTML report with exec summary + findings
  Publish-NRGAssessmentSummary.ps1 Markdown report for OneNote / GitHub

Config/
  controls.json                   195 control definitions + framework citations
  frameworks.json                 CIS, SCuBA, NIST, CMMC, MITRE metadata
  clients.json                    MSP client registry (TenantId + GDAP config)
  schema/                         JSON Schemas for controls.json + clients.json (CI-enforced)
  framework-baselines/            Authoritative SCuBA v1.8.0 + CIS Controls v8.1 ID lists (CI-enforced)

Testing/                          10 Pester suites, 220 tests — the FULL suite gates every PR
  NRG.Security.Tests.ps1          OWASP/ASVS static + runtime invariants
  NRG.FrameworkAccuracy.Tests.ps1 Framework citations vs authoritative baselines
  NRG.GraphRequest.Tests.ps1      Graph response shape (StrictMode paging regression guard)
  ...                             coverage-score, license, maturity-tier, report, helper suites

.github/workflows/                6 workflows: ci, secret-scan, codeql, dependency-review, scorecard, release
```

---

## Controls Coverage

**195 controls across 9 workloads** — every count below is generated from `Config/controls.json` and schema-validated in CI.

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

**220 automated Pester tests across 10 suites** cover all of the above plus framework-citation accuracy — the full suite gates every pull request in CI.

```powershell
# Run the full test suite (same thing CI runs)
Invoke-Pester ./Testing -Output Detailed
```

---

## Client Registry (MSP)

Edit `Config\clients.json` to add tenants:

```json
{
  "ClientName":   "Client Name",
  "TenantDomain": "client.com",
  "TenantId":     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "DelegatedOrg": "client.onmicrosoft.com",
  "DnsDomains":   ["client.com"],
  "SkipPurview":  false,
  "SkipPowerPlatform": true,
  "Active":       true
}
```

Get TenantId from: **Entra ID > Overview > Tenant ID**  
Get DelegatedOrg from: **Partner Center > Customers > client > Domains** (find the `.onmicrosoft.com` domain)

GDAP relationships must be active in Partner Center before the batch runner can access client tenants.

---

## CI/CD

Six GitHub Actions workflows run on every push and pull request to `main`:

| Workflow | What it does |
|---|---|
| **CI** | Full Pester suite (220 tests, 10 files) · PSScriptAnalyzer with SARIF upload · module-manifest validation · JSON-Schema enforcement of `controls.json` + `clients.json` |
| **Secret Scan** | Gitleaks (full history) + TruffleHog (live-verified secrets) — both SHA-pinned; weekly scheduled sweep |
| **CodeQL** | Scans the Actions workflow YAML for supply-chain weaknesses (PowerShell isn't CodeQL-supported; PSSA covers it) |
| **Dependency Review** | Flags vulnerable dependency changes on PRs |
| **Scorecard** | OpenSSF Scorecard supply-chain posture, weekly |
| **Release** | On `v*` tags: CycloneDX SBOM generation + Authenticode signature/integrity verification |

The framework-accuracy suite validates every SCuBA citation against the bundled ScubaGear v1.8.0 policy list, every CIS Controls citation against the v8.1 safeguard list, CMMC domain/level correctness, and ISO 27001:2022 Annex-A ranges — a wrong citation fails the PR, not the client report.

---

## License

Internal use — NRG Technology Services / NextLayerSec LLC. Not licensed for redistribution.

---

*NRG-Assessment v4.12.1 · 195 posture controls + EMAIL/SIGNIN IR heuristics · 232 exported functions · 220-test Pester suite gating CI*

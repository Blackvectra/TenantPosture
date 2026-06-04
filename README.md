# NRG-Assessment

**Read-only M365 security assessment framework for managed service providers.**

Built by Matthew Levorson — NRG Technology Services / NextLayerSec LLC  
GitHub: [Blackvectra/NRG-Assessment-Tool](https://github.com/Blackvectra/NRG-Assessment-Tool)

[![OpenSSF Best Practices](https://img.shields.io/badge/OpenSSF_Best_Practices-Passing_(self--assessed)-blue)](docs/OPENSSF-BEST-PRACTICES.md)
[![SSDF](https://img.shields.io/badge/NIST_SP_800--218-self--attested-green)](docs/SECURE-DEVELOPMENT.md)
[![CISA BOD 20-01](https://img.shields.io/badge/Vulnerability_Disclosure-CISA_BOD_20--01-orange)](docs/VULNERABILITY-DISCLOSURE-POLICY.md)
[![Security Policy](https://img.shields.io/badge/security-policy-red)](SECURITY.md)

> **Security:** Report vulnerabilities privately via the [GitHub Security tab](https://github.com/Blackvectra/NRG-Assessment-Tool/security/advisories/new) or `security@nrgtechservices.com`. We follow a 7-day Critical / 30-day High fix SLA; see [`SECURITY.md`](SECURITY.md) for the full policy.

---

## What It Does

Connects to a Microsoft 365 tenant via delegated auth (or GDAP for MSP batch runs), collects raw configuration data across all M365 services, evaluates 195 security controls, and produces client-ready HTML and Markdown reports with framework citations.

**Zero writes to tenant. Read-only by design.**

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
# Install required modules (exact versions — supply chain pinned)
Install-PSResource -Name Microsoft.Graph.Authentication -Version 2.20.0 -TrustRepository
Install-PSResource -Name ExchangeOnlineManagement       -Version 3.4.0  -TrustRepository
Install-PSResource -Name MicrosoftTeams                -Version 6.4.0  -TrustRepository
Install-PSResource -Name Microsoft.Online.SharePoint.PowerShell -Version 16.0.24720.12000 -TrustRepository
Install-PSResource -Name Pester                        -Version 5.6.1  -TrustRepository
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
  Connect-NRGServices.ps1         Auth (browser/device code, process-scoped MSAL)
  ConvertTo-NRGHtmlSafe.ps1       XSS prevention (all tenant data escapes through here)
  Get-NRGControlDefinitions.ps1   controls.json loader + content validation

Collectors/                       READ-ONLY — raw data collection, no scoring
  AAD/    (6 files)               Auth policies, CA, users+MFA, roles, PIM, identity governance
  EXO/    (3 files)               Mailbox config + connection filter, Defender policies
  DNS/    (1 file)                SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC
  SharePoint/ Teams/ Purview/
  Intune/ PowerPlatform/          (5 files)

Evaluators/                       SCORING ONLY — reads raw data, writes findings
  Test-NRGControl-AAD.ps1         32 controls
  Test-NRGControlEXO.ps1          21 controls
  Test-NRGControlDNS.ps1          6 controls
  Test-NRGControlDefender.ps1     16 controls
  Test-NRGControlSharePoint.ps1   17 controls
  Test-NRGControlTeams.ps1        18 controls
  Test-NRGControlPurview.ps1      14 controls
  Test-NRGControlIntune.ps1       13 controls
  Test-NRGControlPowerPlatform.ps1 6 controls

Publishers/
  Publish-NRGAssessmentHTML.ps1   Interactive HTML report with exec summary + findings
  Publish-NRGAssessmentSummary.ps1 Markdown report for OneNote / GitHub

Config/
  controls.json                   195 control definitions + framework citations
  frameworks.json                 CIS, SCuBA, NIST, CMMC, MITRE metadata
  clients.json                    MSP client registry (TenantId + GDAP config)

Testing/
  NRG.Security.Tests.ps1          100 Pester tests (OWASP/ASVS static + runtime)

.github/workflows/security.yml    CI: PSScriptAnalyzer + Pester + Gitleaks + TruffleHog
```

---

## Controls Coverage

**195 controls across 9 workloads**

| Workload | Controls | Key Areas |
|---|---|---|
| Entra ID (AAD) | 32 | MFA, legacy auth, CA policies, PIM, guest access, SSPR, app consent, break-glass |
| Exchange Online | 21 | Audit, SMTP auth, auto-forward, DKIM, anti-phish, modern auth, DMARC |
| DNS Email Auth | 6 | SPF, DKIM, DMARC enforcement, MTA-STS, TLS-RPT, DNSSEC |
| Defender | 16 | Safe Attachments/Links, spoof intel, ZAP, quarantine, preset policies |
| SharePoint | 17 | External sharing, OneDrive sync, custom script, link expiration, guest expiry |
| Teams | 18 | Federation, consumer accounts, meeting lobby, external chat, app governance |
| Purview | 14 | Unified audit log, DLP, sensitivity labels, retention, insider risk |
| Intune | 13 | Device compliance, BitLocker, EDR, ASR rules, MAM, conditional launch |
| Power Platform | 6 | Tenant isolation, DLP policy, connector classification, governance |

**Severity distribution:** 9 Critical · 59 High · 52 Medium · 23 Low

**Framework citations per control:** CIS M365 v6.0.1 · CISA SCuBA v1.7.1 · NIST SP 800-53 Rev 5 · CMMC 2.0 L2 · MITRE ATT&CK v16.1

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

**77 automated Pester tests** cover all of the above — static analysis on every push via GitHub Actions.

```powershell
# Run the security test suite
Invoke-Pester ./Testing/NRG.Security.Tests.ps1 -Output Detailed
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

GitHub Actions runs on every push to `main`:

| Job | Tool | What it checks |
|---|---|---|
| PSScriptAnalyzer | PowerShell static analysis | Code quality, syntax, anti-patterns |
| Pester | NRG.Security.Tests.ps1 | 77 OWASP/ASVS security invariants |
| Gitleaks | Secret detection | Credentials, tokens, API keys |
| TruffleHog | Deep secret scan | Verified secrets in all commits |
| SBOM | CycloneDX cdxgen | Software bill of materials on release |

---

## License

Internal use — NRG Technology Services / NextLayerSec LLC. Not licensed for redistribution.

---

*NRG-Assessment v4.11.1 · 195 controls · 231 exported functions · 191 Pester tests*

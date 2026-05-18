# NRG-Assessment

**Read-only M365 security assessment framework for managed service providers.**

Built by Matthew Levorson — NRG Technology Services / NextLayerSec LLC  
GitHub: [Blackvectra/NRG-Assessment-Tool](https://github.com/Blackvectra/NRG-Assessment-Tool)

---

## What It Does

Connects to a Microsoft 365 tenant via delegated auth (or GDAP for MSP batch runs), collects raw configuration data across all M365 services, evaluates 188 security controls, and produces client-ready HTML and Markdown reports with framework citations.

**Zero writes to tenant. Read-only by design.**

---

## First-Time Setup

On a fresh machine, run this once:

```powershell
# After extracting the zip
cd C:\path\to\NRG-Assessment-v4.5.5
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
Install-PSResource -Name ExchangeOnlineManagement       -Version 3.2.0  -TrustRepository  # 3.4.0+ has WAM broker crash — tool downgrades automatically
Install-PSResource -Name MicrosoftTeams                -TrustRepository                   # Use latest
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

### MSP Batch Run (GDAP)

```powershell
# 1. Add your clients to Config\clients.json (TenantId + DelegatedOrg required)
# 2. One browser login covers all tenants via GDAP relationships
.\Invoke-NRGBatchAssessment.ps1

# Run a single client
.\Invoke-NRGBatchAssessment.ps1 -OnlyClient clienta.org

# Preview what would run
.\Invoke-NRGBatchAssessment.ps1 -WhatIf
```

---

## Architecture

```
Invoke-NRGAssessment.ps1          ← Entry point (validated params, try/finally)
Invoke-NRGBatchAssessment.ps1     ← GDAP batch runner (one auth, all tenants)
NRG-Assessment.psm1               ← Module loader (recursive dot-source, path traversal check)
NRG-Assessment.psd1               ← Module manifest (153 exports, dependency declarations)

Lib/                              ← Shared infrastructure
  Add-NRGFinding.ps1              State management (findings, exceptions, coverage, raw data)
  Connect-NRGServices.ps1         Auth (browser/device code, process-scoped MSAL)
  ConvertTo-NRGHtmlSafe.ps1       XSS prevention (all tenant data escapes through here)
  Get-NRGControlDefinitions.ps1   controls.json loader + content validation

Collectors/                       READ-ONLY — raw data collection, no scoring
  AAD/    (7 files)               Auth policies, CA, users+MFA, roles, PIM, identity governance
  EXO/    (3 files)               Mailbox config + connection filter, Defender policies
  DNS/    (1 file)                SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC
  SharePoint/ Teams/ Purview/
  Intune/ PowerPlatform/          (5 files)

Evaluators/                       SCORING ONLY — reads raw data, writes findings
  Test-NRGControl-AAD.ps1         41 controls
  Test-NRGControl-EXO.ps1         23 controls
  Test-NRGControl-DNS.ps1         6 controls
  Test-NRGControlDefender.ps1     18 controls
  Test-NRGControlSharePoint.ps1   13 controls
  Test-NRGControlTeams.ps1        17 controls
  Test-NRGControlPurview.ps1      15 controls
  Test-NRGControlIntune.ps1       13 controls
  Test-NRGControlPowerPlatform.ps1 4 controls
  Test-NRGControl-Inventory.ps1   9 named-object evaluators (MFA gaps, stale accounts, OAuth, forwarding)
  Test-NRGControlCopilot.ps1      5 controls (AI/Copilot governance — PPL-3.x)

Publishers/
  Publish-NRGAssessmentHTML.ps1   Interactive HTML report with exec summary + findings
  Publish-NRGAssessmentSummary.ps1 Markdown report for OneNote / GitHub

Config/
  controls.json                   188 control definitions + framework citations
  frameworks.json                 CIS, SCuBA, NIST, CMMC, MITRE metadata
  clients.json                    MSP client registry (TenantId + GDAP config)

Testing/
  NRG.Security.Tests.ps1          77 Pester tests (OWASP/ASVS static + runtime)

.github/workflows/security.yml    CI: PSScriptAnalyzer + Pester + Gitleaks + TruffleHog
```

---

## Controls Coverage

**188 controls across 9 workloads**

| Workload | Controls | Key Areas |
|---|---|---|
| Entra ID (AAD) | 46 | MFA, legacy auth, CA policies, PIM, guest access, SSPR, app consent, break-glass |
| Exchange Online | 28 | Audit, SMTP auth, auto-forward, DKIM, anti-phish, modern auth, DMARC |
| DNS Email Auth | 6 | SPF, DKIM, DMARC enforcement, MTA-STS, TLS-RPT, DNSSEC |
| Defender | 23 | Safe Attachments/Links, spoof intel, ZAP, quarantine, preset policies |
| SharePoint | 17 | External sharing, OneDrive sync, custom script, link expiration, guest expiry |
| Teams | 22 | Federation, consumer accounts, meeting lobby, external chat, app governance |
| Purview | 18 | Unified audit log, DLP, sensitivity labels, retention, insider risk |
| Intune | 17 | Device compliance, BitLocker, EDR, ASR rules, MAM, conditional launch |
| Power Platform | 11 | Tenant isolation, DLP policy, connector classification, governance |

**Severity distribution:** 12 Critical · 88 High · 61 Medium · 27 Low

**Framework citations per control:** CIS M365 v6.0.1 · CISA SCuBA v1.7.1 · NIST SP 800-53 Rev 5 · CMMC 2.0 L2 · MITRE ATT&CK v16.1

---

## Security Hardening

This tool is hardened against the threats it assesses. Every production file has:

- `#Requires -Version 7.0` — blocks PS 5.1 MSHTML injection (CVE-2025-54100)
- `Set-StrictMode -Version Latest` — in orchestrator, publishers, and lib files (intentionally excluded from evaluators/collectors to prevent Graph ConvertFrom-Json property access crashes)
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

Internal use — NRG Technology Services. Not licensed for redistribution.

---

*NRG-Assessment v4.5.5 · 188 controls · 153 exported functions · 77 Pester tests*

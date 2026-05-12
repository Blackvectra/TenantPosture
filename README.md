# NRG Assessment Tool

**Microsoft 365 Security Assessment Framework**
*NRG Technology Services *

[![Version](https://img.shields.io/badge/Version-4.0.0-blue?style=flat-square)]()
[![PowerShell](https://img.shields.io/badge/PowerShell-7.x-blue?style=flat-square&logo=powershell)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)]()
[![Controls](https://img.shields.io/badge/Controls-400%2B%20(roadmap)-orange?style=flat-square)]()

---

## Overview

NRG Assessment Tool is a Microsoft 365 security assessment framework built for MSP-scale operations. It evaluates tenant configuration against multiple security frameworks simultaneously, produces client-ready reports, and runs without making any configuration changes.

**No tenant changes are made at any point.**

```
Collectors → Evaluators → Publishers
```

1. **Collectors** — Query Microsoft Graph, Exchange Online, DNS, and other APIs. Return structured raw data. No scoring, no judgment.
2. **Evaluators** — Read collected data, evaluate against control definitions, produce findings.
3. **Publishers** — Generate HTML, Markdown, and technical reports from findings.

This separation mirrors the pattern used by [CISA ScubaGear](https://github.com/cisagov/ScubaGear) and [EIDSCA](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense). When Microsoft renames a property, exactly one collector breaks — nothing else.

---

## Frameworks Covered

| Framework | Coverage |
|---|---|
| NIST SP 800-53 Rev 5 | AC, AU, CA, CM, IA, IR, RA, SC, SI families |
| CIS Microsoft 365 Foundations Benchmark v3 | All sections |
| CISA SCuBA M365 Secure Configuration Baselines | AAD, EXO, Defender, SharePoint, Teams |
| CMMC 2.0 Level 2 | All 110 practices |
| MITRE ATT&CK Enterprise | Initial Access, Persistence, Credential Access, Exfiltration |
| ISO/IEC 27001:2022 | Annex A controls |

---

## Products Assessed

| Product | Collector | Evaluator | Baseline Doc | Phase |
|---|---|---|---|---|
| Microsoft Entra ID | ✓ | ✓ | [aad.md](baselines/aad.md) | 1–2 |
| Exchange Online | ✓ | ✓ | [exo.md](baselines/exo.md) | 1–3 |
| Defender for Office 365 | ✓ | ✓ | [defender.md](baselines/defender.md) | 2–3 |
| SharePoint Online | ✓ | ✓ | [sharepoint.md](baselines/sharepoint.md) | 4 |
| Microsoft Teams | ✓ | ✓ | [teams.md](baselines/teams.md) | 4 |
| Microsoft Purview | ✓ | ✓ | [purview.md](baselines/purview.md) | 4 |
| Power Platform | ✓ | — | [powerplatform.md](baselines/powerplatform.md) | 4 |
| Microsoft Intune | ✓ | — | [intune.md](baselines/intune.md) | 5 |

---

## Quick Start

### 1. Install Dependencies

```powershell
Install-Module Microsoft.Graph          -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module MicrosoftTeams           -Scope CurrentUser -Force
Install-Module PnP.PowerShell           -Scope CurrentUser -Force
```

### 2. Run Assessment

```powershell
# Standard run — all products
pwsh -ExecutionPolicy RemoteSigned -File .\PowerShell\NRGAssessment\Invoke-NRGAssessment.ps1 `
     -UserPrincipalName admin@client.com

# Quick run — identity and email only
pwsh -ExecutionPolicy RemoteSigned -File .\PowerShell\NRGAssessment\Invoke-NRGAssessment.ps1 `
     -UserPrincipalName admin@client.com -Profile Quick

# Skip unlicensed services
pwsh -ExecutionPolicy RemoteSigned -File .\PowerShell\NRGAssessment\Invoke-NRGAssessment.ps1 `
     -UserPrincipalName admin@client.com -SkipPurview -SkipTeams

# JSON output only (automation / downstream processing)
pwsh -ExecutionPolicy RemoteSigned -File .\PowerShell\NRGAssessment\Invoke-NRGAssessment.ps1 `
     -UserPrincipalName admin@client.com -JsonOnly

# Test connections without collecting
pwsh -ExecutionPolicy RemoteSigned -File .\PowerShell\NRGAssessment\Invoke-NRGAssessment.ps1 `
     -UserPrincipalName admin@client.com -WhatIfConnections

# Specify DNS domains explicitly
pwsh -ExecutionPolicy RemoteSigned -File .\PowerShell\NRGAssessment\Invoke-NRGAssessment.ps1 `
     -UserPrincipalName admin@client.com -DnsDomains @('client.com','subsidiary.com')
```

### 3. View Results

Reports are written to `.\Reports\<TenantName>-<Timestamp>\`:

| File | Description |
|---|---|
| `BaselineReport.html` | Interactive HTML — filterable by framework, severity, status |
| `AssessmentSummary.md` | Markdown executive summary |
| `Findings.json` | Raw findings for downstream processing |
| `TechnicalReport.md` | Full technical detail with remediation commands |

---

## Folder Structure

```
NRG-Assessment-Tool/
│
├── PowerShell/NRGAssessment/       Core PowerShell module
│   ├── Collectors/                 Raw data collection (one file per domain)
│   │   ├── AAD/
│   │   ├── EXO/
│   │   ├── Defender/
│   │   ├── DNS/
│   │   ├── SharePoint/
│   │   ├── Teams/
│   │   ├── Purview/
│   │   ├── PowerPlatform/
│   │   └── Intune/
│   ├── Evaluators/                 Scoring logic (one file per service)
│   ├── Publishers/                 Report generation
│   ├── Lib/                        Shared helpers
│   ├── Config/
│   │   ├── controls.json           Control definitions (data-driven)
│   │   ├── frameworks.json         Framework metadata and crosswalk
│   │   └── branding.psd1
│   ├── Invoke-NRGAssessment.ps1    Entry point
│   ├── NRG-Assessment.psd1         Module manifest
│   └── NRG-Assessment.psm1         Module loader
│
├── baselines/                      Baseline documentation (one .md per product)
│   ├── aad.md
│   ├── exo.md
│   ├── defender.md
│   ├── sharepoint.md
│   ├── teams.md
│   ├── purview.md
│   ├── powerplatform.md
│   └── intune.md
│
├── docs/
│   ├── installation/setup.md
│   ├── prerequisites/permissions.md
│   ├── configuration/configuration.md
│   └── misc/mappings.md
│
├── sample-report/                  Example HTML output
├── Testing/                        Pester tests (Phase 5)
├── images/
├── .github/ISSUE_TEMPLATE/
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## Adding a Control

No code changes required. Edit `PowerShell/NRGAssessment/Config/controls.json`:

```json
{
  "ControlId": "AAD-2.5",
  "Category": "Identity",
  "Title": "Phishing-resistant MFA required for admins",
  "Severity": "High",
  "Description": "All privileged roles require phishing-resistant MFA methods.",
  "BusinessRisk": "Admin accounts compromised via AiTM phishing bypass standard MFA.",
  "Remediation": "Configure Conditional Access policy requiring FIDO2 or certificate-based auth for directory roles.",
  "EffortLevel": "Standard (1-4 hrs)",
  "Frameworks": {
    "NIST-800-53": ["IA-2", "IA-2(1)", "IA-2(2)"],
    "CIS-M365-v3": ["5.2.3.5"],
    "SCuBA-AAD": ["MS.AAD.3.2v1"],
    "CMMC-2": ["IA.L2-3.5.3"],
    "MITRE-ATT&CK": ["T1078", "T1556"]
  }
}
```

Then add the matching evaluator in `Evaluators/Test-NRGControl-AAD.ps1`.

---

## Phase Roadmap

| Phase | Scope | Target Controls | Status |
|---|---|---|---|
| 1 | Architecture + reference collectors | ~15 | ✓ Complete |
| 2 | Identity layer expansion | ~80 | In Progress |
| 3 | Email + Defender depth | ~150 | Planned |
| 4 | SharePoint + Teams + Purview + Power Platform | ~250 | Planned |
| 5 | Intune + Defender XDR + Pester tests | ~320 | Planned |
| 6 | STIG + CMMC + FedRAMP mapping | ~400 | Planned |

---

## Prerequisites

See [docs/prerequisites/permissions.md](docs/prerequisites/permissions.md) for required Graph API permissions and Exchange Online roles.

---

## Author

**Matthew Levorson**
Security Engineer — NRG Technology Services
Principal — NextLayerSec LLC

---

> ⚠️ This tool is internal MSP tooling. It is provided as-is with no warranty. It does not modify tenant configuration.

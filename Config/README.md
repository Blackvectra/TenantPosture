# NRG-Assessment v4

**Microsoft 365 Security Assessment Framework**
*NRG Technology Services — NextLayerSec LLC*

> ⚠️ **Proprietary** — Internal MSP tooling. Not for distribution.

---

## What's new in v4

v4 is a clean architectural rebuild. The bug-prone v3 code is retired.

| | v3 | v4 |
|---|---|---|
| Architecture | Mixed collection + scoring + citations | Strict separation: Collectors / Evaluators / Publishers |
| Duplicate functions | 18 duplicate function definitions across Public/ and Modules/ | Single source of truth — one function per file |
| Control definitions | Hardcoded in PowerShell | JSON-driven (`Config/controls.json`) |
| Framework mapping | Hardcoded | JSON crosswalk (`Config/frameworks.json`) |
| Authentication | Mix of interactive, browser, embedded creds | Device code for every service |
| Adding controls | Code change | JSON edit |
| Adding frameworks | Code change | JSON edit |
| PowerShell version | PS7 with constant module compat issues | PS7 only, modules picked accordingly |

---

## How it works

Three-stage pipeline:

```
Collectors → Evaluators → Publishers
```

1. **Collectors** (`Collectors/<service>/`) — One file per data domain. Each function queries Microsoft Graph / EXO / DNS / etc. and returns a structured hashtable of raw data. **No scoring, no judgment.** A collector either succeeds (returns data) or fails (registers an exception). When Microsoft renames a property, exactly ONE collector breaks.

2. **Evaluators** (`Evaluators/`) — One file per service area. Each function reads collected data from module state, evaluates against control definitions, and calls `Add-NRGFinding`. **No data collection, no API calls.** Evaluators are pure logic.

3. **Publishers** (`Publishers/`) — Read findings from module state and produce reports: Markdown summary, HTML, technical, playbook, etc.

This separation is the same pattern used by ScubaGear, EIDSCA, and other federally-aligned assessment tools.

---

## Installation

```powershell
# Required modules
Install-Module Microsoft.Graph         -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module MicrosoftTeams           -Scope CurrentUser -Force
Install-Module PnP.PowerShell           -Scope CurrentUser -Force
```

---

## Usage

```powershell
# Standard run
pwsh -ExecutionPolicy RemoteSigned -File .\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com

# JSON only (for automation / hand-off)
pwsh -ExecutionPolicy RemoteSigned -File .\Invoke-NRGAssessment.ps1 -JsonOnly

# Skip services
pwsh -ExecutionPolicy RemoteSigned -File .\Invoke-NRGAssessment.ps1 `
     -SkipPurview -SkipTeams -SkipSharePoint

# Test connections only (no collection)
pwsh -ExecutionPolicy RemoteSigned -File .\Invoke-NRGAssessment.ps1 -WhatIfConnections

# Specify DNS domains explicitly (if EXO accepted domains aren't all sending domains)
pwsh -ExecutionPolicy RemoteSigned -File .\Invoke-NRGAssessment.ps1 `
     -DnsDomains @('client.com','subsidiary.com')
```

---

## Folder structure

```
NRG-Assessment-v4/
├── Invoke-NRGAssessment.ps1      Entry point
├── NRG-Assessment.psm1           Module loader (no business logic)
├── NRG-Assessment.psd1           Manifest
├── README.md
├── CHANGELOG.md
│
├── Config/
│   ├── controls.json             Control definitions (data-driven)
│   ├── frameworks.json           Framework metadata
│   └── branding.psd1             NRG brand constants
│
├── Collectors/                   Raw data collection only
│   ├── AAD/                      Entra ID
│   ├── EXO/                      Exchange Online
│   ├── Defender/                 Defender for Office 365
│   ├── DNS/                      External DNS records
│   ├── SharePoint/               SharePoint Online
│   ├── Teams/                    Microsoft Teams
│   ├── Purview/                  DLP / labels / retention
│   ├── PowerPlatform/            Power Platform
│   └── Intune/                   Endpoint / device
│
├── Evaluators/                   Scoring logic only
│   ├── Test-NRGControl-AAD.ps1
│   ├── Test-NRGControl-EXO.ps1
│   └── ...
│
├── Publishers/                   Report generation
│   ├── Publish-NRGAssessmentSummary.ps1
│   └── (HTML, Technical, Playbook coming in Session 4)
│
├── Lib/                          Shared helpers
│   ├── Add-NRGFinding.ps1
│   ├── Connect-NRGServices.ps1
│   └── Get-NRGControlDefinitions.ps1
│
└── Tests/                        Pester tests (Sessions 5+)
```

---

## Adding a new control

No code changes. Edit `Config/controls.json`:

```json
{
  "ControlId": "AAD-2.5",
  "Category": "Identity",
  "Title": "Your new control title",
  "Severity": "High",
  "Description": "What this control checks",
  "BusinessRisk": "Why it matters",
  "Remediation": "How to fix",
  "EffortLevel": "Standard (1-4 hrs)",
  "Frameworks": {
    "NIST-800-53": ["IA-2"],
    "CIS-M365-v6": ["5.2.3.5"]
  }
}
```

Then add the matching evaluator function:

```powershell
function Test-NRGControl-AAD-YourNewControl {
    $controlId = 'AAD-2.5'
    $control = Get-NRGControlById -ControlId $controlId
    $data = Get-NRGRawData -Key 'AAD-AuthPolicies'

    if (<condition>) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' ...
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' ...
    }
}
```

And invoke it from the orchestrator.

---

## Adding a new framework

Edit `Config/frameworks.json` and add the new framework. Then in each `Config/controls.json` entry, add the new framework key:

```json
"Frameworks": {
  "NIST-800-53": ["IA-2"],
  "YourNewFramework": ["YNF-3.1.4"]
}
```

That's it. The reports pick it up automatically.

---

## Phase plan

v4.0.0 (this release) is the foundation. Future sessions expand depth:

| Phase | Scope | Target controls |
|---|---|---|
| Phase 1 (current) | Architecture + reference collectors | ~10–15 |
| Phase 2 | Identity layer expansion | ~80 |
| Phase 3 | Email + Defender depth | ~150 |
| Phase 4 | SharePoint + Teams + Purview + Power Platform | ~250 |
| Phase 5 | Intune + Defender XDR | ~320 |
| Phase 6 | STIG + CMMC + FedRAMP mapping | ~400 |

---

## Author

Matthew Levorson — Security Engineer, NRG Technology Services

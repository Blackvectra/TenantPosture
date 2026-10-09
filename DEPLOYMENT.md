# TenantPosture v4.5.5 — Deployment Guide

## Prerequisites

> **Windows note:** After extracting the zip, run these two commands before anything else:
> ```powershell
> Get-ChildItem -Path . -Recurse | Unblock-File
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```



### PowerShell Version
PowerShell 7.4+ required. All files enforce `#Requires -Version 7.0`.

```powershell
$PSVersionTable.PSVersion   # Must be 7.x
```

### Required Modules

Install with exact versions (supply chain pinned):

```powershell
Install-PSResource -Name Microsoft.Graph.Authentication -Version 2.20.0 -TrustRepository
Install-PSResource -Name ExchangeOnlineManagement       -Version 3.4.0  -TrustRepository
Install-PSResource -Name MicrosoftTeams                -Version 6.4.0  -TrustRepository
Install-PSResource -Name Microsoft.Online.SharePoint.PowerShell -Version 16.0.24720.12000 -TrustRepository
Install-PSResource -Name Pester                        -Version 5.6.1  -TrustRepository
```

> **Why `Install-PSResource`?** It supports exact version pinning and SHAsum verification. `Install-Module` does not support `-RequiredVersion` with hash verification.

### Required Permissions

**Microsoft Graph (delegated):**
- Policy.Read.All
- Directory.Read.All
- Reports.Read.All
- RoleManagement.Read.All
- User.Read.All
- UserAuthenticationMethod.Read.All
- DeviceManagementConfiguration.Read.All
- DeviceManagementApps.Read.All
- DeviceManagementManagedDevices.Read.All
- Application.Read.All

**Exchange Online:**  
Global Reader or Exchange Administrator (read-only cmdlets only)

**SharePoint Online:**  
SharePoint Administrator (read-only)

**Teams:**  
Teams Administrator (read-only)

---

## Single Tenant Run

```powershell
cd TenantPosture

# Standard run — all workloads
.\Invoke-TPAssessment.ps1 -UserPrincipalName admin@client.com

# Skip specific workloads (e.g. client doesn't have Purview/PPL)
.\Invoke-TPAssessment.ps1 -UserPrincipalName admin@client.com `
    -SkipPurview -SkipPowerPlatform

# Explicit DNS domains (overrides EXO accepted domains)
.\Invoke-TPAssessment.ps1 -UserPrincipalName admin@client.com `
    -DnsDomains @('client.com','mail.client.com')

# JSON output only (no HTML/Markdown)
.\Invoke-TPAssessment.ps1 -UserPrincipalName admin@client.com -JsonOnly

# Custom output path
.\Invoke-TPAssessment.ps1 -UserPrincipalName admin@client.com `
    -OutputPath 'C:\Reports\example'
```

**Output files:**
```
output\<TenantDomain>\
  <timestamp>-assessment.html    Full interactive report
  <timestamp>-assessment.md      Markdown summary
  <timestamp>-findings.json      Raw findings (machine-readable)
  <timestamp>-assessment.log     Run log
```

---

## MSP Batch Run (GDAP)

### Setup

1. **Configure `Config\clients.json`**

```json
{
  "clients": [
    {
      "ClientName":   "Example Client",
      "TenantDomain": "example.com",
      "TenantId":     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "DelegatedOrg": "example.onmicrosoft.com",
      "DnsDomains":   ["example.com"],
      "SkipPurview":       true,
      "SkipPowerPlatform": true,
      "Active":       true
    }
  ]
}
```

> **TenantId:** Entra ID > Overview > Tenant ID  
> **DelegatedOrg:** Partner Center > Customers > client > Domains (.onmicrosoft.com domain)

2. **Verify GDAP relationships** are active in Partner Center for all active clients.

### Run

```powershell
# All active clients — one browser login, no per-client prompts
.\Invoke-TPBatchAssessment.ps1

# Single client
.\Invoke-TPBatchAssessment.ps1 -OnlyClient example.com

# Preview only
.\Invoke-TPBatchAssessment.ps1 -WhatIf
```

**Output:**
```
output\
  example.com\                   Per-client reports
  example2.com\
  batch-summary-<ts>.md        Cross-client status table
```

---

## Security Test Suite

Run before any production deployment:

```powershell
Invoke-Pester ./Testing/TP.Security.Tests.ps1 -Output Detailed
```

**Expected:** 77 tests pass. 1 expected skip (Pester test file self-reference false positive).

Runtime tests (marked `[Runtime]`) require the module to be loaded with M365 modules installed. Static tests run without any tenant connection.

---

## Troubleshooting

**"Module not found" on import**

Verify all required modules are installed at the pinned versions. The module manifest (`TenantPosture.psd1`) declares `RequiredModules` — if any are missing, `Import-Module` will fail with a clear error.

**"controls.json content validation failed"**

The loader validates controls.json on every run. If you edited the file manually, check for:
- Invalid Severity (must be Critical/High/Medium/Low/Informational)
- Invalid Workload (must be AAD/EXO/DNS/DEF/SPO/TMS/INT/PVW/PPL)
- ControlId prefix not matching Workload (e.g. `INT-1.1` with `Workload: AAD`)
- Duplicate ControlId values

**"Connect-MgGraph failed"**

For GDAP batch runs: verify the GDAP relationship is active in Partner Center and that the delegated admin role includes the required Graph permissions. The tool requests scopes at auth time — the consent prompt will show what's being requested.

**PIM controls show NotApplicable**

Expected for tenants without Entra ID P2 licensing. The PIM collector probes for P2 availability and sets `PIMAvailable = $false` — evaluators surface this as NotApplicable rather than a gap.

---

## Adding a New Client (MSP)

1. Open `Config\clients.json`
2. Add a new entry — copy an existing one
3. Fill in `TenantId` and `DelegatedOrg`
4. Set `Active: true`
5. Set skip flags appropriate for their license tier
6. Run: `.\Invoke-TPBatchAssessment.ps1 -OnlyClient newclient.com` to validate

---

*TenantPosture v4.5.5 · NRG Technology Services / NextLayerSec LLC*

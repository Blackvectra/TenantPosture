# Installation and Setup

## Prerequisites

- PowerShell 7.x (`pwsh`)
- Windows 10/11 or Windows Server 2019+
- Internet access to Microsoft 365 APIs
- Admin account with permissions listed in [permissions.md](../prerequisites/permissions.md)

---

## Step 1 — Install PowerShell 7

If not already installed:

```powershell
winget install Microsoft.PowerShell
```

Or download from: https://github.com/PowerShell/PowerShell/releases

---

## Step 2 — Install Required Modules

Open PowerShell 7 (`pwsh`) and run:

```powershell
Install-Module Microsoft.Graph          -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module MicrosoftTeams           -Scope CurrentUser -Force
Install-Module PnP.PowerShell           -Scope CurrentUser -Force
```

---

## Step 3 — Clone or Download the Repository

```bash
git clone https://github.com/Blackvectra/NRG-Assessment-Tool.git
cd NRG-Assessment-Tool
```

Or download the ZIP from GitHub → Code → Download ZIP.

---

## Step 4 — Test Connections

Before running a full assessment, verify connections:

```powershell
pwsh -ExecutionPolicy RemoteSigned -File .\PowerShell\NRGAssessment\Invoke-NRGAssessment.ps1 `
     -UserPrincipalName admin@client.com -WhatIfConnections
```

A browser window will open for each service. Sign in with an account that has the required permissions. The tool will confirm each connection and exit without collecting data.

---

## Step 5 — Run Assessment

```powershell
pwsh -ExecutionPolicy RemoteSigned -File .\PowerShell\NRGAssessment\Invoke-NRGAssessment.ps1 `
     -UserPrincipalName admin@client.com
```

Reports are written to `.\Reports\<TenantDomain>-<Timestamp>\`.

---

## First Run Notes

- Browser popups appear once per service on first run. Sign in with MFA as prompted.
- DNS lookups are performed against public resolvers — no tenant auth required.
- The tool makes no configuration changes.
- Total run time: 3–8 minutes depending on tenant size and services included.

---

## Updating

```powershell
cd NRG-Assessment-Tool
git pull origin main
```

Or re-download the ZIP and replace the existing folder.

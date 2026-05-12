# Configuration

The NRG Assessment Tool is configured via parameters passed to `Invoke-NRGAssessment.ps1`. No config file is required for a standard run.

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-UserPrincipalName` | String | Required | UPN of the admin account for authentication |
| `-Profile` | String | `Full` | Run profile: `Full`, `Quick`, `EmailOnly`, `IdentityOnly` |
| `-SkipPurview` | Switch | False | Skip Purview collectors and evaluators |
| `-SkipTeams` | Switch | False | Skip Teams collectors and evaluators |
| `-SkipSharePoint` | Switch | False | Skip SharePoint collectors and evaluators |
| `-SkipPowerPlatform` | Switch | False | Skip Power Platform collectors |
| `-SkipIntune` | Switch | False | Skip Intune collectors |
| `-DnsDomains` | String[] | Auto | Explicit list of DNS domains to assess. Defaults to EXO accepted domains. |
| `-OutputPath` | String | `.\Reports\` | Directory for report output |
| `-JsonOnly` | Switch | False | Produce JSON output only — skip HTML and Markdown publishers |
| `-WhatIfConnections` | Switch | False | Test connections only — no data collection |

---

## Run Profiles

| Profile | Services | Use Case |
|---|---|---|
| `Full` | All connected services | Standard client assessment |
| `Quick` | AAD + EXO + Defender + DNS | Fast posture check |
| `EmailOnly` | EXO + Defender + DNS | Email security audit |
| `IdentityOnly` | AAD only | Identity and access review |

---

## Skipping Services

Use skip flags for tenants without specific licenses:

```powershell
# Business Standard tenant — no Purview DLP, no Teams Phone
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com `
    -SkipPurview -SkipPowerPlatform -SkipIntune
```

Controls for skipped services score `N/A` in the report.

---

## Output Files

All outputs are written to `<OutputPath>\<TenantDomain>-<Timestamp>\`:

| File | Format | Description |
|---|---|---|
| `BaselineReport.html` | HTML | Interactive report with framework filter |
| `AssessmentSummary.md` | Markdown | Executive summary |
| `TechnicalReport.md` | Markdown | Full technical findings with remediation |
| `Findings.json` | JSON | Raw findings for downstream processing |
| `CollectionLog.txt` | Text | Collection run log with timestamps |

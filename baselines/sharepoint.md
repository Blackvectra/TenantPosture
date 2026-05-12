# SharePoint Online Baseline

**NRG Assessment Tool — Baseline Documentation**
*Product: SharePoint Online / OneDrive for Business*

---

## Introduction

This baseline covers SharePoint Online and OneDrive for Business configuration. Controls focus on external sharing, access controls, and data exposure risk.

*Full control definitions added in Phase 4.*

---

## Controls

### SPO-1.1 — External Sharing Restricted

**Criticality:** High

**Description:**
SharePoint and OneDrive external sharing must be set to `ExistingExternalUsersOnly` or `Disabled`. `Anyone` (anonymous links) must not be permitted.

**Check:**
```powershell
Get-SPOTenant | Select-Object SharingCapability, OneDriveSharingCapability
```
`Disabled` or `ExistingExternalUsersOnly` → Satisfied. `NewAndExistingExternalUsers` → Partial. `ExternalUserAndGuestSharing` (Anyone) → Gap.

**Remediation:**
SharePoint Admin Center → Policies → Sharing → Set both SharePoint and OneDrive to `New and existing guests` or more restrictive.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-3, AC-17 |
| CIS M365 v3 | 3.1.1 |
| SCuBA SharePoint | MS.SHAREPOINT.1.1v1 |
| CMMC 2.0 | AC.L2-3.1.3 |
| MITRE ATT&CK | T1567.002 |

---

### SPO-1.2 — Legacy Authentication Blocked for SharePoint

**Criticality:** High

**Description:**
Legacy authentication must be blocked for SharePoint Online access. This aligns with AAD-1.1 but is verified at the SharePoint tenant level independently.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | IA-2, SC-8 |
| CIS M365 v3 | 3.2.1 |
| SCuBA SharePoint | MS.SHAREPOINT.3.1v1 |
| MITRE ATT&CK | T1078 |

---

### SPO-1.3 — OneDrive Sync Restricted to Domain-Joined Devices

**Criticality:** Medium

**Description:**
OneDrive sync must be restricted to devices joined to specified tenant domains, preventing personal device sync of corporate data.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-19, MP-7 |
| CIS M365 v3 | 3.3.1 |
| SCuBA SharePoint | MS.SHAREPOINT.2.1v1 |
| CMMC 2.0 | MP.L2-3.8.1 |
| MITRE ATT&CK | T1567.002 |

---

*Additional controls added in Phase 4.*

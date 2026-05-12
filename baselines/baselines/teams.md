# Microsoft Teams Baseline

**NRG Assessment Tool — Baseline Documentation**
*Product: Microsoft Teams*

---

## Introduction

This baseline covers Microsoft Teams security configuration. Controls focus on external access, guest access, meeting security, and data handling.

*Full control definitions added in Phase 4.*

---

## Controls

### TEAMS-1.1 — External Access Restricted

**Criticality:** High

**Description:**
External access (federation) must be configured to allow communication only with specific trusted domains, or disabled entirely. `Allow all external domains` permits uncontrolled federation with any Teams tenant.

**Check:**
```powershell
Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers, AllowedDomains, BlockedDomains
```

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-17, SC-7 |
| CIS M365 v3 | 6.1.1 |
| SCuBA Teams | MS.TEAMS.1.1v1 |
| MITRE ATT&CK | T1534 |

---

### TEAMS-1.2 — Guest Access Controlled

**Criticality:** Medium

**Description:**
Guest access must be either disabled or limited with appropriate controls. If guest access is enabled, guests must not be able to initiate contact with non-guest users outside of channels they are invited to.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-2, AC-3 |
| CIS M365 v3 | 6.1.2 |
| SCuBA Teams | MS.TEAMS.1.2v1 |
| MITRE ATT&CK | T1534 |

---

### TEAMS-1.3 — Meeting Recording Retention Configured

**Criticality:** Low

**Description:**
Teams meeting recordings stored in OneDrive/SharePoint must have a defined retention policy. Recordings without retention policies persist indefinitely and may contain sensitive information.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AU-11, MP-6 |
| CIS M365 v3 | 6.3.1 |
| SCuBA Teams | MS.TEAMS.6.1v1 |
| MITRE ATT&CK | T1213 |

---

*Additional controls added in Phase 4.*

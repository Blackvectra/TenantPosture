# Power Platform Baseline

**NRG Assessment Tool — Baseline Documentation**
*Product: Microsoft Power Platform (Power Apps, Power Automate, Power BI)*

---

## Introduction

This baseline covers Power Platform security configuration. Power Platform introduces significant data exposure risk in M365 environments and is frequently overlooked in security assessments.

*Full control definitions added in Phase 4.*

---

## Controls

### PP-1.1 — Trial Environment Creation Restricted

**Criticality:** High

**Description:**
Non-admin users must not be able to create Power Platform trial environments. Unrestricted environment creation allows data exfiltration via Power Automate flows connecting to external services without IT visibility.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | CM-7, AC-6 |
| CIS M365 v3 | 7.1.1 |
| SCuBA Power Platform | MS.POWERPLATFORM.1.1v1 |
| MITRE ATT&CK | T1567 |

---

### PP-1.2 — Power Automate External Connector Policy

**Criticality:** Medium

**Description:**
A Data Loss Prevention policy must restrict which connectors Power Automate flows can use. Without a DLP policy, flows can connect to arbitrary external services and exfiltrate data.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-4, CM-7 |
| CIS M365 v3 | 7.2.1 |
| SCuBA Power Platform | MS.POWERPLATFORM.2.1v1 |
| MITRE ATT&CK | T1567, T1048 |

---

*Additional controls added in Phase 4.*

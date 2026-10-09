# Microsoft Power Platform Baseline

**TenantPosture — Baseline Documentation**
*Product: Microsoft Power Platform*

---

## Introduction

This baseline lists the 11 Microsoft Power Platform controls evaluated by TenantPosture. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 5 High · 6 Medium

---

## Controls

### PPL-1.1 — Power Platform Tenant Isolation Enabled

**Severity:** Medium  |  **Category:** Data  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Power Platform tenant isolation restricts cross-tenant connector connections.

**Business risk:**
Without isolation, Power Automate flows can connect to external tenant resources, enabling data exfiltration via legitimate connectors.

**Remediation:**
Power Platform Admin Center > Policies > Tenant Isolation: enable and configure inbound/outbound restrictions.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4, SC-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 9.1.1 |
| CIS Controls v8.1 | 4.1 |
| CISA SCuBA | MS.POWERPLATFORM.3.1v1 |
| CMMC 2.0 | SC.L1-3.13.1 |
| ISO/IEC 27001:2022 | A.5.23, A.8.22 |
| SOC 2 | CC6.6 |
| HIPAA | §164.312(a)(1) |
| PCI DSS | Req 1.4 |
| MITRE ATT&CK | T1048, T1567 |

---

### PPL-1.2 — Power Platform DLP Policy Active

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
A DLP policy for Power Platform classifies connectors as Business, Non-Business, or Blocked.

**Business risk:**
Without DLP, flows can move data between any connectors including personal cloud storage and social media.

**Remediation:**
Power Platform Admin Center > Policies > Data policies: create environment policy. Move business connectors to Business group, block consumer connectors.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4, SC-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 9.2.1 |
| CIS Controls v8.1 | 3.13 |
| CISA SCuBA | MS.POWERPLATFORM.2.1v1 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1048 |

---

### PPL-1.3 — Power Platform Environment Creation Restricted

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Non-admin users cannot create new Power Platform environments.

**Business risk:**
Unrestricted environment creation allows data exfiltration through ungoverned flows outside DLP policy scope.

**Remediation:**
Power Platform Admin Center > Settings: restrict environment creation to admins only.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-5, AC-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 9.3.1 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.POWERPLATFORM.1.1v1 |
| CMMC 2.0 | CM.L2-3.4.5 |
| ISO/IEC 27001:2022 | A.5.23, A.8.32 |
| SOC 2 | CC6.3, CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1578 |

---

### PPL-2.1 — Power Platform Connector Classification Reviewed

**Severity:** Medium  |  **Category:** Data  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Connectors in Power Platform DLP policies are classified as Business, Non-Business, or Blocked.

**Business risk:**
Unclassified connectors default to Non-Business — flows can still mix data between business connectors and unclassified ones.

**Remediation:**
Power Platform Admin Center > Data policies > Edit existing policy > Review all connectors and assign to Business or Blocked groups.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 9.2.2 |
| CIS Controls v8.1 | 3.13 |
| CISA SCuBA | MS.POWERPLATFORM.2.1v1 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.5.23, A.8.30 |
| SOC 2 | CC6.6 |
| HIPAA | §164.308(a)(1)(ii)(D) |
| PCI DSS | Req 6.4.3 |
| MITRE ATT&CK | T1048 |

---

### PPL-2.2 — Power Automate Governance Policy Active

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Guest users are restricted from creating Power Automate flows.

**Business risk:**
Guest users creating flows can automate data movement between organizational data sources and external destinations without IT oversight.

**Remediation:**
Power Platform Admin Center > Tenant settings > Power Automate > Disable for guests.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-5, AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 9.3.2 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.POWERPLATFORM.1.1v1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.23, A.8.32 |
| SOC 2 | CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 6.5.3 |
| MITRE ATT&CK | T1048, T1567 |

---

### PPL-2.3 — Power Apps Portal Creation Restricted

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Non-admin users are restricted from creating public-facing Power Apps portals.

**Business risk:**
Power Apps portals are internet-accessible by default. Non-admin portal creation can inadvertently expose organizational data to the internet.

**Remediation:**
Power Platform Admin Center > Settings > Power Apps > Disable portal creation by non-admins.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-5, AC-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 9.3.3 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.POWERPLATFORM.5.1v1 |
| CMMC 2.0 | CM.L2-3.4.5 |
| ISO/IEC 27001:2022 | A.5.23, A.8.32 |
| SOC 2 | CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 6.5.3 |
| MITRE ATT&CK | T1578, T1190 |

---

### PPL-3.1 — M365 Copilot Sensitivity Label Enforcement

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+ (Copilot requires M365 Copilot add-on)

**Description:**
Sensitivity labels are published with Files & emails scope and an auto-labeling policy is active, enabling Microsoft 365 Copilot to respect data classification boundaries when grounding on tenant content.

**Business risk:**
Without sensitivity labels, Copilot can access and surface any data the user can reach — including HR files, financial records, and confidential strategies — with no awareness of sensitivity. Copilot dramatically amplifies over-sharing risk.

**Remediation:**
Purview > Information protection > Labels > Create/verify labels with Files & emails scope. Enable Copilot integration in label settings. Reference: Microsoft Copilot security baseline.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-16, SC-28 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.4.1 |
| CIS Controls v8.1 | 3.7 |
| CMMC 2.0 | MP.L2-3.8.4 |
| ISO/IEC 27001:2022 | A.8.11, A.8.12 |
| SOC 2 | C1.1, CC6.1 |
| HIPAA | §164.502(b), §164.312(a)(1) |
| PCI DSS | Req 3.4, Req 7.2 |
| MITRE ATT&CK | T1005 |

---

### PPL-3.2 — DLP Policy Active for Copilot Interactions

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 E5 Compliance add-on

**Description:**
At least one enabled Data Loss Prevention policy includes the Microsoft 365 Copilot location, blocking sensitive-information types in Copilot prompts and responses.

**Business risk:**
Without DLP covering Copilot, users can extract sensitive data by prompting Copilot to summarize, translate, or reformat confidential content — bypassing all other data controls.

**Remediation:**
Purview > DLP > Create policy > Locations: Include Microsoft 365 Copilot. Add sensitive info types as conditions. Requires M365 E5 Compliance or equivalent.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28, AC-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.3.4 |
| CIS Controls v8.1 | 3.13 |
| CMMC 2.0 | SC.L2-3.13.16 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1005, T1048 |

---

### PPL-3.3 — Copilot Access Restricted to Licensed Users

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 Copilot add-on license

**Description:**
Microsoft 365 Copilot license assignment is scoped to a defined subset of users with documented business need — not blanket-assigned tenant-wide.

**Business risk:**
Uncontrolled Copilot access means unlicensed users may gain Copilot capabilities through shared accounts or feature rollouts, bypassing governance controls.

**Remediation:**
M365 Admin Center > Settings > Microsoft 365 Copilot > Control access. Assign licenses only to approved users with a documented business need.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.5.1 |
| CIS Controls v8.1 | 6.8 |
| CMMC 2.0 | AC.L1-3.1.1 |
| ISO/IEC 27001:2022 | A.5.18, A.8.3 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 7.2.1 |
| MITRE ATT&CK | T1078 |

---

### PPL-3.4 — Copilot Studio Agent Publishing Governed

**Severity:** High  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Power Platform + Copilot Studio license

**Description:**
Copilot Studio (Power Virtual Agents) bots are not externally published to anonymous channels; bot publisher domains are confined to the tenant's onmicrosoft.com domain.

**Business risk:**
Ungoverned Copilot Studio agents can be built to query sensitive SharePoint libraries, connect to external APIs, and respond to any user in the organization — creating unreviewed data exposure channels at scale.

**Remediation:**
Power Platform Admin Center > Copilot Studio > Policies > Require admin approval for agent publishing. Apply DLP policies to Copilot Studio environment connectors.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-7, AC-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 9.3.4 |
| CIS Controls v8.1 | 6.8 |
| CMMC 2.0 | CM.L2-3.4.6 |
| ISO/IEC 27001:2022 | A.8.32 |
| SOC 2 | CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 6.5.3 |
| MITRE ATT&CK | T1078, T1190 |

---

### PPL-3.5 — Copilot Interaction Audit Logging Active

**Severity:** High  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
Unified Audit Log ingestion is enabled and a Purview retention policy explicitly covers Copilot interactions so prompts/responses are searchable beyond platform-default retention.

**Business risk:**
Without Copilot interaction logging, an insider using Copilot to extract sensitive data leaves no audit trail — the interaction is functionally invisible to security and compliance teams.

**Remediation:**
Ensure Unified Audit Log is enabled (Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true). Copilot interactions are searchable in Purview > Content explorer and Audit > Search.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.1 |
| CIS Controls v8.1 | 8.2, 8.10 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.2 |
| MITRE ATT&CK | T1114, T1562.008 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

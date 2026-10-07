# Microsoft Purview Baseline

**NRG-Assessment — Baseline Documentation**
*Product: Microsoft Purview*

---

## Introduction

This baseline lists the 18 Microsoft Purview controls evaluated by NRG-Assessment. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 1 Critical · 7 High · 6 Medium · 4 Low

---

## Controls

### PVW-1.1 — Unified Audit Log Enabled

**Severity:** Critical  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Microsoft Purview unified audit logging is enabled across M365 services.

**Business risk:**
Without audit logging, there is no record of admin changes, data access, or security policy modifications. Incident investigation is impossible.

**Remediation:**
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.1 |
| CIS Controls v8.1 | 8.2, 8.5 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2 |
| HIPAA | §164.312(b), §164.308(a)(1)(ii)(D) |
| PCI DSS | Req 10.2 |
| MITRE ATT&CK | T1562.008 |

---

### PVW-1.2 — Audit Log Retention Minimum 90 Days

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
Unified audit log retention is configured for at least 90 days.

**Business risk:**
Short retention prevents investigation of incidents discovered after the retention window closes.

**Remediation:**
Configure custom retention policies in Purview Compliance > Audit > Retention policies. E5 provides 1-year default.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-11 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.2 |
| CIS Controls v8.1 | 8.10 |
| CISA SCuBA | MS.DEFENDER.6.3v1 |
| CMMC 2.0 | AU.L2-3.3.2 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2, A1.2 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.5 |
| MITRE ATT&CK | T1562.008 |

---

### PVW-1.3 — DLP Policy Active for Sensitive Data

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
At least one active DLP policy protects sensitive information types from unauthorized sharing.

**Business risk:**
Without DLP, PII, financial data, and PHI can be emailed externally or shared with unauthenticated recipients without detection.

**Remediation:**
Create DLP policies in Purview > Data loss prevention using Microsoft-provided templates (Financial, PII, Health) across Exchange, SharePoint, Teams.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28, AC-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.3.1 |
| CIS Controls v8.1 | 3.13 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7, C1.1 |
| HIPAA | §164.312(e)(1), §164.502(b) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1048, T1567 |

---

### PVW-1.4 — Sensitivity Labels Published

**Severity:** Medium  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
At least one sensitivity label policy is published to users.

**Business risk:**
Without classification labels, sensitive data cannot be automatically protected or audited.

**Remediation:**
Create labels in Purview > Information protection. Publish via label policies. Minimum tiers: Internal, Confidential, Highly Confidential.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-16, SC-28 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.4.1 |
| CIS Controls v8.1 | 3.7 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.11, A.8.12 |
| SOC 2 | C1.1 |
| HIPAA | §164.502(b), §164.312(c)(1) |
| PCI DSS | Req 3.4, Req 7.2 |
| MITRE ATT&CK | T1048, T1005 |

---

### PVW-2.1 — Purview Audit Log Search Enabled

**Severity:** High  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Unified audit log search is enabled and accessible to compliance administrators.

**Business risk:**
Without audit log search, compliance teams cannot investigate incidents, fulfill legal holds, or demonstrate regulatory compliance.

**Remediation:**
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.1 |
| CIS Controls v8.1 | 8.11 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.7 |
| MITRE ATT&CK | T1562.008 |

---

### PVW-2.2 — Communication Compliance Policy Active

**Severity:** Low  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 E5 Compliance add-on

**Description:**
At least one communication compliance policy is active for regulatory monitoring.

**Business risk:**
In regulated industries (finance, healthcare, government), unmonitored communications create compliance liability.

**Remediation:**
Purview > Communication compliance > Create policy. Requires E5 Compliance.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.2.1 |
| CIS Controls v8.1 | 3.14 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.5.34, A.8.16 |
| SOC 2 | CC7.2 |
| HIPAA | §164.308(a)(1)(ii)(D), §164.502(j) |
| PCI DSS | Req 12.10.1 |
| MITRE ATT&CK | T1114 |

---

### PVW-2.3 — Information Barriers Mode Configured

**Severity:** Low  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 E5 Compliance add-on

**Description:**
Information barriers are configured in Single or Multi-segment mode if barriers are deployed.

**Business risk:**
Legacy information barriers mode has known limitations. Modern mode provides more reliable segment enforcement.

**Remediation:**
Set-PolicyConfig -InformationBarrierMode MultiSegment. Requires E5 Compliance.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.2.2 |
| CIS Controls v8.1 | 3.12 |
| CMMC 2.0 | AC.L2-3.1.3 |
| ISO/IEC 27001:2022 | A.5.18, A.8.3 |
| SOC 2 | C1.1, CC6.1 |
| HIPAA | Not cited: no Security Rule specification matches what this control checks (docs/HIPAA-CITATION-CORRECTIONS.md) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1048 |

---

### PVW-2.4 — Insider Risk Management Policy Active

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 E5 Compliance add-on

**Description:**
At least one insider risk management policy is configured to detect data theft or policy violations.

**Business risk:**
Departing employees and malicious insiders can exfiltrate significant data undetected without insider risk monitoring.

**Remediation:**
Purview > Insider risk management > Create policy (Departing user data theft, Data leaks). Requires E5 Compliance.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.2.3 |
| CIS Controls v8.1 | 3.14 |
| CMMC 2.0 | SI.L2-3.14.7 |
| ISO/IEC 27001:2022 | A.6.8, A.8.16 |
| SOC 2 | CC7.2, CC7.3 |
| HIPAA | §164.308(a)(6) |
| PCI DSS | Req 12.10 |
| MITRE ATT&CK | T1005, T1048 |

---

### PVW-2.5 — Retention Policy Covers Key Workloads

**Severity:** High  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
Retention policies are configured for Exchange, SharePoint, OneDrive, and Teams.

**Business risk:**
Without retention policies, data subject to legal hold cannot be preserved. Data may be deleted before regulatory retention requirements are met.

**Remediation:**
Purview > Data lifecycle management > Retention policies. Create policies for Exchange, SharePoint, OneDrive, Teams.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-11 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.3.2 |
| CIS Controls v8.1 | 3.4 |
| CMMC 2.0 | AU.L2-3.3.2 |
| ISO/IEC 27001:2022 | A.8.10, A.8.13 |
| SOC 2 | A1.2, CC2.1 |
| HIPAA | §164.308(a)(7)(ii)(A) |
| PCI DSS | Req 10.5 |
| MITRE ATT&CK | T1070.008 |

---

### PVW-2.6 — Auto-Labeling Policy Active

**Severity:** Medium  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 E5 Compliance add-on

**Description:**
At least one auto-labeling policy automatically applies sensitivity labels to content without user action.

**Business risk:**
Manual labeling is inconsistent. Sensitive data without labels is not protected by policies that depend on classification.

**Remediation:**
Purview > Information protection > Auto-labeling > Create policy for sensitive info types (SSN, credit card, etc.).

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-16, SC-28 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.4.2 |
| CIS Controls v8.1 | 3.7 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.11 |
| SOC 2 | C1.1 |
| HIPAA | §164.502(b), §164.312(c)(1) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1005 |

---

### PVW-3.1 — Audit Logs Exported to SIEM

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Microsoft Sentinel (add-on) or Defender XDR

**Description:**
Unified audit logs are forwarded to a SIEM (Microsoft Sentinel, Splunk, etc.) for long-term retention and correlation.

**Business risk:**
Portal-only audit log access is limited to 90-180 days and requires manual querying. SIEM export enables long-term retention, correlation, and automated alerting.

**Remediation:**
Connect Microsoft Sentinel M365 data connector, or use Defender XDR > Settings > Microsoft Defender XDR > Audit log export.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-4, AU-9 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.3 |
| CIS Controls v8.1 | 8.9, 8.10 |
| CISA SCuBA | MS.DEFENDER.5.2v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15, A.8.16 |
| SOC 2 | CC7.2, CC7.3 |
| HIPAA | §164.312(b), §164.308(a)(6) |
| PCI DSS | Req 10.4, Req 11.5 |
| MITRE ATT&CK | T1562.008 |

---

### PVW-3.2 — eDiscovery Case Management Configured

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
eDiscovery roles are assigned and cases can be opened for legal hold and content search.

**Business risk:**
Without eDiscovery access, compliance and legal teams cannot place holds or export content for litigation, regulatory audits, or HR investigations.

**Remediation:**
Purview > Roles & scopes > eDiscovery Manager. Assign eDiscovery Manager role to compliance team members.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-11, IR-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.5.1 |
| CIS Controls v8.1 | 3.14 |
| CMMC 2.0 | IR.L2-3.6.1 |
| ISO/IEC 27001:2022 | A.5.33 |
| SOC 2 | CC7.4 |
| HIPAA | §164.524 |
| PCI DSS | Req 12.10.5 |
| MITRE ATT&CK | T1114 |

---

### PVW-3.3 — Compliance Score Improvement Actions Tracked

**Severity:** Low  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Microsoft Purview Compliance Manager improvement actions are reviewed and assigned to owners.

**Business risk:**
Compliance Manager surfaces specific misconfiguration risks with remediation steps. Unreviewed action items represent documented known gaps.

**Remediation:**
compliance.microsoft.com > Compliance Manager > Improvement actions > Assign to owners and set target dates.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CA-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.5.2 |
| CMMC 2.0 | CA.L2-3.12.3 |
| ISO/IEC 27001:2022 | A.5.36 |
| SOC 2 | CC4.1, CC4.2 |
| HIPAA | §164.308(a)(8) |
| PCI DSS | Req 12.11 |
| MITRE ATT&CK | T1078 |

---

### PVW-3.4 — Sensitive Information Types Used in DLP Policies

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
DLP policies are configured with Microsoft or custom sensitive information types for automatic detection.

**Business risk:**
Without SIT-based detection, DLP policies provide no classification and cannot automatically protect sensitive data in transit.

**Remediation:**
Purview > DLP > Create or edit policies > Add conditions using sensitive information types (SSN, credit card, health info, etc.).

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28, AC-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.3.1 |
| CIS Controls v8.1 | 3.13, 3.7 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.502(b), §164.312(e)(1) |
| PCI DSS | Req 3.4, Req 12.5.3 |
| MITRE ATT&CK | T1048, T1005 |

---

### PVW-4.1 — Microsoft Purview Audit (Premium) Enabled

**Severity:** High  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 E5 or E5 Compliance add-on

**Description:**
Advanced Audit (now Microsoft Purview Audit Premium) is enabled for all users, capturing high-value events including MailItemsAccessed.

**Business risk:**
Standard audit does not capture MailItemsAccessed — the event that tells you which emails a compromised account read during a breach. Without it, mail exfil investigations are blind.

**Remediation:**
Assign Microsoft 365 E5 or E5 Compliance license to users, then enable Audit Premium: Purview > Audit > Audit log retention policies. Verify MailItemsAccessed events appear in audit search.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.4 |
| CIS Controls v8.1 | 8.5 |
| CISA SCuBA | MS.DEFENDER.6.1v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.2.1 |
| MITRE ATT&CK | T1114.002, T1562.008 |

---

### PVW-4.2 — Audit Log Retention Policy Extends to 1 Year or More

**Severity:** High  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 E5 or E5 Compliance add-on

**Description:**
A custom audit log retention policy preserves audit logs for at least 365 days for the highest-risk user populations.

**Business risk:**
Breaches have a median detection time over 200 days. The default 90-day retention window means the forensic record for most breaches has been purged before the breach is even detected.

**Remediation:**
Purview > Audit > Audit log retention policies > New retention policy. Priority: All activities, Users: All, Duration: 1 year or longer. Requires Audit Premium.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-11 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.5 |
| CIS Controls v8.1 | 8.10 |
| CISA SCuBA | MS.DEFENDER.6.3v1 |
| CMMC 2.0 | AU.L2-3.3.2 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2, A1.2 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.5.1 |
| MITRE ATT&CK | T1562.008, T1070.008 |

---

### PVW-4.3 — Sensitivity Labels Defined and Published

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
Sensitivity labels are configured in Purview and published via label policies to users across all workloads.

**Business risk:**
Without sensitivity labels, data has no classification context. DLP policies that depend on label conditions cannot fire, and information protection policies have nothing to act on.

**Remediation:**
Purview > Information protection > Sensitivity labels > Create label hierarchy (Public, Internal, Confidential, Highly Confidential). Create label policy and publish to all users.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-16, SC-28 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.4.1 |
| CIS Controls v8.1 | 3.7 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.11 |
| SOC 2 | C1.1 |
| HIPAA | §164.502(b) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1005, T1048 |

---

### PVW-4.4 — Records Management Labels Configured for Regulated Data

**Severity:** Low  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
Records management retention labels are configured for content subject to legal or regulatory hold requirements.

**Business risk:**
Without immutable records declarations, content subject to litigation hold can be modified or deleted — creating legal liability and spoliation risk.

**Remediation:**
Purview > Records management > Labels > Create record label with retention action. Publish via label policy. Required for healthcare (HIPAA), government, and financial organizations.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-11, IR-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.3.3 |
| CIS Controls v8.1 | 3.4 |
| CMMC 2.0 | IR.L2-3.6.1 |
| ISO/IEC 27001:2022 | A.5.33, A.8.13 |
| SOC 2 | A1.2, C1.1 |
| HIPAA | §164.530(j) |
| PCI DSS | Req 10.5 |
| MITRE ATT&CK | T1070.008 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

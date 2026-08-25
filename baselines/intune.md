# Microsoft Intune Baseline

**NRG-Assessment — Baseline Documentation**
*Product: Microsoft Intune*

---

## Introduction

This baseline lists the 17 Microsoft Intune controls evaluated by NRG-Assessment. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 1 Critical · 12 High · 3 Medium · 1 Low

---

## Controls

### INT-1.1 — Device Compliance Policies Configured

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
Intune compliance policies are configured and evaluating enrolled devices against security baselines.

**Business risk:**
Without compliance policies, enrolled devices have no enforced security requirements. Non-compliant devices access corporate resources unchecked.

**Remediation:**
Create compliance policies per platform in Intune > Devices > Compliance. Require encryption, password, and OS version minimums.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-2, CM-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.1.1 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | CM.L2-3.4.1 |
| ISO/IEC 27001:2022 | A.8.1 |
| SOC 2 | CC6.1, CC6.6 |
| HIPAA | §164.310(d)(1), §164.312(a)(1) |
| PCI DSS | Req 1.3 |
| MITRE ATT&CK | T1078, T1082 |

---

### INT-1.2 — Non-Compliant Device Access Blocked via CA

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
CA policies block or limit M365 access from devices marked non-compliant by Intune.

**Business risk:**
Compliance policies without CA enforcement are informational only. Non-compliant devices continue accessing data.

**Remediation:**
Create CA policy: require compliant device or hybrid join for all cloud apps.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, CM-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.1.3 |
| CIS Controls v8.1 | 13.5 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.8.1, A.8.3 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(1), §164.310(d)(1) |
| PCI DSS | Req 1.3 |
| MITRE ATT&CK | T1078 |

---

### INT-1.3 — BitLocker Encryption Required on Windows

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
Windows compliance policy requires BitLocker disk encryption.

**Business risk:**
Unencrypted laptops allow physical theft to result in data breach.

**Remediation:**
Intune compliance policy for Windows: Device Health > Require BitLocker = Require.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.1.2 |
| CIS Controls v8.1 | 3.6 |
| CMMC 2.0 | MP.L2-3.8.9 |
| ISO/IEC 27001:2022 | A.8.1, A.8.24 |
| SOC 2 | CC6.7, CC6.1 |
| HIPAA | §164.312(a)(2)(iv), §164.310(d)(1) |
| PCI DSS | Req 3.5.1 |
| MITRE ATT&CK | T1005, T1025 |

---

### INT-1.4 — Mobile Application Management Configured

**Severity:** Medium  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
Intune app protection policies enforce data containment on iOS and Android.

**Business risk:**
On BYOD devices without MAM, users can copy corporate data from managed apps to personal apps with no controls.

**Remediation:**
Create app protection policies in Intune > Apps > App protection policies for iOS and Android targeting Office apps.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-19, SC-28 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.3.1 |
| CIS Controls v8.1 | 3.3, 4.12 |
| CMMC 2.0 | AC.L2-3.1.19 |
| ISO/IEC 27001:2022 | A.8.1 |
| SOC 2 | CC6.1 |
| HIPAA | §164.310(d)(1), §164.312(a)(1) |
| PCI DSS | Req 1.3 |
| MITRE ATT&CK | T1005 |

---

### INT-1.5 — Antivirus Policy Deployed via Intune

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
Intune endpoint security antivirus policies are deployed to Windows devices, enforcing Defender AV settings.

**Business risk:**
Without enforced AV policy, users can disable Defender or create exclusions, leaving endpoints unprotected.

**Remediation:**
Create Endpoint Security > Antivirus policy in Intune. Set CloudBlockLevel = High, enable real-time protection and tamper protection.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.4.1 |
| CIS Controls v8.1 | 10.1, 10.2 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.2 |
| MITRE ATT&CK | T1562.001 |

---

### INT-2.1 — Endpoint Detection and Response Policy Deployed

**Severity:** Critical  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** Microsoft Defender for Endpoint Plan 2

**Description:**
MDE onboarding policy is deployed via Intune, enrolling endpoints into Defender for Endpoint.

**Business risk:**
Without EDR, endpoint threats are invisible. Lateral movement, persistence, and data theft go undetected.

**Remediation:**
Intune > Endpoint security > Endpoint detection and response > Create policy for Windows.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3, SI-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.4.2 |
| CIS Controls v8.1 | 10.7, 13.2 |
| CMMC 2.0 | SI.L2-3.14.7 |
| ISO/IEC 27001:2022 | A.8.7, A.8.16 |
| SOC 2 | CC6.8, CC7.2, CC7.3 |
| HIPAA | §164.308(a)(5)(ii)(B), §164.308(a)(6) |
| PCI DSS | Req 11.5 |
| MITRE ATT&CK | T1055, T1562.001 |

---

### INT-2.2 — Attack Surface Reduction Rules Enabled

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** Microsoft Defender for Endpoint Plan 1+

**Description:**
ASR rules are deployed via Intune endpoint security policy to block common malware delivery techniques.

**Business risk:**
ASR rules block Office macro abuse, credential theft from LSASS, and script-based attacks. Without them, commodity malware delivery succeeds.

**Remediation:**
Intune > Endpoint security > Attack surface reduction > Create ASR rules policy. Enable at minimum: Block Office macros, Block credential stealing, Block JS/VBS launching executables.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3, CM-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.4.3 |
| CIS Controls v8.1 | 10.5 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4 |
| MITRE ATT&CK | T1059, T1003 |

---

### INT-2.3 — Windows Firewall Policy Deployed via Intune

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
Windows Defender Firewall is managed and enforced via Intune endpoint security policy.

**Business risk:**
Without managed firewall policy, users can disable the firewall or create rules that expose services to lateral movement.

**Remediation:**
Intune > Endpoint security > Firewall > Create Windows Firewall policy. Enable domain, private, and public profiles.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.4.4 |
| CIS Controls v8.1 | 4.5 |
| CMMC 2.0 | SC.L1-3.13.1 |
| ISO/IEC 27001:2022 | A.8.20, A.8.21 |
| SOC 2 | CC6.6 |
| HIPAA | §164.312(a)(1), §164.312(e)(1) |
| PCI DSS | Req 1.2 |
| MITRE ATT&CK | T1021, T1590 |

---

### INT-2.4 — macOS FileVault Encryption Required

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
macOS compliance policy requires FileVault disk encryption.

**Business risk:**
Stolen or lost Macs without FileVault expose all organizational data stored locally, including cached credentials and documents.

**Remediation:**
Intune > Devices > Compliance > macOS > Create policy > System Security > Require encryption = Require.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.2.1 |
| CIS Controls v8.1 | 3.6 |
| CMMC 2.0 | MP.L2-3.8.9 |
| ISO/IEC 27001:2022 | A.8.1, A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(a)(2)(iv), §164.310(d)(1) |
| PCI DSS | Req 3.5.1 |
| MITRE ATT&CK | T1005, T1025 |

---

### INT-2.5 — Windows Update Compliance Policy Deployed

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
Windows Update for Business rings or compliance policy ensures devices receive security updates on schedule.

**Business risk:**
Unpatched endpoints are the most exploited attack surface. Without managed update policy, critical patches may sit unapplied for months.

**Remediation:**
Intune > Devices > Windows update rings > Create update ring with feature and quality update schedules.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.5.1 |
| CIS Controls v8.1 | 7.3 |
| CMMC 2.0 | SI.L1-3.14.1 |
| ISO/IEC 27001:2022 | A.8.8 |
| SOC 2 | CC7.1, CC8.1 |
| HIPAA | §164.308(a)(1)(ii)(B), §164.308(a)(8) |
| PCI DSS | Req 6.3.3 |
| MITRE ATT&CK | T1190, T1068 |

---

### INT-3.1 — Device Enrollment Restrictions Configured

**Severity:** Medium  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
Intune enrollment restrictions limit which platforms, ownership types, and OS versions can enroll.

**Business risk:**
Without enrollment restrictions, any device — including unmanaged personal or obsolete devices — can enroll and receive corporate app access.

**Remediation:**
Intune > Devices > Enrollment > Enrollment restrictions > Create policy restricting to managed platforms and minimum OS versions.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-7, AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.1.4 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | CM.L2-3.4.1 |
| ISO/IEC 27001:2022 | A.8.1 |
| SOC 2 | CC6.2 |
| HIPAA | §164.308(a)(4)(ii)(C), §164.310(d)(1) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1078 |

---

### INT-3.2 — Mobile App Configuration Policies Deployed

**Severity:** Low  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
App configuration policies push security settings to managed mobile apps.

**Business risk:**
Without app config policies, managed apps use default settings which may not meet security baselines. Outlook, Teams, and Edge on mobile all have security-relevant configuration options.

**Remediation:**
Intune > Apps > App configuration policies > Create policy for iOS/Android targeting Outlook, Teams, Edge.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-6, AC-19 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.3.2 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | CM.L2-3.4.2 |
| ISO/IEC 27001:2022 | A.8.1 |
| SOC 2 | CC6.1 |
| HIPAA | §164.310(d)(1) |
| PCI DSS | Req 1.3 |
| MITRE ATT&CK | T1078 |

---

### INT-3.3 — Conditional Launch Policies Configured

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
App protection policies include conditional launch settings to block jailbroken devices and enforce OS version requirements.

**Business risk:**
Jailbroken and rooted devices bypass OS security controls. Without conditional launch, compromised devices access corporate apps with full permissions.

**Remediation:**
Intune > Apps > App protection policies > Conditional launch > Add: Jailbroken/rooted devices = Block, Min OS version = current-1.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28, CM-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.3.3 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | CM.L2-3.4.1 |
| ISO/IEC 27001:2022 | A.8.1 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(1), §164.310(d)(1) |
| PCI DSS | Req 7.2, Req 1.3 |
| MITRE ATT&CK | T1078 |

---

### INT-4.1 — Windows LAPS Deployed via Intune

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
Windows Local Administrator Password Solution (LAPS) is deployed via Intune, generating unique randomized local admin passwords escrowed in Entra ID.

**Business risk:**
Shared or static local admin passwords enable pass-the-hash lateral movement — one compromised endpoint hands the attacker credentials that work on every other endpoint with the same password.

**Remediation:**
Intune > Endpoint security > Account protection > Create Windows LAPS policy. Configure: Admin account managed = Yes, Password age = 30 days, Password complexity = Large letters + small letters + numbers + special characters.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2, IA-5 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.1.5 |
| CIS Controls v8.1 | 5.4, 4.7 |
| CMMC 2.0 | IA.L1-3.5.1 |
| ISO/IEC 27001:2022 | A.5.17, A.8.2 |
| SOC 2 | CC6.1 |
| HIPAA | §164.308(a)(5)(ii)(D) |
| PCI DSS | Req 2.2.2 |
| MITRE ATT&CK | T1110, T1021.002 |

---

### INT-4.2 — Windows Hello for Business Deployed

**Severity:** Medium  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
Windows Hello for Business is deployed via Intune policy, enabling phishing-resistant passwordless authentication on enrolled Windows endpoints.

**Business risk:**
WHfB eliminates password-based credential theft on enrolled endpoints — LSASS dumping yields nothing, phishing yields nothing. It is the highest-value passwordless deployment available at no extra license cost.

**Remediation:**
Intune > Devices > Windows > Windows enrollment > Windows Hello for Business settings. Or deploy via endpoint protection policy: Use Windows Hello for Business = Enabled.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2(1) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.1.6 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.17, A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.4 |
| MITRE ATT&CK | T1078, T1110 |

---

### INT-4.3 — Device OS Version Compliance Enforced

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
Device compliance policies enforce minimum OS versions and compliance rate is ≥90% across enrolled devices.

**Business risk:**
Endpoints running outdated OS versions contain unpatched known exploits. KEV-listed vulnerabilities are actively exploited by ransomware operators and nation-state actors.

**Remediation:**
Intune > Devices > Compliance policies > Create policy > OS minimum version = latest-1. Review noncompliant devices report and address outliers.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.5.5 |
| CIS Controls v8.1 | 7.3 |
| CMMC 2.0 | SI.L1-3.14.1 |
| ISO/IEC 27001:2022 | A.8.8 |
| SOC 2 | CC7.1, CC8.1 |
| HIPAA | §164.308(a)(1)(ii)(B) |
| PCI DSS | Req 6.3.3 |
| MITRE ATT&CK | T1190, T1068 |

---

### INT-4.4 — Mobile Device Compliance Requires PIN or Biometric

**Severity:** High  |  **Category:** Endpoint  |  **Automated:** Yes

**License required:** M365 Business Premium or Intune Plan 1

**Description:**
iOS and Android compliance policies require a PIN or biometric lock before accessing managed apps.

**Business risk:**
Unlocked mobile devices give physical access to all managed apps, corporate email, Teams conversations, and OneDrive files — no attacker credential required.

**Remediation:**
Intune > Devices > Compliance > iOS/Android policy > System security > Require password = Require. Set minimum length = 6, complexity = Numeric + symbols.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-5, AC-11 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 4.2.2 |
| CIS Controls v8.1 | 4.3, 4.10 |
| CMMC 2.0 | IA.L1-3.5.1 |
| ISO/IEC 27001:2022 | A.5.17, A.8.1 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(2)(iii), §164.312(d) |
| PCI DSS | Req 8.4 |
| MITRE ATT&CK | T1078, T1005 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

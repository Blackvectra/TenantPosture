# Microsoft Entra ID Baseline

**NRG-Assessment — Baseline Documentation**
*Product: Microsoft Entra ID*

---

## Introduction

This baseline lists the 46 Microsoft Entra ID controls evaluated by NRG-Assessment. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 6 Critical · 23 High · 12 Medium · 5 Low

---

## Controls

### AAD-1.1 — Legacy Authentication Blocked

**Severity:** Critical  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
A Conditional Access policy blocks legacy authentication protocols for all users, or Security Defaults is enabled, which Microsoft documents blocks every authentication request made by an older protocol tenant-wide (including Exchange ActiveSync basic authentication). Legacy auth bypasses MFA entirely.

**Business risk:**
Any account using legacy auth can be compromised without MFA. Attackers actively spray legacy auth endpoints because MFA cannot intercept them.

**Remediation:**
Create a CA policy: All Users, Client apps = Other clients + Exchange ActiveSync, Grant = Block access.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2, IA-5(1) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.2.3 |
| CIS Controls v8.1 | 6.3, 4.1 |
| CISA SCuBA | MS.AAD.1.1v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.17 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.3 |
| MITRE ATT&CK | T1078, T1110.003 |

---

### AAD-1.2 — MFA Required for All Users

**Severity:** Critical  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
A Conditional Access policy requires MFA for all users on all cloud apps at every sign-in, with every user registered. Security Defaults meets this only in part: it requires every user to register for MFA and the 16 administrator roles it names to complete MFA at every sign-in, but prompts other users for MFA only when Microsoft decides it is necessary.

**Business risk:**
Without MFA, a single stolen password enables full account takeover. Password spray, phishing, and credential stuffing all succeed.

**Remediation:**
CA policy: Users = All, Apps = All cloud apps, Grant = Require MFA. Without Microsoft Entra ID P1, enable Security Defaults, which meets this control in part (MFA at every sign-in for 16 administrator roles; other users when Microsoft decides).

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2(1), IA-2(2) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.2.1 |
| CIS Controls v8.1 | 6.3, 6.4 |
| CISA SCuBA | MS.AAD.3.2v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.17, A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.4 |
| MITRE ATT&CK | T1078, T1621 |

---

### AAD-1.3 — Phishing-Resistant MFA Required for Admins

**Severity:** Critical  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
CA policy requires phishing-resistant MFA (Authentication Strength: FIDO2, CBA, or Windows Hello) for all privileged directory roles.

**Business risk:**
Standard MFA is bypassed by AiTM proxy phishing attacks. Attackers use Evilginx2 to steal session tokens even when MFA is completed.

**Remediation:**
CA policy targeting privileged roles with Authentication Strength = Phishing-resistant MFA. Must cover Global Administrator at minimum.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2(1), IA-2(2), IA-2(6) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.2.2 |
| CIS Controls v8.1 | 6.5 |
| CISA SCuBA | MS.AAD.3.6v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.8.2, A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d), §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 8.4 |
| MITRE ATT&CK | T1078.004, T1621, T1557 |

---

### AAD-1.4 — Sign-in Risk CA Policy

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2

**Description:**
CA policy enforces MFA or blocks access when sign-in risk is elevated. Requires Entra ID P2.

**Business risk:**
Without sign-in risk policies, compromised credentials and impossible travel go unchallenged.

**Remediation:**
CA policy: Condition = Sign-in risk high/medium, Grant = Require MFA or Block. Requires Entra P2.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-7, IA-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.2.6 |
| CIS Controls v8.1 | 6.7 |
| CISA SCuBA | MS.AAD.2.3v1 |
| CMMC 2.0 | AC.L2-3.1.8 |
| ISO/IEC 27001:2022 | A.8.16 |
| SOC 2 | CC6.1, CC7.2 |
| HIPAA | §164.312(a)(1) |
| PCI DSS | Req 8.5 |
| MITRE ATT&CK | T1078, T1621 |

---

### AAD-1.5 — User Risk CA Policy

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2

**Description:**
CA policy enforces password change or blocks access when user risk is elevated.

**Business risk:**
High user risk indicates credential compromise. Without automated response, compromised accounts remain active.

**Remediation:**
CA policy: Condition = User risk high, Grant = Require password change. Requires Entra P2.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-7, IA-5 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.2.7 |
| CIS Controls v8.1 | 6.7 |
| CISA SCuBA | MS.AAD.2.1v1 |
| CMMC 2.0 | AC.L2-3.1.8 |
| ISO/IEC 27001:2022 | A.8.16 |
| SOC 2 | CC6.1, CC7.2 |
| HIPAA | §164.312(a)(1) |
| PCI DSS | Req 8.5 |
| MITRE ATT&CK | T1078, T1110 |

---

### AAD-2.1 — Conditional Access Policies Deployed

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
At minimum three enabled CA policies provide coverage for legacy auth block, MFA all users, and MFA for admins.

**Business risk:**
Without Conditional Access or Security Defaults, access control can be password-only (unless legacy per-user MFA is enforced). Security Defaults is a fallback — not a substitute for a mature CA posture.

**Remediation:**
Deploy at minimum: (1) block legacy auth, (2) require MFA all users, (3) phishing-resistant MFA for admin roles.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-17, IA-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.2 |
| CIS Controls v8.1 | 4.1, 6.5 |
| CISA SCuBA | MS.AAD.1.1v1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.15, A.8.3 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(1) |
| PCI DSS | Req 7.2 |
| MITRE ATT&CK | T1078, T1110 |

---

### AAD-2.2 — Named Locations Defined

**Severity:** Low  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
At least one trusted named location (IP range) is defined in Entra ID for use in CA policies.

**Business risk:**
Without named locations, CA cannot distinguish access from trusted office networks vs untrusted locations.

**Remediation:**
Entra ID > Security > Named locations > Add IP ranges location. Mark office and VPN IP ranges as trusted.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-17 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.1 |
| CMMC 2.0 | AC.L2-3.1.12 |
| ISO/IEC 27001:2022 | A.8.3 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(1) |
| PCI DSS | Req 8.2.2 |
| MITRE ATT&CK | T1078 |

---

### AAD-2.3 — Device Compliance Enforced via CA

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1 + Intune

**Description:**
CA policy requires compliant or hybrid-joined device for access to M365 resources.

**Business risk:**
Without device compliance enforcement, unmanaged personal devices access corporate data with no endpoint controls.

**Remediation:**
CA policy: Grant = Require device to be marked as compliant, or Require Microsoft Entra hybrid joined device.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-7, AC-17 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.2.8 |
| CIS Controls v8.1 | 13.5 |
| CISA SCuBA | MS.AAD.3.7v1 |
| CMMC 2.0 | CM.L2-3.4.1 |
| ISO/IEC 27001:2022 | A.8.1 |
| SOC 2 | CC6.1 |
| HIPAA | §164.310(d)(1), §164.312(a)(1) |
| PCI DSS | Req 1.3 |
| MITRE ATT&CK | T1078 |

---

### AAD-3.1 — Global Administrator Count 2-8, Cloud-Only

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
The tenant has 2-8 Global Administrators, all cloud-only (not synced from on-premises AD).

**Business risk:**
More than 8 GAs increases attack surface. Synced GA accounts allow on-prem compromise to escalate directly to cloud tenant control.

**Remediation:**
Reduce GA count to 2-8 break-glass accounts. Remove GA from any on-premises synced accounts and assign to cloud-only accounts.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-6, AC-6(5) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.2.1 |
| CIS Controls v8.1 | 5.4, 6.8 |
| CISA SCuBA | MS.AAD.7.1v1 |
| CMMC 2.0 | AC.L2-3.1.6 |
| ISO/IEC 27001:2022 | A.8.2 |
| SOC 2 | CC6.1 |
| HIPAA | §164.308(a)(4)(ii)(C), §164.312(a)(2)(i) |
| PCI DSS | Req 7.2.1 |
| MITRE ATT&CK | T1078.004, T1098 |

---

### AAD-3.2 — No Permanent Admin Role Assignments

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2

**Description:**
Privileged roles use PIM eligible assignments — no permanent active assignments outside break-glass accounts.

**Business risk:**
Permanent admin accounts are always high-value targets. PIM limits the window of privilege exposure to when it is actually needed.

**Remediation:**
Convert permanent role assignments to PIM eligible. Keep only break-glass accounts as permanent GA.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-6(5) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.2.2 |
| CIS Controls v8.1 | 6.8, 5.4 |
| CISA SCuBA | MS.AAD.7.3v1 |
| CMMC 2.0 | AC.L2-3.1.6 |
| ISO/IEC 27001:2022 | A.8.2 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(C) |
| PCI DSS | Req 7.2.5 |
| MITRE ATT&CK | T1078.004, T1548 |

---

### AAD-3.3 — PIM Requires MFA on Activation

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2

**Description:**
PIM role management policies require MFA when users activate an eligible role assignment.

**Business risk:**
Without MFA on activation, a compromised account can silently elevate to Global Admin via PIM with just a password.

**Remediation:**
PIM > Roles > Select role > Settings > Require MFA on activation.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2(1) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.3.1 |
| CIS Controls v8.1 | 6.5 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.8.2, A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.4 |
| MITRE ATT&CK | T1078.004, T1548 |

---

### AAD-3.4 — PIM Requires Justification on Activation

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2

**Description:**
PIM requires users to provide a reason when activating an eligible role assignment.

**Business risk:**
Without justification, privileged access activations have no audit trail. Insider threat and accidental escalation go undocumented.

**Remediation:**
PIM > Roles > Select role > Settings > Require justification on activation.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-6(9), AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.3.2 |
| CIS Controls v8.1 | 6.8 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.2, A.8.15 |
| SOC 2 | CC6.1 |
| HIPAA | §164.308(a)(1)(ii)(D) |
| PCI DSS | Req 10.2 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-3.5 — PIM GA Activation Requires Approval

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2

**Description:**
Global Administrator PIM activation requires approval from a designated reviewer.

**Business risk:**
Self-approval GA elevation means any compromised eligible account reaches global admin without a second control point.

**Remediation:**
PIM > Global Administrator > Settings > Require approval > Add approvers.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-6(5) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.3.3 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.AAD.7.6v1 |
| CMMC 2.0 | AC.L2-3.1.5 |
| ISO/IEC 27001:2022 | A.8.2 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-3.6 — PIM Max Activation Duration 8 Hours or Less

**Severity:** Low  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2

**Description:**
PIM role policies set maximum activation duration to 8 hours or less.

**Business risk:**
Longer activation windows increase the time a compromised activation session can be abused.

**Remediation:**
PIM > Roles > Select role > Settings > Maximum activation duration = 8 hours.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.3.4 |
| CIS Controls v8.1 | 6.8 |
| CMMC 2.0 | AC.L2-3.1.5 |
| ISO/IEC 27001:2022 | A.8.2 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(C) |
| PCI DSS | Req 7.2.5 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-4.1 — Guest Invite Permissions Restricted

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Only admins or Guest Inviter role members can invite external guest users.

**Business risk:**
Any member being able to invite guests enables uncontrolled external access provisioning without IT oversight.

**Remediation:**
Entra ID > External Identities > External collaboration settings > Guest invite settings = Admins and users in the Guest Inviter role.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.3.1 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.AAD.8.2v1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18, A.5.19 |
| SOC 2 | CC6.2 |
| HIPAA | §164.308(a)(4) |
| PCI DSS | Req 7.2.3 |
| MITRE ATT&CK | T1078 |

---

### AAD-4.2 — External Collaboration Settings Restricted

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Users cannot create new tenants and legacy MSOL PowerShell is blocked.

**Business risk:**
Unrestricted external collaboration settings enable shadow IT tenant creation and legacy protocol abuse.

**Remediation:**
Entra ID > User settings > Restrict non-admin users from creating tenants. Block MSOL PowerShell via authorization policy.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-7, AC-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.3.2 |
| CIS Controls v8.1 | 6.8 |
| CMMC 2.0 | CM.L2-3.4.6 |
| ISO/IEC 27001:2022 | A.5.19, A.5.21 |
| SOC 2 | CC6.2, CC6.6 |
| HIPAA | §164.308(a)(4) |
| PCI DSS | Req 1.3.1 |
| MITRE ATT&CK | T1078 |

---

### AAD-4.3 — B2B Guest Default Permissions Restricted

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Guest users are assigned the Restricted Guest User role — not member-equivalent permissions.

**Business risk:**
Guest users with member-level permissions can enumerate users, groups, and applications — gathering intelligence for targeted attacks.

**Remediation:**
Entra ID > External Identities > External collaboration settings > Guest user access = Most restricted.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.3.3 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.AAD.8.1v1 |
| CMMC 2.0 | AC.L2-3.1.3 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | CC6.2 |
| HIPAA | §164.308(a)(4) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1087, T1069 |

---

### AAD-5.1 — Self-Service Password Reset Enabled

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
SSPR is enabled allowing users to reset their own passwords without helpdesk involvement.

**Business risk:**
Without SSPR, helpdesk becomes a social engineering target — attackers call claiming to be users to get password resets.

**Remediation:**
Entra ID > Password reset > Properties > Self service password reset enabled = All or Selected.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-5 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.4.1 |
| CMMC 2.0 | IA.L2-3.5.7 |
| ISO/IEC 27001:2022 | A.5.17 |
| SOC 2 | CC6.1 |
| HIPAA | §164.308(a)(5)(ii)(D) |
| PCI DSS | Req 8.3.5 |
| MITRE ATT&CK | T1078 |

---

### AAD-5.2 — SSPR Requires Multiple Authentication Methods

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
SSPR is configured to require at least two authentication methods for password reset.

**Business risk:**
Single-method SSPR allows account takeover via one compromised recovery method (phone SIM swap, email compromise).

**Remediation:**
Entra ID > Password reset > Authentication methods > Number of methods required = 2.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2(1), IA-5 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.4.2 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.17 |
| SOC 2 | CC6.1 |
| HIPAA | §164.308(a)(5)(ii)(D) |
| PCI DSS | Req 8.3.5 |
| MITRE ATT&CK | T1078 |

---

### AAD-6.1 — User App Registration Disabled

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Non-admin users cannot register new applications in Entra ID.

**Business risk:**
Users registering apps can accidentally or deliberately grant excessive API permissions, creating OAuth attack surfaces.

**Remediation:**
Entra ID > User settings > App registrations > Users can register applications = No.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-5, AC-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.5.1 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.AAD.5.1v1 |
| CMMC 2.0 | CM.L2-3.4.5 |
| ISO/IEC 27001:2022 | A.8.19 |
| SOC 2 | CC6.3, CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 6.5.4 |
| MITRE ATT&CK | T1528, T1550.001 |

---

### AAD-6.2 — User Consent to Apps Restricted

**Severity:** Critical  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Users cannot consent to application permissions — all consent goes through admin workflow.

**Business risk:**
Consent phishing grants attacker-controlled apps access to mailbox and files. Users cannot distinguish malicious OAuth consent from legitimate.

**Remediation:**
Entra ID > Enterprise apps > Consent and permissions > User consent settings = Do not allow user consent.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.5.2 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.AAD.5.2v1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.23, A.8.19 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4) |
| PCI DSS | Req 6.4.3 |
| MITRE ATT&CK | T1528, T1550.001 |

---

### AAD-6.3 — Admin Consent Workflow Enabled

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Admin consent workflow allows users to request app access that goes through an approval process.

**Business risk:**
Without a consent workflow, users with blocked consent have no approved path — they use shadow IT alternatives instead.

**Remediation:**
Entra ID > Enterprise apps > Consent and permissions > Admin consent requests > Yes + configure reviewers.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.5.3 |
| CIS Controls v8.1 | 6.1 |
| CISA SCuBA | MS.AAD.5.3v1 |
| CMMC 2.0 | AC.L1-3.1.1 |
| ISO/IEC 27001:2022 | A.8.19 |
| SOC 2 | CC6.3, CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 6.5.4 |
| MITRE ATT&CK | T1528 |

---

### AAD-7.1 — Password Protection Lockout Configured

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Account lockout threshold is configured at 10 or fewer failed attempts.

**Business risk:**
High lockout thresholds allow extensive brute force attempts before accounts are locked.

**Remediation:**
Entra ID > Security > Authentication methods > Password protection > Lockout threshold ≤10.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.6.1 |
| CMMC 2.0 | AC.L2-3.1.8 |
| ISO/IEC 27001:2022 | A.5.17, A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.308(a)(5)(ii)(C), §164.308(a)(5)(ii)(D) |
| PCI DSS | Req 8.3.4 |
| MITRE ATT&CK | T1110 |

---

### AAD-7.2 — Break-Glass Accounts Configured

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
At least two cloud-only accounts permanently assigned Global Administrator are kept as emergency access accounts, excluded from every Conditional Access policy that would otherwise reach them. While Security Defaults is enabled (it cannot exclude any account), they are confirmed to exist, with credentials held offline and an MFA method registered for each.

**Business risk:**
Without break-glass accounts, a CA policy misconfiguration can lock all admins out of the tenant permanently.

**Remediation:**
Create two cloud-only GA accounts with strong random passwords, exclude from all CA policies, store credentials in secure offline location. Monitor for sign-in activity.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CP-2, AC-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.2.3 |
| CIS Controls v8.1 | 5.4 |
| CMMC 2.0 | IR.L2-3.6.1 |
| ISO/IEC 27001:2022 | A.5.30, A.8.2 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(2)(ii) |
| PCI DSS | Req 7.2.1 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-8.1 — PIM Alerts Configured

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2

**Description:**
PIM security alerts are configured to detect stale, redundant, and outside-PIM role assignments.

**Business risk:**
Without PIM alerts, over-privileged accounts, dormant admins, and bypass assignments go undetected indefinitely.

**Remediation:**
PIM > Alerts > Review and enable: Roles assigned outside PIM, Redundant assignments, Stale assignments, Too many GA admins.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-6(9), AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.3.5 |
| CIS Controls v8.1 | 13.1 |
| CISA SCuBA | MS.AAD.7.7v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15, A.8.16 |
| SOC 2 | CC7.2 |
| HIPAA | §164.308(a)(1)(ii)(D), §164.312(b) |
| PCI DSS | Req 10.2 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-8.2 — Access Reviews for Privileged Roles

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2

**Description:**
Recurring access reviews are configured for privileged directory roles via PIM.

**Business risk:**
Without access reviews, stale privileged accounts accumulate over time, increasing attack surface with every employee departure or role change.

**Remediation:**
PIM > Microsoft Entra roles > Access reviews > Create recurring quarterly review for Global Admin, Privileged Role Admin, Security Admin.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2(9) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.4.1 |
| CIS Controls v8.1 | 6.8 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18, A.8.2 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-9.1 — Authenticator Number Matching Enabled

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Microsoft Authenticator number matching is explicitly enabled to prevent MFA fatigue attacks.

**Business risk:**
Without number matching, attackers can spam MFA push requests until a user accidentally approves. MFA fatigue is a documented breach technique.

**Remediation:**
Entra ID > Security > Authentication methods > Microsoft Authenticator > Configure > Require number matching = Enabled.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2(1) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.1.1 |
| CIS Controls v8.1 | 6.3 |
| CISA SCuBA | MS.AAD.3.3v2 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.17, A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.4 |
| MITRE ATT&CK | T1621 |

---

### AAD-9.2 — Passwordless Authentication Methods Available

**Severity:** Low  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
FIDO2 security keys or Windows Hello for Business are enabled as passwordless authentication options.

**Business risk:**
Password-based auth carries inherent credential theft risk. Passwordless methods eliminate the credential as an attack vector entirely.

**Remediation:**
Entra ID > Security > Authentication methods > FIDO2 security key > Enable. Consider Windows Hello for Business via Intune policy.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2(1), IA-5 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.1.2 |
| CIS Controls v8.1 | 6.5, 6.3 |
| CISA SCuBA | MS.AAD.3.1v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.17, A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.4 |
| MITRE ATT&CK | T1078, T1110 |

---

### AAD-10.1 — Identity Protection Risky User Workflow

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2

**Description:**
Automated response to Identity Protection risky user signals via CA user risk policy.

**Business risk:**
Identity Protection detects credential compromise, leaked credentials, and anomalous sign-ins. Without automated response, the human follow-up is too slow.

**Remediation:**
CA policy: Condition = User risk = High, Grant = Require password change. Requires Entra P2.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IR-4, AC-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.2.7 |
| CIS Controls v8.1 | 6.7 |
| CISA SCuBA | MS.AAD.2.2v1 |
| CMMC 2.0 | IR.L2-3.6.1 |
| ISO/IEC 27001:2022 | A.5.27, A.8.16 |
| SOC 2 | CC7.2, CC7.3 |
| HIPAA | §164.308(a)(1)(ii)(D), §164.308(a)(6) |
| PCI DSS | Req 10.7 |
| MITRE ATT&CK | T1078, T1110 |

---

### AAD-10.2 — Privileged Accounts Use Dedicated Cloud-Only Accounts

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
All privileged role holders use separate cloud-only accounts, not their day-to-day synced accounts.

**Business risk:**
Using the same account for email and admin work means email phishing can compromise admin credentials. Dedicated admin accounts separate the blast radius.

**Remediation:**
Create dedicated .admin or .onmicrosoft.com accounts for all privileged role holders. Remove privileged roles from on-premises synced accounts.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-6(5) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.1.1 |
| CIS Controls v8.1 | 5.4 |
| CISA SCuBA | MS.AAD.7.3v1 |
| CMMC 2.0 | AC.L2-3.1.6 |
| ISO/IEC 27001:2022 | A.8.2 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(2)(i) |
| PCI DSS | Req 8.2.1 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-10.3 — Break-Glass Account Sign-In Monitoring

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Alerts are configured to notify immediately if break-glass accounts are used.

**Business risk:**
Break-glass accounts bypass all CA policies. Any use should be treated as an incident — either a genuine emergency or unauthorized access.

**Remediation:**
Create a Sentinel or Defender XDR alert rule for sign-in from break-glass account UPNs. Notify SOC immediately on any sign-in.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, IR-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.2.4 |
| CIS Controls v8.1 | 13.1 |
| CMMC 2.0 | IR.L2-3.6.1 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2 |
| HIPAA | §164.308(a)(1)(ii)(D), §164.312(b) |
| PCI DSS | Req 10.2.5 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-10.4 — Sign-in Frequency Session Control Configured

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
CA policy enforces sign-in frequency to limit the lifetime of stolen session tokens.

**Business risk:**
Stolen tokens (from AiTM, token theft via malware) remain valid for the full session lifetime. Sign-in frequency limits re-use to the configured window.

**Remediation:**
CA policy: Session controls > Sign-in frequency > set to 1 hour for privileged users, 8 hours for standard users.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.3.1 |
| CIS Controls v8.1 | 4.3 |
| CMMC 2.0 | AC.L2-3.1.10 |
| ISO/IEC 27001:2022 | A.5.17, A.8.3 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(2)(iii) |
| PCI DSS | Req 8.2.8 |
| MITRE ATT&CK | T1550.001, T1539 |

---

### AAD-11.1 — Device Code Authentication Flow Blocked

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
A Conditional Access policy blocks the device code authentication flow for all users, or Security Defaults is enabled, which Microsoft documents blocks authentication requests that use device code flow.

**Business risk:**
Device code phishing attacks send victims to a legitimate Microsoft URL where they enter an attacker-controlled code — no password required. The attack is especially effective against less technical users.

**Remediation:**
CA policy: Conditions > Authentication flows > Device code flow, Grant = Block. Applies to all users.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.2.10 |
| CIS Controls v8.1 | 4.1 |
| CISA SCuBA | MS.AAD.3.9v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.17 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.4 |
| MITRE ATT&CK | T1528, T1111 |

---

### AAD-11.2 — No Guest Accounts in Highly Privileged Roles

**Severity:** Critical  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
No guest accounts hold Global Administrator, Privileged Role Administrator, or other highly privileged directory roles.

**Business risk:**
Guest accounts are outside the tenant's identity governance. A compromised guest account holding a privileged role provides tenant-wide administrative access from an uncontrolled identity.

**Remediation:**
Remove guest accounts from all privileged roles. Use cloud-only member accounts for all administrative functions.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2, AC-6(5) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.1.2 |
| CIS Controls v8.1 | 6.8, 5.4 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18, A.8.2 |
| SOC 2 | CC6.2, CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 7.2.3 |
| MITRE ATT&CK | T1078, T1078.004 |

---

### AAD-11.3 — Risky Service Principals Reviewed and Remediated

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra ID P2 + Workload Identities add-on

**Description:**
No service principals are flagged as risky by Entra ID Identity Protection without active remediation.

**Business risk:**
Risky service principals represent compromised application identities with persistent, non-interactive access to all assigned resource scopes. Unlike user accounts, they have no MFA and no session expiry.

**Remediation:**
Entra ID > Identity Protection > Risky workload identities. Investigate and remediate flagged service principals. Disable or rotate credentials for compromised identities. Requires Entra ID P2 Workload Identities.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-3, IR-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.5.1 |
| CIS Controls v8.1 | 5.5 |
| CMMC 2.0 | IR.L2-3.6.1 |
| ISO/IEC 27001:2022 | A.5.23, A.8.30 |
| SOC 2 | CC7.2 |
| HIPAA | §164.308(a)(1)(ii)(D) |
| PCI DSS | Req 6.4.3 |
| MITRE ATT&CK | T1078.004, T1550.001 |

---

### AAD-11.4 — Token Protection (Session Binding) Enforced

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
CA policy enforces token protection to bind tokens to the originating device, blocking replay attacks.

**Business risk:**
AiTM (adversary-in-the-middle) phishing steals authenticated session tokens. Without token binding, stolen tokens work from any device — effectively bypassing MFA entirely.

**Remediation:**
CA policy: Session controls > Token protection. Enable for Exchange Online and SharePoint Online at minimum. Requires Entra ID P1+. Note: may cause issues with non-compliant clients — test in report-only mode first.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-12, IA-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.3.2 |
| CMMC 2.0 | AC.L2-3.1.10 |
| ISO/IEC 27001:2022 | A.5.17 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d), §164.312(c)(2) |
| PCI DSS | Req 8.3 |
| MITRE ATT&CK | T1550.001, T1539 |

---

### AAD-11.5 — Continuous Access Evaluation Strict Mode

**Severity:** Low  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
CA policy enforces CAE strict mode ensuring near-real-time session revocation when risk or network conditions change.

**Business risk:**
Default CAE uses best-effort revocation with up to 60-minute delays. Strict mode provides near-real-time enforcement when IP changes or risk signals fire.

**Remediation:**
CA policy > Session controls > Customize continuous access evaluation > Strict enforcement.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.3.3 |
| CIS Controls v8.1 | 6.2 |
| CMMC 2.0 | AC.L2-3.1.11 |
| ISO/IEC 27001:2022 | A.5.17, A.8.16 |
| SOC 2 | CC6.1, CC7.2 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.3 |
| MITRE ATT&CK | T1550.001 |

---

### AAD-11.6 — Cross-Tenant Inbound Trust Settings Restricted

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Default cross-tenant access settings do not trust external MFA or device compliance claims from unknown tenants.

**Business risk:**
Trusting MFA from all external tenants means an attacker controlling a weak tenant can satisfy your MFA requirements using their own weaker authentication — effectively bypassing your Conditional Access policies.

**Remediation:**
Entra ID > External Identities > Cross-tenant access settings > Default settings > Inbound trust. Disable 'Trust MFA from Microsoft Entra tenants' and 'Trust compliant devices' unless specific B2B partner trust is required.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-17, IA-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.3.5 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.23, A.8.22 |
| SOC 2 | CC6.6 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 1.4 |
| MITRE ATT&CK | T1078, T1110 |

---

### AAD-11.7 — Privileged Access Workstation or Device Scope for Admins

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1 + Intune

**Description:**
Conditional Access enforces that privileged role activations or admin operations occur from compliant or specifically designated devices.

**Business risk:**
Admins authenticating from any arbitrary device — including personal laptops with no endpoint controls — expose privileged credentials to malware on unmanaged endpoints.

**Remediation:**
CA policy: Target admin roles > Require compliant device or Hybrid AD join. Alternatively define a named device group as a PAW group and require membership.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-17, CM-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.1.3 |
| CIS Controls v8.1 | 12.8 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.8.2 |
| SOC 2 | CC6.1 |
| HIPAA | §164.308(a)(3)(ii)(A) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-11.8 — Terms of Use Policy Enforced

**Severity:** Low  |  **Category:** Identity  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
A CA policy enforces Terms of Use acceptance for users accessing organizational resources.

**Business risk:**
Without ToU enforcement, there is no documented acknowledgment of acceptable use policy — creating legal and HR gaps, especially for guest users and contractors.

**Remediation:**
Entra ID > Security > Conditional Access > Terms of use > Create ToU document. Add to CA policy: Grant > Require terms of use.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.3.6 |
| CMMC 2.0 | AC.L2-3.1.9 |
| ISO/IEC 27001:2022 | A.5.10 |
| SOC 2 | CC1.4, CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 12.3 |
| MITRE ATT&CK | T1078 |

---

### AAD-11.9 — Workload Identity Conditional Access Policy

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Entra Workload Identities Premium (add-on)

**Description:**
CA policies are applied to service principals and managed identities, not just user accounts.

**Business risk:**
Without CA policies on workload identities, compromised service principals face no access controls — no location restriction, no risk-based blocking, no session limits.

**Remediation:**
CA policy > Users > Select Workload identities > Apply conditions and access controls to high-privilege service principals. Requires Entra Workload Identities Premium add-on.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-3, AC-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.5.2 |
| CIS Controls v8.1 | 6.8, 5.5 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.16, A.8.2 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.6 |
| MITRE ATT&CK | T1078.004, T1550.001 |

---

### AAD-12.1 — Users Without MFA — Named List

**Severity:** Critical  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Identifies every enabled user account with no MFA method registered by name and UPN.

**Business risk:**
Each account without MFA can be compromised with a stolen password alone. A single phished credential gives an attacker full mailbox access, Teams, SharePoint, and the ability to initiate wire transfers or BEC campaigns.

**Remediation:**
Entra ID > Users > [select user] > Authentication methods > Add method. For bulk: Get-MgUser | where MFA not registered → require combined registration via CA policy targeted at these users.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2(1) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.2.1 |
| CIS Controls v8.1 | 6.3 |
| CISA SCuBA | MS.AAD.3.1v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.17, A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.4 |
| MITRE ATT&CK | T1078, T1110 |

---

### AAD-12.2 — Stale Guest Accounts — Named List

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans) — Access Reviews require Entra P2

**Description:**
Identifies guest accounts with no sign-in activity in 90+ days.

**Business risk:**
Stale guest accounts from former vendors, contractors, and partners retain access to SharePoint sites, Teams channels, and any resource they were granted. Ex-partners can exfiltrate data months after their engagement ends.

**Remediation:**
Entra ID > External Identities > All users > Filter by guest, sort by last sign-in. Disable or delete accounts inactive 90+ days. Implement access reviews: PIM > Access reviews > Create review for guest users.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2(3) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.3.4 |
| CIS Controls v8.1 | 5.3 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18, A.6.5 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(C) |
| PCI DSS | Req 8.2.4 |
| MITRE ATT&CK | T1078 |

---

### AAD-12.3 — Stale Licensed Member Accounts — Named List

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Identifies licensed member accounts with no sign-in activity in 90+ days — likely departed employees.

**Business risk:**
Active accounts for departed employees are a primary threat vector. Former employees know the organization's structure, workflows, and email conventions — making them highly effective social engineers if accounts are ever used maliciously.

**Remediation:**
Verify each account represents an active user. Disable accounts for departed employees immediately. Revoke all active sessions. Remove assigned licenses. Review for any recent inbox rules or forwarding.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2(9) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.1.6.1 |
| CIS Controls v8.1 | 5.3 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18, A.6.5 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(C) |
| PCI DSS | Req 8.2.4 |
| MITRE ATT&CK | T1078 |

---

### AAD-12.4 — OAuth Apps with Tenant-Wide Consent — Named List

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Identifies all applications that have been granted OAuth permissions across ALL users (AllPrincipals consent type).

**Business risk:**
Apps with AllPrincipals consent can access every user's mailbox, files, calendar, and identity. Consent phishing campaigns trick admins into granting these permissions to malicious apps. Many legitimate apps accumulate excessive scopes over time.

**Remediation:**
Entra ID > Enterprise applications > All applications > Filter by permissions. Review each AllPrincipals grant. Revoke unnecessary grants: Remove-MgOAuth2PermissionGrant -OAuth2PermissionGrantId <id>.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.5.4 |
| CIS Controls v8.1 | 2.1 |
| CISA SCuBA | MS.AAD.5.2v1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.23, A.8.4 |
| SOC 2 | CC6.3, CC7.2 |
| HIPAA | §164.308(a)(4), §164.308(a)(1)(ii)(D) |
| PCI DSS | Req 6.4.3 |
| MITRE ATT&CK | T1528, T1550.001 |

---

### AAD-13.1 — Microsoft Secure Score

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Microsoft's own assessment of the tenant's security posture across identity, data, apps, and devices.

**Business risk:**
Microsoft Secure Score measures the same controls through Microsoft's lens. A score below 50% indicates fundamental security gaps across the tenant. It is independently verifiable and useful for trend tracking.

**Remediation:**
Review Microsoft Secure Score improvement actions at security.microsoft.com > Secure Score. Prioritize Identity and Email improvement actions first.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CA-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.5.2 |
| CMMC 2.0 | CA.L2-3.12.3 |
| ISO/IEC 27001:2022 | A.5.36 |
| SOC 2 | CC4.1 |
| HIPAA | §164.308(a)(8) |
| PCI DSS | Req 11.6.1 |
| MITRE ATT&CK | T1078 |

### AAD-15.1 — No Application Holds Tenant-Takeover Permissions

**Severity:** Critical  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Verifies that no non-Microsoft application holds an APPLICATION (app-only) permission that confers tenant takeover — for example RoleManagement.ReadWrite.Directory, Application.ReadWrite.All, Domain.ReadWrite.All, or Exchange full_access_as_app.

**Business risk:**
An application permission is exercised with no signed-in user, so no MFA prompt occurs and no Conditional Access policy applies. An app holding one of these can make itself Global Administrator, add a federated domain and forge tokens for any user, or read every mailbox in the tenant. Because the activity carries no user identity it does not resemble a compromised account in the sign-in logs, which is why consent-phished and supply-chain apps use this route for persistence. Delegated-consent reporting cannot see these grants at all.

**Remediation:**
Entra ID > Enterprise applications > select the application > Permissions. Review each application permission and remove any that are not required: Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <spId> -AppRoleAssignmentId <id>. Where the app genuinely needs broad access, scope it down (for Exchange, replace full_access_as_app with an application access policy limiting the app to a mail-enabled security group).

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.5.4 |
| CIS Controls v8.1 | 2.1, 5.4 |
| CMMC 2.0 | AC.L2-3.1.5 |
| MITRE ATT&CK | T1098.001, T1528, T1550.001 |
| ISO/IEC 27001:2022 | A.5.15, A.8.2 |
| SOC 2 | CC6.1, CC6.3 |
| HIPAA | §164.308(a)(4), §164.312(a)(1) |
| PCI DSS v4.0 | Req 7.2.1 |
| CISA SCuBA | MS.AAD.5.2v1 |

---

### AAD-15.2 — Applications with Tenant-Wide Data Permissions — Named List

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Names every non-Microsoft application holding an APPLICATION (app-only) permission that reaches all users' mail, files, sites or chat — for example Mail.ReadWrite, Files.ReadWrite.All, Sites.ReadWrite.All or MailboxSettings.ReadWrite.

**Business risk:**
These permissions read or modify data for every user in the tenant with no signed-in user and no Conditional Access evaluation. MailboxSettings.ReadWrite in particular allows an app to create inbox rules in any mailbox, the usual persistence and exfiltration mechanism after a business email compromise. Grants accumulate silently as integrations are added and are rarely revoked when the integration is retired, so the list tends to grow past anyone's memory of why each one exists.

**Remediation:**
Entra ID > Enterprise applications > All applications > Permissions. For each application permission, record a business owner and a reason, or revoke it: Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <spId> -AppRoleAssignmentId <id>. For Exchange and SharePoint, constrain the app with an application access policy or site-level permission rather than a tenant-wide grant.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 5.5.4 |
| CIS Controls v8.1 | 2.1, 3.3 |
| CMMC 2.0 | AC.L1-3.1.2 |
| MITRE ATT&CK | T1528, T1114.002 |
| ISO/IEC 27001:2022 | A.5.23, A.8.4 |
| SOC 2 | CC6.3, CC7.2 |
| HIPAA | §164.308(a)(4), §164.308(a)(1)(ii)(D) |
| PCI DSS v4.0 | Req 6.4.3 |
| CISA SCuBA | MS.AAD.5.2v1 |

---

### AAD-14.1 — Application Credentials Current and Short-Lived

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (Entra ID Free)

**Description:**
App registration client secrets and certificates are unexpired and issued with a bounded lifetime.

**Business risk:**
A client secret is a standing bearer credential to everything its application can reach. No MFA applies to it, no Conditional Access evaluates it, and no sign-in risk is scored against it. A long-lived secret keeps working for everyone who has ever seen it — a departed administrator, a stale runbook, a CI variable, a chat message — until somebody rotates it, and nothing forces rotation. An expired credential is the other half of the same problem: the fix under outage pressure is a new secret with the longest lifetime available and no reminder set.

**Remediation:**
Entra admin center > App registrations > Certificates and secrets. Remove expired credentials rather than leaving them in place. Reissue anything with a lifetime beyond 180 days at a shorter term and record the rotation date. Prefer certificate credentials or workload identity federation over client secrets where the application supports them.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-5, IA-5(1), AC-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 1.3.4 |
| CIS Controls v8.1 | 5.4, 6.2 |
| CMMC 2.0 | IA.L2-3.5.10, AC.L1-3.1.1 |
| MITRE ATT&CK | T1078.004, T1550.001, T1098.001 |
| ISO/IEC 27001:2022 | A.5.17 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS v4.0 | Req 8.3 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

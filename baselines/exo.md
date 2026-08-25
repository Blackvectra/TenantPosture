# Exchange Online Baseline

**NRG-Assessment — Baseline Documentation**
*Product: Exchange Online*

---

## Introduction

This baseline lists the 31 Exchange Online controls evaluated by NRG-Assessment. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 2 Critical · 18 High · 11 Medium

---

## Controls

### EXO-1.1 — Mailbox Audit Logging Enabled

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Organization-level mailbox audit logging is enabled and not disabled at the tenant or per-mailbox level.

**Business risk:**
Without mailbox auditing, there is no record of who accessed, sent, or deleted emails. BEC and data exfiltration investigation is impossible.

**Remediation:**
Set-OrganizationConfig -AuditDisabled $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.1 |
| CIS Controls v8.1 | 8.2, 8.5 |
| CISA SCuBA | MS.EXO.13.1v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.2 |
| MITRE ATT&CK | T1114, T1070.008 |

---

### EXO-1.2 — SMTP Client Authentication Disabled

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
SMTP AUTH is disabled at the tenant level with no per-mailbox exceptions.

**Business risk:**
SMTP AUTH accepts passwords directly. Compromised accounts with SMTP AUTH enabled can send email without MFA, enabling BEC campaigns.

**Remediation:**
Set-TransportConfig -SmtpClientAuthenticationDisabled $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-8, IA-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.4 |
| CIS Controls v8.1 | 4.8 |
| CISA SCuBA | MS.EXO.5.1v1 |
| CMMC 2.0 | SC.L2-3.13.8 |
| ISO/IEC 27001:2022 | A.8.24 |
| SOC 2 | CC6.7, CC6.1 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 4.2.1 |
| MITRE ATT&CK | T1078, T1114.002 |

---

### EXO-1.3 — External Auto-Forwarding Blocked

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Outbound spam policy blocks automatic forwarding to external recipients. Remote domain wildcard has AutoForwardEnabled = false.

**Business risk:**
Compromised accounts set forwarding rules to exfiltrate all email to attacker addresses. Without this control, BEC exfiltration runs indefinitely.

**Remediation:**
Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off. Set-RemoteDomain -Identity Default -AutoForwardEnabled $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-7, SI-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.2 |
| CIS Controls v8.1 | 3.13 |
| CISA SCuBA | MS.EXO.1.1v2 |
| CMMC 2.0 | SC.L1-3.13.1 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1), §164.402 |
| PCI DSS | Req 3.4, Req 4.2 |
| MITRE ATT&CK | T1114.003 |

---

### EXO-1.4 — DKIM Signing Enabled for All Domains

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
DKIM signing is enabled for all accepted domains with 2048-bit keys on selector1 and selector2.

**Business risk:**
Without DKIM, email cannot be cryptographically verified and messages can be modified in transit without detection.

**Remediation:**
Enable-DkimSigningConfig -Identity domain.com. Publish the CNAME records from M365 admin center.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-8, SC-13 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.1 |
| CIS Controls v8.1 | 9.5 |
| CISA SCuBA | MS.EXO.3.1v1 |
| CMMC 2.0 | SC.L2-3.13.8 |
| ISO/IEC 27001:2022 | A.8.23, A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(i) |
| PCI DSS | Req 4.2 |
| MITRE ATT&CK | T1566, T1036.005 |

---

### EXO-1.5 — Anti-Phishing Impersonation Protection Enabled

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Default anti-phishing policy has user impersonation, organization domain protection, mailbox intelligence, and external sender tagging all enabled.

**Business risk:**
Impersonation attacks are the primary BEC vector. Without protection, lookalike domains and display name spoofs reach inboxes undetected.

**Remediation:**
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableTargetedUserProtection $true -EnableOrganizationDomainsProtection $true -EnableMailboxIntelligence $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3, SI-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.7 |
| CIS Controls v8.1 | 9.7, 10.1 |
| CISA SCuBA | MS.DEFENDER.2.1v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7, A.8.23 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566.001, T1598.003 |

---

### EXO-1.6 — Modern Authentication Enabled

**Severity:** Critical  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Modern authentication (OAuth2) is enabled for Exchange Online.

**Business risk:**
Disabling modern auth forces basic authentication, making MFA ineffective for email clients and bypassing Conditional Access.

**Remediation:**
Set-OrganizationConfig -OAuth2ClientProfileEnabled $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2, SC-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.5 |
| CIS Controls v8.1 | 9.1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.17 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.3 |
| MITRE ATT&CK | T1078, T1110 |

---

### EXO-1.7 — Honor DMARC Policy Enabled

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Anti-phishing policy honors the DMARC policy of sending domains, applying reject or quarantine as specified.

**Business risk:**
Without this setting, EXO ignores p=reject DMARC records from legitimate senders, accepting spoofed email from well-protected domains.

**Remediation:**
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -HonorDmarcPolicy $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.7 |
| CIS Controls v8.1 | 9.5 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.23 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(i) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566, T1036.005 |

---

### EXO-2.3 — POP3 Access Disabled

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
POP3 is disabled at the tenant level. POP3 uses basic authentication and cannot be protected by MFA.

**Business risk:**
POP3 allows credential-based email access that bypasses MFA and Conditional Access.

**Remediation:**
Disable for newly licensed mailboxes: Get-CASMailboxPlan -Filter {PopEnabled -eq $true} | Set-CASMailboxPlan -PopEnabled $false. Disable for existing mailboxes: Get-CASMailbox -ResultSize Unlimited | Set-CASMailbox -PopEnabled $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-8, IA-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.6 |
| CIS Controls v8.1 | 4.8 |
| CMMC 2.0 | SC.L2-3.13.8 |
| ISO/IEC 27001:2022 | A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(ii) |
| PCI DSS | Req 4.2.1 |
| MITRE ATT&CK | T1078, T1110 |

---

### EXO-2.4 — IMAP Access Disabled

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
IMAP is disabled at the tenant level. IMAP uses basic authentication and cannot be protected by MFA.

**Business risk:**
IMAP allows credential-based email access bypassing MFA and CA policies.

**Remediation:**
Disable for newly licensed mailboxes: Get-CASMailboxPlan -Filter {ImapEnabled -eq $true} | Set-CASMailboxPlan -ImapEnabled $false. Disable for existing mailboxes: Get-CASMailbox -ResultSize Unlimited | Set-CASMailbox -ImapEnabled $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-8, IA-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.6 |
| CIS Controls v8.1 | 4.8 |
| CMMC 2.0 | SC.L2-3.13.8 |
| ISO/IEC 27001:2022 | A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(ii) |
| PCI DSS | Req 4.2.1 |
| MITRE ATT&CK | T1078, T1110 |

---

### EXO-2.5 — Customer Lockbox Enabled

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 E5 or E5 Compliance add-on

**Description:**
Customer Lockbox requires explicit admin approval before Microsoft support can access tenant data.

**Business risk:**
Without Customer Lockbox, Microsoft support can access tenant data without notification or approval during support cases.

**Remediation:**
Enable in M365 admin center > Settings > Security & privacy > Customer Lockbox. Requires E5 or E5 Compliance add-on.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, PE-18 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 1.3.6 |
| CIS Controls v8.1 | 3.3 |
| CMMC 2.0 | PE.L1-3.10.1 |
| ISO/IEC 27001:2022 | A.5.23, A.8.16 |
| SOC 2 | CC6.1, CC6.6 |
| HIPAA | §164.308(a)(4)(ii)(A), §164.312(b) |
| PCI DSS | Req 7.2.5 |
| MITRE ATT&CK | T1078.004 |

---

### EXO-2.6 — Shared Mailboxes Block Direct Sign-In

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Shared mailbox accounts are blocked from direct sign-in (no active user account associated).

**Business risk:**
Shared mailboxes with active accounts can be signed into directly with a password, bypassing MFA. Attackers target shared mailboxes for persistence.

**Remediation:**
Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails SharedMailbox | ForEach-Object { Update-MgUser -UserId $_.ExternalDirectoryObjectId -AccountEnabled:$false }

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2, IA-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 1.1.3 |
| CIS Controls v8.1 | 5.3 |
| CMMC 2.0 | AC.L1-3.1.1 |
| ISO/IEC 27001:2022 | A.5.16, A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(2)(i) |
| PCI DSS | Req 8.2.1 |
| MITRE ATT&CK | T1078, T1098 |

---

### EXO-3.1 — Connection Filter Safe List Bypass Disabled

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Microsoft safe list bypass is disabled on the default connection filter policy.

**Business risk:**
Safe list bypass allows senders on Microsoft-maintained lists to skip all EOP filtering — third-party senders can exploit this.

**Remediation:**
Set-HostedConnectionFilterPolicy -Identity Default -EnableSafeList $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.13 |
| CIS Controls v8.1 | 9.7 |
| CMMC 2.0 | SI.L2-3.14.7 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566 |

---

### EXO-3.2 — Outbound Spam Sending Limits Configured

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Outbound spam policy is configured with appropriate per-user sending limits and admin notification.

**Business risk:**
Compromised accounts can send mass phishing without rate limiting. Limits and alerts provide early BEC detection.

**Remediation:**
Set-HostedOutboundSpamFilterPolicy: configure RecipientLimitInternalPerHour, RecipientLimitExternalPerHour, ActionWhenThresholdReached = Alert.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.14 |
| CIS Controls v8.1 | 9.7 |
| CMMC 2.0 | SI.L2-3.14.7 |
| ISO/IEC 27001:2022 | A.8.7, A.8.16 |
| SOC 2 | CC6.8, CC7.2 |
| HIPAA | §164.308(a)(5)(ii)(B), §164.402 |
| PCI DSS | Req 5.4 |
| MITRE ATT&CK | T1078, T1114.003 |

---

### EXO-3.3 — Alert Policy — Email Forwarding Rules

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
An alert policy notifies admins when new email forwarding rules are created.

**Business risk:**
Forwarding rules are the primary BEC persistence mechanism. Without alerts, silent exfiltration continues indefinitely.

**Remediation:**
Defender portal > Policies > Alert policies > Enable: Email forwarding activities.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-12, SI-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.15 |
| CIS Controls v8.1 | 8.11, 13.1 |
| CISA SCuBA | MS.DEFENDER.5.1v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.16 |
| SOC 2 | CC7.2, CC7.3 |
| HIPAA | §164.308(a)(1)(ii)(D), §164.308(a)(6) |
| PCI DSS | Req 10.7 |
| MITRE ATT&CK | T1114.003 |

---

### EXO-3.4 — Alert Policy — Unusual Mail Volume

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
An alert policy detects unusual increases in email reported as phish by users.

**Business risk:**
Volume spikes indicate active phishing campaigns. Without alerts, campaigns run until users complain.

**Remediation:**
Defender portal > Policies > Alert policies > Enable: Unusual increase in email reported as phish.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-4, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.16 |
| CIS Controls v8.1 | 13.1, 8.11 |
| CISA SCuBA | MS.DEFENDER.5.1v1 |
| CMMC 2.0 | SI.L2-3.14.6 |
| ISO/IEC 27001:2022 | A.8.16 |
| SOC 2 | CC7.2, CC7.3 |
| HIPAA | §164.308(a)(1)(ii)(D), §164.308(a)(6) |
| PCI DSS | Req 10.7 |
| MITRE ATT&CK | T1566 |

---

### EXO-3.5 — Transport Rules Changes Audited

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Organization-level audit logging captures transport rule creation and modification.

**Business risk:**
Attackers create transport rules to reroute or intercept mail. Without audit logs, rule changes are invisible.

**Remediation:**
Set-OrganizationConfig -AuditDisabled $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.1 |
| CIS Controls v8.1 | 8.2, 8.5 |
| CISA SCuBA | MS.DEFENDER.6.1v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15, A.8.32 |
| SOC 2 | CC7.2, CC8.1 |
| HIPAA | §164.312(b), §164.308(a)(1)(ii)(D) |
| PCI DSS | Req 10.2, Req 6.5.3 |
| MITRE ATT&CK | T1114, T1070.008 |

---

### EXO-4.1 — Mailbox Audit Log Age Limit Sufficient

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Mailbox audit log retention is set to at least 90 days (180 days recommended).

**Business risk:**
Short audit retention prevents investigation of incidents discovered after the retention window closes. 90 days is the absolute minimum for most IR scenarios.

**Remediation:**
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditLogAgeLimit 180

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-11 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.3 |
| CIS Controls v8.1 | 8.10 |
| CISA SCuBA | MS.DEFENDER.6.3v1 |
| CMMC 2.0 | AU.L2-3.3.2 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2, A1.2 |
| HIPAA | §164.312(b), §164.316(b)(2)(i) |
| PCI DSS | Req 10.5 |
| MITRE ATT&CK | T1070.008 |

---

### EXO-4.2 — Admin Audit Log Enabled

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Exchange admin audit logging captures all cmdlet execution by administrators.

**Business risk:**
Without admin audit logs, malicious or accidental admin changes (transport rules, forwarding, policy changes) are not recorded.

**Remediation:**
Set-AdminAuditLogConfig -AdminAuditLogEnabled $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.1 |
| CIS Controls v8.1 | 8.2, 8.5 |
| CISA SCuBA | MS.DEFENDER.6.1v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15, A.8.18 |
| SOC 2 | CC7.2, CC8.1 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.2 |
| MITRE ATT&CK | T1070.008 |

---

### EXO-4.3 — Safe Attachments for SharePoint OneDrive Teams Enabled

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Safe Attachments ATP protection is enabled globally for SharePoint, OneDrive, and Teams file scanning.

**Business risk:**
Without this setting, malicious files uploaded to SharePoint/OD/Teams are not sandboxed. Files can be shared across the tenant before detection.

**Remediation:**
Defender portal > Policies > Safe Attachments > Global settings > Enable Defender for Office 365 for SharePoint, OneDrive, and Teams.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.3.4 |
| CIS Controls v8.1 | 9.7, 10.1 |
| CISA SCuBA | MS.DEFENDER.1.1v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.2 |
| MITRE ATT&CK | T1566.001, T1204.002 |

---

### EXO-4.4 — Anti-Spam Inbound Policy Properly Configured

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Default inbound anti-spam policy has appropriate action settings for spam, phish, and bulk mail.

**Business risk:**
Misconfigured inbound anti-spam allows higher volumes of spam and phishing to reach user inboxes.

**Remediation:**
Set-HostedContentFilterPolicy -Identity Default -SpamAction MoveToJmf -BulkThreshold 6 -ZapEnabled $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.7 |
| CIS Controls v8.1 | 9.7 |
| CISA SCuBA | MS.DEFENDER.1.2v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4 |
| MITRE ATT&CK | T1566 |

---

### EXO-5.1 — Per-User Mailbox Audit Logging Enabled for All Mailboxes

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
AuditEnabled is set to $true on all mailboxes — no mailboxes have audit logging explicitly disabled.

**Business risk:**
Mailboxes without audit logging cannot be investigated after a BEC incident. Inbox rules, delegation grants, and mail access are not recorded for unaudited mailboxes.

**Remediation:**
Get-Mailbox -ResultSize Unlimited | Where-Object { $_.AuditEnabled -eq $false } | Set-Mailbox -AuditEnabled $true.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.2 |
| CIS Controls v8.1 | 8.2, 8.5 |
| CISA SCuBA | MS.EXO.13.1v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.2 |
| MITRE ATT&CK | T1114, T1070.008 |

---

### EXO-5.2 — Priority Account Protection Active in Anti-Phishing Policy

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Defender for Office 365 Plan 1 (M365 Business Premium)

**Description:**
Tagged priority accounts are explicitly protected by targeted user impersonation protection in Defender anti-phishing policy.

**Business risk:**
Priority accounts are the highest-value BEC targets. Without explicit impersonation protection, spoofed executive emails are handled the same as general spam.

**Remediation:**
Set-AntiPhishPolicy > TargetedUsersToProtect — add executive UPNs. Enable EnableTargetedUserProtection.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.6 |
| CIS Controls v8.1 | 9.7, 10.1 |
| CISA SCuBA | MS.DEFENDER.2.1v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.2 |
| SOC 2 | CC6.1 |
| HIPAA | §164.308(a)(5)(ii)(A) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1566, T1036.005 |

---

### EXO-5.3 — No Allowed Sender Domains Bypassing Anti-Spam Filtering

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
The anti-spam policy contains no allowed sender domains that would cause all mail from those domains to bypass EOP filtering.

**Business risk:**
Allowed sender domains are one of the most common misconfigurations in M365. If a permitted domain is compromised, all mail from it bypasses spam and malware filtering entirely.

**Remediation:**
Set-HostedContentFilterPolicy -Identity Default -AllowedSenderDomains @() — remove all allowed sender domains. Use mail flow rules for legitimate trusted partner exemptions with scoped conditions instead.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.13 |
| CIS Controls v8.1 | 9.7 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566 |

---

### EXO-6.1 — Mailboxes with External Email Forwarding — Named List

**Severity:** Critical  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Identifies every mailbox with a ForwardingSmtpAddress set to an external domain.

**Business risk:**
External email forwarding is the #1 BEC persistence technique. An attacker who compromises a mailbox sets forwarding to maintain access even after a password reset. Forwarding to a personal account also creates an unauthorized data copy outside organizational control.

**Remediation:**
For each listed mailbox: verify the forwarding is intentional and business-justified. Remove unauthorized: Set-Mailbox -Identity <upn> -ForwardingSmtpAddress $null. Also set transport rule to block auto-forward and create an alert policy for new forwarding rules.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.2 |
| CIS Controls v8.1 | 3.13, 8.11 |
| CISA SCuBA | MS.EXO.1.1v2 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1), §164.402 |
| PCI DSS | Req 3.4, Req 4.2 |
| MITRE ATT&CK | T1114.003 |

---

### EXO-6.2 — Shared Mailboxes with Sign-In Enabled — Named List

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Identifies shared mailboxes where the associated user account has interactive sign-in enabled.

**Business risk:**
Shared mailboxes are designed to be accessed via delegation, not direct login. An enabled shared mailbox account bypasses the per-user MFA requirement — it's a permanent backdoor into email with no authentication strength requirement.

**Remediation:**
Update-MgUser -UserId <guid> -AccountEnabled:$false for each shared mailbox account. Or in M365 Admin: Active users > select user > Block sign-in. Verify delegates can still access via Outlook.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-5 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.5 |
| CIS Controls v8.1 | 5.3 |
| CMMC 2.0 | IA.L1-3.5.1 |
| ISO/IEC 27001:2022 | A.5.16 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(2)(i) |
| PCI DSS | Req 8.2.1 |
| MITRE ATT&CK | T1078 |

---

### EXO-6.3 — Mailboxes with Audit Logging Disabled — Named List

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Identifies mailboxes with AuditEnabled explicitly set to $false.

**Business risk:**
A compromised mailbox with audit disabled cannot be investigated. After a BEC incident, forensics cannot determine what emails were read, what rules were created, who accessed the mailbox, or when the compromise began.

**Remediation:**
Get-Mailbox -ResultSize Unlimited | Where-Object { $_.AuditEnabled -eq $false } | Set-Mailbox -AuditEnabled $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.3 |
| CIS Controls v8.1 | 8.2, 8.5 |
| CISA SCuBA | MS.EXO.13.1v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.2 |
| MITRE ATT&CK | T1114, T1070.008 |

---

### EXO-6.4 — Per-User SMTP AUTH Override — Named List

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Identifies users with individual SMTP AUTH enabled, bypassing the org-level SMTP AUTH disable.

**Business risk:**
SMTP AUTH does not support MFA. Users with per-user SMTP AUTH enabled can authenticate to Exchange via legacy protocols with just a password — bypassing all Conditional Access policies and MFA requirements.

**Remediation:**
For each listed user: Set-CASMailbox -Identity <upn> -SmtpClientAuthenticationDisabled $true. If SMTP AUTH is required (printer, scanner, legacy app) use a dedicated service account with a strong password and IP restriction.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.1 |
| CIS Controls v8.1 | 4.8 |
| CISA SCuBA | MS.EXO.5.1v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 4.2.1 |
| MITRE ATT&CK | T1078, T1110 |

---

### EXO-7.1 — No Mailbox Forwarding to External Addresses

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
No mailboxes have a ForwardingSmtpAddress configured to an external recipient. Server-side mailbox forwarding is a common BEC persistence channel that silently exfiltrates all inbound mail.

**Business risk:**
ForwardingSmtpAddress is set at the mailbox level and survives password resets and license changes. Attackers who compromise a single mailbox use it to maintain visibility into the victim's mail after the initial intrusion is contained. It is also a common insider exfil vector for departing employees.

**Remediation:**
Get-Mailbox -ResultSize Unlimited -Filter "ForwardingSmtpAddress -ne `$null" | Set-Mailbox -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false. Also block at transport layer: Set-RemoteDomain Default -AutoForwardEnabled $false.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-6, IR-4, SI-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 6.2.1 |
| CIS Controls v8.1 | 3.13, 8.11 |
| CISA SCuBA | MS.EXO.1.1v2 |
| CMMC 2.0 | AU.L2-3.3.5, IR.L2-3.6.1, SI.L2-3.14.6 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1), §164.402 |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1114.003 |

---

### EXO-7.2 — No Inbox Rules Forwarding Externally

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
No mailbox inbox rules use ForwardTo, RedirectTo, or ForwardAsAttachmentTo to deliver mail to external recipients. Inbox rules are the classic post-credential-compromise persistence channel (MITRE T1114.003).

**Business risk:**
Inbox rules created by an attacker after credential compromise will quietly forward mail of interest (finance, executives, password resets) to an attacker-controlled address. They bypass ForwardingSmtpAddress monitoring and survive sign-in revocation if the rule was created before the revoke.

**Remediation:**
Audit: foreach ($m in Get-Mailbox -ResultSize Unlimited) { Get-InboxRule -Mailbox $m.UserPrincipalName | Where-Object { $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo } }. Disable: Disable-InboxRule -Mailbox <UPN> -Identity <RuleName>. Block at transport: Set-RemoteDomain Default -AutoForwardEnabled $false.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-6, IR-4, SI-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 6.2.1 |
| CIS Controls v8.1 | 3.13, 8.11 |
| CISA SCuBA | MS.EXO.1.1v2 |
| CMMC 2.0 | AU.L2-3.3.5, IR.L2-3.6.1, SI.L2-3.14.6 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1), §164.402 |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1114.003 |

---

### EXO-7.3 — No Mailboxes with Per-User Audit Explicitly Disabled

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
No mailboxes have AuditEnabled = $false set explicitly. As of January 2019, mailbox audit is on by default org-wide; explicit per-user disable is a deliberate override and almost always wrong.

**Business risk:**
Mailboxes with audit explicitly disabled cannot be investigated after a compromise. Inbox-rule creation, mail access by delegates, and sent-item modification are not captured for the disabled mailbox — a deliberate or accidental blind spot that thwarts incident response.

**Remediation:**
Get-Mailbox -ResultSize Unlimited | Where-Object { $_.AuditEnabled -eq $false } | Set-Mailbox -AuditEnabled $true. For a single mailbox: Set-Mailbox -Identity <UPN> -AuditEnabled $true.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, AU-3, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.2 |
| CIS Controls v8.1 | 8.2, 8.5 |
| CISA SCuBA | MS.EXO.13.1v1 |
| CMMC 2.0 | AU.L2-3.3.1, AU.L2-3.3.2 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.2 |
| MITRE ATT&CK | T1070.008 |

---

### EXO-7.4 — No Per-User SMTP AUTH Overrides

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
No mailboxes have SmtpClientAuthenticationDisabled = $false set at the mailbox level. Per-user overrides bypass the tenant-level SMTP AUTH disable and re-enable basic authentication for that mailbox.

**Business risk:**
Per-user SMTP AUTH exceptions re-enable basic auth for the affected mailboxes — bypassing MFA and Conditional Access. They are a classic password-spray and credential-stuffing target, and they are usually granted ad-hoc for legacy scanners or line-of-business apps and then forgotten.

**Remediation:**
For each affected mailbox: Set-CASMailbox -Identity <UPN> -SmtpClientAuthenticationDisabled $true. Migrate senders to OAuth-based SMTP (Microsoft Graph sendMail API) or App Passwords with MFA. For multifunction devices/scanners, prefer SMTP relay via on-prem connector with IP allowlist, or Direct Send (anonymous) — neither requires basic auth.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2, SC-8, SI-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 6.2.2 |
| CIS Controls v8.1 | 4.8 |
| CISA SCuBA | MS.EXO.5.1v1 |
| CMMC 2.0 | IA.L2-3.5.3, SC.L2-3.13.8, SI.L2-3.14.6 |
| ISO/IEC 27001:2022 | A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 4.2.1 |
| MITRE ATT&CK | T1110.003, T1078 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

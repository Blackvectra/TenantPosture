# Microsoft Defender for Office 365 Baseline

**NRG-Assessment — Baseline Documentation**
*Product: Microsoft Defender for Office 365*

---

## Introduction

This baseline lists the 23 Microsoft Defender for Office 365 controls evaluated by NRG-Assessment. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 13 High · 4 Medium · 6 Low

---

## Controls

### DEF-1.1 — Safe Attachments Enabled with Block Action

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Defender for Office 365 Plan 1 (M365 Business Premium)

**Description:**
Defender for Office 365 Safe Attachments policies are enabled with action = Block.

**Business risk:**
Without Safe Attachments, weaponized Office docs and PDFs with exploits are delivered to inboxes without sandbox analysis.

**Remediation:**
Defender portal > Policies > Safe Attachments > Create policy for all recipients with Action = Block. Requires Defender for Office 365 Plan 1.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.3.1 |
| CIS Controls v8.1 | 9.7, 10.7 |
| CISA SCuBA | MS.DEFENDER.1.1v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.2 |
| MITRE ATT&CK | T1566.001, T1204.002 |

---

### DEF-1.2 — Safe Links Enabled and Hardened

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Defender for Office 365 Plan 1 (M365 Business Premium)

**Description:**
Safe Links enabled for email with AllowClickThrough=$false, TrackClicks=$true, EnableForInternalSenders=$true.

**Business risk:**
Without Safe Links, time-of-click URL swapping bypasses pre-delivery scanning.

**Remediation:**
Create Safe Links policy with AllowClickThrough=$false, TrackClicks=$true, EnableForInternalSenders=$true. Requires Defender for Office 365 Plan 1.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.3.2 |
| CIS Controls v8.1 | 9.3 |
| CISA SCuBA | MS.DEFENDER.1.3v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.2 |
| MITRE ATT&CK | T1566.002, T1204.001 |

---

### DEF-1.3 — Spoof Intelligence Enabled

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
Anti-phishing policy has spoof intelligence enabled.

**Business risk:**
Without spoof intelligence, spoofed senders that fail SPF/DKIM pass without evaluation.

**Remediation:**
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableSpoofIntelligence $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8, SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.7 |
| CIS Controls v8.1 | 9.7 |
| CISA SCuBA | MS.DEFENDER.1.3v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.23 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(i) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566, T1036.005 |

---

### DEF-1.4 — Honor DMARC Policy (Defender Layer)

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
Anti-phishing policy honors DMARC policy of sending domains.

**Business risk:**
Without this, EXO delivers email from p=reject domains, undermining the global DMARC ecosystem.

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

### DEF-1.5 — Phishing Threshold Level Aggressive

**Severity:** Low  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
Anti-phishing PhishThresholdLevel is set to 2 (Aggressive) or higher.

**Business risk:**
Standard threshold misses sophisticated phishing that aggressive scanning catches.

**Remediation:**
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -PhishThresholdLevel 2

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3, SI-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.7 |
| CIS Controls v8.1 | 9.7 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7, A.8.23 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566 |

---

### DEF-1.6 — First Contact Safety Tip Enabled

**Severity:** Low  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
Anti-phishing shows a safety tip when users receive email from a first-time sender.

**Business risk:**
First contact attacks rely on users not recognizing unfamiliar senders.

**Remediation:**
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableFirstContactSafetyTips $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.7 |
| CIS Controls v8.1 | 9.7 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566.001 |

---

### DEF-2.1 — Preset Security Policies Applied

**Severity:** Low  |  **Category:** Email  |  **Automated:** Yes

**License required:** Defender for Office 365 Plan 1 (M365 Business Premium)

**Description:**
Microsoft Standard or Strict preset security policy is active, providing baseline Defender configuration.

**Business risk:**
Custom-only configurations may miss settings covered by preset policies. Presets provide Microsoft-recommended defaults as a starting floor.

**Remediation:**
Defender portal > Email & Collaboration > Policies > Preset security policies > Apply Standard or Strict protection.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.3.3 |
| CIS Controls v8.1 | 4.1 |
| CISA SCuBA | MS.DEFENDER.1.1v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.9 |
| SOC 2 | CC8.1 |
| HIPAA | §164.308(a)(8) |
| PCI DSS | Req 2.2 |
| MITRE ATT&CK | T1566 |

---

### DEF-2.2 — Zero-Hour Auto Purge Enabled

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
ZAP retroactively removes malicious mail from user mailboxes after delivery when new threat intelligence identifies it.

**Business risk:**
Without ZAP, malware or phishing delivered before a signature update is never cleaned up from inboxes.

**Remediation:**
Set-HostedContentFilterPolicy -ZapEnabled $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.8 |
| CIS Controls v8.1 | 9.7, 10.7 |
| CISA SCuBA | MS.DEFENDER.1.2v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4.2 |
| MITRE ATT&CK | T1566 |

---

### DEF-2.3 — Anti-Malware Common Attachments Blocked

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
Common attachment type filter blocks high-risk file extensions regardless of content scan result.

**Business risk:**
Signature-based scanning can be evaded. Blocking .exe, .js, .vbs, .ps1 by extension provides defense-in-depth.

**Remediation:**
Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.9 |
| CIS Controls v8.1 | 9.6 |
| CISA SCuBA | MS.EXO.9.1v2 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.2 |
| MITRE ATT&CK | T1566.001, T1204.002 |

---

### DEF-2.4 — Phishing Directed to Quarantine Not Junk

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
Phishing spam action is Quarantine — not MoveToJmf (junk folder). Quarantined mail is admin-managed.

**Business risk:**
Phishing in junk folders can still be accessed and clicked by users. Quarantine prevents all interaction.

**Remediation:**
Set-HostedContentFilterPolicy -PhishSpamAction Quarantine

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.10 |
| CIS Controls v8.1 | 9.7 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4.2 |
| MITRE ATT&CK | T1566 |

---

### DEF-2.5 — High Confidence Spam to Quarantine

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
High confidence spam action is Quarantine.

**Business risk:**
High-confidence spam in junk remains accessible. Quarantine requires admin review before release.

**Remediation:**
Set-HostedContentFilterPolicy -HighConfidenceSpamAction Quarantine

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.11 |
| CIS Controls v8.1 | 9.7 |
| CISA SCuBA | MS.DEFENDER.1.1v1 |
| CMMC 2.0 | SI.L2-3.14.7 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4.2 |
| MITRE ATT&CK | T1566 |

---

### DEF-2.6 — Bulk Mail Threshold Configured

**Severity:** Low  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
Bulk complaint level threshold is set to 6 or lower for improved bulk mail filtering.

**Business risk:**
Default threshold (7) allows significant bulk/graymail through. Lower values reduce phishing that hides in bulk campaigns.

**Remediation:**
Set-HostedContentFilterPolicy -BulkThreshold 6

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.12 |
| CIS Controls v8.1 | 9.7 |
| CISA SCuBA | MS.DEFENDER.1.1v1 |
| CMMC 2.0 | SI.L2-3.14.7 |
| ISO/IEC 27001:2022 | A.8.23 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566 |

---

### DEF-3.1 — Unauthenticated Sender Indicator Enabled

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
Anti-phishing policy shows a ? indicator in Outlook when sender cannot be authenticated via SPF or DKIM.

**Business risk:**
Without the unauth indicator, users cannot visually distinguish spoofed from legitimate email in Outlook. No visual friction for display name attacks.

**Remediation:**
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableUnauthenticatedSender $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.7 |
| CIS Controls v8.1 | 9.7 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.23 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(i) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566, T1036.005 |

---

### DEF-3.2 — Via Tag Enabled in Anti-Phishing Policy

**Severity:** Low  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
Anti-phishing policy shows the via tag when a sender uses a relay service.

**Business risk:**
Relay-based spoofing is harder to detect without the via tag — attackers use legitimate relays to send spoofed email that passes SPF.

**Remediation:**
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableViaTag $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.7 |
| CIS Controls v8.1 | 9.7 |
| CMMC 2.0 | SI.L2-3.14.7 |
| ISO/IEC 27001:2022 | A.8.23 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(i) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566, T1036.005 |

---

### DEF-3.3 — Defender for Cloud Apps Connected

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Microsoft Defender for Cloud Apps (M365 E5 or add-on)

**Description:**
Microsoft Defender for Cloud Apps M365 connector is active for shadow IT discovery and session controls.

**Business risk:**
Without MDCA, OAuth app abuse, shadow IT cloud usage, and anomalous user behavior in cloud apps go undetected.

**Remediation:**
Defender XDR > Settings > Cloud Apps > Connected apps > Office 365 > Connect.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.4.1 |
| CIS Controls v8.1 | 13.1 |
| CMMC 2.0 | SI.L2-3.14.7 |
| ISO/IEC 27001:2022 | A.5.23, A.8.16 |
| SOC 2 | CC7.2, CC6.6 |
| HIPAA | §164.308(a)(1)(ii)(D), §164.312(b) |
| PCI DSS | Req 10.4, Req 11.5 |
| MITRE ATT&CK | T1528, T1078 |

---

### DEF-3.4 — Defender Alert Email Notifications Configured

**Severity:** High  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Security team receives email notifications for high and critical Defender alerts.

**Business risk:**
Without email notification, Defender alerts only surface if someone actively checks the portal. Critical incidents go undetected until manual review.

**Remediation:**
Defender portal > Settings > Email notifications > Create notification rule for High and Critical severity alerts.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IR-6, AU-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.1.3 |
| CIS Controls v8.1 | 13.1, 8.11 |
| CISA SCuBA | MS.DEFENDER.5.2v1 |
| CMMC 2.0 | IR.L2-3.6.1 |
| ISO/IEC 27001:2022 | A.5.24, A.6.8 |
| SOC 2 | CC7.3, CC7.4 |
| HIPAA | §164.308(a)(6) |
| PCI DSS | Req 12.10.1 |
| MITRE ATT&CK | T1562.008 |

---

### DEF-4.1 — DLP Policy Covers All Key Workloads

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
DLP policies are active for Exchange, SharePoint, OneDrive, and Teams simultaneously.

**Business risk:**
DLP covering only email allows the same sensitive data to be shared freely via Teams or uploaded to SharePoint. Attackers and departing employees exploit uncovered channels.

**Remediation:**
Purview > DLP > Create or edit policy > Choose where to apply > Enable Exchange, SharePoint, OneDrive, Teams, Devices simultaneously.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28, AC-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.3.4 |
| CIS Controls v8.1 | 3.13 |
| CISA SCuBA | MS.DEFENDER.4.2v1 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1048, T1567 |

---

### DEF-4.2 — DLP Policy Uses Sensitive Information Types

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
At least one DLP policy uses sensitive information types (SSN, credit card, health data) for automatic content detection.

**Business risk:**
DLP without SITs cannot automatically identify regulated or sensitive content. Policy enforcement is entirely manual and depends on users correctly classifying their own files.

**Remediation:**
Purview > DLP > Edit policy > Add condition > Content contains > Sensitive info types.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.3.5 |
| CIS Controls v8.1 | 3.13 |
| CISA SCuBA | MS.DEFENDER.4.1v2 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1005, T1048 |

---

### DEF-4.3 — Risky OAuth Application Alerts Configured

**Severity:** High  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Microsoft Defender for Cloud Apps (M365 E5 or add-on)

**Description:**
Alerts are configured for high-privilege OAuth consent grants and risky application behavior.

**Business risk:**
Consent phishing grants attacker-controlled apps persistent access. Without alerts, malicious OAuth grants go undetected until the app is used for data theft.

**Remediation:**
Defender XDR > Cloud Apps > Policies > OAuth app policies. Create policy: App = apps with high privileges, consented by users. Requires Microsoft Defender for Cloud Apps.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-4, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.4.2 |
| CIS Controls v8.1 | 13.1 |
| CISA SCuBA | MS.DEFENDER.5.1v1 |
| CMMC 2.0 | SI.L2-3.14.7 |
| ISO/IEC 27001:2022 | A.5.23, A.6.8 |
| SOC 2 | CC7.2, CC7.3 |
| HIPAA | §164.308(a)(6) |
| PCI DSS | Req 6.4.3 |
| MITRE ATT&CK | T1528, T1550.001 |

---

### DEF-4.4 — Priority Accounts Tagged in Defender

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Defender for Office 365 Plan 2 (M365 E5 or add-on)

**Description:**
Executives and IT admins are tagged as priority accounts in Defender for Office 365 for enhanced protection and differentiated alerts.

**Business risk:**
Priority accounts are disproportionately targeted by BEC, spear phishing, and executive impersonation. Untagged, they receive the same protection as any general user account.

**Remediation:**
Defender portal > Settings > Email & collaboration > User tags > Global Settings > Priority account protection. Tag executives and admins as priority accounts.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3, IR-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.3.5 |
| CISA SCuBA | MS.DEFENDER.2.1v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.2 |
| SOC 2 | CC6.1 |
| HIPAA | Not cited: no Security Rule specification matches what this control checks (docs/HIPAA-CITATION-CORRECTIONS.md) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1566, T1078 |

---

### DEF-4.5 — Endpoint DLP Policy Active on Managed Devices

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 E5 or E5 Compliance add-on

**Description:**
Endpoint DLP policies monitor or block sensitive data actions on Windows endpoints — copy to USB, upload to unsanctioned sites, print.

**Business risk:**
Without Endpoint DLP, a user can copy an entire SharePoint document library to a USB drive or personal Google Drive without any policy enforcement — no alert, no block, no log.

**Remediation:**
Purview > DLP > Create policy > Devices location > Enable. Requires Defender for Endpoint onboarding + Microsoft 365 E5 or Microsoft 365 E5 Compliance.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28, MP-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 3.3.6 |
| CIS Controls v8.1 | 3.13 |
| CISA SCuBA | MS.DEFENDER.4.2v1 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.1, A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1), §164.310(d)(1) |
| PCI DSS | Req 3.4, Req 5.4 |
| MITRE ATT&CK | T1005, T1025 |

---

### DEF-4.6 — Attack Simulation Training Campaigns Active

**Severity:** Low  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Defender for Office 365 Plan 2 (M365 E5 or add-on)

**Description:**
Regular phishing simulation campaigns are run via Attack Simulation Training in Defender.

**Business risk:**
Human error causes >90% of breaches. Without regular simulation, users have no trained muscle memory for identifying phishing — click-through rates on real attacks remain high.

**Remediation:**
Defender portal > Email & collaboration > Attack simulation training > Simulations > Launch simulation. Schedule recurring simulations covering credential harvest, link in attachment, drive-by URL techniques. Requires Defender for Office 365 Plan 2.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AT-2, AT-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.3.6 |
| CIS Controls v8.1 | 14.2 |
| CMMC 2.0 | AT.L2-3.2.1 |
| ISO/IEC 27001:2022 | A.6.3 |
| SOC 2 | CC2.2, CC2.3 |
| HIPAA | §164.308(a)(5)(i) |
| PCI DSS | Req 12.6.3 |
| MITRE ATT&CK | T1566 |

---

### DEF-4.7 — Safe Links Protects Office Applications

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Defender for Office 365 Plan 1 (M365 Business Premium)

**Description:**
Safe Links policy is configured to scan URLs in Office documents (Word, Excel, PowerPoint) and Teams messages at click time.

**Business risk:**
Malicious URLs embedded in Office files are not scanned by default Safe Links email policies. A user receiving a document containing a malicious link via email attachment can click it without Safe Links intervening.

**Remediation:**
Set-SafeLinksPolicy -Identity <PolicyName> -EnableSafeLinksForOffice $true. Or via Defender portal > Policies > Safe links > Enable Office 365 apps protection.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.3.2 |
| CIS Controls v8.1 | 9.3 |
| CISA SCuBA | MS.DEFENDER.1.3v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 5.2 |
| MITRE ATT&CK | T1566.001, T1204.002 |

### DEF-5.1 — Tenant Allow/Block List Entries Time-Boxed

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (EOP)

**Description:**
No allow entry in the Tenant Allow/Block List is permanent; every filtering override carries an expiry.

**Business risk:**
An allow entry overrides a filtering verdict outright — mail, a URL or a file hash on the allow list bypasses the detonation and reputation checks that would otherwise stop it. Entries are routinely added under pressure during an incident to unblock a sender and are almost never removed afterwards. A never-expiring allow is a permanent, undocumented hole in mail filtering that no anti-spam or anti-phishing policy review will surface, because it lives on a different surface entirely.

**Remediation:**
Defender portal > Policies & rules > Threat policies > Tenant Allow/Block Lists. Review every allow entry. Remove any whose reason no longer applies, and set an expiry date on the rest — Microsoft caps allow entries at 30 or 90 days for exactly this reason. Block entries may remain permanent.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-3, SI-4, SI-8, CM-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.1.6 |
| CIS Controls v8.1 | 9.6, 13.4 |
| CMMC 2.0 | SI.L2-3.14.2, SI.L1-3.14.5 |
| MITRE ATT&CK | T1566.001, T1566.002, T1562.001 |
| ISO/IEC 27001:2022 | A.8.7 |
| SOC 2 | CC6.8 |
| HIPAA | §164.308(a)(5)(ii)(B) |
| PCI DSS v4.0 | Req 5.2 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

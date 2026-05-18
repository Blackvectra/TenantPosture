# M365 Security Assessment Report

**Prepared by:** NRG Technology Services
**Tenant:** nextlayersec.io
**Assessment Date:** May 18, 2026
**Tool Version:** 4.5.5

---

## Executive Summary

**Overall Security Posture: Moderate At Risk (79%)**

| Result | Count |
|--------|-------|
| ✅ Satisfied | 64 |
| ⚠️ Partial | 18 |
| ❌ Gap | 10 |
| — Not Applicable | 62 |
| **Total Controls** | **154** |

## Service Coverage

| Service | Connected |
|---------|-----------|
| Microsoft Graph (Entra ID) | ✅ |
| Exchange Online | ✅ |
| Security & Compliance | ❌ |
| Microsoft Teams | ✅ |
| SharePoint Online | ❌ |

## ⛔ Critical Gaps — Immediate Action Required

| Control | Finding | Remediation |
|---------|---------|-------------|
| AAD-1.3 | **Phishing-Resistant MFA Required for Admins** — No CA policy found that requires MFA for privileged directory roles. | CA policy targeting privileged roles with Authentication Strength = Phishing-resistant MFA. Must cover Global Administrator at minimum. |

## 🔴 High Priority Gaps

| Control | Finding | Remediation |
|---------|---------|-------------|
| AAD-9.1 | **Authenticator Number Matching Enabled** — Number matching state is &#39;&#39;. MFA push fatigue attacks are possible — attacker can spam approve requests. | Entra ID &gt; Security &gt; Authentication methods &gt; Microsoft Authenticator &gt; Configure &gt; Require number matching = Enabled. |
| AAD-2.3 | **Device Compliance Enforced via CA** — No CA policy requires compliant or hybrid-joined device. Unmanaged personal devices access corporate resources unchecked. | CA policy: Grant = Require device to be marked as compliant, or Require hybrid Azure AD joined device. |
| AAD-4.1 | **Guest Invite Permissions Restricted** — Anyone can invite guest users (everyone). This allows uncontrolled external access provisioning. | Entra ID &gt; External Identities &gt; External collaboration settings &gt; Guest invite settings = Admins and users in the Guest Inviter role. |
| AAD-3.2 | **No Permanent Admin Role Assignments** — 16 permanent privileged role assignment(s) found. Admins should be eligible in PIM and activate only when needed. | Convert permanent role assignments to PIM eligible. Keep only break-glass accounts as permanent GA. |
| AAD-1.4 | **Sign-in Risk CA Policy** — No sign-in risk CA policy configured. This control requires Entra ID P2 (not included in Business Premium / P1). If you have P2 licensing, create a CA policy with Sign-in risk condition. Otherwise this is expected. | CA policy: Condition = Sign-in risk high/medium, Grant = Require MFA or Block. Requires Entra P2. |
| AAD-6.1 | **User App Registration Disabled** — Any user can register applications. Malicious OAuth apps or accidental exposure of sensitive API permissions is possible. | Entra ID &gt; User settings &gt; App registrations &gt; Users can register applications = No. |
| INT-1.3 | **BitLocker Encryption Required on Windows** — Windows compliance policy exists but BitLocker encryption is not required. Unencrypted devices can access corporate data. | Intune compliance policy for Windows: Device Health &gt; Require BitLocker = Require. |

## 🟡 Other Gaps

| Control | Severity | Finding |
|---------|----------|---------|
| AAD-6.3 | Medium | Admin Consent Workflow Enabled |
| INT-1.4 | Medium | Mobile Application Management Configured |

## All Findings

| Control | Category | State | Severity | Title |
|---------|----------|-------|----------|-------|
| SPO-2.1 | Collaboration | — NotApplicable | Informational | OneDrive Sync Client Restricted to Managed Devices |
| SPO-2.2 | Collaboration | — NotApplicable | Informational | External Sharing Link Expiration Configured |
| SPO-2.3 | Collaboration | — NotApplicable | Informational | SharePoint Third-Party Apps From Store Restricted |
| SPO-2.4 | Collaboration | — NotApplicable | Informational | Custom Script Disabled on SharePoint Sites |
| SPO-2.5 | Collaboration | — NotApplicable | Informational | Third-Party Cloud Storage Disabled in SharePoint |
| SPO-2.6 | Collaboration | — NotApplicable | Informational | Email Attestation Required for Sharing |
| SPO-2.7 | Collaboration | — NotApplicable | Informational | Reauthentication Required for Sharing Links |
| SPO-2.8 | Collaboration | — NotApplicable | Informational | OneDrive Sync Restricted by Tenant Domain GUID |
| SPO-3.1 | Collaboration | — NotApplicable | Informational | Site Collection Admin Access Reviewed |
| SPO-3.2 | Collaboration | — NotApplicable | Informational | SharePoint Sharing Notifications Enabled |
| SPO-3.3 | Collaboration | — NotApplicable | Informational | OneDrive Version History Enabled |
| SPO-3.4 | Collaboration | — NotApplicable | Informational | SharePoint Guest Access Expiration Required |
| TMS-2.1 | Collaboration | — NotApplicable | Informational | Skype Consumer Contact Disabled |
| TMS-2.2 | Collaboration | — NotApplicable | Informational | Unverified App Publisher Blocked |
| TMS-2.3 | Collaboration | — NotApplicable | Informational | Third-Party Cloud Storage Disabled in Teams |
| TMS-2.4 | Collaboration | — NotApplicable | Informational | Teams Email Integration Disabled |
| TMS-2.5 | Collaboration | — NotApplicable | Informational | Cloud Recording Disabled for External Participants |
| TMS-2.6 | Collaboration | — NotApplicable | Informational | Broad Channel Meeting Invite Restricted |
| TMS-2.7 | Collaboration | — NotApplicable | Informational | External User Chat Restricted |
| TMS-2.8 | Collaboration | — NotApplicable | Informational | PSTN Users Cannot Bypass Lobby |
| TMS-3.1 | Collaboration | — NotApplicable | Informational | Teams Meeting Watermarks Enabled |
| TMS-3.2 | Collaboration | — NotApplicable | Informational | Auto-Admit Only Authenticated Organization Users |
| TMS-3.3 | Collaboration | — NotApplicable | Informational | Meeting Chat Disabled for Anonymous Participants |
| TMS-3.4 | Collaboration | — NotApplicable | Informational | Meeting Chat Copy Prevention via DLP |
| PVW-1.1 | Compliance | — NotApplicable | Informational | Unified Audit Log Enabled |
| PVW-1.2 | Compliance | — NotApplicable | Informational | Audit Log Retention Minimum 90 Days |
| PVW-1.3 | Compliance | — NotApplicable | Informational | DLP Policy Active for Sensitive Data |
| PVW-1.4 | Compliance | — NotApplicable | Informational | Sensitivity Labels Published |
| PPL-2.1 | Data | — NotApplicable | Informational | Power Platform Connector Classification Reviewed |
| PVW-2.6 | Data | — NotApplicable | Informational | Auto-Labeling Policy Active |
| PVW-3.4 | Data | — NotApplicable | Informational | Sensitive Information Types Used in DLP Policies |
| DEF-1.1 | Email | ✅ Satisfied | Informational | Safe Attachments Enabled with Block Action |
| DEF-1.2 | Email | ✅ Satisfied | Informational | Safe Links Enabled and Hardened |
| DEF-1.3 | Email | ✅ Satisfied | Informational | Spoof Intelligence Enabled |
| DEF-1.4 | Email | ✅ Satisfied | Informational | Honor DMARC Policy (Defender Layer) |
| DEF-1.5 | Email | ✅ Satisfied | Informational | Phishing Threshold Level Aggressive |
| DEF-1.6 | Email | ✅ Satisfied | Informational | First Contact Safety Tip Enabled |
| DEF-2.1 | Email | ✅ Satisfied | Informational | Preset Security Policies Applied |
| DEF-2.2 | Email | ✅ Satisfied | Informational | Zero-Hour Auto Purge Enabled |
| DEF-2.3 | Email | ✅ Satisfied | Informational | Anti-Malware Common Attachments Blocked |
| DEF-2.4 | Email | ✅ Satisfied | Informational | Phishing Directed to Quarantine Not Junk |
| DEF-2.5 | Email | ✅ Satisfied | Informational | High Confidence Spam to Quarantine |
| DEF-2.6 | Email | ✅ Satisfied | Informational | Bulk Mail Threshold Configured |
| DEF-3.1 | Email | ✅ Satisfied | Informational | Unauthenticated Sender Indicator Enabled |
| DEF-3.2 | Email | ✅ Satisfied | Informational | Via Tag Enabled in Anti-Phishing Policy |
| DNS-1.1 | Email | ✅ Satisfied | Informational | SPF Record Published: nextlayersec.io |
| DNS-1.1 | Email | ✅ Satisfied | Informational | SPF Record Published: nextlayersec.dev |
| DNS-1.1 | Email | ✅ Satisfied | Informational | SPF Record Published: mattlevorson.com |
| DNS-1.2 | Email | ✅ Satisfied | Informational | DKIM Records Published: nextlayersec.io |
| DNS-1.2 | Email | ✅ Satisfied | Informational | DKIM Records Published: nextlayersec.dev |
| DNS-1.2 | Email | ✅ Satisfied | Informational | DKIM Records Published: mattlevorson.com |
| DNS-1.3 | Email | ✅ Satisfied | Informational | DMARC Policy at Quarantine or Reject: nextlayersec.dev |
| DNS-1.3 | Email | ✅ Satisfied | Informational | DMARC Policy at Quarantine or Reject: mattlevorson.com |
| DNS-1.3 | Email | ✅ Satisfied | Informational | DMARC Policy at Quarantine or Reject: nextlayersec.io |
| DNS-1.4 | Email | ✅ Satisfied | Informational | MTA-STS Policy in Enforce Mode: mattlevorson.com |
| DNS-1.4 | Email | ✅ Satisfied | Informational | MTA-STS Policy in Enforce Mode: nextlayersec.io |
| DNS-1.4 | Email | ✅ Satisfied | Informational | MTA-STS Policy in Enforce Mode: nextlayersec.dev |
| DNS-1.5 | Email | ✅ Satisfied | Informational | TLS-RPT Record Published: nextlayersec.dev |
| DNS-1.5 | Email | ✅ Satisfied | Informational | TLS-RPT Record Published: mattlevorson.com |
| DNS-1.5 | Email | ✅ Satisfied | Informational | TLS-RPT Record Published: nextlayersec.io |
| EXO-1.1 | Email | ✅ Satisfied | Informational | Mailbox Audit Logging Enabled |
| EXO-1.2 | Email | ✅ Satisfied | Informational | SMTP Client Authentication Disabled |
| EXO-1.3 | Email | ⚠️ Partial | Medium | External Auto-Forwarding Blocked |
| EXO-1.4 | Email | ✅ Satisfied | Informational | DKIM Signing Enabled for All Domains |
| EXO-1.5 | Email | ⚠️ Partial | Medium | Anti-Phishing Impersonation Protection Enabled |
| EXO-1.6 | Email | ✅ Satisfied | Informational | Modern Authentication Enabled |
| EXO-1.7 | Email | ✅ Satisfied | Informational | Honor DMARC Policy Enabled |
| EXO-2.3 | Email | — NotApplicable | Informational | POP3 Access Disabled |
| EXO-2.4 | Email | — NotApplicable | Informational | IMAP Access Disabled |
| EXO-2.6 | Email | ⚠️ Partial | High | Shared Mailboxes Block Direct Sign-In |
| EXO-3.1 | Email | — NotApplicable | Informational | Connection Filter Safe List Bypass Disabled |
| EXO-3.2 | Email | ✅ Satisfied | Informational | Outbound Spam Sending Limits Configured |
| EXO-3.3 | Email | — NotApplicable | Informational | Alert Policy — Email Forwarding Rules |
| EXO-3.4 | Email | ⚠️ Partial | Low | Alert Policy — Unusual Mail Volume |
| EXO-3.5 | Email | ✅ Satisfied | Informational | Transport Rules Changes Audited |
| EXO-4.1 | Email | ✅ Satisfied | Informational | Mailbox Audit Log Age Limit Sufficient |
| EXO-4.2 | Email | ✅ Satisfied | Informational | Admin Audit Log Enabled |
| EXO-4.3 | Email | ✅ Satisfied | Informational | Safe Attachments for SharePoint OneDrive Teams Enabled |
| EXO-4.4 | Email | ✅ Satisfied | Informational | Anti-Spam Inbound Policy Properly Configured |
| INT-1.1 | Endpoint | ✅ Satisfied | Informational | Device Compliance Policies Configured |
| INT-1.2 | Endpoint | ✅ Satisfied | Informational | Non-Compliant Device Access Blocked via CA |
| INT-1.3 | Endpoint | ❌ Gap | High | BitLocker Encryption Required on Windows |
| INT-1.4 | Endpoint | ❌ Gap | Medium | Mobile Application Management Configured |
| INT-1.5 | Endpoint | ⚠️ Partial | Medium | Antivirus Policy Deployed via Intune |
| INT-2.1 | Endpoint | — NotApplicable | Informational | Endpoint Detection and Response Policy Deployed |
| INT-2.2 | Endpoint | — NotApplicable | Informational | Attack Surface Reduction Rules Enabled |
| INT-2.3 | Endpoint | — NotApplicable | Informational | Windows Firewall Policy Deployed via Intune |
| INT-2.4 | Endpoint | — NotApplicable | Informational | macOS FileVault Encryption Required |
| INT-2.5 | Endpoint | — NotApplicable | Informational | Windows Update Compliance Policy Deployed |
| INT-3.1 | Endpoint | — NotApplicable | Informational | Device Enrollment Restrictions Configured |
| INT-3.2 | Endpoint | — NotApplicable | Informational | Mobile App Configuration Policies Deployed |
| INT-3.3 | Endpoint | — NotApplicable | Informational | Conditional Launch Policies Configured |
| DEF-3.3 | Governance | ⚠️ Partial | Medium | Defender for Cloud Apps Connected |
| DEF-3.4 | Governance | ⚠️ Partial | Medium | Defender Alert Email Notifications Configured |
| EXO-2.5 | Governance | — NotApplicable | Informational | Customer Lockbox Enabled |
| PPL-2.2 | Governance | — NotApplicable | Informational | Power Automate Governance Policy Active |
| PPL-2.3 | Governance | — NotApplicable | Informational | Power Apps Portal Creation Restricted |
| PVW-2.1 | Governance | — NotApplicable | Informational | Purview Audit Log Search Enabled |
| PVW-2.2 | Governance | — NotApplicable | Informational | Communication Compliance Policy Active |
| PVW-2.3 | Governance | — NotApplicable | Informational | Information Barriers Mode Configured |
| PVW-2.4 | Governance | — NotApplicable | Informational | Insider Risk Management Policy Active |
| PVW-2.5 | Governance | — NotApplicable | Informational | Retention Policy Covers Key Workloads |
| PVW-3.1 | Governance | ⚠️ Partial | Medium | Audit Logs Exported to SIEM |
| PVW-3.2 | Governance | — NotApplicable | Informational | eDiscovery Case Management Configured |
| PVW-3.3 | Governance | ⚠️ Partial | Low | Compliance Score Improvement Actions Tracked |
| AAD-1.1 | Identity | ✅ Satisfied | Informational | Legacy Authentication Blocked |
| AAD-1.2 | Identity | ✅ Satisfied | Informational | MFA Required for All Users |
| AAD-1.3 | Identity | ❌ Gap | Critical | Phishing-Resistant MFA Required for Admins |
| AAD-1.4 | Identity | ❌ Gap | High | Sign-in Risk CA Policy |
| AAD-1.5 | Identity | ✅ Satisfied | Informational | User Risk CA Policy |
| AAD-10.1 | Identity | ✅ Satisfied | Informational | Identity Protection Risky User Workflow |
| AAD-10.2 | Identity | ✅ Satisfied | Informational | Privileged Accounts Use Dedicated Cloud-Only Accounts |
| AAD-10.3 | Identity | ✅ Satisfied | Informational | Break-Glass Account Sign-In Monitoring |
| AAD-10.4 | Identity | ⚠️ Partial | Low | Sign-in Frequency Session Control Configured |
| AAD-2.1 | Identity | ✅ Satisfied | Informational | Conditional Access Policies Deployed |
| AAD-2.2 | Identity | ⚠️ Partial | Low | Named Locations Defined |
| AAD-2.3 | Identity | ❌ Gap | High | Device Compliance Enforced via CA |
| AAD-3.1 | Identity | ✅ Satisfied | Informational | Global Administrator Count 2-8, Cloud-Only |
| AAD-3.2 | Identity | ❌ Gap | High | No Permanent Admin Role Assignments |
| AAD-3.3 | Identity | — NotApplicable | Informational | PIM Requires MFA on Activation |
| AAD-3.4 | Identity | — NotApplicable | Informational | PIM Requires Justification on Activation |
| AAD-3.5 | Identity | — NotApplicable | Informational | PIM GA Activation Requires Approval |
| AAD-3.6 | Identity | — NotApplicable | Informational | PIM Max Activation Duration 8 Hours or Less |
| AAD-4.1 | Identity | ❌ Gap | High | Guest Invite Permissions Restricted |
| AAD-4.2 | Identity | ⚠️ Partial | Medium | External Collaboration Settings Restricted |
| AAD-4.3 | Identity | ✅ Satisfied | Informational | B2B Guest Default Permissions Restricted |
| AAD-5.1 | Identity | ✅ Satisfied | Informational | Self-Service Password Reset Enabled |
| AAD-5.2 | Identity | ✅ Satisfied | Informational | SSPR Requires Multiple Authentication Methods |
| AAD-6.1 | Identity | ❌ Gap | High | User App Registration Disabled |
| AAD-6.2 | Identity | ✅ Satisfied | Informational | User Consent to Apps Restricted |
| AAD-6.3 | Identity | ❌ Gap | Medium | Admin Consent Workflow Enabled |
| AAD-7.1 | Identity | ✅ Satisfied | Informational | Password Protection Lockout Configured |
| AAD-7.2 | Identity | ✅ Satisfied | Informational | Break-Glass Accounts Configured |
| AAD-8.1 | Identity | ⚠️ Partial | Medium | PIM Alerts Configured |
| AAD-8.2 | Identity | ⚠️ Partial | Medium | Access Reviews for Privileged Roles |
| AAD-9.1 | Identity | ❌ Gap | High | Authenticator Number Matching Enabled |
| AAD-9.2 | Identity | ✅ Satisfied | Informational | Passwordless Authentication Methods Available |
| DNS-1.6 | Network | ✅ Satisfied | Informational | DNSSEC Enabled: mattlevorson.com |
| DNS-1.6 | Network | ✅ Satisfied | Informational | DNSSEC Enabled: nextlayersec.io |
| DNS-1.6 | Network | ✅ Satisfied | Informational | DNSSEC Enabled: nextlayersec.dev |
| PPL-1.1 | Power Platform | ✅ Satisfied | Informational | Power Platform Tenant Isolation Enabled |
| PPL-1.2 | Power Platform | — NotApplicable | Informational | Power Platform DLP Policy Active |
| PPL-1.3 | Power Platform | ⚠️ Partial | Medium | Power Platform Environment Creation Restricted |
| SPO-1.1 | SharePoint | — NotApplicable | Informational | External Sharing Restricted |
| SPO-1.2 | SharePoint | — NotApplicable | Informational | Default Sharing Link Not Anonymous |
| SPO-1.3 | SharePoint | — NotApplicable | Informational | SharePoint Legacy Authentication Blocked |
| SPO-1.4 | SharePoint | — NotApplicable | Informational | Guest Access Expiration Configured |
| SPO-1.5 | SharePoint | — NotApplicable | Informational | Unmanaged Device Access Restricted |
| TMS-1.1 | Teams | ✅ Satisfied | Informational | External Federation Access Restricted |
| TMS-1.2 | Teams | ⚠️ Partial | Medium | Teams Consumer Account Access Disabled |
| TMS-1.3 | Teams | ⚠️ Partial | Medium | Anonymous Meeting Join Disabled |
| TMS-1.4 | Teams | ✅ Satisfied | Informational | External Participants Cannot Take Screen Control |
| TMS-1.5 | Teams | ⚠️ Partial | Medium | Recording Storage in Organization |
| TMS-1.6 | Teams | ✅ Satisfied | Informational | Teams Guest Access Controlled |

---
*Generated by NRG-Assessment v4.5.5 | NRG Technology Services | May 18, 2026*


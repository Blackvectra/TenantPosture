# Benchmark map

Generated from `Config/controls.json` (CIS Microsoft 365 and ScubaGear citations), `Config/scuba-alignment.json` and `Config/benchmark-mappings.json` on 2026-10-26; `Get-TPBenchmarkMapping` returns the same view and `Testing/TP.BenchmarkMapping.Tests.ps1` fails when a control is in neither list.

**162 of 209 controls are mapped to at least one configuration benchmark; 47 are not, each with the reason.** A control cites a benchmark item only when its evaluator judges the setting the item audits and every state it scores Satisfied passes that audit: a similar topic is not enough, so a control with no such item is listed below rather than given a near-miss. Relations: Equivalent (same setting and threshold), Subset (part of what the item requires; the rest is named in the mapping file), Stricter (passes only when the item passes, can fail where it passes); ScubaGear relations are the ones recorded in `Config/scuba-alignment.json`.

Control frameworks (NIST SP 800-53, CIS Controls v8.1, CMMC, ISO 27001, SOC 2, HIPAA, PCI DSS, MITRE ATT&CK) are mapped separately in `References` and are not configuration benchmarks.

## Benchmarks used

| Key | Benchmark | Version | Publisher |
|---|---|---|---|
| CIS-M365-7.0.0 | CIS Microsoft 365 Foundations Benchmark | 7.0.0 | Center for Internet Security |
| SCUBA-2.0.0 | CISA ScubaGear Secure Configuration Baselines | 2.0.0 | CISA |
| CIS-INTUNE-DEFENDER-AV-1.0.0 | CIS Microsoft Intune for Microsoft Defender Antivirus Benchmark | 1.0.0, Level 1 - Workstation | Center for Internet Security |
| MS-EOP-MDO-RECOMMENDED | Microsoft: Recommended settings for EOP and Microsoft Defender for Office 365 security | Learn page dated 2026-08-10 (Standard and Strict columns) | Microsoft |
| NIST-SP-800-177R1 | NIST SP 800-177 Rev. 1, Trustworthy Email | February 2019 | NIST |
| MS-ZERO-TRUST | Microsoft Zero Trust deployment guidance and Zero Trust Assessment checks | Learn pages and microsoft/zerotrustassessment tests read 2026-10-26 | Microsoft |
| DISA-ENTRA-ID-STIG-V1R1 | DISA Microsoft Entra ID Security Technical Implementation Guide | Version 1 Release 1, 2025-02-28 (also published by CIS as the CIS Microsoft Entra ID STIG Benchmark v1.0.0) | DISA |
| MS-WINDOWS-SECURITY-BASELINE | Microsoft Security Baseline for Windows (Intune MDM security baseline) | Security Baseline for Windows, version 24H2 (same values in 25H2) | Microsoft |
| CIS-INTUNE-WINDOWS11-5.0.0 | CIS Microsoft Intune for Windows 11 Benchmark | 5.0.0, Level 1 | Center for Internet Security |
| MS-LEARN-RECOMMENDED | Microsoft Learn: values Microsoft states as recommended or not recommended in product documentation | Learn pages read 2026-10-26 | Microsoft |
| CIS-INTUNE-OFFICE-1.1.0 | CIS Microsoft Intune for Office Benchmark | 1.1.0, Level 1 | Center for Internet Security |
| MS-APP-PROTECTION-FRAMEWORK | Microsoft Intune Data Protection Framework using app protection policies | Learn page read 2026-10-26 | Microsoft |

CIS benchmark text is licensed and is not reproduced; only recommendation numbers are cited. Three other CIS and DISA documents were read for this review and inform it without being cited here: the CIS Microsoft Edge Benchmark v5.0.0 (device-side, planned as endpoint checks), the CIS Password Policy Guide v21.12 (guidance; its values differ from CIS Microsoft 365 and the STIG and are listed below), and the CIS Controls v8.1 mappings to NIST SP 800-53 Rev. 5 and HIPAA (used to review the framework citations).

## Mapped controls


### AAD

| Control | Title | Benchmarks |
|---|---|---|
| AAD-1.1 | Legacy Authentication Blocked | ScubaGear 2.0.0 MS.AAD.1.1v1 (Equivalent) |
| AAD-1.2 | MFA Required for All Users | CIS M365 v7.0.0 5.2.2.2; ScubaGear 2.0.0 MS.AAD.3.2v2 (Equivalent); DISA Entra ID STIG V1R1: V-270233 (Subset) |
| AAD-1.3 | Phishing-Resistant MFA Required for Admins | CIS M365 v7.0.0 5.2.2.5; ScubaGear 2.0.0 MS.AAD.3.6v1 (Partial) |
| AAD-1.4 | Sign-in Risk CA Policy | CIS M365 v7.0.0 5.2.2.7; ScubaGear 2.0.0 MS.AAD.2.3v1 (Partial) |
| AAD-1.5 | User Risk CA Policy | CIS M365 v7.0.0 5.2.2.6; ScubaGear 2.0.0 MS.AAD.2.1v1 (Partial) |
| AAD-10.1 | Identity Protection Risky User Workflow | ScubaGear 2.0.0 MS.AAD.2.2v1 (Partial) |
| AAD-10.2 | Privileged Accounts Use Dedicated Cloud-Only Accounts | CIS M365 v7.0.0 1.1.1; ScubaGear 2.0.0 MS.AAD.7.3v1 (Equivalent) |
| AAD-10.3 | Break-Glass Account Sign-In Monitoring | CIS M365 v7.0.0 2.2.1 |
| AAD-10.4 | Short Sign-in Frequency for Admins and Guests | CIS M365 v7.0.0 5.2.2.4; Microsoft Zero Trust: Privileged users have short-lived sign-in sessions (Zero Trust Assessment test 21825) (Stricter); Microsoft Zero Trust: Guests don't have long lived sign-in sessions (Zero Trust Assessment test 21824) (Subset) |
| AAD-11.1 | Device Code Authentication Flow Blocked | ScubaGear 2.0.0 MS.AAD.3.9v1 (Equivalent) |
| AAD-11.2 | No Guest Accounts in Highly Privileged Roles | Microsoft Zero Trust: Guests are not assigned high privileged directory roles (Zero Trust Assessment test 22128) (Equivalent) |
| AAD-11.3 | Risky Service Principals Reviewed and Remediated | Microsoft Zero Trust: All risky workload identities are triaged (Zero Trust Assessment test 21862) (Subset) |
| AAD-11.4 | Token Protection (Session Binding) Enforced | CIS M365 v7.0.0 5.2.2.16; Microsoft Zero Trust: Token protection policies are configured (Zero Trust Assessment test 21941) (Equivalent) |
| AAD-11.7 | Privileged Access Workstation or Device Scope for Admins | Microsoft Zero Trust: Conditional Access policies for Privileged Access Workstations are configured (Zero Trust Assessment test 21830) (Stricter) |
| AAD-11.9 | Workload Identity Conditional Access Policy | Microsoft Zero Trust: Workload Identities are configured with risk-based policies (Zero Trust Assessment test 21883) (Equivalent) |
| AAD-12.1 | Users Without MFA — Named List | CIS M365 v7.0.0 5.2.3.4; ScubaGear 2.0.0 MS.AAD.3.1v1 (Unsupported) |
| AAD-12.2 | Stale Guest Accounts — Named List | Microsoft Zero Trust: Inactive guest identities are disabled or removed from the tenant (Zero Trust Assessment test 21858) (Equivalent) |
| AAD-12.3 | Inactive Member Accounts (35 Days) — Named List | DISA Entra ID STIG V1R1: V-270204 (Subset) |
| AAD-12.4 | OAuth Apps with Tenant-Wide Consent — Named List | ScubaGear 2.0.0 MS.AAD.5.2v1 (Unsupported) |
| AAD-14.1 | Application Credentials Current and Short-Lived | CIS M365 v7.0.0 5.1.5.4; ScubaGear 2.0.0 MS.AAD.5.6v1 (Equivalent); Microsoft Zero Trust: Application certificates must be rotated on a regular basis (Zero Trust Assessment test 21992) (Subset) |
| AAD-15.1 | No Application Holds Tenant-Takeover Permissions | ScubaGear 2.0.0 MS.AAD.5.2v1 (Unsupported) |
| AAD-15.2 | Applications with Tenant-Wide Data Permissions — Named List | ScubaGear 2.0.0 MS.AAD.5.2v1 (Unsupported) |
| AAD-2.1 | Conditional Access Policies Deployed | ScubaGear 2.0.0 MS.AAD.1.1v1 (Partial) |
| AAD-2.2 | Named Locations Defined | CIS M365 v7.0.0 5.2.2.14 |
| AAD-2.3 | Device Compliance Enforced via CA | ScubaGear 2.0.0 MS.AAD.3.7v1 (Partial) |
| AAD-3.1 | Global Administrator Count 2-4, Cloud-Only | CIS M365 v7.0.0 1.1.3; ScubaGear 2.0.0 MS.AAD.7.1v1 (Partial) |
| AAD-3.2 | No Permanent Admin Role Assignments | ScubaGear 2.0.0 MS.AAD.7.3v1 (Unsupported) |
| AAD-3.3 | PIM Requires MFA on Activation | Microsoft Zero Trust: Phase 1 - Secure the identity control plane, Step 6: Configure activation settings > Require MFA on activation (Subset) |
| AAD-3.4 | PIM Requires Justification on Activation | Microsoft Zero Trust: Step 6: Configure PIM > Configure activation settings > 'Require justification' (Subset) |
| AAD-3.5 | PIM GA Activation Requires Approval | CIS M365 v7.0.0 5.3.4; ScubaGear 2.0.0 MS.AAD.7.6v1 (Equivalent) |
| AAD-3.6 | PIM Max Activation Duration 4 Hours for High-Impact Roles | Microsoft Zero Trust: Step 6: Configure PIM > Configure activation settings > 'Set maximum activation duration' (Subset) |
| AAD-4.1 | Guest Invite Permissions Restricted | CIS M365 v7.0.0 5.1.6.3; ScubaGear 2.0.0 MS.AAD.8.2v1 (Equivalent) |
| AAD-4.2 | External Collaboration Settings Restricted | CIS M365 v7.0.0 5.1.2.3 |
| AAD-4.3 | B2B Guest Default Permissions Restricted | CIS M365 v7.0.0 5.1.6.2; ScubaGear 2.0.0 MS.AAD.8.1v1 (Equivalent) |
| AAD-5.1 | Self-Service Password Reset Enabled | CIS M365 v7.0.0 5.2.4.1 |
| AAD-5.2 | SSPR Requires Multiple Authentication Methods | CIS M365 v7.0.0 5.2.4.2 |
| AAD-6.1 | User App Registration Disabled | CIS M365 v7.0.0 5.1.2.2; ScubaGear 2.0.0 MS.AAD.5.1v1 (Equivalent) |
| AAD-6.2 | User Consent to Apps Restricted | ScubaGear 2.0.0 MS.AAD.5.2v1 (Equivalent) |
| AAD-6.3 | Admin Consent Workflow Enabled | CIS M365 v7.0.0 5.1.5.2; ScubaGear 2.0.0 MS.AAD.5.3v1 (Equivalent) |
| AAD-7.1 | Password Protection Lockout Configured | CIS M365 v7.0.0 5.2.3.8 |
| AAD-7.2 | Break-Glass Accounts Configured | CIS M365 v7.0.0 1.1.2 |
| AAD-7.3 | Smart Lockout Duration at Least 60 Seconds | CIS M365 v7.0.0 5.2.3.9 |
| AAD-7.4 | Custom Banned Password List Enforced | CIS M365 v7.0.0 5.2.3.2 |
| AAD-7.5 | Passwords Set to Never Expire | CIS M365 v7.0.0 1.3.1 |
| AAD-8.1 | PIM Alerts Configured | ScubaGear 2.0.0 MS.AAD.7.7v1 (Manual) |
| AAD-9.1 | Authenticator Number Matching Enabled | CIS M365 v7.0.0 5.2.3.1; ScubaGear 2.0.0 MS.AAD.3.3v2 (Partial) |
| AAD-9.2 | Passwordless Authentication Methods Available | ScubaGear 2.0.0 MS.AAD.3.1v1 (Unsupported) |

### DEF

| Control | Title | Benchmarks |
|---|---|---|
| DEF-1.1 | Safe Attachments Enabled with Block Action | CIS M365 v7.0.0 2.1.4; ScubaGear 2.0.0 MS.SECURITYSUITE.1.3v1 (Partial) |
| DEF-1.2 | Safe Links Enabled and Hardened | CIS M365 v7.0.0 2.1.1; ScubaGear 2.0.0 MS.SECURITYSUITE.7.1v1 (Partial) |
| DEF-1.3 | Spoof Intelligence Enabled | CIS M365 v7.0.0 2.1.7 |
| DEF-1.4 | Honor DMARC Policy (Defender Layer) | CIS M365 v7.0.0 2.1.7 |
| DEF-1.5 | Phishing Threshold Level Aggressive | CIS M365 v7.0.0 2.1.7 |
| DEF-1.6 | First Contact Safety Tip Enabled | CIS M365 v7.0.0 2.1.7 |
| DEF-2.1 | Preset Security Policies Applied | Microsoft EOP/MDO recommended settings: Introduction: use the Standard and/or Strict preset security policies (Subset) |
| DEF-2.2 | Zero-Hour Auto Purge Enabled | ScubaGear 2.0.0 MS.SECURITYSUITE.1.2v1 (Partial) |
| DEF-2.3 | Anti-Malware Common Attachments Blocked | CIS M365 v7.0.0 2.1.2; ScubaGear 2.0.0 MS.SECURITYSUITE.1.1v1 (Partial) |
| DEF-2.4 | Phishing Directed to Quarantine Not Junk | ScubaGear 2.0.0 MS.SECURITYSUITE.6.1v1 (Partial); Microsoft EOP/MDO recommended settings: Anti-spam policy settings > Phishing detection action (PhishSpamAction) (Equivalent) |
| DEF-2.5 | High Confidence Spam to Quarantine | ScubaGear 2.0.0 MS.SECURITYSUITE.6.1v1 (Partial) |
| DEF-2.6 | Bulk Mail Threshold Configured | Microsoft EOP/MDO recommended settings: Anti-spam policy settings > Bulk email threshold (BulkThreshold) (Equivalent) |
| DEF-3.1 | Unauthenticated Sender Indicator Enabled | Microsoft EOP/MDO recommended settings: Anti-phishing policy settings for all cloud mailboxes > Show (?) for unauthenticated senders for spoof (EnableUnauthenticatedSender) (Equivalent) |
| DEF-3.2 | Via Tag Enabled in Anti-Phishing Policy | Microsoft EOP/MDO recommended settings: Anti-phishing policy settings for all cloud mailboxes > Show "via" tag (EnableViaTag) (Equivalent) |
| DEF-3.3 | Defender for Cloud Apps Connected | CIS M365 v7.0.0 2.4.3 |
| DEF-3.4 | Defender Alert Email Notifications Configured | ScubaGear 2.0.0 MS.SECURITYSUITE.4.2v1 (Partial) |
| DEF-4.1 | DLP Policy Covers All Key Workloads | CIS M365 v7.0.0 3.2.1; ScubaGear 2.0.0 MS.SECURITYSUITE.3.2v1 (Partial) |
| DEF-4.2 | DLP Policy Uses Sensitive Information Types | CIS M365 v7.0.0 3.2.1; ScubaGear 2.0.0 MS.SECURITYSUITE.3.1v1 (Partial) |
| DEF-4.4 | Priority Accounts Tagged in Defender | CIS M365 v7.0.0 2.4.1 |
| DEF-4.5 | Endpoint DLP Policy Active on Managed Devices | ScubaGear 2.0.0 MS.SECURITYSUITE.3.2v1 (Partial) |
| DEF-4.7 | Safe Links Protects Office Applications | CIS M365 v7.0.0 2.1.1; ScubaGear 2.0.0 MS.SECURITYSUITE.7.1v1 (Partial) |

### DNS

| Control | Title | Benchmarks |
|---|---|---|
| DNS-1.1 | SPF Record Published | CIS M365 v7.0.0 2.1.8; ScubaGear 2.0.0 MS.EXO.2.2v3 (Partial) |
| DNS-1.2 | DKIM Records Published | ScubaGear 2.0.0 MS.EXO.3.1v1 (Partial) |
| DNS-1.3 | DMARC Policy at Quarantine or Reject | ScubaGear 2.0.0 MS.EXO.4.2v1 (Partial) |
| DNS-1.4 | MTA-STS Policy in Enforce Mode | NIST SP 800-177r1: Security Recommendation 5-3 (Section 5.2.6) (Subset) |
| DNS-1.6 | DNSSEC Enabled | NIST SP 800-177r1: Security Recommendation 4-2 (Section 4.4.5.1) (Subset) |
| DNS-2.1 | DKIM Key Rotation Cadence | NIST SP 800-177r1: Section 4.5.3, Table 4-3 'Recommended Cryptographic Key Parameters' (RSA/SHA-256 row) (Stricter) |

### EXO

| Control | Title | Benchmarks |
|---|---|---|
| EXO-1.1 | Mailbox Audit Logging Enabled | CIS M365 v7.0.0 6.1.1; ScubaGear 2.0.0 MS.EXO.13.1v1 (Equivalent) |
| EXO-1.2 | SMTP Client Authentication Disabled | CIS M365 v7.0.0 6.5.4; ScubaGear 2.0.0 MS.EXO.5.1v1 (Equivalent) |
| EXO-1.3 | External Auto-Forwarding Blocked | CIS M365 v7.0.0 6.2.1; ScubaGear 2.0.0 MS.EXO.1.1v2 (Partial) |
| EXO-1.4 | DKIM Signing Enabled for All Domains | CIS M365 v7.0.0 2.1.9; ScubaGear 2.0.0 MS.EXO.3.1v1 (Partial) |
| EXO-1.5 | Anti-Phishing Impersonation Protection Enabled | ScubaGear 2.0.0 MS.SECURITYSUITE.2.1v1 (Partial) |
| EXO-1.6 | Modern Authentication Enabled | CIS M365 v7.0.0 6.5.1 |
| EXO-1.7 | Honor DMARC Policy Enabled | CIS M365 v7.0.0 2.1.7 |
| EXO-2.5 | Customer Lockbox Enabled | CIS M365 v7.0.0 1.3.6 |
| EXO-2.6 | Shared Mailboxes Block Direct Sign-In | CIS M365 v7.0.0 1.2.2 |
| EXO-3.1 | Connection Filter Safe List Bypass Disabled | CIS M365 v7.0.0 2.1.13 |
| EXO-3.2 | Outbound Spam Sending Limits Configured | CIS M365 v7.0.0 2.1.15; Microsoft EOP/MDO recommended settings: Outbound spam policy settings > RecipientLimitExternalPerHour, RecipientLimitInternalPerHour, RecipientLimitPerDay, ActionWhenThresholdReached (Equivalent) |
| EXO-3.3 | Alert Policy — Email Forwarding Rules | ScubaGear 2.0.0 MS.SECURITYSUITE.4.1v1 (Partial) |
| EXO-3.4 | Alert Policy — Unusual Mail Volume | ScubaGear 2.0.0 MS.SECURITYSUITE.4.1v1 (Partial) |
| EXO-3.5 | Transport Rules Changes Audited | CIS M365 v7.0.0 3.1.1 |
| EXO-4.1 | Mailbox Audit Log Age Limit Sufficient | ScubaGear 2.0.0 MS.SECURITYSUITE.5.2v1 (Partial) |
| EXO-4.2 | Admin Audit Log Enabled | ScubaGear 2.0.0 MS.SECURITYSUITE.5.1v1 (Partial) |
| EXO-4.3 | Safe Attachments for SharePoint OneDrive Teams Enabled | CIS M365 v7.0.0 2.1.5; ScubaGear 2.0.0 MS.SECURITYSUITE.1.4v1 (Equivalent) |
| EXO-4.4 | Anti-Spam Inbound Policy Properly Configured | Microsoft EOP/MDO recommended settings: Anti-spam policy settings > Bulk email threshold (BulkThreshold), Anti-spam policy settings > Spam detection action (SpamAction), Anti-spam policy settings > Zero-hour auto purge for spam (SpamZapEnabled) and phishing (PhishZapEnabled) (Subset) |
| EXO-5.1 | Per-User Mailbox Audit Logging Enabled for All Mailboxes | CIS M365 v7.0.0 6.1.1; ScubaGear 2.0.0 MS.EXO.13.1v1 (Partial) |
| EXO-5.2 | Priority Account Protection Active in Anti-Phishing Policy | ScubaGear 2.0.0 MS.SECURITYSUITE.2.1v1 (Partial) |
| EXO-5.3 | No Allowed Sender Domains Bypassing Anti-Spam Filtering | CIS M365 v7.0.0 2.1.14 |
| EXO-6.1 | Mailboxes with External Email Forwarding — Named List | ScubaGear 2.0.0 MS.EXO.1.1v2 (Unsupported) |
| EXO-6.2 | Shared Mailboxes with Sign-In Enabled — Named List | CIS M365 v7.0.0 1.2.2 |
| EXO-6.3 | Mailboxes with Audit Logging Disabled — Named List | CIS M365 v7.0.0 6.1.3; ScubaGear 2.0.0 MS.EXO.13.1v1 (Partial) |
| EXO-6.4 | Per-User SMTP AUTH Override — Named List | ScubaGear 2.0.0 MS.EXO.5.1v1 (Partial) |
| EXO-7.1 | No Mailbox Forwarding to External Addresses | ScubaGear 2.0.0 MS.EXO.1.1v2 (Unsupported) |
| EXO-7.2 | No Inbox Rules Forwarding Externally | ScubaGear 2.0.0 MS.EXO.1.1v2 (Unsupported) |
| EXO-7.3 | No Mailboxes with Per-User Audit Explicitly Disabled | CIS M365 v7.0.0 6.1.3; ScubaGear 2.0.0 MS.EXO.13.1v1 (Partial) |
| EXO-7.4 | No Per-User SMTP AUTH Overrides | ScubaGear 2.0.0 MS.EXO.5.1v1 (Partial) |
| EXO-8.2 | No Transport Rule Redirects Mail Externally | CIS M365 v7.0.0 6.2.1 |

### INT

| Control | Title | Benchmarks |
|---|---|---|
| INT-1.1 | Device Compliance Policies Configured | Microsoft Zero Trust: Deployment > Enterprise > Define device compliance policies (Subset) |
| INT-1.2 | Non-Compliant Device Access Blocked via CA | ScubaGear 2.0.0 MS.AAD.3.7v1 (Partial) |
| INT-1.3 | BitLocker Encryption Required on Windows | Microsoft Zero Trust: Recommended compliance settings for Windows 10 and later > Device health > Require BitLocker (Equivalent); CIS Intune Windows 11 5.0.0: 106.1.1 (Equivalent) |
| INT-1.4 | Mobile Application Management Configured | Microsoft Zero Trust: Deployment > Starting point > Apply Application Protection Policies (APP) for data protection (Subset) |
| INT-1.5 | Antivirus Policy Deployed via Intune | CIS Intune Defender AV 1.0.0: 30 recommendations (2.1–2.50) (Stricter) |
| INT-2.2 | Attack Surface Reduction Rules Enabled | CIS Intune Defender AV 1.0.0: 17 recommendations (2.10–2.26) (Stricter) |
| INT-2.3 | Windows Firewall Policy Deployed via Intune | Microsoft Windows security baseline: Firewall > Enable Domain / Private / Public Network Firewall (Subset); CIS Intune Windows 11 5.0.0: 37.1, 37.8, 37.15 (Equivalent) |
| INT-2.5 | Windows Update Compliance Policy Deployed | CIS Intune Windows 11 5.0.0: 104.1, 104.2, 104.3, 104.4, 104.5 (Equivalent) |
| INT-2.6 | Office Macro and Active-Content Hardening Deployed | CIS Intune Office 1.1.0: 24 recommendations (2.1.1.3.2.1.1–2.11.8.7.2.6) (Equivalent) |
| INT-3.1 | Device Enrollment Restrictions Configured | CIS M365 v7.0.0 4.2 |
| INT-3.3 | Conditional Launch Policies Configured | Microsoft App Protection Framework: Level 2 enterprise enhanced data protection: Conditional launch (with the Level 1 conditional launch rows it includes) (Subset) |
| INT-4.1 | Windows LAPS Deployed via Intune | Microsoft Windows security baseline: LAPS > Backup Directory (Subset); CIS Intune Windows 11 5.0.0: 107.1 (Equivalent) |

### PPL

| Control | Title | Benchmarks |
|---|---|---|
| PPL-1.1 | Power Platform Tenant Isolation Enabled | ScubaGear 2.0.0 MS.POWERPLATFORM.3.1v1 (Equivalent) |
| PPL-1.2 | Power Platform DLP Policy Active | ScubaGear 2.0.0 MS.POWERPLATFORM.2.1v1 (Partial) |
| PPL-1.3 | Power Platform Environment Creation Restricted | ScubaGear 2.0.0 MS.POWERPLATFORM.1.1v1 (Equivalent) |
| PPL-2.1 | Power Platform Connector Classification Reviewed | ScubaGear 2.0.0 MS.POWERPLATFORM.2.1v1 (Partial) |
| PPL-2.2 | Power Automate Governance Policy Active | ScubaGear 2.0.0 MS.POWERPLATFORM.1.1v1 (Manual) |
| PPL-2.3 | Power Apps Portal Creation Restricted | ScubaGear 2.0.0 MS.POWERPLATFORM.5.1v1 (Partial) |
| PPL-3.1 | M365 Copilot Sensitivity Label Enforcement | Microsoft Zero Trust: Zero Trust Assessment test 35003 (Stricter) |
| PPL-3.2 | DLP Policy Active for Copilot Interactions | Microsoft Zero Trust: Data loss prevention policies are enabled (Zero Trust Assessment test 35030) (Stricter) |
| PPL-3.5 | Copilot Interaction Audit Logging Active | CIS M365 v7.0.0 3.1.1 |

### PVW

| Control | Title | Benchmarks |
|---|---|---|
| PVW-1.1 | Unified Audit Log Enabled | CIS M365 v7.0.0 3.1.1 |
| PVW-1.2 | Audit Log Retention Minimum 90 Days | ScubaGear 2.0.0 MS.SECURITYSUITE.5.2v1 (Partial) |
| PVW-1.3 | DLP Policy Active for Sensitive Data | CIS M365 v7.0.0 3.2.1 |
| PVW-1.4 | Sensitivity Labels Published | CIS M365 v7.0.0 3.3.1 |
| PVW-2.1 | Purview Audit Log Search Enabled | CIS M365 v7.0.0 3.1.1 |
| PVW-2.2 | Communication Compliance Policy Active | Microsoft Zero Trust: Communication compliance monitoring is configured for Microsoft Copilot (Zero Trust Assessment test 35039) (Equivalent) |
| PVW-2.5 | Retention Policy Covers Key Workloads | Microsoft Zero Trust: Email retention policies are configured (Zero Trust Assessment test 35028) (Stricter) |
| PVW-2.6 | Auto-Labeling Policy Active | Microsoft Zero Trust: Auto-labeling policies are in enforcement mode (Zero Trust Assessment test 35020) (Equivalent) |
| PVW-3.1 | Audit Logs Exported to SIEM | ScubaGear 2.0.0 MS.SECURITYSUITE.4.2v1 (Manual) |
| PVW-3.4 | Sensitive Information Types Used in DLP Policies | Microsoft Zero Trust: Zero Trust Assessment test 35030 (Stricter) |
| PVW-4.1 | Microsoft Purview Audit (Premium) Enabled | ScubaGear 2.0.0 MS.SECURITYSUITE.5.1v1 (Partial); Microsoft Zero Trust: Section 'Purview audit logging is enabled' (Stricter) |
| PVW-4.2 | Audit Log Retention Policy Extends to 1 Year or More | ScubaGear 2.0.0 MS.SECURITYSUITE.5.2v1 (Partial) |
| PVW-4.3 | Sensitivity Labels Defined and Published | CIS M365 v7.0.0 3.3.1 |

### SPO

| Control | Title | Benchmarks |
|---|---|---|
| SPO-1.1 | External Sharing Restricted | CIS M365 v7.0.0 7.2.3; ScubaGear 2.0.0 MS.SHAREPOINT.1.1v1 (Equivalent) |
| SPO-1.2 | Default Sharing Link Not Anonymous | CIS M365 v7.0.0 7.2.7; ScubaGear 2.0.0 MS.SHAREPOINT.2.1v1 (Partial) |
| SPO-1.3 | SharePoint Legacy Authentication Blocked | CIS M365 v7.0.0 7.2.1 |
| SPO-1.4 | Guest Access Expiration Configured | CIS M365 v7.0.0 7.2.9 |
| SPO-1.5 | Unmanaged Device Access Restricted | Microsoft Zero Trust: Recommended policies for Microsoft 365 workloads > Configure SharePoint access control to limit access by unmanaged devices, step 1 (Subset) |
| SPO-2.2 | External Sharing Link Expiration Configured | ScubaGear 2.0.0 MS.SHAREPOINT.3.1v1 (Equivalent) |
| SPO-2.5 | Third-Party Cloud Storage Connectors Disabled | CIS M365 v7.0.0 8.1.1 |
| SPO-2.6 | Email Attestation Required for Sharing | CIS M365 v7.0.0 7.2.10 |
| SPO-2.7 | Reauthentication Required for Sharing Links | CIS M365 v7.0.0 7.2.10; ScubaGear 2.0.0 MS.SHAREPOINT.3.3v2 (Partial) |
| SPO-3.3 | OneDrive Version History Enabled | Microsoft Learn recommended values: Overview of version history limits for document libraries and OneDrive > Types of version limits, note 1 (Equivalent) |
| SPO-3.4 | SharePoint Guest Access Expiration Required | CIS M365 v7.0.0 7.2.9 |

### TMS

| Control | Title | Benchmarks |
|---|---|---|
| TMS-1.1 | External Federation Access Restricted | CIS M365 v7.0.0 8.2.1; ScubaGear 2.0.0 MS.TEAMS.2.1v2 (Equivalent) |
| TMS-1.2 | Teams Consumer Account Access Disabled | CIS M365 v7.0.0 8.2.2 |
| TMS-1.3 | Anonymous Meeting Join Disabled | CIS M365 v7.0.0 8.5.1 |
| TMS-1.4 | External Participants Cannot Take Screen Control | CIS M365 v7.0.0 8.5.7; ScubaGear 2.0.0 MS.TEAMS.1.1v1 (Equivalent) |
| TMS-2.2 | Unverified App Publisher Blocked | CIS M365 v7.0.0 8.4.1; ScubaGear 2.0.0 MS.TEAMS.5.2v2 (Partial) |
| TMS-2.3 | Third-Party Cloud Storage Disabled in Teams | CIS M365 v7.0.0 8.1.1 |
| TMS-2.4 | Teams Email Integration Disabled | CIS M365 v7.0.0 8.1.2; ScubaGear 2.0.0 MS.TEAMS.4.1v1 (Equivalent) |
| TMS-2.7 | External User Chat Restricted | CIS M365 v7.0.0 8.2.1; ScubaGear 2.0.0 MS.TEAMS.2.3v2 (Partial) |
| TMS-2.8 | PSTN Users Cannot Bypass Lobby | CIS M365 v7.0.0 8.5.4; ScubaGear 2.0.0 MS.TEAMS.1.5v1 (Equivalent) |
| TMS-3.2 | Auto-Admit Only Authenticated Organization Users | CIS M365 v7.0.0 8.5.3; ScubaGear 2.0.0 MS.TEAMS.1.3v1 (Partial) |
| TMS-3.3 | Meeting Chat Disabled for Anonymous Participants | CIS M365 v7.0.0 8.5.5 |
| TMS-4.2 | Anonymous Users Cannot Start Meetings | CIS M365 v7.0.0 8.5.2; ScubaGear 2.0.0 MS.TEAMS.1.2v2 (Equivalent) |
| TMS-4.3 | Teams External Domain Federation Restricted to Allowlist | CIS M365 v7.0.0 8.2.1; ScubaGear 2.0.0 MS.TEAMS.2.1v2 (Equivalent) |

## Controls with no benchmark item

"Fixable" means a stated evaluator change would earn a citation (`EarnBy` in the mapping file).

| Control | Title | Why no benchmark item applies | Fixable |
|---|---|---|---|
| AAD-11.5 | Continuous Access Evaluation Strict Mode | No configuration benchmark recommends CAE strict enforcement as a value. |  |
| AAD-11.6 | Cross-Tenant Inbound Trust Settings Restricted | ScubaGear 2.0.0 section 8 covers guest access, invitations and allowed domains, not inbound trust; the DISA Entra ID STIG V1R1 has no cross-tenant rule; the Zero Trust checks include only 'Outbound cross-tenant access settings are configured' (outbound B2B collaboration blocked by default), a different setting, and 'Guest access is protected by strong authentication methods', which suggests accepting the MFA claim for vetted partners rather than recommending it off. |  |
| AAD-11.8 | Terms of Use Policy Enforced | ScubaGear 2.0.0 and the Zero Trust checks have no Terms of Use item. | Yes |
| AAD-13.1 | Microsoft Secure Score | Secure Score is Microsoft's own scoring of many settings, not a configuration setting, and no benchmark sets a Secure Score threshold. |  |
| AAD-6.4 | Users Cannot Create Agent Identity Blueprints | No configuration benchmark covers agent identity blueprints yet: CIS Microsoft 365 v7.0.0, ScubaGear 2.0.0, the DISA Entra ID STIG and the Zero Trust Assessment checks predate Microsoft Entra Agent ID. |  |
| AAD-8.2 | Access Reviews for Privileged Roles | ScubaGear 2.0.0 has no access-review rule; the DISA Entra ID STIG V1R1 has none; the Learn 'Configure Microsoft Entra for increased security' checks have none for role reviews. | Yes |
| DEF-4.3 | Risky OAuth Application Alerts Configured | ScubaGear 2.0.0 MS.SECURITYSUITE.4.1v1 lists seven required alerts (suspicious email sending patterns, suspicious connector activity, suspicious email forwarding activity, messages delayed, tenant restricted from sending unprovisioned email, tenant restricted from sending email, potentially malicious URL click) and a risky OAuth application alert is not among them; checked against the v2.0.0 baseline text on 2026-10-26. |  |
| DEF-4.6 | Attack Simulation Training Campaigns Active | No ScubaGear 2.0.0 rule covers phishing simulation or training. | Yes |
| DEF-5.1 | Tenant Allow/Block List Entries Time-Boxed | Microsoft's Tenant Allow/Block List articles (tenant-allow-block-list-about, -email-spoof-configure, -urls-configure) document that allow entries default to 45 days after last use and can be set to never expire, but make no recommendation against never-expiring allows. | Yes |
| DNS-1.5 | TLS-RPT Record Published | NIST SP 800-177 Rev. |  |
| DNS-2.2 | CAA Record Restricts Certificate Issuance | NIST SP 800-177 Rev. |  |
| DNS-2.3 | TLS Certificate Expiry on Mail Hostnames | NIST SP 800-177 Rev. |  |
| DNS-2.4 | Certificate Transparency Log Hygiene | NIST SP 800-177 Rev. |  |
| EXO-2.3 | POP3 Access Disabled | ScubaGear 2.0.0 EXO and SECURITYSUITE baselines have no POP3/IMAP rule (MS.EXO.5.1v1 is SMTP AUTH only). | Yes |
| EXO-2.4 | IMAP Access Disabled | Same as EXO-2.3: no ScubaGear 2.0.0 rule, no row on the EOP/Defender recommended-settings page. | Yes |
| EXO-8.1 | Mail Flow Connectors Reviewed and Hardened | ScubaGear 2.0.0 EXO and SECURITYSUITE baselines have no connector rule (MS.SECURITYSUITE.8.1v1 is the connection-filter IP allow list, a different object). | Yes |
| EXO-9.1 | Mailboxes Protected by Hold or Retention Policy | No ScubaGear 2.0.0 rule covers mailbox holds or retention policies (MS.SECURITYSUITE.5.2v1 is audit-log retention). | Yes |
| EXO-9.2 | Deleted Item Retention Window at Maximum | Microsoft Learn ('Change how long permanently deleted items are kept for an Exchange Online mailbox', 'Exchange Online limits', 'Mailbox plans in Exchange Online') documents 14 days as the default and 30 as the maximum, and uses 30 in examples, but never recommends it. | Yes |
| INT-2.1 | Endpoint Detection and Response Policy Deployed | Searched the Microsoft Defender for Endpoint security baseline and Windows MDM security baseline settings lists, the CIS Intune Defender AV benchmark (Config/cis-intune-defender-av.json), and Microsoft's Zero Trust common policies. | Yes |
| INT-2.4 | macOS FileVault Encryption Required | Microsoft's Zero Trust common policies page gives recommended compliance settings for Windows, iOS/iPadOS and Android only, not macOS; no Microsoft-published macOS compliance baseline with a FileVault value was found, and ScubaGear has no Intune baseline. |  |
| INT-3.2 | Mobile App Configuration Policies Deployed | No allowed benchmark audits that an app configuration policy exists. |  |
| INT-4.2 | Windows Hello for Business Deployed | The Windows MDM security baseline's Windows Hello for Business section lists only 'Facial Features Use Enhanced Anti Spoofing' = true, which INT-4.2 does not read. |  |
| INT-4.3 | Device OS Version Compliance Enforced | Microsoft's Zero Trust Windows compliance table lists 'Minimum OS version' with no value ('Enter appropriate values ... |  |
| INT-4.4 | Mobile Device Compliance Requires PIN or Biometric | Microsoft's iOS/iPadOS and Android security configuration framework pages set 'Require a password' in DEVICE RESTRICTION profiles (for example iOS personal Level 1, Password > Require a password = Yes), a different setting from a compliance-policy passcode rule. | Yes |
| PPL-3.3 | Copilot Access Restricted to Licensed Users | The 95% threshold is the tool's own heuristic. |  |
| PPL-3.4 | Copilot Studio Agent Publishing Governed | Manual control with no verdict. |  |
| PVW-2.3 | Information Barriers Mode Configured | No allowed benchmark states a recommended information-barriers mode. |  |
| PVW-2.4 | Insider Risk Management Policy Active | The control never reaches a verdict, so no item can be audited by it. | Yes |
| PVW-3.2 | eDiscovery Case Management Configured | Manual control with no verdict. |  |
| PVW-3.3 | Compliance Score Improvement Actions Tracked | Manual control with no verdict, and reviewing Compliance Manager improvement actions is a process, not a configuration value. |  |
| PVW-4.4 | Records Management Labels Configured for Regulated Data | No allowed benchmark recommends configuring record-declaring retention labels: ScubaGear 2.0.0 has no records-management item, the Zero Trust Assessment Purview tests (35001-35041) have none, and 'Implementing Zero Trust with Microsoft Purview' says only that records management 'supports additional restrictions' for high-value content, with no configured value. |  |
| SPO-2.1 | OneDrive Sync Client Restricted to Managed Devices | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| SPO-2.3 | SharePoint Third-Party Apps From Store Restricted | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. | Yes |
| SPO-2.4 | Custom Script Disabled on SharePoint Sites | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. | Yes |
| SPO-2.8 | OneDrive Sync Restricted by Tenant Domain GUID | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| SPO-3.1 | Site Collection Admin Access Reviewed | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| SPO-3.2 | SharePoint Sharing Notifications Enabled | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| SPO-4.1 | Departed-User OneDrive Retention Configured | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| TMS-1.5 | Recording Storage in Organization | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| TMS-1.6 | Teams Guest Access Controlled | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. | Yes |
| TMS-2.1 | Skype Consumer Contact Disabled | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| TMS-2.5 | Cloud Recording Disabled for External Participants | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| TMS-2.6 | Broad Channel Meeting Invite Restricted | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| TMS-3.1 | Teams Meeting Watermarks Enabled | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| TMS-3.4 | Meeting Chat Copy Prevention via DLP | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. | Yes |
| TMS-4.1 | Meeting Recording Expiration Configured | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |
| TMS-4.4 | Teams Events Cannot Be Attended by Anonymous Internet Users | CISA ScubaGear 2.0.0 Teams and SharePoint/OneDrive baselines (v2.0.0 tag, every MS.TEAMS.* and MS.SHAREPOINT.* statement read); docs/TP-SCUBA-ALIGNMENT.md; DISA Entra ID STIG summary (no rule on this topic; DISA publishes no SharePoint Online, OneDrive or Teams service STIG, only Office 365 ProPlus client and on-premises SharePoint 2013 STIGs, per stigviewer's STIG list); Microsoft Learn. |  |

## Where the password sources disagree

| Setting | CIS Microsoft 365 v7.0.0 (the baseline) | CIS Password Policy Guide v21.12 | DISA Entra ID STIG V1R1 |
|---|---|---|---|
| Password expiration | Never expire (1.3.1, AAD-7.5) | Event-based, with an annual backstop | 60 days or less (V-270239) |
| Lockout threshold | 10 or fewer (5.2.3.8, AAD-7.1) | Temporary lockout after 5 | 3 (V-270208) |
| Lockout duration | 60 seconds or more (5.2.3.9, AAD-7.3) | 15 minutes or more | 900 seconds or more (V-270208) |
| Custom banned passwords | Used (5.2.3.2, AAD-7.4) | Deny list incl. previous passwords | Enforced and populated (V-270475) |
| Idle session | 3 hours or less, unmanaged devices (1.3.2) | 15 minutes | 15 minutes, directory level (V-270200) |
| Inactive accounts | No recommendation | Suspend after 45 days | Disable after 35 days (V-270204) |

The NRG Security Baseline follows CIS Microsoft 365 v7.0.0; the other two are reported beside it, never merged into it.


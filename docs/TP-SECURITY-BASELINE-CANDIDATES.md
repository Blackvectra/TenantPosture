# NRG Security Baseline v2.0 — CIS Microsoft 365 Foundations v7.0.0

**Status:** v2.0, 2026-10-25 (owner's decision: "I'd rather have a baseline aligning with CIS than a made up one"). The baseline follows the CIS Microsoft 365 Foundations Benchmark v7.0.0 and nothing else. `Config/tp-baseline.json` encodes this document, and `TP.Baseline.Tests.ps1` fails if a control's tier here differs from the file, if a row names a recommendation that is not in v7.0.0, or if a tier differs from the recommendation's CIS profile.

**Source of truth for IDs, titles, severities and license requirements:** `Config/controls.json`. For CIS numbers, titles and profiles: `Config/framework-baselines/cis-m365-v7.0.0.txt` and the benchmark itself. Which control cites which recommendation, and why, is `docs/TP-CIS-M365-ALIGNMENT.md`.

## What the baseline is, and is not

The assessment answers "what is this tenant's posture against 204 controls and ten frameworks". The baseline answers a narrower question: **is this client configured the way the CIS Microsoft 365 Foundations Benchmark says, at the profile NRG assigns it?** It is a desired-state view over the assessment: it reads findings and never changes them, creates none, and moves no framework score. Every control the tool assesses is still assessed and reported; a control with no CIS recommendation is simply not a baseline requirement.

## Tiers are CIS profiles

| Tier | CIS v7.0.0 profile | Who it applies to |
|---|---|---|
| **Minimum** | E3 Level 1 | Every managed client |
| **Standard** | E5 Level 1 (adds the recommendations CIS lists for E5 only) | Clients on the standard security service |
| **Hardened** | Level 2, E3 and E5 | Regulated, government, high-value targets |
| **Assessment-only** | No CIS Microsoft 365 recommendation | Evidence only |

Tiers are inherited: a Standard client must meet Minimum and Standard, a Hardened client all three. A recommendation's tier is its CIS profile, never an NRG judgment; changing one means CIS changed it.

## How a recommendation becomes a row

- **A control cites it.** The control's row is required at the recommendation's tier and judged by the control's finding. A control cites a recommendation only when every state it passes also passes the CIS audit (`docs/TP-CIS-M365-ALIGNMENT.md`).
- **No control checks it.** A manual row `CIS-<number>` is required at the same tier and always resolves **NotVerified** with reason code `ManualVerificationRequired`. It is never counted as met. Most of these need a new read; section 9 (Microsoft Fabric) is outside what the tool reads.
- **Controls check only part of it** (every citing control is a Subset). The controls' rows are required, and a manual `CIS-<number>` row stands for the settings they do not read, so a partial check can never make the whole recommendation look met.

NRG-only requirements in v1.x (VM-VERIFY-01 and every control without a CIS citation, such as the Intune endpoint policies, DNS hardening beyond SPF/DKIM/DMARC, and PIM settings) are assessment-only in v2.0. VM-VERIFY-01 stays in the device build standard (`Config/device-baseline.json`, DB-4.8).

## Three things that must not collapse into one field

| Concept | Question it answers | Where it comes from |
|---|---|---|
| **Control requirement** | What does NRG require? | This document, then `tp-baseline.json` (expected state, tier, owner, SLA class) |
| **Observed evidence** | Is it configured that way right now? | The assessment finding (Satisfied / Failed / NotApplicable / NotVerified) with its evidence timestamp and source |
| **Effectiveness evidence** | Is it actually working? | The effectiveness check named per control; today mostly telemetry the assessment does not collect, so its state is Unknown until a collector exists |

`Configured = yes, Observed = yes, Effective = unknown` is a legitimate and common state and must be reported as exactly that. It is never rounded up to a pass.

## Governance fields

| Field | Meaning | Values |
|---|---|---|
| **Owner** | The NRG discipline that owns the control and answers for drift | Identity, Email, Endpoint, DNS, Logging, Collaboration & Data (Vulnerability lives in the device build standard) |
| **Evidence source** | The exact collector and API that proves the observed state | Derived from `CollectorDependency` |
| **Expected state** | One sentence an engineer can test against | Editorial |
| **SLA class** | A label only; the number of days per class lives in a separate policy table so NRG can change 7 to 10 without touching 50 controls | Immediate, Critical, High, Standard, Advisory |
| **Depends on** | Controls or prerequisites without which this one is weak or meaningless | Control IDs |
| **Effectiveness check** | What proves the control works, not merely that it is configured | Editorial, each tagged **collected** (the assessment or endpoint scanner reads it today) or **not collected** (a capability gap, stated, never pretended) |
| **Evidence freshness class** | How old observed evidence may be before it becomes NotVerified | Realtime, Daily, Weekly, Monthly, PointInTime |

Rows carried over from v1.x keep their governance values; rows new in v2.0 take them from the control (owner by workload, SLA class by severity) or, for a manual CIS row, from the CIS section and level. Assessment-only controls carry none, because they are not requirements.

## Applicability is per client, not per control

The baseline file will hold only control IDs, tiers and the governance fields above. Whether a control applies to a given tenant comes from the tenant: license gating (`Config/license-service-plans.json` and the tenant's own SKUs), the third-party EDR declaration (`-ThirdPartyEDR`, `clients.json`), and a per-client exceptions file (control ID, reason, compensating control, approver, start date, review date, expiry — an exception past its review date is a finding again). The compliance view keeps three things separate rather than one status enum:

- **Observed** (from the finding): Satisfied / Failed / NotApplicable / NotVerified
- **Constraint** (from licensing): None / LicenseBlocked
- **Disposition** (from the exceptions file): Normal / ApprovedException

A control that produced no verdict this run, or whose evidence is older than its freshness class allows, is **NotVerified**, never Satisfied, whatever it was last month. The display status is derived from the three, and the precedence is to be stress-tested during implementation, not fixed here.

## Results contract

The assessment stays stateless. It emits facts; the PSA or a future operations layer owns ticket state, acknowledgment and remediation clocks. Per baseline control, `results.json` will carry:

`ControlId`, `BaselineVersion`, `TargetTier`, `ObservedState`, `EvidenceTimestamp`, `EvidenceSource`, `EffectivenessState`, `RegressionFlag`, `ExceptionState`

plus a `BaselineCompliance` summary (counts by observed state, constraint and disposition, per tier) and `BaselineRegressions[]` (client, control, baseline tier, previous, current, detected, action). A prior run's baseline version is recorded so a drop between v1.0 and v1.1 can be read as "the standard changed", not "the client got worse".

## Counts

| Tier | Rows | Checked by the tool | Manual (CIS-<number>) |
|---|---|---|---|
| Minimum | 114 | 46 | 68 |
| Standard | 16 | 3 | 13 |
| Hardened | 59 | 21 | 38 |
| Assessment-only controls | 134 | | |

All 160 v7.0.0 recommendations are represented; 70 rows are tool-checked controls and 119 are manual. Effectiveness is read for five rows, from the sign-in log (`AAD-SignInEvidence`, the last 30 days): AAD-1.2 and CIS-5.2.2.1 (no successful interactive sign-in that needed only one factor, for all users and for privileged-role holders), CIS-5.2.2.3, EXO-1.6 and SPO-1.3 (no successful sign-in through a legacy authentication client, tenant-wide, to Exchange Online and to SharePoint Online). Every other row's `EffectivenessCapability` is `NotCollected`.

## Every assessment control

One row per control in `controls.json`; the tier column is what the test compares with `tp-baseline.json`.

| Control | Title | Severity | License requirement | CIS v7.0.0 | Tier |
|---|---|---|---|---|---|
| AAD-1.1 | Legacy Authentication Blocked | Critical | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| AAD-1.2 | MFA Required for All Users | Critical | M365 Business Premium or Entra ID P1 | 5.2.2.2 | **Minimum** |
| AAD-1.3 | Phishing-Resistant MFA Required for Admins | Critical | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| AAD-2.1 | Conditional Access Policies Deployed | High | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| AAD-3.1 | Global Administrator Count 2-4, Cloud-Only | High | Included (all plans) | 1.1.3 | **Minimum** |
| EXO-1.1 | Mailbox Audit Logging Enabled | High | Included (M365 Business Standard+) | 6.1.1 | **Minimum** |
| EXO-1.2 | SMTP Client Authentication Disabled | High | Included (M365 Business Standard+) | 6.5.4 | **Minimum** |
| EXO-1.3 | External Auto-Forwarding Blocked | High | Included (M365 Business Standard+) | 6.2.1 | **Minimum** |
| EXO-1.4 | DKIM Signing Enabled for All Domains | High | Included (M365 Business Standard+) | 2.1.9 | **Minimum** |
| EXO-1.5 | Anti-Phishing Impersonation Protection Enabled | High | Defender for Office 365 Plan 1 (M365 Business Premium) | — | **Assessment-only** |
| EXO-1.6 | Modern Authentication Enabled | Critical | Included (M365 Business Standard+) | 6.5.1 | **Minimum** |
| EXO-1.7 | Honor DMARC Policy Enabled | High | Included (M365 Business Standard+) | 2.1.7 | **Hardened** |
| DNS-1.1 | SPF Record Published | High | Included (M365 Business Standard+) | 2.1.8 | **Minimum** |
| DNS-1.2 | DKIM Records Published | High | Included (M365 Business Standard+) | — | **Assessment-only** |
| DNS-1.3 | DMARC Policy at Quarantine or Reject | Critical | Included (M365 Business Standard+) | — | **Assessment-only** |
| DNS-1.4 | MTA-STS Policy in Enforce Mode | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| DNS-1.5 | TLS-RPT Record Published | Low | Included (M365 Business Standard+) | — | **Assessment-only** |
| DNS-1.6 | DNSSEC Enabled | Low | Included (M365 Business Standard+) | — | **Assessment-only** |
| DNS-2.1 | DKIM Key Rotation Cadence | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| DNS-2.2 | CAA Record Restricts Certificate Issuance | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| DNS-2.3 | TLS Certificate Expiry on Mail Hostnames | High | Included (M365 Business Standard+) | — | **Assessment-only** |
| DNS-2.4 | Certificate Transparency Log Hygiene | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| DEF-1.1 | Safe Attachments Enabled with Block Action | High | Defender for Office 365 Plan 1 (M365 Business Premium) | 2.1.4 | **Hardened** |
| DEF-1.2 | Safe Links Enabled and Hardened | High | Defender for Office 365 Plan 1 (M365 Business Premium) | 2.1.1 | **Hardened** |
| DEF-1.3 | Spoof Intelligence Enabled | High | Included (EOP) | 2.1.7 | **Hardened** |
| DEF-1.4 | Honor DMARC Policy (Defender Layer) | High | Included (EOP) | 2.1.7 | **Hardened** |
| DEF-1.5 | Phishing Threshold Level Aggressive | Low | Included (EOP) | 2.1.7 | **Hardened** |
| DEF-1.6 | First Contact Safety Tip Enabled | Low | Included (EOP) | 2.1.7 | **Hardened** |
| SPO-1.1 | External Sharing Restricted | High | Included (M365 Business Standard+) | 7.2.3 | **Minimum** |
| SPO-1.2 | Default Sharing Link Not Anonymous | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| SPO-1.3 | SharePoint Legacy Authentication Blocked | High | Included (M365 Business Standard+) | 7.2.1 | **Minimum** |
| SPO-1.4 | Guest Access Expiration Configured | Medium | Included (M365 Business Standard+) | 7.2.9 | **Minimum** |
| SPO-1.5 | Unmanaged Device Access Restricted | Medium | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| TMS-1.1 | External Federation Access Restricted | Medium | Included (M365 Business Standard+) | 8.2.1 | **Hardened** |
| TMS-1.2 | Teams Consumer Account Access Disabled | Medium | Included (M365 Business Standard+) | 8.2.2 | **Minimum** |
| TMS-1.3 | Anonymous Meeting Join Disabled | Medium | Included (M365 Business Standard+) | 8.5.1 | **Hardened** |
| TMS-1.4 | External Participants Cannot Take Screen Control | Low | Included (M365 Business Standard+) | 8.5.7 | **Minimum** |
| TMS-1.5 | Recording Storage in Organization | Low | M365 Business Premium or E3+ | — | **Assessment-only** |
| TMS-1.6 | Teams Guest Access Controlled | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| PVW-1.1 | Unified Audit Log Enabled | Critical | Included (M365 Business Standard+) | 3.1.1 | **Minimum** |
| PVW-1.2 | Audit Log Retention Minimum 90 Days | Medium | Included (all plans) | — | **Assessment-only** |
| PVW-1.3 | DLP Policy Active for Sensitive Data | High | M365 Business Premium or E3+ | 3.2.1 | **Minimum** |
| PVW-1.4 | Sensitivity Labels Published | Medium | M365 Business Premium or E3+ | 3.3.1 | **Minimum** |
| INT-1.1 | Device Compliance Policies Configured | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-1.2 | Non-Compliant Device Access Blocked via CA | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-1.3 | BitLocker Encryption Required on Windows | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-1.4 | Mobile Application Management Configured | Medium | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-1.5 | Antivirus Policy Deployed via Intune | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| PPL-1.1 | Power Platform Tenant Isolation Enabled | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| PPL-1.2 | Power Platform DLP Policy Active | High | Included (M365 Business Standard+) | — | **Assessment-only** |
| PPL-1.3 | Power Platform Environment Creation Restricted | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| EXO-2.3 | POP3 Access Disabled | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| EXO-2.4 | IMAP Access Disabled | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| EXO-2.5 | Customer Lockbox Enabled | Medium | M365 E5 or E5 Compliance add-on | 1.3.6 | **Hardened** |
| EXO-2.6 | Shared Mailboxes Block Direct Sign-In | High | Included (M365 Business Standard+) | — | **Assessment-only** |
| AAD-1.4 | Sign-in Risk CA Policy | High | Entra ID P2 | — | **Assessment-only** |
| AAD-1.5 | User Risk CA Policy | High | Entra ID P2 | — | **Assessment-only** |
| AAD-2.2 | Named Locations Defined | Low | M365 Business Premium or Entra ID P1 | 5.2.2.14 | **Hardened** |
| AAD-2.3 | Device Compliance Enforced via CA | High | M365 Business Premium or Entra ID P1 + Intune | — | **Assessment-only** |
| AAD-3.2 | No Permanent Admin Role Assignments | High | Entra ID P2 | — | **Assessment-only** |
| AAD-3.3 | PIM Requires MFA on Activation | High | Entra ID P2 | — | **Assessment-only** |
| AAD-3.4 | PIM Requires Justification on Activation | Medium | Entra ID P2 | — | **Assessment-only** |
| AAD-3.5 | PIM GA Activation Requires Approval | Medium | Entra ID P2 | 5.3.4 | **Standard** |
| AAD-3.6 | PIM Max Activation Duration 8 Hours or Less | Low | Entra ID P2 | — | **Assessment-only** |
| AAD-4.1 | Guest Invite Permissions Restricted | High | Included (all plans) | 5.1.6.3 | **Hardened** |
| AAD-4.2 | External Collaboration Settings Restricted | Medium | Included (all plans) | 5.1.2.3 | **Minimum** |
| AAD-4.3 | B2B Guest Default Permissions Restricted | High | Included (all plans) | 5.1.6.2 | **Minimum** |
| AAD-5.1 | Self-Service Password Reset Enabled | Medium | Included (all plans) | 5.2.4.1 | **Minimum** |
| AAD-5.2 | SSPR Requires Multiple Authentication Methods | Medium | Included (all plans) | 5.2.4.2 | **Hardened** |
| AAD-6.1 | User App Registration Disabled | High | Included (all plans) | 5.1.2.2 | **Minimum** |
| AAD-6.2 | User Consent to Apps Restricted | Critical | Included (all plans) | — | **Assessment-only** |
| AAD-6.3 | Admin Consent Workflow Enabled | Medium | Included (all plans) | 5.1.5.2 | **Minimum** |
| AAD-7.1 | Password Protection Lockout Configured | Medium | Included (all plans) | 5.2.3.8 | **Minimum** |
| AAD-7.2 | Break-Glass Accounts Configured | High | Included (all plans) | 1.1.2 | **Minimum** |
| DEF-2.1 | Preset Security Policies Applied | Low | Defender for Office 365 Plan 1 (M365 Business Premium) | — | **Assessment-only** |
| DEF-2.2 | Zero-Hour Auto Purge Enabled | High | Included (EOP) | — | **Assessment-only** |
| DEF-2.3 | Anti-Malware Common Attachments Blocked | High | Included (EOP) | 2.1.2 | **Minimum** |
| DEF-2.4 | Phishing Directed to Quarantine Not Junk | High | Included (EOP) | — | **Assessment-only** |
| DEF-2.5 | High Confidence Spam to Quarantine | Medium | Included (EOP) | — | **Assessment-only** |
| DEF-2.6 | Bulk Mail Threshold Configured | Low | Included (EOP) | — | **Assessment-only** |
| EXO-3.1 | Connection Filter Safe List Bypass Disabled | Medium | Included (M365 Business Standard+) | 2.1.13 | **Minimum** |
| EXO-3.2 | Outbound Spam Sending Limits Configured | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| EXO-3.3 | Alert Policy — Email Forwarding Rules | High | Included (M365 Business Standard+) | — | **Assessment-only** |
| EXO-3.4 | Alert Policy — Unusual Mail Volume | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| EXO-3.5 | Transport Rules Changes Audited | Medium | Included (M365 Business Standard+) | 3.1.1 | **Minimum** |
| SPO-2.1 | OneDrive Sync Client Restricted to Managed Devices | High | Included (M365 Business Standard+) | — | **Assessment-only** |
| SPO-2.2 | External Sharing Link Expiration Configured | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| SPO-2.3 | SharePoint Third-Party Apps From Store Restricted | Low | Included (M365 Business Standard+) | — | **Assessment-only** |
| SPO-2.4 | Custom Script Disabled on SharePoint Sites | High | Included (M365 Business Standard+) | — | **Assessment-only** |
| SPO-2.5 | Third-Party Cloud Storage Connectors Disabled | Medium | Included (M365 Business Standard+) | 8.1.1 | **Hardened** |
| SPO-2.6 | Email Attestation Required for Sharing | Medium | Included (M365 Business Standard+) | 7.2.10 | **Minimum** |
| SPO-2.7 | Reauthentication Required for Sharing Links | Low | Included (M365 Business Standard+) | 7.2.10 | **Minimum** |
| SPO-2.8 | OneDrive Sync Restricted by Tenant Domain GUID | High | Included (M365 Business Standard+) | — | **Assessment-only** |
| TMS-2.1 | Skype Consumer Contact Disabled | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| TMS-2.2 | Unverified App Publisher Blocked | Medium | Included (M365 Business Standard+) | 8.4.1 | **Minimum** |
| TMS-2.3 | Third-Party Cloud Storage Disabled in Teams | High | Included (M365 Business Standard+) | 8.1.1 | **Hardened** |
| TMS-2.4 | Teams Email Integration Disabled | High | Included (M365 Business Standard+) | 8.1.2 | **Minimum** |
| TMS-2.5 | Cloud Recording Disabled for External Participants | Low | Included (M365 Business Standard+) | — | **Assessment-only** |
| TMS-2.6 | Broad Channel Meeting Invite Restricted | Low | Included (M365 Business Standard+) | — | **Assessment-only** |
| TMS-2.7 | External User Chat Restricted | Medium | Included (M365 Business Standard+) | 8.2.1 | **Hardened** |
| TMS-2.8 | PSTN Users Cannot Bypass Lobby | Medium | Included (M365 Business Standard+) | 8.5.4 | **Minimum** |
| PVW-2.1 | Purview Audit Log Search Enabled | High | Included (M365 Business Standard+) | 3.1.1 | **Minimum** |
| PVW-2.2 | Communication Compliance Policy Active | Low | M365 E5 Compliance add-on | — | **Assessment-only** |
| PVW-2.3 | Information Barriers Mode Configured | Low | M365 E5 Compliance add-on | — | **Assessment-only** |
| PVW-2.4 | Insider Risk Management Policy Active | Medium | M365 E5 Compliance add-on | — | **Assessment-only** |
| PVW-2.5 | Retention Policy Covers Key Workloads | High | M365 Business Premium or E3+ | — | **Assessment-only** |
| PVW-2.6 | Auto-Labeling Policy Active | Medium | M365 E5 Compliance add-on | — | **Assessment-only** |
| INT-2.1 | Endpoint Detection and Response Policy Deployed | Critical | Microsoft Defender for Endpoint Plan 2 or Defender for Business (M365 Business Premium) | — | **Assessment-only** |
| INT-2.2 | Attack Surface Reduction Rules Enabled | High | Microsoft Defender for Endpoint Plan 1+ | — | **Assessment-only** |
| INT-2.3 | Windows Firewall Policy Deployed via Intune | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-2.4 | macOS FileVault Encryption Required | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-2.5 | Windows Update Compliance Policy Deployed | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| AAD-8.1 | PIM Alerts Configured | Medium | Entra ID P2 | — | **Assessment-only** |
| AAD-8.2 | Access Reviews for Privileged Roles | High | Entra ID P2 | — | **Assessment-only** |
| AAD-9.1 | Authenticator Number Matching Enabled | High | Included (all plans) | 5.2.3.1 | **Minimum** |
| AAD-9.2 | Passwordless Authentication Methods Available | Low | Included (all plans) | — | **Assessment-only** |
| AAD-10.1 | Identity Protection Risky User Workflow | High | Entra ID P2 | — | **Assessment-only** |
| AAD-10.2 | Privileged Accounts Use Dedicated Cloud-Only Accounts | High | Included (all plans) | — | **Assessment-only** |
| AAD-10.3 | Break-Glass Account Sign-In Monitoring | High | Included (all plans) | 2.2.1 | **Standard** |
| AAD-10.4 | Sign-in Frequency Session Control Configured | Medium | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| EXO-4.1 | Mailbox Audit Log Age Limit Sufficient | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| EXO-4.2 | Admin Audit Log Enabled | High | Included (M365 Business Standard+) | — | **Assessment-only** |
| EXO-4.3 | Safe Attachments for SharePoint OneDrive Teams Enabled | High | Defender for Office 365 Plan 1 (M365 Business Premium) | 2.1.5 | **Hardened** |
| EXO-4.4 | Anti-Spam Inbound Policy Properly Configured | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| DEF-3.1 | Unauthenticated Sender Indicator Enabled | Medium | Included (EOP) | — | **Assessment-only** |
| DEF-3.2 | Via Tag Enabled in Anti-Phishing Policy | Low | Included (EOP) | — | **Assessment-only** |
| DEF-3.3 | Defender for Cloud Apps Connected | Medium | Microsoft Defender for Cloud Apps (M365 E5 or add-on) | 2.4.3 | **Hardened** |
| DEF-3.4 | Defender Alert Email Notifications Configured | High | Included (all plans) | — | **Assessment-only** |
| SPO-3.1 | Site Collection Admin Access Reviewed | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| SPO-3.2 | SharePoint Sharing Notifications Enabled | Low | Included (M365 Business Standard+) | — | **Assessment-only** |
| SPO-3.3 | OneDrive Version History Enabled | High | Included (M365 Business Standard+) | — | **Assessment-only** |
| SPO-3.4 | SharePoint Guest Access Expiration Required | Medium | Included (M365 Business Standard+) | 7.2.9 | **Minimum** |
| TMS-3.1 | Teams Meeting Watermarks Enabled | Low | Teams Premium (add-on) | — | **Assessment-only** |
| TMS-3.2 | Auto-Admit Only Authenticated Organization Users | High | Included (M365 Business Standard+) | 8.5.3 | **Minimum** |
| TMS-3.3 | Meeting Chat Disabled for Anonymous Participants | Medium | Included (M365 Business Standard+) | 8.5.5 | **Hardened** |
| TMS-3.4 | Meeting Chat Copy Prevention via DLP | Low | Included (M365 Business Standard+) | — | **Assessment-only** |
| PVW-3.1 | Audit Logs Exported to SIEM | Medium | Microsoft Sentinel (add-on) or Defender XDR | — | **Assessment-only** |
| PVW-3.2 | eDiscovery Case Management Configured | Medium | M365 Business Premium or E3+ | — | **Assessment-only** |
| PVW-3.3 | Compliance Score Improvement Actions Tracked | Low | Included (all plans) | — | **Assessment-only** |
| PVW-3.4 | Sensitive Information Types Used in DLP Policies | High | M365 Business Premium or E3+ | — | **Assessment-only** |
| INT-3.1 | Device Enrollment Restrictions Configured | Medium | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-3.2 | Mobile App Configuration Policies Deployed | Low | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-3.3 | Conditional Launch Policies Configured | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| PPL-2.1 | Power Platform Connector Classification Reviewed | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| PPL-2.2 | Power Automate Governance Policy Active | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| PPL-2.3 | Power Apps Portal Creation Restricted | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| AAD-11.1 | Device Code Authentication Flow Blocked | High | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| AAD-11.2 | No Guest Accounts in Highly Privileged Roles | Critical | Included (all plans) | — | **Assessment-only** |
| AAD-11.3 | Risky Service Principals Reviewed and Remediated | High | Entra ID P2 + Workload Identities add-on | — | **Assessment-only** |
| AAD-11.4 | Token Protection (Session Binding) Enforced | High | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| AAD-11.5 | Continuous Access Evaluation Strict Mode | Low | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| AAD-11.6 | Cross-Tenant Inbound Trust Settings Restricted | High | Included (all plans) | — | **Assessment-only** |
| AAD-11.7 | Privileged Access Workstation or Device Scope for Admins | Medium | M365 Business Premium or Entra ID P1 + Intune | — | **Assessment-only** |
| AAD-11.8 | Terms of Use Policy Enforced | Low | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| AAD-11.9 | Workload Identity Conditional Access Policy | Medium | Entra Workload Identities Premium (add-on) | — | **Assessment-only** |
| DEF-4.1 | DLP Policy Covers All Key Workloads | High | M365 Business Premium or E3+ | 3.2.1 | **Minimum** |
| DEF-4.2 | DLP Policy Uses Sensitive Information Types | High | M365 Business Premium or E3+ | — | **Assessment-only** |
| DEF-4.3 | Risky OAuth Application Alerts Configured | High | Included (all plans) | — | **Assessment-only** |
| DEF-4.4 | Priority Accounts Tagged in Defender | Medium | Defender for Office 365 Plan 2 (M365 E5 or add-on) | 2.4.1 | **Standard** |
| DEF-4.5 | Endpoint DLP Policy Active on Managed Devices | High | M365 E5 or E5 Compliance add-on | — | **Assessment-only** |
| DEF-4.6 | Attack Simulation Training Campaigns Active | Low | Defender for Office 365 Plan 2 (M365 E5 or add-on) | — | **Assessment-only** |
| DEF-4.7 | Safe Links Protects Office Applications | High | Defender for Office 365 Plan 1 (M365 Business Premium) | 2.1.1 | **Hardened** |
| EXO-5.1 | Per-User Mailbox Audit Logging Enabled for All Mailboxes | High | Included (all plans) | 6.1.1 | **Minimum** |
| EXO-5.2 | Priority Account Protection Active in Anti-Phishing Policy | Medium | Defender for Office 365 Plan 1 (M365 Business Premium) | — | **Assessment-only** |
| EXO-5.3 | No Allowed Sender Domains Bypassing Anti-Spam Filtering | High | Included (all plans) | 2.1.14 | **Minimum** |
| TMS-4.1 | Meeting Recording Expiration Configured | Medium | Included (M365 Business Standard+) | — | **Assessment-only** |
| TMS-4.2 | Anonymous Users Cannot Start Meetings | High | Included (all plans) | 8.5.2 | **Minimum** |
| TMS-4.3 | Teams External Domain Federation Restricted to Allowlist | High | Included (all plans) | 8.2.1 | **Hardened** |
| TMS-4.4 | Teams Events Cannot Be Attended by Anonymous Internet Users | Medium | Included (all plans) | — | **Assessment-only** |
| INT-4.1 | Windows LAPS Deployed via Intune | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-4.2 | Windows Hello for Business Deployed | Medium | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-4.3 | Device OS Version Compliance Enforced | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| INT-4.4 | Mobile Device Compliance Requires PIN or Biometric | High | M365 Business Premium or Intune Plan 1 | — | **Assessment-only** |
| PVW-4.1 | Microsoft Purview Audit (Premium) Enabled | High | M365 E5 or E5 Compliance add-on | — | **Assessment-only** |
| PVW-4.2 | Audit Log Retention Policy Extends to 1 Year or More | High | M365 E5 or E5 Compliance add-on | — | **Assessment-only** |
| PVW-4.3 | Sensitivity Labels Defined and Published | High | M365 Business Premium or E3+ | 3.3.1 | **Minimum** |
| PVW-4.4 | Records Management Labels Configured for Regulated Data | Low | M365 E5 or E5 Compliance add-on | — | **Assessment-only** |
| PPL-3.1 | M365 Copilot Sensitivity Label Enforcement | High | M365 Business Premium or E3+ (Copilot requires M365 Copilot add-on) | — | **Assessment-only** |
| PPL-3.2 | DLP Policy Active for Copilot Interactions | High | M365 E5 Compliance add-on | — | **Assessment-only** |
| PPL-3.3 | Copilot Access Restricted to Licensed Users | Medium | M365 Copilot add-on license | — | **Assessment-only** |
| PPL-3.4 | Copilot Studio Agent Publishing Governed | High | Power Platform + Copilot Studio license | — | **Assessment-only** |
| PPL-3.5 | Copilot Interaction Audit Logging Active | High | Included (all plans) | 3.1.1 | **Minimum** |
| AAD-12.1 | Users Without MFA — Named List | Critical | Included (all plans) | 5.2.3.4 | **Minimum** |
| AAD-12.2 | Stale Guest Accounts — Named List | High | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| AAD-12.3 | Stale Licensed Member Accounts — Named List | High | M365 Business Premium or Entra ID P1 | — | **Assessment-only** |
| AAD-12.4 | OAuth Apps with Tenant-Wide Consent — Named List | High | Included (all plans) | — | **Assessment-only** |
| EXO-6.1 | Mailboxes with External Email Forwarding — Named List | Critical | Included (all plans) | — | **Assessment-only** |
| EXO-6.2 | Shared Mailboxes with Sign-In Enabled — Named List | High | Included (all plans) | 1.2.2 | **Minimum** |
| EXO-6.3 | Mailboxes with Audit Logging Disabled — Named List | High | Included (all plans) | 6.1.3 | **Minimum** |
| EXO-6.4 | Per-User SMTP AUTH Override — Named List | High | Included (all plans) | — | **Assessment-only** |
| AAD-13.1 | Microsoft Secure Score | Medium | Included (all plans) | — | **Assessment-only** |
| EXO-7.1 | No Mailbox Forwarding to External Addresses | High | Included (all plans) | — | **Assessment-only** |
| EXO-7.2 | No Inbox Rules Forwarding Externally | High | Included (all plans) | — | **Assessment-only** |
| EXO-7.3 | No Mailboxes with Per-User Audit Explicitly Disabled | Medium | Included (all plans) | 6.1.3 | **Minimum** |
| EXO-7.4 | No Per-User SMTP AUTH Overrides | High | Included (all plans) | — | **Assessment-only** |
| EXO-8.1 | Mail Flow Connectors Reviewed and Hardened | High | Included (EOP) | — | **Assessment-only** |
| EXO-8.2 | No Transport Rule Redirects Mail Externally | Critical | Included (EOP) | 6.2.1 | **Minimum** |
| AAD-14.1 | Application Credentials Current and Short-Lived | High | Included (Entra ID Free) | — | **Assessment-only** |
| AAD-15.1 | No Application Holds Tenant-Takeover Permissions | Critical | Included (all plans) | — | **Assessment-only** |
| AAD-15.2 | Applications with Tenant-Wide Data Permissions — Named List | High | Included (all plans) | — | **Assessment-only** |
| DEF-5.1 | Tenant Allow/Block List Entries Time-Boxed | High | Included (EOP) | — | **Assessment-only** |
| EXO-9.1 | Mailboxes Protected by Hold or Retention Policy | High | Exchange Online Plan 2 or Exchange Online Archiving (M365 Business Premium, E3, E5) | — | **Assessment-only** |
| EXO-9.2 | Deleted Item Retention Window at Maximum | Medium | Included (all plans) | — | **Assessment-only** |
| SPO-4.1 | Departed-User OneDrive Retention Configured | Medium | Included (all plans) | — | **Assessment-only** |

## Manual CIS rows

Required at their tier, always NotVerified until a control checks them.

| Row | Recommendation | Profile | Tier |
|---|---|---|---|
| `CIS-1.1.1` | Ensure Administrative accounts are cloud-only | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-1.1.2` | Ensure two emergency access accounts have been defined: the settings AAD-7.2 do not check | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-1.1.4` | Ensure administrative accounts use licenses with a reduced application footprint | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-1.3.1` | Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)' | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-1.3.4` | Ensure 'User owned apps and services' is restricted | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-1.3.5` | Ensure internal phishing protection for Forms is enabled | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-1.3.9` | Ensure shared bookings pages are restricted to select users | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-2.1.3` | Ensure notifications for internal users sending malware is Enabled | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-2.1.6` | Ensure Exchange Online Spam Policies are set to notify administrators | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-2.1.10` | Ensure DMARC records for all Exchange Online domains are published | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-2.1.12` | Ensure the connection filter IP allow list is not used | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-2.1.15` | Ensure outbound anti-spam message limits are in place | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-4.1` | Ensure devices without a compliance policy are marked 'not compliant' | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-4.2` | Ensure device enrollment for personally owned devices is blocked by default | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.2.1` | Ensure 'Per-user MFA' is disabled | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.2.4` | Ensure access to the Entra admin center is restricted | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.3.1` | Ensure users cannot create security groups | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.3.3` | Ensure that 'Owners can manage group membership requests in My Groups' is set to 'No' | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.4.2` | Ensure the maximum number of devices per user is limited | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.4.3` | Ensure the GA role is not added as a local administrator during Entra join | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.4.4` | Ensure local administrator assignment is limited during Entra join | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.4.5` | Ensure Local Administrator Password Solution is enabled | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.5.4` | Ensure password lifetime for applications does not exceed 180 days | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.5.5` | Ensure new application passwords are system-generated | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.5.6` | Ensure maximum certificate lifetime for applications does not exceed 180 days | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.1.8.1` | Ensure that password hash sync is enabled for hybrid deployments | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.2.1` | Ensure multifactor authentication is enabled for all users in administrative roles | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.2.3` | Enable Conditional Access policies to block legacy authentication | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.2.4` | Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.2.9` | Ensure a managed device is required for authentication | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.2.10` | Ensure a managed device is required to register security information | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.2.11` | Ensure sign-in frequency for Intune Enrollment is set to 'Every time' | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.2.12` | Ensure the device code sign-in flow is blocked | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.2.13` | Ensure that periodic reauthentication is required for all users | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.2.17` | Ensure authentication transfer is blocked | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.3.1` | Ensure Microsoft Authenticator is configured to protect against MFA fatigue: the settings AAD-9.1 do not check | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.3.2` | Ensure custom banned passwords lists are used | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.3.3` | Ensure password protection is enabled for on-prem Active Directory | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.3.5` | Ensure weak authentication methods are disabled | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.3.6` | Ensure system-preferred multifactor authentication is enabled | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.3.9` | Ensure that Account 'Lockout duration in seconds' is at least 60 seconds | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.3.10` | Ensure Microsoft Authenticator on companion applications is disabled | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.4.3` | Ensure SSPR registration and authentication re-confirmation are required | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.4.4` | Ensure that users are notified on password resets | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-5.2.4.5` | Ensure all admins are notified when other admins reset their password | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-6.1.2` | Ensure mailbox audit actions are configured | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-6.2.1` | Ensure all forms of mail forwarding are blocked and/or disabled: the settings EXO-1.3, EXO-8.2 do not check | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-6.2.2` | Ensure mail transport rules do not whitelist specific domains | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-6.2.3` | Ensure email from external senders is identified | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-6.3.2` | Ensure the ability to add personal email accounts and calendars is disabled | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-6.5.2` | Ensure MailTips are enabled for end users | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-7.2.2` | Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-7.2.7` | Ensure link sharing is restricted in SharePoint and OneDrive | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-7.2.11` | Ensure the SharePoint default sharing link permission is set | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-8.2.3` | Ensure external Teams users cannot initiate conversations | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-8.2.4` | Ensure the organization cannot communicate with accounts in trial Teams tenants | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-8.4.1` | Ensure app permission policies are configured: the settings TMS-2.2 do not check | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.1` | Ensure guest user access is restricted | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.2` | Ensure external user invitations are restricted | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.3` | Ensure guest access to content is restricted | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.4` | Ensure 'Publish to web' is restricted | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.6` | Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled' | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.7` | Ensure shareable links are restricted | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.8` | Ensure enabling of external data sharing is restricted | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.9` | Ensure 'Block ResourceKey Authentication' is 'Enabled' | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.10` | Ensure access to APIs by service principals is restricted | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.11` | Ensure service principals cannot create and use profiles | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-9.1.12` | Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted | E3 Level 1 / E5 Level 1 | Minimum |
| `CIS-2.4.1` | Ensure Priority account protection is enabled and configured: the settings DEF-4.4 do not check | E5 Level 1 | Standard |
| `CIS-2.4.2` | Ensure Priority accounts have 'Strict protection' presets applied | E5 Level 1 | Standard |
| `CIS-2.4.4` | Ensure Zero-hour auto purge for Microsoft Teams is on | E5 Level 1 | Standard |
| `CIS-2.4.5` | Ensure 'AIR' remediation is enabled | E5 Level 1 | Standard |
| `CIS-3.2.2` | Ensure DLP policies are enabled for Microsoft Teams | E5 Level 1 | Standard |
| `CIS-3.2.3` | Ensure DLP policies are published for Copilot users | E5 Level 1 | Standard |
| `CIS-5.2.2.6` | Enable Identity Protection user risk policies | E5 Level 1 | Standard |
| `CIS-5.2.2.7` | Enable Identity Protection sign-in risk policies | E5 Level 1 | Standard |
| `CIS-5.3.2` | Ensure 'Access reviews' for guest users are configured | E5 Level 1 | Standard |
| `CIS-5.3.3` | Ensure 'Access reviews' for privileged roles are configured | E5 Level 1 | Standard |
| `CIS-5.3.4` | Ensure approval is required for Global Administrator role activation: the settings AAD-3.5 do not check | E5 Level 1 | Standard |
| `CIS-5.3.5` | Ensure approval is required for Privileged Role Administrator activation | E5 Level 1 | Standard |
| `CIS-8.6.1` | Ensure users can report security concerns in Teams | E5 Level 1 | Standard |
| `CIS-1.2.1` | Ensure that only organizationally managed/approved public groups exist | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-1.3.2` | Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-1.3.3` | Ensure 'External sharing' of calendars is not available | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-1.3.7` | Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web' | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-1.3.8` | Ensure that Sways cannot be shared with people outside of your organization | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-2.1.1` | Ensure Safe Links for Office Applications is Enabled: the settings DEF-1.2, DEF-4.7 do not check | E5 Level 2 | Hardened |
| `CIS-2.1.4` | Ensure Safe Attachments policy is enabled: the settings DEF-1.1 do not check | E5 Level 2 | Hardened |
| `CIS-2.1.5` | Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled: the settings EXO-4.3 do not check | E5 Level 2 | Hardened |
| `CIS-2.1.7` | Ensure that an anti-phishing policy has been created: the settings DEF-1.3, DEF-1.4, DEF-1.5, DEF-1.6, EXO-1.7 do not check | E5 Level 2 | Hardened |
| `CIS-2.1.11` | Ensure comprehensive attachment filtering is applied | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-2.4.3` | Ensure Microsoft Defender for Cloud Apps is enabled and configured: the settings DEF-3.3 do not check | E5 Level 2 | Hardened |
| `CIS-5.1.2.5` | Ensure the option to remain signed in is hidden | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.1.2.6` | Ensure 'LinkedIn account connections' is disabled | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.1.3.2` | Ensure that 'Restrict user ability to access groups features in My Groups' is set to 'Yes' | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.1.3.4` | Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No' | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.1.4.1` | Ensure the ability to join devices to Entra is restricted | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.1.4.6` | Ensure users are restricted from recovering BitLocker keys | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.1.5.1` | Ensure user consent to apps accessing company data on their behalf is not allowed | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.1.5.3` | Ensure password addition is blocked for applications | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.1.6.1` | Ensure that collaboration invitations are sent to allowed domains only | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.2.2.5` | Ensure 'Phishing-resistant MFA strength' is required for Administrators | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.2.2.8` | Ensure 'sign-in risk' is blocked for medium and high risk | E5 Level 2 | Hardened |
| `CIS-5.2.2.15` | Ensure exclusionary geographic access controls are utilized | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.2.2.16` | Ensure Token Protection is enforced for session tokens | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.2.3.7` | Ensure the email OTP authentication method is disabled | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-5.3.1` | Ensure privileged role assignments are activated and not assigned | E5 Level 2 | Hardened |
| `CIS-6.3.1` | Ensure users installing Outlook add-ins is not allowed | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-6.5.3` | Ensure additional storage providers are restricted in Outlook on the web | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-6.5.5` | Ensure Direct Send submissions are rejected | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-7.2.4` | Ensure OneDrive content sharing is restricted | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-7.2.5` | Ensure that SharePoint guest users cannot share items they don't own | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-7.2.6` | Ensure SharePoint external sharing is restricted | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-7.2.8` | Ensure external sharing is restricted by security group | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-7.3.1` | Ensure Office 365 SharePoint infected files are disallowed for download | E5 Level 2 | Hardened |
| `CIS-8.5.6` | Ensure only organizers and co-organizers can present | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-8.5.8` | Ensure external meeting chat is off | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-8.5.9` | Ensure meeting recording is off by default | E3 Level 2 / E5 Level 2 | Hardened |
| `CIS-9.1.5` | Ensure 'Interact with and share R and Python' visuals is 'Disabled' | E3 Level 2 / E5 Level 2 | Hardened |

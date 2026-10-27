# NRG and CISA ScubaGear: alignment of requirements

Checked against the released **ScubaGear v2.0.0** (tag commit `6e5a1a4`, 2026-10-22; released 2026-10-27) and its official migration file (`PowerShell/ScubaGear/mappings/scuba-baseline-policy-migrations.csv`, SHA-256 `f53e082bd23db880…`, 56 rows) on 2026-10-27. The data behind this page is `Config/scuba-alignment.json` (read by `Get-TPScubaAlignment`); a test keeps the two in step with `Config/controls.json`.

**Release review (2026-10-27).** The first check, on 2026-09-30, read the migration file at commit `df84e9d` (SHA-256 `471085b4b3504fdd…`, 55 rows). The release adds one row (`MS.SHAREPOINT.3.3v1` to `v2`: the rule now also applies when the external sharing slider is set to Existing guests), corrects several old-id descriptions, and corrects the range targets of `MS.DEFENDER.1.2v1` to `1.5v1` to `MS.SECURITYSUITE.1.1v1 - MS.SECURITYSUITE.1.4v1` (the earlier copy read `1.4v2` to `1.4v5`). No current id NRG cites changed, and the 109 current policy ids in the released baselines equal `Config/framework-baselines/scuba-ids-v2.0.0.txt`. The released text of every cited rule was compared with `df84e9d`: the changes are editorial (wording, punctuation, admin center navigation) except two. `MS.SECURITYSUITE.5.2v1` now reads "retained and searchable for a minimum of 3 months and retrievable for a minimum of 12 months" in place of the OMB M-21-31 minimum; the notes for EXO-4.1, PVW-1.2 and PVW-4.2 already judge that text. `MS.TEAMS.4.1v1`'s instructions now also ask that the accepted SMTP domains list stay empty; TMS-2.4 and ScubaGear's automated check both read `AllowEmailIntoChannel` only, so TMS-2.4 stays Equivalent with the note. Three entries changed in substance: SPO-2.7 (reviewed against the v2 text; Partial, stricter), PPL-1.1 (strength recorded as SHALL) and TMS-2.4 (note); the five entries that record a `MS.DEFENDER.1.2v1` or `1.3v1` migration now carry the corrected range.

**Citations added 2026-10-27.** Seven ScubaGear v2.0.0 policies were checked against their released text and Rego check and against the NRG evaluators that judge the same setting: `MS.AAD.3.5v2` (AAD-17.3 for SMS and voice call, AAD-17.5 for email OTP, each Partial), `MS.AAD.6.1v1` (AAD-7.5, Partial, stricter), `MS.EXO.6.2v1` (EXO-10.1, Partial, stricter and different from ScubaGear's automated check on disabled policies), `MS.SHAREPOINT.1.2v1` (SPO-5.3, Partial, stricter), `MS.SHAREPOINT.1.3v1` (SPO-5.5, Partial: the approved-domain half), `MS.SHAREPOINT.2.2v1` (SPO-5.7, Equivalent; `MS.SHAREPOINT.3.2v1` audits the Anyone-link permissions, a different setting) and `MS.AAD.7.4v1` (AAD-3.2, Partial, replacing its Unsupported `MS.AAD.7.3v1` citation, which is AAD-10.2's requirement). `MS.EXO.6.1v1` (contacts sharing) stays uncited: no NRG control reads it.

## How to read this

- **A migrated citation does not establish equivalence.** The migration file says where an old rule id went, often to a range of new rules. Whether an NRG evaluator satisfies the new rule was decided per requirement against what the evaluator actually reads.
- **An independent scan is evidence, not a target.** NRG reports the observed configuration and its own baseline verdict; ScubaGear reports its own. Two standards can judge the same configuration differently (DMARC `p=quarantine` meets the NRG baseline and falls short of ScubaGear's `p=reject`). That is a difference to understand, not a defect to erase.
- **Requirement strength (SHALL / SHOULD) is ScubaGear's and is kept apart from NRG's risk severity.**

| Relation | Meaning | Citations |
|---|---|---|
| Equivalent | The NRG evaluator checks the same requirement. | 25 |
| Partial | The NRG evaluator covers part of the requirement, or a stricter or looser form of it. Read the note. | 54 |
| Manual | The NRG control is manual or advisory; it asserts nothing about the rule. | 3 |
| Unsupported | The NRG control does not establish this requirement. The citation stays only where the current id still exists, flagged; an obsolete id with no equivalent was removed. | 15 |

Obsolete rule ids the migration file maps to `None` (removed by CISA): `MS.EXO.8.3v1`, `MS.EXO.9.2v1`, `MS.EXO.9.4v1`, `MS.EXO.11.3v1`, `MS.DEFENDER.4.5v1`. NRG cited none of them.

## Obsolete references removed (NRG control kept)

The old rule id no longer exists and the migrated range does not describe what the NRG control checks, so the reference was removed rather than re-pointed.

| NRG control | Old id | Why |
|---|---|---|
| DEF-1.3 Spoof Intelligence Enabled | `MS.DEFENDER.1.3v1` | SCuBA 2.0 has no rule for spoof intelligence; the migrated range does not cover it. Obsolete reference removed; the NRG control stays. |
| DEF-2.1 Preset Security Policies Applied | `MS.DEFENDER.1.1v1` | SCuBA 2.0 judges the outcomes (attachment blocking, scanning, quarantine), not whether the Standard or Strict preset is enabled. Obsolete reference removed; the NRG control stays. |
| DEF-2.6 Bulk Mail Threshold Configured | `MS.DEFENDER.1.1v1` | SCuBA 2.0 has no bulk-mail threshold rule. Obsolete reference removed; the NRG control stays. |
| DEF-4.3 Risky OAuth Application Alerts Configured | `MS.DEFENDER.5.1v1` | Risky OAuth alerts are not among the alerts SCuBA 4.1 requires. Obsolete reference removed; the NRG control stays. |
| DEF-4.4 Priority Accounts Tagged in Defender | `MS.DEFENDER.2.1v1` | A priority-account tag is not impersonation protection (SCuBA 2.1). Obsolete reference removed; the NRG control stays (manual). |
| EXO-3.5 Transport Rules Changes Audited | `MS.DEFENDER.6.1v1` | Transport-rule change auditing is not unified audit logging (5.1). Obsolete reference removed; the NRG control stays. |
| EXO-4.4 Anti-Spam Inbound Policy Properly Configured | `MS.DEFENDER.1.2v1` | SCuBA 2.0 has no rule for the anti-spam inbound policy settings NRG checks. Obsolete reference removed; the NRG control stays. |

## Equivalent

| NRG control | ScubaGear rule | Strength | Previously cited | Note |
|---|---|---|---|---|
| AAD-1.1 Legacy Authentication Blocked | `MS.AAD.1.1v1` | SHALL | same | Both require legacy authentication blocked for all users. SCuBA allows no user exclusions unless configured; NRG reports excluded accounts as an exception (Partial) when no other policy covers them. |
| AAD-1.2 MFA Required for All Users | `MS.AAD.3.2v2` | SHALL | `MS.AAD.3.2v1` (migrated) | v1 was renumbered to v2 in the migration file with the same requirement (MFA for all users). NRG also judges registration separately. |
| AAD-10.2 Privileged Accounts Use Dedicated Cloud-Only Accounts | `MS.AAD.7.3v1` | SHALL | same | Privileged accounts are cloud-only and dedicated. |
| AAD-11.1 Device Code Authentication Flow Blocked | `MS.AAD.3.9v1` | SHOULD | same | Device code flow blocked (for all users on all applications). |
| AAD-3.5 PIM GA Activation Requires Approval | `MS.AAD.7.6v1` | SHALL | same | Global Administrator activation requires approval. |
| AAD-4.1 Guest Invite Permissions Restricted | `MS.AAD.8.2v1` | SHOULD | same | Only Guest Inviters can invite guests. |
| AAD-4.3 B2B Guest Default Permissions Restricted | `MS.AAD.8.1v1` | SHOULD | same | Guest directory access limited. |
| AAD-6.1 User App Registration Disabled | `MS.AAD.5.1v1` | SHALL | same | Only administrators register applications. |
| AAD-6.2 User Consent to Apps Restricted | `MS.AAD.5.2v1` | SHALL | same | Both require user consent to applications restricted; the admin consent workflow is the separate rule 5.3 (AAD-6.3). |
| AAD-6.3 Admin Consent Workflow Enabled | `MS.AAD.5.3v1` | SHALL | same | Admin consent workflow configured. |
| EXO-1.1 Mailbox Audit Logging Enabled | `MS.EXO.13.1v1` | SHALL | same | Mailbox auditing enabled; NRG also checks the audit bypass list. |
| EXO-1.2 SMTP Client Authentication Disabled | `MS.EXO.5.1v1` | SHALL | same | SMTP AUTH disabled. |
| EXO-4.3 Safe Attachments for SharePoint OneDrive Teams Enabled | `MS.SECURITYSUITE.1.4v1` | SHOULD | `MS.DEFENDER.1.1v1` (migrated) | Safe Attachments for SharePoint, OneDrive and Teams = attachments in those workloads scanned for malware. |
| PPL-1.1 Power Platform Tenant Isolation Enabled | `MS.POWERPLATFORM.3.1v1` | SHALL | same | Tenant isolation enabled. The released v2.0.0 baseline marks the rule SHALL (last modified April 2026) and CISA lists it as a BOD 25-01 required configuration. (The 2026-09-30 ScubaGear run reported this rule as "test results missing".) |
| PPL-1.3 Power Platform Environment Creation Restricted | `MS.POWERPLATFORM.1.1v1` | SHALL | same | Environment creation restricted to admins. |
| SPO-1.1 External Sharing Restricted | `MS.SHAREPOINT.1.1v1` | SHALL | same | External sharing limited to existing guests or organization only. |
| SPO-2.2 External Sharing Link Expiration Configured | `MS.SHAREPOINT.3.1v1` | SHALL | same | Anyone-link expiry of 30 days or less. Needs the SharePoint shell. |
| TMS-1.1 External Federation Access Restricted | `MS.TEAMS.2.1v2` | SHALL | same | External access per-domain only. |
| TMS-1.4 External Participants Cannot Take Screen Control | `MS.TEAMS.1.1v1` | SHOULD | same | External participants cannot request control. |
| TMS-2.4 Teams Email Integration Disabled | `MS.TEAMS.4.1v1` | SHALL | same | Teams email integration disabled (`AllowEmailIntoChannel = False`), the setting ScubaGear's automated check reads. The v2.0.0 steps also ask that the "Accept channel email from these SMTP domains" list stay empty; neither tool reads that list, which limits which domains may send to a channel and so matters only while email into channels is allowed. |
| TMS-2.8 PSTN Users Cannot Bypass Lobby | `MS.TEAMS.1.5v1` | SHOULD | same | Dial-in users cannot bypass the lobby. |
| TMS-4.2 Anonymous Users Cannot Start Meetings | `MS.TEAMS.1.2v2` | SHALL | same | Anonymous users cannot start meetings. |
| TMS-4.3 Teams External Domain Federation Restricted to Allowlist | `MS.TEAMS.2.1v2` | SHALL | same | External federation restricted to allowed domains. |
| AAD-14.1 Application Credentials Current and Short-Lived | `MS.AAD.5.6v1` | SHOULD | added 2026-10-26 | Satisfied requires the enabled default application management policy to restrict application password lifetime to 180 days or less, with no exempted actors. It also holds certificates to 180 days, stricter than `MS.AAD.5.7v1` (365), which is met but not cited. |
| SPO-5.7 SharePoint Default Sharing Link Permission Is View | `MS.SHAREPOINT.2.2v1` | SHALL | added 2026-10-27 | Default sharing link permission View (`DefaultLinkPermission`, the setting ScubaGear reads). Needs the SharePoint shell. `MS.SHAREPOINT.3.2v1` (the permissions Anyone links may grant) is a different setting and is not checked. |

## Partial

| NRG control | ScubaGear rule | Strength | Previously cited | Note |
|---|---|---|---|---|
| AAD-3.1 Global Administrator Count 2-4, Cloud-Only | `MS.AAD.7.1v1` | SHALL | same | Stricter than the rule: SCuBA allows two to eight Global Administrators, NRG (since baseline v1.1) two to four, as CIS 1.1.3 does. Every NRG pass meets SCuBA; a tenant with five to eight passes SCuBA and fails NRG. |
| AAD-1.3 Phishing-Resistant MFA Required for Admins | `MS.AAD.3.6v1` | SHALL | same | SCuBA names its highly privileged roles; NRG compares against the privileged roles in this tenant's own role catalog. |
| AAD-1.4 Sign-in Risk CA Policy | `MS.AAD.2.3v1` | SHALL | same | SCuBA requires high-risk sign-ins to be blocked; NRG accepts a risk policy that blocks or requires remediation at high and medium risk. |
| AAD-1.5 User Risk CA Policy | `MS.AAD.2.1v1` | SHALL | same | SCuBA requires high-risk users to be blocked; NRG accepts a policy that blocks or requires password change. |
| AAD-10.1 Identity Protection Risky User Workflow | `MS.AAD.2.2v1` | SHOULD | same | Notification on high-risk users; NRG checks the risky-user workflow. |
| AAD-2.1 Conditional Access Policies Deployed | `MS.AAD.1.1v1` | SHALL | same | Only the legacy-authentication track of AAD-2.1 overlaps MS.AAD.1.1; AAD-2.1 also judges MFA tracks and the approved policy set. |
| AAD-9.1 Authenticator Number Matching Enabled | `MS.AAD.3.3v2` | SHALL | same | v2 requires login context information; NRG checks number matching. |
| DEF-1.1 Safe Attachments Enabled with Block Action | `MS.SECURITYSUITE.1.3v1` | SHALL | `MS.DEFENDER.1.1v1` (migrated) | The migration maps the old preset rule to a range (1.1 to 1.4). Safe Attachments with a block action overlaps "malware is quarantined or dropped" (1.3) only. |
| DEF-1.2 Safe Links Enabled and Hardened | `MS.SECURITYSUITE.7.1v1` | SHOULD | `MS.DEFENDER.1.3v1` (migrated) | NRG is stricter in scope. SCuBA 7.1 passes when the Standard or Strict preset applies URL block-list comparison; NRG also judges recipients covered only by the built-in protection policy (click-through allowed, URL rewrite off) and reports them as not protected. Safe Links hardening overlaps URL block-list comparison (7.1); SCuBA 7.2 and 7.3 (download scanning, click tracking) are separate rules. |
| DEF-2.2 Zero-Hour Auto Purge Enabled | `MS.SECURITYSUITE.1.2v1` | SHALL | `MS.DEFENDER.1.2v1` (migrated) | Zero-hour auto purge is how mail is reviewed after delivery (1.2); SCuBA states the capability, NRG verifies the setting for spam, phishing and malware. |
| DEF-2.3 Anti-Malware Common Attachments Blocked | `MS.SECURITYSUITE.1.1v1` | SHALL | `MS.EXO.9.1v2` (migrated) | SCuBA requires click-to-run attachments (at minimum .exe, .cmd, .vbe) blocked. NRG verifies the attachment filter and, once approved, the blocked-type list. |
| DEF-2.5 High Confidence Spam to Quarantine | `MS.SECURITYSUITE.6.1v1` | SHALL | `MS.DEFENDER.1.1v1` (migrated) | High-confidence spam to quarantine overlaps "spam and phishing are not delivered to the inbox" (6.1). |
| AAD-2.3 Device Compliance Enforced via CA | `MS.AAD.3.7v1` | SHOULD | same | Reviewed 2026-10-26: ScubaGear's automated check passes only a grant of exactly compliant device OR hybrid-joined device; NRG also credits a compliant-device-only policy, so a tenant can pass here and fail ScubaGear's check. |
| DEF-2.4 Phishing Directed to Quarantine Not Junk | `MS.SECURITYSUITE.6.1v1` | SHALL | added 2026-10-26 | Phishing to quarantine in every policy in force covers the phishing half of "spam and phishing are not delivered to the inbox" (6.1), as DEF-2.5 covers the high-confidence spam half. |
| INT-1.2 Non-Compliant Device Access Blocked via CA | `MS.AAD.3.7v1` | SHOULD | added 2026-10-26 | The same judgment as AAD-2.3, with the same difference from ScubaGear's automated check. |
| PVW-4.1 Microsoft Purview Audit (Premium) Enabled | `MS.SECURITYSUITE.5.1v1` | SHALL | `MS.DEFENDER.6.1v1` (migrated), re-added 2026-10-26 | PVW-4.1 now passes only when `UnifiedAuditLogIngestionEnabled = True` is read from the Exchange Online session, the setting 5.1 audits, beside Audit (Premium) licensing; stricter than 5.1. PVW-1.1 remains the direct unified-audit-log control. |
| DEF-3.4 Defender Alert Email Notifications Configured | `MS.SECURITYSUITE.4.2v1` | SHOULD | `MS.DEFENDER.5.2v1` (migrated) | Alerts sent to a monitored address: NRG judges recipients and, once configured, the NRG monitoring address. |
| DEF-4.2 DLP Policy Uses Sensitive Information Types | `MS.SECURITYSUITE.3.1v1` | SHALL | `MS.DEFENDER.4.1v2` (migrated) | SCuBA requires the policy to block named types (card numbers, ITIN, SSN and others); NRG verifies detection of sensitive information types in enforcing rules and reports blocking only when read. |
| DEF-4.5 Endpoint DLP Policy Active on Managed Devices | `MS.SECURITYSUITE.3.2v1` | SHOULD | `MS.DEFENDER.4.2v1` (migrated) | Devices are one of the locations SCuBA 3.2 lists, and 3.2 also needs one enabled rule matching SSN, ITIN and Credit Card Number; NRG checks endpoint DLP on managed devices. |
| DEF-4.7 Safe Links Protects Office Applications | `MS.SECURITYSUITE.7.1v1` | SHOULD | `MS.DEFENDER.1.3v1` (migrated) | Safe Links for Office applications overlaps URL block-list comparison (7.1) in Office documents. |
| DNS-1.1 SPF Record Published | `MS.EXO.2.2v3` | SHALL | `MS.EXO.2.2v2` (migrated) | v3 accepts a hard or soft fail and is the current rule; NRG judges that an SPF record is published and its policy ending. |
| DNS-1.2 DKIM Records Published | `MS.EXO.3.1v1` | SHOULD | same | NRG verifies the published selector records; SCuBA verifies DKIM is enabled in Exchange Online for each domain. |
| DNS-1.3 DMARC Policy at Quarantine or Reject | `MS.EXO.4.2v1` | SHALL | same | SCuBA requires p=reject. The NRG baseline accepts p=quarantine or p=reject. Same configuration, two standards: report the observed policy and judge each against its own requirement. |
| EXO-1.3 External Auto-Forwarding Blocked | `MS.EXO.1.1v2` | SHALL | same | SCuBA reads the remote-domain automatic-forwarding setting (allowed domains configurable). NRG reads outbound spam policies and remote domains and has no allowed-domain list. |
| EXO-1.5 Anti-Phishing Impersonation Protection Enabled | `MS.SECURITYSUITE.2.1v1` | SHOULD | `MS.DEFENDER.2.1v1` (migrated) | SCuBA requires impersonation protection for a sensitive-user list. NRG verifies domain and mailbox-intelligence protection and judges approved priority users only when NRG approves a list (Config/tp-standards.json). |
| EXO-3.3 Alert Policy — Email Forwarding Rules | `MS.SECURITYSUITE.4.1v1` | SHALL | `MS.DEFENDER.5.1v1` (migrated) | SCuBA lists required alerts (suspicious sending, connector, forwarding); NRG checks the forwarding-rule alert only. |
| EXO-3.4 Alert Policy — Unusual Mail Volume | `MS.SECURITYSUITE.4.1v1` | SHALL | `MS.DEFENDER.5.1v1` (migrated) | Unusual mail volume overlaps suspicious email sending patterns (4.1 a). |
| EXO-4.2 Admin Audit Log Enabled | `MS.SECURITYSUITE.5.1v1` | SHALL | `MS.DEFENDER.6.1v1` (migrated) | Admin audit log enabled overlaps unified audit logging (5.1); NRG judges searchability separately. |
| EXO-5.1 Per-User Mailbox Audit Logging Enabled for All Mailboxes | `MS.EXO.13.1v1` | SHALL | same | Per-user mailbox auditing; SCuBA states the tenant requirement. |
| EXO-5.2 Priority Account Protection Active in Anti-Phishing Policy | `MS.SECURITYSUITE.2.1v1` | SHOULD | `MS.DEFENDER.2.1v1` (migrated) | Priority-account protection in the anti-phishing policy overlaps sensitive-user impersonation protection (2.1). |
| EXO-6.3 Mailboxes with Audit Logging Disabled — Named List | `MS.EXO.13.1v1` | SHALL | same | Named mailboxes with auditing bypassed; SCuBA states the tenant requirement. |
| EXO-6.4 Per-User SMTP AUTH Override — Named List | `MS.EXO.5.1v1` | SHALL | same | Per-user SMTP AUTH overrides versus tenant SMTP AUTH disabled. |
| EXO-7.3 No Mailboxes with Per-User Audit Explicitly Disabled | `MS.EXO.13.1v1` | SHALL | same | Per-user audit bypass versus tenant mailbox auditing. |
| EXO-7.4 No Per-User SMTP AUTH Overrides | `MS.EXO.5.1v1` | SHALL | same | Per-user SMTP AUTH overrides versus tenant SMTP AUTH disabled. |
| PPL-1.2 Power Platform DLP Policy Active | `MS.POWERPLATFORM.2.1v1` | SHALL | same | SCuBA requires a DLP policy restricting connectors in the default environment; NRG checks that a DLP policy is active. |
| PPL-2.1 Power Platform Connector Classification Reviewed | `MS.POWERPLATFORM.2.1v1` | SHALL | same | Connector classification review versus a DLP policy restricting the default environment. |
| PPL-2.3 Power Apps Portal Creation Restricted | `MS.POWERPLATFORM.5.1v1` | SHOULD | same | Power Pages site creation restricted; NRG reads the tenant setting when returned. |
| PVW-1.2 Audit Log Retention Minimum 90 Days | `MS.SECURITYSUITE.5.2v1` | SHALL | `MS.DEFENDER.6.3v1` (migrated) | SCuBA requires 3 months searchable and 12 months retrievable; NRG checks a 90-day minimum and (PVW-4.2) one year. |
| PVW-4.2 Audit Log Retention Policy Extends to 1 Year or More | `MS.SECURITYSUITE.5.2v1` | SHALL | `MS.DEFENDER.6.3v1` (migrated) | Retention to one year overlaps "retrievable for 12 months" (5.2). |
| SPO-1.2 Default Sharing Link Not Anonymous | `MS.SHAREPOINT.2.1v1` | SHALL | same | SCuBA requires the default link to be "Specific people"; NRG requires it not to be anonymous. |
| SPO-2.7 Reauthentication Required for Sharing Links | `MS.SHAREPOINT.3.3v2` | SHALL | `MS.SHAREPOINT.3.3v1` (migrated) | Checked against the released v2 text (verification-code reauthentication 30 days or less; v2 also applies at Existing guests). SPO-2.7 reads `EmailAttestationRequired` / `EmailAttestationReAuthDays` (SharePoint shell) at every sharing level except "Only people in your organization", so the Existing guests case is judged. Stricter: Satisfied needs 15 days or fewer (CIS 7.2.10); every NRG pass meets v2, and 16 to 30 days is an NRG Partial that meets v2. Not assessed without the SharePoint shell. |
| TMS-2.2 Unverified App Publisher Blocked | `MS.TEAMS.5.2v2` | SHOULD | same | SCuBA: only agency-approved third-party apps; NRG: unverified publishers blocked. |
| TMS-2.7 External User Chat Restricted | `MS.TEAMS.2.3v2` | SHOULD | same | SCuBA: internal users should not initiate contact with unmanaged users; NRG: external user chat restricted. |
| TMS-3.2 Auto-Admit Only Authenticated Organization Users | `MS.TEAMS.1.3v1` | SHOULD | same | SCuBA: anonymous and dial-in callers not admitted automatically; NRG: auto-admit only organization users. |
| DEF-4.1 DLP Policy Covers All Key Workloads | `MS.SECURITYSUITE.3.2v1` | SHOULD | `MS.DEFENDER.4.2v1` (migrated) | ScubaGear 3.2 is met only when ONE enabled rule, in an Enable-mode policy, matches all three of SSN, ITIN and Credit Card Number, and that policy's location is All for each of Exchange, OneDrive, SharePoint, Teams and Devices. NRG judges workload coverage: enforcing policies with whole-workload scope whose rules match sensitive information types, whatever the types. Policies can cover every workload and still fail 3.2 when no single rule matches all three named types. |
| EXO-1.4 DKIM Signing Enabled for All Domains | `MS.EXO.3.1v1` | SHOULD | same | NRG is stricter. SCuBA 3.1 passes when DKIM signing is enabled; NRG also requires a 2048-bit key and reports a domain with a 1024-bit key as Partial. A pass here with an NRG Partial is expected, not a disagreement. |
| EXO-4.1 Mailbox Audit Log Age Limit Sufficient | `MS.SECURITYSUITE.5.2v1` | SHALL | `MS.DEFENDER.6.3v1` (removed 2026-09-30, re-cited 2026-10-26) | Covers the "searchable for 3 months" half for Exchange record types: every Exchange-scoped custom audit retention policy must be read and none may shorten retention below 90 days. Twelve-month retrievability and other record types are not checked here. |
| AAD-3.2 No Permanent Admin Role Assignments | `MS.AAD.7.4v1` | SHALL | `MS.AAD.7.3v1` (Unsupported; replaced 2026-10-27) | The rule AAD-3.2 judges: no permanent active assignment to a highly privileged role (ScubaGear: an active assignment with no end date, unless the principal is exempted in its configuration file; Entra ID P2 required). Stricter: Satisfied also needs a PIM-eligible assignment, and every active assignment that is not a PIM activation counts as permanent, time-bound ones included. Looser: service principals are not judged, NRG's 17-role list omits Hybrid Identity Administrator, and cloud-only Global Administrators excluded from Conditional Access are set aside as emergency access accounts by inference, not by an approved list. `MS.AAD.7.3v1` is AAD-10.2's. |
| AAD-7.5 Passwords Set to Never Expire | `MS.AAD.6.1v1` | SHALL | added 2026-10-27 | Stricter than ScubaGear's check: NRG requires `passwordValidityPeriodInDays = 2147483647` on every verified domain, federated and subdomains included, and reads an unset value as Microsoft's 90-day default; ScubaGear judges managed verified domains, takes a subdomain's value from its root, and accepts an unset value as never expiring. Every NRG pass meets the rule; a tenant whose domains read null passes ScubaGear and is an NRG shortfall. |
| AAD-17.3 SMS and Voice Call Authentication Methods Disabled | `MS.AAD.3.5v2` | SHALL | added 2026-10-27 | The v2 rule requires SMS, voice call and email OTP disabled in the authentication methods policy. AAD-17.3 judges SMS and voice call; email OTP is AAD-17.5's part. |
| AAD-17.5 Email OTP Authentication Method Disabled | `MS.AAD.3.5v2` | SHALL | added 2026-10-27 | The email OTP part of the v2 rule; SMS and voice call are AAD-17.3's. |
| EXO-10.1 External Calendar Sharing Not Available | `MS.EXO.6.2v1` | SHALL | added 2026-10-27 | Stricter than the rule, which allows sharing with specific domains: the default sharing policy must be disabled and no other enabled policy may share calendars with `*` or anonymously, so every pass meets the rule. ScubaGear's automated check also fails a disabled policy whose entries still name `*` with a calendar action, so a disabled default policy can be an NRG pass and a ScubaGear failure. Contacts sharing (`MS.EXO.6.1v1`) is not checked. |
| SPO-5.3 OneDrive Content Sharing Restricted | `MS.SHAREPOINT.1.2v1` | SHALL | added 2026-10-27 | Same setting (`OneDriveSharingCapability`). Stricter: Satisfied needs Only people in your organization; Existing guests, which the rule accepts, is an NRG Partial (CIS 7.2.4). |
| SPO-5.5 SharePoint External Sharing Limited to Allowed Domains | `MS.SHAREPOINT.1.3v1` | SHALL | added 2026-10-27 | The approved-domain half, the setting ScubaGear's automated check reads; NRG also requires at least one allowed domain. The approved-security-group alternative is not credited here (SPO-5.6 reads it), so restricting by security group alone is an NRG Gap. |

## Manual

| NRG control | ScubaGear rule | Strength | Previously cited | Note |
|---|---|---|---|---|
| AAD-8.1 PIM Alerts Configured | `MS.AAD.7.7v1` | SHALL | same | NRG cannot read PIM alert configuration; the control is manual. |
| PPL-2.2 Power Automate Governance Policy Active | `MS.POWERPLATFORM.1.1v1` | SHALL | same | No documented setting; the NRG control requires manual verification. |
| PVW-3.1 Audit Logs Exported to SIEM | `MS.SECURITYSUITE.4.2v1` | SHOULD | `MS.DEFENDER.5.2v1` (migrated) | SIEM export is not readable from Microsoft 365; the NRG control is manual. |

## Unsupported (citation kept because the rule id is current, flagged)

| NRG control | ScubaGear rule | Strength | Previously cited | Note |
|---|---|---|---|---|
| AAD-12.1 Users Without MFA — Named List | `MS.AAD.3.1v1` | SHALL | same | A named list of users without registered MFA is registration, not phishing-resistant enforcement (3.1). |
| AAD-12.4 OAuth Apps with Tenant-Wide Consent — Named List | `MS.AAD.5.2v1` | SHALL | same | A list of apps with tenant-wide consent is an inventory, not the user-consent restriction (5.2). Covered by AAD-6.2. |
| AAD-15.1 No Application Holds Tenant-Takeover Permissions | `MS.AAD.5.2v1` | SHALL | same | Application permissions held by apps are not the user-consent restriction (5.2). |
| AAD-15.2 Applications with Tenant-Wide Data Permissions — Named List | `MS.AAD.5.2v1` | SHALL | same | Application permissions held by apps are not the user-consent restriction (5.2). |
| AAD-9.2 Passwordless Authentication Methods Available | `MS.AAD.3.1v1` | SHALL | same | MS.AAD.3.1 requires phishing-resistant MFA ENFORCED for all users; AAD-9.2 only checks that passwordless methods are available. Enforcement is AAD-1.3 (administrators). |
| EXO-6.1 Mailboxes with External Email Forwarding — Named List | `MS.EXO.1.1v2` | SHALL | same | Mailbox-level forwarding is not the remote-domain forwarding setting SCuBA reads. |
| EXO-7.1 No Mailbox Forwarding to External Addresses | `MS.EXO.1.1v2` | SHALL | same | Mailbox forwarding is not the remote-domain forwarding setting SCuBA reads. |
| EXO-7.2 No Inbox Rules Forwarding Externally | `MS.EXO.1.1v2` | SHALL | same | Inbox-rule forwarding is not the remote-domain forwarding setting SCuBA reads. |

## ScubaGear 2.0.0 rules no NRG control is aligned to (47)

These are **not assessed by NRG** under a SCuBA reference. Some are Power BI and Security Suite rules ScubaGear marks as manual (its `Warning` and `N/A` results). Listing them is not a claim that NRG should adopt them.

| Rule | Strength | Requirement |
|---|---|---|
| `MS.AAD.3.4v1` | SHALL | The "Authentication methods manage migration" feature SHALL be set to "Migration complete." |
| `MS.AAD.3.8v1` | SHOULD | Managed devices SHOULD be required to register MFA. |
| `MS.AAD.4.1v1` | SHALL | Security logs SHALL be sent to the agency's security operations center for monitoring. |
| `MS.AAD.5.5v1` | SHOULD | Application password addition SHOULD be blocked. |
| `MS.AAD.5.7v1` | SHOULD | Application certificate lifetime SHOULD be restricted to 365 days or less. |
| `MS.AAD.7.2v1` | SHALL | Privileged users SHALL be provisioned with finer-grained roles instead of the Global Administrator role. |
| `MS.AAD.7.5v1` | SHALL | Provisioning users to highly privileged roles SHALL NOT occur outside of a PAM system. |
| `MS.AAD.7.8v1` | SHALL | User activation of the Global Administrator role SHALL trigger an alert. |
| `MS.AAD.7.9v1` | SHOULD | User activation of other highly privileged roles SHOULD trigger an alert. |
| `MS.AAD.8.3v1` | SHOULD | Guest invites SHOULD only be allowed to be sent to specific external domains that have been authorized by the agency for legitimate business purposes. |
| `MS.AAD.9.1v1` | SHALL | Risky AI agents SHALL be blocked. |
| `MS.EXO.4.1v1` | SHALL | A DMARC policy SHALL be published for every second-level domain. |
| `MS.EXO.4.3v1` | SHALL | The DMARC point of contact for aggregate reports SHALL include reports@dmarc.cyber.dhs.gov. |
| `MS.EXO.4.4v1` | SHOULD | An agency point of contact SHOULD be included for aggregate and failure reports. |
| `MS.EXO.6.1v1` | SHALL | Contact folders SHALL NOT be shared with all domains. |
| `MS.EXO.7.1v1` | SHALL | External sender warnings SHALL be implemented. |
| `MS.POWERBI.1.1v1` | SHOULD | The "Publish to Web" feature SHOULD be disabled unless the agency mission requires the capability. |
| `MS.POWERBI.2.1v1` | SHOULD | Guest user access to the Power BI tenant SHOULD be disabled unless the agency mission requires the capability. |
| `MS.POWERBI.3.1v1` | SHOULD | The "Invite external users to your organization" feature SHOULD be disabled unless agency mission requires the capability. |
| `MS.POWERBI.4.1v1` | SHOULD | Service principals with access to APIs SHOULD be restricted to specific security groups. |
| `MS.POWERBI.4.2v1` | SHOULD | Service principals' ability to create and use profiles SHOULD be restricted to specific security groups. |
| `MS.POWERBI.5.1v1` | SHOULD | ResourceKey-based authentication SHOULD be blocked unless a specific use case (e.g., streaming and/or "push" datasets) merits its use. |
| `MS.POWERBI.6.1v1` | SHOULD | Python and R interactions SHOULD be disabled. |
| `MS.POWERBI.7.1v1` | SHOULD | Sensitivity labels SHOULD be enabled for Power BI and employed for sensitive data per enterprise data protection policies. |
| `MS.POWERPLATFORM.1.2v1` | SHALL | The ability to create trial environments SHALL be restricted to administrators. |
| `MS.POWERPLATFORM.2.2v1` | SHOULD | Non-default environments SHOULD have at least one DLP policy. |
| `MS.POWERPLATFORM.3.2v1` | SHOULD | An inbound/outbound connection allowlist SHOULD be configured. |
| `MS.POWERPLATFORM.4.1v1` | SHALL | Content Security Policy (CSP) SHALL be enforced for model-driven and canvas Power Apps. |
| `MS.POWERPLATFORM.6.1v1` | SHOULD | The "Share with everyone" feature SHOULD be disabled. |
| `MS.SECURITYSUITE.2.2v1` | SHOULD | Domain impersonation protection SHOULD be enabled for domains owned by the agency. |
| `MS.SECURITYSUITE.2.3v1` | SHOULD | Domain impersonation protection SHOULD be added for key suppliers and partners. |
| `MS.SECURITYSUITE.2.4v1` | SHOULD | User warnings, comparable to the user safety tips included with EOP, SHOULD be displayed. |
| `MS.SECURITYSUITE.3.3v1` | SHOULD | The action for the DLP policy SHOULD be set to block sharing sensitive information with everyone. |
| `MS.SECURITYSUITE.3.4v1` | SHOULD | Notifications to inform users and help educate them on the proper use of sensitive information SHOULD be enabled in the DLP policy. |
| `MS.SECURITYSUITE.3.5v1` | SHOULD | The DLP policy SHOULD include an action to block access to sensitive information by restricted applications and unwanted Bluetooth applications. |
| `MS.SECURITYSUITE.6.2v1` | SHALL | Allowed domains SHALL NOT be added to inbound anti-spam protection policies. |
| `MS.SECURITYSUITE.7.2v1` | SHOULD | Direct download links SHOULD be scanned for malware. |
| `MS.SECURITYSUITE.7.3v1` | SHOULD | User click tracking SHOULD be enabled. |
| `MS.SECURITYSUITE.8.1v1` | SHOULD | IP allow lists SHOULD NOT be created. |
| `MS.SECURITYSUITE.8.2v1` | SHOULD | Safe lists SHOULD NOT be enabled. |
| `MS.SHAREPOINT.3.2v1` | SHALL | The allowable file and folder permissions for links SHALL be set to view only. |
| `MS.TEAMS.1.4v1` | SHOULD | Internal users SHOULD be admitted to Microsoft Teams meetings automatically. |
| `MS.TEAMS.1.6v1` | SHOULD | Meeting recording SHOULD be disabled. |
| `MS.TEAMS.1.7v2` | SHOULD | "Record an event" SHOULD NOT be set to "Always record." |
| `MS.TEAMS.2.2v2` | SHALL | Unmanaged users SHALL NOT be enabled to initiate contact with internal users. |
| `MS.TEAMS.5.1v2` | SHOULD | Agencies SHOULD only allow installation of Microsoft applications approved by the agency. |
| `MS.TEAMS.5.3v2` | SHOULD | Agencies SHOULD only allow installation of custom applications approved by the agency. |

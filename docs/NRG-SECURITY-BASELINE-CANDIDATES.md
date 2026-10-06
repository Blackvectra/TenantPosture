# NRG Security Baseline v1.0 — Candidate Controls (editorial review)

**Status:** DRAFT for editorial review. This document is not configuration. Nothing in the tool reads it.
Once the tiers and governance fields are settled, the decisions are encoded as `Config/nrg-baseline.json` and a `Get-NRGBaselineCompliance` view; until then this file is the only artifact.

**Source of truth for IDs, titles, severities and license requirements:** `Config/controls.json` (204 controls). The tables were generated from it on 2026-09-29. Edit the editorial columns (tier, reason, why NRG owns this, notes, and the governance fields), never the catalog columns.

## What the baseline is, and is not

The assessment answers "what is this tenant's posture against 204 controls and ten frameworks". The baseline answers a narrower and more operational question: **is this client configured the way NRG says a managed client must be configured?** Frameworks tell us which controls exist. The baseline says which of them NRG requires. The assessment proves whether they are there. Everything else in `controls.json` stays useful as evidence without becoming an operating requirement.

## Tiers (layered, one minimum tier per control)

| Tier | Meaning | Who it applies to |
|---|---|---|
| **Minimum** | Expected on every applicable NRG-managed environment. A deviation needs a written explanation. | Every managed client |
| **Standard** | Normal NRG managed-security posture. Includes everything in Minimum. | Clients on the standard security service |
| **Hardened** | Elevated-risk or regulated environments. Includes Minimum and Standard. | Regulated, government, high-value targets |
| **Assessment-only** | Assessed and reported, mapped to frameworks, but not an NRG operating requirement in v1.0. | Evidence only |

A Standard client must satisfy Minimum + Standard. A Hardened client must satisfy all three. Tiers are inherited, so no control is listed twice.

## The decision test for Minimum

A control is Minimum only if all four hold: it is expected on nearly every applicable NRG-managed environment; it is reasonably deployable without a project; the assessment (or a named manual step) can verify it; and a deviation is important enough that it must be explained. Severity was a starting point, not the rule: several High controls are Assessment-only because they do not apply universally, and several Medium controls are Minimum because they are foundational (audit logging, DKIM records).

## Three things that must not collapse into one field

| Concept | Question it answers | Where it comes from |
|---|---|---|
| **Control requirement** | What does NRG require? | This document, then `nrg-baseline.json` (expected state, tier, owner, SLA class) |
| **Observed evidence** | Is it configured that way right now? | The assessment finding (Satisfied / Failed / NotApplicable / NotVerified) with its evidence timestamp and source |
| **Effectiveness evidence** | Is it actually working? | The effectiveness check named per control; today mostly telemetry the assessment does not collect, so its state is Unknown until a collector exists |

`Configured = yes, Observed = yes, Effective = unknown` is a legitimate and common state and must be reported as exactly that. It is never rounded up to a pass.

## Governance fields (added for the second editorial pass)

| Field | Meaning | Values |
|---|---|---|
| **Owner** | The NRG discipline that owns the control and answers for drift | Identity, Email, Endpoint, DNS, Logging, Collaboration & Data (Vulnerability lives in the device build standard) |
| **Evidence source** | The exact collector and API that proves the observed state | Derived from `CollectorDependency` |
| **Expected state** | One sentence an engineer can test against | Editorial |
| **SLA class** | A label only; the number of days per class lives in a separate policy table so NRG can change 7 to 10 without touching 50 controls | Immediate, Critical, High, Standard, Advisory |
| **Depends on** | Controls or prerequisites without which this one is weak or meaningless | Control IDs |
| **Effectiveness check** | What proves the control works, not merely that it is configured | Editorial, each tagged **collected** (the assessment or endpoint scanner reads it today) or **not collected** (a capability gap, stated, never pretended) |
| **Evidence freshness class** | How old observed evidence may be before it becomes NotVerified | Realtime, Daily, Weekly, Monthly, PointInTime |

Governance fields are filled for the tiered controls only. Assessment-only rows carry owner and evidence source (both derivable) and nothing else, because they are not requirements.

## Applicability is per client, not per control

The baseline file will hold only control IDs, tiers and the governance fields above. Whether a control applies to a given tenant comes from the tenant: license gating (`Config/license-service-plans.json` and the tenant's own SKUs), the third-party EDR declaration (`-ThirdPartyEDR`, `clients.json`), and a per-client exceptions file (control ID, reason, compensating control, approver, start date, review date, expiry — an exception past its review date is a finding again). The compliance view keeps three things separate rather than one status enum:

- **Observed** (from the finding): Satisfied / Failed / NotApplicable / NotVerified
- **Constraint** (from licensing): None / LicenseBlocked
- **Disposition** (from the exceptions file): Normal / ApprovedException

A control that produced no verdict this run, or whose evidence is older than its freshness class allows, is **NotVerified**, never Satisfied, whatever it was last month. The display status is derived from the three, and the precedence is to be stress-tested during implementation, not fixed here.

## Results contract (for the implementation, not this review)

The assessment stays stateless. It emits facts; the PSA or a future operations layer owns ticket state, acknowledgment and remediation clocks. Per baseline control, `results.json` will carry:

`ControlId`, `BaselineVersion`, `TargetTier`, `ObservedState`, `EvidenceTimestamp`, `EvidenceSource`, `EffectivenessState`, `RegressionFlag`, `ExceptionState`

plus a `BaselineCompliance` summary (counts by observed state, constraint and disposition, per tier) and `BaselineRegressions[]` (client, control, baseline tier, previous, current, detected, action). A prior run's baseline version is recorded so a drop between v1.0 and v1.1 can be read as "the standard changed", not "the client got worse".

## Proposed counts


| Tier | Controls |
|---|---|
| Minimum | 30 |
| Standard | 19 |
| Hardened | 18 |
| Assessment-only | 137 |
| Minimum + Standard | 49 |


Effectiveness checks on the 67 tiered controls: **6 collected today**, **61 not collected** (capability gaps, listed in the contradictions section).

Domains: the six from the standard (Identity, Email, Endpoint, DNS, Logging & Audit, Vulnerability) plus **Collaboration & Data** for Teams, SharePoint, Purview and Power Platform, which the six do not cover. Logging & Audit gathers the audit and alerting controls from every workload. **Automated** is Fully (the evaluator reaches a verdict on its own), Partially (a verdict with a named manual step), or Manual (no supported read API; the 17 controls in `Config/coverage-exceptions.psd1`).

Each domain has two tables: the **tier table** (what and why) and the **governance table** (owner, evidence, expected state, SLA class, dependencies, effectiveness, freshness). Rows are in the same order in both.


## Identity (47 controls)

### Identity: tier

| Control ID | Control title | Severity | License requirement | Automated | Proposed tier | Reason | Why NRG owns this | Notes |
|---|---|---|---|---|---|---|---|---|
| AAD-1.1 | Legacy Authentication Blocked | Critical | M365 Business Premium or Entra ID P1 | Fully | **Minimum** | Legacy protocols bypass MFA entirely; every credential-spray campaign targets them. | Blocking legacy auth is the single cheapest control that closes the most incidents NRG responds to. | Security Defaults satisfies it where the tenant has no Entra ID P1. Check for legacy clients (old Outlook, scanners doing SMTP) before enforcing. |
| AAD-1.2 | MFA Required for All Users | Critical | M365 Business Premium or Entra ID P1 | Fully | **Minimum** | Password-only sign-in is the root cause of nearly every BEC case. | NRG does not manage a tenant where a password alone reaches mail. | Security Defaults counts only as Partial: registration is prompted, not enforced at every sign-in. Legacy-auth block (AAD-1.1) must come first or MFA is bypassable. |
| AAD-11.2 | No Guest Accounts in Highly Privileged Roles | Critical | Included (all plans) | Fully | **Minimum** | A guest in a privileged role is administered by someone else's tenant. | No external identity may hold a privileged role in a tenant NRG manages. |  |
| AAD-15.1 | No Application Holds Tenant-Takeover Permissions | Critical | Included (all plans) | Fully | **Minimum** | An application permission with no signed-in user bypasses MFA and Conditional Access entirely. | App-only tenant-takeover permissions are the modern persistence route and are invisible to the delegated-consent checks. | Microsoft first-party apps are set aside in the verdict; every other holder must be known and documented. |
| AAD-2.1 | Conditional Access Policies Deployed | High | M365 Business Premium or Entra ID P1 | Fully | **Minimum** | With P1 licensed, the CA policy set is the mechanism behind every other identity requirement. | NRG builds its identity posture on Conditional Access, so an empty policy set means nothing below is enforced. | Where no P1 license exists, Security Defaults is the accepted substitute and this is license blocked, not failed. |
| AAD-3.1 | Global Administrator Count 2-8, Cloud-Only | High | Included (all plans) | Fully | **Minimum** | Too few GAs is a lockout risk; too many is an attack surface; synced GAs let an on-prem compromise take the tenant. | A bounded, cloud-only admin set is the first thing NRG checks in any takeover investigation. | Cloud-only means no on-premises sync on the admin accounts; the break-glass pair counts toward the total. |
| AAD-6.2 | User Consent to Apps Restricted | Critical | Included (all plans) | Fully | **Minimum** | Illicit consent grants survive password resets and MFA re-enrollment. | Consent phishing is the persistence route NRG sees most after BEC; users must not be able to grant it. | Pair with the admin consent workflow (AAD-6.3) so legitimate requests still have a path; otherwise engineers will loosen it. |
| AAD-7.2 | Break-Glass Accounts Configured | High | Included (all plans) | Partially | **Minimum** | Without a documented break-glass pair, a CA misconfiguration or MFA outage locks NRG out of the tenant it manages. | NRG must always be able to get back in; this protects the client from NRG's own policies. | Excluded from CA, monitored on sign-in (AAD-10.3 is the manual twin), FIDO2 or long random passwords in the vault. Two or more accounts need a human check that they are the right ones. Partially automated: the tool proves fewer than two break-glass accounts; two or more still needs a human to confirm they are the right accounts. |
| AAD-10.2 | Privileged Accounts Use Dedicated Cloud-Only Accounts | High | Included (all plans) | Fully | **Standard** | Admins doing daily work on their admin identity expose the role to every phishing email they open. | Separate admin accounts are NRG's own operating practice; clients get the same standard. |  |
| AAD-11.1 | Device Code Authentication Flow Blocked | High | M365 Business Premium or Entra ID P1 | Fully | **Standard** | Device code phishing relays the MFA prompt; only a block stops it. | Device code flow is an active phishing technique against MSP-managed tenants and has no business use for most clients. | Blocks some legitimate CLI and TV-app sign-ins; document the exception where a client needs it. |
| AAD-2.3 | Device Compliance Enforced via CA | High | M365 Business Premium or Entra ID P1 + Intune | Fully | **Standard** | Compliant-device CA is what makes the endpoint baseline (DB-*) actually gate access. | Without it, an enrolled but non-compliant or unknown device reaches company data with a password and MFA alone. | Requires INT-1.1 compliance policies first. INT-1.2 reads the same setting and counts once (control links). |
| AAD-6.1 | User App Registration Disabled | High | Included (all plans) | Fully | **Standard** | Users registering their own apps is how consent phishing and shadow SaaS get a foothold. | NRG-managed tenants route app registration through an admin. | Developer-heavy clients may need an exception with a named owner. |
| AAD-1.3 | Phishing-Resistant MFA Required for Admins | Critical | M365 Business Premium or Entra ID P1 | Fully | **Hardened** | Push-based MFA on admin accounts is defeated by MFA fatigue and adversary-in-the-middle kits. | NRG requires phishing-resistant admin sign-in for regulated and high-value clients. | Needs authentication strengths (P1) and FIDO2 keys or Windows Hello for Business for every admin. |
| AAD-1.4 | Sign-in Risk CA Policy | High | Entra ID P2 | Fully | **Hardened** | Risk-based CA responds to a compromised session before a human sees the alert. | P2 clients should get automated response; P1 clients cannot and are license blocked. | Requires Entra ID P2. High + Medium sign-in risk per Microsoft's template. |
| AAD-1.5 | User Risk CA Policy | High | Entra ID P2 | Fully | **Hardened** | A high-risk user must be forced to change password, not just flagged. | Same as AAD-1.4. | Requires Entra ID P2. |
| AAD-10.4 | Sign-in Frequency Session Control Configured | Medium | M365 Business Premium or Entra ID P1 | Fully | **Hardened** | Long-lived sessions extend the value of a stolen token. | Sign-in frequency for elevated-risk clients. | User friction; set per client. |
| AAD-11.4 | Token Protection (Session Binding) Enforced | High | M365 Business Premium or Entra ID P1 | Fully | **Hardened** | Token theft is the post-MFA attack; binding sessions to the device defeats replay. | Elevated-risk clients get session binding where their clients support it. | Windows-only and application-limited today; expect exceptions. |
| AAD-11.7 | Privileged Access Workstation or Device Scope for Admins | Medium | M365 Business Premium or Entra ID P1 + Intune | Fully | **Hardened** | Admin sessions from an unmanaged device are the path from a home PC to a tenant. | Privileged access from managed devices only, for clients that can sustain it. |  |
| AAD-3.2 | No Permanent Admin Role Assignments | High | Entra ID P2 | Partially | **Hardened** | Standing admin rights are the target of every privilege-escalation path. | PIM eligible-only admin is NRG's target state where P2 exists. | Requires Entra ID P2. The break-glass pair remains permanent by design. Partially automated: PIM eligibility is read; whether the remaining permanent GAs are the break-glass pair is confirmed by a person. |
| AAD-3.3 | PIM Requires MFA on Activation | High | Entra ID P2 | Fully | **Hardened** | Activation without MFA makes PIM a formality. | Same as AAD-3.2. | Requires Entra ID P2. |
| AAD-8.2 | Access Reviews for Privileged Roles | High | Entra ID P2 | Fully | **Hardened** | Privileged access that is never reviewed only grows. | Quarterly access reviews are part of NRG's regulated-client offering. | Requires Entra ID P2 and the AccessReview.Read.All consent. |
| AAD-10.1 | Identity Protection Risky User Workflow | High | Entra ID P2 | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-11.3 | Risky Service Principals Reviewed and Remediated | High | Entra ID P2 + Workload Identities add-on | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-11.5 | Continuous Access Evaluation Strict Mode | Low | M365 Business Premium or Entra ID P1 | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-11.6 | Cross-Tenant Inbound Trust Settings Restricted | High | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-11.8 | Terms of Use Policy Enforced | Low | M365 Business Premium or Entra ID P1 | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-11.9 | Workload Identity Conditional Access Policy | Medium | Entra Workload Identities Premium (add-on) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-12.1 | Users Without MFA — Named List | Critical | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — | Named-object or duplicate evidence for AAD-1.2; counts once via control links. |
| AAD-12.2 | Stale Guest Accounts — Named List | High | Included (all plans) — Access Reviews require Entra P2 | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-12.3 | Stale Licensed Member Accounts — Named List | High | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-12.4 | OAuth Apps with Tenant-Wide Consent — Named List | High | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — | Named-object or duplicate evidence for AAD-6.2; counts once via control links. |
| AAD-13.1 | Microsoft Secure Score | Medium | Included (all plans) | Partially | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — | Secure Score is Microsoft's number, reported as context, never scored. |
| AAD-14.1 | Application Credentials Current and Short-Lived | High | Included (Entra ID Free) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-15.2 | Applications with Tenant-Wide Data Permissions — Named List | High | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — | Named-object or duplicate evidence for AAD-15.1; counts once via control links. |
| AAD-2.2 | Named Locations Defined | Low | M365 Business Premium or Entra ID P1 | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-3.4 | PIM Requires Justification on Activation | Medium | Entra ID P2 | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-3.5 | PIM GA Activation Requires Approval | Medium | Entra ID P2 | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-3.6 | PIM Max Activation Duration 8 Hours or Less | Low | Entra ID P2 | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-4.1 | Guest Invite Permissions Restricted | High | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-4.2 | External Collaboration Settings Restricted | Medium | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-4.3 | B2B Guest Default Permissions Restricted | High | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-5.1 | Self-Service Password Reset Enabled | Medium | Included (all plans) | Manual | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| AAD-5.2 | SSPR Requires Multiple Authentication Methods | Medium | Included (all plans) | Manual | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| AAD-6.3 | Admin Consent Workflow Enabled | Medium | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-7.1 | Password Protection Lockout Configured | Medium | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-9.1 | Authenticator Number Matching Enabled | High | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |
| AAD-9.2 | Passwordless Authentication Methods Available | Low | Included (all plans) | Fully | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — |  |

### Identity: governance

| Control ID | Owner | Evidence source | Expected state | SLA class | Depends on | Effectiveness check | Effectiveness capability | Freshness |
|---|---|---|---|---|---|---|---|---|
| AAD-1.1 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) | A Conditional Access policy blocks legacy authentication for all users on all apps (or Security Defaults is on where no P1 exists). | Critical | — | Sign-in logs show zero successful legacy-protocol sign-ins over the period. | not collected | Daily |
| AAD-1.2 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies); Graph: authorization and authentication-method policies, Security Defaults (Invoke-NRGCollectAADAuthPolicies) | An enabled CA policy requires MFA (or an authentication strength) for all users on all cloud apps, and every enabled member has a registered method. | Critical | AAD-1.1 | Sign-in logs show interactive sign-ins completing MFA; no MFA-less success outside the break-glass pair. | not collected | Daily |
| AAD-11.2 | Identity | Graph: directory role members (Invoke-NRGCollectAADRoles) | No guest account holds any privileged directory role. | Critical | — | Same as AAD-3.1. | not collected | Daily |
| AAD-15.1 | Identity | Graph: appRoleAssignedTo on Graph, Exchange and SharePoint (Invoke-NRGCollectAADAppPermissions) | No application holds a tenant-takeover application permission other than documented Microsoft first-party apps. | Critical | — | App-role assignment delta between runs is empty or explained by a change ticket. | collected | Daily |
| AAD-2.1 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) | At least one enabled Conditional Access policy exists and the NRG baseline policy set is deployed (report-only policies do not count). | High | — | Same as AAD-1.2 and AAD-2.3: sign-in logs show the policies applied, not just present. | not collected | Weekly |
| AAD-3.1 | Identity | Graph: directory role members (Invoke-NRGCollectAADRoles) | Two to eight Global Administrators, all cloud-only, including the break-glass pair. | Critical | — | Audit logs show no role-assignment changes outside change tickets. | not collected | Weekly |
| AAD-6.2 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) | Users cannot consent to applications; consent goes through the admin consent workflow. | Critical | — | No new user-consented OAuth grants appear in the delegated-consent table since the last run (AAD-12.4 delta). | collected | Daily |
| AAD-7.2 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) | At least two cloud-only, CA-excluded emergency accounts exist, documented in the client record. | High | — | A quarterly test sign-in from each account succeeds and is logged (AAD-10.3, manual today). | not collected | Monthly |
| AAD-10.2 | Identity | Graph: directory role members (Invoke-NRGCollectAADRoles) | Every privileged role holder is a dedicated cloud-only admin account, not a daily-use identity. | High | AAD-3.1 | Admin accounts have no mailbox or license beyond what admin work needs. | not collected | Weekly |
| AAD-11.1 | Identity | Graph: authorization and authentication-method policies, Security Defaults (Invoke-NRGCollectAADAuthPolicies); Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) | A CA policy blocks the device code flow for all users. | High | AAD-2.1 | Sign-in logs show device-code sign-ins blocked, not merely challenged. | not collected | Weekly |
| AAD-2.3 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) | An enabled CA policy requires a compliant device for all users on all cloud apps. | High | AAD-2.1, INT-1.1 | Sign-in logs show sign-ins from non-compliant devices blocked. | not collected | Weekly |
| AAD-6.1 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) | Users cannot register applications. | Standard | — | No new user-owned app registrations appear since the last run. | not collected | Weekly |
| AAD-1.3 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) | An enabled CA policy requires a phishing-resistant authentication strength for every privileged role. | High | AAD-1.2 | Sign-in logs show admin sign-ins using FIDO2 or Windows Hello for Business only. | not collected | Weekly |
| AAD-1.4 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) | An enabled CA policy responds to High and Medium sign-in risk. | Standard | AAD-2.1 | Identity Protection risk detections show remediation, not just detection. | not collected | Weekly |
| AAD-1.5 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) | An enabled CA policy requires password change for High user risk. | Standard | AAD-2.1 | Risky users are remediated, not dismissed, within the SLA. | not collected | Weekly |
| AAD-10.4 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) | Sign-in frequency is set to the NRG value for the client tier. | Standard | AAD-2.1 | Session durations in sign-in logs do not exceed the configured frequency. | not collected | Weekly |
| AAD-11.4 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) | Token protection is enforced for Exchange and SharePoint on supported clients. | Standard | AAD-2.1 | Sign-in logs show sessions rejected on token replay. | not collected | Weekly |
| AAD-11.7 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) | Privileged roles can sign in only from compliant or privileged-access devices. | Standard | AAD-2.3 | Admin sign-ins originate from managed devices only. | not collected | Weekly |
| AAD-3.2 | Identity | Graph: PIM eligibility and assignment schedules, access reviews (Invoke-NRGCollectAADPIM); Graph: directory role members (Invoke-NRGCollectAADRoles) | No permanent privileged role assignments beyond the break-glass pair; admins are PIM-eligible. | High | AAD-7.2 | PIM activation history shows admins activating roles, not holding them. | not collected | Weekly |
| AAD-3.3 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) | Every privileged PIM role requires MFA on activation. | Standard | AAD-3.2 | PIM activation events show MFA satisfied. | not collected | Weekly |
| AAD-8.2 | Identity | Graph: PIM eligibility and assignment schedules, access reviews (Invoke-NRGCollectAADPIM) | A recurring access review covers every privileged role. | Standard | AAD-3.2 | Reviews complete on schedule with decisions applied, not auto-approved. | not collected | Monthly |
| AAD-10.1 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) |  |  |  |  |  |  |
| AAD-11.3 | Identity | Graph: authorization and authentication-method policies, Security Defaults (Invoke-NRGCollectAADAuthPolicies) |  |  |  |  |  |  |
| AAD-11.5 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) |  |  |  |  |  |  |
| AAD-11.6 | Identity | Graph: authorization and authentication-method policies, Security Defaults (Invoke-NRGCollectAADAuthPolicies) |  |  |  |  |  |  |
| AAD-11.8 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) |  |  |  |  |  |  |
| AAD-11.9 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) |  |  |  |  |  |  |
| AAD-12.1 | Identity | Graph: users and MFA registration report (Invoke-NRGCollectAADUsers) |  |  |  |  |  |  |
| AAD-12.2 | Identity | Graph: guests, stale accounts, OAuth grants, subscribed SKUs (Invoke-NRGCollectAADInventory) |  |  |  |  |  |  |
| AAD-12.3 | Identity | Graph: guests, stale accounts, OAuth grants, subscribed SKUs (Invoke-NRGCollectAADInventory) |  |  |  |  |  |  |
| AAD-12.4 | Identity | Graph: guests, stale accounts, OAuth grants, subscribed SKUs (Invoke-NRGCollectAADInventory) |  |  |  |  |  |  |
| AAD-13.1 | Identity | Graph: guests, stale accounts, OAuth grants, subscribed SKUs (Invoke-NRGCollectAADInventory) |  |  |  |  |  |  |
| AAD-14.1 | Identity | Graph: guests, stale accounts, OAuth grants, subscribed SKUs (Invoke-NRGCollectAADInventory) |  |  |  |  |  |  |
| AAD-15.2 | Identity | Graph: appRoleAssignedTo on Graph, Exchange and SharePoint (Invoke-NRGCollectAADAppPermissions) |  |  |  |  |  |  |
| AAD-2.2 | Identity | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) |  |  |  |  |  |  |
| AAD-3.4 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) |  |  |  |  |  |  |
| AAD-3.5 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) |  |  |  |  |  |  |
| AAD-3.6 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) |  |  |  |  |  |  |
| AAD-4.1 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) |  |  |  |  |  |  |
| AAD-4.2 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) |  |  |  |  |  |  |
| AAD-4.3 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) |  |  |  |  |  |  |
| AAD-5.1 | Identity | Graph: authorization and authentication-method policies, Security Defaults (Invoke-NRGCollectAADAuthPolicies) |  |  |  |  |  |  |
| AAD-5.2 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) |  |  |  |  |  |  |
| AAD-6.3 | Identity | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) |  |  |  |  |  |  |
| AAD-7.1 | Identity | Graph: authorization and authentication-method policies, Security Defaults (Invoke-NRGCollectAADAuthPolicies) |  |  |  |  |  |  |
| AAD-9.1 | Identity | Graph: authorization and authentication-method policies, Security Defaults (Invoke-NRGCollectAADAuthPolicies) |  |  |  |  |  |  |
| AAD-9.2 | Identity | Graph: authorization and authentication-method policies, Security Defaults (Invoke-NRGCollectAADAuthPolicies) |  |  |  |  |  |  |

## Email (48 controls)

### Email: tier

| Control ID | Control title | Severity | License requirement | Automated | Proposed tier | Reason | Why NRG owns this | Notes |
|---|---|---|---|---|---|---|---|---|
| DEF-1.3 | Spoof Intelligence Enabled | High | Included (EOP) | Fully | **Minimum** | Spoof intelligence is included in EOP and stops internal-domain spoofing. | Included in every plan; no reason for it to be off. |  |
| DEF-2.2 | Zero-Hour Auto Purge Enabled | High | Included (EOP) | Fully | **Minimum** | ZAP removes mail already delivered once it is known bad. | Included in EOP; the control that limits the blast radius of a campaign. |  |
| DEF-2.3 | Anti-Malware Common Attachments Blocked | High | Included (EOP) | Fully | **Minimum** | Blocking executable attachment types is the cheapest malware control there is. | Included in EOP. |  |
| EXO-1.2 | SMTP Client Authentication Disabled | High | Included (M365 Business Standard+) | Fully | **Minimum** | SMTP AUTH is password-only and is the protocol credential sprays use to send from a compromised mailbox. | No tenant NRG manages leaves SMTP AUTH on tenant-wide. | Multifunction printers and line-of-business apps need per-mailbox exceptions (EXO-7.4 lists them) or a relay connector. |
| EXO-1.3 | External Auto-Forwarding Blocked | High | Included (M365 Business Standard+) | Fully | **Minimum** | Automatic external forwarding is the BEC exfiltration channel. | Every BEC case NRG has worked involved forwarding; blocking it tenant-wide is non-negotiable. | Remote-domain block does not stop admin-set mailbox forwarding, which EXO-7.1 catches. |
| EXO-1.4 | DKIM Signing Enabled for All Domains | High | Included (M365 Business Standard+) | Fully | **Minimum** | Unsigned mail is trivially spoofable and fails DMARC alignment. | Outbound authentication is NRG's deliverability and anti-spoof baseline. | Pairs with DNS-1.2; both must be in place. |
| EXO-1.6 | Modern Authentication Enabled | Critical | Included (M365 Business Standard+) | Fully | **Minimum** | Basic authentication to Exchange has no MFA. | Modern auth is a precondition for MFA to mean anything on mail. | Microsoft has retired basic auth; this should always pass and a failure is a red flag. |
| EXO-7.1 | No Mailbox Forwarding to External Addresses | High | Included (all plans) | Fully | **Minimum** | A forwarding address set by an admin or an attacker with admin bypasses the remote-domain block. | Zero external mailbox forwarding is the standard; every exception is named. | Named-object check; exceptions documented per mailbox. |
| EXO-7.2 | No Inbox Rules Forwarding Externally | High | Included (all plans) | Fully | **Minimum** | Inbox rules that forward externally are the most common BEC persistence artifact. | Same as EXO-7.1. | Tri-state recipient classification; an unresolved recipient is reported, not assumed internal. |
| EXO-8.2 | No Transport Rule Redirects Mail Externally | Critical | Included (EOP) | Fully | **Minimum** | A transport rule redirecting mail externally is a tenant-wide exfiltration channel and is rarely legitimate. | No external redirect rules without a documented purpose. |  |
| DEF-1.1 | Safe Attachments Enabled with Block Action | High | Defender for Office 365 Plan 1 (M365 Business Premium) | Fully | **Standard** | Attachment detonation is the primary malware control in mail. | Same as EXO-1.5. | License blocked on EOP-only tenants. |
| DEF-1.2 | Safe Links Enabled and Hardened | High | Defender for Office 365 Plan 1 (M365 Business Premium) | Fully | **Standard** | Time-of-click URL protection is the primary phishing control in mail. | Same as EXO-1.5. | License blocked on EOP-only tenants. |
| EXO-1.5 | Anti-Phishing Impersonation Protection Enabled | High | Defender for Office 365 Plan 1 (M365 Business Premium) | Fully | **Standard** | Impersonation protection catches the display-name and lookalike-domain phish that gets past DMARC. | Standard for every Defender for Office 365 P1 client (Business Premium includes it). | License blocked on EOP-only tenants, not failed. |
| EXO-2.6 | Shared Mailboxes Block Direct Sign-In | High | Included (M365 Business Standard+) | Fully | **Standard** | A shared mailbox with sign-in enabled is an unmonitored account with no MFA and a known address. | Shared mailboxes exist for delegation, not sign-in. | EXO-6.2 is the named-list twin. |
| EXO-5.3 | No Allowed Sender Domains Bypassing Anti-Spam Filtering | High | Included (all plans) | Fully | **Standard** | An allowed sender domain bypasses every filter for that domain and is the classic "allow our partner" mistake. | NRG does not run tenant-wide sender-domain allow lists. |  |
| DEF-1.4 | Honor DMARC Policy (Defender Layer) | High | Included (EOP) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — | Named-object or duplicate evidence for EXO-1.7; counts once via control links. |
| DEF-1.5 | Phishing Threshold Level Aggressive | Low | Included (EOP) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-1.6 | First Contact Safety Tip Enabled | Low | Included (EOP) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-2.1 | Preset Security Policies Applied | Low | Defender for Office 365 Plan 1 (M365 Business Premium) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-2.4 | Phishing Directed to Quarantine Not Junk | High | Included (EOP) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-2.5 | High Confidence Spam to Quarantine | Medium | Included (EOP) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-2.6 | Bulk Mail Threshold Configured | Low | Included (EOP) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-3.1 | Unauthenticated Sender Indicator Enabled | Medium | Included (EOP) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-3.2 | Via Tag Enabled in Anti-Phishing Policy | Low | Included (EOP) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-3.3 | Defender for Cloud Apps Connected | Medium | Microsoft Defender for Cloud Apps (M365 E5 or add-on) | Manual | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| DEF-4.1 | DLP Policy Covers All Key Workloads | High | M365 Business Premium or E3+ | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-4.2 | DLP Policy Uses Sensitive Information Types | High | M365 Business Premium or E3+ | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-4.4 | Priority Accounts Tagged in Defender | Medium | Defender for Office 365 Plan 2 (M365 E5 or add-on) | Manual | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| DEF-4.5 | Endpoint DLP Policy Active on Managed Devices | High | M365 E5 or E5 Compliance add-on | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-4.6 | Attack Simulation Training Campaigns Active | Low | Defender for Office 365 Plan 2 (M365 E5 or add-on) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-4.7 | Safe Links Protects Office Applications | High | Defender for Office 365 Plan 1 (M365 Business Premium) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DEF-5.1 | Tenant Allow/Block List Entries Time-Boxed | High | Included (EOP) | Fully | **Assessment-only** | Useful Defender evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-1.7 | Honor DMARC Policy Enabled | High | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-2.3 | POP3 Access Disabled | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-2.4 | IMAP Access Disabled | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-2.5 | Customer Lockbox Enabled | Medium | M365 E5 or E5 Compliance add-on | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-3.1 | Connection Filter Safe List Bypass Disabled | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-3.2 | Outbound Spam Sending Limits Configured | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-4.3 | Safe Attachments for SharePoint OneDrive Teams Enabled | High | Defender for Office 365 Plan 1 (M365 Business Premium) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-4.4 | Anti-Spam Inbound Policy Properly Configured | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-5.2 | Priority Account Protection Active in Anti-Phishing Policy | Medium | Defender for Office 365 Plan 1 (M365 Business Premium) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-6.1 | Mailboxes with External Email Forwarding — Named List | Critical | Included (all plans) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — | Named-object or duplicate evidence for EXO-7.1; counts once via control links. |
| EXO-6.2 | Shared Mailboxes with Sign-In Enabled — Named List | High | Included (all plans) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — | Named-object or duplicate evidence for EXO-2.6; counts once via control links. |
| EXO-6.4 | Per-User SMTP AUTH Override — Named List | High | Included (all plans) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — | Named-object or duplicate evidence for EXO-7.4; counts once via control links. |
| EXO-7.4 | No Per-User SMTP AUTH Overrides | High | Included (all plans) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-8.1 | Mail Flow Connectors Reviewed and Hardened | High | Included (EOP) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-9.1 | Mailboxes Protected by Hold or Retention Policy | High | Exchange Online Plan 2 or Exchange Online Archiving (M365 Business Premium, E3, E5) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-9.2 | Deleted Item Retention Window at Maximum | Medium | Included (all plans) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |

### Email: governance

| Control ID | Owner | Evidence source | Expected state | SLA class | Depends on | Effectiveness check | Effectiveness capability | Freshness |
|---|---|---|---|---|---|---|---|---|
| DEF-1.3 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) | Spoof intelligence is enabled in the in-force anti-phishing policy. | High | — | Spoof intelligence insight shows spoofed senders blocked. | not collected | Weekly |
| DEF-2.2 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) | Zero-hour auto purge is enabled for phishing, malware and spam. | High | — | ZAP actions appear in the threat protection status report. | not collected | Weekly |
| DEF-2.3 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) | The common attachments filter is enabled with the NRG blocked-type list. | High | — | Message trace shows blocked attachment types quarantined. | not collected | Weekly |
| EXO-1.2 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) | SMTP AUTH is disabled tenant-wide; per-mailbox exceptions are documented (EXO-7.4). | Critical | — | Message trace shows no SMTP AUTH submissions outside the documented exceptions. | not collected | Daily |
| EXO-1.3 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) | Outbound spam policy and remote domain block automatic external forwarding. | Critical | — | Message trace shows no auto-forwarded messages leaving the tenant. | not collected | Daily |
| EXO-1.4 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) | DKIM signing is enabled for every accepted domain with rotated keys. | High | DNS-1.2 | DMARC aggregate reports show DKIM-aligned pass for outbound mail. | not collected | Weekly |
| EXO-1.6 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) | Modern authentication is enabled and basic authentication is off for every protocol. | High | — | Sign-in logs show no basic-auth successes. | not collected | Weekly |
| EXO-7.1 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) | No mailbox forwards to an external address (ForwardingSmtpAddress or ForwardingAddress) without a documented exception. | Critical | EXO-1.3 | Message trace shows no forwarded mail to external recipients. | not collected | Daily |
| EXO-7.2 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) | No inbox rule forwards or redirects to an external recipient. | Critical | EXO-1.3 | Same as EXO-7.1; the forwarding-rule alert (EXO-3.3) fires on any new rule. | not collected | Daily |
| EXO-8.2 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) | No transport rule redirects or blind-copies mail externally without a documented purpose. | Critical | — | Message trace shows no rule-redirected external mail. | not collected | Daily |
| DEF-1.1 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) | Safe Attachments is enabled with Block action in the in-force policy for all recipients. | High | — | Threat Explorer shows detonation verdicts blocking attachments. | not collected | Weekly |
| DEF-1.2 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) | Safe Links is enabled with click tracking and no user override in the in-force policy. | High | — | URL click reports show blocked clicks. | not collected | Weekly |
| EXO-1.5 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) | Impersonation protection covers priority users and all accepted domains in the in-force anti-phishing policy. | High | DEF-1.3 | Threat Explorer shows impersonation detections being quarantined. | not collected | Weekly |
| EXO-2.6 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) | Every shared mailbox has sign-in blocked. | High | — | No interactive sign-ins by shared mailbox accounts in sign-in logs. | not collected | Weekly |
| EXO-5.3 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) | No allowed sender domains in any anti-spam policy. | High | — | Spoofed mail from those domains would be filtered; message trace shows no allow-listed bypasses. | not collected | Weekly |
| DEF-1.4 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| DEF-1.5 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| DEF-1.6 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| DEF-2.1 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| DEF-2.4 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| DEF-2.5 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| DEF-2.6 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| DEF-3.1 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| DEF-3.2 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| DEF-3.3 | Email | Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) |  |  |  |  |  |  |
| DEF-4.1 | Email | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| DEF-4.2 | Email | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| DEF-4.4 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| DEF-4.5 | Email | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| DEF-4.6 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| DEF-4.7 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| DEF-5.1 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) |  |  |  |  |  |  |
| EXO-1.7 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| EXO-2.3 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| EXO-2.4 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| EXO-2.5 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| EXO-3.1 | Email | Exchange Online PowerShell: connection filter policy (Invoke-NRGCollectEXOConnectionFilter) |  |  |  |  |  |  |
| EXO-3.2 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| EXO-4.3 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| EXO-4.4 | Email | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| EXO-5.2 | Email | Exchange Online PowerShell: Defender for Office 365 and EOP policies in force (Invoke-NRGCollectDefender) |  |  |  |  |  |  |
| EXO-6.1 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) |  |  |  |  |  |  |
| EXO-6.2 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) |  |  |  |  |  |  |
| EXO-6.4 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) |  |  |  |  |  |  |
| EXO-7.4 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) |  |  |  |  |  |  |
| EXO-8.1 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) |  |  |  |  |  |  |
| EXO-9.1 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) |  |  |  |  |  |  |
| EXO-9.2 | Email | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) |  |  |  |  |  |  |

## DNS (10 controls)

### DNS: tier

| Control ID | Control title | Severity | License requirement | Automated | Proposed tier | Reason | Why NRG owns this | Notes |
|---|---|---|---|---|---|---|---|---|
| DNS-1.1 | SPF Record Published | High | Included (M365 Business Standard+) | Fully | **Minimum** | No SPF means anyone can send as the client. | Domain authentication is NRG's anti-spoofing baseline for every managed domain. |  |
| DNS-1.2 | DKIM Records Published | High | Included (M365 Business Standard+) | Fully | **Minimum** | DKIM selectors must be published or EXO-1.4 signing does nothing. | Same as DNS-1.1. | Checks the customer selector CNAMEs, not the rotating targets. |
| DNS-1.3 | DMARC Policy at Quarantine or Reject | Critical | Included (M365 Business Standard+) | Fully | **Minimum** | p=none reports spoofing and stops none of it. | Enforced DMARC is NRG's target state for every managed domain. | A documented rollout window at p=none with reporting (DMARCian) is an accepted exception with a review date. |
| DNS-1.4 | MTA-STS Policy in Enforce Mode | Medium | Included (M365 Business Standard+) | Fully | **Hardened** | MTA-STS stops downgrade attacks on inbound mail transport. | Regulated clients; operationally quiet once set. |  |
| DNS-1.5 | TLS-RPT Record Published | Low | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful domain evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DNS-1.6 | DNSSEC Enabled | Low | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful domain evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DNS-2.1 | DKIM Key Rotation Cadence | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful domain evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DNS-2.2 | CAA Record Restricts Certificate Issuance | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful domain evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DNS-2.3 | TLS Certificate Expiry on Mail Hostnames | High | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful domain evidence; not a universal NRG operating requirement in v1.0. | — |  |
| DNS-2.4 | Certificate Transparency Log Hygiene | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful domain evidence; not a universal NRG operating requirement in v1.0. | — |  |

### DNS: governance

| Control ID | Owner | Evidence source | Expected state | SLA class | Depends on | Effectiveness check | Effectiveness capability | Freshness |
|---|---|---|---|---|---|---|---|---|
| DNS-1.1 | DNS | DNS over HTTPS (Cloudflare, Google) with Resolve-DnsName fallback (Invoke-NRGCollectDNSEmailRecords) | Every managed domain publishes exactly one valid SPF record ending in -all or ~all. | High | — | DMARC aggregate reports show SPF pass for the expected senders. | not collected | Daily |
| DNS-1.2 | DNS | DNS over HTTPS (Cloudflare, Google) with Resolve-DnsName fallback (Invoke-NRGCollectDNSEmailRecords) | Both Microsoft DKIM selector CNAMEs resolve for every accepted domain. | High | EXO-1.4 | Same as EXO-1.4. | not collected | Daily |
| DNS-1.3 | DNS | DNS over HTTPS (Cloudflare, Google) with Resolve-DnsName fallback (Invoke-NRGCollectDNSEmailRecords) | Every managed domain publishes DMARC at p=quarantine or p=reject with the NRG reporting address (DMARCian). | Critical | DNS-1.1, DNS-1.2 | DMARC aggregate reports show aligned senders and no unexplained failure trend. | not collected | Daily |
| DNS-1.4 | DNS | DNS over HTTPS (Cloudflare, Google) with Resolve-DnsName fallback (Invoke-NRGCollectDNSEmailRecords) | MTA-STS is published in enforce mode with a valid policy file. | Standard | — | TLS-RPT reports show no delivery failures. | not collected | Daily |
| DNS-1.5 | DNS | DNS over HTTPS (Cloudflare, Google) with Resolve-DnsName fallback (Invoke-NRGCollectDNSEmailRecords) |  |  |  |  |  |  |
| DNS-1.6 | DNS | DNS over HTTPS (Cloudflare, Google) with Resolve-DnsName fallback (Invoke-NRGCollectDNSEmailRecords) |  |  |  |  |  |  |
| DNS-2.1 | DNS | DNS over HTTPS (Cloudflare, Google) with Resolve-DnsName fallback (Invoke-NRGCollectDNSEmailRecords) |  |  |  |  |  |  |
| DNS-2.2 | DNS | DNS over HTTPS (Cloudflare, Google) with Resolve-DnsName fallback (Invoke-NRGCollectDNSEmailRecords) |  |  |  |  |  |  |
| DNS-2.3 | DNS | DNS over HTTPS (Cloudflare, Google) with Resolve-DnsName fallback (Invoke-NRGCollectDNSEmailRecords) |  |  |  |  |  |  |
| DNS-2.4 | DNS | DNS over HTTPS (Cloudflare, Google) with Resolve-DnsName fallback (Invoke-NRGCollectDNSEmailRecords) |  |  |  |  |  |  |

## Logging & Audit (20 controls)

### Logging & Audit: tier

| Control ID | Control title | Severity | License requirement | Automated | Proposed tier | Reason | Why NRG owns this | Notes |
|---|---|---|---|---|---|---|---|---|
| EXO-1.1 | Mailbox Audit Logging Enabled | High | Included (M365 Business Standard+) | Fully | **Minimum** | Mailbox auditing is the evidence in every BEC investigation. | NRG cannot investigate what was not logged. | On by default since 2019; a false here is deliberate and must be explained. |
| EXO-4.2 | Admin Audit Log Enabled | High | Included (M365 Business Standard+) | Fully | **Minimum** | Admin audit logging records every configuration change, including an attacker's. | Same as EXO-1.1. | Read through Get-AdminAuditLogConfig on the Exchange session. |
| PVW-1.1 | Unified Audit Log Enabled | Critical | Included (M365 Business Standard+) | Fully | **Minimum** | The unified audit log is the single searchable record of tenant activity. | Same as EXO-1.1. | PVW-2.1 (search enabled) reads the same switch and counts once. |
| DEF-3.4 | Defender Alert Email Notifications Configured | High | Included (all plans) | Fully | **Standard** | Alerts nobody receives are not alerts. | Defender notifications must reach NRG's queue, not a client mailbox nobody reads. | Point at the NRG monitoring address, not an individual. |
| DEF-4.3 | Risky OAuth Application Alerts Configured | High | Included (all plans) | Fully | **Standard** | Risky OAuth app alerts are the early warning for consent phishing. | Same as DEF-3.4. |  |
| EXO-3.3 | Alert Policy — Email Forwarding Rules | High | Included (M365 Business Standard+) | Fully | **Standard** | The forwarding-rule alert policy is the fastest BEC detection Microsoft offers. | Same as DEF-3.4. |  |
| PVW-1.2 | Audit Log Retention Minimum 90 Days | Medium | Included (all plans) | Fully | **Standard** | 90 days is the minimum window in which a compromise is usually discovered. | NRG's investigation window. | 180 days is the default today; one year needs E5 (PVW-4.2, Hardened). |
| PVW-4.1 | Microsoft Purview Audit (Premium) Enabled | High | M365 E5 or E5 Compliance add-on | Fully | **Hardened** | Audit (Premium) adds the MailItemsAccessed events that prove what an attacker read. | E5 clients get the full investigation record. | Requires E5 or E5 Compliance. |
| PVW-4.2 | Audit Log Retention Policy Extends to 1 Year or More | High | M365 E5 or E5 Compliance add-on | Fully | **Hardened** | One-year retention covers the long-dwell compromise. | Same as PVW-4.1. | Requires E5 or E5 Compliance. |
| AAD-10.3 | Break-Glass Account Sign-In Monitoring | High | Included (all plans) | Manual | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| AAD-8.1 | PIM Alerts Configured | Medium | Entra ID P2 | Manual | **Assessment-only** | Useful identity evidence; not a universal NRG operating requirement in v1.0. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| EXO-3.4 | Alert Policy — Unusual Mail Volume | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-3.5 | Transport Rules Changes Audited | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-4.1 | Mailbox Audit Log Age Limit Sufficient | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-5.1 | Per-User Mailbox Audit Logging Enabled for All Mailboxes | High | Included (all plans) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| EXO-6.3 | Mailboxes with Audit Logging Disabled — Named List | High | Included (all plans) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — | Named-object or duplicate evidence for EXO-7.3; counts once via control links. |
| EXO-7.3 | No Mailboxes with Per-User Audit Explicitly Disabled | Medium | Included (all plans) | Fully | **Assessment-only** | Useful mail evidence; not a universal NRG operating requirement in v1.0. | — |  |
| PPL-3.5 | Copilot Interaction Audit Logging Active | High | Included (all plans) | Fully | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — |  |
| PVW-2.1 | Purview Audit Log Search Enabled | High | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — | Named-object or duplicate evidence for PVW-1.1; counts once via control links. |
| PVW-3.1 | Audit Logs Exported to SIEM | Medium | Microsoft Sentinel (add-on) or Defender XDR | Manual | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |

### Logging & Audit: governance

| Control ID | Owner | Evidence source | Expected state | SLA class | Depends on | Effectiveness check | Effectiveness capability | Freshness |
|---|---|---|---|---|---|---|---|---|
| EXO-1.1 | Logging | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) | Organization-wide mailbox auditing is enabled and no mailbox is in the audit bypass list. | High | — | A test search returns MailItemsAccessed or similar events for a known mailbox. | not collected | Weekly |
| EXO-4.2 | Logging | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) | Admin audit logging is enabled. | High | — | A test search returns the assessment sign-in itself as an admin audit event. | not collected | Weekly |
| PVW-1.1 | Logging | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) | Unified audit log ingestion is enabled. | Critical | — | A test search of the unified audit log returns recent events. | not collected | Weekly |
| DEF-3.4 | Logging | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) | Defender alert notifications are sent to the NRG monitoring address. | High | — | A test alert reaches the NRG queue. | not collected | Weekly |
| DEF-4.3 | Logging | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) | The risky-OAuth-app alert policy is enabled and routed to NRG. | High | DEF-3.4 | A consent event produces an alert in the NRG queue. | not collected | Weekly |
| EXO-3.3 | Logging | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) | The forwarding-rule alert policy is enabled and routed to NRG. | High | DEF-3.4, PVW-1.1 | A test inbox rule produces an alert in the NRG queue. | not collected | Weekly |
| PVW-1.2 | Logging | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) | Audit log retention is at least 90 days (180 by default; one year on E5). | Standard | PVW-1.1 | Events older than 90 days are still searchable. | not collected | Monthly |
| PVW-4.1 | Logging | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) | Audit (Premium) is enabled for E5-licensed users. | Standard | PVW-1.1 | MailItemsAccessed events appear for E5 mailboxes. | not collected | Monthly |
| PVW-4.2 | Logging | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) | A retention policy keeps audit records for one year or more. | Standard | PVW-4.1 | Events older than 180 days are searchable. | not collected | Monthly |
| AAD-10.3 | Logging | Graph: PIM role policies, consent settings, app-registration settings (Invoke-NRGCollectAADIdentityGovernance) |  |  |  |  |  |  |
| AAD-8.1 | Logging | Graph: PIM eligibility and assignment schedules, access reviews (Invoke-NRGCollectAADPIM) |  |  |  |  |  |  |
| EXO-3.4 | Logging | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| EXO-3.5 | Logging | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| EXO-4.1 | Logging | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| EXO-5.1 | Logging | Exchange Online PowerShell: organization, transport and authentication configuration (Invoke-NRGCollectEXOMailboxConfig) |  |  |  |  |  |  |
| EXO-6.3 | Logging | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) |  |  |  |  |  |  |
| EXO-7.3 | Logging | Exchange Online PowerShell: mailboxes, inbox rules, connectors, transport rules (Invoke-NRGCollectEXOInventory) |  |  |  |  |  |  |
| PPL-3.5 | Logging | Graph: Copilot licensing and settings (Invoke-NRGCollectM365Copilot) |  |  |  |  |  |  |
| PVW-2.1 | Logging | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| PVW-3.1 | Logging | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |

## Endpoint (17 controls)

### Endpoint: tier

| Control ID | Control title | Severity | License requirement | Automated | Proposed tier | Reason | Why NRG owns this | Notes |
|---|---|---|---|---|---|---|---|---|
| INT-1.1 | Device Compliance Policies Configured | High | M365 Business Premium or Intune Plan 1 | Fully | **Minimum** | Compliance policies are the definition of a healthy device that everything else gates on. | Every Intune-licensed client gets a compliance policy set; DB-2.1 enrollment feeds it. | License blocked without Intune, not failed. |
| INT-1.3 | BitLocker Encryption Required on Windows | High | M365 Business Premium or Intune Plan 1 | Fully | **Minimum** | Unencrypted laptops turn a theft into a breach notification. | Disk encryption is mandatory in the device build standard (DB-2.5). |  |
| INT-1.5 | Antivirus Policy Deployed via Intune | High | M365 Business Premium or Intune Plan 1 | Fully | **Minimum** | Antivirus policy is the minimum protection for every managed Windows device. | DB-3.2 in the device standard. | Where a third-party EDR is declared, this is reported as covered by it, not passed. |
| INT-2.1 | Endpoint Detection and Response Policy Deployed | Critical | Microsoft Defender for Endpoint Plan 2 or Defender for Business (M365 Business Premium) | Fully | **Minimum** | EDR is the control that turns an infection into an alert instead of a ransomware event. | DB-3.2; NRG's stack is Defender for Endpoint or Cortex XDR. | ThirdPartyEDR declares Cortex; the check leaves the score and is verified in the vendor console. |
| INT-2.5 | Windows Update Compliance Policy Deployed | High | M365 Business Premium or Intune Plan 1 | Fully | **Minimum** | Patch deadlines are the exposure window (DB-4.1). | Update rings with an enforced deadline on every managed Windows device. | DB-4.7 and DB-4.8 cover monitoring and verification of the same process. |
| INT-2.2 | Attack Surface Reduction Rules Enabled | High | Microsoft Defender for Endpoint Plan 1+ | Fully | **Standard** | ASR rules block the Office-macro and script techniques ransomware starts with. | Standard on every Defender for Endpoint client. | Audit mode first; block mode is the requirement. |
| INT-4.1 | Windows LAPS Deployed via Intune | High | M365 Business Premium or Intune Plan 1 | Fully | **Standard** | Shared local admin passwords are the lateral-movement path on every network. | LAPS is DB-2.3 in the device standard. |  |
| INT-4.3 | Device OS Version Compliance Enforced | High | M365 Business Premium or Intune Plan 1 | Fully | **Standard** | An out-of-date OS is a device the compliance policy should be refusing. | Pairs with INT-2.5 so an unpatched device loses access rather than persisting. |  |
| INT-4.2 | Windows Hello for Business Deployed | Medium | M365 Business Premium or Intune Plan 1 | Fully | **Hardened** | Windows Hello for Business is the phishing-resistant credential for users, not just admins. | Elevated-risk clients. | Hardware and rollout dependent. |
| INT-1.2 | Non-Compliant Device Access Blocked via CA | High | M365 Business Premium or Intune Plan 1 | Fully | **Assessment-only** | Useful endpoint evidence; not a universal NRG operating requirement in v1.0. | — | Named-object or duplicate evidence for AAD-2.3; counts once via control links. |
| INT-1.4 | Mobile Application Management Configured | Medium | M365 Business Premium or Intune Plan 1 | Fully | **Assessment-only** | Useful endpoint evidence; not a universal NRG operating requirement in v1.0. | — |  |
| INT-2.3 | Windows Firewall Policy Deployed via Intune | High | M365 Business Premium or Intune Plan 1 | Fully | **Assessment-only** | Useful endpoint evidence; not a universal NRG operating requirement in v1.0. | — |  |
| INT-2.4 | macOS FileVault Encryption Required | High | M365 Business Premium or Intune Plan 1 | Fully | **Assessment-only** | Useful endpoint evidence; not a universal NRG operating requirement in v1.0. | — |  |
| INT-3.1 | Device Enrollment Restrictions Configured | Medium | M365 Business Premium or Intune Plan 1 | Fully | **Assessment-only** | Useful endpoint evidence; not a universal NRG operating requirement in v1.0. | — |  |
| INT-3.2 | Mobile App Configuration Policies Deployed | Low | M365 Business Premium or Intune Plan 1 | Fully | **Assessment-only** | Useful endpoint evidence; not a universal NRG operating requirement in v1.0. | — |  |
| INT-3.3 | Conditional Launch Policies Configured | High | M365 Business Premium or Intune Plan 1 | Fully | **Assessment-only** | Useful endpoint evidence; not a universal NRG operating requirement in v1.0. | — |  |
| INT-4.4 | Mobile Device Compliance Requires PIN or Biometric | High | M365 Business Premium or Intune Plan 1 | Fully | **Assessment-only** | Useful endpoint evidence; not a universal NRG operating requirement in v1.0. | — |  |

### Endpoint: governance

| Control ID | Owner | Evidence source | Expected state | SLA class | Depends on | Effectiveness check | Effectiveness capability | Freshness |
|---|---|---|---|---|---|---|---|---|
| INT-1.1 | Endpoint | Graph: Intune compliance policies, enrollment configuration, update rings, devices (Invoke-NRGCollectIntuneDeviceCompliance) | An assigned compliance policy exists per managed platform with a non-compliance action. | High | — | Device compliance report shows devices evaluated, not "not evaluated". | not collected | Weekly |
| INT-1.3 | Endpoint | Graph: Intune compliance policies, enrollment configuration, update rings, devices (Invoke-NRGCollectIntuneDeviceCompliance) | An assigned policy requires BitLocker on Windows with recovery keys escrowed to Entra. | High | INT-1.1 | Encryption report shows every Windows device encrypted with a key in Entra. | not collected | Weekly |
| INT-1.5 | Endpoint | Graph: Intune endpoint-security policies by template (Invoke-NRGCollectIntuneEndpointSecurity) | An assigned antivirus policy configures Defender Antivirus (real-time, cloud protection, PUA). | High | INT-1.1 | Defender for Endpoint shows AV signatures current and real-time protection on per device (DEV-2.x). | collected | Weekly |
| INT-2.1 | Endpoint | Graph: Intune endpoint-security policies by template (Invoke-NRGCollectIntuneEndpointSecurity) | An assigned EDR policy onboards every managed Windows device to Defender for Endpoint (or the declared third-party EDR is confirmed in its console). | Critical | INT-1.1 | Every enrolled device appears as onboarded and active in the EDR console (DEV-2.1). | collected | Daily |
| INT-2.5 | Endpoint | Graph: Intune compliance policies, enrollment configuration, update rings, devices (Invoke-NRGCollectIntuneDeviceCompliance) | Assigned update rings enforce a deadline and grace period on every Windows device. | High | INT-1.1 | Update compliance report shows devices within the deadline (DEV-4.1); DB-4.7 monitors failures. | collected | Weekly |
| INT-2.2 | Endpoint | Graph: Intune endpoint-security policies by template (Invoke-NRGCollectIntuneEndpointSecurity) | An assigned ASR policy sets the NRG rule set to Block. | High | — | ASR report shows rules in block mode and detections occurring. | not collected | Weekly |
| INT-4.1 | Endpoint | Graph: Intune endpoint-security policies by template (Invoke-NRGCollectIntuneEndpointSecurity) | An assigned Windows LAPS policy backs up the local admin password to Entra and rotates it. | High | INT-1.1 | Every Windows device has a current LAPS password in Entra (DEV-4.x). | collected | Weekly |
| INT-4.3 | Endpoint | Graph: Intune compliance policies, enrollment configuration, update rings, devices (Invoke-NRGCollectIntuneDeviceCompliance) | Compliance policy requires the NRG minimum OS build per platform. | Standard | INT-2.5 | Device compliance report shows no devices below the minimum. | not collected | Weekly |
| INT-4.2 | Endpoint | Graph: Intune compliance policies, enrollment configuration, update rings, devices (Invoke-NRGCollectIntuneDeviceCompliance) | Windows Hello for Business is enabled for enrolled Windows devices. | Standard | INT-1.1 | Sign-in logs show WHfB as the method for user sign-ins. | not collected | Weekly |
| INT-1.2 | Endpoint | Graph: Intune compliance policies, enrollment configuration, update rings, devices (Invoke-NRGCollectIntuneDeviceCompliance); Graph: Conditional Access policies (Invoke-NRGCollectAADCAPolicies) |  |  |  |  |  |  |
| INT-1.4 | Endpoint | Graph: Intune app protection and configuration policies (Invoke-NRGCollectIntuneAppProtection) |  |  |  |  |  |  |
| INT-2.3 | Endpoint | Graph: Intune endpoint-security policies by template (Invoke-NRGCollectIntuneEndpointSecurity) |  |  |  |  |  |  |
| INT-2.4 | Endpoint | Graph: Intune compliance policies, enrollment configuration, update rings, devices (Invoke-NRGCollectIntuneDeviceCompliance) |  |  |  |  |  |  |
| INT-3.1 | Endpoint | Graph: Intune compliance policies, enrollment configuration, update rings, devices (Invoke-NRGCollectIntuneDeviceCompliance) |  |  |  |  |  |  |
| INT-3.2 | Endpoint | Graph: Intune app protection and configuration policies (Invoke-NRGCollectIntuneAppProtection) |  |  |  |  |  |  |
| INT-3.3 | Endpoint | Graph: Intune app protection and configuration policies (Invoke-NRGCollectIntuneAppProtection) |  |  |  |  |  |  |
| INT-4.4 | Endpoint | Graph: Intune compliance policies, enrollment configuration, update rings, devices (Invoke-NRGCollectIntuneDeviceCompliance) |  |  |  |  |  |  |

## Collaboration & Data (62 controls)

### Collaboration & Data: tier

| Control ID | Control title | Severity | License requirement | Automated | Proposed tier | Reason | Why NRG owns this | Notes |
|---|---|---|---|---|---|---|---|---|
| SPO-1.3 | SharePoint Legacy Authentication Blocked | High | Included (M365 Business Standard+) | Fully | **Minimum** | Legacy auth to SharePoint bypasses MFA the same way it does for mail. | Same reason as AAD-1.1. |  |
| SPO-1.1 | External Sharing Restricted | High | Included (M365 Business Standard+) | Fully | **Standard** | Unrestricted external sharing is how a client's data ends up on the open internet. | NRG-managed tenants restrict sharing to existing or authenticated guests. | Anyone links are the specific thing to remove; SPO-1.2 covers the default link type. |
| SPO-1.2 | Default Sharing Link Not Anonymous | Medium | Included (M365 Business Standard+) | Fully | **Standard** | An anonymous default link makes every share an anonymous share. | Same as SPO-1.1. |  |
| SPO-3.3 | OneDrive Version History Enabled | High | Included (M365 Business Standard+) | Fully | **Assessment-only** | Version history is the ransomware recovery mechanism for OneDrive. | Recovery is part of the managed service. | On by default; a false here is deliberate. Assessment-only in v1.0 because the read needs the SharePoint Management Shell (`-IncludeSharePointShell`), which is not part of the normal Standard run; candidate for promotion to Standard once shell collection is standard. Governance row kept below. |
| TMS-3.2 | Auto-Admit Only Authenticated Organization Users | High | Included (M365 Business Standard+) | Fully | **Standard** | The lobby is the only thing between an external caller and a meeting. | NRG-managed tenants keep externals in the lobby until admitted. | Only OrganizerOnly / EveryoneInCompanyExcludingGuests satisfy it. |
| PVW-1.3 | DLP Policy Active for Sensitive Data | High | M365 Business Premium or E3+ | Fully | **Hardened** | DLP is the control for regulated data leaving the tenant. | Regulated clients. | Needs a sensitive-information-type design first; PVW-3.4 and DEF-4.1/4.2 are the same policy family. |
| PVW-4.3 | Sensitivity Labels Defined and Published | High | M365 Business Premium or E3+ | Fully | **Hardened** | Sensitivity labels are the foundation for DLP, Copilot and sharing controls. | Regulated clients. | PVW-1.4 reads the same state and counts once. |
| SPO-1.5 | Unmanaged Device Access Restricted | Medium | M365 Business Premium or Entra ID P1 | Fully | **Hardened** | Unmanaged devices downloading company files defeat every endpoint control. | Same goal as AAD-2.3, applied to SharePoint and OneDrive access. | Relies on CA (Entra ID P1). |
| SPO-2.1 | OneDrive Sync Client Restricted to Managed Devices | High | Included (M365 Business Standard+) | Fully | **Hardened** | Sync on unmanaged devices copies company data to home PCs. | Elevated-risk clients. |  |
| TMS-4.3 | Teams External Domain Federation Restricted to Allowlist | High | Included (all plans) | Fully | **Hardened** | Open federation lets any Teams tenant message users directly, the current phishing channel of choice. | Regulated clients run an allowlist. | Business impact; needs a partner list. |
| PPL-1.1 | Power Platform Tenant Isolation Enabled | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — |  |
| PPL-1.2 | Power Platform DLP Policy Active | High | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — |  |
| PPL-1.3 | Power Platform Environment Creation Restricted | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — |  |
| PPL-2.1 | Power Platform Connector Classification Reviewed | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — |  |
| PPL-2.2 | Power Automate Governance Policy Active | Medium | Included (M365 Business Standard+) | Partially | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — | No documented tenant setting; the evaluator reports manual verification. |
| PPL-2.3 | Power Apps Portal Creation Restricted | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — |  |
| PPL-3.1 | M365 Copilot Sensitivity Label Enforcement | High | M365 Business Premium or E3+ (Copilot requires M365 Copilot add-on) | Fully | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — |  |
| PPL-3.2 | DLP Policy Active for Copilot Interactions | High | M365 E5 Compliance add-on | Fully | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — |  |
| PPL-3.3 | Copilot Access Restricted to Licensed Users | Medium | M365 Copilot add-on license | Fully | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — |  |
| PPL-3.4 | Copilot Studio Agent Publishing Governed | High | Power Platform + Copilot Studio license | Manual | **Assessment-only** | Useful Power Platform evidence; most managed clients have no Power Platform footprint. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| PVW-1.4 | Sensitivity Labels Published | Medium | M365 Business Premium or E3+ | Fully | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — | Named-object or duplicate evidence for PVW-4.3; counts once via control links. |
| PVW-2.2 | Communication Compliance Policy Active | Low | M365 E5 Compliance add-on | Fully | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — |  |
| PVW-2.3 | Information Barriers Mode Configured | Low | M365 E5 Compliance add-on | Fully | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — |  |
| PVW-2.4 | Insider Risk Management Policy Active | Medium | M365 E5 Compliance add-on | Manual | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| PVW-2.5 | Retention Policy Covers Key Workloads | High | M365 Business Premium or E3+ | Fully | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — |  |
| PVW-2.6 | Auto-Labeling Policy Active | Medium | M365 E5 Compliance add-on | Fully | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — |  |
| PVW-3.2 | eDiscovery Case Management Configured | Medium | M365 Business Premium or E3+ | Manual | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| PVW-3.3 | Compliance Score Improvement Actions Tracked | Low | Included (all plans) | Manual | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| PVW-3.4 | Sensitive Information Types Used in DLP Policies | High | M365 Business Premium or E3+ | Fully | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — |  |
| PVW-4.4 | Records Management Labels Configured for Regulated Data | Low | M365 Business Premium or E3+ | Fully | **Assessment-only** | Useful compliance evidence; requirement depends on the client's regulatory scope. | — |  |
| SPO-1.4 | Guest Access Expiration Configured | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — |  |
| SPO-2.2 | External Sharing Link Expiration Configured | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — |  |
| SPO-2.3 | SharePoint Third-Party Apps From Store Restricted | Low | Included (M365 Business Standard+) | Manual | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| SPO-2.4 | Custom Script Disabled on SharePoint Sites | High | Included (M365 Business Standard+) | Manual | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| SPO-2.5 | Third-Party Cloud Storage Connectors Disabled | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — |  |
| SPO-2.6 | Email Attestation Required for Sharing | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — |  |
| SPO-2.7 | Reauthentication Required for Sharing Links | Low | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — |  |
| SPO-2.8 | OneDrive Sync Restricted by Tenant Domain GUID | High | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — |  |
| SPO-3.1 | Site Collection Admin Access Reviewed | Medium | Included (M365 Business Standard+) | Manual | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| SPO-3.2 | SharePoint Sharing Notifications Enabled | Low | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — |  |
| SPO-3.4 | SharePoint Guest Access Expiration Required | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — |  |
| SPO-4.1 | Departed-User OneDrive Retention Configured | Medium | Included (all plans) | Fully | **Assessment-only** | Useful sharing evidence; not a universal NRG operating requirement in v1.0. | — |  |
| TMS-1.1 | External Federation Access Restricted | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-1.2 | Teams Consumer Account Access Disabled | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-1.3 | Anonymous Meeting Join Disabled | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-1.4 | External Participants Cannot Take Screen Control | Low | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-1.5 | Recording Storage in Organization | Low | M365 Business Premium or E3+ | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-1.6 | Teams Guest Access Controlled | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-2.1 | Skype Consumer Contact Disabled | Medium | Included (M365 Business Standard+) | Manual | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| TMS-2.2 | Unverified App Publisher Blocked | Medium | Included (M365 Business Standard+) | Manual | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| TMS-2.3 | Third-Party Cloud Storage Disabled in Teams | High | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-2.4 | Teams Email Integration Disabled | High | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-2.5 | Cloud Recording Disabled for External Participants | Low | Included (M365 Business Standard+) | Manual | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — | No automated check (Config/coverage-exceptions.psd1); reported as requires manual verification. |
| TMS-2.6 | Broad Channel Meeting Invite Restricted | Low | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-2.7 | External User Chat Restricted | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-2.8 | PSTN Users Cannot Bypass Lobby | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-3.1 | Teams Meeting Watermarks Enabled | Low | Teams Premium (add-on) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-3.3 | Meeting Chat Disabled for Anonymous Participants | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-3.4 | Meeting Chat Copy Prevention via DLP | Low | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-4.1 | Meeting Recording Expiration Configured | Medium | Included (M365 Business Standard+) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-4.2 | Anonymous Users Cannot Start Meetings | High | Included (all plans) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |
| TMS-4.4 | Teams Events Cannot Be Attended by Anonymous Internet Users | Medium | Included (all plans) | Fully | **Assessment-only** | Useful Teams evidence; business impact varies too much for a universal requirement. | — |  |

### Collaboration & Data: governance

| Control ID | Owner | Evidence source | Expected state | SLA class | Depends on | Effectiveness check | Effectiveness capability | Freshness |
|---|---|---|---|---|---|---|---|---|
| SPO-1.3 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) | Legacy authentication to SharePoint is blocked. | High | — | No legacy-auth SharePoint sign-ins in sign-in logs. | not collected | Weekly |
| SPO-1.1 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) | External sharing is limited to existing or authenticated guests; anyone links are off. | High | — | Sharing audit shows no anonymous links created. | not collected | Weekly |
| SPO-1.2 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) | The default sharing link is not anonymous. | Standard | SPO-1.1 | Same as SPO-1.1. | not collected | Weekly |
| SPO-3.3 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) | OneDrive version history is enabled with the default or higher version count. | Standard | — | A restore from version history succeeds in a recovery test. | not collected | Monthly |
| TMS-3.2 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) | Meeting auto-admit is OrganizerOnly or EveryoneInCompanyExcludingGuests. | Standard | — | Meeting audit shows external participants admitted from the lobby, never auto-admitted. | not collected | Weekly |
| PVW-1.3 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) | A DLP policy in enforce mode covers the client's sensitive information types across Exchange, SharePoint, OneDrive and Teams. | Standard | PVW-1.1 | DLP reports show matches and blocks, not only test-mode hits. | not collected | Weekly |
| PVW-4.3 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) | Sensitivity labels are defined and published to all users. | Standard | — | Label usage reports show labels being applied. | not collected | Monthly |
| SPO-1.5 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) | Unmanaged devices get browser-only, no-download access to SharePoint and OneDrive. | Standard | AAD-2.3 | No file downloads from unmanaged devices in the audit log. | not collected | Weekly |
| SPO-2.1 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) | OneDrive sync is restricted to devices joined to the tenant domain. | Standard | INT-1.1 | No sync client sessions from unmanaged devices in the audit log. | not collected | Weekly |
| TMS-4.3 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) | External federation is restricted to an allowlist of partner domains. | Standard | — | Chat audit shows no messages from unlisted domains. | not collected | Weekly |
| PPL-1.1 | Collaboration & Data | Power Platform admin API over REST, in-process (Invoke-NRGCollectPowerPlatform) |  |  |  |  |  |  |
| PPL-1.2 | Collaboration & Data | Power Platform admin API over REST, in-process (Invoke-NRGCollectPowerPlatform) |  |  |  |  |  |  |
| PPL-1.3 | Collaboration & Data | Power Platform admin API over REST, in-process (Invoke-NRGCollectPowerPlatform) |  |  |  |  |  |  |
| PPL-2.1 | Collaboration & Data | Power Platform admin API over REST, in-process (Invoke-NRGCollectPowerPlatform) |  |  |  |  |  |  |
| PPL-2.2 | Collaboration & Data | Power Platform admin API over REST, in-process (Invoke-NRGCollectPowerPlatform) |  |  |  |  |  |  |
| PPL-2.3 | Collaboration & Data | Power Platform admin API over REST, in-process (Invoke-NRGCollectPowerPlatform) |  |  |  |  |  |  |
| PPL-3.1 | Collaboration & Data | Graph: Copilot licensing and settings (Invoke-NRGCollectM365Copilot) |  |  |  |  |  |  |
| PPL-3.2 | Collaboration & Data | Graph: Copilot licensing and settings (Invoke-NRGCollectM365Copilot) |  |  |  |  |  |  |
| PPL-3.3 | Collaboration & Data | Graph: Copilot licensing and settings (Invoke-NRGCollectM365Copilot) |  |  |  |  |  |  |
| PPL-3.4 | Collaboration & Data | Graph: Copilot licensing and settings (Invoke-NRGCollectM365Copilot) |  |  |  |  |  |  |
| PVW-1.4 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| PVW-2.2 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| PVW-2.3 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| PVW-2.4 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| PVW-2.5 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| PVW-2.6 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| PVW-3.2 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| PVW-3.3 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| PVW-3.4 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| PVW-4.4 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| SPO-1.4 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| SPO-2.2 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| SPO-2.3 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| SPO-2.4 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| SPO-2.5 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| SPO-2.6 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| SPO-2.7 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| SPO-2.8 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| SPO-3.1 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| SPO-3.2 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| SPO-3.4 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| SPO-4.1 | Collaboration & Data | Graph SharePoint tenant settings; SPO Management Shell when -IncludeSharePointShell (Invoke-NRGCollectSharePoint) |  |  |  |  |  |  |
| TMS-1.1 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-1.2 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-1.3 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-1.4 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-1.5 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| TMS-1.6 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-2.1 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-2.2 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-2.3 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-2.4 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-2.5 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-2.6 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-2.7 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-2.8 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-3.1 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-3.3 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-3.4 | Collaboration & Data | Security & Compliance PowerShell: audit, retention, DLP, labels, alert policies (Invoke-NRGCollectPurview) |  |  |  |  |  |  |
| TMS-4.1 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-4.2 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |
| TMS-4.4 | Collaboration & Data | Teams PowerShell: meeting, messaging and federation policies (Invoke-NRGCollectTeams) |  |  |  |  |  |  |

SPO-3.3 is Assessment-only in v1.0; its governance row is kept as written so nothing is re-derived when it is promoted. Promotion condition: `-IncludeSharePointShell` collection becomes part of the normal Standard run.

## Vulnerability Management (endpoint build standard, not `controls.json`)

The 204 tenant controls contain no vulnerability-management control, because Microsoft 365 does not expose vulnerability state through Microsoft Graph. The requirement therefore lives in the endpoint build standard (`Config/device-baseline.json`, v1.1), where the endpoint compliance scanner's `DEV-*` checks already provide the device-side evidence. Three distinct requirements, because most organizations implement only the first two:

| ID | Requirement | Tier | Owner | Automated | SLA class | Freshness | Why NRG owns this | Effectiveness check | Notes |
|---|---|---|---|---|---|---|---|---|---|
| DB-4.2 | Third-party applications are patched within the defined remediation window (patch **policy**) | **Minimum** | Vulnerability | Manual | High | Weekly | Browsers, PDF readers and conferencing clients are the most exploited software on any endpoint and Windows Update does not touch them. | RMM patch compliance report shows the estate inside the window (**not collected**). | RMM third-party patching or Intune Enterprise App Management. No tenant-side verifier yet. |
| DB-4.7 | Patch deployment is monitored and failures are investigated (patch **delivery**) | **Minimum** | Vulnerability | Manual | High | Weekly | A failed or reboot-pending deployment leaves the exposure in place while the console says done. | Every failed or reboot-pending deployment has a ticket within the SLA (**not collected**). | Weekly review of failures and pending reboots; every failure a ticket. |
| DB-4.8 | Vulnerability remediation is independently verified against the current vulnerability state (patch **effectiveness**; the standard's **VM-VERIFY-01**) | **Minimum** | Vulnerability | Manual | Immediate for KEV, Critical otherwise | Daily | The patching tool is evidence of deployment. Defender Vulnerability Management is evidence of remediation. They are not the same thing. | Defender Vulnerability Management affected-device count for the CVE is zero (**not collected**; needs a Defender for Endpoint API collector with its own consent). | `VerifiedBy: []` on purpose: the standard exists before the automation. Allow for Microsoft's documented lag: software changes appear in about two hours, exposure score recalculates daily, a pending restart keeps a device exposed. For actively exploited (KEV) vulnerabilities the ticket closes only at affected-device count zero or with a documented exception, compensating control and review date. |

The device build standard's item IDs are pinned to the `DB-n.n` shape by `NRG.DeviceBaseline.Tests.ps1`, which is why the two new items are DB-4.7 and DB-4.8 rather than DB-4.2A and VM-VERIFY-01; VM-VERIFY-01 is the standard's name for DB-4.8 and will be the control ID in `nrg-baseline.json`'s vulnerability domain.

The 39 `DEV-*` endpoint checks are not listed here: they are already governed by the device build standard's Mandatory flag (25 of 29 items), and a `DEV-*` check enters the NRG baseline through the DB item that names it in `VerifiedBy`.

## Logging and observability: the composite control to add in v1.1

The baseline should eventually say more than "logging enabled". The target statement is: **required telemetry exists, is retained for the NRG minimum, and is accessible during incident response.** That is a composite over existing controls, not a new evaluator:

| Telemetry | Evidence today | Retention | Gap |
|---|---|---|---|
| Entra sign-in and audit logs | Not read by the assessment (the sign-in triage mode reads them on demand) | Set by license (Entra ID Free 7 days, P1/P2 30 days), not by configuration | The control can state the requirement; the tool can only confirm the license tier |
| Unified audit log | PVW-1.1, PVW-1.2, PVW-4.1, PVW-4.2 | 180 days default, one year on E5 | Effectiveness (a test search returns events) not collected |
| Exchange mailbox and admin audit | EXO-1.1, EXO-4.2, EXO-5.1 | Governed by Purview retention | Same |
| Defender alerts | DEF-3.4, DEF-4.3, EXO-3.3 | Portal retention | Alert delivery to the NRG queue not collected |
| Endpoint telemetry | INT-2.1, DEV-2.x | Defender for Endpoint retention | Device reporting health not collected |
| Firewall events | Out of scope by decision (network equipment is not on the roadmap) | — | Answered in the SSP as inherited |

## Contradictions to review before v1.0 is locked

These are generated mechanically from the tables above so the review can accept or fix each one consciously.


**Minimum controls whose evidence is manual-only:** none

**Controls whose prerequisite sits in a higher tier:** none

**Effectiveness checks that depend on telemetry NRG does not collect today (61 of 67):** AAD-1.1 (Minimum), AAD-1.2 (Minimum), AAD-2.1 (Minimum), AAD-3.1 (Minimum), AAD-7.2 (Minimum), AAD-11.2 (Minimum), AAD-6.1 (Standard), AAD-11.1 (Standard), AAD-10.2 (Standard), AAD-2.3 (Standard), AAD-1.3 (Hardened), AAD-1.4 (Hardened), AAD-1.5 (Hardened), AAD-3.2 (Hardened), AAD-3.3 (Hardened), AAD-8.2 (Hardened), AAD-11.4 (Hardened), AAD-11.7 (Hardened), AAD-10.4 (Hardened), SPO-1.5 (Hardened), EXO-1.2 (Minimum), EXO-1.3 (Minimum), EXO-1.4 (Minimum), EXO-1.6 (Minimum), EXO-7.1 (Minimum), EXO-7.2 (Minimum), EXO-8.2 (Minimum), EXO-2.6 (Standard), EXO-5.3 (Standard), EXO-1.5 (Standard), DEF-1.1 (Standard), DEF-1.2 (Standard), DEF-1.3 (Minimum), DEF-2.2 (Minimum), DEF-2.3 (Minimum), DNS-1.1 (Minimum), DNS-1.2 (Minimum), DNS-1.3 (Minimum), DNS-1.4 (Hardened), EXO-1.1 (Minimum), EXO-4.2 (Minimum), PVW-1.1 (Minimum), PVW-1.2 (Standard), DEF-3.4 (Standard), DEF-4.3 (Standard), EXO-3.3 (Standard), PVW-4.1 (Hardened), PVW-4.2 (Hardened), INT-1.1 (Minimum), INT-1.3 (Minimum), INT-2.2 (Standard), INT-4.3 (Standard), INT-4.2 (Hardened), SPO-1.3 (Minimum), SPO-1.1 (Standard), SPO-1.2 (Standard), TMS-3.2 (Standard), SPO-2.1 (Hardened), TMS-4.3 (Hardened), PVW-1.3 (Hardened), PVW-4.3 (Hardened)

These are not wrong. They are the honest state: for every one of them the compliance view will report `Effective = Unknown` until a collector exists (sign-in logs, message trace, DMARC aggregate reports, Defender reports, Purview search). Marking them now is what stops the baseline from pretending.

**Effectiveness checks collected today (the endpoint scanner or a delta between runs):** AAD-6.2, AAD-15.1, INT-1.5, INT-2.1, INT-2.5, INT-4.1

## How to review this document

1. Change **Proposed tier** wherever you disagree. The 49 Minimum + Standard nominations are a starting point; the target is a set engineers genuinely operate, not the largest defensible list.
2. Every Minimum and Standard row must keep a one-sentence **Why NRG owns this** and an **Expected state** an engineer can test. If you cannot write one, the control is Assessment-only.
3. Check the **SLA class** and **Freshness** against what NRG will actually staff. A Daily freshness class means the assessment (or a lighter collector) runs daily for that control.
4. Add operational notes where a control regularly needs an exception (printers on SMTP AUTH, CLI tools on device code flow, partner federation) so the exceptions file has a vocabulary from day one.
5. Work the contradictions section: accept each manual-only Minimum consciously, fix any inverted dependency, and leave the not-collected effectiveness checks marked as such.
6. Lock v1.0. Then, and only then, encode it as `Config/nrg-baseline.json` and build the view and its tests.

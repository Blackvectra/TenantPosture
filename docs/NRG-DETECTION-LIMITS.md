# NRG detection limits

What the assessment does **not** establish, stated per control, so a reader can tell
a verified result from a configuration observation. Written from a review of the
Standard baseline (50 required controls) against each control's expected state in
`Config/nrg-baseline.json` and the evaluator that scores it. Update this file when an
evaluator changes.

How to read it: **Verified** is what the finding proves. **Not established** is what the
expected state asks for that the finding does not prove. A control that reports
Satisfied while part of its expected state is not established is listed under
"Satisfied with limits". Nothing here changes a verdict; it says how far a verdict reaches.

## Tool-wide limits

- **Configuration is not effectiveness.** No control measures whether a setting works in
  practice (effectiveness is Unknown for all 50 baseline controls).
- **Microsoft 365 only.** A non-Microsoft product (for example a third-party EDR) is
  declared by the assessor and never verified.
- **Read scope.** Whatever the signed-in account and the granted scopes cannot read is
  reported as not assessed, never as a pass.
- **Exchange authentication policies are not read.** EXO-1.6 says so: with SMTP AUTH available
  and no legacy-authentication block it reports an exposure (Partial) and states that
  whether a password is actually accepted is not established.
- **NRG-specific standards the tool does not know.** Six baseline expectations name an
  NRG standard that ships undefined: the monitoring address (`MonitoringAddresses`), the
  required ASR rule list (`Config/asr-required-rules.json`), and in `Config/nrg-standards.json`
  the DMARC reporting addresses, the common-attachment blocked-file-type list, the priority
  users and the required Conditional Access templates. Until each is approved, only the half
  that does not need it is verified and the rest is reported not assessed.

## Former "Satisfied with limits" controls: now complete checks or explicit incomplete verdicts

Seven controls used to report Satisfied while part of their expected state was not proved.
Each now judges every component. A full pass needs every component supported; an
established shortfall is always reported (Partial, or Gap when nothing else was met); a
component that cannot be established leaves the control **not assessed** with the verified
components kept in the Detail. Nothing narrows the baseline requirement.

| Control | Components judged | What keeps it from Satisfied |
|---|---|---|
| AAD-6.2 User consent | Users cannot freely consent: user consent is disabled, or limited to low-impact permissions from verified publishers | Unrestricted user consent is a Gap; the consent setting unreadable, or a custom grant policy, is not assessed. The admin consent workflow is AAD-6.3's requirement: AAD-6.2 shows it only as related context and it never changes this verdict, so one disabled workflow is one baseline failure. |
| AAD-2.1 CA policies | Three coverage tracks **and** every template in `RequiredConditionalAccessTemplates` Enforced (report-only, narrower or missing policies do not count) | The approved template list is empty until NRG approves it: tracks verified, set **not assessed** |
| DEF-2.2 ZAP | Spam, phishing **and malware** ZAP in every policy in force | Malware ZAP off is a shortfall; malware policies or `ZapEnabled` not read is not assessed (the collector now reads `ZapEnabled`) |
| DEF-2.3 Common attachments | Filter on in every malware policy in force **and** every approved file type blocked | `CommonAttachmentFileTypes` empty: filter verified, list **not assessed** |
| DNS-1.3 DMARC | p=quarantine/reject, pct, sp **and** the approved reporting address in `rua` | `DmarcReportingAddresses` empty: enforcement verified, reporting address **not assessed** |
| EXO-1.5 Impersonation | Organization-domain and mailbox-intelligence protection acting **and** the approved priority users listed with user protection on and an action | `PriorityUsers` empty: priority users **not assessed** |
| INT-1.5 Antivirus | An assigned Defender Antivirus policy **and** real-time, cloud-delivered and PUA protection read as on | A setting off or audit-only is a shortfall; settings not read, not set by any policy, or an unrecognized value is not assessed |

The approved lists live in `Config/nrg-standards.json` and **ship empty on purpose**: the
tool does not invent NRG's standard. Until a list is approved, the control that needs it
reports the approved-list component as not assessed, and the report files it under
"Verified in part — an NRG standard is not approved or configured" (scope bucket
`StandardNotApproved`, baseline reason code `StandardNotApproved`), never under "data did not
collect". A collector that failed is still named as the cause first.

Remaining limits inside these checks:

- **INT-1.5** parses Settings Catalog definition ids by suffix (`defender_allowrealtimemonitoring`,
  `defender_allowcloudprotection`, `defender_puaprotection`). Unverified against a live tenant.
  Legacy (intent-based) antivirus policies have no settings read, so they stay not assessed.
- **EXO-1.5** matches priority users to `TargetedUsersToProtect` entries of the form
  `Display Name;address`; other shapes do not match and show as a shortfall.
- **AAD-2.1** judges the approved templates with the Conditional Access view's own matching
  (an all-users policy may still exclude break-glass accounts by design).
- **DEF-2.2** reads malware ZAP from `Get-MalwareFilterPolicy`; results saved before this
  change carry no `ZapEnabled` and report malware ZAP as not assessed.

## Coverage judgments (Conditional Access, Defender presets, DLP)

- **Combined exclusion coverage.** A principal is unprotected only when it is excluded from
  every qualifying policy. Group membership is **not resolved**, so two policies excluding
  different groups are reported as unproven, not covered. Emergency-access accounts excluded
  everywhere show as an exception; record an approved deviation if that is intended.
- **Privileged roles** are the roles this tenant's own catalog marks privileged, not
  Microsoft's fixed list.
- **Preset recipient scope.** A preset rule that returns no recipient scope is not assumed to
  cover everyone. Exclusion identities are stored by the current collector; older results keep
  only a flag and say so.
- **DLP.** Workload coverage, detection and enforcement are separate claims. Only enforcing
  policies count; rule actions (`BlockAccess`) are reported only when read.
- **Authentication policies and Conditional Access conditions** beyond applications, platforms,
  locations, device filter and risk levels (for example session controls) are not modeled.

## Changed in this review

These were narrower than their expected state and now verify the whole requirement or
say what is not assessed:

- **EXO-1.6** Modern authentication **and** password availability: SMTP AUTH (switch and
  per-mailbox overrides) plus the tenant's legacy-authentication block. SMTP AUTH carries
  OAuth too, so enabled alone is not "passwords allowed".
- **EXO-1.1** Auditing switch **and** no account in the audit bypass list.
- **DEF-3.4 / EXO-3.3** Recipients exist **and** reach a configured NRG monitoring address.
- **INT-2.2** Reads each assigned ASR policy's rule modes; judged only against the approved
  rule list (empty until approved), so it reports the modes read and leaves the rule-set
  half not assessed.
- **INT-1.1** Coverage per enrolled platform (a Windows policy does not cover iOS); the
  policies' non-compliance actions are not read, so it does not reach Satisfied (see
  "Evidence boundaries shown with the control" below).
- **DEF-2.3** Judged over the malware policies in force. A filter on in a policy that
  applies to nobody no longer satisfies it.
- **Policies in force (17 evaluators).** A tenant with **no** custom rules has an empty rule
  list, which used to be read as "rules not collected" and kept every custom policy in
  force, even ones that apply to nobody. An empty collected list is now distinct from an
  unread one (`Get-NRGRuleList`).

## Controls whose verdict can be Satisfied only for what the tool can see

- **Email authentication (DNS-1.x).** Lookups run from the assessor's workstation. A
  resolver that cannot reach a name reports the lookup as failed, not absent. The MTA-STS
  policy file is fetched over HTTPS from that workstation.
- **DKIM (DNS-1.2).** Checks the customer's selector CNAMEs, not their targets.
- **Audit (PVW-1.1/1.2, EXO-4.2).** Reads the configured retention, not whether the audit
  log actually holds events for that long.
- **Forwarding (EXO-7.1 / EXO-6.1, EXO-7.2).** Mailbox forwarding and inbox rules are read;
  a rule whose recipient cannot be resolved leaves EXO-7.2 not assessed rather than clean.

## Incident-response tools (`Invoke-NRGSignInTriage`, `Invoke-NRGEmailAssessment`)

These are heuristics, not baseline controls.

- A result of "no strong indicators" is allowed only when every required read completed
  and every required detector ran; otherwise the verdict is NOT CLEARED.
- Recent sign-ins are not re-ordered newest-first (Graph `$orderby` support with the date
  filter was not verified), so a truncated read may omit older events in the window.
- Same-domain inbox-rule forwarding is judged against the mailbox's own domain only, so
  forwarding between two domains of one organization can be flagged for review.
- The phishing-origin ranker reads message previews (about 255 characters), so a link later
  in the body is not seen.
- None of the incident-response changes has had a live tenant run.

## Evidence boundaries shown with the control

Some controls have a component of their expected state the assessment does not establish, whatever
the tenant looks like, because the evaluator does not read that evidence. These are recorded in
`Config/evidence-limits.json`, and the main HTML report, the report site, the Markdown report's control
detail and the remediation playbook show "Not established: <component>." wherever the control is
displayed (never in the executive summary), so a reader cannot take the verified half for the
whole requirement.

**INT-1.1 — Device Compliance Policies Configured.** The assessment verifies that compliance
policies exist, are assigned, and cover each enrolled platform. It does not currently read or
validate the configured non-compliance actions, including when a device is marked noncompliant,
blocked, retired or otherwise acted upon. Therefore, the assessment cannot prove that noncompliant
devices lose access or that remediation actions occur. Until those actions are collected and
evaluated, INT-1.1 does not return Satisfied: verified components stay visible in the Detail while
the overall result is Gap (no assigned policy), Partial (a platform with no policy) or Not assessed
(every platform covered, actions unread). Reading "a compliance policy exists" as "noncompliant
devices are actively restricted" is the misreading this entry exists to prevent; Conditional Access
(AAD-2.3 / INT-1.2) is what turns device state into restricted access.

## Open verification

- INT-2.2's ASR settings parser and INT-1.5's antivirus settings parser follow the documented
  Settings Catalog structure and are unverified against a live tenant.
- The approved NRG lists in `Config/nrg-standards.json` and `Config/asr-required-rules.json`
  are empty; each affected control reports that component not assessed until NRG approves it.
- The 2026-09-30 baseline reference predates the changes above; regenerate it from a fresh
  read-only run.

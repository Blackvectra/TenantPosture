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
- **Exchange authentication policies are not read.** EXO-1.6 says so.
- **NRG-specific standards the tool does not know.** Four baseline expectations name an
  NRG standard that is not defined anywhere in the tool: the monitoring address
  (`MonitoringAddresses`), the required ASR rule list (`Config/asr-required-rules.json`,
  ships empty), the DMARC reporting address, and the common-attachment blocked-file-type
  list. Until each is defined, only the half that does not need it is verified.

## Satisfied with limits (verified in part)

| Control | Verified | Not established |
|---|---|---|
| AAD-6.2 User consent restricted | Users cannot consent to applications | The expected state also says consent goes through the **admin consent workflow**; that is AAD-6.3, which is not a baseline-required control (and is a Gap in the 2026-09-30 run) |
| AAD-2.1 CA policies deployed | At least one enabled CA policy; three coverage tracks (legacy-auth block, MFA all users, MFA admins) | "The NRG baseline policy set" is not defined in the tool; the three tracks are a proxy |
| DEF-2.2 Zero-hour auto purge | Spam and phish ZAP in every anti-spam policy in force | Malware ZAP (an anti-malware setting) is not read |
| DEF-2.3 Common attachments filter | The filter is on in every malware policy in force (judged over policies in force, not "any policy") | The **NRG blocked-type list** is not compared, only that the filter is on |
| DNS-1.3 DMARC | Policy is quarantine or reject, pct, per domain | The **NRG reporting address** (DMARCian) is not checked in `rua` |
| EXO-1.5 Impersonation protection | Organization-domain and mailbox-intelligence protection on, each with an action | **Priority users** (targeted user protection) are not evaluated |
| INT-1.5 Antivirus policy | An assigned Defender Antivirus policy exists | Its settings (real-time protection, cloud protection, PUA) are not read |

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
  policies' non-compliance actions are not read, so it does not reach Satisfied.
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

## Open verification

- INT-2.2's ASR settings parser follows the documented Settings Catalog structure and is
  unverified against a live tenant.
- The 2026-09-30 baseline reference predates the changes above; regenerate it from a fresh
  read-only run.

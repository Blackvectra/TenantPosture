# NRG validation plan

NRG is ready when its findings are defensible and its unknowns are explicit. Green tests
show the code does what the tests say; they do not show the tool is right about a tenant.
This plan separates the two questions a live run has to answer and says what counts as
evidence for each.

## 1. Baseline accuracy (does the verdict match the tenant?)

Two questions per control: **is a reported gap real**, and **does a passing configuration
satisfy every mandatory component**?

For each row of the spot-check sheet, compare the finding with the portal or PowerShell value
named in its row. A mismatch is an investigation, not yet a defect. Rule out, in order:

1. **Collection time.** The run and the portal were read at different moments.
2. **Scope.** The signed-in account, a `-Skip` flag, or an unread section limited what the tool saw (the finding's Detail says which).
3. **Policy precedence.** A preset or custom policy in force is not the default policy the portal shows first.
4. **Approved standard.** The expected state names an NRG list that is not approved yet (`Config/tp-standards.json`, `Config/asr-required-rules.json`, monitoring address). The control should say "not assessed", not pass.
5. **Detector defect.** Only after 1 to 4: capture the raw collector output, the Detail and the portal value, and add a failing test before changing the evaluator.

What each verdict proves is in `TP-DETECTION-LIMITS.md`. A Satisfied that the limits
document says is verified in part is a defect in the document or the evaluator, whichever
is wrong.

Cases a live run should cover at least once: a genuinely compliant setting (Satisfied), a
known shortfall (Partial or Gap), an unread section (not assessed), an empty collected list,
an unassigned or report-only policy, an exclusion, and conflicting policies in force.

## 2. IR detection accuracy (does a suspicious finding have evidence, and does a lookalike stay quiet?)

The incident-response tools (`Invoke-TPSignInTriage`, `Invoke-TPEmailAssessment`) are
heuristics. Two things have to be shown, and clean tenant data shows neither:

- **Known positives.** A controlled test tenant or mailbox that contains the behavior (a hidden inbox rule forwarding out, a successful sign-in from an anonymizer, a consent grant with `Mail.Send`) must be flagged, with the corroborating evidence in the finding.
- **Benign lookalikes.** A newsletter folder rule, a same-domain forward, a legitimate DocuSign message, a travelling user on a VPN, a new MFA method registered by the user must NOT produce an unjustified alert.

Fixture tests already cover both directions for the inbox-rule, phish-origin, brand-spoof,
credential-stuffing correlation, anonymous-IP and risk detectors (`Email-IR/Testing`). They
prove the logic, not the detection rate against real tenant behavior. The remaining gap is
a controlled tenant run with seeded positives and lookalikes; until one exists, an IR
"no strong indicators" result is only as strong as the completeness statement beside it
(`NOT CLEARED — EVIDENCE INCOMPLETE` whenever a required read or detector did not finish).

## 3. Output parity

The same verdict and the same evidence limitation must read the same in the results JSON, the
HTML report, the Markdown summary and the XLSX workbook. `TP.OutputParity.Tests.ps1`
publishes one findings set to all four and checks the shortfall and the not-assessed sentence
in each. A format that drops a limitation reads cleaner than the run it reprints.

## 4. What this plan does not establish

- Effectiveness. A setting being on is not evidence it works.
- Anything outside Microsoft 365 (a third-party EDR is declared, never verified).
- Detection rates of the IR heuristics against real attacker behavior.

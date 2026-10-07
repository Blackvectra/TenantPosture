# HIPAA citation corrections (2026-10-06)

Sixteen controls in `Config/controls.json` cited one of three HIPAA Security Rule implementation
specifications that do not describe what their evaluators check, and a seventeenth (PVW-3.2) cited
the bare section 164.316. Building the HIPAA readiness view
surfaced them: a readiness row would have read "satisfied" for a requirement the check has nothing
to do with.

The rule applied here: remove a citation that does not describe what the evaluator checks; replace it
only where another Security Rule item describes the check itself; never add a citation just to keep
a control cited. Citations a control already carried beside the removed one were kept as they were
and were not re-reviewed in this change.

## The three specifications

- **164.308(a)(4)(ii)(A), isolating health care clearinghouse functions.** "If a health care
  clearinghouse is part of a larger organization, the clearinghouse must implement policies and
  procedures that protect the electronic protected health information of the clearinghouse from
  unauthorized access by the larger organization." It applies to one kind of entity structure,
  which no tenant setting establishes.
- **164.308(a)(5)(ii)(A), security reminders.** "Periodic security updates." It is part of the
  security awareness and training standard, a workforce activity.
- **164.316(b)(2)(i), time limit.** "Retain the documentation required by paragraph (b)(1) of this
  section for 6 years." Paragraph (b)(1) is the written policies and procedures and the record of
  actions, activities or assessments the Security Rule requires to be documented. It is not a
  retention period for audit logs, mailbox audit records or content.

## Changes

| Control | Previous citation | What the evaluator checks | New citation | Reason |
|---|---|---|---|---|
| TMS-1.1 | 164.308(a)(4)(ii)(A), 164.312(e)(1) | Teams federation is not open to every external domain | 164.312(e)(1) | Clearinghouse citation removed; the other citation kept. |
| TMS-1.5 | 164.308(a)(4)(ii)(A), 164.310(d)(2)(ii) | Meeting recordings are stored in SharePoint/OneDrive under the organization's retention | none | Both removed. Clearinghouse as above; media re-use (removing ePHI from media before reuse) is not what the check examines (found by review of PR #121). Listed in `Config/hipaa-uncited-controls.json`. |
| PPL-1.1 | 164.308(a)(4)(ii)(A), 164.312(a)(1) | Power Platform tenant isolation restricts cross-tenant connections | 164.312(a)(1) | Clearinghouse citation removed; the other citation kept. |
| EXO-2.5 | 164.308(a)(4)(ii)(A), 164.312(b) | Customer Lockbox requires approval before Microsoft support can access tenant data | 164.312(b) | Clearinghouse citation removed; the other citation kept. |
| SPO-2.8 | 164.308(a)(4)(ii)(A), 164.310(d)(1) | OneDrive sync is restricted to the organization's tenant IDs | 164.310(d)(1) | Clearinghouse citation removed; the other citation kept. |
| PVW-2.3 | 164.308(a)(4)(ii)(A) | Information Barriers mode, when barriers are deployed | none | Removed. No Security Rule item describes segmenting communication between internal groups; listed in `Config/hipaa-uncited-controls.json`. |
| AAD-11.6 | 164.308(a)(4)(ii)(A) | Whether the default cross-tenant inbound settings accept MFA or device-compliance claims made by other organizations' tenants | 164.312(d) | Replaced. Person or entity authentication: "verify that a person or entity seeking access to electronic protected health information is the one claimed." Accepting another tenant's MFA claim is relying on that tenant to perform the verification. |
| TMS-4.3 | 164.308(a)(4)(ii)(A) | Teams federation is limited to an allowlist of external domains, or disabled | 164.312(e)(1) | Replaced. Transmission security: "guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network." The allowlist decides which external organizations can exchange messages with users; TMS-1.1 checks the same setting and already cites it. |
| DEF-4.4 | 164.308(a)(5)(ii)(A) | Accounts are tagged as priority accounts in Defender for Office 365 | none | Removed. Tagging is a prerequisite for differentiated protection and alerting, not a safeguard the Security Rule names; listed as uncited. |
| EXO-5.2 | 164.308(a)(5)(ii)(A) | Tagged priority accounts are covered by targeted user impersonation protection in the anti-phishing policy | none | Removed. Impersonation protection is not protection from malicious software (164.308(a)(5)(ii)(B)); listed as uncited. |
| PVW-1.2 | 164.312(b), 164.316(b)(2)(i) | Unified audit log retention of at least 90 days | 164.312(b) | Time-limit citation removed; audit controls kept. |
| PVW-2.5 | 164.316(b)(2)(i), 164.308(a)(7)(ii)(A) | Retention policies cover Exchange, SharePoint, OneDrive and Teams | 164.308(a)(7)(ii)(A) | Time-limit citation removed; the other citation kept. |
| EXO-4.1 | 164.312(b), 164.316(b)(2)(i) | Mailbox audit log age limit of at least 90 days | 164.312(b) | Time-limit citation removed; audit controls kept. |
| TMS-4.1 | 164.316(b)(2)(i), 164.502 | Meeting recordings expire after 60 to 90 days | 164.502 | Time-limit citation removed; the Privacy Rule citation kept (see below). |
| PVW-4.2 | 164.316(b)(2)(i), 164.312(b) | A custom audit log retention policy of at least one year | 164.312(b) | Time-limit citation removed; audit controls kept. An earlier audit had pinned 164.316(b)(2)(i) on this control; the pin now expects 164.312(b). |
| PVW-4.4 | 164.316(b)(2)(i), 164.530(j) | Records management retention labels exist for regulated content | 164.530(j) | Time-limit citation removed; the Privacy Rule citation kept (see below). |
| PVW-3.2 | 164.316, 164.524 | eDiscovery roles are assigned and cases can be opened | 164.524 | Bare 164.316 (policies and procedures and documentation) removed: it names no standard, and eDiscovery case management is not a documentation requirement. Found when the readiness view started reading section-level citations (review of PR #121). The Privacy Rule citation is kept. |

## Not changed here, for review

- **PVW-4.4 cites 164.530(j)**, the Privacy Rule's six-year retention of its own documentation. It is
  the same kind of mismatch as 164.316(b)(2)(i) for a records-label check. The HIPAA readiness view
  covers the Security Rule only, so it is listed rather than changed.
- **TMS-4.1 cites 164.502** with no paragraph, the Privacy Rule's general rule on uses and
  disclosures. Recording expiry is not a use or disclosure rule; also listed rather than changed.
- The citations kept beside the removed ones were reviewed on 2026-10-07 after review of PR #121
  found TMS-1.5's media re-use citation (removed above). Two are kept but debatable: **EXO-2.5**
  (Customer Lockbox) cites audit controls, 164.312(b), where access control, 164.312(a)(1), may fit
  better; **PVW-2.5** (retention policies cover the key workloads) cites the data backup plan,
  164.308(a)(7)(ii)(A), and retention policies preserve content but are not a backup. Neither is
  changed without a decision.

## How it is held

- `Config/hipaa-uncited-controls.json` lists the four controls left without a HIPAA citation, each
  with its reason. `NRG.FrameworkCoverage.Tests.ps1` accepts an empty HIPAA citation only for a listed
  control, and fails if a listed control gains one without leaving the list.
- The same test fails if any control cites 164.308(a)(4)(ii)(A), 164.308(a)(5)(ii)(A) or
  164.316(b)(2)(i) again.
- The `baselines/*.md` framework tables were updated for the seventeen controls.

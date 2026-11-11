# AI use readiness review

`New-TPAiUseReview.ps1` writes a review a client can keep: how its Microsoft 365
configuration stood in relation to AI use of its data on the date of a saved
full assessment. It reads one `-results.json`, writes one HTML page (and a PDF
with `-Pdf`), and connects to nothing: no sign-in, no Graph, no Exchange, no
network. Nothing is collected or re-evaluated to write it, and the results file
is not modified.

```powershell
.\New-TPAiUseReview.ps1 -ResultsPath .\output\contoso-20261110-090000-results.json -ClientName 'Contoso Ltd' -Pdf
.\New-TPAiUseReview.ps1 -ResultsPath .\output\clinic-20261110-090000-results.json -ClientName 'Contoso Family Health' -HIPAA -Profile nls
```

| Parameter | Meaning |
|---|---|
| `-ResultsPath` | The saved results file of a **full** run. A partial (`-ControlId`) or quick (`-Quick`) run, or an incident-response output, is refused with exit 4 and nothing is written. |
| `-ClientName` | The organization name printed on the page. A label only: nothing is copied from the file to name the client. |
| `-PreparedBy` | Who prepared it; defaults to the loaded profile's company name. |
| `-Profile` | Branding profile (`Config/profiles/<name>.psd1`). |
| `-OutputPath` | Folder for the output; defaults to the results file's folder. The folder is proved able to hold an owner-only file first. |
| `-HIPAA` | Uses the ePHI wording for the sensitive-information review area. **Wording only**: it does not assess, verify or determine HIPAA compliance, and the page says so. |
| `-Pdf` | Also prints the HTML to PDF with the Edge, Chrome or Chromium already installed. Optional: when no browser can print, the HTML is still written and the console says `HTML generated; PDF unavailable`. |

Output: `<client>-ai-use-review-<yyyyMMdd-HHmmss>.html` (and `.pdf`), written
with the same owner-only permissions as every other output. Exit 0 on success
(a PDF that could not be printed is reported, not an error), 4 when refused or
on a fatal error.

## What is on the page

**About this review.** What it is and, before any number, what it is not: not
an AI risk assessment, not a determination of compliance with any law,
regulation or standard, not a statement that AI use is safe, approved or
governed, not a measure of whether anyone uses an AI tool. It has no score. The
five counts are how many of the reviewed controls fall in each group.

**1. Observed AI-related configuration.** From the saved assessment:

- Entitlement: whether the recorded subscriptions carry Microsoft Copilot (the
  paid add-on) and Copilot Studio, judged through the same license profile the
  live run uses; "not read" when the file holds no subscription list.
- Microsoft Copilot seats: the state the D1 reader
  (`Get-TPCopilotLicensingState`) gives, and every count the collector
  recorded (seats purchased, seat assignments the subscriptions report,
  distinct accounts holding a seat, enabled member accounts holding a seat,
  enabled member accounts). Each count is rendered with its status:

  | Status | Meaning |
  |---|---|
  | Complete | The whole population was read; the number is the total. |
  | Lower bound ("at least N") | The read did not finish; N were found. Not a total. |
  | Not established | The read did not finish and found none. **Not zero.** |
  | Not read | The collector did not record this value. |

  The subscription list and the user enumeration each carry the read status
  the collector recorded (Collected, Failed, Truncated, NotRun). The older
  compatibility count fields are never read, so an older results file reads as
  unknown completeness rather than as a number.
- PPL-3.3, the share of enabled members holding a seat, as an **observation**:
  it is never counted as a safeguard, whatever its finding says.
- Copilot Studio agents: how many environments were listed, how many have
  Dataverse, how many were read in full, in part or not at all (the per-run
  environment cap applies), and the agent counts as complete or lower bounds.
  A failed environment list is "the agent inventory is unknown", never zero
  agents; a results file without the collector says no inventory is recorded.
- Three fixed statements: configuration and licensing are not usage; a
  recognized subscription with no seat assigned, or no paid add-on at all, does
  not establish that AI is unavailable or unused (Microsoft Copilot Chat is
  available to eligible accounts without a license); agents, connectors and
  third-party tools follow their own terms.

**2. Safeguards in place.** Controls of the catalog recorded Satisfied, each
labeled by its relationship to AI use:

| Relationship | Meaning |
|---|---|
| AI-specific | A Copilot or Copilot Studio setting. |
| Direct access | Decides what an account, and so Copilot acting as that account, can read. |
| Supporting governance | Supports that governance (guest lifecycle, external access review, DLP policies). |
| General | A general application or consent control that also bounds AI integrations. |

A Satisfied finding whose collector did not complete (coverage Failed or
Skipped) is not a safeguard: it is listed under "Not verified" as a conflict
between two records.

**3. Items needing attention.** Controls recorded Gap or Partial, AI-specific
first, each with what changing the setting does to users (from
`Config/operational-impact.json`; a control with no entry says "Operational
impact not documented", never "no impact").

**4. Organizational decisions and evidence gaps.** Five areas only the
organization can decide and record: approved tools, sensitive information
(ePHI wording with `-HIPAA`), human review of AI output, guidance and
accountability, vendor terms. Each is "Not recorded in this assessment", with
the type of evidence that would answer it and suggested roles (suggestions:
nobody is appointed by the review). Then the controls the assessor declared
covered by a third-party product (declared, not verified by the assessment),
and every reviewed control that produced no verdict with the reason the
assessment's own scope classifier gives: no finding recorded, the check
errored, the data was not collected, the license is not held, manual review
only, skipped by the operator, standard not approved, or a satisfied finding
beside a failed collector.

**5. Prioritized next steps.** Grouped by what each step needs: improvements
with current capabilities, decisions or documentation requiring the client,
additional collection or review, licensing or separately scoped projects. Each
names its evidence basis, a suggested role, the dependency, the operational
impact, an effort class (never an hour figure) and how it is verified (a later
full assessment records the control as Satisfied).

**Sources and dates.** The vendor statements with their Microsoft Learn sources
and the date they were read (the date they were checked, not a publication or
product-change date), the assessment date and tool version, and the catalog
version applied. The three dates are kept apart on the page.

## What it reads, and what it never carries

The file is read three ways, each bounded by `Get-TPRunRecordMaxBytes`:

- `Read-TPRunRecord` for the metadata and the trimmed findings (control id,
  state, severity, title; no Detail).
- `Get-TPAiUseReviewScope` for the kind of run and the scope classification
  exactly as `-FromResults` would compute it (`Select-TPReplayedFinding`, then
  `Get-TPAssessmentScope` over the saved findings, coverage and raw inventory).
  It returns bucket names per control id and nothing else.
- `Read-TPAiUseFacts` for the allowlisted aggregates: the Copilot collector's
  section statuses and measurements, SKU part numbers and service plan names
  (a SKU id is reduced to present or absent), per-environment Copilot Studio
  statuses and counts, each collector's coverage status and success flag.

The model and the page therefore carry no finding detail, no account name or
UPN, no object id, no agent or environment name, no error text, no operator and
no tenant identifier. Every displayed value is escaped; the page loads nothing
and runs nothing (`default-src 'none'`); every link is an https Microsoft URL.
`TP.AiUseReview.Tests.ps1` plants sentinels for each of these in a synthetic
results file and asserts none reaches the facts, the model or the page.

## The catalog

`Config/ai-use-review.json` (`version`, `vendorFactsRetrieved`) maps 43 of the
assessment's controls to a relationship, a scope sentence, an explanation and,
where one exists, a Microsoft reference with its retrieval date; lists PPL-3.3
as an observation; defines the five organizational areas; and records the
vendor facts with their sources. It is validated when loaded: a control listed
twice, an id not in `controls.json`, an id that is not a control id, an unknown
relationship, a reference that is not an https Microsoft URL or has no
retrieval date, or a suggested role outside the fixed set (Business owner,
Security/IT administrator, Data owner, Privacy/legal adviser) is an error, and
nothing is written. Catalog membership is separate from `controls.json`: the
210 controls not in the catalog are not reviewed here and the page says so.

## Limits

- It describes the configuration the assessment read on one date. Settings
  change; a later full assessment is the way to confirm anything.
- It covers the Microsoft 365 settings the assessment reads. AI tools outside
  Microsoft 365, Copilot usage and prompt activity, Copilot connectors and the
  Copilot Chat administrative settings are not covered, and the page says so.
- The organizational areas are review items. The review records no answers
  and keeps no questionnaire.
- The PDF is printed by the headless browser on the workstation (Edge on
  Windows is the intended printer); printing has been exercised by the tests
  with Playwright's headless shell only.
- Not built in this slice: an `-AiUseReview` switch on
  `Invoke-TPAssessment.ps1`; any new collection; adoption scoring.

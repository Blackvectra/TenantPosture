# Roadmap

What is planned, what is open for contributors, and what needs the owner's
decision. This is a proposal and a working list: items move when the owner
confirms them, and nothing here is a commitment to a date.

For how to contribute, see [`CONTRIBUTING.md`](../CONTRIBUTING.md). Earlier
release plans are kept for history in the `ROADMAP-v4.x` files beside this one.

## How to read this

| Label | Meaning |
|---|---|
| **Good first contribution** | Self-contained, needs no tenant, and has an existing pattern to follow. |
| **Needs a tenant** | Cannot be finished without running against a real Microsoft 365 tenant. |
| **Owner decision** | Blocked on a policy choice only the owner can make. |

## Validation against real tenants

The largest gap in the project is not a missing feature. Several checks are
proven by synthetic tests only.

- **Needs a tenant.** Run the AI use readiness review and its Copilot
  deployment gate on a real full-run results file: compare each blocker
  control's verdict with the admin portals, on a Security Defaults tenant and
  on a Conditional Access tenant. Background: [`TP-AI-USE-REVIEW.md`](TP-AI-USE-REVIEW.md).
- **Needs a tenant.** Confirm the Settings Catalog parsers (ASR rule modes,
  antivirus settings) and the Copilot Studio readings that follow third-party
  usage rather than a Microsoft field description.
- **Needs a tenant.** Confirm the sign-in evidence filters and the beta
  endpoints the project notes as not yet run against a live tenant, following
  the runbook in [`TP-LIVE-VALIDATION.md`](TP-LIVE-VALIDATION.md).
- **Good first contribution.** A live-validation checklist per workload: for
  each control, the portal page or command that shows the same value the tool
  reads.

## AI and Copilot

- **Owner decision.** The Copilot deployment gate's blocker list, whether a
  Partial result blocks, and how old a results file may be.
- Internal oversharing. The gate reads tenant sharing settings but not which
  sites and files are shared with whom. Closing this needs new collection
  (site permissions, or SharePoint Advanced Management reports) and its own
  design.
- **Good first contribution.** Record client-held vendor evidence in the
  review: a small data file listing each document's title, date and source,
  rendered under "Vendor terms and contractual review" as held by the client
  and not verified by the tool. Background:
  [`TP-COPILOT-VENDOR-EVIDENCE.md`](TP-COPILOT-VENDOR-EVIDENCE.md).
- An `-AiUseReview` switch on `Invoke-TPAssessment.ps1`, so the review is
  written during a run.
- Copilot Chat administrative settings, connectors and web search: none is
  collected today.
- Agent and API risk. Map the Copilot Studio agent checks (authentication,
  access, tools that call external services) to the OWASP lists for API
  security and for large language model applications, citing OWASP's own
  publications. A mapping is documentation first; any new check follows the
  citation rule in the contributing guide.

## Controls and views

- Backup control: whether Microsoft 365 data is protected by a backup the
  tenant can show.
- A "what matters most" report view: the few findings that change risk the
  most, in plain language.
- Endpoint checks for Microsoft Edge against a published benchmark (`DEV-*`).
- A CIS Controls Implementation Group 1 view.
- A DISA STIG view.
- Windows Hello for Business through Account protection and settings-catalog
  policies (INT-4.2 is not assessed for most tenants until this is read).
- **Good first contribution.** Section error reasons for more collectors. The
  Purview collector records why a section failed; most others do not yet, so
  their findings say "not collected" without the reason.

## Project health

- **Good first contribution.** Documentation fixes. If a document disagrees
  with the code, the code is right and the document needs a pull request.
- **Good first contribution.** A test for any behavior you find that has none.
- Issue labels and a short list of starter issues drawn from this page.
- A published sample report built from synthetic data, so a newcomer can see
  the output without a tenant.

## Not planned

- Network equipment (firewalls, switches, access points). The tool assesses
  Microsoft 365; network configuration is out of scope.
- Writing to a tenant from the assessment. Any change to tenant configuration
  belongs to the separate, explicitly invoked apply script.

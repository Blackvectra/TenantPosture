# v4.6.5 Correctness Sweep — Acceptance Criteria

**Status.** Open. No new feature work begins until every Critical and High entry in this document is either Resolved or explicitly marked WONTFIX with rationale.

**Scope.** Findings that are wrong, missing, or silently dropped from real-run output. Not: feature gaps, performance issues, cosmetic drift, doc drift. Those have separate roadmaps (v4.7, v4.8, v4.9).

**Why this exists.** A false Gap on a Critical control is a trust-destroying event. A false Satisfied on a Critical control is worse — it tells the client they're safe when they aren't. A silently-dropped finding is the worst of both: the client has no signal at all. The 14 NRE bugs we fixed across PRs #27 / #2 / #29 / #4 silently dropped findings indiscriminately, including some that mapped to Critical CIS Controls. Until every known correctness defect is closed or accepted, every new feature inherits the trust deficit.

## Prioritization rule

Entries are processed in this strict order:

1. **Critical-control correctness.** Any defect that produces a wrong Critical-severity finding (missing, false-positive, false-negative, silently-dropped). Resolve first.
2. **High-control correctness.** Same, for High-severity findings.
3. **Counts that drive client decisions.** Mailbox / user / device / OAuth population counts that the playbook surfaces to operators. Wrong here = wrong remediation scope.
4. **Medium-control correctness.**
5. **Low / Informational correctness.**
6. **Manual-review controls.** Any control that currently emits "Manual review required" with no automation path — categorize as either (a) plan to automate in v4.7+ or (b) accept as permanent manual.

A defect that crashes the entire publish step (e.g. XLSX failing to generate at all) is treated as **Critical regardless of which control surfaces it**, because it removes evidence the auditor or operator depends on.

## Known incorrect findings (sweep state)

### Resolved (already shipped)

| # | ControlId(s) affected | Severity of impact | Symptom | Root cause | Fix | Shipped |
|---|---|---|---|---|---|---|
| 1 | AAD-9.1 (Authenticator Number Matching) | High → silently dropped | `WARNING: The property 'FeatureSettings' cannot be found` | StrictMode + `$mfaConfig.FeatureSettings.NumberMatchingRequiredState` direct dereference; collector legitimately returns `$null` for `featureSettings` on tenants where MS enforces platform default | `Get-NRGNestedProperty` | PR #27 |
| 2 | AAD-11.6 (Cross-Tenant Access Trust) | High → silently dropped | `WARNING: ... 'CrossTenantAccessPolicy' cannot be found` | Same pattern, deep + first-level | PR #27 (deep), PR #29 (first-level miss) | PR #29 |
| 3 | AAD-11.1 (Device Code Flow Blocked) | High → silently dropped | `WARNING: ... 'AuthenticationFlowsPolicy' cannot be found` | Same | `Get-NRGNestedProperty` | PR #27 |
| 4 | AAD-4.2 (External Collab Restricted) | Medium → silently dropped | `WARNING: ... 'BlockMsolPowerShell' cannot be found` | Same | `Get-NRGSafeProperty` | PR #27 |
| 5 | AAD-9.2 (Passwordless Methods) | Low → silently dropped | `WARNING: ... 'State' cannot be found` | `$fido2.State` when `$fido2` is `$null` (Where-Object returned no match) | Inline null guard + default | PR #27 |
| 6 | AAD-3.1 (Global Admin Count) | High → silently dropped | `WARNING: ... 'RoleDefinitionId' cannot be found` | `Where-Object { $_.RoleDefinitionId -eq $GA_ROLE_ID }` on items missing that field | `Get-NRGSafeProperty` inside filter | PR #27 |
| 7 | AAD-11.3 (Risky Service Principals) | High → silently dropped | `WARNING: ... 'RiskyServicePrincipals' cannot be found` | Direct deref | `Get-NRGNestedProperty` | PR #27 |
| 8 | DEF-4.6 (Attack Sim Active) | Low → silently dropped | `WARNING: ... 'SimulationCampaigns' cannot be found` | Direct deref | `Get-NRGNestedProperty` | PR #27 |
| 9 | DEF-4.4 (Priority Accounts Tagged) | Low → silently dropped | `WARNING: ... 'PriorityAccounts' cannot be found` | Direct deref | `Get-NRGNestedProperty` | PR #27 |
| 10 | EXO-5.1 (Per-User Audit) | High → silently dropped | `WARNING: ... 'AuditDisabledCount' cannot be found` | `$auditSummary` was `$null` | `Get-NRGNestedProperty` | PR #27 |
| 11 | EXO-5.2 (Priority Account Email Protection) | Medium → silently dropped | `WARNING: ... 'PriorityAccounts' cannot be found` | Direct deref + `$ap.Policies` chain | `Get-NRGNestedProperty` + `Get-NRGSafeProperty` | PR #27 |
| 12 | EXO-5.3 (Allowed Sender Domains) | Medium → silently dropped | `WARNING: ... 'AllowedSenderDomains' cannot be found` | Direct deref + `Where-Object { $_.IsDefault }` on items missing IsDefault | `Get-NRGNestedProperty` + `Get-NRGSafeProperty` in filter | PR #27 |
| 13 | INT-1.3 (BitLocker Required) | High → silently dropped | `WARNING: ... 'Count' cannot be found` | `$bitlockerRequired = $winPolicies | Where-Object {...}` — `$null` when no match; `.Count` then NRE'd | `@(...)` wrapper + safe-prop in filter | PR #29 |
| 14 | XLSX compliance matrix (all controls × all frameworks) | **Critical** — entire artifact failed to generate | `WARNING: XLSX publish failed: The property 'PCIDSS' cannot be found` | `$ctrl.References.PCIDSS` direct deref under StrictMode | `Get-NRGNestedProperty` for all 10 framework citations | PR #27 |
| 15 | XLSX `PCIDSS` column header misspelled `PCIDASSS` | Cosmetic but auditor-facing | Column appeared in XLSX with wrong header | Typo in publisher | Fixed alongside #14 | PR #27 |
| 16 | EXO-6.3 (Mailboxes Unaudited — Named List) | High — wrong count surfaced | "43 mailboxes unaudited" was an undercount on dmvwrr (>1000-mailbox tenant) | `Get-Mailbox -ResultSize 1000` cap silently truncated | `-ResultSize Unlimited` for population-counting calls | PR #29 |
| 17 | EXO-6.1, EXO-6.2, EXO-6.4, EXO-7.1, EXO-7.2 (other named-list checks) | High — same undercount risk | Same | Same | Same | PR #29 |
| 18 | HTML playbook artifact | **Critical** — entire artifact failed | `WARNING: Playbook publish failed: Cannot bind parameter 'Id'` | `function H` collided with built-in `h` alias (= `Get-History -Id [long]`); PowerShell routed the title string into the alias | Renamed to `EscHtml` | PR #29 |
| 19 | Branding leak: NRG real phone `(701) 250-9400` in NLS public repo | Privacy | Was in `Config/branding.psd1` and psm1 fallback | Initial port left brand defaults intact | Cleared to empty | (security sweep) |
| 20 | Branding leak: real client name `ClientA`, `Client B` in NLS docs / clients.json | Privacy | MSP-internal client names in public repo | Initial port left sample clients in place | Sanitized to `example.com` / `example2.com` | (security sweep) |
| 21 | Branding leak: 38 client assessment HTML/JSON files tracked in NRG `output/` | Privacy | `clienta.org`, `nextlayersec.io` real tenant configs in main | `.gitignore` only excluded `Reports/`, not `output/` | Added `output/` to `.gitignore` + `git rm -r --cached output/` | PR #29 |

### Open (to investigate before declaring v4.6.5 done)

| # | ControlId(s) affected | Severity of impact | Symptom | Suspected root cause | Validation step |
|---|---|---|---|---|---|
| 22 | All DNS-* controls on tenants with multiple accepted domains | Unknown — possibly High | DNS-1.2 fires per-domain (3 findings on nextlayersec) — is this consistent? Are some DNS controls firing once for the first domain only? | Per-domain expansion logic in DNS evaluators may be inconsistent | Run against a tenant with 4+ accepted domains, count DNS findings per domain |
| 23 | License-tier detection (`Get-NRGTenantLicenseProfile`) | High if false | Tenants on Business Premium are being detected correctly in current samples — what's the false-negative rate on E5, E3, F1/F3, F5, GCC, EDU SKUs? | Pure mapping table — drift between MS SKU names and ours | Cross-reference our SKU table against the live `SubscribedSku` data on a non-BP tenant |
| 24 | Manual-review controls (count: 16 in dmvwrr run, listed as "Manual review required") | Per-control varies | Currently emit Partial with no actionable detail | Some can be automated (e.g. EXO-2.6 Shared Mailbox sign-in via `Get-MgUser` + check enabled state); some cannot (PVW-3.1 SIEM export — depends on customer SIEM) | Triage each into (a) automate by v4.7 (b) accept permanent manual |
| 25 | Findings count drift across artifacts in a single run | Low — confusing | Some artifacts say "32 Phase 1 items"; same run's exec says "28 Critical+High"; same run's all-findings table count: ? | Independent count calculations in different publishers | Add a single source-of-truth count emitted into `$reportMetadata` |
| 26 | EXO `Get-Mailbox -ResultSize 10` sampling at `Invoke-NRGCollectEXOMailboxConfig.ps1:122` | Per-control varies | Only 10 mailboxes sampled to infer "default mailbox configuration" | Intentional for performance, but could miss outliers | Document the sampling assumption + emit a coverage warning when tenant size > sample size |
| 27 | Power Platform connector classification (PPL-2.1) | Medium | Currently `NotApplicable` on every tenant in our samples | Collector may not be enumerating connectors at all, OR feature not licensed on sample tenants | Run against a tenant with PowerApps Premium and verify collector returns data |
| 28 | All `(Manual review required)` Defender controls (DEF-3.3, DEF-3.4, DEF-4.3) | Medium | Currently Partial with no concrete state | Defender for Cloud Apps API + Risky OAuth alerts API are accessible — these should be automatable | Spec the Graph calls; either implement or move to v4.7 explicitly |

### Categorized for follow-on roadmaps (NOT v4.6.5 blockers)

These are real correctness gaps but they're feature work, not regression fixes:

- AAD-1.4 / AAD-1.5 / AAD-10.1 — sign-in risk / user risk / Identity Protection workflow. Currently emit a Gap with a "Requires Entra P2" note. **Correctness behavior to fix**: when tenant doesn't hold P2, should emit `NotApplicable` not `Gap`. (Misclassification — appears as a real gap on every BP-only tenant.) → v4.7
- AAD-2.2 — Named Locations Defined. Emits Gap if zero named locations. **Correctness question**: is "zero named locations" actually a Gap, or is it acceptable for tenants that don't use IP-based CA? → v4.7
- All `PPL-3.x` (Copilot governance, 5 controls) — currently `NotApplicable` even on tenants with Copilot licensed. → v4.7

## Definition of Done for v4.6.5

The sweep is complete when **every** condition below holds:

1. Three real-run assessments (against tenants of different license tiers: BP, E5, F-series) produce **zero** `WARNING: Evaluator … cannot be found on this object` lines.
2. Three real-run assessments produce **zero** `WARNING: <Publisher> publish failed` lines.
3. Three real-run assessments produce **zero** `WARNING: There are more results available …` lines.
4. The `Total Controls` count in the assessment header matches the sum of `Satisfied + Partial + Gap + NotApplicable` (no silently-dropped findings).
5. The XLSX compliance matrix generates on every run with all 11 sheets populated and column headers correct.
6. The HTML playbook generates on every run.
7. Every entry in the "Open" table above is either Resolved or explicitly marked WONTFIX with one-line rationale.
8. A regression test exists in `Testing/NRG.Correctness.Tests.ps1` that loads a known-good fixture, runs all evaluators, and asserts zero StrictMode warnings (catches the next NRE before it ships).

## Validation method

For each Resolved entry above:
1. Identify a tenant where the original bug was reproducible.
2. Re-run `.\Invoke-NRGAssessment.ps1 -UserPrincipalName <upn>`.
3. Verify the specific `WARNING` line is gone AND the affected ControlId now emits a real finding (Satisfied / Gap / Partial / NotApplicable, not silently dropped).
4. Note the run timestamp + tenant in this doc.

The simplest tenant to use is the operator's own tenant — covers AAD, EXO, DEF, INT for the Resolved entries. A second tenant covers per-domain DNS behavior (entry #22). A third tenant (E5 or non-BP) covers license-tier detection (entry #23).

## Cross-cutting recommendations

These came out of the strategic-doc review and aren't blockers for v4.6.5 itself, but should land before v4.7 begins:

- **CLAUDE.md update gate.** Add a one-line item to a new `CONTRIBUTING.md`: "If your PR adds a control, changes a Graph scope, renames an evaluator, or alters publisher output shape, update `CLAUDE.md` in the same PR." A CI check can diff `CLAUDE.md`'s last-edit-SHA against `Evaluators/`, `Collectors/`, `Publishers/`, `Config/controls.json` last-edit-SHAs and warn if the docs are >10 commits behind.
- **Persistence-layer schema (v5.0 prep).** Before any history-store code lands, design the schema with explicit handling for: (a) ControlId additions and renames between versions, (b) per-tenant isolation, (c) retention policy default. Versioned schema migration is in scope from day 1, not an afterthought.

## Open questions for the operator

1. **The strategic doc this reviews** — is it stored somewhere I should reference (so future correctness sweeps inherit the same framing), or was it an out-of-band review?
2. **Item 19 (Azure subscription assessment) repo** — green-light to scaffold a new `NRG-Azure-Assessment` repo when v4.6.5 closes, or hold for v5.x?
3. **Tenants for validation runs.** The operator's own tenant covers most of the Resolved bugs. We need at minimum one non-BP tenant to validate entry #23 (license detection). Which tenant?

---

*Document owner: NextLayerSec. Sequenced ahead of all v4.7+ feature work per strategic review.*

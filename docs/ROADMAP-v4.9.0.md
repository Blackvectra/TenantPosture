# Roadmap v4.9.0 — Analytics + Scoping + Attestation + Portfolio

**Status:** Design. No code yet. Supersedes `docs/ROADMAP-v4.7.md` (analytics) and `docs/ROADMAP-v4.8.md` (IG scoping, attestation, portfolio, Maester eval) — both consolidated here as a single coordinated release.

**Why combined.** The original v4.7 / v4.8 split was sequencing convenience, but the features tightly couple in practice: the Maturity Model (F1) wants IG coverage as an input, the Portfolio dashboard (F13) wants Maturity and Incident-Likelihood as columns, and Attestation (F12) and Responsibility Map (F5) are both schema migrations on the same `controls.json` rows. Shipping together = **one** baseline jump, **one** tenant scope-grant cycle, **one** CHANGELOG entry, **one** documentation update for clients.

**Scope:** Both `TenantPosture` and the sibling `TenantPosture` repo land each feature in lockstep — same control IDs, same finding shapes, identical baseline JSON entries. Branding only.

**Principles** (inherited; unchanged):
- Read-only invariant holds. Every new collector uses GET-only Graph and read-only EXO cmdlets.
- Every new evaluator follows the `Add-TPFinding` contract.
- Every new control gets one row in `Config/controls.json` and one entry in the relevant baseline JSON.
- Every new feature ships at least one Pester test.
- Module manifest exports stay in sync between psm1 and psd1.

---

## Scope boundary (the principle, not a feature)

`TenantPosture` is a **Microsoft tenant cloud assessment tool**. It collects through Graph, EXO, Teams, SharePoint, Intune, Purview, Defender for O365, and Power Platform APIs plus authoritative DNS. It is **not**, and will not become:

- An endpoint hardening scanner. No per-device WMI/registry reads. No `Get-HotFix`, `manage-bde -status`, `Get-LocalUser`, `Get-LocalGroupMember`, autorun-policy, PS-logging-policy, or exploit-protection registry checks.
- A third-party EDR connector. No Cortex XDR API, no MDR-platform integrations we don't own.
- A patch-management dashboard. Endpoint patch state is RMM/Intune-managed; this tool reports the Intune-side *cloud signal* only.

Endpoint-side checks belong in a separate companion tool running under RMM agent context. Its output schema is a future contract, not part of this repo.

What stays in scope from CIS IG1/IG2: identity & MFA & CA & role assignments & SP allowlist (Graph); email auth stack (DNS) and email policy (EXO + Defender for O365); Intune cloud signal (compliance policies exist, devices report compliant, app-protection policies exist); cloud audit log retention setting; M365 backup configuration (policy existence — restore testing is out of scope).

---

## Feature matrix

| # | Feature | New controls | New collectors | Schema changes | New Graph scopes | Effort |
|---|---|---|---|---|---|---|
| **Schema migration** (one combined PR) | | | | | | |
| F5 | Responsibility Map | 0 | 0 | `Responsibility` per control | 0 | 0.5 d |
| F11 | IG1/IG2 grouping | 0 | 0 | `ImplementationGroup` per control + `baselines/cis-ig-matrix.json` | 0 | 0.5 d |
| **Self-contained analytics** | | | | | | |
| F10 | License Waste / Right-Sizing | 5 (`LIC-1.1..5`) — new workload code `LIC` | 0 | 0 | 0 | 1 d |
| F4 | Thread Hijack Composite | 1 (`EXO-9.1`) | 0 (composes existing data) | 0 | 0 | 1 d |
| F8 | Supply Chain Risk | 3 (`AAD-15.1..3`) | 1 optional (GDAP via Partner Center, `-IncludeGDAPReview`) | 0 | 0 (optional Partner Center API) | 1.5 d |
| **Derived analytics (read all findings)** | | | | | | |
| F1 | Maturity Model | 0 (derived) | 0 | 0 | 0 | 1 d |
| F2 | Incident Likelihood | 0 (derived) | 0 | `IncidentRiskMultipliers` per control + `baselines/incident-anchors.json` | 0 | 1.5 d |
| F12 | Governance Attestation | 0 (attested mapping) | 0 | new `Config/attestation-items.json` | 0 | 1 d |
| **New collectors / scopes** | | | | | | |
| F9 | Security Culture Signals | 1 (`AAD-16.1`) | 1 (Attack Simulator) | 0 | **+1 `AttackSimulation.Read.All`** | 1.5 d |
| F3 | Admin Behavioral Baseline | 1 (`AAD-14.1`) | 1 (30-day sign-in window) | 0 | 0 (reuses existing) | 2 d |
| **Cross-tenant surfaces** | | | | | | |
| F6 | Regression Alerting | 0 (reuses evaluators) | 0 | 0 | 0 | 1 d |
| F7 | Self-Service Portal — Phase 1 | 0 | 0 | 0 | 0 | 1 d |
| F13 | Portfolio HTML Dashboard | 0 | 0 | 0 | 0 | 1 d |
| **Evaluation only** | | | | | | |
| F14 | Maester integration eval | 0 | 0 | 0 | 0 | 0.5 d (doc only) |

**Total:** 11 new controls + 1 new workload code (`LIC`) + 1 new Graph scope + 3 schema additions to `controls.json` + 4 new baseline JSON files (`cis-ig-matrix.json`, `incident-anchors.json`, `attestation-items.json`, `pricing.json`). Headline estimate: **~14 dev-days** end to end excluding research time for the embedded reference data.

---

## Feature detail

### F5 — Shared Responsibility Map

`controls.json` schema: required `Responsibility` field per control. Allowed values: `MSP`, `ClientIT`, `Vendor`, `Microsoft`, `Shared`. New helper `Lib/Get-TPFindingResponsibility.ps1` returns the value with baseline-JSON overrides allowed for client-specific deviations. Publisher gets a new "Accountability Matrix" HTML section grouping gaps by responsible party. One-time migration: populate all 188 existing controls (DNS-* → Shared; PPL-* Copilot → ClientIT; Defender preset / CA creation → MSP; license decisions → ClientIT; platform defaults → Microsoft).

### F11 — IG1/IG2 grouping on existing controls

`controls.json` schema: required `ImplementationGroup` field per control. Allowed values: `IG1`, `IG2`, `IG3`, `NotMapped`. Mapping source: CIS Controls v8.1 IG matrix in `baselines/cis-ig-matrix.json` (frozen reference). New helper `Lib/Get-TPIGScore.ps1` returns `@{ IG; Total; Satisfied; Gap; CoveragePct; CriticalGaps }`. Publisher gets three IG scorecard tiles next to the existing license-tier card. JSON output gets a top-level `IGScores` block.

### F10 — Licensing Waste / Right-Sizing

New evaluator `Test-TPControlLicenseWaste.ps1`. Composes from existing `AAD-Inventory.SubscribedSkus` plus per-workload deployment state already collected. Match table: Defender O365 P1/P2 → Safe Attachments + Safe Links deployed; Intune (any) → at least one compliance policy + enrolled devices; Purview/E5 Compliance → ≥1 DLP policy active; Entra P1 → ≥1 enabled CA policy; Entra P2 → PIM eligibility used. Five new controls `LIC-1.1..1.5`. New workload code `LIC` — add to `Get-TPControlDefinitions.ps1` and the workload scorecard grid.

### F4 — Thread Hijack Composite Risk

New evaluator `Test-TPControlEXOThreadHijackComposite.ps1`. No new collector; composes `EXO-MailboxConfig` (forwarding, transport rules), `DNS-Summary` (DMARC), `Defender-Policies` (Safe Links), `EXO-MailboxConfig.MailboxPermissions` (FullAccess delegations). Risk score 0–100; threshold map <30 Low, 30–60 Medium, 60+ High. Detail field renders an explicit attack-path narrative for the executive summary.

### F8 — Vendor & Supply Chain Risk

New evaluator `Test-TPControlAADSupplyChainRisk.ps1`. No new mandatory collector; composes `AAD-Inventory` (service principals + delegated permissions), `AAD-Users` (guests by external domain), `AAD-DirectoryRoles` (role assignments to guests). Three new controls `AAD-15.1..15.3`. Optional opt-in `-IncludeGDAPReview` flag pulls GDAP relationships via Partner Center API for partner-managed tenants.

### F1 — Tenant Security Maturity Model

Tiers: Initial (1) → Developing (2) → Defined (3) → Managed (4) → Optimizing (5). Classification rule combines coverage % of license-applicable controls, critical-gap count, and sustained-period history. New helper `Lib/Get-TPMaturityTier.ps1`. Publisher: maturity badge above the score ring, tier-ladder visualization, trajectory arrow vs last assessment. JSON output: top-level `Maturity` block. **History store:** `output/<tenant>/maturity-history.json`, append-only, fields covered by the existing signed integrity manifest.

### F2 — Incident Likelihood Scoring

Per-incident-type probability and expected annual loss anchored to Verizon DBIR base rates and IBM Cost of a Data Breach loss curves (both 2025 editions). `controls.json` schema: optional `IncidentRiskMultipliers` per control. New `baselines/incident-anchors.json` (frozen at release; verify redistribution terms — see open questions). New helper `Lib/Get-TPIncidentLikelihood.ps1`. Publisher: new "Financial Risk Forecast" HTML section above Attack Scenario Analysis. Renders four cards (BEC, Ransomware, Data exfiltration, Credential compromise) with probability bar and dollar figure.

### F12 — Governance Attestation Form

Two new entry points at repo root: `Invoke-TPAttestation.ps1` (interactive CLI walks operator through items; writes `output/<tenant>/attestation-<year>.json`) and `Publish-TPAttestationForm.ps1` (standalone static HTML form, strict CSP, self-contained, exports to JSON). Item set defined in `Config/attestation-items.json`; initial ~12–15 items (IR plan exists, IR plan tested, pentest within 12 months, security awareness training, phishing simulation, vendor security clauses, PAW use, post-incident reviews, restore tested, RACI documented, data classification policy, change-management policy, access review cadence, vulnerability disclosure process). Orchestrator folds the most recent attestation file into the findings stream — `Satisfied` / `Gap` / `Stale`. New evaluator `Test-TPControlAttested.ps1` emits one finding per mapped CIS Control safeguard.

### F9 — Security Culture Signals

Composite signal — does the org *engage* with security as a practice? Inputs: voluntary MFA registration rate (excluding CA-forced), Attack Simulator campaign in last 180 days, evidence of admin role reviews (PIM access reviews or role-assignment changes in last 90 days), audit-log activity from non-Global-Admin security operators in last 30 days. New collector `Invoke-TPCollectAttackSim.ps1`. **Requires new Graph scope `AttackSimulation.Read.All`** — this is the only new scope in v4.9.0; needs re-consent in every client tenant on rollout. One new control `AAD-16.1` (Informational severity, composite Culture Score 0–100). Degrade gracefully when scope not granted (emits `NotApplicable` with operator-facing note).

### F3 — Privileged Account Behavioral Baseline

New collector `Invoke-TPCollectAADAdminSignInTelemetry.ps1`. Pulls last 30 days of sign-in logs filtered to users with active privileged role assignments. Persists timestamp, IP, country, ASN, device ID, app ID, CA result. Reuses existing `AuditLog.Read.All`. New evaluator splits the window into `baseline` (days 8–30) and `recent` (days 1–7); detects three anomaly classes: new country, new ASN, new sign-in hour window outside admin's historical distribution. One new control `AAD-14.1`. Highest-volume data change in this release.

### F6 — Security Regression Alerting

New entry point `Invoke-TPRegressionCheck.ps1` at repo root. Loads the most recent full-assessment JSON for the tenant; re-runs only Critical and High evaluators against the live tenant; any control that was `Satisfied` in baseline and is now `Gap` or `Partial` is a regression. Outputs stdout table, `output/<tenant>/regression-<timestamp>.json`, optional webhook POST (Slack/Teams format). Exit codes: 0 = no regressions, 1 = regressions present, 2 = baseline not found. Designed for Task Scheduler / cron / Azure Automation.

### F7 — Client Self-Service Portal — Phase 1

New flag on `Publish-TPAssessmentHTML.ps1`: `-SelfServiceMode`. Strips MSP-only content (pricing, hourly rate, services pitch, internal notes). Adds prominent "Last assessment: YYYY-MM-DD" banner and simple client-side findings search/filter (vanilla JS, CSP-safe with the existing sha256-hash strategy). Embeds findings as `<script type="application/json">` for the filter widget. Output: `<tenant>-self-service.html` — single self-contained file. **Phase 2** (hosted multi-tenant portal with per-client login) is explicitly out of scope here and tracked separately.

### F13 — Portfolio HTML Dashboard

New publisher `Publish-TPPortfolioHTML.ps1`. Called from `Invoke-TPBatchAssessment.ps1` at end of batch run; consumes `$batchResults` plus each client's `results.json`. Output: `output/portfolio-<timestamp>.html` — single self-contained file. Sections: header strip (timestamp, client count, average score); sortable client table (name, score, maturity tier from F1, IG1 %, IG2 %, critical gaps, high gaps, delta since last run, report link); workload heatmap (clients × workloads cells colored by per-workload coverage); top-10 risk roll-up across all clients; client-name search + score range slider + "show only critical." All tenant data through `ConvertTo-TPHtmlSafe`. Strict CSP identical to per-client report.

### F14 — Maester Integration Evaluation

Eval-only feature. Deliverable: `docs/MAESTER-EVALUATION.md` with side-by-side control coverage matrix (Maester check ID ↔ NRG ControlId), where Maester is more current (newer Entra API surface, newer SCuBA rule IDs), where NRG is more current (multi-tenant orchestration, license-aware scoring, interactive HTML, attestation), four integration options (run as child process / pull citation DB / adopt for specific workloads / don't integrate), and recommendation. **No code in v4.9.0** — downstream features land in a subsequent release based on which option this doc recommends.

---

## Implementation order

Sequenced to minimize cross-feature merge conflicts. Schema migrations land together so `controls.json` is touched once.

| Wave | PR | Includes | Why this order |
|---|---|---|---|
| 1 | Schema PR | F5 (Responsibility) + F11 (IG groups) | One combined migration on the 188 controls. One validation tool addition. One CHANGELOG entry. Everything downstream depends on these fields. |
| 2 | License Waste | F10 | Self-contained, new workload code, no scope changes. Quick win that demonstrates the v4.9 schema in use. |
| 3 | Composite Risk | F4 + F8 | No new collectors, no scopes. Both compose existing data. Land together. |
| 4 | Derived analytics | F1 (Maturity) + F2 (Incident Likelihood) | Both read all findings. Want F5+F11 schema and F4/F10 data points to be live. |
| 5 | Attestation | F12 | Depends on F11 IG mapping. Adds first non-evaluator finding source. |
| 6 | Culture Signals | F9 | New Graph scope — coordinated app reg update + per-tenant re-consent. |
| 7 | Admin Behavioral Baseline | F3 | Largest data-volume change (30-day window). Lands after the surrounding analytics so we can see it in context. |
| 8 | Regression Alerting | F6 | Needs all evaluators stable. |
| 9 | Self-Service Portal Phase 1 | F7 | Pure publisher; benefits from F1, F2, F5 already in the report. |
| 10 | Portfolio Dashboard | F13 | Cross-client roll-up; benefits from F1, F11, F12 already live. |
| 11 | Maester Eval | F14 | Independent; doc-only; can be picked up any time after Wave 1. |

Each wave is one PR per repo, lockstep across both repos.

---

## Cross-cutting changes

**`controls.json` schema additions** (Wave 1 lands all three at once):
- `Responsibility` — required, enum `{MSP, ClientIT, Vendor, Microsoft, Shared}` (F5)
- `ImplementationGroup` — required, enum `{IG1, IG2, IG3, NotMapped}` (F11)
- `IncidentRiskMultipliers` — optional, `@{ BEC=float; Ransomware=float; DataExfil=float; CredentialCompromise=float }` (F2)

**New baseline JSON files:**
- `baselines/cis-ig-matrix.json` (F11)
- `baselines/incident-anchors.json` (F2)
- `baselines/pricing.json` (F10)
- `Config/attestation-items.json` (F12)

**Graph scope additions** (only one): `AttackSimulation.Read.All` for F9. Coordinated app-reg update and per-tenant re-consent required at rollout.

**New workload code:** `LIC` for F10. Add to control prefix validation list and HTML workload scorecard.

**Tests** — one Pester file per feature, all in `Testing/`:
`TP.Responsibility.Tests.ps1` · `TP.IGScoring.Tests.ps1` · `TP.LicenseWaste.Tests.ps1` · `TP.ThreadHijack.Tests.ps1` · `TP.SupplyChain.Tests.ps1` · `TP.Maturity.Tests.ps1` · `TP.IncidentLikelihood.Tests.ps1` · `TP.Attestation.Tests.ps1` · `TP.Culture.Tests.ps1` · `TP.AdminBaseline.Tests.ps1` · `TP.Regression.Tests.ps1` · `TP.SelfService.Tests.ps1` · `TP.Portfolio.Tests.ps1`.

**Tooling** — `tools/Validate-Baselines.ps1` (new, small) ensures every control has the new required fields populated before commits land. Wired into CI as part of the existing Module Manifest job.

**Module manifest** — every new function exported by Wave 2+ must appear in both `TenantPosture.psd1 FunctionsToExport` and `TenantPosture.psm1 $script:ExportedFunctions`.

**CHANGELOG** — one consolidated v4.9.0 entry rolled up at the end of Wave 10 (or as we ship). Sub-sections per wave.

**Read-only invariant** — every new collector is GET-only. F3 admin telemetry is read-only. F6 regression check is read-only. F7 / F13 publishers write to operator workstation only. F12 attestation writes to operator workstation only. No tenant writes anywhere in this release.

---

## Open questions (resolve before each wave lands)

1. **DBIR / CoDB licensing** (F2). Embedding base rates from Verizon DBIR 2025 and IBM Cost of a Data Breach 2025 — verify distribution terms permit redistribution in `baselines/incident-anchors.json`, or fall back to cite-and-link (operator pulls the doc, the report shows the citation but not the embedded number).
2. **CIS IG matrix licensing** (F11). Verify CIS membership terms allow redistributing the CIS Controls v8.1 IG mapping in `baselines/cis-ig-matrix.json`, or cite + link from the report.
3. **AttackSimulation scope re-consent** (F9). Requires re-consent in every client tenant on rollout. Acceptable churn, or do we skip F9 in v4.9.0 and ship as v4.9.1? Decision needed before Wave 6.
4. **Maturity tier history forgery** (F1). `output/<tenant>/maturity-history.json` is local. Easy to forge locally. Current mitigation: file is covered by the existing signed integrity manifest. Sufficient, or escalate?
5. **GDAP enumeration opt-in** (F8). Partner Center API requires partner consent separate from tenant consent. `-IncludeGDAPReview` flag (opt-in) is the proposed default. Confirm before Wave 3.
6. **Portfolio scale at 50+ clients** (F13). Workload heatmap gets dense beyond ~50 rows. Set a threshold (e.g. ≥ 50 clients) for switching to a paginated/grouped view?
7. **Maester license boundary** (F14). MIT — compatible with this repo's MIT license. Confirm derivative-work boundary before adopting any Maester code directly.
8. **Operator UPN at attestation time** (F12). When operator runs from a partner tenant under GDAP, `AttestedBy` should record the operator UPN, not the client tenant identity. Confirm UPN is available from the connection context at attestation time.

---

## Acceptance criteria for v4.9.0 ship

A v4.9.0 release is considered ready when:
- All 14 features land per implementation order, each with its own merged PR and green CI.
- `Config/controls.json` validates clean under the v4.9 schema (all 188 + 11 new = 199 controls have `Responsibility` and `ImplementationGroup`; new controls have `IncidentRiskMultipliers` where applicable).
- New Graph scope `AttackSimulation.Read.All` is granted in at least the NRG sandbox tenant and at least one client tenant for testing.
- `Test-TPEnvironment` (carryover polish item) reports green for an operator workstation with the full module loaded.
- Re-run of the most recent real-tenant assessment produces a report whose top-line score is within ±5% of the v4.6.7 baseline (the v4.6.7 baseline assessment is included in `output/baseline-v4.6.7-<tenant>.json` as a regression anchor).
- The runbook (`docs/INCIDENT-RESPONSE.md`) has a stanza added for "attestation file leak" since attestation JSON contains client governance claims.
- A v4.9.0 entry in CHANGELOG.md covers every wave.

---

*Design owner: NRG Technology Services / NextLayerSec LLC. This document supersedes `docs/ROADMAP-v4.7.md` and `docs/ROADMAP-v4.8.md`. Both source documents remain in place for git history but should not be modified going forward.*

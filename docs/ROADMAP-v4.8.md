# Roadmap v4.8 — IG1/IG2 grouping, attestation, and portfolio surface

> **⚠️ SUPERSEDED.** This document has been rolled into [`docs/ROADMAP-v4.9.0.md`](ROADMAP-v4.9.0.md), which combines the v4.7 (analytics) and v4.8 (IG scoping / attestation / portfolio / Maester) waves into a single coordinated release. Do not modify this file going forward — it remains in place for git-history continuity only. Implementation tracking moves to the v4.9.0 doc.

**Status:** Design. No code yet. Sibling of `docs/ROADMAP-v4.7.md`. v4.7 covers analytics features; v4.8 covers scoping clarity, the IG1/IG2 view onto existing 188 controls, the governance-attestation hole, and the cross-client surface.

**Scope:** Both `NRG-Assessment` and the sibling repo land each feature in lockstep — same control IDs, same finding shapes, identical baseline JSON entries. Branding is the only diff.

---

## Scope boundary (this section is the principle, not a feature)

`NRG-Assessment` is a **Microsoft tenant cloud assessment tool**. It collects through Graph, EXO, Teams, SharePoint, Intune, Purview, Defender for O365, and Power Platform APIs plus authoritative DNS. It is **not**, and will not become:

- An endpoint hardening scanner. No per-device WMI/registry reads. No `Get-HotFix`, `manage-bde -status`, `Get-LocalUser`, `Get-LocalGroupMember`, autorun-policy, PS-logging-policy, or exploit-protection registry checks.
- A third-party EDR connector. No Cortex XDR API, no MDR-platform integrations we don't manage.
- A patch-management dashboard. Endpoint patch state is RMM/Intune-managed; this tool reports the Intune-side *cloud signal* only.

Endpoint-side checks belong in a separate companion tool running under RMM agent context. That tool's output schema is a future contract, not part of this repo.

What stays in scope from CIS IG1/IG2:
- Identity, MFA, CA, role assignments, SP allowlist (Graph)
- Email auth stack (DNS) and email policy (EXO + Defender for O365)
- Intune *cloud signal*: compliance policies exist, devices report compliant, app-protection policies exist
- Cloud audit log retention setting (not log completeness verification)
- M365 backup configuration (policy existence — restore testing is out of scope)

---

## Feature 11 — IG1/IG2 grouping on existing controls

**Problem.** The 188 controls already map to CIS M365 v6, SCuBA, NIST 800-53r5, CMMC, ISO 27001, SOC 2, HIPAA, PCI DSS, DISA STIG, and MITRE ATT&CK. They are **not tagged by CIS Implementation Group** (IG1, IG2, IG3). Government and regulated clients ask for an IG1 / IG2 conformance view explicitly.

**Architecture.**
- `Config/controls.json` schema extension: required `ImplementationGroup` field per control. Allowed values: `IG1`, `IG2`, `IG3`, `NotMapped`.
- Mapping source: CIS Controls v8.1 IG matrix (frozen reference embedded in `baselines/cis-ig-matrix.json`). One-time mapping pass populates every control. Controls that don't map cleanly to a CIS Control safeguard get `NotMapped`.
- New: `Lib/Get-NRGIGScore.ps1` — `Get-NRGIGScore -Findings $f -ImplementationGroup 'IG1'` returns `@{ IG=1; Total=N; Satisfied=S; Gap=G; CoveragePct=P; CriticalGaps=C }`.
- Publisher: new HTML scorecard tiles — three IG cards (IG1, IG2, IG3) next to existing license-tier card. Each shows score + gap count + critical count.
- JSON output: new top-level `IGScores` block with `IG1`, `IG2`, `IG3` entries.
- Backwards compatibility: framework citations table unchanged. Adds one column (IG) to the existing All Findings table.

**Validation.** A new check in `tools/Validate-Baselines.ps1` (already proposed in v4.7) ensures every control has `ImplementationGroup` populated before commits land.

**No new controls.** Schema/data migration on existing 188.

**Effort.** Half day per the user's estimate, plus mapping research time.

---

## Feature 12 — Governance attestation form

**Problem.** A meaningful share of IG1/IG2 controls cannot be pulled from any tenant API. Examples: IR plan exists and is current; pentest conducted in last 12 months; security-awareness training records; vendor contracts include security requirements; PAW usage compliance; post-incident reviews documented. These need attestation, not scripting.

**Architecture.**
- Two new entry points at repo root:
  - `Invoke-NRGAttestation.ps1` — interactive prompt-driven CLI form. Walks the operator through the attestation items, writes `output/<tenant>/attestation-<year>.json`.
  - `Publish-NRGAttestationForm.ps1` — generates a standalone static HTML form that an operator (or the client) can open in a browser, fill in, and *export to JSON*. Single self-contained file with strict CSP (consistent with the existing report security model). No backend.
- Attestation items defined in `Config/attestation-items.json`. Each item: `Id`, `Question`, `Category`, `EvidenceField` (free text), `LastReviewed` (date), `NextReviewDue` (auto-calculated), `MappedControls` (array of CIS Control safeguards), `Required` (bool).
- Initial item set (target ~12–15 items): IR plan, IR plan tested, pentest within 12 months, security awareness training completed for all users, phishing simulation in last 6 months, vendor security clauses present, PAW used for admin tasks, post-incident reviews on all material incidents, backup restore tested, RACI documented, data classification policy, change management policy, access review cadence, vulnerability disclosure process.
- The orchestrator (`Invoke-NRGAssessment.ps1`) reads the most recent `attestation-<year>.json` if present and folds attested items into the findings stream with state `Satisfied`, `Gap` (item answered No), or `Stale` (item not attested this year). Detail field includes the attestation date and operator name.
- A new evaluator `Evaluators/Test-NRGControlAttested.ps1` reads the attestation file and emits one finding per mapped CIS Control.

**Security.**
- Attestation JSON is sensitive (records what client claims about their governance). `Set-NRGSensitiveFileAcl` applied on write.
- Attestation HTML form enforces same strict CSP as the main report (Trusted Types, no inline event handlers, nonce on script blocks).
- Attestation entries include `AttestedBy` (operator UPN) and `AttestedAt` (timestamp). No PII beyond the operator identity.

**New controls.** No new technical controls — attestation items map to existing CIS Control safeguards via `MappedControls`.

**Effort.** Half day per user estimate.

---

## Feature 13 — Cross-client HTML portfolio dashboard

**Problem.** Current batch run produces per-client HTML + a flat `batch-summary-<timestamp>.md` markdown table. There's no interactive cross-client surface. Quarterly MSP reviews want one pane showing every tenant's score, critical-gap count, maturity tier, IG1/IG2 coverage, and delta-since-last-quarter.

**Architecture.**
- New publisher: `Publishers/Publish-NRGPortfolioHTML.ps1`.
- Called from `Invoke-NRGBatchAssessment.ps1` at the end of the batch run, after all per-client assessments complete.
- Consumes the `$batchResults` array already accumulated by the batch runner plus each client's `results.json`.
- Output: `output/portfolio-<timestamp>.html` — single self-contained file, no external assets, openable in any browser.
- Sections:
  - Header strip with run timestamp, client count, average score.
  - Sortable client table: name, score, maturity tier (from v4.7 F1), IG1 %, IG2 %, critical gaps, high gaps, delta since last run, report link.
  - Workload heatmap: rows = clients, columns = workloads (AAD, EXO, DEF, etc.), cells colored red/yellow/green by per-workload coverage.
  - Top risk roll-up: ten most common Critical/High gaps across all clients (with count of affected tenants).
  - Quick filter: client name search, score range slider, "show only clients with critical gaps."
- All client tenant data passes through `ConvertTo-NRGHtmlSafe` before render. No client data ever leaves the operator workstation.
- CSP enforcement identical to per-client report (strict CSP via `<meta>` plus Trusted Types).

**No new controls.** Publisher-only addition.

**Effort.** 1 day per user estimate.

---

## Feature 14 — Maester integration evaluation

**Problem.** [Maester](https://maester.dev) is a community PowerShell test framework for M365 posture assessment with active maintenance and CIS / SCuBA / Entra ID coverage. Some checks may be more current there than in our hand-rolled evaluators; some may overlap and waste effort. Need a structured comparison before committing to integrate, build alongside, or ignore.

**Architecture.**
- This is an **evaluation feature, not a build feature.** Deliverable is `docs/MAESTER-EVALUATION.md` with:
  - Side-by-side control coverage matrix (Maester check ID ↔ NRG ControlId).
  - Where Maester is more current (e.g. newer Entra ID API surface, newer CISA SCuBA rule IDs).
  - Where NRG is more current (multi-tenant orchestration, license-aware baselines, interactive HTML).
  - Integration options:
    1. Run Maester as a child process from the orchestrator, merge its Pester results into our findings stream.
    2. Pull Maester's framework-citation database periodically and use it to keep our `FrameworkIds` fields fresh.
    3. Adopt Maester for specific workloads where its coverage clearly exceeds ours; deprecate the overlapping NRG evaluators.
    4. Don't integrate; treat as a benchmark for review.
- Recommendation lands in the doc after the matrix is built. No code change in this feature; downstream features (likely a v4.9 wave) implement the chosen path.

**Effort.** Half day per user estimate.

---

## Implementation order

F11 → F12 → F13 → F14 (sequenced; F11 is the schema migration that F13's portfolio HTML depends on).

| # | Feature | Depends on | Order rationale |
|---|---------|------------|-----------------|
| 11 | IG1/IG2 grouping | – | Schema migration; lands first |
| 12 | Governance attestation | F11 (for IG mapping) | Can run in parallel with F13 once F11 lands |
| 13 | Portfolio HTML dashboard | F11, optionally v4.7 F1 (maturity), v4.7 F2 (likelihood) | Most useful once F11 fields exist |
| 14 | Maester evaluation | – | Independent; can start anytime |

v4.7 and v4.8 land independently. If v4.7 F1 (maturity) is in by the time F13 ships, the portfolio dashboard surfaces the tier; if not, it falls back to raw score.

---

## Cross-cutting changes

- **Module manifest.** Each new function exported by F11/F12/F13 must appear in both `NRG-Assessment.psd1` and `NRG-Assessment.psm1` exports list.
- **CHANGELOG.** v4.8.0 entry on implementation begin.
- **Read-only invariant.** F11 schema migration is config-only. F12 attestation writes to the operator's `output/` directory (not to tenant). F13 portfolio is pure render. No tenant writes anywhere.
- **No new Graph scopes.** Everything reuses what's already requested.

---

## Open questions

1. **CIS IG matrix licensing.** Embedding CIS Controls v8.1 IG mapping data — verify CIS membership terms allow redistribution in our `baselines/cis-ig-matrix.json`. If not, cite + link from the doc rather than embed.
2. **Attestation operator identity.** When operator runs from a partner tenant under GDAP, `AttestedBy` should record the operator UPN, not the client tenant identity. Confirm UPN is available from the connection context at attestation time.
3. **Portfolio dashboard scale.** At ~50+ clients the workload heatmap gets dense. Threshold for switching to a paginated/grouped view?
4. **Maester integration license.** Maester is MIT — compatible with this repo's CC BY-ND license on docs. Confirm derivative-work boundary before adopting any code directly.

---

*Design owner: NRG Technology Services / NextLayerSec LLC. Reviews before implementation begins. Companion: `docs/ROADMAP-v4.7.md`.*

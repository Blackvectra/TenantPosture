# Roadmap v4.7 — Ten new feature areas

**Status:** Design. No code yet. This document defines architecture, control IDs, data shapes, and publisher impact for the v4.7 feature wave. Implementation tracked in [#TBD] once this design is approved.

**Scope:** Both `NRG-Assessment-Tool` (this repo) and the sibling repo land each feature in lockstep — same control IDs, same finding shapes, identical baseline JSON entries. Branding is the only diff.

**Principles:**
- Read-only invariant holds. Every new collector uses GET-only Graph and read-only EXO cmdlets.
- Every new evaluator follows the `Add-NRGFinding` contract (ControlId, State, Category, Title, Severity, Detail, FrameworkIds, CurrentValue, RequiredValue, Remediation).
- Every new control gets one row in `Config/controls.json` and one `Configuration` entry in exactly one `baselines/nrg-baseline-*.json` tier file.
- Every new feature includes a Pester test in `Testing/`.
- Module manifest exports stay in sync between `NRG-Assessment.psm1` and `NRG-Assessment.psd1`.

---

## Feature 1 — Tenant Security Maturity Model (TSMM)

**Problem.** A score of 74% is abstract. Executives want a tier and a trajectory. MSP sales want a service-tier ladder mapped to maturity progression.

**Tiers.** Initial (1) · Developing (2) · Defined (3) · Managed (4) · Optimizing (5).

**Tier classification rule** (resolved at publish time from current findings + historical results):

| Tier         | Coverage of license-applicable controls | Critical gaps | Sustained periods |
|--------------|------------------------------------------|---------------|-------------------|
| Initial      | < 40%                                   | any           | n/a               |
| Developing   | 40–60%                                  | ≤ 5 critical  | n/a               |
| Defined      | 60–75%                                  | 0 critical    | n/a               |
| Managed      | 75–90%                                  | 0 critical, ≤ 3 high | ≥ 2 consecutive assessments at Defined or above |
| Optimizing   | ≥ 90%                                   | 0 critical, 0 high | ≥ 3 consecutive assessments at Managed |

**Architecture.**
- New: `Lib/Get-NRGMaturityTier.ps1` — `Get-NRGMaturityTier -CurrentFindings $f -HistoricalResults $hist` returns `@{ Tier=4; TierName='Managed'; CoveragePct=82; CriticalGaps=0; HighGaps=2; Trajectory='Improving' }`.
- Publisher addition in `Publish-NRGAssessmentHTML.ps1`: maturity badge above the score ring, ladder visualization, trajectory arrow vs last assessment.
- JSON output: top-level `Maturity` block with tier, name, coverage, gap counts, trajectory.
- Delta report integration: tier movement highlighted in `Publish-NRGDeltaReport.ps1`.

**No new controls.** Maturity is derived, not evaluated.

---

## Feature 2 — Incident Likelihood Scoring

**Problem.** The risk quant numbers already in v4.6 are abstract dollars. Sales conversations need per-incident-type probability and expected annual loss anchored to industry data.

**Incident types.** BEC · Ransomware · Data exfiltration · Credential compromise.

**Anchors.**
- Verizon DBIR 2025 base rates per pattern (frozen, embedded in module).
- IBM Cost of a Data Breach 2025 expected loss per incident type by org size.

**Probability formula (per type).**
```
P(incident) = BaseRate(industry, size)
            × (1 + Σ riskMultiplier(controlGap) for relevant gaps)
            × tenureFactor(years_managed)
```
Each relevant control has a published `IncidentRiskMultiplier` per incident type in `Config/controls.json`. Sum is bounded to `[0, 1)`.

**Architecture.**
- New: `Lib/Get-NRGIncidentLikelihood.ps1` — `Get-NRGIncidentLikelihood -Findings $f -TenantProfile $p` returns array of `@{ IncidentType; ProbabilityPct; ExpectedAnnualLossUSD; ContributingControlIds; DBIRAnchor; CoDBAnchor }`.
- New embedded data: `baselines/incident-anchors.json` — DBIR base rates and CoDB loss curves (frozen at release).
- `Config/controls.json` schema extension: new optional `IncidentRiskMultipliers = @{ BEC=0.15; Ransomware=0.02; ... }` per control.
- Publisher: new "Financial Risk Forecast" HTML section before Attack Scenario Analysis. Renders 4 cards, one per incident type, with probability bar and dollar figure.

**No new controls.** Existing control gaps drive the score.

---

## Feature 3 — Privileged Account Behavioral Baseline

**Problem.** Microsoft's risky-sign-in is anchored to global threat intel, not per-tenant norms. An admin who has never signed in from outside North Dakota at 2am is a meaningful tenant-specific signal.

**Architecture.**
- New collector: `Collectors/AAD/Invoke-NRGCollectAADAdminSignInTelemetry.ps1`.
  - Pulls last 30 days of sign-in logs filtered to users with active privileged role assignments.
  - Captures per sign-in: UTC timestamp, IP, country, ASN, device ID, app ID, conditional-access result.
  - Persists to a new raw-data key `AAD-AdminSignInTelemetry`.
- New evaluator: `Evaluators/Test-NRGControlAADAdminBehavioralBaseline.ps1`.
  - Splits the 30-day window into `baseline` (days 8–30) and `recent` (days 1–7).
  - Detects three anomaly classes: new country, new ASN, new sign-in hour window outside admin's historical distribution.
  - Emits one finding per anomalous admin with the deviation list in `Detail`.
- Graph scopes required: `AuditLog.Read.All` (already in scope list ✓), `RoleManagement.Read.Directory`.

**New controls.**

| ControlId | Title | Severity | Workload | Tier |
|-----------|-------|----------|----------|------|
| AAD-14.1 | Admin behavioral baseline — no anomalies | High | AAD | premium |

---

## Feature 4 — Email Thread Hijacking Indicators

**Problem.** Thread hijacking is the most damaging BEC variant. It is enabled by the *combination* of external forwarding rules, weak DMARC, absent Safe Links, and mailbox delegation patterns. Reporting each gap individually undersells the composite risk.

**Architecture.**
- New evaluator: `Evaluators/Test-NRGControlEXOThreadHijackComposite.ps1`.
- No new collector — composes findings from existing raw data:
  - `EXO-MailboxConfig` (auto-forwarding, transport rules)
  - `DNS-Summary` (DMARC policy state per domain)
  - `Defender-Policies` (Safe Links enablement)
  - `EXO-MailboxConfig.MailboxPermissions` (FullAccess delegations)
- Risk score = 0–100. Threshold mapping: <30 Low, 30–60 Medium, 60+ High.
- Finding renders an explicit attack-path narrative: *"Forwarding rules in N mailboxes + DMARC `p=none` on M domains + Safe Links off for K policies + L FullAccess delegations to non-admin accounts = thread hijacking enabled."*

**New controls.**

| ControlId | Title | Severity | Workload | Tier |
|-----------|-------|----------|----------|------|
| EXO-9.1 | Thread hijack composite risk indicator | High | EXO | basic |

---

## Feature 5 — Shared Responsibility Accountability Map

**Problem.** MSP engagements stall when remediation ownership is unclear. The report needs to explicitly tag each gap to a responsible party.

**Architecture.**
- `Config/controls.json` schema extension: required `Responsibility` field per control. Allowed values: `MSP`, `ClientIT`, `Vendor`, `Microsoft`, `Shared`.
- `Add-NRGFinding` accepts the field from the control definition (no API change to callers — pulled from `Get-NRGControlById`).
- New: `Lib/Get-NRGFindingResponsibility.ps1` — returns responsibility for a finding, with overrides allowed via baseline JSON for client-specific deviations (e.g., a client where DNS is managed by a third party).
- Publisher: new HTML section "Accountability Matrix" — table of all gaps grouped by responsible party.
- One-time migration: populate `Responsibility` on all 188 existing controls. Default mapping:
  - DNS-* → `Shared` (MSP recommends, client DNS provider executes)
  - PPL-* (Copilot governance) → `ClientIT`
  - Defender preset deployment, CA policy creation → `MSP`
  - License purchase decisions → `ClientIT`
  - Platform behavior (e.g., default tenant settings) → `Microsoft`

**No new controls.** Schema/data migration only.

---

## Feature 6 — Security Regression Alerting

**Problem.** A quarterly assessment misses drift between runs. A lightweight scheduled check that detects Critical/High `Satisfied → Gap` transitions catches configuration drift before it becomes an incident.

**Architecture.**
- New entry point: `Invoke-NRGRegressionCheck.ps1` at repo root.
- Loads the most recent full-assessment JSON for the tenant from `./output/<tenant>/`.
- Re-runs only the Critical and High evaluators (no Medium, no Low) against the live tenant.
- Compares results: any control that was `Satisfied` in the baseline JSON and is now `Gap` or `Partial` is a regression.
- Outputs:
  - Stdout table.
  - JSON file `./output/<tenant>/regression-<timestamp>.json`.
  - Optional webhook POST to `-WebhookUrl` (Slack/Teams incoming webhook format).
  - Exit code 0 = no regressions, 1 = regressions present, 2 = baseline not found.
- Designed to run via Task Scheduler / cron / Azure Automation runbook.

**No new controls.** Reuses existing evaluators.

---

## Feature 7 — Client Self-Service Posture Portal (Phase 1: static HTML)

**Problem.** Clients ask for ad-hoc status updates between assessments. Generating a new report each time is high-touch and slow.

**Phase 1 scope (this release).**
- New flag on `Publish-NRGAssessmentHTML.ps1`: `-SelfServiceMode`.
- Strips MSP-only content: pricing, hourly rate, services pitch, internal notes.
- Adds: prominent "Last assessment: YYYY-MM-DD" banner, simple client-side search/filter on findings (vanilla JS, no framework, CSP-safe with nonce).
- Embeds the findings JSON as a `<script type="application/json">` block for the filter widget to read.
- Output: `<tenant>-self-service.html` — single self-contained file, openable in any browser, no server required.
- CSP enforcement remains intact (current report already enforces strict CSP; the filter widget uses `Trusted Types`).

**Phase 2 (deferred, separate decision).**
- Hosted multi-tenant portal with per-client login, scheduled refresh from MSP runs, posture dashboard. Likely new repo. Tracked separately.

**No new controls.** Publisher-only change.

---

## Feature 8 — Vendor & Supply Chain Risk Indicators

**Problem.** Supply chain compromise increasingly enters through MSP and vendor relationships. Government and regulated clients are starting to ask explicitly.

**Architecture.**
- New evaluator: `Evaluators/Test-NRGControlAADSupplyChainRisk.ps1`.
- No new collector — composes from existing raw data:
  - `AAD-Inventory` (service principals + delegated permissions)
  - `AAD-Users` (guests filtered by external domain)
  - `AAD-DirectoryRoles` (role assignments to guests)
- Optional new collector: `Collectors/AAD/Invoke-NRGCollectAADGDAPRelationships.ps1` to enumerate GDAP relationships for the tenant via Partner Center API — partner-side, opt-in via `-IncludeGDAPReview` flag.

**New controls.**

| ControlId | Title | Severity | Workload | Tier |
|-----------|-------|----------|----------|------|
| AAD-15.1 | Service principals with tenant-wide admin consent reviewed | High | AAD | basic |
| AAD-15.2 | Vendor-domain guest accounts with admin role | High | AAD | basic |
| AAD-15.3 | GDAP relationships reviewed within last 90 days | Medium | AAD | premium |

---

## Feature 9 — Security Culture Indicators

**Problem.** A composite signal that reflects whether the org is *engaging* with security as a practice — not just whether technical controls are configured. Justifies awareness-services upsell.

**Composite signals.**
- Voluntary MFA registration rate (registered ÷ enabled-licensed users) excluding CA-forced registrations.
- Presence of any Attack Simulation campaign in last 180 days.
- Evidence of admin role reviews (PIM access reviews completed, or role assignments changed in last 90 days).
- Audit log activity from non-Global-Admin security operators in last 30 days.

**Architecture.**
- New collector: `Collectors/AAD/Invoke-NRGCollectAttackSim.ps1` — pulls Defender Attack Simulator campaigns via Graph (`reports/security/getAttackSimulationSimulationUserCoverage` and related endpoints). Requires `AttackSimulation.Read.All` — **new scope addition** to `Connect-NRGServices.ps1` scope list.
- New evaluator: `Evaluators/Test-NRGControlAADCultureSignals.ps1` — emits one composite Culture Score finding (0–100).

**New controls.**

| ControlId | Title | Severity | Workload | Tier |
|-----------|-------|----------|----------|------|
| AAD-16.1 | Security culture composite signal | Informational | AAD | basic |

---

## Feature 10 — Licensing Waste / Right-Sizing Analysis

**Problem.** Clients paying for premium SKUs but not extracting value. Low-cost remediation opportunity for MSP; demonstrates ROI on existing client spend.

**Architecture.**
- New evaluator: `Evaluators/Test-NRGControlLicenseWaste.ps1`.
- No new collector — composes from existing raw data: `AAD-Inventory.SubscribedSkus` + per-workload deployment state already collected by Defender/Intune/Purview collectors.
- Match table (license → required deployed feature → evaluator data key):

| License SKU             | Required deployment                | Data check                                    |
|-------------------------|------------------------------------|-----------------------------------------------|
| Defender for O365 P1/P2 | Safe Attachments + Safe Links policy with users assigned | `Defender-Policies.SafeAttachments.Members > 0` |
| Intune (any)            | At least one compliance policy + enrolled devices | `Intune.CompliancePolicies.Count > 0`         |
| Purview / E5 Compliance | At least one DLP policy active     | `Purview.DLPPolicies | Where Enabled`         |
| Entra P1                | At least one CA policy enabled (non-baseline) | `AAD-CAPolicies | Where State -eq enabled`    |
| Entra P2                | PIM eligibility used, identity protection policy enabled | `AAD-PIMSchedules.Count > 0`                  |

- Each row produces one finding. Detail block surfaces annual licensed cost (from new `pricing.json` reference data) and a ROI estimate for activating the feature.

**New controls.**

| ControlId | Title | Severity | Workload | Tier |
|-----------|-------|----------|----------|------|
| LIC-1.1   | Defender for O365 licensed features deployed | Medium | Licensing | premium |
| LIC-1.2   | Intune licensed compliance deployed | Medium | Licensing | basic |
| LIC-1.3   | Purview/Compliance DLP deployed when licensed | Medium | Licensing | e5 |
| LIC-1.4   | Entra P1 CA policies activated | Medium | Licensing | premium |
| LIC-1.5   | Entra P2 PIM / Identity Protection activated | Medium | Licensing | premium |

- New workload code: `LIC`. Add to control prefix list in `Get-NRGControlDefinitions.ps1` and the HTML report workload scorecard grid.

---

## Implementation order (proposed)

Sequenced to minimize cross-feature merge conflicts. Each row is its own PR per repo, lockstep across the two repos.

| # | Feature | Why this order | Blocks |
|---|---------|----------------|--------|
| 1 | F5: Responsibility Map | Schema migration — touches every control. Land first to avoid rebasing later features. | All later features inherit the field. |
| 2 | F10: Licensing Waste | Self-contained, new workload code, no scope changes. | – |
| 3 | F4: Thread Hijack Composite | No new collector, no new scopes. | F2 references it. |
| 4 | F8: Supply Chain Risk | No new mandatory collector. | – |
| 5 | F1: Maturity Model | Reads all findings — needs F5 + F10 in place to be meaningful. | F6 trajectory hooks in. |
| 6 | F2: Incident Likelihood | Reads control multipliers — wants F4/F8 in place. | – |
| 7 | F9: Culture Signals | New scope `AttackSimulation.Read.All` — needs coordinated app reg update. | – |
| 8 | F3: Admin Behavioral Baseline | New collector with 30-day window. Largest data volume change. | – |
| 9 | F6: Regression Alerting | Needs all evaluators stable. | – |
| 10 | F7: Self-Service Portal | Publisher-only; benefits from F1, F2, F5 being in the report. | – |

---

## Cross-cutting changes

- **Module manifest.** Every feature adds exports to `NRG-Assessment.psd1` `FunctionsToExport` and `NRG-Assessment.psm1` `$script:ExportedFunctions`. The two lists must stay in sync.
- **Tests.** Each feature ships at least one Pester test in `Testing/`:
  - `NRG.Maturity.Tests.ps1`, `NRG.IncidentLikelihood.Tests.ps1`, `NRG.AdminBaseline.Tests.ps1`, `NRG.ThreadHijack.Tests.ps1`, `NRG.Responsibility.Tests.ps1`, `NRG.Regression.Tests.ps1`, `NRG.SelfService.Tests.ps1`, `NRG.SupplyChain.Tests.ps1`, `NRG.Culture.Tests.ps1`, `NRG.LicenseWaste.Tests.ps1`.
- **CHANGELOG.** v4.7.0 entry added when implementation begins, with one bullet per feature.
- **Graph scope additions** (only one): `AttackSimulation.Read.All` for F9. All other features reuse existing scopes.
- **Baseline JSON migrations.** F5 (Responsibility), F2 (IncidentRiskMultipliers) add new fields per control. Validation script `tools/Validate-Baselines.ps1` (new, small) ensures every control has the new fields populated before commits land.
- **Read-only invariant.** All new collectors verified GET-only. F6 Regression Alerting only reads. F7 Self-Service only generates static HTML. No new Apply-* scripts in this wave.

---

## Open questions

1. **DBIR / CoDB licensing.** Embedding base rates from those publications — is that distribution-safe under their terms, or do we cite + link instead? Decision needed before F2 lands.
2. **Maturity tier history.** Where does the "consecutive assessments" history live? Proposal: small `output/<tenant>/maturity-history.json` updated each run. Easy to forge, but signed-hash manifest already exists.
3. **GDAP enumeration (F8).** Partner Center API requires partner consent separate from tenant consent. Make it an opt-in flag (`-IncludeGDAPReview`) for the first cut.
4. **Culture Signals scope (F9).** `AttackSimulation.Read.All` requires re-consent in every client tenant. Acceptable, or do we degrade gracefully when scope not granted?

---

*Design owner: NRG Technology Services / NextLayerSec. Review before implementation begins.*

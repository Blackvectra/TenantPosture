# Polish Roadmap — v4.6.6 → v4.6.9

**Goal.** Twenty small tweaks across four patch releases that compound to make NRG-Assessment best-in-class. Each item is independently shippable; nothing in a later release depends on something in an earlier release.

**Sequencing principle.** Visible wins early (operator feels the difference on the next run), infrastructure middle (resilience + perceived speed), credibility late (output quality the auditor leans on). Each release groups items that share an editing surface so the diffs stay tight and reviewable.

**Out of scope of this doc.** Other v4.6.6 selections (signing scaffolding, adversarial fixture tests, supply-chain CI, batch auto-discovery cmdlet) live in their own track. This doc is the polish track only.

---

## v4.6.6 — Visible wins + assessor trust

Five items chosen so an operator who upgrades from v4.6.5 → v4.6.6 sees a difference in the first 30 seconds of the first run.

| # | Item | Effort | Rationale |
|---|---|---|---|
| 1 | **`-Open` flag** auto-opens the HTML report in the default browser when the run completes | 10 min | Eliminates the "now what" pause. `Start-Process $htmlPath`. Other tools don't do this. |
| 2 | **Final summary emoji line** — `🟢 73 satisfied · 🟡 32 partial · 🔴 45 gap · 1h 47m · output: ...` | 15 min | Operator eyeballs status in one line. Replaces the multi-line summary block as the final-final output. |
| 3 | **Output filename collision guard** — append a 3-char hash before `.json` so two runs in the same minute don't overwrite each other | 30 min | I've seen this cause real bugs. Trivial fix. |
| 4 | **Assessor self-check banner at startup** — runs 5 controls against the operator's own account (MFA enrolled, phishing-resistant method present, recent sign-in from unusual IP) and prints a 3-line banner | 1 day | No competitor self-validates. Powerful trust signal: "the tool that's auditing you, audits itself first." Failures are warnings, never blocking. |
| 5 | **`Test-NRGEnvironment`** cmdlet — pre-flight checker | ½ day | Verifies PS 7+, the 4 required modules at correct versions, network reachability to login.microsoftonline.com, write permission to `./output/`. Names specific fix command for each missing item. Beats Maester's silence-then-crash model. |

**Total effort:** ~2 days. **New CLI surface:** `-Open` flag on `Invoke-NRGAssessment.ps1`; new `Test-NRGEnvironment` cmdlet.

---

## v4.6.7 — Performance perception + resilience

Five items so long-running batch jobs feel responsive and recover gracefully when something goes wrong mid-run.

| # | Item | Effort | Rationale |
|---|---|---|---|
| 6 | **Live finding emission during evaluators** — stream each finding's `ControlId + State` as `Add-NRGFinding` is called | ½ day | Today: silent until "203 findings evaluated" prints at the end. New: operator sees each finding fly past as evaluators run. Perceived speed jump; nobody else does this. |
| 7 | **Run-state checkpointing** — write the collector-phase `RawData` to a temp JSON before any publisher runs | 1 day | Today: if `Publish-NRGComplianceMatrix` fails (Python missing, etc.), the 5-min collection cost is wasted. New: collection result persisted to `./output/.checkpoint-<baseName>.json`; if publishers fail, operator re-runs with `-FromCheckpoint` and skips collection entirely. |
| 8 | **`-Quiet` mode** — suppress every `Write-Host` that isn't an error. Return exit code only | 2 hours | Required for cron / CI scheduling. Most assessment tools have noisy console output that breaks pipelines. |
| 9 | **Run metadata in JSON output** — `PowerShellVersion`, `OS`, `OperatorIPEgress`, `ModuleVersions`, `ElapsedSeconds` in the `Metadata` block | 30 min | Helps reproduce bugs when client says "it worked on Bob's machine." Free debug evidence. |
| 10 | **CA-policy diagnostic at connect** — startup probe that names the blocking CA policy if scope is silently dropped | 1 day | Most-painful failure mode: `Connect-MgGraph` succeeds, `Get-MgUser` returns empty because operator's tenant has a CA policy that blocks the assessor scopes from their location. Today: silent. New: tool names the policy and tells the operator exactly what to fix. |

**Total effort:** ~3 days. **New surfaces:** `-Quiet` flag, `.checkpoint-*.json` file convention, `-FromCheckpoint` flag.

---

## v4.6.8 — Output credibility

Five items that make the client-facing report harder to challenge in an auditor meeting.

| # | Item | Effort | Rationale |
|---|---|---|---|
| 11 | **Reproducibility evidence per finding** — every finding gets a `ReproduceQuery` field with the exact Graph URI / EXO cmdlet that produced this result | 1 day per workload (drop-in helper at `Add-NRGFinding`) | Auditor catnip. Client pushes back on a finding; operator pastes the query, runs it themselves, sees the same result. Nobody does this. |
| 12 | **Confidence indicator per finding** — `Confidence: HighAPIConfirmed / MediumInferred / LowHeuristic` | ½ day | Today every gap reads equally certain; some are heuristics. Surfacing the difference protects the operator from over-claiming on heuristic findings. |
| 13 | **Severity rationale per control** — one-line "why this severity" derived from `BusinessRisk` field, surfaced inline next to the severity badge | ½ day | Auditors ask "why is this Critical not Medium?" — answer is in the report. |
| 14 | **Per-finding `RemediationTimeMinutes` field** — replaces flat 15–30 min default in playbook with an evidence-grounded estimate per control | ½ day | Today: playbook says "15–30 min" for everything from "publish a CAA record" (5 min) to "deploy LAPS to 500 endpoints" (1 day). New: per-control honest estimate. Better Phase 1 time math. |
| 15 | **Tenant timezone awareness** — show last sign-in / last-modified timestamps in the tenant's primary timezone, not the operator's | 2 hours | Catches DST + travel-timezone confusion. Operator running from East Coast assessing West Coast tenant doesn't get "logged in at 03:14" findings that are actually noon-local. |

**Total effort:** ~3 days. **Schema additions:** `ReproduceQuery`, `Confidence`, `RemediationTimeMinutes` per finding. Document in `Config/schema/controls.schema.json` and the controls.json migration.

---

## v4.6.9 — Power-user features

Five items for experienced operators who iterate, compare, and debug.

| # | Item | Effort | Rationale |
|---|---|---|---|
| 16 | **`-OnlyControls 'AAD-1.*','EXO-1.*'`** filter | ½ day | Operator iterating during remediation reruns only the controls they changed. 30s instead of 5min per cycle. Mostly a wildcard match on ControlId; skip evaluators whose IDs don't match. |
| 17 | **`-Compare <prior-json>`** | 2 hours | One-shot delta against a specific prior run JSON, prints inline. Today delta is automatic-against-most-recent only. |
| 18 | **Clipboard executive summary** — `-CopyExecSummary` puts the exec text in the clipboard | 5 min | Operator pastes into a ConnectWise ticket immediately. `Set-Clipboard $execText`. |
| 19 | **`-Verbose` Graph timing table** — when verbose is on, format the per-call timing data as a structured table at end of run | 2 hours | Helps operator profile slow tenants. Build on the existing run metadata; minimal new work. |
| 20 | **Resume on token expiry** — auto-reconnect when a 401 fires mid-run, retry the failed call | 1 day | Long runs (>60 min, common for >500-user tenants) hit token expiry mid-execution. Today: the run dies. New: detect 401, refresh, retry. Don't lose the run. |

**Total effort:** ~2 days. **New CLI surface:** `-OnlyControls`, `-Compare`, `-CopyExecSummary` flags.

---

## Total

~10 days of focused work spread across 4 patch releases (~2.5 days average per release). Every item adds something no competitor (Maester, ScubaGear, Microsoft365DSC, M365 Lighthouse) currently does. Every item is independently shippable — a release can drop any item without affecting the others.

## Implementation contract per release

Each v4.6.x release ships with:
1. The 5 items above
2. Updated `CHANGELOG.md` entry with one bullet per item
3. Updated `Testing/NRG.Polish.Tests.ps1` — at least one Pester test per item asserting the new behavior
4. Updated `CLAUDE.md` if the item changes a public CLI surface or schema field
5. Lockstep diff in the sibling repo (NRG ↔ NLS)

## Out of scope for this track

These items belong to other roadmaps and are intentionally NOT in v4.6.x:

- **Signing scaffolding (soft mode)** — own track, lands in v4.6.6 alongside polish
- **Adversarial fixture test suite** — own track, lands in v4.6.6 alongside polish
- **Supply-chain CI (Dependabot + Gitleaks + CodeQL)** — own track, lands in v4.6.6 alongside polish
- **Batch auto-discovery cmdlet (`Add-NRGClient`)** — own track, lands in v4.6.6 alongside polish
- **v4.7 features** (Maturity Model, Incident Likelihood, Privileged Baseline, Thread Hijack, Responsibility Map, Regression Alerting, Self-Service Portal, Supply Chain Risk, Culture Signals, License Waste) — separate ROADMAP
- **v4.8 features** (IG1/IG2 grouping, attestation, portfolio HTML, Maester eval) — separate ROADMAP

## Future track — HAWK-style incident response

The operator is interested in **HAWK** ([T0pCyber/hawk](https://github.com/T0pCyber/hawk)) — M365 incident response (BEC investigation, EXO transport log analysis, suspicious sign-in pattern detection). This is a **different problem class** from NRG-Assessment (posture vs forensics) and warrants its own repo, not an integration into this one.

Proposed: **`NRG-IncidentResponse`** (separate repo). Same Collectors / Evaluators / Publishers pipeline, different evaluator focus:
- **Collectors:** EXO transport logs, Unified Audit Log, MailItemsAccessed events, sign-in logs filtered by suspicious-activity heuristics
- **Evaluators:** BEC indicators (mailbox rule + external forwarding + DKIM bypass), credential theft chains (impossible travel + new device + privilege escalation), data exfiltration patterns (mass download + external sharing + sync)
- **Publishers:** Forensic timeline HTML, IOC export (STIX 2.1), Sentinel incident JSON

Either fork HAWK's logic into the new repo (faster but requires license review) or rebuild on top of NRG-Assessment's existing architecture (slower but cleaner integration). **Recommend rebuild** — HAWK's PowerShell is functional but pre-dates `Set-StrictMode -Version Latest` and modern Graph SDK patterns.

Scoped as a v5.x project track, not v4.6.x.

---

*Track owner: NextLayerSec. Sequenced after v4.6.5 close.*

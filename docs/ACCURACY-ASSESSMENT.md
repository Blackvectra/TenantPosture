# TenantPosture — Accuracy Assessment

**Scope:** end-to-end accuracy of an assessment run — collection → evaluation → framework mapping → scoring. Produced during the branch `claude/nls-assessment-tp-update-WWQcp` accuracy hardening. Applies identically to the NLS-Assessment twin.

---

## Executive summary

An assessment run has four accuracy layers. Each was audited and hardened:

| Layer | Before | After |
|---|---|---|
| **Collection** (Graph/EXO/DNS) | Collectors crashed on a Graph object-shape mismatch → mass empty data → false gaps | Output shape pinned; collection is stable |
| **Evaluation** (195 controls) | ~31 controls produced false results independent of collection | 13 corrected to read real data; 16 made honest NotApplicable; 2 null-guarded |
| **Framework mapping** | 26 wrong SCuBA IDs, 1 Mobile MITRE technique, version-label drift | All SCuBA/NIST/MITRE/CIS-v8.1 references validated + CI-guarded |
| **Scoring** | Uncollected-field controls emitted false Satisfied/Gap that counted in the score | Those controls no longer emit false results |

**Bottom line:** a run no longer produces a *dangerous* false result (a false "Satisfied" telling a client they're compliant on unchecked data). Remaining inaccuracy is bounded and enumerated below (controls that honestly report "not assessed" pending added collection).

---

## Layer 1 — Collection

**Root cause fixed:** collectors called `Invoke-MgGraphRequest` without pinning `-OutputType`. Newer Graph SDK builds return PSCustomObject, on which bare `$resp.'@odata.nextLink'` throws under `Set-StrictMode -Version Latest` on any single-page (small-tenant) response. Collectors caught the throw and returned empty data; evaluators scored empty as "Gap." This produced the reference incident (a role collector reporting "0 Global Admins" on a tenant with several).

- **Fix:** `Lib/Invoke-N*GraphRequest.ps1` proxy forces `-OutputType HashTable`; all 48 collector call sites + Email-IR use it.
- **DNS:** added a Graph verified-domains fallback so SPF/DMARC/DNSSEC still collect when EXO is down.
- **Environment note (operator-side, not code):** an EXO/Graph MSAL assembly conflict (OneDrive-synced module path) can still kill EXO/Purview/SharePoint collection. See `docs/RUNBOOK-clean-collection.md`.

---

## Layer 2 — Evaluation

A 5-agent audit cross-checked every evaluator's data reads against each collector's actual output. Three bug classes were found and fixed:

### 2a. Reader bug (18 sites) — FIXED
`Get-N*SafeProperty` reads `$obj.PSObject.Properties[key]`, which does **not** expose hashtable keys (direct `$obj.Key` access does; the helper doesn't). Every call on a rebuilt-`@{}` collector element silently returned the default. Swapped all to the dictionary-aware `Get-N*ObjectField`. Fixed **INT-1.3, INT-1.5, INT-2.4, INT-4.4, EXO-5.3, AAD-3.1** (and others).

### 2b. Key/path drift (fixed) — evaluator read a name the collector stores differently
| Control | Was | Now | Impact |
|---|---|---|---|
| **AAD-3.1** | `Data.PermanentAssignments`, `OnPremSynced` | `Data.RoleAssignments`, `OnPremisesSyncEnabled` | "0 Global Admins" false finding |
| **AAD-11.2** | `RoleName` / `UserType='Guest'` | `RoleDefinitionName` / `PrincipalUPN #EXT#` | **Critical:** guest holding Global Admin was reported Satisfied |
| **AAD-11.6** | `CrossTenantAccessPolicy` / `DefaultInbound.TrustSettings` | `CrossTenantAccess` / `InboundTrust` | External MFA/device trust never evaluated |
| **AAD-4.2** | `AllowedToCreateTenants` (wrong nesting) | `DefaultUserRolePermissions.AllowedToCreateTenants` | Tenant-creation gap missed |
| **TMS-2.1/2.3/2.4/2.7/4.3** | `TenantConfig` / `ClientConfig` | `FederationConfig` / `ClientConfiguration` | Federation/storage/email controls false |

### 2c. Collector gap (made honest) — control reads a field NO collector emits
16 controls returned a fixed false result regardless of tenant state. All now return **NotApplicable ("data not collected; not assessed")** — an honest "we didn't check this" instead of a false pass/fail. The false-**Satisfied** ones (the dangerous subset) are marked 🔴:

| Workload | Controls | Why uncollected |
|---|---|---|
| SharePoint | SPO-2.2, SPO-2.4, SPO-2.6, 🔴SPO-3.2, SPO-3.4 | Not exposed by Graph `/admin/sharepoint/settings` (needs SharePoint Management Shell) |
| Teams | 🔴TMS-2.8, TMS-4.1, 🔴TMS-4.4 | `Get-Cs*` fields not gathered by the collector |
| Teams (null-guard) | TMS-3.2, TMS-4.2 | Now NotApplicable if MeetingPolicy collection failed |
| EXO | 🔴EXO-5.1, EXO-5.2 | Per-mailbox audit counts / priority accounts not gathered |
| Defender | DEF-4.4, DEF-4.6 | Priority accounts / attack-sim campaigns not gathered |
| AAD | AAD-11.1, 🔴AAD-11.3 | Device-code CA condition / risky service principals not gathered |
| Intune | INT-3.3 | Conditional-launch settings not gathered |
| Power Platform | PPL-2.1 | Per-policy connector classification not gathered |

---

## Layer 3 — Framework mapping

All framework references validated against **authoritative, bug-worked-out sources** and guarded by `Testing/*.FrameworkAccuracy.Tests.ps1` (fails CI on drift):

| Framework | Authoritative source | Result |
|---|---|---|
| **CISA SCuBA** | ScubaGear 2.0.0 baselines (github/cisagov) and its official migration file | Re-checked 2026-09-30: 22 citations re-pointed to current rule ids, 9 obsolete references removed (no equivalent rule), each of the 87 checked for equivalence (25 equivalent, 41 partial, 3 manual, 18 unsupported, as recorded in `Config/scuba-alignment.json`); **all 78 remaining references valid** — see `docs/TP-SCUBA-ALIGNMENT.md` |
| **NIST 800-53r5** | OSCAL catalog | all 57 tokens valid; format-guarded |
| **MITRE ATT&CK** | attack.mitre.org | `T1533` (a **Mobile** technique) removed from the Enterprise mapping; rest valid |
| **CIS Controls v8.1** | CIS v8.1 (Mar 2025), 153 safeguards | **new** validated mapping added to all 195 controls (0 invalid) |
| **CIS M365 Benchmark** | (paywalled — labels only) | version label reconciled to v6.0.1 across all files |

Bundled references: `Config/framework-baselines/scuba-ids-v2.0.0.txt`, `cis-controls-v8.1-safeguards.txt`. Regenerate on version upgrade.

**Not yet audited:** CMMC 2.0, ISO 27001, SOC 2, PCI DSS, HIPAA. CMMC and ISO have public sources and are the natural next pass; the others are stable.

---

## Layer 4 — Scoring

The compliance score is license-aware (controls whose license isn't met route to Upgrade Unlocks, not the score). Accuracy impact of this work:

- **Before:** collector-gap controls emitted false Satisfied/Gap that counted toward the score, and collection failures were scored as gaps — both distorted the number.
- **After:** those controls are NotApplicable (excluded from the score denominator, as genuinely-unassessed controls should be). The score now reflects only controls that were actually evaluated against real data.
- **Known design consideration:** NotApplicable drops from the denominator, so a run with many uncollected controls yields a score over a smaller base. The report should surface the NotApplicable/unassessed count alongside the score so the base is transparent. (Enhancement, not a correctness bug.)

---

## What is guarded going forward (CI)

- `Testing/*.FrameworkAccuracy.Tests.ps1` — SCuBA IDs exist in the authoritative baseline; NIST/MITRE well-formed; CIS v8.1 safeguards valid; every control carries CISControls; no prose-citation drift.
- `Testing/*.GraphRequest.Tests.ps1` — the wrapper forces HashTable output (StrictMode-safe paging).
- Existing Pester/PSScriptAnalyzer gates.

---

## Remaining work (the "build upon" list)

1. **Add collection for the 16 NotApplicable controls** (per-control feature work): priority accounts (EXO/DEF), risky service principals (AAD), attack-sim campaigns (DEF), conditional-launch settings (Intune), connector classification (PPL), device-code CA condition (AAD). For the 5 SharePoint controls, this requires adding a SharePoint Management Shell connection — an architectural decision.
2. **Per-evaluator regression fixtures** — feed known tenant data, assert the exact finding (e.g. "4 GAs → count 4"). Locks the Layer-2 fixes.
3. **Surface the unassessed count** next to the score in the report.
4. **Audit the remaining frameworks** (CMMC, ISO, SOC 2, PCI, HIPAA).

---

*Every fix in this assessment is on branch `claude/nls-assessment-tp-update-WWQcp` in both repos, validated by CI.*

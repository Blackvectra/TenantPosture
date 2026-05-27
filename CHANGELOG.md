# Changelog

## v4.6.6 (2026-05-27) — fresh-install hotfix

Two latent bugs surfaced when an operator unboxed v4.6.5 from a fresh GitHub zip on a Windows workstation without MicrosoftTeams installed:

### Fixed

- **`New-Item -LiteralPath ... -ItemType Directory` doesn't work** — `-LiteralPath` is not in `New-Item`'s parameter set, even on PowerShell 7. The line had worked on previous runs only because the `output/` directory already existed (the `Test-Path` guard skipped `New-Item`). On a fresh install, `New-Item` ran and failed with "A parameter cannot be found that matches parameter name 'LiteralPath'". Five sites affected:
  - `Invoke-NRGAssessment.ps1:139`
  - `Invoke-NRGBatchAssessment.ps1:307`
  - `Apply-NRGBaseline.ps1:441`
  - `Build/New-NRGCodeSigningCert.ps1:138` (introduced in v4.6.5)
  - `tools/Generate-SBOM.ps1:40`
  
  All switched to `[void][System.IO.Directory]::CreateDirectory($path)` — cross-version, parameter-set-free, not flagged by the Pester `-LiteralPath` regex.

- **`MicrosoftTeams` demoted from `RequiredModules` to soft dependency.** Listing it as a hard requirement blocked the entire module from loading on operator workstations without Teams installed — the wrong failure mode for an optional collector. `Connect-NRGServices` already handles Teams gracefully (imports on-demand, skips with clear error if not installed). Operators can now run assessments without Teams installed; the Teams collector simply gets skipped.

### Notes

The v4.6.5 release shipped with `ModuleVersion = '4.6.4'` in the manifest due to a post-merge Copilot Autofix that reverted the version bump. v4.6.6 corrects the version to 4.6.6 and ships the fresh-install hotfix. If you installed v4.6.5 and got "v4.6.4" in the banner with a `New-Item -LiteralPath` crash on first run, this release fixes both.

## v4.6.5 (2026-05-27)

Patch release closing the correctness sweep defined in `docs/CORRECTNESS-SWEEP-v4.6.5.md`. No new features. Every defect surfaced by three real-tenant runs and a follow-on code-review audit is either Resolved here or explicitly tracked Open.

### Fixed

- **Per-tenant remediation script dispatch (Critical).** Generated `<tenant>-remediation.ps1` files called `Apply-NRG* -ErrorAction Stop` with no `-Finding` argument. Every `Apply-NRG*` function declares `[Parameter(Mandatory)] [object] $Finding`, so every dispatched call would have failed at runtime. The generated script now loads its sibling `<baseName>-results.json`, builds `$findingsByCtrl`, and passes `-Finding $fnd` per dispatch. The JSON-load runs BEFORE `Connect-NRGServices` so a missing or corrupt JSON fails fast without paying the Graph/EXO authentication cost. `ConvertFrom-Json` is wrapped in try/catch with a diagnostic message. `$assessment.Findings` is null-checked explicitly so an unexpected JSON shape produces an actionable error rather than silent zero-iteration.
- **14 StrictMode property-access NREs** across AAD, Defender, EXO, Intune evaluators (PR #27, #29). Each was silently dropping one or more findings from real-tenant reports.
- **`Get-Mailbox -ResultSize 1000` undercount.** Five EXO collector calls capped at 1000 mailboxes; on >1000-mailbox tenants this silently undercounted unaudited / forwarding / shared / SMTP-AUTH populations. Switched to `-ResultSize Unlimited` for population-counting calls.
- **HTML playbook alias collision.** The `function H` introduced in v4.6.4-readability collided with the built-in `h` alias (= `Get-History -Id [long]`); PowerShell's parameter binder routed the title string into `-Id` and crashed the entire HTML playbook artifact. Renamed to `EscHtml`.
- **XLSX compliance matrix `'PCIDSS'` NRE.** Direct dereference of `$ctrl.References.PCIDSS` raised under StrictMode when a control's References hashtable lacked that key. All 10 framework-reference accesses now use `Get-NRGNestedProperty`. Also fixed the misspelled `PCIDASSS` column header.
- **HTML entity leakage in markdown publishers.** `ConvertTo-NRGHtmlSafe` was being applied to markdown source, producing `&gt;` `&#39;` `&#167;` in `<tenant>-playbook.md`, `<tenant>-executive.md`, and `<tenant>-assessment.md`. Markdown `EscMd` now escapes only characters that break markdown table/code-span structure.
- **Findings-table sort under malformed enum values.** `$stateOrder[[string]$_.State]` returned `$null` on unknown values, mixing `$null` with ints in `Sort-Object` comparison. Defensive `?? 99` coerces unknown values to a sortable tail.

### Security / privacy

- **NRG `output/` untracked from HEAD.** 38 files (real client assessment HTML/JSON for ndaco.org and nextlayersec.io) had been tracked because `.gitignore` only excluded `Reports/`. Added `output/` to gitignore and `git rm -r --cached output/`. Files remain in git history; full history rewrite was considered and not chosen — see PR #29.
- **Branding/PII leaks** in initial NLS port surfaced and fixed before any external view (NRG real phone in branding.psd1 / psm1 fallback, "North Dakota" geographic identifier in CLAUDE.md, real client names NDACo / Dunn County in sample configs).

### Release engineering

- **In-house signing scaffolding (soft mode, $0 cost).** New `Build/New-NRGCodeSigningCert.ps1` generates a self-signed Authenticode cert on the operator workstation, installs it into `TrustedPublisher` + `Root`, and stashes the thumbprint at `~/.nrg-assessment/signing-thumbprint.txt` so subsequent signing runs find it automatically. `Build/Sign-Release.ps1` now accepts no args (uses the saved thumbprint) and treats self-signed certs as first-class — no more "self-signed certs are NOT recommended" friction for the in-house workflow. Upgrade path to a paid cert (Microsoft Trusted Signing / Sectigo / DigiCert) is one parameter — no code change.
- **`Apply-NRGBaseline.ps1 -RequireSignedCode`** (new switch, default `$false`). When omitted, emits a `Write-Warning` per unsigned `Apply-NRG*.ps1` file and continues — operators who haven't generated a cert yet aren't blocked. When set, refuses to dispatch if any Apply script has signature status != `Valid` (NotSigned / HashMismatch / UntrustedRoot / Expired all block). Future v5.0 may flip the default; this PR sets the stage.
- **`Lib/Test-NRGSignatureStatus.ps1`** (new exported function). Wraps `Get-AuthenticodeSignature` with three improvements: distinguishes NotSigned / HashMismatch / UntrustedRoot / Expired cases that the raw cmdlet aliases under "Invalid"; resolves self-signed cert chains correctly when the cert is in `TrustedPublisher`; returns a single object with `Status`, `Signer`, `Thumbprint`, `IsSelfSigned`, `NotAfter`, `StatusMessage` so callers don't re-query.
- **`RELEASE-CHECKLIST.md`** (new). Codifies the per-release contract: pre-release OWASP delta walk, `simplify` code-review pass, adversarial-fixture tests, all CI green, one real-tenant run; release-time signing + integrity-manifest generation steps; post-release SBOM + smoke test on the tag. Every v4.6.x release ships against this checklist.

### Documentation

- New `docs/CORRECTNESS-SWEEP-v4.6.5.md` — prioritization rule, 23 Resolved entries with root cause and PR refs, 7 Open entries for follow-up, 3 misclassification entries deferred to v4.7, Definition of Done (8 conditions), cross-cutting recommendations on CLAUDE.md drift and v5.0 persistence schema.
- `CLAUDE.md` rewritten to describe the actual `LicenseRequirement`-per-control architecture (it previously described per-tier `nrg-baseline-*.json` files that never existed).
- New `docs/ROADMAP-v4.7.md` and `docs/ROADMAP-v4.8.md` — design only, no code.

### Readability

- `<tenant>-playbook.md` slimmed: stripped per-item framework citations (now in `<tenant>-assessment.md`) and per-item estimated time (already in the phase summary table). Added TOC and a Phase 1 quick-action checklist.
- New `<tenant>-playbook.html` artifact (strict CSP, Trusted Types, print stylesheet for clean PDF).
- `<tenant>-executive.md` got a Bottom-line one-liner under the score and Current state lines under top-5 priorities.
- `<tenant>-assessment.md` findings table sorted Gap → Partial → Satisfied first; NotApplicable rows folded into a `<details>` appendix.
- `<tenant>-remediation.ps1` is now actually runnable — dispatches to the existing `Apply-NRG*.ps1` scripts via the canonical dispatch table.

## v4.5.5 (2025-05-18)

Major architectural change: rebuilt on the v4.5.0 baseline pattern to eliminate runtime crashes caused by aggressive `Set-StrictMode -Version Latest` propagation into evaluator scope.

### Fixed
- **StrictMode property access crashes** — removed `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'` from script scope in all evaluators and collectors. Was causing runtime failures on `$obj.MissingProperty` access patterns common in `ConvertFrom-Json` data from Microsoft Graph.
- **Injection scanner false positives** — removed overly aggressive regex (`on\w+\s*=`) from the controls.json validator. Was flagging legitimate strings like `Condition =`, `applications =`, `ActionWhenThresholdReached =`.
- **`?.` null-conditional operator crashes** — all null-conditional access replaced with explicit `if ($obj) { $obj.Prop } else { $null }` patterns. Was hitting tokenizer issues under StrictMode in PS 7.6.1.
- **EOM v3.4 WAM broker crash** — `$env:MSAL_ALLOW_BROKER = '0'`, `$env:MSAL_DISABLE_TOKENBROKER = '1'`, `$env:MSAL_DISABLE_WAM = '1'` set before module import. Recommend EOM 3.2.0 for best results.
- **AI- and INV- ControlId prefixes** — renamed to PPL-3.x (AI), AAD-12.x/AAD-13.1 (INV identity), EXO-6.x (INV email) to match standard workload prefixes.
- **`New-Item -LiteralPath -ItemType Directory`** — replaced with `-Path` (more universally supported).
- **`"```"` parse errors** — backtick before closing quote in double-quoted strings was breaking PS string termination. Switched to single-quoted strings for Markdown code fences.

### Added
- **188 controls** across 9 workloads (AAD=46, DEF=23, DNS=6, EXO=28, INT=17, PPL=11, PVW=18, SPO=17, TMS=22).
- **Premium HTML report** — animated score ring, workload scorecard grid, framework matrix, license gap analysis, priority actions, Named Findings section, 90-Day Roadmap, Best Practices section, Secure Score widget.
- **Named findings** — per-user/per-mailbox lists for MFA gaps, stale guests, stale accounts, OAuth grants, external forwarding, shared mailbox sign-in, mailbox audit, SMTP AUTH overrides.
- **XLSX compliance matrix** — 11 sheets, 7 framework-specific exports (CIS, SCuBA, NIST 800-53, CMMC, ISO 27001, SOC 2, HIPAA), license gaps.
- **Delta report** — comparison vs prior assessment run with new/resolved/regressed/unchanged categorization.
- **10 frameworks** — CIS M365 v6.0.1, CISA SCuBA, NIST 800-53r5, CMMC 2.0 L2, ISO 27001:2022, SOC 2 TSC, HIPAA §164, PCI DSS v4.0.1, DISA STIG, MITRE ATT&CK.
- **5 AI/Copilot controls** (PPL-3.1 through PPL-3.5).
- **App-only certificate authentication** for unattended runs.
- **GCC environment support** (`-Environment commercial|gcc|gcchigh|dod`).
- **NonInteractive mode** for CI/CD.
- **FromResults regeneration** — rebuild reports from prior JSON without re-collecting.
- **BaselineResults delta comparison**.
- **Module prerequisite check with auto-install prompt**.
- **GDAP batch runner** (Invoke-NRGBatchAssessment.ps1) for MSP multi-tenant runs.

### Changed
- **`-SkipPurview` defaults to `$true`** — EOM v3.4 IPPSSession WAM crash. Use `-IncludePurview` to opt in.
- **Evaluator discovery dynamic** — orchestrator enumerates `Test-NRGControl*` from loaded module rather than hardcoded list.
- **Disconnect at end of run** — no try/finally chain that fires on every error.

## v4.5.0 (Baseline)

Initial clean architectural rebuild. 75 controls across Collectors → Evaluators → Publishers pipeline.

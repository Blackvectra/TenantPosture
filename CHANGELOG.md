# Changelog

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

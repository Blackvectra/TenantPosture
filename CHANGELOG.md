# Changelog

## v4.5.5 (2026-05-18)

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
- **`-SkipPurview` defaults to `$true`** — EOM v3.4 IPPSSession WAM crash. Use `-IncludePurview` to opt in. (Implemented via script body logic — `[switch]` params do not default to `$true` per PSScriptAnalyzer.)
- **Evaluator discovery dynamic** — orchestrator enumerates `Test-NRGControl*` from loaded module rather than hardcoded list.
- **Disconnect at end of run** — no try/finally chain that fires on every error.

### Fixed (this session)
- **`else`/`elseif` on new line after `}`** — PS parses `}` as end of statement; `else` on next line becomes `CommandNotFoundException`. Affected `Publish-NRGAssessmentHTML.ps1`, `Invoke-NRGCollectDNSEmailRecords.ps1`, `Test-NRGControl-DNS.ps1`, `Publish-NRGDeltaReport.ps1`.
- **`hx (if ...)` in command mode** — function call followed by `(if` causes PS to treat `if` as a command name. Fixed to `hx $(if ...)` subexpression syntax.
- **INT-1.3/INT-1.4/INT-1.5 evaluator logic swapped** — INT-1.3 (BitLocker) was evaluating MAM policies; INT-1.4 (MAM) was evaluating device compliance %; INT-1.5 (Antivirus) was evaluating enrollment restrictions. Each now evaluates its correct control.
- **TMS-1.2/TMS-1.3 evaluator logic swapped** — anonymous meeting join logic was in TMS-1.2; consumer Teams access logic was in TMS-1.3. ControlIds corrected to match controls.json.
- **`EXO-SmtpAuth` filter error** — `Get-CASMailbox -Filter {SmtpClientAuthenticationDisabled -eq $false}` fails (property not filterable). Replaced with `| Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false }` in both EXO collectors.
- **`[switch] $SkipPurview = $true`** — PSScriptAnalyzer `PSAvoidDefaultValueSwitchParameter`. Default moved to script body.
- **`PSScriptRoot` assignment in test** — `$PSScriptRoot` is an automatic variable and cannot be overridden from a calling scope. Test replaced with direct severity validator check.
- **`controls.json` Context block outside `Describe`** — missing `}` for `Module Loader Hardening` Context caused Describe to close prematurely; `controls.json` Context was orphaned at top level. Fixed brace structure.
- **Unused variables across 8 files** — removed `$cloudStorage`, `$privRoles`, `$citations`, `$orgConfig`, `$userRaw`, `$sl`/`$sa`/`$ca`, `$flowEnabled`, `$totalSIT`, `$customScript`, `$thirdParty`/`$thirdPartyStorage`, `$vhEnabled`, `$showAO`, `$ctrl4`, `$ssData`/`$ssFindingDetail`.
- **`$null` comparison direction** — `$_.MaxDurationHours -eq $null` → `$null -eq $_.MaxDurationHours` (PSScriptAnalyzer `PSPossibleIncorrectComparisonWithNull`).
- **`CmdletBinding` before `Set-StrictMode`** — fixed in `Generate-SBOM.ps1`, `Verify-Integrity.ps1`, `Sign-Release.ps1`.
- **`AAD-1.4` false positive framing** — Sign-in Risk CA Policy detail now explicitly states this requires Entra P2, not included in Business Premium.

## v4.5.0 (Baseline)

Initial clean architectural rebuild. 75 controls across Collectors → Evaluators → Publishers pipeline.

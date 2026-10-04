# Known issues

Things that are known, not hidden, and not blocking. Each says what happens, why, and what to do
meanwhile. A fix is its own change, not part of the pull request that recorded it.

## Web GUI (`-Web`)

The server shell, the run list, the report viewer and the tenant box were exercised on a real
workstation (see CHANGELOG).

- **A scan started from the page cannot sign in to Microsoft Graph on Windows.** The page runs the
  assessment in a hidden child process. Graph's sign-in uses the Windows broker (WAM), which needs a
  window to attach to, so it fails with "A window handle must be configured"; Exchange, Purview and
  Teams (which pass `-DisableWAM`) sign in, so the scan continues without Entra ID data and says
  Graph is not connected. An attempted fix (`Set-MgGraphOption -DisableLoginByWAM`) was removed: the
  Graph PowerShell SDK honors that option only for a custom client id (the tool uses the default
  one), and the cmdlet writes a settings file to the operator's profile on every call. **Workaround:
  run the assessment from a PowerShell window (`Invoke-NRGAssessment.ps1`), which is the supported
  path.** A proper fix needs evidence of how the installed SDK behaves first (for example a visible
  console for the child, or a custom client id) and is a separate change.

- **Runs from the command line are not listed.** The GUI lists runs saved under
  `output\<domain>\`, which is where a scan started from the GUI writes. A command-line run writes
  flat files into `output\`, so it does not appear in the GUI's run list. Open the report from the
  output folder instead.
- **The report site is not linked.** The GUI opens the single-page `*-assessment.html` report only.
  The multi-page report site (`<base>-report\`) is in the output folder; the GUI does not link to it.
- **Calling `Start-NRGWebServer` directly needs `-ScriptDir`.** Its default points at `Lib`, where
  the `Web` folder does not exist. `Invoke-NRGAssessment.ps1 -Web` passes the right folder, so normal
  use is not affected.
- **Pode is a separate install.** `Install-Module Pode` fails on a machine whose PowerShellGet or
  NuGet layer is broken; `Install-PSResource` or `Save-PSResource` works without NuGet.
- **The tests that start a real server run only where Pode is installed.** CI skips them. Run
  `Testing/NRG.WebServer.Tests.ps1` locally with Pode installed.

## Not yet run against a live tenant

Covered by tests against stubbed or mock data only: the batch runners, the triage deep-dive of other
users' mailboxes, the email assessment on an account that has a mailbox, endpoint compliance
collection (`Device/` and `-DeviceResults`), delta and monthly reports from two real runs, the SSP
answers file and questionnaire import, `Apply-NRGBaseline.ps1`, the tenant app registration and
consent scripts, and the Settings Catalog parsers. Issue #98 (the authentication strength read that
returned a 400 on 2026-09-24) still needs a live confirmation that it no longer recurs.

## Collection limits seen on a real tenant

- **PVW-2.6 (auto-labeling):** `Get-AutoSensitivityLabelPolicy` is absent in the Security &
  Compliance session when the signed-in account lacks the Purview role or license that grants it. The
  control reads "not assessed" and the Exceptions list names the likely cause.
- **Mailbox reads on an account with no mailbox:** the incident-response email assessment reports
  NOT CLEARED and says the account may have no Exchange Online mailbox. Run it on an account that has
  one.

## Found in the review of PR #106 and not fixed there (follow-ups)

Confirmed by the 2026-10-04 review; none of them produces a clean conclusion from a failed read.

- **Three classifiers decide "not scored".** `Get-NRGAssessmentScope`, the report site and
  `Get-NRGControlStatus` each classify unscored controls; the report site now takes the scope's
  bucket, but the control-status helper still has its own chain.
- **Incident-response "empty is clean" checks are written per evaluator.** The false-clean paths
  found are fixed and pinned; one shared helper would close the class.
- **Conditional Access coverage is judged two ways.** AAD-1.1/1.2/11.1 judge combined coverage;
  AAD-2.1 judges per policy through the Conditional Access view. They can disagree (for example
  two MFA policies with complementary exclusions; a policy for one specific platform).
- **ScubaGear "Warning" is not counted as a difference.** A failed SHOULD rule is reported as
  Warning, and the report site counts only Pass and Fail as a direction difference.
- **A mistyped `-ScubaResultsPath` is ignored silently** when the file does not exist.
- **AAD-6.2's baseline reason** quotes the related AAD-6.3 sentence instead of its own shortfall.
- **The console's Gap line** is built separately from `Format-NRGGapSummary` and words it
  differently.
- **Sign-in triage scoring:** SIGNIN-1.6 reasons include the city, so two cities in the same
  neighboring state score twice; ARIN answers carry no top-level country, so the IP country stays
  empty for North American addresses; EMAIL-4.1's Critical rule rests on `publisherName` (the
  publishing tenant's name), not Microsoft's publisher verification.
- **Two lists of DLP policy modes** (`Get-NRGDlpRuleStates` and DEF-4.1) must change together if
  Microsoft adds a mode.
- **`-FromResults` on a results file without a `Connections` key** throws (files the tool writes
  always carry it).
- **Structure:** `Invoke-NRGAssessment.ps1` is about 1,730 lines; the report-site builder is one
  long function; one Intune read hand-rolls paging instead of `Get-NRGGraphAllPages`;
  `Config/branding.psd1` is read twice in a row. PSScriptAnalyzer reports
  `PSUseDeclaredVarsMoreThanAssignments` for `$monitoringSet` in `Invoke-NRGAssessment.ps1`
  (present before the review; CI does not fail on it).

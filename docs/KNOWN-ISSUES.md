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

## Not yet confirmed on a live run

These fixes passed their tests but have not been seen working against a real tenant or workstation.

- **Sign-in triage.** The recent sign-ins read now retries without its property list if Graph rejects
  it (BadRequest). Confirm the section completes and SIGNIN-1.4 names only active risky users.
- **Email assessment findings.** EMAIL-3.1 (display-name-only leads rank below strong leads) and
  EMAIL-4.1 (an app that was never looked up is "not identified", High until identified) changed
  after the first live run on a real mailbox. Re-run on the same mailbox to confirm.
- **Pode 2.10.0.** It is the minimum supported version. It warns that it has not been tested on
  PowerShell 7.6.6; the server started and listened. Try a newer Pode first if the GUI misbehaves.

## Known, not yet examined

- **EMAIL-2.1 recipients to warn.** The outbound summary reported 7 recipients to warn on 13 sent
  messages (3 external and 4 internal recipients were counted). The count and the wording have not
  been checked against the messages.
- **An EDR alert during a run.** Cortex XDR alerted on the operator's endpoint while the tool ran
  (script detections and a Tor-browser download block). Nothing shows the tool caused any of them;
  the process behind the download event has not been identified. The Tor Project host name was
  removed from every shipped file as a precaution, and a test fails if a live reference returns.
- **INT-1.1 non-compliance actions** are not read, by design; see `NRG-DETECTION-LIMITS.md`.
- **Markdown escaping in the other report publishers.** The NIST matrix, SSP, improvement plan,
  device guide and device baseline publishers escape only pipes and line breaks in Markdown, so
  markup inside tenant-derived text (a policy or app display name) reaches the `.md` file as raw
  HTML, which some Markdown viewers render. Their HTML reports are encoded. The HIPAA readiness
  publisher encodes `&`, `<` and `>` as well (found by review of PR #121); the others follow in a
  separate PR.

## Environment problems on an operator's workstation

Not defects in this tool, but they stop it or its companions from running.

- **PowerShell 7 package layer.** `Install-Module` and `Install-PackageProvider` can fail with
  "Collection was modified" or "NuGet provider is required". Use `Install-PSResource` or
  `Save-PSResource`, which do not need NuGet.
- **ScubaGear rule step on Windows.** ScubaGear 2.0.0 passed its rule files to OPA without a drive
  letter when run from a non-system drive, so every product failed to evaluate. Running it from
  `C:` in Windows PowerShell 5.1 worked. ScubaGear's own sign-in also failed in PowerShell 7 (an
  embedded-browser error from the borrowed MSAL) and worked in 5.1.
- **OneDrive-redirected module folders.** A module file can become an online-only placeholder and
  fail to load. Keep modules out of OneDrive (see `Install-NRGPrerequisites.ps1`).
- **Run in a new window.** A PowerShell window that already loaded another version of the Microsoft
  sign-in library (MSAL) cannot load a different one; open a new window.

## Installer (`Install-NRGPrerequisites.ps1`)

Found on a real workstation on 2026-10-04; each fix is its own change.

- **It accepts Microsoft.Graph.Authentication 2.0 or later.** The module manifest requires 2.20.0
  to 2.99.99, so a machine holding only an older 2.x (2.9.1 was seen) passes the installer and the
  module then fails to load. Install the supported range with
  `Install-PSResource Microsoft.Graph.Authentication -Version '[2.20.0, 3.0.0)'` and remove the
  older version.
- **The Microsoft Store `python` alias counts as Python.** On Windows, `python.exe` under
  `WindowsApps` is a stub that opens the Store; the installer reports "Python found" and the
  openpyxl step fails. Install Python from python.org or `winget install Python.Python.3.12`.
- **The duplicate MSAL check needs a module function it has not loaded.** The installer
  dot-sources `Lib/Repair-NRGModuleHealth.ps1`, which calls `Get-NRGObjectField` from the module,
  so the check cannot complete before the module is imported. Run `Repair-NRGModuleHealth
  -PlanOnly` after `Import-Module`.
- **The Microsoft Store build of PowerShell.** The Exchange Online module failed to import from it;
  launch "PowerShell 7 (x64)" (the MSI build) instead. The entry point warns about it.

## HIPAA citation judgments not yet decided

Kept unchanged by the citation corrections (PR #122) and recorded in
`docs/HIPAA-CITATION-CORRECTIONS.md`; each needs an owner decision.

- **EXO-2.5 (Customer Lockbox)** cites audit controls, 164.312(b). Customer Lockbox gates Microsoft
  support access behind an approval, which is closer to access control, 164.312(a)(1).
- **PVW-2.5 (retention policies cover the key workloads)** cites the data backup plan,
  164.308(a)(7)(ii)(A). Retention policies preserve content against deletion; they are not a backup.

## Pending changes that address an item here

- **The web GUI items above** (run list for command-line runs, report-site link, `-ScriptDir`
  default): pull request #112, which also adds request filtering.
- **A private PowerShell module bundle,** so the tool does not depend on the operator's module
  folders: pull request #108 (scaffold, not active).
- **An offline comparison of two saved results files** (whether two tenants meet the same
  baseline, stating the tier each used): pull request #109.
- **AAD-7.2 and break-glass accounts:** pull request #119 changes which Conditional Access
  policies count against a break-glass account and is held for review.

## Not started

- A single-page report in the ScubaGear layout (today's single page is `*-assessment.html`; the
  ScubaGear-style layout is the multi-page report site).

## NLS-Assessment

NLS-Assessment carries the fixes through v4.14.3 and none since. It is not receiving further
ports: the plan is to run NRG and NLS from one codebase as configuration profiles. Until that
lands, an NLS run does not include the changes recorded here.

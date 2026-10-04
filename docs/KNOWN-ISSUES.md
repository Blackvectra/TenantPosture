# Known issues

Things that are known, not hidden, and not blocking. Each says what happens, why, and what to do
meanwhile. A fix is its own change, not part of the pull request that recorded it.

## Web GUI (`-Web`)

The server shell, the run list, the report viewer and the tenant box were exercised on a real
workstation (see CHANGELOG). A scan started from the page signed in to Exchange, Purview and Teams
but not Graph (a hidden child process has no window handle for WAM); the fix is in place but a GUI
scan has not yet been confirmed end to end against a tenant.

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

## Distribution-list scan (`Invoke-NRGDistributionListScan.ps1`, DL-* series)

Tested against a stubbed Exchange boundary (raw-shaped fixtures, including omitted properties, a
throttled read, an oversized list and a failed member read) and by running the real entry script in
a child process against stand-in modules. **Not yet run against a live tenant.**

- **How Exchange shapes an empty `ManagedBy` is unconfirmed.** The collector treats an omitted
  property as "not read" and a property that came back empty as "none", so "no owner" (DL-1.2) needs
  `ManagedBy` returned as an empty list. If a live tenant returns `$null` for an ownerless list, DL-1.2
  reads "not assessed" for it instead of a Gap (the safe direction). Confirm on a real tenant.
- **`IsDirSynced` is read but its presence on every list object is unconfirmed.** When it is true the
  worksheet says the change belongs where the list is mastered; when it is absent it says "not
  returned".
- **Join default.** The `Set-DistributionGroup` reference gives `Closed` as the default
  `MemberJoinRestriction` for universal distribution groups; the Exchange Online "Create and manage
  distribution lists" page states no default. The worksheet quotes the cmdlet reference. Some notes
  say "Open by default"; that is not what the reference says.
- **Not read:** Microsoft 365 (Unified) groups and Teams-connected groups; members of a nested group
  (listed as nested, not expanded); whether a named owner is a current, active account; transport
  rules, connectors and other paths that decide who can mail a list.
- **Mail-enabled security groups** come back from the same cmdlet as distribution lists and are
  included, labeled by type. Whether they belong in this scan is an open question for the owner.
- **Scale.** Members are one Exchange call per list. A tenant with thousands of lists is slow, and a
  throttled call is retried three times (2, 4, 8 seconds) before that list's member read is marked
  failed. Evaluating and publishing are linear in the number of lists, measured at about 16 and 20
  milliseconds per list (2000 lists: roughly 30 and 40 seconds) on a development machine, not on a
  live tenant. A list over `-MemberReadLimit` (default 5000) is truncated, and no "no external member" is
  claimed for it.
- **The CSV is long format** (one row per list per recommendation), not one row per list.
- **The DL-* findings are not baseline controls.** They are not in `Config/controls.json`, are not
  scored, and appear in no other report.
- **The NRG standards ship empty.** Until the owner approves `DistributionListMaxMembers`,
  `DistributionListAllowedJoinRestrictions`, `DistributionListAllowedDepartRestrictions` and
  `DistributionListExternalMembers` in `Config/nrg-standards.json`, DL-1.4, DL-1.5, DL-2.1 and DL-2.2
  are reported and not assessed.
- **No framework item is cited where none was verified.** ScubaGear has no distribution-list rule and
  no CIS item was verified; the NIST ids are this tool's mapping (SI-8 is a related fit only).

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

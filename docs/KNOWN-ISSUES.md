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

## Distribution-list scan (`Invoke-NRGDistributionListScan.ps1`)

Built and tested against stubbed Exchange output only; it has not been run against a live tenant.
Confirm on the first live run:

- **Output shapes.** The tests assume `ManagedBy` is an empty collection (not omitted) for a list
  with no owner (an omitted or null `ManagedBy` reads "not assessed", so the owner finding would
  never fire if Exchange returned null), that the `...WithDisplayNames` properties return readable
  names when the switches are passed, that `Guid` comes back as text, that
  `Get-DistributionGroupMember` rows carry `WindowsLiveID` (the UPN is taken from it, then from
  `PrimarySmtpAddress`), and that `Get-DynamicDistributionGroupMember` rows carry
  `PrimarySmtpAddress` and `RecipientTypeDetails` (they carry no `ExternalEmailAddress`).
- **Direct members only.** A nested group is listed, not expanded, so an outside member inside a
  nested group is not seen; the list's DL-3.1 finding says so ("not assessed in full") whenever a
  list has a nested group and no direct outside member. A nested distribution list is also a row of
  its own in the worksheet.
- **Microsoft 365 Groups and Teams-connected groups are out of scope** (a different object with its
  own sender settings, `Get-UnifiedGroup`). Settled as an assumption, to be confirmed by the owner.
- **A guest is outside by type; a mail user is judged by `ExternalEmailAddress`.** A mail user whose
  external address is in a domain that is not an accepted domain (some hybrid routing domains)
  reads as outside.
- **A dynamic list's members are the calculated list Exchange stores** (refreshed about every 24
  hours), a snapshot and not the live filter. An empty calculated list reads "not assessed": a new
  or recently changed list has not been calculated yet.
- **Role-scoped accounts.** An administrator whose recipient scope is limited sees only the lists in
  that scope and gets no error; a scan that returns no lists says so and does not claim none exist.
- **Throttling.** Reads are retried with a growing delay; after three lists in a row stay
  throttled, member reads stop and the remaining lists read "members not read". Run again later or
  lower `-MemberReadListLimit`. Defaults: 2000 members per list, members read for the first 1000
  lists; settings are read for every list.
- **Internal use only.** The worksheet and CSV list owners and members (display name and UPN). Do
  not send them to a client unreviewed. Assumed internal-only; confirm.
- **The hardening commands are never run by the tool.** They are text; the primary change for DL-1.1
  can bounce legitimate outside senders (vendors, scanners, web forms), and the worksheet says so
  beside each command.

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

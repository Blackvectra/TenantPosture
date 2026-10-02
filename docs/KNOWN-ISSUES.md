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

## Distribution-list scan (`-DistributionListsOnly`)

Tested against a stubbed Exchange boundary fed raw cmdlet shapes; **not yet run against a live
tenant**. Until it is, treat these as open:

- **Microsoft 365 Groups and Teams-connected lists are not read** (`Get-UnifiedGroup` is not called).
  The worksheet says so. Whether they belong in scope is the owner's decision.
- **Nested groups are listed, not expanded.** A list whose nested group holds an external member is
  not reported as having one; the nested group is assessed under its own row when it is a list in the
  scan, and otherwise the external-member check reads "Not assessed" for the parent.
- **Dynamic-list members can differ from who receives mail sent now.** The collector uses
  `Get-DynamicDistributionGroupMember`, which Microsoft documents as the calculated membership list
  stored on the group and refreshed about every 24 hours. If that cmdlet is unavailable it falls back
  to `Get-Recipient -RecipientPreviewFilter`, which Microsoft says is the older procedure and returns
  the recipients matching the filter at that moment, not the stored list; the worksheet labels which
  one it used. Neither has been run against a live tenant.
- **Outlook Safe Senders (per mailbox) are not read.** That bypass is unmeasured, not absent; reading
  it is one query per mailbox.
- **Microsoft's own pages disagree** on whether mail from an IP Allow List address can still fail DMARC
  (the anti-spam troubleshooting page says it cannot be overridden; the allowlist page says it skips
  SPF, DKIM and DMARC). The scan treats the IP Allow List as a spam-filtering bypass either way and
  prints both statements.
- **A transport rule is tied to a list only through `SentTo`.** A rule scoped by `SentToMemberOf` or a
  recipient domain is reported tenant-wide and is not matched to individual lists.
- **The three NRG standards ship empty**, so the member-cap, external-member and join-setting checks
  read "Not assessed" until the owner approves values in `Config/nrg-standards.json`.
- **The printed commands are templates.** They follow Microsoft's documented syntax but were not run
  against a tenant; run each with `-WhatIf` first. A mail-enabled security group may need
  `-BypassSecurityGroupManagerCheck` to change its owner; the worksheet does not add it.
- **No ScubaGear or CIS item is cited**, because none written for distribution lists was found. If one
  is published, add it to the catalog with a test that checks it against the authoritative baseline.

## Not yet run against a live tenant

Covered by tests against stubbed or mock data only: the batch runners, the triage deep-dive of other
users' mailboxes, the distribution-list scan, the email assessment on an account that has a mailbox, endpoint compliance
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

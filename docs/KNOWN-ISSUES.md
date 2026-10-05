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
  Out of scope by the owner's decision: classic distribution lists only for now, because lists with
  external users are the target. The worksheet says so; this is a scope boundary, not a defect.
- **"Lists with an external member" is a floor.** It counts lists whose members were read and that hold
  at least one external member; a list whose member read failed is in "members not read" and is not
  counted, and a truncated list can only have more. It is an observation, not a verdict: external
  members stay by the owner's decision, so there is no standard that judges them.
- **Nested groups are listed, not expanded.** A list whose nested group holds an external member is
  not reported as having one, and the allowed-senders proposal lists the nested group itself (Microsoft
  allows a group as an allowed sender, which admits its members), not its members.
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
- **The two NRG standards ship empty**, so the member-cap and join-setting checks read "Not assessed"
  until the owner approves values in `Config/nrg-standards.json`.
- **A list whose `IsDirSynced` was not returned is treated as not synchronized.** Exchange omits a
  property it does not return, and the scan does not guess: it prints that list's commands. A list
  that is synchronized from on-premises Active Directory gets none, because Microsoft documents that
  such a group must be managed on-premises and Exchange Online refuses the change.
- **SCL -1 rules are judged only by what the scan can verify.** A condition on the
  `Authentication-Results` header or on a source IP range verifies the sender; any other header does
  not, and a rule whose conditions the scan cannot classify reads "Not assessed" rather than
  "none weak". `HeaderMatches` is judged by the header name the rule stores; a rule that omits it is
  not treated as verifying.
- **The allowed-senders command is a proposal, not a verified fix.** It is built from each member's
  primary SMTP address, which Microsoft documents as an identifier, but it has not been run against a
  tenant: run it with `-WhatIf` first and on one list before many. It is a snapshot (a later member is
  not on it), it rejects every sender not on it (an owner, shared mailbox or application that mails the
  list and is not a member must be added), and it matches the sender's address, so it does not
  authenticate an outside sender. The cmdlet reference documents no limit on how many senders one list
  may hold; the scan reads at most `-MaxMembersPerList` (500) members and withholds a command longer
  than a spreadsheet cell holds. The proposal assumes each external member is a mail contact or mail
  user (Microsoft's requirement for an outside sender to be accepted), which a member of a distribution
  list always is. An existing allow list is never replaced, and the scan does not compare it with the
  members because Exchange returns allowed senders as directory names, not addresses.
- **The printed commands are bundles, and none has been run against a tenant.** Each follows Microsoft's
  documented syntax: `-WhatIf` and `-Confirm` are documented on every cmdlet used, `@{Add=...}` and
  `@{Remove=...}` on the connection filter and anti-spam policies, and the overwrite form on
  `AcceptMessagesOnlyFromSendersOrMembers`. What Microsoft does **not** document, and the scan therefore cannot
  claim: **clearing `AcceptMessagesOnlyFromSendersOrMembers` or `ModeratedBy` with `$null`** (the rollback that
  restores a captured empty list writes `$null`; the bundle says so, and its check afterwards is what proves the state
  came back); **whether `Disable-TransportRule` leaves a rule's `Mode` alone** (its page is silent; the check shows
  the mode); and **removing several entries of different IP types in one `@{Remove=...}`** (Microsoft's example removes
  one value). Exchange returns allowed senders as names or GUIDs unless asked for display names, so the verify step
  after an allowed-senders change compares a count, not addresses. An ownerless list's owner is one-way, because
  Microsoft states every distribution list must have at least one owner. `Disable-TransportRule` has a built-in
  confirmation pause and the `Set-*` cmdlets have none, which is why a tenant-wide apply carries `-Confirm`. A preset
  (Standard or Strict) anti-spam policy gets no command, because Microsoft says not to modify the policies behind a
  preset. A mail-enabled security group may need `-BypassSecurityGroupManagerCheck` to change its owner; the
  worksheet does not add it. Run a bundle's preview first and on one object before many.
- **The scan account's Exchange permissions are documented, not validated.** Microsoft publishes no per-cmdlet role
  table. [`EXCHANGE-RBAC-DISTRIBUTION-LISTS.md`](EXCHANGE-RBAC-DISTRIBUTION-LISTS.md) lists the cmdlets the scan calls
  (pinned against the collector by a test), the read-only grants Microsoft documents (View-Only Organization
  Management, Global Reader), and the `Get-ManagementRole -Cmdlet` check to run in a tenant before relying on a custom
  role group. Until that check is recorded, a custom role group for the scan is unverified.
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

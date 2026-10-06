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
- **The printed commands are records, and none has been run against a tenant.** Each follows Microsoft's
  documented syntax: `-WhatIf` and `-Confirm` are documented on every cmdlet used, `@{Add=...}` and
  `@{Remove=...}` on the connection filter and anti-spam policies, and the overwrite form on
  `AcceptMessagesOnlyFromSendersOrMembers`. A passing unit test shows the scan builds what it intends and that each
  Compare returns the right True or False for a given object; it does not show that Exchange accepts a command or that
  a rollback restores the real configuration. **The one controlled test that would** is
  [`DL-REMEDIATION-VALIDATION-RUNBOOK.md`](DL-REMEDIATION-VALIDATION-RUNBOOK.md): a disposable cloud-only list,
  preview, apply, verify, rollback and restoration, with the tenant-wide records out of the first run. It has not been run.
  What Microsoft does **not** document, and the scan therefore cannot claim: **clearing `AcceptMessagesOnlyFromSendersOrMembers`
  or `ModeratedBy` with `$null`** (so a captured empty list is a labeled **manual action** with no rollback command, and the
  undo is given in words); **whether `Disable-TransportRule` leaves a rule's `Mode` alone** (its page is silent; the check
  shows the mode); and **removing several entries of different IP types in one `@{Remove=...}`** (Microsoft's example
  removes one value). Exchange returns allowed senders, owners and moderators as names or GUIDs unless asked for display
  names, so the Compare for those is a **count**, which establishes how many entries there are, not which. An ownerless list's
  owner is a manual action too, because Microsoft states every distribution list must have at least one owner.
  `Disable-TransportRule` has a built-in confirmation pause and the `Set-*` cmdlets have none, which is why a tenant-wide
  apply carries `-Confirm`. A preset (Standard or Strict) anti-spam policy gets no command, because Microsoft says not to
  modify the policies behind a preset. A mail-enabled security group may need `-BypassSecurityGroupManagerCheck` to change
  its owner; the worksheet does not add it. A documented rollback for an allowed-senders change exists through
  `AcceptMessagesOnlyFrom` and `AcceptMessagesOnlyFromDLMembers` with `@{Remove=...}`; it is not used yet because the
  apply would have to split individual senders from groups, so it is a candidate to promote once the controlled test has run.
  Run a record's preview first and on one object before many.
- **A list with external members is held for a business-purpose review, not because the setting is unsuitable.** An external
  member receives the list's mail; who legitimately sends to the list is a business question the scan cannot answer.
  Requiring authenticated senders rejects every unauthenticated, external sender, whether or not they are members, so the
  change is withheld until someone who knows the purpose has decided. The allowed-senders proposal is the alternative that
  keeps named outside senders.
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

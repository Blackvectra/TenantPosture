# Distribution-list scan

`Invoke-NRGDistributionListScan.ps1` lists every distribution list in a tenant with its members
and its current settings, compares each setting with a documented recommendation, and writes a
worksheet an administrator uses to harden the lists.

It is **read-only**. It never creates, adds, removes or changes a user, a group or a setting. The
worksheet prints, as text, the PowerShell an administrator would run to close a shortfall; the
tool never runs it.

It connects to **Exchange Online only**. Every other area (Entra ID, Defender, Teams, SharePoint,
Intune, Purview, Power Platform, DNS) and Microsoft 365 (Unified) groups, including
Teams-connected groups, are **not assessed**, and every output says so.

## Run it

```powershell
.\Invoke-NRGDistributionListScan.ps1 -UserPrincipalName admin@client.com
.\Invoke-NRGDistributionListScan.ps1 -DelegatedOrganization client.onmicrosoft.com -TenantId <guid>   # GDAP
```

| Parameter | Purpose |
|---|---|
| `-UserPrincipalName` | Sign-in hint for the Exchange Online window |
| `-DelegatedOrganization` | GDAP: the client's `.onmicrosoft.com` routing domain. Without it Exchange connects to the operator's own organization |
| `-TenantId` | A session for any other tenant is refused |
| `-OutputPath` | Default `.\output` |
| `-MemberReadLimit` | The most members read per list (default 5000); a larger list is read up to the limit and marked truncated |
| `-KeepSession` | Leave the Exchange Online session open |

Exit codes: `0` success, `1` sign-in failure, `2` no lists found, `3` partial read (a section failed
or a list was truncated), `4` fatal.

Output, written through the restricted-file writer (`Set-NRGSensitiveFileContent`: owner, SYSTEM and
Administrators on Windows; mode 0600 elsewhere), because it holds tenant inventory:

- `<tenant>-<timestamp>-distribution-lists.txt`: one section per list.
- `<tenant>-<timestamp>-distribution-lists.csv`: one row per list per recommendation, plus a scan
  row. (Long format on purpose, so a filter on `Status` lists every shortfall across all lists.)

## What each list shows

1. **Members**: UPN (or address, for a contact or group) and display name, nothing else. External
   members (outside the tenant's accepted domains) and nested groups are listed apart. Members of a
   nested group are **not** expanded.
2. **Current settings**: owners (`ManagedBy`), `RequireSenderAuthenticationEnabled`,
   `AcceptMessagesOnlyFrom*`, `ModerationEnabled`/`ModeratedBy`, `MemberJoinRestriction`,
   `MemberDepartRestriction`, `HiddenFromAddressListsEnabled`.
3. **Comparison**: for each recommendation, the current value, the recommended value and where it
   comes from, a status, what was read and what was not, the Microsoft source, the mapped NIST
   control, and, only beside a shortfall, the command text.

Lists are read with `Get-DistributionGroup` (distribution lists, **mail-enabled security groups**
and room lists, labeled by type), `Get-DynamicDistributionGroup`, `Get-DistributionGroupMember` and
`Get-DynamicDistributionGroupMember`, each resolved through `Get-NRGExoCommand` so it binds to the
Exchange Online session.

## The DL-* series

Recommendations live in `Config/distribution-list-baseline.json`, one entry each with the setting,
the recommended value, why, a Microsoft Learn source and the NIST mapping. They are **not** in
`Config/controls.json`: they are worksheet findings, not baseline controls, and nothing here is
scored.

| Id | Setting | Recommended | Where the recommendation comes from | NIST SP 800-53 Rev 5 (tool's mapping) |
|---|---|---|---|---|
| DL-1.1 | `RequireSenderAuthenticationEnabled` | `True` | Microsoft documented default ("Only allow messages from people inside my organization") | AC-3, SC-7, SI-8 (related only) |
| DL-1.2 | `ManagedBy` | at least one owner | Microsoft: a list must have at least one owner | AC-2 |
| DL-1.3 | `ModerationEnabled` + approver | when on, a moderator or an owner is named | Microsoft: with no moderator, the owners approve | none verified |
| DL-1.4 | `MemberJoinRestriction` | NRG standard | **NRG** (`DistributionListAllowedJoinRestrictions`) | AC-2, AC-6 (related) |
| DL-1.5 | `MemberDepartRestriction` | NRG standard | **NRG** (`DistributionListAllowedDepartRestrictions`) | none verified |
| DL-1.6 | `HiddenFromAddressListsEnabled` | none | reported only: Microsoft documents that a hidden list can still be mailed | none verified |
| DL-2.1 | member count | NRG standard | **NRG** (`DistributionListMaxMembers`) | AC-2 (related) |
| DL-2.2 | external members | NRG standard | **NRG** (`DistributionListExternalMembers` = `Prohibited`) | AC-4, AC-2 (related) |
| DL-2.3 | nested groups | none | reported only | AC-2 (related) |
| DL-0.1 | was the inventory read in full | n/a | the scan itself: what was read and what was not | none verified |

### What the frameworks do and do not say

- **CISA ScubaGear** has no rule for distribution-list settings. No SCuBA id is cited.
- **CIS Microsoft 365 Foundations**: no item written for distribution-list settings was verified. No
  CIS number is cited.
- **NIST SP 800-53 Rev 5** has no control for distribution lists. The `Nist80053` ids are **this
  tool's mapping**, labeled that way in every output, each chosen because the Rev 5 statement fits
  what the setting does (AC-2 account management and group membership; AC-3 access enforcement;
  AC-4 information flow; AC-6 least privilege; SC-7 boundary protection). SI-8 is a related fit
  only: the setting narrows the unsolicited-mail path but is not a spam-protection mechanism. Where
  no framework item fit, the finding says "no framework item verified".
- **Microsoft Learn** is the source for every recommended value (see `SourceUrl` per entry). One
  point to know: the `Set-DistributionGroup` reference gives `Closed` as the default
  `MemberJoinRestriction` for universal distribution groups (and `Open` as the default
  `MemberDepartRestriction`); the worksheet quotes that, not "Open by default".

### Statuses

| Status | Meaning |
|---|---|
| Meets | Read, and matches the recommendation |
| Shortfall | Read, and does not (Gap) |
| Partly meets | Genuinely part-way, for example mail from unauthenticated senders is accepted but only from named senders |
| Reported only | No recommendation to judge it by; shown so it is not read as "protected" |
| Not assessed | The evidence was missing (a property Exchange omitted, a member read that failed, a section that did not collect) |
| Not assessed (no approved NRG standard) | NRG's judgment, and the standard is not approved, so the setting is reported and not judged |
| Does not apply | For example a join setting on a dynamic list |

Missing evidence is never Satisfied. An omitted property is "not read", never "empty": a list with no
`ManagedBy` returned is "owner not read", and only a `ManagedBy` that came back empty is "no owner".

## NRG standards: shipped empty

Anything that is NRG's own judgment is read from `Config/nrg-standards.json` and **ships empty**
until the owner approves it. An empty value means the setting is reported and **not assessed**,
never met.

| Key | Values | Judges |
|---|---|---|
| `DistributionListMaxMembers` | one whole number, for example `"500"` | DL-2.1 |
| `DistributionListAllowedJoinRestrictions` | any of `Open`, `Closed`, `ApprovalRequired`, most preferred first | DL-1.4 |
| `DistributionListAllowedDepartRestrictions` | any of `Open`, `Closed`, most preferred first | DL-1.5 |
| `DistributionListExternalMembers` | `Prohibited` | DL-2.2 |

An invalid value is dropped and named in the worksheet, never guessed at. The first approved join or
leave value is what the printed command uses.

## Limits and how reads fail

- A failed query is never "no lists": `Data.SectionStatus` records `DistributionGroups`,
  `DynamicDistributionGroups`, `AcceptedDomains` and `Members` as `Collected` or `Failed`.
- A throttled Exchange call is retried with backoff (2, 4, 8 seconds); one that still fails marks
  **that list's** member read failed, never "no members".
- A list over `-MemberReadLimit` is read up to the limit (`limit + 1` is requested, so exactly at the
  limit differs from over it) and marked truncated: the count is "at least", and "no external member"
  is never claimed for it.
- A member whose address cannot be classified is counted as unclassified, never as internal. With no
  accepted-domain read, no member is called external or internal.
- A directory-synced list (`IsDirSynced`) is changed where it is mastered. The worksheet shows the
  flag, DL-1.2 says so for an ownerless list, and the note beside every command for such a list says
  the cloud command is expected to be refused (not confirmed against a live tenant).
- Tenant text is hostile: control characters and bidirectional overrides are stripped, a leading
  `=`, `+`, `-` or `@` in a CSV cell is defused, and the identity in a command is a single-quoted
  address or GUID only (anything else prints a placeholder).

## Files

| File | Role |
|---|---|
| `Invoke-NRGDistributionListScan.ps1` | Entry point: connect (Exchange only), collect, evaluate, publish |
| `Lib/Connect-NRGExchangeOnly.ps1` | Exchange Online sign-in and nothing else |
| `Collectors/EXO/Invoke-NRGCollectDistributionLists.ps1` | Read-only collector; raw data key `EXO-DistributionLists` |
| `Evaluators/Test-NRGControlDistributionLists.ps1` | The DL-* verdicts |
| `Lib/Get-NRGDistributionListBaseline.ps1` | Catalog and standards loaders; command text builder |
| `Config/distribution-list-baseline.json` | The recommendations (reviewable data) |
| `Config/nrg-standards.json` | The four `DistributionList*` standards (empty) |
| `Publishers/Publish-NRGDistributionListWorksheet.ps1` | The `.txt` and `.csv` |
| `Testing/NRG.DistributionList{Collector,Evaluator,Worksheet}.Tests.ps1` | Pinned behavior |

## Open questions for the owner

1. **Scope.** Are Microsoft 365 (Unified) groups and Teams-connected groups in scope, or only
   classic distribution lists? Today they are not read. Mail-enabled security groups are read (the
   same cmdlet returns them) and labeled.
2. **Audience.** The worksheet is treated as internal-only (it names members). Confirm.
3. **Standards.** Which NRG judgments to approve, and to what values: a member cap, whether external
   members are prohibited, and the join and leave policy.

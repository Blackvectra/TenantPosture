# Fresh read-only run and portal spot-checks

Nothing in this document has been performed. It says how to run the assessment read-only and
how to check what it reports against the tenant, so live validation can be claimed only after
someone has done it. Local tests and CI show the code does what the tests say; only a live run
shows it is right about a tenant.

## 1. Prepare

- Branch: the current head of PR #106 (`claude/nls-assessment-nrg-update-WWQcp`). Do not merge first.
- Use a workstation with PowerShell 7, the Microsoft Graph and Exchange Online modules, and (for SharePoint) the SharePoint Online Management Shell. The assessment is read-only: it makes no change to the tenant.
- Decide, and do not invent, the organizational standards the tool cannot know. Until you supply them, the controls that need them report that component **not assessed**:
  - the monitoring mailbox: `-MonitoringAddress alerts@your-domain.com` (or `MonitoringAddresses` in `Config/clients.json`)
  - the approved NRG lists in `Config/nrg-standards.json` (DMARC reporting address, blocked file types, priority users, required Conditional Access templates) and `Config/asr-required-rules.json`
- Client results JSON is sensitive and is never committed.

## 2. Run

```powershell
./Invoke-NRGAssessment.ps1 -TenantDomain <tenant>.onmicrosoft.com -IncludeSharePointShell `
    -BaselineTier Standard -ThirdPartyEDR '<product if not Defender>' `
    -MonitoringAddress <address if approved>
```

Optional independent scan on the same tenant, for comparison only:
`Invoke-SCuBA -ProductNames * -M365Environment commercial -OutPath <folder>` (ScubaGear 2.0.0).

Build the report site from the results JSON the run wrote (connects to nothing):

```powershell
./New-NRGReportSite.ps1 -ResultsPath .\output\<tenant>-<timestamp>-results.json `
    -OutputPath .\output\site -ScubaResultsPath <folder>\ScubaResults.csv
```

## 3. Spot-check method

For each row: read the finding's Detail, find the same setting in the portal or PowerShell, and
record what you see. A mismatch is an investigation first. Rule out, in order: collection time,
scope (the signed-in account, a `-Skip` flag, an unread section named in the Detail), policy
precedence, an NRG standard that is not approved, and only then a detector defect. For a defect,
keep the raw collector output, the Detail and the portal value, and add a failing test before any
code change.

## 4. Rows changed by this PR (check these first)

| Control | What the finding should say | Where to look |
|---|---|---|
| AAD-1.1 | Blocked by the policies named; any account excluded from every qualifying policy is named as an exception; a policy whose application scope is None is not credited | Entra > Protection > Conditional Access: each policy's Users, Target resources, Conditions, Grant |
| AAD-11.1 | Device code flow blocked for all users on all applications, or the exclusions named | Conditional Access policy with Authentication flows = Device code flow |
| AAD-1.2 | MFA enforcement, registration and (separately, AAD-1.3) phishing resistance stated apart; exclusions across policies named | Conditional Access; Entra > Protection > Authentication methods > Activity (registration) |
| AAD-1.3 | Strength judged from the authentication strength's allowed methods; role coverage against this tenant's privileged roles | Entra > Protection > Authentication methods > Authentication strengths |
| DEF-2.1 | Preset on, who it covers, who is excluded and what they fall back to | Defender portal > Email & collaboration > Policies & rules > Threat policies > Preset security policies (Manage protection settings) |
| DEF-4.1 / DEF-4.2 / PVW-3.4 | Only enforcing (On) DLP policies counted; a policy in test mode reported, not credited | Purview > Data loss prevention > Policies (Mode) and each rule's conditions and actions |
| DNS-1.3 | Observed record stated; NRG baseline judgment; reporting address judged only against an approved NRG address | `Resolve-DnsName -Type TXT _dmarc.<domain>` |
| DEF-2.2, DEF-2.3, EXO-1.5, INT-1.5, AAD-6.2, AAD-2.1 | Verified components kept; approved-list components not assessed until approved | The setting each Detail names |

Also re-check the controls the last live run flagged: EXO-1.6, EXO-1.1, DEF-3.4, EXO-3.3, INT-2.2,
INT-1.1, DEF-2.3. INT-1.5's and INT-2.2's Settings Catalog parsers have not been verified live.

## 5. Report back

Keep local validation, CI and live validation separate. For each spot-check: the control, what NRG
said, what the portal showed, and whether it is explained (time, scope, precedence, unapproved
standard) or a defect. Then rerun and reassess.

## 6. Comparison worksheet (one row per control, priority order)

Connect each row in this chain: ticket, intended setting, fresh evidence, NRG verdict, independent
result. Start with the controls this PR changed: Conditional Access scope and exclusions, preset
coverage, and DLP enforcement mode.

| Ticket | Control | Intended setting (who it covers) | Observed in the portal | NRG observed value | NRG verdict (verified / shortfall / not assessed) | Independent result (rule, strength) | Explained? | Defect? |
|---|---|---|---|---|---|---|---|---|
| | AAD-1.1 | Legacy authentication blocked for all users on all apps | | | | MS.AAD.1.1v1, SHALL | | |
| | AAD-11.1 | Device code flow blocked for all users | | | | MS.AAD.3.9v1, SHOULD | | |
| | AAD-1.2 / AAD-1.3 | MFA required for all users; phishing-resistant for admins | | | | MS.AAD.3.2v2, MS.AAD.3.6v1 | | |
| | DEF-2.1 | Preset applies to everyone, exclusions named | | | | no 2.0 equivalent | | |
| | DEF-4.1 / DEF-4.2 | DLP enforcing (Mode On) on Exchange, SharePoint, OneDrive, Teams; blocks named types | | | | MS.SECURITYSUITE.3.1v1, 3.2v1 | | |
| | DNS-1.3 | DMARC per the NRG requirement | | | | MS.EXO.4.2v1, SHALL (reject) | | |

"Explained" means the difference is collection time, scope, precedence, an unapproved NRG standard,
or two standards judging the same configuration differently. "Defect" means none of those apply: keep
the raw collector output and add a failing test before changing code.

What the fresh run must also show, because fixtures cannot: the collectors returned the evidence the
new checks need (preset exclusion identities, DLP rule `BlockAccess`, antivirus settings, malware
`ZapEnabled`), and each report says what was and was not read. If a field is absent, the finding
should say "not read"; an absent field that reads as a pass is a defect.

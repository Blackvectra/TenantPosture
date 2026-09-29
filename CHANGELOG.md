# Changelog

## Unreleased

- **Defects found by the first live baseline validation (NRGTS, 2026-09-29),
  fixed without touching a single verdict.** DNS collection ran only inside
  the Exchange branch of the entry point, so an Exchange connection failure
  also removed the three DNS Minimum controls; the DNS collector already
  falls back to Graph verifiedDomains, and the step now runs whenever Graph
  or Exchange connected. "Was not read" is now a collection gap in the scope
  classifier: SPO-1.2's "the default link type was not read" was filed as
  not applicable to this tenant, which changes the denominator's meaning,
  and the baseline inherited it. INT-2.2 no longer depends on INT-2.1 (ASR
  is enforced by Defender Antivirus beside a third-party EDR; the edge read
  as misleading on a Cortex tenant). Every NotVerified baseline row now
  carries a cause (collector unavailable and which, skipped by operator,
  quick scan, manual control, manual verification, evidence not read, stale
  evidence, evaluator error, no result) and the summary, both reports and
  the validation tool print the split, so "27 not verified" reads as an
  engineering list. Connection failures record their first stack frames in
  the Exceptions array. Partial stays Failed in the baseline by decision.

- **Exchange and Purview never connected because Teams connected first.**
  Root cause of the "Exchange/Purview connection" validation defect, found
  on the first run from the MSI PowerShell build with ExchangeOnlineManagement
  3.10.1. Both modules load `Microsoft.Identity.Client` and its Broker into
  the default load context, and the runtime keeps one copy per name: a
  later load binds to the loaded copy when it is the same or newer and
  fails with 0x80131040 ("The located assembly's manifest definition does
  not match the assembly reference") when it is older. MicrosoftTeams 8.0.0
  carries MSAL 4.82.0 and ExchangeOnlineManagement 3.10.1 carries 4.83.1,
  so with Teams first both `Connect-ExchangeOnline` and
  `Connect-IPPSSession` failed before any prompt, every run.
  `Connect-NRGServices` now connects Graph, Exchange, Purview, then Teams,
  and proves the Teams session with `Get-CsTenant` before reporting it
  connected (a Connect that returns cleanly can still leave every cmdlet
  failing with "You must call the Connect-MicrosoftTeams cmdlet").
  `NRG.WorkloadSkip.Tests.ps1` pins the order.

- **EXO-2.6 scored a failed section as a clean list (second live run,
  Exchange half).** `Get-Mailbox` omitted `LicenseReconciliationNeeded` on
  the live tenant, the shared-mailbox sign-in loop threw under StrictMode,
  `SectionStatus.SharedMailboxes` read `Failed`, and the evaluator reported
  "28 shared mailbox(es) found — none have direct sign-in enabled" because
  it consulted the section status only when the mailbox list was empty. The
  collector reads both license fields through `Get-NRGObjectField`, and
  EXO-2.6 and EXO-6.2 now report not assessed whenever the section did not
  complete, whatever the list holds. `NRG.ExchangeTruth.Tests.ps1` replays
  the live shape. The validation tool notes every Satisfied row whose
  collector reported a failed section, for the operator to confirm the
  evaluator does not read it.

- **The Exchange module floor follows the PowerShell version.** The first
  live run of v4.14.3 found ExchangeOnlineManagement 3.9.2 installed beside
  PowerShell 7.6.6: the installer accepted it because it checked only the
  3.7.2 minimum, and `Connect-ExchangeOnline` then failed inside the module
  ("You cannot call a method on a null-valued expression"). Microsoft's
  support table pairs 3.10.0+ with 7.6 and 3.5.0–3.9.2 with 7.4/7.5.
  `Get-NRGExoModuleFloor` now returns the range for the running PowerShell,
  and the installer, the entry point's preflight and `Get-NRGModuleHealth`
  read it; a version above the ceiling is warned about at preflight. The
  Microsoft Store (MSIX) build of PowerShell is recognized by its
  `WindowsApps` home and the MSI build recommended, because the Exchange
  module failed to import from it on the same machine. The installer's
  `$psVer:` parse error is fixed and every script is now parse-tested.

- **NRG Security Baseline v1.0 — candidate controls for editorial review**
  (`docs/NRG-SECURITY-BASELINE-CANDIDATES.md`). The assessment measures
  posture against 204 controls; the baseline will say which of them NRG
  requires of every managed client. This document is the editorial pass,
  not configuration: every control with its severity, license requirement,
  automation level, a proposed tier (Minimum / Standard / Hardened /
  Assessment-only), the reason, why NRG owns it, and operational notes.
  30 Minimum + 20 Standard + 18 Hardened nominated; 136 stay
  assessment-only evidence. Tiers are layered (a Standard client satisfies
  Minimum + Standard). Applicability is per client (licensing, third-party
  EDR, a per-client exceptions file), never per control, and the future
  compliance view keeps observed state, license constraint and exception
  disposition separate. `Config/nrg-baseline.json` and
  `Get-NRGBaselineCompliance` follow once v1.0 is locked. Second editorial
  pass adds seven governance fields per tiered control: owner, evidence
  source (derived from the collector), expected state, SLA class (a label;
  the day counts live elsewhere), dependencies, an effectiveness check
  tagged collected or not collected, and an evidence-freshness class. The
  document keeps control requirement, observed evidence and effectiveness
  evidence as three separate concepts, states the stateless results
  contract, and ends with a mechanically generated contradictions section
  (manual-only Minimum controls, inverted dependencies, and the 62 of 68
  effectiveness checks that need telemetry the tool does not collect).
- **NRG Security Baseline v1.0 is implemented as a desired-state layer**
  (`Config/nrg-baseline.json`, `Lib/Get-NRGBaseline.ps1`, `-BaselineTier`).
  A view over the findings: no new finding, no changed finding, no moved
  framework score. Per required control the results JSON carries
  ObservedState, Constraint, Disposition, EffectivenessState, dependency
  state, evidence timestamp and freshness; a missing finding, a collector
  that did not succeed, a skipped workload, a manual control or stale
  evidence all resolve NotVerified, never Satisfied. Approved exceptions
  live per client in `Config/baseline-exceptions/<tenant-domain>.psd1`
  (review date required; expired ones are reported, not honored) and change
  only the disposition. Effectiveness is Unknown wherever the assessment
  does not read the evidence (62 of 68 controls today) and is read from
  ingested endpoint results otherwise. `BaselineRegressions` compares with
  `-BaselineResults` only under the same baseline version and tier. The
  HTML and Markdown reports gain an NRG Security Baseline section with
  configuration compliance and effectiveness visibility as separate
  blocks. `NRG.Baseline.Tests.ps1` pins every invariant and the
  document-to-config tier agreement.
- **Device build standard v1.1: patch policy, delivery and effectiveness
  are three requirements.** DB-4.2 is now the patch policy (within a
  defined remediation window); DB-4.7 requires patch deployment to be
  monitored and failures investigated; DB-4.8 requires remediation to be
  verified against the current vulnerability state (Defender Vulnerability
  Management), the standard's VM-VERIFY-01. The patching tool is evidence
  of deployment, Defender is evidence of remediation, and they are not the
  same thing. DB-4.8 ships with no `VerifiedBy` on purpose: the requirement
  exists before the automation, and a Defender Vulnerability Management
  collector can make it machine-verifiable later without changing it.
  29 requirements, 25 mandatory. `RA-5 Vulnerability Monitoring and
  Scanning` added to the 800-53 catalog for the citation.

## v4.14.3 (2026-09-26)

v5.0 backlog sweep: the collector-fields section (places where a collector
recorded something Graph never said), the known issues it found, the owner's
AAD-1.4 / 1.5 scoring decision, and a short mechanical sweep.

- **Every consented app was reported by its object ID.** The name lookup built
  its URL as `"…/servicePrincipals/$cid?`$select=…"`, and PowerShell allows
  `?` in a variable name, so it read the unset variable `$cid?` (StrictMode
  throws), the per-app `catch` fell back to the ID, and no app was ever named.
  It also looked up only the first 30. The URL now uses `${cid}` and every
  app is looked up. `NRG.ExternalShapes.Tests.ps1` fails on any variable name
  containing `?` in a module file.
- **AAD-1.4 and AAD-1.5 credited any risk level.** A Conditional Access risk
  policy applies only to the levels it selects, and both controls accepted
  any, so a low-only policy scored Satisfied. Owner's rule: sign-in risk is
  Satisfied when the enabled policies together cover High and Medium
  (Microsoft's template), Partial with one of the two, a Gap with neither;
  user risk is Satisfied only with High ("require password change for
  high-risk users").
- **SharePoint shell settings.** `Get-SPOTenant` was read by dot-access, so a
  module version without a newer property (`EnableAutoExpirationVersionTrim`)
  threw and lost every shell setting, and a present-but-empty value defaulted
  to `$false` / `0`, which SPO-1.4, 2.2, 2.6, 2.7, 3.2, 3.3 and 3.4 scored.
  Each property is now read separately and stored as not read when absent;
  those controls report the missing property as not assessed. SPO-3.3 still
  passes a limit of 100 or more versions when trimming was not read.
- **The OAuth consent grant list** logged its page cap and still reported the
  truncated list as collected; it now reads through `Get-NRGGraphAllPages`.
- **Purview is assessed by default.** It was skipped unless `-IncludePurview`
  was given, because ExchangeOnlineManagement 3.4.0 (October 2023) crashed in
  the WAM broker, and the batch runner never passed the switch, so every
  batch run silently skipped all 18 Purview controls. Microsoft's module has
  had a supported `-DisableWAM` switch since 3.7.2, which the Exchange and
  Security & Compliance sign-ins now pass when the installed module has it
  (the sign-in is not weaker: MSAL uses the system browser with the same MFA
  and Conditional Access). The module floor is 3.7.2 with no pin, and
  `Install-NRGPrerequisites.ps1` caps the version by the PowerShell in use
  (3.5–3.9.x need 7.4, 3.10+ needs 7.6) instead of downgrading to 3.2.0.
  `-IncludePurview` still parses and does nothing; `-SkipPurview` opts out.
- **A skipped workload reads "not assessed".** `Register-NRGCoverage` rejected
  the `Skipped` status the scope classifier looked for, and the entry point
  never recorded a `-Skip` flag, so the controls of a workload the operator
  skipped on purpose were reported as "could not be assessed — data did not
  collect ... re-run once the cause is resolved". Each `-Skip*` flag is now
  recorded, and those controls land in a new "Not assessed — workload skipped
  by the operator" group in the HTML report and the Markdown summary.
- **README.** 27 of `Invoke-NRGAssessment.ps1`'s 45 parameters
  (`-IncludePurview`, `-IncludeSharePointShell`, the `-Skip*` switches,
  `-JsonOnly`, app-only sign-in, …) appeared nowhere in it; it now has a
  parameter table that `NRG.DocAccuracy.Tests.ps1` keeps equal to the real
  parameter list. README and CLAUDE.md gave the output location as a
  per-timestamp or per-tenant folder; files are written flat to `.\output\`
  as `<tenant>-<yyyyMMdd-HHmmss>-…`.

- **Directory-setting booleans read "False" as on.** Graph returns Password
  Rule Settings values as strings, and `[bool]"False"` is `$true` in
  PowerShell, so `EnableBannedPasswordCheck` and
  `EnableBannedPasswordCheckOnPremises` were written to the results JSON as on
  for a tenant that had turned them off. They are now read as True or False,
  and anything else as not read. No scored control reads either field; AAD-7.1
  scores the lockout threshold only.
- **Paged collections were read from their first page only.** Conditional
  Access policies, the beta token-protection read, named locations
  (`$top=100`, while a tenant may hold 195), risky service principals and
  attack simulations were each one request that ignored `@odata.nextLink`, so
  anything past the first page was dropped and the rest reported as the whole
  list. A trusted named location on page two made AAD-2.2 report none marked
  as trusted, and a simulation history longer than one page could count no
  launched campaign (DEF-4.6). New `Get-NRGGraphAllPages`
  (`Lib/Invoke-NRGGraphRequest.ps1`) follows `@odata.nextLink` and throws,
  leaving the section unread, when a response carries no `value` collection
  or the page cap is reached, instead of returning a partial list.
- **AAD-13.1 claimed a peer group it did not use.** Below the all-tenants
  average, the finding said Microsoft "rates this tenant behind comparable
  organizations". That average covers every Microsoft 365 tenant, so the
  finding now names only the benchmark it compared against. A score with no
  maximum was graded "0 / 0 (0%) — Critical"; it is now not assessed.
- **AAD-7.1's not-collected message** said the read "requires beta endpoint
  access"; the collector has read `/v1.0/groupSettings` since v4.6.4.

Tests: `NRG.GraphRequest.Tests.ps1` pins the paging helper (every page,
headers on every page, empty is empty, a malformed or capped read throws);
`NRG.IdentityTruth.Tests.ps1` drives the real CA and password-rule collectors
with a two-page named-location response and True, False and unreadable
setting values; `NRG.SecureScore.Tests.ps1` pins the benchmark wording and
the missing maximum; `NRG.SharePointSettings.Tests.ps1` drives the real
SharePoint collector with an older `Get-SPOTenant` shape and each shell
control with one property missing; `NRG.IdentityTruth.Tests.ps1` also pins the
risk levels and the named consented apps. Each new bug test fails on the code
before this change.

Swept and clean: no TODO/FIXME or known-issue marker describes a live
problem, and no expandable string reads `"$obj.Member"` (which prints the
object's type name) or `"$name:"` (a scope prefix).

## v4.14.2 (2026-09-25)

**Conditional Access: every policy's real state, and Microsoft's own
recommended baseline.** Owner's ask: "does the report say what CA policies
are enabled in audit mode and maybe provide CA that should be in place for
future. I know you can add so many policies i could add one just for an app
we use or linkedin for example." The HTML report and Markdown summary now
carry a Conditional Access section:

- **Every policy, with its true state** — On, Report-only (audit), Off, or
  an unrecognized state (never read as Off), each with a plain-English
  description of who it targets, what it targets, and what it requires.
- **A recommended baseline** compared against 11 of Microsoft's own
  documented Conditional Access policy templates (block legacy
  authentication, MFA for all users, MFA for admins, phishing-resistant MFA
  for admins, MFA for Azure management, block device code flow, risk-based
  sign-in and user policies, device compliance, the compliant-or-MFA
  alternative, no persistent browser session), each cited to its Microsoft
  Learn page. Every row is Enforced, Partly in place, Covered by Security
  Defaults, Needs a license, Not read, or Not in place — never a guess from
  unread data.
- **A policy scoped to specific apps, groups or users — the owner's own
  LinkedIn example — is listed as custom and never judged** against a
  template it was never meant to satisfy. Matching is conservative: a
  template is only Enforced from a policy that is genuinely On, targets all
  users (or, for the two admin templates, every role this tenant's own role
  catalog marks privileged), and targets all resources with no exclusion; a
  narrower, report-only, or weaker policy shows as Partly in place, never
  Enforced.
- New `Lib/Get-NRGConditionalAccessView.ps1` (`Config/conditional-access-baseline.json`
  holds the template catalog). A view, like `Get-NRGAssessmentScope`: it
  emits no findings and moves no score.
- Two bugs caught while building this, both regression-tested: a policy
  scoped to one app matched the "require MFA for admins" template, because
  that template's eligibility check never looked at which resources the
  policy targeted; and every baseline row read "needs a license" even when
  a policy was actively enforcing it, because the license check ran before
  the match check and treated "licensing was not read" as a confirmed
  absence. A device-code or legacy-authentication policy that only requires
  MFA (rather than blocking) is never credited as partial protection —
  Microsoft documents that MFA does not stop either attack.
- Review fixes: a policy on all resources that excludes the Azure
  management resource is not credited for the Azure-management template; a
  user-risk policy without the High level (Microsoft's template is "high-risk
  users") and a sign-in risk policy with neither High nor Medium (the
  template selects both) are not credited, and one with only one of the two
  is partly in place; the persistent-browser template needs All users to be
  in force; and a license profile object with no SKU data
  (`HasLicenseData = $false`) is unread licensing, never "needs a license".

## v4.14.1 (2026-09-25)

Fixes from the first live run of v4.14.0. Every item below produced a wrong
verdict, a verdict with no reason, or a console line that said nothing.

- **Six Purview sections never ran, silently.** Audit retention policies,
  label policies, auto-labeling, retention labels, communication compliance
  and information barriers (PVW-1.2, 1.4, 2.2, 2.3, 2.6, 4.2, 4.3, 4.4) read
  "not collected" with nothing in Exceptions. The module did not return
  `IsEopSession`, so the Purview session was taken for Exchange Online and
  its commands skipped. The session is now recognized by name
  (`ExchangeOnlineProtection_N`) and endpoint too, and a command that cannot
  be resolved marks its section Failed and logs why.
- **EXO-3.1 could never be assessed.** Its collector existed but the entry
  point never ran it. It runs now, and a test fails if any control depends on
  data no collector the entry point runs produces.
- **PIM role policies were cut to 50.** `$top=50` returned 50 of the tenant's
  role policies and no next page, so the Global Administrator policy was
  missing (AAD-3.5 not assessed) and AAD-3.3/3.4/3.6 judged 4 privileged
  roles. `$top` is gone and any policy the list misses is read by ID. GA
  activation without approval is now a Gap, not Partial.
- **AAD-13.1 compared against a "5% average".** Microsoft's peer average is
  on a 0-100 scale and was divided by the tenant's maximum points, so any
  tenant above 5% passed. It is read as a percentage.
- **INT-3.1 passed on the Windows Mobile block** Intune ships in every tenant.
  That block no longer counts as a restriction.
- **INT-2.4 / INT-4.4 read the enrolled devices.** With no Macs or phones
  enrolled they say so and are not applicable (INT-4.4 had scored a Gap from
  a default Android policy); a Mac or phone enrolled with no policy is a Gap.
- **MTA-STS (DNS-1.4).** A published `_mta-sts` record whose `mta-sts.`
  host does not exist (authoritative no A/AAAA) is a Gap: senders cannot
  fetch the policy. A failed lookup stays not assessed.
- **Exchange test-mode connectors** are now collected
  (`-IncludeTestModeConnectors`) and reviewed under EXO-8.1, which also
  removes the Exchange warning from the console.
- **Wording that was not true:** EXO-2.3/2.4 said POP3/IMAP use basic auth
  and bypass MFA (Exchange Online retired that in October 2022); EXO-9.2
  called deleted mail unrecoverable on mailboxes that are under a hold;
  PPL-3.3 passed with "no user can invoke Copilot" when nobody is licensed
  (now not applicable; Copilot Chat needs no license); AAD-1.4/1.5/10.1 ended
  "Otherwise this is expected".
- **AAD-12.1 and AAD-1.2 count the same people.** The Entra Connect sync
  account is excluded from both, and each says so.
- **No verdict without a reason.** Seven controls printed a bare Satisfied;
  a finding with no Detail now carries its observed value.
- **Console.** Collectors print one aligned line each, grouped by workload,
  with status, time and what was found, and a summary line; the
  restricted-character warning at module load is gone (14 Email-IR function
  names had a second hyphen and were renamed, e.g.
  `Test-NRGEmailControlAuthMethods`); the Graph WAM notice is one line; the
  missing-permission line printed `System.Object[]` and now names the
  permissions and the controls they block; report files are listed by name
  under the output folder; the footer counts controls and says when there are
  more findings than controls. The NIST matrix HTML is now listed and
  access-restricted like every other output.
- **Security Defaults is read by every Conditional Access control.** While
  Security Defaults is on, Microsoft lets Conditional Access policies be
  created but not turned on, so the CA list is empty or holds policies that
  cannot take effect. Every CA control read that as an unprotected tenant, and
  the break-glass check reported "no emergency access path". Now:
  - AAD-1.1 (legacy authentication) and AAD-11.1 (device code flow) are
    Satisfied through Security Defaults, which blocks both. Their definitions
    now say Security Defaults meets them.
  - AAD-1.3 is Partial: the 16 administrator roles Security Defaults names do
    MFA at every sign-in, but Security Defaults does not require a
    phishing-resistant method.
  - AAD-1.2 is Partial, never Satisfied (v4.14.0 passed it whatever the
    registration): only the 16 named administrator roles do MFA at every
    sign-in, and other users are prompted when Microsoft decides it is
    necessary, so crediting MFA on every access to a non-privileged account
    (NIST IA-2(2), SCuBA MS.AAD.3.2v1, PCI 8.4) would claim more than
    Security Defaults enforces. Its definition now says Security Defaults
    meets it only in part. Security Defaults needs no license, so a
    registration shortfall (fixed by registering users) is exempt from
    license gating and scored as Partial; with every user registered, what
    remains needs Conditional Access (Entra ID P1), so on a tenant without P1
    that finding is not scored, like any unlicensed control. License gating,
    the scope section, the roadmap, the improvement plan, the playbook, the
    remediation script, the compliance matrix and the HTML report all pass
    the finding to `Test-NRGLicenseRequirementMet -Finding`.
  - AAD-1.2 needs the MFA registration report, which Microsoft documents as
    requiring Microsoft Entra ID P1 or P2, so on a Security Defaults tenant
    without either it is not assessed (it used to pass without reading
    registration). The finding says so, and says re-running will not help
    when Graph refused the report for that reason.
  - AAD-1.4, 1.5, 2.1, 2.3, 10.1, 10.4, 11.4, 11.5, 11.7, 11.8, 11.9 and
    INT-1.2 stay Gaps. Each now says Security Defaults is on, that no CA
    policy can be enforced while it is, and how to move to Conditional Access
    without a gap in protection. A report-only policy no longer earns half
    credit or the advice "switch the policy to On". The risk findings
    (AAD-1.4, 1.5, 10.1) say no Conditional Access risk policy can be in
    force and that the legacy Identity Protection risk policies are not read.
  - AAD-2.2 with no named locations is still a Gap; named locations that
    exist no longer pass, because nothing can use them (not applicable).
  - AAD-7.2 no longer reports a false missing-CA-exclusion Gap. It is a Gap
    when the role data proves Microsoft's recommendation unmet (no, or only
    one, permanent Global Administrator assignment on an account not marked
    as synchronized from on-premises), and requires manual verification only
    with two or more such accounts. AAD-3.2 no longer credits CA exclusions
    while Security Defaults is on. Where the tool cannot tell, both say it
    requires manual verification and reach the manual-review questionnaire;
    AAD-7.2's definition (the question asked) says what to confirm while
    Security Defaults is on.
  - SPO-1.5 no longer passes for an unmanaged-device restriction beside
    Security Defaults: Microsoft documents that the restriction relies on
    Conditional Access policies, and none can be on. Its license requirement
    is now Microsoft Entra ID P1 (Microsoft: those settings require Entra ID
    P1 or P2), so on a tenant without P1 it is not scored. This also applies
    with Security Defaults off: `AllowFullAccess` on a Business Standard
    tenant was a scored Gap and is now not scored (upgrade opportunity).
  - The HTML report (Priority Actions and each finding's "How to fix it") and
    the remediation playbook show a Security Defaults finding's own
    remediation (turn Security Defaults off and the replacement Conditional
    Access policies on in one change; for AAD-1.2, a registration campaign)
    instead of the control's generic text (for SPO-1.5, the `Set-SPOTenant`
    change a tenant set to `AllowLimitedAccess` has already made). The
    remediation script prints that order of operations first.
  - The Assessment Scope section no longer names a failed Conditional Access
    read as the reason a Security Defaults finding went unassessed, and its
    manual-review line says those controls have no automated test *or* an
    automated check that could not reach a verdict.

  A Security Defaults state that was not read is never read as disabled.
  Where the Conditional Access read shows no policy On (the only case in
  which Security Defaults can be enabled), AAD-1.1, 1.2, 1.3 and 11.1 are not
  assessed and are filed as a collection gap; with a policy On, the
  Conditional Access verdict stands. A response without a boolean
  `isEnabled` is recorded as not read. The Conditional Access console line
  says "Security Defaults on".

## v4.14.0 (2026-09-24)

Closes the remaining known issues that could make a report look worse, or
different, than the tenant actually is.

- **GDAP batch mode (#79).** The batch runner passes each client's
  `-TenantDomain` and `-KeepSession` to the assessment, so tenant pinning,
  the Purview `-DelegatedOrganization` and the shared Graph session all apply
  in batch mode. Per-client Graph switches request the full scope list, and
  Teams is disconnected between clients.
- **Third-party EDR (Cortex XDR).** `-ThirdPartyEDR` or `ThirdPartyEDR` in
  clients.json reports the Microsoft Defender endpoint checks (INT-1.5,
  INT-2.1, INT-2.2, DEV-2.x) as covered by that product (declared, not
  verified) and leaves them out of the score instead of scoring them as gaps.
  A Defender check that passed keeps its verdict. Works on `-FromResults`.
- **Consent.** AAD-8.2, AAD-11.3 and DEF-4.6 now name the Graph permission
  the tenant has not consented to. New `Grant-NRGGraphConsent.ps1` does the
  one-time consent (sign-in only). App-only onboarding requests all three.
- **Power Platform actually collects.** The admin module is Windows
  PowerShell 5.1 only and the old fallback called a cmdlet that does not
  exist, so PPL-* never collected. The collector now signs in to the Power
  Platform admin API in-process (one extra browser sign-in, same flow as
  Graph, no child process) and reads it over REST, pinned to the Graph
  tenant, with per-section status. PPL-2.2 and PPL-2.3 no longer score
  Partial from a setting that was never read.
- **Conditional Access tiers** (AAD-10.4, 11.4, 11.7, 11.8, 11.9): None ->
  Gap, Audit mode -> Partial, Enabled -> Satisfied.
- **Not configured is a Gap; unlicensed is not scored.** Controls that
  scored Partial (half credit) when nothing was configured now score Gap
  when the tenant holds the license, and are moved out of the score as an
  upgrade opportunity when it does not (Set-NRGLicenseGating). The license
  profile no longer reads Microsoft 365 Business Standard
  (O365_BUSINESS_PREMIUM) as Business Premium, and E3 tenants now satisfy
  "Business Premium or E3+".
- **False verdicts found by an evaluator-vs-collector audit:** AAD-1.2 read
  security defaults from a key nothing writes and printed "disabled"
  unread, and missed MFA required through authentication strengths;
  PVW-4.3 said "labels defined but none published" from a list never
  collected; DEF-4.5 / PVW-2.5 missed workloads because 'A, B' was split on
  the comma without trimming; INT-2.1 passed on an unverified branding
  declaration. Six Purview controls that could never produce a verdict now
  collect their data; PVW-2.4 / PVW-3.2 say plainly they need manual review.
- **`-RegisterApp` moved out of the read-only module** to `Onboard/`; the
  switch works as before. A test fails if any module-loaded file calls a
  Graph write cmdlet.
- **Defender judges the policies actually in force.** Exchange Online
  applies a custom policy whose rule is enabled, else an enabled preset,
  else the default / Built-in protection policy. The tool read the default
  policy only (or "any" policy): the Built-in protection Safe Links policy
  (click-through allowed, internal senders off, URL rewrite off) was called
  hardened; a custom policy turned off but applied by an enabled rule was
  ignored; and a preset covering everyone left the default's weaker values
  reported as the tenant's. Verdicts now cover every policy that can apply
  (Partial when some recipients are protected and some are not, naming
  which), and the default drops out only when an enabled rule provably
  covers every accepted domain. DEF-2.1 needs an enabled preset RULE (a
  custom policy named "Standard users" passed); DEF-2.2 reads
  SpamZapEnabled / PhishZapEnabled (the deprecated ZapEnabled was absent
  and failed the anti-spam section); DEF-2.4 no longer claims users cannot
  release quarantined phishing (Microsoft's default lets them); DEF-4.6
  does not count a scheduled simulation; DEF-4.7 no longer errors; a Safe
  Links / Safe Attachments read that failed is "not collected", not an
  Error scored as a failure, and not "not licensed" when licensing was not
  read.
- **Purview, Power Platform, Copilot.** PPL-1.1 ("Tenant Isolation
  Enabled") scored the number of environments and passed tenants with
  isolation off. PVW-2.1 read the admin audit log (always on in Exchange
  Online) instead of the Unified Audit Log. PVW-3.4 counted DLP policies
  instead of rules using sensitive information types. PVW-1.4 counted
  defined labels instead of published ones. PPL-3.1/3.2/3.5 no longer
  score gaps from Purview sections that did not run; simulation-only
  auto-labeling is not enforcement; the Copilot DLP location (Workload
  "Applications") is recognized; "AI" no longer matches "Email" in policy
  names; Copilot licensing is detected by service plan (the "M365_Copilot"
  SKU was missed) with every page of users read and guests excluded.
  PPL-3.4 is manual review — publishing channels are not readable, and an
  app's publisher domain is not one. PVW-2.2 says when policies exist but
  are off; PVW-4.2 with no one-year policy is a Gap.
- **Exchange controls read the setting they name.** EXO-3.5 and EXO-4.2
  read the mailbox-audit switch; they now read Unified Audit Log ingestion
  and `AdminAuditLogEnabled` (`Get-AdminAuditLogConfig`, pinned to the
  Exchange Online session). EXO-4.1 no longer scores `AuditLogAgeLimit`,
  which Microsoft says no longer governs retention (180 days by default,
  one year for E5); it flags a custom audit retention policy that shortens
  Exchange records instead. EXO-6.3 / EXO-7.3 flagged `AuditEnabled =
  False`, which Exchange ignores while organization auditing is on; they now
  read audit bypass associations, the setting that actually silences a
  user. EXO-4.3 reads `EnableATPForSPOTeamsODB` rather than "a Safe
  Attachments mail policy is on". EXO-3.2 accepts the default "User
  restricted from sending email" alert policy. EXO-5.3 never collected the
  allowed-sender lists, so it passed every tenant. EXO-1.3, 1.5, 1.7, 5.2
  and 5.3 judge the policies in force; 'Automatic' forwarding is not
  counted as blocked, and a remote-domain block alone is part-way because
  it does not stop admin-set mailbox forwarding. EXO-5.2 does not count
  users listed with action NoAction. EXO-1.4 treats a custom domain with no
  DKIM configuration as unsigned and reads the documented key-size fields.
  EXO-1.2 no longer reports SMTP AUTH enabled when `Get-TransportConfig` was
  not read. EXO-6.4 / EXO-7.4 do not claim an org-level disable that is not
  there, and report the full override count rather than the capped list.
  EXO-9.1 counted the MRM "Default MRM Policy" (on every mailbox, holds
  nothing) as a hold; it now reads organization-wide retention policies and
  per-mailbox exclusions. EXO-8.1 recognizes `smtp:*;1` as unscoped;
  EXO-8.2 does not give half credit for a recipient it could not resolve and
  no longer crashes on a single-domain tenant; DEF-5.1 reads spoofed-sender
  and IP allow entries and no longer crashes when it finds a never-expiring
  allow. EXO-1.5 and EXO-4.3 now carry their Defender for Office 365 Plan 1
  license requirement.
- **Teams controls score the setting they name.** TMS-1.4 scored the lobby
  and TMS-1.6 the screen-control setting; TMS-1.4 now reads
  `AllowExternalParticipantGiveRequestControl`, TMS-1.6 reads Teams guest
  access plus who may invite guests, and TMS-1.5 (a duplicate of TMS-2.3)
  reads whether retention covers the OneDrive / SharePoint locations holding
  recordings. TMS-3.2 passed lobby settings that admit guests, invitees or
  every federated organization. TMS-1.3 honors the org-wide
  `DisableAnonymousJoin` and the lobby. TMS-2.6, 3.1 and 3.3 read fields the
  collector never wrote (3.3 read a property that does not exist; the
  setting is `MeetingChatEnabledType`) and could never reach a verdict.
  TMS-2.7 called an allowlist Partial while TMS-1.1 / 4.3 called it
  Satisfied; all three now agree, with blocklist mode Partial. TMS-2.3 and
  SPO-2.5 include Egnyte. TMS-4.4 reads the events policy (town halls and
  webinars, both public by default) — Microsoft retired live events on June
  30, 2026. TMS-2.1 is reported retired (Skype consumer interop ended May 5,
  2025), TMS-2.5 as platform-enforced (external participants cannot record),
  TMS-2.2 as manual review. TMS-3.4 no longer reports "no DLP policies" when
  the DLP list was not read. The collector records per-section status and no
  longer defaults an unreturned federation setting to "disabled"; TMS-3.1
  carries its Teams Premium license requirement.
- **Intune controls count what enforces something.** Policies must be
  assigned (an unassigned draft passed INT-1.1, 2.1–2.5 and 4.1). Endpoint
  security templates are bucketed by template, not family: Credential Guard
  passed as LAPS and a USB-block Device Control policy as ASR rules. INT-1.2
  ("non-compliant devices blocked via CA") passed on any configuration
  profile, a Wi-Fi profile included; it now reads Conditional Access for a
  compliant-device requirement. INT-1.4 counted app CONFIGURATION policies
  as app protection. INT-3.1 and INT-4.2 passed on the enrollment
  configurations every tenant has by default; they now read what the
  restrictions block and the Windows Hello state. INT-4.3 reported overall
  compliance as "OS-version compliant" with no minimum OS rule anywhere.
  INT-3.3 counted the default PIN-retry and offline-wipe limits as
  conditional launch; it now needs a minimum OS version. INT-1.3 accepts
  "Require encryption of data storage"; INT-2.4 no longer accepts System
  Integrity Protection as FileVault; INT-4.4 reads iOS `passcodeRequired`.
  INT-1.5 no longer scores Partial from enrollment configurations. The
  collectors read every Graph field through the field helper — a missing
  `description` failed the whole compliance-policy section.
- **Not configured is never half credit (sweep).** AAD-4.3 (guest role at
  Microsoft's default) and AAD-11.5 (CAE strict mode off, the default) scored
  Partial; they are Gaps. AAD-11.6 scored Partial when the cross-tenant
  settings were not returned at all — half credit for data it never read — and
  is now not assessed. The DLP-coverage and retention-coverage controls no
  longer read an unread policy list as "none".
- **EXO-7.2 partial sweeps; EXO-2.3 / 2.4 existing mailboxes.** The inbox
  rule sweep stops at 2,000 mailboxes (`-InboxRuleScanLimit`) and recorded
  that it did, but nothing read it: a larger tenant got "no inbox rules
  forward externally" from a partial sweep. A clean result over part of the
  tenant, or with unreadable mailboxes, is now not assessed; disabled
  forwarding rules are named as disabled. POP / IMAP were judged on the CAS
  mailbox plans, which only set the default for new mailboxes; existing
  mailboxes are now counted too.
- **Endpoint checks.** DEV-4.1 (local administrators) and DEV-5.1 (OS
  build) are inventory and always reported Pass; they now report "requires
  manual verification" with each device's entry, including from older
  result files. Several result files for one device (an RMM share keeping a
  file per run) are reduced to the latest, so a laptop fixed since March no
  longer counts as failing. The firewall checks read the effective
  (ActiveStore) configuration — the local store flagged an untouched
  machine whose "NotConfigured" means Block — RDP / NLA read the Group
  Policy value first, an absent NLA value is the Windows default (required),
  and Windows LAPS with BackupDirectory 0 (disabled) is no longer a pass.
- **AAD-12.3 / AAD-12.4.** Stale accounts are judged on the last
  successful sign-in (a password-spray attempt made a departed user look
  active; a token-refresh-only user looked stale) and accounts created in
  the last 90 days are skipped. A tenant-wide grant of sign-in scopes only
  (openid, profile, email, offline_access, User.Read) is not a finding.
- **Identity verdicts corrected against Graph's documented shapes.**
  AAD-6.2 (Critical) read the user-consent setting from the wrong level of
  the authorization policy, so every tenant scored "consent restricted" —
  including tenants where users can consent to any app. Conditional Access:
  a pilot-group or Exchange-ActiveSync-only legacy block no longer passes
  AAD-1.1; an all-users MFA policy covers admins (AAD-1.3); blocking and
  risk-remediation policies count for AAD-1.4/1.5 (the collector now sends
  the Prefer header that reveals riskRemediation); "compliant OR MFA" does
  not enforce a device (AAD-2.3); a device-code policy must block
  (AAD-11.1); AAD-11.7 is judged on configuration, not a policy name
  containing "PAW"; a risk-only "every time" re-prompt is not a periodic
  sign-in frequency (AAD-10.4); token protection (beta shape), CAE strict
  mode, terms of use, device filters and workload-identity conditions are
  now collected, so AAD-11.4/11.5/11.7/11.8/11.9 can pass. AAD-1.2: MFA not
  required is a Gap however many users registered; partly required is
  Partial; the Entra Connect sync account is left out of the registration
  count. Roles: activated PIM and CA-excluded break-glass accounts are not
  standing access (AAD-3.2); eligible guests and synced accounts count
  (AAD-11.2, AAD-10.2, AAD-3.1); Global Administrator held by a group is
  reported as not assessed; built-in roles are recognized by template id
  when the role-definition read fails. Break-glass exclusion must cover
  every all-users / admin policy, and an unreadable exclusion group is
  unknown, not "not excluded". AAD-4.1/6.3/7.2 no longer score from failed
  reads; AAD-4.3 distinguishes the default guest role from Restricted
  Guest; number matching reads the setting's state (AAD-9.1); Authenticator
  phone sign-in counts as passwordless (AAD-9.2); a role access review
  created in the tutorial shape is recognized (AAD-8.2). AAD-5.1, AAD-5.2
  and AAD-10.3 now say plainly they need manual review — the data they read
  answered a different question. AAD-1.2 and AAD-3.1 carried bare NIST ids,
  so they were missing from the NIST family view and the SSP; they now
  carry their full citations.
- **The SSP no longer reports a requirement "Implemented" it did not
  check.** A requirement was derived Implemented when no mapped control had
  a Gap, even if most of them were NotApplicable (not collected, not
  licensed, or covered by a declared third-party EDR): 3.5.3 (MFA) read
  Implemented with one of fifteen controls actually passing. Implemented
  now requires every mapped control to have passed; each unscored control
  shows why. A client-attested status no longer counts as tool-verified.
- **Numbers derived from findings agree with the score.** The remediation
  roadmap and NIST improvement plan made every per-domain DNS finding its
  own fix (projected NIST coverage above 100%); both now plan one step per
  control. The score, the scope section and the SSP share one worst-state
  order, so a control passing on one domain and unread on another is no
  longer a pass in the ring and "not assessed" in the scope section. The
  Executive Overview no longer counts the 35 endpoint checks as assessed
  when no device results were supplied. Severity pills count controls, not
  findings. The Markdown summary and HTML score column show Errors, and the
  report no longer says Errors are excluded from coverage (they count as
  failures) or that "all assessed controls are satisfied" beside Partial or
  Error results. The XLSX NIST Families sheet includes endpoint verdicts.
- **"No automated test" means that.** A NotApplicable the scope section
  could not classify was reported as "no automated test — manual review",
  including controls that ran and found the feature off. Those now sit in
  their own "not applicable to this tenant" group with the reason stated.
- **DNS-2.1 .. 2.4 never read the collector's data.** The collector writes
  each domain as an ordered dictionary; those four evaluators only accepted
  a plain hashtable, so on every live run DNS-2.2 said "No CAA record" for a
  domain whose CAA had just been read, and DNS-2.1/2.3/2.4 never reached a
  verdict. A new test runs the real collector into the evaluators.
- **DNS records are read the way the RFCs define them.** Two SPF records,
  more than 10 lookup terms, and `+all`/bare `all` are failures (the last
  authorizes every sender, and scored half credit); `redirect=` is followed;
  no `all` is neutral, a Gap. Two DMARC records apply no policy; `p = reject`
  with spaces is reject (was read as p=none); `v=DMARC1` is case-exact;
  `p=quarantine` meets "Quarantine or Reject"; `sp=none` is Partial. A
  subdomain inherits its organizational domain's DMARC, its signed parent
  zone's DNSSEC and its parent's CAA, instead of false gaps. CAA with only
  `iodef` restricts nothing (Gap), only `issuewild` restricts wildcards
  (Partial). DKIM with only selector2 is Partial, not "no DKIM". An MTA-STS
  policy file that could not be fetched is not assessed rather than scored.
  Zero certificates in CT logs is not a gap; Google Trust Services and
  other common public CAs are no longer flagged as possible mis-issuance.
- **License detection reads service plans, not product names.** Unlicensed
  controls leave the score, so a detection miss hides a real gap. Checked
  against Microsoft's licensing reference, the old detection never marked
  EXO-9.1's requirement met on any tenant (the hold/retention control was
  never scored); read Microsoft 365 E5 as lacking Defender for Endpoint
  Plan 1; read Office 365 E3/E5 as holding Entra ID P1/P2 (they do not);
  labeled Office 365 E5 "Microsoft 365 E5"; and let any one compliance plan
  unlock every "E5 Compliance" control. `Config/license-service-plans.json`
  now maps each requirement, and each control where features differ
  (Customer Lockbox, Endpoint DLP, Audit Premium, ...), to the service plans
  that deliver it. Requirements corrected from the Purview and Defender
  service descriptions: audit retention (PVW-1.2), Copilot audit (PPL-3.5)
  and consent alert policies (DEF-4.3) are in every plan; hold/retention
  (EXO-9.1) is met by Exchange Online Archiving, which Business Premium
  includes; EDR (INT-2.1) is met by Defender for Business. When licensing
  was not read, the report says so instead of listing every gap as
  license-blocked, and the upgrade pitch names the license actually missing.
  The XLSX License Gaps sheet uses the same per-control test.
- **PVW-1.2 and PVW-1.3 scored each other's subject.** PVW-1.2 ("audit log
  retention of 90 days") scored DLP and PVW-1.3 ("DLP policy active")
  scored retention policies. Each now scores its own; DLP in test mode is
  Partial, none is a Gap.
- **SharePoint controls score the setting they name.** SPO-1.2 ("default
  sharing link not Anyone") scored legacy authentication, SPO-1.3 scored
  the sync restriction, SPO-1.4 and SPO-1.5 scored other unrelated settings.
  Each now reads its own setting (default link type, legacy auth, guest
  expiration, unmanaged-device access). Guest and link controls report
  NotApplicable on a tenant with external sharing off instead of raising
  gaps about links that cannot exist; the sync restriction needs its switch
  on (a leftover domain list is not a restriction); reauthentication needs
  email attestation on; a retention value that was not read is no longer
  "0 days".

## v4.13.0 (2026-09-24)

Accuracy + hardening release. Every fix below was found by running the tool
against a live tenant and checking verdicts against raw data, live DNS and
Microsoft documentation; each ships with a test that fails on the old code.

- **Scans are pinned to the requested tenant.** `-TenantDomain` and the Web
  GUI resolve the target tenant and abort before collecting if the sign-in
  lands anywhere else; Exchange gets `-DelegatedOrganization` for GDAP.
- **No false "audit log disabled".** `Get-AdminAuditLogConfig` (and
  `Get-Recipient`, `Get-TenantAllowBlockListItems`) now run in the Exchange
  Online session; Security & Compliance always reports UAL as off.
- **AAD-1.3** no longer counts any authentication strength as
  phishing-resistant. **AAD-10.2 / AAD-11.2** assessed again. **PIM
  (AAD-3.3-3.6)** scored per privileged role; GA approval assessable.
- **Every finding reaches NIST/CMMC/SSP rollups**; controls score once, not
  once per domain; MFA and shared-mailbox counts agree across controls.
- Defender / DKIM / Copilot collector crashes, compliance-matrix XLSX, and a
  set of false passes/gaps on failed collections (EXO-1.3, EXO-3.1, EXO-8.x,
  PVW-1.x, AAD-6.1, AAD-2.1, AAD-3.1, DEF-2.1) fixed.
- **Conditional Access "is there a policy" controls score in three tiers**
  (AAD-10.4, 11.4, 11.7, 11.8, 11.9): None -> Gap, Audit mode (report-only)
  -> Partial, Enabled -> Satisfied. Nothing configured used to earn half
  credit.
- `-RegisterApp` never overwrites an unreadable clients.json; Email-IR tests
  run in CI; standalone Tor-exit detection removed.

Earlier in this cycle:

- **Application (app-only) permissions are now assessed — AAD-15.1 / AAD-15.2.**
  AAD-12.4 reads `oauth2PermissionGrants` with consentType `AllPrincipals`,
  which is the **delegated** consent table: an app acting as a signed-in user.
  An app-only grant is an `appRoleAssignment` and is not in that table at all,
  so a malicious application permission returned **zero rows** from the
  endpoint AAD-12.4 queries and the report said the tenant was clean. That is
  the modern persistence and business-email-compromise route, and the tool was
  blind to it.
  The distinction is the whole point: an application permission is exercised
  with **no signed-in user**, so no MFA prompt fires, no Conditional Access
  policy applies, and the activity does not look like a person in the sign-in
  logs. `Mail.ReadWrite` app-only reads every mailbox; Exchange
  `full_access_as_app` takes full control of all of them;
  `RoleManagement.ReadWrite.Directory` makes the app Global Administrator;
  `Domain.ReadWrite.All` adds a federated domain and forges tokens for anyone.
  `Collectors/AAD/Invoke-NRGCollectAADAppPermissions.ps1` asks each high-value
  RESOURCE who holds a role on it (Microsoft Graph, Exchange Online,
  SharePoint) rather than asking every principal what it holds — three paged
  queries instead of hundreds. **No new Graph scope is required**, so there is
  no re-consent in any client tenant, and a test asserts that.
  `Config/app-permissions-risk.json` holds the risk judgement as reviewable
  data in two tiers, each entry carrying the reason it is rated; a permission
  in neither tier is collected and reported but **not scored**, because absence
  from the catalog means unrated, never safe. Microsoft first-party apps
  legitimately hold these, so they are excluded from the verdict and their
  count is stated in the finding — set aside, never silently dropped — while an
  app whose owner cannot be determined is scored rather than waved through.
  Every watched resource must report `Collected` before either control reaches
  a verdict: Exchange is where `full_access_as_app` lives, so scoring Graph
  alone and calling it clean would miss the worst grant in the product.
  Caught while building it: `@odata.nextLink` read through
  `Get-NRGNestedProperty` never resolves, because that helper splits its path
  on `.` and looks for `@odata` then `nextLink`. Paging stopped silently after
  page one, which would have reported a partial list as a full enumeration on
  any tenant large enough to page. It now reads through `Get-NRGObjectField`,
  and a test pins that a second page is followed.
  26 tests added; control count 202 -> 204.

- **The scope section misclassified its own blind spots.** A code review of the
  section added one commit earlier found five defects, all real. The worst:
  `Test-NRGLicenseRequirementMet` returns `$false` when there is **no SKU data**
  (deliberately — Upgrade Unlocks should over-report an upgrade need rather
  than hide one), and the classifier inverted it. So "we cannot tell how this
  tenant is licensed" became "licence gated, benign", and on any run where the
  licence profile did not populate — including every `-FromResults` republish —
  controls whose own `Detail` said *"EXO data not collected"* were reported as
  benign instead of "these are NOT passes". The honesty section had the
  dishonesty bug. Signals are now consulted only when positively present,
  strongest first: the evaluator's self-declared advisory marker, then hard
  evidence from the `CollectorDependency` raw data (only when raw data is
  populated — an empty map means replay, not universal failure), then licence
  on explicit evidence only, then prose last. Also fixed: `-Quick` drops
  evaluators on purpose, and their controls were reported as "produced no
  result at all… treat this as a tool fault" (they now get a
  `NotEvaluatedThisMode` bucket); the Markdown publisher omitted
  `-LicenseProfile` that the HTML publisher passed, so one run's two
  deliverables bucketed the same control differently; the prose pattern missed
  *"… collector did not run."* and *"Neither … produced data."*, reporting
  failed collectors as controls with no automated test; and `-FromResults` now
  restores `Coverage` and `RawData` into module state, so a republish no longer
  silently drops the "collectors that did not complete" block. The prose
  patterns are now derived empirically by running all 179 evaluators against
  empty state, and a test does exactly that and asserts every resulting
  `NotApplicable` lands in collection-failed or self-declared-advisory with
  nothing called licence gated — the test that would have caught four of the
  five. Six of its assertions fail against the previous commit.

- **The report now says what it did NOT assess.** `NotApplicable` is excluded
  from the compliance denominator, so a control that silently stops producing
  a verdict makes the score go **up** — which is the shape of every
  high-consequence bug this tool has had (the omitted `signInActivity`
  property, the missing PIM `SectionStatus`, the DNS lookup read as an absent
  record). In each case the score looked fine and nothing in the deliverable
  said the control had gone quiet. `Lib/Get-NRGAssessmentScope.ps1` sorts all
  202 controls into exactly one bucket — scored, licence-gated, collection
  failed, no automated test, or **no result at all** (the set difference
  `controls.json − findings`, which nothing computed before) — and renders as
  an **Assessment Scope and Limitations** section directly under the score in
  the HTML report (`id="scope"`) and in the Markdown summary, with
  plain-language limitations written for whoever signs the report rather than
  for the operator. It is a view, not a verdict: `NRG.AssessmentScope.Tests.ps1`
  (17 tests) pins that it emits no findings and moves no score, that the
  buckets sum with no control counted twice, that a 403/consent failure is
  classified as a collection failure rather than as advisory, that the worst
  state wins for multi-instance controls, that replayed result JSON classifies
  identically, and that the limitations text never says anything is compliant.

- **Export List Sync now exists in NRG.** `NRG.EvaluatorWiring.Tests.ps1` had
  said since it was written that "Export List Sync checks psd1<->psm1"; the
  twin repo had that check and this one did not. `Testing/NRG.ExportSync.Tests.ps1`
  pins `FunctionsToExport` (psd1) to `$script:ExportedFunctions` (psm1) as a set
  comparison in both directions with a duplicate check, requires every exported
  name to be DEFINED somewhere under `Lib/`, `Collectors/`, `Evaluators/`,
  `Publishers/` or `Email-IR/` (read from the AST, so it needs no Graph/EXO
  modules to run), and pins the README's "N exported functions" to the psm1
  count. `tools/Sync-ExportedFunctions.ps1 -Validate` runs the same check as an
  `export-sync` CI job; `-Fix` rewrites the psd1 list from the psm1. Porting it
  found a latent bug in the tool: `-Fix` located the end of the block with a
  non-greedy `.*?\)`, which stopped at the first `)` anywhere — inside the
  section comment "(Email-IR/ subtree)" — and wrote a manifest that no longer
  parsed. The block now ends at the `)` alone on a line at the block's own
  indentation, and the rewritten manifest is parsed on a temporary file and
  checked against the psm1 count before the real file is touched. Mutation
  tests confirmed the suite fails on a dropped psd1 entry and on an exported
  name with no definition.
- **A failed DNS lookup was reported as an absent record.** `Resolve-NRGDns`
  returned `@()` for any DoH response lacking an `Answer` and never read
  `Status` — but Cloudflare returns SERVFAIL as HTTP 200 with `Status: 2` and no
  `Answer`, so a failing resolver was indistinguishable from NXDOMAIN. Worse,
  that was a bare `return`, which also short-circuited the Google fallback and
  the `Resolve-DnsName` fallback beneath it: one transient SERVFAIL meant the
  healthy resolver was never asked. The DNS evaluators score an absent record as
  a **Gap**, so this told a client their SPF/DMARC/MTA-STS was missing when it
  was not — a false finding in the deliverable an MSP sells remediation from.
  Only Status 0 (NoError/NODATA) and 3 (NXDOMAIN) are now treated as
  authoritative "no record"; anything else falls through to the next provider.
  The resolver gained an optional `-Outcome` returning
  `Answered` / `NoRecord` / `LookupFailed`, the collector records it per record
  type in `LookupStatus`, and `Add-NRGDnsLookupFailedFinding` gates the seven
  evaluators that score absence (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC,
  CAA) so a failed lookup reports `NotApplicable`, with the control's NIST
  citations so the finding still reaches the family rollup. Review of the first
  version found four holes, all closed: a DoH body with no readable `Status`
  (proxy block page, captive portal) was read as `NoRecord` and never fell
  through; the `Resolve-DnsName` fallback mapped NXDOMAIN to `LookupFailed`
  (it throws Win32 9003/9501 for absence — now `NoRecord`), which would have
  made every DNS control unable to report a Gap wherever DoH is blocked;
  `LookupStatus` was assigned after each parse pipeline, so a throw in between
  left the gate fail-open on a live run (now initialised to `LookupFailed`);
  and the DKIM evaluator was not gated at all. Independent verification of
  those fixes found two more, both closed: the `Resolve-DnsName` fallback had
  no Section/Type filter, so a NODATA response delivered as the zone's SOA in
  the Authority section was stringified into a truthy "record" and reported
  `Answered` — a DS lookup on an unsigned zone scored DNS-1.6 Satisfied on a
  DoH-blocked workstation (only Answer-section rows of the requested type now
  count); and `"Status": null` read as Status 0 because `$null -as [int]` is
  `0` (now a failure that falls through). In the collector, `Failed` coverage
  was unreachable for a single-domain tenant — the per-domain entry list was
  built with the `$x = if (...) { @(...) }` trap, so the lone hashtable's
  `.Count` was its key count and every-lookup-failed reported `Partial` on
  the most common tenant shape; the per-record throw paths were silent (five
  empty catches, three that never registered an exception) so "see
  Exceptions" pointed at an empty array; and the outcome was written
  unvalidated, so a blank would have replaced the fail-closed default and
  opened the gate. All three closed and pinned by a new
  `NRG.DnsCollector.Tests.ps1`, which drives the collector through a mocked
  resolver injected into module scope — the first test to exercise the
  collector at all. An adversarial-input pass over the resolver then closed
  one more false verdict: the `Resolve-DnsName` fallback rendered CAA and DS
  rows as PSObject text (`@{Section=Answer; Type=CAA; …}`), which the
  collector's `FLAGS TAG "VALUE"` parse could never match, so a present CAA
  record scored DNS-2.2 as "No CAA record published" wherever DoH is blocked;
  every fallback row is now rendered in the DoH text shape and a row that
  cannot be is a `LookupFailed`, never an `Answered` with unusable data. Same
  pass hardened `Status` parsing (whole numbers and digit strings only —
  `''`, `$false` and floats no longer coerce to a code; an `XmlDocument` body
  is rejected), added Win32 9701 `DNS_ERROR_RECORD_DOES_NOT_EXIST` to the
  absence codes, made Answer rows lacking `type`/`data` skip rather than fail
  the provider, and fixed TXT parsing for RFC 1035 `\"` escapes and Google's
  unquoted pre-joined form. `-Reason` now carries which
  providers failed and why into `$d.Errors` and the Exceptions array, and DNS
  coverage registers `Partial`/`Failed` instead of `Collected` on a run in
  which lookups did not complete.
  Absent `LookupStatus` counts as collected, so replayed older JSON is
  unaffected. The multi-segment TXT join was checked and is correct — a long
  SPF or DMARC record split across character-strings is reassembled before
  parsing.
- **Graph omits `signInActivity` entirely for users who never signed in.** Documented
  on the user resource type: the property "isn't returned for a user who never
  signed in or last signed in before April 2020." Under StrictMode the nested
  read `$_.signInActivity.lastSignInDateTime ?? ''` therefore THREW on exactly the
  accounts the guest and stale-account queries exist to find, failing the whole
  section — so those controls reported `NotApplicable` on any tenant with a single
  never-signed-in guest, which is nearly all of them. Silently non-functional
  rather than falsely clean, and nothing surfaced it, because `NotApplicable` is
  excluded from the score's denominator. All nested API reads now go through
  `Get-NRGNestedProperty`, enforced statically. Sign-in timestamps now parse with
  `TryParse` + `InvariantCulture` + `RoundtripKind` rather than a bare `[datetime]`
  cast, which was culture-sensitive on whatever workstation the tool runs from.
- **AAD-3.2 claimed "No permanent privileged role assignments" without the role
  data.** `$permanentPriv` merely stayed empty when `AAD-DirectoryRoles` was
  missing or its section had not landed, and the Satisfied branch fired anyway —
  a clean bill of health on a privilege-escalation control, worded identically to
  a genuinely clean tenant. It now reports `NotApplicable` without that evidence.
  The PIM half had the same hole: `AAD-PIMSchedules` pre-initialises every section
  to `@()` and published no `SectionStatus`, so a failed eligible-schedule query
  read as "no PIM adoption" and scored `Partial` — half credit for a verdict never
  computed. The collector now publishes `SectionStatus` and the evaluator consults
  it.
- **The XLSX compliance matrix was silently not produced on `-FromResults`.**
  `$Metadata.Operator ?? ''` throws under StrictMode when the key is absent —
  the missing-key error fires before `??` can supply the default. The live path
  sets `Operator`; the replay path builds a fallback carrying only
  TenantDomain / AssessmentDate / ToolVersion. Because the entry point wraps
  each publisher in a `try/catch` that degrades to a warning, the deliverable
  just did not exist, with one line in console output and no other signal. Six
  publishers carried the pattern; all now read metadata through
  `Get-NRGObjectField`, and a static test fails on any new occurrence.
- **The summary sheets did not account for Error findings.** Errors are scored
  as failures and sit in the denominator, but the NIST matrix Summary (XLSX and
  Markdown) and the compliance-matrix Summary listed only met / partial / gaps /
  not-assessable — so a reader adding the rows came up short of the finding
  count with no way to tell whether the missing rows were passes or failures.
  The per-family and per-control rollups already carried an Error column; the
  headline summaries did not, because `Error` was never placed in the XLSX
  payload. The compliance-matrix summary now also prints the arithmetic
  (`41+40+41+40+40=202`) so the invariant is visible rather than implied.
- **External-recipient classification was wrong for the shape Exchange actually
  returns.** The parser split a recipient string on `@` and required exactly two
  parts. Exchange renders a rule recipient as `"user@dom.tld"
  [SMTP:user@dom.tld]` — the address appears **twice**, so the split yields three
  parts and the guard returned "internal" for **every genuine external rule
  recipient**. Mailbox forwarding parsed correctly only by luck of having one
  `@`. EXO-7.2 therefore reported a clean bill of health on tenants with live
  external forwarding rules: the sweep ran, `SectionStatus` said `Collected`, and
  every honesty guard passed — the list was not empty-from-failure, it was
  empty-from-wrong-answer. Extracted to `Lib/Get-NRGRecipientClass.ps1` with a
  dedicated suite covering the real shapes, because the old parser had **no test
  coverage at all**: every fixture fed the evaluators a pre-computed
  `IsExternal` flag and never exercised it.
- **Classification is now tri-state.** A boolean collapsed "known internal" and
  "could not tell" into the same, safe-looking answer. A legacy `[EX:/o=…]` DN
  can be an in-tenant user or a mail contact resolving anywhere, and the string
  cannot say which — so it is resolved through `Get-Recipient`, and where
  resolution fails it reports `Unresolved` and the control reports
  `NotApplicable` rather than clean. Same rule `SectionStatus` applies to an
  empty list.
- **EXO-6.1 and EXO-7.1 scored the wrong set.** Both read `ForwardingMailboxes`
  unfiltered and reported the total as "forwarding externally", discarding the
  `IsExternal` the collector had already computed — so internal delegation
  forwarding produced a Critical gap on correctly-configured tenants. EXO-7.2
  applied the filter correctly thirty lines away in the same file.
- **`ForwardingAddress` mailboxes were never collected.** The filter named only
  `ForwardingSmtpAddress`, so every mailbox forwarding via the other property was
  invisible to the whole assessment. `ForwardingAddress` points at a recipient
  object, and a mail contact is a recipient object resolving to an external
  address — so the blind spot covered forwarding straight out of the tenant.
  Both properties are now collected, one row per mechanism (a mailbox can carry
  both), and findings count distinct mailboxes rather than rows.
- **Inbox-rule sweep sees hidden rules and no longer swallows "contains errors".**
  `-IncludeHidden` (probed, not assumed — an older EXO module lacking it would
  have failed the whole sweep) surfaces rules planted via EWS or Graph, which is
  the actual attacker path. Exchange *warns* rather than throws on a rule it
  cannot interpret and returns it with empty action properties; those warnings
  were discarded, turning a rule nobody could read into a rule that forwards
  nowhere. They are now collected as `UnparseableRules` and EXO-7.2 degrades to
  `NotApplicable` instead of claiming clean. Mailboxes whose rule query threw are
  counted too.
- **NIST-first reporting.** `Invoke-NRGAssessment.ps1 -Framework <NIST|CIS|SCuBA|CMMC|All>`
  selects which framework cards the HTML report presents. **NRG defaults to
  NIST; NLS defaults to All** — the one deliberate behavioral difference
  between the twins, pinned in each repo by its own test because a careless
  mirror would silently flip it and the report would still render and still
  score correctly while showing the wrong practice's frameworks to a client.
  Narrowing the report never narrows the assessment: every control keeps every
  citation, every framework is still scored, and the results JSON and XLSX
  matrix are identical either way. A test renders the report both ways and
  asserts no framework score moves.
- **Standalone NIST-only HTML report.** `-NISTMatrix` now emits a self-contained
  HTML page beside the Markdown and XLSX — family table, full control matrix,
  not-assessable list and the unscored physical/device section — that names no
  other framework anywhere on it. A test greps for CIS, SCuBA, CMMC, ISO 27001,
  SOC 2, HIPAA, PCI DSS and MITRE and fails on any leak, because a stray
  framework name in one table cell undermines the whole premise of the document.
- **The framework grid sizes itself.** `.fw-grid` interpolated the column count
  from a hardcoded 4, so a single-framework report rendered one card at quarter
  width with three empty columns beside it.

- **Endpoint device compliance scanner (`DEV-*`, 35 checks).** The tenant half of
  the assessment reads Intune POLICY; this reads device STATE. `Device/
  Invoke-NRGDeviceCompliance.ps1` runs on the endpoint (RMM-deployed, as SYSTEM),
  writes one JSON result, and `-DeviceResults <folder>` on the assessment ingests
  a folder of them. Findings aggregate per control with failing hostnames in
  AffectedObjects — one row saying "41 of 60 failing", not 2,100 rows nobody
  reads — and each maps to 800-53 so device findings land in the same report,
  score and NIST family rollup as everything else.
  Checks span encryption and boot integrity (BitLocker, TPM, Secure Boot, VBS),
  malware defense (real-time protection, tamper protection, ASR, controlled
  folder access, MDE onboarding), network exposure (firewall, SMBv1, LLMNR, RDP
  NLA), accounts (local admins, RID 500/501, LAPS), patch state, session lock,
  legacy surface and audit policy.
- **The endpoint script is Windows PowerShell 5.1** — stock Windows ships 5.1,
  not 7 — and is the single carve-out from the repo-wide `#Requires -Version 7`
  floor. The security suite scopes that exception to the top-level `Device/`
  folder and asserts it EARNS it: no MSHTML, no COM, no Invoke-Expression, no
  network. A separate static guard pins no PS7-only syntax, no module import,
  and read-only behavior apart from the single result write.
- **Elevation is reported, never assumed.** BitLocker, TPM, Secure Boot and the
  audit policy return nothing without admin rights, which is indistinguishable
  from "not configured". Those emit NotAssessed and are excluded from the fleet
  denominator, so a control reads "2 of 5 compliant — 1 device could not run
  this check" rather than inventing a pass or a failure for a machine nobody
  measured.
- **`$rows = if (...) { @(...) } else { @() }` assigns `$null`.** An if-block
  yielding an empty array is enumerated away by the pipeline, so `$rows.Count`
  threw under StrictMode for every control absent from a result file. Caught by
  the new suite before it shipped; build such variables in two statements.
- **A device control that genuinely does not apply now says so.** "RDP disabled
  on every machine" and "BitLocker unreadable everywhere" both report
  NotApplicable, but the first is good news and the second is a blind spot, and
  the detail now distinguishes them.

- **Managed device build standard (`Config/device-baseline.json`).** The device
  guide answers "what does 800-53 require"; this answers "what do I do to this
  laptop, and in what order". 27 requirements across five lifecycle stages —
  procurement, provisioning, hardening, in service, offboarding — of which 23
  are mandatory. Rendered by `Publish-NRGDeviceBaseline.ps1` as a printable
  checklist plus the reasoning underneath, and emitted alongside the guide by
  `New-NRGDeviceGuide.ps1`. Same no-network contract, statically enforced.
  Every requirement states why it exists, how to do it, the 800-53 control it
  satisfies, and whether the assessment can verify it — roughly a third cannot
  be checked from a tenant (BIOS passwords, firmware settings, certificates of
  destruction) and those rows say so rather than letting a reader assume the
  scan covers them. Tests pin that every `VerifiedBy` exists in controls.json
  and every `Nist` entry resolves in the 800-53 catalog; both rot silently
  otherwise.
- **Two more instances of the PowerShell backtick trap**, caught before they
  shipped this time. A backtick inside a double-quoted string is the escape
  character, so ```M``` lost its code formatting and ```$(...)``` escaped the
  interpolation outright, emitting the literal source text. A `\"` in the same
  file was worse — a backslash is not a PowerShell escape, so it terminated the
  string and broke the parse.

- **Device guide — reference material, no scanning (`New-NRGDeviceGuide.ps1`).**
  Not everything is a scan. This renders `Config/nist-physical.json` into a
  printable NIST device and endpoint guide — 31 controls across five areas with
  98 implementation options, as Markdown plus self-contained HTML with print
  styling and no external assets. It **connects to nothing**: no sign-in, no
  Graph, no Exchange Online, no endpoint touched. That independence is the
  point — the guide is usable before a tenant is attached, during a sales
  conversation, and on a site with nothing open. `-ResultsPath` optionally
  annotates it with a prior run's verdicts.
  Two invariants are enforced by test, because both are easy to break by
  accident: a static guard fails the build if `Invoke-NRGGraphRequest`,
  `Connect-MgGraph`, `Invoke-RestMethod` or friends ever appear in either file;
  and supplying findings may change what the guide reports as *already done* but
  never what it *recommends* — a test diffs the rendered options with and
  without findings and requires them identical, so two clients with the same
  obligations cannot get different advice because one happened to be scanned.
- **The guide claimed assessment results it never had.** `@($null).Count` is 1,
  not 0, so an omitted `-Findings` still counted as "findings supplied" and
  every control printed "Assessment result: Not assessed" against an assessment
  that had never run. Caught by the test asserting the no-findings guide carries
  no verdicts at all.
- **`New-Item -ItemType Directory -Path` replaced with
  `[IO.Directory]::CreateDirectory`.** `New-Item` has no `-LiteralPath` overload
  and its `-Path` interprets wildcards, so an output directory containing `[`
  or `]` failed outright — and it violated the repo's own ASVS V12.3.1
  literal-path invariant, which the static security suite caught.

- **Standalone NIST SP 800-53 Rev 5 matrix (`-NISTMatrix`).** Clients assessed
  against 800-53 should not have to read their posture out of a multi-framework
  report. `Publish-NRGNISTMatrix.ps1` emits a single-framework deliverable from
  the same run — Markdown always, XLSX when openpyxl is present — across six
  sheets: Summary, Control Matrix (one row per 800-53 control and the tenant
  control evidencing it), By Control, By Family, Physical & Device, and Not
  Assessed. Official Rev 5 titles come from a new
  `Config/nist-800-53-catalog.json`, because a row reading `AC-6(9)  Gap` is not
  something an auditor can work from. `-AllFiles` implies the switch.
  **Strictly additive:** `Publish-NRGComplianceMatrix` keeps all ten frameworks,
  no existing output changes, and a test asserts that publishing the NIST matrix
  does not move the CIS, SCuBA or CMMC score by a point.
- **The matrix refuses to overstate its scope.** The score is labeled as
  coverage of the 57 controls the tool exercises, not 800-53 baseline
  completion. The physical/media/personnel section stays unscored. Controls that
  came back `NotApplicable` get their own sheet stating that a missing license or
  an unconnected service is neither a pass nor a gap — a matrix that omits what
  it could not evaluate reads as full coverage of a smaller scope.
- **Rollup tables gained an Error column.** Met + Partial + Gap + N/A did not
  reach Assessed on any tenant with a thrown evaluator, so a reader adding a row
  up came short with no way to tell whether the missing rows were passes or
  failures. Fixed in the NIST matrix, the HTML family table and the Markdown
  summary; the XLSX family sheet already had it.
- **Two backticked terms lost their code formatting in the NIST matrix.** A
  backtick inside a PowerShell double-quoted string is the escape character. The
  regression test asserts with `.Contains` and an explicit character, because a
  backtick is *also* the escape character in a `-like` wildcard — the obvious
  `-BeLike '*`x`*'` assertion silently tests for something else.

- **NIST SP 800-53 Rev 5 coverage rolled up by control family.** The report scored
  NIST as one aggregate percentage, which tells a reader working an 800-53,
  FedRAMP, or CMMC assessment nothing about WHICH families are weak — every other
  view groups by M365 workload, the engineer's lens rather than the auditor's.
  All 195 controls already carried a `References.NIST` citation, so only the
  rollup was missing. `Lib/Get-NRGNISTFamilyCoverage.ps1` groups findings by
  family (12 families, 57 distinct 800-53 controls) and by individual control,
  reusing `Get-NRGCoverageScore` so family scores use the identical formula and
  denominator rules as every other score in the tool. Renders in the HTML report
  (`id="nist-families"`), the Markdown summary, and a `NIST Families` sheet in
  the XLSX matrix. A finding citing controls in two families counts in each — so
  family rows do not sum to the assessment total, which every surface states on
  the page. `NotApplicable` stays out of the denominator, and a family with
  nothing assessable reads "Not assessed", never a red 0%.
- **Physical, media and device 800-53 controls now stated explicitly.** A tenant
  scan can evidence endpoint posture and cannot see a locked server room, a
  certificate of destruction, or a returned badge. Omitting those controls
  silently was the dangerous option: a reader looking at a clean family table
  would reasonably infer the physical families had been assessed and passed.
  `Config/nist-physical.json` defines 31 controls across AC, CM, IA, MA, MP, PE,
  PS, SC and SI, each naming the device aspect it covers, the tool controls that
  evidence it, the evidence an assessor must collect off-tenant, and two or more
  implementation options. Scopes: Tenant (10), Hybrid (7), Attested (14).
  Nothing in the section is scored — Attested rows always read "Attestation
  required", never Satisfied and never Partial.
- **PPL-1.2 crashed the whole Power Platform evaluator under StrictMode.**
  `$d.DLPAvailable`, `$d.Environments` and `$d.DLPPolicies` were read by direct
  dot-access; a `Data` block missing any of them threw, and because all four
  PPL-1.x controls share one function the throw took PPL-1.1, PPL-1.2 and
  PPL-1.3 down with it. Same class as the seven Conditional Access crashes: a
  guard that assumes a field exists in order to check whether it exists.
- **Seven paid-off entries removed from the coverage-debt list.** DEF-3.4,
  DEF-4.3, EXO-2.6, EXO-3.4, PPL-1.3, SPO-2.5 and TMS-3.4 genuinely discriminate
  now but were still listed in `coverage-exceptions.psd1`.
- **A Copilot tenant could be told, on its own report, that it needs to buy
  Copilot.** LicenseRequirement matching is exact and the controls.json string
  lost its price suffix while the suppression set kept the bare form.
  `Test-NRGLicenseRequirementMet` now retries once with a trailing price
  parenthetical stripped — narrowly, requiring a currency amount inside it, so
  qualifiers like "(add-on)" that distinguish real requirements are never
  collapsed.

- **Eliminated the false-compliance bug class (25 controls).** Collectors that run
  several independent queries wrap each in its own try/catch, then set
  `Success = $true` regardless — so an EMPTY result list was ambiguous between
  "queried, found nothing" and "the query failed", and evaluators were reading it
  as compliance. A throttled or 403'd `Get-Mailbox` therefore reported "No
  mailboxes are configured with an external forwarding address" and "No inbox
  rules forward mail externally" — a clean bill of health on the primary BEC
  exfiltration and persistence checks. Collectors now publish
  `Data.SectionStatus` (NotRun/Collected/Failed) and evaluators consult it
  before concluding Satisfied, reporting NotApplicable with a re-run prompt
  instead. Fixed across EXO-6.1/6.2/6.3/6.4, EXO-7.2, AAD-3.1, AAD-10.2,
  AAD-11.2, AAD-12.2/12.3/12.4. AAD-3.1 also fixed in the other direction: it
  reported "fewer than 2 Global Administrators" when the role read failed, a
  false alarm that costs as much credibility as a false pass.
- **Advisory controls no longer inflate the score.** 11 controls with no
  programmatic check emitted `Partial`, worth 0.5 each toward the compliance
  score — free credit on every tenant for verdicts never computed. All now
  `NotApplicable` (excluded from the denominator) and still surfaced as manual
  review. Enforced by a new static AST guard.
- **7 placeholder controls implemented for real**, coverage 184 -> 191 of 195:
  EXO-2.6 (shared mailbox sign-in, evidence-graded: confirmed via Entra = Gap,
  license-heuristic = Partial), DEF-3.4 and DEF-4.3 (alert policy notification
  coverage via `Get-ProtectionAlert`), EXO-3.4 (unusual mail volume alerting),
  TMS-3.4 (Teams DLP coverage), PPL-1.3 (environment creation restriction via
  `Get-TenantSettings`). SPO-2.5 re-scoped to the connector surface that is
  actually readable, with every finding stating which surface it verified.
- **EXO-4.4 no longer contradicts itself:** passed BulkThreshold 7 while its own
  remediation instructed 6. Now flags above 6. Changes client-visible verdicts
  for tenants on the Microsoft default.
- **Fixed 66 controls declaring raw-data keys no collector produces**
  (`Teams-Config`, `Purview-AuditConfig`, `SharePoint-TenantSettings`,
  `PowerPlatform-DLP`, ...) plus one orphan read (`AAD-Roles`, real key
  `AAD-DirectoryRoles`). Harmless at runtime today, structurally misleading for
  anything built on the metadata.
- **Five new CI suites:** docs-freshness (headline counts computed from source,
  so no README number can go stale), HTML report render + XSS-escaping smoke
  test, evaluator honesty (no Satisfied/Partial on uncollected data),
  collector contract (every declared dependency is a real collector key), and
  golden fixtures pinning both-direction verdicts across the Critical, BEC,
  ransomware and privilege-escalation control paths.
- StrictMode safety: external cmdlet output whose shape is not guaranteed now
  reads through `Get-*ObjectField` — direct dot-access throws before a `??`
  default can apply, which would have silently disabled three new controls.

- **Framework accuracy:** corrected 70 systematically-mismatched SCuBA citations
  against the ScubaGear v1.8.0 baseline text (34 remapped, 36 removed); fixed
  7 CMMC 2.0 domain/level errors across 64 rows; all six frameworks now
  CI-validated against bundled authoritative ID lists.
- **Fixed a real PS 7.0–7.4 crash:** StrictMode throws on dot-access to missing
  hashtable keys — every collector paging loop (`$resp.'@odata.nextLink'`)
  crashed on single-page responses for operators on ≤7.4 (PS 7.5 masked it).
  All paging/@odata reads switched to null-safe indexer form.
- **11 controls made actionable** (were placeholder NotApplicable): INT-3.3,
  PPL-2.1, TMS-2.8/4.1/4.4, AAD-11.3, DEF-4.6, EXO-5.1/5.2, plus honest
  advisories for DEF-4.4/SPO-2.4. Three new read-only Graph scopes
  (IdentityRiskyServicePrincipal.Read.All, AttackSimulation.Read.All, AccessReview.Read.All — require
  one-time admin re-consent per tenant); optional SharePoint Management Shell
  path for SPO-2.2/2.6/3.2/3.4.
- **CI now gates on the full test suite** (220 tests / 10 files — previously 1)
  and enforces JSON Schemas for `controls.json` (schema v2, rewritten to match
  the real control shape) and `clients.json` (new).
- Manifest MaximumVersion caps on Graph.Authentication (<3.0) and
  ExchangeOnlineManagement (<4.0).
- Release pipeline: packaged zip + SHA256SUMS + SBOM attached to a draft
  GitHub Release on `v*` tags; categorized release notes (`.github/release.yml`).
- README refreshed to match shipped reality (counts, workflows, entry points).

## v4.12.1 (2026-06-11)

Port of NLS-Assessment v4.12.1 (security fixes + EMAIL-4.x persistence checks + batch triage sweep). NRG-named throughout.

### Security
- recipients.csv formula-injection neutralized (cells starting with = + - @ tab CR get an apostrophe prefix; Pester-pinned).
- Email-IR report CSP tightened: script-src 'none' (no scripts exist in these reports; browser now enforces it).

### Added
- `Invoke-NRGEmailCollectUserSecurity` collector — per-user OAuth2 grants + registered auth methods (`IR-UserConsents` / `IR-UserAuthMethods`), GET-only, -TargetUpn admin/delegated pivot.
- `EMAIL-4.1 Test-NRGEmailControl-OAuthConsents` — illicit-consent persistence (survives password reset + MFA re-enrollment); Critical for mail/file write-or-send scopes.
- `EMAIL-4.2 Test-NRGEmailControl-AuthMethods` — attacker-added MFA detection; full method inventory for the containment call; flags >1 phone + methods registered in last 14 days.
- `UserAuthenticationMethod.Read.All` added to `Connect-NRGEmailAdminServices` (grouped with mail scopes; -SkipMailDive doesn't prompt for it).
- `Invoke-NRGBatchSignInTriage.ps1` — the "morning sweep": triage every active clients.json tenant, batch summary with CRITICAL-IOCS clients first, exit 10 on any critical IoCs.
- 7 new Pester cases. ModuleVersion 4.12.0 -> 4.12.1; exports 252 -> 255 (psd1+psm1 in sync).

## v4.12.0 (2026-06-11)

Port of NLS-Assessment v4.12.0 — Email Account Assessment mode (Email-IR/ subtree, sign-in triage, per-user mailbox IR, Containment & Recovery Runbook). See Email-IR/README.md.

## v4.11.1 (2026-06-03)

**Release scope:** combined v4.11.0 + v4.11.1 catch-up release ported from NLS-Assessment. v4.11.0 adds the Monthly Compliance Report publisher (new recurring MSP deliverable). v4.11.1 is a polish pass that drives PSScriptAnalyzer warning count from **127 → 0** with no behavior changes — one real bug fixed, 11 unused-variable removals, two new `PSScriptAnalyzerSettings.psd1` suppressions (each with rationale + sunset path), documentation drift corrected.

### Added — Monthly Compliance Report publisher (v4.11.0)

New recurring MSP deliverable, distinct from the one-shot assessment HTML. HIPAA-framed, designed for Business Associate documentation trail and client-facing monthly status reporting.

- **`Publishers/Publish-NRGMonthlyReport.ps1`** — emits a self-contained HTML monthly report + sibling JSON state file. Sections: Posture Snapshot (score ring + state bars + baseline/trend note), Work Completed This Period, In Progress, Queued / Roadmap, Residual Risk Statement (Critical/High/Total open + license-blocked callout), HIPAA Defensibility Note (§164.308(a)(1) ongoing risk-management documentation).
- **`Config/monthly-delta/`** — per-month per-tenant operator-maintained `.psd1` files driving the three status tables. Each row maps to a control via ControlId; HIPAA safeguard citation auto-pulled from `controls.json` `FrameworkIds` (HIPAA-prefixed entry).
- **`Config/monthly-delta/EXAMPLE-example.com-2026-05.psd1`** — reference delta showing supported shape.
- **CLI flags on `Invoke-NRGAssessment.ps1`**: `-MonthlyReport`, `-MonthlyDeltaPath`, `-MonthlyPriorPath` (optional, omit on baseline). Path-traversal + missing-file `ValidateScript` guards match `-FromResults` pattern.
- **`Testing/NRG.MonthlyReport.Tests.ps1`** — 12-case Pester suite. Pins baseline-vs-trend rendering, JSON state shape (next month's input), score formula via `Get-NRGCoverageScore -ErrorHandling Gap`, defensive input handling (missing file, path traversal, malformed delta), empty-arrays graceful render, XSS escaping on operator-supplied delta strings.
- **Module exports**: `Publish-NRGMonthlyReport` added (count 230 → 231).

Design notes:

- Self-contained — no external tracking system dependency. State lives in two artifacts the operator manages: the per-month delta `.psd1` + the previous month's output JSON (auto-produced).
- Score uses `-ErrorHandling Gap` to match the HTML assessment report's score ring (so monthly score never silently disagrees with the main HTML deliverable).
- XSS guard via `ConvertTo-NRGHtmlSafe` (or inline fallback when the helper isn't loaded). Every operator-supplied string flows through.
- HIPAA citation lookup is best-effort; missing citations render as '—' rather than blocking the row.

### Fixed — real bug (v4.11.1)

- **`Publishers/Publish-NRGMonthlyReport.ps1` license callout had a dead `$controlsWord` variable** — the singular/plural switch was assigned (`if (1) {'control'} else {'controls'}`) but never interpolated into the rendered text. On tenants with exactly 1 license-blocked control, the callout would have read "1 of the open gaps cannot be remediated" (grammar-correct by accident only because the original wording said "of the open gaps" generically). Reworked the sentence to actually use the singular/plural word: "1 control cannot be remediated" vs "N controls cannot be remediated".

### Fixed — runspace scope warning (v4.11.1)

- **`Lib/Start-NRGWebServer.ps1` browser auto-launch ScriptBlock** flagged by `PSUseUsingScopeModifierInNewRunspaces`. The `param($u)/-ArgumentList $url` pattern works but is non-idiomatic and the warning was real (PSA couldn't see the param binding through the ScriptBlock boundary in some edge cases). Switched to `$using:url` — same behavior, drops the warning, more idiomatic PS7. Also added a `Write-Verbose` to the inner catch so a failed `Start-Process` surfaces under `-Verbose`.

### Cleanup — dead-code removal (11 sites, v4.11.1)

Removed 11 unused-variable assignments left over from prior refactors. None changed observable behavior; all were `$x = <expr>` followed by zero reads:

- `Invoke-NRGAssessment.ps1:194` — `$resolvedOutput` (replaced with `$null = ...` to preserve the side-effecting path-format validation while making the discard explicit; restoring the intended bounds-check is a future-PR concern).
- `Evaluators/Test-NRGControlDefender.ps1` — `$sl`, `$sa` (Safe Links / Safe Attachments raw reads, leftover from a refactor that moved those into separate evaluators), `$ca` (MDCA-via-CA-policy proxy that became advisory-only).
- `Collectors/AAD/Invoke-NRGCollectAADPIM.ps1:30` — `$testResp` (probe response value never inspected; only the absence of a thrown exception matters; replaced with `$null = Invoke-MgGraphRequest ...` to make the intentional discard explicit).
- `Publishers/Publish-NRGAssessmentSummary.ps1:69` + `Publish-NRGRemediationPlaybook.ps1:294` — `$scored` (extracted in v4.10.1 alongside the other coverage values but never referenced; only `$total` and `$score` make it into the rendered output).
- `Publishers/Publish-NRGDeltaReport.ps1:247` — `$toolVer` (escaped via `EscMdStrict` but the resulting variable was never used).
- `Publishers/Publish-NRGRemediationScript.ps1:54-56,245` — `$date`, `$version`, `$opUPN`, `$titleL` (header-block remnants from an earlier rendering pass).

### PSScriptAnalyzer suppressions added (v4.11.1)

Two rules suppressed in `PSScriptAnalyzerSettings.psd1`, each with rationale + a sunset condition per the existing suppression policy:

- **`PSUseBOMForUnicodeEncodedFile`** — UTF-8 without BOM is the canonical encoding for PowerShell 7. Every script in this repo has `#Requires -Version 7.0`. The rule targets PS 5.1 compatibility, which we don't support. Drops 72 false positives.
- **`PSAvoidUsingEmptyCatchBlock`** — all 40 existing empty catches are intentional defensive swallows around best-effort operations (DNS record absence, service disconnect cleanup, best-effort version reads, browser auto-launch fallbacks). Each already has `-ErrorAction SilentlyContinue` on the wrapped cmdlet AND the catch is double-defense.

Both suppressions list a "re-evaluate when…" condition so they're explicit technical-debt markers, not silent erosion.

### Documentation drift corrected (v4.11.1)

- `CLAUDE.md`: version line bumped `4.10.1 → 4.11.1`.
- `README.md`: footer bumped `v4.10.1 → v4.11.1`.

### Verification

- All changed files parse cleanly (0 syntax errors).
- PSScriptAnalyzer: **0 Errors, 0 Warnings** (target state for the polish release).
- Helper smoke test passes: `Publish-NRGMonthlyReport` runs against the example delta file and produces valid HTML + JSON outputs.
- ModuleVersion: 4.10.1 → 4.11.1 (jumps past 4.11.0 since both v4.11.0 and v4.11.1 land in this combined release).

## v4.10.1 (2026-05-31)

**Release scope:** further hardening pass that addresses the 3 deferred items from the v4.10.0 code-review punch list. Pure refactor + bug fix release — no new features, no parameter changes, no breaking changes to existing callers. Net: ~2,400 fewer lines of duplicated logic, two new shared Lib helpers, two new Pester suites pinning their behavior, one latent StrictMode bug fixed in the Delta publisher, one switch-fallthrough bug fixed in the Remediation Playbook publisher.

### Added

- **`Lib/Get-NRGCoverageScore.ps1`** — canonical coverage-score helper. Returns `[ordered]@{Satisfied,Partial,Gap,NA,Error,Unknown,Total,Scored,Score}` from a single foreach pass over findings. Supports `-Workload` (ControlId-prefix filter), `-FrameworkId` (FrameworkIds prefix filter), and `-ErrorHandling Exclude|Gap` (Exclude = canonical Maturity semantics, drops Error from denominator; Gap = preserves the historical publisher semantics where Error deflates the score). Now exported via `NRG-Assessment.psm1`/`.psd1` (export #229).
- **`Lib/Get-NRGObjectField.ps1`** — shape-agnostic field reader for hashtables, OrderedDictionaries, PSCustomObjects (incl. `ConvertFrom-Json` output), and Synchronized hashtables. Never throws on missing keys under StrictMode. Returns the supplied `-Default` for misses. Exported as #230. Documented in its header why a new helper instead of extending `Get-NRGSafeProperty` (the existing helper is property-only; six+ evaluators depend on that property-only behavior).
- **`Testing/NRG.CoverageScore.Tests.ps1`** — new Pester suite pinning every documented behavior of `Get-NRGCoverageScore`: state counting, `-ErrorHandling` variants, score rounding at half-integer boundaries, `-Workload` + `-FrameworkId` filters, PSCustomObject inputs, missing-FrameworkIds StrictMode safety.
- **`Testing/NRG.ObjectField.Tests.ps1`** — new Pester suite pinning every shape branch of `Get-NRGObjectField` (hashtable, ordered, PSCustomObject, Synchronized hashtable, ConvertFrom-Json output, null input).
- **Per-state counts on `Get-NRGMaturityTier` return** — added `Satisfied`, `Partial`, `Gap`, `NotApplicable`, `Total` keys alongside the existing 9. Lets the orchestrator's summary banner (and future callers) read counts from one source instead of re-deriving with `Where-Object`.

### Changed — deduplication

- **Score formula extracted from 5 sites** to one canonical helper. Sites now delegating to `Get-NRGCoverageScore`:
  - `Lib/Get-NRGMaturityTier.ps1` (variant: `-ErrorHandling Exclude`, the documented "Error doesn't tank CI gates" rule)
  - `Publishers/Publish-NRGAssessmentHTML.ps1` × 3 (tenant-wide ring score, per-workload scores, per-framework scores — all use `-ErrorHandling Gap` to preserve historical numbers)
  - `Publishers/Publish-NRGAssessmentSummary.ps1`
  - `Publishers/Publish-NRGRemediationPlaybook.ps1`
  - `Publishers/Publish-NRGDeltaReport.ps1` (deleted nested `Get-Score` function)
- **Shape-agnostic field reader extracted** from `Get-NRGMaturityTier.ps1` (nested `Read-FindingField` deleted) and `Publish-NRGDeltaReport.ps1` (`$getBag` scriptblock + DMARC-regression block — 5 inline shape-switches removed).
- **Orchestrator summary banner** now reads counts from `$reportMetadata['Maturity']` (precomputed at line 583) instead of 5× `Where-Object` over `$findings`. Fail-soft fallback: if Maturity is unavailable (helper threw, or a `-FromResults` baseline pre-dating v4.10.1), banner falls back to one `Get-NRGCoverageScore` call. Banner always renders.

### Fixed — bugs surfaced during the extraction

- **`Publishers/Publish-NRGRemediationPlaybook.ps1` executive-summary `$posture`** was a `switch ($true) { … }` with no `break` statements. Switch-fallthrough meant `$posture` was secretly an array — `@('Strong','Moderate','At Risk')` for any tenant scoring ≥ 85, `@('Moderate','At Risk')` for any tenant scoring 65-84. Visible bug in every executive markdown for any tenant scoring above 40. Rewritten as `if/elseif` (same pattern the Summary publisher already used).
- **`Publishers/Publish-NRGDeltaReport.ps1` `$getBag`** had latent StrictMode bugs at `$bag.Success` and `$bag.Data`: when called with a `PSCustomObject` bag that didn't have those properties (e.g., a baseline JSON from a tool version that named the collector result differently), the access would throw rather than gracefully returning `@()`. Same fix on the DMARC-regression block at `$bd.DMARCPolicy` / `$cd.DMARCPolicy`. Now flow through `Get-NRGObjectField` with explicit `-Default` values.

### Internal contract notes

- **`Get-NRGCoverageScore -ErrorHandling Exclude` (Maturity) vs `Gap` (publishers)** — the helper exposes both variants instead of forcing convergence. The HTML score ring (uses `Gap`) and the Maturity badge (uses `Exclude`) on the same report will still differ slightly on tenants with `Error` findings — by design. Reconciliation is a separate decision for a future release; today's release prioritizes "zero user-visible score shift" over "one global score."
- **Behavior preservation verified by**: the existing `Testing/NRG.MaturityTier.Tests.ps1` suite (all assertions pass against the refactored helper; the canary that pinned v4.10.0 behavior); 32-case manual regression suite covering both helpers' edge cases (StrictMode, $null-skip, typo'd states, PSCustomObject input, filter composition).

## v4.10.0 (2026-05-31)

**Release highlights:** new Maturity tier (roadmap F1), CI/automation threshold exit codes, Quick scan mode, CISA-aligned security program documentation (VDP, SSDF self-attestation, OpenSSF Best Practices self-assessment), and a substantial correctness/security hardening pass.

### Fixed — pre-release security & correctness hardening pass

Two independent code reviews of the v4.10.0 candidate (a recall-mode correctness pass and a security-focused pass) surfaced 7 actionable issues — all addressed in this release:

- **`-FailOnCritical` / `-FailOnHigh` silently failed open when Maturity helper threw.** Both flags previously defaulted gap counts to 0 if `$reportMetadata['Maturity']` was unavailable, silently passing CI gates with the INOPERATIVE state visible only on `-FailOnScoreBelow`. Now all three threshold flags emit the same loud Warning and refuse to exit 0 silently.
- **`-FailOn*` + `-FromResults` had no integrity warning.** A tampered baseline JSON could pass any CI gate. We already loudly reject `-Quick + -FromResults`; now the same warning fires for `-FailOn*`, surfacing the trust boundary in the CI log so a tampered baseline can't silently mislead the operator.
- **`-FailOnScoreBelow` fired exit 12 on zero-findings runs** (derived score = 0 < threshold). A "no findings" run should exit 2, not be re-interpreted as a posture failure. Threshold block now short-circuits when `$findings.Count -eq 0`.
- **Maturity score denominator over-counted `$null` entries.** `$Findings.Count - $na - $err` included `$null` items the loop skipped, deflating the score on dirty `-FromResults` baselines. Replaced with an inside-the-loop `$total` counter.
- **`switch` on State had no default arm.** Typo'd / unknown State values (`'Satisifed'`, a future `'Pending'`, etc.) silently inflated the denominator with zero numerator contribution. Default arm now tracks `UnknownStates` in the result and excludes them from the denominator.
- **Pester test for null-skip was vacuous.** Contained no `$null` entries — would have passed even if the null-skip guard was removed. Replaced with `[object[]]`-typed array literal that actually contains `$null` plus a regression assertion on `ScoredControls`. Also added `[AllowNull()]` to the `Findings` param so the binder accepts arrays with `$null` elements.
- **Summary banner didn't show Error count.** Error-state findings (collector failures) were silently absorbed — banner Total disagreed with the sum of categories by the Error count. Now surfaced as a distinct row when `> 0`.

### Added — automation features: Maturity tier, threshold exit codes, Quick scan

Three-layer security-program documentation aligned to CISA's published expectations for federal-software vendors. Pure documentation + GitHub-config additions; no code or behavior changes.

**Vulnerability Disclosure Policy** ([`docs/VULNERABILITY-DISCLOSURE-POLICY.md`](docs/VULNERABILITY-DISCLOSURE-POLICY.md)) — full CISA BOD 20-01 alignment:

- 3 business-day acknowledgement SLA, 7-day triage SLA, 14-day status updates
- Severity-tied fix SLAs (Critical 7d / High 30d / Medium 60d / Low next release)
- Explicit Safe Harbor language giving researchers authorization to test
- Scope + out-of-scope statement so reports route to the right project
- Recognition / credit policy
- Annual review cadence

**Secure Development self-attestation** ([`docs/SECURE-DEVELOPMENT.md`](docs/SECURE-DEVELOPMENT.md)) — NIST SP 800-218 (SSDF) mapping:

- All 22 SSDF tasks attested with file/workflow evidence
- Matches CISA Secure Software Development Attestation Form 1.0 structure
- PO / PS / PW / RV practice families covered

**OpenSSF Best Practices self-assessment** ([`docs/OPENSSF-BEST-PRACTICES.md`](docs/OPENSSF-BEST-PRACTICES.md)):

- Passing tier: 67 / 67 criteria met (100%)
- Silver tier: 38 / 65 (58%, gap list documented)
- Gold tier: 14 / 56 (25%, aspirational)
- Evidence trail for every criterion in this repository

**Repository hygiene**:

- [`SECURITY.md`](SECURITY.md) — rewritten with the same disclosure SLA, scope statement, and Safe Harbor as the VDP (was: short paragraph + email)
- [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) — security checklist required on every PR (read-only invariant, input validation, no plaintext PII, StrictMode-safe field access)
- [`.github/ISSUE_TEMPLATE/config.yml`](.github/ISSUE_TEMPLATE/config.yml) — surfaces the private security advisory channel BEFORE the operator can open a public issue describing a vulnerability
- [`.github/CODEOWNERS`](.github/CODEOWNERS) — auto-routes security-sensitive paths (CI workflows, auth/connect code, sensitive-file ACL helper) to the security engineer
- [`.well-known/security.txt`](.well-known/security.txt) — RFC 9116 machine-readable security contact metadata
- [`README.md`](README.md) — OpenSSF Best Practices + SSDF + CISA BOD 20-01 badges, security policy CTA above the fold
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — security-vulnerability reporting section, `security:` commit prefix convention

Why this matters operationally: government / regulated-industry MSP buyers (NRG clients with CISA BOD 18-01 obligations) increasingly require a published VDP + SSDF attestation from every tool in their pipeline. This release lets the sales conversation point at the repo instead of having to handwave.

### Fixed — post-PR#13 code review hardening pass

15 findings from a recall-mode code review of the maturity / threshold / Quick PR. Highest-severity items grouped:

- **`-FromResults` path crashed on every invocation.** Line 360 did `@{} + $priorData.Metadata`, but `ConvertFrom-Json` returns `PSCustomObject`, not `Hashtable` → `A hash table can only be added to another hash table`. Switched to `ConvertFrom-Json -AsHashtable` and explicit `[hashtable]` casts so `Maturity` / threshold lookups work on the re-published metadata.
- **Maturity helper crashed on empty findings.** Mandatory `[object[]]` without `[AllowEmptyCollection()]` rejected `@()` — tenants with all `Skip*` flags silently lost the badge AND silently disabled `-FailOnScoreBelow`. Added `[AllowEmptyCollection()]` and an explicit zero-score / Tier 1 result.
- **Maturity helper crashed on malformed findings under StrictMode.** `Where-Object State -eq 'X'` simple syntax throws `PropertyNotFoundException` on items missing `State`. Replaced with a single shape-agnostic pass that handles both `Hashtable` and `PSCustomObject` (FromResults shape), tolerates missing fields, and skips `$null` entries.
- **`State='Error'` findings deflated the maturity score.** `Add-NRGFinding` accepts `State='Error'` for collector failures (transient throttling, partial collection). The old denominator counted these as gaps, producing false `-FailOnScoreBelow` CI alarms on flaky tenants. Now excluded from the denominator and surfaced as `ErrorFindings` in the result.
- **`-FailOnScoreBelow` silently no-op'd when Maturity classification failed.** The old guard `Contains('Maturity')` returned false on any helper exception, skipping the CI gate without notification. Now logs a `Write-Warning` declaring the gate INOPERATIVE for that run, and the summary banner shows `Maturity unavailable (<reason>)`.
- **Quick mode swallowed `Get-NRGControlDefinitions` failure → 0 evaluators → exit 2.** A corrupted `controls.json` produced an "empty assessment" that CI read as a benign signal. Now fails closed via the outer fatal-exit path.
- **Quick mode + FromResults silently ignored the switch.** Now emits a `Write-Warning` explaining the user must re-run against the live tenant.
- **Threshold exit codes (10/11/12) hijacked `$NRGFatalExitCode`.** A real crash that occurred after a threshold breach masqueraded as a graceful policy trip; a graceful trip looked like a fatal crash. Moved to `$script:NRGThresholdExitCode` with explicit precedence (fatal > threshold > success) at the final exit-resolution block.
- **Threshold counts re-derived from `$findings`** were now read from `$reportMetadata.Maturity.CriticalGaps` / `.HighGaps` so the badge and the CI gate can never disagree.
- **Maturity recompute lifted out of the `if (-not $skipCollection)` guard** so `-FromResults` runs always re-classify against the current findings stream rather than using stale baseline metadata.
- **Windows guard `-not $IsWindows -and $env:OS -ne 'Windows_NT'`** was over-permissive — any non-Windows shell with that env var inherited bypassed the guard and crashed mid-onboarding. Simplified to `-not $IsWindows` (PS7's authoritative variable); skips the throw under `-WhatIf` so MSP techs can preview the call from a Mac.
- **`Set-StrictMode` / `$ErrorActionPreference = 'Stop'` moved out of file scope and into the function body** in `Get-NRGMaturityTier.ps1`, matching the convention used by every other Lib helper. The previous file-scope assignment leaked into module session state during dot-source.

New Pester coverage in `Testing/NRG.MaturityTier.Tests.ps1` for the empty-findings path, Error exclusion, PSCustomObject inputs, and missing-property survival under StrictMode.

### Added — automation features: Maturity tier, threshold exit codes, Quick scan

Four operator-facing features for CI/automation pipelines and quick triage:

- **`Lib/Get-NRGMaturityTier.ps1`** (new, roadmap F1) — derives a 1–5 tier (Initial / Developing / Defined / Managed / Optimizing) from the final findings stream. Tier rules combine score % and absolute Critical/High gap counts so the badge can never disagree with the score ring. Embedded in `$reportMetadata.Maturity` so every publisher (HTML, JSON, Markdown, Playbook, Delta) sees the same classification. Score formula matches the existing HTML publisher: `round(100 * (Satisfied + 0.5*Partial) / ScoredControls)`.
- **`-Quick` switch** on `Invoke-NRGAssessment.ps1` — filters the evaluator set to only those that score Critical + High controls. Same collectors run; only the scoring pass is short-circuited. Useful for "give me a 60-second triage" runs. Metadata now records `QuickScan = $true` so downstream consumers can flag that the report intentionally skipped Medium / Low.
- **`-FailOnCritical N`, `-FailOnHigh N`, `-FailOnScoreBelow N`** — opt-in threshold exit codes (default 0 = disabled). Distinct exit-code range (10/11/12) so CI callers can disambiguate "no findings" (code 2) from "too many Critical gaps" (code 10). First-match wins, most severe signal lands.
- **`-BaselineResults <path>`** — already implemented (`Publishers/Publish-NRGDeltaReport.ps1`, 473 lines covering score delta, finding regressions, CA drift, role drift, OAuth drift, DMARC drift). Now surfaced in README so operators discover it.

New Pester suite `Testing/NRG.MaturityTier.Tests.ps1` pins all five tier transitions, the half-credit Partial scoring, NotApplicable exclusion, and the output-shape contract.

### Added — HIPAA / SOC 2 / PCI DSS / ISO 27001 citations to every control

A framework-coverage audit found that only 33 of 195 controls had a HIPAA citation, 41 had SOC 2, 17 had PCI DSS, and 72 had ISO 27001 — and 10 of the 33 HIPAA mappings were on the wrong Security Rule subpart (e.g., mailbox audit logging was cited as §164.312(e)(2) Integrity when it should be §164.312(b) Audit Controls).

This release lands citations for all four frameworks across every one of the 195 controls. 720 of 780 possible cells were changed. CIS, CMMC, NIST, MITRE, and SCuBA citations were preserved unchanged.

**Confirmed HIPAA mapping errors corrected** (the 10 the audit found):

| Control | Old | New |
|---|---|---|
| EXO-1.1 Mailbox Audit Logging | §164.312(e)(2) | §164.312(b) Audit Controls |
| EXO-1.2 SMTP Client Auth Disabled | §164.312(e)(2) | §164.312(e)(1) Transmission Security |
| EXO-5.1 Per-User Mailbox Audit (all) | §164.308(a)(1) | §164.312(b) |
| EXO-7.3 No mailboxes w/ audit disabled | §164.308(a)(1) | §164.312(b) |
| AAD-7.2 Break-Glass Accounts | §164.308(a)(3) | §164.312(a)(2)(ii) Emergency Access Procedure |
| INT-4.3 Device OS Version Compliance | §164.308(a)(5) Training | §164.308(a)(1)(ii)(B) Risk Management |
| PVW-1.1 Unified Audit Log Enabled | §164.308(a)(1) | §164.312(b), §164.308(a)(1)(ii)(D) |
| PVW-2.4 Insider Risk Management | §164.308(a)(1) | §164.308(a)(6) Security Incident Procedures |
| PVW-4.2 Audit Log Retention ≥ 1 yr | §164.308(a)(1) | §164.316(b)(2)(i) Time Limit + §164.312(b) |
| PVW-4.3 Sensitivity Labels Defined | §164.514(b) Deidentification | §164.502(b) Minimum Necessary |

**Coverage delta:**

| Framework | Before | After |
|---|---|---|
| HIPAA | 33 / 195 (17%) | **195 / 195 (100%)** |
| SOC 2 | 41 / 195 (21%) | **195 / 195 (100%)** |
| PCI DSS | 17 / 195 (9%) | **195 / 195 (100%)** |
| ISO 27001 | 72 / 195 (37%) | **195 / 195 (100%)** |

**New Pester invariant** (`Testing/NRG.FrameworkCoverage.Tests.ps1`) pins the contract for future PRs: every control must carry a non-empty citation for all 8 frameworks, each in the right shape (HIPAA `§164.*`, SOC 2 TSC codes, PCI `Req N.N`, ISO `A.[5-8].N`), and the 10 HIPAA fixes are pinned by control ID so a future edit cannot regress them silently.

### Added — app-only tenant onboarding (`-RegisterApp`) (ported into v4.10.0)

A one-time onboarding flow that registers a read-only enterprise app + certificate in a customer tenant, so subsequent scans run **app-only** — no device-code prompts, and immune to Conditional Access "Authentication Flows" policies (the `AADSTS530036` block that prevents the Teams/EXO device-code sign-in on hardened tenants).

- **`Lib/Register-NRGTenantApp.ps1`** (new) — generates a self-signed client-auth cert in `Cert:\CurrentUser\My`, creates the app registration, creates its service principal, and either auto-grants admin consent (`-GrantConsent`, operator must be Global Admin) or emits an admin-consent URL for a Global Admin. Records `ClientId` / `TenantId` / `CertThumbprint` in `Config/clients.json`.
- **Permission GUIDs are resolved at runtime** from the target tenant's own Microsoft Graph service principal — never hardcoded. Permissions with no application-permission equivalent are reported and skipped.
- **The app it creates is read-only** (all requested Graph permissions are `*.Read.All`). The onboarding step is the one sanctioned directory write, isolated in this function and gated behind `-RegisterApp` + `SupportsShouldProcess`/`-WhatIf`.
- **Entry-script wiring** (`Invoke-NRGAssessment.ps1`):
  - `-RegisterApp -TenantDomain <domain>` — connects interactively with write scopes, runs onboarding, exits.
  - `-TenantDomain <domain>` on a normal scan — looks up the onboarded `ClientId` + cert thumbprint from `clients.json` and runs app-only with zero typed GUIDs. Falls back to interactive with a hint if the tenant isn't onboarded.
- Exchange Online app-only needs one manual follow-up (assign the app the **Global Reader** directory role); the function prints the instruction.
- `clients.json` gains `ClientId`, `CertThumbprint`, `AuthMode`, `OnboardedAt` fields; the file's ACL is restricted on write.

**Note:** the connection side (`Connect-NRGServices` AppOnly parameter set) already supported cert auth; this release adds the missing onboarding + auto-lookup.

## v4.9.0 (2026-05-29) — local web GUI

### Added — local web GUI

New `-Web` flag on `Invoke-NRGAssessment.ps1` launches a local Pode-backed web server (loopback only, `127.0.0.1:8765` by default) and opens the operator's browser to a single-page GUI. The GUI is a thin shell over the existing module:

- **Tenant list** is read from `Config/clients.json`; ad-hoc domains can be entered directly.
- **Click a tenant** → confirm prompt → kicks off `Invoke-NRGAssessment.ps1` as a child job. The operator authorizes Microsoft Graph / EXO in the child's auth-popup browser window the same way they would for a CLI run.
- **Live progress** — the server polls the child job's stdout and the GUI updates a progress bar and log tail every second.
- **History** sidebar lists prior runs from `./output/` (per-tenant subfolders, latest first).
- **View report inline** — clicking a run loads the existing CSP-hardened `<tenant>-assessment.html` into a sandboxed iframe (`sandbox="allow-same-origin"`); the report's own strict CSP still applies inside the frame.

Files added:

- `Lib/Start-NRGWebServer.ps1` (303 lines) — server entry point + 5 routes.
- `Web/index.html`, `Web/static/app.css`, `Web/static/app.js` — vanilla HTML/CSS/JS; no framework, no bundler, CSP-friendly (all DOM wiring via `addEventListener`, no inline handlers).

Security posture:

- Server binds to `127.0.0.1` only — never `0.0.0.0`, never exposed to the network.
- Server-side CSP on every response: `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'`. Same shape as the report publisher.
- Path-traversal guards on both `:tenant` and `:id` route parameters; domain regex on scan-trigger.
- No `Invoke-Expression`, no `[scriptblock]::Create`, no eval anywhere.
- Pode is loaded as a **soft dependency** (not in `RequiredModules`) so CLI users aren't affected. The flag emits a clear one-line install instruction if Pode isn't present.

Prerequisites for `-Web`:

- `Install-Module Pode -MinimumVersion 2.10.0 -Scope CurrentUser` (one-time, free, MIT).

Module exports updated in both `NRG-Assessment.psd1` `FunctionsToExport` and `NRG-Assessment.psm1` `$script:ExportedFunctions` to include `Start-NRGWebServer`.

## v4.6.7 (2026-05-27) — polished release

Polish-and-correctness bundle covering everything surfaced by the v4.6.6 review of the frontierprecision.com run. Lockstep with NRG v4.6.7.

### Fixed — correctness

- **Six StrictMode property-access NREs in `Test-NRGControlIntune.ps1`.** The user's frontierprecision.com run printed `The property 'ConditionalLaunchSettings' cannot be found on this object.` for `INT-3.3`. Same unguarded pattern surfaced at five more sites:
  - `INT-3.3`  ConditionalLaunchSettings (line 290)
  - `INT-1.2`  TemplateType (line 129)
  - `INT-3.1`  Platform (line 205) + SystemIntegrityProtectionEnabled / StorageRequireEncryption (line 210)
  - `INT-4.4`  Platform (line 371) + PasswordRequired / RequirePassword (line 375)
  
  All six switched to `Get-NRGSafeProperty -Object $_ -Property '<name>' -Default <safe>` — the same canonical pattern already used at line 84 (INT-1.3 BitLocker). The `??` null-coalescing operator only handles `$null` values; under StrictMode a missing property throws before `??` can coalesce.

- **EOM downgrade fails on OneDrive-synced PowerShell module paths.** The user's run showed `Cannot remove package path C:\Users\…\OneDrive - …\Documents\PowerShell\Modules\ExchangeOnlineManagement\3.2.0` because OneDrive holds file locks on every file in the synced tree. `Invoke-NRGAssessment.ps1` now detects a OneDrive-synced `ModuleBase` BEFORE calling `Uninstall-PSResource` and prints an actionable message ("pause OneDrive sync on Documents OR move PowerShell modules out of OneDrive") instead of letting the uninstall fail mid-sweep.

- **EXO "more results available" warning recurrence.** `Collectors/EXO/Invoke-NRGCollectEXOMailboxConfig.ps1:122` deliberately samples 10 user mailboxes for audit-config inspection — but EXO emits a `WARNING: There are more results available...` line on every call. Operators reading the warning assumed the v4.6.5 ResultSize sweep had regressed. The sampling call now passes `-WarningAction SilentlyContinue` and the inline comment explains the intent.

### Fixed — UI / browser

- **Click handler on collapsible rows now ignores clicks on `<a>`, `<button>`, `<input>`, `<select>`, `<textarea>`** descendants. Previously, a click anywhere inside the expanded detail row bubbled up and collapsed the row before the click could resolve. The fix is a `e.target.closest('a,button,input,select,textarea')` early-return inside the click handler.

### Fixed — security / hardening

- **CSP now explicitly sets `frame-ancestors 'none'` and `object-src 'none'`.** Per CSP spec, neither directive inherits from `default-src 'none'` — without explicit declarations the assessment report was embeddable in cross-origin iframes (clickjacking surface) and could load `<object>`/`<embed>` plugin content. The sibling playbook publisher already set `frame-ancestors 'none'`; assessment.html was the only outlier.

- **CSP integrity self-check at publish time.** `Publish-NRGAssessmentHTML.ps1` now re-derives the SHA-256 of the inline `<script>` body actually written into `$html` and throws if it disagrees with the `script-src 'sha256-...'` claim baked into the CSP. Catches the exact regression we fixed in v4.6.6.1 (interpolation drift between hashed source and emitted body) at publish time rather than in the operator's browser.

- **Self-signed code-signing cert explicit non-CA constraint.** `Build/New-NRGCodeSigningCert.ps1` now passes `-TextExtension '2.5.29.19={text}cA=false'` so even though the cert is installed in `CurrentUser\Root` (required for self-signed chain validation), it cannot issue certs for arbitrary subjects. Loss of the private key enables impersonation of THIS publisher only, not arbitrary code signing. Banner now states this explicitly.

### Fixed — cosmetic

- **`Publish-NRGRemediationPlaybook.ps1` fallback `?? '4.5.5'`** now falls back to `$script:NRGAssessmentVersion` (current module version) and only to the string `'unknown'` if even that is unavailable. Previously, generated playbooks could print v4.5.5 in their footer if the entry script forgot to populate `$Metadata.ToolVersion`.

- **Sanitized `sample-report/example-assessment.html` regenerated** with the current publisher. The previous sample contained stale `onclick=` and the OLD `function goto` / `function toggle` JS body, which would either silently fail under CSP or mislead reviewers into thinking inline-onclick was supported.

### Added — invariants

- **Pester regression guards** for the CSP era:
  - `HTML publisher emits NO inline onclick= attributes` — catches re-introduction of the bug we just fixed.
  - `HTML publisher CSP frame-ancestors and object-src locked down` — catches accidental CSP-policy weakening.

### Build / CI

- **Pester and PSScriptAnalyzer pinned to upper bounds** (`[5.5.0,5.99.99]` and `[1.21.0,1.99.99]`) on both `Install-PSResource` and `Install-Module` paths. Prevents a future breaking 6.x major from being auto-adopted on the next CI run — bumping the major now requires a deliberate workflow edit.

- **Retry-loop sleep on the final iteration is skipped.** Previously, on a full-failure path CI hung an extra 8s before throwing. The retry now sleeps only between attempts, not after the last one.

- **Removed unverified "ubuntu-latest ships [Pester/PSScriptAnalyzer] in the toolcache" comment** from the workflow — it isn't a load-bearing claim and the fast-path is still a correct no-op when the runner image doesn't preinstall the module.

### Added — GitHub repository security surface

The v4.6.7 line also brought the repo's GitHub-side security posture up to match the in-code hardening. None of this changes module code (ModuleVersion stays 4.6.7); it is repository / CI / documentation infrastructure.

- **`.github/dependabot.yml`** — `github-actions` ecosystem, weekly, grouped into one PR. (PowerShell modules from PSGallery aren't a Dependabot-supported ecosystem; runtime module versions stay pinned in the manifest.)
- **`.github/workflows/codeql.yml`** — CodeQL Advanced scanning the Actions workflow YAML for supply-chain weaknesses (`security-extended` + `security-and-quality`).
- **`.github/workflows/ci.yml`** — PSScriptAnalyzer job now emits SARIF and uploads to Code Scanning (`category=psscriptanalyzer`). SARIF `startLine`/`startColumn` clamped to ≥1 (PSScriptAnalyzer emits 0 for whole-file rules, which SARIF 2.1.0 rejects); relative paths via `GetRelativePath`.
- **`.github/workflows/dependency-review.yml`** — blocks PRs introducing moderate-or-higher CVEs. (License allow-list dropped — GitHub's dependency graph doesn't populate SPDX licenses for most action repos, so an allow-list false-fails first-party actions.)
- **`.github/workflows/scorecard.yml`** — OSSF Scorecard weekly + on push; `ossf/scorecard-action` SHA-pinned per the supply-chain rule CodeQL enforces.
- **`.github/workflows/secret-scan.yml`** — Gitleaks + TruffleHog on push/PR and a weekly full-history sweep. Both third-party actions SHA-pinned. Isolated from `ci.yml` so a scanner hiccup can't block the core gates.
- **`.github/workflows/release.yml`** — on `v*` tags: CycloneDX SBOM from `tools/Generate-SBOM.ps1`, plus a windows-latest Authenticode + integrity-manifest verification (fails on tamper, tolerates unsigned in-house builds).

### Added — documentation

- **`docs/INCIDENT-RESPONSE.md`** — per-scenario runbook (GitHub credential leak, M365 enterprise-app secret leak, malicious dependency / compromised action, signing-cert compromise, active tenant compromise during an assessment). Referenced from `SECURITY.md`.
- **`docs/ROADMAP-v4.9.0.md`** — consolidates the former v4.7 (analytics) and v4.8 (IG scoping / attestation / portfolio / Maester) roadmaps into one coordinated release; `ROADMAP-v4.7.md` and `ROADMAP-v4.8.md` marked SUPERSEDED.

### Fixed — documentation accuracy

A documentation-drift audit caught several stale claims, now corrected:

- **`SECURITY.md` CI/CD section rewritten to match reality.** It previously listed Gitleaks, TruffleHog, CycloneDX SBOM, and an Authenticode catalog check as running CI steps when no workflow implemented them, and omitted the CodeQL / Scorecard / Dependency Review / Dependabot steps that *do* run. The four claimed-but-missing steps are now actually implemented (above), and the section names the workflow file behind each step so it can be verified against `.github/workflows/`.
- **Version strings reconciled to 4.6.7** in the `NRG-Assessment.psm1` header banner, `CLAUDE.md`, and the `SECURITY.md` footer (all had lagged at 4.5.5 / 4.6.5 while the manifest and `$script:NRGAssessmentVersion` were already 4.6.7).
- **`SECURITY.md` "35 production files"** claim replaced with a count-free phrasing to stop the number drifting out of sync.

## v4.6.6.1 (2026-05-27) — HTML report CSP hotfix

### Fixed

- **Interactive buttons silently broken in HTML assessment report.** The CSP emitted by `Publishers/Publish-NRGAssessmentHTML.ps1` was `script-src 'sha256-...'` — correctly authorizing the inline `<script>` block, but with no `'unsafe-inline'` or `'unsafe-hashes'`. Every `onclick="goto(...)"` on the header nav and every `onclick='toggle(this)'` on the expandable finding rows was therefore blocked by the browser, with no visible error to the operator. Nav links and row expanders rendered as cursor-pointer but did nothing on click.

  Fix: removed all inline `onclick=` attributes. Nav spans now use `data-goto="<id>"`; expandable rows are identified by their existing `class="exp"`. Handlers are attached via `addEventListener` inside the existing CSP-hashed `<script>` block, so the SHA-256 hash covers them automatically — no CSP relaxation needed.

  Affected: every HTML assessment report produced by v4.6.3 (when the CSP hash was introduced) through v4.6.6. The playbook HTML was unaffected (no interactive elements).

## v4.6.6 (2026-05-27) — fresh-install hotfix

Two latent bugs surfaced when an operator unboxed v4.6.5 from a fresh GitHub zip on a Windows workstation without MicrosoftTeams installed.

### Fixed

- **`New-Item -LiteralPath ... -ItemType Directory` doesn't work** — `-LiteralPath` is not in `New-Item`'s parameter set even on PS 7. Five sites switched to `[void][System.IO.Directory]::CreateDirectory($path)`:
  - `Invoke-NRGAssessment.ps1`, `Invoke-NRGBatchAssessment.ps1`, `Apply-NRGBaseline.ps1`, `Build/New-NRGCodeSigningCert.ps1`, `tools/Generate-SBOM.ps1`
- **`MicrosoftTeams` demoted from `RequiredModules` to soft dependency.** Module no longer fails to load on workstations without Teams. `Connect-NRGServices` already handles on-demand load.

## v4.6.5 (2026-05-27)

Patch release closing the correctness sweep defined in `docs/CORRECTNESS-SWEEP-v4.6.5.md`. No new features. Every defect surfaced by three real-tenant runs and a follow-on code-review audit is either Resolved here or explicitly tracked Open.

### Fixed

- **Per-tenant remediation script dispatch (Critical).** Generated `<tenant>-remediation.ps1` files called `Apply-NRG* -ErrorAction Stop` with no `-Finding` argument. Every `Apply-NRG*` function declares `[Parameter(Mandatory)] [object] $Finding`, so every dispatched call would have failed at runtime. The generated script now loads its sibling `<baseName>-results.json`, builds `$findingsByCtrl`, and passes `-Finding $fnd` per dispatch. The JSON-load runs BEFORE `Connect-NRGServices` so a missing or corrupt JSON fails fast without paying the Graph/EXO authentication cost. `ConvertFrom-Json` is wrapped in try/catch with a diagnostic message. `$assessment.Findings` is null-checked so an unexpected JSON shape produces an actionable error rather than silent zero-iteration.
- **14 StrictMode property-access NREs** across AAD, Defender, EXO, Intune evaluators (PR #2, #4). Each was silently dropping one or more findings from real-tenant reports.
- **`Get-Mailbox -ResultSize 1000` undercount.** Five EXO collector calls capped at 1000 mailboxes. Switched to `-ResultSize Unlimited` for population-counting calls.
- **HTML playbook alias collision.** `function H` collided with the built-in `h` alias (= `Get-History -Id [long]`). Renamed to `EscHtml`.
- **XLSX compliance matrix `'PCIDSS'` NRE.** All 10 framework-reference accesses now use `Get-NRGNestedProperty`. Also fixed the `PCIDASSS` column header typo.
- **HTML entity leakage in markdown publishers.** `ConvertTo-NRGHtmlSafe` was being applied to markdown source. Markdown `EscMd` now escapes only characters that break markdown table/code-span structure.
- **Findings-table sort under malformed enum values.** Defensive `?? 99` coerces unknown values to a sortable tail.

### Security / privacy

- **`.gitignore` now excludes `output/`.** NRG had the same gap as NLS (only `Reports/` was excluded); NRG never had real client data committed because the port excluded `output/` at copy time, but future `Invoke-NRGAssessment` runs would have started tracking output files.
- **Sample HTML sanitization.** `sample-report/example-assessment.html` had 7 occurrences of real personal domain `mattlevorson.com` (secondary domain on the source tenant) and 2 admin display names rendered as `NRG Technology Services / NextLayerSec LLC` (collision from `Matthew Levorson → NRG Technology Services / NextLayerSec LLC` sanitization). Replaced with `example2.com` / `Admin 2` / `Admin 3`.
- **Branding/PII leaks** in initial NRG port surfaced and fixed: NRG phone number in `branding.psd1`, "North Dakota" geographic identifier in CLAUDE.md, real client names NDACo / Dunn County in sample configs.

### Release engineering

- **In-house signing scaffolding (soft mode, $0 cost).** New `Build/New-NRGCodeSigningCert.ps1` generates a self-signed Authenticode cert on the operator workstation, installs it into `TrustedPublisher` + `Root`, and stashes the thumbprint at `~/.nrg-assessment/signing-thumbprint.txt`. `Build/Sign-Release.ps1` treats self-signed as first-class for in-house use. Upgrade path to a paid cert is one parameter.
- **`Apply-NRGBaseline.ps1 -RequireSignedCode`** (new switch, default `$false`). Soft warning by default; hard refusal when set. Future v5.0 may flip the default.
- **`Lib/Test-NRGSignatureStatus.ps1`** (new exported function). Wraps `Get-AuthenticodeSignature` with friendlier status mapping and self-signed chain resolution.
- **`RELEASE-CHECKLIST.md`** (new). Codifies the per-release contract: pre-release OWASP delta walk, code-review pass, adversarial fixtures, real-tenant run; release-time signing + integrity-manifest generation; post-release SBOM + smoke test.

### Documentation

- New `docs/CORRECTNESS-SWEEP-v4.6.5.md` — prioritization rule, 24 Resolved entries with root cause and PR refs, 7 Open entries for follow-up, 3 misclassification entries deferred to v4.7, Definition of Done.
- `CLAUDE.md` rewritten to describe the actual `LicenseRequirement`-per-control architecture.
- New `docs/ROADMAP-v4.7.md` and `docs/ROADMAP-v4.8.md` — design only, no code.

### Readability

- `<tenant>-playbook.md` slimmed (TOC + checklist, no per-item framework wall or time-estimate).
- New `<tenant>-playbook.html` artifact (strict CSP, Trusted Types, print stylesheet).
- `<tenant>-executive.md` got a Bottom-line one-liner and Current state lines under top-5 priorities.
- `<tenant>-assessment.md` findings table sorted Gap → Partial → Satisfied first; NotApplicable folded.
- `<tenant>-remediation.ps1` is now actually runnable.
- New `sample-report/example-assessment.html` so prospective users can see what the tool produces without running an assessment first.

## v4.5.5 (2025-05-18)

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
- **`-SkipPurview` defaults to `$true`** — EOM v3.4 IPPSSession WAM crash. Use `-IncludePurview` to opt in.
- **Evaluator discovery dynamic** — orchestrator enumerates `Test-NRGControl*` from loaded module rather than hardcoded list.
- **Disconnect at end of run** — no try/finally chain that fires on every error.

## v4.5.0 (Baseline)

Initial clean architectural rebuild. 75 controls across Collectors → Evaluators → Publishers pipeline.

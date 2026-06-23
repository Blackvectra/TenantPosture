# NRG-Assessment — Email-IR Mode (v4.12.0+)

The **Email Account Assessment** is a focused variant of the NRG-Assessment tool that targets ONE user's mailbox instead of the whole tenant. Use it during a suspected compromise — BEC, phish-stolen credentials, attacker-installed inbox rules, mass outbound to external — when you have the user's credentials (or guide the user through running it themselves) but may not have full tenant-admin access.

## When to use

| Scenario | Tool |
|---|---|
| Tenant-wide posture (CIS, SCuBA, NIST, CMMC) | `Invoke-NRGAssessment.ps1` (admin scope, 21 Graph scopes) |
| Monthly recurring deliverable | `Invoke-NRGAssessment.ps1 -MonthlyReport` |
| **Suspect compromise, don't yet know which user(s)** | **`Invoke-NRGSignInTriage.ps1` — admin-scope sign-in triage** |
| **Compromised user account already known** | **`Invoke-NRGEmailAssessment.ps1` — per-user mailbox IR** |

The two IR tools are the two halves of one workflow: triage finds the suspect users from the tenant's sign-in logs, then you deep-dive each one's mailbox.

For MSP fleets, `Invoke-NRGBatchSignInTriage.ps1` (v4.12.1) loops the triage across every active client in `Config/clients.json` and writes a batch summary with compromised clients sorted to the top.

## Two workflows

### A — Single-shot admin (auto deep-dive)

```powershell
# Admin signs in once; triage + auto deep-dive top 5 flagged users
.\Invoke-NRGSignInTriage.ps1 -DeepDive 5
```

One admin login (requests `Mail.Read.All` for the deep-dive). Triage scores
every user's sign-in IoCs, ranks them, then reads the top N users' mailboxes
in the same session and runs the per-user `EMAIL-*` evaluators. One unified
report.

### B — Triage, then per-user with a Temporary Access Pass

```powershell
# 1. Admin triage only — no Mail.Read.All consent
.\Invoke-NRGSignInTriage.ps1 -SkipMailDive

# 2. For each flagged user, issue a Temporary Access Pass in
#    Microsoft Entra > Users > [user] > Authentication methods >
#    Add authentication method > Temporary Access Pass.
#    Sign in as the user with the TAP, then:
.\Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@corp.com
```

Use B when the client BAA prohibits the assessment tool reading mailboxes
under admin auth. A TAP is a one-time-use, time-limited passcode — it does
**not** change the user's password and does not require their existing MFA.

**Both workflows are read-only.** The tool never writes to the tenant; you
issue the TAP yourself in the Admin Center.

## Phase 0 — Sign-in triage (admin scope)

`Invoke-NRGSignInTriage.ps1` reads tenant-wide sign-in logs (admin scopes:
`AuditLog.Read.All`, `IdentityRiskyUser.Read.All`, `Directory.Read.All`,
`User.Read.All`, plus `Mail.Read.All` + `MailboxSettings.Read.All` +
`UserAuthenticationMethod.Read.All` unless
`-SkipMailDive`). It scores every user against these IoCs:

| Control | Looks for | Score |
|---|---|---|
| `SIGNIN-1.1` | Failed→success cluster (≥5 failures in 30 min then a success) — credential stuffing succeeded | 60 |
| `SIGNIN-1.2` | Anonymous-IP sign-in (TOR / anon-VPN, Microsoft-flagged) | 50 success / 15 failed |
| `SIGNIN-1.3` | Impossible travel / unfamiliar features | 40 |
| `SIGNIN-1.4` | Microsoft Identity Protection risky users (Entra ID P2) | high 50 / med 25 / low 10 |
| `SIGNIN-1.5` | IP threat-intel enrichment — RDAP geolocation + ASN owner + Tor exit-node cross-check on every suspicious source IP. A successful sign-in from flagged infra (TOR_EXIT / HOSTING_ASN / KNOWN_VPN_ASN) | +30 |
| `SIGNIN-2.1` | Rank aggregator — produces the prioritized user list, highest IoC score first | — |

`SIGNIN-1.5` is gated by `-EnableThreatIntel` (default **on**). It submits the
flagged sign-in IPs to `rdap.org` for geolocation + ASN-owner enrichment —
confirm the client's data-handling policy permits this, or pass
`-EnableThreatIntel:$false` to skip the external calls. Tor-exit detection
no longer fetches from `check.torproject.org` (Cortex XDR + other EDRs flag
that hostname as suspicious infrastructure contact); pass an
operator-curated local list via `-TorExitListPath` if you need standalone
Tor flagging, or rely on Microsoft Identity Protection's
`anonymizedIPAddress` risk-event type (Entra ID P2) which already covers
Tor for those tenants. All users with a
non-zero IoC score appear in the triage report's ranked table (not just the
deep-dived subset).

## Phase 1 — Per-user mailbox deep-dive

Reads one user's mailbox. Under workflow A this runs automatically (admin
auth, `/users/<upn>/...`); under workflow B you run it yourself signed in as
the user (delegated, `/me/...`). Either way it runs these heuristics:

| Control | Looks for |
|---|---|
| `EMAIL-1.1` | Suspicious inbox rules (hidden names, forward-external, delete) — classic BEC persistence + cover-tracks IoCs |
| `EMAIL-1.2` | Server-side forwarding (limited under delegated scope; falls back to advisory) |
| `EMAIL-2.1` | Outbound activity scan — BEC subject patterns (wire transfer, gift card, urgent payment), volume bursts, external recipient counts |
| `EMAIL-3.1` | Most-likely original phish ranker — scores inbound + recoverable-items messages on: external sender + Microsoft-impersonation + urgency keywords + suspicious URLs + display-name spoof + RECOVERED-from-Deletions |
| `EMAIL-3.2` | (Optional, `-EnableThreatIntel`) WHOIS-via-RDAP lookup of top sender domains — flags domains registered in last 30 days |
| `EMAIL-4.1` | OAuth consent grants — illicit-consent persistence that **survives password reset and MFA re-enrollment**. Flags grants with mail/file write-or-send scopes (Mail.ReadWrite, Mail.Send, EWS, IMAP/POP/SMTP); read-scope grants land as verify-with-user |
| `EMAIL-4.2` | Registered MFA methods — full inventory to read to the user on the containment call, flags >1 phone method and any method registered in the last 14 days (attacker-added MFA). Feeds Containment Runbook step 2 |

`EMAIL-4.x` need admin-tier scopes (`Directory.Read.All`, `UserAuthenticationMethod.Read.All`) — full coverage under the admin triage deep-dive; under delegated user scope they register NotApplicable with the admin-context equivalent.

Delegated user-scope reads (no admin required, workflow B):

- `User.Read` — basic profile of /me
- `Mail.Read` — inbox, sent items, recoverable items (deleted phish)
- `MailboxSettings.Read` — inbox rules, server-side forwarding settings

## Usage

```powershell
# Basic
.\Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@corp.com

# Wider outbound window + threat intel
.\Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@corp.com -WindowDays 14 -EnableThreatIntel

# Non-interactive (for CI/SOAR/Task Scheduler)
.\Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@corp.com -NonInteractive -FailOnCriticalIoC
```

## Output

Per-user output directory `output/<user>/`:

- `<timestamp>-email-results.json` — raw collected data + findings + exceptions
- `<timestamp>-email-incident.html` — incident report (HTML, self-contained)
- `<timestamp>-email-incident.md` — Markdown summary

All output files self-hardened via `Set-NRGSensitiveFileContent` (v4.11.3 publisher self-hardening pattern). On Windows, ACLs restrict to the operator + Administrators before tenant data lands.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, no critical IoCs |
| 1 | Authentication failure |
| 2 | No findings produced |
| 3 | Partial collection (one or more collectors failed) |
| 4 | Fatal error |
| 10 | (Only with `-FailOnCriticalIoC`) Critical IoC found |

## Folder structure

```
Email-IR/
├── Lib/
│   ├── Connect-NRGEmailServices.ps1   delegated 3-scope Graph connection
│   └── Get-NRGThreatIntel.ps1          WHOIS + DNS helpers (no API key needed)
├── Collectors/
│   └── Invoke-NRGEmailCollectMailbox.ps1   sent + inbox + recoverable + rules + forwarding
├── Evaluators/
│   └── Test-NRGEmailControls.ps1       5 IoC checks
├── Publishers/
│   └── Publish-NRGEmailIncidentReport.ps1  HTML + Markdown incident report
├── Testing/
│   └── NRG.EmailIR.Tests.ps1           Pester suite (heuristic regression pins)
└── README.md                            (this file)
```

Auto-loaded by `NRG-Assessment.psm1` via the `$loadOrder` array — no separate import required. Drop into the same NRG-Assessment install.

## Privacy + scope notes

- **Body content NOT collected.** Only sender, recipients, subject, URLs (extracted via regex from `bodyPreview`), and attachment counts. Body itself is never retained, written to JSON, or rendered in the report.
- **Threat intel (opt-in only).** `-EnableThreatIntel` submits external sender domains to `rdap.org` for registration-age lookup. Operator's responsibility to confirm this fits the client's data-handling policy.
- **Read-only invariant preserved.** Inherits the tool-wide guarantee: no Graph writes, no mailbox modifications.
- **Recoverable Items.** Some tenants restrict the `recoverableitemsdeletions` endpoint under delegated scope. Falls back gracefully with a noted limitation.

## Limitations vs admin-scope IR

Things this tool **cannot** see at user-scope (would need admin):

| Need | Admin scope required |
|---|---|
| Sign-in audit log (IPs, locations, MFA challenges) | `AuditLog.Read.All` |
| ~~MFA method changes (attacker added their phone)~~ | Covered since v4.12.1 — `EMAIL-4.2` under admin triage deep-dive |
| ~~OAuth app consents this user granted~~ | Covered since v4.12.1 — `EMAIL-4.1` under admin triage deep-dive |
| Search-and-purge phish across other users | E5 Defender + admin role |
| Server-side `ForwardingSmtpAddress` | EXO Online — `Get-Mailbox` |
| Microsoft Defender alerts on this user | `SecurityEvents.Read.All` |

The HTML report includes a "Recommended Actions" section that calls out which of these to run from an admin context as follow-up.

## Containment & Recovery Runbook

Every per-user incident report renders a **Containment & Recovery Runbook** —
the operator's fixed next-steps sequence, with the tool filling in the
specifics for this user:

1. **Sign out all active sessions** — `Revoke-MgUserSignInSession -UserId <upn>` (UPN substituted)
2. **Re-require MFA** — delete any unrecognized auth method (attacker may have added their own)
3. **Reset the password** — after sessions are revoked, never live alongside an attacker session
4. **Delete the rules the attacker created** — each flagged inbox rule (from `EMAIL-1.1`) is named with a precise `Remove-MgUserMailFolderMessageRule -UserId <upn> -MailFolderId Inbox -MessageRuleId <id>` command
5. **Re-enroll MFA** — re-register a trusted method or issue a Temporary Access Pass
6. **Clear browser cache, history, and cookies** — on the user's device(s); stolen session cookies survive a password reset

Each step is tagged with where it runs: **Admin · PowerShell**, **Admin ·
Entra Portal**, or **On user device**. The runbook is also emitted in the
Markdown summary. The tool remains **read-only** — it *generates* these
commands; the operator runs them and issues the TAP in the Admin Center.

## Tests

```powershell
Invoke-Pester ./Email-IR/Testing/NRG.EmailIR.Tests.ps1 -Output Detailed
```

The suite pins the IoC scoring + phish-ranker heuristics against synthetic fixtures — a future refactor of scoring weights can't silently change verdicts.

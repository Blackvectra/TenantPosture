# Defender "malicious_tor_access" alert — cause and fix

## Symptom

Microsoft Defender **Behavioral Threat Protection** raises
`malicious_tor_access` against `pwsh.exe` while (or shortly after) running an
NRG-Assessment sign-in triage or Email-IR job:

```
Component:            Behavioral Threat Protection
Rule:                 malicious_tor_access
Application:          PowerShell 7 (pwsh.exe)
Status code:          c0400067
```

## Cause

This is **not malware and not a compromise.** Versions of the tool from
**before 2026-06-23** fetched a public Tor exit-node list from a
Tor Project host on the first sign-in-triage run,
to flag logins coming from Tor exit nodes.

That fetch is a legitimate threat-intel enrichment, but connecting to a Tor
Project host is exactly what Defender for Endpoint, Cortex XDR, and CrowdStrike
flag as Tor-infrastructure contact — **on the analyst's own machine.** The
alert fires on the enrichment call, not on anything malicious.

The outbound was **removed in commit `a614ca3`** (in `main`). If your endpoint
still alerts, it is running an **older installed/extracted copy** that predates
the removal — likely because no packaged release had been cut yet.

## Fix

1. **Update the installed copy to current `main`** (or the first `v4.13.0+`
   release, which is the first build to ship without the Tor fetch):

   ```powershell
   cd C:\path\to\NRG-Assessment
   git pull                     # if it's a clone
   # — or — replace the extracted folder with a fresh v4.13.0+ download
   ```

2. **Confirm the installed copy is clean** — this must return nothing.
   (`Select-String` has no `-Recurse` parameter — use `Get-ChildItem -Recurse`
   piped into it. `Testing\` is excluded because
   `NRG.NetworkEgress.Tests.ps1` — the guard that enforces this — legitimately
   quotes the pattern it's checking for, in its own `It` description and its
   `-imatch` line; that's the detector, not an offender.)

   ```powershell
   Get-ChildItem -Recurse -Include *.ps1,*.psm1 |
       Where-Object { $_.FullName -notmatch '\\Testing\\' } |
       Select-String -Pattern ('tor' + 'project') |
       Where-Object { $_.Line.TrimStart() -notlike '#*' }
   ```

3. **Dismiss the historical Defender alert** once updated — the behavior is
   gone, not suppressed.

## Why it can't come back

`Testing/NRG.NetworkEgress.Tests.ps1` (runs in CI on every PR) fails the build
if any non-comment source line references the Tor Project host or its bulk exit list, and
pins the full allowed-egress host list — a new outbound host is now a
deliberate, reviewed change.

## Tor detection

Standalone Tor-exit detection (the live exit-list fetch, and the
local-exit-list-file workaround that briefly replaced it) has been removed
from the tool entirely — no `-TorExitListPath`, no `Test-NRGIPIsTorExit`.
Tor sign-ins are still caught for **Entra ID P2 tenants**: Microsoft Identity
Protection labels them server-side via `anonymizedIPAddress` in
`riskEventTypes_v2`, and the triage scorer (`SIGNIN-1.2`) consumes that
signal unchanged — no outbound call, never did. P1 / no-P2 tenants have no
Tor-specific signal from this tool; the `SIGNIN-1.5` IP threat-intel control
(hosting/VPN ASN tagging via RDAP) still applies.

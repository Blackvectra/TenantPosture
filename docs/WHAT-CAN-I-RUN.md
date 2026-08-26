# What can I run?

Every entry point in this tool, what it needs, and what it gives you back.

Written because the tool grew past the point where that was obvious. If you are
coming back to this after six months, start here.

---

## The short version

| I want to… | Run this |
|---|---|
| Assess one client's tenant | `Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com` |
| Assess every client | `Invoke-NRGBatchAssessment.ps1` |
| Include their laptops | Add `-DeviceResults .\collected\client\` |
| Hand a client a NIST document | Add `-NISTMatrix` |
| Build a CMMC / 800-171 plan | Add `-SSP` |
| Find out who got phished | `Invoke-NRGSignInTriage.ps1` |
| Investigate one mailbox | `Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@client.com` |
| Print device guidance (no scan) | `New-NRGDeviceGuide.ps1` |
| Set up a new machine | `Install-NRGPrerequisites.ps1` |
| Actually change tenant settings | `Apply-NRGBaseline.ps1` — the only one that writes |

---

## Posture assessment

### `Invoke-NRGAssessment.ps1` — the main one

One tenant, 195 controls, client-ready report. Everything else orbits this.

```powershell
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com
```

**Needs:** a browser sign-in (or app-only cert — see `-AppId`/`-CertificateThumbprint`).
**Gives you:** two files in `output\<tenant>\` — the interactive report
(`<timestamp>-assessment.html`) and the machine record (`<timestamp>-results.json`).

The report defaults to **NIST only** — that is deliberate and specific to NRG.
Pass `-Framework All` for the four-framework view. It narrows the *report*, never
the assessment: every control keeps every citation and every framework is still
scored, so switching later costs nothing.

Parameters worth knowing:

| Flag | Effect |
|---|---|
| `-Framework NIST\|CIS\|SCuBA\|CMMC\|All` | Which frameworks the report shows. Default **NIST**. |
| `-NISTMatrix` | Also emit the standalone NIST-only matrix (Markdown + HTML + XLSX). |
| `-SSP` | Also emit the 800-171 Rev 2 System Security Plan (see below). |
| `-SSPAnswers <psd1>` | The client's written answers for the 69 requirements no scan reaches. |
| `-DeviceResults <folder>` | Fold in endpoint scan results (see below). |
| `-AllFiles` | Every sidecar deliverable, not just the two-file default. Implies `-NISTMatrix`. |
| `-Quick` | Critical + High controls only. Faster, noisier-free. |
| `-BaselineResults <json>` | Compare against a prior run, emit a drift report. |
| `-IncludePurview` | Purview is **skipped by default** (EOM WAM crash). Opt in. |
| `-FailOnCritical / -FailOnHigh / -FailOnScoreBelow` | Non-zero exit for CI or Task Scheduler. |
| `-JsonOnly` | Machine record only, no report. |

### `Invoke-NRGBatchAssessment.ps1` — every client, one login

Loops `Config\clients.json` using GDAP. One browser sign-in covers all tenants.

```powershell
.\Invoke-NRGBatchAssessment.ps1              # all active clients
.\Invoke-NRGBatchAssessment.ps1 -OnlyClient example.com
.\Invoke-NRGBatchAssessment.ps1 -WhatIf      # preview, connects to nothing
```

Per-client reports plus `output\batch-summary-<timestamp>.md`.

**Always `-WhatIf` first after editing clients.json.**

---

## Endpoints

### `Device\Invoke-NRGDeviceCompliance.ps1` — runs ON the laptop, not here

This one is different: you do not run it on your machine. It is pushed to
endpoints by ConnectWise RMM (or an Intune platform script) and runs **as
SYSTEM**. It is Windows PowerShell **5.1** — the only file in the repo that is —
because stock Windows does not have 7.

```powershell
# On the endpoint, via RMM
.\Invoke-NRGDeviceCompliance.ps1     # -> C:\ProgramData\NRG\device-compliance.json
```

35 checks: encryption and boot integrity, malware defence, network exposure,
accounts, patch state, session lock, legacy surface, audit policy.

**Run it elevated.** Nine checks need administrative rights; run without and they
report `NotAssessed` — never a pass, never a failure — and the run is flagged
partial.

Then collect the JSONs and feed them back in:

```powershell
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com `
    -DeviceResults .\collected\client\ -NISTMatrix
```

Findings aggregate per control with the failing hostnames attached — one row
reading "41 of 60 failing", not 2,100 rows.

---

## Incident response

Separate from posture assessment. These are for when something has *happened*.

### `Invoke-NRGSignInTriage.ps1` — "who got popped?"

You suspect compromise but do not know who. Pulls tenant sign-in logs, scores
every user for IoCs (failed→success bursts, anonymous IP / Tor, impossible
travel, risky users), ranks them, then deep-dives the top scorers' mailboxes in
the same session.

**Needs:** admin sign-in. **Gives you:** `output\IR-Triage\`.

`Invoke-NRGBatchSignInTriage.ps1` runs the same sweep across every GDAP client —
the morning check.

### `Invoke-NRGEmailAssessment.ps1` — one mailbox, deep

You already know which user. Inbox rules, forwarding, outbound activity, phish
origin, auth methods, OAuth consents.

```powershell
.\Invoke-NRGEmailAssessment.ps1 -UserPrincipalName alice@client.com
```

**Runs with the user's own credentials — no admin scope needed.** That matters
when you are working an incident and cannot wait for admin access.

Output: `output\<upn>\<timestamp>-email-incident.html`.

---

## Documents (no scanning)

### `-SSP` — the CMMC / 800-171 plan

Not a separate script — a switch on the main assessment. Emits a worked System
Security Plan against all 110 NIST SP 800-171 Rev 2 requirements, as Markdown,
HTML and an XLSX working copy.

```powershell
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com -SSP `
    -SSPAnswers .\Config\ssp\client.com.psd1
```

Each requirement answers four questions: is it in place, what proves it, how do
we close it, and **what will closing it do to the business**. That last one is
why the document exists — it is the question a client asks back at every gap
list, and the answer lives in `Config/operational-impact.json`.

**41 of the 110 are evidenced by the scan. The other 69 are not**, and the plan
says so on the first page and lists them on the last. Those are policy,
process, physical and personnel; you answer them in
`Config/ssp/<client>.psd1` — copy `Config/ssp/example.psd1` and fill it in.
Answers survive between assessments instead of being retyped every year.

A status you assert in the answers file renders stamped *client-attested* and
never counts as tool-verified. That is deliberate and not adjustable.

### `New-NRGDeviceGuide.ps1` — connects to nothing

Reference material for devices. No sign-in, no Graph, no endpoint access — so it
works before a tenant is attached, during a sales conversation, or on a site with
nothing open.

```powershell
.\New-NRGDeviceGuide.ps1 -ClientName 'Example Client'
```

Produces two documents:

- **`nist-device-guide.md/.html`** — 31 NIST controls organised by control, with
  98 implementation options and the evidence to keep. The auditor's lens.
- **`nist-device-guide-baseline.md/.html`** — the same material as a build
  standard, 27 requirements across procure → provision → harden → in-service →
  offboard. The technician's lens.

`-ResultsPath <results.json>` annotates the guide with a prior run's verdicts.
It never changes what the guide *recommends* — only what it reports as done.

---

## Setup and write mode

### `Install-NRGPrerequisites.ps1`

Run once on a fresh machine. Installs and pins the modules (EOM at 3.2.0),
sets execution policy, unblocks files, optionally installs Python + openpyxl for
XLSX output.

Run it **elevated** if your PowerShell module path is inside OneDrive — it will
tell you if it is.

### `Apply-NRGBaseline.ps1` — ⚠ the only script that writes

Everything else in this repo is read-only without exception. This one changes
tenant configuration. Mandatory `-WhatIf` support, `-Confirm` on auth-policy and
admin-role changes.

---

## Where things live

```
Config/          the data you edit — controls, clients, branding, device rules
Collectors/      pull raw data from a tenant (or, for Device/, read result files)
Evaluators/      turn raw data into findings
Publishers/      turn findings into documents
Lib/             shared helpers — scoring, NIST rollups, escaping, file ACLs
Device/          the endpoint script. PS 5.1. Does not run on your machine.
Testing/         35 Pester suites. Run: Invoke-Pester ./Testing/
docs/            this file, and the policy docs
```

**The config files are the ones you will actually edit:**

| File | What it holds |
|---|---|
| `clients.json` | Your client list — TenantId, DelegatedOrg, skip flags |
| `controls.json` | The 195 tenant controls and every framework citation |
| `device-controls.json` | The 35 endpoint checks (`DEV-*`) |
| `device-baseline.json` | The 27-item build standard |
| `nist-physical.json` | The 31 physical / media / device controls |
| `nist-800-53-catalog.json` | Official 800-53 Rev 5 titles |
| `nist-800-171-r2.json` | The 110 CMMC L2 requirements and their 800-171A objectives |
| `operational-impact.json` | What enabling each control does to the business |
| `ssp/<client>.psd1` | Your answers for the 69 requirements no scan reaches |
| `branding.psd1` | Company name, colours, rates |

---

## What this tool does not do

Worth knowing so you do not promise it:

- **Six of the twenty 800-53 families have no technical coverage** — Planning,
  Program Management, Risk Assessment, System and Services Acquisition, Supply
  Chain Risk Management, PII Processing. Those are documents and processes; no
  scanner reaches them.
- **Network equipment is not assessed.** Switches, firewalls and access points
  need config ingestion, which does not exist yet.
- **Physical and environmental controls are never scored** — locked rooms, badge
  logs, certificates of destruction. They appear in the device guide as
  attestation items and are deliberately never claimed as compliant.
- **Nothing here is a CIS benchmark scanner.** The 35 endpoint checks are a
  NIST-mapped subset, not the several hundred recommendations in a CIS Benchmark.

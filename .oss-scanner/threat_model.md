# Threat model

Read by the OSS Scanner before it starts. Free text, kept short.

## What this project does and where untrusted input enters

TenantPosture is a PowerShell 7 module an MSP runs from a workstation against a
customer's Microsoft 365 tenant. It reads configuration through Microsoft Graph,
Exchange Online, Teams, Security & Compliance and SharePoint PowerShell, evaluates
it against a control catalog, and writes reports (HTML, Markdown, XLSX, JSON) to a
local `output/` folder. It is read-only toward the tenant by design: no collector,
evaluator or publisher writes tenant configuration. The one write-mode script,
`Apply-TPBaseline.ps1`, is separate, is never loaded by the module, and takes
`-WhatIf`.

Untrusted input, in order of concern:

1. **Tenant data returned by the Microsoft APIs.** Display names, policy names,
   inbox-rule names and recipients, group names, DNS TXT records, domain names,
   application names and so on are chosen by the tenant or by an attacker who
   already has a foothold in it. All of it flows into the HTML report, the
   Markdown summary, the XLSX workbook and the results JSON. The HTML report is
   opened in the operator's browser.
2. **Public DNS and certificate-transparency answers** (`Collectors/DNS/`):
   DNS-over-HTTPS JSON from Cloudflare and Google, `Resolve-DnsName` output,
   and `crt.sh` JSON. Parsed, then rendered in the reports.
3. **Files the operator replays or ingests.** A prior run's results JSON
   (`-FromResults`), endpoint results JSON produced on customer devices
   (`-DeviceResults`), ScubaGear results (`-ScubaResultsPath`), questionnaire
   workbooks (`Import-TP*Questionnaire.ps1`), and PSD1 data files under `Config/`
   (`clients.json`, SSP answers, baseline exceptions, profiles). The PSD1 files
   are read with `Import-PowerShellDataFile`; they must never be executed.
4. **The local web GUI** (`Invoke-TPAssessment.ps1 -Web`, `Lib/Start-TPWebServer.ps1`,
   `Web/`, `Lib/*Web*.ps1`): a
   Pode server bound to loopback that lists runs and serves report files. Its
   threat is a web page in the operator's browser (DNS rebinding, cross-site
   requests, path traversal through run ids and folder names), not the network.
5. **Command-line parameters and environment** (`-TenantDomain`, `-Profile`,
   `TP_PROFILE`, `-OutputPath`): operator-supplied, but a profile or tenant
   name becomes part of a file path.

The sign-in itself is delegated to the Microsoft modules; the tool holds tokens
in memory only.

## Components that matter most / least

Most:

- `Publishers/` and `Web/`: every place tenant data is written into HTML or
  Markdown. Missing or wrong escaping here is script execution in the operator's
  browser with the report's contents, which include the customer's security
  posture.
- `Lib/Resolve-TPWebRunPath.ps1`, `Lib/Test-TPWebRequestAllowed.ps1`,
  `Lib/Get-TPWebRunIndex.ps1`: the only code that turns a request into a path.
- `Collectors/DNS/Invoke-TPCollectDNSEmailRecords.ps1` and
  `Lib/Resolve-TPDns.ps1`: parsing of external JSON and DNS records.
- Anything that builds a file path from a name: output file naming in the entry
  points, `TenantPosture.psm1` profile loading, `Lib/Set-TPBaselineException.ps1`,
  `Lib/New-TPProfile.ps1`, `Lib/Get-TPSSPAnswers.ps1`.
- The results JSON writer: it must never contain tokens, credentials or user data
  beyond UPN and display name.

In scope but secondary: evaluators (`Evaluators/`), which decide verdicts. A
wrong verdict is a correctness bug, not a vulnerability, unless an attacker in
the tenant can craft data that makes a control read as satisfied.

Least / out of scope:

- `Device/Invoke-TPDeviceCompliance.ps1` runs on endpoints as SYSTEM under
  Windows PowerShell 5.1 and only reads local state and writes one JSON file.
  In scope for what it writes, not for the registry reads.
- `Testing/`, `Email-IR/Testing/`, `tools/`, `docs/`, `baselines/`: tests and
  documentation.
- `Apply/` and `Apply-TPBaseline.ps1`: write mode, operator-driven, behind
  `-WhatIf`/`-Confirm`. Changes to tenant configuration there are intended.
- Remediation text in `Config/controls.json` naming write cmdlets is
  documentation for a human, not executed.

## How to exercise it

- `Import-Module ./TenantPosture.psm1` loads everything without the Microsoft
  modules. Collectors cannot run without a tenant, but every evaluator and
  publisher can be driven from fixtures.
- `Testing/` holds about 2,600 Pester tests. `TP.SmokeRun.Tests.ps1` runs the
  real entry point against stubbed Graph/Exchange/Teams modules and produces a
  full report set; `TP.GoldenFixtures.Tests.ps1` and `TP.OutputParity.Tests.ps1`
  feed fixtures through the publishers. Fixtures are inline in the tests and
  carry raw API shapes, not derived fields.
- `Invoke-TPAssessment.ps1 -FromResults <results.json>` republishes every report
  from a JSON file with no sign-in, which is the easiest way to drive the
  publishers with crafted data.
- `TP.WebServer.Tests.ps1` tests the request policy and path resolver as pure
  functions; the real-server context needs Pode (not installed in the image).

## How you rate severity

- Script or HTML injection into any report or GUI page from tenant-controlled
  data: **high**. The report is opened by the operator, who holds admin access
  to the tenant.
- Path traversal or symlink following in the web GUI, or a request from another
  origin that the policy admits: **high**.
- Execution of a data file (`Import-PowerShellDataFile` replaced by something
  that runs code, or `Invoke-Expression` over any input): **critical**.
- Tokens, credentials or secrets written to disk or into a report: **critical**.
- A path built from a tenant name, profile name or run id that escapes the
  intended folder: **high**.
- Denial of service against the local tool from malformed API data: **low**
  unless it causes a false "satisfied" verdict, which is **medium**.
- Any change that lets the module perform a write against the tenant: **high**,
  by the read-only contract.

## Anything to leave alone

- Reports naming `Set-*`, `New-*`, `Remove-*` cmdlets in remediation text are
  expected; `TP.ClientRegistry.Tests.ps1` already proves none are invoked.
- `Device/` is Windows PowerShell 5.1 on purpose and the only file allowed below
  the `#Requires -Version 7` floor.
- `Set-StrictMode -Version Latest` is active module-wide; a property read on an
  absent field throws. That is intended, and `Get-TPObjectField` is the guard.
- Pode's own error page for unrouted paths is outside the GUI's JSON contract
  and is documented as such.

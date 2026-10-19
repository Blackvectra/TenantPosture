# Security Policy — TenantPosture

## Read-Only Posture

This tool is **read-only by design.** No cmdlets that write, modify, or delete tenant data are executed during an assessment run. The evaluators contain remediation command strings as documentation only — they are never executed.

Enforced by: CI static analysis (`Read-Only Posture` test in `TP.Security.Tests.ps1`) verifies no tenant write cmdlets appear outside of `-Remediation` strings in any production file.

Two sanctioned write paths ship in this repository. Neither executes during an assessment run:

1. `Register-TPTenantApp` — optional onboarding helper that creates a read-only enterprise app in a customer tenant. Gated behind `-RegisterApp` + `SupportsShouldProcess` (`-WhatIf` / `-Confirm`).
2. `Apply-TPBaseline.ps1` and the scripts it dot-sources from `Apply/` — the explicit write-mode remediation tool, which modifies tenant configuration by design. It is a separate entry point, never invoked by `Invoke-TPAssessment.ps1`, and carries mandatory `-WhatIf` support with `-Confirm` on auth-policy and admin-role changes.

---

## Data the Tool Writes

An assessment's results JSON and reports carry tenant configuration, verdicts and, where a finding names an object, that object's UPN or display name — nothing more about a person, and never a token or a credential. Every results file is written through `Set-TPSensitiveFileContent`, which restricts the file's ACL to the operator.

The incident-response mode (`Invoke-TPSignInTriage.ps1`, `Invoke-TPBatchSignInTriage.ps1`, `Invoke-TPEmailAssessment.ps1`) is the documented exception, because its indicators are the data. For the window it reads, its JSON and reports carry:

- each sign-in's source IP address, Microsoft's geolocation of it (city, state, country and the coordinates Graph records), client application, device details, risk state, Conditional Access result and authentication details, with the account's UPN and display name;
- each registered authentication method's type, registration time and display value — a phone number is masked at collection to its country code and last two digits (`ConvertTo-TPMaskedPhone`: `+1 2065550100` is stored as `+1 ********00`), enough to ask the user whether the number ending in 00 is theirs;
- the mailbox's own record: the account's id, display name, mail address and UPN; every inbox rule as Graph returns it (name, conditions, actions, forwarding and redirect addresses, enabled state), because a rule is the indicator; the mailbox settings' language, time zone, working hours, delegate delivery option and automatic-reply state;
- every OAuth consent the account granted: the grant id, the client service principal id, the application's display name, application id and publisher, the consent type and the scopes;
- for each message read, the sender, recipients, subject, attachment count and the URLs found in the first ~250 characters of the body, each stored through `ConvertTo-TPRedactedUrl`: the host, path and ordinary parameters stay (the link is the indicator), and the value of a credential-bearing parameter (`sig=`, `token=`, `access_token=`, `code=`, `key=`, a name ending in `token`, `secret`, `password`, `signature` or `credential`) and any `user:password@` before the host are replaced by `[redacted]`. Message bodies are never retained, and neither are the automatic-reply texts a mailbox may have configured (only their state, audience, schedule and whether a text is set).

Treat `output\IR-Triage\` and `output\<user>\` as incident evidence: hand them to the client or the incident lead, keep them under the client's retention rule and delete them when the case closes. `Email-IR/Testing/TP.IRDataContract.Tests.ps1` drives the real collectors and fails if a full phone number or a credential-bearing query value reaches the raw data.

Two lookups leave the workstation, both through `rdap.org` and both carrying only the value looked up, nothing about the tenant: the sign-in triage submits each flagged sign-in IP address for its registrant and ASN (on by default; `-EnableThreatIntel:$false` on `Invoke-TPSignInTriage.ps1` or `Invoke-TPBatchSignInTriage.ps1` sends nothing), and the mailbox assessment submits external sender domains for their registration age only when `-EnableThreatIntel` is passed. `rdap.org` is a redirector: it answers with a redirect to the authoritative RDAP server, which the request follows, so an IP address is also disclosed to the regional registry responsible for it (ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC) and a domain to its top-level-domain registry's RDAP service. A firewall rule or a data-handling review must cover those destinations, not only `rdap.org`. Confirm the client's data-handling policy permits the lookups before running with them on.

---

## Reporting a Vulnerability

We follow a **coordinated vulnerability disclosure** model aligned to NIST SP 800-218 (SSDF), CISA's Secure-by-Design pledge, and CISA Binding Operational Directive 20-01 ("Develop and Publish a Vulnerability Disclosure Policy"). Researchers who report in good faith are protected by the [Safe Harbor](#safe-harbor) clause below.

### How to report

**Preferred (private):** Open a private security advisory via the repository's [Security tab → "Report a vulnerability"](https://github.com/Blackvectra/TenantPosture/security/advisories/new). This routes the report directly to the maintainers, keeps it private until coordinated disclosure, and produces a CVE if applicable.

**Alternative (email):** `support@nextlayersec.dev`. Subject line: `[TenantPosture SECURITY] <one-line summary>`.

**Do NOT** open a public GitHub issue, post in a forum, or disclose on social media until the coordinated-disclosure window has closed.

### What to include

- Affected version(s) — output of `Get-Module TenantPosture | Select-Object Version`
- Affected component — file path, function name, control ID, or evaluator
- Reproducer — minimal PowerShell snippet, command sequence, or step-by-step instructions
- Impact — what an attacker can achieve, what data is exposed, what assumptions must hold
- Suggested mitigation if you have one
- Whether you intend to publish your own write-up, and on what timeline

### Our response commitments

| Stage | Target SLA | Notes |
|---|---|---|
| Acknowledgement | **3 business days** | Confirms we received the report and have an owner |
| Initial triage | **7 business days** | Severity assessment + scope confirmation + assigned tracking ID |
| Status updates | **Every 14 days** | Progress, blockers, expected fix date |
| Fix released | **Severity-dependent** (see below) | Coordinated with reporter before public disclosure |
| Public advisory + CVE | **At fix release** | Or 90 days after triage, whichever is sooner |

**Fix-release SLA by severity** (CVSS 3.1 base score):

| Severity | CVSS | Target |
|---|---|---|
| Critical | 9.0–10.0 | 7 calendar days |
| High | 7.0–8.9 | 30 calendar days |
| Medium | 4.0–6.9 | 60 calendar days |
| Low | 0.1–3.9 | Next scheduled release |

If 90 days elapse from triage without a fix, we will publish the advisory with the agreed-upon mitigation guidance, even if a complete fix is not yet available. Researchers may request a shorter or longer window in extenuating circumstances.

### What's in scope

- The PowerShell module (`TenantPosture.psm1`, `Lib/`, `Collectors/`, `Evaluators/`, `Publishers/`, `Email-IR/`) and all entry scripts (`Invoke-TPAssessment.ps1`, `Invoke-TPBatchAssessment.ps1`, `Invoke-TPSignInTriage.ps1`, `Invoke-TPBatchSignInTriage.ps1`, `Invoke-TPEmailAssessment.ps1`, `Install-TPPrerequisites.ps1`)
- The write-mode remediation tool (`Apply-TPBaseline.ps1` and `Apply/`) — the only code in this repository that modifies tenant configuration
- The HTML/Markdown/XLSX/JSON report artifacts (XSS, injection, sensitive-data leakage in output)
- The control definition pipeline (`Config/controls.json`, schema validation, framework citations)
- The local web GUI (`Lib/Start-TPWebServer.ps1`, `Web/`) — loopback-only by design
- The tenant onboarding helper (`Onboard/Register-TPTenantApp.ps1`, outside the module)
- CI/CD workflows (`.github/workflows/`)
- Sample reports, sample data, documentation that could mislead operators
- Supply-chain integrity (Authenticode signing, SBOM, dependency pinning)

### What's NOT in scope

- Vulnerabilities in upstream Microsoft Graph SDK, ExchangeOnlineManagement, MicrosoftTeams, Pode, or other declared dependencies — report those to the respective project
- Vulnerabilities in Microsoft 365 itself or in a tenant's configuration (this tool just reads and reports them)
- DoS via maliciously crafted `controls.json` if you can already write to the repo (you've already won)
- "Information disclosure" of data the operator already has access to (the tool prints tenant inventory by design)
- Findings that require an attacker to already have administrative access to the operator's workstation

---

## Safe Harbor

NRG Technology Services / NextLayerSec LLC considers good-faith security research that complies with this policy to be **authorized activity** and will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, destruction of data, and interruption or degradation of services
- Do not exploit a discovered vulnerability beyond what's necessary to confirm it
- Do not exfiltrate any data and stop testing as soon as a vulnerability is confirmed
- Do not publicly disclose the vulnerability before we have had a chance to fix it (per the SLA above)
- Report only to the channels listed in this document
- Do not engage in social engineering or physical attacks against NRG Technology Services / NextLayerSec LLC employees

Researchers who comply with this policy will be acknowledged in the advisory (with consent) and in this repository's `SECURITY-CREDITS.md` if/when one is created.

---

## Security Controls Applied

### OWASP Top 10:2021

| Control | Implementation |
|---|---|
| A01 — Broken Access Control | `-LiteralPath` on all file ops; path traversal checks on `OutputPath`, `ClientsFile`, config files; tenantTag sanitized before use in output paths |
| A02 — Cryptographic Failures | TLS 1.2/1.3 enforced at entry; process-scoped MSAL token cache; no credential serialization |
| A03 — Injection | `[ValidatePattern]`/`[ValidateSet]`/`[ValidateScript]` on all parameters; controls.json content validated against allowlists; HTML output through `ConvertTo-TPHtmlSafe` |
| A04 — Insecure Design | Read-only architecture; fail-closed on missing security helpers; session cleanup in `finally` |
| A07 — Auth Failures | `try/finally` guarantees EXO/Graph disconnect; process-scoped MSAL prevents cross-session token leakage |
| A08 — Supply Chain | No `Install-Module` in production code; `PSResourceGet` with version pinning recommended; Gitleaks + TruffleHog in CI |
| A09 — Logging Failures | `-Encoding utf8` on all `Out-File`; no plaintext HTTP |
| A10 — SSRF | All outbound requests use validated URLs; DNS queries use validated FQDNs only |

### ASVS v5 Controls

| Control | Implementation |
|---|---|
| V5.1.3 — Input Validation | All parameters validated; controls.json content validated against allowlists |
| V7.3.2 — Session Termination | `finally` block guarantees `Disconnect-TPServices` runs |
| V11.2.2 — TLS | `[Net.ServicePointManager]::SecurityProtocol = Tls12 -bor Tls13` at entry |
| V12.3.1 — Path Traversal | `-LiteralPath` universally; `GetFullPath()` origin checks on all config files |
| V16.2.3 — Output Encoding | `-Encoding utf8` on all `Out-File` calls |
| V16.4.1 — Error Handling | `Set-StrictMode -Version Latest` + `$ErrorActionPreference = 'Stop'` on all files |

### CVE-2025-54100

`#Requires -Version 7.0` on every production file blocks the PS 5.1 MSHTML injection vulnerability.

---

## controls.json Security

The JSON control definition file is validated at load time before any evaluator runs:

- **ControlId format** — `^[A-Z]{2,4}-\d{1,3}\.\d{1,3}$`
- **Severity allowlist** — Critical, High, Medium, Low, Informational only
- **Workload allowlist** — AAD, EXO, DNS, DEF, SPO, TMS, INT, PVW, PPL only
- **Category allowlist** — Identity, Email, Endpoint, Data, Collaboration, Governance, Network only
- **Prefix/Workload consistency** — ControlId prefix must match declared Workload
- **Remediation injection scan** — `<script>`, `javascript:`, `on*=` patterns throw
- **Duplicate detection** — duplicate ControlIds throw before any evaluator sees data
- **Fail-closed** — any violation throws before the first evaluator runs

---

## CI/CD Security Pipeline

Each row below names the workflow file that implements it, so this list can be verified against `.github/workflows/` at any time.

**On every push and pull request to `main`** (Dependency Review on pull requests only):


1. **PSScriptAnalyzer** (`ci.yml`) — static analysis; Error severity fails the build. Findings upload to Code Scanning as SARIF. A separate **PowerShell Security Analysis** job (`tools/Invoke-TPSecurityAnalysis.ps1`, rules in `PSScriptAnalyzerSecurity.psd1`) runs the analyzer's security rules (Invoke-Expression, plain-text and wrongly typed credentials, unencrypted authentication, broken hash algorithms, hard-coded computer names) at every severity; any finding fails the build, and an in-source `[SuppressMessage()]` counts as a finding. The same job runs Microsoft's **InjectionHunter** rules (code-injection patterns, which CodeQL does not analyze in PowerShell); a finding passes only when reviewed into `tools/injection-baseline.json` with its reason, or when it is a `-replace` proven by the AST to replace only with the empty string, and a baseline entry nothing matches fails as stale. CI installs PSScriptAnalyzer, Pester and Pode by exact version and SHA-256 (`tools/pinned-modules.psd1`, `tools/Install-TPPinnedModule.ps1`): a gallery package whose hash differs is refused before it is read.
2. **Pester** (`ci.yml`) — OWASP/ASVS security invariants (static + runtime).
3. **CodeQL** (`codeql.yml`) — scans the GitHub Actions workflow YAML for supply-chain weaknesses; `security-extended` + `security-and-quality` query packs.
4. **Gitleaks** (`secret-scan.yml`) — fast regex/entropy secret detection across full git history.
5. **TruffleHog** (`secret-scan.yml`) — verified secret scan; confirms candidates against live services to suppress false positives.
6. **Dependency Review** (`dependency-review.yml`) — blocks PRs that introduce moderate-or-higher severity vulnerable dependencies.
7. **zizmor** (`zizmor.yml`) — static security analysis of the workflows themselves (template injection, token permissions, persisted credentials, cache poisoning, impostor commits, known-vulnerable actions, Dependabot cooldown) at its strictest persona; any finding fails the build, and a deliberate exception is suppressed in place with a stated reason. Installed by exact version and SHA-256; also weekly. `TP.WorkflowSecurity.Tests.ps1` pins the gate, SHA-pinned actions, `persist-credentials: false`, a concurrency group and no workflow-level write access.
8. **OSS Scanner image** (`oss-scanner-image.yml`) — builds `.oss-scanner/Dockerfile` (base image by digest, Python packages by SHA-256, PowerShell modules through the pinned installer) and starts the image with no network, on every change to its inputs and weekly, so a broken pin fails a pull request instead of a scanner submission.

**On a weekly schedule:**

9. **OSSF Scorecard** (`scorecard.yml`) — repository security-health metric (branch protection, pinned deps, token permissions, etc.); results upload to Code Scanning.
10. **Gitleaks / TruffleHog full-history sweep** (`secret-scan.yml`) — catches secrets introduced via force-push or a branch that bypassed PR review.

**On version tags (`v*`):**

11. **CycloneDX SBOM** (`release.yml`) — software bill of materials generated from `tools/Generate-SBOM.ps1` and attached to the workflow run.
12. **Authenticode + integrity check** (`release.yml`, windows-latest) — verifies the integrity manifest and Authenticode signature status. Fails on tamper (HashMismatch / Expired / UntrustedRoot); tolerates unsigned in-house builds (operator signs locally via `Build/Sign-Release.ps1`).

**Dependency hygiene:** Dependabot (`dependabot.yml`) opens weekly PRs for GitHub Actions version bumps; every third-party action is SHA-pinned.

---

## Threat Model

See `docs/security/THREAT-MODEL.md` for the full threat model including:
- Trust boundaries (tenant data, config files, output files)
- Attack vectors considered
- Accepted residuals with rationale
- Supply chain risk assessment

---

## Secure Development Framework Alignment

TenantPosture self-attests to NIST SP 800-218 (SSDF) practices. See [`docs/SECURE-DEVELOPMENT.md`](docs/SECURE-DEVELOPMENT.md) for the per-task mapping (PO, PS, PW, RV practice families) and the evidence trail.

OpenSSF Best Practices self-assessment is tracked in [`docs/OPENSSF-BEST-PRACTICES.md`](docs/OPENSSF-BEST-PRACTICES.md).

---

## Incident Response

If you suspect a credential leak, malicious dependency, signed-release tamper, or active tenant compromise observed during an assessment, follow [docs/INCIDENT-RESPONSE.md](docs/INCIDENT-RESPONSE.md) — a per-scenario runbook covering containment, eradication, and customer notification timelines.

---

*TenantPosture v4.12.1 · Hardened against OWASP Top 10:2021, ASVS v5, CVE-2025-54100 · NIST SP 800-218 (SSDF) aligned · CISA BOD 20-01 VDP compliant*

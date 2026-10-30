# Security testing methodology

What each check in CI tests, which phase of a penetration test it corresponds
to, and which phases nothing here automates. The frame is the Penetration
Testing Execution Standard (PTES); the OSSTMM vocabulary is noted where it
differs. The point of the mapping is the gaps as much as the coverage: an
automated scan is evidence about one phase, never a penetration test.

## The scans, by PTES phase

| PTES phase | OSSTMM channel / idea | What runs here | Where |
|---|---|---|---|
| Pre-engagement | Scope, rules of engagement | The tool is read-only by contract; the scope of every check is the repository and the local web GUI. No tenant is ever a target of a scan. | `SECURITY.md`, `CLAUDE.md` |
| Intelligence gathering | Posture review | The dependency inventory: SBOM on release, Dependabot over every ecosystem, pinned versions and digests, the weekly gallery freshness check. | `release.yml`, `dependabot.yml`, `tools/Test-TPPinnedModuleFreshness.ps1` |
| Threat modeling | Trust boundaries, attack surface | Written threat model: where untrusted input enters (tenant data rendered into reports, DNS answers, replayed files, questionnaire PDFs, the local GUI) and how each is bounded. | `docs/security/THREAT-MODEL.md`, `.oss-scanner/threat_model.md` |
| Vulnerability analysis — static (SAST) | Code review, data-network security | PSScriptAnalyzer security rules at every severity, InjectionHunter (code-injection patterns), CodeQL over the workflows, zizmor over the workflows, gitleaks and TruffleHog over the history. Any unreviewed finding fails. | `ci.yml`, `codeql.yml`, `zizmor.yml`, `secret-scan.yml` |
| Vulnerability analysis — dynamic (DAST) | Active probing of the running system | OWASP ZAP's baseline scan against the real `-Web` server on loopback: spider, browser-driven AJAX spider, passive checks of every response (headers, CSP, cookies, caching, disclosure, cross-domain). Any alert not reviewed with a reason fails. | `dast.yml`, `.zap/rules.tsv` |
| Vulnerability analysis — artifact | Supply-chain inspection | Trivy over the built OSS Scanner image (operating system and package CVEs, HIGH and CRITICAL) and over its Dockerfile (misconfiguration rules at every severity). Any finding fails unless reviewed with a statement; a CVE the distribution has not fixed is excluded, since nothing here can act on it. | `oss-scanner-image.yml`, `.trivyignore.yaml` |
| Vulnerability analysis — fuzzing | Input validation under malformed data | A deterministic mutation fuzzer runs every parser that reads untrusted input (results JSON, MCP JSON-RPC lines, XCCDF/ARF, ScubaGear results, endpoint result files, DoH TXT data, web path segments) and the three output escapers. It checks each one's contract on every case: answer or refuse with a fixed sentence that never echoes the input; no crash on an omitted field; no hang; an allowed path stays inside the output folder; escaped text forms no markup; a generated literal parses back to its input. The seed is fixed (`TP_FUZZ_SEED`), so a failure reproduces, and `TP_FUZZ_ITERATIONS` lengthens a local run. | `Testing/TP.Fuzz.Tests.ps1`, `tools/TPFuzz.ps1` |
| Vulnerability analysis — active (DAST) | Active probing with attack payloads | OWASP ZAP's active scanner (`.zap/active-scan.yaml`, ZAP Automation Framework) against the same loopback server and fixture: injection, path traversal, header and parameter tampering on every route, with the URL path and the request headers as input vectors, because the routes take their input from the path and the request policy judges Host, Origin and Sec-Fetch-Site. `tools/Test-TPZapActiveScan.ps1` fails on any alert not reviewed IGNORE in `.zap/rules.tsv`, on a scan that reached nothing, and on any new entry in the output folder. | `dast.yml` (job `zap-active`), `.zap/active-scan.yaml` |
| Exploitation | Verification by exploit | **Partly automated.** The ZAP active scan sends attack payloads and reports what they provoke, but it does not take a finding further to show its consequence. The Pester suites prove specific attacks fail against the request guard and the path resolver (traversal, Host-header rebinding, forged Origin, method tampering, Trojan Source), which is an exploit attempt in test form, but no scanner here attempts exploitation of a live finding. | `Testing/TP.WebServer.Tests.ps1`, `TP.Security.Tests.ps1` |
| Post-exploitation | Impact, persistence, lateral movement | **Not applicable to the tool itself** and not attempted. The deliverables' honesty rules (no false `Implemented`, no reassurance text, an unassessed control is named) are the controls against the tool being used to understate a tenant's exposure. | `CLAUDE.md` honesty rules, `TP.AssessmentScope.Tests.ps1` |
| Reporting | Findings with evidence and reproduction | Every scanner writes SARIF to Code Scanning or an artifact with the request, response and rule; every reviewed exception records its reason beside the rule it accepts. | `tools/injection-baseline.json`, `.zap/rules.tsv`, `.trivyignore.yaml` |

## What this is not

- **Not a penetration test.** A penetration test of this tool would exploit a
  finding to show its consequence. Nothing here does. The baseline scan says
  what the server sends; the active scan tries known attacks against it and
  reports what they provoke, but it follows no finding further.
- **Not a test of a tenant.** The tool assesses Microsoft 365 configuration
  and never probes a client's systems; the scans above target the repository
  and a loopback server over fixture data.
- **Not an attack on `/api/scan`.** The active scan excludes `POST
  /api/scan`, because an accepted request starts a real assessment against the
  domain in its body; its validation is tested by `TP.WebServer.Tests.ps1`
  instead. The active job also fails if the output folder gains an entry
  during the scan, which is how a request reaching that route would show.

## Reviewing an exception

A scan whose exceptions nobody can audit has stopped scanning. Each file keeps
the reason beside the rule, and a test fails an entry without one:

| File | Scanner | What an entry must carry |
|---|---|---|
| `tools/injection-baseline.json` | InjectionHunter | path, rule, the flagged text, a count, a reason |
| `.zap/rules.tsv` | ZAP | rule id, `IGNORE`/`WARN`/`FAIL`, a reason of more than sixty characters |
| `.trivyignore.yaml` | Trivy | `id` (a `DS-` rule or a CVE), a `statement` of more than sixty characters |

Fix the code when the code is wrong. An exception is for a finding that is
true and accepted, with the reason it is accepted written where the next
reader finds it.

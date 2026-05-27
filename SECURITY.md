# Security Policy — NRG-Assessment

## Read-Only Posture

This tool is **read-only by design.** No cmdlets that write, modify, or delete tenant data are executed during an assessment run. The evaluators contain remediation command strings as documentation only — they are never executed.

Enforced by: CI static analysis (`Read-Only Posture` test in `NRG.Security.Tests.ps1`) verifies no tenant write cmdlets appear outside of `-Remediation` strings in any production file.

---

## Security Controls Applied

### OWASP Top 10:2025

| Control | Implementation |
|---|---|
| A01 — Broken Access Control | `-LiteralPath` on all file ops; path traversal checks on `OutputPath`, `ClientsFile`, config files; tenantTag sanitized before use in output paths |
| A02 — Cryptographic Failures | TLS 1.2/1.3 enforced at entry; process-scoped MSAL token cache; no credential serialization |
| A03 — Injection | `[ValidatePattern]`/`[ValidateSet]`/`[ValidateScript]` on all parameters; controls.json content validated against allowlists; HTML output through `ConvertTo-NRGHtmlSafe` |
| A04 — Insecure Design | Read-only architecture; fail-closed on missing security helpers; session cleanup in `finally` |
| A07 — Auth Failures | `try/finally` guarantees EXO/Graph disconnect; process-scoped MSAL prevents cross-session token leakage |
| A08 — Supply Chain | No `Install-Module` in production code; `PSResourceGet` with version pinning recommended; Gitleaks + TruffleHog in CI |
| A09 — Logging Failures | `-Encoding utf8` on all `Out-File`; no plaintext HTTP |
| A10 — SSRF | All outbound requests use validated URLs; DNS queries use validated FQDNs only |

### ASVS v5 Controls

| Control | Implementation |
|---|---|
| V5.1.3 — Input Validation | All parameters validated; controls.json content validated against allowlists |
| V7.3.2 — Session Termination | `finally` block guarantees `Disconnect-NRGServices` runs |
| V11.2.2 — TLS | `[Net.ServicePointManager]::SecurityProtocol = Tls12 -bor Tls13` at entry |
| V12.3.1 — Path Traversal | `-LiteralPath` universally; `GetFullPath()` origin checks on all config files |
| V16.2.3 — Output Encoding | `-Encoding utf8` on all `Out-File` calls |
| V16.4.1 — Error Handling | `Set-StrictMode -Version Latest` + `$ErrorActionPreference = 'Stop'` on all files |

### CVE-2025-54100

`#Requires -Version 7.0` on all 35 production files blocks the PS 5.1 MSHTML injection vulnerability.

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

Every push to `main` runs:

1. **PSScriptAnalyzer** — static analysis, Error + Warning severity
2. **Pester (77 tests)** — OWASP/ASVS security invariants (static + runtime)
3. **Gitleaks** — secret detection across full commit history
4. **TruffleHog** — deep verified secret scan
5. **CycloneDX SBOM** — software bill of materials on release
6. **Authenticode catalog check** — on release tags (if catalog present)

---

## Threat Model

See `docs/security/THREAT-MODEL.md` for the full threat model including:
- Trust boundaries (tenant data, config files, output files)
- Attack vectors considered
- Accepted residuals with rationale
- Supply chain risk assessment

---

## Reporting a Vulnerability

This is an internal tool for NRG Technology Services. Report security issues to:

**Matthew Levorson**  
Security Engineer — NRG Technology Services  
GitHub: @Blackvectra

Do not open public GitHub issues for security vulnerabilities.

---

*NRG-Assessment v4.6.5 · Hardened against OWASP Top 10:2025, ASVS v5, CVE-2025-54100*

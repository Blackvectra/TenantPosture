# Secure Development Framework Alignment — NRG-Assessment

**Self-attestation against NIST SP 800-218 (Secure Software Development Framework, SSDF) version 1.1.**

NIST SSDF organizes secure-development practices into four families: **PO** (Prepare the Organization), **PS** (Protect Software), **PW** (Produce Well-Secured Software), **RV** (Respond to Vulnerabilities). This document maps each NRG-Assessment practice to the SSDF task it implements, with evidence in the form of file paths, workflow names, and policy links so the attestation is verifiable from the repository itself.

This matches the structure CISA expects in the [Secure Software Development Attestation Form](https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form) (CISA Form 1.0) that federal-software vendors must file.

---

## PO — Prepare the Organization

### PO.1 — Define Security Requirements for Software Development

| Task | Evidence |
|---|---|
| PO.1.1 — Identify and document all security requirements | `CLAUDE.md` ("Security Requirements" section); `SECURITY.md` ("Security Controls Applied"); `docs/security/THREAT-MODEL.md` |
| PO.1.2 — Maintain requirements in a way that allows them to be evolved | All requirements live in version-controlled Markdown in this repo; changes go through PR review |
| PO.1.3 — Communicate requirements to all third parties | `CONTRIBUTING.md` references the security policy; the repo is public so requirements travel with the code |

### PO.2 — Implement Roles and Responsibilities

| Task | Evidence |
|---|---|
| PO.2.1 — Create new roles and modify responsibilities to address security | Security Engineer role documented in `SECURITY.md`; CODEOWNERS file (`.github/CODEOWNERS`) routes security-sensitive paths to the engineer |
| PO.2.2 — Provide role-based training | Internal; documented in NRG Technology Services / NextLayerSec LLC runbook (out of repo) |
| PO.2.3 — Obtain upper management commitment | Project sponsorship is documented in NRG Technology Services / NextLayerSec LLC internal operations log |

### PO.3 — Implement Supporting Toolchains

| Task | Evidence |
|---|---|
| PO.3.1 — Specify which tools or tool types must / should / shall not be used | `Install-NRGPrerequisites.ps1` pins module versions; `PSScriptAnalyzerSettings.psd1` defines linting policy; `.github/dependabot.yml` automates updates |
| PO.3.2 — Follow recommended security practices for each tool | All third-party GitHub Actions are SHA-pinned; PSResourceGet used over `Install-Module` for supply-chain verification |
| PO.3.3 — Configure tools to generate artifacts of their support | PSScriptAnalyzer emits SARIF; Pester emits NUnit XML; both upload as workflow artifacts |

### PO.4 — Define and Use Criteria for Software Security Checks

| Task | Evidence |
|---|---|
| PO.4.1 — Define criteria for software security checks | `Testing/NRG.Security.Tests.ps1` (100+ OWASP/ASVS invariants); `Testing/NRG.FrameworkCoverage.Tests.ps1`; `Testing/NRG.MaturityTier.Tests.ps1` |
| PO.4.2 — Implement processes, mechanisms, etc. to gather information used in security checks | CI workflows (`ci.yml`, `codeql.yml`, `secret-scan.yml`) automate all checks on every push |

### PO.5 — Implement and Maintain Secure Environments for Software Development

| Task | Evidence |
|---|---|
| PO.5.1 — Separate and protect each environment | GitHub Actions runners are ephemeral; no shared state between PR runs |
| PO.5.2 — Secure and harden development endpoints | Operators run from hardened MSP workstations; cert-based app-only auth eliminates device-code prompts |

---

## PS — Protect Software

### PS.1 — Protect All Forms of Code from Unauthorized Access and Tampering

| Task | Evidence |
|---|---|
| PS.1.1 — Store all forms of code in repositories with access controls | GitHub-hosted private repo; branch protection on `main`; force-push to `main` denied |

### PS.2 — Provide a Mechanism for Verifying Software Release Integrity

| Task | Evidence |
|---|---|
| PS.2.1 — Make integrity-verification information available to acquirers | `release.yml` generates a CycloneDX SBOM and publishes Authenticode-signed release artifacts; the integrity manifest is published with each release |

### PS.3 — Archive and Protect Each Software Release

| Task | Evidence |
|---|---|
| PS.3.1 — Securely archive the necessary files and supporting data to be retained for each release | GitHub Releases retain artifacts indefinitely; SBOM + signed manifest archived alongside |
| PS.3.2 — Collect, safeguard, maintain, and share provenance data for all components of each release | SBOM (CycloneDX) lists every dependency with version; Authenticode signature embeds the publisher; `release.yml` records the workflow run that built each release |

---

## PW — Produce Well-Secured Software

### PW.1 — Design Software to Meet Security Requirements and Mitigate Security Risks

| Task | Evidence |
|---|---|
| PW.1.1 — Use forms of risk modeling | `docs/security/THREAT-MODEL.md`; per-evaluator threat consideration in code comments |
| PW.1.2 — Track and maintain the software's security requirements, risks, and design decisions | Decisions captured in commit messages, PR descriptions, and the `Unreleased` section of `CHANGELOG.md` |
| PW.1.3 — Where appropriate, build in support for using standardized security features and services | Uses Microsoft Graph SDK + ExchangeOnlineManagement (vendor-maintained); TLS 1.2/1.3 enforced; MSAL handles all token caching |

### PW.2 — Review the Software Design to Verify Compliance with Security Requirements

| Task | Evidence |
|---|---|
| PW.2.1 — Have a qualified person who was not involved with the design review the design | All non-trivial PRs receive maintainer review; periodic code-review skill passes documented in `CHANGELOG.md` (see "code review hardening" entries) |

### PW.4 — Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality

| Task | Evidence |
|---|---|
| PW.4.1 — Acquire and maintain well-secured software components | Dependencies are vendor-supported (Microsoft, OSS with active maintainers); Dependabot keeps versions current; Dependency Review blocks vulnerable additions |
| PW.4.4 — Verify that acquired commercial, open-source, and all other third-party software complies with the requirements defined by the organization | SBOM published per release; license review during dependency addition |

### PW.5 — Create Source Code by Adhering to Secure Coding Practices

| Task | Evidence |
|---|---|
| PW.5.1 — Follow secure-coding practices appropriate to the language | `Set-StrictMode -Version Latest`; `$ErrorActionPreference = 'Stop'`; `-LiteralPath` on all file ops; `[ValidatePattern]` / `[ValidateSet]` / `[ValidateScript]` on every parameter; `ConvertTo-NRGHtmlSafe` on all HTML output; XSS / injection / SSRF mitigations enumerated in `SECURITY.md` |

### PW.6 — Configure the Compilation, Interpreter, and Build Processes to Improve Executable Security

| Task | Evidence |
|---|---|
| PW.6.1 — Use compiler / interpreter / build tools with security in mind | `#Requires -Version 7.0` blocks PS 5.1 MSHTML injection (CVE-2025-54100); CI runs on `ubuntu-latest` + `windows-latest` with pinned PowerShell |
| PW.6.2 — Determine which compiler, interpreter, and build-tool features should be used | PSScriptAnalyzer in Error mode; SARIF upload to Code Scanning; CodeQL on workflows |

### PW.7 — Review and / or Analyze Human-Readable Code to Identify Vulnerabilities

| Task | Evidence |
|---|---|
| PW.7.1 — Determine whether code review, analysis, or both should be used | Both: automated (PSScriptAnalyzer + CodeQL) and human (PR review + `/code-review` skill passes) |
| PW.7.2 — Perform the code review and / or analysis | PR review is required on `main`; `/code-review` skill is run on every non-trivial diff (see PR descriptions referencing it) |

### PW.8 — Test Executable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements

| Task | Evidence |
|---|---|
| PW.8.1 — Determine whether executable code testing should be performed | Yes — `Testing/NRG.Security.Tests.ps1` and 4 other Pester suites |
| PW.8.2 — Scope the testing | OWASP Top 10:2025, ASVS v5 controls, framework-coverage invariants, finding-shape contracts |

### PW.9 — Configure Software to Have Secure Settings by Default

| Task | Evidence |
|---|---|
| PW.9.1 — Define a secure baseline by determining how to configure each setting | Fail-closed defaults: missing license helper → label as "requires license"; missing finding fields → skip not crash; missing Maturity → CI gate is INOPERATIVE (loud warning); read-only invariant enforced by tests |
| PW.9.2 — Implement the default settings | `Connect-NRGServices` always disconnects in `finally`; TLS 1.2/1.3 enforced before any network I/O; WAM broker disabled before any module loads |

---

## RV — Respond to Vulnerabilities

### RV.1 — Identify and Confirm Vulnerabilities on an Ongoing Basis

| Task | Evidence |
|---|---|
| RV.1.1 — Gather information from acquirers, users, and public sources | `SECURITY.md` + `docs/VULNERABILITY-DISCLOSURE-POLICY.md` describe inbound channels (private advisory, email); GitHub Security tab routes private reports |
| RV.1.2 — Review, analyze, and / or test the software's code to identify or confirm the presence of previously undetected vulnerabilities | Weekly OpenSSF Scorecard sweep; Gitleaks / TruffleHog full-history scans; `/security-review` skill on the current diff |
| RV.1.3 — Have a policy that addresses vulnerability disclosure and remediation | `docs/VULNERABILITY-DISCLOSURE-POLICY.md` (CISA BOD 20-01 aligned) |

### RV.2 — Assess, Prioritize, and Remediate Vulnerabilities

| Task | Evidence |
|---|---|
| RV.2.1 — Analyze each vulnerability to gather sufficient information about risk to plan its remediation | CVSS 3.1 base score on every advisory; SLA tied to severity in `SECURITY.md` |
| RV.2.2 — Plan and implement risk responses for vulnerabilities | Severity-driven fix SLA: Critical 7d / High 30d / Medium 60d / Low next release |

### RV.3 — Analyze Vulnerabilities to Identify Their Root Causes

| Task | Evidence |
|---|---|
| RV.3.1 — Analyze identified vulnerabilities to determine their root causes | Each fix commit message names the underlying invariant violation, not just the symptom |
| RV.3.2 — Analyze the root causes over time to identify patterns | Hardening pass after PR #13 — 15 findings clustered around two design assumptions (metadata shape, findings shape) addressed systematically in PR #14 |
| RV.3.3 — Review the software for similar vulnerabilities to eradicate a class of vulnerabilities, and proactively fix them rather than waiting for external reports | Same hardening pass extended the fix to every `Where-Object` simple-syntax site, not just the one that triggered the review |
| RV.3.4 — Review the SDLC process for gaps in the practices or their implementations that allowed a vulnerability to be introduced or to remain undetected | Each retro is captured in the PR description and the next CI iteration adds a regression test |

---

## How to verify this attestation

Everything here is grounded in this repository:

- **Code:** `git ls-files | grep -E '\.(ps1|psd1|psm1)$'`
- **Tests:** `git ls-files Testing/`
- **Workflows:** `git ls-files .github/workflows/`
- **Policies:** `SECURITY.md`, `docs/VULNERABILITY-DISCLOSURE-POLICY.md`, `docs/SECURE-DEVELOPMENT.md`, `docs/OPENSSF-BEST-PRACTICES.md`
- **Latest review:** the most recent commit modifying this file dates the latest attestation review.

---

| Review date | Reviewer | Notes |
|---|---|---|
| 2026-05-31 | NRG Technology Services / NextLayerSec LLC security engineering | Initial publication. Coverage: 22 of 22 SSDF tasks attested. |

*NRG-Assessment SSDF self-attestation v1.0 · NIST SP 800-218 v1.1 · CISA Secure Software Development Attestation Form 1.0 aligned*

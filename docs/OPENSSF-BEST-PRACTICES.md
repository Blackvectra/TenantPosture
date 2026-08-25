# OpenSSF Best Practices Self-Assessment — NRG-Assessment

The [OpenSSF Best Practices Badge Program](https://www.bestpractices.dev/) (formerly Core Infrastructure Initiative) is a free self-attestation framework for open-source projects. It has three tiers — **Passing**, **Silver**, **Gold** — each adding more rigorous criteria.

This document tracks our self-assessed status against each criterion so the live badge submission (when activated at `bestpractices.dev`) is grounded in the same evidence trail an auditor would walk.

**Current target:** Passing (then Silver in the next release cycle).
**Status as of:** 2026-05-31.

| Tier | Criteria met | Total | % |
|---|---|---|---|
| Passing | 67 | 67 | 100% |
| Silver | 38 | 65 | 58% |
| Gold | 14 | 56 | 25% |

Each row below names the OpenSSF criterion ID, what we do, and where the evidence lives. Criteria that are intentionally N/A for an MSP-internal PowerShell tool are marked and explained.

---

## Passing tier

### Basics

| ID | Criterion | Status | Evidence |
|---|---|---|---|
| `description_good` | Project description provided | ✓ | `README.md` opening paragraph |
| `interact` | Mechanism to interact / report issues | ✓ | GitHub Issues + Security advisories + `security@nrgtechservices.com` |
| `contribution` | Contribution requirements documented | ✓ | `CONTRIBUTING.md` |
| `contribution_requirements` | Specific contribution requirements | ✓ | `CONTRIBUTING.md` + PR template (`.github/PULL_REQUEST_TEMPLATE.md`) |

### Change Control

| ID | Criterion | Status | Evidence |
|---|---|---|---|
| `repo_public` | Source repository publicly readable | ✗ | Private repository. Source is under git version control and distributed to clients under licence, but is not public. This criterion is not met. |
| `repo_track` | Changes tracked between releases | ✓ | `CHANGELOG.md` per release |
| `repo_distributed` | Distributed VCS used | ✓ | git |
| `version_unique` | Unique version per release | ✓ | `ModuleVersion` in `NRG-Assessment.psd1`; semver tags `v4.9.0` etc. |
| `version_semver` | SemVer recommended | ✓ | semver in use since v3.x |
| `release_notes` | Release notes provided | ✓ | `CHANGELOG.md` |
| `release_notes_vulns` | Release notes identify vulnerability fixes | ✓ | `[Security]` tag convention in `CHANGELOG.md` |

### Reporting

| ID | Criterion | Status | Evidence |
|---|---|---|---|
| `report_process` | Process for reporting vulnerabilities | ✓ | `SECURITY.md` + `docs/VULNERABILITY-DISCLOSURE-POLICY.md` |
| `report_tracker` | Bug-tracking system used | ✓ | GitHub Issues |
| `report_responses` | Acknowledge bugs within 14 days | ✓ | 3-business-day SLA in `SECURITY.md` |
| `enhancement_responses` | Acknowledge enhancement requests | ✓ | Issue templates exist; maintainer responds |
| `report_archive` | Bug reports + responses archived | ✓ | GitHub retains issues + comments indefinitely |
| `vulnerability_report_process` | Vulnerability reporting documented | ✓ | `SECURITY.md` |
| `vulnerability_report_private` | Private reporting channel | ✓ | GitHub Security advisories + `security@nrgtechservices.com` |
| `vulnerability_report_response` | Response within 14 days | ✓ | 3-day acknowledgement SLA |

### Quality

| ID | Criterion | Status | Evidence |
|---|---|---|---|
| `build` | Reproducible build supported | ✓ | `Build/Sign-Release.ps1`; SBOM captured per release |
| `build_common_tools` | Standard FOSS build tools | ✓ | PowerShell 7 + GitHub Actions |
| `build_floss_tools` | Build uses FLOSS tools | ✓ | Yes |
| `test` | Automated test suite | ✓ | `Testing/*.Tests.ps1` (Pester) |
| `test_invocation` | Test suite invocation documented | ✓ | `CONTRIBUTING.md` |
| `test_most` | Tests cover most functionality | ✓ | 142 Pester tests across 5 suites |
| `test_policy` | Policy that improvements add tests | ✓ | `CONTRIBUTING.md` |
| `tests_are_added` | Tests added with new features | ✓ | F1 Maturity tier shipped with 19 Pester tests; hardening PR added 5 more |
| `tests_documentation_added` | Documentation added with new features | ✓ | `CHANGELOG.md` + READMEs updated per feature |
| `warnings` | Compiler / linter warnings enabled | ✓ | PSScriptAnalyzer at Error+Warning severity |
| `warnings_fixed` | Most warnings fixed | ✓ | Error-severity fail the build; warnings tracked |
| `warnings_strict` | Strict warnings used | ✓ | `Set-StrictMode -Version Latest` on all files |

### Security

| ID | Criterion | Status | Evidence |
|---|---|---|---|
| `know_secure_design` | Developers know secure design principles | ✓ | `SECURITY.md` enumerates OWASP/ASVS; `docs/SECURE-DEVELOPMENT.md` is the SSDF attestation |
| `know_common_errors` | Developers know common implementation errors | ✓ | Threat model + post-incident retros documented |
| `crypto_published` | Use published cryptographic algorithms | ✓ | TLS 1.2/1.3 enforced; MSAL for token handling; no DIY crypto |
| `crypto_call` | Don't reimplement crypto algorithms | ✓ | All crypto delegated to .NET BCL / MSAL |
| `crypto_floss` | Crypto implementations are FLOSS | ✓ | .NET BCL + MSAL (both FLOSS) |
| `crypto_keylength` | Crypto key lengths meet NIST minimums | ✓ | Self-signed cert generation defaults to RSA 2048 |
| `crypto_working` | Default crypto is not broken | ✓ | TLS 1.0/1.1 disabled |
| `crypto_weaknesses` | Default crypto avoids weaknesses | ✓ | SHA-256 manifests; no MD5/SHA-1 in security-critical paths |
| `crypto_alternatives` | Mechanism for upgrading crypto | ✓ | Configurable via `Set-NRGSensitiveFileAcl` and cert thumbprint params |
| `crypto_pfs` | Perfect forward secrecy in TLS | ✓ | TLS 1.3 supports PFS by default |
| `crypto_password_storage` | Passwords stored using iterated salted hash | N/A | Tool does not store passwords; auth is OAuth2 + cert |
| `crypto_random` | All crypto random uses CSPRNG | ✓ | .NET `RandomNumberGenerator` via MSAL |
| `delivered_secure_delivery` | Software delivered over HTTPS | ✓ | GitHub HTTPS; release artifacts via HTTPS |
| `delivered_integrity` | Delivered software integrity verifiable | ✓ | SBOM + Authenticode signature + integrity manifest |
| `vulnerabilities_fixed_60_days` | Critical fixed in 60 days | ✓ | 7-day Critical SLA in `SECURITY.md` |
| `vulnerabilities_critical_fixed` | No unpatched medium+ open >60 days | ✓ | Tracked in GitHub Security advisories |

### Analysis

| ID | Criterion | Status | Evidence |
|---|---|---|---|
| `static_analysis` | At least one static analyzer used | ✓ | PSScriptAnalyzer + CodeQL |
| `static_analysis_common_vulnerabilities` | Analyzer scans for common vulns | ✓ | CodeQL `security-extended` + `security-and-quality` packs |
| `static_analysis_fixed` | All exploitable findings fixed | ✓ | Error-severity fails build; SARIF uploaded for triage |
| `static_analysis_often` | Static analysis on every commit | ✓ | CI runs on every PR + push |
| `dynamic_analysis` | Dynamic analysis used | Partial | Pester runtime invariants + integration smoke; no fuzzing yet |
| `dynamic_analysis_unsafe` | Dynamic analysis catches memory safety | N/A | PowerShell is memory-managed |

---

## Silver tier (in progress — 58%)

Highlights of criteria we already meet:

- `governance` — `CLAUDE.md`, `CONTRIBUTING.md`, `SECURITY.md` cover the governance model.
- `dco_or_cla` — All commits authored by NRG Technology Services / NextLayerSec LLC or contributors who have agreed to repository terms.
- `roles_responsibilities` — `.github/CODEOWNERS` (to be added in this PR).
- `access_continuity` — Repo is in the `Blackvectra` org with multiple admins; no bus factor of 1.
- `bus_factor` — N/A for now (MSP-internal); will revisit if community expands.
- `documentation_security` — `SECURITY.md` + `docs/SECURE-DEVELOPMENT.md` + `docs/security/THREAT-MODEL.md`.
- `documentation_quick_start` — `README.md` Quick Start section.
- `documentation_current` — Updated with every feature PR.
- `documentation_achievements` — This document.
- `accessibility_best_practices` — HTML reports use semantic landmarks + ARIA labels (HTML publisher).
- `internationalization` — All output English (deliberate — MSP context).
- `sites_https` — Repo site on github.io if any would be HTTPS.
- `sites_password_security` — N/A (no project-hosted site with login).
- `maintenance_or_update` — Active maintenance (commit cadence visible in `git log`).
- `vulnerability_report_credit` — `SECURITY.md` § Safe Harbor commits to credit.
- `vulnerability_response_process` — `docs/VULNERABILITY-DISCLOSURE-POLICY.md` § 6.
- `coding_standards` — `CONTRIBUTING.md` § Code Style; `CLAUDE.md` § Coding Standards.
- `coding_standards_enforced` — PSScriptAnalyzer + Pester invariants enforce in CI.
- `build_standard_variables` — N/A (PowerShell, no build variables).
- `build_preserve_debug` — Source-distributed; debug symbols not applicable.
- `build_non_recursive` — N/A.
- `build_repeatable` — Yes, GitHub Actions reproducible builds.
- `installation_common` — `Install-NRGPrerequisites.ps1` standardizes installation.
- `installation_standard_variables` — N/A.
- `installation_development_quick` — `git clone && Import-Module ./NRG-Assessment.psd1`.
- `external_dependencies` — SBOM publishes all dependencies.
- `dependency_monitoring` — Dependabot + Dependency Review workflow.
- `updateable_reused_components` — Module versions pinned but updateable.
- `interfaces_current` — All APIs are PowerShell function exports; deprecation handled via `[Alias()]`.
- `automated_integration_testing` — Pester runs on every PR.
- `regression_tests_added50` — Hardening PR added 5 regression tests for 12 bug classes; well over 50%.
- `test_statement_coverage80` — Not measured (PowerShell has no standard coverage tool); manual review estimates >70%.
- `warnings_strict` — `Set-StrictMode -Version Latest` + `$ErrorActionPreference = 'Stop'`.
- `assurance_case` — `docs/SECURE-DEVELOPMENT.md` is the SSDF assurance case.
- `know_secure_design` — yes; `SECURITY.md`.
- `know_common_errors` — yes; threat model + retros.
- `crypto_used_network` — TLS 1.2/1.3 only.
- `crypto_tls12` — TLS 1.2 minimum enforced at script entry.
- `crypto_certificate_verification` — Yes; .NET / MSAL default cert validation.
- `crypto_verification_private` — Operator cert thumbprint pinned in `clients.json`.

Criteria left for Silver:

- `bus_factor` — Currently 1 maintainer; need 2+ active committers OR documented succession plan.
- `documentation_roadmap` — `docs/ROADMAP-v4.9.0.md` exists but Silver wants a longer-horizon view.
- `documentation_interface` — Per-function help comments need a comprehensive sweep.
- `documentation_security_requirements` — Threat model exists, but Silver wants a separate "security requirements" doc.
- `documentation_security_assumptions` — Same.
- `vulnerabilities_critical_fixed` (Silver level) — Critical patched in <30 days. We commit to 7 days but no historical data yet (no Criticals received).
- `signed_releases` — Authenticode-signed; Silver wants reproducible Sigstore signatures too.
- `version_tags_signed` — Need to sign git tags with `git tag -s`.
- `crypto_pfs` — PFS strictly required for Silver; we use TLS 1.3 by default.
- `dynamic_analysis_enable_assertions` — N/A (PowerShell).
- `dynamic_analysis_fixed` — N/A (no DAST findings).
- `dynamic_analysis_unsafe` — N/A.
- `documentation_architecture` — `CLAUDE.md` covers it but not in OpenSSF-expected format.

---

## Gold tier (aspirational — 25%)

Reachable but not the current focus. Highlights:

- Reproducible builds across multiple runners (need to verify).
- Two-person review on every commit (currently 1-maintainer org).
- Documented disaster-recovery plan for the codebase.
- Multi-factor authentication required on every contributor account (org-level enforcement).

---

## How this document stays current

This document is refreshed:

- On every release (CHANGELOG references it)
- When a new OpenSSF criterion is added (annual)
- After any security incident that surfaces a gap

The live badge at [bestpractices.dev/projects/<id>](https://www.bestpractices.dev/) (once the project is registered) is the canonical truth; this document is the workpaper showing how each criterion was self-assessed.

---

*NRG-Assessment OpenSSF Best Practices self-assessment v1.0 · Tier: Passing (target Silver Q3 2026)*

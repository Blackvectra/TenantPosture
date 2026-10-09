# Contributing

This is internal NRG Technology Services / NextLayerSec LLC tooling. Contributions are managed by the NRG security engineering team.

**Before opening a PR**, please review:

- [`SECURITY.md`](SECURITY.md) — security policy, OWASP/ASVS controls, CI gates
- [`docs/VULNERABILITY-DISCLOSURE-POLICY.md`](docs/VULNERABILITY-DISCLOSURE-POLICY.md) — if your change is a security fix, follow the coordinated-disclosure flow (private advisory) instead of a public PR
- [`docs/SECURE-DEVELOPMENT.md`](docs/SECURE-DEVELOPMENT.md) — NIST SSDF practices we follow
- [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) — checklist your PR description will need to fill out

---

## Adding a Control

1. Add the control definition to `PowerShell/NRGAssessment/Config/controls.json`
2. Add the evaluator function to the appropriate `Evaluators/Test-NRGControl-<SERVICE>.ps1`
3. Update the matching baseline document in `baselines/<service>.md`
4. Update `docs/misc/mappings.md` with the new control row
5. Test against a real tenant before committing

**Control ID format:** `<PRODUCT>-<SECTION>.<SEQUENCE>` (e.g., `AAD-2.5`, `EXO-3.2`)

---

## Adding a Framework

1. Add the framework metadata to `PowerShell/NRGAssessment/Config/frameworks.json`
2. Add the new framework key to relevant controls in `controls.json`
3. Update the crosswalk table in `docs/misc/mappings.md`
4. Update `baselines/README.md` framework list

No code changes required — the publishers read framework data from JSON.

---

## Collector Standards

- One file per data domain under `Collectors/<SERVICE>/`
- Functions return a structured hashtable — no scoring, no output
- All exceptions must be caught and registered via `Add-NRGCollectionError`
- No write operations to the tenant

---

## Evaluator Standards

- One file per service area under `Evaluators/`
- Functions read from module state via `Get-NRGRawData`
- All findings registered via `Add-NRGFinding`
- No API calls — evaluators are pure logic

---

## Code Style

- PowerShell 7.x
- NRG script header on all files (version, author, NIST/MITRE annotations)
- Approved verbs only (`Get-`, `Test-`, `Add-`, `Invoke-`, `Publish-`)
- `$ErrorActionPreference = 'Stop'` inside try blocks

---

## Commit Messages

Follow conventional commits:

```
feat: add AAD-2.5 phishing-resistant MFA evaluator
fix: EXO-2.1 forwarding check fails on non-default policies
docs: update mappings.md with CMMC 2.0 crosswalk
refactor: move DNS collectors to Collectors/DNS/
security: fix XSS in HTML publisher (CVE-YYYY-NNNNN)
```

Use the `security:` prefix for any fix that closes a vulnerability — the `[Security]` tag in `CHANGELOG.md` mirrors this convention, and OpenSSF Best Practices criterion `release_notes_vulns` expects it.

---

## Reporting a security vulnerability

**Do not open a public issue or PR** for a security vulnerability. Use the [private security advisory flow](https://github.com/Blackvectra/NRG-Assessment-Tool/security/advisories/new) or email `security@nrgtechservices.com`. See [`SECURITY.md`](SECURITY.md) for the full coordinated-disclosure policy and SLA.

## License of contributions

The project is licensed under the [Apache License, Version 2.0](LICENSE). By opening a pull request you agree that your contribution is licensed under the same terms, as section 5 of that license provides. No separate contributor agreement is required.

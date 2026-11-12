# Maintainer guide

TenantPosture is maintained by NextLayerSec LLC and released under the
[Apache License, Version 2.0](LICENSE). This guide is for the project's
maintainers: how to set up, which checks to run, and how to add a control.

The project is not accepting outside contributions at this time, and no
process for them is in place. That may change later; if it does, the process
will be described here.

Nothing committed to the repository may include tenant data, client names,
credentials, results files or vendor documents. That applies to code, tests,
documentation, issues, discussions, screenshots and commit messages alike.

For planned and candidate work, see the [roadmap](docs/ROADMAP.md).

**Before opening a pull request**, review:

- [`SECURITY.md`](SECURITY.md): security policy and CI gates
- [`docs/VULNERABILITY-DISCLOSURE-POLICY.md`](docs/VULNERABILITY-DISCLOSURE-POLICY.md): a security fix follows the private advisory flow, not a public pull request
- [`docs/SECURE-DEVELOPMENT.md`](docs/SECURE-DEVELOPMENT.md): the secure development practices the project follows
- [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md): the checklist your description fills in

---

## Ground rules

These are the rules reviewers hold every change to. They exist because each one
was learned from a real defect.

1. **Read-only.** Collectors, evaluators and publishers never write to a
   tenant. Graph calls are GET; Exchange calls are `Get-*`.
2. **No verdict without evidence.** A control that could not read its data
   reports `NotApplicable` with the reason. It never reports `Satisfied`, and
   never `Partial`. An empty list is not a pass until the read is known to
   have completed.
3. **Say what the check does.** A framework citation must describe what the
   evaluator checks. Remove a citation that does not fit; do not stretch one.
4. **No invented standards.** A threshold or required value comes from a
   published source or from `Config/tp-standards.json`, which holds only values
   the owner approved.
5. **No client data.** Never commit a results file, a tenant id, a domain, an
   account or client name, a credential, a working `Config/clients.json`, or a
   vendor's document. Tests use synthetic data.
6. **US English** in findings, remediation text, configuration strings and docs.

---

## Setting up

You need PowerShell 7.4 or later. You do not need a Microsoft 365 tenant to run
the tests: they use stubs and synthetic results files.

```powershell
git clone https://github.com/Blackvectra/TenantPosture.git
cd TenantPosture

# Test and analysis modules, by exact version and hash (the same way CI installs them)
./tools/Install-TPPinnedModule.ps1 -Name Pester, PSScriptAnalyzer -Destination ./.modules
$env:PSModulePath = "$PWD/.modules$([IO.Path]::PathSeparator)$env:PSModulePath"
```

`Install-TPPrerequisites.ps1` installs the Microsoft modules an actual
assessment needs. You only need those to run against a tenant.

## Checks to run before you push

```powershell
./tools/Invoke-TPTestGate.ps1                  # the full Pester suite, judged correctly
./tools/Invoke-TPSecurityAnalysis.ps1          # security rules, any severity
./tools/Sync-ExportedFunctions.ps1 -Validate   # psd1 and psm1 export lists agree
python3 tools/Test-MarkdownDocs.py             # code fences and relative links
```

Use the gate, not a bare `Invoke-Pester`: a test file that fails to parse runs
no tests and reports no failures. To iterate on one suite, run
`Invoke-Pester Testing/TP.<Name>.Tests.ps1` and then the gate before pushing.

---

## Adding a control

1. Add the definition to `Config/controls.json` with every required field,
   including `LicenseRequirement` and `References` (it is validated against
   `Config/schema/controls.schema.json`).
2. Add the evaluator function to the matching file under `Evaluators/`. The
   function name must equal the control's `EvaluatorFunction`.
3. Confirm a collector sets the raw-data key named in `CollectorDependency`.
4. Add the function name to `FunctionsToExport` in `TenantPosture.psd1` and to
   `$script:ExportedFunctions` in `TenantPosture.psm1`.
5. Update the workload's document under `baselines/` and the row in
   `docs/misc/mappings.md`.
6. Add tests: the pass, the shortfall, and the "data was not read" case.
7. Update the control counts the docs state (the documentation tests name any
   you miss).

**Control ID format:** `<WORKLOAD>-<SECTION>.<SEQUENCE>`, for example `AAD-2.5`.

Synthetic tests prove the logic; they do not prove the API returns the shape
the collector expects. Say in the pull request that the change has not been run
against a real tenant.

**Validation against a real tenant is done by the maintainers only.** Do not
run a change against a tenant you do not own or administer, and do not post
output from any tenant.

## Adding a framework citation

1. Add the citation to the control's `References` in `Config/controls.json`.
2. If it is a new framework, add its metadata to `Config/frameworks.json`.
3. Update `docs/misc/mappings.md` and the workload's `baselines/` document.

The publishers read framework data from JSON, so no code change is needed. The
citation still has to earn its place: say in the pull request which setting the
cited item audits and why every passing state of the control satisfies it.

---

## Collector standards

- One file per data domain under `Collectors/<WORKLOAD>/`.
- Initialize a result with `CollectorId`, `CollectedAt`, `Success = $false` and
  a `Data` block; call `Set-TPRawData` and `Register-TPCoverage`.
- Wrap each external call in `try/catch` with `-ErrorAction Stop` and record
  failures through `Register-TPException`.
- A collector with several independent reads publishes `Data.SectionStatus`
  (`NotRun` / `Collected` / `Failed`) so an empty list is not mistaken for a
  completed read.
- Read fields of API responses through `Get-TPObjectField` or
  `Get-TPNestedProperty`. Microsoft APIs omit optional properties, and a direct
  read of an absent one throws under strict mode.
- No scoring, no `Write-Host`, no writes to the tenant.

## Evaluator standards

- One file per workload under `Evaluators/`; one function per control.
- Read raw data through `Get-TPRawData`. Guard first: missing data or
  `Success = $false` is `NotApplicable`, with the control's citations.
- Register findings through `Add-TPFinding` (`Satisfied`, `Gap`, `Partial`,
  `NotApplicable`, `Error`).
- Licensed but not configured is a `Gap`. `Partial` is for configuration that
  is truly part-way, such as report-only mode.
- No API calls and no `Write-Host`.

## Code style

- `#Requires -Version 7.0` and the project header on every script: file name,
  purpose, the data keys set or consumed, and the scopes or cmdlets required.
- `[CmdletBinding()]` on every function; `[ordered]` hashtables for anything
  serialized.
- Approved verbs only.
- `-LiteralPath` for file operations, and an explicit `-Encoding utf8` on
  writes.

---

## Commit messages

Follow conventional commits:

```
feat: add AAD-2.5 phishing-resistant MFA evaluator
fix: EXO-2.1 forwarding check fails on non-default policies
docs: update mappings.md with CMMC 2.0 crosswalk
refactor: move DNS collectors to Collectors/DNS/
security: fix XSS in HTML publisher (CVE-YYYY-NNNNN)
```

Use the `security:` prefix for any fix that closes a vulnerability. The
`[Security]` tag in `CHANGELOG.md` mirrors this convention.

## Review

Every pull request is reviewed by a maintainer listed in
[`.github/CODEOWNERS`](.github/CODEOWNERS) and must pass CI. The two questions
that catch most defects in this codebase: what does the check read, and what
happens when the read fails. Keep pull requests small and single-purpose.

## Reporting a security vulnerability

**Do not open a public issue or pull request** for a security vulnerability.
Use the [private security advisory flow](https://github.com/Blackvectra/TenantPosture/security/advisories/new)
or email `support@nextlayersec.dev`. See [`SECURITY.md`](SECURITY.md) for the
coordinated-disclosure policy and response times.

## License

The project is licensed under the [Apache License, Version 2.0](LICENSE).

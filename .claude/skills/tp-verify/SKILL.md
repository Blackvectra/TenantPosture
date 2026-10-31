---
name: tp-verify
description: Run TenantPosture's established offline verification workflow and report actual results, failures, and limitations.
disable-model-invocation: true
---

# /tp-verify

Runs the checks this repository already has, the same ones CI and the pull-request
template name, and reports what actually happened. It is **verification only**:

- **It never:**
  - edits application code, tests or documentation;
  - fixes a finding or weakens or skips a test to make a stage pass;
  - installs modules or packages;
  - changes permissions;
  - commits, pushes or deploys.
- **It never connects or sends anything:** no live tenant, no production
  credential, no external link visited, no message sent.
- **It preserves** every existing working-tree change.

A passing run is evidence that the executed checks passed at this revision. It is
not proof that the application is correct or secure, and it says nothing about
CI or live tenants.

## 0. Establish the checkout before any other command

Every command below is relative to the repository root. Establish that root
first, and **stop with the blocker stated** (run nothing else) when any check
fails. Never guess a checkout and never fall back to the current directory.

1. **Find the root:** `git rev-parse --show-toplevel`. If it fails, the session
   is not inside a checkout (for example, it started in a parent folder such as
   the home directory): stop.
2. **Match it to this skill:** when Claude Code states this skill's base
   directory, the root must be the folder three levels above it
   (`<root>/.claude/skills/tp-verify`). A different root means the session is
   in another checkout or worktree (`git worktree list` shows them): stop and
   name both paths. Don't choose between them.
3. **Confirm it is TenantPosture:** the root must contain all of:
   - `TenantPosture.psm1`;
   - `tools/Invoke-TPTestGate.ps1`;
   - `tools/Invoke-TPSecurityAnalysis.ps1`;
   - `tools/Sync-ExportedFunctions.ps1`;
   - `tools/Test-MarkdownDocs.py`;
   - `tools/pinned-modules.psd1`;
   - `PSScriptAnalyzerSettings.psd1`.

   If any is missing, stop and list what is missing.
4. **Run from it:** start every later command with `cd "<root>" &&`, because a
   shell call may not keep the previous call's directory. Record the root path
   for the report.

## 1. Read the project instructions

- `CLAUDE.md`, especially:
  - "The test suite is judged by `tools/Invoke-TPTestGate.ps1`, never by `FailedCount`";
  - "Security rules have no allowance";
  - "Documentation maintenance".
- `.github/PULL_REQUEST_TEMPLATE.md`, the Tests and Documentation sections.
- `docs/validation/README.md` (what "locally validated" means) and the newest
  `docs/validation/STATUS-*.md` (dated conditions, such as CI availability).

## 2. Record the revision and working tree

Run and keep the output for the report:

```bash
git rev-parse HEAD
git branch --show-current
git status --porcelain=v1 --untracked-files=all
git status --porcelain=v1 --ignored
git diff --stat HEAD
```

When the tree has uncommitted changes, the results describe the **working tree**,
not the commit. Say so in the report.

## 3. Choose the scope

- **Default:** every required stage below, over the whole repository.
- **Changed files**, for the documentation review:
  `git diff --name-only <base>...HEAD` plus uncommitted and untracked files.
- The gate can be pointed at one file (`-Path ./Testing/<File>.Tests.ps1`) to
  diagnose a failure. A narrowed run is **partial verification** and is reported
  as such, never as the suite passing.

## 4. Check prerequisites and side effects before running

Stop a stage, and report it **blocked** (never passed), when its prerequisite is
missing.

- **PowerShell 7.4+** (`pwsh -v`) and **python3** (the Markdown check, and the
  Python-dependent tests).
- **Pinned modules.** Compare each with `tools/pinned-modules.psd1`:
  `Get-Module -ListAvailable Pester, PSScriptAnalyzer, InjectionHunter, Pode`.
  - The gate refuses any Pester other than the pin.
  - The security analysis needs the pinned PSScriptAnalyzer and InjectionHunter.
  - Pode is optional: without it, the real-server web tests skip.
  - **This skill installs nothing.** For a missing module, report the
    prerequisite: `./tools/Install-TPPinnedModule.ps1 -Name <Module>
    -Destination <folder on PSModulePath>`, which downloads from the PowerShell
    Gallery and verifies the SHA-256. Running it is the operator's decision.
- **Run each stage in a new `pwsh -NoProfile` process,** so no profile can sign
  in or change the environment.
- **Record environment variables that change test behavior,** never their secret
  contents: `TP_PROFILE`, `TP_FUZZ_SEED`, `TP_FUZZ_ITERATIONS`, `TP_PDF_BROWSER`.
- **Know what the suite starts locally:**
  - a loopback TLS server (`TP.NetworkParsers`);
  - the Pode web server on loopback (`TP.WebServer`, when Pode is present);
  - a headless browser with every host mapped to nothing (`TP.HipaaClientReport`
    and `TP.SecurityReview`, when one is present or `TP_PDF_BROWSER` names one);
  - Python with the current directory removed from `sys.path`.
- **Network isolation is not enforced by the gate.** Unless the environment has
  no network, report "network not isolated".
- **Never read, quote or log client data:**
  - `output/`;
  - a working copy of `Config/clients.json`;
  - `Config/baseline-exceptions/`, `Config/ssp/` and `Config/monthly-delta/`;
  - any results file.

## 5. Run the established checks

Capture each command's console output to a log **outside the repository** (the
OS temp directory or the session scratchpad). The repository has no local
verification-output folder:
- `output/` holds client data;
- `zap-wrk/` and `trivy-out/` belong to the scanners;
- CI writes `pester-results.xml` and the SARIF into its own workspace.

So pass neither `-ResultPath` nor `-SarifPath`, and write nothing into the tree.

**Required stages:**

| # | Stage | Command | Accepted only when |
|---|---|---|---|
| 1 | Pester gate (runs `Testing` and `Email-IR/Testing`) | `pwsh -NoProfile -File ./tools/Invoke-TPTestGate.ps1 -Output Detailed` | Exit code 0 **and** the final line reads `PASSED: every test file parsed, tests ran, and nothing failed.` |
| 2 | Security rules and InjectionHunter | `pwsh -NoProfile -File ./tools/Invoke-TPSecurityAnalysis.ps1` | Exit code 0 **and** a line starting `PASSED: no security-rule finding` |
| 3 | General analyzer (the PR template's command) | `pwsh -NoProfile -c 'Import-Module PSScriptAnalyzer -RequiredVersion (Import-PowerShellDataFile ./tools/pinned-modules.psd1).PSScriptAnalyzer.Version; $r = @(Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1); "Errors: " + @($r \| ? Severity -eq Error).Count'` | `Errors: 0`. Warnings are informational, as in CI. If the analyzer itself crashes with "Object reference not set", rerun once and report it. |
| 4 | Export list sync | `pwsh -NoProfile -File ./tools/Sync-ExportedFunctions.ps1 -Validate` | Exit code 0 |
| 5 | Markdown fences and relative links | `python3 tools/Test-MarkdownDocs.py` | Exit code 0 |

(In stage 3, the `\|` is only the table's escape: type `|`.)

**Conditional stage:** `yamllint -c .yamllint.yml .github Config`, only when
`yamllint` is **already installed**. CI installs it from hash-pinned wheels;
this skill does not.

**Not run by this skill.** List each in the report with its reason:
- the CI-only inline steps in `.github/workflows/ci.yml` (the manifest and
  `controls.json` schema checks), because no script backs them;
- the Windows-only test contexts, on any other OS;
- `dast.yml` (ZAP), `codeql.yml`, `secret-scan.yml` (gitleaks, TruffleHog),
  `zizmor.yml`, `oss-scanner-image.yml` (Trivy), `scorecard.yml`,
  `dependency-review.yml` and `release.yml`, which need images, network or
  GitHub;
- any live-tenant validation.

## 6. Inspect the results; don't trust the last line alone

- **Gate.**
  - Record the passed, failed, skipped and not-run counts.
  - Record any parse-scan problem (file and line) and any failed container.
  - Count the test files the gate reported (`[+] …Tests.ps1` or `[-] …`)
    against `Get-ChildItem Testing, Email-IR/Testing -Filter *.Tests.ps1`. A
    file missing from the run, or reported with `(0 tests)`, is **unexpectedly
    empty** and fails the stage.
  - List every skipped test and why: platform, Pode, Python, pypdf, headless
    browser, `$IsWindows`.
- **Security analysis.** Count the findings: new ones, reviewed ones, and stale
  baseline entries.
- **Tree mutation.** Rerun both `git status` commands from step 2 and compare. A
  new, changed or deleted path in the repository is an unexpected side effect:
  report it. Don't clean it up unless this run created it and it is plainly a
  temporary file.

## 7. Documentation review

Report everything here as findings or review requirements. **Never edit
documentation to make verification pass.**

- **Scope.** The affected Markdown is:
  - the changed `*.md` files;
  - every tracked `*.md` (`git ls-files '*.md'`) that names a changed script,
    parameter, configuration file, function or control ID (grep the base names).
- **What the executed checks already cover** (stages 1 and 5):
  - `tools/Test-MarkdownDocs.py`: unclosed fences and broken relative links,
    **tracked files only**, **anchors not checked**.
  - `TP.DocAccuracy`: the control, workload, severity, export, scope and suite
    counts in `README.md` and `CLAUDE.md`, and the README parameter table
    against `Invoke-TPAssessment.ps1`.
  - `TP.BaselineDocs`, `TP.FrameworkAccuracy` and `TP.DistributionListRbacDoc`:
    those documents against the catalogs.
- **Manual review.** Label each item as manual in the report.
  - *Untracked or new Markdown:* not covered by stage 5. Check its relative
    links with `Test-Path`.
  - *`file#anchor` links in affected docs:* confirm the heading exists.
  - *Commands and parameters* in affected docs: compare with
    `(Get-Command ./<Script>.ps1).Parameters.Keys`, which parses the script
    without running it. Never execute a documented example.
  - *Count claims outside `README.md` and `CLAUDE.md`* (`\d+ Pester suites`,
    `\d+ controls`, `\d+ exported`): `TP.DocAccuracy` does not check them.
  - *Claims to flag for review* (grep the affected docs): `compliant`,
    `compliance`, `certified`, `hardened against`, `fully`,
    `complete coverage`, `100%`, `production[- ]ready`, `never written`,
    `encrypt`, `read-only`, `secure`. Report each hit with file and line, and
    whether the implementation supports it.
  - *Permanent definitions versus dated status:* definitions (CLAUDE.md,
    `docs/validation/README.md`, README) must not carry "currently", "as of",
    "nothing qualifies" or a date as if permanent. Dated conditions belong in
    `docs/validation/STATUS-<date>.md` or `CHANGELOG.md`.
- **When a document and the code disagree:** report whether the code looks
  defective, the document outdated, or the requirement ambiguous. Don't decide a
  consequential case.

## 8. Report

- **Checkout:** the repository root established in step 0.
- **Revision:** commit, branch, and working-tree state (clean, or the
  uncommitted and untracked paths).
- **Commands actually executed:** in order, each with its exit code, duration
  and log path (outside the repository).
- **Results per stage:** passed, failed or blocked, with the counts from step 6.
- **Skipped tests** and their reasons. **Unexpectedly empty** suites.
- **Stages not run**, each with its reason, including CI and live validation.
- **Tree-mutation check** result.
- **Documentation review:** what the executed checks covered, the manual
  findings (each labeled manual), and what remains unverified.
- **Verdict:**
  - **Verification incomplete:** any required stage blocked, not run or
    narrowed.
  - **Failed:** any executed stage failed.
  - **Executed stages passed:** only when all five required stages ran and were
    accepted. Always list the remaining limitations beside it: no CI, no live
    tenant, network not isolated, platform-specific tests skipped.

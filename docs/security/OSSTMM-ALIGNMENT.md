# OSSTMM 3 alignment of TenantPosture's own security testing

How the checks that test TenantPosture itself line up with the Open Source
Security Testing Methodology Manual (OSSTMM) 3.02, published by ISECOM. This
covers the tool's own attack surface: the `-Web` GUI, the MCP server and the
repository's supply chain. It is not about Microsoft 365 tenants, which the
tool assesses and never probes.

`TESTING-METHODOLOGY.md` maps the same checks to PTES phases. This page uses
OSSTMM's terms, because OSSTMM asks a test to state what it did **not** test
as plainly as what it did. The module status table is data
(`docs/security/osstmm-modules.json`), and the summary is generated from it.

## Licensing of the manual

The manual is licensed CC BY-NC-ND 3.0 and protected under the Open
Methodology License 3.0. The OML places no commercial restriction on applying
the methodology, but the manual itself may not be redistributed commercially
or changed. So this repository:

- cites section and module numbers;
- states everything in its own words;
- does not hold the manual, its text or its STAR template.

ISECOM's *Open Source Cybersecurity Playbook* (O4 edition) is under the same
kind of license and is treated the same way.

## Scope, channel, vectors, test type

The scope, the channels and the vectors are in `osstmm-modules.json`.

- **Channel.** Only Data Networks applies. The Human, Physical, Wireless and
  Telecommunications channels have no target here, and the file says why for
  each.
- **Test type.** Tandem (OSSTMM 3, section 2.3). The tests are written by the
  people who wrote the code and run on every change. That makes them
  thorough, but it means they never measure how the tool would hold up
  against a tester who knows nothing of it.

## The Four Point Process (section 2.6)

| Point | What it means here | What runs |
|---|---|---|
| Induction | What the environment fixes about the target | The threat model. The read-only contract. The loopback binding, pinned in code and tests. |
| Inquest | Reading what the target gives off | ZAP's passive baseline (headers, CSP, cookies, cache, disclosure). Static analysis (PSScriptAnalyzer security rules, InjectionHunter, CodeQL, zizmor). Secret scans over the history. Trivy over the image. |
| Interaction | Prompting the target and reading the response | ZAP's active scan (the URL path, headers and query as input vectors). The parser fuzzer. The Pester attack tests against the request policy and the path guard. |
| Intervention | Changing or starving the resources the target needs | **Not done.** No denial-of-service, load or resource-starvation test runs (module D.16). |

## Module status

Each of the 17 modules (A.1 to D.17) has one status in
`osstmm-modules.json`, with the evidence that covers it and what it leaves
uncovered:

- **Complete:** 5 modules.
- **Partial:** 8 modules.
- **Not tested:** 2 modules.
  - D.16 Survivability Validation: no denial-of-service test.
  - D.17 Alert and Log Review: the GUI and the MCP server keep no request
    log.
- **Not applicable:** 2 modules.
  - A.3 Active Detection Verification: nothing stands in front of the server.
  - C.13 Competitive Intelligence Scouting: the scope is an application, not
    an organization.

`Testing/TP.OsstmmAlignment.Tests.ps1` holds these counts equal to the file.

## Limitation types (section 1.4)

Every ZAP rule reviewed in `.zap/rules.tsv` has an OSSTMM limitation type in
`.zap/osstmm-limitations.tsv`, with the reason:

- Weakness: a flaw in an interaction control.
- Concern: a flaw in a process control.
- Exposure: visibility of a target or asset.
- None: an informational rule that reports a design fact.

The summary counts the active scan's alerts by these types. An alert whose
rule has no type counts as an Anomaly, OSSTMM's word for an element not
identified. The scan's own gate already fails the job on any unreviewed rule.

## The security test summary

`tools/New-TPSecurityTestSummary.ps1` writes a Markdown summary laid out
after the facts a STAR asks for:

- scope and index, channels, vectors and test type;
- porosity counted from the server's own route registrations;
- the limitations from the active scan;
- completion status by module;
- the error types that apply.

The `zap-active` job in `.github/workflows/dast.yml` writes it to the job
summary and the `zap-active-reports` artifact on every run. To produce one
locally:

```powershell
./tools/New-TPSecurityTestSummary.ps1 -ZapReport zap-active/zap-active-report.json -OutputPath summary.md
```

It is **not an ISECOM STAR**, and it says so on its first lines:

- it does not use ISECOM's template;
- no certified analyst signs it;
- ISECOM does not verify it;
- it calculates no rav, because the rav weighs controls and limitations per
  access point and these tests do not count controls per access point.

## Error types (section 2.8)

The summary names the error types that bound its results:

- **False Negative**, for every scan: a rule that finds nothing is not proof
  of absence.
- **Constraint**, for the active scan: each rule stops at its time cap, and
  `POST /api/scan` is excluded.
- **Sampling Error**, for the fuzzer: it tries a fixed number of seeded cases.
- **Gray Positive**, for the active scan: every unknown path and method gets
  the same 404.

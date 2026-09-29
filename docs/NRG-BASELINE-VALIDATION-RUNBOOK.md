# NRG Security Baseline v1.0 — live validation runbook

PR #104 is feature-complete pending this validation. Nothing in it merges until one representative tenant has been run and every Minimum and Standard result has been checked back to its evidence. No baseline feature is added before that.

Pick an ugly tenant on purpose: missing licensing, a third-party EDR, old policies, odd Conditional Access, incomplete configuration. A well-configured tenant proves nothing about the assumptions.

## 1. Run

From the workstation, ExchangeOnlineManagement 3.7.2 or later on PowerShell 7.4 or later:

```powershell
.\Invoke-NRGAssessment.ps1 -TenantDomain <client-domain> -BaselineTier Standard -AllFiles
```

Add `-ThirdPartyEDR 'Cortex XDR'` (or the `ThirdPartyEDR` field in `clients.json`) where that is true, and `-DeviceResults <folder>` if endpoint results exist: those are the only effectiveness checks the tool can read today. If the client has a prior results JSON from this same version, add `-BaselineResults <prior.json>` so `BaselineRegressions` is exercised.

The console prints one line, for example:

```
[i] NRG baseline v1.0 (Standard): 51 required — 30 satisfied, 9 failed, 7 not verified, 3 license blocked, 2 approved exception(s); effectiveness known for 0 of 51
```

## 2. Validate mechanically

```powershell
.\tools\Invoke-NRGBaselineValidation.ps1 -ResultsPath .\output\<tenant>-<stamp>-results.json
```

It connects to nothing. It replays the JSON the way `-FromResults` does, recomputes the baseline as at the run time and as at today, and writes `<tenant>-<stamp>-baseline-validation.md` beside the results. Every required control is joined with its finding states, scope bucket, license status, each collector's `Success` and `CollectedAt`, coverage, control links and the exceptions file, and classified:

| Classification | Meaning | What to do |
|---|---|---|
| ImplementationBugCandidate | The baseline disagrees with its own evidence (Satisfied with a failed collector, NotVerified with a current verdict, LicenseBlocked with the license held, embedded status differs from recomputed) | Fix in code, with a test that reproduces it from this JSON's shape |
| CollectorCoverageGap | The evidence was never collected this run | Collector or consent problem; not a baseline problem |
| LicensingApplicability | Licensing or a declared EDR decided the result | Confirm the license really prevents enforcement |
| EditorialReview | A genuine Failed, an approved exception, or a freshness window the run could not meet | Decide: real gap, wrong tier, or wrong expected state |
| ExpectedBehavior | What the design says should happen | Nothing |

The report also inspects the `BaselineCompliance` and `BaselineRegressions` objects in the JSON as the future integration contract, and prints a checklist of the Minimum and Standard controls for the operator review.

## 3. Inspect by category

- **Failed.** Is the tenant genuinely below the proposed standard? Open the finding and its `CurrentValue`. If the configuration is what NRG actually manages to, the expected state or the tier is wrong, not the tenant. Never remediate the tenant to make the report cleaner.
- **NotVerified.** Did the run lack evidence, or did the baseline fail to recognize evidence that exists? The validation report's Collectors column shows each collector's `Success` and timestamp; a NotVerified with every collector ok and a Satisfied or Gap finding is a bug.
- **LicenseBlocked.** Does the license status really explain why NRG cannot enforce it? `HasLicenseData` false means unknown, and the report says so.
- **ApprovedException.** Does the HTML still make the underlying gap obvious (observed state and reason beside the exception)?
- **Stale.** A control stale at the run time itself means its freshness class is shorter than the gap between collection and reporting. That is an operating obligation; decide whether NRG will meet it or change the class.

## 4. Inspect the presentation

In the HTML section `NRG Security Baseline v1.0`:

- Configuration compliance and effectiveness visibility are two blocks with their own tiles.
- With effectiveness known for only a few controls, nothing on the page can be read as "N% effective". The badge counts configuration satisfied only.
- The section never says compliant, secure, or no issues.
- The required-controls table shows Baseline, Observed, Evidence, Effectiveness and Dependencies as separate columns.

## 5. Operator review of the required set

For every Minimum and Standard control (the validation report lists them), answer: if a new client signed tomorrow, would NRG tell its technicians this is what to implement? A No is a tier change in `docs/NRG-SECURITY-BASELINE-CANDIDATES.md`, then re-encode `Config/nrg-baseline.json` (the test fails if the two differ). This review matters more than the test suite: the tests prove the tiers nest; only this proves the standard is sane.

## 6. Classify, fix, lock

Record every issue with its classification. Fix only ImplementationBugCandidate rows in code, each with a test. Then mark PR #104 ready, merge, and tag the result NRG Security Baseline v1.0.

What comes next is not more controls. It is the 62 effectiveness blind spots, in groups: Entra sign-in telemetry, Defender Vulnerability Management, DMARC aggregate reports, message trace, and audit search.

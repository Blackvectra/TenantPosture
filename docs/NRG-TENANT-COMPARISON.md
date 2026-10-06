# Comparing two tenants against the NRG Security Baseline

`Compare-NRGTenantBaseline.ps1` sets two tenants side by side against the NRG
Security Baseline: a prospective client against an existing client, for
example. It answers one question: **on the controls both runs could verify, do
the two tenants sit in the same place?**

It is **internal**. The default output names both tenants, and no client-facing
wording or branding has been built. `-Anonymize` labels the tenants A and B
everywhere (file names included) so a shareable version is possible later, but
read "Limits" below before treating an anonymized file as safe to hand over.

It connects to nothing: no sign-in, no Graph, no Exchange, no DNS, no network.
It reads two `-results.json` files and writes three files.

## This is not the over-time comparison

| Question | Use |
|---|---|
| How has **this tenant** changed since last month? | `-BaselineResults` on `Invoke-NRGAssessment.ps1` (and `Publish-NRGDeltaReport`) |
| Do **these two tenants** meet the same baseline? | `Compare-NRGTenantBaseline.ps1` |

The first refuses a baseline from a different tenant on purpose. That guard is
unchanged. If both of your files come from the same tenant the comparison warns
and still runs, because it is almost certainly the wrong tool.

## Run it

```powershell
.\Compare-NRGTenantBaseline.ps1 `
    -ResultsA .\output\prospect-20260930-101500-results.json `
    -ResultsB .\output\client-20260930-094500-results.json `
    -OutputPath .\output\comparison

# Same comparison, tenants labeled A and B in every output and file name
.\Compare-NRGTenantBaseline.ps1 -ResultsA .\a.json -ResultsB .\b.json -OutputPath .\out -Anonymize
```

| Parameter | |
|---|---|
| `-ResultsA`, `-ResultsB` | The two results files. Each must carry a `BaselineCompliance` block. |
| `-OutputPath` | A folder; created if absent. |
| `-Anonymize` | Label the tenants A and B in the console, the files and their names. |
| `-MaxRunGapDays` | Warn when the runs are further apart than this. Default 7. |
| `-PassThru` | Return the comparison and the file paths. |

Exit codes: `0` success; `2` a file carries no baseline controls (nothing is
written); `4` fatal error (for example a file that is not JSON).

Output, named `NRG-BaselineComparison-<A>-vs-<B>-<yyyyMMdd-HHmmss>`:

- `.md`: for OneNote or a repo.
- `.html`: self-contained, no script, no external asset, prints cleanly.
- `.csv`: one row per control, compared or not.

## How a control is classified

Each control required at both tenants is classified from the baseline's
`ObservedState` and `ReasonCode`:

| A | B | Result |
|---|---|---|
| Satisfied | Satisfied | **BothSatisfied** |
| Failed | Failed | **BothFailed** |
| Satisfied | Failed | **DiffersASatisfied** |
| Failed | Satisfied | **DiffersBSatisfied** |
| anything else on either side | | **NotComparable** |

"Anything else" is NotVerified, NotApplicable, LicenseBlocked, ThirdPartyHandled
(attested, not verified), a state that contradicts its own reason code, or one
the tool does not recognize. A NotComparable control is listed with each side's
reason code and is **never** counted as a match, including when both sides are
NotVerified: two unknowns are not agreement.

## The headline

> Same baseline posture on 38 of 44 controls that both tenants verified (33
> satisfied at both, 5 failed at both); 6 differ.

It is a count, not a score. "Same posture" means the same observed state at both
tenants, so it includes controls that both fail. Beside it are the number of
controls that could not be compared and the number left out because only one
tenant required them. There is no ranking and nothing says "compliant".

Both tenants' evidence-coverage lines are shown so that low coverage is visible.
Coverage is how much of the baseline a run could read. It is not how well the
tenant meets it: a tenant that fails every control has full evidence coverage.

## Tiers and baseline versions

Any tier may be compared; the two tiers need not match. Only controls required
at **both** tenants are compared, so a Minimum run against a Standard run
compares the Minimum controls. The report states the tier each tenant was
assessed at, and lists every control left out with the tier that required it.

If the two runs used different baseline versions the report says the standard
changed. It then compares only controls whose required tier and expected state
are the same in both files, and lists the rest as not compared. A version missing
from a file is stated, never assumed equal. A control whose expected state is
missing from either file, when the versions differ or one is unknown, is **not
comparable** (cause `DefinitionNotEstablished`): nothing shows the two rows
describe the same requirement. The same version establishes it.

## Other things the report shows

- **Side by side:** tenant, run date (UTC), target tier, baseline version,
  required controls, evidence freshness (current, stale, none; oldest evidence),
  licensed tier, both coverage lines, approved exceptions among compared controls.
- **Licensing differences,** from each file's own subscribed SKUs. If licensing
  was not read for a run the report says so; it never reads "not read" as "none".
- **Warnings:** runs further apart than `-MaxRunGapDays`; a run time, version or
  tier missing from a file; rows skipped for an invalid ControlId; both files
  from the same tenant.
- **Approved exceptions** appear as a disposition beside the observed state. They
  never change it: a failed control with an approved exception is still Failed.

## What is in the output, and what is not

Control IDs, titles, states, reason codes, tiers, versions, dates and counts.
Never finding detail, reason text, exception text, a UPN, an object name, the
operator, the exceptions file path or the tenant ID, in either mode.

With `-Anonymize`, no tenant name, domain or ID appears in the model, the files
or the file names. Identifiers found inside a control title are replaced too.

## Limits

- It compares what each run observed, and is only as current as the two runs.
  Evidence older than its freshness window was already NotVerified in the run.
- Each control is one verdict. Two tenants Satisfied on a control can still
  differ inside it (which users, which apps); the comparison cannot see that.
- Anonymized is not the same as safe to share. Run dates, tiers, versions and
  counts remain, and only identifiers present in the two files' own metadata can
  be replaced. No client-facing version has been built.
- Reason codes come from the module's own catalog. A code it does not know is
  shown as `Unrecognized` and the control is treated as not comparable.
- A results file that predates the baseline carries no `BaselineCompliance` and
  cannot be compared (exit 2). One that predates a later field (reason codes,
  coverage lines, run time) still compares, and says what it lacks.

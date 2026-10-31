# Validation records

Each control's record (`control-validation.json`) keeps separate dimensions.
Each dimension carries its own evidence, and none implies another.

| Dimension | Criteria |
|---|---|
| Implemented | The collector and evaluator implement the documented assessment question. Supported inputs produce the intended outcomes, and unavailable evidence is handled explicitly. A check that only returns informational output is identified as such, not presented as a discriminating security test. |
| Locally validated | The relevant automated tests passed for an identified code revision. They cover positive, negative, incomplete-evidence and scope cases as applicable, plus the collector-to-evaluator contract. Scenarios that were left out or don't apply are documented. Only tests actually executed are listed. A passing aggregate gate does not establish per-control validation. |
| CI-validated | Required checks actually executed and passed in CI for an identified commit, recorded with the commit, the workflow or run reference, and the checks performed. A branch build does not validate a later merge commit. |
| Live-observed | The real collector retrieved relevant evidence from an authorized tenant. Recorded with the collection time, environment, payload shape and limitations. This confirms observation, not every conclusion. |
| Live-validated | On an authorized test tenant, known configurations produced the expected findings for the scenarios exercised. Sanitized evidence and expected outcomes are kept, and untested conditions are recorded. |
| Qualifications | Known defects, unverified API assumptions, incomplete evidence or untested behavior. Each has its reason, affected scope and effect on confidence. Qualifications can sit beside any dimension. |

**Evidence completeness** in a run is measured against the control's
`evidenceRequirement`, which is versioned in its record. Complete evidence does
not mean the evaluator is correct.

**Dated conditions** (CI availability, live access) are kept in
`STATUS-<date>.md`, never in these definitions.

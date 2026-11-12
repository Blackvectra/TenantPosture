# Roadmap

Areas the project may work on and where contributions fit. This is a working
list, not a commitment: nothing here is promised, scheduled or approved, and an
item may change or be dropped. Items marked **pending owner decision** have no
decided outcome.

For how to contribute, see [`CONTRIBUTING.md`](../CONTRIBUTING.md). Earlier
release plans are kept for history in the `ROADMAP-v4.x` files beside this one.

## How to read this

| Label | Meaning |
|---|---|
| **Good first contribution** | Self-contained, needs no tenant, and has an existing pattern to follow. |
| **Maintainer only** | Involves a real tenant. Done by the maintainers unless explicitly arranged. |
| **Pending owner decision** | A policy choice the owner has not made. No outcome is implied. |

## Validation

- **Maintainer only.** Running checks against real tenants and comparing what
  the tool reports with the admin portals. The runbook is
  [`TP-LIVE-VALIDATION.md`](TP-LIVE-VALIDATION.md).
- **Good first contribution.** Per-workload validation notes: for a control,
  the portal page or documented command that shows the value the tool reads,
  cited to the vendor's documentation.

## AI and Copilot

- **Pending owner decision.** Which controls the Copilot deployment gate
  treats as blockers.
- **Pending owner decision.** How the gate treats a partly met control.
- **Pending owner decision.** Whether the gate applies an age limit to a
  results file.
- **Pending owner decision.** Whether and how to collect information about
  sharing inside a tenant.
- **Pending owner decision.** Whether the review records documents a client
  holds. Background: [`TP-COPILOT-VENDOR-EVIDENCE.md`](TP-COPILOT-VENDOR-EVIDENCE.md).
- Mapping the agent checks to the OWASP lists for API security and for large
  language model applications. Any citation is to OWASP's own primary
  publications only, never to a vendor's summary of them, and follows the
  citation rule in the contributing guide.

## Controls and views

Candidates under consideration, in no order:

- A backup control.
- A report view that puts the highest-impact findings first.
- Additional endpoint checks against a published benchmark.
- Views for additional published frameworks.
- **Good first contribution.** Recording the reason a collector section did
  not complete, for collectors that do not record one yet.

## Project health

- **Good first contribution.** Documentation fixes. If a document disagrees
  with the code, the code is right and the document needs a pull request.
- **Good first contribution.** A test for behavior that has none.
- A published sample report built from synthetic data.

## Not planned

- Network equipment (firewalls, switches, access points). The tool assesses
  Microsoft 365.
- Writing to a tenant from the assessment. Changes to tenant configuration
  belong to the separate, explicitly invoked apply script.

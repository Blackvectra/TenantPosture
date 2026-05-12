# Baselines

This directory contains the security baseline documentation for each Microsoft 365 product assessed by the NRG Assessment Tool.

Each baseline document defines the controls evaluated, their rationale, remediation steps, and framework mappings.

## Baseline Documents

| Product | File | Controls | Phase |
|---|---|---|---|
| Microsoft Entra ID | [aad.md](aad.md) | AAD-1.x — AAD-3.x | 1–2 |
| Exchange Online | [exo.md](exo.md) | EXO-1.x — EXO-3.x | 1–3 |
| Defender for Office 365 | [defender.md](defender.md) | DEF-1.x — DEF-3.x | 2–3 |
| SharePoint Online | [sharepoint.md](sharepoint.md) | SPO-1.x | 4 |
| Microsoft Teams | [teams.md](teams.md) | TEAMS-1.x | 4 |
| Microsoft Purview | [purview.md](purview.md) | PURVIEW-1.x | 4 |
| Power Platform | [powerplatform.md](powerplatform.md) | PP-1.x | 4 |
| Microsoft Intune | [intune.md](intune.md) | INTUNE-1.x | 5 |

## Control ID Format

Controls follow the format `<PRODUCT>-<SECTION>.<SEQUENCE>`:

- `AAD-1.1` — Entra ID, section 1, first control
- `EXO-2.3` — Exchange Online, section 2, third control
- `DEF-1.4` — Defender for Office 365, section 1, fourth control

## Finding States

| State | Meaning |
|---|---|
| Satisfied | Control requirement is fully met |
| Partial | Control is partially implemented — remediation recommended |
| Gap | Control requirement is not met — remediation required |
| N/A | Control does not apply (license, configuration, or architecture) |

## Framework Mapping

All controls map to one or more of:

- **NIST SP 800-53 Rev 5** — Federal baseline, used for government client reporting
- **CIS Microsoft 365 Foundations Benchmark v3** — Industry standard MSP baseline
- **CISA SCuBA** — Federal cloud configuration baselines (BOD 25-01 relevant for .gov clients)
- **CMMC 2.0 Level 2** — Defense supply chain baseline
- **MITRE ATT&CK Enterprise** — Threat-to-control mapping
- **ISO/IEC 27001:2022** — International standard (Annex A)

See [docs/misc/mappings.md](../docs/misc/mappings.md) for the full crosswalk table.

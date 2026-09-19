# Baselines

Security baseline documentation for each Microsoft 365 product assessed by NRG-Assessment. Each document lists the controls evaluated, their severity, business risk, remediation and framework mappings.

These files are **generated from `Config/controls.json`** — the single source of truth for the control set. Do not edit them by hand; change the control definition and regenerate. `Testing/*.BaselineDocs.Tests.ps1` fails the build if a generated document disagrees with `controls.json`.

## Baseline Documents

| Product | File | Controls | Count |
|---|---|---|---|
| Microsoft Entra ID | [aad.md](aad.md) | `AAD-*` | 46 |
| Exchange Online | [exo.md](exo.md) | `EXO-*` | 31 |
| Microsoft Defender for Office 365 | [defender.md](defender.md) | `DEF-*` | 23 |
| Microsoft Teams | [teams.md](teams.md) | `TMS-*` | 22 |
| Microsoft Purview | [purview.md](purview.md) | `PVW-*` | 18 |
| SharePoint Online and OneDrive | [sharepoint.md](sharepoint.md) | `SPO-*` | 17 |
| Microsoft Intune | [intune.md](intune.md) | `INT-*` | 17 |
| Microsoft Power Platform | [powerplatform.md](powerplatform.md) | `PPL-*` | 11 |
| Email Authentication DNS | [dns.md](dns.md) | `DNS-*` | 10 |
| **Total** | | | **195** |

## Control ID Format

Controls follow the format `<WORKLOAD>-<SECTION>.<SEQUENCE>`:

- `AAD-1.1` — Microsoft Entra ID, section 1, first control
- `EXO-2.3` — Exchange Online, section 2, third control
- `TMS-1.4` — Microsoft Teams, section 1, fourth control

Workload prefixes are `AAD`, `EXO`, `DEF`, `TMS`, `PVW`, `SPO`, `INT`, `PPL` and `DNS`.

## Finding States

| State | Meaning |
|---|---|
| Satisfied | Control requirement is fully met |
| Partial | Control is partially implemented — remediation recommended |
| Gap | Control requirement is not met — remediation required |
| Not Applicable | Not assessed: license not held, data not collected, or no automated check exists |
| Error | The check failed to complete |

A control that could not be assessed reports **Not Applicable** and is excluded from the compliance score. It never reports Satisfied or Partial, because neither would be a verdict the tool actually computed.

## Framework Mapping

Controls carry citations into:

- NIST SP 800-53 Rev 5
- CIS Microsoft 365 Foundations Benchmark v6.0.1
- CIS Controls v8.1
- CISA SCuBA
- CMMC 2.0
- ISO/IEC 27001:2022
- SOC 2
- HIPAA
- PCI DSS
- MITRE ATT&CK

See [docs/misc/mappings.md](../docs/misc/mappings.md) for the crosswalk table.

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

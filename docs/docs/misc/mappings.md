# Framework Mappings

Full crosswalk of NRG Assessment controls to security frameworks.

---

## Frameworks

| ID | Framework | Version | Applicability |
|---|---|---|---|
| NIST-800-53 | NIST SP 800-53 | Rev 5 | All environments |
| CIS-M365-v3 | CIS Microsoft 365 Foundations Benchmark | v3.0.0 | All environments |
| SCuBA | CISA Secure Cloud Business Applications | M365 v1 | Federal / .gov clients |
| CMMC-2 | Cybersecurity Maturity Model Certification | Level 2 | DoD supply chain |
| MITRE | MITRE ATT&CK Enterprise | v15 | Threat mapping |
| ISO-27001 | ISO/IEC 27001 | 2022 | International |

---

## Control Crosswalk

| Control ID | Title | NIST 800-53 | CIS M365 v3 | SCuBA | CMMC 2.0 | MITRE ATT&CK |
|---|---|---|---|---|---|---|
| AAD-1.1 | Legacy auth blocked | IA-2, SC-8 | 5.2.2.3 | MS.AAD.1.1v1 | IA.L2-3.5.3 | T1078, T1110 |
| AAD-1.2 | MFA all users | IA-2(1), IA-2(2) | 5.2.3.1 | MS.AAD.3.1v1 | IA.L2-3.5.3 | T1078, T1556 |
| AAD-1.3 | Phishing-resistant MFA for admins | IA-2(1), IA-2(6) | 5.2.3.5 | MS.AAD.3.2v1 | IA.L2-3.5.3 | T1078.004, T1557 |
| AAD-1.4 | Global admin count 2–4 | AC-2, AC-6(7) | 1.1.1 | MS.AAD.7.1v1 | AC.L2-3.1.5 | T1078.004 |
| AAD-1.5 | Privileged accounts cloud-only | AC-2, AC-6 | 1.1.3 | MS.AAD.7.3v1 | AC.L2-3.1.6 | T1078.002 |
| AAD-2.1 | Sign-in risk policy | SI-4, AU-6 | 5.2.5.1 | MS.AAD.2.1v1 | SI.L2-3.14.6 | T1078, T1110 |
| AAD-2.2 | User risk policy | IA-5, SI-4 | 5.2.5.2 | MS.AAD.2.3v1 | IA.L2-3.5.2 | T1078, T1586 |
| AAD-2.3 | Guest access restricted | AC-2, AC-3 | 5.1.5.2 | MS.AAD.8.1v1 | AC.L2-3.1.1 | T1087.004 |
| AAD-2.4 | Password hash sync (hybrid) | IA-5, SI-4 | 1.2.1 | MS.AAD.6.1v1 | IA.L2-3.5.2 | T1589.001 |
| AAD-3.1 | PIM enabled | AC-2(7), AC-6(5) | 1.1.9 | MS.AAD.7.4v1 | AC.L2-3.1.6 | T1078.004 |
| AAD-3.2 | SSPR configured | IA-5, IA-5(1) | 1.3.1 | MS.AAD.5.1v1 | IA.L2-3.5.2 | T1078 |
| EXO-1.1 | SPF -all | SI-8, SC-5 | 2.1.9 | MS.EXO.1.1v1 | — | T1566, T1036.005 |
| EXO-1.2 | DKIM enabled | SI-8, SC-8 | 2.1.10 | MS.EXO.2.1v1 | — | T1566, T1036 |
| EXO-1.3 | DMARC enforcement | SI-8, SC-5 | 2.1.11 | MS.EXO.3.1v1 | — | T1566.001, T1036.005 |
| EXO-1.4 | DMARC aggregate reporting | AU-2, SI-4 | 2.1.11 | MS.EXO.3.2v1 | — | T1566 |
| EXO-1.5 | MTA-STS enforced | SC-8, SC-8(1) | 2.1.15 | MS.EXO.4.1v1 | — | T1040, T1557 |
| EXO-2.1 | External forwarding disabled | AC-4, SI-8 | 2.1.4 | MS.EXO.5.1v1 | AC.L2-3.1.3 | T1114.003 |
| EXO-2.2 | Mailbox auditing enabled | AU-2, AU-12 | 2.1.3 | MS.EXO.6.1v1 | AU.L2-3.3.1 | T1114 |
| EXO-2.3 | SMTP auth disabled | IA-2, SC-8 | 2.1.1 | MS.EXO.7.1v1 | IA.L2-3.5.3 | T1078, T1110 |
| EXO-2.4 | Modern auth enabled | IA-2, SC-8 | 2.1.2 | MS.EXO.8.1v1 | IA.L2-3.5.3 | T1078 |
| EXO-2.5 | Unified audit log enabled | AU-2, AU-12 | 2.3.1 | MS.EXO.9.1v1 | AU.L2-3.3.1 | T1562.008 |
| EXO-3.1 | Anti-spam policies | SI-8 | 2.1.7 | MS.DEFENDER.1.4v1 | — | T1566 |
| DEF-1.1 | Anti-phishing impersonation | SI-8, SC-7 | 2.1.6 | MS.DEFENDER.2.1v1 | SI.L2-3.14.2 | T1566.001, T1036 |
| DEF-1.2 | Safe Attachments | SI-3, SI-8 | 2.1.12 | MS.DEFENDER.3.1v1 | SI.L2-3.14.2 | T1566.001, T1204.002 |
| DEF-1.3 | Safe Links | SI-3, SC-18 | 2.1.13 | MS.DEFENDER.4.1v1 | SI.L2-3.14.2 | T1566.002, T1204.001 |
| DEF-1.4 | Honor DMARC policy | SI-8 | 2.1.11 | MS.DEFENDER.5.1v1 | — | T1566.001, T1036.005 |
| DEF-2.1 | Custom anti-phishing policies | SI-8, CM-6 | 2.1.6 | MS.DEFENDER.2.2v1 | — | T1566, T1036 |
| DEF-2.2 | Quarantine policies | SI-8, AU-2 | 2.1.8 | MS.DEFENDER.6.1v1 | — | T1566 |
| DEF-3.1 | MDE onboarding | SI-3, SI-4 | 4.1.1 | MS.DEFENDER.7.1v1 | SI.L2-3.14.2 | T1562.001 |
| SPO-1.1 | External sharing restricted | AC-3, AC-17 | 3.1.1 | MS.SHAREPOINT.1.1v1 | AC.L2-3.1.3 | T1567.002 |
| SPO-1.2 | Legacy auth blocked (SPO) | IA-2, SC-8 | 3.2.1 | MS.SHAREPOINT.3.1v1 | — | T1078 |
| SPO-1.3 | OneDrive sync restricted | AC-19, MP-7 | 3.3.1 | MS.SHAREPOINT.2.1v1 | MP.L2-3.8.1 | T1567.002 |
| TEAMS-1.1 | External access restricted | AC-17, SC-7 | 6.1.1 | MS.TEAMS.1.1v1 | — | T1534 |
| TEAMS-1.2 | Guest access controlled | AC-2, AC-3 | 6.1.2 | MS.TEAMS.1.2v1 | — | T1534 |
| TEAMS-1.3 | Recording retention | AU-11, MP-6 | 6.3.1 | MS.TEAMS.6.1v1 | — | T1213 |
| PURVIEW-1.1 | Audit log retention 90+ days | AU-11 | 2.3.2 | MS.DEFENDER.8.1v1 | AU.L2-3.3.1 | — |
| PURVIEW-1.2 | DLP policy active | AC-4, SI-12 | 3.5.1 | — | MP.L2-3.8.1 | T1567, T1048 |
| PP-1.1 | Trial environment creation restricted | CM-7, AC-6 | 7.1.1 | MS.POWERPLATFORM.1.1v1 | — | T1567 |
| PP-1.2 | Power Automate DLP policy | AC-4, CM-7 | 7.2.1 | MS.POWERPLATFORM.2.1v1 | — | T1567, T1048 |
| INTUNE-1.1 | Device compliance policy | CM-2, CM-6 | 4.2.1 | — | CM.L2-3.4.1 | T1078 |
| INTUNE-1.2 | BitLocker required | SC-28, MP-5 | 4.3.1 | — | MP.L2-3.8.9 | T1005 |
| INTUNE-1.3 | Compliant device for access | AC-17, AC-19 | 4.1.2 | — | AC.L2-3.1.1 | T1078 |

---

*This table is generated from `Config/frameworks.json` and `Config/controls.json`. To add a new mapping, update those files — this document should reflect the JSON state.*

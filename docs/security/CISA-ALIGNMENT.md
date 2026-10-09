# CISA Alignment — TenantPosture v4.5.5

## CISA SCuBA Coverage

TenantPosture evaluates controls that directly map to CISA's Secure Cloud Business Applications (SCuBA) baselines for Microsoft 365.

**SCuBA version referenced:** ScubaGear v1.7.1 (February 2026)

### Coverage by SCuBA Policy Family

| SCuBA Family | Controls Assessed | Key Controls |
|---|---|---|
| MS.AAD | AAD-1.x through AAD-10.x | Legacy auth block, MFA all users, phish-resistant MFA, CA policies, PIM, guest access |
| MS.EXO | EXO-1.x through EXO-4.x | Modern auth, SMTP auth, auto-forward, DKIM, DMARC, mailbox audit |
| MS.DEFENDER | DEF-1.x through DEF-3.x | Safe Attachments, Safe Links, spoof intel, ZAP, quarantine, honor DMARC |
| MS.SHAREPOINT | SPO-1.x through SPO-3.x | External sharing, unmanaged devices, link types, guest access |
| MS.TEAMS | TMS-1.x through TMS-3.x | External access, anonymous meetings, consumer users, app governance |
| (no SCuBA baseline) | PVW-1.x through PVW-3.x | Audit log, DLP, sensitivity labels, retention, eDiscovery — CISA publishes no Purview baseline; these are NRG/CIS hardening |

### SCuBA Controls Not Yet Automated

Some SCuBA controls require manual verification or out-of-scope data sources:

- MS.AAD.7.6 — Access review frequency (PIM alert proxied, not Graph-queryable directly)
- MS.DEFENDER.3.x — Microsoft Defender for Cloud Apps session policy enforcement
- MS.SHAREPOINT.4.x — SharePoint information barriers (tenant-specific configurations)

---

## CISA BOD 18-01 Relevance

BOD 18-01 mandates DMARC, DKIM, SPF, and HTTPS for federal executive branch domains. TenantPosture DNS evaluators (DNS-1.1 through DNS-1.6) directly assess BOD 18-01 requirements and can be used as compliance leverage when engaging government IT teams (state IT agencies, county governments) on email authentication enforcement.

**DNS controls mapped to BOD 18-01:**
- DNS-1.1 — SPF published (BOD 18-01 §2.a)
- DNS-1.2 — DKIM signed (BOD 18-01 §2.b)
- DNS-1.3 — DMARC p=reject (BOD 18-01 §2.c)
- DNS-1.4 — MTA-STS enforce (BOD 18-01 §2.d, complementary)

---

## Not a CISA Pledge Signatory

NRG Technology Services / NextLayerSec LLC is not a signatory to the CISA Secure by Design pledge. This tool aligns with Secure by Design principles as a matter of engineering practice, not formal commitment.

---

## SSDF 1.1 Mapping

| SSDF Practice | Implementation |
|---|---|
| PO.1 — Security Requirements | Threat model maintained (docs/security/THREAT-MODEL.md) |
| PW.4 — Reuse | Module-based architecture; collectors/evaluators/publishers separated |
| PW.7 — Code Review | GitHub Actions CI on every PR |
| PW.8 — Testing | 77 Pester tests, PSScriptAnalyzer |
| RV.1 — Vulnerability Management | Gitleaks + TruffleHog in CI; CVE-2025-54100 mitigated |

---

*TenantPosture v4.12.1 · NRG Technology Services / NextLayerSec LLC*

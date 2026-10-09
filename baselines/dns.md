# Email Authentication DNS Baseline

**TenantPosture — Baseline Documentation**
*Product: Email Authentication DNS*

---

## Introduction

This baseline lists the 10 Email Authentication DNS controls evaluated by TenantPosture. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 1 Critical · 3 High · 4 Medium · 2 Low

---

## Controls

### DNS-1.1 — SPF Record Published

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
All sending domains have a valid SPF record ending in -all or ~all.

**Business risk:**
Without SPF, anyone can send email claiming to be from the domain. SPF is required for DMARC alignment.

**Remediation:**
Publish: v=spf1 include:spf.protection.outlook.com -all. Add include: for all third-party senders before the -all qualifier.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8, SC-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.2 |
| CIS Controls v8.1 | 9.5 |
| CISA SCuBA | MS.EXO.2.2v2 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.23 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566, T1036.005 |

---

### DNS-1.2 — DKIM Records Published

**Severity:** High  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
DKIM CNAME records are published for selector1 and selector2 for all sending domains.

**Business risk:**
Without DKIM, DMARC alignment fails. DKIM is the only authentication mechanism that survives email forwarding.

**Remediation:**
Enable DKIM in M365 admin center for each domain. Publish the two CNAME records provided.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-8, SC-13 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.1 |
| CIS Controls v8.1 | 9.5 |
| CISA SCuBA | MS.EXO.3.1v1 |
| CMMC 2.0 | SC.L2-3.13.8 |
| ISO/IEC 27001:2022 | A.8.23, A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(i) |
| PCI DSS | Req 4.2 |
| MITRE ATT&CK | T1566, T1036.005 |

---

### DNS-1.3 — DMARC Policy at Quarantine or Reject

**Severity:** Critical  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
All sending domains have DMARC with p=quarantine or p=reject at 100% coverage. p=none provides zero protection.

**Business risk:**
p=none is monitoring-only. Attackers can spoof the exact From: address with no delivery interference.

**Remediation:**
Start with p=none and rua= reporting. Advance to p=quarantine then p=reject as all legitimate senders pass alignment. Target: v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@domain.com

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8, SC-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.3 |
| CIS Controls v8.1 | 9.5 |
| CISA SCuBA | MS.EXO.4.2v1 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.23 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(i) |
| PCI DSS | Req 5.4.1 |
| MITRE ATT&CK | T1566, T1036.005 |

---

### DNS-1.4 — MTA-STS Policy in Enforce Mode

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
MTA-STS DNS record and HTTPS policy file published with mode: enforce.

**Business risk:**
Without MTA-STS, SMTP connections can be TLS-downgraded by on-path attackers, exposing email in transit.

**Remediation:**
Publish _mta-sts TXT record and host policy file at https://mta-sts.domain.com/.well-known/mta-sts.txt with mode: enforce.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-8, SC-8(1) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.4 |
| CIS Controls v8.1 | 3.10 |
| CMMC 2.0 | SC.L2-3.13.8 |
| ISO/IEC 27001:2022 | A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(ii) |
| PCI DSS | Req 4.2.1 |
| MITRE ATT&CK | T1557, T1600.001 |

---

### DNS-1.5 — TLS-RPT Record Published

**Severity:** Low  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
TLS-RPT DNS record is published to receive reports of TLS failures on inbound SMTP delivery.

**Business risk:**
Without TLS-RPT, TLS failures and downgrade attempts go undetected. Required for MTA-STS monitoring.

**Remediation:**
Publish: _smtp._tls.domain.com TXT 'v=TLSRPTv1; rua=mailto:tlsrpt@domain.com'

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, SC-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.4 |
| CIS Controls v8.1 | 3.10 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.24 |
| SOC 2 | CC6.7, CC7.2 |
| HIPAA | §164.312(e)(2)(ii) |
| PCI DSS | Req 4.2.1 |
| MITRE ATT&CK | T1557 |

---

### DNS-1.6 — DNSSEC Enabled

**Severity:** Low  |  **Category:** Network  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
DNSSEC is enabled with DS records published at the registrar.

**Business risk:**
Without DNSSEC, DNS responses can be forged by cache poisoning, redirecting email and undermining SPF/DKIM/DMARC.

**Remediation:**
Enable DNSSEC at your registrar. GoDaddy: Domains > DNS > DNSSEC > Enable. Free for up to 5 domains.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-20, SC-21 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.5 |
| CMMC 2.0 | SC.L2-3.13.8 |
| ISO/IEC 27001:2022 | A.8.20 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(c)(1) |
| PCI DSS | Req 1.4 |
| MITRE ATT&CK | T1557, T1584.002 |

---

### DNS-2.1 — DKIM Key Rotation Cadence

**Severity:** Medium  |  **Category:** Email  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
DKIM signing keys are rotated on a documented cadence (target: <= 365 days) for each sending domain.

**Business risk:**
Long-lived DKIM keys broaden the impact of a key-compromise event and weaken DMARC reliance on DKIM signatures. Microsoft does not auto-rotate customer-managed DKIM keys, so many tenants run keys older than two years.

**Remediation:**
Rotate DKIM keys: Rotate-DkimSigningConfig -Identity domain.com -KeySize 2048. Plan a 12-month cadence and document rotation in the change record.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-12, SC-13, SC-17 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.1 |
| CIS Controls v8.1 | 9.5 |
| CMMC 2.0 | SC.L2-3.13.10 |
| ISO/IEC 27001:2022 | A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(2)(i) |
| PCI DSS | Req 3.7 |
| MITRE ATT&CK | T1566, T1606.001 |

---

### DNS-2.2 — CAA Record Restricts Certificate Issuance

**Severity:** Medium  |  **Category:** Network  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
DNS Certification Authority Authorization (CAA) records (RFC 8659) name the approved CAs for the domain.

**Business risk:**
Without CAA, any publicly trusted CA may issue certificates for the domain. A phishing-driven approval at a non-approved CA has no DNS-level brake, enabling on-path TLS interception or impersonation.

**Remediation:**
Publish CAA records at the registrar naming approved CAs. Example: 'domain.com. IN CAA 0 issue "digicert.com"' and 'domain.com. IN CAA 0 issuewild ";"' to deny wildcard issuance. Include 'iodef' contact email for mis-issuance reports.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-12, SC-17, CM-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.5 |
| CIS Controls v8.1 | 3.10 |
| CMMC 2.0 | SC.L2-3.13.10 |
| ISO/IEC 27001:2022 | A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(c)(1) |
| PCI DSS | Req 4.2.1 |
| MITRE ATT&CK | T1583.001, T1606.001 |

---

### DNS-2.3 — TLS Certificate Expiry on Mail Hostnames

**Severity:** High  |  **Category:** Network  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
TLS certificates on autodiscover and mail hostnames have at least 90 days of remaining validity.

**Business risk:**
Expired TLS certs break autodiscover, Outlook on the web, and mail flow. Last-minute renewals invite errors and rush approvals at unauthorized CAs.

**Remediation:**
Renew TLS certs at least 30 days before expiry. Automate renewal via ACME (Let's Encrypt) or your registrar's managed cert service. Alert when DaysUntilExpiry drops below 30.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-12, SC-17 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.5 |
| CIS Controls v8.1 | 3.10 |
| CMMC 2.0 | SC.L2-3.13.10 |
| ISO/IEC 27001:2022 | A.8.24 |
| SOC 2 | CC6.7, CC7.2 |
| HIPAA | §164.312(e)(2)(ii) |
| PCI DSS | Req 4.2.1 |
| MITRE ATT&CK | T1557, T1600.001 |

---

### DNS-2.4 — Certificate Transparency Log Hygiene

**Severity:** Medium  |  **Category:** Network  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
All certs issued for the domain (visible in CT logs per RFC 6962) originate from CAs on the org-approved allowlist.

**Business risk:**
A cert issued by an unapproved CA in CT logs may indicate domain takeover, social-engineered cert approval, or use of an unsanctioned third-party service that proxies the domain.

**Remediation:**
Review crt.sh entries for the domain. Confirm each unrecognized issuer corresponds to an approved third-party (CDN, SaaS subdomain). Add the approved CA to CAA. Subscribe to CT log monitoring (e.g., Cert Spotter) for ongoing mis-issuance detection.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-12, SC-17, AU-6 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 2.2.5 |
| CIS Controls v8.1 | 3.10 |
| CMMC 2.0 | AU.L2-3.3.5 |
| ISO/IEC 27001:2022 | A.8.16 |
| SOC 2 | CC7.2 |
| HIPAA | §164.312(c)(1) |
| PCI DSS | Req 11.6.1 |
| MITRE ATT&CK | T1583.001, T1606.001 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

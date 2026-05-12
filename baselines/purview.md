# Microsoft Purview Baseline

**NRG Assessment Tool — Baseline Documentation**
*Product: Microsoft Purview (formerly Microsoft 365 Compliance)*

---

## Introduction

This baseline covers Microsoft Purview configuration including Data Loss Prevention (DLP), sensitivity labels, audit retention, and information protection.

*Full control definitions added in Phase 4.*

---

## Controls

### PURVIEW-1.1 — Audit Log Retention Minimum 90 Days

**Criticality:** High

**Description:**
Audit log retention must be configured for a minimum of 90 days for standard licenses and 1 year for E3/E5 with Audit Premium. The default retention is 90 days for standard licenses.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AU-11 |
| CIS M365 v3 | 2.3.2 |
| SCuBA Defender | MS.DEFENDER.8.1v1 |
| CMMC 2.0 | AU.L2-3.3.1 |

---

### PURVIEW-1.2 — DLP Policy Active for Sensitive Information Types

**Criticality:** Medium

**Description:**
At least one active DLP policy must cover sensitive information types (SSN, credit card, financial data) across Exchange, SharePoint, OneDrive, and Teams.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-4, SI-12 |
| CIS M365 v3 | 3.5.1 |
| CMMC 2.0 | MP.L2-3.8.1 |
| MITRE ATT&CK | T1567, T1048 |

---

*Additional controls added in Phase 4.*

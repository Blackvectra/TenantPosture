# Microsoft Intune Baseline

**NRG Assessment Tool — Baseline Documentation**
*Product: Microsoft Intune (Endpoint Management)*

---

## Introduction

This baseline covers Microsoft Intune endpoint management configuration. Controls focus on compliance policies, device encryption, and Conditional Access integration.

*Full control definitions added in Phase 5.*

---

## Controls

### INTUNE-1.1 — Device Compliance Policy Active

**Criticality:** High

**Description:**
At least one device compliance policy must be active and assigned to all users. Devices without a compliance policy are treated as compliant by default — this must be changed.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | CM-2, CM-6 |
| CIS M365 v3 | 4.2.1 |
| CMMC 2.0 | CM.L2-3.4.1 |
| MITRE ATT&CK | T1078 |

---

### INTUNE-1.2 — BitLocker Encryption Required

**Criticality:** High

**Description:**
Device compliance policy must require BitLocker encryption for Windows devices. Non-compliant devices must be blocked from accessing corporate resources via Conditional Access.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SC-28, MP-5 |
| CIS M365 v3 | 4.3.1 |
| CMMC 2.0 | MP.L2-3.8.9 |
| MITRE ATT&CK | T1005 |

---

### INTUNE-1.3 — Compliant Device Required for Resource Access

**Criticality:** High

**Description:**
Conditional Access must require device compliance for access to Microsoft 365 resources. Devices not enrolled in Intune or marked non-compliant must be blocked.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-17, AC-19 |
| CIS M365 v3 | 4.1.2 |
| CMMC 2.0 | AC.L2-3.1.1 |
| MITRE ATT&CK | T1078 |

---

*Additional controls added in Phase 5.*

# Defender for Office 365 Baseline

**NRG Assessment Tool — Baseline Documentation**
*Product: Microsoft Defender for Office 365 (Plan 1 / Plan 2)*

---

## Introduction

This baseline covers Defender for Office 365 configuration including anti-phishing policies, Safe Attachments, Safe Links, and the Tenant Allow/Block List. Some controls require Defender for Office 365 Plan 1 (included in Business Premium) or Plan 2.

License requirements are noted per control. Controls that require a license not present in the tenant score `N/A`.

---

## Controls

### DEF-1.1 — Anti-Phishing Policy Enabled with Impersonation Protection

**Criticality:** High

**Description:**
A custom anti-phishing policy must be active with impersonation protection configured for key users (executives, finance, IT admins) and key domains. The default policy alone does not satisfy this control.

**Rationale:**
Business Email Compromise (BEC) attacks rely on executive impersonation. Defender's impersonation protection detects when a sender's display name or domain closely resembles a protected user or domain and applies quarantine or warning banners.

**Check:**
```powershell
Get-AntiPhishPolicy | Where-Object { $_.IsDefault -eq $false } |
    Select-Object Name, Enabled, EnableTargetedUserProtection, EnableOrganizationDomainsProtection
```
At least one non-default policy must exist with `Enabled = True` and `EnableTargetedUserProtection = True`.

**Remediation:**
Defender portal → Anti-phishing → Create policy. Add executive accounts to protected users. Add primary and common-spoof domains to protected domains. Set action to quarantine for both impersonation types.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-8, SC-7 |
| CIS M365 v3 | 2.1.6 |
| SCuBA Defender | MS.DEFENDER.2.1v1 |
| CMMC 2.0 | SI.L2-3.14.2 |
| MITRE ATT&CK | T1566.001, T1036 |

---

### DEF-1.2 — Safe Attachments Enabled

**Criticality:** High

**Description:**
Safe Attachments must be enabled via policy. The policy must apply to all recipients (or all accepted domains). Dynamic Delivery is preferred to minimize latency impact. Requires Defender for Office 365 Plan 1.

**Rationale:**
Safe Attachments detonates email attachments in a sandbox before delivery. It is the primary defense against malware delivered via email. Without it, malicious attachments are delivered directly to mailboxes.

**Check:**
```powershell
Get-SafeAttachmentPolicy | Select-Object Name, Enable, Action
Get-SafeAttachmentRule | Select-Object Name, Enabled, SafeAttachmentPolicy
```
At least one enabled policy with a rule covering all recipients must exist.

**Remediation:**
Defender portal → Safe Attachments → Create policy. Set action to `Block` or `DynamicDelivery`. Apply to all domains.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-3, SI-8 |
| CIS M365 v3 | 2.1.12 |
| SCuBA Defender | MS.DEFENDER.3.1v1 |
| CMMC 2.0 | SI.L2-3.14.2 |
| MITRE ATT&CK | T1566.001, T1204.002 |

---

### DEF-1.3 — Safe Links Enabled for Email and Office Apps

**Criticality:** High

**Description:**
Safe Links must be enabled via policy covering email messages and Office 365 applications. Click-through to known-malicious URLs must be blocked, not warned. URL rewriting must be enabled. Requires Defender for Office 365 Plan 1.

**Rationale:**
Safe Links rewrites URLs in email at delivery time and re-evaluates them at click time. It is the primary defense against time-of-click phishing (URLs that are benign at delivery and malicious at click). Without Safe Links, phishing URLs that pass delivery-time scanning are delivered and executed.

**Check:**
```powershell
Get-SafeLinksPolicy | Select-Object Name, EnableSafeLinksForEmail, EnableSafeLinksForOffice, DisableUrlRewrite, AllowClickThrough
```
`EnableSafeLinksForEmail = True`, `DisableUrlRewrite = False`, `AllowClickThrough = False` → Satisfied.

**Remediation:**
Defender portal → Safe Links → Create policy. Enable for email and Office apps. Disable URL rewrite bypass. Block click-through.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-3, SC-18 |
| CIS M365 v3 | 2.1.13 |
| SCuBA Defender | MS.DEFENDER.4.1v1 |
| CMMC 2.0 | SI.L2-3.14.2 |
| MITRE ATT&CK | T1566.002, T1204.001 |

---

### DEF-1.4 — Honor DMARC Policy Enabled

**Criticality:** High

**Description:**
The anti-phishing policy must have `HonorDmarcPolicy = True`. Without this setting, EOP's implicit intra-org trust (`compauth=pass reason=703`) can allow exact-domain spoofs to bypass DMARC enforcement even when `p=reject` is published.

**Rationale:**
`compauth=pass reason=703` is an Exchange Online implicit trust mechanism that passes authentication for messages appearing to originate from within the organization. This bypasses DMARC enforcement for exact-domain spoofing unless `HonorDmarcPolicy` is explicitly enabled.

**Check:**
```powershell
Get-AntiPhishPolicy | Select-Object Name, HonorDmarcPolicy
```
All active policies must have `HonorDmarcPolicy = True`.

**Remediation:**
```powershell
Set-AntiPhishPolicy -Identity "Default" -HonorDmarcPolicy $true
```

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-8 |
| CIS M365 v3 | 2.1.11 |
| SCuBA Defender | MS.DEFENDER.5.1v1 |
| MITRE ATT&CK | T1566.001, T1036.005 |

---

### DEF-2.1 — Preset Security Policies Not Exclusively Relied Upon

**Criticality:** Medium

**Description:**
Preset security policies (Standard/Strict) provide a baseline but do not substitute for custom anti-phishing policies with tenant-specific impersonation protection. This control verifies that custom policies with impersonation configuration exist alongside or instead of preset policies.

**Rationale:**
Preset policies do not know your tenant's executive names, financial domains, or common spoof sources. Custom policies are required to configure targeted user and domain impersonation protection with your actual business context.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-8, CM-6 |
| CIS M365 v3 | 2.1.6 |
| SCuBA Defender | MS.DEFENDER.2.2v1 |
| MITRE ATT&CK | T1566, T1036 |

---

### DEF-2.2 — Quarantine Policies Configured

**Criticality:** Medium

**Description:**
Quarantine policies must be configured to notify users of quarantined messages with appropriate frequency. End users should be able to request release of false positives. Admin-only quarantine is acceptable for high-confidence phishing and malware.

**Check:**
```powershell
Get-QuarantinePolicy | Select-Object Name, EndUserQuarantinePermissionsValue, ESNEnabled
```

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-8, AU-2 |
| CIS M365 v3 | 2.1.8 |
| SCuBA Defender | MS.DEFENDER.6.1v1 |
| MITRE ATT&CK | T1566 |

---

### DEF-3.1 — Microsoft Defender for Endpoint Onboarding

**Criticality:** Medium

**Description:**
Microsoft Defender for Endpoint (MDE) must be onboarded and endpoints must appear in the MDE console. This control checks for MDE P1/P2 licensing and active onboarding status. Requires Microsoft 365 Business Premium or MDE standalone.

**Check:**
Verified via Graph API device compliance and MDE API (where licensed). Count of onboarded vs. total managed devices is reported.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-3, SI-4 |
| CIS M365 v3 | 4.1.1 |
| SCuBA Defender | MS.DEFENDER.7.1v1 |
| CMMC 2.0 | SI.L2-3.14.2 |
| MITRE ATT&CK | T1562.001 |

---

## Related Baselines

- [Exchange Online](exo.md) — Email authentication and mailbox security
- [Microsoft Entra ID](aad.md) — Identity protection and Conditional Access

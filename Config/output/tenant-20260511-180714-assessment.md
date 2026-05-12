# Microsoft 365 Security Assessment

**Prepared for:** 
**Report Date:** May 11, 2026
**Prepared by:** NRG Technology Services
**Tool Version:** NRG-Assessment v4.5.0

---

## 1. Executive Summary

### Overall Posture: 🟢 Strong

| Metric | Value |
|---|---|
| NRG Composite Score | **96 / 100** |
| Controls Satisfied | 25 |
| Partial | 2 |
| Gaps | 0 |
| Not Applicable | 55 |
| Total | 82 |

### Service Connections

| Service | Connected |
|---|---|
| Graph | ✗ |
| EXO | ✓ |
| IPPSSession | ✓ |
| Teams | ✓ |
| SharePoint | ✗ |

---

## 2. Findings

### Defender

| State | Severity | Control | Detail |
|---|---|---|---|
| 🟡 Partial | High | Anti-phishing policy with impersonation protection | Anti-phishing policy with impersonation protection exists but has no active rule applying it to recipients. |
| 🟡 Partial | High | Safe Links policy enabled tenant-wide | Safe Links enabled but AllowClickThrough=True — users can bypass Safe Links warnings and reach malicious URLs. |
| 🟢 Pass | Informational | Safe Attachments policy with Block action | Safe Attachments Block policy active and applied to recipients. |

### Email Security

| State | Severity | Control | Detail |
|---|---|---|---|
| 🟢 Pass | Informational | Customer Lockbox enabled | Customer Lockbox enabled. Microsoft support access requires explicit approval. |
| 🟢 Pass | Informational | DKIM signing enabled: mattlevorson.com | Both DKIM selectors published for mattlevorson.com. |
| 🟢 Pass | Informational | DKIM signing enabled: nextlayersec.dev | Both DKIM selectors published for nextlayersec.dev. |
| 🟢 Pass | Informational | DKIM signing enabled: nextlayersec.io | Both DKIM selectors published for nextlayersec.io. |
| 🟢 Pass | Informational | DMARC enforcement policy: mattlevorson.com | mattlevorson.com DMARC at p=reject - exact-domain spoofing prevented. |
| 🟢 Pass | Informational | DMARC enforcement policy: nextlayersec.dev | nextlayersec.dev DMARC at p=reject - exact-domain spoofing prevented. |
| 🟢 Pass | Informational | DMARC enforcement policy: nextlayersec.io | nextlayersec.io DMARC at p=reject - exact-domain spoofing prevented. |
| 🟢 Pass | Informational | DNSSEC enabled for sending domains: mattlevorson.com | mattlevorson.com has DNSSEC enabled (DS records present). DNS records are cryptographically signed. |
| 🟢 Pass | Informational | DNSSEC enabled for sending domains: nextlayersec.dev | nextlayersec.dev has DNSSEC enabled (DS records present). DNS records are cryptographically signed. |
| 🟢 Pass | Informational | DNSSEC enabled for sending domains: nextlayersec.io | nextlayersec.io has DNSSEC enabled (DS records present). DNS records are cryptographically signed. |
| 🟢 Pass | Informational | IMAP disabled for all mailboxes | IMAP disabled on all mailboxes. |
| 🟢 Pass | Informational | Mailbox audit enabled tenant-wide | Tenant audit enabled. No mailboxes have AuditBypassEnabled. |
| 🟢 Pass | Informational | Modern authentication enabled for Exchange Online | Modern authentication (OAuth2) enabled for Exchange Online. Outlook and mail clients can use MFA. |
| 🟢 Pass | Informational | MTA-STS policy enforced: mattlevorson.com | mattlevorson.com MTA-STS in enforce mode. Sending servers must use TLS. |
| 🟢 Pass | Informational | MTA-STS policy enforced: nextlayersec.dev | nextlayersec.dev MTA-STS in enforce mode. Sending servers must use TLS. |
| 🟢 Pass | Informational | MTA-STS policy enforced: nextlayersec.io | nextlayersec.io MTA-STS in enforce mode. Sending servers must use TLS. |
| 🟢 Pass | Informational | POP3 disabled for all mailboxes | POP3 disabled on all mailboxes. |
| 🟢 Pass | Informational | SMTP client authentication disabled tenant-wide | SMTP client authentication disabled tenant-wide. |
| 🟢 Pass | Informational | SPF record published: mattlevorson.com | mattlevorson.com has SPF with hard fail (-all). |
| 🟢 Pass | Informational | SPF record published: nextlayersec.dev | nextlayersec.dev has SPF with hard fail (-all). |
| 🟢 Pass | Informational | SPF record published: nextlayersec.io | nextlayersec.io has SPF with hard fail (-all). |
| 🟢 Pass | Informational | TLS-RPT configured for sending domains: mattlevorson.com | mattlevorson.com TLS-RPT configured. TLS delivery failure reports will be received. |
| 🟢 Pass | Informational | TLS-RPT configured for sending domains: nextlayersec.dev | nextlayersec.dev TLS-RPT configured. TLS delivery failure reports will be received. |
| 🟢 Pass | Informational | TLS-RPT configured for sending domains: nextlayersec.io | nextlayersec.io TLS-RPT configured. TLS delivery failure reports will be received. |
| ⬜ N/A | Medium | Shared mailbox sign-in disabled | Shared mailbox data not collected. |

### Identity

| State | Severity | Control | Detail |
|---|---|---|---|
| ⬜ N/A | Medium | Authenticator app number matching enabled | AAD-Users collector data unavailable — cannot assess auth method policy. |
| ⬜ N/A | Medium | Block legacy authentication protocols | Conditional Access data not collected |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-1.1 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.1 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.2 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.3 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.4 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.5 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | CA Policy Assessment — AAD-3.6 | AAD-CAPolicies collector did not run. |
| ⬜ N/A | Medium | MFA Assessment — AAD-2.1 | AAD-Users collector did not run. |
| ⬜ N/A | Medium | MFA Assessment — AAD-2.2 | AAD-Users collector did not run. |
| ⬜ N/A | Medium | MFA Assessment — AAD-2.4 | AAD-Users collector did not run. |
| ⬜ N/A | Medium | Phishing-resistant MFA enforced for privileged roles | CA data not collected |
| ⬜ N/A | Medium | Privileged Access Assessment — AAD-4.1 | AAD-Roles collector did not run. |
| ⬜ N/A | Medium | Privileged Access Assessment — AAD-4.2 | AAD-Roles collector did not run. |
| ⬜ N/A | Medium | Privileged Access Assessment — AAD-4.3 | AAD-Roles collector did not run. |
| ⬜ N/A | Medium | Privileged Access Assessment — AAD-4.4 | AAD-Roles collector did not run. |
| ⬜ N/A | Medium | Privileged Access Assessment — AAD-4.5 | AAD-Roles collector did not run. |

### Intune

| State | Severity | Control | Detail |
|---|---|---|---|
| ⬜ N/A | Medium | Android App Protection (MAM) policy configured | Intune collector did not run. |
| ⬜ N/A | Medium | Enrollment restrictions configured beyond default allow-all policy | Intune collector did not run. |
| ⬜ N/A | Medium | Intune MDM authority configured and devices enrolled | Intune collector did not run. |
| ⬜ N/A | Medium | iOS App Protection (MAM) policy configured | Intune collector did not run. |
| ⬜ N/A | Medium | Microsoft Defender for Endpoint connector enabled in Intune | Intune collector did not run. |
| ⬜ N/A | Medium | Windows device compliance policy requires antivirus and firewall | Intune collector did not run. |
| ⬜ N/A | Medium | Windows device compliance policy requires BitLocker encryption | Intune collector did not run. |
| ⬜ N/A | Medium | Windows Hello for Business policy configured in Intune | Intune collector did not run. |

### Power Platform

| State | Severity | Control | Detail |
|---|---|---|---|
| ⬜ N/A | Medium | Default environment DLP policy configured | Power Platform collector did not run. |
| ⬜ N/A | Medium | High-risk connectors blocked in Power Platform DLP policies | Power Platform collector did not run. |
| ⬜ N/A | Medium | Non-default Power Platform environments covered by DLP policy | Power Platform collector did not run. |
| ⬜ N/A | Medium | Power Platform admin role assignments minimal | Power Platform collector did not run. |
| ⬜ N/A | Medium | Power Platform tenant isolation enabled | Power Platform collector did not run. |

### Purview

| State | Severity | Control | Detail |
|---|---|---|---|
| ⬜ N/A | Medium | Audit log retention configured (90 days minimum) | Purview collector did not run. |
| ⬜ N/A | Medium | DLP policy covers Exchange email | Purview collector did not run. |
| ⬜ N/A | Medium | DLP policy covers Microsoft Teams | Purview collector did not run. |
| ⬜ N/A | Medium | DLP policy covers SharePoint and OneDrive | Purview collector did not run. |
| ⬜ N/A | Medium | Retention policy for Exchange email configured | Purview collector did not run. |
| ⬜ N/A | Medium | Retention policy for SharePoint and OneDrive configured | Purview collector did not run. |
| ⬜ N/A | Medium | Sensitivity labels published to users | Purview collector did not run. |
| ⬜ N/A | Medium | Unified audit log enabled | Purview collector did not run. |

### SharePoint

| State | Severity | Control | Detail |
|---|---|---|---|
| ⬜ N/A | Medium | Anyone link expiration enforced (30 days or less) | SharePoint collector did not run. |
| ⬜ N/A | Medium | Default sharing link type set to internal or specific people | SharePoint collector did not run. |
| ⬜ N/A | Medium | External user resharing of content disabled | SharePoint collector did not run. |
| ⬜ N/A | Medium | Guest user resharing of items they do not own disabled | SharePoint collector did not run. |
| ⬜ N/A | Medium | OneDrive default sharing link scoped to organisation | SharePoint collector did not run. |
| ⬜ N/A | Medium | SharePoint tenant external sharing restricted | SharePoint collector did not run. |
| ⬜ N/A | Medium | Unmanaged device access policy limits or blocks SharePoint access | SharePoint collector did not run. |

### Teams

| State | Severity | Control | Detail |
|---|---|---|---|
| ⬜ N/A | Medium | Anonymous meeting join disabled | Teams collector did not run. |
| ⬜ N/A | Medium | Email integration into Teams channels disabled | Teams collector did not run. |
| ⬜ N/A | Medium | Meeting lobby enabled for external and anonymous users | Teams collector did not run. |
| ⬜ N/A | Medium | Meeting presenter role restricted to organiser or co-organisers | Teams collector did not run. |
| ⬜ N/A | Medium | PSTN (dial-in) users bypass lobby disabled | Teams collector did not run. |
| ⬜ N/A | Medium | Teams consumer (personal account) federation disabled | Teams collector did not run. |
| ⬜ N/A | Medium | Teams external access (federation) restricted | Teams collector did not run. |
| ⬜ N/A | Medium | Third-party cloud storage apps disabled in Teams | Teams collector did not run. |

---

## 3. Configuration Inventory

Data collected during this assessment. Use as your reference baseline.

### DNS Email Security

| Domain | SPF | DKIM | DMARC Policy | DMARC Record | MTA-STS |
|---|---|---|---|---|---|
| mattlevorson.com | ✓ -all | ✓ Both selectors | ✓ reject | v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailt... | enforce |
| nextlayersec.dev | ✓ -all | ✓ Both selectors | ✓ reject | v=DMARC1; p=reject; rua=mailto:support@nextlayersec.dev; ... | enforce |
| nextlayersec.io | ✓ -all | ✓ Both selectors | ✓ reject | v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; ruamailto... | enforce |

### Exchange Online Configuration

| Setting | Value |
|---|---|
| Mailbox Audit | ✓ Enabled |
| Customer Lockbox | ✓ Enabled |
| SMTP Client Auth | ✓ Disabled |
| Total Mailboxes | 3 |
| POP3 Enabled | 0 mailboxes |
| IMAP Enabled | 0 mailboxes |
| ActiveSync Enabled | 3 mailboxes |
| Audit Bypass | ✓ None |

---

*Prepared by NRG Technology Services | (701) 751-4NRG | nrgtechservices.com*
*Read-only assessment — no configuration changes were made*


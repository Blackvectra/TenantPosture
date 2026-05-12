# Microsoft 365 Security Assessment

**Prepared for:** nextlayersec.io
**Report Date:** May 11, 2026
**Prepared by:** NRG Technology Services
**Tool Version:** NRG-Assessment v4.5.0

---

## 1. Executive Summary

### Overall Posture: 🟡 Moderate

| Metric | Value |
|---|---|
| NRG Composite Score | **68 / 100** |
| Controls Satisfied | 43 |
| Partial | 8 |
| Gaps | 18 |
| Not Applicable | 12 |
| Total | 81 |

### Top 5 Priority Actions

1. 🔴 **Critical** — Phishing-resistant MFA enforced for privileged roles
2. 🔴 **Critical** — Conditional Access: MFA required for all users on all cloud apps
3. 🔴 **Critical** — Unified audit log enabled
4. 🟠 **High** — MFA registered for all enabled user accounts
5. 🟠 **High** — Conditional Access: MFA required for Azure management

### Service Connections

| Service | Connected |
|---|---|
| Graph | ✓ |
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
| 🔴 Gap | Critical | Conditional Access: MFA required for all users on all cloud apps | No enabled CA policy requires MFA for All users on All cloud apps. Compromised credentials provide immediate account access. |
| 🔴 Gap | High | Conditional Access: MFA required for Azure management | No enabled CA policy enforces MFA for Azure management (Azure portal, CLI, PowerShell). App ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013. |
| 🔴 Gap | High | Global Administrator accounts are dedicated (no assigned licenses) | Licensed GA accounts are daily-use accounts — exposed to phishing, malware, and browser-based attacks during normal work. A compromised daily-use account with GA is an immediate full-tenant compromise. |
| 🔴 Gap | High | MFA registered for all enabled user accounts | MFA registration critically low at 80%. Enforcing AAD-3.1 CA MFA policy at this registration level will lock out 1 users. |
| 🔴 Gap | Critical | Phishing-resistant MFA enforced for privileged roles | No Conditional Access policy enforces a phishing-resistant Authentication Strength on privileged roles. |
| 🔴 Gap | High | PIM used for Global Administrator role (JIT access model) | PIM is available but not consistently applied to the Global Administrator role. Permanent standing access means a compromised admin account immediately has full tenant privileges. |
| 🟡 Partial | High | Break-glass Global Administrator account exists | Break-glass candidate(s) detected based on heuristic (unlicensed, cloud-only GA, sign-in > 30 days or never). Manual verification required — credential storage, CA exclusion, and sign-in alert cannot be confirmed automatically. |
| 🟡 Partial | Medium | No Conditional Access policies remaining in report-only mode | Report-only policies provide zero enforcement. They generate logs but do not block or require anything. |
| 🟢 Pass | Informational | Authenticator app number matching enabled |  |
| 🟢 Pass | Informational | Block legacy authentication protocols | Legacy authentication blocked by 1 Conditional Access policy(ies). |
| 🟢 Pass | Informational | Conditional Access: Legacy authentication blocked |  |
| 🟢 Pass | Informational | Conditional Access: Sign-in risk policy configured (Entra ID P2) |  |
| 🟢 Pass | Informational | Conditional Access: User risk policy configured (Entra ID P2) |  |
| 🟢 Pass | Informational | Global Administrator count between 2 and 5 |  |
| 🟢 Pass | Informational | MFA enforced via Conditional Access (not per-user MFA or Security Defaults) |  |
| 🟢 Pass | Informational | No on-premises synced accounts hold Entra ID admin roles |  |
| 🟢 Pass | Informational | Security Defaults disabled in favor of Conditional Access |  |

### Intune

| State | Severity | Control | Detail |
|---|---|---|---|
| 🔴 Gap | High | Android App Protection (MAM) policy configured | No Android App Protection policy configured. Corporate data on Android personal devices has no controls. Data can be copied to personal apps, screenshots can be taken, and data cannot be remotely wiped. |
| 🔴 Gap | High | iOS App Protection (MAM) policy configured | No iOS App Protection policy configured. Corporate data accessed via Outlook, Teams, or OneDrive on personal iOS devices has no copy/paste, screenshot, or backup restrictions. If a device is lost or an employee leaves, data cannot be remotely wiped. |
| 🔴 Gap | High | Microsoft Defender for Endpoint connector enabled in Intune | No Microsoft Defender for Endpoint connector found in Intune. MDE threat risk scores are not integrated with device compliance, meaning compromised devices remain "compliant" in Intune. |
| 🔴 Gap | High | Windows device compliance policy requires antivirus and firewall | No Windows compliance policy requires antivirus or firewall. Endpoints can be enrolled as "compliant" with no AV or firewall active. |
| 🔴 Gap | Medium | Windows Hello for Business policy configured in Intune | No Windows Hello for Business policy found. Windows sign-in defaults to password only on enrolled devices. WHfB provides phishing-resistant biometric/PIN authentication at the device level. |
| 🟡 Partial | Medium | Enrollment restrictions configured beyond default allow-all policy | No custom enrollment restrictions found. The default policy allows all device types (Android, iOS, Windows, macOS) to enroll without restriction. Personal/unmanaged devices can enroll without controls. |
| 🟡 Partial | High | Intune MDM authority configured and devices enrolled | Intune is licensed and the API is accessible, but no managed devices found. Endpoint compliance and management policies cannot be enforced until devices are enrolled. |
| 🟢 Pass | Informational | Windows device compliance policy requires BitLocker encryption |  |

### Power Platform

| State | Severity | Control | Detail |
|---|---|---|---|
| 🟢 Pass | Informational | Power Platform admin role assignments minimal |  |
| ⬜ N/A | Medium | Default environment DLP policy configured | Power Platform DLP data not available. Install Microsoft.PowerApps.Administration.PowerShell for full DLP assessment: Install-Module Microsoft.PowerApps.Administration.PowerShell |
| ⬜ N/A | Medium | High-risk connectors blocked in Power Platform DLP policies | Power Platform DLP data not available. Install Microsoft.PowerApps.Administration.PowerShell for DLP connector assessment. |
| ⬜ N/A | Medium | Non-default Power Platform environments covered by DLP policy | Power Platform DLP data not available. Install Microsoft.PowerApps.Administration.PowerShell. |
| ⬜ N/A | Medium | Power Platform tenant isolation enabled | Tenant isolation data not available via Graph beta API. Verify Power Platform is provisioned in this tenant. |

### Purview

| State | Severity | Control | Detail |
|---|---|---|---|
| 🔴 Gap | Critical | Unified audit log enabled | The unified audit log is disabled. All M365 user and admin activity is not being recorded. Incident response and forensics are impossible without this data. |
| 🟡 Partial | Medium | Audit log retention configured (90 days minimum) | Audit log retains 90 days — meets minimum. Recommend extending to 365 days (requires Microsoft 365 E5 or Audit Premium add-on). |
| 🟡 Partial | Medium | Sensitivity labels published to users | 5 sensitivity label(s) exist but none are published to users. Labels exist in the system but users cannot apply them to documents. |
| 🟢 Pass | Informational | DLP policy covers Exchange email |  |
| 🟢 Pass | Informational | DLP policy covers Microsoft Teams |  |
| 🟢 Pass | Informational | DLP policy covers SharePoint and OneDrive |  |
| 🟢 Pass | Informational | Retention policy for Exchange email configured |  |
| 🟢 Pass | Informational | Retention policy for SharePoint and OneDrive configured |  |

### SharePoint

| State | Severity | Control | Detail |
|---|---|---|---|
| ⬜ N/A | Medium | Anyone link expiration enforced (30 days or less) | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | Default sharing link type set to internal or specific people | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | External user resharing of content disabled | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | Guest user resharing of items they do not own disabled | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | OneDrive default sharing link scoped to organisation | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | SharePoint tenant external sharing restricted | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |
| ⬜ N/A | Medium | Unmanaged device access policy limits or blocks SharePoint access | SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted. |

### Teams

| State | Severity | Control | Detail |
|---|---|---|---|
| 🔴 Gap | High | Anonymous meeting join disabled | Unauthenticated anonymous users can join Teams meetings. Anyone with the meeting link can attend without signing in, with no audit trail. |
| 🔴 Gap | Low | Email integration into Teams channels disabled | Teams channels accept email via a channel email address. Anyone who discovers or is given a channel email address can post content directly into Teams, bypassing message controls. |
| 🔴 Gap | Medium | Meeting presenter role restricted to organiser or co-organisers | Anyone in a meeting can present by default. External attendees can share screens and content without restriction. |
| 🔴 Gap | Medium | Teams consumer (personal account) federation disabled | Teams users can communicate with Teams personal (consumer) accounts. This allows unmanaged, unsecured personal accounts to interact with internal users and potentially exfiltrate data. |
| 🔴 Gap | Medium | Teams external access (federation) restricted | Teams federation is enabled with all external organisations. Any Teams user globally can contact your users and initiate chats or calls. |
| 🔴 Gap | Low | Third-party cloud storage apps disabled in Teams | Third-party cloud storage enabled in Teams: GoogleDrive, Box, DropBox, ShareFile. Users can share files from unmanaged external storage, bypassing DLP and retention policies. |
| 🟢 Pass | Informational | Meeting lobby enabled for external and anonymous users |  |
| 🟢 Pass | Informational | PSTN (dial-in) users bypass lobby disabled |  |

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


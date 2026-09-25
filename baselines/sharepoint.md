# SharePoint Online and OneDrive Baseline

**NRG-Assessment — Baseline Documentation**
*Product: SharePoint Online and OneDrive*

---

## Introduction

This baseline lists the 17 SharePoint Online and OneDrive controls evaluated by NRG-Assessment. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 6 High · 8 Medium · 3 Low

---

## Controls

### SPO-1.1 — External Sharing Restricted

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
SharePoint external sharing is set to Existing Guests or less — not Anyone (anonymous links).

**Business risk:**
Anonymous sharing links can be accessed by anyone with the URL, with no authentication or audit trail.

**Remediation:**
Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, AC-17 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.1 |
| CIS Controls v8.1 | 3.3, 6.8 |
| CISA SCuBA | MS.SHAREPOINT.1.1v1 |
| CMMC 2.0 | AC.L2-3.1.3 |
| ISO/IEC 27001:2022 | A.5.19, A.5.21 |
| SOC 2 | CC6.2, CC6.7 |
| HIPAA | §164.308(a)(4)(ii)(B), §164.312(e)(1) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1213.002 |

---

### SPO-1.2 — Default Sharing Link Not Anonymous

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Default sharing link type is Internal or Specific people — not Anyone.

**Business risk:**
Defaulting to anonymous links means users create them accidentally, without understanding the exposure.

**Remediation:**
Set-SPOTenant -DefaultSharingLinkType Internal

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.2 |
| CIS Controls v8.1 | 3.3 |
| CISA SCuBA | MS.SHAREPOINT.2.1v1 |
| CMMC 2.0 | AC.L2-3.1.3 |
| ISO/IEC 27001:2022 | A.5.16, A.5.18 |
| SOC 2 | CC6.2 |
| HIPAA | §164.308(a)(4)(ii)(B), §164.312(a)(2)(i) |
| PCI DSS | Req 8.2.1 |
| MITRE ATT&CK | T1213.002 |

---

### SPO-1.3 — SharePoint Legacy Authentication Blocked

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
SharePoint blocks legacy authentication, requiring modern auth for all access.

**Business risk:**
Legacy auth to SharePoint bypasses MFA and CA, allowing password-only access to documents.

**Remediation:**
Set-SPOTenant -LegacyAuthProtocolsEnabled $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2, SC-8 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.3.1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| ISO/IEC 27001:2022 | A.5.17, A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.3 |
| MITRE ATT&CK | T1078, T1110 |

---

### SPO-1.4 — Guest Access Expiration Configured

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Guest access to SharePoint is configured to expire and require re-authentication.

**Business risk:**
Permanent guest access means departed vendors and compromised external accounts retain access indefinitely.

**Remediation:**
Set-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays 60

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2(3) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.6 |
| CIS Controls v8.1 | 6.2, 3.4 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(C) |
| PCI DSS | Req 8.2.4 |
| MITRE ATT&CK | T1078 |

---

### SPO-1.5 — Unmanaged Device Access Restricted

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** M365 Business Premium or Entra ID P1

**Description:**
SharePoint access from unmanaged devices is limited to browser-only or blocked.

**Business risk:**
Unmanaged devices have no endpoint controls. Data downloaded leaves the organization's security boundary.

**Remediation:**
Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, AC-17 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.3.2 |
| CIS Controls v8.1 | 3.3, 13.5 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.8.1 |
| SOC 2 | CC6.6 |
| HIPAA | §164.310(d)(1), §164.312(a)(1) |
| PCI DSS | Req 1.3 |
| MITRE ATT&CK | T1213.002 |

---

### SPO-2.1 — OneDrive Sync Client Restricted to Managed Devices

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
OneDrive sync is restricted to domain-joined or Intune-managed devices via tenant GUID allowlist.

**Business risk:**
Unrestricted sync allows personal, unmanaged devices to mirror all SharePoint and OneDrive content locally.

**Remediation:**
Set-SPOTenant -AllowedDomainGuidsForSyncApp @('your-tenant-guid')

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28, AC-19 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.7 |
| CIS Controls v8.1 | 3.3, 13.5 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.1 |
| SOC 2 | CC6.6, CC6.7 |
| HIPAA | §164.310(d)(1) |
| PCI DSS | Req 1.3 |
| MITRE ATT&CK | T1005 |

---

### SPO-2.2 — External Sharing Link Expiration Configured

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Anonymous sharing links are configured to expire after 30 days or less.

**Business risk:**
Permanent anonymous links remain accessible indefinitely even after the sharing need ends.

**Remediation:**
Set-SPOTenant -RequireAnonymousLinksExpireInDays 30

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.3 |
| CIS Controls v8.1 | 3.4 |
| CISA SCuBA | MS.SHAREPOINT.3.1v1 |
| CMMC 2.0 | AC.L2-3.1.3 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(C) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1213.002 |

---

### SPO-2.3 — SharePoint Third-Party Apps From Store Restricted

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Third-party app installation from the SharePoint store is disabled or restricted.

**Business risk:**
Store apps can access SharePoint data with user-granted permissions. Malicious or compromised apps exfiltrate data.

**Remediation:**
SharePoint Admin Center > Settings > Apps > disable apps from the SharePoint store.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.3.3 |
| CIS Controls v8.1 | 2.5 |
| CMMC 2.0 | CM.L2-3.4.6 |
| ISO/IEC 27001:2022 | A.5.23, A.8.19 |
| SOC 2 | CC6.3, CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 6.4.3 |
| MITRE ATT&CK | T1195 |

---

### SPO-2.4 — Custom Script Disabled on SharePoint Sites

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Custom script execution is disabled on personal and all SharePoint sites.

**Business risk:**
Custom scripts enable JavaScript injection into SharePoint pages — XSS, credential harvesting, and data exfiltration.

**Remediation:**
Set-SPOSite -DenyAddAndCustomizePages 1 (applies to all sites)

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-18, SI-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.3.4 |
| CIS Controls v8.1 | 2.7 |
| CMMC 2.0 | SI.L1-3.14.2 |
| ISO/IEC 27001:2022 | A.8.28 |
| SOC 2 | CC6.8, CC8.1 |
| HIPAA | §164.312(c)(1), §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 6.4.1 |
| MITRE ATT&CK | T1059 |

---

### SPO-2.5 — Third-Party Cloud Storage Connectors Disabled

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Third-party cloud storage providers (Dropbox, Box, Google Drive, ShareFile) are disabled so corporate files cannot be moved into storage the tenant does not control or audit. Verified against the Teams client configuration, which is the connector surface exposed to PowerShell; the Microsoft 365 admin center "Third-party storage services" toggle is not readable via API and remains a manual check.

**Business risk:**
Third-party storage integration allows organizational data to move to unmanaged cloud services outside DLP policy coverage.

**Remediation:**
Disable the connectors: Set-CsTeamsClientConfiguration -Identity Global -AllowDropBox $false -AllowBox $false -AllowGoogleDrive $false -AllowShareFile $false. Then confirm the separate Microsoft 365 admin center setting: admin.microsoft.com > Settings > Org settings > Services > Third-party storage services > off.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.3.5 |
| CIS Controls v8.1 | 3.3 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.5.23 |
| SOC 2 | CC6.7 |
| HIPAA | §164.308(a)(4)(ii)(B), §164.312(e)(1) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1048, T1567 |

---

### SPO-2.6 — Email Attestation Required for Sharing

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
External users must verify their email address before accessing shared SharePoint content.

**Business risk:**
Without email attestation, anonymous link recipients have no identity verification — links shared to wrong address are accessed by unintended parties.

**Remediation:**
Set-SPOTenant -EmailAttestationRequired $true -EmailAttestationReAuthDays 30

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-3, AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.4 |
| CIS Controls v8.1 | 3.3 |
| CMMC 2.0 | IA.L1-3.5.2 |
| ISO/IEC 27001:2022 | A.5.17, A.5.18 |
| SOC 2 | CC6.2 |
| HIPAA | §164.308(a)(4)(ii)(C), §164.312(d) |
| PCI DSS | Req 8.3 |
| MITRE ATT&CK | T1078 |

---

### SPO-2.7 — Reauthentication Required for Sharing Links

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Users accessing SharePoint via sharing links must reauthenticate periodically.

**Business risk:**
Persistent sharing link sessions allow access after the sharing intent has ended or the account has been compromised.

**Remediation:**
Set-SPOTenant -EmailAttestationReAuthDays 30

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.5 |
| CIS Controls v8.1 | 6.2 |
| CISA SCuBA | MS.SHAREPOINT.3.3v1 |
| CMMC 2.0 | AC.L2-3.1.11 |
| ISO/IEC 27001:2022 | A.5.17 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.3 |
| MITRE ATT&CK | T1078 |

---

### SPO-2.8 — OneDrive Sync Restricted by Tenant Domain GUID

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
OneDrive sync is restricted to authorized tenant GUIDs preventing cross-tenant syncing.

**Business risk:**
Without GUID restriction, users can sync organizational data to personal Microsoft 365 tenants or competitor tenants.

**Remediation:**
Set-SPOTenant -AllowedDomainGuidsForSyncApp (Get-SPOTenant).TenantId

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4, SC-28 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.8 |
| CIS Controls v8.1 | 3.3, 13.5 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.5.23, A.8.1 |
| SOC 2 | CC6.6, CC6.7 |
| HIPAA | §164.308(a)(4)(ii)(A), §164.310(d)(1) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1005 |

---

### SPO-3.1 — Site Collection Admin Access Reviewed

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Site collection administrators are reviewed periodically to ensure no excessive accumulation.

**Business risk:**
Site collection admins have full read/write access to all site content. Stale or excessive site admins are a data exfiltration risk.

**Remediation:**
Review site admins: Get-SPOSite -Limit ALL | ForEach-Object { Get-SPOUser -Site $_.Url -Group 'Site Collection Administrators' }

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2(9) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.1.1 |
| CIS Controls v8.1 | 5.4, 6.8 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18, A.8.2 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1078 |

---

### SPO-3.2 — SharePoint Sharing Notifications Enabled

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Content owners receive notifications when their files or folders are re-shared.

**Business risk:**
Silent re-sharing allows data to spread beyond intended recipients without the owner's awareness.

**Remediation:**
Set-SPOTenant -NotifyOwnersWhenItemsReshared $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.9 |
| CIS Controls v8.1 | 3.14 |
| CMMC 2.0 | AC.L1-3.1.1 |
| ISO/IEC 27001:2022 | A.8.16 |
| SOC 2 | CC7.2 |
| HIPAA | §164.308(a)(1)(ii)(D) |
| PCI DSS | Req 10.7 |
| MITRE ATT&CK | T1213.002 |

---

### SPO-3.3 — OneDrive Version History Enabled

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Version history is enabled in OneDrive and SharePoint for ransomware recovery capability.

**Business risk:**
Without version history, ransomware-encrypted files cannot be recovered to a clean state. Version history is the primary ransomware recovery control for cloud storage.

**Remediation:**
Verify via SharePoint Admin Center > Settings that versioning is enabled and version limits are adequate (≥100 versions).

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CP-9, CP-10 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.3.6 |
| CIS Controls v8.1 | 11.1, 11.2 |
| CMMC 2.0 | CM.L2-3.4.2 |
| ISO/IEC 27001:2022 | A.8.13 |
| SOC 2 | A1.2 |
| HIPAA | §164.312(c)(1), §164.308(a)(7)(ii)(A) |
| PCI DSS | Req 10.5 |
| MITRE ATT&CK | T1486 |

---

### SPO-3.4 — SharePoint Guest Access Expiration Required

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
External guest access to SharePoint requires periodic re-authentication and is configured to expire.

**Business risk:**
Permanent guest access accumulates over time — departed vendors and ex-clients retain access to organizational data indefinitely.

**Remediation:**
Set-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays 60

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2(3) |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.6 |
| CIS Controls v8.1 | 6.2, 3.4 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(C) |
| PCI DSS | Req 8.2.4 |
| MITRE ATT&CK | T1078 |

### SPO-4.1 — Departed-User OneDrive Retention Configured

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
A deleted user OneDrive is retained long enough for the business to retrieve its contents before permanent deletion.

**Business risk:**
When a user account is deleted their OneDrive is kept for a configurable period and then destroyed. The default is 30 days, which is frequently shorter than the time it takes anyone to realise a departing employee was the only person holding a document. Once the period elapses the content is unrecoverable — there is no backup behind it.

**Remediation:**
Set-SPOTenant -DeletedUserPersonalSiteRetentionPeriodInDays 365 (maximum 3650). Pair it with an offboarding step that reassigns ownership of the OneDrive before the account is deleted, so retention is a safety net rather than the plan.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CP-9, CP-10, SI-12 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 7.2.10 |
| CIS Controls v8.1 | 11.1, 3.4 |
| CMMC 2.0 | MP.L2-3.8.9 |
| MITRE ATT&CK | T1485, T1531 |
| ISO/IEC 27001:2022 | A.8.13 |
| SOC 2 | A1.2 |
| HIPAA | §164.308(a)(7)(ii)(A) |
| PCI DSS v4.0 | Req 10.5 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

# Microsoft Entra ID Baseline

**NRG Assessment Tool — Baseline Documentation**
*Product: Microsoft Entra ID (Azure Active Directory)*

---

## Introduction

This baseline defines the security configuration requirements for Microsoft Entra ID as assessed by the NRG Assessment Tool. Each control maps to one or more security frameworks and produces a finding of **Satisfied**, **Partial**, **Gap**, or **N/A**.

Controls are evaluated against:
- NIST SP 800-53 Rev 5
- CIS Microsoft 365 Foundations Benchmark v3
- CISA SCuBA AAD Secure Configuration Baseline
- CMMC 2.0 Level 2
- MITRE ATT&CK Enterprise

---

## Controls

### AAD-1.1 — Legacy Authentication Blocked

**Criticality:** High

**Description:**
Legacy authentication protocols (Basic Auth, SMTP Auth via legacy clients, POP3, IMAP) do not support modern multi-factor authentication. All legacy authentication must be blocked via Conditional Access.

**Rationale:**
Legacy auth is the primary attack vector for password spray and credential stuffing against M365 tenants. Blocking it eliminates a class of attacks that bypass MFA entirely.

**Check:**
Conditional Access policy exists that blocks legacy authentication (client app conditions: `Exchange ActiveSync Clients`, `Other Clients`) targeting `All Users`.

**Remediation:**
```powershell
# Verify legacy auth block policy exists
Get-MgIdentityConditionalAccessPolicy | Where-Object {
    $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
    $_.Conditions.ClientAppTypes -contains 'other'
} | Select-Object DisplayName, State
```
Create a CA policy: Conditions → Client apps → Exchange ActiveSync + Other clients → Block.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | IA-2, IA-2(12), SC-8 |
| CIS M365 v3 | 5.2.2.3 |
| SCuBA AAD | MS.AAD.1.1v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| MITRE ATT&CK | T1078, T1110 |

---

### AAD-1.2 — MFA Required for All Users

**Criticality:** High

**Description:**
Multi-factor authentication must be enforced for all users via Conditional Access. Security Defaults or per-user MFA do not satisfy this control — a CA policy is required.

**Rationale:**
MFA blocks over 99% of automated credential attacks. Per-user MFA is not auditable at scale and does not support risk-based conditions.

**Check:**
Conditional Access policy exists in `Enabled` state targeting `All Users` with grant control requiring MFA. Security Defaults alone scores `Partial`.

**Remediation:**
Create CA policy: Users → All users → Conditions → (as needed) → Grant → Require MFA. Exclude break-glass accounts.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | IA-2, IA-2(1), IA-2(2) |
| CIS M365 v3 | 5.2.3.1 |
| SCuBA AAD | MS.AAD.3.1v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| MITRE ATT&CK | T1078, T1556 |

---

### AAD-1.3 — Phishing-Resistant MFA for Privileged Roles

**Criticality:** High

**Description:**
Accounts assigned privileged directory roles (Global Admin, Privileged Role Admin, Security Admin, etc.) must use phishing-resistant MFA methods: FIDO2 security key or certificate-based authentication. TOTP/authenticator app alone does not satisfy this control for privileged accounts.

**Rationale:**
AiTM (Adversary-in-the-Middle) phishing attacks bypass standard push/TOTP MFA. Privileged accounts are the highest-value targets. FIDO2 and certificate-based auth are not vulnerable to AiTM.

**Check:**
CA policy exists requiring authentication strength of `Phishing-resistant MFA` for users assigned any privileged directory role.

**Remediation:**
Create CA policy: Users → Directory roles → [all privileged roles] → Grant → Require authentication strength → Phishing-resistant MFA.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | IA-2(1), IA-2(2), IA-2(6) |
| CIS M365 v3 | 5.2.3.5 |
| SCuBA AAD | MS.AAD.3.2v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| MITRE ATT&CK | T1078.004, T1557 |

---

### AAD-1.4 — Global Administrator Count

**Criticality:** High

**Description:**
The number of active Global Administrator accounts must be between 2 and 4. Fewer than 2 creates a break-glass risk. More than 4 indicates overprivileged accounts that expand the attack surface.

**Rationale:**
Global Admin is the highest-privilege role in M365. Every additional Global Admin account is a credential theft target. Excess admins are one of the most common misconfigurations found in MSP-managed tenants.

**Check:**
Count of enabled accounts assigned the Global Administrator role is ≥2 and ≤4.

**Remediation:**
```powershell
# Enumerate Global Admins
$gaRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq 'Global Administrator' }
Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id |
    Select-Object DisplayName, UserPrincipalName
```
Remove Global Admin from accounts that don't require it. Use scoped admin roles (Exchange Admin, Security Admin) instead.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-2, AC-6, AC-6(7) |
| CIS M365 v3 | 1.1.1 |
| SCuBA AAD | MS.AAD.7.1v1 |
| CMMC 2.0 | AC.L2-3.1.5 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-1.5 — Privileged Accounts Cloud-Only

**Criticality:** High

**Description:**
Accounts assigned privileged directory roles must be cloud-only (not synced from on-premises Active Directory). Synced privileged accounts inherit on-premises AD vulnerabilities — a DCSync or credential compromise on-premises directly yields cloud admin access.

**Rationale:**
Hybrid identity introduces a lateral movement path from on-premises to cloud. A single on-premises credential compromise can result in full M365 tenant takeover if the compromised account holds cloud admin roles.

**Check:**
No accounts with `OnPremisesSyncEnabled = true` are assigned privileged directory roles.

**Remediation:**
Create dedicated cloud-only admin accounts for privileged roles. Remove privileged roles from synced accounts.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-2, AC-6, SC-7 |
| CIS M365 v3 | 1.1.3 |
| SCuBA AAD | MS.AAD.7.3v1 |
| CMMC 2.0 | AC.L2-3.1.6 |
| MITRE ATT&CK | T1078.002, T1003 |

---

### AAD-2.1 — Sign-In Risk Policy Enabled

**Criticality:** Medium

**Description:**
A Conditional Access policy must be configured to respond to Entra ID Protection sign-in risk signals. High-risk sign-ins should require MFA step-up or be blocked. Requires Entra ID P2 or Microsoft 365 Business Premium.

**Rationale:**
Sign-in risk detection identifies anomalous authentication patterns (impossible travel, anonymous IP, atypical location, token anomalies). Without a policy, detections are logged but not acted on.

**Check:**
CA policy exists in `Enabled` state using sign-in risk conditions (`High` at minimum) with grant control requiring MFA or blocking access.

**Remediation:**
Create CA policy: Conditions → Sign-in risk → High → Grant → Require MFA.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-4, AU-6, RA-5 |
| CIS M365 v3 | 5.2.5.1 |
| SCuBA AAD | MS.AAD.2.1v1 |
| CMMC 2.0 | SI.L2-3.14.6 |
| MITRE ATT&CK | T1078, T1110 |

---

### AAD-2.2 — User Risk Policy Enabled

**Criticality:** Medium

**Description:**
A Conditional Access policy must respond to Entra ID Protection user risk signals. High user risk should require password change or block sign-in. Requires Entra ID P2 or Microsoft 365 Business Premium.

**Rationale:**
User risk reflects confirmed or suspected account compromise (leaked credentials, confirmed malicious sign-in). Without a policy, a compromised account continues to operate until manually discovered.

**Check:**
CA policy exists using user risk conditions (`High` at minimum) with grant control requiring password change or blocking access.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | IA-5, SI-4 |
| CIS M365 v3 | 5.2.5.2 |
| SCuBA AAD | MS.AAD.2.3v1 |
| CMMC 2.0 | IA.L2-3.5.2 |
| MITRE ATT&CK | T1078, T1586 |

---

### AAD-2.3 — Guest Access Restricted

**Criticality:** Medium

**Description:**
Guest user access permissions must be restricted. The default guest access level allows guests to enumerate directory objects. `GuestUserRoleId` must be set to `Restricted Guest User` (least privilege).

**Rationale:**
Overpermissioned guest access allows external users to enumerate users, groups, and other directory objects — useful reconnaissance for external attackers who gain access to a guest account.

**Check:**
`Get-MgPolicyAuthorizationPolicy` returns `GuestUserRoleId` equal to `2af84b1e-32c8-42b7-82bc-daa82404023b` (Restricted Guest User).

**Remediation:**
External Identities → External collaboration settings → Guest user access → Guest users have limited access to properties and memberships of directory objects.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-2, AC-3, AC-6 |
| CIS M365 v3 | 5.1.5.2 |
| SCuBA AAD | MS.AAD.8.1v1 |
| CMMC 2.0 | AC.L2-3.1.1 |
| MITRE ATT&CK | T1087.004 |

---

### AAD-2.4 — Password Hash Sync or Passthrough Auth (Hybrid Only)

**Criticality:** Medium

**Description:**
Hybrid environments using AD Connect must have Password Hash Synchronization (PHS) enabled as a fallback, even when Passthrough Authentication (PTA) is the primary method. PHS enables Entra ID Protection leaked credential detection.

**Rationale:**
Without PHS, Entra ID Protection cannot evaluate whether credentials appear in breach databases. PHS also provides resilience if on-premises AD becomes unavailable.

**Check:**
Applied only when `OnPremisesSyncEnabled` accounts exist in the tenant. PHS enabled status checked via `Get-MgOrganization`.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | IA-5, SI-4 |
| CIS M365 v3 | 1.2.1 |
| SCuBA AAD | MS.AAD.6.1v1 |
| CMMC 2.0 | IA.L2-3.5.2 |
| MITRE ATT&CK | T1589.001 |

---

### AAD-3.1 — Privileged Identity Management Enabled

**Criticality:** Medium

**Description:**
Privileged Identity Management (PIM) must be active for the tenant, with privileged roles configured for Just-In-Time (JIT) activation. Permanent privileged role assignments must be minimized. Requires Entra ID P2.

**Rationale:**
Permanent admin assignments mean any credential compromise immediately yields admin access. PIM enforces time-limited elevation with approval workflows and audit logs.

**Check:**
PIM is activated for the tenant. No more than 2 permanent Global Admin assignments exist outside of break-glass accounts.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-2(7), AC-6(5) |
| CIS M365 v3 | 1.1.9 |
| SCuBA AAD | MS.AAD.7.4v1 |
| CMMC 2.0 | AC.L2-3.1.6 |
| MITRE ATT&CK | T1078.004 |

---

### AAD-3.2 — Self-Service Password Reset Configured

**Criticality:** Low

**Description:**
Self-Service Password Reset (SSPR) should be enabled and require at least two authentication methods. SSPR with weak method requirements (single factor, security questions only) is a risk.

**Rationale:**
SSPR with strong method requirements reduces help desk burden and attack surface. SSPR misconfigured with single-factor or weak methods becomes an account takeover vector.

**Check:**
SSPR is enabled (`All` or `Selected`). Number of required methods is ≥2. Security questions are not the only configured method.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | IA-5, IA-5(1) |
| CIS M365 v3 | 1.3.1 |
| SCuBA AAD | MS.AAD.5.1v1 |
| CMMC 2.0 | IA.L2-3.5.2 |
| MITRE ATT&CK | T1078 |

---

## Removed / Superseded Policies

| Control | Reason |
|---|---|
| Per-user MFA enforcement | Superseded by Conditional Access MFA (AAD-1.2) |
| Security Defaults | Superseded by Conditional Access policies |

---

## Related Baselines

- [Exchange Online](exo.md) — Email authentication and mailbox security
- [Defender for Office 365](defender.md) — Anti-phishing and threat protection

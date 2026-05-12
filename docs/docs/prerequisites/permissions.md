# Required Permissions

The NRG Assessment Tool requires read-only permissions across Microsoft Graph, Exchange Online, SharePoint, and Teams. **No write permissions are required or requested.**

---

## Microsoft Graph API Permissions (Application or Delegated)

| Permission | Scope | Used By |
|---|---|---|
| `Policy.Read.All` | Delegated | Conditional Access, auth policies |
| `Directory.Read.All` | Delegated | Users, groups, roles, directory objects |
| `RoleManagement.Read.Directory` | Delegated | Directory role assignments |
| `IdentityRiskEvent.Read.All` | Delegated | Identity Protection risk detections |
| `SecurityEvents.Read.All` | Delegated | Secure Score, security alerts |
| `DeviceManagementConfiguration.Read.All` | Delegated | Intune compliance policies |
| `Organization.Read.All` | Delegated | Tenant config, auth settings |
| `ReportSettings.Read.All` | Delegated | Audit log settings |
| `PrivilegedAccess.Read.AzureAD` | Delegated | PIM role assignments |

---

## Exchange Online Roles

| Role | Used By |
|---|---|
| `View-Only Recipients` | Mailbox audit, forwarding rules |
| `View-Only Configuration` | Transport config, anti-spam, DKIM, DMARC |
| `Security Reader` | Anti-phishing, Safe Attachments, Safe Links |

The built-in **Security Reader** role in Exchange Online covers all required Exchange access.

---

## SharePoint / PnP PowerShell

| Permission | Used By |
|---|---|
| SharePoint `read` site collection admin | External sharing settings |
| `Sites.Read.All` (Graph) | OneDrive sync config |

---

## DNS (No Authentication)

DNS collectors perform public DNS lookups only. No credentials required.

---

## Recommended Account Setup

Create a dedicated assessment account per tenant:

```
display name:  NRG Assessment (Read-Only)
UPN:           nrg-assessment@<tenant>.onmicrosoft.com
license:       None required (cloud-only service account)
roles:         Security Reader (Entra ID + Defender)
               View-Only Organization Management (Exchange)
               SharePoint Admin (read-only delegation)
```

Exclude this account from Conditional Access policies that would block non-interactive sign-in or require compliant device.

---

## Interactive Authentication

The tool uses **interactive browser authentication** (MSAL). On first run per service, a browser window opens for admin login with MFA. The token is cached for the session duration. No credentials are stored to disk.

See [setup.md](../installation/setup.md) for first-run walkthrough.

# App-Only Authentication — NRG-Assessment

> **Current status:** The tool currently uses interactive/delegated auth (browser prompt).  
> App-only certificate authentication is the next feature to add for unattended/scheduled runs.  
> This document describes how to set it up when implemented.

---

## When You Need App-Only Auth

- Scheduled assessments (Task Scheduler, Windows Service)
- CI/CD pipeline assessments
- Headless server environments with no interactive desktop
- Automated monthly compliance reports

---

## Setup (Once per Tenant)

### 1. Register an App in Entra ID

```powershell
# In the target tenant
# Entra ID > App registrations > New registration
# Name: NRG-Assessment
# Supported account types: This org directory only
# Redirect URI: none
```

### 2. Grant API Permissions (Application, not Delegated)

Required **application** permissions:
```
Microsoft Graph:
  Policy.Read.All
  Directory.Read.All
  Reports.Read.All
  RoleManagement.Read.All
  User.Read.All
  UserAuthenticationMethod.Read.All (requires admin consent)
  DeviceManagementConfiguration.Read.All
  DeviceManagementApps.Read.All
  DeviceManagementManagedDevices.Read.All
  Application.Read.All
```

**Grant admin consent** after adding all permissions.

> **Note:** Exchange Online and SharePoint do not support app-only auth for all cmdlets the tool uses. Some collectors will need to fall back to delegated auth or use the REST API directly.

### 3. Create a Certificate

```powershell
# Self-signed for testing (use CA-issued cert in production)
$cert = New-SelfSignedCertificate `
    -Subject "CN=NRG-Assessment" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -NotAfter (Get-Date).AddYears(2)

# Export public key for upload to Entra
Export-Certificate -Cert $cert -FilePath "NRG-Assessment.cer"
```

Upload `NRG-Assessment.cer` to: App registration > Certificates & secrets > Certificates > Upload certificate

### 4. Run with App-Only Auth

```powershell
# Not yet implemented — placeholder for future Connect-NRGServices update
.\Invoke-NRGAssessment.ps1 `
    -AppOnly `
    -ClientId   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -TenantId   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -Thumbprint "ABCDEF1234567890..."
```

---

## Current Workaround

Until app-only is implemented, use **device code flow** for headless environments:

```powershell
# Device code prompts in console — open URL on another device to authenticate
.\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com
# When prompted: open https://microsoft.com/devicelogin and enter the code shown
```

---

*Feature status: Planned for v4.6.0*

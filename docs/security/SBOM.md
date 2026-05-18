# Software Bill of Materials — NRG-Assessment v4.5.5

## Runtime Dependencies

| Package | Version | Source | Purpose |
|---|---|---|---|
| Microsoft.Graph.Authentication | 2.20.0 | PSGallery | Graph API authentication |
| ExchangeOnlineManagement | 3.4.0 | PSGallery | Exchange Online cmdlets |
| MicrosoftTeams | 6.4.0 | PSGallery | Teams policy collection |
| Microsoft.Online.SharePoint.PowerShell | 16.0.24720.12000 | PSGallery | SharePoint collection |
| PowerShell | 7.4+ | Microsoft | Runtime |

## Test Dependencies

| Package | Version | Source | Purpose |
|---|---|---|---|
| Pester | 5.6.1 | PSGallery | Security test suite |
| PSScriptAnalyzer | latest | PSGallery | Static analysis (CI) |

## Install Commands (Exact Versions)

```powershell
Install-PSResource -Name Microsoft.Graph.Authentication -Version 2.20.0 -TrustRepository
Install-PSResource -Name ExchangeOnlineManagement       -Version 3.4.0  -TrustRepository
Install-PSResource -Name MicrosoftTeams                -Version 6.4.0  -TrustRepository
Install-PSResource -Name Microsoft.Online.SharePoint.PowerShell -Version 16.0.24720.12000 -TrustRepository
Install-PSResource -Name Pester                        -Version 5.6.1  -TrustRepository
```

> **Use `Install-PSResource` not `Install-Module`** — PSResourceGet supports SHAsum verification; Install-Module does not.

## CycloneDX SBOM

A machine-readable CycloneDX SBOM (`nrg-assessment.cdx.json`) is generated automatically on GitHub release via the `cdxgen` step in `.github/workflows/security.yml`.

## Version Pinning Rationale

All dependencies are pinned to exact versions to:
1. Prevent supply chain substitution attacks
2. Ensure reproducible installs across MSP workstations
3. Allow regression testing against specific API behaviors

When updating a dependency version: update this file, the psd1 `RequiredModules`, DEPLOYMENT.md install block, and the GitHub Actions workflow simultaneously.

---

*Last updated: May 2026 · v4.5.5*

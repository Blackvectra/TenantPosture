#Requires -Version 7.0
<#
.SYNOPSIS
    Generates a CycloneDX 1.5 SBOM for TenantPosture.

.DESCRIPTION
    Enumerates the PowerShell module dependencies declared in the manifest and emits
    a CycloneDX 1.5 JSON SBOM suitable for upload to vulnerability databases or
    customer supply chain reviews.
#>

[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'sbom\tp-assessment.cdx.json'),
    [string] $RepoRoot   = (Split-Path -Parent $PSScriptRoot),
    # Audit fix (v4.6.x LOW): default Version is read from the module manifest
    # at runtime instead of being a hardcoded constant that drifts every
    # release. Operators can still override via -Version on the command line.
    [string] $Version
)

if ([string]::IsNullOrWhiteSpace($Version)) {
    $manifestPath = Join-Path $RepoRoot 'TenantPosture.psd1'
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $manifestData = Import-PowerShellDataFile -LiteralPath $manifestPath -ErrorAction Stop
            if ($manifestData.ModuleVersion) { $Version = [string]$manifestData.ModuleVersion }
        } catch {
            Write-Warning "Could not read ModuleVersion from manifest, falling back to placeholder: $($_.Exception.Message)"
        }
    }
    if ([string]::IsNullOrWhiteSpace($Version)) { $Version = '0.0.0-unknown' }
}


$outputDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDir)) {
    # LiteralPath: avoid wildcard expansion if the path contains [ ] *.
    # v4.6.3 P2.
    [void][System.IO.Directory]::CreateDirectory($outputDir)
}

# The components are the modules the manifest actually requires (hard
# dependencies) plus every optional runtime dependency a shipped feature
# imports on demand: the Graph submodules and the Teams and SharePoint shells
# (collectors), Pode (the -Web GUI, Lib/Start-TPWebServer.ps1, 2.10 or later)
# and openpyxl (the XLSX publishers, through Lib/Invoke-TPPython.ps1; the
# installer pins 3.1.5). An optional dependency left out of the SBOM is a
# release attesting an incomplete inventory, so a downstream scanner cannot
# report exposure in a supported feature. Licenses are what each package
# publishes, read at the gallery, never assumed from the publisher: the
# Microsoft Graph SDK, ExchangeOnlineManagement (its license.txt from 3.7.2
# on), MicrosoftTeams (likewise), Pode and openpyxl are MIT; the SharePoint
# Online Management Shell publishes no license file in its gallery package
# and ships under Microsoft's license terms.
$manifestPath = Join-Path $RepoRoot 'TenantPosture.psd1'
$required = @()
# An SBOM with the required modules missing is wrong, not partial: the release
# attests it, so an unreadable manifest fails the generation outright.
$m = Import-PowerShellDataFile -LiteralPath $manifestPath -ErrorAction Stop
foreach ($r in @($m.RequiredModules)) {
    if ($r -is [hashtable]) { $required += @{ Name = [string]$r.ModuleName; Version = [string]$r.ModuleVersion; Max = [string]$r.MaximumVersion } }
    else { $required += @{ Name = [string]$r; Version = ''; Max = '' } }
}
if ($required.Count -eq 0) { throw "No RequiredModules found in $manifestPath; refusing to write an SBOM without the hard dependencies." }
$licenseOf = @{
    'Microsoft.Graph.Authentication'            = 'MIT'
    'Microsoft.Graph.Reports'                   = 'MIT'
    'Microsoft.Graph.Identity.Governance'       = 'MIT'
    'Microsoft.Graph.Identity.SignIns'          = 'MIT'
    'Microsoft.Graph.Users'                     = 'MIT'
    'ExchangeOnlineManagement'                  = 'MIT'
    'MicrosoftTeams'                            = 'MIT'
    'Microsoft.Online.SharePoint.PowerShell'    = 'LicenseRef-Microsoft-Software-License-Terms'
    'Pode'                                      = 'MIT'
    'openpyxl'                                  = 'MIT'
}
# Where a component is published and by whom. Everything not listed here is a
# Microsoft module on the PowerShell Gallery.
$originOf = @{
    'Pode'     = @{ Ecosystem = 'powershell'; Supplier = 'Badgerati (Matthew Kelly)'; SupplierUrl = 'https://github.com/Badgerati/Pode'; Distribution = 'https://www.powershellgallery.com/packages/Pode/{0}' }
    'openpyxl' = @{ Ecosystem = 'pypi';       Supplier = 'openpyxl contributors';   SupplierUrl = 'https://pypi.org/project/openpyxl/';   Distribution = 'https://pypi.org/project/openpyxl/{0}/' }
}
$defaultOrigin = @{ Ecosystem = 'powershell'; Supplier = 'Microsoft Corporation'; SupplierUrl = 'https://www.powershellgallery.com'; Distribution = 'https://www.powershellgallery.com/packages/{1}/{0}' }
$optional = @(
    # Graph SDK submodules Connect-TPServices imports when present (Lib/Connect-TPServices.ps1).
    @{ Name = 'Microsoft.Graph.Reports';                Version = '2.20.0';         Scope = 'optional' }
    @{ Name = 'Microsoft.Graph.Identity.Governance';    Version = '2.20.0';         Scope = 'optional' }
    @{ Name = 'Microsoft.Graph.Identity.SignIns';       Version = '2.20.0';         Scope = 'optional' }
    @{ Name = 'Microsoft.Graph.Users';                  Version = '2.20.0';         Scope = 'optional' }
    @{ Name = 'MicrosoftTeams';                         Version = '6.5.0';          Scope = 'optional' }
    @{ Name = 'Microsoft.Online.SharePoint.PowerShell'; Version = '16.0.24720.12000'; Scope = 'optional' }
    # The -Web GUI (Lib/Start-TPWebServer.ps1) imports Pode and requires 2.10.0 or later.
    @{ Name = 'Pode';                                   Version = '2.10.0';         Scope = 'optional'; Semantics = 'declared minimum; imported by -Web on demand' }
    # The XLSX publishers run openpyxl through Lib/Invoke-TPPython.ps1; Install-TPPrerequisites.ps1 pins this version.
    @{ Name = 'openpyxl';                               Version = '3.1.5';          Scope = 'optional'; Semantics = 'pinned by the installer; used by the XLSX publishers on demand' }
)
$dependencies = @()
foreach ($r in $required) { $dependencies += @{ Name = $r.Name; Version = $r.Version; Max = $r.Max; Scope = 'required'; License = $(if ($licenseOf.ContainsKey($r.Name)) { $licenseOf[$r.Name] } else { 'NOASSERTION' }) } }
foreach ($o in $optional) { $dependencies += @{ Name = $o.Name; Version = $o.Version; Max = ''; Scope = 'optional'; License = $(if ($licenseOf.ContainsKey($o.Name)) { $licenseOf[$o.Name] } else { 'NOASSERTION' }); Semantics = $(if ($o.ContainsKey('Semantics')) { $o.Semantics } else { '' }) } }
foreach ($d in $dependencies) {
    $origin = if ($originOf.ContainsKey($d.Name)) { $originOf[$d.Name] } else { $defaultOrigin }
    $d['Purl'] = "pkg:$($origin.Ecosystem)/$($d.Name)@$($d.Version)"
    $d['Supplier'] = $origin.Supplier
    $d['SupplierUrl'] = $origin.SupplierUrl
    $d['Distribution'] = ($origin.Distribution -f $d.Version, $d.Name)
}

$bom = [ordered]@{
    bomFormat    = 'CycloneDX'
    specVersion  = '1.5'
    serialNumber = "urn:uuid:$([guid]::NewGuid())"
    version      = 1
    metadata = [ordered]@{
        timestamp = (Get-Date).ToString('o')
        tools = @(
            [ordered]@{
                vendor  = 'NRG Technology Services / NextLayerSec LLC'
                name    = 'Generate-SBOM.ps1'
                version = '1.0'
            }
        )
        component = [ordered]@{
            type    = 'application'
            'bom-ref' = "pkg:tp-assessment@$Version"
            name    = 'TenantPosture'
            version = $Version
            description = 'Read-only Microsoft 365 security assessment tool'
            licenses = @(
                @{ license = @{ id = 'Apache-2.0' } }
            )
            supplier = @{
                name = 'NRG Technology Services / NextLayerSec LLC'
                url  = @('https://www.nrgtechservices.com')
            }
        }
    }
    components = @($dependencies | ForEach-Object {
        [ordered]@{
            type       = 'library'
            'bom-ref'  = $_.Purl
            name       = $_.Name
            version    = $_.Version
            purl       = $_.Purl
            scope      = $_.Scope
            # `version` is the declared MINIMUM; the manifest allows a range and
            # the installed version varies by workstation. The range is recorded
            # as a property so an inventory tool does not read the floor as exact.
            properties = @(
                @{ name = 'tenantposture:version-semantics'; value = $(if ($_.Scope -eq 'required') { 'declared minimum; manifest range in tenantposture:version-range' } elseif ($_.ContainsKey('Semantics') -and $_.Semantics) { $_.Semantics } else { 'tested version; imported on demand' }) }
                @{ name = 'tenantposture:version-range'; value = $(if ($_.Max) { "[$($_.Version),$($_.Max)]" } else { "[$($_.Version),)" }) }
            )
            licenses   = @($(if ($_.License -like 'LicenseRef-*' -or $_.License -eq 'NOASSERTION') { @{ license = @{ name = $_.License } } } else { @{ license = @{ id = $_.License } } }))
            supplier   = @{ name = $_.Supplier; url = @($_.SupplierUrl) }
            externalReferences = @(
                @{ type = 'distribution'; url = $_.Distribution }
            )
        }
    })
    dependencies = @(
        [ordered]@{
            ref = "pkg:tp-assessment@$Version"
            dependsOn = @($dependencies | ForEach-Object { $_.Purl })
        }
    )
}

$bom | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputPath -Encoding utf8
Write-Host "[+] CycloneDX SBOM written: $OutputPath" -ForegroundColor Green
Write-Host "    Components: $($dependencies.Count)" -ForegroundColor DarkGray
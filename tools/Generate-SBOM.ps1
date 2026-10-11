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
# dependencies) plus the optional modules the collectors import on demand.
# Licenses are the publishers' stated terms: the Microsoft Graph SDK and
# PnP.PowerShell are MIT; ExchangeOnlineManagement, MicrosoftTeams and the
# SharePoint Online shell ship under Microsoft's proprietary license terms.
$manifestPath = Join-Path $PSScriptRoot '..' 'TenantPosture.psd1'
$required = @()
try {
    $m = Import-PowerShellDataFile -LiteralPath $manifestPath
    foreach ($r in @($m.RequiredModules)) {
        if ($r -is [hashtable]) { $required += @{ Name = [string]$r.ModuleName; Version = [string]$r.ModuleVersion; Max = [string]$r.MaximumVersion } }
        else { $required += @{ Name = [string]$r; Version = ''; Max = '' } }
    }
} catch { Write-Warning "Could not read RequiredModules from the manifest: $($_.Exception.Message)" }
$licenseOf = @{
    'Microsoft.Graph.Authentication'            = 'MIT'
    'ExchangeOnlineManagement'                  = 'LicenseRef-Microsoft-Software-License-Terms'
    'MicrosoftTeams'                            = 'LicenseRef-Microsoft-Software-License-Terms'
    'Microsoft.Online.SharePoint.PowerShell'    = 'LicenseRef-Microsoft-Software-License-Terms'
}
$optional = @(
    @{ Name = 'MicrosoftTeams';                         Version = '6.5.0';          Scope = 'optional' }
    @{ Name = 'Microsoft.Online.SharePoint.PowerShell'; Version = '16.0.24720.12000'; Scope = 'optional' }
)
$dependencies = @()
foreach ($r in $required) { $dependencies += @{ Name = $r.Name; Version = $r.Version; Scope = 'required'; License = $(if ($licenseOf.ContainsKey($r.Name)) { $licenseOf[$r.Name] } else { 'NOASSERTION' }) } }
foreach ($o in $optional) { $dependencies += @{ Name = $o.Name; Version = $o.Version; Scope = 'optional'; License = $(if ($licenseOf.ContainsKey($o.Name)) { $licenseOf[$o.Name] } else { 'NOASSERTION' }) } }

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
            'bom-ref'  = "pkg:powershell/$($_.Name)@$($_.Version)"
            name       = $_.Name
            version    = $_.Version
            purl       = "pkg:powershell/$($_.Name)@$($_.Version)"
            scope      = $_.Scope
            # A minimum version from the manifest: what the tool requires, not
            # what a particular workstation has installed.
            licenses   = @($(if ($_.License -like 'LicenseRef-*' -or $_.License -eq 'NOASSERTION') { @{ license = @{ name = $_.License } } } else { @{ license = @{ id = $_.License } } }))
            supplier   = @{ name = 'Microsoft Corporation'; url = @('https://www.powershellgallery.com') }
            externalReferences = @(
                @{ type = 'distribution'; url = "https://www.powershellgallery.com/packages/$($_.Name)/$($_.Version)" }
            )
        }
    })
    dependencies = @(
        [ordered]@{
            ref = "pkg:tp-assessment@$Version"
            dependsOn = @($dependencies | ForEach-Object { "pkg:powershell/$($_.Name)@$($_.Version)" })
        }
    )
}

$bom | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputPath -Encoding utf8
Write-Host "[+] CycloneDX SBOM written: $OutputPath" -ForegroundColor Green
Write-Host "    Components: $($dependencies.Count)" -ForegroundColor DarkGray
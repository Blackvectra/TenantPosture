#Requires -Version 7.0
<#
.SYNOPSIS
    Generates a CycloneDX 1.5 SBOM for NRG-Assessment.

.DESCRIPTION
    Enumerates the PowerShell module dependencies declared in the manifest and emits
    a CycloneDX 1.5 JSON SBOM suitable for upload to vulnerability databases or
    customer supply chain reviews.
#>

[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'sbom\nrg-assessment.cdx.json'),
    [string] $RepoRoot   = (Split-Path -Parent $PSScriptRoot),
    # Audit fix (v4.6.x LOW): default Version is read from the module manifest
    # at runtime instead of being a hardcoded constant that drifts every
    # release. Operators can still override via -Version on the command line.
    [string] $Version
)

if ([string]::IsNullOrWhiteSpace($Version)) {
    $manifestPath = Join-Path $RepoRoot 'NRG-Assessment.psd1'
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
    New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
}

# Known dependencies (matches docs/security/SBOM.md)
$dependencies = @(
    @{ Name = 'Microsoft.Graph.Authentication';      Version = '2.26.1'; License = 'MIT' }
    @{ Name = 'ExchangeOnlineManagement';            Version = '3.7.2';  License = 'MIT' }
    @{ Name = 'Microsoft.Graph.Reports';             Version = '2.26.1'; License = 'MIT' }
    @{ Name = 'Microsoft.Graph.Identity.Governance'; Version = '2.26.1'; License = 'MIT' }
    @{ Name = 'Microsoft.Graph.Identity.SignIns';    Version = '2.26.1'; License = 'MIT' }
    @{ Name = 'Microsoft.Graph.Users';               Version = '2.26.1'; License = 'MIT' }
    @{ Name = 'MicrosoftTeams';                      Version = '6.5.0';  License = 'MIT' }
    @{ Name = 'PnP.PowerShell';                      Version = '3.0.0';  License = 'MIT' }
)

$bom = [ordered]@{
    bomFormat    = 'CycloneDX'
    specVersion  = '1.5'
    serialNumber = "urn:uuid:$([guid]::NewGuid())"
    version      = 1
    metadata = [ordered]@{
        timestamp = (Get-Date).ToString('o')
        tools = @(
            [ordered]@{
                vendor  = 'NRG Technology Services'
                name    = 'Generate-SBOM.ps1'
                version = '1.0'
            }
        )
        component = [ordered]@{
            type    = 'application'
            'bom-ref' = "pkg:nrg-assessment@$Version"
            name    = 'NRG-Assessment'
            version = $Version
            description = 'Read-only Microsoft 365 security assessment tool'
            licenses = @(
                @{ license = @{ id = 'MIT' } }
            )
            supplier = @{
                name = 'NRG Technology Services'
                url  = @('https://nrgtechservices.com')
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
            licenses   = @(@{ license = @{ id = $_.License } })
            supplier   = @{ name = 'Microsoft Corporation'; url = @('https://www.powershellgallery.com') }
            externalReferences = @(
                @{ type = 'distribution'; url = "https://www.powershellgallery.com/packages/$($_.Name)/$($_.Version)" }
            )
        }
    })
    dependencies = @(
        [ordered]@{
            ref = "pkg:nrg-assessment@$Version"
            dependsOn = @($dependencies | ForEach-Object { "pkg:powershell/$($_.Name)@$($_.Version)" })
        }
    )
}

$bom | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "[+] CycloneDX SBOM written: $OutputPath" -ForegroundColor Green
Write-Host "    Components: $($dependencies.Count)" -ForegroundColor DarkGray
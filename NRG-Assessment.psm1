#
# NRG-Assessment.psm1
# Module loader - dot-sources all functions from Lib, Collectors, Evaluators, Publishers
#
# Author: Matthew Levorson, NRG Technology Services
# Version: 4.0.0
#
# Architecture:
#   - Lib/         Shared helpers (Add-NRGFinding, Connect-NRGServices, etc.)
#   - Collectors/  Raw data collection only (Get-NRGCollector-*)
#   - Evaluators/  Scoring logic only (Test-NRGControl-*)
#   - Publishers/  Report generation (Publish-NRG*)
#   - Config/      JSON control + framework definitions
#
# Each function has ONE source file. No duplicates anywhere in the repo.
#

# StrictMode intentionally off - allows safe property access patterns in collectors
$ErrorActionPreference = 'Continue'

# Module-scoped constants
$script:NRGAssessmentVersion = '4.0.0'
$script:NRGModuleRoot        = $PSScriptRoot

# Module-scoped findings collection (populated by evaluators, consumed by publishers)
$script:NRGFindings    = [System.Collections.Generic.List[object]]::new()
$script:NRGExceptions  = [System.Collections.Generic.List[object]]::new()
$script:NRGCoverage    = [System.Collections.Generic.Dictionary[string,string]]::new()
$script:NRGRawData     = @{}

# Load branding (optional - falls back to defaults if missing)
$brandPath = Join-Path $PSScriptRoot 'Config\branding.psd1'
$script:NRGBrand = if (Test-Path $brandPath) {
    try {
        Import-PowerShellDataFile -Path $brandPath -ErrorAction Stop
    } catch {
        Write-Warning "Branding file invalid, using defaults: $_"
        $null
    }
} else { $null }

if (-not $script:NRGBrand) {
    $script:NRGBrand = @{
        CompanyName    = 'NRG Technology Services'
        Phone          = '(701) 751-4NRG'
        Website        = 'nrgtechservices.com'
        Email          = 'security@nrgtechservices.com'
        PrimaryColor   = '#1a3a6b'
        SecondaryColor = '#e87722'
        LogoUrl        = ''
    }
}

# Function loader - dot-source by folder in dependency order
$loadOrder = @('Lib', 'Collectors', 'Evaluators', 'Publishers')

foreach ($folder in $loadOrder) {
    $folderPath = Join-Path $PSScriptRoot $folder
    if (-not (Test-Path $folderPath)) {
        Write-Warning "Module folder not found: $folder"
        continue
    }

    # Recursive so Collectors/AAD/*.ps1 is found
    $files = Get-ChildItem -Path $folderPath -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue

    foreach ($file in $files) {
        try {
            . $file.FullName 3>$null
        } catch {
            Write-Warning "Failed to load $($file.Name): $($_.Exception.Message)"
        }
    }
}

# Explicitly list exports - avoids PS warning about * exporting private helpers
$script:ExportedFunctions = @(
    # Lib - core state management
    'Add-NRGFinding','Get-NRGFindings','Clear-NRGFindings',
    'Register-NRGException','Get-NRGExceptions',
    'Register-NRGCoverage','Get-NRGCoverage',
    'Set-NRGRawData','Get-NRGRawData',
    # Lib - connections
    'Connect-NRGServices','Disconnect-NRGServices',
    # Lib - control definitions
    'Get-NRGControlDefinitions','Get-NRGControlById','Get-NRGFrameworkCitations',
    # Collectors
    'Invoke-NRGCollectAADAuthPolicies','Invoke-NRGCollectAADCAPolicies',
    'Invoke-NRGCollectEXOMailboxConfig','Invoke-NRGCollectDNSEmailRecords',
    # Evaluators
    'Test-NRGControlAADLegacyAuth','Test-NRGControlAADPhishResistantMFA',
    'Test-NRGControlEXOMailboxAudit','Test-NRGControlEXOSmtpAuth',
    'Test-NRGControlDNSSPF','Test-NRGControlDNSDKIM','Test-NRGControlDNSDMARC',
    # Publishers
    'Publish-NRGAssessmentSummary'
)
Export-ModuleMember -Function $script:ExportedFunctions -Variable NRGAssessmentVersion, NRGBrand

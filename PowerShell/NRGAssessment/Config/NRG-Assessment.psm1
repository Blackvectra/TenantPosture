#
# NRG-Assessment.psm1
# Module loader - dot-sources all functions from Lib, Collectors, Evaluators, Publishers
#
# Author: Matthew Levorson, NRG Technology Services
# Version: 4.5.0
#
# Sessions:
#   1-4  AAD, EXO, DNS, Defender (34 controls)
#   5-6  SharePoint, Teams, Purview, Intune, Power Platform (+36 = 70 controls)
#
# StrictMode intentionally off - allows safe property access patterns in collectors
$ErrorActionPreference = 'Continue'
$script:NRGAssessmentVersion = '4.5.0'
$script:NRGModuleRoot        = $PSScriptRoot
$script:NRGFindings    = [System.Collections.Generic.List[object]]::new()
$script:NRGExceptions  = [System.Collections.Generic.List[object]]::new()
$script:NRGCoverage    = [System.Collections.Generic.Dictionary[string,string]]::new()
$script:NRGRawData     = @{}

$brandPath = Join-Path $PSScriptRoot 'Config\branding.psd1'
$script:NRGBrand = if (Test-Path $brandPath) {
    try { Import-PowerShellDataFile -Path $brandPath -ErrorAction Stop }
    catch { Write-Warning "Branding file invalid, using defaults: $_"; $null }
} else { $null }
if (-not $script:NRGBrand) {
    $script:NRGBrand = @{
        CompanyName    = 'NRG Technology Services'
        Phone          = '(701) 751-4NRG'
        Website        = 'nrgtechservices.com'
        Email          = 'security@nrgtechservices.com'
        PrimaryColor   = '#1a3a6b'
        SecondaryColor = '#e87722'
        AccentColor    = '#4a7ba6'
        LogoUrl        = ''
    }
}

$loadOrder = @('Lib', 'Collectors', 'Evaluators', 'Publishers')
foreach ($folder in $loadOrder) {
    $folderPath = Join-Path $PSScriptRoot $folder
    if (-not (Test-Path $folderPath)) { Write-Warning "Module folder not found: $folder"; continue }
    $files = Get-ChildItem -Path $folderPath -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        try { . $file.FullName 3>$null }
        catch { Write-Warning "Failed to load $($file.Name): $($_.Exception.Message)" }
    }
}

$script:ExportedFunctions = @(
    # ── Lib ───────────────────────────────────────────────────────────────────
    'Add-NRGFinding','Get-NRGFindings','Clear-NRGFindings',
    'Register-NRGException','Get-NRGExceptions',
    'Register-NRGCoverage','Get-NRGCoverage',
    'Set-NRGRawData','Get-NRGRawData',
    'Connect-NRGServices','Disconnect-NRGServices',
    'Get-NRGControlDefinitions','Get-NRGControlById','Get-NRGFrameworkCitations',

    # ── Collectors — Sessions 1-4 ─────────────────────────────────────────────
    'Invoke-NRGCollectAADAuthPolicies','Invoke-NRGCollectAADCAPolicies',
    'Invoke-NRGCollectAADUsers','Invoke-NRGCollectAADRoles','Invoke-NRGCollectAADPIM',
    'Invoke-NRGCollectEXOMailboxConfig','Invoke-NRGCollectDefender',
    'Invoke-NRGCollectDNSEmailRecords',

    # ── Collectors — Sessions 5-6 ─────────────────────────────────────────────
    'Invoke-NRGCollectSharePoint',
    'Invoke-NRGCollectTeams',
    'Invoke-NRGCollectPurview',
    'Invoke-NRGCollectIntune',
    'Invoke-NRGCollectPowerPlatform',

    # ── Evaluators — Sessions 1-4 ─────────────────────────────────────────────
    'Test-NRGControlAADLegacyAuth','Test-NRGControlAADPhishResistantMFA',
    'Test-NRGControlAADMFA','Test-NRGControlAADCA','Test-NRGControlAADPrivAccess',
    'Test-NRGControlEXOMailboxAudit','Test-NRGControlEXOSmtpAuth',
    'Test-NRGControlEXOPop3','Test-NRGControlEXOImap',
    'Test-NRGControlEXOCustomerLockbox','Test-NRGControlEXOSharedMailbox','Test-NRGControlEXOModernAuth',
    'Test-NRGControlDNSSPF','Test-NRGControlDNSDKIM','Test-NRGControlDNSDMARC',
    'Test-NRGControlDNSMTASTS','Test-NRGControlDNSTLSRPT','Test-NRGControlDNSDNSSEC',
    'Test-NRGControlDefender',

    # ── Evaluators — Sessions 5-6 ─────────────────────────────────────────────
    'Test-NRGControlSharePoint',
    'Test-NRGControlTeams',
    'Test-NRGControlPurview',
    'Test-NRGControlIntune',
    'Test-NRGControlPowerPlatform',

    # ── Publishers ────────────────────────────────────────────────────────────
    'Publish-NRGAssessmentSummary','Publish-NRGAssessmentHTML'
)
Export-ModuleMember -Function $script:ExportedFunctions -Variable NRGAssessmentVersion, NRGBrand

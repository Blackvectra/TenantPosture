#
# Invoke-NRGAssessment.ps1
# Entry point for NRG-Assessment v4.5.0
#
# Flow:
#   1. Import module (loads Lib, Collectors, Evaluators, Publishers)
#   2. Connect to M365 services
#   3. Run collectors -> raw data stored in module state
#   4. Run evaluators -> findings registered via Add-NRGFinding
#   5. Run publishers -> Markdown + HTML + JSON written to output/
#
# Usage:
#   pwsh -ExecutionPolicy RemoteSigned -File .\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com
#

[CmdletBinding()]
param(
    [string]   $UserPrincipalName,
    [string]   $OutputPath,
    [switch]   $SkipPurview,
    [switch]   $SkipTeams,
    [switch]   $SkipSharePoint,
    [switch]   $SkipIntune,
    [switch]   $SkipPowerPlatform,
    [switch]   $SkipDNS,
    [string[]] $DnsDomains,
    [switch]   $JsonOnly,
    [switch]   $WhatIfConnections
)

# Disable WAM broker before any module loads.
# Must be after param() but before Import-Module.
# Prevents RuntimeBroker NullReferenceException on EXO, IPPS, Teams, Graph.
$env:MSAL_ALLOW_BROKER = '0'
$ErrorActionPreference = 'Stop'
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ── Banner ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " NRG-Assessment v4.5.0 - Read-Only M365 Security Assessment" -ForegroundColor Cyan
Write-Host " NRG Technology Services  |  75 Controls" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ── Output path ──────────────────────────────────────────────────────────────
if (-not $OutputPath) { $OutputPath = Join-Path $scriptDir 'output' }
if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }

# ── Import module ────────────────────────────────────────────────────────────
Write-Host "[-] Loading NRG-Assessment module..." -ForegroundColor Cyan
$manifestPath = Join-Path $scriptDir 'NRG-Assessment.psd1'
try {
    Import-Module $manifestPath -Force -ErrorAction Stop
    Write-Host "  [+] Module loaded (v$($script:NRGAssessmentVersion))" -ForegroundColor Green
} catch {
    Write-Host "  [!] Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Clear-NRGFindings

# ── Connect to services ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Establishing service connections (Graph: browser | Teams/EXO/IPPS: device code)..." -ForegroundColor Cyan
$connectParams = @{}
if ($UserPrincipalName) { $connectParams['UserPrincipalName'] = $UserPrincipalName }
if ($SkipPurview)       { $connectParams['SkipPurview']       = $true }
if ($SkipTeams)         { $connectParams['SkipTeams']         = $true }

# Always defer SharePoint — PnP loads Graph.Core which conflicts with Graph SDK
$connectParams['SkipSharePoint'] = $true

$rawConn = @(Connect-NRGServices @connectParams)
$conn = $rawConn | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1
if (-not $conn) {
    $conn = [hashtable]@{
        Graph=$false; EXO=$false; IPPSSession=$false
        Teams=$false; SharePoint=$false; TenantDomain=$null; TenantId=$null
    }
}
if (-not $conn.ContainsKey('SharePoint')) { $conn['SharePoint'] = $false }

if ($WhatIfConnections) {
    Write-Host ""
    Write-Host "Connections (WhatIf mode, no collection):" -ForegroundColor Yellow
    $conn | Format-Table -AutoSize
    return
}

# ── Run collectors ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Running collectors..." -ForegroundColor Cyan

if ($conn.Graph) {
    Write-Host "  [*] AAD: Auth + authorization policies..."
    [void](Invoke-NRGCollectAADAuthPolicies)

    Write-Host "  [*] AAD: Conditional Access policies..."
    [void](Invoke-NRGCollectAADCAPolicies)

    Write-Host "  [*] AAD: Users and MFA registration state..."
    [void](Invoke-NRGCollectAADUsers)

    Write-Host "  [*] AAD: Directory role assignments..."
    [void](Invoke-NRGCollectAADRoles)

    Write-Host "  [*] AAD: PIM eligible and active schedules..."
    [void](Invoke-NRGCollectAADPIM)

    if (-not $SkipSharePoint) {
        Write-Host "  [*] SharePoint: Tenant settings via Graph..."
        [void](Invoke-NRGCollectSharePoint)
    }

    if (-not $SkipIntune) {
        Write-Host "  [*] Intune: Device compliance, MAM, MTD, enrollment..."
        [void](Invoke-NRGCollectIntune)
    }

    if (-not $SkipPowerPlatform) {
        Write-Host "  [*] Power Platform: Environments, tenant isolation, DLP..."
        [void](Invoke-NRGCollectPowerPlatform)
    }
}

if ($conn.EXO) {
    Write-Host "  [*] EXO: Mailbox configuration..."
    [void](Invoke-NRGCollectEXOMailboxConfig)

    Write-Host "  [*] Defender: Safe Attachments, Safe Links, Anti-phishing..."
    [void](Invoke-NRGCollectDefender)

    if (-not $SkipDNS) {
        Write-Host "  [*] DNS: SPF/DKIM/DMARC/MTA-STS for accepted domains..."
        if ($DnsDomains) {
            [void](Invoke-NRGCollectDNSEmailRecords -Domains $DnsDomains)
        } else {
            [void](Invoke-NRGCollectDNSEmailRecords)
        }
    }
}

if ($conn.Teams -and -not $SkipTeams) {
    Write-Host "  [*] Teams: Meeting, external access, client policies..."
    [void](Invoke-NRGCollectTeams)
}

if ($conn.IPPSSession -and -not $SkipPurview) {
    Write-Host "  [*] Purview: Audit, DLP, retention, sensitivity labels..."
    [void](Invoke-NRGCollectPurview)
}

# ── Run evaluators ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Running evaluators..." -ForegroundColor Cyan

# AAD
Test-NRGControlAADLegacyAuth
Test-NRGControlAADPhishResistantMFA
Test-NRGControlAADMFA
Test-NRGControlAADCA
Test-NRGControlAADPrivAccess

# EXO
Test-NRGControlEXOMailboxAudit
Test-NRGControlEXOSmtpAuth
Test-NRGControlEXOPop3
Test-NRGControlEXOImap
Test-NRGControlEXOCustomerLockbox
Test-NRGControlEXOSharedMailbox
Test-NRGControlEXOModernAuth

# DNS
Test-NRGControlDNSSPF
Test-NRGControlDNSDKIM
Test-NRGControlDNSDMARC
Test-NRGControlDNSMTASTS
Test-NRGControlDNSTLSRPT
Test-NRGControlDNSDNSSEC

# Defender
Test-NRGControlDefender

# Sessions 5+6
if (-not $SkipSharePoint)    { Test-NRGControlSharePoint }
if (-not $SkipTeams)         { Test-NRGControlTeams }
if (-not $SkipPurview)       { Test-NRGControlPurview }
if (-not $SkipIntune)        { Test-NRGControlIntune }
if (-not $SkipPowerPlatform) { Test-NRGControlPowerPlatform }

$findings = Get-NRGFindings
Write-Host "  [+] $($findings.Count) findings evaluated" -ForegroundColor Green

# ── Publish reports ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Generating reports..." -ForegroundColor Cyan

$timestamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
$tenantTag = if ($conn.TenantDomain) { ($conn.TenantDomain -split '\.')[0] } else { 'tenant' }
$baseName  = "$tenantTag-$timestamp"

$reportMetadata = @{
    TenantDomain   = $conn.TenantDomain
    TenantId       = $conn.TenantId
    Operator       = $UserPrincipalName
    AssessmentDate = (Get-Date).ToString('MMMM dd, yyyy')
    AssessmentTime = (Get-Date).ToString('o')
    ToolVersion    = $script:NRGAssessmentVersion
    Brand          = $script:NRGBrand
}

if ($JsonOnly) {
    $jsonPath = Join-Path $OutputPath "$baseName-results.json"
    @{
        Metadata    = $reportMetadata
        Findings    = $findings
        Exceptions  = (Get-NRGExceptions)
        Coverage    = (Get-NRGCoverage)
        Connections = $conn
    } | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
    Write-Host "  [+] JSON results: $jsonPath" -ForegroundColor Green
} else {
    $mdPath = Join-Path $OutputPath "$baseName-assessment.md"
    Publish-NRGAssessmentSummary -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $mdPath
    Write-Host "  [+] Markdown:     $mdPath" -ForegroundColor Green

    $htmlPath = Join-Path $OutputPath "$baseName-assessment.html"
    Publish-NRGAssessmentHTML -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $htmlPath
    Write-Host "  [+] HTML:         $htmlPath" -ForegroundColor Green

    $jsonPath = Join-Path $OutputPath "$baseName-results.json"
    @{
        Metadata    = $reportMetadata
        Findings    = $findings
        Exceptions  = (Get-NRGExceptions)
        Coverage    = (Get-NRGCoverage)
        Connections = $conn
    } | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
    Write-Host "  [+] JSON:         $jsonPath" -ForegroundColor Green
}

# ── Summary ──────────────────────────────────────────────────────────────────
$s = @{
    Satisfied = @($findings | Where-Object State -eq 'Satisfied').Count
    Partial   = @($findings | Where-Object State -eq 'Partial').Count
    Gap       = @($findings | Where-Object State -eq 'Gap').Count
    NA        = @($findings | Where-Object State -eq 'NotApplicable').Count
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Assessment Complete  (v4.5.0 / 70 controls)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Satisfied        $($s.Satisfied)" -ForegroundColor Green
Write-Host "  Partial          $($s.Partial)" -ForegroundColor Yellow
Write-Host "  Gap              $($s.Gap)" -ForegroundColor Red
Write-Host "  Not Applicable   $($s.NA)" -ForegroundColor DarkGray
Write-Host "  Total            $($findings.Count)" -ForegroundColor White
Write-Host "  Output           $OutputPath" -ForegroundColor White
Write-Host ""

# ── Disconnect ───────────────────────────────────────────────────────────────
Disconnect-NRGServices
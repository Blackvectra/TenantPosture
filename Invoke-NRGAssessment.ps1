#
# Invoke-NRGAssessment.ps1
# Entry point for NRG-Assessment v4.
#
# Flow:
#   1. Import module (which loads Lib, Collectors, Evaluators, Publishers)
#   2. Connect to M365 services (device code)
#   3. Run collectors -> raw data stored in module state
#   4. Run evaluators -> findings registered via Add-NRGFinding
#   5. Run publishers -> reports written to output/
#
# Example:
#   pwsh -ExecutionPolicy RemoteSigned -File .\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com
#

[CmdletBinding()]
param(
    [string]   $UserPrincipalName,
    [string]   $OutputPath,
    [switch]   $SkipPurview,
    [switch]   $SkipTeams,
    [switch]   $SkipSharePoint,
    [switch]   $SkipDNS,
    [string[]] $DnsDomains,
    [switch]   $JsonOnly,
    [switch]   $WhatIfConnections
)

$ErrorActionPreference = 'Stop'
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ── Banner ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " NRG-Assessment v4.0.0 - Read-Only M365 Security Assessment" -ForegroundColor Cyan
Write-Host " NRG Technology Services" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ── Output path ─────────────────────────────────────────────────────────────
if (-not $OutputPath) {
    $OutputPath = Join-Path $scriptDir 'output'
}
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# ── Import module ───────────────────────────────────────────────────────────
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

# ── Connect to services ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Establishing service connections (device code)..." -ForegroundColor Cyan
$connectParams = @{}
if ($UserPrincipalName) { $connectParams['UserPrincipalName'] = $UserPrincipalName }
if ($SkipPurview)       { $connectParams['SkipPurview']       = $true }
if ($SkipTeams)         { $connectParams['SkipTeams']         = $true }
if ($SkipSharePoint)    { $connectParams['SkipSharePoint']    = $true }

# Always defer SharePoint - PnP loads old Graph.Core that breaks Graph cmdlets if connected first
$connectParams['SkipSharePoint'] = $true

$rawConn = @(Connect-NRGServices @connectParams)
$conn = $rawConn | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1
if (-not $conn) {
    $conn = [hashtable]@{ Graph=$false; EXO=$false; IPPSSession=$false; Teams=$false; SharePoint=$false; TenantDomain=$null; TenantId=$null }
}
if (-not $conn.ContainsKey('SharePoint')) { $conn['SharePoint'] = $false }

if ($WhatIfConnections) {
    Write-Host ""
    Write-Host "Connections (WhatIf mode, no collection):" -ForegroundColor Yellow
    $conn | Format-Table -AutoSize
    return
}

# ── Run collectors ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Running collectors..." -ForegroundColor Cyan

if ($conn.Graph) {
    Write-Host "  [*] AAD: Authorization + auth method policies..."
    [void](Invoke-NRGCollectAADAuthPolicies)

    Write-Host "  [*] AAD: Conditional Access policies..."
    [void](Invoke-NRGCollectAADCAPolicies)

    Write-Host "  [*] AAD: Users and MFA registration state..."
    [void](Invoke-NRGCollectAADUsers)

    Write-Host "  [*] AAD: Directory role assignments..."
    [void](Invoke-NRGCollectAADRoles)

    Write-Host "  [*] AAD: PIM eligible and active schedules (P2)..."
    [void](Invoke-NRGCollectAADPIM)
}

if ($conn.EXO) {
    Write-Host "  [*] EXO: Mailbox configuration..."
    [void](Invoke-NRGCollectEXOMailboxConfig)

    if (-not $SkipDNS) {
        Write-Host "  [*] DNS: SPF/DKIM/DMARC/MTA-STS for accepted domains..."
        if ($DnsDomains) {
            [void](Invoke-NRGCollectDNSEmailRecords -Domains $DnsDomains)
        } else {
            [void](Invoke-NRGCollectDNSEmailRecords)
        }
    }
}

# ── SharePoint connection (after Graph collectors to avoid assembly conflict) ─
if (-not $SkipSharePoint -and $conn['TenantDomain']) {
    Write-Host "  [*] SharePoint Online (post-collection to avoid Graph assembly conflict)..." -ForegroundColor Cyan
    try {
        if (Get-Module -ListAvailable -Name PnP.PowerShell -ErrorAction SilentlyContinue) {
            Import-Module PnP.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
            $prefix = ($conn['TenantDomain'] -split '\.')[0]
            $spoUrl = "https://$prefix-admin.sharepoint.com"
            Write-Host "  [*] SharePoint: $spoUrl" -ForegroundColor Cyan
            Write-Host "  Open: https://microsoft.com/devicelogin and enter the code below" -ForegroundColor Yellow
            Connect-PnPOnline -Url $spoUrl -DeviceLogin -ErrorAction Stop | Out-Null
            $conn['SharePoint'] = $true
            Write-Host "  [+] SharePoint connected" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] SharePoint: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ── Run evaluators ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Running evaluators..." -ForegroundColor Cyan

Test-NRGControlAADLegacyAuth
Test-NRGControlAADPhishResistantMFA
Test-NRGControlAADMFA
Test-NRGControlAADCA
Test-NRGControlAADPrivAccess
Test-NRGControlEXOMailboxAudit
Test-NRGControlEXOSmtpAuth
Test-NRGControlDNSSPF
Test-NRGControlDNSDKIM
Test-NRGControlDNSDMARC

$findings = Get-NRGFindings

Write-Host "  [+] $($findings.Count) findings evaluated" -ForegroundColor Green

# ── Publish reports ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Generating reports..." -ForegroundColor Cyan

$timestamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
$tenantTag = if ($conn.TenantDomain) { ($conn.TenantDomain -split '\.')[0] } else { 'tenant' }
$baseName  = "$tenantTag-$timestamp"

$reportMetadata = @{
    TenantDomain     = $conn.TenantDomain
    TenantId         = $conn.TenantId
    Operator         = $UserPrincipalName
    AssessmentDate   = (Get-Date).ToString('MMMM dd, yyyy')
    AssessmentTime   = (Get-Date).ToString('o')
    ToolVersion      = $script:NRGAssessmentVersion
    Brand            = $script:NRGBrand
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
    # Markdown summary report
    $mdPath = Join-Path $OutputPath "$baseName-assessment.md"
    Publish-NRGAssessmentSummary -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $mdPath

    # JSON for downstream tooling
    $jsonPath = Join-Path $OutputPath "$baseName-results.json"
    @{
        Metadata    = $reportMetadata
        Findings    = $findings
        Exceptions  = (Get-NRGExceptions)
        Coverage    = (Get-NRGCoverage)
        Connections = $conn
    } | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8
    Write-Host "  [+] Markdown: $mdPath" -ForegroundColor Green
    Write-Host "  [+] JSON:     $jsonPath" -ForegroundColor Green
}

# ── Summary ─────────────────────────────────────────────────────────────────
$s = @{
    Satisfied = @($findings | Where-Object State -eq 'Satisfied').Count
    Partial   = @($findings | Where-Object State -eq 'Partial').Count
    Gap       = @($findings | Where-Object State -eq 'Gap').Count
    NA        = @($findings | Where-Object State -eq 'NotApplicable').Count
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Assessment Complete" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Satisfied        $($s.Satisfied)" -ForegroundColor Green
Write-Host "  Partial          $($s.Partial)" -ForegroundColor Yellow
Write-Host "  Gap              $($s.Gap)" -ForegroundColor Red
Write-Host "  Not Applicable   $($s.NA)" -ForegroundColor DarkGray
Write-Host "  Total            $($findings.Count)" -ForegroundColor White
Write-Host "  Output           $OutputPath" -ForegroundColor White
Write-Host ""

# ── Disconnect ──────────────────────────────────────────────────────────────
Disconnect-NRGServices

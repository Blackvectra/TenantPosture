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

$conn = Connect-NRGServices @connectParams

# Ensure all keys exist even if connection was skipped
foreach ($svc in @('Graph','EXO','IPPSSession','Teams','SharePoint','TenantDomain','TenantId')) {
    if (-not $conn.ContainsKey($svc)) { $conn[$svc] = $null }
}

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
    [void](Get-NRGCollector-AAD-AuthPolicies)

    Write-Host "  [*] AAD: Conditional Access policies..."
    [void](Get-NRGCollector-AAD-CAPolicies)
}

if ($conn.EXO) {
    Write-Host "  [*] EXO: Mailbox configuration..."
    [void](Get-NRGCollector-EXO-MailboxConfig)

    if (-not $SkipDNS) {
        Write-Host "  [*] DNS: SPF/DKIM/DMARC/MTA-STS for accepted domains..."
        if ($DnsDomains) {
            [void](Get-NRGCollector-DNS-EmailRecords -Domains $DnsDomains)
        } else {
            [void](Get-NRGCollector-DNS-EmailRecords)
        }
    }
}

# ── Run evaluators ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Running evaluators..." -ForegroundColor Cyan

Test-NRGControl-AAD-LegacyAuth
Test-NRGControl-AAD-PhishResistantMFA
Test-NRGControl-EXO-MailboxAudit
Test-NRGControl-EXO-SmtpAuth
Test-NRGControl-DNS-SPF
Test-NRGControl-DNS-DKIM
Test-NRGControl-DNS-DMARC

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

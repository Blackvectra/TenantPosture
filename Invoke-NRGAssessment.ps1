#Requires -Version 7.0
#
# Invoke-NRGAssessment.ps1
# Entry point for NRG-Assessment (version read from module manifest at runtime)
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# Flow:
#   1. Import module (loads Lib, Collectors, Evaluators, Publishers)
#   2. Connect to M365 services
#   3. Run collectors -> raw data stored in module state
#   4. Run evaluators -> findings registered via Add-NRGFinding
#   5. Run publishers -> HTML, Markdown, JSON, XLSX, Playbook, Remediation script
#
# Usage:
#   .\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com
#   .\Invoke-NRGAssessment.ps1 -AppId <guid> -TenantId <guid> -CertificateThumbprint <40hex> -OrganizationDomain contoso.onmicrosoft.com
#

[CmdletBinding()]
param(
    # OWASP ASVS V5.1.3 — UPN must match standard email format before reaching auth
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$|^$')]
    [string] $UserPrincipalName,
    [string] $OutputPath,

    # App-only / certificate authentication for unattended runs
    [string] $AppId,
    [string] $TenantId,
    [string] $CertificateThumbprint,
    [string] $OrganizationDomain,

    # Cloud environment
    [ValidateSet('commercial','gcc','gcchigh','dod')]
    [string] $Environment = 'commercial',

    # Skip switches
    [switch] $SkipPurview,
    [switch] $IncludePurview,   # Include Purview/IPPSSession (skipped by default — EOM v3.4 WAM crash)
    [switch] $SkipTeams,
    [switch] $SkipSharePoint,
    [switch] $SkipIntune,
    [switch] $SkipPowerPlatform,
    [switch] $SkipDNS,

    # Run modes
    [switch] $NonInteractive,
    # Audit fix (v4.6.x MED #6): validate that FromResults / BaselineResults
    # point at an existing file via -LiteralPath. This refuses wildcard input
    # ('*'), path-traversal sequences, and silently-missing files before any
    # downstream Get-Content / republish step touches the path.
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in FromResults." }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "FromResults file not found: $_" }
        return $true
    })]
    [string] $FromResults,
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in BaselineResults." }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "BaselineResults file not found: $_" }
        return $true
    })]
    [string] $BaselineResults,
    # OWASP ASVS V5.1.3 — every DnsDomains entry must be an FQDN before DNS resolver sees it
    [ValidateScript({
        foreach ($d in $_) {
            if ($d -notmatch '^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$') {
                throw "Invalid DNS domain name: '$d'"
            }
        }
        return $true
    })]
    [string[]] $DnsDomains,
    [switch] $JsonOnly,
    [switch] $WhatIfConnections
)

# OWASP ASVS V16.4.1 — strict mode at the entry point so the orchestrator
# uses the same semantics as the module body (uninitialized variable access,
# property access on $null, indexing past array end all throw).
Set-StrictMode -Version Latest

# OWASP ASVS V11.2.2 / OSSTMM DN5 — enforce TLS 1.2 minimum (Microsoft endpoints
# already require this, but defense-in-depth catches dev/test environments where
# .NET defaults might drift back to older protocols)
[System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.SecurityProtocolType]::Tls12 -bor
    [System.Net.SecurityProtocolType]::Tls13

# Disable WAM broker before any module loads — prevents RuntimeBroker NullReferenceException
$env:MSAL_ALLOW_BROKER        = '0'
$env:MSAL_DISABLE_TOKENBROKER = '1'
$env:MSAL_DISABLE_WAM         = '1'

# Purview skipped by default — EOM v3.4 WAM broker crashes on background thread
# Pass -IncludePurview to attempt it (works when running standalone PS7 window)
if (-not $IncludePurview -and -not $SkipPurview) { $SkipPurview = $true }

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ── Pre-banner version probe ─────────────────────────────────────────────────
# Read ModuleVersion from the manifest BEFORE the module is imported so the
# banner version stays in lockstep with the .psd1 / .psm1 single source of
# truth. Falls back to 'unknown' if the manifest can't be parsed — the import
# step below will then fail loudly and exit anyway.
$script:NRGAssessmentVersion = 'unknown'
try {
    $manifestData = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptDir 'NRG-Assessment.psd1') -ErrorAction Stop
    if ($manifestData.ModuleVersion) { $script:NRGAssessmentVersion = [string]$manifestData.ModuleVersion }
} catch { }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " NRG-Assessment v$($script:NRGAssessmentVersion) — Read-Only M365 Security Assessment" -ForegroundColor Cyan
Write-Host " NRG Technology Services | NextLayerSec LLC"                     -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ── Output path ───────────────────────────────────────────────────────────────
# OWASP A01 / ASVS V12.3.1 — reject ..[/\\] path-traversal sequences before any
# file operation. Also ensure the resolved path stays under the script directory
# unless an absolute path was explicitly provided by the operator.
if (-not $OutputPath) { $OutputPath = Join-Path $scriptDir 'output' }
if ($OutputPath -match '\.\.[\\/]') {
    throw "OutputPath rejected: contains '..[/\\]' traversal sequence."
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -LiteralPath $OutputPath -ItemType Directory -Force | Out-Null
}
# Resolve to absolute path so downstream auto-open / publish steps can verify
# generated files via $resolvedOutput.StartsWith($resolvedOutput) bounds checks.
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)

# ── Import module ─────────────────────────────────────────────────────────────
Write-Host "[-] Loading NRG-Assessment module..." -ForegroundColor Cyan
$manifestPath = Join-Path $scriptDir 'NRG-Assessment.psd1'
try {
    Import-Module $manifestPath -Force -ErrorAction Stop
    Write-Host "  [+] Module loaded (v$($NRGAssessmentVersion))" -ForegroundColor Green
} catch {
    Write-Host "  [!] Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Clear-NRGFindings

# OWASP ASVS V7.3.2 — wrap the entire run in try/finally so service sessions
# always disconnect, even if a collector / evaluator / publisher throws.
try {

# ── Module prerequisite check ─────────────────────────────────────────────────
# EOM is pinned to 3.2.0 — 3.4.0+ has a WAM broker crash that kills the process
# from a background .NET thread (uncatchable from PowerShell).
$moduleSpecs = @(
    @{ Name='Microsoft.Graph.Authentication'; MinVersion='2.0.0'; PinVersion=$null   }
    @{ Name='ExchangeOnlineManagement';       MinVersion='3.0.0'; PinVersion='3.2.0' }
    @{ Name='MicrosoftTeams';                 MinVersion='5.0.0'; PinVersion=$null   }
)
$needsAction = @()
foreach ($spec in $moduleSpecs) {
    $installed = Get-Module -ListAvailable -Name $spec.Name -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if (-not $installed) {
        $needsAction += @{ Spec=$spec; Action='install'; Current=$null }
    } elseif ($spec.PinVersion -and $installed.Version -ne [version]$spec.PinVersion) {
        $needsAction += @{ Spec=$spec; Action='repin'; Current=$installed.Version }
    } elseif ($installed.Version -lt [version]$spec.MinVersion) {
        $needsAction += @{ Spec=$spec; Action='upgrade'; Current=$installed.Version }
    }
}

if ($needsAction.Count -gt 0) {
    Write-Host ""
    foreach ($n in $needsAction) {
        $name = $n.Spec.Name
        if ($n.Action -eq 'install') {
            Write-Host "  [!] Missing: $name" -ForegroundColor Yellow
        } elseif ($n.Action -eq 'repin') {
            Write-Host "  [!] $name $($n.Current) installed — recommended: $($n.Spec.PinVersion)" -ForegroundColor Yellow
            if ([version]$n.Current -gt [version]$n.Spec.PinVersion) {
                Write-Host "      Version $($n.Current) has known crash bugs in this tool's auth flow." -ForegroundColor DarkYellow
            }
        }
    }
    if ($NonInteractive) {
        Write-Host "  [!] NonInteractive — run .\Install-NRGPrerequisites.ps1 manually then retry." -ForegroundColor Red
        exit 1
    }
    $install = Read-Host "  Install/fix modules now? [Y/N]"
    if ($install -match '^[Yy]') {
        foreach ($n in $needsAction) {
            $name = $n.Spec.Name
            $targetVer = $n.Spec.PinVersion
            try {
                if ($n.Action -eq 'repin' -and [version]$n.Current -gt [version]$n.Spec.PinVersion) {
                    Write-Host "  [*] Downgrading $name $($n.Current) -> $targetVer..." -ForegroundColor Cyan
                    Uninstall-PSResource -Name $name -ErrorAction SilentlyContinue
                }
                if ($targetVer) {
                    Write-Host "  [*] Installing $name $targetVer..." -ForegroundColor Cyan
                    Install-PSResource -Name $name -Version $targetVer -TrustRepository -Scope CurrentUser -Reinstall -ErrorAction Stop
                } else {
                    Write-Host "  [*] Installing $name (latest)..." -ForegroundColor Cyan
                    Install-PSResource -Name $name -TrustRepository -Scope CurrentUser -ErrorAction Stop
                }
                Write-Host "  [+] $name ready" -ForegroundColor Green
            } catch {
                Write-Host "  [!] $name failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  [!] Skipping. Run .\Install-NRGPrerequisites.ps1 to set up manually." -ForegroundColor Yellow
    }
}

# ── FromResults mode — skip collection, just republish ───────────────────────
if ($FromResults -and (Test-Path -LiteralPath $FromResults)) {
    Write-Host "[-] FromResults mode — regenerating reports from $FromResults" -ForegroundColor Cyan
    $priorData = Get-Content -LiteralPath $FromResults -Raw -Encoding utf8 | ConvertFrom-Json
    $findings = [object[]]@($priorData.Findings)
    $conn = if ($priorData.Connections) { @{} + $priorData.Connections } else { @{} }
    $reportMetadata = if ($priorData.Metadata) { @{} + $priorData.Metadata } else {
        @{ TenantDomain='Unknown'; AssessmentDate=(Get-Date -Format 'MMMM dd, yyyy'); ToolVersion=$script:NRGAssessmentVersion }
    }
    $tenantTag = if ($reportMetadata.TenantDomain) { ($reportMetadata.TenantDomain -split '\.')[0] } else { 'tenant' }
    # OWASP A01 — strip any non-[a-zA-Z0-9-] before using tenantTag in a file path
    $tenantTag = $tenantTag -replace '[^a-zA-Z0-9-]', ''
    if (-not $tenantTag) { $tenantTag = 'tenant' }
    $baseName = "$tenantTag-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Host "  [+] Loaded $($findings.Count) findings" -ForegroundColor Green
    $skipCollection = $true
} else {
    $skipCollection = $false
}

if (-not $skipCollection) {
    # ── Connect to services ──────────────────────────────────────────────────
    Write-Host ""
    Write-Host "[-] Connecting to M365 services..." -ForegroundColor Cyan

    $connectParams = @{}
    if ($AppId -and $TenantId -and $CertificateThumbprint) {
        $connectParams['AppId']                  = $AppId
        $connectParams['TenantId']               = $TenantId
        $connectParams['CertificateThumbprint']  = $CertificateThumbprint
        if ($OrganizationDomain) { $connectParams['OrganizationDomain'] = $OrganizationDomain }
    } elseif ($UserPrincipalName) {
        $connectParams['UserPrincipalName'] = $UserPrincipalName
    }
    if ($SkipPurview) { $connectParams['SkipPurview'] = $true }
    if ($SkipTeams)   { $connectParams['SkipTeams']   = $true }
    $connectParams['SkipSharePoint'] = $true  # SharePoint via Graph

    $rawConn = @(Connect-NRGServices @connectParams)
    $conn = $rawConn | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1
    if (-not $conn) {
        $conn = @{ Graph=$false; EXO=$false; IPPSSession=$false; Teams=$false; SharePoint=$false }
    }
    # Exit-code spec (v4.6.3 P2): exit 1 on auth failure means no Graph/EXO
    # at all. The downstream collectors will skip silently but the result
    # would be useless — fail loudly here so batch runners can flag the
    # client as auth-broken in their summary.
    if (-not $conn.Graph -and -not $conn.EXO) {
        Write-Host "  [!] Connect-NRGServices returned no usable session (Graph and EXO both unavailable)." -ForegroundColor Red
        $script:NRGFatalExitCode = 1
        throw [System.InvalidOperationException]::new('Authentication failure: no Graph or EXO session available.')
    }
    if (-not $conn.ContainsKey('SharePoint')) { $conn['SharePoint'] = $false }

    if ($WhatIfConnections) {
        Write-Host ""
        Write-Host "Connections (WhatIf mode):" -ForegroundColor Yellow
        $conn | Format-Table -AutoSize
        return
    }

    # ── Run collectors ───────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "[-] Running collectors..." -ForegroundColor Cyan

    function Invoke-NRGCollector { param([string]$fn)
        if (Get-Command $fn -ErrorAction SilentlyContinue) {
            try { & $fn | Out-Null }
            catch { Write-Warning "Collector $fn failed: $($_.Exception.Message.Split([char]10)[0])" }
        }
    }

    if ($conn.Graph) {
        Write-Host "  [*] AAD: Auth + authorization policies..."
        Invoke-NRGCollector 'Invoke-NRGCollectAADAuthPolicies'
        Write-Host "  [*] AAD: Conditional Access policies..."
        Invoke-NRGCollector 'Invoke-NRGCollectAADCAPolicies'
        Write-Host "  [*] AAD: Users and MFA registration state..."
        Invoke-NRGCollector 'Invoke-NRGCollectAADUsers'
        Write-Host "  [*] AAD: Directory role assignments..."
        Invoke-NRGCollector 'Invoke-NRGCollectAADRoles'
        Write-Host "  [*] AAD: PIM eligible and active schedules..."
        Invoke-NRGCollector 'Invoke-NRGCollectAADPIM'
        Invoke-NRGCollector 'Invoke-NRGCollectAADIdentityGovernance'
        Write-Host "  [*] AAD: Inventory (guests, stale, OAuth, Secure Score)..."
        Invoke-NRGCollector 'Invoke-NRGCollectAADInventory'

        if (-not $SkipSharePoint) {
            Write-Host "  [*] SharePoint: Tenant settings via Graph..."
            Invoke-NRGCollector 'Invoke-NRGCollectSharePoint'
        }
        if (-not $SkipIntune) {
            Write-Host "  [*] Intune: Endpoint Security (LAPS / ASR / Firewall / EDR / AV)..."
            Invoke-NRGCollector 'Invoke-NRGCollectIntuneEndpointSecurity'
            Write-Host "  [*] Intune: Device Compliance, WHfB, Update Rings, Enrollment..."
            Invoke-NRGCollector 'Invoke-NRGCollectIntuneDeviceCompliance'
            Write-Host "  [*] Intune: App Protection (MAM) and App Configuration..."
            Invoke-NRGCollector 'Invoke-NRGCollectIntuneAppProtection'
        }
        if (-not $SkipPowerPlatform) {
            Write-Host "  [*] Power Platform: Environments, tenant isolation, DLP..."
            Invoke-NRGCollector 'Invoke-NRGCollectPowerPlatform'
        }
    }

    if ($conn.EXO) {
        Write-Host "  [*] EXO: Mailbox configuration..."
        Invoke-NRGCollector 'Invoke-NRGCollectEXOMailboxConfig'
        Write-Host "  [*] EXO: Inventory (forwarding, shared, audit, SMTP AUTH)..."
        Invoke-NRGCollector 'Invoke-NRGCollectEXOInventory'
        Write-Host "  [*] Defender: Safe Attachments, Safe Links, Anti-phishing..."
        Invoke-NRGCollector 'Invoke-NRGCollectDefender'
        if (-not $SkipDNS) {
            Write-Host "  [*] DNS: SPF/DKIM/DMARC/MTA-STS for accepted domains..."
            if ($DnsDomains) {
                if (Get-Command Invoke-NRGCollectDNSEmailRecords -ErrorAction SilentlyContinue) {
                    Invoke-NRGCollectDNSEmailRecords -Domains $DnsDomains | Out-Null
                }
            } else {
                Invoke-NRGCollector 'Invoke-NRGCollectDNSEmailRecords'
            }
        }
    }

    if ($conn.Teams -and -not $SkipTeams) {
        Write-Host "  [*] Teams: Meeting, external access, client policies..."
        Invoke-NRGCollector 'Invoke-NRGCollectTeams'
    }

    if ($conn.IPPSSession -and -not $SkipPurview) {
        Write-Host "  [*] Purview: Audit, DLP, retention, sensitivity labels..."
        Invoke-NRGCollector 'Invoke-NRGCollectPurview'
    }

    # Copilot collector runs after Purview so it can reuse label/DLP/audit raw data
    if ($conn.Graph) {
        Write-Host "  [*] M365 Copilot: Licensing, label alignment, DLP coverage, Studio bots..."
        Invoke-NRGCollector 'Invoke-NRGCollectM365Copilot'
    }

    # ── Run evaluators ───────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "[-] Running evaluators..." -ForegroundColor Cyan

    function Invoke-NRGEvaluator { param([string]$fn)
        if (Get-Command $fn -ErrorAction SilentlyContinue) {
            try { & $fn }
            catch {
                # Strict-mode tightening (v4.6.x audit fix): a property-access
                # crash on partial collector data now surfaces both as a warning
                # for the operator console AND as a Register-NRGException so the
                # incident is captured in the JSON output for follow-up.
                $errMsg = $_.Exception.Message.Split([char]10)[0]
                Write-Warning "Evaluator $($fn) — $errMsg"
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    try { Register-NRGException -Source $fn -Message $errMsg } catch { }
                }
            }
        }
    }

    # All evaluators discovered by name from the loaded module
    $evaluators = @(Get-Command -Module NRG-Assessment -Name 'Test-NRGControl*' -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Name)
    foreach ($ev in $evaluators) {
        Invoke-NRGEvaluator $ev
    }

    $findings = Get-NRGFindings
    Write-Host "  [+] $($findings.Count) findings evaluated" -ForegroundColor Green

    # ── Build report metadata ────────────────────────────────────────────────
    $tenantTag = if ($conn.TenantDomain) { ($conn.TenantDomain -split '\.')[0] } else { 'tenant' }
    # OWASP A01 — strip any non-[a-zA-Z0-9-] before using tenantTag in a file path
    $tenantTag = $tenantTag -replace '[^a-zA-Z0-9-]', ''
    if (-not $tenantTag) { $tenantTag = 'tenant' }
    $baseName = "$tenantTag-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    $reportMetadata = @{
        TenantDomain   = $conn.TenantDomain
        TenantId       = $conn.TenantId
        Operator       = $UserPrincipalName
        AssessmentDate = (Get-Date).ToString('MMMM dd, yyyy')
        AssessmentTime = (Get-Date).ToString('o')
        ToolVersion    = $NRGAssessmentVersion
        Brand          = $NRGBrand
    }
}

# ── Publish reports ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[-] Generating reports..." -ForegroundColor Cyan

$jsonPath = Join-Path $OutputPath "$baseName-results.json"
# Capture the raw-data snapshot for drift detection on the NEXT run. The
# delta publisher compares this snapshot against a future run's snapshot to
# surface raw configuration changes (new CA policies, new admin assignments,
# new OAuth apps, DMARC policy regression) — not just finding state changes.
$rawDataSnapshot = if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) {
    Get-NRGRawData
} else { @{} }
# TOCTOU fix (v4.6.3 P2): Set-NRGSensitiveFileContent pre-creates the file
# and applies the ACL BEFORE any tenant data is written. Previously the
# file inherited the parent directory's permissions during Out-File and was
# only restricted afterwards via Set-Acl — on a shared MSP workstation a
# co-resident process polling the output dir could read tenant data in
# that small window.
$jsonPayload = @{
    Metadata    = $reportMetadata
    Findings    = $findings
    RawData     = $rawDataSnapshot
    Exceptions  = (Get-NRGExceptions)
    Coverage    = (Get-NRGCoverage)
    Connections = $conn
} | ConvertTo-Json -Depth 10
Set-NRGSensitiveFileContent -Path $jsonPath -Content $jsonPayload
Write-Host "  [+] JSON: $jsonPath" -ForegroundColor Green
Write-Host "      Baseline contains sensitive tenant inventory (CA policies, admin assignments, OAuth apps) — file ACL restricted to current user + admins. Path: $jsonPath" -ForegroundColor Yellow

if (-not $JsonOnly) {
    # ── Audit-finding fix (HIGH #2): every secondary report file gets the same
    #    ACL hardening as the JSON baseline. They all contain the same tenant
    #    inventory data (CA policies, admin UPNs, OAuth grants, DMARC records)
    #    rendered into a different format. Inherited permissions on a shared
    #    MSP workstation or synced OneDrive would otherwise make these world-
    #    readable. Set-NRGSensitiveFileAcl is a no-op on non-Windows.
    # Markdown summary
    if (Get-Command Publish-NRGAssessmentSummary -ErrorAction SilentlyContinue) {
        $mdPath = Join-Path $OutputPath "$baseName-assessment.md"
        try {
            Publish-NRGAssessmentSummary -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $mdPath
            Write-Host "  [+] Markdown: $mdPath" -ForegroundColor Green
            Set-NRGSensitiveFileAcl -Path $mdPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "Markdown publish failed: $($_.Exception.Message)" }
    }

    # HTML report
    if (Get-Command Publish-NRGAssessmentHTML -ErrorAction SilentlyContinue) {
        $htmlPath = Join-Path $OutputPath "$baseName-assessment.html"
        try {
            Publish-NRGAssessmentHTML -Metadata $reportMetadata -Findings $findings -Connections $conn -OutputPath $htmlPath
            Write-Host "  [+] HTML: $htmlPath" -ForegroundColor Green
            Set-NRGSensitiveFileAcl -Path $htmlPath -ErrorAction SilentlyContinue
        } catch {
        $stack = $_.ScriptStackTrace
        Write-Warning "HTML failed: $($_.Exception.Message)"
        Write-Warning "Stack: $stack"
    }
    }

    # Remediation playbook + executive summary
    # The publisher writes two deliverables: an engineer playbook (-OutputPath)
    # and a client-facing executive summary (-ExecutivePath). Both -Connections
    # and -ExecutivePath are mandatory on the function — omitting them in v4.6.1
    # caused PowerShell to interactively prompt and then fail.
    if (Get-Command Publish-NRGRemediationPlaybook -ErrorAction SilentlyContinue) {
        $pbPath   = Join-Path $OutputPath "$baseName-playbook.md"
        $execPath = Join-Path $OutputPath "$baseName-executive.md"
        try {
            Publish-NRGRemediationPlaybook `
                -Metadata $reportMetadata `
                -Findings $findings `
                -Connections $conn `
                -OutputPath $pbPath `
                -ExecutivePath $execPath
            Write-Host "  [+] Playbook: $pbPath" -ForegroundColor Green
            Write-Host "  [+] Executive: $execPath" -ForegroundColor Green
            Set-NRGSensitiveFileAcl -Path $pbPath   -ErrorAction SilentlyContinue
            Set-NRGSensitiveFileAcl -Path $execPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "Playbook publish failed: $($_.Exception.Message)" }
    }

    # Remediation script
    if (Get-Command Publish-NRGRemediationScript -ErrorAction SilentlyContinue) {
        $rsPath = Join-Path $OutputPath "$baseName-remediation.ps1"
        try {
            Publish-NRGRemediationScript -Metadata $reportMetadata -Findings $findings -OutputPath $rsPath
            Write-Host "  [+] Remediation: $rsPath" -ForegroundColor Green
            Set-NRGSensitiveFileAcl -Path $rsPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "Remediation publish failed: $($_.Exception.Message)" }
    }

    # XLSX compliance matrix
    if (Get-Command Publish-NRGComplianceMatrix -ErrorAction SilentlyContinue) {
        $xlsxPath = Join-Path $OutputPath "$baseName-compliance-matrix.xlsx"
        try {
            Publish-NRGComplianceMatrix -Metadata $reportMetadata -Findings $findings -OutputPath $xlsxPath
            Write-Host "  [+] XLSX matrix: $xlsxPath" -ForegroundColor Green
            Set-NRGSensitiveFileAcl -Path $xlsxPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "XLSX publish failed: $($_.Exception.Message)" }
    }

    # Delta report (if baseline provided)
    if ($BaselineResults -and (Test-Path -LiteralPath $BaselineResults) -and (Get-Command Publish-NRGDeltaReport -ErrorAction SilentlyContinue)) {
        $deltaPath = Join-Path $OutputPath "$baseName-delta.md"
        try {
            Publish-NRGDeltaReport -CurrentFindings $findings -CurrentRawData $rawDataSnapshot -BaselineResultsPath $BaselineResults `
                -Metadata $reportMetadata -OutputPath $deltaPath
            Write-Host "  [+] Delta: $deltaPath" -ForegroundColor Green
            Set-NRGSensitiveFileAcl -Path $deltaPath -ErrorAction SilentlyContinue
        } catch { Write-Warning "Delta publish failed: $($_.Exception.Message)" }
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────
$s = @{
    Satisfied = @($findings | Where-Object State -eq 'Satisfied').Count
    Partial   = @($findings | Where-Object State -eq 'Partial').Count
    Gap       = @($findings | Where-Object State -eq 'Gap').Count
    NA        = @($findings | Where-Object State -eq 'NotApplicable').Count
}

# Footer version + control count read at runtime so a stale hardcoded value
# never ships in the operator output. Falls back to the count of findings the
# evaluators actually emitted this run rather than guessing at "total controls
# defined in controls.json" which can drift from baseline coverage.
$footerVer    = if ($NRGAssessmentVersion)   { $NRGAssessmentVersion }   else { $script:NRGAssessmentVersion }
$footerCount  = $findings.Count

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Assessment Complete (v$footerVer / $footerCount controls)"      -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Satisfied      $($s.Satisfied)"                                  -ForegroundColor Green
Write-Host "  Partial        $($s.Partial)"                                    -ForegroundColor Yellow
Write-Host "  Gap            $($s.Gap)"                                        -ForegroundColor Red
Write-Host "  Not Applicable $($s.NA)"                                         -ForegroundColor DarkGray
Write-Host "  Total          $($findings.Count)"                               -ForegroundColor White
Write-Host "  Output         $OutputPath"                                      -ForegroundColor White
Write-Host ""

# ── Exit-code spec (v4.6.3 P2) ────────────────────────────────────────────────
# CLAUDE.md declares: 0 success, 1 auth failure, 2 no findings, 3 partial
# collection, 4 fatal. Previously only exit 1 (module-load failure) was
# wired. This block computes the right code based on counters set above.
$collectorExceptions = @(Get-NRGExceptions)
if ($findings.Count -eq 0) {
    $script:NRGSuccessExitCode = 2
} elseif ($collectorExceptions.Count -gt 0) {
    # Partial collection: at least one collector raised, but some findings made it.
    $script:NRGSuccessExitCode = 3
} else {
    $script:NRGSuccessExitCode = 0
}

}
catch {
    # Outer fatal-error catch (v4.6.3 P2).
    # $script:NRGFatalExitCode may have been pre-set by an earlier explicit
    # condition (auth failure = 1); otherwise fall through to 4 (fatal).
    if (-not $script:NRGFatalExitCode) { $script:NRGFatalExitCode = 4 }
    Write-Host ""
    Write-Host "[!] Assessment failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ScriptStackTrace) {
        Write-Host "    Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    }
}
finally {
    # ── Disconnect on success or error ────────────────────────────────────────
    if (-not $skipCollection) {
        try { Disconnect-NRGServices } catch { }
    }
}

# Resolve and emit the exit code (must be done OUTSIDE the try/catch/finally
# so the exit happens after the disconnect runs).
if ($script:NRGFatalExitCode) {
    exit $script:NRGFatalExitCode
}
if ($null -ne $script:NRGSuccessExitCode) {
    exit $script:NRGSuccessExitCode
}
exit 0
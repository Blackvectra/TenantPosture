#Requires -Version 7.0

<#
.SYNOPSIS
    Distribution-list scan: read every distribution list in a Microsoft 365 tenant and
    produce a plain worksheet that helps close each list's email exposure.

.DESCRIPTION
    Connects to Exchange Online ONLY (no Microsoft Graph, no Teams, no Purview), reads
    the tenant's distribution lists, mail-enabled security groups and dynamic
    distribution lists, and for each one records who can send to it, who owns it, who
    can join it and who is on it. It then writes a worksheet: a text file and a CSV, one
    row per list, with the finding, the recommended setting and, as TEXT, the commands
    an Exchange administrator would run to harden the list.

    READ-ONLY. This scan never creates, adds, removes or changes a list, a member or a
    setting. The commands in the worksheet are printed for a person to review and run;
    this tool never runs them.

    It assesses distribution lists and nothing else. Entra ID, Conditional Access,
    Defender, Teams, SharePoint, Intune, Purview and DNS are NOT assessed by this scan,
    and the output says so. Run Invoke-NRGAssessment.ps1 for the tenant assessment.

    Scope: classic distribution lists, mail-enabled security groups and dynamic
    distribution lists. Microsoft 365 Groups (including Teams-connected groups) are a
    different object with their own sender settings and are not covered.

.PARAMETER TenantDomain
    The tenant's primary domain (for example contoso.com). When given, the session is
    checked against that tenant and the scan stops, reading nothing, if the sign-in
    landed on a different one. For an MSP client under GDAP, the client's DelegatedOrg
    in Config/clients.json is used automatically.

.PARAMETER DelegatedOrganization
    The client's .onmicrosoft.com routing domain (GDAP). Overrides clients.json.

.PARAMETER UserPrincipalName
    Optional: the administrator's UPN, to pre-fill the sign-in.

.PARAMETER OutputPath
    Output directory. Defaults to .\output\. Files are named
    <tenant>-<yyyyMMdd-HHmmss>-distribution-lists.txt / .csv / -results.json.

.PARAMETER MemberLimit
    Members read per list (default 2000). A list larger than this is reported as
    truncated, never as complete.

.PARAMETER MemberReadListLimit
    Lists whose members are read (default 1000). Settings are read for every list.

.PARAMETER NoMembers
    Leave the member-by-member listing out of the text worksheet (counts, outside
    members and findings are still written).

.PARAMETER ReuseSession
    Use an Exchange Online session that is already open in this window, as it is.
    Without it, an open session stops the scan: one window, one tenant.

.EXAMPLE
    .\Invoke-NRGDistributionListScan.ps1

    Sign in as an Exchange administrator and scan the tenant the account belongs to.

.EXAMPLE
    .\Invoke-NRGDistributionListScan.ps1 -TenantDomain contoso.com

    Scan contoso.com (a GDAP client), refusing to continue if the sign-in is for any
    other tenant.

.OUTPUTS
    .\output\<tenant>-<timestamp>-distribution-lists.txt           the worksheet
    .\output\<tenant>-<timestamp>-distribution-lists.csv           one row per list
    .\output\<tenant>-<timestamp>-distribution-lists-results.json  findings and raw data

.NOTES
    NRG Technology Services / NextLayerSec LLC. Read-only: Get-* cmdlets only.
    The files hold the tenant's list inventory and member names, and are written with
    restricted permissions. INTERNAL USE.
    Exit codes: 0 complete | 1 auth failure or wrong tenant | 2 no lists returned |
                3 partial collection | 4 fatal error.
#>

[CmdletBinding()]
param(
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61})+$')]
    [string] $TenantDomain,

    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*\.onmicrosoft\.com$')]
    [string] $DelegatedOrganization,

    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
    [string] $UserPrincipalName,

    [string] $OutputPath,

    [ValidateRange(1, 100000)]
    [int] $MemberLimit = 2000,

    [ValidateRange(1, 100000)]
    [int] $MemberReadListLimit = 1000,

    [switch] $NoMembers,
    [switch] $ReuseSession
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:NRGDLFatalExitCode   = $null
$script:NRGDLSuccessExitCode = $null

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
if (-not $OutputPath) { $OutputPath = Join-Path $scriptDir 'output' }
if ($OutputPath -match '\.\.[\\/]') { throw "OutputPath rejected: contains '..[/\\]' traversal sequence." }
[void][System.IO.Directory]::CreateDirectory($OutputPath)

Write-Host ''
Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ' NRG Distribution List Scan'                                  -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
Write-Host '  This scan:' -ForegroundColor Yellow
Write-Host '    1. Signs in to Exchange Online ONLY (no Microsoft Graph, no other service)' -ForegroundColor Yellow
Write-Host '    2. READS distribution lists, mail-enabled security groups and dynamic lists:' -ForegroundColor Yellow
Write-Host '       who can send to each, its owners, who can join, and its members' -ForegroundColor Yellow
Write-Host '    3. Writes a worksheet (.txt), a CSV and a results file. The commands in the' -ForegroundColor Yellow
Write-Host '       worksheet are TEXT for an administrator; this tool never runs them' -ForegroundColor Yellow
Write-Host '    4. Does NOT change any list, member or setting' -ForegroundColor Yellow
Write-Host '    5. Does NOT assess anything else: Entra ID, Conditional Access, Defender, Teams,' -ForegroundColor Yellow
Write-Host '       SharePoint, Intune, Purview and DNS are out of scope for this scan' -ForegroundColor Yellow
Write-Host ''
Write-Host "  Output          : $OutputPath"
Write-Host "  Member limit    : $MemberLimit per list (settings are read for every list)"
Write-Host ''

# ── Load the module ──────────────────────────────────────────────────────────
Write-Host '[-] Loading NRG-Assessment module...' -ForegroundColor Cyan
try {
    # The psm1, not the manifest: the manifest declares the Graph modules as required, and
    # this scan signs in to Exchange Online only.
    Import-Module (Join-Path $scriptDir 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    Write-Host '  [+] Module loaded' -ForegroundColor Green
} catch {
    Write-Host "  [!] Module load failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Clear-NRGState

# ── Which tenant must this be? ───────────────────────────────────────────────
$targetTenantId = $null
$targetDelegatedOrg = $DelegatedOrganization
if ($TenantDomain) {
    $clientRec = $null
    $clientsPath = Join-Path $scriptDir 'Config' 'clients.json'
    if (Test-Path -LiteralPath $clientsPath) {
        try {
            $rawClients = Get-Content -LiteralPath $clientsPath -Raw -Encoding utf8 | ConvertFrom-Json
            $list = if ($rawClients.PSObject.Properties['clients']) { @($rawClients.clients) } else { @($rawClients) }
            $clientRec = $list | Where-Object { $_.PSObject.Properties['TenantDomain'] -and $_.TenantDomain -eq $TenantDomain } | Select-Object -First 1
        } catch { $clientRec = $null }
    }
    if ($clientRec -and $clientRec.PSObject.Properties['TenantId'] -and "$($clientRec.TenantId)" -match '^[0-9a-fA-F-]{36}$' -and "$($clientRec.TenantId)" -ne '00000000-0000-0000-0000-000000000000') {
        $targetTenantId = "$($clientRec.TenantId)".ToLowerInvariant()
    } else {
        $targetTenantId = Resolve-NRGTenantId -Domain $TenantDomain
    }
    if (-not $targetDelegatedOrg -and $clientRec -and $clientRec.PSObject.Properties['DelegatedOrg'] -and "$($clientRec.DelegatedOrg)" -match '\.onmicrosoft\.com$') {
        $targetDelegatedOrg = [string]$clientRec.DelegatedOrg
    }
    if (-not $targetTenantId) {
        Write-Host "  [!] Could not resolve a tenant ID for $TenantDomain, so the connected tenant cannot be confirmed. Nothing was read." -ForegroundColor Red
        Write-Host '      Check the network, or add the client with its TenantId to Config/clients.json.' -ForegroundColor Red
        exit 1
    }
}

$connection = $null
try {
    # ── Connect ──────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '[-] Connecting to Exchange Online...' -ForegroundColor Cyan
    Write-Host '      Sign-in window may open behind this one.' -ForegroundColor DarkGray
    try {
        $connectParams = @{}
        if ($UserPrincipalName)   { $connectParams['UserPrincipalName'] = $UserPrincipalName }
        if ($targetDelegatedOrg)  { $connectParams['DelegatedOrganization'] = $targetDelegatedOrg }
        if ($targetTenantId)      { $connectParams['ExpectedTenantId'] = $targetTenantId }
        if ($ReuseSession)        { $connectParams['ReuseSession'] = $true }
        $connection = Connect-NRGExchangeOnlineOnly @connectParams
        Write-Host "  [+] Exchange Online - $($connection.Account)  (tenant $($connection.TenantId))" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Exchange Online: $($_.Exception.Message)" -ForegroundColor Red
        foreach ($hint in @((Get-NRGMsalConflictHint -Message $_.Exception.Message), (Get-NRGExoConnectHint -Message $_.Exception.Message))) {
            if ($hint) { Write-Host "      $hint" -ForegroundColor Yellow }
        }
        $script:NRGDLFatalExitCode = 1
        throw
    }

    # ── Collect ──────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '[-] Reading distribution lists (read-only)...' -ForegroundColor Cyan
    $raw = Invoke-NRGCollectDistributionLists -MemberLimit $MemberLimit -MemberReadListLimit $MemberReadListLimit
    $sections = $raw.Data.SectionStatus
    foreach ($key in @($sections.Keys | Sort-Object)) {
        $ok = ($sections[$key] -eq 'Collected')
        Write-Host ('  [{0}] {1,-20} {2}' -f $(if ($ok) { '+' } else { '!' }), $key, $sections[$key]) -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
    }
    foreach ($e in @($raw.Data.Errors)) { Write-Host "      $e" -ForegroundColor Yellow }
    Write-Host ("  [+] {0} list(s): {1} distribution, {2} mail-enabled security, {3} dynamic" -f $raw.Data.Stats.ListsTotal, $raw.Data.Stats.DistributionGroups, $raw.Data.Stats.MailEnabledSecurityGroups, $raw.Data.Stats.DynamicGroups) -ForegroundColor Green
    if ($raw.Data.Stats.MemberReadsFailed + $raw.Data.Stats.MemberReadsNotRead -gt 0) {
        Write-Host ("  [!] Members NOT read for {0} list(s) ({1} failed, {2} not attempted); they will read 'not assessed'." -f ($raw.Data.Stats.MemberReadsFailed + $raw.Data.Stats.MemberReadsNotRead), $raw.Data.Stats.MemberReadsFailed, $raw.Data.Stats.MemberReadsNotRead) -ForegroundColor Yellow
    }
    if ($raw.Data.Stats.MemberReadsTruncated -gt 0) {
        Write-Host ("  [!] {0} list(s) are larger than the {1}-member limit; only the first {1} were read." -f $raw.Data.Stats.MemberReadsTruncated, $MemberLimit) -ForegroundColor Yellow
    }

    # ── Evaluate ─────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '[-] Evaluating...' -ForegroundColor Cyan
    Test-NRGDistributionListControls
    $findings = @(Get-NRGFindings)
    Write-Host "  [+] $($findings.Count) finding(s)" -ForegroundColor Green

    # ── Publish ──────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '[-] Writing the worksheet...' -ForegroundColor Cyan
    $domain = [string]$raw.Data.TenantInitialDomain
    if (-not $domain -and $connection) { $domain = [string]$connection.Organization }
    if (-not $domain -and $TenantDomain) { $domain = $TenantDomain }
    $tenantTag = if ($domain) { (($domain -split '\.')[0] -replace '[^a-zA-Z0-9_-]', '_') } else { 'tenant' }
    $baseName = "$tenantTag-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    $collectionComplete = (@($sections.Values | Where-Object { $_ -ne 'Collected' }).Count -eq 0)
    $metadata = [ordered]@{
        AssessmentMode     = 'DistributionListScan'
        AssessmentDate     = (Get-Date -Format 'yyyy-MM-dd HH:mm')
        TenantDomain       = $(if ($domain) { $domain } else { 'unknown' })
        TenantId           = $(if ($connection) { $connection.TenantId } else { '' })
        ConnectedAccount   = $(if ($connection) { $connection.Account } else { '' })
        ToolVersion        = $(if (Get-Variable -Name NRGAssessmentVersion -ErrorAction SilentlyContinue) { [string]$NRGAssessmentVersion } else { 'unknown' })
        Services           = @('ExchangeOnline')
        NotAssessed        = @($raw.Data.Scope.NotCovered)
        MemberLimit        = $MemberLimit
        MemberReadListLimit = $MemberReadListLimit
        CollectionComplete = $collectionComplete
        FindingCount       = $findings.Count
    }

    $published = Publish-NRGDistributionListWorksheet -Metadata $metadata -Findings $findings -RawData $raw `
        -OutputDirectory $OutputPath -BaseName $baseName -NoMembers:$NoMembers
    Write-Host "  [+] Worksheet: $($published.TextPath)" -ForegroundColor Green
    Write-Host "  [+] CSV:       $($published.CsvPath)" -ForegroundColor Green

    $jsonPath = Join-Path $OutputPath "$baseName-distribution-lists-results.json"
    $payload = [ordered]@{
        Metadata    = $metadata
        Findings    = $findings
        RawData     = (Get-NRGRawData)
        Exceptions  = @(Get-NRGExceptions)
        Coverage    = (Get-NRGCoverage)
        Connections = @{ ExchangeOnline = $true; Graph = $false }
    } | ConvertTo-Json -Depth 12
    # The file holds the list inventory and member names: restricted permissions are
    # applied BEFORE any data is written.
    Set-NRGSensitiveFileContent -Path $jsonPath -Content $payload
    Write-Host "  [+] Results:   $jsonPath" -ForegroundColor Green

    # ── Summary ──────────────────────────────────────────────────────────────
    $c = $published.Counts
    Write-Host ''
    Write-Host '════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host ' Distribution List Scan Summary' -ForegroundColor Cyan
    Write-Host '════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host "  Lists read              : $($published.ListCount)"
    Write-Host "  Needs attention         : $($c['NeedsAttention'])" -ForegroundColor $(if ($c['NeedsAttention'] -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Partly protected        : $($c['PartlyProtected'])" -ForegroundColor $(if ($c['PartlyProtected'] -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Not fully assessed      : $($c['NotFullyAssessed'])" -ForegroundColor $(if ($c['NotFullyAssessed'] -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  OK in what was read     : $($c['OkInWhatWasRead'])"
    Write-Host '  Everything else (Entra ID, Defender, Teams, SharePoint, Intune, Purview, DNS) was NOT assessed.' -ForegroundColor DarkGray
    if (-not $collectionComplete) {
        Write-Host '  NOT COMPLETE: part of the evidence could not be read; see the sections above and the worksheet.' -ForegroundColor Yellow
    }
    Write-Host ''

    if (-not $raw.Success) {
        $script:NRGDLSuccessExitCode = 3
    } elseif ($published.ListCount -eq 0 -and $collectionComplete) {
        $script:NRGDLSuccessExitCode = 2
    } elseif (-not $collectionComplete -or @(Get-NRGExceptions).Count -gt 0) {
        $script:NRGDLSuccessExitCode = 3
    } else {
        $script:NRGDLSuccessExitCode = 0
    }
} catch {
    if (-not $script:NRGDLFatalExitCode) {
        Write-Host "[!] Fatal error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
        $script:NRGDLFatalExitCode = 4
    }
} finally {
    # Disconnect only a session this run opened; one it was told to reuse is the caller's.
    if ($connection -and -not $connection.Reused) { try { Disconnect-NRGExchangeOnlineOnly } catch { Write-Verbose "Disconnect: $($_.Exception.Message)" } }
}

if ($script:NRGDLFatalExitCode) { exit $script:NRGDLFatalExitCode }
if ($null -ne $script:NRGDLSuccessExitCode) { exit $script:NRGDLSuccessExitCode }
exit 0

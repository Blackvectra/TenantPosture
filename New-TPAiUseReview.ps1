#Requires -Version 7.0
<#
.SYNOPSIS
    Writes the client-facing AI use readiness review (HTML, and a PDF with
    -Pdf) from a saved full-run results file. Connects to nothing.

.DESCRIPTION
    New-TPAiUseReview.ps1
    TenantPosture — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson

    An offline view over one -results.json: what the assessment observed about
    Microsoft Copilot entitlement and seats and Copilot Studio agents, which
    recorded settings support AI use of the tenant's data, which need
    attention, what the organization itself has to decide and record, and the
    next steps grouped by what each needs. No score, no re-evaluation, no
    tenant contact, no new collection.

    The file is read three ways, each bounded (Get-TPRunRecordMaxBytes):
    Read-TPRunRecord for the metadata and the trimmed findings (no Detail),
    Get-TPAiUseReviewScope for the run kind and the scope classification as
    -FromResults computes it, and Read-TPAiUseFacts for the allowlisted
    aggregate facts. The source file is never modified.

    A partial (-ControlId) or quick (-Quick) run, or an incident-response
    output, is refused (exit 4): a review a client keeps must not read as the
    whole tenant when it is not. A full run whose individual reads failed or
    were cut short is written, with every gap named.

.PARAMETER ResultsPath
    The saved -results.json of a full assessment.
.PARAMETER ClientName
    The organization name printed on the review. A display label only; nothing
    is copied from the results file to name the client.
.PARAMETER PreparedBy
    Who prepared the review; defaults to the loaded profile's company name.
.PARAMETER Profile
    Profile name for branding (Config/profiles/<name>.psd1).
.PARAMETER OutputPath
    Folder for the output; defaults to the results file's folder.
.PARAMETER HIPAA
    Use the ePHI wording for the sensitive-information review area. This
    selects wording only: it does not assess, verify or determine HIPAA
    compliance, and the page says so.
.PARAMETER User
    Up to 25 user principal names. For each, the page adds what that one
    account needs before a Microsoft Copilot license is assigned to it
    (account, licenses, MFA registration, device), read from the results
    file. Without it the page names no account.
.PARAMETER Pdf
    Also print the HTML to PDF with the Edge, Chrome or Chromium already
    installed (ConvertTo-TPPdf). Optional: when no browser is found the HTML is
    still written and the PDF is reported as unavailable.

.EXAMPLE
    .\New-TPAiUseReview.ps1 -ResultsPath .\output\contoso-20261110-090000-results.json -ClientName 'Contoso Ltd' -Pdf

    Data consumed: one -results.json. Graph scopes / cmdlets used: none.
    Exit codes: 0 success (a PDF that could not be printed is reported, the HTML
    is still written), 4 refused or fatal.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Results file not found: $_" }
        return $true
    })]
    [string] $ResultsPath,

    [ValidateLength(0, 120)]
    [string] $ClientName = '',

    [ValidateLength(0, 120)]
    [string] $PreparedBy = '',

    [ValidatePattern('^[a-z0-9-]{0,40}$', Options = 'None')]
    [string] $Profile = '',

    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $OutputPath,

    [switch] $HIPAA,

    [ValidateCount(0, 25)]
    [ValidateLength(3, 256)]
    [string[]] $User = @(),

    [switch] $Pdf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$profileEnvBefore = $env:TP_PROFILE
try {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    if ($Profile) { $env:TP_PROFILE = $Profile }
    try { Import-Module (Join-Path $scriptDir 'TenantPosture.psm1') -Force -ErrorAction Stop }
    finally {
        if ($Profile) {
            if ($null -eq $profileEnvBefore) { Remove-Item -LiteralPath Env:TP_PROFILE -ErrorAction SilentlyContinue }
            else { $env:TP_PROFILE = $profileEnvBefore }
        }
    }

    $resultsFull = (Resolve-Path -LiteralPath $ResultsPath).Path
    if (-not $OutputPath) { $OutputPath = Split-Path -Parent $resultsFull }
    $null = [System.IO.Directory]::CreateDirectory($OutputPath)
    # The same proof every entry point makes before writing tenant data: the
    # folder can hold an owner-only file (an exFAT stick cannot).
    try { $null = Test-TPSensitiveOutputFolder -Path $OutputPath }
    catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red; exit 4 }

    $run = Read-TPRunRecord -Path $resultsFull
    if ($run.IsIncidentResponse) {
        Write-Host '  [!] That file is an incident-response output, not an assessment. Nothing was written.' -ForegroundColor Yellow
        exit 4
    }
    $scope = Get-TPAiUseReviewScope -Path $resultsFull
    $runScope = [string]$scope.RunScope
    if ($runScope -ne 'Full') {
        $why = if ($runScope -eq 'Partial') { 'a partial run (-ControlId)' } else { 'a quick scan (-Quick)' }
        Write-Host "  [!] The AI use readiness review covers the whole tenant and is not written from $why. Run a full assessment. Nothing was written." -ForegroundColor Yellow
        exit 4
    }
    $facts = Read-TPAiUseFacts -Path $resultsFull
    $userFacts = @()
    if (@($User).Count -gt 0) { $userFacts = @(Read-TPAiUseUserFacts -Path $resultsFull -UserPrincipalName $User) }
    $model = Get-TPAiUseReview -Findings @($run.Findings) -Metadata $run.Metadata -Facts $facts -ScopeBuckets $scope.Buckets -ClientName $ClientName -PreparedBy $PreparedBy -Hipaa:$HIPAA -UserFacts $userFacts
    Write-Host ''
    if (-not $model.Available) {
        Write-Host "  [!] $($model.Note)" -ForegroundColor Yellow
        Write-Host '      Nothing was written.' -ForegroundColor Yellow
        exit 4
    }

    $tag = ($ClientName -replace '[^a-zA-Z0-9-]', '')
    if ($tag.Length -gt 40) { $tag = $tag.Substring(0, 40) }
    if (-not $tag) { $tag = 'client' }
    $base = "$tag-ai-use-review-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $files = Publish-TPAiUseReview -Model $model -OutputPath (Join-Path $OutputPath "$base.html") -Pdf:$Pdf

    $names = $model.GroupNames
    Write-Host "  AI use readiness review: $($model.ClientName)" -ForegroundColor Green
    foreach ($k in $names.Keys) { Write-Host ("    {0,-44} {1,3} of {2}" -f $names[$k], $model.Counts[$k], $model.CatalogControls) }
    Write-Host "  Copilot deployment gate: $($model.Readiness.Label)" -ForegroundColor $(switch ($model.Readiness.Outcome) { 'BlockersFound' { 'Red' } 'NoBlockersInCheckedControls' { 'Green' } default { 'Yellow' } })
    foreach ($b in @($model.Readiness.Blockers)) { Write-Host "    blocker     $($b.ControlId)  $($b.Title)" }
    foreach ($b in @($model.Readiness.NotVerified)) { Write-Host "    no verdict  $($b.ControlId)  $($b.Title)" }
    if (@($model.Users).Count -gt 0) { Write-Host "  [i] The page names $(@($model.Users).Count) account(s) you passed with -User." -ForegroundColor DarkGray }
    if ($scope.DroppedFindings -gt 0) { Write-Host "  [i] $($scope.DroppedFindings) finding(s) in the file were not control findings and were not read." -ForegroundColor DarkGray }
    Write-Host ''
    Write-Host "  [+] HTML: $($files.Html)" -ForegroundColor Green
    if ($Pdf) {
        if ($files.Pdf) { Write-Host "  [+] PDF:  $($files.Pdf)" -ForegroundColor Green }
        else { Write-Host "  [!] $($files.PdfNote)" -ForegroundColor Yellow }
    }
    Write-Host '  This script connected to nothing and did not modify the results file.' -ForegroundColor DarkGray
    Write-Host ''
    exit 0
} catch {
    Write-Error "AI use readiness review failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 4
}

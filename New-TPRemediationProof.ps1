#Requires -Version 7.0
<#
.SYNOPSIS
    Build a proof-of-fix certificate from two saved results files of one
    tenant: what TenantPosture observed for each re-checked control before
    and after the fix. Offline: it connects to nothing.

.DESCRIPTION
    The natural pairing is a full run (or the run that found the gap) as
    -BeforeResults and a -ControlId re-check made after fixing as
    -AfterResults. The certificate lists the controls the after run covers
    (narrowed by -ControlId here when given) that the before run also
    assessed, with each control's state and current value before and after
    and a verdict: Resolved, Improved, Not resolved, Regressed, Not
    verifiable, No earlier verdict or Already met. A control the after run
    could not judge is Not verifiable, never resolved.

    Refused (exit 4) when the files are from different tenants (their
    TenantIds differ or one has none) or the after run is not newer than the
    before run. The evidence block carries both run times (UTC), tool
    versions, the SHA-256 of both files and the selection patterns; never the
    operator or the tenant ID.

    Output: <tenant>-proof-<yyyyMMdd-HHmmss>.html (branded, printable) and .md
    in -OutputPath. Invoke-TPAssessment.ps1 -ProofAgainst <before file> does
    the same right after a run.

.PARAMETER BeforeResults
    The earlier results file (-results.json).
.PARAMETER AfterResults
    The later results file of the same tenant.
.PARAMETER ControlId
    Optional wildcard patterns (the -ControlId rule) narrowing the controls.
.PARAMETER OutputPath
    Folder for the two files. Default: the folder of -AfterResults.
.PARAMETER PassThru
    Return the model and the file paths.

.EXAMPLE
    .\New-TPRemediationProof.ps1 -BeforeResults .\output\contoso-20261001-090000-results.json `
        -AfterResults .\output\contoso-20261020-101500-results.json -ControlId EXO-1.6

.NOTES
    Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
    Data consumed: two -results.json files. Graph scopes / cmdlets used: none.
    Exit codes: 0 success, 2 no control in both runs, 4 refused or fatal.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Results file not found: $_" }
        return $true
    })]
    [string] $BeforeResults,

    [Parameter(Mandatory)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Results file not found: $_" }
        return $true
    })]
    [string] $AfterResults,

    [string[]] $ControlId,

    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $OutputPath,

    [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    # The psm1, not the manifest: no Graph module is needed.
    Import-Module (Join-Path $scriptDir 'TenantPosture.psm1') -Force -ErrorAction Stop

    $beforePath = (Resolve-Path -LiteralPath $BeforeResults).Path
    $afterPath = (Resolve-Path -LiteralPath $AfterResults).Path
    if (-not $OutputPath) { $OutputPath = Split-Path -Parent $afterPath }

    # Errors name the parameter, never the path.
    $read = {
        param([string] $Path, [string] $Which)
        try { return (Read-TPRunRecord -Path $Path -Hash) } catch { throw "-$Which could not be read: $($_.Exception.Message)" }
    }
    $before = & $read $beforePath 'BeforeResults'
    $after = & $read $afterPath 'AfterResults'

    $proof = Get-TPRemediationProof -Before $before -After $after -ControlId @($ControlId | Where-Object { $_ })
    Write-Host ''
    if (-not $proof.Available) {
        Write-Host "  [!] $($proof.Note)" -ForegroundColor Yellow
        Write-Host '      Nothing was written.' -ForegroundColor Yellow
        Write-Host ''
        exit $(if ($proof.Refused) { 4 } else { 2 })
    }

    $files = Publish-TPRemediationProof -Proof $proof -OutputPath $OutputPath
    Write-Host '  Proof of fix' -ForegroundColor Green
    Write-Host "  $($proof.Headline)" -ForegroundColor Cyan
    foreach ($k in $proof.Counts.Keys) { if ($proof.Counts[$k] -gt 0) { Write-Host "    $($proof.Counts[$k]) $k" } }
    foreach ($n in @($proof.Notes)) { Write-Host "  [i] $n" -ForegroundColor DarkGray }
    Write-Host ''
    Write-Host "  [+] HTML:     $($files.Html)" -ForegroundColor Green
    Write-Host "  [+] Markdown: $($files.Markdown)" -ForegroundColor Green
    Write-Host '  This script connected to nothing.' -ForegroundColor DarkGray
    Write-Host ''
    if ($PassThru) { return [pscustomobject]@{ Proof = $proof; Files = $files } }
    exit 0
} catch {
    Write-Error "Proof of fix failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 4
}

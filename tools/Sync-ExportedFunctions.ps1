#Requires -Version 7.0
#
# Sync-ExportedFunctions.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Validates that FunctionsToExport in NRG-Assessment.psd1 matches
# $script:ExportedFunctions in NRG-Assessment.psm1, and optionally rewrites the
# psd1 list from the psm1 (the single source of truth).
#
# Sets:     nothing (read-only unless -Fix)
# Consumes: NRG-Assessment.psm1, NRG-Assessment.psd1
# Cmdlets:  none against any tenant
#
# Usage:
#   ./tools/Sync-ExportedFunctions.ps1 -Validate   # CI: exit 1 if out of sync
#   ./tools/Sync-ExportedFunctions.ps1 -Fix        # rewrite the psd1 list
#
# Testing/NRG.ExportSync.Tests.ps1 pins the same invariant in Pester; this
# script is the operator-facing form with a -Fix mode.

[CmdletBinding()]
param(
    # Check-only mode (for CI). Exits 1 if the lists differ.
    [switch] $Validate,

    # Overwrite FunctionsToExport in the psd1 to match the psm1.
    [switch] $Fix
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
$psm1Path = Join-Path $repoRoot 'NRG-Assessment.psm1'
$psd1Path = Join-Path $repoRoot 'NRG-Assessment.psd1'

# ── $script:ExportedFunctions from the psm1 ──────────────────────────────────
$psm1Content = Get-Content -LiteralPath $psm1Path -Raw
if ($psm1Content -match '(?s)\$script:ExportedFunctions\s*=\s*@\((.*?)\)') {
    $psm1Block = $Matches[1]
} else {
    throw 'Could not find $script:ExportedFunctions = @(...) in NRG-Assessment.psm1'
}
$psm1Functions = @([regex]::Matches($psm1Block, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })

# ── FunctionsToExport from the psd1 (data only, never executed) ──────────────
$psd1Data      = Import-PowerShellDataFile -LiteralPath $psd1Path
$psd1Functions = @($psd1Data.FunctionsToExport)

# ── Compare in both directions ───────────────────────────────────────────────
$inPsm1Only = @($psm1Functions | Where-Object { $_ -notin $psd1Functions })
$inPsd1Only = @($psd1Functions | Where-Object { $_ -notin $psm1Functions })
$synced     = ($inPsm1Only.Count -eq 0 -and $inPsd1Only.Count -eq 0)

if ($synced) {
    Write-Host "Export lists are in sync ($($psm1Functions.Count) functions)." -ForegroundColor Green
    exit 0
}

Write-Host 'Export lists are OUT OF SYNC.' -ForegroundColor Red
if ($inPsm1Only.Count -gt 0) {
    Write-Host '  In .psm1 but missing from .psd1:' -ForegroundColor Yellow
    $inPsm1Only | ForEach-Object { Write-Host "    - $_" }
}
if ($inPsd1Only.Count -gt 0) {
    Write-Host '  In .psd1 but missing from .psm1:' -ForegroundColor Yellow
    $inPsd1Only | ForEach-Object { Write-Host "    - $_" }
}

if ($Validate) { exit 1 }

if ($Fix) {
    Write-Host 'Updating .psd1 FunctionsToExport to match .psm1...' -ForegroundColor Cyan
    $psd1Content = Get-Content -LiteralPath $psd1Path -Raw

    # The block ends at the first ')' that sits ALONE on a line at the same
    # indentation as 'FunctionsToExport', not at the first ')' anywhere: the
    # list carries section comments such as "(Email-IR/ subtree)", and a
    # non-greedy '.*?\)' stopped inside one of them, leaving the tail of the
    # old list dangling after the new block and a psd1 that no longer parsed.
    $blockRx = [regex]'(?ms)^(?<indent>[ \t]*)FunctionsToExport\s*=\s*@\(.*?^\k<indent>\)[ \t]*$'
    $m = $blockRx.Match($psd1Content)
    if (-not $m.Success) { throw 'Could not locate the FunctionsToExport = @( ... ) block in NRG-Assessment.psd1' }
    $indent     = $m.Groups['indent'].Value
    $newEntries = ($psm1Functions | ForEach-Object { "$indent    '$_'" }) -join ",`n"
    $newBlock   = "${indent}FunctionsToExport = @(`n$newEntries`n${indent})"
    $updated    = $psd1Content.Substring(0, $m.Index) + $newBlock + $psd1Content.Substring($m.Index + $m.Length)

    # Never write a manifest that does not parse: prove the result on a
    # temporary file first, then replace the real one.
    $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "NRG-Assessment.$([guid]::NewGuid().ToString('N')).psd1")
    try {
        Set-Content -LiteralPath $tmp -Value $updated -Encoding utf8NoBOM -NoNewline
        $check = Import-PowerShellDataFile -LiteralPath $tmp
        $written = @($check.FunctionsToExport)
        if ($written.Count -ne $psm1Functions.Count -or @($written | Where-Object { $_ -notin $psm1Functions }).Count -gt 0) {
            throw "Rewritten manifest lists $($written.Count) functions, expected $($psm1Functions.Count); not written"
        }
        Copy-Item -LiteralPath $tmp -Destination $psd1Path -Force
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Updated .psd1 with $($psm1Functions.Count) functions." -ForegroundColor Green
    exit 0
}

Write-Host ''
Write-Host 'Run with -Fix to update the .psd1, or -Validate for CI.' -ForegroundColor Cyan
exit 1

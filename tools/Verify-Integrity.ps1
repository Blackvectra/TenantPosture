#Requires -Version 7.0
<#
.SYNOPSIS
    Verifies integrity of the NRG Assessment Tool against a published manifest.

.DESCRIPTION
    Computes SHA-256 hashes of every PS1, PSM1, PSD1, and JSON file in the repo
    (excluding output/, .git/, tools/) and compares against tools/integrity-manifest.txt.

    Returns exit 0 if all files match, 1 if any mismatch or missing file.

.PARAMETER ManifestPath
    Path to the integrity manifest. Default: tools\integrity-manifest.txt.

.PARAMETER Update
    Regenerate the manifest. Use only when releasing.

.EXAMPLE
    .\tools\Verify-Integrity.ps1
.EXAMPLE
    .\tools\Verify-Integrity.ps1 -Update
#>

[CmdletBinding()]
param(
    [ValidateScript({
        if ($_ -match '\.\.[\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $ManifestPath = (Join-Path $PSScriptRoot 'integrity-manifest.txt'),

    [switch] $Update
)


$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $repoRoot) { $repoRoot = (Get-Location).Path }

$includeExtensions = @('.ps1', '.psm1', '.psd1', '.json')

$files = Get-ChildItem -LiteralPath $repoRoot -Recurse -File |
    Where-Object {
        $_.Extension -in $includeExtensions -and
        $_.FullName -notmatch '\\output\\' -and
        $_.FullName -notmatch '\\\.git\\' -and
        $_.FullName -notmatch '\\\.github\\' -and
        $_.FullName -notmatch '[\\/]\.modules[\\/]' -and
        $_.FullName -notmatch '\\tools\\integrity-manifest'
    } |
    Sort-Object FullName

if ($Update) {
    Write-Host "Generating integrity manifest..." -ForegroundColor Cyan
    $entries = foreach ($f in $files) {
        $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
        $relPath = $f.FullName.Substring($repoRoot.Length + 1).Replace('\','/')
        "$hash  $relPath"
    }
    $header = @(
        "# NRG Assessment Tool - Integrity Manifest"
        "# Algorithm: SHA-256"
        "# Generated: $(Get-Date -Format 'o')"
        "# Files: $($files.Count)"
        "#"
    )
    ($header + $entries) | Out-File -LiteralPath $ManifestPath -Encoding utf8
    Write-Host "  [+] Wrote $($files.Count) entries to $ManifestPath" -ForegroundColor Green
    return
}

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    Write-Host "  [!] Manifest not found at $ManifestPath" -ForegroundColor Red
    Write-Host "      Generate with: .\tools\Verify-Integrity.ps1 -Update" -ForegroundColor Yellow
    exit 1
}

$expected = @{}
Get-Content -LiteralPath $ManifestPath | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
    $parts = $_ -split '\s+', 2
    if ($parts.Count -eq 2) {
        $expected[$parts[1].Trim()] = $parts[0].Trim()
    }
}

$mismatches = @()
$extras     = @()

foreach ($f in $files) {
    $relPath = $f.FullName.Substring($repoRoot.Length + 1).Replace('\','/')
    $hash    = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
    if (-not $expected.ContainsKey($relPath)) {
        $extras += $relPath
        continue
    }
    if ($expected[$relPath] -ne $hash) {
        $mismatches += [pscustomobject]@{ Path=$relPath; Expected=$expected[$relPath]; Actual=$hash }
    }
    $expected.Remove($relPath)
}
$missing = $expected.Keys

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  NRG Assessment Tool - Integrity Verification" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Files checked:   $($files.Count)"
Write-Host "  Matches:         $($files.Count - $mismatches.Count - $extras.Count)" -ForegroundColor Green
Write-Host "  Mismatches:      $($mismatches.Count)" -ForegroundColor $(if ($mismatches.Count) {'Red'} else {'Gray'})
Write-Host "  Missing files:   $($missing.Count)" -ForegroundColor $(if ($missing.Count) {'Red'} else {'Gray'})
Write-Host "  Extra files:     $($extras.Count)" -ForegroundColor $(if ($extras.Count) {'Yellow'} else {'Gray'})
Write-Host ""

if ($mismatches) {
    Write-Host "MISMATCHED FILES (possible tampering):" -ForegroundColor Red
    foreach ($m in $mismatches) {
        Write-Host "  $($m.Path)" -ForegroundColor Red
        Write-Host "    Expected: $($m.Expected)" -ForegroundColor DarkGray
        Write-Host "    Actual:   $($m.Actual)" -ForegroundColor DarkGray
    }
}
if ($missing) {
    Write-Host "MISSING FILES (in manifest, not on disk):" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}
if ($extras) {
    Write-Host "EXTRA FILES (on disk, not in manifest):" -ForegroundColor Yellow
    $extras | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}

if ($mismatches.Count -eq 0 -and $missing.Count -eq 0) {
    Write-Host "  [+] Integrity verified." -ForegroundColor Green
    exit 0
} else {
    Write-Host "  [!] Integrity check FAILED." -ForegroundColor Red
    exit 1
}
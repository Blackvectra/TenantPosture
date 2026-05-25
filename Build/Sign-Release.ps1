#Requires -Version 7.0
<#
.SYNOPSIS
    Authenticode-signs all .ps1/.psm1/.psd1 files in the repo and produces a signed .cat catalog.

.DESCRIPTION
    Requires a CA-issued code-signing certificate installed in Cert:\CurrentUser\My
    (or accessible via thumbprint). Self-signed certs are NOT recommended per Microsoft Learn.

    Uses a timestamp server so signatures remain valid after the certificate expires.

    Default timestamp servers (in priority order):
      http://timestamp.digicert.com
      http://timestamp.sectigo.com

    The resulting NRG-Assessment.cat is verified at orchestrator startup via Test-FileCatalog
    unless -SkipCatalogCheck is passed.

.PARAMETER CertificateThumbprint
    SHA-1 thumbprint of the code-signing certificate to use. Must already be installed
    in a certificate store accessible to the running user.

.PARAMETER TimestampServer
    URL of an RFC 3161 timestamp server. Defaults to DigiCert.

.PARAMETER RepoRoot
    Repository root to sign. Defaults to one level up from this script.

.EXAMPLE
    .\Build\Sign-Release.ps1 -CertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string] $CertificateThumbprint,

    # Audit fix (v4.6.x LOW): pattern previously accepted any FQDN-shaped
    # host, which let a typo or attacker-controlled DNS entry slip past the
    # validator. Tighten to the four publicly-trusted RFC 3161 timestamp
    # services the release process actually uses. Add new entries here only
    # after the operator vets the new authority.
    [ValidatePattern('^https?://(timestamp\.digicert\.com|timestamp\.sectigo\.com|timestamp\.globalsign\.com|timestamp\.entrust\.com)(/.*)?$')]
    [string] $TimestampServer = 'http://timestamp.digicert.com',

    [string] $RepoRoot
)


if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
if (-not (Test-Path -LiteralPath $RepoRoot)) {
    throw "Repository root not found: $RepoRoot"
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  NRG Assessment Tool - Release Signing" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Locate certificate
$cert = Get-ChildItem -Path Cert:\CurrentUser\My,Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $CertificateThumbprint } |
    Select-Object -First 1

if (-not $cert) {
    throw "Code-signing certificate with thumbprint $CertificateThumbprint not found in CurrentUser\My or LocalMachine\My."
}

if ($cert.Subject -match 'self.?signed' -or $cert.Issuer -eq $cert.Subject) {
    Write-Warning "Certificate appears to be self-signed. Microsoft Learn discourages this for production code signing."
    Write-Warning "Continue at your own discretion."
}

if ($cert.NotAfter -lt (Get-Date).AddDays(30)) {
    Write-Warning "Certificate expires within 30 days ($($cert.NotAfter)). Rotation strongly recommended."
}

Write-Host "  Cert subject:   $($cert.Subject)" -ForegroundColor Green
Write-Host "  Cert issuer:    $($cert.Issuer)" -ForegroundColor Green
Write-Host "  Cert expires:   $($cert.NotAfter)" -ForegroundColor Green
Write-Host "  Timestamp:      $TimestampServer" -ForegroundColor Green
Write-Host ""

# Find all signable files
$signableExt = @('.ps1','.psm1','.psd1','.ps1xml')
$files = Get-ChildItem -Path $RepoRoot -Recurse -File |
    Where-Object {
        $_.Extension -in $signableExt -and
        $_.FullName -notmatch '\\output\\' -and
        $_.FullName -notmatch '\\\.git\\'
    } |
    Sort-Object FullName

Write-Host "[-] Signing $($files.Count) files..." -ForegroundColor Cyan

$signed = 0
$failed = 0
foreach ($f in $files) {
    try {
        $result = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert `
                                             -TimestampServer $TimestampServer `
                                             -HashAlgorithm SHA256 -ErrorAction Stop
        if ($result.Status -eq 'Valid') {
            $signed++
            Write-Host "  [+] $($f.FullName.Substring($RepoRoot.Length + 1))" -ForegroundColor Green
        } else {
            $failed++
            Write-Host "  [!] $($f.FullName.Substring($RepoRoot.Length + 1)) — $($result.Status): $($result.StatusMessage)" -ForegroundColor Yellow
        }
    } catch {
        $failed++
        Write-Host "  [X] $($f.FullName.Substring($RepoRoot.Length + 1)) — $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "  Signed:  $signed" -ForegroundColor Green
Write-Host "  Failed:  $failed" -ForegroundColor $(if ($failed) { 'Red' } else { 'DarkGray' })
Write-Host ""

if ($failed -gt 0) {
    throw "Signing failed for $failed file(s)."
}

# Generate catalog
$catalogPath = Join-Path $RepoRoot 'NRG-Assessment.cat'
Write-Host "[-] Generating catalog $catalogPath..." -ForegroundColor Cyan

try {
    $catResult = New-FileCatalog -Path $RepoRoot -CatalogFilePath $catalogPath `
                                  -CatalogVersion 2 -ErrorAction Stop
    Write-Host "  [+] Catalog generated. Hash entries: $($catResult.Count)" -ForegroundColor Green
} catch {
    throw "Catalog generation failed: $($_.Exception.Message)"
}

# Sign the catalog itself
Write-Host "[-] Signing catalog..." -ForegroundColor Cyan
$catSig = Set-AuthenticodeSignature -FilePath $catalogPath -Certificate $cert `
                                     -TimestampServer $TimestampServer `
                                     -HashAlgorithm SHA256 -ErrorAction Stop
if ($catSig.Status -ne 'Valid') {
    throw "Catalog signature status: $($catSig.Status)"
}
Write-Host "  [+] Catalog signed and timestamped." -ForegroundColor Green

# Verify
Write-Host "[-] Verifying..." -ForegroundColor Cyan
$verify = Test-FileCatalog -CatalogFilePath $catalogPath -Path $RepoRoot -Detailed
if ($verify.Status -eq 'Valid') {
    Write-Host "  [+] Test-FileCatalog: Valid" -ForegroundColor Green
} else {
    throw "Test-FileCatalog returned: $($verify.Status)"
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Release signing complete." -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
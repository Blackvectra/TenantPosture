#Requires -Version 7.0
<#
.SYNOPSIS
    Authenticode-signs all .ps1/.psm1/.psd1 files in the repo and produces a signed .cat catalog.

.DESCRIPTION
    Signs every PowerShell file in the repo with the supplied code-signing certificate.

    Cert source options (any of):
      - Microsoft Trusted Signing / Sectigo / DigiCert (paid, public-CA-issued) — best for
        external distribution because the cert chain validates without local trust.
      - Self-signed cert from Build/New-TPCodeSigningCert.ps1 — perfect for in-house use
        where the operator workstations trust the cert locally. Signature still serves
        integrity (Verify-Integrity.ps1) and policy (Apply-TPBaseline.ps1 -RequireSignedCode)
        purposes. Upgrade to a paid cert later by passing a different -CertificateThumbprint;
        no other change required.

    Uses an RFC 3161 timestamp server so signatures remain valid after the certificate
    expires. The timestamp is useful for self-signed certs too — it pins WHEN the signature
    was applied, even if WHO is only self-attested.

    Default timestamp servers (in priority order):
      http://timestamp.digicert.com
      http://timestamp.sectigo.com

    The resulting TenantPosture.cat is verified at orchestrator startup via Test-FileCatalog
    unless -SkipCatalogCheck is passed.

.PARAMETER CertificateThumbprint
    SHA-1 thumbprint of the code-signing certificate. If omitted, reads from
    ~/.tp-assessment/signing-thumbprint.txt (written by New-TPCodeSigningCert.ps1
    when invoked with -SaveThumbprintForBuild).

.PARAMETER TimestampServer
    URL of an RFC 3161 timestamp server. Defaults to DigiCert.

.PARAMETER RepoRoot
    Repository root to sign. Defaults to one level up from this script.

.EXAMPLE
    # In-house, self-signed (one-time setup):
    .\Build\New-TPCodeSigningCert.ps1 -SaveThumbprintForBuild
    .\Build\Sign-Release.ps1   # picks up the saved thumbprint

.EXAMPLE
    # Paid cert (Microsoft Trusted Signing / Sectigo / DigiCert):
    .\Build\Sign-Release.ps1 -CertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567'
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string] $CertificateThumbprint,

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

# Resolve thumbprint: explicit param wins; otherwise pick up the one
# New-TPCodeSigningCert.ps1 stashed in the operator's profile.
if (-not $CertificateThumbprint) {
    $thumbFile = Join-Path $env:USERPROFILE '.tp-assessment/signing-thumbprint.txt'
    if (Test-Path -LiteralPath $thumbFile) {
        $CertificateThumbprint = (Get-Content -LiteralPath $thumbFile -Raw).Trim()
        Write-Verbose "Loaded thumbprint from $thumbFile"
    } else {
        throw "No -CertificateThumbprint supplied and no saved thumbprint at $thumbFile. Run Build/New-TPCodeSigningCert.ps1 -SaveThumbprintForBuild first, or pass -CertificateThumbprint explicitly."
    }
}

if ($CertificateThumbprint -notmatch '^[0-9a-fA-F]{40}$') {
    throw "Thumbprint '$CertificateThumbprint' is not a 40-hex SHA-1. Refusing to proceed."
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

# Detect self-signed (Issuer == Subject). Inform but don't warn — for in-house
# use, self-signed is the supported default. Upgrading to a paid cert later
# only changes which thumbprint gets passed; this script doesn't care.
$isSelfSigned = ($cert.Issuer -eq $cert.Subject)
if ($isSelfSigned) {
    Write-Host "  Mode:           Self-signed (in-house)" -ForegroundColor Yellow
    Write-Host "                  Operators must trust the cert in their workstation's TrustedPublisher / Root stores." -ForegroundColor DarkGray
    Write-Host "                  Build/New-TPCodeSigningCert.ps1 does this for the workstation that generated the cert." -ForegroundColor DarkGray
} else {
    Write-Host "  Mode:           CA-issued" -ForegroundColor Green
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
$catalogPath = Join-Path $RepoRoot 'TenantPosture.cat'
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
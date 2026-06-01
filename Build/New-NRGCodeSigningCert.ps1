#Requires -Version 7.0
#
# New-NRGCodeSigningCert.ps1
# One-time per workstation. Generates a self-signed Authenticode code-signing
# certificate, stores it in the operator's CurrentUser cert store, and
# emits the thumbprint so it can be plumbed into Build/Sign-Release.ps1.
#
# Author: Matthew Levorson / NRG Technology Services / NextLayerSec LLC
#
# WHY SELF-SIGNED (and when to upgrade)
#   For in-house use the operator workstation trusts the certificate locally.
#   That's sufficient when the tool only runs on machines the operator
#   controls. The signature still serves three real purposes even when
#   self-signed:
#     1. Integrity — Verify-Integrity.ps1 + Get-AuthenticodeSignature
#        detect ANY post-signing tamper of a .ps1.
#     2. Identity — every signed artifact records WHO signed it (subject
#        and serial number embedded in the certificate).
#     3. Policy gate — Apply-NRGBaseline.ps1 -RequireSignedCode refuses
#        to dot-source unsigned scripts. Self-signed counts as signed.
#
#   Upgrade path: when budget allows or when you distribute externally,
#   swap the cert for a Microsoft Trusted Signing / Sectigo / DigiCert
#   cert. Sign-Release.ps1 takes any cert thumbprint — no logic change.
#
# OWASP A04 / A08 — Software and Data Integrity
#

[CmdletBinding(SupportsShouldProcess)]
param(
    # Subject common name. Default is recognizable in the cert store and on
    # any signed artifact. Customize if you want per-operator identity
    # (e.g. -Subject 'CN=NRG-Assessment Signing, OU=mlevorson').
    [Parameter()]
    [string] $Subject = 'CN=NRG-Assessment Internal Signing',

    # Years valid. Self-signed certs can be long-lived since you control
    # the trust store. 3 years balances rotation discipline with not
    # re-signing every release.
    [Parameter()]
    [ValidateRange(1, 10)]
    [int] $Years = 3,

    # Persist the thumbprint to disk for Build/Sign-Release.ps1 to pick up
    # automatically. Stored under the operator's user profile, NOT in the
    # repo (the path includes the operator's username, so it's
    # per-workstation).
    [Parameter()]
    [switch] $SaveThumbprintForBuild,

    # Skip the local trust step. Without this, the cert is added to the
    # operator's Trusted Publishers store so PowerShell's RemoteSigned /
    # AllSigned policy will accept scripts signed by this cert without
    # prompting. Skip if you want to install the trust manually.
    [Parameter()]
    [switch] $SkipTrust
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    # New-SelfSignedCertificate is Windows-only. The rest of NRG-Assessment
    # is cross-platform, but Authenticode signing of PowerShell scripts is
    # specifically a Windows feature — Linux/macOS pwsh ignores
    # Authenticode signatures entirely.
} else {
    Write-Error 'Authenticode code-signing certs can only be generated on Windows. Run this script from your operator workstation, not from a Linux/macOS PowerShell host.'
    return
}

$notAfter = (Get-Date).AddYears($Years)

Write-Host ''
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host ' NRG-Assessment — Code-Signing Cert (self-signed, in-house)' -ForegroundColor Cyan
Write-Host '================================================================' -ForegroundColor Cyan
Write-Host "  Subject:    $Subject"
Write-Host "  Valid for:  $Years years (until $($notAfter.ToString('yyyy-MM-dd')))"
Write-Host "  Store:      Cert:\CurrentUser\My"
Write-Host ''

if (-not $PSCmdlet.ShouldProcess($Subject, 'Generate self-signed code-signing certificate')) {
    Write-Host '[WhatIf] Would generate cert but no changes made.' -ForegroundColor Yellow
    return
}

# Type CodeSigningCert sets the right EKU (1.3.6.1.5.5.7.3.3) so
# Authenticode tooling accepts it. KeyExportPolicy NonExportable is best
# practice for production but blocks the operator from moving the cert to
# another workstation. Default to Exportable for in-house multi-machine
# operator scenarios; tighten manually if the threat model warrants.
#
# Explicit BasicConstraints `cA=false` and KeyUsage DigitalSignature only:
# even though this cert ends up in the operator's CurrentUser\Root store
# (required for self-signed chain validation), it is NOT a CA — anyone
# with the private key can only impersonate THIS publisher, not issue
# certs for arbitrary subjects.
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyExportPolicy Exportable `
    -KeyUsage DigitalSignature `
    -TextExtension @('2.5.29.19={text}cA=false') `
    -NotAfter $notAfter

Write-Host "  [+] Cert generated. Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green

# Add to Trusted Publishers so PowerShell accepts the signature without a
# trust prompt. Without this, an operator running a signed script gets
# a one-time "Do you want to run software from this publisher" prompt;
# self-signed certs default to NO trust which means even AllSigned
# rejects them. Adding to TrustedPublisher fixes that.
if (-not $SkipTrust) {
    $trustedStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        'TrustedPublisher', 'CurrentUser')
    try {
        $trustedStore.Open('ReadWrite')
        $trustedStore.Add($cert)
        Write-Host '  [+] Added to Cert:\CurrentUser\TrustedPublisher' -ForegroundColor Green
    } finally {
        $trustedStore.Close()
    }

    # Also add to Root so the signature chains. Self-signed certs are
    # both their own root and their own leaf — without this, signature
    # verification fails with "chain could not be built."
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        'Root', 'CurrentUser')
    try {
        $rootStore.Open('ReadWrite')
        $rootStore.Add($cert)
        Write-Host '  [+] Added to Cert:\CurrentUser\Root (chain anchor)' -ForegroundColor Green
    } finally {
        $rootStore.Close()
    }
} else {
    Write-Host '  [!] Trust install skipped — install manually via Cert:\CurrentUser\TrustedPublisher and Cert:\CurrentUser\Root' -ForegroundColor Yellow
}

if ($SaveThumbprintForBuild) {
    $configDir = Join-Path $env:USERPROFILE '.nrg-assessment'
    if (-not (Test-Path -LiteralPath $configDir)) {
        [void][System.IO.Directory]::CreateDirectory($configDir)
    }
    $thumbFile = Join-Path $configDir 'signing-thumbprint.txt'
    Set-Content -LiteralPath $thumbFile -Value $cert.Thumbprint -Encoding utf8
    Write-Host "  [+] Thumbprint saved to $thumbFile (Build/Sign-Release.ps1 will pick this up automatically)" -ForegroundColor Green
}

Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Cyan
Write-Host "  1. Sign a release:  .\Build\Sign-Release.ps1 -CertificateThumbprint $($cert.Thumbprint)"
Write-Host "  2. Verify:          .\tools\Verify-Integrity.ps1"
Write-Host '  3. Enforce signing in remediation runs:'
Write-Host '       .\Apply-NRGBaseline.ps1 -ResultsPath .\output\<...>.json -RequireSignedCode'
Write-Host ''
Write-Host 'When you upgrade to a paid cert (Microsoft Trusted Signing / Sectigo / DigiCert),' -ForegroundColor DarkGray
Write-Host 'pass that cert thumbprint to Sign-Release.ps1 instead — no other change needed.'  -ForegroundColor DarkGray
Write-Host ''
Write-Host 'Security note:' -ForegroundColor DarkGray
Write-Host '  This cert is installed in your CurrentUser scope only (not LocalMachine), and' -ForegroundColor DarkGray
Write-Host '  it is a NON-CA cert (cA=false, DigitalSignature only). Loss of the private key' -ForegroundColor DarkGray
Write-Host '  enables impersonation of this specific publisher, NOT arbitrary code signing.' -ForegroundColor DarkGray
Write-Host '  Treat the private key the same as any other long-lived credential.' -ForegroundColor DarkGray
Write-Host ''

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

    The tracked tree must be clean before signing (git status --porcelain, untracked files
    aside): the manifests are computed from the working tree and the "Sign vX.Y.Z" commit
    carries only the signed scripts and the manifests, so a locally edited tracked file
    (Config/clients.json on an operator workstation) would be hashed into a manifest the
    tagged commit cannot satisfy. Stash such edits first.

    The resulting TenantPosture.cat is a signed catalog of the COMMITTED tree: the files git
    tracks plus the manifests this script writes, which the "Sign vX.Y.Z" commit adds. It is
    built from one exported copy of that tree (New-FileCatalog records only file names when
    given a list of files, and the tree holds several README.md and example.psd1). Verify a
    clone with: .\Build\Sign-Release.ps1 -VerifyCatalogOnly   (no private key needed;
    the catalog's own signature must be Valid, or carry the thumbprint passed as
    -CertificateThumbprint, before its hashes count for anything). Nothing in the tool
    reads it at run time.

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

    [string] $RepoRoot,

    # Verify an existing TenantPosture.cat against this tree's tracked files
    # and sign nothing: no certificate, no signing, no manifest refresh.
    [switch] $VerifyCatalogOnly
)

# Every failure below is terminating: a signing, normalization or manifest
# error must stop the release, never leave a half-signed tree that commits.
$ErrorActionPreference = 'Stop'

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
if (-not (Test-Path -LiteralPath $RepoRoot)) {
    throw "Repository root not found: $RepoRoot"
}
# Absolute, so every path built from it compares with Get-ChildItem's FullName.
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).ProviderPath.TrimEnd('\', '/')

$catalogPath       = Join-Path $RepoRoot 'TenantPosture.cat'
$verifyScript      = Join-Path $RepoRoot 'tools' 'Verify-Integrity.ps1'
$integrityManifest = Join-Path $RepoRoot 'tools' 'integrity-manifest.txt'
$manifestPath      = Join-Path $RepoRoot 'FILES.sha256'
# The files this script itself (re)writes; the only tracked files allowed to
# differ from the index before signing, and the ones the sign commit adds.
$generatedFiles    = @($integrityManifest, $manifestPath, $catalogPath)

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCmd) { throw 'git was not found on PATH; the catalog and the clean-tree check need the tracked file list.' }

function Get-TPTrackedFiles {
    <# Repository-relative paths of every file git tracks, forward slashes. #>
    $global:LASTEXITCODE = 0
    $list = @(& $gitCmd.Source -C $RepoRoot -c core.quotepath=off ls-files)
    if ($LASTEXITCODE -ne 0 -or $list.Count -eq 0) { throw "git ls-files failed in $RepoRoot (exit $LASTEXITCODE); is it a clone?" }
    return $list
}

function Export-TPCatalogTree {
    <#
        Copies the committed tree (tracked files, the catalog itself excepted, plus
        the generated manifests when present) under one new folder, preserving
        relative paths, and returns that folder. New-FileCatalog and Test-FileCatalog
        then see one rooted tree, which is the only shape in which they record and
        compare relative paths.
    #>
    $dest = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-catalog-" + [System.IO.Path]::GetRandomFileName().Replace('.', ''))
    # [IO.Directory]::CreateDirectory, never New-Item -Path: -Path expands wildcards.
    $null = [System.IO.Directory]::CreateDirectory($dest)
    $rels = [System.Collections.Generic.List[string]]::new()
    foreach ($rel in (Get-TPTrackedFiles)) { $rels.Add($rel) }
    # The integrity manifest is the one generated file the sign commit stages,
    # so it joins the export when present. FILES.sha256 is a release-archive
    # record: an untracked copy (from an extracted release, say) is cataloged
    # only if git tracks it, or a fresh clone could never match the catalog.
    if (Test-Path -LiteralPath $integrityManifest -PathType Leaf) {
        $rel = [System.IO.Path]::GetRelativePath($RepoRoot, $integrityManifest).Replace('\', '/')
        if (-not $rels.Contains($rel)) { $rels.Add($rel) }
    }
    $count = 0
    foreach ($rel in ($rels | Sort-Object -Unique)) {
        $src = Join-Path $RepoRoot ($rel -replace '/', [string][System.IO.Path]::DirectorySeparatorChar)
        if ($src -eq $catalogPath) { continue }
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { throw "Tracked file '$rel' is missing from the working tree; the catalog describes the committed tree, so restore or remove it first." }
        $dst = Join-Path $dest ($rel -replace '/', [string][System.IO.Path]::DirectorySeparatorChar)
        $null = [System.IO.Directory]::CreateDirectory((Split-Path -Parent $dst))
        Copy-Item -LiteralPath $src -Destination $dst
        $count++
    }
    Write-Verbose "Exported $count tracked file(s) to $dest"
    return $dest
}

function Assert-TPCatalogSignature {
    <#
        Test-FileCatalog's Status is the hash comparison only; the catalog's own
        Authenticode result is its Signature property. A tree an attacker can write
        can carry a freshly generated, unsigned catalog whose hashes all match, so
        the hashes are trusted only once the signature is: Valid on this workstation,
        or signed by the expected thumbprint (an in-house signer this workstation
        does not trust reads NotTrusted and is accepted only when pinned).
    #>
    param([Parameter(Mandatory)] $Catalog, [AllowNull()] [string] $ExpectedThumbprint)
    $sig = $Catalog.Signature
    $status = if ($null -ne $sig) { [string]$sig.Status } else { '' }
    $tp = if ($null -ne $sig -and $sig.SignerCertificate) { [string]$sig.SignerCertificate.Thumbprint } else { '' }
    if ($ExpectedThumbprint) {
        if ($tp -ne $ExpectedThumbprint) { throw "The catalog is signed by '$tp' (status $status), not the expected $ExpectedThumbprint." }
        if ($status -notin @('Valid', 'NotTrusted')) { throw "The catalog signature does not verify ($status)." }
    } elseif ($status -ne 'Valid') {
        throw "The catalog signature is not Valid ($status; signer '$tp'). Pass -CertificateThumbprint to accept the pinned in-house signer on a workstation that does not trust it."
    }
    Write-Host "  [+] Catalog signature: $status, signer $tp" -ForegroundColor Green
}

if ($VerifyCatalogOnly) {
    if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) { throw "No catalog at $catalogPath to verify." }
    $tree = Export-TPCatalogTree
    try {
        $verify = Test-FileCatalog -CatalogFilePath $catalogPath -Path $tree -Detailed
        Assert-TPCatalogSignature -Catalog $verify -ExpectedThumbprint $CertificateThumbprint
        if ($verify.Status -ne 'Valid') { throw "Test-FileCatalog returned $($verify.Status) for the tracked tree." }
        Write-Host "  [+] Test-FileCatalog: Valid over the tracked tree." -ForegroundColor Green
    } finally {
        Remove-Item -LiteralPath $tree -Recurse -Force -ErrorAction SilentlyContinue
    }
    return
}

# The manifests below hash the working tree and the sign commit carries only
# the signed scripts and the manifests, so a tracked file edited locally
# (Config/clients.json on an operator workstation) would be hashed into a
# manifest the tagged commit can never satisfy. Only the files this script
# writes may differ from the index.
$global:LASTEXITCODE = 0
$dirty = @(& $gitCmd.Source -C $RepoRoot status --porcelain --untracked-files=no)
if ($LASTEXITCODE -ne 0) { throw "git status failed in $RepoRoot (exit $LASTEXITCODE)." }
$dirty = @($dirty | Where-Object { $_ } | ForEach-Object { $_.Substring(3).Trim() } | Where-Object {
    (Join-Path $RepoRoot ($_ -replace '/', [string][System.IO.Path]::DirectorySeparatorChar)) -notin $generatedFiles
})
if ($dirty.Count -gt 0) {
    throw "Refusing to sign: tracked files differ from the index ($($dirty -join ', ')). Commit or stash them first (git stash push -- <path>); the manifests must describe the tree that will be committed."
}
# Everything below works from the tracked files, never from a folder walk: the
# sign commit carries nothing else, so an untracked or ignored local script
# (a secrets.ps1, a scratch file, an ignored .psd1) is neither signed nor
# hashed into a manifest the tagged tree could not satisfy.
$tracked = @(Get-TPTrackedFiles)
$toFull = { param($rel) Join-Path $RepoRoot ($rel -replace '/', [string][System.IO.Path]::DirectorySeparatorChar) }

# Resolve thumbprint: explicit param wins; otherwise pick up the one
# New-TPCodeSigningCert.ps1 stashed in the operator's profile.
if (-not $CertificateThumbprint) {
    $thumbFile = Join-Path $env:USERPROFILE '.tp-assessment/signing-thumbprint.txt'
    if (Test-Path -LiteralPath $thumbFile) {
        # The pointer decides which key signs the release. It is trusted only
        # when this user owns both the file and its folder and no other
        # identity (beyond SYSTEM and Administrators) can write the file or
        # create, delete or replace entries in the folder; a repointable file is
        # refused and the thumbprint must be passed explicitly.
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        # Compared by SID, never by name: well-known principals render as
        # localized names on a non-English Windows.
        $allowedSids = @($me.User.Value, 'S-1-5-18', 'S-1-5-32-544')
        $sidOf = {
            param($identity)
            try { ([System.Security.Principal.NTAccount]$identity).Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { try { ([System.Security.Principal.SecurityIdentifier][string]$identity).Value } catch { [string]$identity } }
        }
        # Primitive mutation bits only. Write, Modify and FullControl are composite
        # masks that also contain read and synchronize bits, so a read-only audit
        # or backup principal would otherwise be reported as able to repoint the file.
        $changeRights = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                        [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
                        [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                        [System.Security.AccessControl.FileSystemRights]::Delete -bor
                        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
        foreach ($target in @($thumbFile, (Split-Path -Parent $thumbFile))) {
            $acl = Get-Acl -LiteralPath $target
            $owner = [string]$acl.Owner
            if ((& $sidOf $owner) -notin $allowedSids) { throw "Refusing to read $thumbFile`: '$target' is owned by $owner, not by you. Pass -CertificateThumbprint explicitly." }
            $foreign = @($acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and (($_.FileSystemRights -band $changeRights) -ne 0) -and ((& $sidOf ([string]$_.IdentityReference)) -notin $allowedSids)
            })
            if ($foreign.Count -gt 0) {
                throw "Refusing to read $thumbFile`: '$target' can be changed by $(@($foreign | ForEach-Object { [string]$_.IdentityReference }) -join ', '). Restrict it to your account or pass -CertificateThumbprint explicitly."
            }
        }
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

# The signable files: the tracked ones with a signable extension.
$signableExt = @('.ps1','.psm1','.psd1','.ps1xml')
$files = @($tracked | Where-Object { [System.IO.Path]::GetExtension($_) -in $signableExt } |
    ForEach-Object { Get-Item -LiteralPath (& $toFull $_) } | Sort-Object FullName)

Write-Host "[-] Signing $($files.Count) files..." -ForegroundColor Cyan

# The committed representation is LF (.gitattributes: text eol=lf), and git
# normalizes CRLF to LF on commit. Set-AuthenticodeSignature appends its
# signature block with CRLF line endings (PowerShell issue #3361), so a signed
# LF file that is committed as-is has its block rewritten by git: the tagged
# checkout then carries different bytes from the ones the manifests below were
# computed over, and the release job reports manifest mismatches. So a file
# that had no CRLF before signing is normalized back to LF after signing, and
# the signature is read again: it must still verify on the bytes that will be
# committed, or the release stops here rather than shipping bytes that differ
# from the commit.
function Restore-TPLineEndings {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [bool] $HadCrLf)
    if ($HadCrLf) { return }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $text = [System.Text.UTF8Encoding]::new($false).GetString($bytes, $(if ($hasBom) { 3 } else { 0 }), $bytes.Length - $(if ($hasBom) { 3 } else { 0 }))
    if (-not $text.Contains("`r`n")) { return }
    $text = $text.Replace("`r`n", "`n")
    [System.IO.File]::WriteAllText($Path, $text, [System.Text.UTF8Encoding]::new($hasBom))
}

# Signing is transactional: the unsigned bytes of every file are kept until the
# whole set is signed, and any failure (a timestamp request that times out,
# a signature that does not survive normalization) restores all of them, so
# the tree is as it was and the run can simply be repeated. Without that, a
# failure midway left the earlier scripts signed, and the clean-tree check
# above then refused every retry.
$originals = [ordered]@{}
$signed = 0
$failed = 0
foreach ($f in $files) {
    $rel = $f.FullName.Substring($RepoRoot.Length + 1)
    try {
        $before = [System.IO.File]::ReadAllBytes($f.FullName)
        $originals[$f.FullName] = $before
        $hadCrLf = [System.Text.UTF8Encoding]::new($false).GetString($before).Contains("`r`n")
        $result = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert `
                                             -TimestampServer $TimestampServer `
                                             -HashAlgorithm SHA256 -ErrorAction Stop
        if ($result.Status -ne 'Valid') {
            $failed++
            Write-Host "  [!] $rel — $($result.Status): $($result.StatusMessage)" -ForegroundColor Yellow
            continue
        }
        Restore-TPLineEndings -Path $f.FullName -HadCrLf $hadCrLf
        $check = Get-AuthenticodeSignature -LiteralPath $f.FullName
        if ($check.Status -ne 'Valid') {
            $failed++
            Write-Host "  [!] $rel — signed, but the signature does not verify once the signature block is normalized to LF, the form git commits ($($check.Status)). The committed file would not carry a valid signature; do not commit it." -ForegroundColor Red
            continue
        }
        $signed++
        Write-Host "  [+] $rel" -ForegroundColor Green
    } catch {
        $failed++
        Write-Host "  [X] $rel — $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "  Signed:  $signed" -ForegroundColor Green
Write-Host "  Failed:  $failed" -ForegroundColor $(if ($failed) { 'Red' } else { 'DarkGray' })
Write-Host ""

function Restore-TPUnsignedBytes {
    <# Puts every file's pre-signing bytes back; returns how many it restored. #>
    param([Parameter(Mandatory)] $Map)
    $restored = 0
    foreach ($path in @($Map.Keys)) {
        try { [System.IO.File]::WriteAllBytes($path, $Map[$path]); $restored++ }
        catch { Write-Host "  [!] Could not restore $path`: $($_.Exception.Message)" -ForegroundColor Red }
    }
    return $restored
}

if ($failed -gt 0) {
    $restored = Restore-TPUnsignedBytes -Map $originals
    throw "Signing failed for $failed file(s); the unsigned bytes of $restored file(s) were restored, so the tree is as it was and the run can be repeated."
}

# Everything after this point (manifests, catalog) is part of the same
# transaction: a failure there restores the unsigned bytes too, so a
# timestamp outage during catalog signing or a manifest that does not verify
# never leaves a half-done tree that the clean-tree check would then refuse.
# The generated files are part of it as well: the integrity manifest and
# FILES.sha256 are rewritten from the signed bytes and the catalog is
# rebuilt, so restoring the scripts alone would leave manifests that hash
# bytes no longer on disk and could replace a valid catalog with a partial
# one. Each is snapshotted here, bytes or absence, and put back on failure.
function Save-TPGeneratedFiles {
    <# Snapshot of each generated file: its bytes, or $null when it does not exist. #>
    param([Parameter(Mandatory)] [string[]] $Paths)
    $snapshot = [ordered]@{}
    foreach ($path in $Paths) {
        $snapshot[$path] = if (Test-Path -LiteralPath $path -PathType Leaf) { [System.IO.File]::ReadAllBytes($path) } else { $null }
    }
    return $snapshot
}
function Restore-TPGeneratedFiles {
    <# Puts each generated file back as snapshotted: its bytes, or removed when it did not exist. Returns how many it restored. #>
    param([Parameter(Mandatory)] $Snapshot)
    $restored = 0
    foreach ($path in @($Snapshot.Keys)) {
        try {
            if ($null -eq $Snapshot[$path]) {
                if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
            } else {
                [System.IO.File]::WriteAllBytes($path, $Snapshot[$path])
            }
            $restored++
        } catch { Write-Host "  [!] Could not restore $path`: $($_.Exception.Message)" -ForegroundColor Red }
    }
    return $restored
}
$generatedSnapshot = Save-TPGeneratedFiles -Paths $generatedFiles
try {

# The committed integrity manifest (tools/integrity-manifest.txt, written by
# tools/Verify-Integrity.ps1 -Update) hashes the same scripts signing just
# changed, so it is written here, after signing and before the catalog: the
# release workflow verifies it over the tagged commit.
if (Test-Path -LiteralPath $verifyScript -PathType Leaf) {
    Write-Host "[-] Writing tools/integrity-manifest.txt from the signed tree..." -ForegroundColor Cyan
    # The refresh runs under $ErrorActionPreference = 'Stop' (set above and in
    # the script itself), so an unreadable file is a terminating error, never a
    # silently shorter manifest. The refreshed manifest is then verified in the
    # same session: $LASTEXITCODE is reset first, because a called script's
    # exit code lands there and a stale value from an earlier native command
    # would otherwise pass for a result.
    # -ManifestPath names the repository manifest explicitly: with FILES.sha256 at
    # the root (regenerated above when present) the verifier would otherwise take
    # the tree for an extracted release. -PathList hands it the tracked files that
    # fall inside its own filter (the extensions it hashes, outside .github\ and
    # output\), so no ignored or untracked file enters the manifest.
    $manifestFiles = @($tracked | Where-Object {
        [System.IO.Path]::GetExtension($_) -in @('.ps1', '.psm1', '.psd1', '.json') -and
        $_ -notlike '.github/*' -and $_ -notlike 'output/*' -and $_ -ne 'tools/integrity-manifest.txt'
    })
    & $verifyScript -Update -ManifestPath $integrityManifest -PathList $manifestFiles
    $global:LASTEXITCODE = 0
    & $verifyScript -ManifestPath $integrityManifest
    if ($LASTEXITCODE -ne 0) { throw "tools/integrity-manifest.txt does not verify against the signed tree it was just generated from (exit $LASTEXITCODE)." }
}

# A release archive carries FILES.sha256 (written by the release workflow from
# the packaged tree). Signing changes every script's bytes, so the manifest is
# rewritten from the signed tree BEFORE the catalog is built, so the catalog
# covers the final manifest and Test-FileCatalog stays valid.
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    Write-Host "[-] Regenerating FILES.sha256 from the signed tracked tree..." -ForegroundColor Cyan
    # Tracked files plus the integrity manifest just written; never FILES.sha256
    # itself nor the catalog, which is rebuilt and re-signed after this.
    $rels = @($tracked) + @(if (Test-Path -LiteralPath $integrityManifest -PathType Leaf) { 'tools/integrity-manifest.txt' })
    $manifest = @($rels | Sort-Object -Unique | Where-Object { $_ -ne 'FILES.sha256' -and $_ -ne 'TenantPosture.cat' } | ForEach-Object {
            '{0}  {1}' -f (Get-FileHash -LiteralPath (& $toFull $_) -Algorithm SHA256).Hash.ToLower(), $_
        })
    # LF, whatever the platform: git normalizes text on commit, and a catalog
    # or hash over CRLF bytes would not describe the committed file.
    [System.IO.File]::WriteAllText($manifestPath, (($manifest -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    Write-Host "  [+] FILES.sha256 rewritten ($(@($manifest).Count) entries)." -ForegroundColor Green
}

# Generate catalog. It describes the COMMITTED tree, so it is built from one
# exported copy of the tracked files plus the manifests written above (which
# the same "Sign" commit adds), never from the repository folder itself:
# New-FileCatalog -Path <folder> takes everything underneath, .git\ (whose
# index changes on the very commit that adds the catalog) and output\
# included, and such a catalog could never validate a fresh clone; given a
# list of files it records only their names, and the tree holds several
# README.md and example.psd1. One rooted export is the shape that works.
Write-Host "[-] Generating catalog $catalogPath from the tracked tree..." -ForegroundColor Cyan
$tree = Export-TPCatalogTree
try {
    try {
        $catResult = New-FileCatalog -Path $tree -CatalogFilePath $catalogPath `
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

    # Verify, over the same exported tree the catalog was built from, and the
    # catalog's own signature by the certificate that just signed it.
    Write-Host "[-] Verifying..." -ForegroundColor Cyan
    $verify = Test-FileCatalog -CatalogFilePath $catalogPath -Path $tree -Detailed
    Assert-TPCatalogSignature -Catalog $verify -ExpectedThumbprint $cert.Thumbprint
    if ($verify.Status -eq 'Valid') {
        Write-Host "  [+] Test-FileCatalog: Valid" -ForegroundColor Green
    } else {
        throw "Test-FileCatalog returned: $($verify.Status)"
    }
} finally {
    Remove-Item -LiteralPath $tree -Recurse -Force -ErrorAction SilentlyContinue
}

} catch {
    $restored = Restore-TPUnsignedBytes -Map $originals
    $restoredGenerated = Restore-TPGeneratedFiles -Snapshot $generatedSnapshot
    throw "Release signing failed after the scripts were signed ($($_.Exception.Message)); the unsigned bytes of $restored file(s) and the prior state of $restoredGenerated generated file(s) (integrity manifest, FILES.sha256, catalog) were restored, so the tree is as it was and the run can be repeated."
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Release signing complete." -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
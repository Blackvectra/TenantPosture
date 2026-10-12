#Requires -Version 7.0
<#
.SYNOPSIS
    Verifies integrity of the NRG Assessment Tool against a published manifest.

.DESCRIPTION
    Computes SHA-256 hashes of every PS1, PSM1, PSD1, and JSON file in the repo
    (excluding output/, .git/, .github/) and compares against tools/integrity-manifest.txt.

    In an extracted release there is no tools/integrity-manifest.txt (the release
    workflow leaves it out: it hashes the whole repository tree, tests included, and
    would report every file the archive omits as missing) but there is FILES.sha256,
    the archive's own record of every packaged file. When FILES.sha256 is present at
    the root and -ManifestPath was not given, every file under the root is verified
    against it (FILES.sha256 itself and output/ excepted), a file the record does not
    name fails the verification, and a repository manifest that has appeared beside
    it is ignored.

    Returns exit 0 if all files match, 1 if any mismatch or missing file.

.PARAMETER ManifestPath
    Path to the integrity manifest. Default: tools\integrity-manifest.txt.

.PARAMETER Update
    Regenerate the manifest. Use only when releasing.

.EXAMPLE
    .\tools\Verify-Integrity.ps1
.EXAMPLE
    .\tools\Verify-Integrity.ps1 -Update
.EXAMPLE
    .\tools\Verify-Integrity.ps1 -Update -PathList (git ls-files '*.ps1' '*.psm1' '*.psd1' '*.json')
#>

[CmdletBinding()]
param(
    [ValidateScript({
        if ($_ -match '\.\.[\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $ManifestPath = (Join-Path $PSScriptRoot 'integrity-manifest.txt'),

    [switch] $Update,

    # With -Update only: the repository-relative paths (forward slashes) to hash,
    # instead of walking the folder. Build/Sign-Release.ps1 passes the tracked
    # files, so an ignored or untracked local script never enters the manifest.
    # (Not named -Files: variable names are case-insensitive and $files is the
    # walked list below.)
    [string[]] $PathList
)

# Terminating throughout: an unreadable file must stop a manifest refresh
# (a shorter manifest would verify clean against the files it names), and a
# hash that cannot be computed is a failed verification, not a skipped file.
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $repoRoot) { $repoRoot = (Get-Location).Path }

$includeExtensions = @('.ps1', '.psm1', '.psd1', '.json')

# Extracted release: the archive's FILES.sha256 is at the root. Its presence alone
# selects archive mode (unless -ManifestPath was given explicitly): a repository
# manifest that has appeared beside it does not switch the mode, because in a tree
# an attacker can write, an injected tools/integrity-manifest.txt (even an empty one)
# would otherwise turn every packaged file into a tolerated extra and exit 0 without
# a single hash checked. Build/Sign-Release.ps1 passes -ManifestPath for the
# repository manifest on purpose.
$archiveManifest = Join-Path $repoRoot 'FILES.sha256'
$archiveMode = (-not $PSBoundParameters.ContainsKey('ManifestPath')) -and
               (Test-Path -LiteralPath $archiveManifest -PathType Leaf)
if ($archiveMode) {
    if ($Update) { throw 'FILES.sha256 is written by the release workflow from the packaged tree; -Update regenerates the repository manifest and does not apply to an extracted release.' }
    $ManifestPath = $archiveManifest
    Write-Host "  [i] FILES.sha256 is present: verifying the extracted release against it (every packaged file)." -ForegroundColor Cyan
}

# Separators are matched either way: the repository manifest is read on
# whatever workstation the operator uses. Only the manifest being read is left
# out, by its exact path: a prefix match would also have hidden a planted
# tools\integrity-manifest-evil.ps1 from the extra-file check.
$manifestFull = if (Test-Path -LiteralPath $ManifestPath) { (Resolve-Path -LiteralPath $ManifestPath).ProviderPath } else { $ManifestPath }
# Archive mode leaves out only the root output\ folder (what the tool itself
# writes) and the manifests, never a folder by name anywhere in the tree: the
# module loader runs every *.ps1 under Lib, Collectors, Evaluators and
# Publishers, so a script planted at Lib\output\evil.ps1 or Lib\.github\x.ps1
# must reach the extra-file check. The repository mode keeps its folder
# exclusions: there, extras are reported, not failed.
# -Force: PowerShell treats a dot-prefixed name as hidden on Linux and macOS,
# and a hidden folder is where a planted script would hide from a walk.
$rootOutput = (Join-Path $repoRoot 'output') + [string][System.IO.Path]::DirectorySeparatorChar
$files = Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Force -ErrorAction Stop |
    Where-Object {
        if ($archiveMode) {
            (-not $_.FullName.StartsWith($rootOutput, [System.StringComparison]::Ordinal)) -and
            $_.FullName -ne $manifestFull -and
            $_.FullName -ne $archiveManifest
        } else {
            $_.Extension -in $includeExtensions -and
            $_.FullName -notmatch '[\\/]output[\\/]' -and
            $_.FullName -notmatch '[\\/]\.git[\\/]' -and
            $_.FullName -notmatch '[\\/]\.github[\\/]' -and
            $_.FullName -ne $manifestFull -and
            $_.FullName -ne $archiveManifest
        }
    } |
    Sort-Object FullName

if ($PathList -and -not $Update) { throw '-PathList applies to -Update only; verification always walks the folder.' }
if ($Update -and $PathList) {
    $files = @($PathList | Where-Object { $_ } | Sort-Object -Unique | ForEach-Object {
        $full = Join-Path $repoRoot ($_ -replace '/', [string][System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Listed file '$_' does not exist under $repoRoot; the manifest was not written." }
        Get-Item -LiteralPath $full
    } | Sort-Object FullName)
}

if ($Update) {
    Write-Host "Generating integrity manifest..." -ForegroundColor Cyan
    $entries = @(foreach ($f in $files) {
        $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        if (-not $hash) { throw "No hash was computed for $($f.FullName); the manifest was not written." }
        $relPath = $f.FullName.Substring($repoRoot.Length + 1).Replace('\','/')
        "$hash  $relPath"
    })
    if ($entries.Count -ne $files.Count) { throw "Hashed $($entries.Count) of $($files.Count) files; the manifest was not written." }
    $header = @(
        "# NRG Assessment Tool - Integrity Manifest"
        "# Algorithm: SHA-256"
        "# Generated: $(Get-Date -Format 'o')"
        "# Files: $($files.Count)"
        "#"
    )
    # LF line endings whatever the platform: Out-File would write CRLF on Windows,
    # git normalizes the committed text to LF, and a catalog or hash computed over
    # the CRLF bytes would not describe the file a fresh clone carries.
    [System.IO.File]::WriteAllText($ManifestPath, ((@($header) + @($entries)) -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    # Read it back: the file on disk must carry every entry, or the refresh failed.
    $written = @(Get-Content -LiteralPath $ManifestPath -ErrorAction Stop | Where-Object { $_ -and -not $_.StartsWith('#') })
    if ($written.Count -ne $files.Count) { throw "The manifest at $ManifestPath holds $($written.Count) entries for $($files.Count) files." }
    Write-Host "  [+] Wrote $($files.Count) entries to $ManifestPath" -ForegroundColor Green
    return
}

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    Write-Host "  [!] Manifest not found at $ManifestPath" -ForegroundColor Red
    Write-Host "      Generate with: .\tools\Verify-Integrity.ps1 -Update" -ForegroundColor Yellow
    exit 1
}

# Ordinal keys: a recorded path is exact. A PowerShell hashtable compares keys
# without case, so on a case-sensitive file system a file renamed only by case
# (Lib/Foo.ps1 to lib/foo.ps1) would still match its entry and verify clean
# while the module could no longer load it.
$expected = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
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
    $hash    = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not $expected.ContainsKey($relPath)) {
        $extras += $relPath
        continue
    }
    if ($expected[$relPath] -ne $hash) {
        $mismatches += [pscustomobject]@{ Path=$relPath; Expected=$expected[$relPath]; Actual=$hash }
    }
    $expected.Remove($relPath)
}
# An array, not the live key collection: an empty collection is still truthy, which printed the
# MISSING FILES heading under a clean verification.
$missing = @($expected.Keys)

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
    # In an extracted release a file the record does not name is a failure, not a
    # curiosity: a .ps1 added under Lib/ is dot-sourced by the module on import. In a
    # repository checkout new files precede the next manifest refresh and are reported.
    if ($archiveMode) {
        Write-Host "FILES NOT IN THE RELEASE RECORD (on disk, absent from FILES.sha256; an added file is a failure):" -ForegroundColor Red
        $extras | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    } else {
        Write-Host "EXTRA FILES (on disk, not in manifest):" -ForegroundColor Yellow
        $extras | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    }
}

if ($mismatches.Count -eq 0 -and $missing.Count -eq 0 -and (-not $archiveMode -or $extras.Count -eq 0)) {
    Write-Host "  [+] Integrity verified." -ForegroundColor Green
    exit 0
} else {
    Write-Host "  [!] Integrity check FAILED." -ForegroundColor Red
    exit 1
}
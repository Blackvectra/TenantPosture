#Requires -Version 7.0
<#
.SYNOPSIS
    Installs a CI module by exact version, refusing the package unless its
    SHA-256 matches tools/pinned-modules.psd1.

.DESCRIPTION
    The gallery install cmdlets take whatever the gallery serves for a version
    range and check no hash, so a republished or substituted package
    would run in CI with the job's token. This script downloads the .nupkg for
    the pinned version, compares its SHA-256 with the pin (ordinal, before
    anything is extracted), and extracts it to <Destination>/<Name>/<Version>,
    refusing any entry that would land outside that folder. NuGet packaging
    metadata is not extracted.

    With -ExportToGitHubEnv the destination is put first on PSModulePath for
    the later steps of the job, through $GITHUB_ENV.

    TenantPosture — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Data: tools/pinned-modules.psd1 (read). Network: www.powershellgallery.com.

.PARAMETER Name
    One or more module names from the pin file.

.PARAMETER Destination
    The folder the modules are extracted under. Default: <temp>/tp-pinned-modules.

.PARAMETER PackagePath
    A local .nupkg used in place of the download (one Name only). The hash is
    checked exactly as for a download; the tests use this.

.PARAMETER DefinitionsOnly
    Defines the functions and does nothing else (for the tests).
#>
[CmdletBinding()]
param(
    [ValidatePattern('\A[A-Za-z][A-Za-z0-9.]{1,63}\z')]
    [string[]] $Name,

    [ValidateNotNullOrEmpty()]
    [string] $Destination = (Join-Path ([System.IO.Path]::GetTempPath()) 'tp-pinned-modules'),

    [ValidateNotNullOrEmpty()]
    [string] $PinFile = (Join-Path $PSScriptRoot 'pinned-modules.psd1'),

    [string] $PackagePath,

    [switch] $ExportToGitHubEnv,

    [switch] $DefinitionsOnly
)

# Reads one pin and refuses a malformed one: a version range or a short hash
# would turn the pin back into "whatever the gallery serves".
function Get-TPModulePin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $PinFile
    )
    Set-StrictMode -Version Latest
    $pins = Import-PowerShellDataFile -LiteralPath $PinFile
    if (-not $pins.ContainsKey($Name)) { throw "No pin for module '$Name' in $PinFile." }
    $pin = $pins[$Name]
    $version = [string]$pin['Version']
    $sha = [string]$pin['Sha256']
    if ($version -cnotmatch '\A\d+\.\d+\.\d+\z') { throw "Pin for '$Name' has version '$version'; an exact x.y.z version is required." }
    if ($sha -cnotmatch '\A[0-9a-f]{64}\z') { throw "Pin for '$Name' has no 64-character lower-case SHA-256." }
    [pscustomobject]@{ Name = $Name; Version = $version; Sha256 = $sha }
}

# Compares the package with the pin before anything in it is read.
function Test-TPPackageHash {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Sha256
    )
    Set-StrictMode -Version Latest
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    return [string]::Equals($actual, $Sha256, [System.StringComparison]::OrdinalIgnoreCase)
}

# Extracts the package into $Target. Every entry must resolve inside $Target
# (no "..", no rooted name); the NuGet metadata is skipped.
function Expand-TPModulePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Target
    )
    Set-StrictMode -Version Latest
    $root = [System.IO.Path]::GetFullPath($Target).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        foreach ($entry in $zip.Entries) {
            $rel = $entry.FullName
            if ($rel -ceq '[Content_Types].xml' -or $rel.StartsWith('_rels/') -or $rel.StartsWith('package/') -or ($rel -notmatch '/' -and $rel.EndsWith('.nuspec'))) { continue }
            $dest = [System.IO.Path]::GetFullPath((Join-Path $root ([Uri]::UnescapeDataString($rel))))
            if (-not $dest.StartsWith($root, [System.StringComparison]::Ordinal)) {
                throw "Package entry '$rel' resolves outside $root; the package was refused."
            }
            # Directory.CreateDirectory takes the path literally (no wildcards).
            if ($rel.EndsWith('/')) { $null = [System.IO.Directory]::CreateDirectory($dest); continue }
            $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($dest))
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
        }
    } finally {
        $zip.Dispose()
    }
}

# Downloads (or takes) the package, checks it, and installs it. Returns the
# folder holding the module manifest.
function Install-TPModulePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Pin,
        [Parameter(Mandatory)] [string] $Destination,
        [string] $PackagePath
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $nupkg = if ($PackagePath) { $PackagePath } else { Join-Path ([System.IO.Path]::GetTempPath()) ('{0}.{1}.{2}.nupkg' -f $Pin.Name, $Pin.Version, [guid]::NewGuid().ToString('N')) }
    try {
        if (-not $PackagePath) {
            $uri = 'https://www.powershellgallery.com/api/v2/package/{0}/{1}' -f $Pin.Name, $Pin.Version
            $delays = @(2, 4, 8)
            for ($i = 0; ; $i++) {
                try { Invoke-WebRequest -Uri $uri -OutFile $nupkg -UseBasicParsing -ErrorAction Stop; break }
                catch {
                    if ($i -ge $delays.Count) { throw }
                    Write-Host ('Download of {0} failed ({1}); retrying in {2}s.' -f $Pin.Name, $_.Exception.Message, $delays[$i])
                    Start-Sleep -Seconds $delays[$i]
                }
            }
        }
        if (-not (Test-TPPackageHash -Path $nupkg -Sha256 $Pin.Sha256)) {
            throw ("{0} {1}: the package's SHA-256 does not match tools/pinned-modules.psd1; refused, nothing installed." -f $Pin.Name, $Pin.Version)
        }
        $target = Join-Path (Join-Path $Destination $Pin.Name) $Pin.Version
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
        Expand-TPModulePackage -Path $nupkg -Target $target
        if (-not (Test-Path -LiteralPath (Join-Path $target "$($Pin.Name).psd1"))) {
            throw ("{0} {1}: no module manifest after extraction." -f $Pin.Name, $Pin.Version)
        }
        return $target
    } finally {
        if (-not $PackagePath -and (Test-Path -LiteralPath $nupkg)) { Remove-Item -LiteralPath $nupkg -Force }
    }
}

if ($DefinitionsOnly) { return }

$ErrorActionPreference = 'Stop'
if (-not $Name) { throw 'Name one or more modules from the pin file.' }
if ($PackagePath -and $Name.Count -ne 1) { throw '-PackagePath takes exactly one -Name.' }
$null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetFullPath($Destination))
foreach ($n in $Name) {
    $pin = Get-TPModulePin -Name $n -PinFile $PinFile
    $installed = Install-TPModulePackage -Pin $pin -Destination $Destination -PackagePath $PackagePath
    Write-Host ('{0} {1} installed at {2} (SHA-256 verified).' -f $pin.Name, $pin.Version, $installed)
}
if ($ExportToGitHubEnv) {
    if (-not $env:GITHUB_ENV) { throw '-ExportToGitHubEnv needs GITHUB_ENV (a GitHub Actions job).' }
    $full = [System.IO.Path]::GetFullPath($Destination)
    Add-Content -LiteralPath $env:GITHUB_ENV -Value ('PSModulePath={0}{1}{2}' -f $full, [System.IO.Path]::PathSeparator, $env:PSModulePath) -Encoding utf8
}

#Requires -Version 7.0
<#
.SYNOPSIS
    Reports every PowerShell module in tools/pinned-modules.psd1 that has a
    newer stable release on the PowerShell Gallery.

.DESCRIPTION
    Dependabot keeps the Actions, the Python tools and the scanner image's
    base digest current, but it cannot read the PowerShell Gallery, so the
    pinned modules (Pester, PSScriptAnalyzer, InjectionHunter, Pode) would age
    silently. This check asks the gallery for each module's latest stable
    version and exits 1 when one is newer than the pin and has been public
    for at least -CooldownDays (the same seven days Dependabot waits), naming
    the edit to make. A release younger than that is listed and not failed.

    It changes nothing: the bump stays a deliberate edit of the version and its
    hash together, checked by tools/Install-TPPinnedModule.ps1.

    TenantPosture — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Data: tools/pinned-modules.psd1 (read). Network: www.powershellgallery.com.

.PARAMETER CooldownDays
    How long a release must have been public before it counts. Default 7.

.PARAMETER DefinitionsOnly
    Defines the functions and does nothing else (for the tests).
#>
[CmdletBinding()]
param(
    [ValidateRange(0, 365)]
    [int] $CooldownDays = 7,

    [ValidateNotNullOrEmpty()]
    [string] $PinFile = (Join-Path $PSScriptRoot 'pinned-modules.psd1'),

    [switch] $DefinitionsOnly
)

# The stable releases of one module from a gallery feed response, as
# { Version; Published }. The feed is filtered by id on the server, but only
# an entry whose title is the module's own name counts, and a version or date
# that does not parse is dropped rather than guessed.
function Get-TPGalleryReleases {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Entries
    )
    Set-StrictMode -Version Latest
    $text = { param($v) if ($v -is [System.Xml.XmlElement]) { $v.InnerText } else { [string]$v } }
    foreach ($e in @($Entries | Where-Object { $null -ne $_ })) {
        if (-not [string]::Equals((& $text $e.title), $Name, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $p = $e.properties
        if ((& $text $p.IsPrerelease) -eq 'true') { continue }
        $ver = $null
        if (-not [version]::TryParse((& $text $p.Version), [ref]$ver)) { continue }
        $when = [datetime]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if (-not [datetime]::TryParse((& $text $p.Published), [cultureinfo]::InvariantCulture, $styles, [ref]$when)) { continue }
        [pscustomobject]@{ Version = $ver; Published = $when }
    }
}

# The verdict for one module. Only releases public for at least $CooldownDays
# count. Newer: a counted release in the pinned major version is newer than the
# pin (fails the check). NewMajor: the only newer counted releases are a later
# major version, which is a migration to plan, not a pin to bump (reported,
# never failed). Current: nothing newer. Unknown: no releases were read.
function Get-TPPinFreshness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Pinned,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Releases,
        [Parameter(Mandatory)] [datetime] $Now,
        [Parameter(Mandatory)] [int] $CooldownDays
    )
    Set-StrictMode -Version Latest
    $row = [ordered]@{ Name = $Name; Pinned = $Pinned; LatestSameMajor = $null; LatestOverall = $null; Status = 'Unknown' }
    $have = $null
    $counted = @($Releases | Where-Object { $null -ne $_ -and ($Now - $_.Published).TotalDays -ge $CooldownDays })
    if (-not [version]::TryParse($Pinned, [ref]$have) -or @($Releases | Where-Object { $null -ne $_ }).Count -eq 0) { return [pscustomobject]$row }
    $sameMajor = @($counted | Where-Object { $_.Version.Major -eq $have.Major } | Sort-Object Version -Descending | Select-Object -First 1)
    $overall = @($counted | Sort-Object Version -Descending | Select-Object -First 1)
    if ($sameMajor.Count -gt 0) { $row.LatestSameMajor = [string]$sameMajor[0].Version }
    if ($overall.Count -gt 0) { $row.LatestOverall = [string]$overall[0].Version }
    $row.Status = if ($sameMajor.Count -gt 0 -and $sameMajor[0].Version -gt $have) { 'Newer' }
                  elseif ($overall.Count -gt 0 -and $overall[0].Version.Major -gt $have.Major) { 'NewMajor' }
                  else { 'Current' }
    [pscustomobject]$row
}

if ($DefinitionsOnly) { return }

$ErrorActionPreference = 'Stop'
$pins = Import-PowerShellDataFile -LiteralPath $PinFile
$now = [datetime]::UtcNow
$rows = @(foreach ($name in ($pins.Keys | Sort-Object)) {
    $releases = @()
    try {
        $filter = [uri]::EscapeDataString(("Id eq '{0}' and IsPrerelease eq false" -f $name))
        $uri = 'https://www.powershellgallery.com/api/v2/Packages()?$filter={0}&$orderby=Published%20desc&$top=40' -f $filter
        $releases = @(Get-TPGalleryReleases -Name $name -Entries @(Invoke-RestMethod -Uri $uri -ErrorAction Stop))
    } catch {
        Write-Host ('{0}: the gallery did not answer ({1}).' -f $name, $_.Exception.Message) -ForegroundColor Yellow
    }
    Get-TPPinFreshness -Name $name -Pinned ([string]$pins[$name]['Version']) -Releases $releases -Now $now -CooldownDays $CooldownDays
})

Write-Host ''
foreach ($r in $rows) {
    Write-Host ('{0,-18} pinned {1,-8} newest same-major {2,-8} newest overall {3,-8} {4}' -f $r.Name, $r.Pinned, ($r.LatestSameMajor ?? '-'), ($r.LatestOverall ?? '-'), $r.Status)
}
Write-Host ''
foreach ($r in @($rows | Where-Object Status -eq 'NewMajor')) {
    Write-Host ("{0}: a new major version ({1}) is available. That is a migration to plan and test, not a pin bump; this check does not fail on it." -f $r.Name, $r.LatestOverall) -ForegroundColor Yellow
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host ("::warning title=New major version::{0} {1} is available (pinned {2})." -f $r.Name, $r.LatestOverall, $r.Pinned) }
}
$newer = @($rows | Where-Object Status -eq 'Newer')
foreach ($r in $newer) {
    Write-Host ("{0} {1} is out of date: {2} has been public for at least {3} days. Update tools/pinned-modules.psd1 with the new version and the SHA-256 of https://www.powershellgallery.com/api/v2/package/{0}/{2}, then run the suites." -f $r.Name, $r.Pinned, $r.LatestSameMajor, $CooldownDays) -ForegroundColor Red
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host ("::error title=Pinned module out of date::{0} {1} is pinned; {2} is available." -f $r.Name, $r.Pinned, $r.LatestSameMajor) }
}
if ($newer.Count -gt 0) { exit 1 }
$unknown = @($rows | Where-Object Status -eq 'Unknown')
if ($unknown.Count -gt 0) {
    Write-Host ('Could not read the releases of: {0}. Not judged; rerun later.' -f (($unknown | ForEach-Object Name) -join ', ')) -ForegroundColor Yellow
    exit 3
}
Write-Host 'Every pinned module is on the newest release of its major version that has been public for the cooldown.' -ForegroundColor Green
exit 0

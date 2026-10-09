#Requires -Version 7.0
#
# Resolve-TPWebRunPath.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The path guard for the local web GUI (Start-TPWebServer). This is the ONLY
# place a request becomes a file path: a route passes the URL segments here and
# serves what comes back, never a path it built itself. It is a file of its own,
# apart from the run listing, so the security-relevant code is small enough to
# read in one sitting and is tested without a server.
#
# A run is addressed by (folder, id). The folder segment is the tenant folder
# name, or the reserved segment Get-TPWebFlatSegment returns for the output
# folder itself (a command-line run writes flat files there). Two layers, each
# tested on its own:
#   1. Every segment is an ASCII whitelist (Test-TPWebSegment), not a list of
#      separators to reject.
#   2. The resolved path is checked lexically: the boundary built from the
#      request must sit inside the output folder, and the file inside the
#      boundary. A symbolic link or junction inside the report folder is
#      refused, and an item that cannot be inspected is refused (fail closed).
#
# Consumed:  Get-TPObjectField (Lib/Get-TPObjectField.ps1)
# Reads:     file system metadata under the output folder only.
# Graph scopes / cmdlets used: none.

# The path segment that stands for "the output folder itself". An underscore
# prefix keeps it out of the set of names the GUI can create for a tenant (the
# scan route accepts only letters, digits, dots and hyphens). Even so a real
# folder with this name is never listed or served as a tenant folder, so the
# segment cannot be ambiguous.
function Get-TPWebFlatSegment {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return '_flat'
}

# One path segment from a URL. A whitelist, not a blacklist of separators: the
# value is joined onto the output folder, so it may carry nothing but a plain
# file or folder name. Letters, digits, dot, underscore and hyphen; the first
# character may not be a dot or hyphen; no "..".
#
# \z, not $: in .NET `$` also matches before a final line feed, so "abc`n" would
# pass a `$`-anchored pattern. -cmatch, not -match: -match is case-insensitive,
# and .NET case folding lets a few non-ASCII characters (the Kelvin sign) through
# a [A-Za-z] class.
function Test-TPWebSegment {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Value)

    if ([string]::IsNullOrEmpty($Value)) { return $false }
    if ($Value.Length -gt 255) { return $false }
    if ($Value.Contains('..')) { return $false }
    return ($Value -cmatch '\A[A-Za-z0-9_][A-Za-z0-9._-]*\z')
}

# $true only when the item can be inspected and is NOT a symbolic link or
# junction. Fail closed: a path that cannot be read (removed in a race, access
# denied) is "not plain", so the caller refuses it rather than serving what it
# could not check.
#
# LinkType is the property PowerShell has carried since 6.0 (LinkTarget, from
# .NET 6, would be absent on older runtimes and make this guard fail open
# without a word), with LinkTarget as a second signal. HardLink is deliberately
# NOT refused: LinkType reports it for every name of a file that has more than
# one, so refusing it would refuse the real file as well. A cloud-sync
# placeholder (OneDrive Files On-Demand) carries the reparse-point attribute but
# is neither a SymbolicLink nor a Junction, so it is served.
function Test-TPWebPathIsPlain {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $false }
    if ([string](Get-TPObjectField -Item $item -Key 'LinkType' -Default '') -in @('SymbolicLink', 'Junction')) { return $false }
    if (-not [string]::IsNullOrEmpty([string](Get-TPObjectField -Item $item -Key 'LinkTarget' -Default ''))) { return $false }
    return $true
}

# The one place a resolution result is built, so a status always carries the
# same HTTP code and message. Status is what the caller decides on; HttpStatus
# and Message are what a route sends. Messages are fixed text, never an echo of
# the request.
function New-TPWebResolution {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateSet('Ok', 'BadRequest', 'NotFound')] [string] $Status,
        [Parameter()] [AllowNull()] [string] $Path
    )

    $http    = @{ Ok = 200; BadRequest = 400; NotFound = 404 }
    $message = @{ Ok = ''; BadRequest = 'Invalid path segment.'; NotFound = 'Not found.' }
    [pscustomobject]@{
        Status     = $Status
        HttpStatus = $http[$Status]
        Message    = $message[$Status]
        Path       = $Path
    }
}

# Resolve one servable file for a run, or say why not. Never throws.
#   -Kind Report    <dir>\<Id>-assessment.html
#   -Kind SitePage  <dir>\<Id>-report\<Page>   (.html or .csv only)
# where <dir> is the tenant folder, or the output folder for the flat segment.
function Resolve-TPWebRunPath {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $OutputRoot,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Folder,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Id,
        [Parameter(Mandatory)] [ValidateSet('Report', 'SitePage')] [string] $Kind,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Page
    )

    Set-StrictMode -Version Latest

    if (-not (Test-TPWebSegment -Value $Folder)) { return (New-TPWebResolution -Status BadRequest) }
    if (-not (Test-TPWebSegment -Value $Id))     { return (New-TPWebResolution -Status BadRequest) }

    $dir = if ($Folder -eq (Get-TPWebFlatSegment)) { $OutputRoot } else { Join-Path $OutputRoot $Folder }
    $boundary = $dir
    switch ($Kind) {
        'Report' {
            $target = Join-Path $dir ($Id + '-assessment.html')
        }
        'SitePage' {
            # Only the pages the report site is made of: an .html page or the
            # ActionPlan.csv. Anything else in the folder is not served.
            if (-not (Test-TPWebSegment -Value $Page)) { return (New-TPWebResolution -Status BadRequest) }
            if ($Page -notmatch '\.(html|csv)\z')       { return (New-TPWebResolution -Status BadRequest) }
            $boundary = Join-Path $dir ($Id + '-report')
            $target   = Join-Path $boundary $Page
        }
    }

    # The boundary is built from the request, so it is pinned first: it must sit
    # inside the output folder (the output folder itself, for the flat layout).
    # Then the file must sit inside the boundary. Checking only the second
    # would let a segment that moved the boundary take the file with it.
    $sep     = [System.IO.Path]::DirectorySeparatorChar
    $alt     = [System.IO.Path]::AltDirectorySeparatorChar
    $cmp     = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    $outFull = [System.IO.Path]::GetFullPath($OutputRoot).TrimEnd($sep, $alt) + $sep
    $root    = [System.IO.Path]::GetFullPath($boundary).TrimEnd($sep, $alt) + $sep
    if (-not $root.StartsWith($outFull, $cmp)) { return (New-TPWebResolution -Status BadRequest) }
    $full = [System.IO.Path]::GetFullPath($target)
    if (-not $full.StartsWith($root, $cmp)) { return (New-TPWebResolution -Status BadRequest) }

    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return (New-TPWebResolution -Status NotFound) }
    # A link inside the report folder could point anywhere, and the tool never
    # creates one. The folder above it (the tenant folder, or the output folder)
    # is the operator's own and may legitimately be a link: people redirect
    # their output folder with a junction, so only the report folder and the
    # file are held to this.
    if (-not (Test-TPWebPathIsPlain -Path $full)) { return (New-TPWebResolution -Status NotFound) }
    if ($Kind -eq 'SitePage' -and -not (Test-TPWebPathIsPlain -Path $boundary)) { return (New-TPWebResolution -Status NotFound) }

    return (New-TPWebResolution -Status Ok -Path $full)
}

#Requires -Version 7.0
#
# Get-NRGWebRunIndex.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Run listing and path resolution for the local web GUI (Start-NRGWebServer).
# Everything here is a pure function over the output folder: no Pode, no
# network, no tenant call. They live in their own file for two reasons.
#   1. Pode runs every route body in a runspace built from a default session
#      state, so module functions are not visible there; Start-NRGWebServer
#      loads this file (and Get-NRGObjectField.ps1) into those runspaces with
#      Use-PodeScript.
#   2. The path guards are the security-relevant part of the server, and they
#      are tested directly here without a server, so CI (which has no Pode)
#      still exercises them.
#
# Two output layouts are listed:
#   - tenant folder: output\<domain>\<base>-results.json  (the GUI and the batch
#     runner write here)
#   - flat:          output\<base>-results.json            (a command-line run)
# A run is addressed by (folder, id), never by a path from the client. The
# folder segment is the tenant folder name, or the reserved segment returned
# by Get-NRGWebFlatSegment for the flat layout.
#
# Consumed:  Get-NRGObjectField (Lib/Get-NRGObjectField.ps1)
# Reads:     ./output/ only: *-results.json (Metadata.TenantDomain),
#            <base>-assessment.html and <base>-report\ (existence and serving)
# Graph scopes / cmdlets used: none.

# The path segment that stands for "the output folder itself". An underscore
# prefix keeps it out of the set of names the GUI can create for a tenant (the
# scan route accepts only letters, digits, dots and hyphens). Even so a real
# folder with this name is never listed or served as a tenant folder, so the
# segment cannot be ambiguous.
function Get-NRGWebFlatSegment {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return '_flat'
}

# Results files that are not tenant assessments and must never be listed:
# incident-response mailbox runs (-email-results.json) and sign-in triage
# (-signin-triage*). Neither has an assessment report to open.
function Test-NRGWebRunResultName {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Name)

    if ($Name -notmatch '-results\.json$') { return $false }
    if ($Name -match '-email-results\.json$') { return $false }
    if ($Name -match '-signin-triage') { return $false }
    return $true
}

# One path segment from a URL. A whitelist, not a blacklist of separators: the
# value is joined onto the output folder, so it may carry nothing but a plain
# file or folder name. Letters, digits, dot, underscore and hyphen; the first
# character may not be a dot or hyphen; no "..".
function Test-NRGWebSegment {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Value)

    if ([string]::IsNullOrEmpty($Value)) { return $false }
    if ($Value.Length -gt 255) { return $false }
    if ($Value.Contains('..')) { return $false }
    # -cmatch: -match is case-insensitive, and .NET case folding lets a few
    # non-ASCII characters (the Kelvin sign) through a [A-Za-z] class.
    return ($Value -cmatch '^[A-Za-z0-9_][A-Za-z0-9._-]*$')
}

# $true when the item is a symbolic link or junction. A cloud-sync placeholder
# (OneDrive Files On-Demand) carries the reparse-point attribute but has no
# LinkTarget, so it is NOT refused; only a real link is.
function Test-NRGWebIsLink {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $false }
    return (-not [string]::IsNullOrEmpty([string](Get-NRGObjectField -Item $item -Key 'LinkTarget' -Default '')))
}

# Resolve one servable file for a run, or say why not. Never throws; the caller
# turns Status into the HTTP response (HttpStatus is already the code).
#   -Kind Report    <dir>\<Id>-assessment.html
#   -Kind SitePage  <dir>\<Id>-report\<Page>   (.html or .csv only)
# where <dir> is the tenant folder, or the output folder for the flat segment.
# Containment is checked twice: the segments are whitelisted so they cannot
# carry a separator, and the resolved full path must still sit inside the
# folder it was meant for.
function Resolve-NRGWebRunPath {
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

    $result = {
        param($Status, $Code, $Message, $Path)
        [pscustomobject]@{ Status = $Status; HttpStatus = $Code; Message = $Message; Path = $Path }
    }
    $bad      = { & $result 'BadRequest' 400 'Invalid path segment.' $null }
    $notFound = { & $result 'NotFound' 404 'Not found.' $null }

    if (-not (Test-NRGWebSegment -Value $Folder)) { return (& $bad) }
    if (-not (Test-NRGWebSegment -Value $Id))     { return (& $bad) }

    $dir = if ($Folder -eq (Get-NRGWebFlatSegment)) { $OutputRoot } else { Join-Path $OutputRoot $Folder }
    $boundary = $dir
    switch ($Kind) {
        'Report' {
            $target = Join-Path $dir ($Id + '-assessment.html')
        }
        'SitePage' {
            # Only the pages the report site is made of: an .html page or the
            # ActionPlan.csv. Anything else in the folder is not served.
            if (-not (Test-NRGWebSegment -Value $Page)) { return (& $bad) }
            if ($Page -notmatch '\.(html|csv)$')        { return (& $bad) }
            $boundary = Join-Path $dir ($Id + '-report')
            $target   = Join-Path $boundary $Page
        }
    }

    # The boundary is built from the request, so it is pinned first: it must sit
    # inside the output folder (the output folder itself, for the flat layout).
    # Then the file must sit inside the boundary. Checking only the second
    # would let a segment that moved the boundary take the file with it.
    $sep  = [System.IO.Path]::DirectorySeparatorChar
    $cmp  = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    $outFull = [System.IO.Path]::GetFullPath($OutputRoot).TrimEnd($sep, [System.IO.Path]::AltDirectorySeparatorChar) + $sep
    $root = [System.IO.Path]::GetFullPath($boundary).TrimEnd($sep, [System.IO.Path]::AltDirectorySeparatorChar) + $sep
    if (-not $root.StartsWith($outFull, $cmp)) { return (& $bad) }
    $full = [System.IO.Path]::GetFullPath($target)
    if (-not $full.StartsWith($root, $cmp)) { return (& $bad) }

    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return (& $notFound) }
    # A link inside the report folder could point anywhere. The tool never
    # creates one, so one here is refused rather than followed.
    if (Test-NRGWebIsLink -Path $full) { return (& $notFound) }
    if ($Kind -eq 'SitePage' -and (Test-NRGWebIsLink -Path $boundary)) { return (& $notFound) }

    return (& $result 'Ok' 200 '' $full)
}

# Tenant domain as recorded in a results file (Metadata.TenantDomain), or ''.
# Only the Metadata object is materialized. A results file holds the whole raw
# inventory, and ConvertFrom-Json on a 15 MB file took 6 s against 0.1 s here;
# the top-level key order is not stable between runs (hashtable order), so the
# head of the file cannot be read instead. Anything unreadable, oversized or not
# a plausible domain returns '' and the caller falls back to the file name.
function Read-NRGWebRunTenantDomain {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)

    Set-StrictMode -Version Latest

    $maxBytes = 128MB
    try {
        if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt $maxBytes) { return '' }
        # FileShare ReadWrite: a scan that is still writing must not make the
        # listing throw.
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $doc = [System.Text.Json.JsonDocument]::Parse($stream)
            try {
                if ($doc.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return '' }
                $el = [System.Text.Json.JsonElement]::new()
                if (-not $doc.RootElement.TryGetProperty('Metadata', [ref]$el)) { return '' }
                if ($el.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return '' }
                $meta = $el.GetRawText() | ConvertFrom-Json -ErrorAction Stop
            } finally { $doc.Dispose() }
        } finally { $stream.Dispose() }

        $domain = [string](Get-NRGObjectField -Item $meta -Key 'TenantDomain' -Default '')
        # 'Unknown' is what a replay of a file with no metadata records.
        if ($domain -match '^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$' -and $domain -ne 'Unknown') { return $domain }
        return ''
    } catch {
        Write-Verbose "Tenant domain not read from $Path : $($_.Exception.Message)"
        return ''
    }
}

# Display label for a flat-layout run: Metadata.TenantDomain when the file has
# it, else the tenant tag in the file name (<tag>-<yyyyMMdd-HHmmss>-results.json;
# the tag is only the first label of the domain). The label is for display; it
# is never used to build a path. -Cache (a synchronized hashtable) keeps the
# answer per file until its length or write time changes, so polling the list
# does not re-read every results file.
function Get-NRGWebRunLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.IO.FileInfo] $File,
        [Parameter()] [AllowNull()] [hashtable] $Cache
    )

    Set-StrictMode -Version Latest

    $key   = $File.FullName
    $stamp = '{0}|{1}' -f $File.Length, $File.LastWriteTimeUtc.Ticks
    if ($null -ne $Cache -and $Cache.ContainsKey($key)) {
        $hit = $Cache[$key]
        if ([string](Get-NRGObjectField -Item $hit -Key 'Stamp' -Default '') -eq $stamp) {
            return [string](Get-NRGObjectField -Item $hit -Key 'Label' -Default '')
        }
    }

    $label = Read-NRGWebRunTenantDomain -Path $File.FullName
    if (-not $label) {
        $tag = $File.BaseName -replace '-results$', ''
        $tag = $tag -replace '-\d{8}-\d{6}$', ''
        if ($tag -match '^\d{8}-\d{6}$') { $tag = '' }
        $tag = ($tag -replace '[\p{C}]', '').Trim()
        if ($tag.Length -gt 253) { $tag = $tag.Substring(0, 253) }
        $label = if ($tag) { $tag } else { '(unknown tenant)' }
    }
    if ($null -ne $Cache) { $Cache[$key] = @{ Stamp = $stamp; Label = $label } }
    return $label
}

# Every assessment run under the output folder, newest first, one row each.
#   id        base name of the run (the file name without -results.json)
#   tenant    display label (folder name, or the label above for a flat run)
#   folder    the address segment the report and site routes take
#   layout    'tenant-folder' | 'flat'
#   timestamp results file write time, yyyy-MM-dd HH:mm:ss
#   sizeKb    results file size
#   hasReport the single-page report exists and the report route would serve it
#   hasSite   the multi-page report site exists and its pages would be served
# hasReport / hasSite come from the same resolver the routes use, so a row is
# only ever offered a link the server will answer.
function Get-NRGWebRunList {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $OutputRoot,
        [Parameter()] [AllowNull()] [hashtable] $LabelCache
    )

    Set-StrictMode -Version Latest

    if (-not (Test-Path -LiteralPath $OutputRoot -PathType Container)) { return @() }

    $flat    = Get-NRGWebFlatSegment
    $entries = [System.Collections.Generic.List[object]]::new()

    foreach ($file in @(Get-ChildItem -LiteralPath $OutputRoot -File -Filter '*-results.json' -ErrorAction SilentlyContinue)) {
        if (Test-NRGWebRunResultName -Name $file.Name) {
            $entries.Add([pscustomobject]@{ File = $file; Folder = $flat; Layout = 'flat'; Label = $null })
        }
    }
    foreach ($dir in @(Get-ChildItem -LiteralPath $OutputRoot -Directory -ErrorAction SilentlyContinue)) {
        # The reserved segment is never a tenant folder.
        if ($dir.Name -eq $flat) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $dir.FullName -File -Filter '*-results.json' -ErrorAction SilentlyContinue)) {
            if (Test-NRGWebRunResultName -Name $file.Name) {
                $entries.Add([pscustomobject]@{ File = $file; Folder = $dir.Name; Layout = 'tenant-folder'; Label = $dir.Name })
            }
        }
    }

    # A list, not `$rows = foreach ...`: a loop that yields nothing assigns
    # $null, and @($null).Count is 1, which would serialize as [null].
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @($entries | Sort-Object { $_.File.LastWriteTime } -Descending)) {
        $file  = $e.File
        $base  = $file.BaseName -replace '-results$', ''
        $label = if ($e.Layout -eq 'flat') { Get-NRGWebRunLabel -File $file -Cache $LabelCache } else { $e.Label }

        $report = Resolve-NRGWebRunPath -OutputRoot $OutputRoot -Folder $e.Folder -Id $base -Kind Report
        $site   = Resolve-NRGWebRunPath -OutputRoot $OutputRoot -Folder $e.Folder -Id $base -Kind SitePage -Page 'index.html'

        $rows.Add([ordered]@{
            id        = $base
            tenant    = $label
            folder    = $e.Folder
            layout    = $e.Layout
            timestamp = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss', [cultureinfo]::InvariantCulture)
            sizeKb    = [int]($file.Length / 1KB)
            hasReport = ($report.Status -eq 'Ok')
            hasSite   = ($site.Status -eq 'Ok')
        })
    }
    return $rows.ToArray()
}

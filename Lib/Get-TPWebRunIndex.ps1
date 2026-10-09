#Requires -Version 7.0
#
# Get-TPWebRunIndex.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The run listing for the local web GUI (Start-TPWebServer): which assessment
# runs exist under the output folder, what to call each, and whether it has a
# report and a report site. Pure functions over files: no Pode, no network, no
# tenant call. The path guard lives apart, in Resolve-TPWebRunPath.ps1; the
# listing asks it whether a link would be served, so a row is only ever offered
# a link the server will answer.
#
# Two output layouts are listed:
#   - tenant folder: output\<domain>\<base>-results.json  (the GUI and the batch
#     runner write here)
#   - flat:          output\<base>-results.json            (a command-line run)
#
# Pode runs every route body in a runspace built from a default session state,
# so module functions are not visible there; Start-TPWebServer loads these
# files into those runspaces with Use-PodeScript.
#
# Consumed:  Get-TPObjectField, Test-TPDomainName, Resolve-TPWebRunPath /
#            Get-TPWebFlatSegment
# Reads:     ./output/ *-results.json (Metadata only) and, optionally,
#            Config/clients.json (to name a flat run the way its client is named)
# Graph scopes / cmdlets used: none.

# Results files that are not tenant assessments and must never be listed:
# incident-response mailbox runs (-email-results.json) and sign-in triage
# (-signin-triage*). Neither has an assessment report to open.
function Test-TPWebRunResultName {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Name)

    if ($Name -notmatch '-results\.json\z') { return $false }
    if ($Name -match '-email-results\.json\z') { return $false }
    if ($Name -match '-signin-triage') { return $false }
    return $true
}

# Metadata.TenantDomain and Metadata.TenantId as recorded in a results file;
# either is '' when absent or not usable. Only the Metadata object is
# materialized: a results file holds the whole raw inventory, and
# ConvertFrom-Json on a 15 MB file took 6 s against 0.1 s here. The top-level key
# order is not stable between runs (hashtable order), so the head of the file
# cannot be read instead. Unreadable or oversized files return empty values and
# the caller falls back to the file name.
function Read-TPWebRunMetadata {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Path)

    Set-StrictMode -Version Latest

    $empty    = [pscustomobject]@{ TenantDomain = ''; TenantId = '' }
    $maxBytes = 128MB
    try {
        if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt $maxBytes) { return $empty }
        # FileShare ReadWrite: a scan that is still writing must not make the
        # listing throw.
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $doc = [System.Text.Json.JsonDocument]::Parse($stream)
            try {
                if ($doc.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return $empty }
                $el = [System.Text.Json.JsonElement]::new()
                if (-not $doc.RootElement.TryGetProperty('Metadata', [ref]$el)) { return $empty }
                if ($el.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return $empty }
                $meta = $el.GetRawText() | ConvertFrom-Json -ErrorAction Stop
            } finally { $doc.Dispose() }
        } finally { $stream.Dispose() }

        $domain = [string](Get-TPObjectField -Item $meta -Key 'TenantDomain' -Default '')
        # Only a domain name is used as a label. 'Unknown', which a replay of a
        # file with no metadata records, is a single label and so is dropped here.
        if (-not (Test-TPDomainName -Value $domain)) { $domain = '' }
        $tenantId = [string](Get-TPObjectField -Item $meta -Key 'TenantId' -Default '')
        $tenantId = if ($tenantId -cmatch '\A[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\z') { $tenantId.ToLowerInvariant() } else { '' }
        return [pscustomobject]@{ TenantDomain = $domain; TenantId = $tenantId }
    } catch {
        Write-Verbose "Metadata not read from $Path : $($_.Exception.Message)"
        return $empty
    }
}

# Read-TPWebRunMetadata, remembered per file until its length or write time
# changes, so polling the list does not re-read every results file. -Cache is a
# synchronized hashtable shared by the server's route runspaces.
function Get-TPWebRunMetadata {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.IO.FileInfo] $File,
        [Parameter()] [AllowNull()] [hashtable] $Cache
    )

    Set-StrictMode -Version Latest

    $key   = $File.FullName
    $stamp = '{0}|{1}' -f $File.Length, $File.LastWriteTimeUtc.Ticks
    if ($null -ne $Cache -and $Cache.ContainsKey($key)) {
        $hit = $Cache[$key]
        if ([string](Get-TPObjectField -Item $hit -Key 'Stamp' -Default '') -eq $stamp) {
            return (Get-TPObjectField -Item $hit -Key 'Metadata')
        }
    }
    $meta = Read-TPWebRunMetadata -Path $File.FullName
    if ($null -ne $Cache) { $Cache[$key] = @{ Stamp = $stamp; Metadata = $meta } }
    return $meta
}

# Config/clients.json as a lookup from what a results file records to the name
# the client is filed under. A GUI or batch run is saved under the client's
# TenantDomain, but a results file records the tenant's INITIAL domain (the
# .onmicrosoft.com one: Connect-TPServices prefers isInitial), so the same
# client would be two names. Keys: "id:<tenant guid>" and "org:<DelegatedOrg>",
# both lowercase. Unreadable or absent: an empty map, and labels fall back to what
# the results file says. Only domain-shaped values are used.
function Get-TPWebClientMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ClientsFile)

    Set-StrictMode -Version Latest

    $map = @{}
    if ([string]::IsNullOrEmpty($ClientsFile) -or -not (Test-Path -LiteralPath $ClientsFile -PathType Leaf)) { return $map }
    try {
        $raw = Get-Content -LiteralPath $ClientsFile -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Verbose "clients.json not read: $($_.Exception.Message)"
        return $map
    }
    foreach ($client in @(Get-TPObjectField -Item $raw -Key 'clients' -Default @())) {
        $domain = [string](Get-TPObjectField -Item $client -Key 'TenantDomain' -Default '')
        if (-not (Test-TPDomainName -Value $domain)) { continue }
        $tenantId = ([string](Get-TPObjectField -Item $client -Key 'TenantId' -Default '')).ToLowerInvariant()
        if ($tenantId -cmatch '\A[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\z') { $map["id:$tenantId"] = $domain }
        $org = ([string](Get-TPObjectField -Item $client -Key 'DelegatedOrg' -Default '')).ToLowerInvariant()
        if (Test-TPDomainName -Value $org) { $map["org:$org"] = $domain }
    }
    return $map
}

# What to call a flat-layout run, most specific first: the client it belongs to
# in clients.json (by tenant id, then by routing domain), else the domain its
# results file records, else the tenant tag in the file name
# (<tag>-<yyyyMMdd-HHmmss>-results.json; the tag is only the first label of the
# domain). A label is for display and is never used to build a path.
function Resolve-TPWebRunLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.IO.FileInfo] $File,
        [Parameter(Mandatory)] [AllowNull()] [object] $Metadata,
        [Parameter()] [AllowNull()] [hashtable] $ClientMap
    )

    Set-StrictMode -Version Latest

    $domain   = [string](Get-TPObjectField -Item $Metadata -Key 'TenantDomain' -Default '')
    $tenantId = [string](Get-TPObjectField -Item $Metadata -Key 'TenantId' -Default '')
    if ($null -ne $ClientMap) {
        if ($tenantId -and $ClientMap.ContainsKey("id:$tenantId")) { return [string]$ClientMap["id:$tenantId"] }
        $orgKey = "org:$($domain.ToLowerInvariant())"
        if ($domain -and $ClientMap.ContainsKey($orgKey)) { return [string]$ClientMap[$orgKey] }
    }
    if ($domain) { return $domain }

    $tag = $File.BaseName -replace '-results\z', ''
    $tag = $tag -replace '-\d{8}-\d{6}\z', ''
    if ($tag -match '\A\d{8}-\d{6}\z') { $tag = '' }
    $tag = ($tag -replace '[\p{C}]', '').Trim()
    if ($tag.Length -gt 253) { $tag = $tag.Substring(0, 253) }
    if ($tag) { return $tag }
    return '(unknown tenant)'
}

# Every assessment run under the output folder, newest first, one row each.
#   id        base name of the run (the file name without -results.json)
#   tenant    display label (folder name, or Resolve-TPWebRunLabel for a flat run)
#   folder    the address segment the report and site routes take
#   layout    'tenant-folder' | 'flat'
#   timestamp results file write time, yyyy-MM-dd HH:mm:ss
#   sizeKb    results file size
#   hasReport the single-page report exists and the report route would serve it
#   hasSite   the multi-page report site exists and its pages would be served
function Get-TPWebRunList {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $OutputRoot,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ClientsFile,
        [Parameter()] [AllowNull()] [hashtable] $MetadataCache
    )

    Set-StrictMode -Version Latest

    if (-not (Test-Path -LiteralPath $OutputRoot -PathType Container)) { return @() }

    $flat    = Get-TPWebFlatSegment
    $entries = [System.Collections.Generic.List[object]]::new()

    foreach ($file in @(Get-ChildItem -LiteralPath $OutputRoot -File -Filter '*-results.json' -ErrorAction SilentlyContinue)) {
        if (Test-TPWebRunResultName -Name $file.Name) {
            $entries.Add([pscustomobject]@{ File = $file; Folder = $flat; Layout = 'flat'; Label = $null })
        }
    }
    foreach ($dir in @(Get-ChildItem -LiteralPath $OutputRoot -Directory -ErrorAction SilentlyContinue)) {
        # The reserved segment is never a tenant folder.
        if ($dir.Name -eq $flat) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $dir.FullName -File -Filter '*-results.json' -ErrorAction SilentlyContinue)) {
            if (Test-TPWebRunResultName -Name $file.Name) {
                $entries.Add([pscustomobject]@{ File = $file; Folder = $dir.Name; Layout = 'tenant-folder'; Label = $dir.Name })
            }
        }
    }

    # Read once per listing, and only when a flat run needs it.
    $clientMap = $null
    if (@($entries | Where-Object { $_.Layout -eq 'flat' }).Count -gt 0) { $clientMap = Get-TPWebClientMap -ClientsFile $ClientsFile }

    # A list, not `$rows = foreach ...`: a loop that yields nothing assigns
    # $null, and @($null).Count is 1, which would serialize as [null].
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @($entries | Sort-Object { $_.File.LastWriteTime } -Descending)) {
        $file  = $e.File
        $base  = $file.BaseName -replace '-results\z', ''
        $label = if ($e.Layout -eq 'flat') {
            Resolve-TPWebRunLabel -File $file -Metadata (Get-TPWebRunMetadata -File $file -Cache $MetadataCache) -ClientMap $clientMap
        } else { $e.Label }

        $report = Resolve-TPWebRunPath -OutputRoot $OutputRoot -Folder $e.Folder -Id $base -Kind Report
        $site   = Resolve-TPWebRunPath -OutputRoot $OutputRoot -Folder $e.Folder -Id $base -Kind SitePage -Page 'index.html'

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

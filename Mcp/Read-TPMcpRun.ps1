#Requires -Version 7.0
#
# Read-TPMcpRun.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose:  Read one assessment results file for the local MCP server
#           (Start-TPMcpServer.ps1), materializing only the parts a tool may
#           use: Metadata, Findings, Coverage, BaselineCompliance, each raw-data
#           key's Success flag and the subscribed SKUs (license profile). The
#           raw inventory, the Exceptions array and the connection record are
#           never materialized, so no tool can return them.
# Consumes: <OutputRoot>/<folder>/<id>-results.json, resolved ONLY by
#           Resolve-TPWebRunPath -Kind Results (the caller passes the path it
#           returned, never one it built).
# Graph scopes / cmdlets used: none. No network, no file write.

# The largest results file read. A real one is a few MB to tens of MB; the
# bound keeps a stray file from exhausting memory in a long-lived process.
function Get-TPMcpMaxResultsBytes {
    [CmdletBinding()]
    [OutputType([long])]
    param()
    return 256MB
}

function ConvertFrom-TPMcpJsonElement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element,
        [switch] $AsHashtable
    )
    $raw = $Element.GetRawText()
    if ($AsHashtable) { return ($raw | ConvertFrom-Json -AsHashtable -Depth 128 -ErrorAction Stop) }
    return ($raw | ConvertFrom-Json -Depth 128 -ErrorAction Stop)
}

# One child element by name, or $null.
function Get-TPMcpJsonChild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element,
        [Parameter(Mandatory)] [string] $Name
    )
    if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return $null }
    $child = [System.Text.Json.JsonElement]::new()
    if ($Element.TryGetProperty($Name, [ref]$child)) { return , $child }
    return $null
}

# Reads the file. Throws with a fixed sentence (never the path) when the file is
# too large, unreadable or not a results object; the caller turns that into a
# tool error.
function Read-TPMcpRunFile {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [string] $Path)

    Set-StrictMode -Version Latest

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.Length -gt (Get-TPMcpMaxResultsBytes)) { throw 'The results file is larger than this server reads.' }

    $run = [ordered]@{
        Metadata           = $null
        Findings           = @()
        Coverage           = $null
        BaselineCompliance = $null
        RawDataStatus      = @{}
        HasRawData         = $false
        SubscribedSkus     = @()
        IsIncidentResponse = $false
    }

    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 256
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $doc = [System.Text.Json.JsonDocument]::Parse($stream, $options)
        try {
            $root = $doc.RootElement
            if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'The file is not an assessment results file.' }

            # Incident-response output is never served (sign-in addresses,
            # geolocation, message metadata).
            if ($null -ne (Get-TPMcpJsonChild -Element $root -Name 'DeepDives')) { $run.IsIncidentResponse = $true; return $run }

            $meta = Get-TPMcpJsonChild -Element $root -Name 'Metadata'
            if ($null -ne $meta -and $meta.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
                $run.Metadata = ConvertFrom-TPMcpJsonElement -Element $meta
            }

            $fe = Get-TPMcpJsonChild -Element $root -Name 'Findings'
            if ($null -ne $fe) {
                if ($fe.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                    $list = [System.Collections.Generic.List[object]]::new()
                    foreach ($f in $fe.EnumerateArray()) {
                        if ($f.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) { $list.Add((ConvertFrom-TPMcpJsonElement -Element $f)) }
                    }
                    $run.Findings = $list.ToArray()
                } elseif ($fe.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
                    $run.Findings = @(ConvertFrom-TPMcpJsonElement -Element $fe)
                }
            }
            foreach ($f in @($run.Findings)) {
                if ([string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '') -match '\A(EMAIL|SIGNIN)-') { $run.IsIncidentResponse = $true; return $run }
            }

            $ce = Get-TPMcpJsonChild -Element $root -Name 'Coverage'
            if ($null -ne $ce -and $ce.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
                $run.Coverage = ConvertFrom-TPMcpJsonElement -Element $ce -AsHashtable
            }

            $be = Get-TPMcpJsonChild -Element $root -Name 'BaselineCompliance'
            if ($null -ne $be -and $be.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
                $run.BaselineCompliance = ConvertFrom-TPMcpJsonElement -Element $be
            }

            # Raw data: only whether each collector succeeded, and the SKUs.
            $re = Get-TPMcpJsonChild -Element $root -Name 'RawData'
            if ($null -ne $re -and $re.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
                foreach ($p in $re.EnumerateObject()) {
                    $entry = @{}
                    $ok = Get-TPMcpJsonChild -Element $p.Value -Name 'Success'
                    if ($null -ne $ok) {
                        if ($ok.ValueKind -eq [System.Text.Json.JsonValueKind]::True)  { $entry['Success'] = $true }
                        if ($ok.ValueKind -eq [System.Text.Json.JsonValueKind]::False) { $entry['Success'] = $false }
                    }
                    $run.RawDataStatus[$p.Name] = $entry
                }
                $run.HasRawData = ($run.RawDataStatus.Count -gt 0)
                $inv = Get-TPMcpJsonChild -Element $re -Name 'AAD-Inventory'
                $data = if ($null -ne $inv) { Get-TPMcpJsonChild -Element $inv -Name 'Data' } else { $null }
                $skus = if ($null -ne $data) { Get-TPMcpJsonChild -Element $data -Name 'SubscribedSkus' } else { $null }
                if ($null -ne $skus -and $skus.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                    $run.SubscribedSkus = @(ConvertFrom-TPMcpJsonElement -Element $skus | Where-Object { $null -ne $_ })
                }
            }
        } finally { $doc.Dispose() }
    } finally { $stream.Dispose() }
    return $run
}

# Read-TPMcpRunFile, remembered per file until its length or write time
# changes. A handful of runs is kept; the server is a long-lived process.
function Get-TPMcpRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [hashtable] $Cache
    )
    $file  = Get-Item -LiteralPath $Path -ErrorAction Stop
    $stamp = '{0}|{1}|{2}' -f $file.FullName, $file.Length, $file.LastWriteTimeUtc.Ticks
    if ($Cache.ContainsKey($stamp)) { return $Cache[$stamp] }
    $run = Read-TPMcpRunFile -Path $file.FullName
    if ($Cache.Count -ge 4) { $Cache.Clear() }
    $Cache[$stamp] = $run
    return $run
}

# One field of a materialized object, with an array kept an array.
# Get-TPObjectField returns through the pipeline, which unrolls a one-element
# array into its element (FrameworkIds of one citation became a string); this
# reader does not. Absent fields return $null, as under StrictMode they must.
function Get-TPMcpField {
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [object] $Item,
        [Parameter(Mandatory)] [string] $Key
    )
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) {
        if ($Item.Contains($Key)) { return , $Item[$Key] }
        return $null
    }
    $p = $Item.PSObject.Properties[$Key]
    if ($null -ne $p) { return , $p.Value }
    return $null
}

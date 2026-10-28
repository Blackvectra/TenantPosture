#Requires -Version 7.0
#
# Read-TPRunRecord.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Read one saved assessment results file for the offline MSP
#   deliverables (the fleet dashboard and the proof of fix), keeping only what
#   they render: Metadata, each finding's ControlId / State / Severity / Title /
#   CurrentValue / RequiredValue / Category, and the BaselineCompliance block.
#   RawData, Exceptions, Connections and every finding's Detail and
#   AffectedObjects are never materialized, so they cannot reach an output.
#   An incident-response file (DeepDives, EMAIL-* / SIGNIN-* findings) is
#   flagged and carries nothing else.
#
#   A JsonDocument is parsed once and only the needed elements are turned into
#   objects: a results file holds the whole raw inventory (tens of MB), and the
#   fleet dashboard reads every run in the output folder.
#
# Data consumed: <name>-results.json written by Invoke-TPAssessment.ps1.
# Data set: none. Graph scopes / cmdlets used: none. No network, no write.

function Get-TPRunRecordMaxBytes {
    [CmdletBinding()]
    [OutputType([long])]
    param()
    return 256MB
}

# The finding fields the offline deliverables render. Detail is not among them:
# it can name users and objects, and none of these outputs needs it.
function Get-TPRunRecordFindingFields {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @('ControlId', 'State', 'Severity', 'Title', 'Category', 'CurrentValue', 'RequiredValue')
}

function Read-TPRunRecord {
    <#
    .SYNOPSIS
        Reads a results JSON file for an offline deliverable: Metadata, a
        trimmed finding list and BaselineCompliance, plus (with -Hash) the
        SHA-256 of the exact bytes on disk.
    .DESCRIPTION
        Throws a fixed sentence (never the content) when the file is too large,
        is not JSON, or is not a results object. Returns IsIncidentResponse =
        $true, and nothing else, for an incident-response output.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [switch] $Hash,
        # Also materialize the Conditional Access and Intune checklists, trimmed
        # to each row's id, area, title, reason, severity, status and the
        # recommended change (never a row's detail, items, policy names or the
        # report-only policy bodies), for the client security review.
        [switch] $IncludeChecklists
    )

    Set-StrictMode -Version Latest

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item -isnot [System.IO.FileInfo]) { throw 'The results path is not a file.' }
    if ($item.Length -gt (Get-TPRunRecordMaxBytes)) { throw 'The results file is larger than this tool reads.' }

    $record = [ordered]@{
        FileName           = $item.Name
        FileWriteTimeUtc   = $item.LastWriteTimeUtc
        FileBytes          = $item.Length
        Sha256             = ''
        Metadata           = $null
        Findings           = @()
        BaselineCompliance = $null
        IsIncidentResponse = $false
        DroppedFindings    = 0
        CAChecklist        = $null
        IntuneChecklist    = $null
    }

    $fields = Get-TPRunRecordFindingFields
    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 256
    $stream = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($Hash) {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try { $record.Sha256 = [System.Convert]::ToHexString($sha.ComputeHash($stream)).ToLowerInvariant() } finally { $sha.Dispose() }
            $null = $stream.Seek(0, [System.IO.SeekOrigin]::Begin)
        }
        try {
            $doc = [System.Text.Json.JsonDocument]::Parse($stream, $options)
        } catch {
            throw 'The results file is not valid JSON.'
        }
        try {
            $root = $doc.RootElement
            if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'The file is not an assessment results file.' }
            $el = [System.Text.Json.JsonElement]::new()

            if ($root.TryGetProperty('DeepDives', [ref]$el)) { $record.IsIncidentResponse = $true; return $record }

            if ($root.TryGetProperty('Metadata', [ref]$el) -and $el.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
                $record.Metadata = $el.GetRawText() | ConvertFrom-Json -Depth 64 -ErrorAction Stop
            }

            if ($root.TryGetProperty('Findings', [ref]$el)) {
                $items = if ($el.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) { @($el.EnumerateArray()) }
                         elseif ($el.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) { @($el) }
                         else { @() }
                $list = [System.Collections.Generic.List[object]]::new()
                foreach ($f in $items) {
                    if ($f.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { continue }
                    $row = [ordered]@{}
                    foreach ($name in $fields) {
                        $v = [System.Text.Json.JsonElement]::new()
                        if (-not $f.TryGetProperty($name, [ref]$v)) { continue }
                        $row[$name] = switch ($v.ValueKind) {
                            ([System.Text.Json.JsonValueKind]::String) { $v.GetString() }
                            ([System.Text.Json.JsonValueKind]::Null)   { $null }
                            ([System.Text.Json.JsonValueKind]::Undefined) { $null }
                            default { $v.GetRawText() | ConvertFrom-Json -Depth 32 -ErrorAction Stop }
                        }
                    }
                    $cid = [string](Get-TPObjectField -Item $row -Key 'ControlId' -Default '')
                    if ($cid -match '\A(EMAIL|SIGNIN)-') { $record.IsIncidentResponse = $true; $record.Metadata = $null; $record.Findings = @(); return $record }
                    # Add-TPFinding's ControlId rule: a file is input, and a value that
                    # is not a control ID never reaches a rendered table.
                    if ($cid -cnotmatch '\A[A-Z]{2,8}-\d+\.\d+\z') { $record.DroppedFindings++; continue }
                    $list.Add([pscustomobject]$row)
                }
                $record.Findings = $list.ToArray()
            }

            if ($root.TryGetProperty('BaselineCompliance', [ref]$el) -and $el.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
                $record.BaselineCompliance = $el.GetRawText() | ConvertFrom-Json -Depth 64 -ErrorAction Stop
            }

            if ($IncludeChecklists) {
                foreach ($key in 'CAChecklist', 'IntuneChecklist') {
                    if (-not ($root.TryGetProperty($key, [ref]$el) -and $el.ValueKind -eq [System.Text.Json.JsonValueKind]::Object)) { continue }
                    $full = $el.GetRawText() | ConvertFrom-Json -Depth 64 -ErrorAction Stop
                    $keep = @('Id', 'Kind', 'Area', 'Title', 'Why', 'Severity', 'Status', 'Recommended', 'SourceUrl', 'LicenseRequirement')
                    $rows = @(@(Get-TPObjectField -Item $full -Key 'Rows' -Default @()) | Where-Object { $null -ne $_ } | ForEach-Object {
                            $src = $_; $r = [ordered]@{}
                            foreach ($k in $keep) { $r[$k] = [string](Get-TPObjectField -Item $src -Key $k -Default '') }
                            if ($r.Id -cmatch '\A(MT\.\d{4}|TP-[A-Z-]{1,30})\z') { [pscustomobject]$r }
                        })
                    $record[$key] = [ordered]@{
                        Available       = [bool](Get-TPObjectField -Item $full -Key 'Available' -Default $false)
                        Rows            = $rows
                        SecurityDefaults = (Get-TPObjectField -Item $full -Key 'SecurityDefaults' -Default $null)
                        MaesterReference = [string](Get-TPObjectField -Item $full -Key 'MaesterReference' -Default '')
                    }
                }
            }
        } finally { $doc.Dispose() }
    } finally { $stream.Dispose() }
    return $record
}

# When the run was made: Metadata.AssessmentTime (UTC), else $null. The file's
# write time is a different fact (a copy or a republish moves it) and is never
# substituted here; a caller that falls back to it says so.
function Get-TPRunRecordTime {
    [CmdletBinding()]
    param([AllowNull()] [object] $Record)
    $meta = Get-TPObjectField -Item $Record -Key 'Metadata' -Default $null
    return (ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $meta -Key 'AssessmentTime' -Default $null))
}

# What kind of run a results file records: 'Full', 'Partial' (-ControlId /
# -ExcludeControlId) or 'Quick' (-Quick, Critical and High only). Only a Full
# run describes the whole tenant.
function Get-TPRunScope {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [object] $Metadata)
    $sel = Get-TPObjectField -Item $Metadata -Key 'ControlSelection' -Default $null
    if ($null -ne $sel -and [bool](Get-TPObjectField -Item $sel -Key 'Partial' -Default $true)) { return 'Partial' }
    if ([bool](Get-TPObjectField -Item $Metadata -Key 'QuickScan' -Default $false)) { return 'Quick' }
    return 'Full'
}

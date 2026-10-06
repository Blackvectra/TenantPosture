#Requires -Version 7.0
#
# Get-NRGObjectField.ps1  (v4.10.1)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Shape-agnostic field reader that works against hashtables,
#          OrderedDictionaries, and PSCustomObjects under StrictMode without
#          throwing on missing keys. Returns the field value or the supplied
#          default. Created to consolidate the two inline copies in
#          Get-NRGMaturityTier.ps1 (Read-FindingField nested function) and
#          Publish-NRGDeltaReport.ps1 ($getBag scriptblock).
#
# Inputs:  -Item   any object or $null (PSCustomObject from ConvertFrom-Json,
#                  hashtable from live runs, ordered hashtable from metadata,
#                  Synchronized hashtable for module-scope state).
#          -Key    string key/property name to read.
#          -Default value returned when Item is $null, the key is absent, or
#                   the read throws. Default is $null.
#
# Outputs: The field value, or -Default. Never throws.
#
# Why a new helper vs extending Get-NRGSafeProperty:
#   Get-NRGSafeProperty (Lib/Add-NRGFinding.ps1) is property-only — it reads
#   PSObject.Properties and returns Default for hashtables. Six+ evaluators
#   call it with PSCustomObject collector results and depend on that
#   property-only behavior. Adding dictionary support there would silently
#   change behavior in those evaluators. A new sibling helper with explicit
#   IDictionary handling is the surgical move.

function Get-NRGObjectField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()]
        [object] $Item,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $Key,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object] $Default = $null
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($null -eq $Item) { return $Default }

    try {
        # [hashtable], [OrderedDictionary], Synchronized hashtable, and any
        # custom IDictionary implementation all flow through this branch.
        if ($Item -is [System.Collections.IDictionary]) {
            if ($Item.Contains($Key)) { return $Item[$Key] }
            return $Default
        }
        # PSCustomObject + any other object with a PSObject view (covers
        # ConvertFrom-Json output and pretty much anything else).
        $p = $Item.PSObject.Properties[$Key]
        if ($null -ne $p) { return $p.Value }
        return $Default
    } catch {
        # Defensive: any property-access oddity (e.g., a PSObject view
        # without a Properties collection on some exotic .NET type) lands
        # here. Better to return Default than to crash a long-running
        # assessment over a single bad field read.
        return $Default
    }
}

function Get-NRGRuleList {
    <#
    .SYNOPSIS
        Reads a rule LIST field keeping an empty list distinct from an unread one.
    .DESCRIPTION
        Get-NRGObjectField hands an empty array back through the pipeline, so the
        caller receives $null: indistinguishable from "the rules were not
        collected". Get-NRGInForcePolicies reads $null as "cannot tell, keep every
        custom policy", which counted a policy that applies to nobody as in force.
        Here $null still means the field is absent or was not read, and an empty
        collected list stays an empty list.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Item,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Key
    )
    if ($null -eq $Item) { return $null }
    $v = $null
    if ($Item -is [System.Collections.IDictionary]) {
        if ($Item.Contains($Key)) { $v = $Item[$Key] }
    } else {
        $p = $Item.PSObject.Properties[$Key]
        if ($p) { $v = $p.Value }
    }
    if ($null -eq $v) { return $null }
    return , @($v)
}

# Reads a timestamp from API or replayed data without depending on the
# workstation's culture. Graph JSON can arrive as a [datetime] (already parsed)
# or as an ISO 8601 string; older results files hold the invariant-culture
# string a [string] cast produced ("09/25/2026 10:00:00"). A bare
# [datetime]::Parse uses the CURRENT culture, so under en-GB that string throws
# on any day above 12 and swaps day and month below it. Returns a UTC
# [datetime], or $null when the value is absent or unparseable (unknown, never
# a throw). A value with no zone is taken as UTC, which is what Graph sends.
function ConvertTo-NRGUtcDateTime {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()]
        [object] $Value
    )
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $parsed = [datetime]::MinValue
    if ($Value -is [datetime]) {
        $parsed = $Value
    } elseif (-not [datetime]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)) {
        return $null
    }
    if ($parsed.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($parsed, [System.DateTimeKind]::Utc) }
    return $parsed.ToUniversalTime()
}

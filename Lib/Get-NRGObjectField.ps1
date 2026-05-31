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

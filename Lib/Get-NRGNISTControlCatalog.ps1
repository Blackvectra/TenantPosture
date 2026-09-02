#Requires -Version 7.0
#
# Get-NRGNISTControlCatalog.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Loads Config/nist-800-53-catalog.json — the official Rev 5 titles for
#          the 800-53 controls this assessment touches, plus the full 20-family
#          list — and answers title lookups for the standalone NIST matrix.
#
#          A matrix row reading "AC-6(9)   Gap" is not a deliverable. The reader
#          works from their own 800-53 documentation and POA&M, where the control
#          is "Least Privilege | Log Use of Privileged Functions", and a matrix
#          they have to cross-reference by hand to use is one they will not use.
#
#          Titles are Rev 5, which differ from Rev 4 in several places this tool
#          cites (AC-11, AT-2, AU-2, AU-4, AC-6(9), AC-16). Citing a Rev 4 title
#          under a Rev 5 heading is the kind of error an auditor notices first,
#          so NRG.NISTMatrix.Tests.ps1 pins the renamed ones by name.
#
# Inputs:  -ControlId   an 800-53 identifier, e.g. 'AC-2' or 'SC-8(1)'.
#          -ConfigPath  optional override of the catalog path (tests).
#
# Outputs: Get-NRGNISTControlCatalog  -> [ordered] @{ Controls; Families; Available }
#          Get-NRGNISTControlTitle    -> [string] title, or '' when unknown.
#          Get-NRGNISTFamilyTitle     -> [string] family name, or the bare code.
#
# Consumes: Config/nist-800-53-catalog.json only. No findings, no Graph, no EXO.
#

# Module-scope cache. Declared explicitly — StrictMode is active module-wide and
# reading an undeclared variable throws rather than yielding $null.
$script:NRGNistCatalog = $null

function Get-NRGNISTControlCatalog {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($script:NRGNistCatalog -and -not $ConfigPath) { return $script:NRGNistCatalog }

    $moduleRoot = $PSScriptRoot ? (Split-Path -Parent $PSScriptRoot) : (Get-Location).Path
    $path = if ($ConfigPath) { $ConfigPath } else { Join-Path $moduleRoot 'Config' 'nist-800-53-catalog.json' }

    $empty = [ordered]@{ Controls = @{}; Families = @{}; Available = $false }

    if (-not (Test-Path -LiteralPath $path)) {
        Write-Verbose "nist-800-53-catalog.json not found at $path — matrix rows will carry identifiers without titles."
        return $empty
    }

    # Same containment check the other config loaders apply: a config path that
    # resolves outside the module root is not a config file.
    if (-not $ConfigPath) {
        $resolved     = [System.IO.Path]::GetFullPath($path)
        $resolvedRoot = [System.IO.Path]::GetFullPath($moduleRoot)
        if (-not $resolved.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "nist-800-53-catalog.json resolved outside module root: $resolved"
        }
    }

    try {
        $json = Get-Content -LiteralPath $path -Raw -Encoding utf8 -ErrorAction Stop
        $data = $json | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Warning "Failed to load nist-800-53-catalog.json: $($_.Exception.Message)"
        return $empty
    }

    # Flatten the two JSON objects into ordinary case-insensitive hashtables so
    # callers do not have to care that they arrived as PSCustomObjects.
    # A default [hashtable] is already case-insensitive, which is what we want
    # for identifier lookups.
    $controls = @{}
    $controlsNode = Get-NRGObjectField -Item $data -Key 'controls' -Default $null
    if ($null -ne $controlsNode) {
        foreach ($p in $controlsNode.PSObject.Properties) {
            $controls[[string]$p.Name] = [string]$p.Value
        }
    }
    $families = @{}
    $familiesNode = Get-NRGObjectField -Item $data -Key 'families' -Default $null
    if ($null -ne $familiesNode) {
        foreach ($p in $familiesNode.PSObject.Properties) {
            $families[[string]$p.Name] = [string]$p.Value
        }
    }

    $result = [ordered]@{
        Controls  = $controls
        Families  = $families
        Available = ($controls.Count -gt 0)
    }

    if (-not $ConfigPath) { $script:NRGNistCatalog = $result }
    return $result
}

function Get-NRGNISTControlTitle {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [string] $ControlId,

        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ([string]::IsNullOrWhiteSpace($ControlId)) { return '' }

    $cat = if ($ConfigPath) { Get-NRGNISTControlCatalog -ConfigPath $ConfigPath } else { Get-NRGNISTControlCatalog }
    $id  = $ControlId.Trim()

    if ($cat.Controls.ContainsKey($id)) { return [string]$cat.Controls[$id] }

    # An enhancement with no entry of its own falls back to its base control's
    # title, marked as the enhancement. Better a row reading
    # "Least Privilege (enhancement 12)" than a bare identifier — and far better
    # than inventing a title, which in a compliance deliverable is a fabrication.
    if ($id -match '^([A-Z]{2}-\d{1,3})\((\d{1,3})\)$') {
        $base = $Matches[1]
        $enh  = $Matches[2]
        if ($cat.Controls.ContainsKey($base)) {
            return "$([string]$cat.Controls[$base]) (enhancement $enh)"
        }
    }
    return ''
}

function Get-NRGNISTFamilyTitle {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [string] $Family,

        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ([string]::IsNullOrWhiteSpace($Family)) { return '' }

    $cat = if ($ConfigPath) { Get-NRGNISTControlCatalog -ConfigPath $ConfigPath } else { Get-NRGNISTControlCatalog }
    $f   = $Family.Trim()
    if ($cat.Families.ContainsKey($f)) { return [string]$cat.Families[$f] }
    return $f
}

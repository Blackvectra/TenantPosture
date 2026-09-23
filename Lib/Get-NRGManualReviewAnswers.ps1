#Requires -Version 7.0
#
# Get-NRGManualReviewAnswers.ps1
# Dependencies: Get-NRGObjectField, ConvertTo-NRGSSPClientSlug, Config/manual-review/*.psd1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Loads the per-client manual-review answers file — the human half
#          of the controls.json manual-review questionnaire, mirroring
#          Get-NRGSSPAnswers.ps1 exactly but for controls.json ControlIds
#          instead of NIST 800-171 requirement ids, and read from
#          Config/manual-review/ instead of Config/ssp/.
#
#          Read with Import-PowerShellDataFile, which parses data only — it
#          does not execute the file, for the same reason the SSP answers
#          file does not: this file is edited by hand and may be emailed
#          between the MSP and the client.
#
# Inputs:  -Path       explicit path to a .psd1 answers file, or
#          -ClientName resolved to Config/manual-review/<slug>.psd1 via the
#                      SAME slugging rule Get-NRGSSPAnswers uses, so the
#                      client-facing file layout stays predictable.
#
# Outputs: [ordered] hashtable — Controls, Path, Available. Available is
#          $false when no file was found, which is a normal state: the
#          questionnaire still renders, with every prior answer blank.
#
# Consumes: Config/manual-review/*.psd1. No Graph, no EXO, no network.
#

function Get-NRGManualReviewAnswers {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $Path,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $ClientName
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $empty = [ordered]@{ Controls = @{}; Path = ''; Available = $false }

    $moduleRoot = if ($script:NRGModuleRoot) { $script:NRGModuleRoot }
                  elseif ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
                  else { (Get-Location).Path }

    $resolved = ''
    if ($Path) {
        if ($Path -match '\.\.[\\/]') { throw 'Path traversal not allowed in -Path.' }
        $resolved = $Path
    } elseif ($ClientName) {
        $slug = ConvertTo-NRGSSPClientSlug -ClientName $ClientName
        if (-not $slug) { return $empty }
        $resolved = Join-Path $moduleRoot 'Config' 'manual-review' "$slug.psd1"
    } else {
        return $empty
    }

    if (-not (Test-Path -LiteralPath $resolved)) {
        Write-Verbose "Manual-review answers file not found at $resolved — answers will be blank."
        return $empty
    }

    try {
        $data = Import-PowerShellDataFile -LiteralPath $resolved -ErrorAction Stop
    } catch {
        Write-Warning "Manual-review answers file could not be parsed, continuing without it: $($_.Exception.Message)"
        return $empty
    }

    $controls = @{}
    $node = Get-NRGObjectField -Item $data -Key 'Controls' -Default $null
    if ($node -is [System.Collections.IDictionary]) {
        foreach ($k in $node.Keys) { $controls[[string]$k] = $node[$k] }
    }

    [ordered]@{
        Controls  = $controls
        Path      = $resolved
        Available = $true
    }
}

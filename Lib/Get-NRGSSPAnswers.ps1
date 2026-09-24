#Requires -Version 7.0
#
# Get-NRGSSPAnswers.ps1
# Dependencies: Get-NRGObjectField, Config/ssp/*.psd1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Loads the per-client SSP answers file — the half of a System
#          Security Plan no scan can produce.
#
#          41 of the 110 NIST SP 800-171 Rev 2 requirements have automated
#          evidence in this tool. The other 69 are policy, process, physical
#          security and personnel: who authorizes access, where the media is
#          destroyed, how often awareness training runs. Those answers exist in
#          the client's head or in a binder, and an SSP is not a document until
#          they are written down. This file is where they live, so they survive
#          between assessments instead of being retyped every year.
#
#          Read with Import-PowerShellDataFile, which parses data only — it
#          does not execute the file. That matters: an answers file is edited
#          by hand and may be emailed between the MSP and the client, and a
#          .psd1 that could run code would make that an execution vector.
#
# Inputs:  -Path       explicit path to a .psd1 answers file, or
#          -ClientName resolved to Config/ssp/<slug>.psd1.
#
# Outputs: [ordered] hashtable — System, Inherited, Requirements, Path,
#          Available. Available is $false when no file was found, which is a
#          normal state: the SSP still renders, with every narrative blank and
#          the missing answers counted and stated.
#
# Consumes: Config/ssp/*.psd1. No Graph, no EXO, no network.
#

function Get-NRGSSPAnswers {
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

    $empty = [ordered]@{
        System = @{}; Inherited = @{}; Requirements = @{}
        Path = ''; Available = $false
    }

    $moduleRoot = if ($script:NRGModuleRoot) { $script:NRGModuleRoot }
                  elseif ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
                  else { (Get-Location).Path }

    $resolved = ''
    if ($Path) {
        if ($Path -match '\.\.[\\/]') { throw 'Path traversal not allowed in -Path.' }
        $resolved = $Path
    } elseif ($ClientName) {
        # Slug the client name rather than trusting it as a filename: it comes
        # from clients.json and a tenant domain contains dots, which are fine,
        # but a stray separator would escape the answers folder. Shared with
        # Import-NRGSSPQuestionnaire.ps1 via ConvertTo-NRGSSPClientSlug so both
        # resolve the exact same file for the exact same client.
        $slug = ConvertTo-NRGSSPClientSlug -ClientName $ClientName
        if (-not $slug) { return $empty }
        $resolved = Join-Path $moduleRoot 'Config' 'ssp' "$slug.psd1"
    } else {
        return $empty
    }

    if (-not (Test-Path -LiteralPath $resolved)) {
        Write-Verbose "SSP answers file not found at $resolved — narratives will be blank."
        return $empty
    }

    try {
        $data = Import-PowerShellDataFile -LiteralPath $resolved -ErrorAction Stop
    } catch {
        # A malformed answers file must not take the assessment down. The SSP
        # renders without it and says so.
        Write-Warning "SSP answers file could not be parsed, continuing without it: $($_.Exception.Message)"
        return $empty
    }

    $reqs = @{}
    $node = Get-NRGObjectField -Item $data -Key 'Requirements' -Default $null
    if ($node -is [System.Collections.IDictionary]) {
        foreach ($k in $node.Keys) { $reqs[[string]$k] = $node[$k] }
    }

    [ordered]@{
        System       = (Get-NRGObjectField -Item $data -Key 'System'    -Default @{})
        Inherited    = (Get-NRGObjectField -Item $data -Key 'Inherited' -Default @{})
        Requirements = $reqs
        Path         = $resolved
        Available    = $true
    }
}

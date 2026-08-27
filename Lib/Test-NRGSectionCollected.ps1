#Requires -Version 7.0
#
# Test-NRGSectionCollected.ps1
# Dependencies: Get-NRGNestedProperty
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Answers the one question that stands between a collector failure and
#          a false clean bill of health: did THIS section of the raw data
#          actually get collected?
#
#          A collector that runs several independent queries wraps each in its
#          own try/catch so one failure does not abort the rest, then reports
#          Success = $true because the collector itself completed. That makes
#          Success useless for the question an evaluator needs answered. A
#          missing section and an empty-but-real section look identical, and
#          reading the first as compliance is how the tool told a client their
#          third-party cloud storage was disabled when the query had simply
#          failed.
#
#          Two sources of truth, in order:
#
#            1. Data.SectionStatus.<Section> — the explicit contract.
#               'Collected' means the query ran and its result is
#               trustworthy, whatever it contains, including nothing.
#               'Failed' / 'NotRun' mean the result is an unknown.
#
#            2. Presence of Data.<Section> — the fallback for collectors that
#               do not publish SectionStatus yet, and for result JSON captured
#               before SectionStatus existed. A section initialised to $null
#               and never populated reads as not collected; a section that
#               landed reads as collected.
#
#          The fallback is deliberately weaker than the contract and cannot
#          replace it: a section initialised to @() rather than $null is
#          indistinguishable from a query that legitimately returned nothing.
#          That is exactly why collectors with independent sub-queries are
#          required to publish SectionStatus rather than relying on this.
#
# Inputs:  -Raw      the raw-data envelope from Get-NRGRawData.
#          -Section  the section name inside Data.
#
# Outputs: [bool] — $true when the section can be trusted as evidence.
#
# Consumes: raw data only. No Graph, no EXO, no network.
#

function Test-NRGSectionCollected {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()]
        [object] $Raw,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $Section
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # No envelope at all, or the collector itself failed: nothing to trust.
    if ($null -eq $Raw) { return $false }
    $ok = Get-NRGNestedProperty -Object $Raw -Path 'Success' -Default $null
    if ($null -ne $ok -and -not $ok) { return $false }

    # 1. The explicit contract wins wherever the collector publishes it.
    $status = Get-NRGNestedProperty -Object $Raw -Path "Data.SectionStatus.$Section" -Default $null
    if ($null -ne $status) { return ([string]$status -eq 'Collected') }

    # 2. Fallback: did the section land at all?
    #
    # The container is inspected directly rather than through
    # Get-NRGNestedProperty, which returns an EMPTY ARRAY as $null — PowerShell
    # enumerates @() away across a function return. That made "collected, and
    # this tenant genuinely has none" indistinguishable from "never landed",
    # and the guard suppressed real compliance on clean tenants.
    #
    # The distinction that matters:
    #   key absent, or present holding $null -> the collector initialised it
    #                                           and the sub-query never filled
    #                                           it. Not collected.
    #   key present holding @()             -> the query ran and found none.
    #                                           Collected, and compliant.
    $data = Get-NRGNestedProperty -Object $Raw -Path 'Data' -Default $null
    if ($null -eq $data) { return $false }

    $value = $null
    if ($data -is [System.Collections.IDictionary]) {
        if (-not $data.Contains($Section)) { return $false }
        $value = $data[$Section]
    } else {
        $prop = $data.PSObject.Properties[$Section]
        if ($null -eq $prop) { return $false }
        $value = $prop.Value
    }
    return ($null -ne $value)
}

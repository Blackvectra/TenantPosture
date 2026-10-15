#Requires -Version 7.0
#
# Get-TPSectionNotCollectedDetail.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Builds the Detail of a "section was not collected; not assessed" finding
# and appends the reason the collector recorded for that section, so the
# deliverable says what to fix (a missing role, a refused cmdlet, a throttled
# read) instead of only that nothing was read.
#
# Sets:     nothing (pure function)
# Consumes: <raw>.Data.SectionErrors.<Section> (written by collectors that
#           record it; the Purview collector today), with the registered
#           exception for -CollectorSource as the fallback on a live run.
# Cmdlets:  none
#
# WHY
# ---
# On the 2026-10-14 live run PVW-2.6 read "AutoLabelPolicies was not
# collected; not assessed." while the Exceptions array said that
# Get-AutoSensitivityLabelPolicy was not available to the signed-in account
# (a missing Purview role). The ticket raised from the report could not say
# what to do, because the report never carried the reason. A reason the
# collector already wrote down belongs in the finding that depends on it.
# The text keeps the original sentence as its prefix, so every consumer
# that keys on "was not collected" (the scope classifier, the baseline
# reason contract, the tests) is unchanged.

function Get-TPSectionNotCollectedDetail {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # The collector's result envelope (Get-TPRawData output); $null is allowed.
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Raw,

        # The section name as the collector publishes it in SectionStatus.
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Section,

        # The Source the collector registers its exception under for this
        # section (for example 'Purview-AutoLabelPolicies'). Read only when
        # the envelope carries no SectionErrors entry; on a live run the
        # exception is still in module state.
        [string] $CollectorSource
    )

    $text = "$Section was not collected; not assessed."
    $why  = [string](Get-TPNestedProperty -Object $Raw -Path "Data.SectionErrors.$Section" -Default '')
    if ([string]::IsNullOrWhiteSpace($why) -and $CollectorSource) {
        $match = @(Get-TPExceptions | Where-Object {
            [string](Get-TPObjectField -Item $_ -Key 'Source' -Default '') -eq $CollectorSource
        }) | Select-Object -Last 1
        if ($match) { $why = [string](Get-TPObjectField -Item $match -Key 'Message' -Default '') }
    }
    if (-not [string]::IsNullOrWhiteSpace($why)) {
        $why = $why.Trim()
        if ($why.Length -gt 600) { $why = $why.Substring(0, 600) + '...' }
        $text += " Reason recorded by the collector: $why"
    }
    return $text
}

#Requires -Version 7.0
#
# Get-NRGEvidenceLimits.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Components of a control's expected state the assessment never establishes (Config/evidence-limits.json),
#          so every surface that shows the control can say so briefly.
#
# Sets:     nothing (pure lookup)
# Consumes: Config/evidence-limits.json
# Cmdlets:  none
#

# ControlId -> @{ NotEstablished; Reason }. An absent or unreadable file means no limits are recorded.
function Get-NRGEvidenceLimitMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $map = @{}
    $path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config/evidence-limits.json'
    try {
        if (Test-Path -LiteralPath $path) {
            $cfg = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
            foreach ($l in @(Get-NRGObjectField -Item $cfg -Key 'Limits' -Default @())) {
                $c = [string](Get-NRGObjectField -Item $l -Key 'Control' -Default '')
                $n = [string](Get-NRGObjectField -Item $l -Key 'NotEstablished' -Default '')
                if ($c -and $n) { $map[$c] = @{ NotEstablished = $n; Reason = [string](Get-NRGObjectField -Item $l -Key 'Reason' -Default '') } }
            }
        }
    } catch { Write-Verbose "Get-NRGEvidenceLimitMap: $($_.Exception.Message)"; $map = @{} }
    return $map
}

# "Not established: configured non-compliance actions." for a control with a recorded limit, otherwise ''.
function Get-NRGEvidenceLimitNote {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $ControlId)
    $map = Get-NRGEvidenceLimitMap
    if (-not $ControlId -or -not $map.ContainsKey($ControlId)) { return '' }
    return "Not established: $($map[$ControlId].NotEstablished)."
}

# The same note as a Markdown suffix for a table cell (" *Not established: ...*"), or '' when none is recorded.
function Get-NRGEvidenceLimitMd {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $ControlId)
    $n = Get-NRGEvidenceLimitNote -ControlId $ControlId
    if ($n) { return " *$n*" }
    return ''
}

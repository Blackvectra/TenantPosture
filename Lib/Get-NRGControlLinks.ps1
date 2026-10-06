#Requires -Version 7.0
#
# Get-NRGControlLinks.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Groups of controls that read the same tenant setting, so the score
#          counts each group once (Config/control-links.json).
#
# Sets:     nothing (pure lookup; cached in module scope)
# Consumes: Config/control-links.json
# Cmdlets:  none
#

# ControlId -> @{ Primary; Members; Reason } for every control in a group.
# An unreadable or absent file means no links: every control scores alone,
# which is the behavior before linking existed.
function Get-NRGControlLinkMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    if ($null -ne (Get-Variable -Name NRGControlLinkMap -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) {
        return $script:NRGControlLinkMap
    }
    $map = @{}
    $path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config/control-links.json'
    try {
        if (Test-Path -LiteralPath $path) {
            $cfg = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
            foreach ($g in @(Get-NRGObjectField -Item $cfg -Key 'groups' -Default @())) {
                $primary = [string](Get-NRGObjectField -Item $g -Key 'Primary' -Default '')
                if (-not $primary) { continue }
                $members = @(@($primary) + @(@(Get-NRGObjectField -Item $g -Key 'Linked' -Default @()) | ForEach-Object { [string]$_ } | Where-Object { $_ }))
                $entry = @{ Primary = $primary; Members = $members; Reason = [string](Get-NRGObjectField -Item $g -Key 'Reason' -Default '') }
                foreach ($m in $members) { $map[$m] = $entry }
            }
        }
    } catch {
        Write-Verbose "Get-NRGControlLinkMap: $path unreadable, controls score individually. $($_.Exception.Message)"
        $map = @{}
    }
    $script:NRGControlLinkMap = $map
    return $map
}

# " Scored together with EXO-6.2 (both read ...); counted once." or ''.
function Get-NRGControlLinkNote {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $ControlId)
    $map = Get-NRGControlLinkMap
    if (-not $map.ContainsKey($ControlId)) { return '' }
    $e = $map[$ControlId]
    $others = @($e.Members | Where-Object { $_ -ne $ControlId })
    if ($others.Count -eq 0) { return '' }
    $why = if ($e.Reason) { " ($($e.Reason.TrimEnd('.').Substring(0,1).ToLowerInvariant() + $e.Reason.TrimEnd('.').Substring(1)))" } else { '' }
    return " Scored together with $($others -join ', ')$why; the setting counts once in the score."
}

# Config/control-links.json "Views": ControlId -> @{ Of; Reason }. Absent or unreadable means no views.
function Get-NRGControlViewMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $map = @{}
    $path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config/control-links.json'
    try {
        if (Test-Path -LiteralPath $path) {
            $cfg = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
            foreach ($v in @(Get-NRGObjectField -Item $cfg -Key 'Views' -Default @())) {
                $c = [string](Get-NRGObjectField -Item $v -Key 'Control' -Default '')
                $of = [string](Get-NRGObjectField -Item $v -Key 'Of' -Default '')
                if ($c -and $of) { $map[$c] = @{ Of = $of; Reason = [string](Get-NRGObjectField -Item $v -Key 'Reason' -Default '') } }
            }
        }
    } catch { Write-Verbose "Get-NRGControlViewMap: $($_.Exception.Message)"; $map = @{} }
    return $map
}

# How many of the scored Gap controls are separate deficiencies. 69 Gap controls are not 69 exposures:
#   - controls that read the same setting are already counted once in the score (Folded: the extra
#     members, shown beside their primary);
#   - a named-object view of a control that already reports a shortfall (Views; the parent is a Gap or Partial) restates it;
#   - every remaining control is a different baseline requirement. Root causes can still overlap (one
#     missing Conditional Access policy can fail several), and this does not assume they do.
function Get-NRGGapSummary {
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Findings)
    $scored = @(Get-NRGScoringFindings -Findings $Findings)
    $gaps = @($scored | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '') -eq 'Gap' })
    # A view restates a shortfall its parent already reports, so the parent may be a Gap or a Partial.
    $gapIds = @{}
    foreach ($g in $scored) {
        if ([string](Get-NRGObjectField -Item $g -Key 'State' -Default '') -in @('Gap', 'Partial', 'Error')) { $gapIds[[string](Get-NRGObjectField -Item $g -Key 'ControlId' -Default '')] = $true }
    }
    $links = Get-NRGControlLinkMap
    $views = Get-NRGControlViewMap
    $viewRows = [System.Collections.Generic.List[object]]::new()
    $folded = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $gaps) {
        $cid = [string](Get-NRGObjectField -Item $g -Key 'ControlId' -Default '')
        $members = @(Get-NRGObjectField -Item $g -Key 'LinkedControls' -Default @())
        if ($members.Count -gt 1) { $folded.Add([ordered]@{ Primary = $cid; AlsoCounted = @($members | Where-Object { $_ -ne $cid }) }) }
        if ($views.ContainsKey($cid)) {
            $of = $views[$cid].Of
            $ofGroup = if ($links.ContainsKey($of)) { $links[$of].Primary } else { $of }
            if ($gapIds.ContainsKey($of) -or $gapIds.ContainsKey($ofGroup)) {
                $viewRows.Add([ordered]@{ Control = $cid; Of = $of; Reason = $views[$cid].Reason })
            }
        }
    }
    $foldedCount = 0; foreach ($f in $folded) { $foldedCount += @($f.AlsoCounted).Count }
    [ordered]@{
        GapControls          = $gaps.Count
        NamedViews           = @($viewRows)
        DistinctDeficiencies = $gaps.Count - $viewRows.Count
        FoldedSameSetting    = @($folded)
        FoldedControls       = $foldedCount
    }
}

# One sentence for the console, the Markdown summary and the report site, so no surface words it differently.
function Format-NRGGapSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Summary)
    $t = [int]$Summary.GapControls; $v = @($Summary.NamedViews).Count; $u = [int]$Summary.DistinctDeficiencies; $fc = [int]$Summary.FoldedControls
    $text = "$t Gap control(s): $u distinct requirement(s)"
    if ($v -gt 0) { $text += " and $v named-object view(s) of a control that already reports the shortfall" }
    $text += '.'
    if ($fc -gt 0) { $text += " A further $fc control(s) read the same setting as a Gap control and are already counted once in the score." }
    $text += ' Distinct requirements can still share a root cause (for example one missing Conditional Access policy); this does not assume they do.'
    return $text
}

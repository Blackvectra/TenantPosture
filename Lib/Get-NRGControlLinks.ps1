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

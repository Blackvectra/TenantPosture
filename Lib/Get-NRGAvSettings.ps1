#Requires -Version 7.0
#
# Get-NRGAvSettings.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Read the Microsoft Defender Antivirus settings INT-1.5 names (real-time
#          protection, cloud-delivered protection, potentially unwanted application
#          protection) from a Settings Catalog policy's settings payload.
#
#          INT-1.5's expected state is that an assigned antivirus policy CONFIGURES
#          Defender Antivirus, not that one exists. Three rules keep it honest: a
#          setting the policy does not contain is 'NotConfigured' (the policy does not
#          establish it, the platform default may still apply), a value that is not a
#          known token is 'Unknown:<token>' and never taken to be On, and the parser
#          walks every nested node because the nesting differs between templates.
#          The Settings Catalog definition ids are parsed by suffix; the parser has NOT
#          been verified against a live tenant (see docs/NRG-DETECTION-LIMITS.md).
#
# Data consumed: none.  Graph scopes / cmdlets: none (parsing only).

function Get-NRGAvSettings {
    <#
    .SYNOPSIS
        Returns [ordered] RealTimeProtection / CloudProtection / PuaProtection, each
        'On' | 'Audit' | 'Off' | 'NotConfigured' | 'Unknown:<token>'.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] $Settings)

    $out = [ordered]@{ RealTimeProtection = 'NotConfigured'; CloudProtection = 'NotConfigured'; PuaProtection = 'NotConfigured' }
    $value = {
        param([string] $Setting, [string] $Token)
        switch ($Setting) {
            'PuaProtection' { switch ($Token) { '1' { 'On' } '2' { 'Audit' } '0' { 'Off' } default { "Unknown:$Token" } } }
            default         { switch ($Token) { '1' { 'On' } '0' { 'Off' } default { "Unknown:$Token" } } }
        }
    }
    $walk = $null
    $walk = {
        param($Node)
        if ($null -eq $Node) { return }
        if ($Node -is [System.Collections.IDictionary]) {
            $defId  = [string](Get-NRGObjectField -Item $Node -Key 'settingDefinitionId' -Default '')
            $choice = Get-NRGObjectField -Item $Node -Key 'choiceSettingValue' -Default $null
            if ($choice) {
                $name = $null
                if     ($defId -match '(?i)defender_allowrealtimemonitoring$') { $name = 'RealTimeProtection' }
                elseif ($defId -match '(?i)defender_allowcloudprotection$')    { $name = 'CloudProtection' }
                elseif ($defId -match '(?i)defender_puaprotection$')           { $name = 'PuaProtection' }
                if ($name) {
                    $val = [string](Get-NRGObjectField -Item $choice -Key 'value' -Default '')
                    if ($val) { $out[$name] = & $value $name (($val -split '_')[-1]) }
                }
            }
            foreach ($k in @($Node.Keys)) { & $walk $Node[$k] }
        } elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
            foreach ($child in $Node) { & $walk $child }
        }
    }
    & $walk $Settings
    return $out
}

function Test-NRGAvSettingSet {
    <#
    .SYNOPSIS
        Judges read antivirus settings across the assigned policies. Per setting the
        best value across policies wins (On > Audit > Off); a setting no policy
        contains is NotConfigured, and an unknown token is reported as not established.
    #>
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $SettingMaps)
    $rank = @{ 'On' = 3; 'Audit' = 2; 'Off' = 1 }
    $rows = foreach ($name in @('RealTimeProtection', 'CloudProtection', 'PuaProtection')) {
        $best = 'NotConfigured'; $r0 = 0; $unknown = $null
        foreach ($m in @($SettingMaps)) {
            if ($null -eq $m) { continue }
            $v = [string](Get-NRGObjectField -Item $m -Key $name -Default 'NotConfigured')
            if ($v -like 'Unknown:*') { $unknown = $v; continue }
            $r = $rank[$v]; if ($null -eq $r) { continue }
            if ($r -gt $r0) { $best = $v; $r0 = $r }
        }
        if ($best -eq 'NotConfigured' -and $unknown) { $best = $unknown }
        [ordered]@{ Setting = $name; Value = $best }
    }
    return @($rows)
}

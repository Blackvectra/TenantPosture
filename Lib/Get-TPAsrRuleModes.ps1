#Requires -Version 7.0
#
# Get-TPAsrRuleModes.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Read which Attack Surface Reduction rules a Settings Catalog policy
#          configures and in what mode (Block / Audit / Warn / Off), and judge
#          that against an APPROVED required-rule list.
#
#          INT-2.2's expected state is "the NRG ASR rule set, every rule in Block
#          mode". An assigned policy existing proves none of that. Two rules keep
#          the verdict honest: a mode that cannot be read is Unknown and is never
#          taken to be Block; and the required rule list is an operator-approved
#          file (Config/asr-required-rules.json) that ships EMPTY, because the
#          tool must not invent NRG's standard. With no approved list, the modes
#          read are reported and the rule-set half stays not assessed.
#
#          The Settings Catalog shape (settingInstance trees whose choice values
#          end in _block / _audit / _warn / _off) is parsed generically, walking
#          every nested node, because the exact nesting differs between templates;
#          a value whose last token is not a known mode is 'Unknown:<token>'.
#
# Data consumed: none.  Graph scopes / cmdlets: none (parsing only).

function Get-TPAsrRuleModes {
    <#
    .SYNOPSIS
        Returns an [ordered] map of rule key (lower-case) to mode for every ASR
        setting found anywhere in a Settings Catalog settings payload.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] $Settings)

    $modes = [ordered]@{}
    $normalize = {
        param([string] $Token)
        switch -Regex ($Token.ToLowerInvariant()) {
            '^block$'                        { 'Block'; break }
            '^audit$'                        { 'Audit'; break }
            '^warn$'                         { 'Warn'; break }
            '^(off|disable|disabled|notconfigured)$' { 'Off'; break }
            default                          { "Unknown:$Token" }
        }
    }
    $walk = $null
    $walk = {
        param($Node)
        if ($null -eq $Node) { return }
        if ($Node -is [System.Collections.IDictionary]) {
            $defId = [string](Get-TPObjectField -Item $Node -Key 'settingDefinitionId' -Default '')
            $choice = Get-TPObjectField -Item $Node -Key 'choiceSettingValue' -Default $null
            if ($defId -match '(?i)attacksurfacereduction' -and $choice) {
                $val = [string](Get-TPObjectField -Item $choice -Key 'value' -Default '')
                if ($val) {
                    $key = if ($defId -match '(?i)attacksurfacereductionrules_(.+)$') { $Matches[1].ToLowerInvariant() } else { $defId.ToLowerInvariant() }
                    $token = ($val -split '_')[-1]
                    $modes[$key] = & $normalize $token
                }
            }
            foreach ($k in @($Node.Keys)) { & $walk $Node[$k] }
        } elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
            foreach ($child in $Node) { & $walk $child }
        }
    }
    & $walk $Settings
    return $modes
}

function Get-TPAsrRequiredRules {
    <#
    .SYNOPSIS
        The operator-approved required ASR rules from Config/asr-required-rules.json
        (empty until approved). Each entry: Id (a rule key or a distinctive part of
        one) and Name.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()
    $root = Split-Path -Parent $PSScriptRoot
    $path = Join-Path $root 'Config' 'asr-required-rules.json'
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    try {
        $j = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10
        return @(@(Get-TPObjectField -Item $j -Key 'Rules' -Default @()) | Where-Object { $_ })
    } catch { return @() }
}

function Test-TPAsrRuleSet {
    <#
    .SYNOPSIS
        Judges read rule modes against the required rules. Per required rule the
        best mode across policies wins (Block > Warn > Audit > Off); a rule with no
        setting found is 'NotConfigured'.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [AllowEmptyCollection()] [object[]] $RuleModeMaps,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Required
    )
    $rank = @{ 'Block' = 4; 'Warn' = 3; 'Audit' = 2; 'Off' = 1 }
    $rows = foreach ($req in @($Required)) {
        $id = ([string](Get-TPObjectField -Item $req -Key 'Id' -Default '')).ToLowerInvariant()
        if (-not $id) { continue }
        $best = 'NotConfigured'; $bestRank = 0
        foreach ($map in @($RuleModeMaps)) {
            if ($null -eq $map) { continue }
            foreach ($k in @($map.Keys)) {
                if ($k -like "*$id*") {
                    $m = [string]$map[$k]; $r = $rank[$m]; if ($null -eq $r) { $r = 0 }
                    if ($r -gt $bestRank -or ($best -eq 'NotConfigured')) { $best = $m; $bestRank = $r }
                }
            }
        }
        [ordered]@{ Id = $id; Name = [string](Get-TPObjectField -Item $req -Key 'Name' -Default $id); Mode = $best }
    }
    $rows = @($rows)
    return [ordered]@{
        Rows     = $rows
        Required = $rows.Count
        Blocking = @($rows | Where-Object { $_.Mode -eq 'Block' }).Count
        NotBlock = @($rows | Where-Object { $_.Mode -ne 'Block' })
    }
}

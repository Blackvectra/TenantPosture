#Requires -Version 7.0
#
# Get-TPScubaAlignment.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Read Config/scuba-alignment.json: for every NRG control that cites a CISA
#          ScubaGear rule, the current rule id, how well the NRG evaluator's coverage
#          matches the rule (Equivalent / Partial / Manual / Unsupported), the rule's
#          SHALL / SHOULD strength, and the ScubaGear and migration-file versions the
#          mapping was checked against. A VIEW: it changes no verdict and no score.
#          A migrated citation does not establish equivalence; the relation says what
#          the NRG evaluator actually covers.
#
# Data consumed: none.  Graph scopes / cmdlets: none (parsing only).

function Get-TPScubaAlignment {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([string] $Path)
    if (-not $Path) { $Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config' 'scuba-alignment.json' }
    $r = [ordered]@{ Available = $false; Source = $null; Mappings = @{} }
    if (-not (Test-Path -LiteralPath $Path)) { return $r }
    try { $j = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20 } catch { return $r }
    $r.Available = $true
    $r.Source = Get-TPObjectField -Item $j -Key 'Source' -Default $null
    $map = [ordered]@{}
    foreach ($m in @(Get-TPObjectField -Item $j -Key 'Mappings' -Default @())) {
        $cid = [string](Get-TPObjectField -Item $m -Key 'Control' -Default '')
        if ($cid) { $map[$cid] = $m }
    }
    $r.Mappings = $map
    return $r
}

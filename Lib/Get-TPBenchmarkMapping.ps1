#Requires -Version 7.0
#
# Get-TPBenchmarkMapping.ps1
# Dependencies: Get-TPObjectField
# TenantPosture
# Author: Matthew Levorson
#
# Purpose:  One view of which configuration benchmark each control is mapped
#           to: CIS Microsoft 365 Foundations and CISA ScubaGear from
#           controls.json (References.CIS, References.SCuBA), every other
#           benchmark from Config/benchmark-mappings.json, and the reason for
#           each control no benchmark item describes.
# Consumes: Config/controls.json, Config/benchmark-mappings.json, Config/scuba-alignment.json
#
# A citation here follows the repo's citation rule: the control judges the
# setting the item audits and every state it scores Satisfied passes the
# item. A control with no such item is listed with the reason, never given
# a near-miss to fill the column. A view: it creates no finding.

function Get-TPBenchmarkMapping {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [string] $ControlsPath,
        [string] $MappingPath,
        [string] $ScubaAlignmentPath
    )
    $root = Split-Path -Parent $PSScriptRoot
    if (-not $ControlsPath)       { $ControlsPath       = Join-Path $root 'Config' 'controls.json' }
    if (-not $MappingPath)        { $MappingPath        = Join-Path $root 'Config' 'benchmark-mappings.json' }
    if (-not $ScubaAlignmentPath) { $ScubaAlignmentPath = Join-Path $root 'Config' 'scuba-alignment.json' }
    $r = [ordered]@{ Available = $false; Benchmarks = [ordered]@{}; Controls = [ordered]@{}; Unmapped = [ordered]@{}; Summary = $null }
    if (-not (Test-Path -LiteralPath $ControlsPath) -or -not (Test-Path -LiteralPath $MappingPath)) { return $r }
    try {
        $cj = Get-Content -LiteralPath $ControlsPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
        $mj = Get-Content -LiteralPath $MappingPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
    } catch { return $r }
    $controls = @(if ($cj -is [array]) { $cj } else { Get-TPObjectField -Item $cj -Key 'controls' -Default @() })
    $scubaRel = @{}
    if (Test-Path -LiteralPath $ScubaAlignmentPath) {
        try {
            $sa = Get-Content -LiteralPath $ScubaAlignmentPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
            foreach ($m in @(Get-TPObjectField -Item $sa -Key 'Mappings' -Default @())) {
                $c = [string](Get-TPObjectField -Item $m -Key 'Control' -Default '')
                if ($c) { $scubaRel[$c] = [string](Get-TPObjectField -Item $m -Key 'Relation' -Default '') }
            }
        } catch { Write-Verbose "ScubaGear alignment not read: $($_.Exception.Message)" }
    }

    $r.Benchmarks['CIS-M365-7.0.0'] = [ordered]@{ Name = 'CIS Microsoft 365 Foundations Benchmark'; Version = '7.0.0'; Publisher = 'Center for Internet Security'; Kind = 'Configuration benchmark'; Source = 'controls.json References.CIS' }
    $r.Benchmarks['SCUBA-2.0.0']    = [ordered]@{ Name = 'CISA ScubaGear Secure Configuration Baselines'; Version = '2.0.0'; Publisher = 'CISA'; Kind = 'Government configuration benchmark'; Source = 'controls.json References.SCuBA' }
    $bm = Get-TPObjectField -Item $mj -Key 'benchmarks' -Default $null
    if ($null -ne $bm) { foreach ($p in $bm.PSObject.Properties) { $r.Benchmarks[$p.Name] = $p.Value } }

    $fileMapped = Get-TPObjectField -Item $mj -Key 'controls' -Default $null
    $fileUnmapped = Get-TPObjectField -Item $mj -Key 'unmapped' -Default $null
    foreach ($c in $controls) {
        $cid = [string](Get-TPObjectField -Item $c -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        $refs = Get-TPObjectField -Item $c -Key 'References' -Default $null
        $rows = [System.Collections.Generic.List[object]]::new()
        $cis = [string](Get-TPObjectField -Item $refs -Key 'CIS' -Default '')
        foreach ($id in @($cis -split '[,;]\s*' | Where-Object { $_.Trim() })) {
            $rows.Add([ordered]@{ Benchmark = 'CIS-M365-7.0.0'; ItemId = $id.Trim(); Relation = 'Cited'; Source = 'controls.json' })
        }
        $sc = [string](Get-TPObjectField -Item $refs -Key 'SCuBA' -Default '')
        if ($sc.Trim()) {
            $rel = if ($scubaRel.ContainsKey($cid) -and $scubaRel[$cid]) { $scubaRel[$cid] } else { 'Cited' }
            $rows.Add([ordered]@{ Benchmark = 'SCUBA-2.0.0'; ItemId = $sc.Trim(); Relation = $rel; Source = 'controls.json' })
        }
        $more = if ($null -ne $fileMapped) { Get-TPObjectField -Item $fileMapped -Key $cid -Default $null } else { $null }
        foreach ($m in @($more | Where-Object { $null -ne $_ })) {
            $row = [ordered]@{
                Benchmark = [string](Get-TPObjectField -Item $m -Key 'Benchmark' -Default '')
                ItemId    = [string](Get-TPObjectField -Item $m -Key 'ItemId' -Default '')
                ItemTitle = [string](Get-TPObjectField -Item $m -Key 'ItemTitle' -Default '')
                Relation  = [string](Get-TPObjectField -Item $m -Key 'Relation' -Default '')
                Source    = 'benchmark-mappings.json'
            }
            $cond = [string](Get-TPObjectField -Item $m -Key 'Condition' -Default '')
            if ($cond) { $row['Condition'] = $cond }
            $rows.Add($row)
        }
        if ($rows.Count -gt 0) {
            $r.Controls[$cid] = $rows.ToArray()
        } else {
            $u = if ($null -ne $fileUnmapped) { Get-TPObjectField -Item $fileUnmapped -Key $cid -Default $null } else { $null }
            $r.Unmapped[$cid] = [ordered]@{
                Reason = [string](Get-TPObjectField -Item $u -Key 'Reason' -Default '')
                EarnBy = [string](Get-TPObjectField -Item $u -Key 'EarnBy' -Default '')
            }
        }
    }
    $r.Summary = [ordered]@{ Controls = $controls.Count; Mapped = $r.Controls.Count; Unmapped = $r.Unmapped.Count }
    $r.Available = $true
    return $r
}

#Requires -Version 7.0
#
# Get-NRGDistributionListBaseline.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Load the distribution-list recommendation catalog
#          (Config/distribution-list-baseline.json) and interpret the three NRG
#          distribution-list standards in Config/nrg-standards.json. One place
#          decides whether a standard is approved, so the evaluator and the
#          worksheet cannot disagree about it.
#
# Sets:     nothing (pure lookup)
# Consumes: Config/distribution-list-baseline.json, Config/nrg-standards.json
#           (through Get-NRGStandards). No Graph, no Exchange, no network.
#
# THE RULE THIS FILE ENFORCES
# ---------------------------
# A recommendation whose Basis is 'NRG' is a judgment the owner has not made
# until a value is approved in Config/nrg-standards.json. An empty list, an
# unreadable file, or a value this file does not recognize all mean "not
# approved", and the check reports "not assessed". They never mean "met": a
# check that passes because nothing was required is a false clean result.

function Get-NRGDistributionListBaseline {
    <#
    .SYNOPSIS
        Returns the recommendation catalog as @{ Available; Entries; ById; NistMappingNote; FrameworkNote }.
        A missing or unreadable file yields Available = $false and no entries; callers
        report "recommendations not loaded", never an empty (and so clean) catalog.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([string] $Path)

    $out = [ordered]@{ Available = $false; Entries = @(); ById = @{}; NistMappingNote = ''; FrameworkNote = 'no framework item verified'; Error = '' }
    if (-not $Path) { $Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config' 'distribution-list-baseline.json' }
    if (-not (Test-Path -LiteralPath $Path)) { $out.Error = "Catalog not found: $Path"; return $out }
    try {
        $j = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10
    } catch { $out.Error = "Catalog unreadable: $($_.Exception.Message)"; return $out }

    $out.NistMappingNote = [string](Get-NRGObjectField -Item $j -Key 'NistMappingNote' -Default '')
    $fw = [string](Get-NRGObjectField -Item $j -Key 'FrameworkNote' -Default '')
    if ($fw) { $out.FrameworkNote = $fw }

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @(Get-NRGObjectField -Item $j -Key 'recommendations' -Default @())) {
        $id = [string](Get-NRGObjectField -Item $r -Key 'ControlId' -Default '')
        if (-not $id) { continue }
        $cmds = [ordered]@{}
        $cmdNode = Get-NRGObjectField -Item $r -Key 'AdminCommands' -Default $null
        if ($cmdNode) { foreach ($p in $cmdNode.PSObject.Properties) { $cmds[[string]$p.Name] = [string]$p.Value } }
        $entries.Add([pscustomobject][ordered]@{
            ControlId     = $id
            Kind          = [string](Get-NRGObjectField -Item $r -Key 'Kind' -Default 'Finding')
            EmitsFinding  = [bool](Get-NRGObjectField -Item $r -Key 'EmitsFinding' -Default ([string](Get-NRGObjectField -Item $r -Key 'Kind' -Default 'Finding') -eq 'Finding'))
            Title         = [string](Get-NRGObjectField -Item $r -Key 'Title' -Default $id)
            Setting       = [string](Get-NRGObjectField -Item $r -Key 'Setting' -Default '')
            AppliesTo     = @(@(Get-NRGObjectField -Item $r -Key 'AppliesTo' -Default @()) | ForEach-Object { [string]$_ })
            Recommended   = [string](Get-NRGObjectField -Item $r -Key 'Recommended' -Default '')
            Basis         = [string](Get-NRGObjectField -Item $r -Key 'Basis' -Default '')
            StandardKey   = [string](Get-NRGObjectField -Item $r -Key 'StandardKey' -Default '')
            Severity      = [string](Get-NRGObjectField -Item $r -Key 'Severity' -Default 'Informational')
            Why           = [string](Get-NRGObjectField -Item $r -Key 'Why' -Default '')
            SourceUrl     = [string](Get-NRGObjectField -Item $r -Key 'SourceUrl' -Default '')
            AlsoSee       = @(@(Get-NRGObjectField -Item $r -Key 'AlsoSee' -Default @()) | ForEach-Object { [string]$_ })
            Nist80053     = @(@(Get-NRGObjectField -Item $r -Key 'Nist80053' -Default @()) | ForEach-Object { [string]$_ })
            AdminCommands = $cmds
            RuleCommand   = [string](Get-NRGObjectField -Item $r -Key 'RuleCommand' -Default '')
        })
    }
    $out.Entries = @($entries)
    foreach ($e in $entries) { $out.ById[$e.ControlId] = $e }
    $out.Available = ($entries.Count -gt 0)
    if (-not $out.Available) { $out.Error = 'Catalog holds no recommendations.' }
    return $out
}

function Get-NRGDistributionListStandards {
    <#
    .SYNOPSIS
        Interprets the two NRG distribution-list standards (a member cap and a join
        restriction). There is deliberately no standard for external members: the owner
        decided external members stay, so they are shown and never judged. Each answer carries
        Approved ($true only for a recognized, usable value) and Issue (why an
        entered value was not accepted), so "empty" and "entered but unusable" are
        both "not assessed" and the worksheet can say which.
    .PARAMETER Standards
        The dictionary Get-NRGStandards returns; read through when omitted. Tests
        pass one in so the real Config/nrg-standards.json is never edited.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] $Standards)

    if ($null -eq $Standards) { $Standards = Get-NRGStandards }
    $vals = {
        param([string] $Key)
        @(@(Get-NRGObjectField -Item $Standards -Key $Key -Default @()) |
            Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { ([string]$_).Trim() })
    }

    # Max members: exactly one whole number >= 1.
    $max = [ordered]@{ Approved = $false; Value = $null; Issue = '' }
    $m = @(& $vals 'DistributionListMaxMembers')
    if ($m.Count -gt 1) {
        $max.Issue = 'DistributionListMaxMembers must hold one number; it holds ' + $m.Count + ', so no cap is applied.'
    } elseif ($m.Count -eq 1) {
        $n = 0
        if ($m[0] -match '^\d{1,9}$' -and [int]::TryParse($m[0], [ref]$n) -and $n -ge 1) { $max.Approved = $true; $max.Value = $n }
        else { $max.Issue = "DistributionListMaxMembers value '$($m[0])' is not a whole number of 1 or more, so no cap is applied." }
    }

    # Join restriction: any of the three documented values.
    $valid = @('Open', 'Closed', 'ApprovalRequired')
    $join = [ordered]@{ Approved = $false; Allowed = @(); Issue = '' }
    $j = @(& $vals 'DistributionListMemberJoinRestriction')
    if ($j.Count -gt 0) {
        $bad = @($j | Where-Object { $_ -notin $valid })
        if ($bad.Count -gt 0) { $join.Issue = "DistributionListMemberJoinRestriction accepts Open, Closed or ApprovalRequired; '$($bad -join "', '")' is not one of them, so join restriction is not judged." }
        else { $join.Approved = $true; $join.Allowed = @($valid | Where-Object { $_ -in $j }) }
    }

    return [ordered]@{ MaxMembers = $max; JoinRestriction = $join }
}

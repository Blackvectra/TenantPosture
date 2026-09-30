#Requires -Version 7.0
#
# Get-NRGEffectiveCoverage.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Judge COMBINED coverage of a protection that is delivered by one or more
#          scoped policies (Conditional Access, Defender preset rules). A policy that
#          excludes someone is not automatically a gap: another qualifying policy may
#          cover them. A principal is unprotected only when it is excluded from EVERY
#          qualifying policy. Group membership is not resolved, so two policies that
#          exclude DIFFERENT principals leave overlap unproven, never covered.
#
# Kinds:  None        no qualifying policy
#         Full        at least one qualifying policy has no exclusions
#         Exceptions  the same principal(s) are excluded from every qualifying policy
#                     (confirmed unprotected)
#         Unproven    every qualifying policy has exclusions, but none is excluded from
#                     all of them by identifier; whether any user sits in all the
#                     excluded groups was not resolved
#
# Data consumed: none.  Graph scopes / cmdlets: none (parsing only).

function Get-NRGExclusionCoverage {
    <#
    .SYNOPSIS
        $Candidates: objects with Name and Exclusions (string[] of principal ids,
        prefixed by type so a user and a group never collide).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Candidates)

    $c = @($Candidates | Where-Object { $null -ne $_ })
    $r = [ordered]@{ Kind = 'None'; Names = @(); FullNames = @(); Exceptions = @(); ExcludedBy = [ordered]@{} }
    if ($c.Count -eq 0) { return $r }
    $r.Names = @($c | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '') })
    $sets = @(); $full = @()
    foreach ($x in $c) {
        $ex = @(@(Get-NRGObjectField -Item $x -Key 'Exclusions' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        $n = [string](Get-NRGObjectField -Item $x -Key 'Name' -Default '')
        $r.ExcludedBy[$n] = $ex
        if ($ex.Count -eq 0) { $full += $n }
        $sets += ,$ex
    }
    if ($full.Count -gt 0) { $r.Kind = 'Full'; $r.FullNames = $full; return $r }
    $inter = @($sets[0])
    foreach ($s in $sets) { $inter = @($inter | Where-Object { $_ -in $s }) }
    if ($inter.Count -gt 0) { $r.Kind = 'Exceptions'; $r.Exceptions = $inter } else { $r.Kind = 'Unproven' }
    return $r
}

function Get-NRGCANarrowing {
    <#
    .SYNOPSIS
        Why a Conditional Access policy does NOT cover everyone on everything, beyond
        user exclusions: a narrower application, platform, location or device scope, or
        a risk condition. An empty result means the policy's scope is all users and all
        resources with no extra condition.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] $Policy)
    $why = [System.Collections.Generic.List[string]]::new()
    $inc = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.IncludeUsers' -Default @())
    if ($inc -notcontains 'All') { $why.Add('applies to only some users, groups or roles') }
    $apps = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Applications.Include' -Default @())
    if ($apps -notcontains 'All') { $why.Add($(if ($apps -contains 'None' -or $apps.Count -eq 0) { 'applies to no application' } else { 'applies to only some applications' })) }
    if (@(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Applications.Exclude' -Default @() | Where-Object { $_ }).Count -gt 0) { $why.Add('excludes some applications') }
    if (@(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Platforms' -Default @() | Where-Object { $_ }).Count -gt 0) { $why.Add('limited to some device platforms') }
    $locInc = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Locations.Include' -Default @() | Where-Object { $_ })
    if ($locInc.Count -gt 0 -and $locInc -notcontains 'All') { $why.Add('limited to some locations') }
    if (@(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Locations.Exclude' -Default @() | Where-Object { $_ }).Count -gt 0) { $why.Add('excludes some locations') }
    if ([string](Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Devices.FilterMode' -Default '')) { $why.Add('limited by a device filter') }
    if (@(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.SignInRiskLevels' -Default @() | Where-Object { $_ }).Count -gt 0 -or
        @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.UserRiskLevels' -Default @() | Where-Object { $_ }).Count -gt 0) { $why.Add('applies only at certain risk levels') }
    return @($why)
}

function Get-NRGCAPrincipalExclusions {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] $Policy)
    $o = [System.Collections.Generic.List[string]]::new()
    foreach ($id in @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.ExcludeUsers' -Default @() | Where-Object { $_ })) { $o.Add("user:$id") }
    foreach ($id in @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.ExcludeGroups' -Default @() | Where-Object { $_ })) { $o.Add("group:$id") }
    foreach ($id in @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.ExcludeRoles' -Default @() | Where-Object { $_ })) { $o.Add("role:$id") }
    return @($o)
}

function Get-NRGCAEffectiveCoverage {
    <#
    .SYNOPSIS
        Combined coverage for a protection delivered by enabled Conditional Access
        policies. The caller passes the policies that already deliver the protection
        (right grant, client type or flow); this sorts them into those that cover all
        users on all applications with no extra condition (candidates, judged by their
        exclusions) and those narrowed by scope or condition (reported, never counted).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Policies)

    $cands = @(); $narrowed = @()
    foreach ($p in @($Policies | Where-Object { $null -ne $_ })) {
        $name = [string](Get-NRGObjectField -Item $p -Key 'DisplayName' -Default '')
        $nar  = @(Get-NRGCANarrowing -Policy $p)
        if ($nar.Count -gt 0) { $narrowed += [pscustomobject]@{ Name = $name; Why = ($nar -join '; ') }; continue }
        $cands += [pscustomobject]@{ Name = $name; Exclusions = @(Get-NRGCAPrincipalExclusions -Policy $p) }
    }
    $cov = Get-NRGExclusionCoverage -Candidates $cands
    $cov['Narrowed'] = @($narrowed)
    return $cov
}

function Get-NRGCAPrincipalLabel {
    <#
    .SYNOPSIS
        Adds the account name to a 'user:<id>' exclusion when the user list was collected, so a
        finding names who is excluded, not just a GUID. Unresolvable ids stay as they are.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Principal)
    if ($Principal -notmatch '^user:(.+)$') { return $Principal }
    $id = $Matches[1]
    $raw = Get-NRGRawData -Key 'AAD-Users'
    if (-not $raw) { return $Principal }
    foreach ($u in @(Get-NRGNestedProperty -Object $raw -Path 'Data.Users' -Default @())) {
        if ([string](Get-NRGObjectField -Item $u -Key 'Id' -Default '') -eq $id) {
            $upn = [string](Get-NRGObjectField -Item $u -Key 'UserPrincipalName' -Default '')
            if ($upn) { return "$Principal ($upn)" }
        }
    }
    return $Principal
}

function Get-NRGCACoverageVerdict {
    <#
    .SYNOPSIS
        Turns a combined-coverage result into Verified / Shortfalls / NotEstablished
        statements for Add-NRGExpectedStateFinding.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Coverage, [Parameter(Mandatory)] [string] $What)
    $v = @(); $s = @(); $u = @()
    $names = $Coverage.Names -join ', '
    switch ($Coverage.Kind) {
        'Full' {
            $v += "$What for all users on all applications by: $($Coverage.FullNames -join ', ')."
        }
        'Exceptions' {
            $v += "$What by: $names."
            $s += "every qualifying policy excludes the same principal(s), so they are not covered: $((@($Coverage.Exceptions) | ForEach-Object { Get-NRGCAPrincipalLabel -Principal $_ }) -join ', '). If these are emergency-access accounts, record them as an approved exception."
        }
        'Unproven' {
            $v += "$What by: $names."
            $u += "whether any user is excluded from every one of these policies; each excludes different users or groups and group membership was not resolved ($((@($Coverage.ExcludedBy.Keys) | ForEach-Object { "$_ excludes $(@($Coverage.ExcludedBy[$_]).Count)" }) -join '; '))."
        }
    }
    foreach ($n in @($Coverage.Narrowed)) {
        $note = "'$($n.Name)' also delivers it but $($n.Why), so it is not counted as all-user coverage."
        if ($Coverage.Kind -eq 'None') { $s += "only a narrower policy delivers it: $note" }
        elseif ($Coverage.Kind -eq 'Full' -or [string]$n.Why -eq 'applies to no application') { $v += $(if ([string]$n.Why -eq 'applies to no application') { "'$($n.Name)' is enabled but applies to no application, so it provides no protection and is not counted." } else { $note }) }
        else { $u += "what the narrower policy adds: $note" }
    }
    return [ordered]@{ Verified = $v; Shortfalls = $s; NotEstablished = $u }
}

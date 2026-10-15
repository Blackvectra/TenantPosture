#Requires -Version 7.0
#
# Get-TPEffectiveCoverage.ps1
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
# Client app types: a protection that has to apply to every interactive sign-in
# (MFA, an authentication strength, a risk response, a device requirement) is
# narrowed by a policy whose Conditions.ClientAppTypes leaves out 'browser' or
# 'mobileAppsAndDesktopClients' — a browser-only MFA policy leaves every desktop
# and mobile client unprompted. Callers state what they require
# (-RequiredClientAppTypes); the legacy-authentication block requires 'other' and
# passes that instead. 'all' covers every type. Graph requires clientAppTypes on
# every policy, so an empty list is not a read value and is not judged.
#
# Data consumed: none.  Graph scopes / cmdlets: none (parsing only).

function Get-TPExclusionCoverage {
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
    $r.Names = @($c | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '') })
    $sets = @(); $full = @()
    foreach ($x in $c) {
        $ex = @(@(Get-TPObjectField -Item $x -Key 'Exclusions' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        $n = [string](Get-TPObjectField -Item $x -Key 'Name' -Default '')
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

function Get-TPCAInteractiveClientAppTypes {
    <#
    .SYNOPSIS
        The client app types every interactive sign-in uses: the browser and the
        mobile and desktop clients (Microsoft's own MFA and risk templates leave the
        client-apps condition unset, which is these plus the legacy types). The one
        copy of the list; MFA, risk and device-requirement checks require it.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @('browser', 'mobileAppsAndDesktopClients')
}

function Get-TPCAClientAppTypeShortfall {
    <#
    .SYNOPSIS
        Why a policy's client-apps condition leaves some of the required client app
        types outside it, or '' when every required type is covered ('all', or each
        type listed). An empty ClientAppTypes list is not a read value (Graph
        requires the property on every policy) and is not judged; it never counts
        as 'all'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Policy, [AllowNull()] [string[]] $Required)
    $req = @($Required | Where-Object { $_ })
    if ($req.Count -eq 0) { return '' }
    $types = @(Get-TPNestedProperty -Object $Policy -Path 'Conditions.ClientAppTypes' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
    if ($types.Count -eq 0 -or $types -contains 'all') { return '' }
    $missing = @($req | Where-Object { $_ -notin $types })
    if ($missing.Count -eq 0) { return '' }
    return "limited to some client app types ($($types -join ', ')), so $($missing -join ' and ') sign-ins are outside it"
}

function Get-TPCANarrowing {
    <#
    .SYNOPSIS
        Why a Conditional Access policy does NOT cover everyone on everything, beyond
        user exclusions: a narrower application, client-app, platform, location or
        device scope, or a risk condition. An empty result means the policy's scope is
        all users and all resources with no extra condition. -RequiredClientAppTypes
        names the client app types the protection must reach (none by default);
        -Ignore drops reasons the caller expects (a risk policy applies only at
        certain risk levels by design).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] $Policy, [AllowNull()] [string[]] $RequiredClientAppTypes = @(), [AllowNull()] [string[]] $Ignore = @())
    $why = [System.Collections.Generic.List[string]]::new()
    $inc = @(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Users.IncludeUsers' -Default @())
    if ($inc -notcontains 'All') { $why.Add('applies to only some users, groups or roles') }
    $apps = @(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Applications.Include' -Default @())
    if ($apps -notcontains 'All') { $why.Add($(if ($apps -contains 'None' -or $apps.Count -eq 0) { 'applies to no application' } else { 'applies to only some applications' })) }
    if (@(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Applications.Exclude' -Default @() | Where-Object { $_ }).Count -gt 0) { $why.Add('excludes some applications') }
    $clientShort = Get-TPCAClientAppTypeShortfall -Policy $Policy -Required $RequiredClientAppTypes
    if ($clientShort) { $why.Add($clientShort) }
    # Platforms holds Graph's includePlatforms. 'all' is "Any device" and narrows
    # nothing unless platforms are also excluded; a specific list does narrow.
    # Results from before ExcludePlatforms was collected read as no exclusion.
    $platInc = @(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Platforms' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $platExc = @(Get-TPNestedProperty -Object $Policy -Path 'Conditions.ExcludePlatforms' -Default @() | Where-Object { $_ })
    if (($platInc.Count -gt 0 -and $platInc -notcontains 'all') -or $platExc.Count -gt 0) { $why.Add('limited to some device platforms') }
    $locInc = @(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Locations.Include' -Default @() | Where-Object { $_ })
    if ($locInc.Count -gt 0 -and $locInc -notcontains 'All') { $why.Add('limited to some locations') }
    if (@(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Locations.Exclude' -Default @() | Where-Object { $_ }).Count -gt 0) { $why.Add('excludes some locations') }
    if ([string](Get-TPNestedProperty -Object $Policy -Path 'Conditions.Devices.FilterMode' -Default '')) { $why.Add('limited by a device filter') }
    if (@(Get-TPNestedProperty -Object $Policy -Path 'Conditions.SignInRiskLevels' -Default @() | Where-Object { $_ }).Count -gt 0 -or
        @(Get-TPNestedProperty -Object $Policy -Path 'Conditions.UserRiskLevels' -Default @() | Where-Object { $_ }).Count -gt 0) { $why.Add('applies only at certain risk levels') }
    $skip = @($Ignore | Where-Object { $_ })
    return @($why | Where-Object { $_ -notin $skip })
}

function Get-TPCAPrincipalExclusions {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] $Policy)
    $o = [System.Collections.Generic.List[string]]::new()
    foreach ($id in @(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Users.ExcludeUsers' -Default @() | Where-Object { $_ })) { $o.Add("user:$id") }
    foreach ($id in @(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Users.ExcludeGroups' -Default @() | Where-Object { $_ })) { $o.Add("group:$id") }
    foreach ($id in @(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Users.ExcludeRoles' -Default @() | Where-Object { $_ })) { $o.Add("role:$id") }
    return @($o)
}

function Get-TPCAEffectiveCoverage {
    <#
    .SYNOPSIS
        Combined coverage for a protection delivered by enabled Conditional Access
        policies. The caller passes the policies that already deliver the protection
        (right grant, client type or flow); this sorts them into those that cover all
        users on all applications with no extra condition (candidates, judged by their
        exclusions) and those narrowed by scope or condition (reported, never counted).
        -RequiredClientAppTypes and -Ignore are passed to Get-TPCANarrowing.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Policies, [AllowNull()] [string[]] $RequiredClientAppTypes = @(), [AllowNull()] [string[]] $Ignore = @())

    $cands = @(); $narrowed = @()
    foreach ($p in @($Policies | Where-Object { $null -ne $_ })) {
        $name = [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default '')
        $nar  = @(Get-TPCANarrowing -Policy $p -RequiredClientAppTypes $RequiredClientAppTypes -Ignore $Ignore)
        if ($nar.Count -gt 0) { $narrowed += [pscustomobject]@{ Name = $name; Why = ($nar -join '; ') }; continue }
        $cands += [pscustomobject]@{ Name = $name; Exclusions = @(Get-TPCAPrincipalExclusions -Policy $p) }
    }
    $cov = Get-TPExclusionCoverage -Candidates $cands
    $cov['Narrowed'] = @($narrowed)
    return $cov
}

function Get-TPCAPrincipalLabel {
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
    $raw = Get-TPRawData -Key 'AAD-Users'
    if (-not $raw) { return $Principal }
    foreach ($u in @(Get-TPNestedProperty -Object $raw -Path 'Data.Users' -Default @())) {
        if ([string](Get-TPObjectField -Item $u -Key 'Id' -Default '') -eq $id) {
            $upn = [string](Get-TPObjectField -Item $u -Key 'UserPrincipalName' -Default '')
            if ($upn) { return "$Principal ($upn)" }
        }
    }
    return $Principal
}

function Get-TPCACoverageVerdict {
    <#
    .SYNOPSIS
        Turns a combined-coverage result into Verified / Shortfalls / NotEstablished
        statements for Add-TPExpectedStateFinding.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Coverage, [Parameter(Mandatory)] [string] $What)
    $v = @(); $s = @(); $u = @(); $ao = @()
    $names = $Coverage.Names -join ', '
    switch ($Coverage.Kind) {
        'Full' {
            $v += "$What for all users on all applications by: $($Coverage.FullNames -join ', ')."
        }
        'Exceptions' {
            $v += "$What by: $names."
            $s += "every qualifying policy excludes the same principal(s), so they are not covered: $((@($Coverage.Exceptions) | ForEach-Object { Get-TPCAPrincipalLabel -Principal $_ }) -join ', '). If these are emergency-access accounts, record them as an approved exception (the tenant's EmergencyAccess record in Config/baseline-exceptions), which reports the exclusion as approved and keeps it named."
            # The excluded principals as structured data, so the approval pass
            # (Set-TPEmergencyAccessApproval) judges ids, never prose.
            $ao = @(@($Coverage.Exceptions) | ForEach-Object { [ordered]@{ Principal = [string]$_; Exclusion = 'SharedByEveryQualifyingPolicy' } })
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
    return [ordered]@{ Verified = $v; Shortfalls = $s; NotEstablished = $u; AffectedObjects = $ao }
}

function Get-TPCADeviceComplianceCoverage {
    <#
    .SYNOPSIS
        One judgment of the compliant-or-hybrid-joined device requirement for AAD-2.3
        and INT-1.2 (two controls, one question). Enabled policies whose grant
        NECESSARILY involves a device control (Test-TPCAGrantRequires) are judged on
        combined coverage: all users, all applications, no narrowing, and the
        interactive client app types (a browser-only requirement leaves the desktop
        and mobile clients unchecked), with exclusions combined across policies.
        Optional: enabled policies that list a device control only as one alternative
        in the grant (Microsoft's compliant-or-MFA template), which lets MFA alone
        through from an unmanaged device and enforces nothing. Staged: report-only
        policies that would cover everyone if turned on. Both are named, never
        credited. Module scope, not exported; AAD-2.3 and INT-1.2 call it.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Policies)
    $devCtl = @('compliantDevice', 'domainJoinedDevice')
    $pols = @($Policies | Where-Object { $null -ne $_ })
    $stateOf = { param($p) [string](Get-TPObjectField -Item $p -Key 'State' -Default '') }
    $nameOf  = { param($p) [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default '?') }
    $listsDevice = { param($p) @((Get-TPCAGrantAlternatives -Policy $p).Controls | Where-Object { $_ -in $devCtl }).Count -gt 0 }
    $requiring  = @($pols | Where-Object { (& $stateOf $_) -eq 'enabled' -and (Test-TPCAGrantRequires -Policy $_ -Any $devCtl) })
    $optional   = @($pols | Where-Object { (& $stateOf $_) -eq 'enabled' -and (& $listsDevice $_) -and -not (Test-TPCAGrantRequires -Policy $_ -Any $devCtl) })
    $reportOnly = @($pols | Where-Object { (& $stateOf $_) -eq 'enabledForReportingButNotEnforced' -and (Test-TPCAGrantRequires -Policy $_ -Any $devCtl) })
    $types = Get-TPCAInteractiveClientAppTypes
    $cov = Get-TPCAEffectiveCoverage -Policies $requiring -RequiredClientAppTypes $types
    # A report-only policy counts as staged only when it is not narrowed (its
    # exclusions are not judged: it enforces nothing either way).
    $staged = Get-TPCAEffectiveCoverage -Policies $reportOnly -RequiredClientAppTypes $types
    return [ordered]@{
        Coverage  = $cov
        Requiring = @($requiring | ForEach-Object { & $nameOf $_ })
        Optional  = @($optional | ForEach-Object { & $nameOf $_ })
        Staged    = @($staged.Names)
    }
}

function Add-TPCADeviceComplianceFinding {
    <#
    .SYNOPSIS
        Emits the AAD-2.3 or INT-1.2 finding from Get-TPCADeviceComplianceCoverage.
        Satisfied only when enabled policies requiring a device cover all users on all
        applications (Full); a principal every such policy excludes is Partial naming
        it; different exclusions are not assessed; a policy narrower than everyone is
        a Gap that names why; one that lists the device only as an alternative beside
        MFA is Partial naming it (never Satisfied); a report-only policy that would
        cover everyone is Partial, named as staged, because report-only enforces
        nothing; nothing at all is the plain Gap.
        -Consequence is the control's own sentence on what the gap lets through.
        Literal -State values on purpose (Get-TPControlAutomationAudit).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] $Control,
        [AllowNull()] $FrameworkIds,
        [Parameter(Mandatory)] $Model,
        [Parameter(Mandatory)] [string] $Consequence,
        [Parameter(Mandatory)] [string] $RequiredValue
    )
    $cov = $Model.Coverage
    $optionalNames = @($Model.Optional | Where-Object { $_ })
    $stagedNames   = @($Model.Staged | Where-Object { $_ })
    $optionalNote = if ($optionalNames.Count -gt 0) {
        "$($optionalNames -join ', ') lists a compliant or hybrid-joined device only as one alternative in the grant (operator OR), so MFA alone still grants access from an unmanaged device; not counted."
    } else { '' }
    $stagedNote = if ($stagedNames.Count -gt 0) {
        "$($stagedNames -join ', ') would require it of everyone but is in report-only mode, which enforces nothing."
    } else { '' }
    if ($cov.Kind -ne 'None' -or @($cov.Narrowed).Count -gt 0) {
        $cv = Get-TPCACoverageVerdict -Coverage $cov -What 'A compliant or hybrid-joined device is required'
        $v = @($cv.Verified); $s = @($cv.Shortfalls); $u = @($cv.NotEstablished)
        # A note about a policy that is not counted never goes into Verified unless
        # the verdict is already Full: it would turn a Gap into a Partial.
        if ($optionalNote) { if ($cov.Kind -eq 'Full') { $v += $optionalNote } else { $s += $optionalNote } }
        if ($stagedNote)   { if ($cov.Kind -eq 'Full') { $v += $stagedNote }   else { $s += $stagedNote } }
        if ($cov.Kind -eq 'None') { $s += $Consequence }
        Add-TPExpectedStateFinding -ControlId $ControlId -Control $Control -FrameworkIds $FrameworkIds `
            -Verified $v -Shortfalls $s -NotEstablished $u -AffectedObjects $cv.AffectedObjects `
            -CurrentValue "Device requirement: $($cov.Kind) coverage$(if (@($cov.Names).Count) { ' by ' + (@($cov.Names) -join ', ') })" `
            -RequiredValue $RequiredValue
        return
    }
    if ($stagedNames.Count -gt 0) {
        Add-TPFinding -ControlId $ControlId -State 'Partial' -Category $Control.Category -Title $Control.Title -Severity 'Medium' -FrameworkIds $FrameworkIds `
            -Detail "A compliant or hybrid-joined device is required of all users on all applications only by a policy in report-only mode, which enforces nothing: $($stagedNames -join ', '). $Consequence$(if ($optionalNote) { " $optionalNote" })" `
            -CurrentValue "Report-only: $($stagedNames -join ', ')" -RequiredValue $RequiredValue -Remediation $Control.Remediation
    } elseif ($optionalNote) {
        # A device listed only as an alternative stays Partial (pinned since the
        # 2026-10-04 review): the policy prompts for something on every sign-in,
        # but MFA alone still admits an unmanaged device, so it is never Satisfied.
        Add-TPFinding -ControlId $ControlId -State 'Partial' -Category $Control.Category -Title $Control.Title -Severity 'Medium' -FrameworkIds $FrameworkIds `
            -Detail "No Conditional Access policy requires a compliant or hybrid-joined device of everyone. $optionalNote $Consequence" `
            -CurrentValue 'Device requirement optional (OR)' -RequiredValue $RequiredValue -Remediation $Control.Remediation
    } else {
        Add-TPFinding -ControlId $ControlId -State 'Gap' -Category $Control.Category -Title $Control.Title -Severity $Control.Severity -FrameworkIds $FrameworkIds `
            -Detail "No Conditional Access policy requires a compliant or hybrid-joined device. $Consequence" `
            -CurrentValue 'No CA policy requires a compliant or hybrid-joined device' -RequiredValue $RequiredValue -Remediation $Control.Remediation
    }
}

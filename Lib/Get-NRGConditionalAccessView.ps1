#Requires -Version 7.0
#
# Get-NRGConditionalAccessView.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Reporting view of Conditional Access — every policy with its true
#          state and a plain-English description, compared with Microsoft's
#          own documented Conditional Access policy templates. A VIEW, like
#          Get-NRGAssessmentScope: it emits no findings, moves no score, and
#          writes nothing to module state.
#
# Sets:     nothing.
# Consumes: AAD-CAPolicies (Data.Policies, Data.SectionStatus),
#           AAD-AuthPolicies (only through Get-NRGSecurityDefaultsState),
#           AAD-DirectoryRoles (Data.RoleDefinitions, for admin-role coverage),
#           Config/conditional-access-baseline.json,
#           an optional license profile (Get-NRGTenantLicenseProfile output).
# Cmdlets / Graph: none.
#
# Why this exists (owner's ask, 2026-09-25): "does the report say what CA
# policies are enabled in audit mode and maybe provide CA that should be in
# place for future. I know you can add so many policies i could add one just
# for an app we use or linkedin for example." So: every policy's real state —
# On (enabled), Report-only (audit) (enabledForReportingButNotEnforced) or Off
# (disabled), never blurred into one another; a comparison against Microsoft's
# own templates, so a client can see what still needs building; and a policy
# scoped to one app (the owner's LinkedIn example) is listed as custom and
# never judged against a template it was never meant to satisfy.
#
# Matching is deliberately conservative: a template is Enforced only when the
# policy is enabled, targets ALL users (or, for the two admin templates, at
# least one role this tenant's own AAD-DirectoryRoles catalog marks
# privileged), targets ALL resources with no resource exclusion, and its
# grant/condition genuinely requires what the template requires. Anything
# report-only, disabled, narrower in scope, or weaker in its grant is shown as
# "Similar" (it exists and relates to the template but does not fully
# implement it) rather than credited — never Enforced from a resource-scoped
# or report-only policy. A policy matching no template is Custom and is never
# judged: the LinkedIn/single-app case is exactly this.

function Get-NRGCABaselineCatalog {
    <#
    .SYNOPSIS
        The recommended Conditional Access template catalog, cached.
    .DESCRIPTION
        Reads Config/conditional-access-baseline.json once per module load.
        Returns $null (never throws) if the file is missing or malformed, so
        callers can render a "could not be built" state instead of crashing
        the report.
    #>
    [CmdletBinding()]
    param([string] $CatalogPath)

    if (-not $CatalogPath -and $null -ne (Get-Variable -Name NRGCABaselineCatalog -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) {
        return $script:NRGCABaselineCatalog
    }
    $path = if ($CatalogPath) { $CatalogPath } else { Join-Path (Split-Path -Parent $PSScriptRoot) 'Config/conditional-access-baseline.json' }
    try {
        if (-not (Test-Path -LiteralPath $path)) { return $null }
        $cfg = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
        $templates = @(Get-NRGObjectField -Item $cfg -Key 'templates' -Default @())
        if ($templates.Count -eq 0) { return $null }
        if (-not $CatalogPath) { $script:NRGCABaselineCatalog = $templates }
        return $templates
    } catch {
        Write-Verbose "Get-NRGCABaselineCatalog: $path unreadable or malformed. $($_.Exception.Message)"
        return $null
    }
}

# "On" / "Report-only (audit)" / "Off" / "Unknown state (<raw>)". A state the
# tool does not recognize is never Off — an unrecognized value is not evidence
# the policy is inactive.
function Get-NRGCAStateLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $State)
    switch ($State) {
        'enabled'                             { return 'On' }
        'enabledForReportingButNotEnforced'   { return 'Report-only (audit)' }
        'disabled'                            { return 'Off' }
        default                               { return "Unknown state ($(if ($State) { $State } else { 'not read' }))" }
    }
}

# Plain-English description of one policy's conditions and controls, built
# only from the fields the collector stores (Invoke-NRGCollectAADCAPolicies).
function Get-NRGCAPolicyDescription {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Policy, [hashtable] $RoleNames)

    $users = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.IncludeUsers' -Default @())
    $whoParts = [System.Collections.Generic.List[string]]::new()
    if ($users -contains 'All') {
        $whoParts.Add('all users')
    } else {
        $roleIds = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.IncludeRoles' -Default @() | Where-Object { $_ })
        if ($roleIds.Count -gt 0) {
            $names = @($roleIds | ForEach-Object { if ($RoleNames -and $RoleNames.ContainsKey([string]$_)) { $RoleNames[[string]$_] } else { $_ } })
            $whoParts.Add("$($roleIds.Count) role(s): $(($names | Select-Object -First 5) -join ', ')$(if ($roleIds.Count -gt 5) { ', and more' })")
        }
        $grpCount = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.IncludeGroups' -Default @() | Where-Object { $_ }).Count
        if ($grpCount -gt 0) { $whoParts.Add("$grpCount group(s)") }
        $usrCount = @($users | Where-Object { $_ -and $_ -ne 'All' }).Count
        if ($usrCount -gt 0) { $whoParts.Add("$usrCount named user(s)") }
        if ($whoParts.Count -eq 0) { $whoParts.Add('a scoped set of users') }
    }
    $excUsers = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.ExcludeUsers' -Default @() | Where-Object { $_ }).Count
    $excGrps  = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.ExcludeGroups' -Default @() | Where-Object { $_ }).Count
    $excRoles = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.ExcludeRoles' -Default @() | Where-Object { $_ }).Count
    $excNote = ''
    if ($excUsers + $excGrps + $excRoles -gt 0) {
        $bits = @()
        if ($excUsers) { $bits += "$excUsers user(s)" }
        if ($excGrps)  { $bits += "$excGrps group(s)" }
        if ($excRoles) { $bits += "$excRoles role(s)" }
        $excNote = ", excluding $($bits -join ', ')"
    }

    $apps = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Applications.Include' -Default @())
    $what = if ($apps -contains 'All') { 'all cloud apps' }
            elseif ($apps.Count -gt 0) { "$($apps.Count) specific app(s)/resource(s)" }
            else { 'no resources are targeted (not evaluated by any sign-in)' }
    $excApps = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Applications.Exclude' -Default @() | Where-Object { $_ }).Count
    $appExcNote = if ($excApps -gt 0) { ", excluding $excApps resource(s)" } else { '' }

    $grant = Get-NRGCAGrantAlternatives -Policy $Policy
    $controlsText = if ($grant.Controls.Count -eq 0) {
        'requires no access control (grant not read or not configured)'
    } else {
        $names = @($grant.Controls | ForEach-Object {
            switch ($_) {
                'mfa'             { 'multifactor authentication' }
                'block'           { 'blocking access' }
                'compliantDevice' { 'a compliant device' }
                'domainJoinedDevice' { 'a Microsoft Entra hybrid joined device' }
                'authStrength'    { 'an authentication strength' }
                'termsOfUse'      { 'terms of use' }
                'passwordChange'  { 'a password change' }
                'compliantApplication' { 'an approved client app' }
                default           { [string]$_ }
            }
        })
        $joiner = if ($grant.Operator -eq 'OR') { ' or ' } else { ' and ' }
        "requires $($names -join $joiner)"
    }

    "Targets $($whoParts -join ', ')$excNote, for $what$appExcNote, and $controlsText."
}

# ── Template match functions ──────────────────────────────────────────────
# Each returns 'Enforced' | 'Similar' | 'NoMatch'. 'Enforced' is only ever
# returned for a policy that is State 'enabled': callers gate on state first,
# so a report-only or disabled policy that would otherwise match is always
# 'Similar', never 'Enforced'.

function Test-NRGCAAllResourcesNoExclusion {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $Policy)
    if (-not (Test-NRGCAAllApps -Policy $Policy)) { return $false }
    return (@(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Applications.Exclude' -Default @() | Where-Object { $_ }).Count -eq 0)
}

function Get-NRGCAAdminRoleCoverage {
    <#
    .SYNOPSIS
        Which of the tenant's own privileged roles (AAD-DirectoryRoles,
        IsPriv = $true) this policy's IncludeRoles covers, minus ExcludeRoles.
    .DESCRIPTION
        Never claims Microsoft's specific 14-role list is covered — it can
        only compare against roles this tenant's own role catalog says are
        privileged, and says so. $null when the role catalog was not
        collected: coverage cannot be judged either way.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy, [AllowNull()] [hashtable] $PrivRoleIds)
    if ($null -eq $PrivRoleIds) { return $null }
    if ($PrivRoleIds.Count -eq 0) { return $null }
    $inc = [System.Collections.Generic.HashSet[string]]::new([string[]]@(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.IncludeRoles' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ }))
    $exc = [System.Collections.Generic.HashSet[string]]::new([string[]]@(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.ExcludeRoles' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ }))
    $allUsers = (@(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.IncludeUsers' -Default @()) -contains 'All')
    $covered = [System.Collections.Generic.List[string]]::new()
    foreach ($rid in $PrivRoleIds.Keys) {
        if ($exc.Contains($rid)) { continue }
        if ($allUsers -or $inc.Contains($rid)) { $covered.Add($rid) }
    }
    [pscustomobject]@{ CoveredCount = $covered.Count; TotalPriv = $PrivRoleIds.Count; RoleScoped = ($inc.Count -gt 0 -and -not $allUsers) }
}

function Test-NRGCATemplateMatch {
    <#
    .SYNOPSIS
        Match one policy against one template. Returns 'Enforced' | 'Similar' | 'NoMatch'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $TemplateId, [Parameter(Mandatory)] $Policy, [hashtable] $PrivRoleIds)

    $isOn = ([string](Get-NRGObjectField -Item $Policy -Key 'State' -Default '') -eq 'enabled')

    # Every template below except mfa-azure-mgmt (which is deliberately
    # scoped to one resource suite) targets ALL resources. A policy scoped to
    # fewer resources — the owner's example: one scoped just to LinkedIn — is
    # never "similar" to a broad template: it is a different, deliberate
    # policy and is left Custom, never compared. This is the single gate that
    # keeps a narrow, intentional policy from being read as an incomplete
    # attempt at a template it was never meant to satisfy.
    $allApps = Test-NRGCAAllApps -Policy $Policy

    switch ($TemplateId) {
        'block-legacy-auth' {
            if (-not $allApps) { return 'NoMatch' }
            # 'other' is the client-app type that carries IMAP, POP and SMTP
            # AUTH — the same field the scored AAD-1.1 evaluator keys on
            # (Test-NRGControlAADLegacyAuth), so the two never disagree about
            # which policies are even eligible.
            $types = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.ClientAppTypes' -Default @() | ForEach-Object { [string]$_ })
            if ($types -notcontains 'other') { return 'NoMatch' }
            # Grant must actually BLOCK. Requiring MFA on legacy-protocol
            # traffic is not a partial implementation of this template —
            # legacy clients cannot complete an MFA challenge either way, so
            # a policy that only requires MFA here is not evidence of
            # anything and is left NoMatch rather than shown as Similar.
            if (-not (Test-NRGCAGrantRequires -Policy $Policy -Any @('block'))) { return 'NoMatch' }
            if ($isOn -and (Test-NRGCAAllUsers -Policy $Policy)) { return 'Enforced' }
            return 'Similar'
        }
        'mfa-all-users' {
            if (-not $allApps) { return 'NoMatch' }
            if (-not (Test-NRGCAAllUsers -Policy $Policy)) { return 'NoMatch' }
            $needsMfa = Test-NRGCAGrantRequires -Policy $Policy -Any @('mfa', 'authStrength')
            if (-not $needsMfa) { return 'NoMatch' }
            if ($isOn -and (Test-NRGCAAllResourcesNoExclusion -Policy $Policy)) { return 'Enforced' }
            return 'Similar'
        }
        'mfa-admins' {
            if (-not $allApps) { return 'NoMatch' }
            $cov = Get-NRGCAAdminRoleCoverage -Policy $Policy -PrivRoleIds $PrivRoleIds
            if ($null -eq $cov -or $cov.CoveredCount -eq 0) { return 'NoMatch' }
            $needsMfa = Test-NRGCAGrantRequires -Policy $Policy -Any @('mfa', 'authStrength')
            if (-not $needsMfa) { return 'NoMatch' }
            if ($isOn -and $cov.CoveredCount -eq $cov.TotalPriv) { return 'Enforced' }
            return 'Similar'
        }
        'admin-phish-resistant-mfa' {
            if (-not $allApps) { return 'NoMatch' }
            $cov = Get-NRGCAAdminRoleCoverage -Policy $Policy -PrivRoleIds $PrivRoleIds
            if ($null -eq $cov -or $cov.CoveredCount -eq 0) { return 'NoMatch' }
            $phish = Test-NRGAuthStrengthPhishResistant -GrantControls (Get-NRGNestedProperty -Object $Policy -Path 'GrantControls' -Default $null)
            if ($phish -ne $true) { return 'NoMatch' }
            if ($isOn -and $cov.CoveredCount -eq $cov.TotalPriv) { return 'Enforced' }
            return 'Similar'
        }
        'mfa-azure-mgmt' {
            # Deliberately resource-scoped by Microsoft's own design, not an
            # "All resources" template, so no allApps gate here: a policy
            # scoped to exactly this resource suite is the correct
            # implementation, not a narrower cousin of it.
            $azureMgmt = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
            $apps = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Applications.Include' -Default @() | ForEach-Object { [string]$_ })
            $excl = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Applications.Exclude' -Default @() | ForEach-Object { [string]$_ })
            # An exclusion of this resource means the policy never applies to it.
            $targetsAzureMgmt = ($apps -contains 'All' -or $apps -contains $azureMgmt) -and $excl -notcontains $azureMgmt
            if (-not $targetsAzureMgmt) { return 'NoMatch' }
            $needsMfa = Test-NRGCAGrantRequires -Policy $Policy -Any @('mfa', 'authStrength')
            if (-not $needsMfa) { return 'NoMatch' }
            if ($isOn -and (Test-NRGCAAllUsers -Policy $Policy)) { return 'Enforced' }
            return 'Similar'
        }
        'block-device-code' {
            if (-not $allApps) { return 'NoMatch' }
            $flows = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.AuthFlows' -Default @())
            $methods = (@($flows | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'transferMethods' -Default '') }) -join ',')
            if ($methods -notmatch 'deviceCode') { return 'NoMatch' }
            # Grant must BLOCK. A device-code policy that only requires MFA
            # does not stop the flow — attackers relay the MFA prompt too
            # (the same rule AAD-11.1's evaluator applies) — so it is left
            # NoMatch, never shown as a partial implementation.
            if (-not (Test-NRGCAGrantRequires -Policy $Policy -Any @('block'))) { return 'NoMatch' }
            if ($isOn -and (Test-NRGCAAllUsers -Policy $Policy)) { return 'Enforced' }
            return 'Similar'
        }
        'sign-in-risk' {
            if (-not $allApps) { return 'NoMatch' }
            # Microsoft's template selects High and Medium. Risk levels are
            # discrete, so a policy with neither never applies to an elevated
            # sign-in; one with only one of them is part of the template.
            $levels = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.SignInRiskLevels' -Default @() | ForEach-Object { [string]$_ })
            $high = $levels -contains 'high'; $medium = $levels -contains 'medium'
            if (-not ($high -or $medium)) { return 'NoMatch' }
            $responds = Test-NRGCAGrantRequires -Policy $Policy -Any @('mfa', 'authStrength', 'block')
            if (-not $responds) { return 'NoMatch' }
            if ($isOn -and $high -and $medium -and (Test-NRGCAAllUsers -Policy $Policy)) { return 'Enforced' }
            return 'Similar'
        }
        'user-risk' {
            if (-not $allApps) { return 'NoMatch' }
            # "Require password change for high-risk users": a policy without
            # High never applies to the users the template exists for.
            $levels = @(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.UserRiskLevels' -Default @() | ForEach-Object { [string]$_ })
            if ($levels -notcontains 'high') { return 'NoMatch' }
            $responds = Test-NRGCAGrantRequires -Policy $Policy -Any @('mfa', 'authStrength', 'passwordChange', 'riskRemediation', 'unknownFutureValue', 'block')
            if (-not $responds) { return 'NoMatch' }
            if ($isOn -and (Test-NRGCAAllUsers -Policy $Policy)) { return 'Enforced' }
            return 'Similar'
        }
        'device-compliance-all-users' {
            if (-not $allApps) { return 'NoMatch' }
            if (-not (Test-NRGCAAllUsers -Policy $Policy)) { return 'NoMatch' }
            $requiresDevice = Test-NRGCAGrantRequires -Policy $Policy -Any @('compliantDevice', 'domainJoinedDevice')
            if (-not $requiresDevice) { return 'NoMatch' }
            if ($isOn -and (Test-NRGCAAllResourcesNoExclusion -Policy $Policy)) { return 'Enforced' }
            return 'Similar'
        }
        'compliant-hybrid-or-mfa-all-users' {
            if (-not $allApps) { return 'NoMatch' }
            if (-not (Test-NRGCAAllUsers -Policy $Policy)) { return 'NoMatch' }
            $grant = Get-NRGCAGrantAlternatives -Policy $Policy
            $hasDevice = @($grant.Controls | Where-Object { $_ -in @('compliantDevice', 'domainJoinedDevice') }).Count -gt 0
            $hasMfa = @($grant.Controls | Where-Object { $_ -in @('mfa', 'authStrength') }).Count -gt 0
            if (-not ($grant.Operator -eq 'OR' -and $hasDevice -and $hasMfa)) { return 'NoMatch' }
            if ($isOn) { return 'Enforced' }
            return 'Similar'
        }
        'persistent-browser' {
            if (-not $allApps) { return 'NoMatch' }
            $pb = Get-NRGNestedProperty -Object $Policy -Path 'SessionControls.PersistentBrowser' -Default $null
            if ($null -eq $pb) { return 'NoMatch' }
            $enabled = [bool](Get-NRGObjectField -Item $pb -Key 'IsEnabled' -Default $false)
            if (-not $enabled) { return 'NoMatch' }
            $mode = [string](Get-NRGObjectField -Item $pb -Key 'Mode' -Default '')
            if ($isOn -and $mode -eq 'never' -and (Test-NRGCAAllUsers -Policy $Policy)) { return 'Enforced' }
            return 'Similar'
        }
        default { return 'NoMatch' }
    }
}

function Get-NRGConditionalAccessView {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [object] $RawData,
        [AllowNull()] [object] $LicenseProfile,
        [string] $CatalogPath
    )
    Set-StrictMode -Version Latest

    $result = [ordered]@{
        Available          = $false
        UnavailableReason  = ''
        ReadStatus         = 'NotCollected'
        SecurityDefaultsState = $null
        Policies           = @()
        Counts             = [ordered]@{ Total = 0; On = 0; ReportOnly = 0; Off = 0; Unknown = 0
                                          MatchesRecommendation = 0; SimilarToRecommendation = 0; Custom = 0 }
        Baseline           = @()
        Custom             = @()
    }

    $catalog = Get-NRGCABaselineCatalog -CatalogPath $CatalogPath
    if ($null -eq $catalog) {
        $result.UnavailableReason = 'The Conditional Access baseline catalog (Config/conditional-access-baseline.json) could not be read.'
        return $result
    }
    foreach ($req in @('Get-NRGCAGrantAlternatives', 'Test-NRGCAAllUsers', 'Test-NRGCAAllApps', 'Test-NRGAuthStrengthPhishResistant', 'Get-NRGSecurityDefaultsState')) {
        if (-not (Get-Command $req -ErrorAction SilentlyContinue)) {
            $result.UnavailableReason = "Required helper '$req' is not loaded."
            return $result
        }
    }

    $rd = if ($null -ne $RawData) { $RawData } elseif (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) { Get-NRGRawData } else { $null }
    $ca = if ($rd -and $rd -is [System.Collections.IDictionary] -and $rd.Contains('AAD-CAPolicies')) { $rd['AAD-CAPolicies'] }
          elseif ($rd -and (Get-NRGObjectField -Item $rd -Key 'AAD-CAPolicies' -Default $null)) { Get-NRGObjectField -Item $rd -Key 'AAD-CAPolicies' -Default $null }
          elseif ($null -eq $RawData -and (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue)) { Get-NRGRawData -Key 'AAD-CAPolicies' }
          else { $null }

    $result.SecurityDefaultsState = Get-NRGSecurityDefaultsState

    if ($null -eq $ca) {
        $result.ReadStatus = 'NotCollected'
        $result.Available = $true
        return $result
    }
    if ((Get-NRGObjectField -Item $ca -Key 'Success' -Default $null) -ne $true) {
        $result.ReadStatus = 'CollectorFailed'
        $result.Available = $true
        return $result
    }
    $result.ReadStatus = 'Collected'
    $result.Available = $true

    # Role catalog for admin-role coverage. $null (not @{}) when not
    # collected, so Get-NRGCAAdminRoleCoverage can tell "no privileged roles"
    # from "the catalog was not read".
    $privRoleIds = $null
    $roleNames = @{}
    $roleRaw = if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) { Get-NRGRawData -Key 'AAD-DirectoryRoles' } else { $null }
    if ($roleRaw -and (Get-NRGObjectField -Item $roleRaw -Key 'Success' -Default $null) -eq $true) {
        $defs = @(Get-NRGNestedProperty -Object $roleRaw -Path 'Data.RoleDefinitions' -Default @())
        if ($defs.Count -gt 0) {
            $privRoleIds = @{}
            foreach ($d in $defs) {
                $id = [string](Get-NRGObjectField -Item $d -Key 'Id' -Default '')
                if (-not $id) { continue }
                $roleNames[$id] = [string](Get-NRGObjectField -Item $d -Key 'DisplayName' -Default $id)
                if ((Get-NRGObjectField -Item $d -Key 'IsPriv' -Default $false) -eq $true) { $privRoleIds[$id] = $true }
            }
        }
    }

    $policies = @(Get-NRGNestedProperty -Object $ca -Path 'Data.Policies' -Default @() | Where-Object { $null -ne $_ })
    $sdOn = ($result.SecurityDefaultsState -eq $true)

    $viewPolicies = [System.Collections.Generic.List[object]]::new()
    $custom = [System.Collections.Generic.List[object]]::new()
    $matchByTemplate = @{}
    foreach ($t in $catalog) { $matchByTemplate[[string]$t.Id] = [ordered]@{ Enforced = @(); Similar = @() } }

    foreach ($p in $policies) {
        $stateRaw = [string](Get-NRGObjectField -Item $p -Key 'State' -Default '')
        $name = [string](Get-NRGObjectField -Item $p -Key 'DisplayName' -Default '(unnamed policy)')
        $matched = [System.Collections.Generic.List[string]]::new()
        $similar = [System.Collections.Generic.List[string]]::new()
        foreach ($t in $catalog) {
            $r = Test-NRGCATemplateMatch -TemplateId ([string]$t.Id) -Policy $p -PrivRoleIds $privRoleIds
            if ($r -eq 'Enforced') { $matched.Add([string]$t.Id); $matchByTemplate[[string]$t.Id].Enforced += $name }
            elseif ($r -eq 'Similar') { $similar.Add([string]$t.Id); $matchByTemplate[[string]$t.Id].Similar += $name }
        }
        $cls = if ($matched.Count -gt 0) { 'MatchesRecommendation' } elseif ($similar.Count -gt 0) { 'SimilarToRecommendation' } else { 'Custom' }
        $entry = [ordered]@{
            Id              = [string](Get-NRGObjectField -Item $p -Key 'Id' -Default '')
            DisplayName     = $name
            StateRaw        = $stateRaw
            StateLabel      = Get-NRGCAStateLabel -State $stateRaw
            Description     = Get-NRGCAPolicyDescription -Policy $p -RoleNames $roleNames
            Classification  = $cls
            MatchedTemplateIds = @($matched)
            SimilarTemplateIds = @($similar)
        }
        $viewPolicies.Add($entry)
        if ($cls -eq 'Custom') { $custom.Add($entry) }

        switch ($stateRaw) {
            'enabled'                           { $result.Counts.On++ }
            'enabledForReportingButNotEnforced' { $result.Counts.ReportOnly++ }
            'disabled'                          { $result.Counts.Off++ }
            default                             { $result.Counts.Unknown++ }
        }
        switch ($cls) {
            'MatchesRecommendation'   { $result.Counts.MatchesRecommendation++ }
            'SimilarToRecommendation' { $result.Counts.SimilarToRecommendation++ }
            'Custom'                  { $result.Counts.Custom++ }
        }
    }
    $result.Counts.Total = $policies.Count
    $result.Policies = @($viewPolicies)
    $result.Custom = @($custom)

    # Baseline comparison. Security Defaults means NO Conditional Access
    # policy can be in force (Get-NRGSecurityDefaultsState's documented
    # rule), so every template is CoveredBySecurityDefaults or Missing
    # depending on what Security Defaults itself is documented to do — never
    # Enforced from a policy that cannot take effect.
    $sdCovers = @{ 'block-legacy-auth' = $true; 'mfa-admins' = $true; 'mfa-azure-mgmt' = $true; 'block-device-code' = $true }
    $baseline = [System.Collections.Generic.List[object]]::new()
    foreach ($t in $catalog) {
        $tid = [string]$t.Id
        # A live, enabled policy is direct evidence the license is held —
        # licensing is judged only for a template NOTHING implements. And
        # "no SKU data" is not "not licensed" (Get-NRGAssessmentScope's same
        # rule): a null LicenseProfile makes Test-NRGLicenseRequirementMet
        # return $false, which is correct for "assume the gap needs a
        # license" but wrong for a firm "you are not licensed" claim, so it
        # is worded as unread, not as a confirmed missing license. A profile
        # object is not evidence either: Get-NRGTenantLicenseProfile returns
        # one with HasLicenseData = $false when no SKU was read.
        $licKnown = ($null -ne $LicenseProfile) -and ((Get-NRGObjectField -Item $LicenseProfile -Key 'HasLicenseData' -Default $false) -eq $true)
        $licMet = $true
        if ($licKnown -and (Get-Command Test-NRGLicenseRequirementMet -ErrorAction SilentlyContinue)) {
            try { $licMet = Test-NRGLicenseRequirementMet -LicenseRequirement ([string]$t.LicenseRequirement) -LicenseProfile $LicenseProfile } catch { $licMet = $true }
        }
        $status = 'Missing'
        $note = ''
        if ($sdOn) {
            if ($sdCovers.ContainsKey($tid)) {
                $status = 'CoveredBySecurityDefaults'
                $note = 'Security Defaults enforces this without a Conditional Access policy.'
            } else {
                $status = 'Missing'
                $note = 'Security Defaults is enabled and does not provide this; a Conditional Access policy cannot be turned on while it is on.'
            }
        } elseif ($null -eq $result.SecurityDefaultsState -and $result.Counts.On -eq 0) {
            $status = 'NotRead'
            $note = 'Whether Security Defaults is on was not read; with no Conditional Access policy On, either could be true.'
        } elseif (@($matchByTemplate[$tid].Enforced).Count -gt 0) {
            $status = 'Enforced'
        } elseif (@($matchByTemplate[$tid].Similar).Count -gt 0) {
            $status = 'Similar'
            $note = 'A related policy exists but is report-only, disabled, or narrower than this template.'
        } elseif ($licKnown -and -not $licMet) {
            $status = 'NotLicensed'
            $note = "Requires $($t.LicenseRequirement)."
        } elseif (-not $licKnown) {
            $note = 'Licensing was not read, so whether this needs a purchase is unknown.'
        }
        $baseline.Add([ordered]@{
            Id                   = $tid
            Name                 = [string]$t.Name
            Category             = [string]$t.Category
            SourceUrl            = [string]$t.SourceUrl
            Summary              = [string]$t.Summary
            LicenseRequirement   = [string]$t.LicenseRequirement
            Status               = $status
            Note                 = $note
            MatchingPolicyNames  = @($matchByTemplate[$tid].Enforced)
            SimilarPolicyNames   = @($matchByTemplate[$tid].Similar)
        })
    }
    $result.Baseline = @($baseline)

    return $result
}

#Requires -Version 7.0
#
# Get-TPSecurityDefaultsState.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: Single reader of Security Defaults state and the shared finding emitter for Conditional Access controls while it is on.
#
# Consumes: AAD-AuthPolicies (Data.SecurityDefaults.IsEnabled),
#           AAD-CAPolicies (Data.Policies[].State/DisplayName)
# Sets: none.
# Graph / cmdlets: No Graph calls. Module state only.
#
# Why this exists. While Security Defaults is enabled, Microsoft lets
# Conditional Access policies be created but not turned on
# (https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/set-up-multi-factor-authentication),
# so the CA list is empty or holds only policies that cannot take effect.
# Every CA control read that as a tenant with nothing protecting it ("no CA
# policy blocks legacy authentication") and the break-glass check reported
# "no emergency access path", while Security Defaults was blocking legacy
# authentication and device code flow and requiring administrators to do MFA.
#
# The rules:
#   - Get-TPSecurityDefaultsState returns $true / $false only for a genuine
#     boolean read from a successful AAD-AuthPolicies collection. Anything
#     else is $null, which means "not read" and never "disabled". Callers
#     compare -eq $true / -eq $false; the value is never used as a boolean.
#   - A CA policy is never credited beside Security Defaults, and a Security
#     Defaults verdict is never asserted over a CA read that contradicts it:
#     a CA policy reported On beside Security Defaults (documented as
#     impossible) makes the control not assessed.
#   - A state that was NOT read is not "disabled". Where the Conditional
#     Access read shows no policy On (the only case in which Security Defaults
#     can be enabled), a control whose verdict differs between Security
#     Defaults on and off is not assessed (Test-TPSecurityDefaultsUnresolved,
#     Add-TPSecurityDefaultsUnreadFinding); Get-TPAssessmentScope files it
#     as a collection gap by the unread prefix.
#   - Security Defaults is free (Microsoft: "Required licenses: None"), so a
#     finding whose remaining fix needs no license (legacy authentication
#     blocked, device code flow blocked, an MFA registration shortfall) is
#     not license gated: Test-TPSecurityDefaultsLicenseFree names those
#     findings, and Test-TPLicenseRequirementMet -Finding answers "met" for
#     them. AAD-1.2 with every user registered is still Partial (only the 16
#     named administrator roles do MFA at every sign-in), and what remains
#     needs Conditional Access, so that finding stays license gated.
#   - A finding emitted here carries its own remediation (the move to
#     Conditional Access); Get-TPFindingRemediation makes the publishers
#     render it instead of the control's generic text.
#   - None of these functions is exported; evaluators, collectors, publishers
#     and the Lib views call them in module scope.

# Every finding Add-TPSecurityDefaultsFinding emits starts with this, and
# Test-TPSecurityDefaultsLicenseFree keys on it (replayed results carry the
# Detail, not the raw data). Change both together.
$script:TPSecurityDefaultsDetailPrefix = 'Security Defaults is enabled. '

# Every finding Add-TPSecurityDefaultsUnreadFinding emits starts with this,
# and Get-TPAssessmentScope files it as a collection gap by it (the state
# could be read on a re-run; no license is implied). Change both together.
$script:TPSecurityDefaultsUnreadPrefix = 'Security Defaults state was not read. '

# Controls whose Security Defaults findings can need no license: Security
# Defaults blocks legacy authentication (AAD-1.1) and device code flow
# (AAD-11.1), and an AAD-1.2 registration shortfall is fixed by registering
# users. Which AAD-1.2 findings qualify: Test-TPSecurityDefaultsLicenseFree.
$script:TPSecurityDefaultsLicenseFreeControls = @('AAD-1.1', 'AAD-1.2', 'AAD-11.1')

# The AAD-1.2 Security Defaults registration-shortfall Detail contains this,
# and Test-TPSecurityDefaultsLicenseFree keys on it. Change both together.
$script:TPSecurityDefaultsShortfallMarker = 'have not registered a method'

$script:TPSecurityDefaultsCAClause = 'Microsoft documents that Conditional Access policies can be created but cannot be turned on while Security Defaults is enabled, so no Conditional Access policy is in force.'

$script:TPSecurityDefaultsTransition = 'Security Defaults must be turned off before any Conditional Access policy can be turned on; Microsoft says organizations that replace it with Conditional Access must disable it and should immediately enable Conditional Access policies. Create the replacement policies first (they can be created, not turned on, while Security Defaults is enabled): require MFA for all users, require MFA for administrators, block legacy authentication, block device code flow and require MFA for Azure management. Then turn off Security Defaults and turn those policies on in the same change, so the tenant is not left without the protections Security Defaults provides. Conditional Access requires Microsoft Entra ID P1 or Microsoft 365 Business Premium.'

$script:TPSecurityDefaultsNoExclusionNote = ' An administrator cannot exclude any account from Security Defaults (its only exclusion is Microsoft''s automatic one for directory synchronization accounts), so emergency access (break-glass) accounts cannot be recognized by Conditional Access exclusion; none was set aside.'

function Get-TPSecurityDefaultsState {
    <#
    .SYNOPSIS
        $true / $false when Security Defaults was read; $null when it was not.
    .DESCRIPTION
        $null covers every way the state can go unread: AAD-AuthPolicies is
        absent, its Success is not $true, Data.SecurityDefaults is $null (the
        collector's sub-read threw), or IsEnabled is absent, null or not a
        boolean ('true', 1). Replayed results JSON qualifies, because
        ConvertFrom-Json turns JSON true/false into [bool]. Never throws.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)] [AllowNull()] [object] $AuthPolicies)

    if (-not $PSBoundParameters.ContainsKey('AuthPolicies')) {
        $AuthPolicies = if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) { Get-TPRawData -Key 'AAD-AuthPolicies' } else { $null }
    }
    if ($null -eq $AuthPolicies) { return $null }
    if ((Get-TPObjectField -Item $AuthPolicies -Key 'Success' -Default $null) -ne $true) { return $null }
    $v = Get-TPNestedProperty -Object $AuthPolicies -Path 'Data.SecurityDefaults.IsEnabled' -Default $null
    if ($v -is [bool]) { return $v }
    return $null
}

function Add-TPSecurityDefaultsFinding {
    <#
    .SYNOPSIS
        Emits a Conditional Access control's finding on a tenant where
        Security Defaults is enabled.
    .DESCRIPTION
        Precondition: the caller has checked (Get-TPSecurityDefaultsState)
        -eq $true. -Detail is the control-specific body; this prefixes
        "Security Defaults is enabled." and appends the documented reason no
        CA policy is in force, plus the CA policies that cannot take effect.
        A CA read listing a policy as On beside Security Defaults is a
        contradiction and yields NotApplicable instead of -State.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Title,
        [AllowNull()] $FrameworkIds,
        [Parameter(Mandatory)] [ValidateSet('Satisfied','Partial','Gap','NotApplicable')] [string] $State,
        [string] $Severity,
        [Parameter(Mandatory)] [string] $Detail,
        [string] $CurrentValue,
        [string] $RequiredValue,
        [string] $Remediation,
        [switch] $NeedsConditionalAccess
    )

    # (a) Conditional Access context, read only as positively collected data.
    $ca = if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) { Get-TPRawData -Key 'AAD-CAPolicies' } else { $null }
    $caRead = ($null -ne $ca) -and ((Get-TPObjectField -Item $ca -Key 'Success' -Default $null) -eq $true)
    $pols = @()
    if ($caRead) {
        $pols = @(@(Get-TPNestedProperty -Object $ca -Path 'Data.Policies' -Default @()) | Where-Object { $null -ne $_ })
    }
    $stateOf = { param($p) [string](Get-TPObjectField -Item $p -Key 'State' -Default '') }
    $nameOf  = { param($p) $n = [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default ''); if ($n) { $n } else { '(unnamed policy)' } }
    $on = @($pols | Where-Object { (& $stateOf $_) -eq 'enabled' })

    $base = @{ ControlId = $ControlId; Category = $Category; Title = $Title }
    if ($null -ne $FrameworkIds) { $base.FrameworkIds = @($FrameworkIds) }

    # (b) Conflict. Microsoft documents that a CA policy cannot be On while
    # Security Defaults is enabled, so the two reads disagree. Neither is
    # credited: the control is not assessed.
    if ($caRead -and $on.Count -gt 0) {
        $shown = @($on | Select-Object -First 5 | ForEach-Object { & $nameOf $_ }) -join ', '
        if ($on.Count -gt 5) { $shown += ", and $($on.Count - 5) more" }
        Add-TPFinding @base -State 'NotApplicable' `
            -Detail "Security Defaults reads as enabled, but the Conditional Access read lists $($on.Count) policy(ies) as On. Microsoft documents that Conditional Access policies cannot be turned on while Security Defaults is enabled, so the two reads disagree (the configuration may have changed during the run); this control was not assessed. Re-run the assessment." `
            -CurrentValue "Conditional Access policies reported On: $shown"
        return
    }

    # (c) Policies that exist but cannot take effect. A NotApplicable finding
    # gets the count only: Get-TPAssessmentScope classifies it by its prose,
    # and a tenant-supplied policy name must not decide where it is filed.
    $staged = ''
    if ($caRead -and $pols.Count -gt 0) {
        $lead = " The tenant has $($pols.Count) Conditional Access policy(ies) that cannot take effect until Security Defaults is turned off"
        if ($State -eq 'NotApplicable') {
            $staged = "$lead."
        } else {
            $label = {
                param($p)
                $s = & $stateOf $p
                if ($s -eq 'enabledForReportingButNotEnforced') { 'report-only' }
                elseif ($s -eq 'disabled') { 'off' }
                elseif ($s) { $s }
                else { 'state not read' }
            }
            $list = @($pols | Select-Object -First 5 | ForEach-Object { "$(& $nameOf $_) [$(& $label $_)]" }) -join ', '
            if ($pols.Count -gt 5) { $list += ", and $($pols.Count - 5) more" }
            $staged = "${lead}: $list."
        }
    }

    # (d) Detail.
    $text = $script:TPSecurityDefaultsDetailPrefix + $Detail.Trim() + ' ' + $script:TPSecurityDefaultsCAClause + $staged

    # (e) Remediation.
    $fix = $Remediation
    if ($NeedsConditionalAccess) {
        $fix = if ([string]::IsNullOrWhiteSpace($Remediation)) { $script:TPSecurityDefaultsTransition }
               else { $script:TPSecurityDefaultsTransition + ' For this control: ' + $Remediation }
    }

    # (f) Emit. FrameworkIds always travel, so a NotApplicable still reaches
    # the NIST family rollup; optional fields only when non-empty.
    $extra = @{}
    if (-not [string]::IsNullOrWhiteSpace($Severity))      { $extra.Severity = $Severity }
    if (-not [string]::IsNullOrWhiteSpace($CurrentValue))  { $extra.CurrentValue = $CurrentValue }
    if (-not [string]::IsNullOrWhiteSpace($RequiredValue)) { $extra.RequiredValue = $RequiredValue }
    if (-not [string]::IsNullOrWhiteSpace($fix))           { $extra.Remediation = $fix }
    Add-TPFinding @base @extra -State $State -Detail $text
}

function Test-TPSecurityDefaultsLicenseFree {
    <#
    .SYNOPSIS
        $true when a finding is a Security Defaults verdict whose remaining
        fix needs no license, so no license gates it.
    .DESCRIPTION
        Security Defaults needs no license, yet the LicenseRequirement of
        AAD-1.1, AAD-1.2 and AAD-11.1 names Microsoft Entra ID P1 (the
        Conditional Access way to meet them). Exempt:
          - AAD-1.1 and AAD-11.1 Security Defaults findings (Security Defaults
            blocks legacy authentication and device code flow by itself);
          - the AAD-1.2 registration shortfall (its fix is registering users)
            and AAD-1.2's not-assessed finding (registration was not read,
            which is a collection gap, not a missing license).
        Not exempt: AAD-1.2 with every user registered. It is Partial because
        only the 16 named administrator roles do MFA at every sign-in, and
        the rest needs a Conditional Access policy, so on a tenant without
        Entra ID P1 license gating takes it out of the score like any other
        unlicensed control. Keyed on ControlId, State and the Detail (prefix
        and shortfall marker), so it holds on replayed results. Never throws.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Position = 0)] [AllowNull()] [object] $Finding)

    if ($null -eq $Finding) { return $false }
    $cid = [string](Get-TPObjectField -Item $Finding -Key 'ControlId' -Default '')
    if ($cid -notin $script:TPSecurityDefaultsLicenseFreeControls) { return $false }
    $detail = [string](Get-TPObjectField -Item $Finding -Key 'Detail' -Default '')
    if (-not $detail.StartsWith($script:TPSecurityDefaultsDetailPrefix, [System.StringComparison]::Ordinal)) { return $false }
    if ($cid -ne 'AAD-1.2') { return $true }
    if ([string](Get-TPObjectField -Item $Finding -Key 'State' -Default '') -eq 'NotApplicable') { return $true }
    return $detail.Contains($script:TPSecurityDefaultsShortfallMarker)
}

function Test-TPSecurityDefaultsUnresolved {
    <#
    .SYNOPSIS
        $true when the Security Defaults state was not read AND the
        Conditional Access read succeeded with no policy On.
    .DESCRIPTION
        Microsoft documents that no Conditional Access policy can be turned
        on while Security Defaults is enabled, so a CA read listing a policy
        in State 'enabled' proves it is off and the CA logic stands. With no
        policy On, Security Defaults may be on or off, and a control whose
        verdict differs between the two (AAD-1.1, AAD-1.2, AAD-1.3, AAD-11.1)
        must not pick one: an unread state is never "disabled". A CA read
        that failed returns $false: the evaluator's own CA gate already
        reports the control not assessed. Never throws.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($null -ne (Get-TPSecurityDefaultsState)) { return $false }
    $ca = if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) { Get-TPRawData -Key 'AAD-CAPolicies' } else { $null }
    if ($null -eq $ca -or (Get-TPObjectField -Item $ca -Key 'Success' -Default $null) -ne $true) { return $false }
    $on = @(@(Get-TPNestedProperty -Object $ca -Path 'Data.Policies' -Default @()) | Where-Object {
        $null -ne $_ -and [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -eq 'enabled' })
    return ($on.Count -eq 0)
}

function Add-TPSecurityDefaultsUnreadFinding {
    <#
    .SYNOPSIS
        Emits the not-assessed finding for a control whose verdict depends on
        a Security Defaults state that was not read.
    .DESCRIPTION
        Precondition: Test-TPSecurityDefaultsUnresolved is $true. States what
        each state would mean, commits to neither, and carries the control's
        citations so the NotApplicable still reaches the NIST rollup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Title,
        [AllowNull()] $FrameworkIds,
        [Parameter(Mandatory)] [string] $Question,
        [Parameter(Mandatory)] [string] $IfOn,
        [Parameter(Mandatory)] [string] $IfOff,
        [string] $Extra
    )
    $text = $script:TPSecurityDefaultsUnreadPrefix +
        "No Conditional Access policy is On, which is the only case in which Security Defaults can be enabled, so $Question was not assessed: if Security Defaults is enabled, $IfOn; if it is disabled, $IfOff." +
        $(if ($Extra) { ' ' + $Extra.Trim() } else { '' }) +
        ' Re-run the assessment so the Security Defaults state is read (GET /policies/identitySecurityDefaultsEnforcementPolicy, Policy.Read.All; see Exceptions).'
    $base = @{ ControlId = $ControlId; Category = $Category; Title = $Title; State = 'NotApplicable'; Detail = $text }
    if ($null -ne $FrameworkIds) { $base.FrameworkIds = @($FrameworkIds) }
    Add-TPFinding @base
}

function Test-TPSecurityDefaultsVerdictDetail {
    <#
    .SYNOPSIS
        $true when a finding Detail is a Security Defaults verdict: it starts
        with the emitter's prefix, or license gating wrapped one ("Not scored:
        ... upgrade opportunity ... Result before the license check: <State>
        — Security Defaults is enabled. ...").
    .DESCRIPTION
        Get-TPAssessmentScope uses it so that a failed AAD-CAPolicies read is
        never named as the reason for a finding that did not depend on it.
        Never throws.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Position = 0)] [AllowNull()] [AllowEmptyString()] [string] $Detail)

    if ([string]::IsNullOrEmpty($Detail)) { return $false }
    if ($Detail.StartsWith($script:TPSecurityDefaultsDetailPrefix, [System.StringComparison]::Ordinal)) { return $true }
    return ($Detail -match 'upgrade opportunity') -and ($Detail -match ('Result before the license check: \w+ — ' + [regex]::Escape($script:TPSecurityDefaultsDetailPrefix)))
}

function Get-TPFindingRemediation {
    <#
    .SYNOPSIS
        The remediation text a publisher should render for a finding.
    .DESCRIPTION
        Publishers prefer the control's generic Remediation from controls.json.
        A Security Defaults finding carries its own (turn Security Defaults
        off and the replacement Conditional Access policies on in one change;
        for AAD-1.2, a registration campaign), and the generic text is wrong
        for it: SPO-1.5's "Set-SPOTenant -ConditionalAccessPolicy
        AllowLimitedAccess" on a tenant already set that way, AAD-1.2's "Or
        enable Security Defaults" on a tenant that has it. So a finding whose
        Detail carries the Security Defaults prefix and has its own
        Remediation renders that; everything else keeps the old order
        (control text, then the finding's). Never throws.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)] [AllowNull()] [object] $Finding,
        [Parameter(Position = 1)] [AllowNull()] [object] $Control
    )
    $own    = [string](Get-TPObjectField -Item $Finding -Key 'Remediation' -Default '')
    $detail = [string](Get-TPObjectField -Item $Finding -Key 'Detail' -Default '')
    if ($own -and $detail.StartsWith($script:TPSecurityDefaultsDetailPrefix, [System.StringComparison]::Ordinal)) { return $own }
    $generic = [string](Get-TPObjectField -Item $Control -Key 'Remediation' -Default '')
    if ($generic) { return $generic }
    return $own
}

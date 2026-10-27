#Requires -Version 7.0
#
# Test-TPControlEntraAuthMethods.ps1
#
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: AAD-17.1 to AAD-17.6 — application credential restrictions in the
#          tenant application management policy, and authentication methods
#          settings, each judged on the setting its CIS Microsoft 365 v7.0.0
#          recommendation audits.
#
#   AAD-17.1  CIS 5.1.5.3   passwordAddition restriction (apps and service principals)
#   AAD-17.2  CIS 5.1.5.5   customPasswordAddition restriction (apps and service principals)
#   AAD-17.3  CIS 5.2.3.5   SMS and Voice call methods disabled
#   AAD-17.4  CIS 5.2.3.6   system-preferred MFA enabled for all users
#   AAD-17.5  CIS 5.2.3.7   Email OTP method disabled
#   AAD-17.6  CIS 5.2.3.10  Microsoft Authenticator on companion applications disabled
#
# Consumes: AAD-Inventory (Data.AppManagementPolicy, SectionStatus.AppManagementPolicy;
#           the tenant-wide defaultAppManagementPolicy read AAD-14.1 already makes),
#           AAD-AuthPolicies (Data.AuthMethodsPolicy from the v1.0 authentication
#           methods policy; Data.AuthMethodsPolicyBeta and
#           SectionStatus.AuthMethodsPolicyBeta from the beta read, which alone
#           defines systemCredentialPreferences and companionAppAllowedState).
# Graph scopes: none directly (collectors use Policy.Read.All). No Graph calls here.
#

# The all-zero GUID is Graph's "no group" value for a feature setting's single
# include/exclude target.
$script:TPNoTargetId = '00000000-0000-0000-0000-000000000000'

# One app management policy restriction, judged for applications and for service
# principals. Returns Verified / Shortfalls / NotEstablished sentences and a
# CurrentValue. Module scope, not exported.
function Get-TPAppPasswordRestrictionVerdict {
    [CmdletBinding()]
    param([AllowNull()] $Inventory, [Parameter(Mandatory)] [string] $RestrictionType, [Parameter(Mandatory)] [string] $Name)
    $v = @(); $s = @(); $n = @(); $cur = @()
    $status = [string](Get-TPNestedProperty -Object $Inventory -Path 'Data.SectionStatus.AppManagementPolicy' -Default '')
    $pol = Get-TPNestedProperty -Object $Inventory -Path 'Data.AppManagementPolicy' -Default $null
    if ($status -ne 'Collected' -or $null -eq $pol) {
        $n += "the tenant application management policy was not read ($(if ($status) { "section $status" } else { 'a results file from before it was collected' }))."
        return [pscustomobject]@{ Verified = $v; Shortfalls = $s; NotEstablished = $n; CurrentValue = 'Tenant application management policy not read' }
    }
    $enabled = Get-TPObjectField -Item $pol -Key 'IsEnabled' -Default $null
    if ($enabled -ne $true) {
        if ($null -eq $enabled) { $n += 'whether the tenant application management policy is enabled was not returned.' }
        else { $s += "the tenant application management policy is not enabled (isEnabled = false), so no $Name restriction applies to anything." }
        return [pscustomobject]@{ Verified = $v; Shortfalls = $s; NotEstablished = $n; CurrentValue = "isEnabled = $enabled" }
    }
    $now = [datetime]::UtcNow
    foreach ($scope in @(
            @{ Key = 'PasswordRestrictions';                 Label = 'applications';       Path = 'applicationRestrictions' },
            @{ Key = 'ServicePrincipalPasswordRestrictions'; Label = 'service principals'; Path = 'servicePrincipalRestrictions' })) {
        # An older results file stored only the application half.
        if (-not (Test-TPFieldPresent -Item $pol -Key $scope.Key)) {
            $n += "the $($scope.Path) half of the policy was not stored (a results file from before it was collected)."
            $cur += "$($scope.Label): not read"
            continue
        }
        $r = @(@(Get-TPObjectField -Item $pol -Key $scope.Key -Default @()) | Where-Object { $null -ne $_ -and [string](Get-TPObjectField -Item $_ -Key 'RestrictionType' -Default '') -eq $RestrictionType }) | Select-Object -First 1
        if (-not $r) {
            $s += "the policy sets no $RestrictionType restriction for $($scope.Label)."
            $cur += "$($scope.Label): no $RestrictionType restriction"
            continue
        }
        $state = [string](Get-TPObjectField -Item $r -Key 'State' -Default '')
        $cur += "$($scope.Label): $RestrictionType $(if ($state) { $state } else { 'state not returned' })"
        if ($state -eq 'disabled') { $s += "the $RestrictionType restriction for $($scope.Label) is disabled."; continue }
        if ($state -ne 'enabled') { $n += "the state of the $RestrictionType restriction for $($scope.Label) was not returned as enabled or disabled ('$state')."; continue }
        $after = ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $r -Key 'RestrictForAppsCreatedAfterDateTime' -Default $null)
        if ($after -and $after.Year -gt 1) {
            if ($after -gt $now) {
                $s += "the $RestrictionType restriction for $($scope.Label) takes effect only for objects created after $($after.ToString('yyyy-MM-dd')), a date not yet reached, so it restricts nothing today."
            } else {
                $s += "the $RestrictionType restriction for $($scope.Label) applies only to objects created after $($after.ToString('yyyy-MM-dd')), so older $($scope.Label) are not restricted."
            }
            continue
        }
        $exempt = [int](Get-TPObjectField -Item $r -Key 'ExcludedActorAttributes' -Default 0)
        $note = if ($exempt -gt 0) { " Callers holding $exempt custom security attribute exemption(s) are exempt; review them." } else { '' }
        $v += "The tenant application management policy enforces $RestrictionType for every one of its $($scope.Label) ($Name).$note"
    }
    return [pscustomobject]@{ Verified = $v; Shortfalls = $s; NotEstablished = $n; CurrentValue = "isEnabled = True; $($cur -join '; ')" }
}

# Per-application app management policies override the tenant default for the
# apps they are assigned to; they are not read, so a pass is about the default.
function Get-TPAppPolicyVerifiedNote {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Verdict)
    $verified = @($Verdict.Verified)
    if ($verified.Count -and -not @($Verdict.Shortfalls).Count -and -not @($Verdict.NotEstablished).Count) {
        $verified[-1] = "$($verified[-1]) Per-application policies that override this default for individual applications are not read."
    }
    return ,$verified
}

# ── AAD-17.1 Password addition blocked for applications (CIS 5.1.5.3) ────────
function Test-TPControlAADAppPasswordAdditionBlocked {
    [CmdletBinding()] param()
    $cid = 'AAD-17.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $inv = Get-TPRawData -Key 'AAD-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AAD inventory not collected; not assessed.'
        return
    }
    $pv = Get-TPAppPasswordRestrictionVerdict -Inventory $inv -RestrictionType 'passwordAddition' -Name 'no new client secret can be added'
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
        -Verified (Get-TPAppPolicyVerifiedNote -Verdict $pv) -Shortfalls $pv.Shortfalls -NotEstablished $pv.NotEstablished -CurrentValue $pv.CurrentValue `
        -RequiredValue 'defaultAppManagementPolicy isEnabled = true; passwordAddition restriction enabled in applicationRestrictions and servicePrincipalRestrictions, applying to every object (no created-after date)'
}

# ── AAD-17.2 New application passwords system-generated (CIS 5.1.5.5) ───────
function Test-TPControlAADAppCustomPasswordBlocked {
    [CmdletBinding()] param()
    $cid = 'AAD-17.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $inv = Get-TPRawData -Key 'AAD-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AAD inventory not collected; not assessed.'
        return
    }
    $pv = Get-TPAppPasswordRestrictionVerdict -Inventory $inv -RestrictionType 'customPasswordAddition' -Name 'a new client secret must be generated by Microsoft Entra ID, never supplied by the caller'
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
        -Verified (Get-TPAppPolicyVerifiedNote -Verdict $pv) -Shortfalls $pv.Shortfalls -NotEstablished $pv.NotEstablished -CurrentValue $pv.CurrentValue `
        -RequiredValue 'defaultAppManagementPolicy isEnabled = true; customPasswordAddition restriction enabled in applicationRestrictions and servicePrincipalRestrictions, applying to every object (no created-after date)'
}

# The state of named methods in the v1.0 authentication methods policy, each of
# which must be disabled. Returns Verified / Shortfalls / NotEstablished sentences
# and a CurrentValue. Module scope, not exported.
function Get-TPAuthMethodDisabledVerdict {
    [CmdletBinding()]
    param([AllowNull()] $Auth, [Parameter(Mandatory)] [hashtable[]] $Methods)
    $v = @(); $s = @(); $n = @(); $cur = @()
    $configs = @(Get-TPNestedProperty -Object $Auth -Path 'Data.AuthMethodsPolicy.AuthenticationMethodConfigs' -Default @() | Where-Object { $null -ne $_ })
    $migration = [string](Get-TPNestedProperty -Object $Auth -Path 'Data.AuthMethodsPolicy.PolicyMigrationState' -Default '')
    foreach ($m in $Methods) {
        $cfg = @($configs | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Id' -Default '') -eq $m.Id }) | Select-Object -First 1
        if (-not $cfg) { $n += "the $($m.Name) method configuration ($($m.Id)) was not returned in the authentication methods policy."; $cur += "$($m.Name): not returned"; continue }
        $state = [string](Get-TPObjectField -Item $cfg -Key 'State' -Default '')
        $cur += "$($m.Name): $(if ($state) { $state } else { 'state not returned' })"
        if ($state -eq 'disabled') { $v += "The $($m.Name) method ($($m.Id)) is disabled in the authentication methods policy."; continue }
        if ($state -eq 'enabled') {
            $targets = @(@(Get-TPObjectField -Item $cfg -Key 'IncludeTargets' -Default @()) | Where-Object { $null -ne $_ } | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'id' -Default '') } | Where-Object { $_ })
            $who = if ($targets -contains 'all_users') { 'all users' } elseif ($targets.Count) { "$($targets.Count) targeted group(s)" } else { 'targets not returned' }
            $s += "the $($m.Name) method ($($m.Id)) is enabled (for $who)."
            continue
        }
        $n += "the state of the $($m.Name) method was not returned as enabled or disabled ('$state')."
    }
    # Until migration is complete, Microsoft still respects the legacy MFA and SSPR
    # policies, which this tool does not read; the verdict is about this policy only.
    if ($v.Count -and $migration -and $migration -ne 'migrationComplete') {
        $v[-1] = "$($v[-1]) The policy migration state is $migration, so the legacy MFA and SSPR policies (not read by this tool) are still respected for the methods they allow."
    }
    return [pscustomobject]@{ Verified = $v; Shortfalls = $s; NotEstablished = $n; CurrentValue = ($cur -join '; ') }
}

# Gate shared by the v1.0 method checks. Returns the AAD-AuthPolicies envelope,
# or $null after emitting the not-assessed finding.
function Get-TPAuthMethodsPolicyOrNotAssessed {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ControlId, [Parameter(Mandatory)] $Control, [AllowNull()] $FrameworkIds)
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category -Title $Control.Title -FrameworkIds $FrameworkIds -Detail 'AAD-AuthPolicies collector did not run; not assessed.'
        return $null
    }
    if (-not (Test-TPSectionCollected $auth 'AuthMethodsPolicy') -or $null -eq (Get-TPNestedProperty -Object $auth -Path 'Data.AuthMethodsPolicy' -Default $null)) {
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category -Title $Control.Title -FrameworkIds $FrameworkIds -Detail 'AuthMethodsPolicy was not collected; not assessed.'
        return $null
    }
    return $auth
}

# ── AAD-17.3 Weak authentication methods disabled (CIS 5.2.3.5) ──────────────
function Test-TPControlAADWeakAuthMethodsDisabled {
    [CmdletBinding()] param()
    $cid = 'AAD-17.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPAuthMethodsPolicyOrNotAssessed -ControlId $cid -Control $ctrl -FrameworkIds $cit
    if ($null -eq $auth) { return }
    $pv = Get-TPAuthMethodDisabledVerdict -Auth $auth -Methods @(@{ Id = 'Sms'; Name = 'SMS' }, @{ Id = 'Voice'; Name = 'Voice call' })
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
        -Verified $pv.Verified -Shortfalls $pv.Shortfalls -NotEstablished $pv.NotEstablished -CurrentValue $pv.CurrentValue `
        -RequiredValue 'Authentication methods policy: Sms state = disabled and Voice state = disabled'
}

# ── AAD-17.5 Email OTP method disabled (CIS 5.2.3.7) ─────────────────────────
function Test-TPControlAADEmailOtpDisabled {
    [CmdletBinding()] param()
    $cid = 'AAD-17.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPAuthMethodsPolicyOrNotAssessed -ControlId $cid -Control $ctrl -FrameworkIds $cit
    if ($null -eq $auth) { return }
    $pv = Get-TPAuthMethodDisabledVerdict -Auth $auth -Methods @(@{ Id = 'Email'; Name = 'Email OTP' })
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
        -Verified $pv.Verified -Shortfalls $pv.Shortfalls -NotEstablished $pv.NotEstablished -CurrentValue $pv.CurrentValue `
        -RequiredValue 'Authentication methods policy: Email state = disabled'
}

# Gate shared by the two beta settings. Returns the AuthMethodsPolicyBeta block,
# or $null after emitting the not-assessed finding.
function Get-TPAuthMethodsBetaOrNotAssessed {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ControlId, [Parameter(Mandatory)] $Control, [AllowNull()] $FrameworkIds, [Parameter(Mandatory)] [string] $Setting)
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category -Title $Control.Title -FrameworkIds $FrameworkIds -Detail 'AAD-AuthPolicies collector did not run; not assessed.'
        return $null
    }
    $status = Get-TPNestedProperty -Object $auth -Path 'Data.SectionStatus.AuthMethodsPolicyBeta' -Default $null
    $beta = Get-TPNestedProperty -Object $auth -Path 'Data.AuthMethodsPolicyBeta' -Default $null
    if ([string]$status -ne 'Collected' -or $null -eq $beta) {
        $why = if ($null -eq $status) { 'a results file from before this check' } else { "section $status" }
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category -Title $Control.Title -FrameworkIds $FrameworkIds `
            -Detail "The beta authentication methods policy, which alone returns $Setting, was not read ($why); not assessed."
        return $null
    }
    return $beta
}

# ── AAD-17.4 System-preferred MFA enabled (CIS 5.2.3.6) ──────────────────────
function Test-TPControlAADSystemPreferredMfa {
    [CmdletBinding()] param()
    $cid = 'AAD-17.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $beta = Get-TPAuthMethodsBetaOrNotAssessed -ControlId $cid -Control $ctrl -FrameworkIds $cit -Setting 'systemCredentialPreferences'
    if ($null -eq $beta) { return }
    $required = 'systemCredentialPreferences state = enabled with includeTargets containing all_users'
    $scp = Get-TPObjectField -Item $beta -Key 'SystemCredentialPreferences' -Default $null
    if ($null -eq $scp) {
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -NotEstablished @('the tenant did not return systemCredentialPreferences in the authentication methods policy.') `
            -CurrentValue 'systemCredentialPreferences not returned' -RequiredValue $required
        return
    }
    $state = [string](Get-TPObjectField -Item $scp -Key 'State' -Default '')
    $inc = @(@(Get-TPObjectField -Item $scp -Key 'IncludeTargetIds' -Default @()) | Where-Object { $_ })
    $exc = @(@(Get-TPObjectField -Item $scp -Key 'ExcludeTargetIds' -Default @()) | Where-Object { $_ -and $_ -ne $script:TPNoTargetId })
    $v = @(); $s = @(); $n = @()
    $excNote = if ($exc.Count) { " $($exc.Count) excluded target(s) ($($exc -join ', ')) are outside it; confirm each exclusion is documented." } else { '' }
    $allUsers = $inc -contains 'all_users'
    switch ($state) {
        'enabled' {
            if ($allUsers) { $v += "System-preferred multifactor authentication is enabled for all users.$excNote" }
            elseif ($inc.Count) { $s += "system-preferred multifactor authentication is enabled only for $($inc.Count) targeted group(s), not all users." }
            else { $n += 'system-preferred multifactor authentication is enabled but its include targets were not returned.' }
        }
        'default' {
            # Microsoft-managed: Microsoft documents its current value as Enabled, but
            # Microsoft decides it; CIS requires the setting Enabled.
            if ($allUsers) { $v += "System-preferred multifactor authentication is Microsoft managed for all users, which Microsoft documents as enabled today.$excNote" }
            $s += 'the setting is Microsoft managed (state default), not set to Enabled, so Microsoft can change it without the tenant changing anything.'
        }
        'disabled' { $s += 'system-preferred multifactor authentication is disabled, so users are prompted for the method they used last or chose, which can be SMS or voice.' }
        default    { $n += "the system-preferred multifactor authentication state was not returned as enabled, default or disabled ('$state')." }
    }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $v -Shortfalls $s -NotEstablished $n `
        -CurrentValue "state = $(if ($state) { $state } else { 'not returned' }); includeTargets = $(if ($inc.Count) { $inc -join ', ' } else { 'none' }); excludeTargets = $(if ($exc.Count) { $exc -join ', ' } else { 'none' })" `
        -RequiredValue $required
}

# ── AAD-17.6 Authenticator on companion applications disabled (CIS 5.2.3.10) ─
function Test-TPControlAADAuthenticatorCompanionAppsDisabled {
    [CmdletBinding()] param()
    $cid = 'AAD-17.6'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $beta = Get-TPAuthMethodsBetaOrNotAssessed -ControlId $cid -Control $ctrl -FrameworkIds $cit -Setting 'featureSettings.companionAppAllowedState'
    if ($null -eq $beta) { return }
    $required = 'MicrosoftAuthenticator featureSettings.companionAppAllowedState state = disabled for all users, with no excluded group'
    if ((Get-TPObjectField -Item $beta -Key 'AuthenticatorConfigReturned' -Default $false) -ne $true) {
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -NotEstablished @('the Microsoft Authenticator method configuration was not returned by the beta authentication methods policy.') `
            -CurrentValue 'MicrosoftAuthenticator configuration not returned' -RequiredValue $required
        return
    }
    $cas = Get-TPObjectField -Item $beta -Key 'CompanionAppAllowedState' -Default $null
    if ($null -eq $cas) {
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -NotEstablished @('the Microsoft Authenticator configuration did not return featureSettings.companionAppAllowedState.') `
            -CurrentValue 'companionAppAllowedState not returned' -RequiredValue $required
        return
    }
    $state = [string](Get-TPObjectField -Item $cas -Key 'State' -Default '')
    $inc = [string](Get-TPObjectField -Item $cas -Key 'IncludeTargetId' -Default '')
    $exc = [string](Get-TPObjectField -Item $cas -Key 'ExcludeTargetId' -Default '')
    $methodState = [string](Get-TPObjectField -Item $beta -Key 'AuthenticatorState' -Default '')
    $v = @(); $s = @(); $n = @()
    switch ($state) {
        'disabled' {
            if ($inc -and $inc -ne 'all_users') { $s += "Microsoft Authenticator on companion applications is disabled only for group $inc, not all users." }
            else { $v += 'Microsoft Authenticator on companion applications (Authenticator Lite, for example in Outlook mobile) is disabled for all users.' }
            if ($exc -and $exc -ne $script:TPNoTargetId) { $s += "group $exc is excluded from the disabled state, so its members can still approve sign-ins in a companion application." }
        }
        'default' { $s += 'the setting is Microsoft managed (state default), which Microsoft documents as Enabled, so users can approve sign-ins from a companion application such as Outlook mobile.' }
        'enabled' { $s += 'Microsoft Authenticator on companion applications is enabled, so users can approve sign-ins from a companion application such as Outlook mobile.' }
        default   { $n += "the companion application state was not returned as enabled, default or disabled ('$state')." }
    }
    if ($methodState -eq 'disabled' -and $s.Count) {
        $s[-1] = "$($s[-1]) The Microsoft Authenticator method itself is disabled, so this applies only if it is turned on."
    }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $v -Shortfalls $s -NotEstablished $n `
        -CurrentValue "companionAppAllowedState = $(if ($state) { $state } else { 'not returned' }); includeTarget = $(if ($inc) { $inc } else { 'not returned' }); excludeTarget = $(if ($exc -and $exc -ne $script:TPNoTargetId) { $exc } else { 'none' })" `
        -RequiredValue $required
}

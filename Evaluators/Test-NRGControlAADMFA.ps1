#Requires -Version 7.0
#
# Test-NRGControlAADMFA.ps1
# Evaluates AAD-1.2 "MFA Required for All Users" (canonical control per
# Config/controls.json).
#
# v4.6.4: scope-of-emission contracted to AAD-1.2 ONLY. Earlier revisions of
# this file emitted findings under AAD-2.1, AAD-2.2 and AAD-2.4 with the
# wrong Title strings, colliding with the older monolithic AAD evaluator
# (Test-NRGControl-AAD.ps1) which is the canonical evaluator for those IDs.
# The cross-emit logic was removed; this file now matches the EvaluatorFunction
# field declared in controls.json for AAD-1.2.
#
# Reads from module state:
#   Get-NRGRawData -Key 'AAD-Users'         (Invoke-NRGCollectAADUsers)
#   Get-NRGRawData -Key 'AAD-AuthPolicies'  (Invoke-NRGCollectAADAuthPolicies) — Data.SecurityDefaults
#   Get-NRGRawData -Key 'AAD-CAPolicies'    (Invoke-NRGCollectAADCAPolicies)   — MFA enforcement
#
# NIST SP 800-53: IA-2(1), IA-2(2)
# MITRE ATT&CK:   T1078, T1110, T1621
#


# Entra Connect's directory-sync service account (Sync_<server>_<id>,
# "On-Premises Directory Synchronization Service Account"). Microsoft says to
# exclude it from MFA and it cannot register a method. One definition so
# AAD-1.2 and AAD-12.1 count the same population.
function Test-NRGDirectorySyncAccount {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowNull()] $User)
    if ($null -eq $User) { return $false }
    return ([string](Get-NRGObjectField -Item $User -Key 'UserPrincipalName' -Default '') -match '^Sync_') -and
           ([string](Get-NRGObjectField -Item $User -Key 'DisplayName' -Default '') -match 'Directory Synchronization')
}

function Test-NRGControlAADMFA {
    [CmdletBinding()] param()

    $userRaw = Get-NRGRawData -Key 'AAD-Users'
    $authRaw = Get-NRGRawData -Key 'AAD-AuthPolicies'

    # Both collectors must have data to evaluate AAD-1.2 confidently
    if ((-not $userRaw -or -not $userRaw.Success) -and
        (-not $authRaw -or -not $authRaw.Success)) {
        $detail = 'Neither AAD-Users nor AAD-AuthPolicies collector produced data.'
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'NotApplicable' `
            -Category 'Identity' -Title 'MFA Required for All Users' -Detail $detail
        return
    }

    # Security defaults are collected by AAD-AuthPolicies (Data.SecurityDefaults
    # .IsEnabled), not AAD-Users. Reading AAD-Users.Data.SecurityDefaultsEnabled
    # — a key no collector writes — made this always $null: a tenant enforcing
    # MFA through security defaults was scored on registration instead, and the
    # finding printed "Security Defaults: disabled" without having read it.
    # $null means "not read", never "disabled".
    $secDefEnabled = $null
    if ($authRaw -and $authRaw.Success) {
        $secDefEnabled = Get-NRGNestedProperty -Object $authRaw -Path 'Data.SecurityDefaults.IsEnabled' -Default $null
    }
    $secDefText = if ($secDefEnabled -eq $false) { 'Security Defaults: disabled.' } else { 'Security Defaults: not read.' }
    # Two statements. An if-block yielding an empty array assigns $null, and
    # BOTH branches can yield empty here — a tenant with no users collected
    # hits it through the true branch, not just the false one. Nothing
    # downstream calls .Count today, but the trap is one edit away from being
    # a crash.
    $users  = @()
    $mfaReg = @()
    $mfaRegCollected = $false
    if ($userRaw -and $userRaw.Success) {
        $users  = @($userRaw.Data['Users'])
        # AAD-Users publishes MFARegistration as a summary hashtable
        # {TotalUsersWithMFA, TotalUsersWithoutMFA, RegistrationDetails}, NOT
        # a list of per-user records. Reading it directly as a list (old:
        # @($userRaw.Data['MFARegistration'])) put the summary hashtable
        # itself into $mfaReg, and the Where-Object below then dot-read
        # UserPrincipalName off that hashtable — which throws under
        # StrictMode on every tenant where Security Defaults are off. Read
        # the actual per-user list, and track whether the sub-query
        # collected so an empty result isn't mistaken for 0% registered.
        $mfaRegCollected = Test-NRGSectionCollected $userRaw 'MFARegistration'
        $mfaReg = @(Get-NRGNestedProperty -Object $userRaw -Path 'Data.MFARegistration.RegistrationDetails' -Default @())
    }

    # Security Defaults satisfies AAD-1.2 by itself (MFA universally required).
    if ($secDefEnabled -eq $true) {
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Satisfied' `
            -Category 'Identity' -Title 'MFA Required for All Users' `
            -Severity 'Critical' `
            -CurrentValue 'Security Defaults enabled — MFA enforced for all users' `
            -RequiredValue 'CA policy requiring MFA for All users on All cloud apps, or Security Defaults enabled' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'AAD-1.2')
        return
    }

    # Compute MFA registration completeness as a proxy for AAD-1.2 readiness.
    # Without CA-policy data here we cannot prove enforcement, but registration
    # < 100% is a hard blocker on enforcing AAD-1.2 even when a CA policy exists.
    $enabledMembers = @($users | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -eq 'Member' })
    $totalEnabled   = $enabledMembers.Count

    if ($totalEnabled -eq 0) {
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'NotApplicable' `
            -Category 'Identity' -Title 'MFA Required for All Users' `
            -Detail 'No enabled member accounts found in tenant.'
        return
    }

    if (-not $mfaRegCollected) {
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'NotApplicable' `
            -Category 'Identity' -Title 'MFA Required for All Users' `
            -Detail 'MFA registration details were not collected; cannot compute registration completeness for AAD-1.2.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'AAD-1.2')
        return
    }

    # Entra Connect's directory-sync service account cannot register MFA and
    # Microsoft says to exclude it from MFA policies; counting it made a fully
    # enforced tenant read "below 100% — will lock out 1 user".
    $population = @($enabledMembers | Where-Object { -not (Test-NRGDirectorySyncAccount $_) })
    $syncExcluded = $enabledMembers.Count - $population.Count
    $syncNote = if ($syncExcluded -gt 0) { " ($syncExcluded Entra Connect sync service account(s) excluded; they cannot register MFA.)" } else { '' }
    $unregistered = @($population | Where-Object {
        $upn = $_.UserPrincipalName
        $rec = $mfaReg | Where-Object { $_.UserPrincipalName -eq $upn }
        (-not $rec) -or ($rec.IsMfaRegistered -eq $false)
    })
    $unregisteredCnt = $unregistered.Count
    $totalEnabled    = $population.Count
    $registeredPct   = if ($totalEnabled -gt 0) { [math]::Round((($totalEnabled - $unregisteredCnt) / $totalEnabled) * 100, 1) } else { 100 }
    $sample = ($unregistered | Select-Object -First 5 | ForEach-Object { $_.UserPrincipalName }) -join ', '

    # Enforcement decides the verdict; registration only qualifies it. MFA that
    # is not REQUIRED is not configured — a Gap however many users registered
    # (it scored Partial at 90%+ registration with no policy at all).
    $caRaw  = Get-NRGRawData -Key 'AAD-CAPolicies'
    $caRead = [bool]($caRaw -and $caRaw.Success)
    $enforcing = @()
    if ($caRead) {
        # Enabled, All users, All cloud apps, and MFA REQUIRED (the mfa control
        # or an authentication strength; with OR, only when every alternative
        # is MFA).
        $enforcing = @(@($caRaw.Data['Policies']) | Where-Object {
            [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '') -eq 'enabled' -and
            (Test-NRGCAAllUsers $_) -and (Test-NRGCAAllApps $_) -and
            (Test-NRGCAGrantRequires -Policy $_ -Any @('mfa','authStrength'))
        })
    }
    $cit = Get-NRGFrameworkCitations -ControlId 'AAD-1.2'
    $req = 'CA policy requiring MFA for All users on All cloud apps (or Security Defaults), with every user registered'

    if (-not $caRead) {
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'NotApplicable' -Category 'Identity' -Title 'MFA Required for All Users' -FrameworkIds $cit `
            -Detail "$registeredPct% of users are MFA-registered, but Conditional Access policies were not collected, so whether MFA is required could not be assessed. $secDefText"
        return
    }
    # Part-way: MFA is asked for, but not of everyone on everything — report-
    # only (Audit mode), scoped to some users/apps, or offered as one
    # alternative beside a compliant device.
    $partway = @()
    if ($enforcing.Count -eq 0) {
        $partway = @(@($caRaw.Data['Policies']) | Where-Object {
            $st = [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '')
            $asks = @(Get-NRGNestedProperty -Object $_ -Path 'GrantControls.BuiltInControls' -Default @()) -contains 'mfa' -or
                    [string](Get-NRGNestedProperty -Object $_ -Path 'GrantControls.AuthStrengthId' -Default '')
            $st -in @('enabled','enabledForReportingButNotEnforced') -and $asks
        })
    }
    if ($enforcing.Count -eq 0 -and $partway.Count -gt 0) {
        $how = @($partway | ForEach-Object {
            $why = if ([string]$_.State -ne 'enabled') { 'report-only (Audit mode)' }
                   elseif (-not (Test-NRGCAAllUsers $_) -or -not (Test-NRGCAAllApps $_)) { 'not all users / all apps' }
                   else { 'MFA is one alternative (OR)' }
            "$($_.DisplayName) [$why]" })
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Partial' -Category 'Identity' -Title 'MFA Required for All Users' -Severity 'Critical' -FrameworkIds $cit `
            -Detail "MFA is requested but not required of all users on all apps: $($how -join '; '). $secDefText" `
            -CurrentValue "MFA partly enforced; $registeredPct% registered" -RequiredValue $req -Remediation 'Enforce MFA (or an authentication strength) for All users on All cloud apps, with MFA required rather than one alternative.'
        return
    }
    if ($enforcing.Count -eq 0) {
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'MFA Required for All Users' -Severity 'Critical' -FrameworkIds $cit `
            -Detail "No Conditional Access policy requires MFA for all users on all cloud apps. $secDefText $registeredPct% of users have registered MFA, but registration alone does not require it at sign-in." `
            -CurrentValue "No enforcing policy; $registeredPct% registered" -RequiredValue $req `
            -Remediation 'Create a Conditional Access policy requiring MFA (or an authentication strength) for All users on All cloud apps, excluding only break-glass accounts. Stage it in report-only first.'
        return
    }
    $names = ($enforcing | ForEach-Object { $_.DisplayName } | Select-Object -First 3) -join ', '
    if ($unregisteredCnt -eq 0) {
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Satisfied' -Category 'Identity' -Title 'MFA Required for All Users' -Severity 'Critical' -FrameworkIds $cit `
            -CurrentValue "MFA required by: $names. 100% registered ($totalEnabled/$totalEnabled enabled members)." -RequiredValue $req
    } else {
        # Enforced, but unregistered users will be asked to register at their
        # next sign-in — whoever holds the password then enrolls the second
        # factor. Part-way, and not a lock-out.
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Partial' -Category 'Identity' -Title 'MFA Required for All Users' -Severity 'Critical' -FrameworkIds $cit `
            -Detail "MFA is required ($names), but $unregisteredCnt of $totalEnabled enabled member(s) have not registered a method. They will be asked to register at their next sign-in, so whoever holds their password can enroll the second factor — or they are excluded from the policy.$syncNote" `
            -CurrentValue "$registeredPct% registered. Sample: $sample" -RequiredValue $req `
            -Remediation 'Run an MFA registration campaign or issue Temporary Access Passes so every enabled user registers; check that unregistered accounts are not excluded from the MFA policy.'
    }
}

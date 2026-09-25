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
            -FrameworkIds @('IA-2(1)','IA-2(2)')
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
            -FrameworkIds @('IA-2(1)','IA-2(2)')
        return
    }

    $unregistered = @($enabledMembers | Where-Object {
        $upn = $_.UserPrincipalName
        $rec = $mfaReg | Where-Object { $_.UserPrincipalName -eq $upn }
        (-not $rec) -or ($rec.IsMfaRegistered -eq $false)
    })
    $unregisteredCnt = $unregistered.Count
    $registeredPct   = [math]::Round((($totalEnabled - $unregisteredCnt) / $totalEnabled) * 100, 1)

    if ($unregisteredCnt -eq 0) {
        # Cross-reference: verify an MFA-enforcing CA policy exists.
        # Registration alone does NOT prove enforcement — without this check,
        # a tenant with 100% registration and zero enforcing policy was
        # reported Satisfied (false pass). Ported from the NLS twin.
        $caRaw = Get-NRGRawData -Key 'AAD-CAPolicies'
        $caRead = [bool]($caRaw -and $caRaw.Success)
        $hasMfaCaPolicy = $false
        if ($caRead) {
            $policies = @($caRaw.Data['Policies'])
            # Enforcing = enabled, All users, All cloud apps, and MFA REQUIRED:
            # the 'mfa' built-in control or any authentication strength (every
            # strength is a set of multifactor combinations). Requiring MFA
            # with authentication strengths used to be missed entirely. With
            # the OR operator, MFA is required only when it is the sole control
            # — "MFA or compliant device" lets a compliant device through
            # without MFA.
            $hasMfaCaPolicy = [bool](@($policies | Where-Object {
                $p = $_
                $builtIn  = @(Get-NRGNestedProperty -Object $p -Path 'GrantControls.BuiltInControls' -Default @())
                $strength = [string](Get-NRGNestedProperty -Object $p -Path 'GrantControls.AuthStrengthId' -Default '')
                $operator = [string](Get-NRGNestedProperty -Object $p -Path 'GrantControls.Operator' -Default '')
                $controls = @($builtIn) + @(if ($strength) { 'authenticationStrength' })
                $mfaGrant = ($builtIn -contains 'mfa') -or [bool]$strength
                $required = $mfaGrant -and ($operator -ne 'OR' -or @($controls).Count -eq 1)
                [string](Get-NRGObjectField -Item $p -Key 'State' -Default '') -eq 'enabled' -and
                @(Get-NRGNestedProperty -Object $p -Path 'Conditions.Users.IncludeUsers' -Default @()) -contains 'All' -and
                @(Get-NRGNestedProperty -Object $p -Path 'Conditions.Applications.Include' -Default @()) -contains 'All' -and
                $required
            }).Count -gt 0)
        }

        if (-not $caRead) {
            # Registration is complete, but whether anything ENFORCES MFA was
            # not read. Scoring that Partial would assert a missing policy.
            Add-NRGFinding -ControlId 'AAD-1.2' -State 'NotApplicable' `
                -Category 'Identity' -Title 'MFA Required for All Users' `
                -Detail "100% MFA registered, but Conditional Access policies were not collected, so enforcement could not be assessed. $secDefText" `
                -FrameworkIds @('IA-2(1)','IA-2(2)')
            return
        }

        if (-not $hasMfaCaPolicy) {
            # 100% registered but no enforcing policy — Partial, not Satisfied
            Add-NRGFinding -ControlId 'AAD-1.2' -State 'Partial' `
                -Category 'Identity' -Title 'MFA Required for All Users' `
                -Severity 'Critical' `
                -Detail '100% MFA registered but no CA policy found enforcing MFA for All Users / All Cloud Apps. Registration alone does not prove enforcement.' `
                -CurrentValue "100% MFA registered ($totalEnabled/$totalEnabled enabled members). $secDefText No enforcing CA policy detected." `
                -RequiredValue '100% MFA registration AND enforced CA policy (or Security Defaults)' `
                -Remediation 'Create a Conditional Access policy requiring MFA for All users on All cloud apps. Registration alone is insufficient — a CA policy is required to enforce MFA at sign-in.' `
                -FrameworkIds @('IA-2(1)','IA-2(2)')
            return
        }

        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Satisfied' `
            -Category 'Identity' -Title 'MFA Required for All Users' `
            -Severity 'Critical' `
            -CurrentValue "100% MFA registered ($totalEnabled/$totalEnabled enabled members). $secDefText Enforcing CA policy found." `
            -RequiredValue '100% MFA registration AND enforced CA policy (or Security Defaults)' `
            -FrameworkIds @('IA-2(1)','IA-2(2)')
    }
    elseif ($registeredPct -ge 90) {
        $sample = ($unregistered | Select-Object -First 5 | Select-Object -ExpandProperty UserPrincipalName) -join ', '
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Partial' `
            -Category 'Identity' -Title 'MFA Required for All Users' `
            -Severity 'Critical' `
            -Detail "MFA registration $registeredPct% — below 100%. Enforcing a CA MFA policy at this level will lock out $unregisteredCnt user(s)." `
            -CurrentValue "$registeredPct% registered ($unregisteredCnt of $totalEnabled unregistered). Sample: $sample" `
            -RequiredValue '100% MFA registration before universal CA enforcement' `
            -Remediation 'Run an MFA Registration Campaign (Entra ID > Authentication methods > Registration campaign). Use Temporary Access Pass (TAP) for onboarding. Reach 100% before enforcing MFA CA policy.' `
            -FrameworkIds @('IA-2(1)','IA-2(2)')
    }
    else {
        $sample = ($unregistered | Select-Object -First 10 | Select-Object -ExpandProperty UserPrincipalName) -join ', '
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Gap' `
            -Category 'Identity' -Title 'MFA Required for All Users' `
            -Severity 'Critical' `
            -Detail "MFA registration critically low at $registeredPct%. Universal MFA cannot be enforced without locking users out." `
            -CurrentValue "$registeredPct% registered ($unregisteredCnt of $totalEnabled unregistered). Sample: $sample" `
            -RequiredValue '100% MFA registration AND enforced CA policy for All users / All cloud apps' `
            -Remediation 'Enable Registration Campaign immediately. Issue Temporary Access Passes (TAPs) for bulk onboarding. Do not enforce universal MFA CA policy until registration exceeds 95%.' `
            -FrameworkIds @('IA-2(1)','IA-2(2)')
    }
}

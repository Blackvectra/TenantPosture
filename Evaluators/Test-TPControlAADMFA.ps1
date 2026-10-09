#Requires -Version 7.0
#
# Test-TPControlAADMFA.ps1
# Evaluates AAD-1.2 "MFA Required for All Users" (canonical control per
# Config/controls.json).
#
# v4.6.4: scope-of-emission contracted to AAD-1.2 ONLY. Earlier revisions of
# this file emitted findings under AAD-2.1, AAD-2.2 and AAD-2.4 with the
# wrong Title strings, colliding with the older monolithic AAD evaluator
# (Test-TPControl-AAD.ps1) which is the canonical evaluator for those IDs.
# The cross-emit logic was removed; this file now matches the EvaluatorFunction
# field declared in controls.json for AAD-1.2.
#
# Reads from module state:
#   Get-TPRawData -Key 'AAD-Users'         (Invoke-TPCollectAADUsers)
#   Get-TPRawData -Key 'AAD-AuthPolicies'  (Invoke-TPCollectAADAuthPolicies) — Security Defaults, via Get-TPSecurityDefaultsState
#   Get-TPRawData -Key 'AAD-CAPolicies'    (Invoke-TPCollectAADCAPolicies)   — MFA enforcement
#
# NIST SP 800-53: IA-2(1), IA-2(2)
# MITRE ATT&CK:   T1078, T1110, T1621
#


# Entra Connect's directory-sync service account (Sync_<server>_<id>,
# "On-Premises Directory Synchronization Service Account"). Microsoft says to
# exclude it from MFA and it cannot register a method. One definition so
# AAD-1.2 and AAD-12.1 count the same population.
function Test-TPDirectorySyncAccount {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowNull()] $User)
    if ($null -eq $User) { return $false }
    return ([string](Get-TPObjectField -Item $User -Key 'UserPrincipalName' -Default '') -match '^Sync_') -and
           ([string](Get-TPObjectField -Item $User -Key 'DisplayName' -Default '') -match 'Directory Synchronization')
}

function Test-TPControlAADMFA {
    [CmdletBinding()] param()

    $userRaw = Get-TPRawData -Key 'AAD-Users'
    $authRaw = Get-TPRawData -Key 'AAD-AuthPolicies'

    # Both collectors must have data to evaluate AAD-1.2 confidently
    if ((-not $userRaw -or -not $userRaw.Success) -and
        (-not $authRaw -or -not $authRaw.Success)) {
        $detail = 'Neither AAD-Users nor AAD-AuthPolicies collector produced data.'
        Add-TPFinding -ControlId 'AAD-1.2' -State 'NotApplicable' `
            -Category 'Identity' -Title 'MFA Required for All Users' -Detail $detail
        return
    }

    # Security defaults are collected by AAD-AuthPolicies, not AAD-Users.
    # Reading AAD-Users.Data.SecurityDefaultsEnabled — a key no collector
    # writes — made this always $null: a tenant enforcing MFA through security
    # defaults was scored on registration instead, and the finding printed
    # "Security Defaults: disabled" without having read it. The state is read
    # in one place (Get-TPSecurityDefaultsState); $null means "not read",
    # never "disabled".
    $secDefEnabled = Get-TPSecurityDefaultsState -AuthPolicies $authRaw
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
        $mfaRegCollected = Test-TPSectionCollected $userRaw 'MFARegistration'
        $mfaReg = @(Get-TPNestedProperty -Object $userRaw -Path 'Data.MFARegistration.RegistrationDetails' -Default @())
    }

    # Compute MFA registration completeness. Without CA-policy data here we
    # cannot prove enforcement, but registration < 100% is a hard blocker on
    # enforcing AAD-1.2 even when a CA policy exists.
    $enabledMembers = @($users | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -eq 'Member' })

    # Entra Connect's directory-sync service account cannot register MFA and
    # Microsoft says to exclude it from MFA policies; counting it made a fully
    # enforced tenant read "below 100% — will lock out 1 user".
    $population = @($enabledMembers | Where-Object { -not (Test-TPDirectorySyncAccount $_) })
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
    $cit = Get-TPFrameworkCitations -ControlId 'AAD-1.2'
    $req = 'CA policy requiring MFA for All users on All cloud apps at every sign-in, with every user registered'

    # Security Defaults requires every user to register for MFA and prompts
    # them when Microsoft decides it is necessary — not at every sign-in; only
    # the 16 administrator roles it names do MFA every time, and an
    # administrator cannot require more. That is MFA at every sign-in for some
    # accounts but not all, so it is Partial even with every user registered:
    # a Satisfied would credit IA-2(2), MS.AAD.3.2v1 and PCI 8.4 (MFA on
    # access to non-privileged accounts) that Security Defaults does not
    # enforce. Registration counts the same as on the CA path: since July 29,
    # 2024 there is no grace period, so whoever holds an unregistered user's
    # password enrolls the second factor. Registration that was not read is
    # not a pass. Licensing (Test-TPSecurityDefaultsLicenseFree): the
    # shortfall is fixed by registering users, so it stays scored; with every
    # user registered what remains needs Conditional Access (Entra ID P1), so
    # license gating treats it like any other unlicensed control.
    if ($secDefEnabled -eq $true) {
        $sdCommon = @{ ControlId = 'AAD-1.2'; Category = 'Identity'; Title = 'MFA Required for All Users'; FrameworkIds = $cit }
        if (-not $mfaRegCollected) {
            # The registration report requires Microsoft Entra ID P1 or P2,
            # which a Security Defaults tenant often lacks; when Graph refused
            # it for that reason, re-running will not change the answer.
            $why = if ([string](Get-TPNestedProperty -Object $userRaw -Path 'Data.MFARegistrationFailure' -Default '') -eq 'PremiumLicenseRequired') {
                'MFA registration details were not collected: Graph refused the registration report because this tenant has no Microsoft Entra ID P1 or P2 license, which Microsoft requires for that report, so whether every user has registered cannot be read by this tool on this tenant and was not assessed. Re-running will not change this; confirm each user''s registered methods on their Authentication methods page in the Microsoft Entra admin center.'
            } else {
                'MFA registration details were not collected (see Exceptions), so whether every user has registered was not assessed. Microsoft documents that the registration report requires Microsoft Entra ID P1 or P2.'
            }
            Add-TPSecurityDefaultsFinding @sdCommon -State 'NotApplicable' -Detail $why
            return
        }
        if ($population.Count -eq 0) {
            Add-TPFinding -ControlId 'AAD-1.2' -State 'NotApplicable' `
                -Category 'Identity' -Title 'MFA Required for All Users' -FrameworkIds $cit `
                -Detail $(if ($enabledMembers.Count -eq 0) { 'No enabled member accounts found in tenant.' } else { 'No enabled member accounts other than Entra Connect sync service accounts found in tenant.' })
            return
        }
        $sdSync = if ($syncExcluded -gt 0) { " $syncExcluded Entra Connect sync service account(s) are not counted; Security Defaults excludes directory synchronization accounts from MFA." } else { '' }
        $sdFrequency = 'Only the 16 administrator roles Security Defaults names must complete MFA at every sign-in; other users are prompted for MFA when Microsoft decides it is necessary (based on factors such as location, device, role and task), not at every sign-in, and an administrator cannot require more.'
        if ($unregisteredCnt -eq 0) {
            Add-TPSecurityDefaultsFinding @sdCommon -State 'Partial' -Severity 'Critical' `
                -Detail "Every user must register for MFA, and all $totalEnabled enabled member account(s) have registered.$sdSync $sdFrequency Legacy authentication, which cannot perform MFA, is blocked. MFA at every sign-in for all users requires a Conditional Access policy." `
                -CurrentValue "Security Defaults enabled; 100% registered ($totalEnabled/$totalEnabled enabled members); MFA at every sign-in for the 16 named administrator roles only" -RequiredValue $req `
                -Remediation 'Require MFA (or an authentication strength) for All users on All cloud apps with a Conditional Access policy, excluding only emergency access accounts.' -NeedsConditionalAccess
        } else {
            Add-TPSecurityDefaultsFinding @sdCommon -State 'Partial' -Severity 'Critical' `
                -Detail "Every user must register for MFA, but $unregisteredCnt of $totalEnabled enabled member account(s) $($script:TPSecurityDefaultsShortfallMarker). Security Defaults has had no registration grace period since July 29, 2024, so they are asked to register at their next sign-in, and whoever holds their password can enroll the second factor.$sdSync $sdFrequency" `
                -CurrentValue "Security Defaults enabled; $registeredPct% registered. Sample: $sample" -RequiredValue $req `
                -Remediation 'Run an MFA registration campaign or issue Temporary Access Passes so every enabled user registers. Requiring MFA at every sign-in for all users then needs a Conditional Access policy (Microsoft Entra ID P1), and Security Defaults must be turned off before any Conditional Access policy can be turned on.'
        }
        return
    }

    if ($enabledMembers.Count -eq 0) {
        Add-TPFinding -ControlId 'AAD-1.2' -State 'NotApplicable' `
            -Category 'Identity' -Title 'MFA Required for All Users' `
            -Detail 'No enabled member accounts found in tenant.'
        return
    }

    if (-not $mfaRegCollected) {
        Add-TPFinding -ControlId 'AAD-1.2' -State 'NotApplicable' `
            -Category 'Identity' -Title 'MFA Required for All Users' `
            -Detail 'MFA registration details were not collected; cannot compute registration completeness for AAD-1.2.' `
            -FrameworkIds $cit
        return
    }

    # Enforcement decides the verdict; registration only qualifies it. MFA that
    # is not REQUIRED is not configured — a Gap however many users registered
    # (it scored Partial at 90%+ registration with no policy at all).
    $caRaw  = Get-TPRawData -Key 'AAD-CAPolicies'
    $caRead = [bool]($caRaw -and $caRaw.Success)
    $enforcing = @()
    if ($caRead) {
        # Enabled, All users, All cloud apps, and MFA REQUIRED (the mfa control
        # or an authentication strength; with OR, only when every alternative
        # is MFA).
        $enforcing = @(@($caRaw.Data['Policies']) | Where-Object {
            [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -eq 'enabled' -and
            (Test-TPCAAllUsers $_) -and (Test-TPCAAllApps $_) -and
            (Test-TPCAGrantRequires -Policy $_ -Any @('mfa','authStrength'))
        })
    }
    if (-not $caRead) {
        Add-TPFinding -ControlId 'AAD-1.2' -State 'NotApplicable' -Category 'Identity' -Title 'MFA Required for All Users' -FrameworkIds $cit `
            -Detail "$registeredPct% of users are MFA-registered, but Conditional Access policies were not collected, so whether MFA is required could not be assessed. $secDefText"
        return
    }
    # Security Defaults not read and no CA policy On: it may be on (then this
    # is the Security Defaults verdict above) or off (then the Gap below).
    # $null is never "disabled", so neither is asserted.
    if (Test-TPSecurityDefaultsUnresolved) {
        Add-TPSecurityDefaultsUnreadFinding -ControlId 'AAD-1.2' -Category 'Identity' -Title 'MFA Required for All Users' -FrameworkIds $cit `
            -Question 'whether MFA is required' `
            -IfOn 'every user must register for MFA, the 16 administrator roles it names must complete MFA at every sign-in, and other users are prompted when Microsoft decides it is necessary' `
            -IfOff 'no Conditional Access policy requires MFA' `
            -Extra "$registeredPct% of enabled member accounts have registered an MFA method.$syncNote"
        return
    }
    # Part-way: MFA is asked for, but not of everyone on everything — report-
    # only (Audit mode), scoped to some users/apps, or offered as one
    # alternative beside a compliant device.
    $partway = @()
    if ($enforcing.Count -eq 0) {
        $partway = @(@($caRaw.Data['Policies']) | Where-Object {
            $st = [string](Get-TPObjectField -Item $_ -Key 'State' -Default '')
            $asks = @(Get-TPNestedProperty -Object $_ -Path 'GrantControls.BuiltInControls' -Default @()) -contains 'mfa' -or
                    [string](Get-TPNestedProperty -Object $_ -Path 'GrantControls.AuthStrengthId' -Default '')
            $st -in @('enabled','enabledForReportingButNotEnforced') -and $asks
        })
    }
    if ($enforcing.Count -eq 0 -and $partway.Count -gt 0) {
        $how = @($partway | ForEach-Object {
            $why = if ([string]$_.State -ne 'enabled') { 'report-only (Audit mode)' }
                   elseif (-not (Test-TPCAAllUsers $_) -or -not (Test-TPCAAllApps $_)) { 'not all users / all apps' }
                   else { 'MFA is one alternative (OR)' }
            "$($_.DisplayName) [$why]" })
        Add-TPFinding -ControlId 'AAD-1.2' -State 'Partial' -Category 'Identity' -Title 'MFA Required for All Users' -Severity 'Critical' -FrameworkIds $cit `
            -Detail "MFA is requested but not required of all users on all apps: $($how -join '; '). $secDefText" `
            -CurrentValue "MFA partly enforced; $registeredPct% registered" -RequiredValue $req -Remediation 'Enforce MFA (or an authentication strength) for All users on All cloud apps, with MFA required rather than one alternative.'
        return
    }
    if ($enforcing.Count -eq 0) {
        Add-TPFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 'MFA Required for All Users' -Severity 'Critical' -FrameworkIds $cit `
            -Detail "No Conditional Access policy requires MFA for all users on all cloud apps. $secDefText $registeredPct% of users have registered MFA, but registration alone does not require it at sign-in." `
            -CurrentValue "No enforcing policy; $registeredPct% registered" -RequiredValue $req `
            -Remediation 'Create a Conditional Access policy requiring MFA (or an authentication strength) for All users on All cloud apps, excluding only break-glass accounts. Stage it in report-only first.'
        return
    }
    # Three separate questions, kept apart: is MFA REQUIRED (enforcement, judged across
    # every qualifying policy so exclusions are combined, not ignored), are users
    # REGISTERED (registration), and is the method phishing-resistant (AAD-1.3, not
    # inferred here). Each verified half stays in the Detail.
    $cov = Get-TPCAEffectiveCoverage -Policies $enforcing
    $cv  = Get-TPCACoverageVerdict -Coverage $cov -What 'MFA is required'
    $verified = @($cv.Verified); $short = @($cv.Shortfalls); $unknown = @($cv.NotEstablished)
    if ($cov.Kind -eq 'None') {
        # Every enforcing policy is narrower than all users on all apps.
        $short += "MFA is required only under narrower scope: $(($cov.Narrowed | ForEach-Object { "$($_.Name) ($($_.Why))" }) -join '; ')."
    }
    if ($unregisteredCnt -eq 0) { $verified += "All $totalEnabled enabled member account(s) have registered an MFA method.$syncNote" }
    else { $short += "$unregisteredCnt of $totalEnabled enabled member(s) have not registered a method. They will be asked to register at their next sign-in, so whoever holds their password can enroll the second factor - or they are excluded from the policy. Sample: $sample.$syncNote" }
    Add-TPExpectedStateFinding -ControlId 'AAD-1.2' -Control ([pscustomobject]@{ Category = 'Identity'; Title = 'MFA Required for All Users'; Severity = 'Critical'; Remediation = 'Require MFA (or an authentication strength) for All users on All cloud apps, excluding only emergency access accounts, and run an MFA registration campaign so every enabled user registers.' }) `
        -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknown `
        -CurrentValue "MFA enforcement: $($cov.Kind); $registeredPct% registered ($($totalEnabled - $unregisteredCnt)/$totalEnabled)" -RequiredValue $req
}

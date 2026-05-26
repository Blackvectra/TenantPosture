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
#   Get-NRGRawData -Key 'AAD-AuthPolicies'  (Invoke-NRGCollectAADAuthPolicies)
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

    $secDefEnabled = if ($userRaw -and $userRaw.Success) { $userRaw.Data['SecurityDefaultsEnabled'] } else { $null }
    $users         = if ($userRaw -and $userRaw.Success) { @($userRaw.Data['Users']) }           else { @() }
    $mfaReg        = if ($userRaw -and $userRaw.Success) { @($userRaw.Data['MFARegistration']) } else { @() }

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

    $unregistered = @($enabledMembers | Where-Object {
        $upn = $_.UserPrincipalName
        $rec = $mfaReg | Where-Object { $_.UserPrincipalName -eq $upn }
        (-not $rec) -or ($rec.IsMfaRegistered -eq $false)
    })
    $unregisteredCnt = $unregistered.Count
    $registeredPct   = [math]::Round((($totalEnabled - $unregisteredCnt) / $totalEnabled) * 100, 1)

    if ($unregisteredCnt -eq 0) {
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Satisfied' `
            -Category 'Identity' -Title 'MFA Required for All Users' `
            -Severity 'Critical' `
            -CurrentValue "100% MFA registered ($totalEnabled/$totalEnabled enabled members). Security Defaults: disabled (assumes CA-managed enforcement)." `
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

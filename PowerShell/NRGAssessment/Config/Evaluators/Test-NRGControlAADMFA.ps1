#
# Test-NRGControlAADMFA.ps1
# Evaluates MFA registration completeness and Security Defaults state.
#
# Controls:
#   AAD-2.1  MFA registered for all enabled user accounts
#   AAD-2.2  MFA enforced via CA (not per-user or Security Defaults)
#   AAD-2.4  Security Defaults disabled (CA-managed tenant)
#
# Reads from module state:
#   Get-NRGRawData -Key 'AAD-Users'
#
# NIST SP 800-53: IA-2(1), IA-2(2)
# MITRE ATT&CK:   T1110 (Brute Force)
#

function Test-NRGControlAADMFA {
    [CmdletBinding()] param()

    $raw = Get-NRGRawData -Key 'AAD-Users'

    # Collector failed or not run — skip all controls with context
    if (-not $raw -or -not $raw.Success) {
        $detail = if ($raw) { "Collector failed: $($raw.Exceptions -join '; ')" } else { 'AAD-Users collector did not run.' }
        foreach ($id in @('AAD-2.1','AAD-2.2','AAD-2.4')) {
            Add-NRGFinding -ControlId $id -State 'NotApplicable' `
                -Category 'Identity' -Title "MFA Assessment — $id" `
                -Detail $detail
        }
        return
    }

    $users          = $raw.Data['Users']
    $mfaReg         = $raw.Data['MFARegistration']
    $secDefEnabled  = $raw.Data['SecurityDefaultsEnabled']

    #--------------------------------------------------------------------------
    # AAD-2.1  MFA registered for all enabled member accounts
    # IA-2(1) | T1110 — unregistered users bypass CA MFA enforcement
    # Thresholds: 100% = Satisfied | >=90% = Partial | <90% = Gap
    #--------------------------------------------------------------------------
    $enabledMembers  = @($users | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -eq 'Member' })
    $totalEnabled    = $enabledMembers.Count

    if ($totalEnabled -eq 0) {
        Add-NRGFinding -ControlId 'AAD-2.1' -State 'NotApplicable' `
            -Category 'Identity' -Title 'MFA registered for all enabled user accounts' `
            -Detail 'No enabled member accounts found in tenant.'
    }
    else {
        $unregistered = @($enabledMembers | Where-Object {
            $upn = $_.UserPrincipalName
            $rec = $mfaReg | Where-Object { $_.UserPrincipalName -eq $upn }
            (-not $rec) -or ($rec.IsMfaRegistered -eq $false)
        })
        $unregisteredCnt = $unregistered.Count
        $registeredPct   = [math]::Round((($totalEnabled - $unregisteredCnt) / $totalEnabled) * 100, 1)

        if ($unregisteredCnt -eq 0) {
            Add-NRGFinding -ControlId 'AAD-2.1' -State 'Satisfied' `
                -Category 'Identity' -Title 'MFA registered for all enabled user accounts' `
                -Severity 'High' `
                -CurrentValue "100% ($totalEnabled/$totalEnabled enabled member accounts MFA registered)" `
                -RequiredValue '100% of enabled member accounts registered for MFA'
        }
        elseif ($registeredPct -ge 90) {
            $sample = ($unregistered | Select-Object -First 5 | Select-Object -ExpandProperty UserPrincipalName) -join ', '
            Add-NRGFinding -ControlId 'AAD-2.1' -State 'Partial' `
                -Category 'Identity' -Title 'MFA registered for all enabled user accounts' `
                -Severity 'High' `
                -Detail "MFA registration is $registeredPct% — below 100% but above enforcement threshold. Enable Registration Campaign to close the gap before enforcing AAD-3.1." `
                -CurrentValue "$registeredPct% registered ($unregisteredCnt of $totalEnabled unregistered). Sample unregistered: $sample" `
                -RequiredValue '100% of enabled member accounts registered for MFA' `
                -Remediation 'Enable MFA Registration Campaign: Entra ID > Authentication methods > Registration campaign. Use Temporary Access Pass (TAP) for onboarding. Target 95%+ before enforcing MFA CA policy.'
        }
        else {
            $sample = ($unregistered | Select-Object -First 10 | Select-Object -ExpandProperty UserPrincipalName) -join ', '
            Add-NRGFinding -ControlId 'AAD-2.1' -State 'Gap' `
                -Category 'Identity' -Title 'MFA registered for all enabled user accounts' `
                -Severity 'High' `
                -Detail "MFA registration critically low at $registeredPct%. Enforcing AAD-3.1 CA MFA policy at this registration level will lock out $unregisteredCnt users." `
                -CurrentValue "$registeredPct% registered ($unregisteredCnt of $totalEnabled unregistered). Sample (first 10): $sample" `
                -RequiredValue '95%+ registration before CA enforcement; 100% target' `
                -Remediation 'Enable Registration Campaign (Entra ID > Authentication methods > Registration campaign). Use Temporary Access Pass (TAP) for bulk onboarding without helpdesk calls. Do not enforce AAD-3.1 until registration exceeds 95%.' `
                -FrameworkIds @('IA-2(1)','IA-2(2)')
        }
    }

    #--------------------------------------------------------------------------
    # AAD-2.2 + AAD-2.4  Security Defaults state
    # IA-2(2) — Security Defaults is mutually exclusive with Conditional Access
    # Both controls assessed from the same data point
    #--------------------------------------------------------------------------
    if ($secDefEnabled -eq $true) {
        Add-NRGFinding -ControlId 'AAD-2.2' -State 'Gap' `
            -Category 'Identity' -Title 'MFA enforced via Conditional Access (not per-user MFA or Security Defaults)' `
            -Severity 'High' `
            -Detail 'Security Defaults is enabled. CA policies cannot be enforced while Security Defaults is active. Break-glass exclusions, named locations, and risk-based policies are all blocked.' `
            -CurrentValue 'Security Defaults: enabled' `
            -RequiredValue 'Security Defaults: disabled; MFA enforcement via Conditional Access' `
            -Remediation 'Stage equivalent CA policies in report-only first. Disable Security Defaults (Entra ID > Properties > Manage Security Defaults) only after CA policies are verified in report-only. The two cannot coexist.' `
            -FrameworkIds @('IA-2(1)','IA-2(2)')

        Add-NRGFinding -ControlId 'AAD-2.4' -State 'Gap' `
            -Category 'Identity' -Title 'Security Defaults disabled in favor of Conditional Access' `
            -Severity 'Medium' `
            -Detail 'Security Defaults is enabled — tenant cannot use Conditional Access. See AAD-2.2 for full remediation.' `
            -CurrentValue 'Security Defaults: enabled' `
            -RequiredValue 'Security Defaults: disabled' `
            -FrameworkIds @('IA-2','IA-2(2)')
    }
    else {
        Add-NRGFinding -ControlId 'AAD-2.2' -State 'Satisfied' `
            -Category 'Identity' -Title 'MFA enforced via Conditional Access (not per-user MFA or Security Defaults)' `
            -Severity 'High' `
            -CurrentValue 'Security Defaults: disabled — tenant managed via Conditional Access' `
            -RequiredValue 'Security Defaults: disabled; MFA enforcement via Conditional Access'

        Add-NRGFinding -ControlId 'AAD-2.4' -State 'Satisfied' `
            -Category 'Identity' -Title 'Security Defaults disabled in favor of Conditional Access' `
            -Severity 'Medium' `
            -CurrentValue 'Security Defaults: disabled' `
            -RequiredValue 'Security Defaults: disabled'
    }
}

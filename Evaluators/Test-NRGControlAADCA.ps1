#Requires -Version 7.0
#
# Test-NRGControlAADCA.ps1
# Evaluates AAD-2.1 "Conditional Access Policies Deployed" (canonical control
# per Config/controls.json).
#
# v4.6.4: scope-of-emission contracted to AAD-2.1 ONLY. Earlier revisions of
# this file emitted findings under AAD-2.3, AAD-3.1, AAD-3.2, AAD-3.3, AAD-3.4,
# AAD-3.5 and AAD-3.6 with the wrong Title strings, colliding with the older
# monolithic AAD evaluator (Test-NRGControl-AAD.ps1) which is the canonical
# evaluator for those IDs. The cross-emit logic was removed; this file now
# matches the EvaluatorFunction field declared in controls.json for AAD-2.1.
#
# Reads from module state:
#   Get-NRGRawData -Key 'AAD-CAPolicies'  (Invoke-NRGCollectAADAuthPolicies)
#
# NIST SP 800-53: AC-17, IA-2
# MITRE ATT&CK:   T1078, T1110
#

function Test-NRGControlAADCA {
    [CmdletBinding()] param()

    $caRaw = Get-NRGRawData -Key 'AAD-CAPolicies'

    if (-not $caRaw -or -not $caRaw.Success) {
        $detail = if ($caRaw) { "CA collector failed: $(@(Get-NRGObjectField -Item $caRaw -Key 'Exceptions' -Default @()) -join '; ')" } else { 'AAD-CAPolicies collector did not run.' }
        Add-NRGFinding -ControlId 'AAD-2.1' -State 'NotApplicable' `
            -Category 'Identity' -Title 'Conditional Access Policies Deployed' -Detail $detail
        return
    }

    $policies = @($caRaw.Data['Policies'])
    $enabled  = @($policies | Where-Object { $_.State -eq 'enabled' })

    # Three canonical coverage tracks per controls.json description:
    #   (1) Block legacy authentication
    #   (2) Require MFA for all users / all cloud apps
    #   (3) Phishing-resistant MFA / MFA for admin roles
    $blockLegacy = @($enabled | Where-Object {
        ($_.Conditions.ClientAppTypes -contains 'other' -or
         $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync') -and
        $_.GrantControls.BuiltInControls -contains 'block'
    }).Count -gt 0

    $mfaAllUsers = @($enabled | Where-Object {
        @(Get-NRGNestedProperty -Object $_ -Path 'Conditions.Users.IncludeUsers' -Default @()) -contains 'All' -and
        @(Get-NRGNestedProperty -Object $_ -Path 'Conditions.Applications.IncludeApplications' -Default @()) -contains 'All' -and
        @(Get-NRGNestedProperty -Object $_ -Path 'GrantControls.BuiltInControls' -Default @()) -contains 'mfa'
    }).Count -gt 0

    $mfaAdmins = @($enabled | Where-Object {
        $_.Conditions.Users.IncludeRoles -and
        $_.GrantControls.BuiltInControls -contains 'mfa'
    }).Count -gt 0

    $tracks = @()
    if ($blockLegacy) { $tracks += 'block-legacy-auth' }
    if ($mfaAllUsers) { $tracks += 'mfa-all-users' }
    if ($mfaAdmins)   { $tracks += 'mfa-admin-roles' }
    $covered = $tracks.Count

    if ($enabled.Count -eq 0) {
        Add-NRGFinding -ControlId 'AAD-2.1' -State 'Gap' `
            -Category 'Identity' -Title 'Conditional Access Policies Deployed' `
            -Severity 'High' `
            -Detail 'No enabled Conditional Access policies found. Tenant relies on Security Defaults or password-only access control.' `
            -CurrentValue '0 enabled CA policies' `
            -RequiredValue 'At least 3 enabled CA policies covering (1) block legacy auth, (2) MFA all users, (3) MFA / phishing-resistant MFA for admin roles' `
            -Remediation 'Deploy at minimum: (1) block legacy auth, (2) require MFA all users, (3) phishing-resistant MFA for admin roles. Stage each in report-only mode first.' `
            -FrameworkIds @('AC-17','IA-2')
    }
    elseif ($covered -ge 3) {
        Add-NRGFinding -ControlId 'AAD-2.1' -State 'Satisfied' `
            -Category 'Identity' -Title 'Conditional Access Policies Deployed' `
            -Severity 'High' `
            -CurrentValue "$($enabled.Count) enabled CA policies. Coverage tracks satisfied: $($tracks -join ', ')." `
            -RequiredValue 'At least 3 enabled CA policies covering legacy-auth block, MFA all users, and admin MFA' `
            -FrameworkIds @('AC-17','IA-2')
    }
    else {
        $missing = @('block-legacy-auth','mfa-all-users','mfa-admin-roles') | Where-Object { $_ -notin $tracks }
        Add-NRGFinding -ControlId 'AAD-2.1' -State 'Partial' `
            -Category 'Identity' -Title 'Conditional Access Policies Deployed' `
            -Severity 'High' `
            -Detail "CA policies are deployed but baseline coverage is incomplete. Missing track(s): $($missing -join ', '). See AAD-1.1, AAD-1.2 and AAD-1.3 for per-track detail." `
            -CurrentValue "$($enabled.Count) enabled CA policies. Coverage tracks satisfied: $($tracks -join ', ')." `
            -RequiredValue 'Coverage on all three tracks: block-legacy-auth, mfa-all-users, mfa-admin-roles' `
            -Remediation 'Add CA policies to close missing tracks. Verify MFA registration (>= 95%) before enforcing universal MFA.' `
            -FrameworkIds @('AC-17','IA-2')
    }
}

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
#   Get-NRGRawData -Key 'AAD-CAPolicies'  (Invoke-NRGCollectAADCAPolicies)
#   Security Defaults via Get-NRGSecurityDefaultsState (AAD-AuthPolicies)
#
# NIST SP 800-53: AC-17, IA-2
# MITRE ATT&CK:   T1078, T1110
#

function Test-NRGControlAADCA {
    [CmdletBinding()] param()

    $cit = Get-NRGFrameworkCitations -ControlId 'AAD-2.1'
    $sd  = Get-NRGSecurityDefaultsState

    # While Security Defaults is enabled no CA policy can be turned on, so
    # this control's requirement cannot be met and the answer is already
    # known: a Gap, stating what Security Defaults does provide rather than
    # "password-only". Runs before the CA gate, since CA data cannot change it.
    if ($sd -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId 'AAD-2.1' -Category 'Identity' -Title 'Conditional Access Policies Deployed' -FrameworkIds $cit `
            -State 'Gap' -Severity 'High' `
            -Detail 'Conditional Access is not in use. Security Defaults covers part of the baseline this control tracks: legacy authentication is blocked (AAD-1.1), every user must register for MFA and is prompted when Microsoft decides it is necessary (AAD-1.2), and 16 administrator roles must complete MFA at every sign-in, with no requirement that the method be phishing-resistant (AAD-1.3). Security Defaults cannot be scoped, cannot exclude emergency access accounts, has no report-only mode, and offers none of the Conditional Access conditions and controls (device compliance, locations, risk, session controls).' `
            -CurrentValue 'Security Defaults enabled; 0 Conditional Access policies in force' `
            -RequiredValue 'At least 3 enabled CA policies covering (1) block legacy auth, (2) MFA all users, (3) MFA / phishing-resistant MFA for admin roles' `
            -Remediation 'Deploy at minimum: (1) block legacy auth, (2) require MFA all users, (3) phishing-resistant MFA for admin roles.' -NeedsConditionalAccess
        return
    }

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
    # Same readings as AAD-1.1 / 1.2 / 1.3: legacy block for ALL users on the
    # 'other' client type; MFA (or an authentication strength) for all users
    # and all apps; MFA for admins, which an all-users policy also provides.
    $blockLegacy = @($enabled | Where-Object {
        @($_.Conditions.ClientAppTypes) -contains 'other' -and (Test-NRGCAAllUsers $_) -and (Test-NRGCAGrantRequires -Policy $_ -Any @('block'))
    }).Count -gt 0

    $mfaAllUsers = @($enabled | Where-Object {
        (Test-NRGCAAllUsers $_) -and (Test-NRGCAAllApps $_) -and (Test-NRGCAGrantRequires -Policy $_ -Any @('mfa','authStrength'))
    }).Count -gt 0

    $mfaAdmins = $mfaAllUsers -or (@($enabled | Where-Object {
        @($_.Conditions.Users.IncludeRoles).Count -gt 0 -and (Test-NRGCAGrantRequires -Policy $_ -Any @('mfa','authStrength'))
    }).Count -gt 0)

    $tracks = @()
    if ($blockLegacy) { $tracks += 'block-legacy-auth' }
    if ($mfaAllUsers) { $tracks += 'mfa-all-users' }
    if ($mfaAdmins)   { $tracks += 'mfa-admin-roles' }
    $covered = $tracks.Count

    if ($enabled.Count -eq 0) {
        Add-NRGFinding -ControlId 'AAD-2.1' -State 'Gap' `
            -Category 'Identity' -Title 'Conditional Access Policies Deployed' `
            -Severity 'High' `
            -Detail $(if ($sd -eq $false) { 'No enabled Conditional Access policies found, and Security Defaults is disabled.' } else { 'No enabled Conditional Access policies found. Security Defaults: not read.' }) `
            -CurrentValue '0 enabled CA policies' `
            -RequiredValue 'At least 3 enabled CA policies covering (1) block legacy auth, (2) MFA all users, (3) MFA / phishing-resistant MFA for admin roles' `
            -Remediation 'Deploy at minimum: (1) block legacy auth, (2) require MFA all users, (3) phishing-resistant MFA for admin roles. Stage each in report-only mode first.' `
            -FrameworkIds $cit
    }
    elseif ($covered -ge 3) {
        # The three tracks are a proxy. The expected state is the NRG baseline policy set,
        # an approved list (Config/nrg-standards.json RequiredConditionalAccessTemplates,
        # empty until approved) judged against the Conditional Access view's own
        # Enforced / Similar / Missing status per template.
        $verified = @("$($enabled.Count) enabled CA policies cover the legacy-auth block, MFA for all users and admin MFA ($($tracks -join ', ')).")
        $short = @(); $unknown = @()
        $wanted = @((Get-NRGStandards).RequiredConditionalAccessTemplates)
        if ($wanted.Count -eq 0) {
            $unknown += 'whether the NRG baseline policy set is deployed, because none is approved (Config/nrg-standards.json RequiredConditionalAccessTemplates is empty). The three tracks above are a proxy.'
        } else {
            $view = $null
            try { $view = Get-NRGConditionalAccessView } catch { $view = $null }
            $rows = if ($view -and (Get-NRGObjectField -Item $view -Key 'ReadStatus' -Default '') -eq 'Collected') { @(Get-NRGObjectField -Item $view -Key 'Baseline' -Default @()) } else { @() }
            $enf = @(); $notEnf = @(); $unk = @()
            foreach ($id in $wanted) {
                $row = @($rows | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Id' -Default '') -eq $id } | Select-Object -First 1)
                if ($row.Count -eq 0) { $unk += "$id (unknown template or not evaluated)"; continue }
                $st = [string](Get-NRGObjectField -Item $row[0] -Key 'Status' -Default '')
                if ($st -eq 'Enforced') { $enf += $id }
                elseif ($st -eq 'NotRead') { $unk += "$id (Conditional Access state not read)" }
                else { $notEnf += "$id ($st)" }
            }
            if ($enf.Count)    { $verified += "Required NRG policies enforced: $($enf -join ', ')." }
            if ($notEnf.Count) { $short += "Required NRG policies not enforced: $($notEnf -join '; ') (report-only, narrower or missing policies do not count)." }
            if ($unk.Count)    { $unknown += "required NRG policies that could not be evaluated: $($unk -join '; ')." }
        }
        Add-NRGExpectedStateFinding -ControlId 'AAD-2.1' -Control ([pscustomobject]@{ Category = 'Identity'; Title = 'Conditional Access Policies Deployed'; Severity = 'High'; Remediation = 'Deploy the approved NRG Conditional Access policy set. Stage each in report-only mode first, then enforce.' }) `
            -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknown `
            -CurrentValue "$($enabled.Count) enabled CA policies. Coverage tracks satisfied: $($tracks -join ', ')." `
            -RequiredValue 'The approved NRG Conditional Access policy set, enabled (report-only does not count)'
    }
    else {
        $missing = @('block-legacy-auth','mfa-all-users','mfa-admin-roles') | Where-Object { $_ -notin $tracks }
        # Policies that cover none of the baseline tracks are not part of the
        # baseline: that is a Gap, not half credit.
        $state = if ($covered -eq 0) { 'Gap' } else { 'Partial' }
        Add-NRGFinding -ControlId 'AAD-2.1' -State $state `
            -Category 'Identity' -Title 'Conditional Access Policies Deployed' `
            -Severity 'High' `
            -Detail "CA policies are deployed but baseline coverage is incomplete. Missing track(s): $($missing -join ', '). See AAD-1.1, AAD-1.2 and AAD-1.3 for per-track detail." `
            -CurrentValue "$($enabled.Count) enabled CA policies. Coverage tracks satisfied: $($tracks -join ', ')." `
            -RequiredValue 'Coverage on all three tracks: block-legacy-auth, mfa-all-users, mfa-admin-roles' `
            -Remediation 'Add CA policies to close missing tracks. Verify MFA registration (>= 95%) before enforcing universal MFA.' `
            -FrameworkIds $cit
    }
}

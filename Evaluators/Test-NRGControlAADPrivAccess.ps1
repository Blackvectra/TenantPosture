#
# Test-NRGControlAADPrivAccess.ps1
# Evaluates privileged access hygiene.
#
# Controls:
#   AAD-4.1  Global Administrator count between 2 and 5
#   AAD-4.2  No on-premises synced accounts hold Entra ID admin roles
#   AAD-4.3  Global Administrator accounts are dedicated (no licenses)
#   AAD-4.4  PIM used for Global Administrator role (JIT model)
#   AAD-4.5  Break-glass Global Administrator account exists
#
# Break-glass detection (AAD-4.5) is heuristic:
#   Candidate = cloud-only GA, unlicensed, no interactive sign-in in 30+ days
#   Manual verification required — cannot automate credential storage or CA exclusion checks.
#
# Reads from module state:
#   Get-NRGRawData -Key 'AAD-Roles'   (new Session 2 collector)
#   Get-NRGRawData -Key 'AAD-PIM'     (new Session 2 collector)
#   Get-NRGRawData -Key 'AAD-Users'   (new Session 2 collector)
#
# NIST SP 800-53: AC-2(7), AC-6(2), AC-6(5), IA-2(6), CP-6, IR-4
# MITRE ATT&CK:   T1078.002 (Domain Accounts), T1078.004 (Cloud Accounts),
#                 T1098 (Account Manipulation)
#

function Test-NRGControlAADPrivAccess {
    [CmdletBinding()] param()

    $roleRaw = Get-NRGRawData -Key 'AAD-Roles'
    $pimRaw  = Get-NRGRawData -Key 'AAD-PIM'
    $userRaw = Get-NRGRawData -Key 'AAD-Users'

    # Roles collector failed — skip all controls
    if (-not $roleRaw -or -not $roleRaw.Success) {
        $detail = if ($roleRaw) { "Collector failed: $($roleRaw.Exceptions -join '; ')" } else { 'AAD-Roles collector did not run.' }
        foreach ($id in @('AAD-4.1','AAD-4.2','AAD-4.3','AAD-4.4','AAD-4.5')) {
            Add-NRGFinding -ControlId $id -State 'NotApplicable' `
                -Category 'Identity' -Title "Privileged Access Assessment — $id" -Detail $detail
        }
        return
    }

    # Well-known Entra ID built-in role template GUID — stable across all tenants
    $GA_ROLE_ID = '62e90394-69f5-4237-9190-012177145e10'

    $allAssignments = @($roleRaw.Data['PermanentAssignments'])
    $globalAdmins   = @($allAssignments | Where-Object { $_.RoleDefinitionId -eq $GA_ROLE_ID })
    $gaCount        = $globalAdmins.Count

    #--------------------------------------------------------------------------
    # AAD-4.1  Global Admin count between 2 and 5
    # AC-2, AC-6(5) — blast radius vs. recovery redundancy
    #--------------------------------------------------------------------------
    if ($gaCount -ge 2 -and $gaCount -le 5) {
        Add-NRGFinding -ControlId 'AAD-4.1' -State 'Satisfied' `
            -Category 'Identity' -Title 'Global Administrator count between 2 and 5' `
            -Severity 'High' `
            -CurrentValue "Permanent Global Administrator count: $gaCount" `
            -RequiredValue 'Between 2 and 5 permanent Global Administrator assignments'
    }
    elseif ($gaCount -lt 2) {
        Add-NRGFinding -ControlId 'AAD-4.1' -State 'Partial' `
            -Category 'Identity' -Title 'Global Administrator count between 2 and 5' `
            -Severity 'High' `
            -Detail 'Single Global Administrator creates recovery risk — MFA device loss, account lockout, or Entra outage can result in complete loss of admin access.' `
            -CurrentValue "Permanent Global Administrator count: $gaCount" `
            -RequiredValue 'Minimum 2 Global Administrator accounts for redundancy' `
            -Remediation 'Add a second GA account as dedicated break-glass: cloud-only, unlicensed, credentials sealed offline (see AAD-4.5).' `
            -FrameworkIds @('AC-2','AC-6(5)')
    }
    else {
        $gaList = ($globalAdmins | Select-Object -ExpandProperty PrincipalUPN) -join ', '
        Add-NRGFinding -ControlId 'AAD-4.1' -State 'Gap' `
            -Category 'Identity' -Title 'Global Administrator count between 2 and 5' `
            -Severity 'High' `
            -Detail "Excess Global Administrators expand the attack surface. Each additional permanent GA is another account that can be compromised for full tenant takeover." `
            -CurrentValue "Permanent Global Administrator count: $gaCount. Accounts: $gaList" `
            -RequiredValue 'Maximum 5 permanent Global Administrator assignments' `
            -Remediation 'Reduce to 5 or fewer. Reassign excess to scoped roles (Exchange Admin, User Admin, Security Admin, etc.). Migrate remaining to PIM eligible where P2 is licensed.' `
            -FrameworkIds @('AC-2','AC-6(5)')
    }

    #--------------------------------------------------------------------------
    # AAD-4.2  No on-prem synced accounts hold Entra ID admin roles
    # AC-6(5), IA-2(6) | T1078.002 — on-prem AD → tenant admin kill chain
    # Critical: on-prem AD compromise = immediate Entra GA via Entra Connect
    #--------------------------------------------------------------------------
    $syncedAdmins = @($allAssignments | Where-Object { $_.OnPremSynced -eq $true })

    if ($syncedAdmins.Count -eq 0) {
        Add-NRGFinding -ControlId 'AAD-4.2' -State 'Satisfied' `
            -Category 'Identity' -Title 'No on-premises synced accounts hold Entra ID admin roles' `
            -Severity 'Critical' `
            -CurrentValue 'No on-premises synced accounts found with Entra ID role assignments' `
            -RequiredValue 'Zero on-premises synced accounts in any Entra ID directory role'
    }
    else {
        $syncedList = ($syncedAdmins | ForEach-Object { "$($_.PrincipalUPN) [$($_.RoleName)]" }) -join '; '
        Add-NRGFinding -ControlId 'AAD-4.2' -State 'Gap' `
            -Category 'Identity' -Title 'No on-premises synced accounts hold Entra ID admin roles' `
            -Severity 'Critical' `
            -Detail 'On-prem AD compromise (DCSync, credential dump, domain takeover) directly produces Entra Global Admin access via Entra Connect sync. This is a complete hybrid identity kill chain (T1078.002).' `
            -CurrentValue "$($syncedAdmins.Count) synced account(s) with Entra roles: $syncedList" `
            -RequiredValue 'Zero on-premises synced accounts in any Entra ID directory role' `
            -Remediation 'Remove role assignments from synced accounts immediately. Create dedicated cloud-only admin accounts with no on-prem counterpart. On-prem accounts should be standard user accounts only in the cloud tenant.' `
            -FrameworkIds @('AC-6(5)','IA-2(6)')
    }

    #--------------------------------------------------------------------------
    # AAD-4.3  GA accounts are dedicated (no assigned licenses)
    # AC-6(2), AC-6(5) — daily-use account with GA = maximum credential exposure
    # Proxy: license assignment indicates daily-use account (mailbox, apps)
    #--------------------------------------------------------------------------
    if ($userRaw -and $userRaw.Success) {
        $users = @($userRaw.Data['Users'])

        $gaWithLicense = @($globalAdmins | ForEach-Object {
            $upn  = $_.PrincipalUPN
            $user = $users | Where-Object { $_.UserPrincipalName -eq $upn }
            if ($user -and $user.AssignedLicenses.Count -gt 0) {
                [PSCustomObject]@{ UPN = $upn; LicenseCount = $user.AssignedLicenses.Count }
            }
        } | Where-Object { $_ -ne $null })

        if ($gaWithLicense.Count -eq 0) {
            Add-NRGFinding -ControlId 'AAD-4.3' -State 'Satisfied' `
                -Category 'Identity' -Title 'Global Administrator accounts are dedicated (no assigned licenses)' `
                -Severity 'High' `
                -CurrentValue 'All Global Administrator accounts are unlicensed — consistent with dedicated admin-only account pattern' `
                -RequiredValue 'All GA accounts unlicensed (no daily-use mailbox or app access)'
        }
        else {
            $licensed = ($gaWithLicense | Select-Object -ExpandProperty UPN) -join ', '
            Add-NRGFinding -ControlId 'AAD-4.3' -State 'Gap' `
                -Category 'Identity' -Title 'Global Administrator accounts are dedicated (no assigned licenses)' `
                -Severity 'High' `
                -Detail 'Licensed GA accounts are daily-use accounts — exposed to phishing, malware, and browser-based attacks during normal work. A compromised daily-use account with GA is an immediate full-tenant compromise.' `
                -CurrentValue "GA accounts with assigned licenses (likely daily-use): $licensed" `
                -RequiredValue 'All GA accounts unlicensed — admin tasks use dedicated cloud-only account, daily work uses separate licensed account' `
                -Remediation 'Create dedicated cloud-only admin accounts: unlicensed, no mailbox, used only for admin tasks. Remove GA role from daily-use licensed accounts. Assign daily-use accounts appropriate scoped roles only.' `
                -FrameworkIds @('AC-6(2)','AC-6(5)')
        }
    }
    else {
        Add-NRGFinding -ControlId 'AAD-4.3' -State 'NotApplicable' `
            -Category 'Identity' -Title 'Global Administrator accounts are dedicated (no assigned licenses)' `
            -Detail 'AAD-Users collector data unavailable — cannot assess GA account license state.'
    }

    #--------------------------------------------------------------------------
    # AAD-4.4  PIM used for Global Administrator role (JIT model)
    # AC-2(7), AC-6(2) — limit standing privilege window
    #--------------------------------------------------------------------------
    if ($pimRaw -and $pimRaw.Data['PIMAvailable'] -eq $true) {
        $eligibleGACount = $pimRaw.Data['EligibleGACount']

        if ($gaCount -eq 0 -and $eligibleGACount -gt 0) {
            # Ideal: all GA access via PIM eligible, zero permanent
            Add-NRGFinding -ControlId 'AAD-4.4' -State 'Satisfied' `
                -Category 'Identity' -Title 'PIM used for Global Administrator role (JIT access model)' `
                -Severity 'High' `
                -CurrentValue "All GA access via PIM eligible ($eligibleGACount eligible assignments). Zero permanent GA holders." `
                -RequiredValue 'All operational Global Admin access via PIM eligible assignments; permanent GA limited to break-glass only'
        }
        elseif ($gaCount -le 2 -and $eligibleGACount -gt 0) {
            # Acceptable: break-glass permanent + PIM for operational admins
            Add-NRGFinding -ControlId 'AAD-4.4' -State 'Partial' `
                -Category 'Identity' -Title 'PIM used for Global Administrator role (JIT access model)' `
                -Severity 'High' `
                -Detail 'PIM is in use but permanent GA assignments still exist alongside eligible assignments. Permanent GAs should be break-glass accounts only.' `
                -CurrentValue "$gaCount permanent GA(s) + $eligibleGACount PIM eligible assignment(s)" `
                -RequiredValue 'Zero permanent GA assignments for operational admins; eligible only via PIM' `
                -Remediation 'Convert remaining permanent GAs to PIM eligible. Retain max 1-2 permanent accounts as break-glass (with access alert, sealed credentials, CA exclusion).' `
                -FrameworkIds @('AC-2(7)','AC-6(2)','AC-6(5)')
        }
        else {
            Add-NRGFinding -ControlId 'AAD-4.4' -State 'Gap' `
                -Category 'Identity' -Title 'PIM used for Global Administrator role (JIT access model)' `
                -Severity 'High' `
                -Detail 'PIM is available but not consistently applied to the Global Administrator role. Permanent standing access means a compromised admin account immediately has full tenant privileges.' `
                -CurrentValue "$gaCount permanent GA(s), $eligibleGACount PIM eligible" `
                -RequiredValue 'All operational GA assignments via PIM eligible; zero or break-glass-only permanent assignments' `
                -Remediation 'Migrate all operational GA assignments to PIM eligible. Activation settings: require MFA, justification required, max 8-hour duration. Consider approval workflow for production tenants.' `
                -FrameworkIds @('AC-2(7)','AC-6(2)','AC-6(5)')
        }
    }
    else {
        # P2 not licensed — NotApplicable with licensing gap context
        $errNote = if ($pimRaw -and $pimRaw.Exceptions.Count -gt 0) { " Collector error: $($pimRaw.Exceptions[0])" } else { '' }
        Add-NRGFinding -ControlId 'AAD-4.4' -State 'NotApplicable' `
            -Category 'Identity' -Title 'PIM used for Global Administrator role (JIT access model)' `
            -Severity 'High' `
            -Detail "Entra ID P2 not licensed or RoleManagement schedule endpoints not provisioned. Cannot assess JIT access model. Current permanent GA count: $gaCount.$errNote" `
            -CurrentValue "PIM not available. Permanent GA count: $gaCount" `
            -RequiredValue 'Entra ID P2 required for PIM (included in M365 Business Premium)' `
            -Remediation 'Upgrade to M365 Business Premium or add Entra ID P2 add-on. PIM for Global Admin is a critical control — permanent GA without PIM means standing full-tenant access. This is a licensing gap finding.' `
            -FrameworkIds @('AC-2(7)','AC-6(2)','AC-6(5)')
    }

    #--------------------------------------------------------------------------
    # AAD-4.5  Break-glass account exists (heuristic detection)
    # AC-2(7), CP-6, IR-4 — emergency access for identity system failures
    # Heuristic: cloud-only GA, unlicensed, no interactive sign-in in 30+ days (or never)
    # Result.Partial = candidate found, needs manual verification
    # Result.Gap = no candidate found, break-glass likely missing
    #--------------------------------------------------------------------------
    if ($userRaw -and $userRaw.Success) {
        $users = @($userRaw.Data['Users'])

        $breakGlassCandidates = @($globalAdmins | ForEach-Object {
            $upn  = $_.PrincipalUPN
            $user = $users | Where-Object { $_.UserPrincipalName -eq $upn }
            if ($user) {
                $unlicensed  = ($user.AssignedLicenses.Count -eq 0)
                $cloudOnly   = ($user.OnPremisesSyncEnabled -ne $true)
                $lastSignIn  = $user.LastInteractiveSignIn
                $staleSignIn = ($null -eq $lastSignIn) -or
                               ((New-TimeSpan -Start ([datetime]$lastSignIn) -End (Get-Date)).TotalDays -gt 30)

                if ($unlicensed -and $cloudOnly -and $staleSignIn) {
                    [PSCustomObject]@{
                        UPN        = $upn
                        LastSignIn = if ($lastSignIn) { $lastSignIn } else { 'Never' }
                    }
                }
            }
        } | Where-Object { $_ -ne $null })

        if ($breakGlassCandidates.Count -ge 1) {
            $candidateList = ($breakGlassCandidates | ForEach-Object {
                "$($_.UPN) (last sign-in: $($_.LastSignIn))"
            }) -join '; '
            # Partial: candidate detected but cannot verify offline credential storage or CA exclusion
            Add-NRGFinding -ControlId 'AAD-4.5' -State 'Partial' `
                -Category 'Identity' -Title 'Break-glass Global Administrator account exists' `
                -Severity 'High' `
                -Detail 'Break-glass candidate(s) detected based on heuristic (unlicensed, cloud-only GA, sign-in > 30 days or never). Manual verification required — credential storage, CA exclusion, and sign-in alert cannot be confirmed automatically.' `
                -CurrentValue "Candidate(s): $candidateList" `
                -RequiredValue 'Verified break-glass GA: cloud-only, unlicensed, credentials sealed offline, sign-in alert configured, tested quarterly' `
                -Remediation 'Verify manually: (1) credentials printed and stored in sealed envelope in physical safe, (2) account excluded from MFA CA via named location, (3) sign-in alert configured in Entra ID or Azure Monitor, (4) tested quarterly from known IP.'
        }
        else {
            Add-NRGFinding -ControlId 'AAD-4.5' -State 'Gap' `
                -Category 'Identity' -Title 'Break-glass Global Administrator account exists' `
                -Severity 'High' `
                -Detail 'No break-glass account candidates identified. All GA accounts have recent sign-ins and/or assigned licenses — inconsistent with a dedicated break-glass pattern. Without break-glass, a failed MFA provider or misconfigured CA policy can lock all admins out of the tenant permanently.' `
                -CurrentValue 'No unlicensed cloud-only GA with stale or no interactive sign-in found' `
                -RequiredValue '1-2 dedicated break-glass GA accounts: cloud-only, unlicensed, 20+ char random password, CA excluded, credentials sealed offline' `
                -Remediation 'Create dedicated break-glass GA: cloud-only, unlicensed, 20+ char random password, excluded from MFA CA via named location, credentials printed and stored in physical safe. Configure sign-in alert in Azure Monitor. Test quarterly.' `
                -FrameworkIds @('AC-2(7)','CP-6','IR-4')
        }
    }
    else {
        Add-NRGFinding -ControlId 'AAD-4.5' -State 'NotApplicable' `
            -Category 'Identity' -Title 'Break-glass Global Administrator account exists' `
            -Detail 'AAD-Users collector data unavailable — cannot assess break-glass account pattern.'
    }
}

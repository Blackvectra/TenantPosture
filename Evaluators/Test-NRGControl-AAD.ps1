#Requires -Version 7.0

# Safe property accessor — prevents throw on null nested object access

# ── Collection Guard ────────────────────────────────────────────────────────
# Returns $true if AAD data was successfully collected
function Test-NRGAADDataAvailable {
    $ca   = Get-NRGRawData -Key 'AAD-CAPolicies'
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    $usr  = Get-NRGRawData -Key 'AAD-Users'
    $rol  = Get-NRGRawData -Key 'AAD-Roles'
    # At least one AAD collector must have succeeded
    return ($ca   -and $ca.Success)   -or
           ($auth -and $auth.Success) -or
           ($usr  -and $usr.Success)  -or
           ($rol  -and $rol.Success)
}


# Returns $true only when the named AAD-DirectoryRoles section was collected.
#
# Invoke-NRGCollectAADRoles sets Success = (assignments -OR- eligibility), so a
# tenant whose permanent-assignment read failed while eligibility succeeded
# still reports Success = $true with RoleAssignments and PrivRoles empty. Every
# real tenant has at least one privileged assignment, so an empty list there is
# a failed read — never a clean tenant — and reporting "no guest admins" or "no
# synced admins" from it is a false pass on the tenant-takeover controls.
#
# Absent SectionStatus (older captured data) is treated as collected so a
# replayed results JSON keeps its previous behaviour.
function Test-NRGRoleSectionCollected {
    [CmdletBinding()]
    param(
        [AllowNull()] $Roles,
        [Parameter(Mandatory)] [string] $Section
    )
    $status = Get-NRGNestedProperty -Object $Roles -Path "Data.SectionStatus.$Section" -Default $null
    if ($null -eq $status) { return $true }
    return ($status -eq 'Collected')
}

function Get-SafeProp {
    param($obj, [string]$prop, $default = $null)
    if ($null -eq $obj) { return $default }
    try {
        $val = $obj.$prop
        if ($null -eq $val) { return $default }
        return $val
    } catch { return $default }
}

#
# Test-NRGControl-AAD.ps1  (v4.5.5)
# Evaluates Entra ID (AAD) security controls.
# SCORING ONLY — no API calls, no data collection.
# Reads from module state via Get-NRGRawData; writes findings via Add-NRGFinding.
#
# NIST SP 800-53: IA-2, IA-5, AC-6, AC-2, AC-7
# MITRE ATT&CK:   T1078, T1110, T1621, T1528
#

# ── AAD-1.1 Legacy Authentication Block ──────────────────────────────────────
function Test-NRGControlAADLegacyAuth {
    [CmdletBinding()] param()

    $controlId = 'AAD-1.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $caData = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $caData -or -not $caData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Conditional Access data not collected'
        return
    }

    $blockPolicies = @($caData.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        (($_.Conditions.ClientAppTypes -contains 'other') -or
         ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync')) -and
        ($_.GrantControls.BuiltInControls -contains 'block')
    })

    if ($blockPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail "Legacy auth blocked by $($blockPolicies.Count) CA policy(ies): $($blockPolicies.DisplayName -join ', ')"
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'No Conditional Access policy found that blocks legacy authentication (Other clients).' `
            -CurrentValue 'No blocking CA policy' -RequiredValue 'CA policy blocking Other clients for all users' `
            -Remediation $control.Remediation
    }
}

# ── AAD-1.3 Phishing-Resistant MFA for Admins ────────────────────────────────
function Test-NRGControlAADPhishResistantMFA {
    [CmdletBinding()] param()

    $controlId = 'AAD-1.3'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $caData = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $caData -or -not $caData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Conditional Access data not collected'
        return
    }

    # Look for CA policy targeting roles AND using Authentication Strength (phishing-resistant)
    $phishResistantPolicies = @($caData.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        @($_.Conditions.Users.IncludeRoles).Count -gt 0 -and
        (-not [string]::IsNullOrEmpty($_.GrantControls.AuthStrengthId))
    })

    # Also check for policies targeting roles with MFA (lower bar — Partial)
    $mfaForRolePolicies = @($caData.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        @($_.Conditions.Users.IncludeRoles).Count -gt 0 -and
        ($_.GrantControls.BuiltInControls -contains 'mfa')
    })

    if ($phishResistantPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail "Phishing-resistant MFA (Authentication Strength) required for admin roles by $($phishResistantPolicies.Count) CA policy(ies)."
    } elseif ($mfaForRolePolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail 'Admin roles have MFA required via CA, but not using Authentication Strength (phishing-resistant). AiTM attacks can bypass standard MFA.' `
            -CurrentValue 'CA requires standard MFA for admin roles' `
            -RequiredValue 'CA using Authentication Strength (phishing-resistant MFA) for admin roles' `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'No CA policy found that requires MFA for privileged directory roles.' `
            -CurrentValue 'No phishing-resistant MFA for admins' `
            -RequiredValue 'CA policy with Authentication Strength targeting admin roles' `
            -Remediation $control.Remediation
    }
}

# ── AAD-1.4 Sign-in Risk CA Policy ───────────────────────────────────────────
function Test-NRGControlAADSignInRisk {
    [CmdletBinding()] param()
    $cid = 'AAD-1.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca  = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $riskPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and @($_.Conditions.SignInRiskLevels).Count -gt 0 -and
        ($_.GrantControls.BuiltInControls -contains 'mfa' -or -not [string]::IsNullOrEmpty($_.GrantControls.AuthStrengthId))
    })
    if ($riskPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Sign-in risk CA policy active: $($riskPolicies[0].DisplayName)"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No sign-in risk CA policy configured. This control requires Entra ID P2 (not included in Business Premium / P1). If you have P2 licensing, create a CA policy with Sign-in risk condition. Otherwise this is expected.' -CurrentValue 'No sign-in risk policy' -RequiredValue 'CA policy: signInRiskLevels = high/medium + require MFA' -Remediation $ctrl.Remediation
    }
}

# ── AAD-1.5 User Risk CA Policy ───────────────────────────────────────────────
function Test-NRGControlAADUserRisk {
    [CmdletBinding()] param()
    $cid = 'AAD-1.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca  = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $riskPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and @($_.Conditions.UserRiskLevels).Count -gt 0 -and
        ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.BuiltInControls -contains 'passwordChange')
    })
    if ($riskPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "User risk CA policy active: $($riskPolicies[0].DisplayName)"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No CA policy responds to elevated user risk. Compromised accounts are not automatically challenged. Requires Entra ID P2.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-2.2 Named Locations Defined ──────────────────────────────────────────
function Test-NRGControlAADNamedLocations {
    [CmdletBinding()] param()
    $cid = 'AAD-2.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca  = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $namedLocations   = @(Get-NRGNestedProperty -Object $ca -Path 'Data.NamedLocations' -Default @())
    $trustedLocations = @($namedLocations | Where-Object { $_.IsTrusted })
    if ($trustedLocations.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($trustedLocations.Count) trusted named location(s) defined."
    } elseif ($namedLocations.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "$($namedLocations.Count) named location(s) defined but none marked as trusted." -CurrentValue 'Named locations defined, none trusted' -RequiredValue 'At least one trusted IP range defined'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No named locations defined. Cannot enforce location-based CA conditions or exclude trusted office IPs.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-2.3 Device Compliance Enforced via CA ─────────────────────────────────
function Test-NRGControlAADDeviceComplianceCA {
    [CmdletBinding()] param()
    $cid = 'AAD-2.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca  = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $compliancePolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        ($_.GrantControls.BuiltInControls -contains 'compliantDevice' -or $_.GrantControls.BuiltInControls -contains 'domainJoinedDevice')
    })
    if ($compliancePolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Device compliance required by $($compliancePolicies.Count) CA policy(ies)."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No CA policy requires compliant or hybrid-joined device. Unmanaged personal devices access corporate resources unchecked.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-3.2 No Permanent Admin Assignments ────────────────────────────────────
function Test-NRGControlAADNoPermanentAdmins {
    [CmdletBinding()] param()
    $cid = 'AAD-3.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pim = Get-NRGRawData -Key 'AAD-PIMSchedules'
    $roles = Get-NRGRawData -Key 'AAD-DirectoryRoles'
    if (-not $pim -or -not $pim.Success) {
        if ($pim -and $pim.PIMAvailable -eq $false) {
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM not available (requires Entra P2 license)'; return
        }
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM data not collected'; return
    }
    $permanentPriv = @()
    if ($roles -and $roles.Success) {
        $permanentPriv = @($roles.Data['RoleAssignments'] | Where-Object {
            $_.IsPriv -and $_.PrincipalType -notmatch 'servicePrincipal'
        })
    }
    $eligibleCount = @($pim.Data['EligibleSchedules']).Count
    if ($permanentPriv.Count -eq 0 -and $eligibleCount -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "No permanent privileged role assignments. $eligibleCount eligible (PIM) assignment(s) configured."
    } elseif ($permanentPriv.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($permanentPriv.Count) permanent privileged role assignment(s) found. Admins should be eligible in PIM and activate only when needed." -CurrentValue "Permanent: $($permanentPriv.PrincipalDisplayName -join ', ')" -RequiredValue 'All privileged roles via PIM eligible assignments only' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'PIM available but no eligible schedules configured. Consider migrating permanent admins to PIM.'
    }
}

# ── AAD-3.3 PIM Requires MFA on Activation ───────────────────────────────────
function Test-NRGControlAADPIMMFA {
    [CmdletBinding()] param()
    $cid = 'AAD-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected or PIM not licensed'; return
    }
    $noMFA = @($gov.Data['PIMRolePolicies'] | Where-Object { $_.RequiresMFA -eq $false })
    if ($noMFA.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'All PIM role policies require MFA on activation.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($noMFA.Count) PIM role policy(ies) do not require MFA on activation." -Remediation $ctrl.Remediation
    }
}

# ── AAD-3.4 PIM Requires Justification ───────────────────────────────────────
function Test-NRGControlAADPIMJustification {
    [CmdletBinding()] param()
    $cid = 'AAD-3.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected'; return
    }
    $noJust = @($gov.Data['PIMRolePolicies'] | Where-Object { $_.RequiresJustification -eq $false })
    if ($noJust.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'All PIM role policies require justification on activation.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($noJust.Count) PIM role policy(ies) do not require justification — no audit trail for why privilege was elevated." -Remediation $ctrl.Remediation
    }
}

# ── AAD-3.5 PIM GA Activation Requires Approval ──────────────────────────────
function Test-NRGControlAADPIMApproval {
    [CmdletBinding()] param()
    $cid = 'AAD-3.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected'; return
    }
    # Focus on Global Administrator role policy specifically
    $gaPolicy = @($gov.Data['PIMRolePolicies'] | Where-Object { $_.DisplayName -match 'Global' -or $_.ScopeId -match 'Global' }) | Select-Object -First 1
    if (-not $gaPolicy) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Global Administrator PIM policy not found in collected data'; return
    }
    if ($gaPolicy.RequiresApproval -eq $true) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Global Administrator PIM activation requires approval.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'GA PIM activation does not require approval — any eligible user can self-activate. Consider requiring approval for highest-privilege role.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-3.6 PIM Max Activation Duration ──────────────────────────────────────
function Test-NRGControlAADPIMDuration {
    [CmdletBinding()] param()
    $cid = 'AAD-3.6'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected'; return
    }
    $longDuration = @($gov.Data['PIMRolePolicies'] | Where-Object { $_.MaxDurationHours -gt 8 })
    $unknownDuration = @($gov.Data['PIMRolePolicies'] | Where-Object { $null -eq $_.MaxDurationHours })
    if ($longDuration.Count -eq 0 -and $unknownDuration.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'All PIM role policies have max activation ≤8 hours.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "$($longDuration.Count) role policy(ies) allow activation >8 hours. Shorter windows reduce blast radius." -CurrentValue ">8h max duration" -RequiredValue '≤8 hours max duration'
    }
}

# ── AAD-4.1 Guest Invite Permissions Restricted ───────────────────────────────
function Test-NRGControlAADGuestInvite {
    [CmdletBinding()] param()
    $cid = 'AAD-4.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    $inviteFrom = [string](Get-NRGNestedProperty -Object $gov -Path 'Data.ExternalCollab.AllowInvitesFrom' -Default 'everyone')
    $secure     = @('adminsAndGuestInviters','admins','none')
    if ($inviteFrom -in $secure) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Guest invitations restricted to: $inviteFrom"
    } elseif ($inviteFrom -eq 'adminsGuestInvitersAndAllMembers') {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'All members can invite guests — restrict to admins only.' -CurrentValue $inviteFrom -RequiredValue 'adminsAndGuestInviters or admins'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Anyone can invite guest users ($inviteFrom). This allows uncontrolled external access provisioning." -CurrentValue $inviteFrom -RequiredValue 'adminsAndGuestInviters' -Remediation $ctrl.Remediation
    }
}

# ── AAD-4.2 External Collaboration Settings ───────────────────────────────────
function Test-NRGControlAADExternalCollab {
    [CmdletBinding()] param()
    $cid = 'AAD-4.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    $collab = Get-NRGNestedProperty -Object $gov -Path 'Data.ExternalCollab'
    $gaps = @()
    if (Get-NRGNestedProperty -Object $collab -Path 'DefaultUserRolePermissions.AllowedToCreateTenants') { $gaps += 'Users can create new tenants' }
    if ((Get-SafeProp $collab 'BlockMsolPowerShell') -ne $true) { $gaps += 'Legacy MSOL PowerShell not blocked' }
    if ($gaps.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'External collaboration settings properly restricted.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "External collab gaps: $($gaps -join '; ')" -Remediation $ctrl.Remediation
    }
}

# ── AAD-4.3 B2B Guest Default Permissions Restricted ─────────────────────────
function Test-NRGControlAADGuestPermissions {
    [CmdletBinding()] param()
    $cid = 'AAD-4.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # GuestUserRoleId: 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Guest User (restricted)
    # 2af84b1e-32c8-42b7-82bc-daa82404023b = Guest User (very restricted, recommended)
    # bf6b3c49-c849-4f4c-b32d-... = Member user role (too permissive)
    $restrictedRoleIds = @(
        '10dae51f-b6af-4016-8d66-8c2a99b929b3',  # Guest User
        '2af84b1e-32c8-42b7-82bc-daa82404023b'   # Restricted Guest User
    )
    $guestRoleId = [string]((Get-SafeProp (Get-SafeProp $gov.Data 'ExternalCollab') 'GuestUserRoleId') ?? '')
    if ($guestRoleId -in $restrictedRoleIds) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Guest user default permissions are restricted.'
    } elseif ([string]::IsNullOrEmpty($guestRoleId)) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Guest role ID not available in collected data'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Guest users may have excessive default permissions. Set to Restricted Guest User.' -CurrentValue "RoleId: $guestRoleId" -RequiredValue 'Restricted Guest User role' -Remediation $ctrl.Remediation
    }
}

# ── AAD-5.1 SSPR Enabled ──────────────────────────────────────────────────────
function Test-NRGControlAADSSPR {
    [CmdletBinding()] param()
    $cid = 'AAD-5.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    $sspr = [bool]((Get-SafeProp (Get-SafeProp $auth.Data 'AuthorizationPolicy') 'AllowedToUseSSPR') ?? $false)
    if ($sspr) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Self-service password reset is enabled for users.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'SSPR is disabled. Users must contact helpdesk for all password resets — increases helpdesk load and time-to-recover on credential issues.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-5.2 SSPR Requires Multiple Auth Methods ───────────────────────────────
function Test-NRGControlAADSSPRMethods {
    [CmdletBinding()] param()
    $cid = 'AAD-5.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    $ssprPolicy = Get-NRGNestedProperty -Object $gov -Path 'Data.SSPRPolicy' -Default $null
    if (-not $gov -or -not $gov.Success -or -not $ssprPolicy) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SSPR policy data not collected'; return
    }
    $methodsConfigured = Get-NRGNestedProperty -Object $ssprPolicy -Path 'MethodsConfigured' -Default @()
    $enabledMethods = @($methodsConfigured | Where-Object { $_.State -eq 'enabled' })
    if ($enabledMethods.Count -ge 2) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($enabledMethods.Count) authentication methods enabled for SSPR."
    } elseif ($enabledMethods.Count -eq 1) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'Only one authentication method enabled for SSPR. At least two required for account recovery resilience.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No authentication methods configured for SSPR.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-6.1 User App Registration Disabled ────────────────────────────────────
function Test-NRGControlAADUserAppReg {
    [CmdletBinding()] param()
    $cid = 'AAD-6.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    $extCollab = Get-SafeProp $gov.Data 'ExternalCollab'
    $defPerms  = Get-SafeProp $extCollab 'DefaultUserRolePermissions'
    $canCreate = [bool]((Get-SafeProp $defPerms 'AllowedToCreateApps') ?? $true)
    if (-not $canCreate) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Users cannot register applications. Only admins can create app registrations.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Any user can register applications. Malicious OAuth apps or accidental exposure of sensitive API permissions is possible.' -CurrentValue 'AllowedToCreateApps = $true' -RequiredValue 'AllowedToCreateApps = $false' -Remediation $ctrl.Remediation
    }
}

# ── AAD-6.2 User Consent to Apps Restricted ───────────────────────────────────
function Test-NRGControlAADUserConsent {
    [CmdletBinding()] param()
    $cid = 'AAD-6.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    $consentPolicies = @((Get-SafeProp (Get-SafeProp $gov.Data 'ExternalCollab') 'PermissionGrantPolicies') ?? @())
    # ManagePermissionGrantsForSelf.microsoft-user-default-legacy = users can consent to anything
    # ManagePermissionGrantsForSelf.microsoft-user-default-low = users can consent to low-risk only
    $unrestrictedConsent = $consentPolicies | Where-Object { $_ -match 'legacy|ByDefault' }
    if (-not $unrestrictedConsent) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'User consent to applications is restricted.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Users can consent to any app permissions. Consent phishing attacks grant attacker apps access to mailbox, files, and contacts without admin awareness.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-6.3 Admin Consent Workflow Enabled ────────────────────────────────────
function Test-NRGControlAADAdminConsentWorkflow {
    [CmdletBinding()] param()
    $cid = 'AAD-6.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    $consentEnabled = [bool](Get-NRGNestedProperty -Object $gov -Path 'Data.ConsentPolicy.IsEnabled' -Default $false)
    if ($consentEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Admin consent workflow enabled — users can request app access via approval process.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Admin consent workflow disabled. Users who need app access have no path to request it — may bypass controls or use unmanaged alternatives.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-7.1 Password Protection Enabled ──────────────────────────────────────
function Test-NRGControlAADPasswordProtection {
    [CmdletBinding()] param()
    $cid = 'AAD-7.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success -or -not $auth.Data['PasswordProtection']) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Password protection data not collected (requires beta endpoint access)'; return
    }
    $pp = $auth.Data['PasswordProtection']
    $lockout = [int]($pp.LockoutThreshold ?? 10)
    if ($lockout -le 10) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Password lockout threshold: $lockout failed attempts."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "Lockout threshold is $lockout — consider reducing to ≤10 to limit brute force window." -CurrentValue "LockoutThreshold = $lockout" -RequiredValue '≤10 failed attempts'
    }
}

# ── AAD-7.2 Break-Glass Accounts Configured ───────────────────────────────────
function Test-NRGControlAADBreakGlass {
    [CmdletBinding()] param()
    $cid = 'AAD-7.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    $bgAccounts = @($gov.Data['BreakGlassIndicators'] | Where-Object { $_.CAExcluded -eq $true -and -not $_.Synced })
    $allGAs     = @($gov.Data['BreakGlassIndicators'])
    if ($bgAccounts.Count -ge 2) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($bgAccounts.Count) cloud-only GA account(s) excluded from CA policies — consistent with break-glass pattern."
    } elseif ($bgAccounts.Count -eq 1) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'Only one CA-excluded cloud-only GA found. Best practice is two break-glass accounts for redundancy.' -CurrentValue '1 break-glass account' -RequiredValue '2 break-glass accounts'
    } elseif ($allGAs.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No CA-excluded cloud-only GA accounts detected. If CA policies break, there is no emergency access path to the tenant.' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No GA accounts found to evaluate'
    }
}

# ── AAD-8.1 PIM Alerts Configured ────────────────────────────────────────────
function Test-NRGControlAADPIMAlerts {
    [CmdletBinding()] param()
    $cid = 'AAD-8.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pim = Get-NRGRawData -Key 'AAD-PIMSchedules'
    if (-not $pim -or -not $pim.PIMAvailable) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'PIM not available (requires Entra P2)'; return
    }
    # PIM alerts are tenant-configured — check for data presence as proxy
    # Full alert config requires GET /beta/privilegedAccess/aadRoles/alerts
    Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
        -Detail 'PIM is available. Verify alerts are configured in PIM > Alerts: Roles assigned outside PIM, Redundant roles, Stale assignments. Manual verification required.' `
        -Remediation $ctrl.Remediation
}

# ── AAD-8.2 Access Reviews for Privileged Roles ───────────────────────────────
function Test-NRGControlAADAccessReviews {
    [CmdletBinding()] param()
    $cid = 'AAD-8.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pim = Get-NRGRawData -Key 'AAD-PIMSchedules'
    if (-not $pim -or -not $pim.PIMAvailable) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'PIM not available — access reviews require Entra P2'; return
    }
    # Access review definitions need the AccessReview.Read.All scope, which is a
    # re-consent scope (like AAD-11.3 / DEF-4.6). Until the enterprise app is
    # re-consented the collector can't read them — report NotApplicable, never a
    # false "no reviews" gap.
    if (-not $pim.AccessReviewsCollected) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail 'Access review data not collected — requires the AccessReview.Read.All scope (re-consent the enterprise app in each tenant). Verify manually in PIM > Microsoft Entra roles > Access reviews.'
        return
    }
    $reviews = @($pim.Data['AccessReviews'] ?? @())
    $activeStatuses = @('InProgress', 'NotStarted', 'Applying', 'Applied')
    $roleReviews = @($reviews | Where-Object {
        (Get-NRGObjectField -Item $_ -Key 'TargetsRoles') -eq $true -and
        ([string](Get-NRGObjectField -Item $_ -Key 'Status')) -in $activeStatuses
    })
    if ($roleReviews.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($roleReviews.Count) active access review(s) recertify privileged directory-role assignments. Standing admin access is periodically re-attested instead of accumulating unchecked." `
            -CurrentValue "$($roleReviews.Count) role access review(s) active"
    } elseif ($reviews.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($reviews.Count) access review(s) exist but none target privileged directory roles. Groups/apps are reviewed, but Global Admin and other privileged role assignments are not recertified." `
            -CurrentValue 'Access reviews present, none for privileged roles' `
            -RequiredValue 'A recurring access review scoped to privileged directory roles' `
            -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No access reviews are configured. Privileged role assignments are never recertified, so stale or over-provisioned admin access accumulates unnoticed.' `
            -CurrentValue 'No access reviews configured' `
            -RequiredValue 'A recurring access review scoped to privileged directory roles' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-9.1 Authenticator Number Matching Enabled ────────────────────────────
function Test-NRGControlAADAuthenticatorNumberMatch {
    [CmdletBinding()] param()
    $cid = 'AAD-9.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    $ampConfigs = @(Get-NRGNestedProperty -Object $auth -Path 'Data.AuthMethodsPolicy.AuthenticationMethodConfigs' -Default @())
    $mfaConfig  = $ampConfigs | Where-Object { $_.Id -eq 'MicrosoftAuthenticator' } | Select-Object -First 1
    # Microsoft enforced number matching as the platform default in May 2023.
    # When the property is null/empty the API is reporting "MS is enforcing it
    # at the platform level" — NOT "we don't know". Treating absence as unknown
    # produced "Number matching state is ''" Gap findings on every modern
    # tenant (mirrors the AAD-2.3 fix in Test-NRGControlAADCA.ps1).
    $nmStateRaw = Get-NRGNestedProperty -Object $mfaConfig -Path 'FeatureSettings.NumberMatchingRequiredState'
    $nmState    = if ($null -eq $nmStateRaw -or [string]::IsNullOrWhiteSpace([string]$nmStateRaw)) {
                      'default'
                  } else {
                      [string]$nmStateRaw
                  }
    if ($nmState -eq 'enabled' -or $nmState -eq 'default') {
        $msg = if ($nmState -eq 'enabled') {
            'Microsoft Authenticator number matching is explicitly enabled — MFA fatigue attacks blocked.'
        } else {
            'Number matching: enabled (Microsoft platform default since May 2023). Explicit configuration is optional but ensures it cannot be disabled.'
        }
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail $msg `
            -CurrentValue "NumberMatchingRequiredState = $nmState" `
            -RequiredValue 'enabled (or default)'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "Number matching state is '$nmState'. MFA push fatigue attacks are possible — attacker can spam approve requests." `
            -CurrentValue "NumberMatchingRequiredState = $nmState" `
            -RequiredValue 'enabled' -Remediation $ctrl.Remediation
    }
}

# ── AAD-9.2 Passwordless Auth Methods Available ───────────────────────────────
function Test-NRGControlAADPasswordless {
    [CmdletBinding()] param()
    $cid = 'AAD-9.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    $ampConfigs = @(Get-NRGNestedProperty -Object $auth -Path 'Data.AuthMethodsPolicy.AuthenticationMethodConfigs' -Default @())
    $fido2      = $ampConfigs | Where-Object { (Get-SafeProp $_ 'Id') -eq 'Fido2' } | Select-Object -First 1
    $whi        = $ampConfigs | Where-Object { (Get-SafeProp $_ 'Id') -eq 'WindowsHello' } | Select-Object -First 1
    $fido2State = [string](Get-SafeProp $fido2 'State' 'notConfigured')
    $whiState   = [string](Get-SafeProp $whi   'State' 'notConfigured')
    $passwordlessEnabled = ($fido2State -eq 'enabled') -or ($whiState -eq 'enabled')
    if ($passwordlessEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Passwordless auth enabled: FIDO2=$fido2State, WindowsHello=$whiState"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail 'No passwordless authentication methods are enabled. Passwordless eliminates credential theft risk entirely for enrolled users.' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-10.1 Identity Protection Risky User Workflow ─────────────────────────
function Test-NRGControlAADIdentityProtection {
    [CmdletBinding()] param()
    $cid = 'AAD-10.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # Check for user risk policy as proxy for Identity Protection workflow
    $userRiskPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and @($_.Conditions.UserRiskLevels).Count -gt 0
    })
    if ($userRiskPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'User risk CA policy is active — Identity Protection risk signals are actioned automatically.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No automated response to user risk signals. Compromised accounts detected by Identity Protection are not automatically remediated. Requires Entra P2.' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-10.2 Privileged Accounts Dedicated Cloud-Only ────────────────────────
function Test-NRGControlAADPrivCloudOnly {
    [CmdletBinding()] param()
    $cid = 'AAD-10.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $roles = Get-NRGRawData -Key 'AAD-DirectoryRoles'
    if (-not $roles -or -not $roles.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Directory role data not collected'; return
    }
    $syncedPriv = @($roles.Data['PrivRoles'] | Where-Object {
        $_.OnPremisesSyncEnabled -eq $true -and $_.PrincipalType -notmatch 'servicePrincipal'
    })
    if (@($roles.Data['PrivRoles']).Count -eq 0 -and -not (Test-NRGRoleSectionCollected -Roles $roles -Section 'RoleAssignments')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail 'Role assignment enumeration did not complete (see Exceptions) — on-premises synced privileged accounts could not be assessed.'
        return
    }
    if ($syncedPriv.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'No privileged role assignments are using on-premises synced accounts.'
    } else {
        # v4.6.4 PII FIX: prior code interpolated the full PrincipalUPN list into
        # Detail (renders in HTML client report → PII leak). Move UPNs to the
        # structured AffectedObjects field; keep Detail count-only.
        $affected = @($syncedPriv | ForEach-Object {
            [ordered]@{
                DisplayName    = [string]$_.PrincipalUPN
                AssignmentType = 'OnPremSyncedPrivilegedRole'
            }
        })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($syncedPriv.Count) privileged account(s) are synced from on-premises AD. On-prem compromise directly escalates to cloud tenant. See AffectedObjects for the per-account list." `
            -CurrentValue "Synced privileged accounts: $($syncedPriv.Count)" `
            -RequiredValue 'Zero synced accounts in privileged roles' -Remediation $ctrl.Remediation `
            -AffectedObjects $affected
    }
}

# ── AAD-10.3 Emergency Access Account Monitoring ─────────────────────────────
function Test-NRGControlAADBreakGlassMonitoring {
    [CmdletBinding()] param()
    $cid = 'AAD-10.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    $bgAccounts = @($gov.Data['BreakGlassIndicators'] | Where-Object { $_.CAExcluded -eq $true })
    if ($bgAccounts.Count -ge 2) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($bgAccounts.Count) break-glass account(s) detected. Verify sign-in alerts are configured in Microsoft Sentinel or Defender XDR to notify when these accounts are used."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Break-glass accounts not confirmed or insufficient. Configure sign-in alerts so any break-glass usage triggers immediate notification.' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-10.4 User Sign-in Frequency Session Control ─────────────────────────
function Test-NRGControlAADSignInFrequency {
    [CmdletBinding()] param()
    $cid = 'AAD-10.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $freqPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        $_.SessionControls.SignInFrequency -and
        $_.SessionControls.SignInFrequency.IsEnabled -eq $true
    })
    if ($freqPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Sign-in frequency session control configured by $($freqPolicies.Count) CA policy(ies). Forces re-authentication periodically to limit stolen token lifetime."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail 'No sign-in frequency session control configured. Stolen tokens remain valid for the default session lifetime (up to 90 days).' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.1 Device Code Authentication Flow Blocked ─────────────────────────
function Test-NRGControlAADDeviceCode {
    [CmdletBinding()] param()
    $cid = 'AAD-11.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    # The signal IS collected: Invoke-NRGCollectAADCAPolicies stores each policy's
    # authentication-flow condition as Conditions.AuthFlows (the raw Graph
    # authenticationFlows object, which carries transferMethods). A CA policy that
    # blocks device code has transferMethods containing 'deviceCode'.
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Conditional Access policy data not collected'; return
    }
    $caBlocks = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        ((@($_.Conditions.AuthFlows) | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'transferMethods') }) -join ',') -match 'deviceCode'
    }).Count -gt 0
    if ($caBlocks) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Device code authentication flow is blocked by a Conditional Access policy. Adversary-in-the-middle phishing via device code is prevented.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Device code authentication flow is not blocked. Attackers use this flow in phishing campaigns where victims visit a URL and enter a code — no password required to compromise the account.' -CurrentValue 'No CA policy blocks deviceCodeFlow' -RequiredValue 'CA policy blocking deviceCodeFlow for all users' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.2 No Guest Users in Highly Privileged Roles ───────────────────────
function Test-NRGControlAADNoGuestInPrivRoles {
    [CmdletBinding()] param()
    $cid = 'AAD-11.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $roles = Get-NRGRawData -Key 'AAD-DirectoryRoles'
    if (-not $roles -or -not $roles.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Directory role data not collected'; return
    }
    $privRoleNames = @(
        'Global Administrator','Privileged Role Administrator','Security Administrator',
        'Exchange Administrator','SharePoint Administrator','Teams Administrator',
        'Application Administrator','Cloud Application Administrator','Conditional Access Administrator',
        'Intune Administrator','User Administrator','Authentication Policy Administrator'
    )
    # Collector stores RoleDefinitionName (not RoleName) and no UserType — guests
    # are identifiable by the #EXT# marker in PrincipalUPN. Reading the old
    # RoleName/UserType keys made $guestPriv always empty -> a guest holding
    # Global Administrator was silently reported Satisfied (Critical false-negative).
    $guestPriv = @($roles.Data['RoleAssignments'] | Where-Object {
        $_.RoleDefinitionName -in $privRoleNames -and $_.PrincipalUPN -like '*#EXT#*'
    })
    if (@($roles.Data['RoleAssignments']).Count -eq 0 -and -not (Test-NRGRoleSectionCollected -Roles $roles -Section 'RoleAssignments')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'Role assignment enumeration did not complete (see Exceptions) — guest privileged access could not be assessed.'
        return
    }
    if ($guestPriv.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'No guest accounts hold highly privileged directory roles.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($guestPriv.Count) guest account(s) hold privileged roles: $($guestPriv.PrincipalDisplayName -join ', '). Guest accounts are outside your identity governance — compromised guest accounts escalate to tenant admin." -CurrentValue "Guest admins: $($guestPriv.Count)" -RequiredValue 'Zero guest accounts in privileged roles' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.3 Risky Service Principals and Applications Reviewed ───────────────
function Test-NRGControlAADRiskyServicePrincipals {
    [CmdletBinding()] param()
    $cid = 'AAD-11.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # $null = endpoint not reachable (scope not consented, or no Workload Identities
    # Premium so detections never run) — honest NotApplicable, not a false pass.
    $risky = Get-NRGNestedProperty -Object $auth -Path 'Data.RiskyServicePrincipals' -Default $null
    if ($null -eq $risky) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Risky workload-identity data unavailable (requires IdentityRiskyServicePrincipal.Read.All consent and Workload Identities Premium); not assessed.'; return
    }
    $risky = @($risky)
    # atRisk / confirmedCompromised are the states that demand action; remediated,
    # dismissed, confirmedSafe and none are resolved or benign.
    $active = @($risky | Where-Object { (Get-NRGObjectField -Item $_ -Key 'RiskState') -in @('atRisk','confirmedCompromised') })
    if ($active.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "No service principals are currently flagged at-risk by Identity Protection ($($risky.Count) workload identities evaluated)."
    } else {
        $names = @($active | ForEach-Object { $n = [string](Get-NRGObjectField -Item $_ -Key 'DisplayName'); if ($n) { $n } else { [string](Get-NRGObjectField -Item $_ -Key 'AppId') } }) | Select-Object -First 10
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($active.Count) service principal(s) are flagged at-risk or confirmed compromised by Identity Protection. Compromised workload identities can hold OAuth grants that persist through user password resets and MFA. Investigate and remediate." `
            -CurrentValue "$($active.Count) risky SP(s): $($names -join ', ')" `
            -RequiredValue 'Zero at-risk / confirmed-compromised service principals' `
            -Remediation $ctrl.Remediation `
            -AffectedObjects $active
    }
}

# ── AAD-11.4 Token Protection (Binding) Conditional Access ───────────────────
function Test-NRGControlAADTokenProtection {
    [CmdletBinding()] param()
    $cid = 'AAD-11.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $tokenPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        $_.SessionControls.SignInFrequency -and
        $_.SessionControls.SignInFrequency.AuthenticationType -eq 'primaryAndSecondaryAuthentication' -or
        ($_.SessionControls.TokenProtection -and $_.SessionControls.TokenProtection.IsEnabled -eq $true)
    })
    if ($tokenPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Token protection (binding) CA policy active. Stolen tokens cannot be replayed from a different device.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'No token protection (binding) CA policy detected. AiTM phishing attacks steal session tokens and replay them from attacker infrastructure. Token binding ties tokens to the originating device.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.5 Continuous Access Evaluation Enabled ────────────────────────────
function Test-NRGControlAADContinuousAccess {
    [CmdletBinding()] param()
    $cid = 'AAD-11.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # CAE is enabled by default in most tenants; CA policy can enforce strict mode
    $caePolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        $_.SessionControls.ContinuousAccessEvaluation -and
        $_.SessionControls.ContinuousAccessEvaluation.Mode -eq 'strict'
    })
    if ($caePolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Continuous Access Evaluation strict mode enforced via CA policy. Session revocation propagates in near-real-time.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'CAE strict mode not enforced. CAE is active by default but strict mode ensures immediate session revocation when IP or risk changes — consider enforcing for sensitive workloads.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.6 Cross-Tenant Access Inbound Trust Settings ──────────────────────
function Test-NRGControlAADCrossTenantAccess {
    [CmdletBinding()] param()
    $cid = 'AAD-11.6'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    $xtap = Get-NRGNestedProperty -Object $auth -Path 'Data.CrossTenantAccess'
    if (-not $xtap) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'Cross-tenant access policy data not available. Verify in Entra ID > External Identities > Cross-tenant access settings that inbound defaults do not trust MFA or device compliance from unknown tenants.' -Remediation $ctrl.Remediation; return
    }
    $trustsMFA    = [bool](Get-NRGNestedProperty -Object $xtap -Path 'InboundTrust.IsMfaAccepted' -Default $false)
    $trustsDevice = [bool](Get-NRGNestedProperty -Object $xtap -Path 'InboundTrust.IsCompliantDeviceAccepted' -Default $false)
    if (-not $trustsMFA -and -not $trustsDevice) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Cross-tenant default inbound settings do not trust external MFA or device compliance claims.'
    } else {
        $trusted = @(); if ($trustsMFA) { $trusted += 'MFA' }; if ($trustsDevice) { $trusted += 'Device Compliance' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Default inbound cross-tenant trust accepts: $($trusted -join ', ') from all external tenants. An attacker in any tenant could satisfy your MFA/compliance requirements using their own tenant's weaker controls." -CurrentValue "Trusts: $($trusted -join ', ')" -RequiredValue 'No trust of external MFA or device compliance by default' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.7 Privileged Access Workstation Indicator ─────────────────────────
function Test-NRGControlAADPrivilegedWorkstation {
    [CmdletBinding()] param()
    $cid = 'AAD-11.7'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # PAW is indicated by CA policies that scope privileged role activation/use to specific named device groups
    $pawPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        ($_.DisplayName -match 'PAW|Privileged Workstation|Admin Workstation' -or
         ($_.Conditions.Devices -and $_.Conditions.Users.IncludeRoles -and @($_.Conditions.Users.IncludeRoles).Count -gt 0))
    })
    if ($pawPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Device-scoped CA policy for privileged roles detected: $($pawPolicies[0].DisplayName). Privileged access is restricted to specific managed devices."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'No device-scoped CA policy for privileged role access detected. Admins can authenticate from any device. A dedicated privileged access workstation or compliant device requirement for admin roles reduces attack surface.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.8 Terms of Use for External Access ─────────────────────────────────
function Test-NRGControlAADTermsOfUse {
    [CmdletBinding()] param()
    $cid = 'AAD-11.8'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $touPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and $_.GrantControls.TermsOfUse -and @($_.GrantControls.TermsOfUse).Count -gt 0
    })
    if ($touPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Terms of use enforced via $($touPolicies.Count) CA policy(ies). Users must acknowledge acceptable use before accessing resources."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'No Terms of Use CA policy detected. For organizations with guests or external contractors, ToU creates legal acknowledgment of acceptable use policies.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.9 Workload Identity CA Policy ─────────────────────────────────────
function Test-NRGControlAADWorkloadIdentityCA {
    [CmdletBinding()] param()
    $cid = 'AAD-11.9'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $wliPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        $_.Conditions.ClientApplications -and
        ($_.Conditions.ClientApplications.IncludeServicePrincipals -or
         $_.Conditions.ClientApplications.IncludeAllServicePrincipals)
    })
    if ($wliPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($wliPolicies.Count) CA policy(ies) apply to workload identities (service principals). Application access is subject to conditional access controls."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'No CA policies applied to workload identities. Service principals and managed identities are not subject to any conditional access controls. Requires Entra ID P2 Workload Identities add-on.' -Remediation $ctrl.Remediation
    }
}
#Requires -Version 7.0
#
# Apply-NRGAADMFA.ps1  (v4.6.3)
# Remediates AAD-2.1: MFA required for all users via Conditional Access policy.
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# CONSUMES : Finding object for ControlId 'AAD-2.1'
# REQUIRES : Microsoft.Graph (Identity.SignIns)
#            Connect-MgGraph must already be established by Apply-NRGBaseline.
# CMDLETS  : Get-MgIdentityConditionalAccessPolicy, New-MgIdentityConditionalAccessPolicy
# SAFETY   : ShouldProcess gate, idempotency re-read.
#
# IDEMPOTENCY:
#   Re-reads CA policies. If an enabled policy targets All users AND requires MFA
#   (BuiltInControls 'mfa' OR AuthStrengthId set), returns AlreadyCompliant.
#
# CREATED POLICY (when applied):
#   DisplayName  : NRG-Require-MFA-All-Users
#   State        : enabledForReportingButNotEnforced  (report-only by default —
#                  operator MUST promote to enabled after excluding break-glass
#                  accounts and validating impact)
#   IncludeUsers : All
#   ExcludeUsers : (none — operator's responsibility to add break-glass before enforcing)
#   BuiltInControls : mfa
#
# OPERATOR RESPONSIBILITY:
#   This intentionally does NOT enforce on apply. AAD-2.1 enforcement without a
#   break-glass exclusion is a known lockout vector. The created policy is
#   report-only; operator reviews sign-in logs, adds break-glass exclusions, then
#   manually flips state to 'enabled'.
#

function Apply-NRGAADMFA {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [object] $Finding
    )

    $controlId = 'AAD-2.1'
    $result = [ordered]@{
        ControlId = $controlId
        Action    = 'Create CA policy: NRG-Require-MFA-All-Users (report-only)'
        Status    = 'Pending'
        Before    = $null
        After     = $null
        Error     = $null
        Timestamp = (Get-Date).ToString('o')
    }

    try {
        $existing = @()
        try {
            $existing = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        } catch {
            $result.Status = 'Failed'
            $result.Error  = "Failed to read CA policies: $($_.Exception.Message)"
            return [PSCustomObject]$result
        }

        # ── M-Idempotency: also match NRG-created policies by displayName, not
        # just by shape. If our previous report-only policy was renamed AND its
        # state is something other than enabled, the shape-only match below
        # wouldn't recognize it and we'd create a duplicate. Treat any
        # NRG-* policy that targets All users with MFA as compliant for
        # apply purposes (regardless of state). The operator can still
        # promote / tune it via portal.
        #
        # v4.6.4 FIX: every nested chained-access ($_.Conditions.Users.IncludeUsers,
        # $_.GrantControls.AuthenticationStrength.Id, ...) blows up under
        # Set-StrictMode -Version Latest the first time any CA policy in the
        # tenant has a $null intermediate object — the entire Where-Object
        # short-circuits to empty → idempotency check returns 0 → DUPLICATE
        # CA POLICY gets created on every apply. Replace with Get-NRGNestedProperty.
        $nrgOwned = @($existing | Where-Object {
            $includeUsers = Get-NRGNestedProperty -Object $_ -Path 'Conditions.Users.IncludeUsers' -Default @()
            $builtInCtrls = Get-NRGNestedProperty -Object $_ -Path 'GrantControls.BuiltInControls' -Default @()
            $authStrengId = Get-NRGNestedProperty -Object $_ -Path 'GrantControls.AuthenticationStrength.Id' -Default ''
            $authStrIdAlt = Get-NRGNestedProperty -Object $_ -Path 'GrantControls.AuthStrengthId' -Default ''
            $_.DisplayName -like 'NRG-*' -and
            (@($includeUsers) -contains 'All') -and
            (
                (@($builtInCtrls) -contains 'mfa') -or
                (-not [string]::IsNullOrEmpty($authStrengId)) -or
                (-not [string]::IsNullOrEmpty($authStrIdAlt))
            )
        })

        # Look for enabled policy: All users + MFA (built-in or auth strength)
        $compliant = @($existing | Where-Object {
            $includeUsers = Get-NRGNestedProperty -Object $_ -Path 'Conditions.Users.IncludeUsers' -Default @()
            $builtInCtrls = Get-NRGNestedProperty -Object $_ -Path 'GrantControls.BuiltInControls' -Default @()
            $authStrengId = Get-NRGNestedProperty -Object $_ -Path 'GrantControls.AuthenticationStrength.Id' -Default ''
            $authStrIdAlt = Get-NRGNestedProperty -Object $_ -Path 'GrantControls.AuthStrengthId' -Default ''
            $_.State -eq 'enabled' -and
            (@($includeUsers) -contains 'All') -and
            (
                (@($builtInCtrls) -contains 'mfa') -or
                (-not [string]::IsNullOrEmpty($authStrengId)) -or
                (-not [string]::IsNullOrEmpty($authStrIdAlt))
            )
        })

        $result.Before = [PSCustomObject]@{
            MfaPolicyCount     = $compliant.Count
            MfaPolicies        = @($compliant | Select-Object Id, DisplayName, State)
            NRGOwnedPolicyCount = $nrgOwned.Count
            NRGOwnedPolicies   = @($nrgOwned  | Select-Object Id, DisplayName, State)
        }

        if ($compliant.Count -gt 0) {
            $result.Status = 'AlreadyCompliant'
            $result.After  = $result.Before
            return [PSCustomObject]$result
        }

        # An NRG-* MFA-shape policy already exists (likely report-only awaiting
        # operator promotion). Do NOT create a duplicate.
        if ($nrgOwned.Count -gt 0) {
            $result.Status = 'AlreadyCompliant'
            $result.Action = "Existing NRG-* MFA policy found ($($nrgOwned[0].DisplayName), state $($nrgOwned[0].State)) — no duplicate created."
            $result.After  = $result.Before
            return [PSCustomObject]$result
        }

        # ── H7: locate break-glass / emergency-access accounts and inject them
        # as exclusions so the policy is safe even if a future operator promotes
        # it from report-only to enabled via portal.
        $bg = $null
        if (Get-Command Get-NRGBreakGlassExclusions -ErrorAction SilentlyContinue) {
            try { $bg = Get-NRGBreakGlassExclusions } catch {
                Write-Verbose "Get-NRGBreakGlassExclusions threw: $($_.Exception.Message)"
            }
        }
        # Two statements. An if-block yielding an empty array assigns $null,
        # and the .Count interpolated into $action below then threw a
        # StrictMode property error — on a tenant with NO break-glass
        # accounts, which is precisely the tenant this code exists to warn
        # about. The warning printed and the policy was never created.
        $excludeUsers  = @()
        $excludeGroups = @()
        if ($bg -and $bg.ExcludeUsers)  { $excludeUsers  = @($bg.ExcludeUsers)  }
        if ($bg -and $bg.ExcludeGroups) { $excludeGroups = @($bg.ExcludeGroups) }

        $bgWarning = $null
        if (-not $bg -or -not $bg.Found) {
            $bgWarning = "WARNING: No break-glass account exclusions detected on this tenant. The CA policy will be created in report-only mode (safe), but if a future operator promotes it to enabled, ALL USERS WILL BE BLOCKED. Create a 'Break Glass' group or named admin before promoting this policy to enabled."
            Write-Warning $bgWarning
        }

        $target = "Tenant Conditional Access policies"
        $action = "Create CA policy 'NRG-Require-MFA-All-Users' (state: enabledForReportingButNotEnforced; excludeUsers=$($excludeUsers.Count), excludeGroups=$($excludeGroups.Count))"
        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            $result.Status = 'Skipped'
            return [PSCustomObject]$result
        }

        $policyBody = @{
            displayName = 'NRG-Require-MFA-All-Users'
            state       = 'enabledForReportingButNotEnforced'
            conditions  = @{
                clientAppTypes = @('all')
                users          = @{
                    includeUsers  = @('All')
                    excludeUsers  = $excludeUsers
                    excludeGroups = $excludeGroups
                }
                applications   = @{
                    includeApplications = @('All')
                }
            }
            grantControls = @{
                operator        = 'OR'
                builtInControls = @('mfa')
            }
        }

        $created = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyBody -ErrorAction Stop

        $after = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop |
                   Where-Object { $_.Id -eq $created.Id })

        $result.After = [PSCustomObject]@{
            CreatedPolicyId  = $created.Id
            DisplayName      = $created.DisplayName
            State            = $created.State
            ExcludedUsers    = if ($bg -and $bg.UserUPNs)   { @($bg.UserUPNs)   } else { @() }
            ExcludedGroups   = if ($bg -and $bg.GroupNames) { @($bg.GroupNames) } else { @() }
            Note             = 'Report-only mode. Confirm break-glass exclusions cover ALL emergency accounts before promoting to enabled.'
            VerificationRead = @($after | Select-Object Id, DisplayName, State)
        }
        # Surface the break-glass warning on the Applied result so the
        # rollback log captures it as a Notes field (Apply-NRGBaseline copies
        # $r.Notes into the rollback entry). $result is an [ordered] hashtable
        # cast to PSCustomObject on return — add Notes as a hashtable key.
        if ($bgWarning) {
            $result['Notes'] = $bgWarning
        }
        $result.Status = 'Applied'
    } catch {
        $result.Status = 'Failed'
        $result.Error  = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

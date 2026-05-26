#Requires -Version 7.0
#
# Apply-NRGAADLegacyAuth.ps1  (v4.6.3)
# Remediates AAD-1.1: Block legacy authentication via Conditional Access policy.
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# CONSUMES : Finding object for ControlId 'AAD-1.1'
# REQUIRES : Microsoft.Graph (Identity.SignIns)
#            Connect-MgGraph must already be established by Apply-NRGBaseline.
# CMDLETS  : Get-MgIdentityConditionalAccessPolicy, New-MgIdentityConditionalAccessPolicy
# SAFETY   : ShouldProcess gate, idempotency re-read, returns rollback-capable
#            Before/After state objects.
#
# IDEMPOTENCY:
#   Re-reads CA policies. If ANY enabled policy already blocks legacy auth
#   (ClientAppTypes 'other' or 'exchangeActiveSync' with BuiltInControls 'block'),
#   returns Status=AlreadyCompliant — no write, no prompt.
#
# CREATED POLICY (when applied):
#   DisplayName       : NRG-Block-Legacy-Authentication
#   State             : enabledForReportingButNotEnforced
#       Deployed in report-only mode so the operator can validate impact in
#       sign-in logs BEFORE switching to enabled. Manual final step.
#   ClientAppTypes    : other, exchangeActiveSync
#   IncludeUsers      : All
#   BuiltInControls   : block
#

function Apply-NRGAADLegacyAuth {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [object] $Finding
    )

    $controlId = 'AAD-1.1'
    $result = [ordered]@{
        ControlId = $controlId
        Action    = 'Create CA policy: NRG-Block-Legacy-Authentication (report-only)'
        Status    = 'Pending'
        Before    = $null
        After     = $null
        Error     = $null
        Timestamp = (Get-Date).ToString('o')
    }

    try {
        # ── 1. Idempotency: re-read current CA policy state ───────────────────
        $existing = @()
        try {
            $existing = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        } catch {
            $result.Status = 'Failed'
            $result.Error  = "Failed to read CA policies: $($_.Exception.Message)"
            return [PSCustomObject]$result
        }

        $blocking = @($existing | Where-Object {
            $_.State -eq 'enabled' -and
            (
                ($_.Conditions.ClientAppTypes -contains 'other') -or
                ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync')
            ) -and
            ($_.GrantControls.BuiltInControls -contains 'block')
        })

        # M-Idempotency: also match NRG-* policies regardless of state, so a
        # renamed-or-report-only NRG policy doesn't cause us to create a
        # duplicate on the next apply.
        $nrgOwned = @($existing | Where-Object {
            $_.DisplayName -like 'NRG-*' -and
            (
                ($_.Conditions.ClientAppTypes -contains 'other') -or
                ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync')
            ) -and
            ($_.GrantControls.BuiltInControls -contains 'block')
        })

        $result.Before = [PSCustomObject]@{
            BlockingPolicyCount  = $blocking.Count
            BlockingPolicies     = @($blocking | Select-Object Id, DisplayName, State)
            NRGOwnedPolicyCount  = $nrgOwned.Count
            NRGOwnedPolicies     = @($nrgOwned | Select-Object Id, DisplayName, State)
        }

        if ($blocking.Count -gt 0) {
            $result.Status = 'AlreadyCompliant'
            $result.After  = $result.Before
            return [PSCustomObject]$result
        }

        if ($nrgOwned.Count -gt 0) {
            $result.Status = 'AlreadyCompliant'
            $result.Action = "Existing NRG-* legacy-auth block policy found ($($nrgOwned[0].DisplayName), state $($nrgOwned[0].State)) — no duplicate created."
            $result.After  = $result.Before
            return [PSCustomObject]$result
        }

        # ── H7: locate break-glass / emergency-access accounts and inject them
        # as exclusions so the policy is safe even if a future operator
        # promotes it from report-only to enabled via portal.
        $bg = $null
        if (Get-Command Get-NRGBreakGlassExclusions -ErrorAction SilentlyContinue) {
            try { $bg = Get-NRGBreakGlassExclusions } catch {
                Write-Verbose "Get-NRGBreakGlassExclusions threw: $($_.Exception.Message)"
            }
        }
        $excludeUsers  = if ($bg -and $bg.ExcludeUsers)  { @($bg.ExcludeUsers)  } else { @() }
        $excludeGroups = if ($bg -and $bg.ExcludeGroups) { @($bg.ExcludeGroups) } else { @() }

        $bgWarning = $null
        if (-not $bg -or -not $bg.Found) {
            $bgWarning = "WARNING: No break-glass account exclusions detected on this tenant. The CA policy will be created in report-only mode (safe), but if a future operator promotes it to enabled, ALL USERS WILL BE BLOCKED. Create a 'Break Glass' group or named admin before promoting this policy to enabled."
            Write-Warning $bgWarning
        }

        # ── 2. Gate the write through ShouldProcess ───────────────────────────
        $target = "Tenant Conditional Access policies"
        $action = "Create CA policy 'NRG-Block-Legacy-Authentication' (state: enabledForReportingButNotEnforced; excludeUsers=$($excludeUsers.Count), excludeGroups=$($excludeGroups.Count))"
        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            $result.Status = 'Skipped'
            return [PSCustomObject]$result
        }

        # ── 3. Apply ──────────────────────────────────────────────────────────
        $policyBody = @{
            displayName = 'NRG-Block-Legacy-Authentication'
            # Report-only first — operator promotes to enabled after validation
            state       = 'enabledForReportingButNotEnforced'
            conditions  = @{
                clientAppTypes = @('other','exchangeActiveSync')
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
                builtInControls = @('block')
            }
        }

        $created = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyBody -ErrorAction Stop

        # ── 4. Re-read for After state ────────────────────────────────────────
        $after = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop |
                   Where-Object { $_.Id -eq $created.Id })

        $result.After = [PSCustomObject]@{
            CreatedPolicyId   = $created.Id
            DisplayName       = $created.DisplayName
            State             = $created.State
            ExcludedUsers     = if ($bg -and $bg.UserUPNs)   { @($bg.UserUPNs)   } else { @() }
            ExcludedGroups    = if ($bg -and $bg.GroupNames) { @($bg.GroupNames) } else { @() }
            Note              = 'Deployed in report-only mode. Confirm break-glass exclusions cover ALL emergency accounts before promoting to enabled.'
            VerificationRead  = @($after | Select-Object Id, DisplayName, State)
        }
        if ($bgWarning) {
            # $result is an [ordered] hashtable cast to PSCustomObject on
            # return — add the Notes as a hashtable key so the cast carries it.
            $result['Notes'] = $bgWarning
        }
        $result.Status = 'Applied'
    } catch {
        $result.Status = 'Failed'
        $result.Error  = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

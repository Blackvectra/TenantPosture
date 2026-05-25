#Requires -Version 7.0
#
# Apply-NRGAADMFA.ps1  (v4.6.1)
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

        # Look for enabled policy: All users + MFA (built-in or auth strength)
        $compliant = @($existing | Where-Object {
            $_.State -eq 'enabled' -and
            (@($_.Conditions.Users.IncludeUsers) -contains 'All') -and
            (
                ($_.GrantControls.BuiltInControls -contains 'mfa') -or
                (-not [string]::IsNullOrEmpty($_.GrantControls.AuthenticationStrength.Id)) -or
                (-not [string]::IsNullOrEmpty($_.GrantControls.AuthStrengthId))
            )
        })

        $result.Before = [PSCustomObject]@{
            MfaPolicyCount = $compliant.Count
            MfaPolicies    = @($compliant | Select-Object Id, DisplayName, State)
        }

        if ($compliant.Count -gt 0) {
            $result.Status = 'AlreadyCompliant'
            $result.After  = $result.Before
            return [PSCustomObject]$result
        }

        $target = "Tenant Conditional Access policies"
        $action = "Create CA policy 'NRG-Require-MFA-All-Users' (state: enabledForReportingButNotEnforced — operator must add break-glass exclusions and promote manually)"
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
                    includeUsers = @('All')
                    excludeUsers = @()
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
            Note             = 'Report-only mode. Add break-glass account exclusions before promoting to enabled.'
            VerificationRead = @($after | Select-Object Id, DisplayName, State)
        }
        $result.Status = 'Applied'
    } catch {
        $result.Status = 'Failed'
        $result.Error  = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

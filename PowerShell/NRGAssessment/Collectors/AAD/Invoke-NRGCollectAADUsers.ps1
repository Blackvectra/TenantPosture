#
# Invoke-NRGCollectAADUsers.ps1
# Collects all Entra ID users, bulk MFA registration state,
# Security Defaults enforcement state, and auth method policy.
# COLLECTION ONLY - no scoring.
#
# NIST SP 800-53: IA-2, AC-2
# MITRE ATT&CK:   T1078 (Valid Accounts)
#
# Required Graph scopes:
#   User.Read.All
#   AuditLog.Read.All                  (SignInActivity on user objects)
#   UserAuthenticationMethod.Read.All  (MFA registration report)
#   Policy.Read.All                    (Security Defaults, auth method policy)
#

function Invoke-NRGCollectAADUsers {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'AAD-Users'
        Timestamp  = [DateTime]::UtcNow.ToString('o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    try {
        # IA-2, AC-2 — All users with sign-in activity
        # SignInActivity requires AuditLog.Read.All
        $selectProps = 'Id,UserPrincipalName,DisplayName,AccountEnabled,UserType,' +
                       'AssignedLicenses,CreatedDateTime,OnPremisesSyncEnabled,SignInActivity'

        $users = @(Get-MgUser -All -Property $selectProps -ErrorAction Stop)

        $result.Data['Users'] = $users | Select-Object -Property @(
            'Id', 'UserPrincipalName', 'DisplayName', 'AccountEnabled',
            'UserType', 'OnPremisesSyncEnabled', 'AssignedLicenses', 'CreatedDateTime',
            @{ N = 'LastInteractiveSignIn';    E = { $_.SignInActivity.LastSignInDateTime } },
            @{ N = 'LastNonInteractiveSignIn'; E = { $_.SignInActivity.LastNonInteractiveSignInDateTime } }
        )

        # IA-2(1) — Bulk MFA registration report
        # More efficient than per-user Get-MgUserAuthenticationMethod (avoids N+1 calls)
        $result.Data['MFARegistration'] = @(
            Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop |
            Select-Object -Property @(
                'Id', 'UserPrincipalName', 'IsAdmin', 'IsMfaCapable', 'IsMfaRegistered',
                'IsPasswordlessCapable', 'IsSsprCapable', 'IsSsprEnabled', 'IsSsprRegistered',
                'DefaultMfaMethod', 'MethodsRegistered'
            )
        )

        # IA-2(2) — Security Defaults state
        $secDef = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        $result.Data['SecurityDefaultsEnabled'] = $secDef.IsEnabled

        # IA-2(8) — Auth method policy: number matching, additional context config
        $authMethodPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
        $result.Data['AuthMethodPolicy'] = $authMethodPolicy

        $result.Data['UserCount']            = $users.Count
        $result.Data['EnabledMemberCount']   = @($users | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -eq 'Member' }).Count
        $result.Data['GuestCount']           = @($users | Where-Object { $_.UserType -eq 'Guest' }).Count
        $result.Data['MFARegisteredCount']   = @($result.Data['MFARegistration'] | Where-Object { $_.IsMfaRegistered -eq $true }).Count

        $result.Success = $true
        Register-NRGCoverage -Family 'AAD-Users' -Status 'Collected'
    }
    catch {
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'AAD-Users' -Message $_.Exception.Message
        Register-NRGCoverage -Family 'AAD-Users' -Status 'Failed' -Note $_.Exception.Message
    }

    Set-NRGRawData -Key 'AAD-Users' -Data $result
    return $result
}

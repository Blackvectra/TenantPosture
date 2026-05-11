<#
.SYNOPSIS
    Collects Entra ID user accounts and MFA registration state.
.DESCRIPTION
    Pulls all enabled users with sign-in activity, bulk MFA registration report,
    Security Defaults state, and authentication method policy configuration.
    Used by Test-NRGControl-AAD.ps1 (MFA controls) and Test-NRGControl-AAD-CA.ps1.
.NOTES
    NIST SP 800-53: IA-2, AC-2
    MITRE ATT&CK:   T1078 (Valid Accounts)
    Required Graph scopes:
        User.Read.All
        AuditLog.Read.All          (SignInActivity on user objects)
        UserAuthenticationMethod.Read.All  (MFA registration report)
        Policy.Read.All            (Security Defaults, auth method policy)
    Version: 2.0.0 (Session 2 — Identity Layer)
#>
function Get-NRGCollector-AAD-Users {
    [CmdletBinding()]
    param(
        [string]$LogPath = 'C:\ProgramData\NRG\Logs\NRGAssessment.log'
    )

    Write-NRGLog -Message '[AAD-Users] Collector starting' -Path $LogPath

    $result = [PSCustomObject]@{
        CollectorId      = 'AAD-Users'
        CollectedAt      = (Get-Date -Format 'o')
        Users            = @()
        MFARegistration  = @()
        SecurityDefaults = $null
        AuthMethodPolicy = $null
        Success          = $false
        Error            = $null
    }

    try {
        # IA-2, AC-2 — Enumerate all users with sign-in activity
        # SignInActivity requires AuditLog.Read.All; omit if permission denied
        $selectProps = 'Id,UserPrincipalName,DisplayName,AccountEnabled,UserType,' +
                       'AssignedLicenses,CreatedDateTime,OnPremisesSyncEnabled,SignInActivity'

        $users = Get-MgUser -All -Property $selectProps -ErrorAction Stop

        $result.Users = $users | Select-Object -Property @(
            'Id', 'UserPrincipalName', 'DisplayName', 'AccountEnabled',
            'UserType', 'OnPremisesSyncEnabled', 'AssignedLicenses', 'CreatedDateTime',
            @{ N = 'LastInteractiveSignIn';    E = { $_.SignInActivity.LastSignInDateTime } },
            @{ N = 'LastNonInteractiveSignIn'; E = { $_.SignInActivity.LastNonInteractiveSignInDateTime } }
        )

        # IA-2(1) — Bulk MFA registration report
        # More efficient than per-user Get-MgUserAuthenticationMethod (avoids N+1 calls)
        $result.MFARegistration = Get-MgReportAuthenticationMethodUserRegistrationDetail `
            -All -ErrorAction Stop |
            Select-Object -Property @(
                'Id', 'UserPrincipalName', 'IsAdmin', 'IsMfaCapable', 'IsMfaRegistered',
                'IsPasswordlessCapable', 'IsSsprCapable', 'IsSsprEnabled', 'IsSsprRegistered',
                'DefaultMfaMethod', 'MethodsRegistered'
            )

        # IA-2(2) — Security Defaults state (mutually exclusive with Conditional Access)
        $secDef = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        $result.SecurityDefaults = [PSCustomObject]@{ IsEnabled = $secDef.IsEnabled }

        # IA-2(8) — Auth method policy: number matching, additional context
        $result.AuthMethodPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop

        $result.Success = $true
        Write-NRGLog -Message "[AAD-Users] Complete. Users: $($result.Users.Count), MFA records: $($result.MFARegistration.Count)" -Path $LogPath
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-NRGLog -Message "[AAD-Users] Error: $($_.Exception.Message)" -Path $LogPath -Level 'ERROR'
    }

    return $result
}

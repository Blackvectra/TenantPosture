#Requires -Version 7.0
#
# Invoke-NRGCollectAADUsers.ps1  (v4.5.5)
# Collects users and their MFA registration state.
# READ-ONLY. Uses paged Graph requests.
#
# Required Graph scopes: User.Read.All, UserAuthenticationMethod.Read.All,
#                        Reports.Read.All
#
# NIST SP 800-53: IA-2 (MFA), AC-2 (account management)
# MITRE ATT&CK:   T1078 (Valid Accounts)
#

function Invoke-NRGCollectAADUsers {
    [CmdletBinding()] param()

    $result = @{
        Success = $false
        Data    = @{
            Users             = @()
            TotalCount        = 0
            SectionStatus     = @{
                MFARegistration = 'NotRun'
            }
            MFARegistration   = @{
                TotalUsersWithMFA    = 0
                TotalUsersWithoutMFA = 0
                RegistrationDetails  = @()
            }
        }
    }

    try {
        # Collect users — paged, select only needed fields
        $allUsers  = [System.Collections.Generic.List[object]]::new()
        $nextLink  = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,assignedLicenses,lastPasswordChangeDateTime,createdDateTime&$top=500&$filter=userType eq ''Member'''

        $pageCount = 0
        # v4.6.4 EMERGENCY FIX (High #4): raised from 20 → 200 to match the
        # other AAD collectors (AAD-Roles, AAD-IdentityGovernance). The old
        # cap of 10,000 users silently truncated mid-size enterprise tenants
        # and produced inconsistent counts vs. other AAD passes. At $top=500
        # × 200 pages = 100k user ceiling, which still bounds memory but
        # covers any realistic single tenant.
        $maxPages  = 200

        while ($nextLink -and $pageCount -lt $maxPages) {
            $pageResp = Invoke-NRGGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($u in @($pageResp.value ?? @())) {
                $allUsers.Add(@{
                    Id                       = [string]$u.id
                    DisplayName              = [string]$u.displayName
                    UserPrincipalName        = [string]$u.userPrincipalName
                    AccountEnabled           = [bool]($u.accountEnabled ?? $false)
                    UserType                 = [string]($u.userType ?? 'Member')
                    OnPremisesSyncEnabled    = $u.onPremisesSyncEnabled  # $null = cloud-only
                    LicenseCount             = @($u.assignedLicenses ?? @()).Count
                    CreatedDateTime          = [string]($u.createdDateTime ?? '')
                    LastPasswordChange       = [string]($u.lastPasswordChangeDateTime ?? '')
                })
            }
            $nextLink = $pageResp['@odata.nextLink']
            $pageCount++
        }
        if ($pageCount -ge $maxPages -and $nextLink) {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-Users' `
                    -Message "Pagination cap reached ($maxPages pages); user list may be truncated."
            }
        }

        $result.Data.Users      = $allUsers.ToArray()
        $result.Data.TotalCount = $allUsers.Count

        # MFA Registration via reports/authenticationMethods/userRegistrationDetails
        # (Reports.Read.All required).
        # v4.12.2 FIX (High): this used to hit
        # /v1.0/reports/credentialUserRegistrationDetails, which only ever
        # existed under /beta and was deprecated (stopped returning data on
        # June 30, 2024) — the v1.0 route is not valid, so the request 404'd
        # on every run, landed in the catch below, and RegistrationDetails
        # stayed empty on every tenant. AAD-12.1 then reported NotApplicable
        # with a misleading "requires Reports.Read.All" detail even when the
        # scope was fully consented.
        try {
            $regDetails = [System.Collections.Generic.List[object]]::new()
            $regLink = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=500'
            $regPage = 0

            while ($regLink -and $regPage -lt $maxPages) {
                $regResp = Invoke-NRGGraphRequest -Method GET -Uri $regLink -ErrorAction Stop
                foreach ($r in @($regResp.value ?? @())) {
                    # userRegistrationDetails carries no top-level "isEnabled" —
                    # that was the legacy per-user MFA enable/enforce/disable
                    # state, retired along with the old API. Every row this
                    # endpoint returns is a user in scope for registration
                    # reporting, so IsEnabled is fixed $true to preserve the
                    # shape existing evaluators (Test-NRGControlInventoryMFAUsers)
                    # already read. Fields read via Get-NRGObjectField since this
                    # is unverified live shape and optional keys may be omitted.
                    $methodsRegistered = @(Get-NRGObjectField -Item $r -Key 'methodsRegistered' -Default @())
                    $regDetails.Add(@{
                        Id                    = [string](Get-NRGObjectField -Item $r -Key 'id' -Default '')
                        UserPrincipalName     = [string](Get-NRGObjectField -Item $r -Key 'userPrincipalName' -Default '')
                        UserDisplayName       = [string](Get-NRGObjectField -Item $r -Key 'userDisplayName' -Default '')
                        IsAdmin               = [bool](Get-NRGObjectField -Item $r -Key 'isAdmin' -Default $false)
                        IsRegistered          = ($methodsRegistered.Count -gt 0)
                        IsEnabled             = $true
                        IsMfaRegistered       = [bool](Get-NRGObjectField -Item $r -Key 'isMfaRegistered' -Default $false)
                        IsMfaCapable          = [bool](Get-NRGObjectField -Item $r -Key 'isMfaCapable' -Default $false)
                        AuthMethodsRegistered = $methodsRegistered
                        IsPasswordlessCapable = [bool](Get-NRGObjectField -Item $r -Key 'isPasswordlessCapable' -Default $false)
                    })
                }
                $regLink = $regResp['@odata.nextLink']
                $regPage++
            }
            if ($regPage -ge $maxPages -and $regLink) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'AAD-MFARegistration' `
                        -Message "Pagination cap reached ($maxPages pages); MFA registration list may be truncated."
                }
            }

            $mfaRegistered   = @($regDetails | Where-Object { $_.IsMfaRegistered }).Count
            $mfaUnregistered = @($regDetails | Where-Object { -not $_.IsMfaRegistered }).Count

            $result.Data.MFARegistration = @{
                TotalUsersWithMFA    = $mfaRegistered
                TotalUsersWithoutMFA = $mfaUnregistered
                RegistrationDetails  = $regDetails.ToArray()
            }
            $result.Data.SectionStatus.MFARegistration = 'Collected'
        } catch {
            # Reports.Read.All may not be consented — non-fatal, record exception
            $result.Data.SectionStatus.MFARegistration = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-MFARegistration' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-Users' -Status 'Collected' `
                -Note "$($allUsers.Count) users collected"
        }

    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'AAD-Users' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'AAD-Users' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'AAD-Users' -Data $result
    }
    return $result
}
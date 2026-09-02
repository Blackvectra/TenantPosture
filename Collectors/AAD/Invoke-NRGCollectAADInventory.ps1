#Requires -Version 7.0
#
# Invoke-NRGCollectAADInventory.ps1  (v4.5.5)
# Collects per-object inventory data for named findings:
#   - Guest users with last sign-in date
#   - Stale member accounts (no sign-in 90+ days)
#   - Service principals with AllPrincipals OAuth grants
#
# LegacyAuthOnlyUsers and RecentRiskEvents are declared in the Data block but
# are not populated by any code path. They are reserved for a future collector
# and must not be read as evidence of anything.
#
# Requires: AuditLog.Read.All, User.Read.All, Application.Read.All
#

function Invoke-NRGCollectAADInventory {
    [CmdletBinding()] param()

    $result = @{
        Success = $false
        Data = @{
            # Per-section collection outcome. Each block below has its own
            # try/catch and Success is set unconditionally at the end, so an
            # empty list here is ambiguous — "enumerated, found none" or "the
            # query failed". Evaluators that would otherwise read empty as
            # compliance must consult this first.
            SectionStatus       = @{
                GuestUsers       = 'NotRun'
                StaleMembers     = 'NotRun'
                OAuthGrantedApps = 'NotRun'
                AppCredentials   = 'NotRun'
            }
            GuestUsers          = @()
            StaleMembers        = @()
            OAuthGrantedApps    = @()
            AppCredentials      = @()
            LegacyAuthOnlyUsers = @()
            RecentRiskEvents    = @()
            SecureScore         = $null
            LastSignInSummary   = @{}
            SubscribedSkus      = @()
        }
    }

    try {
        # Subscribed SKUs — license detection for report suppression
        try {
            $skuResp = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,skuId,servicePlans,capabilityStatus' `
                -ErrorAction Stop
            $result.Data.SubscribedSkus = @($skuResp.value | Where-Object { $_.capabilityStatus -in @('Enabled','Warning') } | ForEach-Object {
                @{
                    SkuPartNumber = [string]$_.skuPartNumber
                    SkuId         = [string]$_.skuId
                    ServicePlans  = @($_.servicePlans | Where-Object { $_.provisioningStatus -eq 'Success' } | Select-Object -ExpandProperty servicePlanName)
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-SubscribedSkus' -Message $_.Exception.Message
            }
            # Log permission hint
            Write-Verbose "AAD-SubscribedSkus failed — needs Organization.Read.All or Directory.Read.All"
        }

        # Guest users + last sign-in
        try {
            $guests = Invoke-NRGGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity&`$filter=userType eq 'Guest'&`$top=500" `
                -ErrorAction Stop
            $result.Data.GuestUsers = @($guests.value ?? @() | ForEach-Object {
                $lastSign = [string]($_.signInActivity.lastSignInDateTime ?? '')
                $daysSince = if ($lastSign) { [int]((Get-Date) - [datetime]$lastSign).TotalDays } else { 9999 }
                @{
                    DisplayName       = [string]$_.displayName
                    UPN               = [string]$_.userPrincipalName
                    AccountEnabled    = [bool]($_.accountEnabled ?? $false)
                    CreatedDateTime   = [string]($_.createdDateTime ?? '')
                    LastSignIn        = $lastSign
                    DaysSinceSignIn   = $daysSince
                    IsStale           = $daysSince -gt 90
                }
            })
            $result.Data.SectionStatus.GuestUsers = 'Collected'
        } catch {
            $result.Data.SectionStatus.GuestUsers = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-GuestInventory' -Message $_.Exception.Message
            }
        }

        # Stale member accounts (signInActivity requires AuditLog.Read.All)
        try {
            $staleResp = Invoke-NRGGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,accountEnabled,signInActivity,assignedLicenses&`$filter=userType eq 'Member' and accountEnabled eq true&`$top=500" `
                -ErrorAction Stop
            $stale = @($staleResp.value ?? @() | Where-Object {
                $lastSign = $_.signInActivity.lastSignInDateTime
                if (-not $lastSign) { return $true }  # never signed in
                ((Get-Date) - [datetime]$lastSign).TotalDays -gt 90
            } | ForEach-Object {
                $lastSign = [string]($_.signInActivity.lastSignInDateTime ?? 'Never')
                $days = if ($lastSign -ne 'Never') { [int]((Get-Date) - [datetime]$lastSign).TotalDays } else { 9999 }
                @{
                    DisplayName     = [string]$_.displayName
                    UPN             = [string]$_.userPrincipalName
                    LastSignIn      = $lastSign
                    DaysSinceSignIn = $days
                    HasLicense      = (@($_.assignedLicenses ?? @()).Count -gt 0)
                }
            })
            $result.Data.StaleMembers = $stale
            $result.Data.SectionStatus.StaleMembers = 'Collected'
        } catch {
            $result.Data.SectionStatus.StaleMembers = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-StaleAccounts' -Message $_.Exception.Message
            }
        }

        # AllPrincipals OAuth grants (app-level consent visible to all users)
        try {
            $grants = Invoke-NRGGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=consentType eq 'AllPrincipals'&`$top=200&`$expand=clientId" `
                -ErrorAction Stop
            if (@($grants.value ?? @()).Count -gt 0) {
                $clientIds = @($grants.value | Select-Object -ExpandProperty clientId -Unique)
                $appNames  = @{}
                foreach ($cid in ($clientIds | Select-Object -First 30)) {
                    try {
                        $sp = Invoke-NRGGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$cid?`$select=displayName,appId,publisherName" `
                            -ErrorAction Stop
                        $appNames[$cid] = [string]($sp.displayName ?? $cid)
                    } catch { $appNames[$cid] = $cid }
                }
                $result.Data.OAuthGrantedApps = @($grants.value ?? @() | ForEach-Object {
                    @{
                        AppName     = $appNames[$_.clientId] ?? [string]$_.clientId
                        ClientId    = [string]$_.clientId
                        Scope       = [string]$_.scope
                        ResourceId  = [string]$_.resourceId
                        ConsentType = 'AllPrincipals'
                    }
                })
            }
            $result.Data.SectionStatus.OAuthGrantedApps = 'Collected'
        } catch {
            $result.Data.SectionStatus.OAuthGrantedApps = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-OAuthGrants' -Message $_.Exception.Message
            }
        }

        # Microsoft Secure Score
        try {
            $ss = Invoke-NRGGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/security/secureScores?$top=1' `
                -ErrorAction Stop
            $latest = @($ss.value ?? @()) | Select-Object -First 1
            if ($latest) {
                $result.Data.SecureScore = @{
                    CurrentScore   = [double]($latest.currentScore ?? 0)
                    MaxScore       = [double]($latest.maxScore ?? 0)
                    Percentage     = if ($latest.maxScore -gt 0) { [int](($latest.currentScore / $latest.maxScore) * 100) } else { 0 }
                    CreatedDate    = [string]($latest.createdDateTime ?? '')
                    # AAD-13.1: Microsoft's peer benchmark — averageComparativeScores
                    # gives the average score by basis (AllTenants / TotalSeats /
                    # IndustryTypes). Lets the evaluator judge "above or below peers"
                    # instead of an arbitrary threshold. Field names per the
                    # secureScore / averageComparativeScore Graph resource types.
                    AverageComparativeScores = @(($latest.averageComparativeScores ?? @()) | ForEach-Object {
                        @{
                            Basis        = [string]($_.basis ?? '')
                            AverageScore = [double]($_.averageScore ?? 0)
                        }
                    })
                    ActiveProfiles = @($latest.activeUserCount ?? 0)
                    ControlScores  = @($latest.controlScores ?? @() | Select-Object -First 20 | ForEach-Object {
                        @{
                            ControlName  = [string]$_.controlName
                            Score        = [double]($_.score ?? 0)
                            # v4.6.4 EMERGENCY FIX (Critical #2): previously this
                            # wrote $_.controlCategory (a STRING like 'Identity')
                            # cast to [double] — which always coerces to 0. The
                            # correct property on a controlScore is maxScore.
                            MaxScore     = [double]($_.maxScore ?? 0)
                            ControlCategory = [string]($_.controlCategory ?? '')
                            Description  = [string]($_.description ?? '')
                        }
                    })
                }
            }
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-SecureScore' -Message $_.Exception.Message
            }
        }

        # ── Application / service principal credential expiry (AAD-14.1) ─────
        # A client secret or certificate on an app registration is a standing
        # credential to whatever that app can reach. Two failure modes, opposite
        # in character and both real:
        #
        #   Expired / expiring — an integration is about to break, or already
        #   has, and the usual fix under time pressure is a new secret with the
        #   longest available lifetime and no calendar entry.
        #
        #   Long-lived — a two-year secret is a two-year window. Anyone who has
        #   ever held it keeps access for its full term, and rotation is the
        #   only thing that closes it.
        #
        # Both are read from the app registration, not the service principal:
        # credentials live on the application object.
        try {
            $apps = @()
            $next = 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999'
            $maxPages = 200; $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $apps += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'AAD-AppCredentials' `
                        -Message "Pagination cap reached ($maxPages pages); application list may be truncated."
                }
            }

            $now = Get-Date
            $creds = foreach ($a in $apps) {
                $appName = [string](Get-NRGObjectField -Item $a -Key 'displayName')
                $appId   = [string](Get-NRGObjectField -Item $a -Key 'appId')
                foreach ($kind in @('passwordCredentials', 'keyCredentials')) {
                    foreach ($c in @(Get-NRGObjectField -Item $a -Key $kind -Default @())) {
                        if ($null -eq $c) { continue }
                        $endRaw = [string](Get-NRGObjectField -Item $c -Key 'endDateTime')
                        if (-not $endRaw) { continue }
                        $end = $null
                        if (-not [DateTime]::TryParse($endRaw, [ref]$end)) { continue }
                        $startRaw = [string](Get-NRGObjectField -Item $c -Key 'startDateTime')
                        $start = $null
                        $lifetimeDays = $null
                        if ($startRaw -and [DateTime]::TryParse($startRaw, [ref]$start)) {
                            $lifetimeDays = [int]([Math]::Round(($end - $start).TotalDays))
                        }
                        @{
                            AppDisplayName = $appName
                            AppId          = $appId
                            CredentialType = $(if ($kind -eq 'passwordCredentials') { 'Secret' } else { 'Certificate' })
                            DisplayName    = [string](Get-NRGObjectField -Item $c -Key 'displayName')
                            EndDateTime    = $end.ToString('o')
                            DaysRemaining  = [int]([Math]::Floor(($end - $now).TotalDays))
                            LifetimeDays   = $lifetimeDays
                        }
                    }
                }
            }
            $result.Data.AppCredentials = @($creds)
            $result.Data.SectionStatus.AppCredentials = 'Collected'
        } catch {
            $result.Data.SectionStatus.AppCredentials = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'AAD-AppCredentials' -Message $_.Exception.Message
            }
        }

        $result.Success = $true

    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'AAD-Inventory' -Message $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'AAD-Inventory' -Data $result
    }
    if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
        $skuCount = @($result.Data.SubscribedSkus).Count
        Register-NRGCoverage -Family 'AAD-Inventory' -Status 'Collected' `
            -Note "Guests=$(@($result.Data.GuestUsers).Count) SKUs=$skuCount"
    }
    return $result
}
#Requires -Version 7.0
#
# Invoke-TPCollectAADInventory.ps1  (v4.5.5)
# Collects per-object inventory data for named findings:
#   - Guest users with last sign-in date
#   - Stale member accounts (no sign-in 90+ days)
#   - Service principals with AllPrincipals OAuth grants
#
# LegacyAuthOnlyUsers and RecentRiskEvents are declared in the Data block but
# are not populated by any code path. They are reserved for a future collector
# and must not be read as evidence of anything.
#
# Requires: AuditLog.Read.All, User.Read.All, Application.Read.All,
#           Policy.Read.All (defaultAppManagementPolicy)
#

function Invoke-TPCollectAADInventory {
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
                AppManagementPolicy = 'NotRun'
            }
            GuestUsers          = @()
            StaleMembers        = @()
            OAuthGrantedApps    = @()
            AppCredentials      = @()
            AppManagementPolicy = $null
            LegacyAuthOnlyUsers = @()
            RecentRiskEvents    = @()
            SecureScore         = $null
            LastSignInSummary   = @{}
            SubscribedSkus      = @()
            # $false once Graph refused signInActivity for lack of Entra ID P1/P2 and the
            # guest and member lists were re-read without it (absent on older results = $true).
            SignInActivityLicensed = $true
        }
    }

    try {
        # Subscribed SKUs — license detection for report suppression
        try {
            $skuResp = Invoke-TPGraphRequest -Method GET `
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
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-SubscribedSkus' -Message $_.Exception.Message
            }
            # Log permission hint
            Write-Verbose "AAD-SubscribedSkus failed — needs Organization.Read.All or Directory.Read.All"
        }

        # Shared by the guest and member reads below. signInActivity requires
        # Microsoft Entra ID P1 or P2 (user resource type) and Graph refuses the
        # WHOLE query without it ("Neither tenant is B2C or tenant doesn't have
        # premium license"), which lost the guest list itself on Business
        # Standard and Office 365 E3 tenants and filed AAD-12.2 and AAD-12.3 as
        # collection failures. On that error the list is re-read without
        # signInActivity and SignInActivityLicensed records the fact, so the
        # controls can say "license", not "the read failed". Any other error
        # still fails the section. Paged through @odata.nextLink.
        $pageUsers = {
            param([string] $Select, [string] $Filter, [string] $Source)
            $rows = @()
            $next = "https://graph.microsoft.com/v1.0/users?`$select=$Select&`$filter=$Filter&`$top=500"
            $maxPages = 200; $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $rows += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source $Source -Message "Pagination cap reached ($maxPages pages); user list may be truncated."
                }
            }
            # Emit the rows one by one, never `,$rows`: an array returned as one
            # object through the try block in $readUsersWithSignIn arrives at the
            # caller's @() NESTED (one element holding the whole list), so an empty
            # list became one empty-array row whose .displayName throws under
            # StrictMode, and a full list became one row. Hashtables are not
            # unrolled by the pipeline, so each row stays whole.
            $rows
        }
        $readUsersWithSignIn = {
            param([string] $Select, [string] $Filter, [string] $Source)
            try { & $pageUsers $Select $Filter $Source }
            catch {
                $why = "$($_.Exception.Message) $([string](Get-TPObjectField -Item $_.ErrorDetails -Key 'Message' -Default ''))"
                if ($why -notmatch 'RequestFromNonPremiumTenant|premium license') { throw }
                $result.Data.SignInActivityLicensed = $false
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source $Source -Message "signInActivity requires Microsoft Entra ID P1 or P2 and Graph refused it ($($_.Exception.Message)); the accounts were re-read without it, so last sign-in is not known."
                }
                & $pageUsers ($Select -replace ',signInActivity', '') $Filter $Source
            }
        }

        # Guest users + last sign-in
        try {
            $guestRows = @(& $readUsersWithSignIn 'id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity' "userType eq 'Guest'" 'AAD-GuestInventory')
            $result.Data.GuestUsers = @($guestRows | ForEach-Object {
                # Graph does NOT return signInActivity at all for a user who
                # never signed in, or who last signed in before April 2020
                # (documented on the user resource type). Under StrictMode the
                # nested dot-access therefore THREW on exactly the accounts this
                # query exists to find, failing the whole section — so the guest
                # and stale-account controls reported NotApplicable on any tenant
                # with a single never-signed-in guest, which is nearly all of them.
                $lastSign  = [string](Get-TPNestedProperty -Object $_ -Path 'signInActivity.lastSignInDateTime' -Default '')
                # Staleness is judged on the last SUCCESSFUL sign-in (interactive
                # or not), as Microsoft's inactive-guest check does:
                # lastSignInDateTime is the last interactive ATTEMPT, so a guest
                # with a failed attempt last week and no success for a year read
                # as active. A guest with no recorded success is judged from the
                # day the account was created; neither date readable is not
                # known (never stale, never fresh).
                $okAt      = ConvertTo-TPUtcDateTime (Get-TPNestedProperty -Object $_ -Path 'signInActivity.lastSuccessfulSignInDateTime' -Default $null)
                $createdAt = ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $_ -Key 'createdDateTime' -Default $null)
                $lastOk    = if ($okAt) { $okAt.ToString('o') } else { '' }
                $created   = if ($createdAt) { $createdAt.ToString('o') } else { [string](Get-TPObjectField -Item $_ -Key 'createdDateTime' -Default '') }
                $basisAt = $okAt; $basis = 'last successful sign-in'
                if (-not $basisAt) { $basisAt = $createdAt; $basis = 'account creation (no successful sign-in recorded)' }
                if (-not $basisAt) { $basis = 'Unknown' }
                $daysSince = if ($basisAt) { [int]([datetime]::UtcNow - $basisAt).TotalDays } else { 9999 }
                @{
                    DisplayName       = [string](Get-TPObjectField -Item $_ -Key 'displayName' -Default '')
                    UPN               = [string](Get-TPObjectField -Item $_ -Key 'userPrincipalName' -Default '')
                    AccountEnabled    = (Get-TPObjectField -Item $_ -Key 'accountEnabled' -Default $null)
                    CreatedDateTime   = $created
                    LastSignIn        = $lastSign
                    LastSuccessfulSignIn = $lastOk
                    LastSignInBasis   = $basis
                    DaysSinceSignIn   = $daysSince
                    # Not known without the license, or with neither date: never stale, never fresh.
                    IsStale           = $(if ($result.Data.SignInActivityLicensed -eq $false -or -not $basisAt) { $null } else { $daysSince -gt 90 })
                }
            })
            $result.Data.SectionStatus.GuestUsers = 'Collected'
        } catch {
            $result.Data.SectionStatus.GuestUsers = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-GuestInventory' -Message $_.Exception.Message
            }
        }

        # Stale member accounts (signInActivity requires AuditLog.Read.All)
        try {
            $staleRows = @(& $readUsersWithSignIn 'id,displayName,userPrincipalName,accountEnabled,createdDateTime,signInActivity,assignedLicenses' "userType eq 'Member' and accountEnabled eq true" 'AAD-StaleAccounts')
            # DISA Microsoft Entra ID STIG V-270204 (ENTR-ID-000090), adopted by the
            # owner on 2026-10-26: an enabled account is inactive when its last
            # sign-in (signInActivity.lastSignInDateTime, the interactive sign-in
            # the STIG check reads) is more than 35 days old, or when it never
            # signed in and was created more than 35 days ago. The tool also
            # counts an account whose last SUCCESSFUL sign-in (Graph's
            # lastSuccessfulSignInDateTime, interactive or not) is more than 35
            # days old, because lastSignInDateTime records attempts too and a
            # departed user being password-sprayed would otherwise look active.
            # Either one makes the account inactive; every account the STIG
            # check lists is listed here. Unlicensed members count as well.
            $parseUtc = { param($v)
                $p = [datetime]::MinValue
                if ($v -and [datetime]::TryParse([string]$v, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$p)) { $p.ToUniversalTime() } else { $null } }
            $now = [datetime]::UtcNow
            $limitDays = 35
            $undetermined = 0
            # Without the license no account can be called stale; the evaluator reads SignInActivityLicensed.
            $stale = @(foreach ($u in $(if ($result.Data.SignInActivityLicensed -eq $false) { @() } else { $staleRows })) {
                $interactive = & $parseUtc (Get-TPNestedProperty -Object $u -Path 'signInActivity.lastSignInDateTime' -Default '')
                $success     = & $parseUtc (Get-TPNestedProperty -Object $u -Path 'signInActivity.lastSuccessfulSignInDateTime' -Default '')
                $created     = & $parseUtc (Get-TPObjectField -Item $u -Key 'createdDateTime' -Default '')
                $reasons = [System.Collections.Generic.List[string]]::new()
                if ($interactive) {
                    if (($now - $interactive).TotalDays -gt $limitDays) { $reasons.Add("last sign-in $([int]($now - $interactive).TotalDays) days ago") }
                } elseif ($created -and ($now - $created).TotalDays -gt $limitDays) {
                    $reasons.Add("no sign-in recorded; created $([int]($now - $created).TotalDays) days ago")
                }
                if ($success -and ($now - $success).TotalDays -gt $limitDays) { $reasons.Add("last successful sign-in $([int]($now - $success).TotalDays) days ago") }
                # No sign-in recorded and no readable creation date: not known.
                if ($reasons.Count -eq 0 -and -not $interactive -and -not $created) { $undetermined++ }
                if ($reasons.Count -eq 0) { continue }
                $last = if ($interactive -and $success) { if ($interactive -gt $success) { $interactive } else { $success } } elseif ($interactive) { $interactive } else { $success }
                @{
                    DisplayName     = [string](Get-TPObjectField -Item $u -Key 'displayName' -Default '')
                    UPN             = [string](Get-TPObjectField -Item $u -Key 'userPrincipalName' -Default '')
                    Id              = [string](Get-TPObjectField -Item $u -Key 'id' -Default '')
                    LastSignIn      = $(if ($last) { $last.ToString('o') } else { 'Never' })
                    LastSignInBasis = ($reasons -join '; ')
                    DaysSinceSignIn = $(if ($last) { [int]($now - $last).TotalDays } else { 9999 })
                    HasLicense      = (@(Get-TPObjectField -Item $u -Key 'assignedLicenses' -Default @()).Count -gt 0)
                }
            })
            $result.Data.StaleMembersThresholdDays = $limitDays
            $result.Data.StaleMembersUndetermined = $undetermined
            $result.Data.StaleMembers = $stale
            $result.Data.SectionStatus.StaleMembers = 'Collected'
        } catch {
            $result.Data.SectionStatus.StaleMembers = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-StaleAccounts' -Message $_.Exception.Message
            }
        }

        # AllPrincipals OAuth grants (app-level consent visible to all users)
        try {
            # oAuth2PermissionGrant has no navigation properties (clientId is a
            # plain string per Microsoft Learn) — $expand=clientId is rejected
            # by Graph's OData parser and fails the whole section on every run.
            # Client display names are already resolved by the per-
            # servicePrincipal lookups below, so no expand is needed.
            # Paged by Get-TPGraphAllPages: at the page cap it throws and the
            # section reads Failed; this loop used to log the cap and report
            # the truncated list as Collected.
            $grants = @(Get-TPGraphAllPages -MaxPages 200 `
                -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=consentType eq 'AllPrincipals'&`$top=200")
            if ($grants.Count -gt 0) {
                $clientIds = @($grants | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'clientId' -Default '') } | Where-Object { $_ } | Sort-Object -Unique)
                $appNames  = @{}
                # Every client is looked up: a cap at the first 30 left the
                # rest named in the report only by their object ID.
                foreach ($cid in $clientIds) {
                    try {
                        $sp = Invoke-TPGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/${cid}?`$select=displayName,appId,publisherName" `
                            -ErrorAction Stop
                        $appNames[$cid] = [string]($sp.displayName ?? $cid)
                    } catch { $appNames[$cid] = $cid }
                }
                $result.Data.OAuthGrantedApps = @($grants | ForEach-Object {
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
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-OAuthGrants' -Message $_.Exception.Message
            }
        }

        # Microsoft Secure Score
        try {
            $ss = Invoke-TPGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/security/secureScores?$top=1' `
                -ErrorAction Stop
            $latest = @($ss.value ?? @()) | Select-Object -First 1
            if ($latest) {
                $result.Data.SecureScore = @{
                    CurrentScore   = [double]($latest.currentScore ?? 0)
                    MaxScore       = [double](Get-TPObjectField -Item $latest -Key 'maxScore' -Default 0)
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
                            MaxScore     = [double](Get-TPObjectField -Item $_ -Key 'maxScore' -Default 0)
                            ControlCategory = [string]($_.controlCategory ?? '')
                            Description  = [string]($_.description ?? '')
                        }
                    })
                }
            }
        } catch {
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-SecureScore' -Message $_.Exception.Message
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
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $apps += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'AAD-AppCredentials' `
                        -Message "Pagination cap reached ($maxPages pages); application list may be truncated."
                }
            }

            $now = Get-Date
            $creds = foreach ($a in $apps) {
                $appName = [string](Get-TPObjectField -Item $a -Key 'displayName')
                $appId   = [string](Get-TPObjectField -Item $a -Key 'appId')
                foreach ($kind in @('passwordCredentials', 'keyCredentials')) {
                    foreach ($c in @(Get-TPObjectField -Item $a -Key $kind -Default @())) {
                        if ($null -eq $c) { continue }
                        $endRaw = [string](Get-TPObjectField -Item $c -Key 'endDateTime')
                        if (-not $endRaw) { continue }
                        # credential endDateTime/startDateTime are ISO 8601 Graph
                        # timestamps — parse with the 4-arg TryParse overload per
                        # CLAUDE.md (InvariantCulture + RoundtripKind, never a bare
                        # 2-arg [ref] call, which PowerShell's method binder cannot
                        # resolve against DateTime.TryParse on this runtime and
                        # throws "Cannot find an overload ... argument count: 2").
                        $end = [datetime]::MinValue
                        if (-not [DateTime]::TryParse($endRaw, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$end)) { continue }
                        $startRaw = [string](Get-TPObjectField -Item $c -Key 'startDateTime')
                        $start = [datetime]::MinValue
                        $lifetimeDays = $null
                        if ($startRaw -and [DateTime]::TryParse($startRaw, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$start)) {
                            $lifetimeDays = [int]([Math]::Round(($end - $start).TotalDays))
                        }
                        @{
                            AppDisplayName = $appName
                            AppId          = $appId
                            CredentialType = $(if ($kind -eq 'passwordCredentials') { 'Secret' } else { 'Certificate' })
                            DisplayName    = [string](Get-TPObjectField -Item $c -Key 'displayName')
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
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-AppCredentials' -Message $_.Exception.Message
            }
        }

        # Tenant application management policy (AAD-14.1): the tenant-wide
        # default that restricts how long a new secret or certificate may be
        # issued for. /policies/defaultAppManagementPolicy is a singleton read
        # with Policy.Read.All (already granted). Each restriction is kept as
        # read; the evaluator judges type, state, maxLifetime and the
        # created-after date. Its own section: a failure leaves it unread.
        try {
            $amp = Invoke-TPGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy' -ErrorAction Stop
            $mkRestriction = { param($r)
                $after = Get-TPObjectField -Item $r -Key 'restrictForAppsCreatedAfterDateTime' -Default $null
                $afterUtc = ConvertTo-TPUtcDateTime $after
                $ex = Get-TPObjectField -Item $r -Key 'excludeActors' -Default $null
                @{
                    RestrictionType = [string](Get-TPObjectField -Item $r -Key 'restrictionType' -Default '')
                    State           = [string](Get-TPObjectField -Item $r -Key 'state' -Default '')
                    MaxLifetime     = [string](Get-TPObjectField -Item $r -Key 'maxLifetime' -Default '')
                    RestrictForAppsCreatedAfterDateTime = $(if ($afterUtc) { $afterUtc.ToString('o') } else { [string]$after })
                    ExcludedActorAttributes = @(Get-TPNestedProperty -Object $ex -Path 'customSecurityAttributes' -Default @() | Where-Object { $null -ne $_ }).Count
                }
            }
            $result.Data.AppManagementPolicy = @{
                IsEnabled            = (Get-TPObjectField -Item $amp -Key 'isEnabled' -Default $null)
                PasswordRestrictions = @(Get-TPNestedProperty -Object $amp -Path 'applicationRestrictions.passwordCredentials' -Default @() | Where-Object { $null -ne $_ } | ForEach-Object { & $mkRestriction $_ })
                KeyRestrictions      = @(Get-TPNestedProperty -Object $amp -Path 'applicationRestrictions.keyCredentials' -Default @() | Where-Object { $null -ne $_ } | ForEach-Object { & $mkRestriction $_ })
                # The same restrictions for service principals (CIS 5.1.5.4 / 5.1.5.6
                # apply the limit to application registrations AND service principals).
                ServicePrincipalPasswordRestrictions = @(Get-TPNestedProperty -Object $amp -Path 'servicePrincipalRestrictions.passwordCredentials' -Default @() | Where-Object { $null -ne $_ } | ForEach-Object { & $mkRestriction $_ })
                ServicePrincipalKeyRestrictions      = @(Get-TPNestedProperty -Object $amp -Path 'servicePrincipalRestrictions.keyCredentials' -Default @() | Where-Object { $null -ne $_ } | ForEach-Object { & $mkRestriction $_ })
            }
            $result.Data.SectionStatus.AppManagementPolicy = 'Collected'
        } catch {
            $result.Data.SectionStatus.AppManagementPolicy = 'Failed'
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'AAD-AppManagementPolicy' -Message $_.Exception.Message
            }
        }

        $result.Success = $true

    } catch {
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'AAD-Inventory' -Message $_.Exception.Message
        }
    }

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'AAD-Inventory' -Data $result
    }
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        $skuCount = @($result.Data.SubscribedSkus).Count
        Register-TPCoverage -Family 'AAD-Inventory' -Status 'Collected' `
            -Note "Guests=$(@($result.Data.GuestUsers).Count) SKUs=$skuCount"
    }
    return $result
}
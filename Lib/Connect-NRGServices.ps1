#Requires -Version 7.0
#
# Connect-NRGServices.ps1  (v4.5.5)
# Authentication to Microsoft 365 services for read-only assessment.
#
# AUTH MODES:
#   1. App-only / certificate-based — UNATTENDED, recommended for scheduled runs.
#      Pass -TenantId, -AppId, -CertificateThumbprint. Required Graph app permissions
#      (read-only): Directory.Read.All, Policy.Read.All, Reports.Read.All,
#      SecurityEvents.Read.All, AuditLog.Read.All, RoleManagement.Read.All,
#      Organization.Read.All, Sites.Read.All, DeviceManagementConfiguration.Read.All,
#      DeviceManagementApps.Read.All, UserAuthenticationMethod.Read.All,
#      IdentityRiskyServicePrincipal.Read.All, AttackSimulation.Read.All,
#      AccessReview.Read.All.
#      EXO: Exchange.ManageAsApp + Global Reader role. See docs/AUTH-APP-ONLY.md.
#      Use CA-issued cert. Self-signed is discouraged per Microsoft Learn.
#
#   2. Interactive browser — ATTENDED, default.
#      Graph, Teams, EXO, and IPPS all use interactive BROWSER MFA (matching
#      ScubaGear). No device-code flow — that is the exact flow AAD-11.1 tells
#      clients to block, and it is EDR-flagged. The WAM broker is disabled at
#      function entry so browser modern-auth is used without the RuntimeBroker
#      crash the old device-code paths worked around.
#
# TOKEN CACHE HYGIENE:
#   Connect-MgGraph uses -ContextScope Process so the MSAL token cache is bound to
#   this PowerShell process and NOT persisted to
#   $env:LOCALAPPDATA\.IdentityService\msal_token_cache.bin (default CurrentUser scope).
#   Orchestrator wraps the run in try/finally with Disconnect-NRGServices.
#
# CONNECTION ORDER (MSAL assembly conflict prevention):
#   Graph -> EXO -> IPPS -> Teams. Teams LAST: the MicrosoftTeams module loads
#   its own Microsoft.Identity.Client(.Broker) into the default load context,
#   and ExchangeOnlineManagement 3.10 then cannot load its own (0x80131040), so
#   Teams-before-Exchange lost Exchange and Purview on every live run. Graph
#   resolves MSAL in its own load context and is unaffected. SharePoint shell
#   stays after everything (PnP loads an older Graph.Core that breaks Graph).
#
# PnP MULTI-TENANT APP DELETED 2024-09-09:
#   The shared PnP Management Shell Entra app (ClientID 31359c7f-bd7e-475c-86db-fdb8c937548e)
#   was deleted by the PnP team as a deliberate security improvement. Customers MUST
#   register their own Entra app for SharePoint. Do NOT use -PersistLogin (writes tokens
#   to $HOME\.m365pnppowershell) or -UseWebLogin (removed in PnP v3, cookie hijacking).
#
# WAM BROKER DISABLED ($env:MSAL_ALLOW_BROKER = '0', $env:MSAL_DISABLE_TOKENBROKER = '1'):
#   Set at function entry, before any connection. WAM crashes with NullReferenceException
#   when pwsh is elevated. Disabling forces MSAL to use interactive browser modern-auth.
#
# CVE-2025-54100 (Dec 2025, CVSS 7.8): MSHTML-based Invoke-WebRequest parser injection
# affects Windows PowerShell 5.1 only. This module requires PowerShell 7.0+ which is
# not vulnerable.
#

# The delegated Microsoft Graph scopes the assessment requests (24). One list,
# used by Connect-NRGServices and Grant-NRGGraphConsent.ps1; the batch runner
# carries a copy (it signs in before the module loads) that
# NRG.TenantPinning.Tests.ps1 pins to this one.
function Get-NRGGraphScopeList {
    [CmdletBinding()] param()
    $scopes = @(
        'User.Read.All','Group.Read.All','Directory.Read.All',
        'Policy.Read.All','AuditLog.Read.All','Application.Read.All',
        'RoleManagement.Read.All','SecurityEvents.Read.All',
        'IdentityRiskyUser.Read.All','Reports.Read.All',
        'Organization.Read.All','Sites.Read.All',
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementApps.Read.All',
        'UserAuthenticationMethod.Read.All',
        # ── v4.6.4 added (6) ─────────────────────────────────────────
        'SharePointTenantSettings.Read.All',
        'DeviceManagementManagedDevices.Read.All',
        'DeviceManagementServiceConfig.Read.All',
        'Policy.Read.PermissionGrant',
        'PrivilegedAccess.Read.AzureAD',
        'TeamSettings.Read.All',
        # ── require client re-consent ────────────────────────────────
        #   IdentityRiskyServicePrincipal.Read.All → AAD-11.3 (risky
        #     workload identities; needs Entra ID P2 + Workload IDs add-on)
        #   AttackSimulation.Read.All → DEF-4.6 (attack-sim training;
        #     Global cloud only, needs Defender for Office 365 P2)
        #   AccessReview.Read.All → AAD-8.2 (access reviews for privileged
        #     roles; needs Entra ID P2). Until re-consented the collector
        #     gets 403 and AAD-8.2 reports NotApplicable.
        'IdentityRiskyServicePrincipal.Read.All',
        'AttackSimulation.Read.All',
        'AccessReview.Read.All'
    )
    return $scopes
}

# The first live run failed inside ExchangeOnlineManagement 3.9.2 on PowerShell
# 7.6 with a bare "You cannot call a method on a null-valued expression" (its
# psm1 lines 554 and 791). Microsoft pairs 3.10.0+ with 7.6, so the message was
# a version mismatch wearing a null-reference costume. When the loaded module
# is outside the range Get-NRGExoModuleFloor gives for this PowerShell, say so
# beside the error instead of leaving the operator to guess.
function Get-NRGExoConnectHint {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Message)
    if (-not (Get-Command Get-NRGExoModuleFloor -ErrorAction SilentlyContinue)) { return '' }
    $mod = Get-Module -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $mod) { $mod = Get-Module -ListAvailable -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1 }
    if (-not $mod) { return '' }
    $floor  = Get-NRGExoModuleFloor
    $v      = $mod.Version
    $tooOld = $v -lt [version]$floor.Min
    $tooNew = [bool]($floor.Max -and $v -gt [version]$floor.Max)
    if (-not ($tooOld -or $tooNew)) { return '' }
    $range = if ($floor.Max) { '[{0},{1}]' -f $floor.Min, $floor.Max } else { '[{0},)' -f $floor.Min }
    $psv   = $PSVersionTable.PSVersion
    return ('ExchangeOnlineManagement {0} is not supported on PowerShell {1} (Microsoft pairs this PowerShell with {2}). ' +
            'Install a supported version: Install-PSResource -Name ExchangeOnlineManagement -Version ''{2}'' -Scope AllUsers -TrustRepository, ' +
            'then remove the other version and open a new window.') -f $v, $psv, $range
}

# A connection failure recorded as a bare message ("You cannot call a method
# on a null-valued expression") cannot be diagnosed from the results JSON: the
# first live run of v4.14.3 produced exactly that for Exchange and Purview,
# with no way to tell whether the throw was in this file or inside the
# ExchangeOnlineManagement module. Append the first stack frames.
function Get-NRGConnectErrorText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord)
    $msg = [string]$ErrorRecord.Exception.Message
    $frames = @()
    try {
        $st = [string]$ErrorRecord.ScriptStackTrace
        if ($st) { $frames = @($st -split "`r?`n" | Where-Object { $_ } | Select-Object -First 3) }
    } catch { $frames = @() }
    if ($frames.Count -gt 0) { $msg = "$msg [at: $($frames -join ' <- ')]" }
    if ($msg.Length -gt 1900) { $msg = $msg.Substring(0, 1900) }
    return $msg
}

function Connect-NRGServices {
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
        [string] $UserPrincipalName,

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string] $TenantId,

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string] $AppId,

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string] $CertificateThumbprint,

        [Parameter(ParameterSetName = 'AppOnly')]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*\.onmicrosoft\.com$')]
        [string] $OrganizationDomain,

        # GDAP batch runner passes $client.DelegatedOrg so the interactive
        # Purview/IPPS session lands on the CLIENT tenant instead of the
        # signed-in operator's own organization (Connect-IPPSSession with no
        # -DelegatedOrganization authenticates to the caller's own org).
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*\.onmicrosoft\.com$')]
        [string] $DelegatedOrganization,

        # When supplied, a pre-existing Graph context / EXO session is only
        # reused if it is actually connected to THIS tenant — otherwise a
        # leftover session from an earlier task (or a different client in
        # the same pwsh process) would silently assess the wrong tenant.
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string] $ExpectedTenantId,

        [switch] $SkipPurview,
        [switch] $SkipTeams,
        [switch] $SkipSharePoint
    )

    # Defense in depth — Microsoft endpoints already require TLS 1.2+
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.SecurityProtocolType]::Tls12 -bor
        [System.Net.SecurityProtocolType]::Tls13

    $isAppOnly = ($PSCmdlet.ParameterSetName -eq 'AppOnly')

    $result = [hashtable]@{
        Graph        = $false
        EXO          = $false
        IPPSSession  = $false
        Teams        = $false
        SharePoint   = $false
        TenantDomain = $null
        TenantId     = $null
        AuthMode     = $PSCmdlet.ParameterSetName
    }

    # Disable the WAM broker + token broker BEFORE any connection so every service
    # authenticates with interactive BROWSER MFA (matching ScubaGear) rather than
    # device-code flow. The broker is what caused the RuntimeBroker
    # NullReferenceException the old device-code paths worked around; with it
    # disabled, modern-auth browser sign-in is safe. Device-code flow is also the
    # exact flow AAD-11.1 tells clients to block — the tool should not rely on it.
    $env:MSAL_ALLOW_BROKER = '0'
    $env:MSAL_DISABLE_TOKENBROKER = '1'

    # ExchangeOnlineManagement 3.7.2 added -DisableWAM, Microsoft's supported
    # way to keep the Exchange and Security & Compliance sign-ins off the
    # Windows broker. It is not a weaker sign-in: MSAL uses the system browser
    # instead, with the same MFA and Conditional Access, and the token stays in
    # the module's in-memory cache. Passed only when the installed module has
    # the parameter, so an older module still connects.
    $exoDisableWam = $false; $ippsDisableWam = $false
    $exoCmd  = Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue
    $ippsCmd = Get-Command Connect-IPPSSession    -ErrorAction SilentlyContinue
    # Parameters can be $null on a command stub whose module has not finished
    # loading; read it through a null check so detection never throws.
    $exoParamsMap  = if ($exoCmd)  { Get-NRGObjectField -Item $exoCmd  -Key 'Parameters' -Default $null } else { $null }
    $ippsParamsMap = if ($ippsCmd) { Get-NRGObjectField -Item $ippsCmd -Key 'Parameters' -Default $null } else { $null }
    if ($null -ne $exoParamsMap)  { $exoDisableWam  = [bool]$exoParamsMap.ContainsKey('DisableWAM') }
    if ($null -ne $ippsParamsMap) { $ippsDisableWam = [bool]$ippsParamsMap.ContainsKey('DisableWAM') }

    # ── MSAL assembly-conflict preflight ──────────────────────────────────────
    # The #1 failure mode in M365 PowerShell tooling (ours AND CISA's ScubaGear)
    # is a Microsoft.Identity.Client version clash between the Graph and Exchange
    # modules. Surface the specific cause up front instead of letting the cryptic
    # "Could not load file or assembly 'Microsoft.Identity.Client'" (or
    # "Method not found ...WithBroker") fire mid-connect. Non-fatal — a warning
    # only; a clean machine sees nothing and the run proceeds.
    if (Get-Command Get-NRGModuleHealth -ErrorAction SilentlyContinue) {
        try {
            $health = Get-NRGModuleHealth
            if ($health.HasConflictRisk) {
                Write-Host "  [!] Module preflight: Microsoft.Identity.Client (MSAL) assembly-conflict risk." -ForegroundColor Yellow
                foreach ($m in $health.Modules) {
                    if ($m.MultipleVersions) {
                        Write-Host "      $($m.Name): $(@($m.Versions).Count) versions installed ($(@($m.Versions) -join ', ')) — keep only one." -ForegroundColor DarkYellow
                    }
                    if ($m.OneDrivePath) {
                        Write-Host "      $($m.Name): installed under a OneDrive-synced path — move PowerShell modules out of OneDrive." -ForegroundColor DarkYellow
                    }
                }
                Write-Host "      This causes 'Could not load file or assembly Microsoft.Identity.Client' at Exchange connect," -ForegroundColor DarkYellow
                Write-Host "      or a token acquisition that never returns — the run hangs on the first collector with no error." -ForegroundColor DarkYellow
                Write-Host "      Fix: Repair-NRGModuleHealth -WhatIf   (review, then re-run without -WhatIf)" -ForegroundColor DarkYellow
                Write-Host "      Then start a NEW PowerShell window — an assembly already loaded cannot be unloaded." -ForegroundColor DarkYellow
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    $bad = @($health.Modules | Where-Object { $_.MultipleVersions -or $_.OneDrivePath } | ForEach-Object { $_.Name })
                    Register-NRGException -Source 'ModulePreflight' -Message ("MSAL assembly-conflict risk on: {0}" -f ($bad -join ', '))
                }
            }
        } catch {
            Write-Verbose "Module preflight skipped: $($_.Exception.Message)"
        }
    }

    # ── 1. Microsoft Graph ────────────────────────────────────────────────────
    Write-Host "  [*] Microsoft Graph..." -ForegroundColor Cyan
    try {
        # v4.6.4 EMERGENCY FIX (Medium #9): align the requested Graph scopes
        # with CLAUDE.md. Previously 15 — missing scopes caused
        # silent permission failures in:
        #   - SharePoint tenant settings (Sites.Read.All deprecated for
        #     /admin/sharepoint/settings; SharePointTenantSettings.Read.All
        #     is the supported scope)
        #   - Intune managed devices and service config (separate scopes
        #     from DeviceManagementConfiguration.Read.All)
        #   - OAuth permission grant inspection (Policy.Read.PermissionGrant)
        #   - PIM read on PIM-managed tenants (PrivilegedAccess.Read.AzureAD)
        #   - Teams settings (TeamSettings.Read.All; previously relied on
        #     module-side Connect-MicrosoftTeams permissions)
        $scopes = Get-NRGGraphScopeList

        # ── Reuse an existing Graph context if the caller already established one ──
        # The GDAP batch runner (Invoke-NRGBatchAssessment) connects to each client
        # tenant with Connect-MgGraph -TenantId AND verifies the context before it
        # invokes this orchestrator. Re-running Connect-MgGraph here with a superset
        # of scopes would trigger MSAL INCREMENTAL CONSENT — an interactive re-auth
        # per client that breaks unattended batch and, with no -TenantId, can
        # silently switch context to the operator's home tenant. A force-reload of
        # Microsoft.Graph.Authentication would also drop the active session. So when
        # a context already exists that holds the core read scopes, reuse it and skip
        # the reconnect. The two re-consent-only scopes (IdentityRiskyServicePrincipal
        # / AttackSimulation) simply stay absent → AAD-11.3 / DEF-4.6 report
        # NotApplicable in batch, which is the already-documented behavior.
        $reuseGraphContext = $false
        if (-not $isAppOnly) {
            try {
                $existingCtx = Get-MgContext -ErrorAction SilentlyContinue
                if ($existingCtx -and $existingCtx.Scopes) {
                    $coreNeeded = @('Directory.Read.All', 'Policy.Read.All', 'User.Read.All')
                    $haveCore = (@($coreNeeded | Where-Object { $existingCtx.Scopes -contains $_ }).Count -eq $coreNeeded.Count)
                    # If the caller told us which tenant it needs, a context
                    # for a DIFFERENT tenant is not eligible for reuse — fall
                    # through to a fresh Connect-MgGraph below rather than
                    # silently assessing whatever tenant was last connected.
                    $tenantMatches = (-not $ExpectedTenantId) -or ("$($existingCtx.TenantId)" -eq $ExpectedTenantId)
                    if ($haveCore -and $tenantMatches) { $reuseGraphContext = $true }
                }
            } catch { $reuseGraphContext = $false }
        }

        if ($reuseGraphContext) {
            Write-Host "  [*] Microsoft Graph (reusing the caller's existing session)..." -ForegroundColor Cyan
        } else {
            # Force-load the LATEST Microsoft.Graph.Authentication to prevent assembly conflicts
            # when multiple versions exist or EOM has loaded an older bundled version
            $mgAuthVersions = @(Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
                Sort-Object Version -Descending)
            if ($mgAuthVersions) {
                Import-Module $mgAuthVersions[0].Path -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 3>$null
            }

            # Pre-import Graph sub-modules before Connect-MgGraph locks the version
            $graphSubModules = @(
                'Microsoft.Graph.Reports',
                'Microsoft.Graph.Identity.Governance',
                'Microsoft.Graph.Identity.SignIns',
                'Microsoft.Graph.Users'
            )
            foreach ($gm in $graphSubModules) {
                if (Get-Module -ListAvailable -Name $gm -ErrorAction SilentlyContinue) {
                    Import-Module $gm -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 3>$null
                }
            }

            if ($isAppOnly) {
                Connect-MgGraph -TenantId $TenantId -ClientId $AppId `
                                -CertificateThumbprint $CertificateThumbprint `
                                -ContextScope Process -NoWelcome -ErrorAction Stop
            } else {
                # -ContextScope Process scopes MSAL token cache to this PS process —
                # token does NOT persist to msal_token_cache.bin on disk.
                # WarningAction: the SDK's multi-line WAM notice is replaced by
                # the one-line hint below. WAM itself stays on.
                Write-Host "      Sign-in window may open behind this one." -ForegroundColor DarkGray
                $mgConnectParams = @{ Scopes = $scopes; ContextScope = 'Process'; NoWelcome = $true; ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
                if ($ExpectedTenantId) { $mgConnectParams['TenantId'] = $ExpectedTenantId }
                Connect-MgGraph @mgConnectParams
            }
        }

        $ctx = Get-MgContext -ErrorAction Stop
        # A caller that names the tenant must get that tenant. Signing in with
        # an account whose home tenant differs (an MSP operator without GDAP
        # to this client, or a stale cached account) otherwise yields a Graph
        # session for the WRONG tenant, and every collector would assess it.
        if ($ctx -and $ExpectedTenantId -and "$($ctx.TenantId)" -ne $ExpectedTenantId) {
            throw "Graph session is for tenant $($ctx.TenantId), not the requested tenant $ExpectedTenantId."
        }
        if ($ctx) {
            if ($isAppOnly) {
                $accountDomain = if ($OrganizationDomain) { $OrganizationDomain } else { $TenantId }
            } else {
                # UPN parsing (v4.6.3 P2 fix): `($ctx.Account -split '@')[-1]` returns
                # the WHOLE string when there's no `@`, which then fails downstream
                # tenant-domain validation with a misleading message. Be explicit.
                # Two statements, not `$x = if (...) { ... } else { @() }`. An
                # if-block yielding an empty array enumerates it away and
                # assigns $null, so the .Count below threw a StrictMode
                # property error instead of producing the clean warning this
                # code was written to produce. The falsy-Account case is the
                # one branch that existed specifically to be handled, and it
                # was the one that crashed.
                $accountParts = @()
                if ($ctx.Account) { $accountParts = @(([string]$ctx.Account) -split '@') }
                if ($accountParts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($accountParts[1])) {
                    Write-Warning "Connect-NRGServices: Graph context account '$($ctx.Account)' is not a valid UPN (expected user@tenant.tld)."
                    return $null
                }
                $accountDomain = $accountParts[1]
                if ($accountDomain -notmatch '^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61})+$') {
                    throw "Invalid tenant domain format from Graph context: $accountDomain"
                }
            }

            $result['Graph']          = $true
            # Verify Organization.Read.All consent (needed for subscribedSkus)
            $ctx = Get-MgContext
            if ($ctx -and $ctx.Scopes -notcontains 'Organization.Read.All') {
                Write-Host "  [!] Organization.Read.All not in token — SKU detection disabled. Run Disconnect-MgGraph then re-run to force re-consent." -ForegroundColor Yellow
            }
            $result['TenantId']       = "$($ctx.TenantId)"
            $result['OperatorDomain'] = $accountDomain

            $consentNotice = [System.Collections.Generic.List[object]]::new()
            # Record what the token was actually granted, so the controls
            # whose permission this tenant never consented to say so by name.
            try {
                $consentMode = if ($isAppOnly) { 'AppOnly' } else { 'Delegated' }
                $missingScopes = @(Set-NRGGraphConsentState -Mode $consentMode -GrantedScopes @($ctx.Scopes) -RequestedScopes $scopes)
                $result['MissingScopes'] = $missingScopes
                if ($missingScopes.Count -gt 0) {
                    # Printed after the '[+] Graph' line below, so the notice
                    # reads as a note on the connection rather than before it.
                    $consentNotice.Add(@("  [!] Graph permissions not granted in this tenant: $($missingScopes -join ', ')", 'Yellow'))
                    $consentScopes = @(Get-NRGConsentScopeMap)
                    $blocked = @($consentScopes | Where-Object { $_.Scope -in $missingScopes } | ForEach-Object { $_.ControlId })
                    if ($blocked.Count -gt 0) {
                        $consentNotice.Add(@("      Not assessed until consented: $($blocked -join ', ')", 'Yellow'))
                    }
                    $fixHint = if ($isAppOnly) { 'Entra admin center > App registrations > the NRG assessment app > API permissions: add these Microsoft Graph application permissions, then Grant admin consent' } else { '.\Grant-NRGGraphConsent.ps1 -TenantDomain <tenant> (Global Administrator, once)' }
                    $consentNotice.Add(@("      Fix: $fixHint", 'DarkGray'))
                }
            } catch {
                Write-Verbose "Connect-NRGServices: could not record granted Graph scopes. $($_.Exception.Message)"
            }

            # Resolve TenantDomain from the CONNECTED tenant, not the signed-in
            # account's UPN. Under GDAP the operator authenticates as their own
            # UPN (e.g. tech@nrgtechservices.com) against a client tenant via
            # -TenantId, so $accountDomain above is the MSP's own domain —
            # using it mislabels every client's report header, output
            # filename and SSP answers lookup with the MSP's domain instead
            # of the client's. Read /organization's verified domains and
            # prefer isInitial (the domain the tenant was created with) then
            # isDefault; fall back to the account/UPN domain only if Graph
            # cannot answer (e.g. Organization.Read.All not yet consented).
            $tenantDomain = $accountDomain
            try {
                if (Get-Command Invoke-NRGGraphRequest -ErrorAction SilentlyContinue) {
                    $org = Invoke-NRGGraphRequest -Method GET `
                        -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains' -ErrorAction Stop
                    $orgRows = @(Get-NRGNestedProperty -Object $org -Path 'value' -Default @())
                    if ($orgRows.Count -gt 0) {
                        $verifiedDomains = @(Get-NRGNestedProperty -Object $orgRows[0] -Path 'verifiedDomains' -Default @())
                        $initialDomain = $verifiedDomains | Where-Object { (Get-NRGNestedProperty -Object $_ -Path 'isInitial' -Default $false) -eq $true } | Select-Object -First 1
                        $defaultDomain = $verifiedDomains | Where-Object { (Get-NRGNestedProperty -Object $_ -Path 'isDefault' -Default $false) -eq $true } | Select-Object -First 1
                        $preferredDomain = if ($initialDomain) { $initialDomain } elseif ($defaultDomain) { $defaultDomain } else { $null }
                        $resolvedName = [string](Get-NRGNestedProperty -Object $preferredDomain -Path 'name' -Default '')
                        if ($resolvedName) { $tenantDomain = $resolvedName }
                    }
                }
            } catch {
                Write-Verbose "Connect-NRGServices: could not resolve tenant domain from Graph /organization — using account UPN domain. $($_.Exception.Message)"
            }
            $result['TenantDomain'] = $tenantDomain

            $who = if ($isAppOnly) { "App $($AppId.Substring(0,8))... in tenant $($TenantId.Substring(0,8))..." } else { $ctx.Account }
            Write-Host "  [+] Graph - $who" -ForegroundColor Green
            foreach ($n in $consentNotice) { Write-Host $n[0] -ForegroundColor $n[1] }
        }
    } catch {
        Write-Host "  [!] Graph: $($_.Exception.Message)" -ForegroundColor Yellow
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Connect-Graph' -Message (Get-NRGConnectErrorText -ErrorRecord $_)
        }
    }

    # ── 2. Exchange Online ────────────────────────────────────────────────────
    # ACCEPTED RESIDUAL RISK: the EXO V3 module dynamically downloads cmdlet code
    # from https://outlook.office365.com/AdminApi/.../EXOModuleFile?Version=... at
    # connection time and loads it into the session. Download is HTTPS and signed
    # (v3.2.0+). See docs/security/THREAT-MODEL.md.
    Write-Host "  [*] Exchange Online..." -ForegroundColor Cyan
    try {
        # ── Reuse an existing EXO session if the caller already established one ──
        # The GDAP batch runner connects EXO with -DelegatedOrganization <client>
        # AND verifies the session tenant before invoking the orchestrator. This
        # interactive branch has NO -DelegatedOrganization, so reconnecting here
        # would open a session against the OPERATOR's own tenant and collect the
        # wrong mailboxes. So if a Connected EXO session already exists, reuse it.
        $reuseExoSession = $false
        if (-not $isAppOnly -and (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
            try {
                $exoConn = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' })
                # As with Graph above, a caller-supplied ExpectedTenantId
                # narrows reuse to a session actually connected to that
                # tenant — a leftover session for a different tenant must
                # not be silently treated as this run's mailbox data.
                if ($ExpectedTenantId) {
                    $exoConn = @($exoConn | Where-Object { "$($_.TenantId)" -eq $ExpectedTenantId })
                }
                if ($exoConn.Count -gt 0) { $reuseExoSession = $true }
            } catch { $reuseExoSession = $false }
        }

        if ($reuseExoSession) {
            $result['EXO'] = $true
            Write-Host "  [+] Exchange Online (reusing the caller's existing session)" -ForegroundColor Green
        }
        elseif ($isAppOnly) {
            $orgDomain = if ($OrganizationDomain) {
                $OrganizationDomain
            } elseif ($result.TenantDomain -match '\.onmicrosoft\.com$') {
                $result.TenantDomain
            } else {
                throw "App-only EXO requires the .onmicrosoft.com routing domain via -OrganizationDomain."
            }
            $exoAppParams = @{ AppId = $AppId; CertificateThumbprint = $CertificateThumbprint; Organization = $orgDomain; ShowBanner = $false; ErrorAction = 'Stop' }
            if ($exoDisableWam) { $exoAppParams['DisableWAM'] = $true }
            Connect-ExchangeOnline @exoAppParams | Out-Null
            $result['EXO'] = $true
            Write-Host "  [+] Exchange Online connected" -ForegroundColor Green
        } else {
            # Interactive browser MFA (matches ScubaGear). The WAM broker is disabled
            # at the top of this function, so modern-auth sign-in uses the system
            # browser without the RuntimeBroker crash the old device-code /
            # UseRPSSession paths worked around.
            $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
            if ($exoDisableWam) { $exoParams['DisableWAM'] = $true }
            if ($UserPrincipalName) { $exoParams['UserPrincipalName'] = $UserPrincipalName }
            # GDAP: without -DelegatedOrganization Exchange connects to the
            # signed-in operator's OWN organization, not the client's.
            if ($DelegatedOrganization) { $exoParams['DelegatedOrganization'] = $DelegatedOrganization }
            Connect-ExchangeOnline @exoParams | Out-Null
            if ($ExpectedTenantId -and (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
                $exoNow = @(Get-ConnectionInformation -ErrorAction SilentlyContinue |
                    Where-Object { $_.State -eq 'Connected' -and -not (Test-NRGEopConnection -Connection $_) }) |
                    Select-Object -Last 1
                $exoTid = [string](Get-NRGObjectField -Item $exoNow -Key 'TenantID' -Default '')
                if ($exoTid -and $exoTid -ne $ExpectedTenantId) {
                    throw "Exchange Online session is for tenant $exoTid, not the requested tenant $ExpectedTenantId."
                }
            }
            $result['EXO'] = $true
            Write-Host "  [+] Exchange Online connected" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] EXO: $($_.Exception.Message)" -ForegroundColor Yellow
        $exoHint = Get-NRGExoConnectHint -Message $_.Exception.Message
        if ($exoHint) { Write-Host "      $exoHint" -ForegroundColor Yellow }
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Connect-EXO' -Message (Get-NRGConnectErrorText -ErrorRecord $_)
        }
    }

    # ── 3. Purview / Security & Compliance ───────────────────────────────────
    if (-not $SkipPurview) {
        Write-Host "  [*] Purview / Security and Compliance..." -ForegroundColor Cyan
        try {
            if ($isAppOnly) {
                # IPPSSession does not yet support app-only cert auth as of EXO V3.5.
                Write-Host "      Note: IPPSSession does not currently support app-only auth. Skipping." -ForegroundColor DarkYellow
            } else {
                # Interactive browser MFA (matches ScubaGear). The WAM broker is
                # disabled at the top of this function, so modern-auth sign-in uses
                # the system browser without the RuntimeBroker crash the old
                # device-code path worked around.
                $ippsParams = @{
                    ShowBanner  = $false
                    ErrorAction = 'Stop'
                }
                if ($ippsDisableWam) { $ippsParams['DisableWAM'] = $true }
                if ($UserPrincipalName) { $ippsParams['UserPrincipalName'] = $UserPrincipalName }
                # Without -DelegatedOrganization, Connect-IPPSSession maps the
                # session to the SIGNED-IN account's own organization — under
                # GDAP that is the MSP's tenant, not the client's, and every
                # Purview/DLP control would then score the MSP's own
                # configuration as the client's.
                if ($DelegatedOrganization) { $ippsParams['DelegatedOrganization'] = $DelegatedOrganization }

                Connect-IPPSSession @ippsParams | Out-Null

                # Verify the IPPS session landed on the tenant Graph connected
                # to. A missing/mismatched -DelegatedOrganization can still
                # silently open the session against the operator's own org.
                if ($result['TenantId'] -and (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
                    $ippsConn = @(Get-ConnectionInformation -ErrorAction SilentlyContinue |
                        Where-Object { $_.ConnectionUri -match 'ps\.compliance' -and $_.State -eq 'Connected' })
                    $ippsTenantId = if ($ippsConn.Count -gt 0) { "$($ippsConn[0].TenantId)" } else { $null }
                    if ($ippsTenantId -and $ippsTenantId -ne $result['TenantId']) {
                        throw "IPPS session tenant ($ippsTenantId) does not match Graph tenant ($($result['TenantId']))."
                    }
                }

                $result['IPPSSession'] = $true
                Write-Host "  [+] Purview / Compliance connected" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Purview: $($_.Exception.Message)" -ForegroundColor Yellow
            $ippsHint = Get-NRGExoConnectHint -Message $_.Exception.Message
            if ($ippsHint) { Write-Host "      $ippsHint" -ForegroundColor Yellow }
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Connect-IPPS' -Message (Get-NRGConnectErrorText -ErrorRecord $_)
            }
        }
    }

    # ── 4. Microsoft Teams ────────────────────────────────────────────────────
    # AFTER Exchange and Purview, deliberately. The MicrosoftTeams module
    # ships its own Microsoft.Identity.Client / .Broker assemblies and loads
    # them into the default load context; ExchangeOnlineManagement 3.10
    # then fails to load its own copy ("The located assembly's manifest
    # definition does not match the assembly reference", 0x80131040) and
    # neither Exchange nor Purview ever connects. Live run 2026-09-29: with
    # Teams first, Exchange and Purview failed on every attempt; with
    # Exchange first (run 3), Exchange, Purview and Teams all connected.
    # Graph is unaffected either way: it resolves MSAL inside its own
    # assembly load context.
    if (-not $SkipTeams) {
        Write-Host "  [*] Microsoft Teams..." -ForegroundColor Cyan
        try {
            # Check both installed and in-session (handles just-installed modules)
            $teamsAvail = (Get-Module -ListAvailable -Name MicrosoftTeams -ErrorAction SilentlyContinue) -or
                          (Get-Module -Name MicrosoftTeams -ErrorAction SilentlyContinue)
            if (-not $teamsAvail) {
                # Try importing directly — may have been installed this session
                try { Import-Module MicrosoftTeams -Force -ErrorAction Stop -WarningAction SilentlyContinue }
                catch { throw 'MicrosoftTeams module not installed. Run: Install-Module MicrosoftTeams -Scope CurrentUser -Force' }
            }
            Import-Module MicrosoftTeams -ErrorAction Stop -WarningAction SilentlyContinue

            if ($isAppOnly) {
                Connect-MicrosoftTeams -TenantId $TenantId -ApplicationId $AppId `
                                       -CertificateThumbprint $CertificateThumbprint `
                                       -ErrorAction Stop | Out-Null
            } else {
                # Import module explicitly in case it was just installed this session
                if (-not (Get-Command Connect-MicrosoftTeams -ErrorAction SilentlyContinue)) {
                    Import-Module MicrosoftTeams -Force -ErrorAction SilentlyContinue
                }
                # Interactive browser MFA (matches ScubaGear); no device-code flow.
                # Pass the already-verified Graph context tenant — under GDAP
                # Connect-MicrosoftTeams with no -TenantId authenticates to
                # the signed-in operator's own organization, not the client's.
                $teamsParams = @{ ErrorAction = 'Stop' }
                if ($result['TenantId']) { $teamsParams['TenantId'] = $result['TenantId'] }
                Connect-MicrosoftTeams @teamsParams | Out-Null
            }
            # Verify the Teams session landed on the tenant Graph connected
            # to. A mismatched or missing tenant hint can still silently
            # authenticate to the operator's own organization, and every
            # TMS-* control would then score that organization's policies
            # as the client's.
            if ($result['TenantId']) {
                $csTenantId = "$((Get-CsTenant -ErrorAction Stop).TenantId)"
                if ($csTenantId -ne $result['TenantId']) {
                    throw "Teams session tenant ($csTenantId) does not match Graph tenant ($($result['TenantId']))."
                }
            }
            $result['Teams'] = $true
            Write-Host "  [+] Teams connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Teams: $($_.Exception.Message)" -ForegroundColor Yellow
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Connect-Teams' -Message (Get-NRGConnectErrorText -ErrorRecord $_)
            }
        }
    }

    # ── 5. SharePoint Online Management Shell ────────────────────────────────
    # Optional. Powers the five SPO tenant controls (SPO-2.2/2.6/3.2/3.4 + the
    # SPO-2.4 advisory) whose settings Graph /admin/sharepoint/settings does NOT
    # expose. Uses Microsoft.Online.SharePoint.PowerShell (NOT PnP — PnP loads an
    # old Graph.Core assembly that breaks Microsoft.Graph in the same session).
    # Best-effort: any failure leaves SharePoint=$false and the SPO collector
    # falls back to Graph-only, so the five controls stay NotApplicable — never a
    # false pass. App-only cert auth isn't supported by this module (like IPPS).
    if (-not $SkipSharePoint) {
        Write-Host "  [*] SharePoint Online Management Shell..." -ForegroundColor Cyan
        try {
            if ($isAppOnly) {
                Write-Host "      Note: SPO Management Shell does not support app-only cert auth. Skipping (Graph-only SPO)." -ForegroundColor DarkYellow
            } elseif (-not ($result['Graph'])) {
                Write-Host "      Note: Graph not connected — cannot derive SPO admin URL. Skipping." -ForegroundColor DarkYellow
            } else {
                $spoAvail = (Get-Module -ListAvailable -Name Microsoft.Online.SharePoint.PowerShell -ErrorAction SilentlyContinue) -or
                            (Get-Module -Name Microsoft.Online.SharePoint.PowerShell -ErrorAction SilentlyContinue)
                if (-not $spoAvail) {
                    Write-Host "      Note: Microsoft.Online.SharePoint.PowerShell not installed. Skipping (Graph-only SPO). Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force" -ForegroundColor DarkYellow
                } else {
                    # PowerShell 7 can load this module only through Windows
                    # PowerShell compatibility (Microsoft: "you must import the
                    # SharePoint module using the -UseWindowsPowerShell
                    # parameter"), which starts powershell.exe as a child
                    # process. The caller opted in (-IncludeSharePointShell);
                    # an ASR rule that blocks the process fails here, and the
                    # SharePoint controls that need it stay not assessed.
                    if ($PSVersionTable.PSEdition -eq 'Core') {
                        $spoMod = @(Get-Module -ListAvailable -Name Microsoft.Online.SharePoint.PowerShell -ErrorAction SilentlyContinue | Sort-Object Version -Descending)[0]
                        $spoTarget = if ($spoMod -and $spoMod.Path) { $spoMod.Path } else { 'Microsoft.Online.SharePoint.PowerShell' }
                        try {
                            Import-Module $spoTarget -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue 3>$null | Out-Null
                        } catch {
                            throw "Windows PowerShell could not be started for the SharePoint Online Management Shell (an Attack Surface Reduction rule that blocks process creation will do this): $($_.Exception.Message)"
                        }
                    } else {
                        Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
                    }
                    # Derive the admin URL from the Graph root site host:
                    # https://contoso.sharepoint.com → https://contoso-admin.sharepoint.com
                    # (also correct for gov: contoso.sharepoint.us → contoso-admin.sharepoint.us).
                    $adminUrl = $null
                    try {
                        $root = Invoke-NRGGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/sites/root' -ErrorAction Stop
                        $webUrl = [string]($root.webUrl ?? '')
                        if ($webUrl -match '^https://([^./]+)\.(sharepoint\.[a-z]+)') {
                            $adminUrl = "https://$($Matches[1])-admin.$($Matches[2])"
                        }
                    } catch {
                        Register-NRGException -Source 'Connect-SPO-RootSite' -Message $_.Exception.Message -ErrorAction SilentlyContinue
                    }
                    if (-not $adminUrl) {
                        Write-Host "      Note: could not derive SPO admin URL from Graph root site. Skipping." -ForegroundColor DarkYellow
                    } else {
                        # Interactive browser MFA (matches ScubaGear). No device-code flow.
                        Connect-SPOService -Url $adminUrl -ErrorAction Stop
                        $result['SharePoint']   = $true
                        $result['SPOAdminUrl']  = $adminUrl
                        Write-Host "  [+] SharePoint Online connected ($adminUrl)" -ForegroundColor Green
                    }
                }
            }
        } catch {
            Write-Host "  [!] SharePoint: $($_.Exception.Message)" -ForegroundColor Yellow
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Connect-SPO' -Message (Get-NRGConnectErrorText -ErrorRecord $_)
            }
        }
    }

    Write-Host ""
    Write-Output $result
}

function Disconnect-NRGServices {
    [CmdletBinding()] param()
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-SPOService -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-PnPOnline -ErrorAction SilentlyContinue | Out-Null } catch {}
    Write-Host "[-] Sessions disconnected." -ForegroundColor DarkGray
}
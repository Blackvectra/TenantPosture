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
#   Graph -> Teams -> EXO -> IPPS. SharePoint deferred to orchestrator (PnP loads
#   older Graph.Core that breaks Graph cmdlets).
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
                Write-Host "      This is what causes 'Could not load file or assembly Microsoft.Identity.Client' at Exchange connect." -ForegroundColor DarkYellow
                Write-Host "      Fix: run .\Install-NRGPrerequisites.ps1, or uninstall the extra versions and Install-Module ExchangeOnlineManagement -RequiredVersion 3.2.0 -Force." -ForegroundColor DarkYellow
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
        # with CLAUDE.md (21 scopes). Previously 15 — missing scopes caused
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
        # NotApplicable in batch, which is the already-documented behaviour.
        $reuseGraphContext = $false
        if (-not $isAppOnly) {
            try {
                $existingCtx = Get-MgContext -ErrorAction SilentlyContinue
                if ($existingCtx -and $existingCtx.Scopes) {
                    $coreNeeded = @('Directory.Read.All', 'Policy.Read.All', 'User.Read.All')
                    $haveCore = (@($coreNeeded | Where-Object { $existingCtx.Scopes -contains $_ }).Count -eq $coreNeeded.Count)
                    if ($haveCore) { $reuseGraphContext = $true }
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
                Connect-MgGraph -Scopes $scopes -ContextScope Process -NoWelcome -ErrorAction Stop
            }
        }

        $ctx = Get-MgContext -ErrorAction Stop
        if ($ctx) {
            if ($isAppOnly) {
                $accountDomain = if ($OrganizationDomain) { $OrganizationDomain } else { $TenantId }
            } else {
                # UPN parsing (v4.6.3 P2 fix): `($ctx.Account -split '@')[-1]` returns
                # the WHOLE string when there's no `@`, which then fails downstream
                # tenant-domain validation with a misleading message. Be explicit.
                $accountParts = if ($ctx.Account) { ([string]$ctx.Account) -split '@' } else { @() }
                if ($accountParts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($accountParts[1])) {
                    Write-Warning "Connect-NRGServices: Graph context account '$($ctx.Account)' is not a valid UPN (expected user@tenant.tld)."
                    return $null
                }
                $accountDomain = $accountParts[1]
                if ($accountDomain -notmatch '^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61})+$') {
                    throw "Invalid tenant domain format from Graph context: $accountDomain"
                }
            }

            $result['Graph']        = $true
            # Verify Organization.Read.All consent (needed for subscribedSkus)
            $ctx = Get-MgContext
            if ($ctx -and $ctx.Scopes -notcontains 'Organization.Read.All') {
                Write-Host "  [!] Organization.Read.All not in token — SKU detection disabled. Run Disconnect-MgGraph then re-run to force re-consent." -ForegroundColor Yellow
            }
            $result['TenantId']     = "$($ctx.TenantId)"
            $result['TenantDomain'] = $accountDomain
            $who = if ($isAppOnly) { "App $($AppId.Substring(0,8))... in tenant $($TenantId.Substring(0,8))..." } else { $ctx.Account }
            Write-Host "  [+] Graph - $who" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Graph: $($_.Exception.Message)" -ForegroundColor Yellow
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Connect-Graph' -Message $_.Exception.Message
        }
    }

    # ── 2. Microsoft Teams ────────────────────────────────────────────────────
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
                Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
            }
            $result['Teams'] = $true
            Write-Host "  [+] Teams connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Teams: $($_.Exception.Message)" -ForegroundColor Yellow
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Connect-Teams' -Message $_.Exception.Message
            }
        }
    }

    # ── 3. Exchange Online ────────────────────────────────────────────────────
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
            Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertificateThumbprint `
                                   -Organization $orgDomain -ShowBanner:$false -ErrorAction Stop | Out-Null
            $result['EXO'] = $true
            Write-Host "  [+] Exchange Online connected" -ForegroundColor Green
        } else {
            # Interactive browser MFA (matches ScubaGear). The WAM broker is disabled
            # at the top of this function, so modern-auth sign-in uses the system
            # browser without the RuntimeBroker crash the old device-code /
            # UseRPSSession paths worked around.
            $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
            if ($UserPrincipalName) { $exoParams['UserPrincipalName'] = $UserPrincipalName }
            Connect-ExchangeOnline @exoParams | Out-Null
            $result['EXO'] = $true
            Write-Host "  [+] Exchange Online connected" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] EXO: $($_.Exception.Message)" -ForegroundColor Yellow
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Connect-EXO' -Message $_.Exception.Message
        }
    }

    # ── 4. Purview / Security & Compliance ───────────────────────────────────
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
                if ($UserPrincipalName) { $ippsParams['UserPrincipalName'] = $UserPrincipalName }

                Connect-IPPSSession @ippsParams | Out-Null
                $result['IPPSSession'] = $true
                Write-Host "  [+] Purview / Compliance connected" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Purview: $($_.Exception.Message)" -ForegroundColor Yellow
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Connect-IPPS' -Message $_.Exception.Message
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
                    Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
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
                Register-NRGException -Source 'Connect-SPO' -Message $_.Exception.Message
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
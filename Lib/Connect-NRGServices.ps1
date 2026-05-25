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
#      DeviceManagementApps.Read.All, UserAuthenticationMethod.Read.All.
#      EXO: Exchange.ManageAsApp + Global Reader role. See docs/AUTH-APP-ONLY.md.
#      Use CA-issued cert. Self-signed is discouraged per Microsoft Learn.
#
#   2. Interactive browser — ATTENDED, default.
#      Graph: interactive browser (no device code, no broker bypass risk).
#      Teams/EXO/IPPS: device code (WAM broker crashes when running elevated).
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
# WAM BROKER DISABLED ($env:MSAL_ALLOW_BROKER = '0'):
#   Set at function entry, before any connection. WAM crashes with NullReferenceException
#   when pwsh is elevated. Disabling forces MSAL to use device-code/browser.
#
# CVE-2025-54100 (Dec 2025, CVSS 7.8): MSHTML-based Invoke-WebRequest parser injection
# affects Windows PowerShell 5.1 only. This module requires PowerShell 7.0+ which is
# not vulnerable.
#

# Script-scoped scriptblock (not exported)
$script:ShowDeviceCodeBox = {
    param([string]$Service, [string]$Url)

    try {
        $parsed = [System.Uri]$Url
        # OWASP A10 / ASVS V12.6.1 — HTTPS-only + Microsoft-domain allowlist.
        # Match either the apex 'microsoft.com' or any '*.microsoft.com'
        # subdomain. Microsoft uses the apex form for the device-code login
        # endpoint (https://microsoft.com/devicelogin), which the previous
        # regex '\.microsoft\.com$' silently rejected because the apex has no
        # leading dot. HTTP remains rejected (Scheme must equal 'https').
        $hostOk = $parsed.Host -eq 'microsoft.com' -or $parsed.Host -match '\.microsoft\.com$'
        if ($parsed.Scheme -ne 'https' -or -not $hostOk) {
            Write-Warning "Refusing to open non-HTTPS or non-Microsoft URL: $Url"
            return
        }
    } catch {
        Write-Warning "Invalid URL — refusing to open: $Url"
        return
    }

    Write-Host ""
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "  |  $Service" -ForegroundColor Yellow
    Write-Host "  |  Opening devicelogin in browser..." -ForegroundColor Cyan
    Write-Host "  |  Enter the code shown BELOW this box" -ForegroundColor Yellow
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Yellow
    try { Start-Process "msedge.exe" -ArgumentList $Url -ErrorAction Stop }
    catch { try { Start-Process $Url } catch { } }
    Write-Host ""
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

    # Disable WAM broker BEFORE any connection
    $env:MSAL_ALLOW_BROKER = '0'

    # ── 1. Microsoft Graph ────────────────────────────────────────────────────
    Write-Host "  [*] Microsoft Graph..." -ForegroundColor Cyan
    try {
        $scopes = @(
            'User.Read.All','Group.Read.All','Directory.Read.All',
            'Policy.Read.All','AuditLog.Read.All','Application.Read.All',
            'RoleManagement.Read.All','SecurityEvents.Read.All',
            'IdentityRiskyUser.Read.All','Reports.Read.All',
            'Organization.Read.All','Sites.Read.All',
            'DeviceManagementConfiguration.Read.All',
            'DeviceManagementApps.Read.All',
            'UserAuthenticationMethod.Read.All'
        )

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

        $ctx = Get-MgContext -ErrorAction Stop
        if ($ctx) {
            if ($isAppOnly) {
                $accountDomain = if ($OrganizationDomain) { $OrganizationDomain } else { $TenantId }
            } else {
                $accountDomain = ($ctx.Account -split '@')[-1]
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
                & $script:ShowDeviceCodeBox 'Microsoft Teams' 'https://microsoft.com/devicelogin'
                Connect-MicrosoftTeams -UseDeviceAuthentication -ErrorAction Stop | Out-Null
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
        if ($isAppOnly) {
            $orgDomain = if ($OrganizationDomain) {
                $OrganizationDomain
            } elseif ($result.TenantDomain -match '\.onmicrosoft\.com$') {
                $result.TenantDomain
            } else {
                throw "App-only EXO requires the .onmicrosoft.com routing domain via -OrganizationDomain."
            }
            Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertificateThumbprint `
                                   -Organization $orgDomain -ShowBanner:$false -ErrorAction Stop | Out-Null
        } else {
            # UseRPSSession bypasses MSAL/WAM entirely — avoids the RuntimeBroker
            # NullReferenceException that fires on a background thread in EOM v3.x
            $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
            if ($UserPrincipalName) { $exoParams['UserPrincipalName'] = $UserPrincipalName }
            try {
                # Try legacy RPS session first — no MSAL, no WAM, no crash
                $exoParams['UseRPSSession'] = $true
                Connect-ExchangeOnline @exoParams | Out-Null
            } catch [System.Management.Automation.ParameterBindingException] {
                # UseRPSSession removed in EOM 3.4.0 — fall back to device code
                $exoParams.Remove('UseRPSSession')
                & $script:ShowDeviceCodeBox 'Exchange Online' 'https://microsoft.com/devicelogin'
                try {
                    $exoParams['Device'] = $true
                    Connect-ExchangeOnline @exoParams | Out-Null
                } catch [System.Management.Automation.ParameterBindingException] {
                    $exoParams.Remove('Device')
                    Connect-ExchangeOnline @exoParams | Out-Null
                }
            } catch {
                # UseRPSSession might throw a different error if deprecated but present
                # Try the version check approach
                $exoParams.Remove('UseRPSSession')
                & $script:ShowDeviceCodeBox 'Exchange Online' 'https://microsoft.com/devicelogin'
                try {
                    $exoParams['Device'] = $true
                    Connect-ExchangeOnline @exoParams | Out-Null
                } catch [System.Management.Automation.ParameterBindingException] {
                    $exoParams.Remove('Device')
                    Connect-ExchangeOnline @exoParams | Out-Null
                }
            }
        }
        $result['EXO'] = $true
        Write-Host "  [+] Exchange Online connected" -ForegroundColor Green
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
                # Force device code auth — WAM broker causes NullReferenceException
                # on background thread when no interactive UI parent exists
                $env:MSAL_ALLOW_BROKER = '0'
                $env:MSAL_DISABLE_TOKENBROKER = '1'

                $ippsParams = @{
                    ShowBanner          = $false
                    ErrorAction         = 'Stop'
                    UseDeviceAuthentication = $true
                }
                if ($UserPrincipalName) { $ippsParams['UserPrincipalName'] = $UserPrincipalName }

                Write-Host "  [*] Purview requires device code auth — open browser:" -ForegroundColor Cyan
                Write-Host "      https://microsoft.com/devicelogin" -ForegroundColor Yellow
                Write-Host "      Sign in as $UserPrincipalName" -ForegroundColor Yellow

                # Fallback if UseDeviceAuthentication param not available in older module
                try {
                    Connect-IPPSSession @ippsParams | Out-Null
                } catch [System.Management.Automation.ParameterBindingException] {
                    $ippsParams.Remove('UseDeviceAuthentication')
                    $ippsParams['Device'] = $true
                    try {
                        Connect-IPPSSession @ippsParams | Out-Null
                    } catch [System.Management.Automation.ParameterBindingException] {
                        $ippsParams.Remove('Device')
                        Connect-IPPSSession @ippsParams | Out-Null
                    }
                }
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

    Write-Host ""
    Write-Output $result
}

function Disconnect-NRGServices {
    [CmdletBinding()] param()
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-PnPOnline -ErrorAction SilentlyContinue | Out-Null } catch {}
    Write-Host "[-] Sessions disconnected." -ForegroundColor DarkGray
}
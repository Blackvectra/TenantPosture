#
# Connect-NRGServices.ps1
# Interactive browser authentication for all M365 services.
#
# REPLACES device code flow — interactive browser opens automatically per service,
# user logs in with MFA normally, browser closes, connection confirmed.
# No codes to copy, no 15-minute open windows, no AiTM exposure.
#
# CONNECTION ORDER MATTERS (MSAL assembly conflict prevention):
#   1. Graph  — loads MSAL at the version Graph SDK requires
#   2. Teams  — shares Graph MSAL cleanly when loaded second
#   3. EXO    — after Graph+Teams to avoid MSAL conflicts
#   4. IPPS   — after EXO (same module)
#   5. PnP    — last, reuses Graph token
#
# GRAPH SUB-MODULE PRE-IMPORT (assembly conflict prevention):
#   Microsoft.Graph.Authentication is locked into the AppDomain by Connect-MgGraph.
#   Sub-modules must be imported BEFORE Connect-MgGraph or their auto-import
#   triggers an assembly conflict at collection time.
#   Reference: github.com/microsoftgraph/msgraph-sdk-powershell/issues/3394
#

function Connect-NRGServices {
    [CmdletBinding()]
    param(
        [string] $UserPrincipalName,
        [switch] $SkipPurview,
        [switch] $SkipTeams,
        [switch] $SkipSharePoint
    )

    $result = [hashtable]@{
        Graph        = $false
        EXO          = $false
        IPPSSession  = $false
        Teams        = $false
        SharePoint   = $false
        TenantDomain = $null
        TenantId     = $null
    }

    # ── 1. Microsoft Graph (MUST BE FIRST) ────────────────────────────────────
    Write-Host "  [*] Microsoft Graph — browser will open for login..." -ForegroundColor Cyan
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

        # Pre-import Graph sub-modules BEFORE Connect-MgGraph
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

        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop

        $ctx = Get-MgContext -ErrorAction Stop
        if ($ctx) {
            $result['Graph']        = $true
            $result['TenantId']     = "$($ctx.TenantId)"
            $result['TenantDomain'] = ($ctx.Account -split '@')[-1]
            Write-Host "  [+] Graph — $($ctx.Account)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Graph: $($_.Exception.Message)" -ForegroundColor Yellow
        Register-NRGException -Source 'Connect-Graph' -Message $_.Exception.Message
    }

    # ── 2. Microsoft Teams (BEFORE EXO) ──────────────────────────────────────
    if (-not $SkipTeams) {
        Write-Host "  [*] Microsoft Teams — browser will open for login..." -ForegroundColor Cyan
        try {
            if (-not (Get-Module -ListAvailable -Name MicrosoftTeams -ErrorAction SilentlyContinue)) {
                throw 'Run: Install-Module MicrosoftTeams -Scope CurrentUser -Force'
            }
            Import-Module MicrosoftTeams -ErrorAction Stop -WarningAction SilentlyContinue
            $teamsParams = @{ ErrorAction = 'Stop' }
            if ($UserPrincipalName) { $teamsParams['AccountId'] = $UserPrincipalName }
            Connect-MicrosoftTeams @teamsParams | Out-Null
            $result['Teams'] = $true
            Write-Host "  [+] Teams connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Teams: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-Teams' -Message $_.Exception.Message
        }
    }

    # ── 3. Exchange Online ────────────────────────────────────────────────────
    Write-Host "  [*] Exchange Online — browser will open for login..." -ForegroundColor Cyan
    try {
        $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($UserPrincipalName) { $exoParams['UserPrincipalName'] = $UserPrincipalName }
        Connect-ExchangeOnline @exoParams | Out-Null
        $result['EXO'] = $true
        Write-Host "  [+] Exchange Online connected" -ForegroundColor Green
    } catch {
        Write-Host "  [!] EXO: $($_.Exception.Message)" -ForegroundColor Yellow
        Register-NRGException -Source 'Connect-EXO' -Message $_.Exception.Message
    }

    # ── 4. Purview / Security & Compliance ───────────────────────────────────
    if (-not $SkipPurview) {
        Write-Host "  [*] Purview / Security and Compliance — browser will open for login..." -ForegroundColor Cyan
        try {
            $ippsParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
            if ($UserPrincipalName) { $ippsParams['UserPrincipalName'] = $UserPrincipalName }
            Connect-IPPSSession @ippsParams | Out-Null
            $result['IPPSSession'] = $true
            Write-Host "  [+] Purview connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Purview: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-IPPS' -Message $_.Exception.Message
        }
    }

    # ── 5. SharePoint Online via PnP ─────────────────────────────────────────
    if (-not $SkipSharePoint -and $result['TenantDomain']) {
        Write-Host "  [*] SharePoint Online — browser will open for login..." -ForegroundColor Cyan
        try {
            if (-not (Get-Module -ListAvailable -Name PnP.PowerShell -ErrorAction SilentlyContinue)) {
                throw 'Run: Install-Module PnP.PowerShell -Scope CurrentUser -Force'
            }
            Import-Module PnP.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
            $prefix = ($result['TenantDomain'] -split '\.')[0]
            $spoUrl = "https://$prefix-admin.sharepoint.com"
            Connect-PnPOnline -Url $spoUrl -Interactive -ErrorAction Stop | Out-Null
            $result['SharePoint'] = $true
            Write-Host "  [+] SharePoint connected ($spoUrl)" -ForegroundColor Green
        } catch {
            Write-Host "  [!] SharePoint: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-SharePoint' -Message $_.Exception.Message
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

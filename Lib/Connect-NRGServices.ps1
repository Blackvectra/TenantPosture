#
# Connect-NRGServices.ps1
# Device code authentication for all M365 services.
#
# Returns hashtable indicating which services connected successfully.
# Failures are non-fatal - collectors will register coverage as Failed for their domain.
#

function Connect-NRGServices {
    [CmdletBinding()]
    param(
        [string[]] $Services = @('Graph','EXO','IPPSSession','Teams','SharePoint'),
        [string]   $UserPrincipalName,
        [switch]   $SkipPurview,
        [switch]   $SkipTeams,
        [switch]   $SkipSharePoint
    )

    $result = @{
        Graph       = $false
        EXO         = $false
        IPPSSession = $false
        Teams       = $false
        SharePoint  = $false
        TenantDomain = $null
        TenantId     = $null
    }

    # ── Microsoft Graph (device code) ───────────────────────────────────────
    if ('Graph' -in $Services) {
        Write-Host "[*] Connecting Microsoft Graph (device code)..." -ForegroundColor Cyan
        try {
            $scopes = @(
                'User.Read.All'
                'Group.Read.All'
                'Directory.Read.All'
                'Policy.Read.All'
                'AuditLog.Read.All'
                'Application.Read.All'
                'RoleManagement.Read.All'
                'SecurityEvents.Read.All'
                'IdentityRiskyUser.Read.All'
                'Reports.Read.All'
                'Organization.Read.All'
                'Sites.Read.All'
                'DeviceManagementConfiguration.Read.All'
                'DeviceManagementApps.Read.All'
            )

            # Increase timeout to 300s - user has 5 min to enter device code
            Connect-MgGraph -Scopes $scopes -UseDeviceCode -NoWelcome -ErrorAction Stop
            $ctx = Get-MgContext
            if ($ctx) {
                $result.Graph = $true
                $result.TenantId = $ctx.TenantId
                if ($ctx.Account) {
                    $result.TenantDomain = ($ctx.Account -split '@')[-1]
                }
                Write-Host "  [+] Microsoft Graph connected ($($ctx.Account))" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Graph connection failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-NRGServices' -Message "Graph: $($_.Exception.Message)"
        }
    }

    # ── Exchange Online (device code) ───────────────────────────────────────
    if ('EXO' -in $Services) {
        Write-Host "[*] Connecting Exchange Online (device code)..." -ForegroundColor Cyan
        try {
            $exoParams = @{
                Device      = $true
                ShowBanner  = $false
                ErrorAction = 'Stop'
            }
            if ($UserPrincipalName) { $exoParams['UserPrincipalName'] = $UserPrincipalName }

            Connect-ExchangeOnline @exoParams
            $result.EXO = $true
            Write-Host "  [+] Exchange Online connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Exchange Online failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-NRGServices' -Message "EXO: $($_.Exception.Message)"
        }
    }

    # ── Security & Compliance Center (Purview) ──────────────────────────────
    if ('IPPSSession' -in $Services -and -not $SkipPurview) {
        Write-Host "[*] Connecting Security & Compliance Center (device code)..." -ForegroundColor Cyan
        try {
            $ippsParams = @{
                Device      = $true
                ShowBanner  = $false
                ErrorAction = 'Stop'
            }
            if ($UserPrincipalName) { $ippsParams['UserPrincipalName'] = $UserPrincipalName }

            # Try -Device first (newer module), fall back to devicecode approach
            try {
                Connect-IPPSSession @ippsParams
            } catch {
                # Older ExchangeOnlineManagement module uses different param
                $ippsParamsFallback = @{ ShowBanner = $false; ErrorAction = 'Stop' }
                if ($UserPrincipalName) { $ippsParamsFallback['UserPrincipalName'] = $UserPrincipalName }
                Connect-IPPSSession @ippsParamsFallback
            }
            $result.IPPSSession = $true
            Write-Host "  [+] Security & Compliance connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] IPPSSession failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-NRGServices' -Message "IPPSSession: $($_.Exception.Message)"
        }
    }

    # ── Microsoft Teams ─────────────────────────────────────────────────────
    if ('Teams' -in $Services -and -not $SkipTeams) {
        Write-Host "[*] Connecting Microsoft Teams (device code)..." -ForegroundColor Cyan
        try {
            if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
                throw 'MicrosoftTeams module not installed. Run: Install-Module MicrosoftTeams -Scope CurrentUser'
            }
            Import-Module MicrosoftTeams -ErrorAction Stop
            Connect-MicrosoftTeams -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            $result.Teams = $true
            Write-Host "  [+] Microsoft Teams connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Teams failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-NRGServices' -Message "Teams: $($_.Exception.Message)"
        }
    }

    # ── SharePoint Online (PnP.PowerShell, device code) ─────────────────────
    if ('SharePoint' -in $Services -and -not $SkipSharePoint -and $result.TenantDomain) {
        Write-Host "[*] Connecting SharePoint Online (device code)..." -ForegroundColor Cyan
        try {
            if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
                throw 'PnP.PowerShell module not installed. Run: Install-Module PnP.PowerShell -Scope CurrentUser'
            }
            Import-Module PnP.PowerShell -ErrorAction Stop

            $tenantPrefix = ($result.TenantDomain -split '\.')[0]
            $spoAdminUrl  = "https://$tenantPrefix-admin.sharepoint.com"

            Connect-PnPOnline -Url $spoAdminUrl -DeviceLogin -ErrorAction Stop
            $result.SharePoint = $true
            Write-Host "  [+] SharePoint Online connected ($spoAdminUrl)" -ForegroundColor Green
        } catch {
            Write-Host "  [!] SharePoint failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-NRGServices' -Message "SharePoint: $($_.Exception.Message)"
        }
    }

    return $result
}

function Disconnect-NRGServices {
    [CmdletBinding()] param()

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-PnPOnline -ErrorAction SilentlyContinue | Out-Null } catch {}

    Write-Host "[-] All M365 sessions disconnected" -ForegroundColor DarkGray
}

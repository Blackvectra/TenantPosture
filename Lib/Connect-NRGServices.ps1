#
# Connect-NRGServices.ps1
# Authenticates to all M365 services required for NRG-Assessment.
#
# Auth model:
#   Graph       — interactive browser (SCuBA pattern, no device code)
#   Teams       — device code
#   EXO         — device code
#   IPPS        — device code
#
# WAM broker disabled globally at function entry ($env:MSAL_ALLOW_BROKER = '0').
# This prevents RuntimeBroker NullReferenceException on machines where the
# Windows Authentication Manager broker is unavailable or misconfigured.
# Must be set before ANY MSAL token acquisition, not just Graph.
#
# CONNECTION ORDER MATTERS (MSAL assembly conflict prevention):
#   1. Graph  — loads MSAL at the version Graph SDK requires
#   2. Teams  — must follow Graph to share MSAL cleanly
#   3. EXO    — after Graph + Teams
#   4. IPPS   — after EXO (same underlying module)
#
# GRAPH SUB-MODULE PRE-IMPORT:
#   Sub-modules must be imported BEFORE Connect-MgGraph.
#   Auto-import after Connect-MgGraph locks the AppDomain assembly version
#   and causes conflicts at collection time.
#   Ref: github.com/microsoftgraph/msgraph-sdk-powershell/issues/3394
#

$script:ShowDeviceCodeBox = {
    param([string]$Service, [string]$Url)
    Write-Host ""
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "  |  $Service" -ForegroundColor Yellow
    Write-Host "  |  Opening devicelogin in Edge..." -ForegroundColor Cyan
    Write-Host "  |  Enter the code shown BELOW this box" -ForegroundColor Yellow
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Yellow
    try { Start-Process "msedge.exe" -ArgumentList $Url -ErrorAction Stop } catch { try { Start-Process $Url } catch {} }
    Write-Host ""
}

function Connect-NRGServices {
    [CmdletBinding()]
    param(
        [string] $UserPrincipalName,
        [switch] $SkipPurview,
        [switch] $SkipTeams,
        [switch] $SkipSharePoint
    )

    # Disable WAM broker globally — must be set before any MSAL token acquisition.
    # Prevents RuntimeBroker NullReferenceException on all services, not just Graph.
    $env:MSAL_ALLOW_BROKER = '0'

    $result = [hashtable]@{
        Graph        = $false
        EXO          = $false
        IPPSSession  = $false
        Teams        = $false
        SharePoint   = $false
        TenantDomain = $null
        TenantId     = $null
    }

    # ── 1. Microsoft Graph — interactive browser (MUST BE FIRST) ─────────────
    Write-Host "  [*] Microsoft Graph — browser will open for login..." -ForegroundColor Cyan
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
            'UserAuthenticationMethod.Read.All'
            'Sites.Read.All'
            'DeviceManagementConfiguration.Read.All'
            'DeviceManagementApps.Read.All'
        )

        # Pre-import Graph sub-modules BEFORE Connect-MgGraph
        $graphSubModules = @(
            'Microsoft.Graph.Reports'
            'Microsoft.Graph.Identity.Governance'
            'Microsoft.Graph.Identity.SignIns'
            'Microsoft.Graph.Users'
            'Microsoft.Graph.Sites'
            'Microsoft.Graph.DeviceManagement'
        )
        foreach ($gm in $graphSubModules) {
            if (Get-Module -ListAvailable -Name $gm -ErrorAction SilentlyContinue) {
                Import-Module $gm -ErrorAction SilentlyContinue -WarningAction SilentlyContinue 3>$null
            }
        }

        # Interactive browser auth — no device code, no WAM broker
        $mgParams = @{ Scopes = $scopes; NoWelcome = $true; ErrorAction = 'Stop' }
        if ($UserPrincipalName) { $mgParams['LoginHint'] = $UserPrincipalName }
        Connect-MgGraph @mgParams | Out-Null

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

    # ── 2. Microsoft Teams — device code (BEFORE EXO) ────────────────────────
    if (-not $SkipTeams) {
        Write-Host "  [*] Microsoft Teams..." -ForegroundColor Cyan
        try {
            if (-not (Get-Module -ListAvailable -Name MicrosoftTeams -ErrorAction SilentlyContinue)) {
                throw 'MicrosoftTeams module not installed. Run: Install-Module MicrosoftTeams -Scope CurrentUser -Force'
            }
            Import-Module MicrosoftTeams -ErrorAction Stop -WarningAction SilentlyContinue
            & $script:ShowDeviceCodeBox 'Microsoft Teams' 'https://microsoft.com/devicelogin'
            Connect-MicrosoftTeams -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            $result['Teams'] = $true
            Write-Host "  [+] Teams connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Teams: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-Teams' -Message $_.Exception.Message
        }
    }

    # ── 3. Exchange Online — device code ─────────────────────────────────────
    Write-Host "  [*] Exchange Online..." -ForegroundColor Cyan
    & $script:ShowDeviceCodeBox 'Exchange Online' 'https://microsoft.com/devicelogin'
    try {
        $p = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($UserPrincipalName) { $p['UserPrincipalName'] = $UserPrincipalName }
        try {
            $p['Device'] = $true
            Connect-ExchangeOnline @p | Out-Null
        } catch [System.Management.Automation.ParameterBindingException] {
            $p.Remove('Device')
            Connect-ExchangeOnline @p | Out-Null
        }
        $result['EXO'] = $true
        Write-Host "  [+] Exchange Online connected" -ForegroundColor Green
    } catch {
        Write-Host "  [!] EXO: $($_.Exception.Message)" -ForegroundColor Yellow
        Register-NRGException -Source 'Connect-EXO' -Message $_.Exception.Message
    }

    # ── 4. Purview / Security & Compliance — device code ─────────────────────
    if (-not $SkipPurview) {
        Write-Host "  [*] Purview / Security and Compliance..." -ForegroundColor Cyan
        & $script:ShowDeviceCodeBox 'Security and Compliance' 'https://microsoft.com/devicelogin'
        try {
            $p = @{ ShowBanner = $false; ErrorAction = 'Stop' }
            if ($UserPrincipalName) { $p['UserPrincipalName'] = $UserPrincipalName }
            try {
                $p['Device'] = $true
                Connect-IPPSSession @p | Out-Null
            } catch [System.Management.Automation.ParameterBindingException] {
                $p.Remove('Device')
                Connect-IPPSSession @p | Out-Null
            }
            $result['IPPSSession'] = $true
            Write-Host "  [+] Purview connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Purview: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-IPPS' -Message $_.Exception.Message
        }
    }

    # ── 5. SharePoint Online via PnP (deferred — called post-collection) ──────
    # PnP loads Graph.Core which conflicts with Graph SDK sub-modules already
    # loaded. Only connect here if explicitly called outside the orchestrator.
    if (-not $SkipSharePoint -and $result['TenantDomain']) {
        Write-Host "  [*] SharePoint Online..." -ForegroundColor Cyan
        try {
            if (-not (Get-Module -ListAvailable -Name PnP.PowerShell -ErrorAction SilentlyContinue)) {
                throw 'PnP.PowerShell module not installed. Run: Install-Module PnP.PowerShell -Scope CurrentUser -Force'
            }
            Import-Module PnP.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
            $prefix = ($result['TenantDomain'] -split '\.')[0]
            $spoUrl = "https://$prefix-admin.sharepoint.com"
            & $script:ShowDeviceCodeBox 'SharePoint Online' 'https://microsoft.com/devicelogin'
            Connect-PnPOnline -Url $spoUrl -PnPManagementShell -LaunchBrowser -ErrorAction Stop | Out-Null
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

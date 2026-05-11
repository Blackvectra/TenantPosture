#
# Connect-NRGServices.ps1
# Device code auth for all M365 services.
#
# CONNECTION ORDER MATTERS (MSAL assembly conflict prevention):
#   1. Graph  — loads MSAL at the version Graph SDK requires
#   2. Teams  — shares Graph MSAL cleanly when loaded second
#   3. EXO    — after Graph+Teams to avoid MSAL conflicts
#   4. IPPS   — after EXO (same module)
#   5. PnP    — last, reuses Graph token
#
# Reference: github.com/microsoftgraph/msgraph-sdk-powershell/issues/3394
#

# Script-scoped scriptblock (NOT a function) so it does not get exported
# and does not trigger the "restricted characters" module warning
$script:ShowDeviceCodeBox = {
    param([string]$Service, [string]$Url)
    $inner = "  $Service  "
    $width = [Math]::Max(64, $inner.Length + 4)
    $line  = [string]('─' * $width)
    $pad   = ' ' * ($width - $inner.Length)
    Write-Host ""
    Write-Host "  ┌$line┐" -ForegroundColor Yellow
    Write-Host "  │$inner$pad│" -ForegroundColor Yellow
    Write-Host "  │  $(' ' * ($width - 2))│" -ForegroundColor Yellow

    # OSC 8 clickable hyperlink (works in Windows Terminal, VS Code, iTerm2)
    $link = "`e]8;;$Url`e\$Url`e]8;;`e\"
    $linkPad = ' ' * ($width - $Url.Length - 12)
    Write-Host "  │  Step 1: " -ForegroundColor Yellow -NoNewline
    Write-Host $link -ForegroundColor Cyan -NoNewline
    Write-Host "$linkPad│" -ForegroundColor Yellow

    $step2 = "Step 2: Enter the code shown BELOW this box"
    $step2pad = ' ' * ($width - $step2.Length - 4)
    Write-Host "  │  $step2$step2pad│" -ForegroundColor Yellow
    Write-Host "  └$line┘" -ForegroundColor Yellow
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
    Write-Host "  [*] Microsoft Graph..." -ForegroundColor Cyan
    & $script:ShowDeviceCodeBox 'Microsoft Graph' 'https://microsoft.com/devicelogin'
    try {
        $scopes = @(
            'User.Read.All','Group.Read.All','Directory.Read.All',
            'Policy.Read.All','AuditLog.Read.All','Application.Read.All',
            'RoleManagement.Read.All','SecurityEvents.Read.All',
            'IdentityRiskyUser.Read.All','Reports.Read.All',
            'Organization.Read.All','Sites.Read.All',
            'DeviceManagementConfiguration.Read.All',
            'DeviceManagementApps.Read.All'
        )
        # -InformationAction Continue required: device code prints via Write-Information (stream 6)
        # Device code text goes to pipeline output - pipe to Out-Host so it displays
        # Reference: github.com/microsoftgraph/msgraph-sdk-powershell/issues/2798
        $env:MSAL_ALLOW_BROKER = '0'  # Disable WAM to ensure device code displays
        Connect-MgGraph -Scopes $scopes -UseDeviceCode -NoWelcome -ErrorAction Stop | Out-Host
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
        Write-Host "  [*] Microsoft Teams..." -ForegroundColor Cyan
        try {
            if (-not (Get-Module -ListAvailable -Name MicrosoftTeams -ErrorAction SilentlyContinue)) {
                throw 'Run: Install-Module MicrosoftTeams -Scope CurrentUser -Force'
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

    # ── 3. Exchange Online ────────────────────────────────────────────────────
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

    # ── 4. Purview / Security & Compliance ───────────────────────────────────
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

    # ── 5. SharePoint Online via PnP ─────────────────────────────────────────
    if (-not $SkipSharePoint -and $result['TenantDomain']) {
        Write-Host "  [*] SharePoint Online..." -ForegroundColor Cyan
        try {
            if (-not (Get-Module -ListAvailable -Name PnP.PowerShell -ErrorAction SilentlyContinue)) {
                throw 'Run: Install-Module PnP.PowerShell -Scope CurrentUser -Force'
            }
            Import-Module PnP.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
            $prefix = ($result['TenantDomain'] -split '\.')[0]
            $spoUrl = "https://$prefix-admin.sharepoint.com"
            & $script:ShowDeviceCodeBox "SharePoint Online" 'https://microsoft.com/devicelogin'
            Connect-PnPOnline -Url $spoUrl -DeviceLogin -ErrorAction Stop | Out-Null
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

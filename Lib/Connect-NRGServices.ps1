#
# Connect-NRGServices.ps1
# Authenticates to all M365 services required for NRG-Assessment.
#
# Auth model:
#   Graph       — interactive browser (SCuBA pattern)
#   Teams       — device code
#   EXO         — device code (-Device with ParameterBindingException fallback)
#   IPPS        — device code via direct MSAL.NET token acquisition
#                 Bypasses EXO module's internal MSAL which initialises WAM broker
#                 even on device code flows in PS7 on some machines.
#                 MSAL.NET is already loaded by the Graph SDK — no new dependency.
#
# Disconnect-ExchangeOnline intentionally NOT called in Disconnect-NRGServices.
# EXO 3.3+ crashes PowerShell on ClearAllTokensAsync (background thread,
# uncatchable) when WAM is unavailable. Sessions expire on process exit.
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

    $result = [hashtable]@{
        Graph        = $false
        EXO          = $false
        IPPSSession  = $false
        Teams        = $false
        SharePoint   = $false
        TenantDomain = $null
        TenantId     = $null
    }

    # ── Try EXO 3.2.0 in PS5.1 only (assembly issue prevents load in PS7) ────
    $isPS7 = $PSVersionTable.PSVersion.Major -ge 6
    if (-not $isPS7) {
        $exa320 = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
                   Where-Object { $_.Version -eq '3.2.0' } | Select-Object -First 1
        if ($exa320) {
            try {
                Import-Module ExchangeOnlineManagement -RequiredVersion 3.2.0 `
                    -Force -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                Write-Host "  [i] ExchangeOnlineManagement 3.2.0 loaded" -ForegroundColor DarkGray
            } catch {}
        }
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

        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop | Out-Null
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
                throw 'MicrosoftTeams not installed. Run: Install-Module MicrosoftTeams -Scope CurrentUser -Force'
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

    # ── 4. Purview — MSAL device code bypass (avoids EXO module WAM init) ─────
    #
    # Root cause: Connect-IPPSSession internally calls InteractiveRequest which
    # initialises RuntimeBroker (WAM) before device code. On PS7 in console
    # context the RuntimeBroker constructor throws NullReferenceException because
    # CoreUIParent has no window handle.
    #
    # Fix: acquire the IPPS token ourselves using MSAL.NET (already loaded by
    # the Graph SDK) with an explicit DeviceCode flow. DeviceCode does not
    # initialise the WAM broker. Pass the token to Connect-IPPSSession -AccessToken.
    #
    if (-not $SkipPurview) {
        Write-Host "  [*] Purview / Security and Compliance..." -ForegroundColor Cyan

        $ippsConnected = $false

        # First try: standard -Device flag (works on machines without WAM restriction)
        try {
            $p = @{ ShowBanner = $false; ErrorAction = 'Stop' }
            if ($UserPrincipalName) { $p['UserPrincipalName'] = $UserPrincipalName }
            & $script:ShowDeviceCodeBox 'Security and Compliance' 'https://microsoft.com/devicelogin'
            try {
                $p['Device'] = $true
                Connect-IPPSSession @p | Out-Null
            } catch [System.Management.Automation.ParameterBindingException] {
                $p.Remove('Device')
                Connect-IPPSSession @p | Out-Null
            }
            $result['IPPSSession'] = $true
            $ippsConnected         = $true
            Write-Host "  [+] Purview connected" -ForegroundColor Green
        } catch {
            $e = $_.Exception.Message
            # WAM crash or other failure — fall through to MSAL bypass
            if ($e -notmatch 'NullReference|RuntimeBroker|Object reference|canceled') {
                Write-Host "  [!] Purview (standard): $e" -ForegroundColor DarkYellow
            }
        }

        # Second try: direct MSAL.NET device code — no WAM broker involved
        # The PowerShell scriptblock callback fails on threadpool threads (no Runspace).
        # Fix: compile a pure C# lambda via Add-Type — no scriptblock, no Runspace needed.
        if (-not $ippsConnected -and $result['TenantId'] -and $result['TenantDomain']) {
            Write-Host "  [i] WAM blocked — acquiring IPPS token via MSAL device code..." -ForegroundColor DarkGray
            & $script:ShowDeviceCodeBox 'Security and Compliance' 'https://microsoft.com/devicelogin'
            try {
                $tenantId  = $result['TenantId']
                $tenantDom = $result['TenantDomain']
                $exoAppId  = 'fb78d390-0c51-40cd-8e17-fdbfab77341b'
                $ippsScope = [string[]]@('https://ps.compliance.protection.outlook.com/.default')

                # Compile C# callback — pure .NET lambda, no PS Runspace required on callback thread.
                # Must reference both MSAL and System.Console assemblies explicitly —
                # .NET 6 splits BCL into separate assemblies; Add-Type doesn't include them by default.
                if (-not ([System.Management.Automation.PSTypeName]'NRGIPPSHelper').Type) {
                    $msalAsmPath    = [Microsoft.Identity.Client.PublicClientApplicationBuilder].Assembly.Location
                    $consoleAsmPath = [System.Console].Assembly.Location
                    Add-Type -TypeDefinition @"
public static class NRGIPPSHelper {
    public static System.Func<Microsoft.Identity.Client.DeviceCodeResult,
                               System.Threading.Tasks.Task> GetCallback() {
        return dcr => {
            System.Console.WriteLine(dcr.Message);
            return System.Threading.Tasks.Task.CompletedTask;
        };
    }
}
"@ -ReferencedAssemblies $msalAsmPath, $consoleAsmPath -ErrorAction Stop
                }
                $dcCallback = [NRGIPPSHelper]::GetCallback()

                $msalBuilder = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($exoAppId)
                $msalBuilder = $msalBuilder.WithAuthority("https://login.microsoftonline.com/$tenantId/")
                $msalApp     = $msalBuilder.Build()

                $tokenBuilder = $msalApp.AcquireTokenWithDeviceCode($ippsScope, $dcCallback)
                $tokenTask    = $tokenBuilder.ExecuteAsync()
                $tokenResult  = $tokenTask.GetAwaiter().GetResult()

                Connect-IPPSSession -AccessToken $tokenResult.AccessToken -DelegatedOrganization $tenantDom -ShowBanner:$false -ErrorAction Stop | Out-Null

                $result['IPPSSession'] = $true
                $ippsConnected         = $true
                Write-Host "  [+] Purview connected (MSAL bypass)" -ForegroundColor Green
            } catch {
                Write-Host "  [!] Purview: $($_.Exception.Message)" -ForegroundColor Yellow
                Register-NRGException -Source 'Connect-IPPS' -Message $_.Exception.Message
            }
        }
    }

    # ── 5. SharePoint Online via PnP ─────────────────────────────────────────
    if (-not $SkipSharePoint -and $result['TenantDomain']) {
        Write-Host "  [*] SharePoint Online..." -ForegroundColor Cyan
        try {
            if (-not (Get-Module -ListAvailable -Name PnP.PowerShell -ErrorAction SilentlyContinue)) {
                throw 'PnP.PowerShell not installed. Run: Install-Module PnP.PowerShell -Scope CurrentUser -Force'
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
    # Disconnect-ExchangeOnline intentionally omitted.
    # EXO 3.3+ crashes on ClearAllTokensAsync (background thread, uncatchable)
    # when WAM broker is unavailable. Sessions expire on process exit.
    try { Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disconnect-PnPOnline -ErrorAction SilentlyContinue | Out-Null } catch {}
    Write-Host "[-] Sessions disconnected." -ForegroundColor DarkGray
}
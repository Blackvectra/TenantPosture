#
# Connect-NRGServices.ps1
# Interactive browser authentication for all M365 services.
#
# Graph uses interactive browser auth (no device code).
# Teams, EXO, IPPS, SharePoint use device code — required when running
# elevated (as Administrator) because WAM broker fails in that context.
#
# CONNECTION ORDER MATTERS (MSAL assembly conflict prevention):
#   1. Graph  — loads MSAL at the version Graph SDK requires
#   2. Teams  — shares Graph MSAL cleanly when loaded second
#   3. EXO    — after Graph+Teams to avoid MSAL conflicts
#   4. IPPS   — after EXO (same module)
#   5. PnP    — last, deferred to post-collection in orchestrator
#
# GRAPH SUB-MODULE PRE-IMPORT (assembly conflict prevention):
#   Microsoft.Graph.Authentication is locked into the AppDomain by Connect-MgGraph.
#   Sub-modules must be imported BEFORE Connect-MgGraph or their auto-import triggers
#   an assembly conflict at collection time.
#   Reference: github.com/microsoftgraph/msgraph-sdk-powershell/issues/3394
#
# WAM BROKER NOTE:
#   $env:MSAL_ALLOW_BROKER = '0' is set before Teams/EXO/IPPS connections.
#   WAM (Windows Authentication Manager) requires a non-elevated user context.
#   Running pwsh as Administrator causes RuntimeBroker NullReferenceException.
#   Disabling WAM forces MSAL to use browser/device code flow instead.
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

    # ── 1. Microsoft Graph (MUST BE FIRST — interactive browser) ─────────────
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
        # Forces assembly resolution before Connect-MgGraph locks the version in.
        # Reference: github.com/microsoftgraph/msgraph-sdk-powershell/issues/3394
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

        # Interactive browser — no device code for Graph
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

    # Disable WAM broker for all remaining connections.
    # WAM fails when pwsh is running elevated (as Administrator).
    # This forces MSAL to use device code / browser popup instead of WAM.
    $env:MSAL_ALLOW_BROKER = '0'

    # ── 2. Microsoft Teams (BEFORE EXO) ──────────────────────────────────────
    if (-not $SkipTeams) {
        Write-Host "  [*] Microsoft Teams — sign in when browser opens..." -ForegroundColor Cyan
        try {
            if (-not (Get-Module -ListAvailable -Name MicrosoftTeams -ErrorAction SilentlyContinue)) {
                throw 'Run: Install-Module MicrosoftTeams -Scope CurrentUser -Force'
            }
            Import-Module MicrosoftTeams -ErrorAction Stop -WarningAction SilentlyContinue
            Connect-MicrosoftTeams -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            $result['Teams'] = $true
            Write-Host "  [+] Teams connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Teams: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-Teams' -Message $_.Exception.Message
        }
    }

    # ── 3. Exchange Online ────────────────────────────────────────────────────
    Write-Host "  [*] Exchange Online — sign in when browser opens..." -ForegroundColor Cyan
    try {
        $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($UserPrincipalName) { $exoParams['UserPrincipalName'] = $UserPrincipalName }
        # Use Device flag to avoid WAM broker crash when running elevated
        try {
            $exoParams['Device'] = $true
            Connect-ExchangeOnline @exoParams | Out-Null
        } catch [System.Management.Automation.ParameterBindingException] {
            # Older EXO module version — no -Device param
            $exoParams.Remove('Device')
            Connect-ExchangeOnline @exoParams | Out-Null
        }
        $result['EXO'] = $true
        Write-Host "  [+] Exchange Online connected" -ForegroundColor Green
    } catch {
        Write-Host "  [!] EXO: $($_.Exception.Message)" -ForegroundColor Yellow
        Register-NRGException -Source 'Connect-EXO' -Message $_.Exception.Message
    }

    # ── 4. Purview / Security & Compliance ───────────────────────────────────
    if (-not $SkipPurview) {
        Write-Host "  [*] Purview / Security and Compliance — sign in when browser opens..." -ForegroundColor Cyan
        try {
            $ippsParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
            if ($UserPrincipalName) { $ippsParams['UserPrincipalName'] = $UserPrincipalName }
            try {
                $ippsParams['Device'] = $true
                Connect-IPPSSession @ippsParams | Out-Null
            } catch [System.Management.Automation.ParameterBindingException] {
                $ippsParams.Remove('Device')
                Connect-IPPSSession @ippsParams | Out-Null
            }
            $result['IPPSSession'] = $true
            Write-Host "  [+] Purview connected" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Purview: $($_.Exception.Message)" -ForegroundColor Yellow
            Register-NRGException -Source 'Connect-IPPS' -Message $_.Exception.Message
        }
    }

    # SharePoint is deferred to post-collection in Invoke-NRGAssessment.ps1
    # to avoid PnP loading an old Graph.Core assembly that breaks Graph cmdlets.

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

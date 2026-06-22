#Requires -Version 7.0
#
# Connect-NRGEmailAdminServices.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Admin-scope Graph connection for the unified Email-IR workflow.
#          Distinct from BOTH:
#            * Connect-NRGServices (21-scope posture assessment — keeps
#              its scope set unchanged so existing posture clients don't
#              suddenly see a Mail.Read.All consent prompt)
#            * Connect-NRGEmailServices (3-scope user-credential IR for
#              when the operator is signing in as the compromised user)
#
#          This connection is invoked by Invoke-NRGSignInTriage when the
#          operator runs the admin-driven workflow: sign in once as a
#          tenant admin, triage sign-in logs to find suspicious users,
#          then auto-dive into each flagged user's mailbox without a
#          per-user credential prompt.
#
# Scopes (7):
#   AuditLog.Read.All           — /auditLogs/signIns (the IoC source)
#   IdentityRiskyUser.Read.All  — /identityProtection/riskyUsers
#   Directory.Read.All          — tenant + user attribute reads, OAuth grants
#   User.Read.All               — display names, UPNs, account-enabled state
#   UserAuthenticationMethod.Read.All — registered MFA methods (EMAIL-4.2:
#                                 attacker-added phone/authenticator detection)
#   Mail.Read.All               — any user's mailbox under admin auth
#   MailboxSettings.Read.All    — any user's inbox rules + forwarding
#
# Note on Mail.Read.All: this is a sensitive, admin-tier scope. Some
# clients restrict this in their BAAs / MSP contracts. The orchestrator
# surfaces this clearly in its consent disclosure and supports
# -SkipMailDive to run triage WITHOUT requesting the mail scopes.

function Connect-NRGEmailAdminServices {
    [CmdletBinding()]
    param(
        [string] $TenantId,

        # Drop the two Mail.* scopes from the request when the operator
        # only wants sign-in triage and will run per-user Email-IR
        # separately with each user's credentials.
        [switch] $SkipMailDive
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    } catch {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft.Graph.Authentication module not installed. Run Install-NRGPrerequisites.ps1 first."
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -Verbose:$false

    $scopes = @(
        'AuditLog.Read.All',
        'IdentityRiskyUser.Read.All',
        'Directory.Read.All',
        'User.Read.All'
    )
    if (-not $SkipMailDive) {
        $scopes += 'Mail.Read.All'
        $scopes += 'MailboxSettings.Read.All'
        # v4.12.1: deep-dive also checks attacker-added MFA methods (EMAIL-4.2).
        # Grouped with the mail scopes because it's only consumed by the
        # per-user deep-dive — triage-only runs shouldn't prompt for it.
        $scopes += 'UserAuthenticationMethod.Read.All'
    }

    Write-Host "  [*] Connecting to Microsoft Graph (admin scope, IR triage)..." -ForegroundColor Cyan
    Write-Host "      Scopes requested ($($scopes.Count)):" -ForegroundColor DarkGray
    foreach ($s in $scopes) { Write-Host "        - $s" -ForegroundColor DarkGray }
    Write-Host "      A browser sign-in window will open. Authenticate as a TENANT ADMIN." -ForegroundColor Yellow
    if (-not $SkipMailDive) {
        Write-Host "      Mail.Read.All and MailboxSettings.Read.All are sensitive scopes." -ForegroundColor Yellow
        Write-Host "      They allow this tool to read any user's mailbox in the tenant —" -ForegroundColor Yellow
        Write-Host "      required for the deep-dive step. Use -SkipMailDive to triage" -ForegroundColor Yellow
        Write-Host "      sign-ins only, then run per-user IR separately." -ForegroundColor Yellow
    }

    $params = @{
        Scopes       = $scopes
        ContextScope = 'Process'
        NoWelcome    = $true
        ErrorAction  = 'Stop'
    }
    if ($TenantId) { $params['TenantId'] = $TenantId }

    Connect-MgGraph @params

    $ctx = Get-MgContext
    if (-not $ctx) { throw "Connect-MgGraph returned no context. Authentication failed." }

    Write-Host "  [+] Connected as admin: $($ctx.Account)" -ForegroundColor Green
    Write-Host "      Tenant: $($ctx.TenantId)" -ForegroundColor DarkGray

    # Verify the scopes we got actually contain what we requested. If the
    # admin consented to a subset (some tenants restrict consent), the
    # collector will fail in confusing ways downstream — surface here.
    $missing = @($scopes | Where-Object { $ctx.Scopes -notcontains $_ })
    if ($missing.Count -gt 0) {
        Write-Warning "Scope shortfall: $($missing -join ', ') was requested but the token does not carry it. The corresponding collectors will be skipped."
    }

    return $ctx
}

function Disconnect-NRGEmailAdminServices {
    [CmdletBinding()] param()
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
}

#Requires -Version 7.0
#
# Connect-NRGEmailServices.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Establish a delegated user-scope Microsoft Graph connection for
#          incident response (NRG-Email). Distinct from Connect-NRGServices,
#          which establishes a 21-scope admin connection for the posture
#          assessment. The IR tool runs with ONE user's credentials — the
#          compromised account — and reads only that user's mailbox + own
#          settings. No tenant-wide reads, no admin scopes.
#
# Scopes requested (delegated, user-only):
#   - User.Read              basic profile of /me
#   - Mail.Read              inbox, sent items, recoverable items
#   - MailboxSettings.Read   inbox rules, server-side forwarding
#
# Inputs:  -UserPrincipalName  optional UPN hint (Graph picks the device
#                              code flow regardless; this just pre-fills
#                              the browser prompt for the operator).
#          -TenantId           optional GUID. When the same operator
#                              runs IR against multiple tenants in one
#                              session, scoping to a specific tenant
#                              avoids the consumer-account fallthrough.
# Outputs: A connected Graph context. Caller must call Disconnect-NRGEmailServices
#          in a finally block.
#
# Security: TLS 1.2/1.3 enforced before any HTTPS call. Token cache is
#          process-scoped (-ContextScope Process) so credentials don't
#          persist after the orchestrator exits. No cert thumbprints,
#          no app-only flow — IR by definition is a user-credential
#          tool. If the compromised user has lost MFA persistence to
#          the attacker, the operator may need to use the recovery
#          flow themselves.

function Connect-NRGEmailServices {
    [CmdletBinding()]
    param(
        [string] $UserPrincipalName,
        [string] $TenantId
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # OWASP ASVS V11.2.2 — TLS 1.2/1.3 minimum before any HTTPS handshake.
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    } catch {
        # PS 7 on some platforms doesn't expose Tls13 in the enum; fall back
        # to Tls12. Microsoft endpoints already require 1.2+ so this is fine.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    # Verify Graph module is loaded.
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft.Graph.Authentication module not installed. Run Install-NRGPrerequisites.ps1 first."
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -Verbose:$false

    $scopes = @('User.Read', 'Mail.Read', 'MailboxSettings.Read')

    Write-Host "  [*] Connecting to Microsoft Graph (delegated, user-scope)..." -ForegroundColor Cyan
    Write-Host "      Scopes: $($scopes -join ', ')" -ForegroundColor DarkGray
    Write-Host "      A browser sign-in window will open. Authenticate as the COMPROMISED user." -ForegroundColor Yellow
    if ($UserPrincipalName) {
        Write-Host "      Expected UPN: $UserPrincipalName" -ForegroundColor DarkGray
    }

    $params = @{
        Scopes       = $scopes
        ContextScope = 'Process'
        NoWelcome    = $true
        ErrorAction  = 'Stop'
    }
    if ($TenantId) { $params['TenantId'] = $TenantId }

    Connect-MgGraph @params

    # Verify the connected identity actually matches the supplied UPN when
    # one was given. If the operator typed alice@corp.com but the browser
    # session signed in as bob@corp.com (browser session reuse), every
    # downstream /me/ call would read bob's mailbox and the IR report
    # would be for the wrong user — silently. This catches that.
    $ctx = Get-MgContext
    if (-not $ctx) {
        throw "Connect-MgGraph returned no context. Authentication failed."
    }
    if ($UserPrincipalName -and $ctx.Account -and ($ctx.Account -ne $UserPrincipalName)) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        throw "Connected as '$($ctx.Account)' but expected '$UserPrincipalName'. The browser session may have reused a different account. Sign out of M365 in the browser, re-run, and verify the prompt."
    }

    Write-Host "  [+] Connected as: $($ctx.Account)" -ForegroundColor Green
    Write-Host "      Tenant: $($ctx.TenantId)" -ForegroundColor DarkGray
    return $ctx
}

function Disconnect-NRGEmailServices {
    [CmdletBinding()] param()
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
}

#Requires -Version 7.0
#
# Connect-NRGExchangeOnlineOnly.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Sign in to Exchange Online and nothing else. Connect-NRGServices always
#          signs in to Microsoft Graph first and asks for 24 Graph scopes; a scan
#          that reads only Exchange recipients (the distribution-list scan) must
#          not ask for them. This connects Exchange, proves which tenant the
#          session belongs to, and returns that.
#
# Sets:     nothing (returns a connection summary)
# Consumes: nothing
# Cmdlets:  Connect-ExchangeOnline, Get-ConnectionInformation, Disconnect-ExchangeOnline
#           (ExchangeOnlineManagement). No Graph, no Teams, no Security & Compliance.
#
# TENANT PINNING
# --------------
# Interactive sign-in lands on whichever tenant the account belongs to, and an MSP
# operator belongs to many. -DelegatedOrganization points the session at a client
# under GDAP; -ExpectedTenantId is checked against the tenant the session actually
# reports, and a mismatch (or a tenant that cannot be read) disconnects and throws,
# so a worksheet is never written for the wrong client.
#
# ONE EXCHANGE SESSION PER PROCESS
# --------------------------------
# Get-NRGExoCommand resolves a cmdlet from "the" Exchange Online session. With two
# connected it could read a different tenant than the one just verified, so a
# session that is already open is reused only when the caller proves it is the
# right tenant (-ExpectedTenantId) or says to take it as it is (-ReuseSession);
# otherwise this stops and says to open a new PowerShell 7 window.

function Connect-NRGExchangeOnlineOnly {
    [CmdletBinding()]
    param(
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
        [string] $UserPrincipalName,

        # GDAP: the client's .onmicrosoft.com routing domain. Without it Exchange
        # connects to the signed-in operator's OWN organization.
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*\.onmicrosoft\.com$')]
        [string] $DelegatedOrganization,

        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string] $ExpectedTenantId,

        [switch] $ReuseSession
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    } catch {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    # Same broker settings Connect-NRGServices applies before any sign-in: modern
    # auth in the system browser, with the same MFA and Conditional Access.
    $env:MSAL_ALLOW_BROKER = '0'
    $env:MSAL_DISABLE_TOKENBROKER = '1'

    $exoCmd = Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue
    if (-not $exoCmd) {
        throw 'The ExchangeOnlineManagement module is not installed or not loadable. Run Install-NRGPrerequisites.ps1, then open a new PowerShell 7 window.'
    }
    # -DisableWAM exists from ExchangeOnlineManagement 3.7.2; passed only when the
    # installed module has it, so an older module still connects.
    $exoParamsMap = Get-NRGObjectField -Item $exoCmd -Key 'Parameters' -Default $null
    $disableWam = ($null -ne $exoParamsMap) -and [bool]$exoParamsMap.ContainsKey('DisableWAM')

    $getConnections = {
        if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return @() }
        try {
            return @(Get-ConnectionInformation -ErrorAction Stop | Where-Object {
                [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '') -eq 'Connected' -and
                -not (Test-NRGEopConnection -Connection $_)
            })
        } catch { return @() }
    }

    $reused = $false
    $existing = @(& $getConnections)
    if ($existing.Count -gt 0) {
        $existingTenant = [string](Get-NRGObjectField -Item $existing[-1] -Key 'TenantID' -Default '')
        $matchesExpected = $ExpectedTenantId -and $existingTenant -and ($existingTenant -eq $ExpectedTenantId)
        if ($ReuseSession -or $matchesExpected) {
            $reused = $true
        } else {
            $where = if ($existingTenant) { "tenant $existingTenant" } else { 'a tenant that could not be read' }
            throw "An Exchange Online session is already open in this window ($where). Open a NEW PowerShell 7 window and run the scan again, or pass -ReuseSession to use the open session as it is."
        }
    }

    if (-not $reused) {
        $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($disableWam)             { $exoParams['DisableWAM'] = $true }
        if ($UserPrincipalName)      { $exoParams['UserPrincipalName'] = $UserPrincipalName }
        if ($DelegatedOrganization)  { $exoParams['DelegatedOrganization'] = $DelegatedOrganization }
        Connect-ExchangeOnline @exoParams | Out-Null
    }

    $now = @(& $getConnections) | Select-Object -Last 1
    $tenantId = [string](Get-NRGObjectField -Item $now -Key 'TenantID' -Default '')
    if ($ExpectedTenantId) {
        if (-not $tenantId) {
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { Write-Verbose "Disconnect after unreadable tenant: $($_.Exception.Message)" }
            throw "Could not read which tenant the Exchange Online session belongs to, so it cannot be confirmed as $ExpectedTenantId. Nothing was read."
        }
        if ($tenantId -ne $ExpectedTenantId) {
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { Write-Verbose "Disconnect after tenant mismatch: $($_.Exception.Message)" }
            throw "Exchange Online session is for tenant $tenantId, not the requested tenant $ExpectedTenantId. Nothing was read."
        }
    }

    return [pscustomobject]@{
        Connected    = ($null -ne $now)
        TenantId     = $tenantId
        Organization = [string](Get-NRGObjectField -Item $now -Key 'Organization' -Default '')
        Account      = [string](Get-NRGObjectField -Item $now -Key 'UserPrincipalName' -Default '')
        Reused       = $reused
    }
}

function Disconnect-NRGExchangeOnlineOnly {
    [CmdletBinding()]
    param()
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { Write-Verbose "Disconnect-ExchangeOnline: $($_.Exception.Message)" }
}

#Requires -Version 7.0
#
# Connect-NRGExchangeOnly.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Sign in to Exchange Online AND NOTHING ELSE, for the distribution-list scan.
#          Connect-NRGServices always opens Microsoft Graph first and then Exchange,
#          Security & Compliance and Teams; a scan that reads only distribution lists
#          should not ask a technician for consent to read the whole tenant, and should
#          not be able to. This function has no Graph, Purview, Teams or SharePoint call
#          at all, and NRG.DistributionLists.Tests.ps1 fails if one appears.
#
# Data keys set/consumed: none.
# Cmdlets: Connect-ExchangeOnline, Get-ConnectionInformation (ExchangeOnlineManagement 3.x)
#
# Same sign-in as the rest of the tool for Exchange: interactive browser MFA, the WAM
# broker disabled, -DisableWAM passed when the installed module has it (not a weaker
# sign-in: MSAL uses the system browser with the same MFA and Conditional Access), and
# -DelegatedOrganization for a GDAP client, because without it Exchange connects to the
# signed-in operator's OWN organization and the scan would read the wrong tenant.

function Connect-NRGExchangeOnly {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
        [string] $UserPrincipalName,

        # GDAP: the client's .onmicrosoft.com routing domain.
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*\.onmicrosoft\.com$')]
        [string] $DelegatedOrganization,

        # When given, a session for any other tenant is refused rather than assessed.
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string] $ExpectedTenantId
    )

    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
    $env:MSAL_ALLOW_BROKER = '0'
    $env:MSAL_DISABLE_TOKENBROKER = '1'

    $result = [ordered]@{ EXO = $false; ReusedSession = $false; TenantId = ''; Error = '' }

    $connect = Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue
    if (-not $connect) {
        $result.Error = 'The ExchangeOnlineManagement module is not installed. Run Install-NRGPrerequisites.ps1, then start a NEW PowerShell 7 window.'
        return $result
    }

    $connected = {
        if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return @() }
        @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object {
            [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '') -eq 'Connected' -and -not (Test-NRGEopConnection -Connection $_) })
    }

    try {
        # An Exchange Online session the caller already opened is reused only when it is
        # provably this run's tenant: a leftover session for another client must never be
        # read as this one's lists.
        $existing = @(& $connected)
        if ($ExpectedTenantId) { $existing = @($existing | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'TenantID' -Default '') -eq $ExpectedTenantId }) }
        elseif ($DelegatedOrganization) { $existing = @() }
        if ($existing.Count -gt 0) {
            $result.EXO = $true
            $result.ReusedSession = $true
            $result.TenantId = [string](Get-NRGObjectField -Item ($existing | Select-Object -Last 1) -Key 'TenantID' -Default '')
            return $result
        }

        $exoParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        $params = Get-NRGObjectField -Item $connect -Key 'Parameters' -Default $null
        if ($null -ne $params -and $params.ContainsKey('DisableWAM')) { $exoParams['DisableWAM'] = $true }
        if ($UserPrincipalName)      { $exoParams['UserPrincipalName'] = $UserPrincipalName }
        if ($DelegatedOrganization)  { $exoParams['DelegatedOrganization'] = $DelegatedOrganization }
        Connect-ExchangeOnline @exoParams | Out-Null

        $now = @(& $connected) | Select-Object -Last 1
        $tid = [string](Get-NRGObjectField -Item $now -Key 'TenantID' -Default '')
        if ($ExpectedTenantId -and $tid -and $tid -ne $ExpectedTenantId) {
            throw "Exchange Online session is for tenant $tid, not the requested tenant $ExpectedTenantId."
        }
        $result.EXO = $true
        $result.TenantId = $tid
    } catch {
        $msg = Get-NRGConnectErrorText -ErrorRecord $_
        $hints = @((Get-NRGMsalConflictHint -Message $_.Exception.Message), (Get-NRGExoConnectHint -Message $_.Exception.Message)) | Where-Object { $_ }
        $result.Error = (@($msg) + @($hints)) -join ' '
        $result.EXO = $false
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Connect-EXO' -Message $msg
        }
    }
    return $result
}

function Disconnect-NRGExchangeOnly {
    # Closes the Exchange Online session this scan opened. Nothing else was connected.
    [CmdletBinding()] param()
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
}

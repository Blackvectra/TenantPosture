#Requires -Version 7.0
#
# Connect-NRGExchangeOnly.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Sign in to Exchange Online ONLY, for the distribution-list scan
#          (Invoke-NRGAssessment.ps1 -DistributionListsOnly). It connects to no Graph,
#          no Security & Compliance (Purview), no Teams and no SharePoint, so a scan
#          that needs one service signs in to one service, and the operator is not
#          asked for permissions the scan never uses.
#
# Sets:     nothing (returns the connection summary)
# Consumes: nothing
# Cmdlets:  Connect-ExchangeOnline, Get-ConnectionInformation, Get-Command
#
# Same sign-in rules as Connect-NRGServices: the WAM broker is kept off so the system
# browser handles the sign-in with the same MFA and Conditional Access; -DisableWAM is
# passed only when the installed module has it; a certificate sign-in is app-only and
# needs the .onmicrosoft.com routing domain; and a session left over from an earlier task
# is reused ONLY when it is verified to be the tenant this run was asked to assess, so a
# worksheet is never written about the wrong client.

function Connect-NRGExchangeOnly {
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
        [string] $UserPrincipalName,

        # The tenant this run must assess. A connected session for any other tenant is refused.
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string] $ExpectedTenantId,

        # GDAP: without it Exchange connects to the signed-in operator's OWN organization.
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*\.onmicrosoft\.com$')]
        [string] $DelegatedOrganization,

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string] $TenantId,

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string] $AppId,

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string] $CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'AppOnly')]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*\.onmicrosoft\.com$')]
        [string] $OrganizationDomain
    )

    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
    $env:MSAL_ALLOW_BROKER = '0'
    $env:MSAL_DISABLE_TOKENBROKER = '1'

    $isAppOnly = ($PSCmdlet.ParameterSetName -eq 'AppOnly')
    $result = [ordered]@{ EXO = $false; TenantId = ''; TenantDomain = ''; AuthMode = $PSCmdlet.ParameterSetName; Reused = $false }
    $want = if ($isAppOnly) { $TenantId } else { $ExpectedTenantId }

    # The connected, non-Security-&-Compliance session, if there is one.
    $current = {
        if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) { return $null }
        try {
            @(Get-ConnectionInformation -ErrorAction Stop | Where-Object {
                [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '') -eq 'Connected' -and -not (Test-NRGEopConnection -Connection $_) }) | Select-Object -Last 1
        } catch { $null }
    }
    $describe = {
        param($c)
        $result.TenantId = [string](Get-NRGObjectField -Item $c -Key 'TenantID' -Default (Get-NRGObjectField -Item $c -Key 'TenantId' -Default ''))
        # Microsoft: Organization is set only for certificate and managed-identity connections, and DelegatedOrganization only
        # for a GDAP one. An interactive sign-in carries neither, and the signed-in account's own domain is not the client's, so
        # an unknown domain stays empty rather than being guessed.
        $dom = [string](Get-NRGObjectField -Item $c -Key 'Organization' -Default '')
        if (-not $dom) { $dom = [string](Get-NRGObjectField -Item $c -Key 'DelegatedOrganization' -Default '') }
        $result.TenantDomain = $dom
    }

    # Reuse a session only when it is provably the requested tenant (the GDAP batch runner connects and
    # verifies a session before calling in). With no tenant to compare against, connect fresh.
    $existing = & $current
    if ($existing -and $want) {
        & $describe $existing
        if ($result.TenantId -and $result.TenantId -ieq $want) {
            $result.EXO = $true; $result.Reused = $true
            return $result
        }
    }

    if (-not (Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue)) {
        throw 'Connect-ExchangeOnline is not available: the ExchangeOnlineManagement module is not installed or not importable. Run .\Install-NRGPrerequisites.ps1.'
    }
    $params = @{ ShowBanner = $false; ErrorAction = 'Stop' }
    $cmd = Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue
    $pmap = if ($cmd) { Get-NRGObjectField -Item $cmd -Key 'Parameters' -Default $null } else { $null }
    if ($null -ne $pmap -and $pmap.ContainsKey('DisableWAM')) { $params['DisableWAM'] = $true }
    if ($isAppOnly) {
        $params['AppId'] = $AppId; $params['CertificateThumbprint'] = $CertificateThumbprint; $params['Organization'] = $OrganizationDomain
    } else {
        if ($UserPrincipalName) { $params['UserPrincipalName'] = $UserPrincipalName }
        if ($DelegatedOrganization) { $params['DelegatedOrganization'] = $DelegatedOrganization }
    }
    try {
        Connect-ExchangeOnline @params | Out-Null
    } catch {
        $msg = Get-NRGConnectErrorText -ErrorRecord $_
        $hint = (Get-NRGMsalConflictHint -Message $msg)
        if (-not $hint) { $hint = (Get-NRGExoConnectHint -Message $msg) }
        throw ("Exchange Online sign-in failed: $msg" + $(if ($hint) { " $hint" } else { '' }))
    }

    $now = & $current
    if ($now) { & $describe $now }
    if ($want) {
        if (-not $result.TenantId) {
            throw "Exchange Online connected, but the tenant could not be read from the session, so it cannot be confirmed as $want. Nothing was collected."
        }
        if ($result.TenantId -ine $want) {
            throw "Exchange Online session is for tenant $($result.TenantId), not the requested tenant $want. Nothing was collected."
        }
    }
    $result.EXO = $true
    return $result
}

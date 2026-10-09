#Requires -Version 7.0
#
# Invoke-TPCollectPowerPlatform.ps1  (v4.14.0)
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: Collect Power Platform environments, DLP policies, tenant isolation
# and tenant settings for assessment evaluation.
#
# READ-ONLY. No tenant configuration is ever modified.
#
# Sets raw data key: 'PowerPlatform'
# Network: login.microsoftonline.com (token), api.bap.microsoft.com (admin API)
#
# HOW IT READS POWER PLATFORM — IN PROCESS, NO CHILD PROCESS:
#   Microsoft.PowerApps.Administration.PowerShell is .NET Framework / Windows
#   PowerShell 5.x only (Microsoft Learn: "incompatible with PowerShell 6.0
#   and later"), so it cannot load in this PowerShell 7 tool. Running it in a
#   powershell.exe child process was tried and is not acceptable: the MSP
#   workstations this runs on block child-process creation with an ASR rule.
#   (An earlier fallback also called Get-MgGraphAccessToken, which is not a
#   Microsoft Graph PowerShell cmdlet, so Power Platform never collected.)
#
#   Instead this collector signs in to the Power Platform admin API inside the
#   current process with MSAL — the same library, and the same system-browser
#   sign-in, that Connect-MgGraph already uses on every run — then calls the
#   REST API directly:
#     - Token: public client 1950a258-227b-4e31-a9cf-717495945fc2, the
#       Microsoft first-party client the official admin module signs in with,
#       authority pinned to the Graph tenant, audience
#       https://service.powerapps.com/. The token is held in memory only.
#     - Environments:    GET  .../Microsoft.BusinessAppPlatform/scopes/admin/environments   (documented)
#     - Tenant settings: POST .../Microsoft.BusinessAppPlatform/listtenantsettings          (documented; a
#                        read-only "list" action that Microsoft defines as POST with no body)
#     - DLP policies:    GET  .../PowerPlatform.Governance/v2/policies                     (used by the admin module)
#     - Tenant isolation:GET  .../PowerPlatform.Governance/v1/tenants/{id}/tenantIsolationPolicy (used by the admin module)
#   Each section records its own SectionStatus; a failed section is Failed,
#   never an empty "compliant" list.
#
# App-only (certificate) runs do not sign in to Power Platform: the
# assessment app would need to be registered in Power Platform as well.
# Those runs report the reason, and the PPL controls go NotApplicable.
#
# NIST SP 800-53: CM-7 (least functionality), AC-4 (information flow)
# MITRE ATT&CK:   T1567 (Exfiltration over Web Service)
#

$script:TPPowerPlatformClientId = '1950a258-227b-4e31-a9cf-717495945fc2'
$script:TPBapRoot               = 'https://api.bap.microsoft.com/providers'

function Invoke-TPCollectPowerPlatform {
    [CmdletBinding()] param()
    $result = [ordered]@{
        CollectorId = 'PowerPlatform'
        CollectedAt = (Get-Date).ToString('o')
        Success     = $false
        Errors      = @()
        Data        = [ordered]@{
            Environments    = @()
            TenantIsolation = $null
            DLPPolicies     = @()
            DLPAvailable    = $false
            # Tenant governance flags (PPL-1.3). $null means "not read" — the
            # evaluator must not read absence as "creation is unrestricted".
            TenantGovernance = $null
            # PPL-2.2 / PPL-2.3. Only keys actually returned are set.
            TenantSettings   = $null
            # Empty lists cannot be told apart from failed queries without this.
            SectionStatus    = [ordered]@{
                Environments     = 'NotRun'
                DLPPolicies      = 'NotRun'
                TenantIsolation  = 'NotRun'
                TenantSettings   = 'NotRun'
                TenantGovernance = 'NotRun'
            }
            Source          = 'none'   # 'bap-api' | 'none'
        }
    }
    $note = {
        param([string] $Source, [string] $Msg)
        $result.Errors += $Msg
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source $Source -Message $Msg
        }
    }

    # ── Tenant and sign-in ────────────────────────────────────────────────────
    $tenantId = $null; $account = $null; $appOnly = $false
    try {
        $ctx = Get-MgContext -ErrorAction Stop
        if ($ctx) {
            $tenantId = [string](Get-TPObjectField -Item $ctx -Key 'TenantId' -Default '')
            $account  = [string](Get-TPObjectField -Item $ctx -Key 'Account' -Default '')
            $appOnly  = ([string](Get-TPObjectField -Item $ctx -Key 'AuthType' -Default '')) -eq 'AppOnly'
        }
    } catch { $tenantId = $null }

    $token = $null
    if (-not $tenantId) {
        & $note 'PowerPlatform-Collector' 'Power Platform not collected: no Graph tenant context to pin the Power Platform sign-in to.'
    } elseif ($appOnly) {
        & $note 'PowerPlatform-Collector' 'Power Platform not collected: app-only (certificate) runs do not sign in to Power Platform. Run interactively to assess PPL controls.'
    } else {
        try {
            $token = Get-TPPowerPlatformToken -TenantId $tenantId -LoginHint $account
        } catch {
            & $note 'PowerPlatform-SignIn' "Power Platform not collected: sign-in to the Power Platform admin API failed: $($_.Exception.Message)"
        }
    }

    if ($token) {
        $result.Data.Source = 'bap-api'

        # Environments (documented)
        try {
            $rows = @(Invoke-TPPowerPlatformApi -Token $token -Paged `
                -Uri "$script:TPBapRoot/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01")
            $result.Data.Environments = @($rows | Where-Object { $_ } | ForEach-Object {
                [ordered]@{
                    Id          = [string](Get-TPObjectField -Item $_ -Key 'name' -Default '')
                    DisplayName = [string](Get-TPNestedProperty -Object $_ -Path 'properties.displayName' -Default '')
                    Type        = [string](Get-TPNestedProperty -Object $_ -Path 'properties.environmentSku' -Default '')
                    Region      = [string](Get-TPObjectField    -Item   $_ -Key  'location' -Default '')
                    State       = [string](Get-TPNestedProperty -Object $_ -Path 'properties.states.management.id' -Default '')
                }
            })
            $result.Data.SectionStatus.Environments = 'Collected'
        } catch {
            $result.Data.SectionStatus.Environments = 'Failed'
            & $note 'PPL-Environments' "Power Platform environments query failed: $($_.Exception.Message)"
        }

        # DLP policies
        try {
            $rows = @(Invoke-TPPowerPlatformApi -Token $token -Paged -Uri "$script:TPBapRoot/PowerPlatform.Governance/v2/policies")
            $result.Data.DLPPolicies = @($rows | Where-Object { $_ } | ForEach-Object {
                $cg = @(Get-TPObjectField -Item $_ -Key 'connectorGroups' -Default @())
                [ordered]@{
                    PolicyName  = [string](Get-TPObjectField -Item $_ -Key 'name' -Default '')
                    DisplayName = [string](Get-TPObjectField -Item $_ -Key 'displayName' -Default '')
                    Type        = [string](Get-TPObjectField -Item $_ -Key 'environmentType' -Default '')
                    # Classifications: Confidential (business), General
                    # (non-business), Blocked.
                    BusinessConnectors = @($cg | Where-Object { "$(Get-TPObjectField -Item $_ -Key 'classification' -Default '')" -match 'Confidential|Business' } | ForEach-Object { @(Get-TPObjectField -Item $_ -Key 'connectors' -Default @()) } | Where-Object { $_ })
                    BlockedConnectors  = @($cg | Where-Object { "$(Get-TPObjectField -Item $_ -Key 'classification' -Default '')" -match 'Blocked' } | ForEach-Object { @(Get-TPObjectField -Item $_ -Key 'connectors' -Default @()) } | Where-Object { $_ })
                }
            })
            # Collected with zero policies is a real answer (PPL-1.2 Gap).
            $result.Data.DLPAvailable = $true
            $result.Data.SectionStatus.DLPPolicies = 'Collected'
        } catch {
            $result.Data.SectionStatus.DLPPolicies = 'Failed'
            & $note 'PPL-DLP' "Power Platform DLP policy query failed: $($_.Exception.Message)"
        }

        # Tenant isolation
        try {
            $iso = Invoke-TPPowerPlatformApi -Token $token -Uri "$script:TPBapRoot/PowerPlatform.Governance/v1/tenants/$tenantId/tenantIsolationPolicy"
            $result.Data.TenantIsolation = [ordered]@{
                IsDisabled = [bool](Get-TPNestedProperty -Object $iso -Path 'properties.isDisabled' -Default $true)
                Rules      = @(Get-TPNestedProperty -Object $iso -Path 'properties.allowedTenants' -Default @())
            }
            $result.Data.SectionStatus.TenantIsolation = 'Collected'
        } catch {
            $result.Data.SectionStatus.TenantIsolation = 'Failed'
            & $note 'PPL-TenantIsolation' "Power Platform tenant isolation query failed: $($_.Exception.Message)"
        }

        # Tenant settings (documented POST list action, no body)
        try {
            $ts = Invoke-TPPowerPlatformApi -Token $token -Method POST `
                -Uri "$script:TPBapRoot/Microsoft.BusinessAppPlatform/listtenantsettings?api-version=2020-10-01"
            # Property casing differs between Microsoft's own example and
            # its definitions table (…NonAdminUsers vs …NonAdminusers); read
            # both. Also accept the powerPlatform.governance location older
            # payloads used.
            $flag = {
                param([string[]] $Names)
                foreach ($n in $Names) {
                    foreach ($p in @($n, "powerPlatform.governance.$n")) {
                        $v = Get-TPNestedProperty -Object $ts -Path $p -Default $null
                        if ($null -ne $v) { return [bool]$v }
                    }
                }
                return $null
            }
            $result.Data.TenantGovernance = [ordered]@{
                EnvironmentCreationRestricted      = & $flag @('disableEnvironmentCreationByNonAdminUsers', 'disableEnvironmentCreationByNonAdminusers')
                TrialEnvironmentCreationRestricted = & $flag @('disableTrialEnvironmentCreationByNonAdminUsers', 'disableTrialEnvironmentCreationByNonAdminusers')
            }
            $result.Data.SectionStatus.TenantGovernance = 'Collected'
            # Only keys the API actually returned: an absent flag must reach
            # the evaluator as "not read", never as its default.
            $settings = [ordered]@{}
            $portals = & $flag @('disablePortalsCreationByNonAdminUsers', 'disablePortalsCreationByNonAdminusers')
            if ($null -ne $portals) { $settings['DisablePortalsCreationByNonAdminUsers'] = $portals }
            $guestsMake = Get-TPNestedProperty -Object $ts -Path 'powerPlatform.powerApps.enableGuestsToMake' -Default $null
            if ($null -ne $guestsMake) { $settings['EnableGuestsToMakePowerApps'] = [bool]$guestsMake }
            $result.Data.TenantSettings = $settings
            $result.Data.SectionStatus.TenantSettings = 'Collected'
        } catch {
            $result.Data.SectionStatus.TenantSettings   = 'Failed'
            $result.Data.SectionStatus.TenantGovernance = 'Failed'
            & $note 'PPL-TenantSettings' "Power Platform tenant settings query failed: $($_.Exception.Message)"
        }

        $result.Success = @($result.Data.SectionStatus.Values | Where-Object { $_ -eq 'Collected' }).Count -gt 0
        if (-not $result.Success) {
            & $note 'PowerPlatform-Collector' 'Power Platform not collected: signed in, but every admin API query failed (see the other PPL exceptions). The account may lack the Power Platform Administrator role in this tenant.'
        }
    }

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'PowerPlatform' -Data $result
    }
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        if ($result.Success) {
            $covNote = "Source=$($result.Data.Source) Envs=$($result.Data.Environments.Count) DLP=$($result.Data.DLPPolicies.Count)"
            $status = if ($result.Errors.Count -gt 0) { 'Partial' } else { 'Collected' }
            Register-TPCoverage -Family 'PowerPlatform' -Status $status -Note $covNote
        } else {
            Register-TPCoverage -Family 'PowerPlatform' -Status 'Failed' -Note ($result.Errors -join '; ')
        }
    }
    return $result
}

# Interactive, in-process sign-in to the Power Platform admin API.
# Uses the MSAL (Microsoft.Identity.Client) that Microsoft.Graph.Authentication
# has already loaded for Connect-MgGraph, with the same system-browser flow
# (no embedded web view, no device code, no child process). The token stays
# in memory for the life of this call. The login hint and NoPrompt let an
# existing browser session complete the sign-in without re-entering anything.
function Get-TPPowerPlatformToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $TenantId,
        [string] $LoginHint,
        [int] $TimeoutSeconds = 180
    )
    $builder = 'Microsoft.Identity.Client.PublicClientApplicationBuilder' -as [type]
    if (-not $builder) {
        # Graph loads its own MSAL into a private assembly load context that
        # PowerShell cannot resolve types from. Exchange Online usually puts
        # one in the shared context first; if not, load the copy that ships
        # with Microsoft.Graph.Authentication (same files, no child process).
        $graphMod = Get-Module Microsoft.Graph.Authentication | Select-Object -First 1
        if (-not $graphMod) { $graphMod = Get-Module -ListAvailable Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1 }
        if ($graphMod) {
            $dep = Join-Path $graphMod.ModuleBase 'Dependencies'
            foreach ($dll in @((Join-Path $dep 'Microsoft.IdentityModel.Abstractions.dll'), (Join-Path $dep 'Core' 'Microsoft.Identity.Client.dll'))) {
                if (Test-Path -LiteralPath $dll) {
                    try { Add-Type -LiteralPath $dll -ErrorAction Stop } catch { Write-Verbose "MSAL load: $dll — $($_.Exception.Message)" }
                }
            }
            $builder = 'Microsoft.Identity.Client.PublicClientApplicationBuilder' -as [type]
        }
    }
    $prompt = 'Microsoft.Identity.Client.Prompt' -as [type]
    if (-not $builder -or -not $prompt) {
        throw 'the Microsoft sign-in library (Microsoft.Identity.Client) could not be loaded from Microsoft.Graph.Authentication'
    }
    $b   = $builder::Create($script:TPPowerPlatformClientId)
    $b   = $b.WithAuthority("https://login.microsoftonline.com/$TenantId")
    $b   = $b.WithRedirectUri('http://localhost')
    $app = $b.Build()
    $req = $app.AcquireTokenInteractive([string[]]@('https://service.powerapps.com//.default'))
    $req = $req.WithUseEmbeddedWebView($false)
    $req = $req.WithPrompt($prompt::NoPrompt)
    if ($LoginHint) { $req = $req.WithLoginHint($LoginHint) }
    $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
    try {
        $res = $req.ExecuteAsync($cts.Token).GetAwaiter().GetResult()
    } finally {
        $cts.Dispose()
    }
    if (-not $res -or -not $res.AccessToken) { throw 'no access token returned' }
    $tokTenant = [string](Get-TPObjectField -Item $res -Key 'TenantId' -Default '')
    if ($tokTenant -and $tokTenant -ne $TenantId) {
        throw "signed in to tenant $tokTenant, not $TenantId"
    }
    return [string]$res.AccessToken
}

# One Power Platform admin API call. -Paged follows nextLink and returns the
# concatenated 'value' rows; otherwise returns the response body.
function Invoke-TPPowerPlatformApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^https://api\.bap\.microsoft\.com/')] [string] $Uri,
        [Parameter(Mandatory)] [string] $Token,
        [ValidateSet('GET', 'POST')] [string] $Method = 'GET',
        [switch] $Paged
    )
    $headers = @{ Authorization = "Bearer $Token"; Accept = 'application/json' }
    if (-not $Paged) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -ContentType 'application/json' -TimeoutSec 60 -ErrorAction Stop
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    $next = $Uri; $pages = 0
    while ($next -and $pages -lt 50) {
        $resp = Invoke-RestMethod -Method $Method -Uri $next -Headers $headers -ContentType 'application/json' -TimeoutSec 60 -ErrorAction Stop
        foreach ($r in @(Get-TPObjectField -Item $resp -Key 'value' -Default @())) { if ($null -ne $r) { $rows.Add($r) } }
        # Get-TPObjectField, not Get-TPNestedProperty: a dotted reader
        # would split '@odata.nextLink' and silently stop after page one.
        $link = [string](Get-TPObjectField -Item $resp -Key 'nextLink' -Default '')
        if (-not $link) { $link = [string](Get-TPObjectField -Item $resp -Key '@odata.nextLink' -Default '') }
        $next = if ($link -match '^https://api\.bap\.microsoft\.com/') { $link } else { $null }
        $pages++
    }
    return $rows.ToArray()
}

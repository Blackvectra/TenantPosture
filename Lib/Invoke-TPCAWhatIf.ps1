#Requires -Version 7.0
#
# Invoke-TPCAWhatIf.ps1
# Dependencies: Get-TPObjectField, Get-TPNestedProperty
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Ask Microsoft's Conditional Access What If evaluation which policies
#   would apply to one simulated sign-in, the way Maester's MT.1033 and MT.1034
#   do. The answer comes from Entra itself, so it accounts for group
#   membership, nested groups and role assignments the tool cannot resolve by
#   reading the policies.
#
# THE ONE POST (owner's decision, 2026-10-28: "follow the way Maester does it")
# ----------------------------------------------------------------------------
# The evaluate action is a POST, and the rest of the tool sends GET only. It is
# allowed here, in this one function, because Microsoft documents it as an
# evaluation of the policies already in the tenant: it changes nothing, it is
# granted by Policy.Read.ConditionalAccess or Policy.Read.All (already held, no
# re-consent), and it is the same call the Entra admin center's What If tool
# makes. The guard is structural, and TP.CAChecklist.Tests.ps1 pins it:
#   - the URI is a constant (v1.0 /identity/conditionalAccess/evaluate); no
#     caller can point this function anywhere else;
#   - the body is built here from a validated user id (GUID), a validated
#     application id (GUID) and a client app type from Microsoft's fixed set;
#     no caller text reaches it;
#   - Invoke-TPGraphRequest stays GET-only, and no other file under Lib/,
#     Collectors/ or Evaluators/ calls Invoke-MgGraphRequest with POST.
#
# Data consumed: none. Graph: POST /identity/conditionalAccess/evaluate (v1.0),
#   Policy.Read.All.

function Invoke-TPCAWhatIfEvaluation {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z', Options = 'None')]
        [string] $UserId,

        [Parameter(Mandatory)]
        [ValidatePattern('\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z', Options = 'None')]
        [string] $ApplicationId,

        [Parameter(Mandatory)]
        [ValidateSet('browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'easSupported', 'other')]
        [string] $ClientAppType
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $body = [ordered]@{
        signInIdentity      = [ordered]@{ '@odata.type' = '#microsoft.graph.userSignIn'; userId = $UserId.ToLowerInvariant() }
        signInContext       = [ordered]@{ '@odata.type' = '#microsoft.graph.applicationContext'; includeApplications = @($ApplicationId.ToLowerInvariant()) }
        signInConditions    = [ordered]@{ clientAppType = $ClientAppType }
        appliedPoliciesOnly = $true
    }
    $json = $body | ConvertTo-Json -Depth 5 -Compress
    $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/evaluate' `
        -Body $json -ContentType 'application/json' -OutputType HashTable -ErrorAction Stop

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @(Get-TPObjectField -Item $resp -Key 'value' -Default @())) {
        if ($null -eq $r) { continue }
        # appliedPoliciesOnly asks for the policies that apply; policyApplies is
        # checked again so a response that lists every policy is read right.
        if ((Get-TPObjectField -Item $r -Key 'policyApplies' -Default $false) -ne $true) { continue }
        $grants = @(Get-TPNestedProperty -Object $r -Path 'grantControls.builtInControls' -Default @() | ForEach-Object { [string]$_ })
        $strength = [string](Get-TPNestedProperty -Object $r -Path 'grantControls.authenticationStrength.requirementsSatisfied' -Default '')
        $op = [string](Get-TPNestedProperty -Object $r -Path 'grantControls.operator' -Default '')
        $rows.Add([ordered]@{
            Id           = [string](Get-TPObjectField -Item $r -Key 'id' -Default '')
            DisplayName  = [string](Get-TPObjectField -Item $r -Key 'displayName' -Default '')
            State        = [string](Get-TPObjectField -Item $r -Key 'state' -Default '')
            Grants       = $grants
            Blocks       = ($grants -contains 'block')
            # MFA is required only when no alternative can stand in for it.
            RequiresMfa  = (($grants -contains 'mfa' -or $strength -eq 'mfa') -and ($grants.Count -le 1 -or $op -eq 'AND'))
        })
    }
    return $rows.ToArray()
}

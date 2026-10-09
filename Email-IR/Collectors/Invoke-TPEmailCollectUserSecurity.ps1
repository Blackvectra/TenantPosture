#Requires -Version 7.0
#
# Invoke-TPEmailCollectUserSecurity.ps1  (v4.12.1)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Collect the two persistence surfaces the mailbox collector can't
#          see — OAuth consent grants and registered authentication methods.
#          Attackers who phish a user routinely (a) trick them into consenting
#          to a mail-reading OAuth app (persistence that survives password
#          reset AND MFA re-enrollment), and (b) add their own phone /
#          authenticator as an MFA method so they can re-auth at will.
#
#          Admin-scope triage deep-dive: reads /users/<upn>/... using
#          Directory.Read.All (grants) + UserAuthenticationMethod.Read.All
#          (methods). Delegated single-user mode (/me) typically lacks
#          these scopes — both blocks fail soft and the evaluators register
#          NotApplicable with an advisory, matching the EMAIL-1.2 pattern.
#
# Sets:    IR-UserConsents     — OAuth2 permission grants where the user is
#                                the principal, app display names resolved
#          IR-UserAuthMethods  — registered auth methods (type, id, metadata)
#
# Graph cmdlets: Invoke-TPGraphRequest (REST), all GET-only.

function Invoke-TPEmailCollectUserSecurity {
    [CmdletBinding()]
    param(
        # Same admin-vs-delegated pivot as Invoke-TPEmailCollectMailbox:
        # supplied -> /users/<upn>/ under admin auth; omitted -> /me/.
        [Parameter(Mandatory = $false)]
        [ValidatePattern('^$|^[a-zA-Z0-9][a-zA-Z0-9._+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
        [string] $TargetUpn
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $userPrefix  = if ($TargetUpn) { "users/$([uri]::EscapeDataString($TargetUpn))" } else { 'me' }
    $collectorId = 'IR-UserSecurity'
    # Coverage is registered at the end from what completed, in its own family.

    # ── OAuth consent grants ─────────────────────────────────────────────────
    $consentBag = [ordered]@{
        CollectorId = "$collectorId-Consents"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        $resp = Invoke-TPGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/${userPrefix}/oauth2PermissionGrants" -ErrorAction Stop
        $grants = @($resp.value)
        $grantsTruncated = [bool]($resp['@odata.nextLink'])

        # Resolve clientId (service principal object id) -> app display name.
        # Needs Directory.Read.All; fail soft per-app so one lookup failure
        # doesn't sink the whole grant list.
        $spCache = @{}
        $normalized = foreach ($g in $grants) {
            $appName = $null
            $spId = [string]$g.clientId
            if ($spId) {
                if ($spCache.ContainsKey($spId)) {
                    $appName = $spCache[$spId]
                } else {
                    try {
                        $sp = Invoke-TPGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/${spId}?`$select=displayName,appId,publisherName" -ErrorAction Stop
                        $appName = [ordered]@{
                            DisplayName   = [string]$sp.displayName
                            AppId         = [string]$sp.appId
                            PublisherName = if ($sp.publisherName) { [string]$sp.publisherName } else { $null }
                        }
                    } catch {
                        $appName = $null
                    }
                    $spCache[$spId] = $appName
                }
            }
            [ordered]@{
                GrantId     = [string]$g.id
                ClientSpId  = $spId
                App         = $appName
                ConsentType = [string]$g.consentType
                Scope       = [string]$g.scope
            }
        }
        $consentBag.Data = [ordered]@{
            Count     = @($normalized).Count
            Truncated = $grantsTruncated
            Grants    = @($normalized)
        }
        $consentBag.Success = $true
    } catch {
        Register-TPException -Source "$collectorId-Consents" -Message $_.Exception.Message
    }
    Set-TPRawData -Key 'IR-UserConsents' -Data $consentBag

    # ── Registered authentication methods ────────────────────────────────────
    $methodBag = [ordered]@{
        CollectorId = "$collectorId-AuthMethods"
        CollectedAt = (Get-Date -Format 'o')
        Success     = $false
        Data        = $null
    }
    try {
        $resp = Invoke-TPGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/${userPrefix}/authentication/methods" -ErrorAction Stop
        $methods = @($resp.value)

        $normalized = foreach ($m in $methods) {
            # @odata.type tells us what kind of method this is, e.g.
            # #microsoft.graph.phoneAuthenticationMethod. Keep the per-type
            # display fields the operator needs to recognize their own
            # methods vs an attacker's.
            $mType = ([string]$m['@odata.type']) -replace '^#microsoft\.graph\.', ''
            $rawCreated = $null
            if ($m.PSObject -and ($m.PSObject.Properties.Name -contains 'createdDateTime')) {
                $rawCreated = $m.createdDateTime
            } elseif ($m -is [hashtable] -and $m.ContainsKey('createdDateTime')) {
                $rawCreated = $m['createdDateTime']
            }
            # Keep ISO 8601: a [string] cast of a parsed DateTime gives the
            # invariant "MM/dd/yyyy" form, which a reader in another culture
            # misreads. An unparseable value is kept as text (read as unknown).
            $createdUtc = ConvertTo-TPUtcDateTime $rawCreated
            $created = if ($createdUtc) { $createdUtc.ToString('o', [cultureinfo]::InvariantCulture) } elseif ($null -ne $rawCreated) { [string]$rawCreated } else { $null }
            $display = $null
            foreach ($fld in @('displayName', 'phoneNumber', 'emailAddress')) {
                $v = $null
                if ($m -is [hashtable]) {
                    if ($m.ContainsKey($fld)) { $v = $m[$fld] }
                } elseif ($m.PSObject -and ($m.PSObject.Properties.Name -contains $fld)) {
                    $v = $m.$fld
                }
                if ($v) { $display = [string]$v; break }
            }
            [ordered]@{
                Id              = [string]$m.id
                MethodType      = $mType
                Display         = $display
                CreatedDateTime = $created
            }
        }
        $methodBag.Data = [ordered]@{
            Count   = @($normalized).Count
            Methods = @($normalized)
        }
        $methodBag.Success = $true
    } catch {
        Register-TPException -Source "$collectorId-AuthMethods" -Message $_.Exception.Message
    }
    Set-TPRawData -Key 'IR-UserAuthMethods' -Data $methodBag

    $usrFailed = @(@($consentBag, $methodBag) | Where-Object { -not $_.Success } | ForEach-Object { $_.CollectorId })
    $usrPartial = [bool]($consentBag.Success -and $consentBag.Data -and [bool](Get-TPObjectField -Item $consentBag.Data -Key 'Truncated' -Default $false))
    if ($usrFailed.Count -eq 2) {
        Register-TPCoverage -Family 'Email-IR-UserSecurity' -Status 'Failed' -Note "No user-security read completed ($($usrFailed -join ', '))."
    } elseif ($usrFailed.Count -gt 0 -or $usrPartial) {
        Register-TPCoverage -Family 'Email-IR-UserSecurity' -Status 'Partial' -Note "Did not complete: $($usrFailed -join ', ')$(if ($usrPartial) { '; consent grants stopped at one page' })."
    } else {
        Register-TPCoverage -Family 'Email-IR-UserSecurity' -Status 'Collected'
    }
}

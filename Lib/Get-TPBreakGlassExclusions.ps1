#Requires -Version 7.0
#
# Get-TPBreakGlassExclusions.ps1  (v4.6.3)
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: Heuristically locate break-glass / emergency-access accounts and
#   groups in the connected tenant so Conditional Access policy bodies created
#   by Apply-NRG*.ps1 can exclude them before the policy is ever promoted to
#   enabled. Closes H7 (CA policy with excludeUsers=@() is a known lockout
#   vector if a future operator flips state to 'enabled' via portal).
#
# Data keys set/consumed: none — direct Graph reads.
# Required Graph scopes:  Group.Read.All, Directory.Read.All (already in the
#   TenantPosture 21-scope set; no Connect-MgGraph re-scope needed).
#
# Heuristics (broad on purpose — break-glass naming is operator-specific):
#   * GROUPS whose displayName matches: 'Break Glass', 'BreakGlass',
#     'Emergency Access', 'EmergencyAccess'. Case-insensitive contains-match.
#   * USERS who hold the Global Administrator role AND whose displayName,
#     givenName, surname, or UPN contains 'break glass' / 'breakglass' /
#     'emergency'. Case-insensitive.
#
# Return shape:
#   [PSCustomObject]@{
#     ExcludeGroups = @( <group ObjectId>, ... )
#     ExcludeUsers  = @( <user  ObjectId>, ... )
#     GroupNames    = @( <displayName>,    ... )   # for log/Notes
#     UserUPNs      = @( <userPrincipalName>, ... )
#     Found         = $true / $false
#   }
#
# Cross-platform / connection safety:
#   - If Get-MgContext returns nothing (no Graph session — e.g. -WhatIf preview
#     without Connect-MgGraph), the function returns Found=$false with empty
#     arrays. The caller decides whether to warn or fall back.
#   - Any Graph error is caught per-step; the function never throws.
#
# OWASP A01 / lockout safety (NIST SP 800-53 AC-2(7)). Mirrors guidance in
# Microsoft Learn "Manage emergency access accounts in Microsoft Entra ID".
#

function Get-TPBreakGlassExclusions {
    [CmdletBinding()]
    param()

    $result = [PSCustomObject]@{
        ExcludeGroups = @()
        ExcludeUsers  = @()
        GroupNames    = @()
        UserUPNs      = @()
        Found         = $false
    }

    # Refuse to even try if Graph isn't connected — silent return with Found=$false.
    $ctx = $null
    try { $ctx = Get-MgContext -ErrorAction SilentlyContinue } catch { }
    if (-not $ctx) {
        Write-Verbose "Get-TPBreakGlassExclusions: no Graph session — returning Found=`$false."
        return $result
    }

    $groupPatterns = @('Break Glass','BreakGlass','Emergency Access','EmergencyAccess')
    $userPatterns  = @('break glass','breakglass','emergency')

    # ── Group lookup ────────────────────────────────────────────────────────
    $groupIds   = [System.Collections.Generic.List[string]]::new()
    $groupNames = [System.Collections.Generic.List[string]]::new()
    if (Get-Command Get-MgGroup -ErrorAction SilentlyContinue) {
        foreach ($pat in $groupPatterns) {
            try {
                # Graph's $filter doesn't support 'contains' on displayName, so
                # use startsWith and then post-filter for substring match.
                # We over-fetch with a small Top cap rather than -All to avoid
                # paging every group in big tenants for a heuristic lookup.
                $hits = @(Get-MgGroup -Filter "startsWith(displayName,'$($pat -replace "'", "''")')" -Top 25 -ErrorAction Stop)
                foreach ($g in $hits) {
                    if ($g.Id -and ($groupIds -notcontains $g.Id)) {
                        $groupIds.Add($g.Id)
                        $groupNames.Add($g.DisplayName)
                    }
                }
            } catch {
                Write-Verbose "Get-TPBreakGlassExclusions: group query for '$pat' failed — $($_.Exception.Message)"
            }
        }
    }

    # ── User lookup via Global Administrator role members ───────────────────
    # Pattern mirrors Collectors/AAD/Invoke-TPCollectAADRoles.ps1.
    $userIds  = [System.Collections.Generic.List[string]]::new()
    $userUpns = [System.Collections.Generic.List[string]]::new()
    if ((Get-Command Get-MgDirectoryRole -ErrorAction SilentlyContinue) -and
        (Get-Command Get-MgDirectoryRoleMember -ErrorAction SilentlyContinue)) {
        try {
            $roles = @(Get-MgDirectoryRole -All -ErrorAction Stop |
                       Where-Object { $_.DisplayName -eq 'Global Administrator' })
            foreach ($r in $roles) {
                try {
                    $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id -All -ErrorAction Stop)
                    foreach ($m in $members) {
                        # Members are MicrosoftGraphDirectoryObject — extract
                        # additional properties only if they look like a user.
                        if (-not $m.AdditionalProperties) { continue }
                        $aps = $m.AdditionalProperties
                        $type = [string]$aps['@odata.type']
                        if ($type -notmatch 'user') { continue }
                        $dn   = [string]$aps['displayName']
                        $upn  = [string]$aps['userPrincipalName']
                        $gn   = [string]$aps['givenName']
                        $sn   = [string]$aps['surname']
                        $haystack = ("$dn $upn $gn $sn").ToLowerInvariant()
                        foreach ($pat in $userPatterns) {
                            if ($haystack.Contains($pat)) {
                                if ($m.Id -and ($userIds -notcontains $m.Id)) {
                                    $userIds.Add($m.Id)
                                    if ($upn) { $userUpns.Add($upn) }
                                }
                                break
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Get-TPBreakGlassExclusions: role-member enumeration for $($r.DisplayName) failed — $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Verbose "Get-TPBreakGlassExclusions: Get-MgDirectoryRole failed — $($_.Exception.Message)"
        }
    }

    $result.ExcludeGroups = @($groupIds)
    $result.ExcludeUsers  = @($userIds)
    $result.GroupNames    = @($groupNames)
    $result.UserUPNs      = @($userUpns)
    $result.Found         = ($groupIds.Count -gt 0 -or $userIds.Count -gt 0)
    return $result
}

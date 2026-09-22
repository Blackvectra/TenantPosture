#Requires -Version 7.0
#
# Test-NRGControlAppPermissions.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Consumes:     AAD-AppPermissions (Data.Grants, Data.SectionStatus, Data.TenantId)
# Sets:         findings only (Add-NRGFinding)
# Cmdlets:      none — scoring only, no Graph or EXO calls
# Dependencies: Get-NRGRawData, Get-NRGControlById, Get-NRGFrameworkCitations,
#               Get-NRGObjectField, Add-NRGFinding
#
# Scores APPLICATION (app-only) permissions — the half of app risk that
# AAD-12.4 structurally cannot see, because it reads the delegated consent
# table and these grants are not in it.
#
# AAD-15.1  Tenant-takeover permissions        Critical
# AAD-15.2  Mass data-access permissions       High (named list)
#
# FIRST-PARTY APPS ARE REPORTED, NEVER SILENTLY DROPPED
# -----------------------------------------------------
# Microsoft's own first-party service principals legitimately hold
# `Directory.ReadWrite.All` and similar; flagging them as findings would bury
# the one grant that matters under twenty that do not. But dropping them
# without saying so would let an attacker hide behind a Microsoft-looking
# name. So they are excluded from the VERDICT and stated explicitly in the
# detail, with the count. The reader can always see how many were set aside.

# Initialised at dot-source time because StrictMode throws on a read of a
# never-assigned script variable — the same reason Get-NRGControlDefinitions
# and Get-NRGSSPPosture declare theirs this way.
$script:NRGAppPermCatalog = $null

# Risk catalog loader. Cached module-scope like the other config loaders.
function Get-NRGAppPermissionRiskCatalog {
    [CmdletBinding()] param([string] $ConfigPath)

    Set-StrictMode -Version Latest

    if (-not $ConfigPath -and $script:NRGAppPermCatalog) { return $script:NRGAppPermCatalog }

    $moduleRoot = if ($script:NRGModuleRoot) { $script:NRGModuleRoot }
                  elseif ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
                  else { (Get-Location).Path }
    $path = if ($ConfigPath) { $ConfigPath } else { Join-Path $moduleRoot 'Config' 'app-permissions-risk.json' }

    if (-not (Test-Path -LiteralPath $path)) {
        Write-Verbose "app-permissions-risk.json not found at $path."
        return $null
    }
    if (-not $ConfigPath) {
        $resolved     = [System.IO.Path]::GetFullPath($path)
        $resolvedRoot = [System.IO.Path]::GetFullPath($moduleRoot)
        if (-not $resolved.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "app-permissions-risk.json resolved outside module root: $resolved"
        }
    }
    try {
        $data = Get-Content -LiteralPath $path -Raw -Encoding utf8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Warning "Failed to load app-permissions-risk.json: $($_.Exception.Message)"
        return $null
    }
    if (-not $ConfigPath) { $script:NRGAppPermCatalog = $data }
    return $data
}

# Shared work for both controls: gate on collection, then split the grants
# into scored (third-party) and set-aside (Microsoft first-party).
#
# Returns $null when no verdict may be reached, having already emitted the
# NotApplicable finding — the caller just returns.
function Get-NRGAppPermissionContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] [object] $Control,
        [AllowEmptyCollection()] [AllowNull()] [string[]] $Citations
    )

    Set-StrictMode -Version Latest

    $raw = Get-NRGRawData -Key 'AAD-AppPermissions'
    if (-not $raw -or -not (Get-NRGObjectField -Item $raw -Key 'Success' -Default $false)) {
        Add-NRGFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category `
            -Title $Control.Title -Severity 'Informational' -FrameworkIds $Citations `
            -Detail 'Application permission data not collected; not assessed.'
        return $null
    }
    $data = Get-NRGObjectField -Item $raw -Key 'Data' -Default $null
    if ($null -eq $data) {
        Add-NRGFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category `
            -Title $Control.Title -Severity 'Informational' -FrameworkIds $Citations `
            -Detail 'Application permission data not collected; not assessed.'
        return $null
    }

    # EMPTY IS NOT CLEAN. Every watched resource must have completed. If even
    # one 403'd or was truncated, an empty grant list cannot distinguish "no
    # app holds this" from "we could not look", and a tenant-takeover control
    # reporting Satisfied on a failed query is the worst output this tool can
    # produce.
    # NOTE the deviation from the usual replay rule. Elsewhere an ABSENT
    # SectionStatus counts as collected, so result JSON captured before that
    # field existed keeps its old behavior. This collector is new: no results
    # file predates it, so there is no legacy behavior to preserve, and
    # "absent" can only mean the collector returned an envelope with Success
    # set and nothing inside it. Reading that as clean is a pure false pass —
    # and on a Critical tenant-takeover control it is the worst one available.
    $sections = Get-NRGObjectField -Item $data -Key 'SectionStatus' -Default $null
    $sectionKeys = @()
    if ($null -ne $sections) { try { $sectionKeys = @($sections.Keys) } catch { $sectionKeys = @() } }

    $incomplete = @()
    if ($sectionKeys.Count -eq 0) {
        $incomplete = @('no section status was reported')
    } else {
        foreach ($k in $sectionKeys) {
            $st = [string](Get-NRGObjectField -Item $sections -Key $k -Default '')
            if ($st -ne 'Collected') { $incomplete += "$k ($st)" }
        }
    }
    if ($incomplete.Count -gt 0) {
        Add-NRGFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category `
            -Title $Control.Title -Severity 'Informational' -FrameworkIds $Citations `
            -Detail ("Application permission enumeration did not complete for: $($incomplete -join ', '). " +
                     'Not assessed — an empty result here cannot be told apart from a failed query, and this control ' +
                     'will not report a pass it did not verify. Re-run once the cause is resolved.')
        return $null
    }

    $catalog = Get-NRGAppPermissionRiskCatalog
    if ($null -eq $catalog) {
        Add-NRGFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category `
            -Title $Control.Title -Severity 'Informational' -FrameworkIds $Citations `
            -Detail 'The application permission risk catalog could not be loaded; not assessed.'
        return $null
    }

    $msOrgs = @{}
    foreach ($o in @(Get-NRGObjectField -Item $catalog -Key 'microsoftOwnerTenantIds' -Default @())) {
        if ($o) { $msOrgs[[string]$o] = $true }
    }
    $tenantId = [string](Get-NRGObjectField -Item $data -Key 'TenantId' -Default '')

    $scored      = [System.Collections.Generic.List[object]]::new()
    $firstParty  = [System.Collections.Generic.List[object]]::new()
    foreach ($g in @(Get-NRGObjectField -Item $data -Key 'Grants' -Default @())) {
        if ($null -eq $g) { continue }
        $owner = [string](Get-NRGObjectField -Item $g -Key 'OwnerOrgId' -Default '')
        # Owner attribution, conservative by default: an unknown owner is
        # treated as third-party and scored, never set aside as Microsoft's.
        $origin = if ($owner -and $msOrgs.ContainsKey($owner)) { 'Microsoft' }
                  elseif ($owner -and $tenantId -and $owner -eq $tenantId) { 'This tenant' }
                  elseif ($owner) { 'External' }
                  else { 'Unknown' }
        $row = [ordered]@{
            Resource      = [string](Get-NRGObjectField -Item $g -Key 'Resource' -Default '')
            Permission    = [string](Get-NRGObjectField -Item $g -Key 'Permission' -Default '')
            PrincipalName = [string](Get-NRGObjectField -Item $g -Key 'PrincipalName' -Default '')
            AppId         = [string](Get-NRGObjectField -Item $g -Key 'AppId' -Default '')
            GrantedOn     = [string](Get-NRGObjectField -Item $g -Key 'GrantedOn' -Default '')
            Origin        = $origin
        }
        if ($origin -eq 'Microsoft') { $firstParty.Add([pscustomobject]$row) } else { $scored.Add([pscustomobject]$row) }
    }

    return [ordered]@{
        Catalog    = $catalog
        Scored     = @($scored)
        FirstParty = @($firstParty)
        TotalCount = @($scored).Count + @($firstParty).Count
    }
}

# Turns a catalog tier into a permission -> reason lookup.
function Get-NRGAppPermissionTierMap {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object] $Catalog, [Parameter(Mandatory)] [string] $Tier)
    Set-StrictMode -Version Latest
    $map = @{}
    foreach ($e in @(Get-NRGObjectField -Item $Catalog -Key $Tier -Default @())) {
        $p = [string](Get-NRGObjectField -Item $e -Key 'Permission' -Default '')
        if ($p) { $map[$p] = [string](Get-NRGObjectField -Item $e -Key 'Why' -Default '') }
    }
    return $map
}

# ── AAD-15.1 Tenant-takeover application permissions ─────────────────────────
function Test-NRGControlAppPermTenantTakeover {
    [CmdletBinding()] param()
    $cid = 'AAD-15.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $ctx = Get-NRGAppPermissionContext -ControlId $cid -Control $ctrl -Citations $cit
    if ($null -eq $ctx) { return }

    $tier1 = Get-NRGAppPermissionTierMap -Catalog $ctx.Catalog -Tier 'tier1'
    $hits  = @($ctx.Scored | Where-Object { $tier1.ContainsKey($_.Permission) })

    $msNote = if ($ctx.FirstParty.Count -gt 0) {
        " $($ctx.FirstParty.Count) grant(s) held by Microsoft first-party applications were reviewed and set aside as expected platform behavior; they are excluded from this verdict."
    } else { '' }

    if ($hits.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -Detail ("No non-Microsoft application holds a tenant-takeover application permission. " +
                     "$($ctx.TotalCount) application-permission grant(s) were enumerated across Microsoft Graph, Exchange Online and SharePoint.$msNote") `
            -CurrentValue 'No tenant-takeover application permissions granted' `
            -RequiredValue 'No application holds tenant-takeover permissions'
        return
    }

    $objects = @($hits | Sort-Object Permission, PrincipalName | Select-Object -First 40 | ForEach-Object {
        $when = if ($_.GrantedOn) { " granted $($_.GrantedOn)" } else { '' }
        "$($_.PrincipalName) [$($_.Origin)] — $($_.Permission) on $($_.Resource)$when — $($tier1[$_.Permission])"
    })
    $perms = @($hits | ForEach-Object { $_.Permission } | Sort-Object -Unique)

    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
        -Severity 'Critical' -FrameworkIds $cit `
        -Detail ("$($hits.Count) application-permission grant(s) confer tenant takeover: $($perms -join ', '). " +
                 'These are APPLICATION permissions, not delegated ones — the app acts with no signed-in user, so no MFA ' +
                 'prompt and no Conditional Access policy applies to it, and its activity does not look like a person in ' +
                 "the sign-in logs. Any one of these can be used to obtain Global Administrator, forge tokens for any user, " +
                 "or read every mailbox in the tenant.$msNote") `
        -CurrentValue "$($hits.Count) tenant-takeover application permission(s) granted" `
        -RequiredValue 'No application holds tenant-takeover permissions' `
        -Remediation $ctrl.Remediation -AffectedObjects $objects
}

# ── AAD-15.2 Mass data-access application permissions — named list ───────────
function Test-NRGControlAppPermDataAccess {
    [CmdletBinding()] param()
    $cid = 'AAD-15.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $ctx = Get-NRGAppPermissionContext -ControlId $cid -Control $ctrl -Citations $cit
    if ($null -eq $ctx) { return }

    $tier2 = Get-NRGAppPermissionTierMap -Catalog $ctx.Catalog -Tier 'tier2'
    $hits  = @($ctx.Scored | Where-Object { $tier2.ContainsKey($_.Permission) })

    $msNote = if ($ctx.FirstParty.Count -gt 0) {
        " $($ctx.FirstParty.Count) grant(s) held by Microsoft first-party applications are excluded from this list."
    } else { '' }

    if ($hits.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -Detail ("No non-Microsoft application holds a tenant-wide data-access application permission.$msNote") `
            -CurrentValue 'No mass data-access application permissions granted' `
            -RequiredValue 'Every application permission reviewed and justified'
        return
    }

    $objects = @($hits | Sort-Object PrincipalName, Permission | Select-Object -First 40 | ForEach-Object {
        $when = if ($_.GrantedOn) { " granted $($_.GrantedOn)" } else { '' }
        "$($_.PrincipalName) [$($_.Origin)] — $($_.Permission) on $($_.Resource)$when"
    })
    $apps  = @($hits | ForEach-Object { $_.PrincipalName } | Sort-Object -Unique)
    $ext   = @($hits | Where-Object { $_.Origin -eq 'External' -or $_.Origin -eq 'Unknown' })

    # Severity rises when the holder is an outside party: the same permission
    # is a larger exposure when the organization does not own the application.
    $sev = if ($ext.Count -gt 0) { 'High' } else { 'Medium' }

    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
        -Severity $sev -FrameworkIds $cit `
        -Detail ("$($apps.Count) application(s) hold $($hits.Count) tenant-wide data-access permission(s) — they can reach " +
                 'every user''s mail, files or chat with no signed-in user and no Conditional Access evaluation. ' +
                 "$($ext.Count) of these grant(s) are held by applications this organization does not own. Each grant should " +
                 "name a business owner and a reason, or be revoked.$msNote") `
        -CurrentValue "$($apps.Count) application(s) with tenant-wide data access" `
        -RequiredValue 'Every application permission reviewed, owned and justified' `
        -Remediation $ctrl.Remediation -AffectedObjects $objects
}

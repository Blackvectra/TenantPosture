#Requires -Version 7.0
#
# Get-TPSignInEffectiveness.ps1
# Dependencies: Get-TPObjectField, Get-TPNestedProperty
# TenantPosture
# Author: Matthew Levorson
#
# Purpose:  Judges whether a protection held, from the sign-in events
#           Invoke-TPCollectAADSignInEvidence stored. A VIEW for the baseline's
#           effectiveness column: it creates no finding and moves no score.
# Consumes: AAD-SignInEvidence, AAD-DirectoryRoles (privileged scope only)
#
# The answer is Effective, Ineffective or Unknown, and the asymmetry is the
# point: one successful bypass in any read proves the protection did not hold
# for that account, so a truncated or partly failed read can still be
# Ineffective; only a complete read with no bypass is Effective, and even then
# it says the protection held for the sign-ins that happened in the window,
# not that nothing could get through. Approved emergency-access accounts are
# set aside by object id and named; a group on the record is not resolved, so
# its members are not set aside.

$script:TPSignInExchangeResourceId   = '00000002-0000-0ff1-ce00-000000000000'
$script:TPSignInSharePointResourceId = '00000003-0000-0ff1-ce00-000000000000'

function Get-TPSignInEffectiveness {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        # LegacyAuthSuccess or SingleFactorSuccess.
        [Parameter(Mandatory)] [ValidateSet('LegacyAuthSuccess', 'SingleFactorSuccess')] [string] $Check,
        # LegacyAuthSuccess: All, Exchange, SharePoint. SingleFactorSuccess: AllUsers, PrivilegedRoles.
        [Parameter(Mandatory)] [ValidateSet('All', 'Exchange', 'SharePoint', 'AllUsers', 'PrivilegedRoles')] [string] $Scope,
        [AllowNull()] [object] $RawData,
        # The tenant's approved emergency-access record: keys 'user:<id>' / 'group:<id>'.
        [AllowNull()] [System.Collections.IDictionary] $EmergencyAccess
    )
    Set-StrictMode -Version Latest
    if ($Check -eq 'LegacyAuthSuccess' -and $Scope -in @('AllUsers', 'PrivilegedRoles')) { throw "Scope $Scope does not apply to $Check." }
    if ($Check -eq 'SingleFactorSuccess' -and $Scope -in @('All', 'Exchange', 'SharePoint')) { throw "Scope $Scope does not apply to $Check." }
    $out = { param([string] $s, [string] $d) [ordered]@{ State = $s; Detail = $d } }

    $get = {
        param([string] $k)
        if ($null -eq $RawData) { return $null }
        if ($RawData -is [System.Collections.IDictionary]) { if ($RawData.Contains($k)) { return $RawData[$k] } else { return $null } }
        return Get-TPObjectField -Item $RawData -Key $k -Default $null
    }
    $ev = & $get 'AAD-SignInEvidence'
    if ($null -eq $ev -or -not [bool](Get-TPObjectField -Item $ev -Key 'Success' -Default $false)) {
        return & $out 'Unknown' 'Sign-in evidence was not collected this run.'
    }
    $data = Get-TPObjectField -Item $ev -Key 'Data' -Default $null
    if (-not [bool](Get-TPObjectField -Item $data -Key 'Available' -Default $false)) {
        $why = [string](Get-TPObjectField -Item $data -Key 'UnavailableReason' -Default '')
        $text = switch ($why) {
            'PremiumLicenseRequired' { 'Sign-in logs could not be read: Microsoft requires Entra ID P1 or P2 to read them through Graph.' }
            'AccessDenied'           { 'Sign-in logs could not be read: the signed-in account holds no role that reads them (Global Reader, Reports Reader or Security Reader).' }
            default                  { 'Sign-in logs could not be read.' }
        }
        return & $out 'Unknown' $text
    }
    $days = [int](Get-TPObjectField -Item $data -Key 'WindowDays' -Default 0)
    $window = "the $days-day sign-in window read"

    $section = if ($Check -eq 'LegacyAuthSuccess') { 'LegacyAuth' } else { 'SingleFactor' }
    $status = [string](Get-TPNestedProperty -Object $data -Path "SectionStatus.$section" -Default 'NotRun')
    $sec = Get-TPNestedProperty -Object $data -Path "Sections.$section" -Default $null
    $events = @(Get-TPObjectField -Item $sec -Key 'Events' -Default @() | Where-Object { $null -ne $_ })
    $truncated = [bool](Get-TPObjectField -Item $sec -Key 'Truncated' -Default $false)
    $complete = ($status -eq 'Collected') -and -not $truncated

    # ── Scope ──
    $label = ''
    $holdersComplete = $true
    switch ($Scope) {
        'All'        { $label = 'legacy-client sign-ins' }
        'Exchange'   {
            $label = 'legacy-client sign-ins to Exchange Online'
            $events = @($events | Where-Object {
                [string](Get-TPObjectField -Item $_ -Key 'ResourceId' -Default '') -eq $script:TPSignInExchangeResourceId -or
                [string](Get-TPObjectField -Item $_ -Key 'ClientAppUsed' -Default '') -ne 'Other clients'
            })
        }
        'SharePoint' {
            $label = 'legacy-client sign-ins to SharePoint Online'
            $events = @($events | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'ResourceId' -Default '') -eq $script:TPSignInSharePointResourceId })
        }
        'AllUsers'   { $label = 'interactive sign-ins that needed only one factor' }
        'PrivilegedRoles' {
            $label = 'interactive single-factor sign-ins by privileged-role holders'
            $roles = & $get 'AAD-DirectoryRoles'
            $rolesOk = $null -ne $roles -and [bool](Get-TPObjectField -Item $roles -Key 'Success' -Default $false)
            $rolesStatus = [string](Get-TPNestedProperty -Object $roles -Path 'Data.SectionStatus.RoleAssignments' -Default 'Collected')
            if (-not $rolesOk -or $rolesStatus -ne 'Collected') {
                return & $out 'Unknown' 'Privileged role assignments were not collected, so the single-factor sign-ins of role holders cannot be picked out.'
            }
            # PIM-eligible administrators come from a separate read. Without it
            # the holder list is short, so a bypass found still counts but no
            # bypass is not established. An absent key (an older results file)
            # replays as collected, the collector doctrine's rule.
            $eligStatus = [string](Get-TPNestedProperty -Object $roles -Path 'Data.SectionStatus.RoleEligibilitySchedules' -Default 'Collected')
            if ($eligStatus -ne 'Collected') { $holdersComplete = $false }
            $pool = @(Get-TPNestedProperty -Object $roles -Path 'Data.AllPrivilegedAssignments' -Default @())
            if ($pool.Count -eq 0) { $pool = @(Get-TPNestedProperty -Object $roles -Path 'Data.PrivRoles' -Default @()) }
            $holders = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($a in $pool) { $p = [string](Get-TPObjectField -Item $a -Key 'PrincipalId' -Default ''); if ($p) { $null = $holders.Add($p) } }
            $events = @($events | Where-Object { $holders.Contains([string](Get-TPObjectField -Item $_ -Key 'UserId' -Default '')) })
            $label += ' (roles assigned to a group are not resolved to its members)'
        }
    }

    # ── Approved emergency-access accounts, by object id ──
    $setAside = @()
    if ($EmergencyAccess -and $EmergencyAccess.Count -gt 0) {
        $approvedUsers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($k in @($EmergencyAccess.Keys)) { $ks = [string]$k; if ($ks -like 'user:*') { $null = $approvedUsers.Add($ks.Substring(5)) } }
        $setAside = @($events | Where-Object { $approvedUsers.Contains([string](Get-TPObjectField -Item $_ -Key 'UserId' -Default '')) })
        $events   = @($events | Where-Object { -not $approvedUsers.Contains([string](Get-TPObjectField -Item $_ -Key 'UserId' -Default '')) })
    }
    $asideNote = ''
    if ($setAside.Count -gt 0) {
        $asideUsers = @($setAside | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'UserPrincipalName' -Default '') } | Where-Object { $_ } | Sort-Object -Unique)
        $asideNote = " $($setAside.Count) sign-in(s) by approved emergency-access account(s) were set aside: $($asideUsers -join ', ')."
    }

    # ── Single-factor: an earlier MFA claim is not a bypass ──
    # Microsoft: authenticationRequirement can read single-factor when a
    # previous MFA claim was accepted; check the authentication steps too.
    $mfaNote = ''; $unverified = @()
    if ($Check -eq 'SingleFactorSuccess') {
        $mfaShown = @(); $confirmed = @()
        foreach ($e in $events) {
            switch (Get-TPSignInMfaEvidence -SignIn $e) {
                'Mfa'          { $mfaShown += $e }
                'SingleFactor' { $confirmed += $e }
                default        { $unverified += $e }
            }
        }
        $events = $confirmed
        if ($mfaShown.Count -gt 0) { $mfaNote += " $($mfaShown.Count) sign-in(s) recorded as single-factor show MFA in their authentication steps (an earlier MFA claim) and were not counted." }
        if ($unverified.Count -gt 0) { $mfaNote += " $($unverified.Count) sign-in(s) carried no authentication steps, so whether an earlier MFA claim covered them is not established." }
    }
    $asideNote = "$mfaNote$asideNote"

    if ($events.Count -gt 0) {
        $byUser = @($events | Group-Object { [string](Get-TPObjectField -Item $_ -Key 'UserPrincipalName' -Default '(no UPN)') } | Sort-Object Count -Descending)
        $named = @($byUser | Select-Object -First 5 | ForEach-Object {
            $first = $_.Group[0]
            $how = @(
                [string](Get-TPObjectField -Item $first -Key 'ClientAppUsed' -Default ''),
                [string](Get-TPObjectField -Item $first -Key 'AppDisplayName' -Default '')
            ) | Where-Object { $_ }
            "$($_.Name) ($($_.Count); $($how -join ', '))"
        })
        $more = if ($byUser.Count -gt 5) { " and $($byUser.Count - 5) more" } else { '' }
        $partial = if (-not $complete -or -not $holdersComplete) { ' The read was not complete, so there may be more.' } else { '' }
        return & $out 'Ineffective' "$($events.Count) successful $label by $($byUser.Count) account(s) in $window`: $($named -join '; ')$more.$partial$asideNote"
    }
    if ($status -ne 'Collected') {
        return & $out 'Unknown' "The sign-in read for $label did not complete, so the absence of a bypass is not established.$asideNote"
    }
    if ($truncated) {
        return & $out 'Unknown' "The sign-in read for $label stopped at its page cap with none in scope found, so the absence of a bypass is not established.$asideNote"
    }
    if (-not $holdersComplete) {
        return & $out 'Unknown' "PIM-eligible role assignments were not collected, so the holder list is incomplete and the absence of a bypass is not established.$asideNote"
    }
    if ($unverified.Count -gt 0) {
        return & $out 'Unknown' "No confirmed $label in $window, but some could not be checked for an earlier MFA claim.$asideNote"
    }
    return & $out 'Effective' "No successful $label in $window. The protection held for the sign-ins that happened; that is not proof no client could get through.$asideNote"
}

function Get-TPSignInMfaEvidence {
    <#
    .SYNOPSIS
        Mfa when a sign-in's authentication steps show a second factor or a
        satisfied MFA requirement, SingleFactor when the steps were recorded
        and show neither, Unknown when no steps were recorded.
    .DESCRIPTION
        The method names and result details are the ones Microsoft lists for
        the Authentication Details of a sign-in (howto-mfa-reporting). A step
        whose requirement is multifactor and that succeeded is MFA whatever
        its method is called.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowNull()] [object] $SignIn)
    $rows = @(Get-TPObjectField -Item $SignIn -Key 'AuthDetails' -Default $null | Where-Object { $null -ne $_ })
    if ($rows.Count -eq 0) { return 'Unknown' }
    $mfaMethod = '^(Mobile app notification|OATH verification code|Text message|Phone call|FIDO2 security key|Passkey|Windows Hello for Business|Passwordless phone sign-in|Microsoft Authenticator|Temporary Access Pass|Previously satisfied)'
    $mfaResult = '(?i)\bMFA\b.*\b(satisfied|completed|successfully)\b'
    foreach ($d in $rows) {
        $ok = Get-TPObjectField -Item $d -Key 'Succeeded' -Default $null
        if ($ok -eq $false) { continue }
        $method = [string](Get-TPObjectField -Item $d -Key 'Method' -Default '')
        $step   = [string](Get-TPObjectField -Item $d -Key 'Step' -Default '')
        $result = [string](Get-TPObjectField -Item $d -Key 'Result' -Default '')
        if ($method -match $mfaMethod -or $result -match $mfaResult -or $step -match '(?i)multi.?factor|\bMFA\b') { return 'Mfa' }
    }
    return 'SingleFactor'
}

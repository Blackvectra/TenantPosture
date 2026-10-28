#Requires -Version 7.0
#
# Get-TPChangeImpact.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Answer "if we fix this, what breaks, and for whom?" for every open
#   finding of a run. Three lists:
#
#     Implement now          licensed, and the change is documented as
#                            invisible to users (Get-TPLowFrictionArchetypes,
#                            the same rule as the improvement plan's 'Do now');
#     Needs planning         licensed, and somebody will notice: a window, a
#                            message to users or a discovery pass first;
#     Could break accounts   the change can lock a person, an administrator, a
#                            device or a mailbox out (Config/change-impact.json,
#                            accountRisk), or its impact is not documented at
#                            all, which is never evidence of no impact.
#
#   Each "could break accounts" item names the accounts the run's own data shows
#   would be affected: legacy-client sign-ins, accounts with no MFA method,
#   admins without a phishing-resistant method, phone-only MFA, permanent admin
#   assignments, SMTP AUTH and forwarding mailboxes, shared-mailbox sign-in,
#   users of non-compliant devices, and the emergency-access accounts every new
#   policy must exclude.
#
# HONESTY RULES (pinned by TP.ChangeImpact.Tests.ps1):
#   - Accounts are named only from data the run read. A source that was not
#     read is NotRead with the reason; a read that failed or stopped at a page
#     cap is incomplete, and with nobody found it is NotEstablished, never
#     "none". NoneFound is said only after a complete read, and it never means
#     nothing can break: what the tool cannot see is stated (Unseen).
#   - A control the tenant is not confirmed licensed for goes to the license
#     decisions, never into the three lists.
#   - It is a VIEW: it creates no finding, changes none, and moves no score.
#
# Inputs:  -Findings, -Metadata, -RawData (defaults to module state),
#          -LicenseProfile, -EmergencyAccessRecord (Get-TPBaselineExceptions
#          output; read by -TenantDomain when omitted), -CatalogPath,
#          -ImpactPath, -AccountCap.
# Consumes raw data keys: AAD-SignInEvidence, AAD-Users, AAD-DirectoryRoles,
#          EXO-Inventory, Intune-DeviceCompliance (all read, none required).
# Graph scopes / cmdlets used: none. No network.

# The authentication methods Microsoft's phishing-resistant strength accepts
# that userRegistrationDetails.methodsRegistered can name: FIDO2 security key,
# device-bound passkeys, Windows Hello for Business and the macOS platform
# credential. A synced passkey is left out on purpose: whether it satisfies the
# tenant's strength depends on the passkey profile, and leaving it out names the
# account for review rather than missing one that would be locked out.
$script:TPPhishResistantMethods = @(
    'fido2SecurityKey', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator',
    'passKeyDeviceBoundWindowsHello', 'windowsHelloForBusiness', 'macOsSecureEnclaveKey'
)
$script:TPPhoneMfaMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone')
# Methods that are not a second factor (self-service password reset only).
$script:TPNonMfaMethods = @('email', 'securityQuestion')
# Every other method name Microsoft documents for methodsRegistered.
$script:TPOtherMfaMethods = @(
    'microsoftAuthenticatorPush', 'microsoftAuthenticatorPasswordless', 'softwareOneTimePasscode',
    'hardwareOneTimePasscode', 'temporaryAccessPass', 'passKeySynced'
)

function Get-TPChangeImpactCatalog {
    [CmdletBinding()]
    param([AllowEmptyString()] [string] $Path = '')
    if (-not $Path) {
        $root = if ((Get-Variable -Name TPModuleRoot -Scope Script -ErrorAction SilentlyContinue) -and $script:TPModuleRoot) { $script:TPModuleRoot } else { Split-Path -Parent $PSScriptRoot }
        $Path = Join-Path $root 'Config' 'change-impact.json'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 32 -ErrorAction Stop)
}

# One raw-data entry from a map that may be module state, a hashtable restored
# from a results file, or $null.
function Get-TPChangeImpactRaw {
    [CmdletBinding()]
    param([AllowNull()] [object] $RawData, [Parameter(Mandatory)] [string] $Key)
    if ($null -eq $RawData) { return $null }
    if ($RawData -is [System.Collections.IDictionary]) { if ($RawData.Contains($Key)) { return $RawData[$Key] } else { return $null } }
    return (Get-TPObjectField -Item $RawData -Key $Key -Default $null)
}

# A section's status: the recorded one, 'Collected' when the collector succeeded
# and recorded none (older results replay as collected), 'NotRead' otherwise.
function Get-TPChangeImpactSection {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [object] $Entry, [Parameter(Mandatory)] [string] $Section)
    if ($null -eq $Entry -or -not [bool](Get-TPObjectField -Item $Entry -Key 'Success' -Default $false)) { return 'NotRead' }
    return [string](Get-TPNestedProperty -Object $Entry -Path "Data.SectionStatus.$Section" -Default 'Collected')
}

# The approved emergency-access users, by lower-case object id.
function Get-TPChangeImpactEmergencyIds {
    [CmdletBinding()]
    param([AllowNull()] [object] $Record)
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ea = Get-TPObjectField -Item $Record -Key 'EmergencyAccess' -Default $null
    if ($ea -is [System.Collections.IDictionary]) {
        foreach ($k in @($ea.Keys)) { $ks = [string]$k; if ($ks -like 'user:*') { $null = $ids.Add($ks.Substring(5)) } }
    }
    return , $ids
}

# Builds one evidence block. Accounts is a list of ordered records
# (DisplayName, UserPrincipalName, ObjectId, Detail); Complete says whether the
# read behind it was whole.
function New-TPChangeImpactBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Type,
        [Parameter(Mandatory)] [string] $Label,
        [ValidateSet('WouldBreak', 'MustExclude')] [string] $Role = 'WouldBreak',
        [AllowNull()] [object[]] $Accounts = @(),
        [bool] $Read = $true,
        [bool] $Complete = $true,
        [AllowEmptyString()] [string] $Note = '',
        [AllowNull()] [System.Collections.Generic.HashSet[string]] $EmergencyIds,
        [int] $AccountCap = 200
    )
    $rows = @($Accounts | Where-Object { $null -ne $_ } | Sort-Object { [string]$_.UserPrincipalName }, { [string]$_.DisplayName })
    if ($Role -eq 'WouldBreak' -and $null -ne $EmergencyIds -and $EmergencyIds.Count -gt 0) {
        foreach ($r in $rows) {
            if ($r.ObjectId -and $EmergencyIds.Contains([string]$r.ObjectId)) {
                $r['Detail'] = (([string]$r.Detail).TrimEnd() + ' Approved emergency-access account: exclude it from the change rather than fix it.').Trim()
            }
        }
    }
    $status = if (-not $Read) { 'NotRead' }
              elseif ($rows.Count -gt 0) { 'Named' }
              elseif ($Complete) { 'NoneFound' }
              else { 'NotEstablished' }
    $shown = @($rows | Select-Object -First $AccountCap)
    return [ordered]@{
        Type      = $Type
        Label     = $Label
        Role      = $Role
        Status    = $status
        Complete  = [bool]($Read -and $Complete)
        Count     = $rows.Count
        Accounts  = $shown
        NotShown  = [math]::Max(0, $rows.Count - $shown.Count)
        Note      = $Note
    }
}

function New-TPChangeImpactAccount {
    [CmdletBinding()]
    param([AllowEmptyString()] [string] $DisplayName = '', [AllowEmptyString()] [string] $UserPrincipalName = '', [AllowEmptyString()] [string] $ObjectId = '', [AllowEmptyString()] [string] $Detail = '')
    return [ordered]@{ DisplayName = $DisplayName; UserPrincipalName = $UserPrincipalName; ObjectId = $ObjectId.ToLowerInvariant(); Detail = $Detail }
}

# The accounts one evidence spec names. $Spec is a catalog entry
# ({ Type, Scope?, ClientApps? }).
function Get-TPChangeImpactEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Spec,
        [AllowNull()] [object] $RawData,
        [AllowNull()] [object] $EmergencyAccessRecord,
        [AllowEmptyString()] [string] $TenantDomain = '',
        [int] $AccountCap = 200
    )
    Set-StrictMode -Version Latest
    $type = [string](Get-TPObjectField -Item $Spec -Key 'Type' -Default '')
    $eaIds = Get-TPChangeImpactEmergencyIds -Record $EmergencyAccessRecord
    $acct = ${function:New-TPChangeImpactAccount}
    $block = {
        param([string] $Label, [object[]] $Accounts = @(), [bool] $Read = $true, [bool] $Complete = $true, [string] $Note = '', [string] $Role = 'WouldBreak')
        New-TPChangeImpactBlock -Type $type -Label $Label -Role $Role -Accounts $Accounts -Read $Read -Complete $Complete -Note $Note -EmergencyIds $eaIds -AccountCap $AccountCap
    }

    switch ($type) {
        { $_ -in @('LegacyAuthSignIns', 'SingleFactorSignIns') } {
            $ev = Get-TPChangeImpactRaw -RawData $RawData -Key 'AAD-SignInEvidence'
            $isLegacy = ($type -eq 'LegacyAuthSignIns')
            $scope = [string](Get-TPObjectField -Item $Spec -Key 'Scope' -Default 'All')
            $apps = @(Get-TPObjectField -Item $Spec -Key 'ClientApps' -Default @() | Where-Object { $_ })
            $label = if (-not $isLegacy) { 'Signed in without a second factor' }
                     elseif ($apps.Count) { "Signed in through $($apps -join ' or ')" }
                     elseif ($scope -eq 'Exchange') { 'Signed in to Exchange Online through a legacy client' }
                     elseif ($scope -eq 'SharePoint') { 'Signed in to SharePoint through a legacy client' }
                     else { 'Signed in through a legacy authentication client' }
            if ($null -eq $ev -or -not [bool](Get-TPObjectField -Item $ev -Key 'Success' -Default $false)) {
                return (& $block $label @() $false $false 'The sign-in log was not read in this run.')
            }
            $data = Get-TPObjectField -Item $ev -Key 'Data' -Default $null
            if (-not [bool](Get-TPObjectField -Item $data -Key 'Available' -Default $false)) {
                $why = switch ([string](Get-TPObjectField -Item $data -Key 'UnavailableReason' -Default '')) {
                    'PremiumLicenseRequired' { 'The sign-in log could not be read: Microsoft requires Entra ID P1 or P2 to read it through Graph.' }
                    'AccessDenied'           { 'The sign-in log could not be read: the signed-in account holds no role that reads it (Global Reader, Reports Reader or Security Reader).' }
                    default                  { 'The sign-in log could not be read.' }
                }
                return (& $block $label @() $false $false $why)
            }
            $days = [int](Get-TPObjectField -Item $data -Key 'WindowDays' -Default 0)
            $section = if ($isLegacy) { 'LegacyAuth' } else { 'SingleFactor' }
            $status = [string](Get-TPNestedProperty -Object $data -Path "SectionStatus.$section" -Default 'NotRun')
            $sec = Get-TPNestedProperty -Object $data -Path "Sections.$section" -Default $null
            $events = @(Get-TPObjectField -Item $sec -Key 'Events' -Default @() | Where-Object { $null -ne $_ })
            $truncated = [bool](Get-TPObjectField -Item $sec -Key 'Truncated' -Default $false)
            if ($status -eq 'NotRun') { return (& $block $label @() $false $false 'This part of the sign-in log was not read.') }
            $complete = ($status -eq 'Collected') -and -not $truncated
            $unknown = 0
            if ($isLegacy) {
                if ($apps.Count) { $events = @($events | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'ClientAppUsed' -Default '') -in $apps }) }
                elseif ($scope -eq 'Exchange') {
                    $events = @($events | Where-Object {
                        [string](Get-TPObjectField -Item $_ -Key 'ResourceId' -Default '') -eq $script:TPSignInExchangeResourceId -or
                        [string](Get-TPObjectField -Item $_ -Key 'ClientAppUsed' -Default '') -ne 'Other clients'
                    })
                } elseif ($scope -eq 'SharePoint') {
                    $events = @($events | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'ResourceId' -Default '') -eq $script:TPSignInSharePointResourceId })
                }
            } else {
                $kept = [System.Collections.Generic.List[object]]::new()
                foreach ($e in $events) {
                    $m = Get-TPSignInMfaEvidence -SignIn $e
                    if ($m -eq 'SingleFactor') { $kept.Add($e) } elseif ($m -eq 'Unknown') { $unknown++ }
                }
                $events = $kept.ToArray()
            }
            $byUser = [ordered]@{}
            foreach ($e in $events) {
                $uid = [string](Get-TPObjectField -Item $e -Key 'UserId' -Default '')
                $upn = [string](Get-TPObjectField -Item $e -Key 'UserPrincipalName' -Default '')
                $k = if ($uid) { $uid } else { $upn.ToLowerInvariant() }
                if (-not $k) { continue }
                if (-not $byUser.Contains($k)) { $byUser[$k] = [ordered]@{ Upn = $upn; Id = $uid; Count = 0; Apps = [System.Collections.Generic.List[string]]::new(); Last = '' } }
                $u = $byUser[$k]; $u.Count++
                $app = if ($isLegacy) { [string](Get-TPObjectField -Item $e -Key 'ClientAppUsed' -Default '') } else { [string](Get-TPObjectField -Item $e -Key 'AppDisplayName' -Default '') }
                if ($app -and -not $u.Apps.Contains($app)) { $u.Apps.Add($app) }
                $t = [string](Get-TPObjectField -Item $e -Key 'CreatedDateTime' -Default '')
                if ($t -gt $u.Last) { $u.Last = $t }
            }
            $rows = foreach ($k in $byUser.Keys) {
                $u = $byUser[$k]
                $when = ConvertTo-TPUtcDateTime $u.Last
                $lastText = if ($null -ne $when) { '; last ' + $when.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { '' }
                $via = if ($u.Apps.Count) { ($(if ($isLegacy) { ' through ' } else { ' to ' }) + ($u.Apps -join ', ')) } else { '' }
                & $acct '' $u.Upn $u.Id "$($u.Count) successful sign-in(s)$via in the $days-day window$lastText."
            }
            $notes = [System.Collections.Generic.List[string]]::new()
            if ($status -eq 'Failed') { $notes.Add('The read failed part-way; sign-ins found before the failure are listed, and the list may not be whole.') }
            if ($truncated) { $notes.Add('The read stopped at its page cap, so the list may not be whole.') }
            if ($unknown -gt 0) { $complete = $false; $notes.Add("$unknown sign-in(s) recorded no authentication steps, so whether they used a second factor is not established; they are not listed.") }
            if ($complete -and @($rows | Where-Object { $null -ne $_ }).Count -eq 0) { $notes.Add("No such sign-in in the $days-day window. A device or account used less often than that is not seen.") }
            return (& $block $label @($rows) $true $complete ($notes -join ' '))
        }

        { $_ -in @('MfaUnregistered', 'AdminsWithoutPhishResistant', 'PhoneOnlyMfa') } {
            $label = switch ($type) {
                'MfaUnregistered'             { 'No MFA method registered' }
                'AdminsWithoutPhishResistant' { 'Administrators with no phishing-resistant method registered' }
                default                       { 'Only a phone method (text or voice) registered for MFA' }
            }
            $users = Get-TPChangeImpactRaw -RawData $RawData -Key 'AAD-Users'
            $status = Get-TPChangeImpactSection -Entry $users -Section 'MFARegistration'
            if ($status -ne 'Collected') {
                $why = if ([string](Get-TPNestedProperty -Object $users -Path 'Data.MFARegistrationFailure' -Default '') -eq 'PremiumLicenseRequired') {
                    'The MFA registration report could not be read: Microsoft requires Entra ID P1 or P2 for it.'
                } else { 'The MFA registration report was not read in this run.' }
                return (& $block $label @() $false $false $why)
            }
            $details = @(Get-TPNestedProperty -Object $users -Path 'Data.MFARegistration.RegistrationDetails' -Default @() | Where-Object { $null -ne $_ })
            # Disabled accounts cannot be locked out; drop the ones the user list
            # shows disabled. Accounts it does not list are kept.
            $disabled = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($u in @(Get-TPNestedProperty -Object $users -Path 'Data.Users' -Default @())) {
                if ($null -eq $u) { continue }
                if ((Get-TPObjectField -Item $u -Key 'AccountEnabled' -Default $true) -eq $false) { $null = $disabled.Add([string](Get-TPObjectField -Item $u -Key 'Id' -Default '')) }
            }
            $known = @($script:TPPhishResistantMethods + $script:TPPhoneMfaMethods + $script:TPNonMfaMethods + $script:TPOtherMfaMethods)
            $rows = [System.Collections.Generic.List[object]]::new()
            $unrecognized = 0
            foreach ($d in $details) {
                $id = [string](Get-TPObjectField -Item $d -Key 'Id' -Default '')
                if ($id -and $disabled.Contains($id)) { continue }
                $upn = [string](Get-TPObjectField -Item $d -Key 'UserPrincipalName' -Default '')
                $name = [string](Get-TPObjectField -Item $d -Key 'UserDisplayName' -Default '')
                $isAdmin = [bool](Get-TPObjectField -Item $d -Key 'IsAdmin' -Default $false)
                $methods = @(Get-TPObjectField -Item $d -Key 'AuthMethodsRegistered' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
                $methodText = if ($methods.Count) { 'Registered: ' + ($methods -join ', ') + '.' } else { 'Nothing registered.' }
                switch ($type) {
                    'MfaUnregistered' {
                        if ((Get-TPObjectField -Item $d -Key 'IsMfaRegistered' -Default $false) -eq $true) { continue }
                        $rows.Add((& $acct $name $upn $id ("No MFA method registered.$(if ($isAdmin) { ' Holds an admin role.' })")))
                    }
                    'AdminsWithoutPhishResistant' {
                        if (-not $isAdmin) { continue }
                        if (@($methods | Where-Object { $_ -in $script:TPPhishResistantMethods }).Count -gt 0) { continue }
                        $extra = if ($methods -contains 'passKeySynced') { ' Has a synced passkey: whether the tenant''s phishing-resistant strength accepts it depends on its passkey settings.' } else { '' }
                        $rows.Add((& $acct $name $upn $id "$methodText$extra"))
                    }
                    default {
                        $strong = @($methods | Where-Object { $_ -notin $script:TPNonMfaMethods })
                        if ($strong.Count -eq 0) { continue }
                        if (@($strong | Where-Object { $_ -notin $known }).Count -gt 0) { $unrecognized++; continue }
                        if (@($strong | Where-Object { $_ -notin $script:TPPhoneMfaMethods }).Count -gt 0) { continue }
                        $rows.Add((& $acct $name $upn $id $methodText))
                    }
                }
            }
            $note = ''
            $complete = $true
            if ($type -eq 'PhoneOnlyMfa' -and $unrecognized -gt 0) {
                $complete = $false
                $note = "$unrecognized account(s) registered a method this tool does not recognize, so whether they rely on phone methods alone is not established; they are not listed."
            }
            if ($type -eq 'AdminsWithoutPhishResistant') { $note = 'Admin status is Microsoft''s isAdmin flag on the registration report; a role assigned to a group is not resolved to its members.' }
            return (& $block $label $rows.ToArray() $true $complete $note)
        }

        { $_ -in @('PrivilegedPermanent', 'GlobalAdmins', 'PrivilegedHolders') } {
            $label = switch ($type) {
                'PrivilegedPermanent' { 'Permanent (standing) privileged role assignments' }
                'GlobalAdmins'        { 'Global Administrators (permanent and eligible)' }
                default               { 'Privileged role holders (permanent and eligible)' }
            }
            $roles = Get-TPChangeImpactRaw -RawData $RawData -Key 'AAD-DirectoryRoles'
            $permStatus = Get-TPChangeImpactSection -Entry $roles -Section 'RoleAssignments'
            $eligStatus = Get-TPChangeImpactSection -Entry $roles -Section 'RoleEligibilitySchedules'
            if ($permStatus -ne 'Collected' -and ($type -eq 'PrivilegedPermanent' -or $eligStatus -ne 'Collected')) {
                return (& $block $label @() $false $false 'Directory role assignments were not read in this run.')
            }
            $pool = if ($type -eq 'PrivilegedPermanent') { @(Get-TPNestedProperty -Object $roles -Path 'Data.RoleAssignments' -Default @()) }
                    else { @(Get-TPNestedProperty -Object $roles -Path 'Data.AllPrivilegedAssignments' -Default @()) }
            $byPrincipal = [ordered]@{}
            foreach ($a in @($pool | Where-Object { $null -ne $_ })) {
                if (-not [bool](Get-TPObjectField -Item $a -Key 'IsPriv' -Default $false)) { continue }
                $roleName = [string](Get-TPObjectField -Item $a -Key 'RoleDefinitionName' -Default '')
                if ($type -eq 'GlobalAdmins' -and $roleName -ne 'Global Administrator') { continue }
                $principalId = [string](Get-TPObjectField -Item $a -Key 'PrincipalId' -Default '')
                if (-not $principalId) { continue }
                if (-not $byPrincipal.Contains($principalId)) {
                    $byPrincipal[$principalId] = [ordered]@{
                        Name = [string](Get-TPObjectField -Item $a -Key 'PrincipalDisplayName' -Default '')
                        Upn  = [string](Get-TPObjectField -Item $a -Key 'PrincipalUPN' -Default '')
                        Kind = [string](Get-TPObjectField -Item $a -Key 'PrincipalType' -Default '')
                        Roles = [System.Collections.Generic.List[string]]::new()
                    }
                }
                $src = [string](Get-TPObjectField -Item $a -Key 'Source' -Default 'permanent')
                $entry = if ($type -eq 'PrivilegedPermanent') { $roleName } else { "$roleName ($src)" }
                if ($entry -and -not $byPrincipal[$principalId].Roles.Contains($entry)) { $byPrincipal[$principalId].Roles.Add($entry) }
            }
            $rows = foreach ($k in $byPrincipal.Keys) {
                $p = $byPrincipal[$k]
                $kindText = if ($p.Kind -match 'group') { ' Assigned to a group: its members are not resolved.' } elseif ($p.Kind -match 'servicePrincipal') { ' A service principal, not a person.' } else { '' }
                & $acct $p.Name $p.Upn $k ("Holds: $($p.Roles -join ', ').$kindText")
            }
            $complete = ($permStatus -eq 'Collected') -and ($type -eq 'PrivilegedPermanent' -or $eligStatus -eq 'Collected')
            $note = if (-not $complete) { 'PIM-eligible assignments were not read, so the list may not be whole.' } else { '' }
            return (& $block $label @($rows) $true $complete $note)
        }

        { $_ -in @('SmtpAuthMailboxes', 'ForwardingMailboxes', 'ForwardingRules', 'SharedMailboxSignIn') } {
            $exo = Get-TPChangeImpactRaw -RawData $RawData -Key 'EXO-Inventory'
            $section = switch ($type) { 'SmtpAuthMailboxes' { 'SmtpAuthEnabledPerUser' } 'ForwardingMailboxes' { 'ForwardingMailboxes' } 'ForwardingRules' { 'InboxRulesForwarding' } default { 'SharedMailboxes' } }
            $label = switch ($type) {
                'SmtpAuthMailboxes'   { 'Mailboxes with SMTP AUTH enabled on the mailbox itself' }
                'ForwardingMailboxes' { 'Mailboxes forwarding to an external address' }
                'ForwardingRules'     { 'Inbox rules forwarding or redirecting outside the organization' }
                default               { 'Shared mailboxes whose account can sign in directly' }
            }
            $status = Get-TPChangeImpactSection -Entry $exo -Section $section
            if ($status -ne 'Collected') {
                $why = if ($status -eq 'NotRead') { 'Exchange Online was not read in this run.' } else { 'This Exchange Online read did not complete in this run.' }
                return (& $block $label @() $false $false $why)
            }
            $data = Get-TPObjectField -Item $exo -Key 'Data' -Default $null
            $rows = [System.Collections.Generic.List[object]]::new()
            $complete = $true; $note = ''
            switch ($type) {
                'SmtpAuthMailboxes' {
                    $list = @(Get-TPObjectField -Item $data -Key 'SmtpAuthEnabledPerUser' -Default @() | Where-Object { $null -ne $_ })
                    foreach ($m in $list) { $rows.Add((& $acct ([string](Get-TPObjectField -Item $m -Key 'DisplayName' -Default '')) ([string](Get-TPObjectField -Item $m -Key 'UPN' -Default '')) '' 'SMTP AUTH is enabled on this mailbox.')) }
                    $total = [int](Get-TPObjectField -Item $data -Key 'SmtpAuthEnabledPerUserCount' -Default $list.Count)
                    if ($total -gt $list.Count) { $complete = $false; $note = "$total mailbox(es) have it enabled; the results file names the first $($list.Count)." }
                }
                'ForwardingMailboxes' {
                    $unclassified = 0
                    foreach ($m in @(Get-TPObjectField -Item $data -Key 'ForwardingMailboxes' -Default @() | Where-Object { $null -ne $_ })) {
                        $class = [string](Get-TPObjectField -Item $m -Key 'Classification' -Default '')
                        if (-not $class) { $class = if ([bool](Get-TPObjectField -Item $m -Key 'IsExternal' -Default $false)) { 'External' } else { 'Internal' } }
                        if ($class -eq 'Unresolved') { $unclassified++; continue }
                        if ($class -ne 'External') { continue }
                        $copy = if ([bool](Get-TPObjectField -Item $m -Key 'DeliverToMailboxAndForward' -Default $false)) { ' keeps a copy' } else { ' keeps no copy' }
                        $rows.Add((& $acct ([string](Get-TPObjectField -Item $m -Key 'DisplayName' -Default '')) ([string](Get-TPObjectField -Item $m -Key 'UPN' -Default '')) '' "Forwards to $([string](Get-TPObjectField -Item $m -Key 'ForwardingAddress' -Default '')) ($([string](Get-TPObjectField -Item $m -Key 'ForwardingMechanism' -Default '')));$copy."))
                    }
                    if ($unclassified -gt 0) { $complete = $false; $note = "$unclassified forwarding target(s) could not be classified as internal or external and are not listed." }
                }
                'ForwardingRules' {
                    $unclassified = 0
                    foreach ($r in @(Get-TPObjectField -Item $data -Key 'InboxRulesForwarding' -Default @() | Where-Object { $null -ne $_ })) {
                        $ext = @(Get-TPObjectField -Item $r -Key 'ExternalRecipients' -Default @() | Where-Object { $_ })
                        if (@(Get-TPObjectField -Item $r -Key 'UnresolvedRecipients' -Default @() | Where-Object { $_ }).Count -gt 0) { $unclassified++ }
                        if ($ext.Count -eq 0) { continue }
                        $on = if ([bool](Get-TPObjectField -Item $r -Key 'Enabled' -Default $true)) { 'enabled' } else { 'disabled' }
                        $rows.Add((& $acct ([string](Get-TPObjectField -Item $r -Key 'DisplayName' -Default '')) ([string](Get-TPObjectField -Item $r -Key 'Mailbox' -Default '')) '' "Rule '$([string](Get-TPObjectField -Item $r -Key 'RuleName' -Default ''))' ($on) sends to $($ext -join ', ')."))
                    }
                    $failed = [int](Get-TPNestedProperty -Object $data -Path 'Stats.MailboxesRuleScanFailed' -Default 0)
                    $parts = @()
                    if ($unclassified -gt 0) { $parts += "$unclassified rule(s) have a recipient that could not be classified." }
                    if ($failed -gt 0) { $parts += "The rules of $failed mailbox(es) could not be read." }
                    if ($parts.Count) { $complete = $false; $note = $parts -join ' ' }
                }
                default {
                    foreach ($m in @(Get-TPObjectField -Item $data -Key 'SharedMailboxSignIn' -Default @() | Where-Object { $null -ne $_ })) {
                        $state = [string](Get-TPObjectField -Item $m -Key 'SignInState' -Default '')
                        $rows.Add((& $acct ([string](Get-TPObjectField -Item $m -Key 'DisplayName' -Default '')) ([string](Get-TPObjectField -Item $m -Key 'UPN' -Default '')) '' $(if ($state -eq 'Probable') { 'Sign-in probably enabled (judged from licensing; Entra was not read for it).' } else { 'Sign-in is enabled on the account.' })))
                    }
                    $unconfirmed = @(Get-TPObjectField -Item $data -Key 'SharedMailboxUnconfirmed' -Default @() | Where-Object { $null -ne $_ }).Count
                    if ($unconfirmed -gt 0) { $complete = $false; $note = "$unconfirmed shared mailbox(es) could not be matched to an Entra account, so whether they can sign in is not established." }
                }
            }
            return (& $block $label $rows.ToArray() $true $complete $note)
        }

        'NonCompliantDevices' {
            $label = 'Users of Intune-managed devices that are not compliant'
            $int = Get-TPChangeImpactRaw -RawData $RawData -Key 'Intune-DeviceCompliance'
            $status = Get-TPChangeImpactSection -Entry $int -Section 'OSComplianceSummary'
            if ($status -ne 'Collected') { return (& $block $label @() $false $false 'Intune managed devices were not read in this run.') }
            $sum = Get-TPNestedProperty -Object $int -Path 'Data.OSComplianceSummary' -Default $null
            $hasList = ($sum -is [System.Collections.IDictionary] -and $sum.Contains('NonCompliantDevices')) -or
                       ($null -ne $sum -and $sum -isnot [System.Collections.IDictionary] -and $null -ne $sum.PSObject.Properties['NonCompliantDevices'])
            if (-not $hasList) { return (& $block $label @() $false $false 'This results file was written before the tool read the user of each device; run the assessment again to name them.') }
            $byUser = [ordered]@{}
            $noUser = 0
            foreach ($d in @(Get-TPObjectField -Item $sum -Key 'NonCompliantDevices' -Default @() | Where-Object { $null -ne $_ })) {
                $upn = [string](Get-TPObjectField -Item $d -Key 'UserPrincipalName' -Default '')
                $dev = "$([string](Get-TPObjectField -Item $d -Key 'DeviceName' -Default 'unnamed device')) ($([string](Get-TPObjectField -Item $d -Key 'OperatingSystem' -Default '')), $([string](Get-TPObjectField -Item $d -Key 'ComplianceState' -Default '')))"
                if (-not $upn) { $noUser++; continue }
                if (-not $byUser.Contains($upn)) { $byUser[$upn] = [System.Collections.Generic.List[string]]::new() }
                $byUser[$upn].Add($dev)
            }
            $rows = foreach ($k in $byUser.Keys) { & $acct '' $k '' ("Device(s): " + ($byUser[$k] -join '; ') + '.') }
            $complete = -not [bool](Get-TPObjectField -Item $sum -Key 'NonCompliantTruncated' -Default $false)
            $parts = @()
            if (-not $complete) { $parts += 'The device read stopped at its page cap, so the list may not be whole.' }
            if ($noUser -gt 0) { $parts += "$noUser non-compliant device(s) have no primary user recorded." }
            $parts += 'Devices not enrolled in Intune are not seen; their users are affected too.'
            return (& $block $label @($rows) $true $complete ($parts -join ' '))
        }

        'EmergencyAccess' {
            $label = 'Emergency-access accounts to exclude'
            $entries = @(Get-TPObjectField -Item $EmergencyAccessRecord -Key 'EmergencyAccessEntries' -Default @() | Where-Object { $null -ne $_ })
            $approved = @($entries | Where-Object { [bool](Get-TPObjectField -Item $_ -Key 'Approved' -Default $false) })
            $rejected = @($entries | Where-Object { -not [bool](Get-TPObjectField -Item $_ -Key 'Approved' -Default $false) })
            $where = if ($TenantDomain) { "Config/baseline-exceptions/$TenantDomain.psd1" } else { 'Config/baseline-exceptions/<tenant>.psd1' }
            if ($approved.Count -eq 0) {
                $note = "No approved emergency-access account is on record for this tenant ($where). Before turning the change on, confirm at least one cloud-only emergency-access account exists and is excluded, or a mistake in the policy can lock every administrator out."
                if ($rejected.Count) { $note += " $($rejected.Count) entry(ies) on file are not approved (missing fields, lapsed review or expired)." }
                return (New-TPChangeImpactBlock -Type $type -Label $label -Role 'MustExclude' -Accounts @() -Read $false -Complete $false -Note $note -AccountCap $AccountCap)
            }
            $rows = foreach ($e in $approved) {
                $kind = [string](Get-TPObjectField -Item $e -Key 'Kind' -Default 'User')
                & $acct ([string](Get-TPObjectField -Item $e -Key 'DisplayName' -Default '')) ([string](Get-TPObjectField -Item $e -Key 'UserPrincipalName' -Default '')) ([string](Get-TPObjectField -Item $e -Key 'ObjectId' -Default '')) $(if ($kind -eq 'Group') { 'A group on the record: exclude the group. Its membership is not resolved by the tool.' } else { 'Exclude this account from the new policy.' })
            }
            $note = "From the tenant's approval record ($where)."
            if ($rejected.Count) { $note += " $($rejected.Count) other entry(ies) on file are not approved and are not listed." }
            return (New-TPChangeImpactBlock -Type $type -Label $label -Role 'MustExclude' -Accounts @($rows) -Read $true -Complete $true -Note $note -AccountCap $AccountCap)
        }

        default { throw "Unknown change-impact evidence type '$type'." }
    }
}

function Get-TPChangeImpact {
    <#
    .SYNOPSIS
        Sorts a run's open findings into Implement now / Needs planning / Could
        break accounts, naming the accounts each risky change would affect.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [AllowNull()] [object] $Metadata,
        [AllowNull()] [object] $RawData,
        [AllowNull()] [object] $LicenseProfile,
        [AllowEmptyString()] [string] $TenantDomain = '',
        [AllowNull()] [object] $EmergencyAccessRecord,
        [AllowEmptyString()] [string] $CatalogPath = '',
        [AllowEmptyString()] [string] $ImpactPath = '',
        [ValidateRange(1, 5000)] [int] $AccountCap = 200
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $catalog = Get-TPChangeImpactCatalog -Path $CatalogPath
    if ($null -eq $catalog) { return [ordered]@{ Available = $false; Note = 'Config/change-impact.json was not found, so the change-impact view was not built.' } }
    if (-not $PSBoundParameters.ContainsKey('RawData')) { $RawData = try { Get-TPRawData } catch { $null } }
    if (-not $PSBoundParameters.ContainsKey('LicenseProfile')) { $LicenseProfile = try { Get-TPTenantLicenseProfile } catch { $null } }
    if (-not $TenantDomain) { $TenantDomain = ([string](Get-TPObjectField -Item $Metadata -Key 'TenantDomain' -Default '')).ToLowerInvariant() }
    if ($TenantDomain -and -not (Test-TPDomainName -Value $TenantDomain)) { $TenantDomain = '' }
    if (-not $PSBoundParameters.ContainsKey('EmergencyAccessRecord')) {
        $EmergencyAccessRecord = if ($TenantDomain) { try { Get-TPBaselineExceptions -TenantDomain $TenantDomain } catch { $null } } else { $null }
    }

    $impactCatalog = if ($ImpactPath) { Get-TPOperationalImpactCatalog -ConfigPath $ImpactPath } else { Get-TPOperationalImpactCatalog }
    $risk = Get-TPObjectField -Item $catalog -Key 'accountRisk' -Default @{}
    $defs = @{}
    foreach ($c in @(Get-TPControlDefinitions)) { $defs[[string]$c.ControlId] = $c }
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }
    $licenseRead = [bool](Get-TPObjectField -Item $LicenseProfile -Key 'HasLicenseData' -Default $false)

    # Every evidence block is computed once per distinct spec.
    $evidenceCache = @{}
    $evidenceFor = {
        param($spec)
        $key = ($spec | ConvertTo-Json -Compress -Depth 4)
        if (-not $evidenceCache.ContainsKey($key)) {
            $evidenceCache[$key] = Get-TPChangeImpactEvidence -Spec $spec -RawData $RawData -EmergencyAccessRecord $EmergencyAccessRecord -TenantDomain $TenantDomain -AccountCap $AccountCap
        }
        return $evidenceCache[$key]
    }

    $tiers = [ordered]@{
        ImplementNow       = [System.Collections.Generic.List[object]]::new()
        NeedsPlanning      = [System.Collections.Generic.List[object]]::new()
        CouldBreakAccounts = [System.Collections.Generic.List[object]]::new()
        LicenseDecision    = [System.Collections.Generic.List[object]]::new()
    }
    $worst = Get-TPControlWorstFindings -Findings @($Findings | Where-Object { $null -ne $_ })
    foreach ($cid in $worst.Keys) {
        $f = $worst[$cid]
        $state = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
        if ($state -notin @('Gap', 'Partial')) { continue }
        $def = if ($defs.ContainsKey($cid)) { $defs[$cid] } else { $null }
        $impact = Get-TPControlOperationalImpact -ControlId $cid -Catalog $impactCatalog
        $it = [ordered]@{
            ControlId     = $cid
            Title         = [string](Get-TPObjectField -Item $def -Key 'Title' -Default ([string](Get-TPObjectField -Item $f -Key 'Title' -Default $cid)))
            Severity      = [string](Get-TPObjectField -Item $def -Key 'Severity' -Default ([string](Get-TPObjectField -Item $f -Key 'Severity' -Default '')))
            State         = $state
            Workload      = [string](Get-TPObjectField -Item $def -Key 'Workload' -Default '')
            Archetype     = [string](Get-TPObjectField -Item $impact -Key 'Archetype' -Default '')
            Effort        = $(if ($null -ne $impact) { [string](Get-TPObjectField -Item $impact -Key 'Effort' -Default '') } else { 'Not documented' })
            ImpactSummary = $(if ($null -ne $impact) { [string](Get-TPObjectField -Item $impact -Key 'Summary' -Default '') } else { 'Operational impact not documented.' })
            UsersNotice   = [string](Get-TPObjectField -Item $impact -Key 'Users' -Default '')
            Reversible    = [string](Get-TPObjectField -Item $impact -Key 'Reversible' -Default '')
            Remediation   = [string](Get-TPFindingRemediation -Finding $f -Control $def)
        }
        $licensed = Test-TPFindingLicensed -Finding $f -Definition $def -LicenseProfile $LicenseProfile
        if (-not $licensed) {
            $it['License'] = [string](Get-TPObjectField -Item $def -Key 'LicenseRequirement' -Default '')
            $it['Reason'] = if ($licenseRead) { 'Not licensed: the tenant''s subscriptions do not include what this control needs.' } else { 'Licensing was not read in this run, so whether the tenant holds what this control needs is not confirmed.' }
            $tiers.LicenseDecision.Add($it); continue
        }
        $entry = if ($risk -is [System.Collections.IDictionary] -and $risk.Contains($cid)) { $risk[$cid] } else { $null }
        if ($null -ne $entry -or $null -eq $impact) {
            $blocks = [System.Collections.Generic.List[object]]::new()
            $ea = $null
            foreach ($spec in @(Get-TPObjectField -Item $entry -Key 'Evidence' -Default @() | Where-Object { $null -ne $_ })) {
                $b = & $evidenceFor $spec
                if ($b.Role -eq 'MustExclude') { $ea = $b } else { $blocks.Add($b) }
            }
            $named = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($b in $blocks) { foreach ($a in @($b.Accounts)) { $k = if ($a.UserPrincipalName) { $a.UserPrincipalName } elseif ($a.ObjectId) { $a.ObjectId } else { $a.DisplayName }; if ($k) { $null = $named.Add($k) } } }
            $it['Why'] = if ($null -ne $entry) { [string](Get-TPObjectField -Item $entry -Key 'Why' -Default '') } else { 'Operational impact not documented. Treat this change as able to break access until someone has checked what it affects.' }
            $it['Evidence'] = $blocks.ToArray()
            $it['EmergencyAccess'] = $ea
            $it['Unseen'] = [string](Get-TPObjectField -Item $entry -Key 'Unseen' -Default '')
            $it['AccountsNamed'] = $named.Count
            $it['MoreNotShown'] = [int](@($blocks | ForEach-Object { [int]$_.NotShown } | Measure-Object -Sum).Sum)
            $it['EvidenceComplete'] = (@($blocks | Where-Object { -not $_.Complete }).Count -eq 0) -and $blocks.Count -gt 0
            $it['ImpactDocumented'] = ($null -ne $impact)
            $tiers.CouldBreakAccounts.Add($it)
        } elseif ((Get-TPRemediationTrack -Licensed $true -Impact $impact) -eq 'Do now') {
            $tiers.ImplementNow.Add($it)
        } else {
            $tiers.NeedsPlanning.Add($it)
        }
    }

    # Each list is wrapped in @() where it is stored: a one-item list returned
    # through a scriptblock arrives as the item, and would serialize as an object.
    $sort = { param($list) @($list | Sort-Object @{ Expression = { $sevRank[[string]$_.Severity] ?? 9 } }, @{ Expression = { if ($_.State -eq 'Gap') { 0 } else { 1 } } }, @{ Expression = { $_.ControlId } }) }
    $allNamed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($it in $tiers.CouldBreakAccounts) { foreach ($b in @($it.Evidence)) { foreach ($a in @($b.Accounts)) { $k = if ($a.UserPrincipalName) { $a.UserPrincipalName } elseif ($a.ObjectId) { $a.ObjectId } else { $a.DisplayName }; if ($k) { $null = $allNamed.Add($k) } } } }

    $time = ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $Metadata -Key 'AssessmentTime' -Default $null)
    $scope = Get-TPRunScope -Metadata $Metadata
    $sel = Get-TPObjectField -Item $Metadata -Key 'ControlSelection' -Default $null
    return [ordered]@{
        Available       = $true
        Note            = ''
        CatalogVersion  = [string](Get-TPObjectField -Item $catalog -Key 'version' -Default '')
        TenantDomain    = $TenantDomain
        AssessedAt      = $(if ($null -ne $time) { $time.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) + ' UTC' } else { [string](Get-TPObjectField -Item $Metadata -Key 'AssessmentDate' -Default 'Not recorded') })
        ToolVersion     = [string](Get-TPObjectField -Item $Metadata -Key 'ToolVersion' -Default '')
        RunScope        = $scope
        ScopeNotice     = $(if ($scope -eq 'Partial') { Format-TPControlSelectionNotice -Selection $sel } elseif ($scope -eq 'Quick') { 'Quick scan: only Critical and High controls were evaluated, so the lists cover those only.' } else { '' })
        Summary         = [ordered]@{
            ImplementNow       = $tiers.ImplementNow.Count
            NeedsPlanning      = $tiers.NeedsPlanning.Count
            CouldBreakAccounts = $tiers.CouldBreakAccounts.Count
            LicenseDecision    = $tiers.LicenseDecision.Count
            AccountsNamed      = $allNamed.Count
        }
        ImplementNow       = @(& $sort $tiers.ImplementNow)
        NeedsPlanning      = @(& $sort $tiers.NeedsPlanning)
        CouldBreakAccounts = @(& $sort $tiers.CouldBreakAccounts)
        LicenseDecision    = @(& $sort $tiers.LicenseDecision)
        EmergencyAccess    = (& $evidenceFor ([ordered]@{ Type = 'EmergencyAccess' }))
        Statement       = 'This view sorts the open findings of this run by what fixing them would disturb. It changes no finding and no score. Accounts are named only from what the run read: a list marked incomplete or not read is not a list of everyone affected, and "none found" never means nothing can break. Test every change in report-only or on a pilot group before turning it on for everyone.'
        TierNotes       = [ordered]@{
            ImplementNow       = 'Licensed, and the change is documented as invisible to users. These can go in without a window.'
            NeedsPlanning      = 'Licensed, and somebody will notice: plan a window, tell the people affected, or do a discovery pass first.'
            CouldBreakAccounts = 'These can lock a person, an administrator, a device or a mailbox out. Each lists the accounts the run''s data shows would be affected and what the tool could not see.'
            LicenseDecision    = 'Not in the lists above: the tenant is not confirmed licensed for what the fix needs.'
        }
    }
}

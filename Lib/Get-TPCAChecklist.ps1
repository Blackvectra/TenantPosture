#Requires -Version 7.0
#
# Get-TPCAChecklist.ps1
# Dependencies: Get-TPObjectField, Get-TPNestedProperty, Test-TPLicenseRequirementMet,
#               Get-TPSecurityDefaultsState
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: The Conditional Access checklist, the way Maester checks it (owner's
#   decision 2026-10-28: "follow the way Maester does it"). Three kinds of row:
#
#     Presence    "is the recommended policy there?" One row per Maester test
#                 (MT.1001, MT.1003-MT.1019, MT.1052, MT.1181): the row passes
#                 when at least one ENABLED policy matches the pattern Maester
#                 matches, judged on state, users and roles, resources, client
#                 apps, conditions and grant or session controls.
#     Hygiene     the policies that exist (MT.1005, MT.1020, MT.1035, MT.1036,
#                 MT.1038, MT.1049, MT.1061, MT.1066, MT.1072, MT.1184,
#                 MT.1224): break-glass exclusions, sync accounts, unprotected
#                 groups, exclusions with no fallback, deleted objects, combined
#                 risk policies, the retired approved-app grant, policies with
#                 no target, Microsoft-managed policies left in report-only.
#     Simulation  Microsoft's What If evaluation for real accounts (MT.1033,
#                 MT.1034, and the tool's own MFA row), from AAD-CAWhatIf.
#
# For every presence row that is not met, the matching Microsoft Conditional
# Access template is returned as a report-only policy body (Config/ca-checklist.json
# 'templates'), with the tenant's approved emergency-access accounts and the
# Directory Synchronization Accounts role excluded. The tool never creates a
# policy: the files are for an administrator to review and import.
#
# WHERE THIS DIFFERS FROM MAESTER (each on purpose, each stated in the output)
#   - A presence row with no enabled match but a report-only policy that WOULD
#     match is "Report-only", not plain "Not met": the policy exists and needs
#     turning on, which is a different job from creating it.
#   - Emergency access accounts come from the tenant's approved record
#     (Config/baseline-exceptions/<tenant>.psd1, EmergencyAccess). Without one,
#     MT.1005 uses Maester's inference (the object most policies exclude) and
#     says the result rests on an inference; MT.1034 simulates only approved
#     accounts.
#   - MT.1033 passes for a user only when an ENABLED policy that BLOCKS applies
#     (Maester passes when any policy applies); a report-only block is named.
#   - MT.1036 does not count an approved emergency-access exclusion as a gap:
#     Microsoft says those accounts are excluded from every policy.
#   - A row whose data the run did not read is "Not assessed", never passed or
#     failed; a row a license blocks is "Needs license" only when the license
#     profile positively shows the license missing.
#
# A VIEW: no finding, no score, no change to any other output. Nothing it
# writes says "compliant".
#
# Inputs:  -RawData (Get-TPRawData output), -EmergencyAccessRecord
#          (Get-TPBaselineExceptions output), -LicenseProfile, -ConfigPath.
# Graph scopes / cmdlets used: none (it reads raw data already collected).

function Get-TPCAChecklistCatalog {
    [CmdletBinding()]
    param([AllowEmptyString()] [string] $Path = '')
    if (-not $Path) { $Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config/ca-checklist.json' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable)
}

function Get-TPCAChecklistStatusNames {
    [CmdletBinding()]
    param()
    return [ordered]@{
        Pass           = 'Passed'
        Fail           = 'Not met'
        Staged         = 'Report-only'
        NotAssessed    = 'Not assessed'
        NotApplicable  = 'Does not apply'
        NeedsLicense   = 'Needs license'
    }
}

# True when a hashtable or object carries the key at all (an older results
# file lacks fields added since; absent is "not read", never "false").
function Test-TPCAChecklistField {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [object] $Item, [Parameter(Mandatory)] [string] $Key)
    if ($null -eq $Item) { return $false }
    if ($Item -is [System.Collections.IDictionary]) { return $Item.Contains($Key) }
    return ($null -ne $Item.PSObject.Properties[$Key])
}

function Get-TPCAChecklist {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [object] $RawData,
        [AllowNull()] [object] $EmergencyAccessRecord,
        [AllowNull()] [object] $LicenseProfile,
        [AllowEmptyString()] [string] $ConfigPath = ''
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not $PSBoundParameters.ContainsKey('RawData')) { $RawData = try { Get-TPRawData } catch { $null } }
    $catalog = Get-TPCAChecklistCatalog -Path $ConfigPath
    $names = Get-TPCAChecklistStatusNames
    if ($null -eq $catalog) {
        return [ordered]@{ Available = $false; Note = 'The Conditional Access checklist catalog (Config/ca-checklist.json) was not found.'; Rows = @(); Fixes = @(); StatusNames = $names }
    }

    $raw = { param([string] $Key) if ($null -eq $RawData) { $null } else { Get-TPObjectField -Item $RawData -Key $Key -Default $null } }
    $ok = { param($Entry) $null -ne $Entry -and (Get-TPObjectField -Item $Entry -Key 'Success' -Default $false) -eq $true }
    $field = { param($Obj, [string] $Path, $Default = @()) Get-TPNestedProperty -Object $Obj -Path $Path -Default $Default }
    $list = { param($Obj, [string] $Path) @(Get-TPNestedProperty -Object $Obj -Path $Path -Default @() | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ }) }
    $has = { param([string[]] $Values, [string] $Want) @($Values | Where-Object { $_ -eq $Want }).Count -gt 0 }

    $caEntry = & $raw 'AAD-CAPolicies'
    $caRead = & $ok $caEntry
    $policies = @()
    if ($caRead) { $policies = @(& $field $caEntry 'Data.Policies' | Where-Object { $null -ne $_ }) }
    $sectionStatus = { param($Entry, [string] $Section) [string](Get-TPNestedProperty -Object $Entry -Path "Data.SectionStatus.$Section" -Default '') }

    $adminRoleIds = @($catalog.adminRoles | ForEach-Object { ([string]$_.Id).ToLowerInvariant() })
    $syncRoleIds = @($catalog.syncRoles | ForEach-Object { ([string]$_.Id).ToLowerInvariant() })
    $exchangeOnline = '00000002-0000-0ff1-ce00-000000000000'
    $azureManagement = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    $guestTypes = @('internalGuest', 'b2bCollaborationGuest', 'b2bCollaborationMember', 'b2bDirectConnectUser', 'otherExternalUser', 'serviceProvider')

    # ── Policy facts, read the same way for every check ─────────────────────
    $state     = { param($Pol) [string](& $field $Pol 'State' '') }
    $name      = { param($Pol) [string](& $field $Pol 'DisplayName' '') }
    $grants    = { param($Pol) @(& $list $Pol 'GrantControls.BuiltInControls') }
    $incUsers  = { param($Pol) @(& $list $Pol 'Conditions.Users.IncludeUsers') }
    $incRoles  = { param($Pol) @(& $list $Pol 'Conditions.Users.IncludeRoles' | ForEach-Object { $_.ToLowerInvariant() }) }
    $excRoles  = { param($Pol) @(& $list $Pol 'Conditions.Users.ExcludeRoles' | ForEach-Object { $_.ToLowerInvariant() }) }
    $incApps   = { param($Pol) @(& $list $Pol 'Conditions.Applications.Include') }
    $clientApp = { param($Pol) @(& $list $Pol 'Conditions.ClientAppTypes') }
    $allUsers  = { param($Pol) & $has (& $incUsers $Pol) 'All' }
    $allApps   = { param($Pol) & $has (& $incApps $Pol) 'All' }
    $riskOnly  = { param($Pol)
        $g = @(& $grants $Pol)
        (& $has $g 'passwordChange') -or (& $has $g 'riskRemediation') -or
        @(& $list $Pol 'Conditions.UserRiskLevels').Count -gt 0 -or @(& $list $Pol 'Conditions.SignInRiskLevels').Count -gt 0
    }
    $requiresMfa = { param($Pol)
        $g = @(& $grants $Pol)
        $strength = [string](& $field $Pol 'GrantControls.AuthStrengthRequirementsSatisfied' '')
        $strengthId = [string](& $field $Pol 'GrantControls.AuthStrengthId' '')
        (& $has $g 'mfa') -or $strength -eq 'mfa' -or ($strengthId -and -not $strength) -or @(& $list $Pol 'GrantControls.CustomControls').Count -gt 0
    }
    $coversAdminRoles = { param($Pol)
        $inc = @(& $incRoles $Pol); $exc = @(& $excRoles $Pol); $everyone = & $allUsers $Pol
        @($adminRoleIds | Where-Object { ((-not $everyone) -and ($_ -notin $inc)) -or ($_ -in $exc) }).Count -eq 0
    }
    $trustedIds = @()
    if ($caRead) {
        $trustedIds = @(& $field $caEntry 'Data.NamedLocations' | Where-Object { $null -ne $_ -and (Get-TPObjectField -Item $_ -Key 'IsTrusted' -Default $false) -eq $true } | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Id' -Default '') })
    }

    # ── Presence rules: one scriptblock per Maester test (the port) ─────────
    $presence = @{
        'MT.1007' = { param($Pol) (-not (& $riskOnly $Pol)) -and (& $requiresMfa $Pol) -and (& $allUsers $Pol) -and (& $allApps $Pol) }
        'MT.1006' = { param($Pol) (-not (& $riskOnly $Pol)) -and (& $requiresMfa $Pol) -and (& $coversAdminRoles $Pol) -and (& $allApps $Pol) }
        'MT.1008' = { param($Pol)
            $apps = @(& $incApps $Pol)
            (-not (& $riskOnly $Pol)) -and (& $requiresMfa $Pol) -and
            ((& $allUsers $Pol) -or @($adminRoleIds | Where-Object { $_ -notin (& $incRoles $Pol) }).Count -eq 0) -and
            ((& $has $apps $azureManagement) -or (& $has $apps 'MicrosoftAdminPortals') -or (& $has $apps 'All'))
        }
        'MT.1009' = { param($Pol) (-not (& $has (& $grants $Pol) 'passwordChange')) -and (& $has (& $grants $Pol) 'block') -and (& $has (& $clientApp $Pol) 'other') -and (& $allApps $Pol) -and (& $allUsers $Pol) }
        'MT.1010' = { param($Pol)
            $apps = @(& $incApps $Pol)
            (& $has (& $grants $Pol) 'block') -and (& $has (& $clientApp $Pol) 'exchangeActiveSync') -and ((& $has $apps $exchangeOnline) -or (& $has $apps 'All')) -and (& $allUsers $Pol)
        }
        'MT.1011' = { param($Pol)
            $exc = @(& $list $Pol 'Conditions.Locations.Exclude')
            $trusted = (& $has $exc 'AllTrusted') -or @($exc | Where-Object { $_ -in $trustedIds }).Count -gt 0
            $apps = @(& $clientApp $Pol)
            (-not (& $has (& $grants $Pol) 'passwordChange')) -and (& $allUsers $Pol) -and $apps.Count -eq 1 -and $apps[0] -eq 'all' -and
            (& $has (& $list $Pol 'Conditions.Applications.UserActions') 'urn:user:registersecurityinfo') -and
            (& $has (& $list $Pol 'Conditions.Locations.Include') 'All') -and $trusted
        }
        'MT.1012' = { param($Pol)
            $levels = & $list $Pol 'Conditions.SignInRiskLevels'
            (-not (& $has (& $grants $Pol) 'passwordChange')) -and (& $requiresMfa $Pol) -and (& $allUsers $Pol) -and (& $allApps $Pol) -and (& $has $levels 'high') -and (& $has $levels 'medium')
        }
        'MT.1013' = { param($Pol) (& $has (& $grants $Pol) 'passwordChange') -and (& $allUsers $Pol) -and (& $allApps $Pol) -and (& $has (& $list $Pol 'Conditions.UserRiskLevels') 'high') }
        'MT.1014' = { param($Pol)
            $g = @(& $grants $Pol)
            $device = @($g | Where-Object { $_ -in @('compliantDevice', 'domainJoinedDevice') })
            $other = @($g | Where-Object { $_ -notin @('compliantDevice', 'domainJoinedDevice') })
            $op = [string](& $field $Pol 'GrantControls.Operator' '')
            $device.Count -gt 0 -and ($other.Count -eq 0 -or $op -eq 'AND') -and (& $coversAdminRoles $Pol) -and (& $allApps $Pol)
        }
        'MT.1015' = { param($Pol) (& $has (& $grants $Pol) 'block') -and @(& $list $Pol 'Conditions.Platforms' | Where-Object { $_ -eq 'all' }).Count -gt 0 }
        'MT.1016' = { param($Pol)
            $types = @(([string](& $field $Pol 'Conditions.Users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes' '')) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $allGuestTypes = @($guestTypes | Where-Object { $_ -notin $types }).Count -eq 0
            $inc = @(& $incUsers $Pol)
            $excludesGuests = $null -ne (& $field $Pol 'Conditions.Users.ExcludeGuestsOrExternalUsers' $null)
            (-not (& $riskOnly $Pol)) -and (& $requiresMfa $Pol) -and (& $allApps $Pol) -and (-not $excludesGuests) -and
            ((& $has $inc 'GuestsOrExternalUsers') -or $allGuestTypes -or (& $has $inc 'All'))
        }
        'MT.1017' = { param($Pol)
            $mode = [string](& $field $Pol 'Conditions.Devices.FilterMode' ''); $rule = [string](& $field $Pol 'Conditions.Devices.FilterRule' '')
            $unmanaged = ($mode -eq 'include' -and $rule -match 'device\.isCompliant -ne True') -or ($mode -eq 'exclude' -and $rule -match 'device\.isCompliant -eq True')
            ((& $field $Pol 'SessionControls.PersistentBrowser.IsEnabled' $false) -eq $true) -and ([string](& $field $Pol 'SessionControls.PersistentBrowser.Mode' '') -eq 'never') -and
            $unmanaged -and (& $allUsers $Pol) -and (& $allApps $Pol)
        }
        'MT.1018' = { param($Pol)
            $mode = [string](& $field $Pol 'Conditions.Devices.FilterMode' ''); $rule = [string](& $field $Pol 'Conditions.Devices.FilterRule' '')
            $unmanaged = ($mode -eq 'include' -and $rule -match 'device\.trustType -ne "ServerAD"' -and $rule -match 'device\.isCompliant -ne True') -or
                         ($mode -eq 'exclude' -and $rule -match 'device\.trustType -eq "ServerAD"' -and $rule -match 'device\.isCompliant -eq True')
            ((& $field $Pol 'SessionControls.SignInFrequency.IsEnabled' $false) -eq $true) -and ([string](& $field $Pol 'SessionControls.SignInFrequency.FrequencyInterval' '') -eq 'timeBased') -and
            $unmanaged -and (& $allUsers $Pol) -and (& $allApps $Pol)
        }
        'MT.1019' = { param($Pol)
            $apps = @(& $clientApp $Pol)
            (& $allUsers $Pol) -and $apps.Count -eq 1 -and $apps[0] -eq 'all' -and ((& $field $Pol 'SessionControls.ApplicationEnforcedRestrictions' $null) -eq $true) -and (& $has (& $incApps $Pol) 'Office365')
        }
        'MT.1001' = { param($Pol) & $has (& $grants $Pol) 'compliantDevice' }
        'MT.1003' = { param($Pol) (-not (& $has (& $grants $Pol) 'passwordChange')) -and (& $allApps $Pol) }
        'MT.1004' = { param($Pol) (-not (& $has (& $grants $Pol) 'passwordChange')) -and (& $allApps $Pol) -and (& $allUsers $Pol) }
        'MT.1052' = { param($Pol)
            $flows = @(& $field $Pol 'Conditions.AuthFlows' | Where-Object { $null -ne $_ } | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'transferMethods' -Default '') })
            $apps = @(& $clientApp $Pol); $g = @(& $grants $Pol)
            $locInc = @(& $list $Pol 'Conditions.Locations.Include')
            (($flows -join ',') -match 'deviceCodeFlow') -and (& $allUsers $Pol) -and $apps.Count -eq 1 -and $apps[0] -eq 'all' -and
            (((& $has $g 'block') -and ($locInc.Count -eq 0 -or (& $has $locInc 'All'))) -or (& $has $g 'compliantDevice') -or (& $has $g 'domainJoinedDevice'))
        }
        'MT.1181' = { param($Pol) (& $has (& $grants $Pol) 'block') -and (& $has (& $list $Pol 'Conditions.AgentIdRiskLevels') 'high') }
    }

    # ── Emergency access: the approved record first, Maester's inference otherwise ─
    $eaUsers = [System.Collections.Generic.List[string]]::new(); $eaGroups = [System.Collections.Generic.List[string]]::new()
    $ea = Get-TPObjectField -Item $EmergencyAccessRecord -Key 'EmergencyAccess' -Default $null
    if ($ea -is [System.Collections.IDictionary]) {
        foreach ($k in @($ea.Keys)) {
            $ks = ([string]$k).ToLowerInvariant()
            if ($ks -like 'user:*') { $eaUsers.Add($ks.Substring(5)) } elseif ($ks -like 'group:*') { $eaGroups.Add($ks.Substring(6)) }
        }
    }
    $eaSource = if (($eaUsers.Count + $eaGroups.Count) -gt 0) { 'ApprovedRecord' } else { 'None' }

    $licenseKnown = $null -ne $LicenseProfile -and (Get-TPObjectField -Item $LicenseProfile -Key 'HasLicenseData' -Default $false) -eq $true
    $licensed = { param([string] $Requirement)
        if (-not $licenseKnown -or -not $Requirement) { return $true }
        try { return [bool](Test-TPLicenseRequirementMet -LicenseRequirement $Requirement -LicenseProfile $LicenseProfile) } catch { return $true }
    }
    $sd = Get-TPSecurityDefaultsState (& $raw 'AAD-AuthPolicies')

    $policyRef = { param($Pol) [ordered]@{ Id = [string](& $field $Pol 'Id' ''); DisplayName = (& $name $Pol); State = (& $state $Pol) } }
    $rows = [System.Collections.Generic.List[object]]::new()
    $newRow = { param($Check, [string] $Status, [string] $Detail, [object[]] $Matched = @(), [object[]] $Items = @())
        [ordered]@{
            Id = [string]$Check.Id; Kind = [string]$Check.Kind; Title = [string]$Check.Title; Why = [string]$Check.Why
            Severity = [string]$Check.Severity; SourceUrl = [string]$Check.SourceUrl; LicenseRequirement = [string]$Check.LicenseRequirement; Recommended = [string]($Check.Recommended ?? '')
            Template = [string]($Check.Template ?? ''); Status = $Status; StatusLabel = $names[$Status]; Detail = $Detail
            Policies = @($Matched); Items = @($Items)
        }
    }

    foreach ($check in @($catalog.checks)) {
        $id = [string]$check.Id
        $kind = [string]$check.Kind
        if ($kind -eq 'Presence') {
            if (-not $caRead) { $rows.Add((& $newRow $check 'NotAssessed' 'The Conditional Access policies were not read in this run.')); continue }
            $rule = $presence[$id]
            if ($id -eq 'MT.1181' -and @($policies | Where-Object { Test-TPCAChecklistField -Item (& $field $_ 'Conditions' $null) -Key 'AgentIdRiskLevels' }).Count -eq 0 -and $policies.Count -gt 0) {
                $rows.Add((& $newRow $check 'NotAssessed' 'Agent identity risk levels were not read (a results file from before this check, or the beta policy list was not read).')); continue
            }
            $on = @($policies | Where-Object { (& $state $_) -eq 'enabled' -and (& $rule $_) })
            if ($on.Count -gt 0) {
                $rows.Add((& $newRow $check 'Pass' ("Met by: " + (@($on | ForEach-Object { & $name $_ }) -join '; ') + '.') @($on | ForEach-Object { & $policyRef $_ })))
                continue
            }
            $staged = @($policies | Where-Object { (& $state $_) -eq 'enabledForReportingButNotEnforced' -and (& $rule $_) })
            if (-not (& $licensed ([string]$check.LicenseRequirement))) {
                $rows.Add((& $newRow $check 'NeedsLicense' "This tenant's subscriptions do not include $([string]$check.LicenseRequirement), which this policy needs.")); continue
            }
            if ($staged.Count -gt 0) {
                $rows.Add((& $newRow $check 'Staged' ("A policy that would meet this is in report-only mode and enforces nothing: " + (@($staged | ForEach-Object { & $name $_ }) -join '; ') + '. Review its report-only results, then turn it on.') @($staged | ForEach-Object { & $policyRef $_ })))
                continue
            }
            $why = if ($sd -eq $true) { 'No enabled policy matches. Security Defaults is on, and while it is on Conditional Access policies cannot be turned on.' } else { 'No enabled policy matches.' }
            $rows.Add((& $newRow $check 'Fail' $why))
            continue
        }

        if ($kind -eq 'Hygiene') {
            if (-not $caRead) { $rows.Add((& $newRow $check 'NotAssessed' 'The Conditional Access policies were not read in this run.')); continue }
            $enabled = @($policies | Where-Object { (& $state $_) -eq 'enabled' })
            switch ($id) {
                'MT.1005' {
                    $scope = @($policies | Where-Object { @(& $list $_ 'Conditions.Applications.AuthenticationContext').Count -eq 0 -and @(& $list $_ 'Conditions.ClientApplications.IncludeServicePrincipals').Count -eq 0 })
                    if ($scope.Count -eq 0) { $rows.Add((& $newRow $check 'NotApplicable' 'There are no Conditional Access policies.')); break }
                    if ($eaSource -eq 'ApprovedRecord') {
                        $missing = @($scope | Where-Object {
                                $xu = @(& $list $_ 'Conditions.Users.ExcludeUsers' | ForEach-Object { $_.ToLowerInvariant() })
                                $xg = @(& $list $_ 'Conditions.Users.ExcludeGroups' | ForEach-Object { $_.ToLowerInvariant() })
                                @($eaUsers | Where-Object { $_ -notin $xu }).Count -gt 0 -or @($eaGroups | Where-Object { $_ -notin $xg }).Count -gt 0
                            })
                        if ($missing.Count -eq 0) { $rows.Add((& $newRow $check 'Pass' "Every policy excludes the $($eaUsers.Count + $eaGroups.Count) approved emergency access account(s) or group(s).")) }
                        else { $rows.Add((& $newRow $check 'Fail' "$($missing.Count) of $($scope.Count) policies do not exclude every approved emergency access account or group." @($missing | ForEach-Object { & $policyRef $_ }))) }
                    } else {
                        # Maester's inference: the user or group most policies exclude.
                        $topUser = @($scope | ForEach-Object { & $list $_ 'Conditions.Users.ExcludeUsers' } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1)
                        $topGroup = @($scope | ForEach-Object { & $list $_ 'Conditions.Users.ExcludeGroups' } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1)
                        $userCount = if ($topUser.Count) { $topUser[0].Count } else { 0 }
                        $groupCount = if ($topGroup.Count) { $topGroup[0].Count } else { 0 }
                        if ($userCount -eq $scope.Count -or $groupCount -eq $scope.Count) {
                            $rows.Add((& $newRow $check 'Pass' "One account or group is excluded from all $($scope.Count) policies. This rests on an inference (there is no approved emergency access record for this tenant): confirm it is the break-glass account and record it."))
                        } else {
                            $best = [math]::Max($userCount, $groupCount)
                            $rows.Add((& $newRow $check 'Fail' "No account or group is excluded from every policy (the most-excluded one is excluded from $best of $($scope.Count)). There is no approved emergency access record for this tenant."))
                        }
                    }
                }
                'MT.1020' {
                    $roles = & $raw 'AAD-DirectoryRoles'
                    if (-not (& $ok $roles) -or (& $sectionStatus $roles 'RoleAssignments') -in @('Failed', 'NotRun')) { $rows.Add((& $newRow $check 'NotAssessed' 'Directory role assignments were not read, so the synchronization accounts are not known.')); break }
                    $members = @(& $field $roles 'Data.RoleAssignments' | Where-Object { $null -ne $_ -and ([string](Get-TPObjectField -Item $_ -Key 'RoleDefinitionId' -Default '')).ToLowerInvariant() -in $syncRoleIds -and ([string](Get-TPObjectField -Item $_ -Key 'PrincipalType' -Default '')) -match 'user' })
                    if ($members.Count -eq 0) { $rows.Add((& $newRow $check 'Pass' 'No user account holds a directory synchronization role.')); break }
                    $memberIds = @($members | ForEach-Object { ([string](Get-TPObjectField -Item $_ -Key 'PrincipalId' -Default '')).ToLowerInvariant() })
                    $bad = @($enabled | Where-Object {
                            $pol = $_
                            if (-not (& $allApps $pol)) { return $false }
                            $inc = @(& $incUsers $pol)
                            if ($inc.Count -eq 0 -and @(& $list $pol 'Conditions.Users.IncludeGroups').Count -eq 0 -and @(& $incRoles $pol).Count -eq 0 -and $null -ne (& $field $pol 'Conditions.Users.IncludeGuestsOrExternalUsers' $null)) { return $false }
                            $ca = @(& $clientApp $pol)
                            if ((& $has (& $grants $pol) 'block') -and (& $has $ca 'exchangeActiveSync') -and (& $has $ca 'other')) { return $false }
                            $incIds = @($inc | ForEach-Object { $_.ToLowerInvariant() })
                            if (@($memberIds | Where-Object { $_ -in $incIds }).Count -gt 0 -or @($syncRoleIds | Where-Object { $_ -in (& $incRoles $pol) }).Count -gt 0) { return $false }
                            $xu = @(& $list $pol 'Conditions.Users.ExcludeUsers' | ForEach-Object { $_.ToLowerInvariant() })
                            $byRole = @($syncRoleIds | Where-Object { $_ -in (& $excRoles $pol) }).Count -gt 0
                            $byMember = @($memberIds | Where-Object { $_ -notin $xu }).Count -eq 0
                            -not ($byRole -or $byMember)
                        })
                    if ($bad.Count -eq 0) { $rows.Add((& $newRow $check 'Pass' 'Every enabled policy for all resources excludes the directory synchronization accounts or does not reach them.')) }
                    else { $rows.Add((& $newRow $check 'Fail' "$($bad.Count) enabled policy(ies) for all resources reach the directory synchronization account(s); exclude the Directory Synchronization Accounts role." @($bad | ForEach-Object { & $policyRef $_ }))) }
                }
                { $_ -in @('MT.1035', 'MT.1038', 'MT.1066') } {
                    $refStatus = & $sectionStatus $caEntry 'ReferencedObjects'
                    $objects = @(& $field $caEntry 'Data.ReferencedObjects.Objects' | Where-Object { $null -ne $_ })
                    if (-not $refStatus -or $refStatus -in @('NotRun', 'Failed')) { $rows.Add((& $newRow $check 'NotAssessed' 'The users, groups and roles the policies name were not read in this run.')); break }
                    $partial = $refStatus -ne 'Collected'
                    $usedBy = { param([string] $Kind, [string] $ObjId)
                        $keys = switch ($Kind) { 'User' { 'IncludeUsers', 'ExcludeUsers' } 'Group' { 'IncludeGroups', 'ExcludeGroups' } default { 'IncludeRoles', 'ExcludeRoles' } }
                        @($policies | Where-Object { $pol = $_; @($keys | Where-Object { @(& $list $pol "Conditions.Users.$_" | ForEach-Object { $_.ToLowerInvariant() }) -contains $ObjId }).Count -gt 0 } | ForEach-Object { & $name $_ })
                    }
                    if ($id -eq 'MT.1035') {
                        $active = @($policies | Where-Object { (& $state $_) -in @('enabled', 'enabledForReportingButNotEnforced') })
                        $groupIds = @($active | ForEach-Object { & $list $_ 'Conditions.Users.IncludeGroups'; & $list $_ 'Conditions.Users.ExcludeGroups' } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
                        if ($groupIds.Count -eq 0) { $rows.Add((& $newRow $check 'Pass' 'No enabled or report-only policy names a group.')); break }
                        $groupRows = @($objects | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Kind' -Default '') -eq 'Group' -and ([string](Get-TPObjectField -Item $_ -Key 'Id' -Default '')) -in $groupIds -and (Get-TPObjectField -Item $_ -Key 'Exists' -Default $null) -eq $true })
                        # Protected: either flag returned True. Open: neither is True and
                        # at least one was returned False. A group with neither flag
                        # returned is unknown, never protected.
                        $protected = { param($g) (Get-TPObjectField -Item $g -Key 'IsManagementRestricted' -Default $null) -eq $true -or (Get-TPObjectField -Item $g -Key 'IsAssignableToRole' -Default $null) -eq $true }
                        $open = @($groupRows | Where-Object { -not (& $protected $_) -and ((Get-TPObjectField -Item $_ -Key 'IsManagementRestricted' -Default $null) -eq $false -or (Get-TPObjectField -Item $_ -Key 'IsAssignableToRole' -Default $null) -eq $false) })
                        $unknown = @($groupRows | Where-Object { -not (& $protected $_) -and $null -eq (Get-TPObjectField -Item $_ -Key 'IsManagementRestricted' -Default $null) -and $null -eq (Get-TPObjectField -Item $_ -Key 'IsAssignableToRole' -Default $null) })
                        $items = @($open | ForEach-Object { [ordered]@{ Kind = 'Group'; Id = [string]$_.Id; DisplayName = [string]$_.DisplayName; UsedBy = @(& $usedBy 'Group' ([string]$_.Id)) } })
                        if ($open.Count -gt 0) { $rows.Add((& $newRow $check 'Fail' "$($open.Count) group(s) used in Conditional Access are neither role-assignable nor in a restricted management administrative unit, so a group owner or a Groups Administrator can change who a policy applies to." @() $items)) }
                        elseif ($unknown.Count -gt 0) { $rows.Add((& $newRow $check 'NotAssessed' "$($unknown.Count) group(s) used in Conditional Access were read without either protection setting (role-assignable, restricted management), so whether they are protected was not established." @() @($unknown | ForEach-Object { [ordered]@{ Kind = 'Group'; Id = [string]$_.Id; DisplayName = [string]$_.DisplayName; UsedBy = @(& $usedBy 'Group' ([string]$_.Id)) } }))) }
                        elseif ($partial -or $groupRows.Count -lt $groupIds.Count) { $rows.Add((& $newRow $check 'NotAssessed' 'Some groups used in Conditional Access could not be read.')) }
                        else { $rows.Add((& $newRow $check 'Pass' "All $($groupIds.Count) group(s) used in enabled or report-only policies are protected.")) }
                        break
                    }
                    $kindsWanted = if ($id -eq 'MT.1038') { @('Group') } else { @('User', 'Group', 'Role') }
                    $gone = @($objects | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Kind' -Default '') -in $kindsWanted -and (Get-TPObjectField -Item $_ -Key 'Exists' -Default $null) -eq $false })
                    $items = @($gone | ForEach-Object { [ordered]@{ Kind = [string]$_.Kind; Id = [string]$_.Id; DisplayName = ''; UsedBy = @(& $usedBy ([string]$_.Kind) ([string]$_.Id)) } })
                    $what = if ($id -eq 'MT.1038') { 'group(s)' } else { 'user(s), group(s) or role(s)' }
                    if ($gone.Count -gt 0) { $rows.Add((& $newRow $check 'Fail' "$($gone.Count) $what named in a policy no longer exist. Remove them from the policies (a deleted group can be restored for 30 days)." @() $items)) }
                    elseif ($partial) { $rows.Add((& $newRow $check 'NotAssessed' 'Some objects named in the policies could not be read (or the list was capped).')) }
                    else { $rows.Add((& $newRow $check 'Pass' 'Every object named in the policies exists.')) }
                }
                'MT.1036' {
                    $exempt = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($x in $eaUsers) { $null = $exempt.Add($x) }; foreach ($x in $eaGroups) { $null = $exempt.Add($x) }; foreach ($x in $syncRoleIds) { $null = $exempt.Add($x) }
                    $items = [System.Collections.Generic.List[object]]::new()
                    foreach ($pair in @(@('User', 'ExcludeUsers', 'IncludeUsers'), @('Group', 'ExcludeGroups', 'IncludeGroups'), @('Role', 'ExcludeRoles', 'IncludeRoles'))) {
                        $excluded = @($enabled | ForEach-Object { & $list $_ "Conditions.Users.$($pair[1])" } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
                        $included = @($enabled | ForEach-Object { & $list $_ "Conditions.Users.$($pair[2])" } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
                        foreach ($objId in $excluded) {
                            if ($objId -in $included -or $exempt.Contains($objId)) { continue }
                            $by = @($enabled | Where-Object { @(& $list $_ "Conditions.Users.$($pair[1])" | ForEach-Object { $_.ToLowerInvariant() }) -contains $objId } | ForEach-Object { & $name $_ })
                            $items.Add([ordered]@{ Kind = $pair[0]; Id = $objId; DisplayName = ''; UsedBy = $by })
                        }
                    }
                    $note = if ($eaSource -eq 'ApprovedRecord') { ' Approved emergency access accounts and the directory synchronization roles are not counted.' } else { ' The directory synchronization roles are not counted; with no approved emergency access record, a break-glass exclusion is listed too.' }
                    if ($items.Count -eq 0) { $rows.Add((& $newRow $check 'Pass' ("Every user, group and role excluded from an enabled policy is included by another enabled policy." + $note))) }
                    else { $rows.Add((& $newRow $check 'Fail' ("$($items.Count) excluded user(s), group(s) or role(s) are not included by any other enabled policy, so nothing covers them." + $note) @() $items.ToArray())) }
                }
                'MT.1049' {
                    $riskPolicies = @($enabled | Where-Object { @(& $list $_ 'Conditions.UserRiskLevels').Count -gt 0 -or @(& $list $_ 'Conditions.SignInRiskLevels').Count -gt 0 })
                    if ($riskPolicies.Count -eq 0) { $rows.Add((& $newRow $check 'NotApplicable' 'No enabled policy uses a risk condition.')); break }
                    $both = @($riskPolicies | Where-Object { @(& $list $_ 'Conditions.UserRiskLevels').Count -gt 0 -and @(& $list $_ 'Conditions.SignInRiskLevels').Count -gt 0 })
                    if ($both.Count -eq 0) { $rows.Add((& $newRow $check 'Pass' 'User risk and sign-in risk are handled by separate policies.')) }
                    else { $rows.Add((& $newRow $check 'Fail' 'These policies combine user risk and sign-in risk, so they apply only when both are present; split them.' @($both | ForEach-Object { & $policyRef $_ }))) }
                }
                'MT.1061' {
                    $regPolicies = @($enabled | Where-Object { & $has (& $list $_ 'Conditions.Applications.UserActions') 'urn:user:registerdevice' })
                    $ds = & $raw 'AAD-DirectorySettings'
                    $mfaConfig = [string](& $field $ds 'Data.DeviceRegistration.MultiFactorAuthConfiguration' '')
                    if ($regPolicies.Count -eq 0) { $rows.Add((& $newRow $check 'Pass' 'No enabled policy targets the register-or-join-devices action, so the two settings cannot conflict.')) }
                    elseif (-not $mfaConfig) { $rows.Add((& $newRow $check 'NotAssessed' 'The device registration policy setting was not read.')) }
                    elseif ($mfaConfig -eq 'required') { $rows.Add((& $newRow $check 'Fail' 'Device settings require MFA to register or join devices AND a Conditional Access policy targets that action; Microsoft enforces the policy only when the device setting is No. Set "Require Multifactor Authentication to register or join devices" to No.' @($regPolicies | ForEach-Object { & $policyRef $_ }))) }
                    else { $rows.Add((& $newRow $check 'Pass' 'Device registration MFA is set by Conditional Access only.')) }
                }
                'MT.1072' {
                    $old = @($enabled | Where-Object { & $has (& $grants $_) 'approvedApplication' })
                    if ($old.Count -eq 0) { $rows.Add((& $newRow $check 'Pass' 'No enabled policy uses the retired approved-client-app grant.')) }
                    else { $rows.Add((& $newRow $check 'Fail' 'These enabled policies rely on "Require approved client app", which Microsoft no longer enforces; move them to "Require app protection policy".' @($old | ForEach-Object { & $policyRef $_ }))) }
                }
                'MT.1184' {
                    $filterKnown = @($policies | Where-Object { Test-TPCAChecklistField -Item (& $field $_ 'Conditions.Applications' $null) -Key 'ApplicationFilterPresent' }).Count -eq $policies.Count
                    $none = @($policies | Where-Object {
                            $apps = @(& $incApps $_ | Where-Object { $_ -ne 'None' })
                            $apps.Count -eq 0 -and @(& $list $_ 'Conditions.Applications.UserActions').Count -eq 0 -and
                            @(& $list $_ 'Conditions.Applications.AuthenticationContext').Count -eq 0 -and
                            (& $field $_ 'Conditions.Applications.ApplicationFilterPresent' $false) -ne $true
                        })
                    if ($none.Count -eq 0) { $rows.Add((& $newRow $check 'Pass' 'Every policy targets at least one resource, user action or authentication context.')) }
                    elseif (-not $filterKnown) { $rows.Add((& $newRow $check 'NotAssessed' 'Application filters were not read (a results file from before this check), so a policy that targets resources by filter cannot be told apart.')) }
                    else { $rows.Add((& $newRow $check 'Fail' 'These policies target no resource, so they do nothing even when on.' @($none | ForEach-Object { & $policyRef $_ }))) }
                }
                'MT.1224' {
                    $managed = @($policies | Where-Object { (& $name $_) -like 'Microsoft-managed:*' })
                    if ($managed.Count -eq 0) { $rows.Add((& $newRow $check 'NotApplicable' 'There are no Microsoft-managed Conditional Access policies in this tenant.')); break }
                    $pending = @($managed | Where-Object { (& $state $_) -eq 'enabledForReportingButNotEnforced' })
                    if ($pending.Count -eq 0) { $rows.Add((& $newRow $check 'Pass' "None of the $($managed.Count) Microsoft-managed policies is in report-only mode.")) }
                    else { $rows.Add((& $newRow $check 'Fail' "$($pending.Count) Microsoft-managed policy(ies) are in report-only mode: review the report-only results and turn them on (Microsoft turns them on itself after its review period)." @($pending | ForEach-Object { & $policyRef $_ }))) }
                }
            }
            continue
        }

        # ── Simulation (What If) ────────────────────────────────────────────
        $wi = & $raw 'AAD-CAWhatIf'
        $wiData = & $field $wi 'Data' $null
        if ($null -eq $wi) { $rows.Add((& $newRow $check 'NotAssessed' 'The What If simulation did not run (it runs on a live assessment with Graph connected).')); continue }
        $users = @(& $field $wiData 'Users' | Where-Object { $null -ne $_ })
        $kindWanted = if ($id -eq 'MT.1034') { 'Emergency' } else { 'Regular' }
        $subset = @($users | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Kind' -Default '') -eq $kindWanted })
        if ($id -eq 'MT.1034' -and $eaSource -ne 'ApprovedRecord') { $rows.Add((& $newRow $check 'NotAssessed' 'There is no approved emergency access record for this tenant, so no break-glass account was simulated. Record the accounts in the EmergencyAccess block of Config/baseline-exceptions/<tenant>.psd1.')); continue }
        if ($subset.Count -eq 0) {
            $reason = [string](& $field $wiData 'UnavailableReason' '')
            $rows.Add((& $newRow $check 'NotAssessed' $(if ($reason) { "No account was simulated ($reason)." } else { 'No account was simulated.' })))
            continue
        }
        $scenario = if ($id -eq 'TP-WHATIF-MFA') { 'Mfa' } else { 'LegacyAuth' }
        $items = [System.Collections.Generic.List[object]]::new()
        $unread = 0; $failures = 0; $stagedOnly = 0
        foreach ($u in $subset) {
            $upn = [string](Get-TPObjectField -Item $u -Key 'UserPrincipalName' -Default '')
            $uid = [string](Get-TPObjectField -Item $u -Key 'UserId' -Default '')
            $scenarios = @(if ($id -eq 'MT.1034') { 'LegacyAuth', 'Mfa' } else { $scenario })
            foreach ($sc in $scenarios) {
                $res = & $field $u "Results.$sc" $null
                if ($null -eq $res -or (Get-TPObjectField -Item $res -Key 'Read' -Default $false) -ne $true) { $unread++; continue }
                $applied = @(Get-TPObjectField -Item $res -Key 'Applied' -Default @() | Where-Object { $null -ne $_ })
                $on = @($applied | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -eq 'enabled' })
                $appliedNames = @($applied | ForEach-Object { "$([string](Get-TPObjectField -Item $_ -Key 'DisplayName' -Default '')) ($([string](Get-TPObjectField -Item $_ -Key 'State' -Default '')))" })
                if ($id -eq 'MT.1034') {
                    if ($applied.Count -gt 0) { $failures++; $items.Add([ordered]@{ Kind = 'User'; Id = $uid; DisplayName = $upn; Scenario = $sc; Result = 'Policies apply'; UsedBy = $appliedNames }) }
                    continue
                }
                $good = @(if ($scenario -eq 'LegacyAuth') { @($on | Where-Object { (Get-TPObjectField -Item $_ -Key 'Blocks' -Default $false) -eq $true }) } else { @($on | Where-Object { (Get-TPObjectField -Item $_ -Key 'Blocks' -Default $false) -eq $true -or (Get-TPObjectField -Item $_ -Key 'RequiresMfa' -Default $false) -eq $true }) })
                if ($good.Count -gt 0) { continue }
                $failures++
                $stagedGood = @(if ($scenario -eq 'LegacyAuth') { @($applied | Where-Object { (Get-TPObjectField -Item $_ -Key 'Blocks' -Default $false) -eq $true }) } else { @($applied | Where-Object { (Get-TPObjectField -Item $_ -Key 'Blocks' -Default $false) -eq $true -or (Get-TPObjectField -Item $_ -Key 'RequiresMfa' -Default $false) -eq $true }) })
                if ($stagedGood.Count -gt 0) { $stagedOnly++ }
                $items.Add([ordered]@{ Kind = 'User'; Id = $uid; DisplayName = $upn; Scenario = $sc; Result = $(if ($stagedGood.Count -gt 0) { 'Only a report-only policy would act' } elseif ($applied.Count -gt 0) { 'Policies apply but none blocks or requires MFA' } else { 'No policy applies' }); UsedBy = $appliedNames })
            }
        }
        $n = $subset.Count
        if ($failures -gt 0) {
            $status = if ($id -ne 'MT.1034' -and $stagedOnly -eq $failures) { 'Staged' } else { 'Fail' }
            $text = switch ($id) {
                'MT.1034' { "$($items.Count) simulated sign-in(s) of approved emergency access accounts are reached by a Conditional Access policy; exclude the accounts from those policies." }
                'MT.1033' { "Legacy authentication (Exchange ActiveSync) is not blocked by an enabled policy for $failures of $n simulated account(s)." }
                default   { "A browser sign-in is not asked for MFA by an enabled policy for $failures of $n simulated account(s)." }
            }
            if (-not (& $licensed ([string]$check.LicenseRequirement))) { $status = 'NeedsLicense'; $text = "This tenant's subscriptions do not include $([string]$check.LicenseRequirement). " + $text }
            $rows.Add((& $newRow $check $status $text @() $items.ToArray()))
        } elseif ($unread -gt 0) {
            $rows.Add((& $newRow $check 'NotAssessed' "The evaluation failed for $unread simulated sign-in(s); see the Exceptions in the results file."))
        } else {
            $text = switch ($id) {
                'MT.1034' { "No Conditional Access policy applies to the $n approved emergency access account(s) in either simulated sign-in." }
                'MT.1033' { "An enabled policy blocks legacy authentication for all $n simulated account(s). The sample is not every account." }
                default   { "An enabled policy asks for MFA (or blocks) in a browser sign-in for all $n simulated account(s). The sample is not every account; device, location and risk were not simulated." }
            }
            $rows.Add((& $newRow $check 'Pass' $text))
        }
    }

    # ── Report-only templates for what is not met ───────────────────────────
    $fixes = [System.Collections.Generic.List[object]]::new()
    $needed = [ordered]@{}
    foreach ($row in $rows) {
        if ($row.Status -ne 'Fail' -or -not $row.Template) { continue }
        if (-not $needed.Contains($row.Template)) { $needed[$row.Template] = [System.Collections.Generic.List[string]]::new() }
        $needed[$row.Template].Add($row.Id)
    }
    foreach ($key in $needed.Keys) {
        $tpl = $catalog.templates[$key]
        if ($null -eq $tpl) { continue }
        $fixes.Add([ordered]@{
            Key = $key; Title = [string]$tpl.Policy.displayName; Rows = $needed[$key].ToArray(); SourceUrl = [string]$tpl.SourceUrl
            Note = [string]($tpl.Note ?? ''); Policy = (ConvertTo-TPCAReportOnlyPolicy -Template $tpl.Policy -AdminRoleIds $adminRoleIds -SyncRoleId $syncRoleIds[0] -ExcludeUserIds $eaUsers.ToArray() -ExcludeGroupIds $eaGroups.ToArray())
        })
    }

    $counts = [ordered]@{}
    foreach ($k in $names.Keys) { $counts[$k] = @($rows | Where-Object { $_.Status -eq $k }).Count }
    $byKind = [ordered]@{}
    foreach ($kd in 'Presence', 'Hygiene', 'Simulation') { $byKind[$kd] = @($rows | Where-Object { $_.Kind -eq $kd }).Count }
    $notes = [System.Collections.Generic.List[string]]::new()
    if ($sd -eq $true) { $notes.Add('Security Defaults is on. While it is on, Conditional Access policies can be created but not turned on; moving to Conditional Access means turning Security Defaults off once the policies are ready.') }
    if ($eaSource -eq 'None') { $notes.Add('There is no approved emergency access record for this tenant. The report-only policies below exclude no break-glass account: add yours to excludeUsers before importing, and record them in the EmergencyAccess block of Config/baseline-exceptions/<tenant>.psd1.') }
    if (-not $caRead) { $notes.Add('The Conditional Access policies were not read in this run, so nothing about them is claimed.') }
    if ((& $sectionStatus $caEntry 'PolicyCompleteness') -in @('Failed', 'NotRun') -and $caRead) { $notes.Add('The beta policy list was not read, so policies only it returns (some user-risk policies) and agent risk levels may be missing.') }

    return [ordered]@{
        Available        = $true
        Note             = ''
        PoliciesRead     = $caRead
        PolicyCount      = $policies.Count
        EnabledCount     = @($policies | Where-Object { (& $state $_) -eq 'enabled' }).Count
        ReportOnlyCount  = @($policies | Where-Object { (& $state $_) -eq 'enabledForReportingButNotEnforced' }).Count
        SecurityDefaults = $sd
        EmergencyAccess  = [ordered]@{ Source = $eaSource; Users = $eaUsers.Count; Groups = $eaGroups.Count }
        Rows             = $rows.ToArray()
        Counts           = $counts
        ByKind           = $byKind
        Fixes            = $fixes.ToArray()
        Notes            = $notes.ToArray()
        StatusNames      = $names
        MaesterReference = [string]$catalog.maesterReference
        CatalogVersion   = [string]$catalog.version
    }
}

# Expands a catalog template into the report-only policy body an administrator
# imports (Entra admin center: Conditional Access > Policies > Upload policy
# file, or POST /identity/conditionalAccess/policies). The state is always
# report-only; ids are the only tenant data it carries.
function ConvertTo-TPCAReportOnlyPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Template,
        [Parameter(Mandatory)] [string[]] $AdminRoleIds,
        [Parameter(Mandatory)] [string] $SyncRoleId,
        [AllowEmptyCollection()] [string[]] $ExcludeUserIds = @(),
        [AllowEmptyCollection()] [string[]] $ExcludeGroupIds = @()
    )
    $copy = ($Template | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable)
    $users = $copy.conditions.users
    foreach ($k in @($users.Keys)) {
        if ($users[$k] -is [System.Collections.IList]) {
            $expanded = [System.Collections.Generic.List[string]]::new()
            foreach ($v in $users[$k]) {
                if ($v -eq '@AdminRoles') { foreach ($r in $AdminRoleIds) { $expanded.Add($r) } }
                elseif ($v -eq '@SyncRole') { $expanded.Add($SyncRoleId) }
                else { $expanded.Add([string]$v) }
            }
            $users[$k] = $expanded.ToArray()
        }
    }
    $guid = '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z'
    $xu = @($ExcludeUserIds | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ -cmatch $guid } | Select-Object -Unique)
    $xg = @($ExcludeGroupIds | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ -cmatch $guid } | Select-Object -Unique)
    if ($xu.Count -gt 0) { $users['excludeUsers'] = @(@($users['excludeUsers'] ?? @()) + $xu) }
    if ($xg.Count -gt 0) { $users['excludeGroups'] = @(@($users['excludeGroups'] ?? @()) + $xg) }
    $copy['state'] = 'enabledForReportingButNotEnforced'
    return $copy
}

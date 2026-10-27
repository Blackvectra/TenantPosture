#Requires -Version 7.0
#
# Invoke-TPCollectAADDirectorySettings.ps1
# Dependencies: Invoke-TPGraphRequest, Get-TPGraphAllPages, Get-TPObjectField,
#               Set-TPRawData, Register-TPException, Register-TPCoverage
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose:  Reads the Entra ID group-creation and device-registration settings
#           the CIS Microsoft 365 Foundations v7.0.0 5.1.3.x and 5.1.4.x
#           recommendations audit, for the AAD-16.x controls.
# Sets:     AAD-DirectorySettings (Data.AuthorizationPolicy, Data.GroupUnified,
#           Data.DeviceRegistration, Data.SectionStatus)
# Consumes: nothing
# Scopes:   Policy.Read.All (authorizationPolicy; deviceRegistrationPolicy lists
#           it as a higher-privileged delegated permission), Directory.Read.All
#           (groupSettings). All already in the tool's scope list; no re-consent.
#           The signed-in account needs a role Microsoft lists for the device
#           registration policy read (Global Reader among them).
#
# Each read is its own section with its own try/catch and SectionStatus, so one
# refused read leaves the others standing and an evaluator never reads a failed
# section as a setting. A property the API did not return is stored as $null,
# never as a default: the evaluators report it not assessed.
#
# Graph references:
#   https://learn.microsoft.com/graph/api/resources/defaultuserrolepermissions
#   https://learn.microsoft.com/graph/group-directory-settings  (Group.Unified)
#   https://learn.microsoft.com/graph/api/deviceregistrationpolicy-get

function ConvertTo-TPDirectorySettingBool {
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][object] $Value)
    # Graph returns JSON booleans for the policy objects and the STRINGS
    # 'True'/'False' for directory setting values; [bool]'False' is $true, so
    # nothing is cast. Anything else is not a value the tool can read.
    if ($Value -is [bool]) { return $Value }
    switch -CaseSensitive ([string]$Value) {
        'True'  { return $true }
        'true'  { return $true }
        'False' { return $false }
        'false' { return $false }
    }
    return $null
}

function Invoke-TPCollectAADDirectorySettings {
    [CmdletBinding()] param()

    $result = @{
        CollectorId = 'AAD-DirectorySettings'
        CollectedAt = (Get-Date).ToUniversalTime().ToString('o')
        Success     = $false
        Data        = [ordered]@{
            AuthorizationPolicy = $null
            GroupUnified        = $null
            DeviceRegistration  = $null
            SectionStatus       = [ordered]@{
                AuthorizationPolicy      = 'NotRun'
                GroupSettings            = 'NotRun'
                DeviceRegistrationPolicy = 'NotRun'
            }
            SectionErrors       = [ordered]@{}
        }
    }

    # ── Authorization policy: who may create security groups (CIS 5.1.3.1) and
    # whether device owners may read their own BitLocker keys (CIS 5.1.4.6).
    try {
        $pol  = Invoke-TPGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -ErrorAction Stop
        $durp = Get-TPObjectField -Item $pol -Key 'defaultUserRolePermissions' -Default $null
        $result.Data.AuthorizationPolicy = [ordered]@{
            DefaultUserRolePermissionsReturned       = ($null -ne $durp)
            AllowedToCreateSecurityGroups            = (ConvertTo-TPDirectorySettingBool (Get-TPObjectField -Item $durp -Key 'allowedToCreateSecurityGroups' -Default $null))
            AllowedToReadBitlockerKeysForOwnedDevice = (ConvertTo-TPDirectorySettingBool (Get-TPObjectField -Item $durp -Key 'allowedToReadBitlockerKeysForOwnedDevice' -Default $null))
        }
        $result.Data.SectionStatus.AuthorizationPolicy = 'Collected'
    } catch {
        $result.Data.SectionStatus.AuthorizationPolicy = 'Failed'
        $result.Data.SectionErrors.AuthorizationPolicy = $_.Exception.Message
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'AAD-DirectorySettings-AuthorizationPolicy' -Message $_.Exception.Message
        }
    }

    # ── Group.Unified directory setting: EnableGroupCreation (CIS 5.1.3.4).
    # Microsoft: a tenant starts with no setting objects and the template
    # defaults apply (EnableGroupCreation True), so a completed read with no
    # Group.Unified object is a known value, recorded as Present = $false.
    try {
        $GROUP_UNIFIED_TEMPLATE_ID = '62375ab9-6b52-47ed-826b-58e47e0e304b'
        $rows    = @(Get-TPGraphAllPages -Uri 'https://graph.microsoft.com/v1.0/groupSettings')
        $unified = @($rows | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'templateId' -Default '') -eq $GROUP_UNIFIED_TEMPLATE_ID }) | Select-Object -First 1
        if ($null -eq $unified) {
            $result.Data.GroupUnified = [ordered]@{ Present = $false; EnableGroupCreation = $null; EnableGroupCreationReturned = $false; GroupCreationAllowedGroupId = '' }
        } else {
            $values = @{}
            foreach ($v in @(Get-TPObjectField -Item $unified -Key 'values' -Default @())) {
                $n = [string](Get-TPObjectField -Item $v -Key 'name' -Default '')
                if ($n) { $values[$n] = Get-TPObjectField -Item $v -Key 'value' -Default $null }
            }
            $result.Data.GroupUnified = [ordered]@{
                Present                     = $true
                EnableGroupCreationReturned = $values.ContainsKey('EnableGroupCreation')
                EnableGroupCreation         = (ConvertTo-TPDirectorySettingBool $values['EnableGroupCreation'])
                GroupCreationAllowedGroupId = [string]($values['GroupCreationAllowedGroupId'] ?? '')
            }
        }
        $result.Data.SectionStatus.GroupSettings = 'Collected'
    } catch {
        $result.Data.SectionStatus.GroupSettings = 'Failed'
        $result.Data.SectionErrors.GroupSettings = $_.Exception.Message
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'AAD-DirectorySettings-GroupSettings' -Message $_.Exception.Message
        }
    }

    # ── Device registration policy (CIS 5.1.4.1 to 5.1.4.5). The membership
    # objects are stored as Microsoft's own @odata.type, never as a verdict.
    try {
        $drp  = Invoke-TPGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/deviceRegistrationPolicy' -ErrorAction Stop
        $join = Get-TPObjectField -Item $drp -Key 'azureADJoin' -Default $null
        $atj  = Get-TPObjectField -Item $join -Key 'allowedToJoin' -Default $null
        $la   = Get-TPObjectField -Item $join -Key 'localAdmins' -Default $null
        $ru   = Get-TPObjectField -Item $la -Key 'registeringUsers' -Default $null
        $laps = Get-TPObjectField -Item $drp -Key 'localAdminPassword' -Default $null

        $membership = {
            param($m)
            if ($null -eq $m) { return $null }
            [ordered]@{
                Type       = [string](Get-TPObjectField -Item $m -Key '@odata.type' -Default '')
                UserCount  = @(Get-TPObjectField -Item $m -Key 'users' -Default @() | Where-Object { $_ }).Count
                GroupCount = @(Get-TPObjectField -Item $m -Key 'groups' -Default @() | Where-Object { $_ }).Count
            }
        }
        # userDeviceQuota is an Int32. A JSON number arrives as Int32 or Int64;
        # anything that is not a whole, non-negative number is not read.
        $q = Get-TPObjectField -Item $drp -Key 'userDeviceQuota' -Default $null
        $quota = $null
        if (($q -is [int] -or $q -is [long]) -and $q -ge 0 -and $q -le [int]::MaxValue) { $quota = [int]$q }
        elseif ($q -is [string] -and $q -cmatch '\A[0-9]{1,9}\z') { $quota = [int]::Parse($q, [cultureinfo]::InvariantCulture) }

        $result.Data.DeviceRegistration = [ordered]@{
            AllowedToJoin         = (& $membership $atj)
            UserDeviceQuota       = $quota
            EnableGlobalAdmins    = (ConvertTo-TPDirectorySettingBool (Get-TPObjectField -Item $la -Key 'enableGlobalAdmins' -Default $null))
            RegisteringUsers      = (& $membership $ru)
            LocalAdminPasswordEnabled = (ConvertTo-TPDirectorySettingBool (Get-TPObjectField -Item $laps -Key 'isEnabled' -Default $null))
        }
        $result.Data.SectionStatus.DeviceRegistrationPolicy = 'Collected'
    } catch {
        $result.Data.SectionStatus.DeviceRegistrationPolicy = 'Failed'
        $result.Data.SectionErrors.DeviceRegistrationPolicy = $_.Exception.Message
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'AAD-DirectorySettings-DeviceRegistrationPolicy' -Message $_.Exception.Message
        }
    }

    $result.Success = $true

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'AAD-DirectorySettings' -Data $result
    }
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        $statuses = @($result.Data.SectionStatus.Values)
        $failed   = @($statuses | Where-Object { $_ -ne 'Collected' }).Count
        $status   = if ($failed -eq $statuses.Count) { 'Failed' } elseif ($failed -gt 0) { 'Partial' } else { 'Collected' }
        $note     = if ($failed -gt 0) { "$failed of $($statuses.Count) directory setting reads did not complete; see Exceptions" } else { 'Group creation and device registration settings read' }
        Register-TPCoverage -Family 'AAD-DirectorySettings' -Status $status -Note $note
    }
    return $result
}

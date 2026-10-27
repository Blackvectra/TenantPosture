#Requires -Version 7.0
#
# Test-TPControlEntraDirectory.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose:  Evaluates the Entra ID group-creation and device-registration settings
#           of CIS Microsoft 365 Foundations v7.0.0 5.1.3.1, 5.1.3.4 and 5.1.4.1
#           to 5.1.4.6 (AAD-16.1 to AAD-16.8).
# Consumes: AAD-DirectorySettings (Invoke-TPCollectAADDirectorySettings):
#           Data.AuthorizationPolicy, Data.GroupUnified, Data.DeviceRegistration,
#           Data.SectionStatus, Data.SectionErrors
# Scopes:   none directly (the collector reads under Policy.Read.All and
#           Directory.Read.All)
#
# Every control judges one setting the CIS audit procedure reads, with the value
# Microsoft documents for it. A setting the tenant did not return, a section
# that did not complete and an older results file without the collector are
# all not assessed, never the default and never a pass.
#
# Microsoft references:
#   https://learn.microsoft.com/graph/api/resources/defaultuserrolepermissions
#   https://learn.microsoft.com/graph/group-directory-settings
#   https://learn.microsoft.com/graph/api/resources/deviceregistrationpolicy
#   https://learn.microsoft.com/graph/api/resources/localadminsettings
#   https://learn.microsoft.com/graph/api/resources/localadminpasswordsettings

# Returns the section's data, or $null after writing the not-assessed finding.
function Get-TPEntraDirectorySettingsSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ControlId,
        [Parameter(Mandatory)][object] $Control,
        [AllowNull()][object] $Citations,
        [Parameter(Mandatory)][ValidateSet('AuthorizationPolicy', 'GroupSettings', 'DeviceRegistrationPolicy')][string] $Section
    )
    $raw = Get-TPRawData -Key 'AAD-DirectorySettings'
    if (-not $raw -or -not (Get-TPObjectField -Item $raw -Key 'Success' -Default $false)) {
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category -Title $Control.Title -FrameworkIds $Citations `
            -Detail 'AAD-DirectorySettings collector did not run (or a results file from before this check); not assessed.'
        return $null
    }
    $status = [string](Get-TPNestedProperty -Object $raw -Path "Data.SectionStatus.$Section" -Default '')
    if ($status -ne 'Collected') {
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category -Title $Control.Title -FrameworkIds $Citations `
            -Detail (Get-TPSectionNotCollectedDetail -Raw $raw -Section $Section -CollectorSource "AAD-DirectorySettings-$Section")
        return $null
    }
    $key = switch ($Section) { 'AuthorizationPolicy' { 'AuthorizationPolicy' } 'GroupSettings' { 'GroupUnified' } default { 'DeviceRegistration' } }
    $data = Get-TPNestedProperty -Object $raw -Path "Data.$key" -Default $null
    if ($null -eq $data) {
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category -Title $Control.Title -FrameworkIds $Citations `
            -Detail "$Section was read but no data was stored; not assessed."
        return $null
    }
    return $data
}

# Microsoft's deviceRegistrationMembership derived types, by @odata.type.
function Get-TPDeviceRegistrationMembershipKind {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object] $Membership)
    $type = [string](Get-TPObjectField -Item $Membership -Key 'Type' -Default '')
    switch ($type) {
        '#microsoft.graph.allDeviceRegistrationMembership'        { return 'All' }
        '#microsoft.graph.enumeratedDeviceRegistrationMembership' { return 'Selected' }
        '#microsoft.graph.noDeviceRegistrationMembership'         { return 'None' }
    }
    return ''
}

function Get-TPDeviceRegistrationMembershipText {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object] $Membership)
    switch (Get-TPDeviceRegistrationMembershipKind -Membership $Membership) {
        'All'      { return 'All' }
        'None'     { return 'None' }
        'Selected' {
            $u = [int](Get-TPObjectField -Item $Membership -Key 'UserCount' -Default 0)
            $g = [int](Get-TPObjectField -Item $Membership -Key 'GroupCount' -Default 0)
            return "Selected ($u user(s), $g group(s))"
        }
    }
    return 'not returned'
}

# ── AAD-16.1 Users cannot create security groups (CIS 5.1.3.1) ─────────────────
function Test-TPControlEntraSecurityGroupCreation {
    [CmdletBinding()] param()
    $cid = 'AAD-16.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pol = Get-TPEntraDirectorySettingsSection -ControlId $cid -Control $ctrl -Citations $cit -Section 'AuthorizationPolicy'
    if ($null -eq $pol) { return }
    $v = Get-TPObjectField -Item $pol -Key 'AllowedToCreateSecurityGroups' -Default $null
    if ($v -isnot [bool]) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The tenant did not return defaultUserRolePermissions.allowedToCreateSecurityGroups on the authorization policy; not assessed.'
    } elseif (-not $v) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Users cannot create security groups in the Microsoft Entra admin centers, the API or PowerShell.' `
            -CurrentValue 'allowedToCreateSecurityGroups = False'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Any user can create a security group and becomes its owner, so a compromised account can create deceptively named groups that an administrator later grants access to or excludes from Conditional Access.' `
            -CurrentValue 'allowedToCreateSecurityGroups = True' -RequiredValue 'allowedToCreateSecurityGroups = False (Users can create security groups: No)' -Remediation $ctrl.Remediation
    }
}

# ── AAD-16.2 Users cannot create Microsoft 365 groups (CIS 5.1.3.4) ────────────
function Test-TPControlEntraM365GroupCreation {
    [CmdletBinding()] param()
    $cid = 'AAD-16.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gu = Get-TPEntraDirectorySettingsSection -ControlId $cid -Control $ctrl -Citations $cit -Section 'GroupSettings'
    if ($null -eq $gu) { return }
    $present = Get-TPObjectField -Item $gu -Key 'Present' -Default $null
    $value   = Get-TPObjectField -Item $gu -Key 'EnableGroupCreation' -Default $null
    $allowed = [string](Get-TPObjectField -Item $gu -Key 'GroupCreationAllowedGroupId' -Default '')
    if ($present -eq $false) {
        # Microsoft: a tenant has no Group.Unified object until one is created,
        # and the template default for EnableGroupCreation is True.
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'The tenant has no Group.Unified directory setting, so Microsoft''s template default applies: EnableGroupCreation is True and any user can create Microsoft 365 groups (and the Teams and SharePoint sites behind them).' `
            -CurrentValue 'Group.Unified not created (EnableGroupCreation default True)' -RequiredValue 'Group.Unified EnableGroupCreation = False' -Remediation $ctrl.Remediation
    } elseif ($present -ne $true -or $value -isnot [bool]) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The Group.Unified directory setting was read but EnableGroupCreation was not returned as True or False; not assessed.'
    } elseif (-not $value) {
        $note = if ($allowed) { " Members of the security group $allowed (GroupCreationAllowedGroupId) can still create them, as Microsoft documents." } else { '' }
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Non-admin users cannot create Microsoft 365 groups in Azure portals, the API or PowerShell.$note" `
            -CurrentValue 'Group.Unified EnableGroupCreation = False'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'The Group.Unified directory setting allows any user to create Microsoft 365 groups (and the Teams and SharePoint sites behind them).' `
            -CurrentValue 'Group.Unified EnableGroupCreation = True' -RequiredValue 'Group.Unified EnableGroupCreation = False' -Remediation $ctrl.Remediation
    }
}

# ── AAD-16.3 Joining devices to Microsoft Entra is restricted (CIS 5.1.4.1) ────
function Test-TPControlEntraDeviceJoinRestricted {
    [CmdletBinding()] param()
    $cid = 'AAD-16.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $drp = Get-TPEntraDirectorySettingsSection -ControlId $cid -Control $ctrl -Citations $cit -Section 'DeviceRegistrationPolicy'
    if ($null -eq $drp) { return }
    $m    = Get-TPObjectField -Item $drp -Key 'AllowedToJoin' -Default $null
    $kind = Get-TPDeviceRegistrationMembershipKind -Membership $m
    $text = Get-TPDeviceRegistrationMembershipText -Membership $m
    if (-not $kind) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The device registration policy did not return a recognized azureADJoin.allowedToJoin membership type; not assessed.'
    } elseif ($kind -in 'Selected', 'None') {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Users may join devices to Microsoft Entra: $text. Microsoft applies this to user-driven Microsoft Entra join on Windows 10 or later only, not to hybrid join, Azure VMs or Autopilot self-deploying mode." `
            -CurrentValue "Users may join devices to Microsoft Entra: $text"
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Every user may join a device to Microsoft Entra, so a compromised account can enroll an attacker-controlled device that inherits device-based access.' `
            -CurrentValue 'Users may join devices to Microsoft Entra: All' -RequiredValue 'Selected or None' -Remediation $ctrl.Remediation
    }
}

# ── AAD-16.4 Maximum devices per user limited (CIS 5.1.4.2) ───────────────────
function Test-TPControlEntraDeviceQuota {
    [CmdletBinding()] param()
    $cid = 'AAD-16.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $drp = Get-TPEntraDirectorySettingsSection -ControlId $cid -Control $ctrl -Citations $cit -Section 'DeviceRegistrationPolicy'
    if ($null -eq $drp) { return }
    $max = 10   # CIS 5.1.4.2 recommended state: 10 or less
    # A replayed results file carries the number as Int64 (ConvertFrom-Json).
    $q = Get-TPObjectField -Item $drp -Key 'UserDeviceQuota' -Default $null
    if (($q -isnot [int] -and $q -isnot [long]) -or $q -lt 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The device registration policy did not return userDeviceQuota as a whole number; not assessed.'
    } elseif ($q -le $max) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "A user can have at most $q Microsoft Entra joined or registered device(s)." -CurrentValue "userDeviceQuota = $q"
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "A user can have up to $q Microsoft Entra joined or registered devices (Microsoft's default is 50), so one compromised account can register many devices that look legitimate." `
            -CurrentValue "userDeviceQuota = $q" -RequiredValue "userDeviceQuota $max or less" -Remediation $ctrl.Remediation
    }
}

# ── AAD-16.5 Global Administrators not added as local admin on join (5.1.4.3) ─
function Test-TPControlEntraJoinGlobalAdminLocalAdmin {
    [CmdletBinding()] param()
    $cid = 'AAD-16.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $drp = Get-TPEntraDirectorySettingsSection -ControlId $cid -Control $ctrl -Citations $cit -Section 'DeviceRegistrationPolicy'
    if ($null -eq $drp) { return }
    $v = Get-TPObjectField -Item $drp -Key 'EnableGlobalAdmins' -Default $null
    if ($v -isnot [bool]) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The device registration policy did not return azureADJoin.localAdmins.enableGlobalAdmins; not assessed.'
    } elseif (-not $v) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'The Global Administrator role is not added to the local administrators group of devices joined to Microsoft Entra from now on (Microsoft applies the setting to future registrations only).' `
            -CurrentValue 'enableGlobalAdmins = False'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Global Administrators become local administrators on every device joined to Microsoft Entra, which invites signing in to endpoints with the tenant''s most privileged accounts.' `
            -CurrentValue 'enableGlobalAdmins = True' -RequiredValue 'enableGlobalAdmins = False' -Remediation $ctrl.Remediation
    }
}

# ── AAD-16.6 Registering user not made local admin on join (CIS 5.1.4.4) ──────
function Test-TPControlEntraJoinRegisteringUserLocalAdmin {
    [CmdletBinding()] param()
    $cid = 'AAD-16.6'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $drp = Get-TPEntraDirectorySettingsSection -ControlId $cid -Control $ctrl -Citations $cit -Section 'DeviceRegistrationPolicy'
    if ($null -eq $drp) { return }
    $m    = Get-TPObjectField -Item $drp -Key 'RegisteringUsers' -Default $null
    $kind = Get-TPDeviceRegistrationMembershipKind -Membership $m
    $text = Get-TPDeviceRegistrationMembershipText -Membership $m
    if (-not $kind) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The device registration policy did not return a recognized azureADJoin.localAdmins.registeringUsers membership type; not assessed.'
    } elseif ($kind -in 'Selected', 'None') {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Registering user is added as local administrator during Microsoft Entra join: $text." `
            -CurrentValue "Registering user added as local administrator: $text"
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Every user who joins a device to Microsoft Entra becomes a local administrator of it.' `
            -CurrentValue 'Registering user added as local administrator: All' -RequiredValue 'Selected or None' -Remediation $ctrl.Remediation
    }
}

# ── AAD-16.7 Microsoft Entra LAPS enabled (CIS 5.1.4.5) ───────────────────────
function Test-TPControlEntraLapsEnabled {
    [CmdletBinding()] param()
    $cid = 'AAD-16.7'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $drp = Get-TPEntraDirectorySettingsSection -ControlId $cid -Control $ctrl -Citations $cit -Section 'DeviceRegistrationPolicy'
    if ($null -eq $drp) { return }
    $v = Get-TPObjectField -Item $drp -Key 'LocalAdminPasswordEnabled' -Default $null
    if ($v -isnot [bool]) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The device registration policy did not return localAdminPassword.isEnabled; not assessed.'
    } elseif ($v) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Microsoft Entra Local Administrator Password Solution is enabled for the tenant. The tenant switch alone rotates no password: the Intune LAPS policy that does is judged by INT-4.1.' `
            -CurrentValue 'localAdminPassword.isEnabled = True'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Microsoft Entra LAPS is off for the tenant (Microsoft''s default), so devices cannot back up their local administrator password to Microsoft Entra ID and a LAPS policy has nowhere to store it.' `
            -CurrentValue 'localAdminPassword.isEnabled = False' -RequiredValue 'localAdminPassword.isEnabled = True' -Remediation $ctrl.Remediation
    }
}

# ── AAD-16.8 Users cannot recover BitLocker keys of their devices (5.1.4.6) ───
function Test-TPControlEntraBitLockerKeyRecovery {
    [CmdletBinding()] param()
    $cid = 'AAD-16.8'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pol = Get-TPEntraDirectorySettingsSection -ControlId $cid -Control $ctrl -Citations $cit -Section 'AuthorizationPolicy'
    if ($null -eq $pol) { return }
    $v = Get-TPObjectField -Item $pol -Key 'AllowedToReadBitlockerKeysForOwnedDevice' -Default $null
    if ($v -isnot [bool]) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The tenant did not return defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice on the authorization policy; not assessed.'
    } elseif (-not $v) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Non-admin users cannot read the BitLocker recovery keys of the devices they own; recovery goes through an administrator.' `
            -CurrentValue 'allowedToReadBitlockerKeysForOwnedDevice = False'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Device owners can read their own BitLocker recovery keys, so an attacker holding a user''s credentials and the device can retrieve the key and decrypt the drive.' `
            -CurrentValue 'allowedToReadBitlockerKeysForOwnedDevice = True' -RequiredValue 'allowedToReadBitlockerKeysForOwnedDevice = False' -Remediation $ctrl.Remediation
    }
}

#
# Test-NRGControlTeams.ps1
# Evaluates Microsoft Teams governance controls.
#
# Controls:
#   TMS-1.1  External access (federation) restricted
#   TMS-1.2  Teams consumer (personal account) federation disabled
#   TMS-1.3  Anonymous meeting join disabled
#   TMS-1.4  Meeting lobby enabled for external and anonymous users
#   TMS-1.5  Meeting presenter role restricted
#   TMS-1.6  PSTN users bypass lobby disabled
#   TMS-2.1  Third-party cloud storage apps disabled
#   TMS-2.2  Email integration into channels disabled
#
# Reads: Get-NRGRawData -Key 'Teams'
#
# NIST SP 800-53: AC-3, AC-17, AC-20, CM-7
# MITRE ATT&CK:   T1078, T1204, T1566
#

function Test-NRGControlTeams {
    [CmdletBinding()] param()

    $raw = Get-NRGRawData -Key 'Teams'

    if (-not $raw -or -not $raw.Success) {
        $detail = if ($raw) { "Collector failed: $($raw.Exceptions -join '; ')" } else { 'Teams collector did not run.' }
        foreach ($id in @('TMS-1.1','TMS-1.2','TMS-1.3','TMS-1.4','TMS-1.5','TMS-1.6','TMS-2.1','TMS-2.2')) {
            $ctrl = Get-NRGControlById -ControlId $id
            Add-NRGFinding -ControlId $id -State 'NotApplicable' `
                -Category 'Teams' -Title ($ctrl.Title) -Detail $detail
        }
        return
    }

    $extPolicy  = $raw.Data['ExternalAccess']
    $mtgPolicy  = $raw.Data['MeetingPolicy']
    $clientCfg  = $raw.Data['ClientConfig']
    $appPolicy  = $raw.Data['AppPermissionPolicy']

    #--------------------------------------------------------------------------
    # TMS-1.1  External access (federation) restricted
    # AC-17, AC-20 | T1078
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'TMS-1.1'
    if ($extPolicy) {
        $fedEnabled = $extPolicy.EnableFederationAccess -eq $true
        $allowedDomains = @()
        if ($extPolicy.AllowedDomains) {
            $allowedDomains = @($extPolicy.AllowedDomains | Where-Object { $_ -is [string] -or $_.Domain })
        }
        if (-not $fedEnabled) {
            Add-NRGFinding -ControlId 'TMS-1.1' -State 'Satisfied' `
                -Category 'Teams' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue 'Federation: disabled' `
                -RequiredValue 'Federation disabled or restricted to allowed domains'
        } elseif ($fedEnabled -and $allowedDomains.Count -gt 0) {
            Add-NRGFinding -ControlId 'TMS-1.1' -State 'Satisfied' `
                -Category 'Teams' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "Federation enabled, restricted to $($allowedDomains.Count) allowed domain(s)" `
                -RequiredValue 'Federation disabled or restricted to specific allowed domains'
        } else {
            Add-NRGFinding -ControlId 'TMS-1.1' -State 'Gap' `
                -Category 'Teams' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'Teams federation is enabled with all external organisations. Any Teams user globally can contact your users and initiate chats or calls.' `
                -CurrentValue 'Federation: enabled for all organisations' `
                -RequiredValue 'Disabled, or AllowedDomains list with specific trusted organisations only' `
                -Remediation 'Teams admin center > Users > External access > Set to Off or configure specific allowed domains.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'TMS-1.1')
        }
    } else {
        Add-NRGFinding -ControlId 'TMS-1.1' -State 'NotApplicable' `
            -Category 'Teams' -Title $ctrl.Title -Detail 'External access policy data not available.'
    }

    #--------------------------------------------------------------------------
    # TMS-1.2  Teams consumer federation disabled
    # AC-17, AC-20 | T1078
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'TMS-1.2'
    if ($extPolicy) {
        # Property name varies by Teams module version
        $consumerEnabled = $false
        if ($extPolicy.PSObject.Properties.Name -contains 'EnableTeamsConsumerAccess') {
            $consumerEnabled = $extPolicy.EnableTeamsConsumerAccess -eq $true
        } elseif ($extPolicy.PSObject.Properties.Name -contains 'AllowTeamsConsumerAccess') {
            $consumerEnabled = $extPolicy.AllowTeamsConsumerAccess -eq $true
        }

        if (-not $consumerEnabled) {
            Add-NRGFinding -ControlId 'TMS-1.2' -State 'Satisfied' `
                -Category 'Teams' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue 'Teams consumer (personal) federation: disabled' `
                -RequiredValue 'Consumer federation disabled'
        } else {
            Add-NRGFinding -ControlId 'TMS-1.2' -State 'Gap' `
                -Category 'Teams' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'Teams users can communicate with Teams personal (consumer) accounts. This allows unmanaged, unsecured personal accounts to interact with internal users and potentially exfiltrate data.' `
                -CurrentValue 'Teams consumer federation: enabled' `
                -RequiredValue 'EnableTeamsConsumerAccess = false' `
                -Remediation 'Teams admin center > Users > External access > Disable "Allow users in my organization to communicate with Teams users whose accounts are not managed by an organization".' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'TMS-1.2')
        }
    } else {
        Add-NRGFinding -ControlId 'TMS-1.2' -State 'NotApplicable' `
            -Category 'Teams' -Title $ctrl.Title -Detail 'External access policy data not available.'
    }

    #--------------------------------------------------------------------------
    # TMS-1.3  Anonymous meeting join disabled
    # AC-3, AC-17 | T1078
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'TMS-1.3'
    if ($mtgPolicy) {
        $anonJoin = $mtgPolicy.AllowAnonymousUsersToJoinMeeting -eq $true
        if (-not $anonJoin) {
            Add-NRGFinding -ControlId 'TMS-1.3' -State 'Satisfied' `
                -Category 'Teams' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue 'Anonymous meeting join: disabled' `
                -RequiredValue 'AllowAnonymousUsersToJoinMeeting = false'
        } else {
            Add-NRGFinding -ControlId 'TMS-1.3' -State 'Gap' `
                -Category 'Teams' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'Unauthenticated anonymous users can join Teams meetings. Anyone with the meeting link can attend without signing in, with no audit trail.' `
                -CurrentValue 'Anonymous meeting join: enabled' `
                -RequiredValue 'AllowAnonymousUsersToJoinMeeting = false' `
                -Remediation 'Teams admin center > Meetings > Meeting policies > Global > Disable "Anonymous users can join a meeting".' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'TMS-1.3')
        }
    } else {
        Add-NRGFinding -ControlId 'TMS-1.3' -State 'NotApplicable' `
            -Category 'Teams' -Title $ctrl.Title -Detail 'Meeting policy data not available.'
    }

    #--------------------------------------------------------------------------
    # TMS-1.4  Meeting lobby enabled for external and anonymous users
    # AC-3 | T1078
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'TMS-1.4'
    if ($mtgPolicy) {
        $admitted = $mtgPolicy.AutoAdmittedUsers
        $lobbyBypass = @('Everyone','EveryoneInCompanyExcludingGuests') -contains $admitted
        # Safe: EveryoneInCompany, EveryoneInSameAndFederatedCompany, OrganizerOnly, InvitedUsersOnly
        # Gap: Everyone (no lobby at all)
        if ($admitted -eq 'Everyone') {
            Add-NRGFinding -ControlId 'TMS-1.4' -State 'Gap' `
                -Category 'Teams' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'Meeting lobby is bypassed for everyone including anonymous users. Anyone with a meeting link joins directly without host approval.' `
                -CurrentValue "AutoAdmittedUsers: $admitted" `
                -RequiredValue 'EveryoneInCompany or OrganizerOnly (requires lobby for external/anonymous users)' `
                -Remediation 'Teams admin center > Meetings > Meeting policies > Global > Who can bypass the lobby > Change from "Everyone" to "People in my org".' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'TMS-1.4')
        } else {
            Add-NRGFinding -ControlId 'TMS-1.4' -State 'Satisfied' `
                -Category 'Teams' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "AutoAdmittedUsers: $admitted (external users require lobby)" `
                -RequiredValue 'EveryoneInCompany or more restrictive'
        }
    } else {
        Add-NRGFinding -ControlId 'TMS-1.4' -State 'NotApplicable' `
            -Category 'Teams' -Title $ctrl.Title -Detail 'Meeting policy data not available.'
    }

    #--------------------------------------------------------------------------
    # TMS-1.5  Meeting presenter role restricted
    # AC-3 | T1078
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'TMS-1.5'
    if ($mtgPolicy) {
        # DesignatedPresenterRoleMode: OrganizerOnlyUserOverride (safest), EveryoneUserOverride (gap), OrganizerAndCoOrganizersUserOverride
        $presenterMode = $mtgPolicy.DesignatedPresenterRoleMode
        if (-not $presenterMode) { $presenterMode = $mtgPolicy.AllowUserToChangePresentationRole }
        if ($presenterMode -eq 'EveryoneUserOverride' -or $presenterMode -eq $true) {
            Add-NRGFinding -ControlId 'TMS-1.5' -State 'Gap' `
                -Category 'Teams' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'Anyone in a meeting can present by default. External attendees can share screens and content without restriction.' `
                -CurrentValue "DesignatedPresenterRoleMode: $presenterMode" `
                -RequiredValue 'OrganizerOnlyUserOverride or OrganizerAndCoOrganizersUserOverride' `
                -Remediation 'Teams admin center > Meetings > Meeting policies > Global > Who can present > Set to "Organizers and co-organizers" or "Specific people".' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'TMS-1.5')
        } else {
            Add-NRGFinding -ControlId 'TMS-1.5' -State 'Satisfied' `
                -Category 'Teams' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "Presenter role: $presenterMode" `
                -RequiredValue 'Organizer-controlled presenter role'
        }
    } else {
        Add-NRGFinding -ControlId 'TMS-1.5' -State 'NotApplicable' `
            -Category 'Teams' -Title $ctrl.Title -Detail 'Meeting policy data not available.'
    }

    #--------------------------------------------------------------------------
    # TMS-1.6  PSTN users bypass lobby disabled
    # AC-3 | T1078
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'TMS-1.6'
    if ($mtgPolicy) {
        $pstnBypass = $mtgPolicy.AllowPSTNUsersToBypassLobby -eq $true
        if (-not $pstnBypass) {
            Add-NRGFinding -ControlId 'TMS-1.6' -State 'Satisfied' `
                -Category 'Teams' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue 'PSTN lobby bypass: disabled' `
                -RequiredValue 'AllowPSTNUsersToBypassLobby = false'
        } else {
            Add-NRGFinding -ControlId 'TMS-1.6' -State 'Gap' `
                -Category 'Teams' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'PSTN (dial-in) users bypass the meeting lobby. Callers with the conference number and ID join directly without host approval.' `
                -CurrentValue 'PSTN lobby bypass: enabled' `
                -RequiredValue 'AllowPSTNUsersToBypassLobby = false' `
                -Remediation 'Teams admin center > Meetings > Meeting policies > Global > Disable "People dialing in can bypass the lobby".' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'TMS-1.6')
        }
    } else {
        Add-NRGFinding -ControlId 'TMS-1.6' -State 'NotApplicable' `
            -Category 'Teams' -Title $ctrl.Title -Detail 'Meeting policy data not available.'
    }

    #--------------------------------------------------------------------------
    # TMS-2.1  Third-party cloud storage apps disabled in Teams
    # CM-7 | T1567
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'TMS-2.1'
    if ($clientCfg) {
        $storageApps = @{
            'Box'           = $clientCfg.AllowBox -eq $true
            'DropBox'       = $clientCfg.AllowDropBox -eq $true
            'GoogleDrive'   = $clientCfg.AllowGoogleDrive -eq $true
            'ShareFile'     = $clientCfg.AllowShareFile -eq $true
            'EgnytePlatform' = $clientCfg.AllowEgnytePlatform -eq $true
        }
        $enabled = @($storageApps.GetEnumerator() | Where-Object { $_.Value } | Select-Object -ExpandProperty Key)

        if ($enabled.Count -eq 0) {
            Add-NRGFinding -ControlId 'TMS-2.1' -State 'Satisfied' `
                -Category 'Teams' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue 'All third-party cloud storage apps disabled' `
                -RequiredValue 'Box, Dropbox, Google Drive, ShareFile all disabled'
        } else {
            Add-NRGFinding -ControlId 'TMS-2.1' -State 'Gap' `
                -Category 'Teams' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail "Third-party cloud storage enabled in Teams: $($enabled -join ', '). Users can share files from unmanaged external storage, bypassing DLP and retention policies." `
                -CurrentValue "Enabled storage apps: $($enabled -join ', ')" `
                -RequiredValue 'All third-party storage apps disabled' `
                -Remediation 'Teams admin center > Teams apps > Setup policies > Disable Box, Dropbox, Google Drive, ShareFile integrations.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'TMS-2.1')
        }
    } else {
        Add-NRGFinding -ControlId 'TMS-2.1' -State 'NotApplicable' `
            -Category 'Teams' -Title $ctrl.Title -Detail 'Teams client configuration data not available.'
    }

    #--------------------------------------------------------------------------
    # TMS-2.2  Email integration into channels disabled
    # CM-7 | T1566.002
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'TMS-2.2'
    if ($clientCfg) {
        $emailInChannel = $clientCfg.AllowEmailIntoChannel -eq $true
        if (-not $emailInChannel) {
            Add-NRGFinding -ControlId 'TMS-2.2' -State 'Satisfied' `
                -Category 'Teams' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue 'Email into channels: disabled' `
                -RequiredValue 'AllowEmailIntoChannel = false'
        } else {
            Add-NRGFinding -ControlId 'TMS-2.2' -State 'Gap' `
                -Category 'Teams' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'Teams channels accept email via a channel email address. Anyone who discovers or is given a channel email address can post content directly into Teams, bypassing message controls.' `
                -CurrentValue 'Email into channels: enabled' `
                -RequiredValue 'AllowEmailIntoChannel = false' `
                -Remediation 'Teams admin center > Teams settings > Email integration > Uncheck "Allow users to send emails to a channel email address".' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'TMS-2.2')
        }
    } else {
        Add-NRGFinding -ControlId 'TMS-2.2' -State 'NotApplicable' `
            -Category 'Teams' -Title $ctrl.Title -Detail 'Teams client configuration data not available.'
    }
}

#Requires -Version 7.0
#
# Test-TPControlCollabCis.ps1
# NRG Technology Services / NextLayerSec LLC — Author: Matthew Levorson
# Evaluates the Teams and SharePoint / OneDrive settings of the CIS Microsoft 365
# Foundations Benchmark v7.0.0 that no earlier control read (TMS-5.x, SPO-5.x).
#
# Reads:  Get-TPRawData -Key 'Teams'             (FederationConfig, ExternalAccessPolicy,
#                                                  MeetingPolicy, MessagingPolicy)
#         Get-TPRawData -Key 'Defender-Policies' (ReportSubmissionPolicy, TMS-5.6)
#         Get-TPRawData -Key 'SharePoint'        (TenantSettings from Graph
#                                                  /admin/sharepoint/settings;
#                                                  TenantSettingsSPO from Get-SPOTenant)
# Cmdlets / scopes: none here. The collectors use Get-CsTenantFederationConfiguration,
#   Get-CsExternalAccessPolicy, Get-CsTeamsMeetingPolicy, Get-CsTeamsMessagingPolicy,
#   Get-ReportSubmissionPolicy, Get-SPOTenant and Graph SharePointTenantSettings.Read.All.
#
# Controls: TMS-5.1 .. TMS-5.6, SPO-5.1 .. SPO-5.7. Config/controls.json is
#   authoritative; each control's EvaluatorFunction names its function here.
#
# Every setting is judged as Microsoft documents it and as the CIS audit reads it:
# Satisfied only for the value the recommendation's audit passes. A value the
# module or Graph did not return is not assessed, never defaulted, and a results
# file from before a read leaves the control not assessed. Teams policies are
# judged on the Global (Org-wide default) policy, the policy the CIS audit reads.
#

# The sentence every shell-only SharePoint control uses when no SharePoint Online
# Management Shell session existed (the same text Test-TPControlSharePoint uses).
function Get-TPCollabNoShellDetail {
    [CmdletBinding()] param()
    'Requires the SharePoint Online Management Shell (Get-SPOTenant); not connected. Not exposed by Graph. Re-run with -IncludeSharePointShell to read it.'
}

# SharePoint context for the SPO-5.x controls: $null when the collector did not
# run, else the Graph tenant settings, the Graph sharing capability and the shell
# block ($null when the shell was not connected).
function Get-TPCollabSpoContext {
    [CmdletBinding()] param()
    $raw = Get-TPRawData -Key 'SharePoint'
    if (-not $raw -or -not (Get-TPObjectField -Item $raw -Key 'Success' -Default $false)) { return $null }
    $data = Get-TPObjectField -Item $raw -Key 'Data' -Default $null
    $ts = Get-TPObjectField -Item $data -Key 'TenantSettings' -Default $null
    return [ordered]@{
        Graph = $ts
        Cap   = [string](Get-TPObjectField -Item $ts -Key 'SharingCapability' -Default '')
        Shell = Get-TPObjectField -Item $data -Key 'TenantSettingsSPO' -Default $null
    }
}

# ── TMS-5.1 External unmanaged Teams users cannot initiate conversations (CIS 8.2.3) ──
# Satisfied when the organization blocks communication with unmanaged Teams
# accounts (AllowTeamsConsumer = False, which also stops them starting one),
# blocks them starting one (AllowTeamsConsumerInbound = False), or the Global
# external access policy does (EnableTeamsConsumerInbound = False).
function Test-TPControlTeamsConsumerInbound {
    [CmdletBinding()] param()
    $cid = 'TMS-5.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $teams = Get-TPRawData -Key 'Teams'
    $fed = Get-TPTeamsSection -Teams $teams -Name 'FederationConfig'
    $pol = Get-TPTeamsSection -Teams $teams -Name 'ExternalAccessPolicy'
    $consumer = Get-TPObjectField -Item $fed -Key 'AllowTeamsConsumer' -Default $null
    $inbound  = Get-TPObjectField -Item $fed -Key 'AllowTeamsConsumerInbound' -Default $null
    $polIn    = Get-TPObjectField -Item $pol -Key 'EnableTeamsConsumerInbound' -Default $null
    if ($consumer -eq $false) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Communication with unmanaged Teams accounts is off for the organization (AllowTeamsConsumer = False), so an unmanaged account cannot start a conversation either.' `
            -CurrentValue 'AllowTeamsConsumer = False'
    } elseif ($inbound -eq $false) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Unmanaged Teams accounts cannot find or start a conversation with users in the organization (AllowTeamsConsumerInbound = False); users here must start every conversation.' `
            -CurrentValue 'AllowTeamsConsumerInbound = False'
    } elseif ($polIn -eq $false) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'The Global external access policy stops unmanaged Teams accounts starting a conversation with its users (EnableTeamsConsumerInbound = False). Users assigned another external access policy are governed by that policy, which was not read.' `
            -CurrentValue 'Global external access policy: EnableTeamsConsumerInbound = False'
    } elseif ($consumer -eq $true -and $inbound -eq $true -and $polIn -eq $true) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Unmanaged (personal or free) Teams accounts can search for users in the organization by email address and start a chat or meeting with them. Such accounts take minutes to create and carry no accountability, and the contact arrives outside email filtering.' `
            -CurrentValue 'AllowTeamsConsumer = True; AllowTeamsConsumerInbound = True; Global policy EnableTeamsConsumerInbound = True' `
            -RequiredValue 'AllowTeamsConsumerInbound = False (or AllowTeamsConsumer = False, or the Global external access policy EnableTeamsConsumerInbound = False)' `
            -Remediation $ctrl.Remediation
    } else {
        $unread = @()
        if ($null -eq $consumer) { $unread += 'AllowTeamsConsumer' }
        if ($null -eq $inbound)  { $unread += 'AllowTeamsConsumerInbound' }
        if ($null -eq $polIn)    { $unread += 'the Global external access policy EnableTeamsConsumerInbound' }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "$($unread -join ', ') was not collected; not assessed."
    }
}

# ── TMS-5.2 No communication with trial-only Teams tenants (CIS 8.2.4) ───────
# ExternalAccessWithTrialTenants is Allowed or Blocked; Microsoft's default is
# Blocked. MicrosoftTeams modules before 6.4.0 do not return it.
function Test-TPControlTeamsTrialTenants {
    [CmdletBinding()] param()
    $cid = 'TMS-5.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $fed = Get-TPTeamsSection -Teams (Get-TPRawData -Key 'Teams') -Name 'FederationConfig'
    $v = [string](Get-TPObjectField -Item $fed -Key 'ExternalAccessWithTrialTenants' -Default '')
    if (-not $v) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'ExternalAccessWithTrialTenants (tenant federation configuration) was not collected; not assessed. MicrosoftTeams modules before 6.4.0 do not return it.'
    } elseif ($v -eq 'Blocked') {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Users in tenants that hold only trial licenses cannot reach users here by chat, call or meeting, and users here cannot reach them. Domains on the AllowedTrialTenantDomains list, if any, are still allowed and were not read.' `
            -CurrentValue 'ExternalAccessWithTrialTenants = Blocked'
    } elseif ($v -eq 'Allowed') {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Users can be contacted by accounts in trial-only Teams tenants. Trial tenants are short-lived, cost nothing to create and are used for spam and phishing over Teams.' `
            -CurrentValue 'ExternalAccessWithTrialTenants = Allowed' -RequiredValue 'ExternalAccessWithTrialTenants = Blocked' -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "ExternalAccessWithTrialTenants returned '$v', which is not a value Microsoft documents (Allowed, Blocked); not assessed."
    }
}

# ── TMS-5.3 Only organizers and co-organizers can present (CIS 8.5.6) ────────
# DesignatedPresenterRoleMode sets the default "Who can present" for new
# meetings: OrganizerOnlyUserOverride, EveryoneInCompanyUserOverride (people
# in the organization and guests) or EveryoneUserOverride (Microsoft's default).
function Test-TPControlTeamsPresenterRole {
    [CmdletBinding()] param()
    $cid = 'TMS-5.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $meet = Get-TPTeamsSection -Teams (Get-TPRawData -Key 'Teams') -Name 'MeetingPolicy'
    $v = [string](Get-TPObjectField -Item $meet -Key 'DesignatedPresenterRoleMode' -Default '')
    $req = 'DesignatedPresenterRoleMode = OrganizerOnlyUserOverride'
    switch ($v) {
        '' {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail 'DesignatedPresenterRoleMode (global meeting policy) was not collected; not assessed.'
        }
        'OrganizerOnlyUserOverride' {
            Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
                -Detail 'New meetings default to only the organizer and co-organizers presenting; everyone else joins as an attendee. An organizer can still change this in a meeting''s options.' `
                -CurrentValue "DesignatedPresenterRoleMode = $v"
        }
        'EveryoneInCompanyUserOverride' {
            Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
                -Detail 'New meetings default to every authenticated person in the organization, guests included, joining as a presenter. External and anonymous participants join as attendees, but any internal attendee or guest can take over the screen.' `
                -CurrentValue "DesignatedPresenterRoleMode = $v" -RequiredValue $req -Remediation $ctrl.Remediation
        }
        'EveryoneUserOverride' {
            Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
                -Detail 'New meetings default to everyone presenting (Microsoft''s default): anyone who joins, external and anonymous participants included, can share content with the whole meeting.' `
                -CurrentValue "DesignatedPresenterRoleMode = $v" -RequiredValue $req -Remediation $ctrl.Remediation
        }
        default {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail "DesignatedPresenterRoleMode returned '$v', which is not a value Microsoft documents; not assessed."
        }
    }
}

# ── TMS-5.4 External meeting chat off (CIS 8.5.8) ────────────────────────────
# AllowExternalNonTrustedMeetingChat: whether users can read and send chat in
# meetings hosted by organizations with no trusted relationship. Default True.
function Test-TPControlTeamsExternalMeetingChat {
    [CmdletBinding()] param()
    $cid = 'TMS-5.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $meet = Get-TPTeamsSection -Teams (Get-TPRawData -Key 'Teams') -Name 'MeetingPolicy'
    $v = Get-TPObjectField -Item $meet -Key 'AllowExternalNonTrustedMeetingChat' -Default $null
    if ($null -eq $v) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'AllowExternalNonTrustedMeetingChat (global meeting policy) was not collected; not assessed.'
    } elseif ($v -eq $false) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Users cannot read or send chat in meetings hosted by organizations the tenant has no trusted relationship with.' `
            -CurrentValue 'AllowExternalNonTrustedMeetingChat = False'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Users can read and send chat in meetings hosted by organizations the tenant does not trust, where links and files from unknown senders reach them outside email filtering.' `
            -CurrentValue 'AllowExternalNonTrustedMeetingChat = True' -RequiredValue 'AllowExternalNonTrustedMeetingChat = False' -Remediation $ctrl.Remediation
    }
}

# ── TMS-5.5 Meeting recording off by default (CIS 8.5.9) ─────────────────────
# AllowCloudRecording in the Global meeting policy; users who must record are
# given a separate policy.
function Test-TPControlTeamsCloudRecording {
    [CmdletBinding()] param()
    $cid = 'TMS-5.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $meet = Get-TPTeamsSection -Teams (Get-TPRawData -Key 'Teams') -Name 'MeetingPolicy'
    $v = Get-TPObjectField -Item $meet -Key 'AllowCloudRecording' -Default $null
    if ($null -eq $v) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'AllowCloudRecording (global meeting policy) was not collected; not assessed.'
    } elseif ($v -eq $false) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Meeting recording is off in the Global meeting policy; recording is granted on purpose through a separate policy.' `
            -CurrentValue 'AllowCloudRecording = False'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Everyone on the Global meeting policy can record meetings, capturing confidential discussion and shared screens into stored files by default.' `
            -CurrentValue 'AllowCloudRecording = True' -RequiredValue 'AllowCloudRecording = False in the Global policy' -Remediation $ctrl.Remediation
    }
}

# ── TMS-5.6 Users can report security concerns in Teams (CIS 8.6.1) ──────────
# Three places, every component judged: the Teams Global messaging policy
# (AllowSecurityEndUserReporting = True) and the report submission policy
# (Teams reports to the reporting mailbox only, and email reports to custom
# reporting addresses).
function Test-TPControlTeamsSecurityReporting {
    [CmdletBinding()] param()
    $cid = 'TMS-5.6'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $verified = @(); $short = @(); $unread = @()

    $msg = Get-TPTeamsSection -Teams (Get-TPRawData -Key 'Teams') -Name 'MessagingPolicy'
    $rep = Get-TPObjectField -Item $msg -Key 'AllowSecurityEndUserReporting' -Default $null
    if ($null -eq $rep) { $unread += 'The Global Teams messaging policy (AllowSecurityEndUserReporting) was not collected.' }
    elseif ($rep -eq $true) { $verified += 'Report a security concern is on in the Global Teams messaging policy.' }
    else { $short += 'Report a security concern is off in the Global Teams messaging policy (AllowSecurityEndUserReporting = False), so users cannot report a Teams message.' }

    $def = Get-TPRawData -Key 'Defender-Policies'
    $defData = Get-TPObjectField -Item $def -Key 'Data' -Default $null
    $rsp = Get-TPObjectField -Item $defData -Key 'ReportSubmissionPolicy' -Default $null
    if (-not $def -or -not (Get-TPObjectField -Item $def -Key 'Success' -Default $false)) {
        $unread += 'The Defender collector did not run, so the user reported settings (Get-ReportSubmissionPolicy) were not read.'
    } elseif ($null -eq $rsp) {
        $unread += 'The user reported settings were not read (the results file predates the Get-ReportSubmissionPolicy read).'
    } elseif (-not (Get-TPObjectField -Item $rsp -Key 'Available' -Default $false)) {
        $unread += "Get-ReportSubmissionPolicy failed: $([string](Get-TPObjectField -Item $rsp -Key 'Error' -Default 'no reason recorded'))"
    } elseif (-not (Get-TPObjectField -Item $rsp -Key 'Exists' -Default $false)) {
        $short += 'No report submission policy exists, so reported messages have no reporting mailbox.'
    } else {
        foreach ($sw in @(
                @{ K = 'ReportChatMessageEnabled'; Want = $false; Ok = 'Reported Teams messages are not sent to Microsoft (ReportChatMessageEnabled = False).'; Bad = 'Reported Teams messages are sent to Microsoft (ReportChatMessageEnabled = True), not kept in the organization.' },
                @{ K = 'ReportChatMessageToCustomizedAddressEnabled'; Want = $true; Ok = 'Reported Teams messages go to the reporting mailbox.'; Bad = 'Reported Teams messages do not go to a reporting mailbox (ReportChatMessageToCustomizedAddressEnabled = False).' },
                @{ K = 'ReportJunkToCustomizedAddress'; Want = $true; Ok = 'Junk reports go to the reporting mailbox.'; Bad = 'Junk reports do not go to a reporting mailbox (ReportJunkToCustomizedAddress = False).' },
                @{ K = 'ReportNotJunkToCustomizedAddress'; Want = $true; Ok = 'Not-junk reports go to the reporting mailbox.'; Bad = 'Not-junk reports do not go to a reporting mailbox (ReportNotJunkToCustomizedAddress = False).' },
                @{ K = 'ReportPhishToCustomizedAddress'; Want = $true; Ok = 'Phishing reports go to the reporting mailbox.'; Bad = 'Phishing reports do not go to a reporting mailbox (ReportPhishToCustomizedAddress = False).' })) {
            $v = Get-TPObjectField -Item $rsp -Key $sw.K -Default $null
            if ($null -eq $v) { $unread += "$($sw.K) was not returned." }
            elseif ([bool]$v -eq $sw.Want) { $verified += $sw.Ok }
            else { $short += $sw.Bad }
        }
        foreach ($k in @('ReportJunkAddresses', 'ReportNotJunkAddresses', 'ReportPhishAddresses')) {
            # Presence is read from the field itself: an empty list replayed from
            # JSON is present and empty, never "not returned".
            # The collector stores $null for a list the cmdlet did not return.
            $rawList = $null
            $present = Test-TPFieldPresent -Item $rsp -Key $k
            if ($present) { $rawList = if ($rsp -is [System.Collections.IDictionary]) { , $rsp[$k] } else { , $rsp.PSObject.Properties[$k].Value } }
            $list = @(@($rawList) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            if (-not $present -or $null -eq $rawList) {
                $unread += "$k was not returned."
            } elseif ($list.Count -gt 0) {
                $verified += "$k names a reporting mailbox ($($list -join ', '))."
            } else {
                $short += "$k is empty: no reporting mailbox is set."
            }
        }
    }

    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unread `
        -CurrentValue $(if ($short.Count) { "$($short.Count) of the user reporting settings fall short" } else { '' }) `
        -RequiredValue 'AllowSecurityEndUserReporting = True; ReportChatMessageEnabled = False; ReportChatMessageToCustomizedAddressEnabled = True; ReportJunk/NotJunk/PhishToCustomizedAddress = True with a reporting mailbox in each address list'
}

# ── SPO-5.1 Infected files cannot be downloaded (CIS 7.3.1) ──────────────────
# DisallowInfectedFileDownload hides the Download button on the Virus Found
# page; Microsoft's default is False.
function Test-TPControlSPOInfectedFileDownload {
    [CmdletBinding()] param()
    $cid = 'SPO-5.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ctx = Get-TPCollabSpoContext
    if (-not $ctx) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'SharePoint collector did not run; not assessed.'
        return
    }
    $noShell = Get-TPCollabNoShellDetail
    if ($null -eq $ctx.Shell) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $noShell
        return
    }
    $unread = Get-TPSpoShellUnread -Shell $ctx.Shell -Keys 'DisallowInfectedFileDownload'
    if ($unread) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $unread
    } elseif ((Get-TPObjectField -Item $ctx.Shell -Key 'DisallowInfectedFileDownload' -Default $null) -eq $true) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'A file detected as infected in SharePoint, OneDrive or Teams cannot be downloaded from the Virus Found page.' -CurrentValue 'DisallowInfectedFileDownload = True'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Users can still download a file SharePoint has detected as infected: the Virus Found page shows a Download button (Microsoft''s default).' `
            -CurrentValue 'DisallowInfectedFileDownload = False' -RequiredValue 'DisallowInfectedFileDownload = True' -Remediation $ctrl.Remediation
    }
}

# ── SPO-5.2 SharePoint and OneDrive integration with Entra B2B (CIS 7.2.2) ───
# With the integration on, every file and folder share with an external person
# creates a guest account, so Entra external collaboration settings and
# Conditional Access apply. Microsoft's default is False.
function Test-TPControlSPOB2BIntegration {
    [CmdletBinding()] param()
    $cid = 'SPO-5.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ctx = Get-TPCollabSpoContext
    if (-not $ctx) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'SharePoint collector did not run; not assessed.'
        return
    }
    $noShell = Get-TPCollabNoShellDetail
    if ($null -eq $ctx.Shell) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $noShell
        return
    }
    $unread = Get-TPSpoShellUnread -Shell $ctx.Shell -Keys 'EnableAzureADB2BIntegration'
    if ($unread) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $unread
    } elseif ((Get-TPObjectField -Item $ctx.Shell -Key 'EnableAzureADB2BIntegration' -Default $null) -eq $true) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Sharing a file or folder with an external person creates a Microsoft Entra guest account, so guest invitation settings and Conditional Access apply to it.' -CurrentValue 'EnableAzureADB2BIntegration = True'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'File and folder shares with external people use SharePoint''s own one-time-passcode authentication: no guest account is created, so Entra guest settings, access reviews and Conditional Access do not reach those recipients.' `
            -CurrentValue 'EnableAzureADB2BIntegration = False' -RequiredValue 'EnableAzureADB2BIntegration = True' -Remediation $ctrl.Remediation
    }
}

# ── SPO-5.3 OneDrive content sharing restricted (CIS 7.2.4) ──────────────────
# OneDriveSharingCapability = Disabled ("Only people in your organization").
# OneDrive cannot be more permissive than SharePoint (Microsoft Learn), so a
# SharePoint setting of disabled read from Graph settles it without the shell.
function Test-TPControlSPOOneDriveSharing {
    [CmdletBinding()] param()
    $cid = 'SPO-5.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ctx = Get-TPCollabSpoContext
    if (-not $ctx) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'SharePoint collector did not run; not assessed.'
        return
    }
    $noShell = Get-TPCollabNoShellDetail
    $req = 'OneDriveSharingCapability = Disabled'
    if ($ctx.Cap -eq 'disabled') {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'External sharing is off for SharePoint, and Microsoft documents that OneDrive cannot be more permissive than SharePoint, so OneDrive content is shared only inside the organization.' `
            -CurrentValue 'SharingCapability = disabled'
        return
    }
    if ($null -eq $ctx.Shell) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "SharePoint external sharing is not off, so OneDrive's own level decides. $noShell"
        return
    }
    $unread = Get-TPSpoShellUnread -Shell $ctx.Shell -Keys 'OneDriveSharingCapability'
    $v = [string](Get-TPObjectField -Item $ctx.Shell -Key 'OneDriveSharingCapability' -Default '')
    if ($unread) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $unread
    } elseif ($v -eq 'Disabled') {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'OneDrive content can be shared only with people in the organization.' -CurrentValue "OneDriveSharingCapability = $v"
    } elseif ($v -in @('ExistingExternalUserSharingOnly', 'ExternalUserSharingOnly')) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "OneDrive content can be shared with external people who sign in ($v); Anyone links are off. Personal OneDrive files can still leave the organization through a user's own share." `
            -CurrentValue "OneDriveSharingCapability = $v" -RequiredValue $req -Remediation $ctrl.Remediation
    } elseif ($v -eq 'ExternalUserAndGuestSharing') {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'OneDrive content can be shared with anyone, including through Anyone links that need no sign-in (Microsoft''s default).' `
            -CurrentValue "OneDriveSharingCapability = $v" -RequiredValue $req -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "OneDriveSharingCapability returned '$v', which is not a value Microsoft documents; not assessed."
    }
}

# ── SPO-5.4 Guests cannot share items they don't own (CIS 7.2.5) ─────────────
# Graph isResharingByExternalUsersEnabled ("whether guests are allowed to
# reshare files, folders, and sites they don't own") is the inverse of
# Set-SPOTenant -PreventExternalUsersFromResharing.
function Test-TPControlSPOGuestResharing {
    [CmdletBinding()] param()
    $cid = 'SPO-5.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ctx = Get-TPCollabSpoContext
    $v = if ($ctx) { Get-TPObjectField -Item $ctx.Graph -Key 'IsResharingByExternalUsersEnabled' -Default $null } else { $null }
    if ($null -eq $v) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'isResharingByExternalUsersEnabled (Graph SharePoint tenant settings) was not collected; not assessed.'
    } elseif ($v -eq $false) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Guests cannot reshare files, folders or sites they do not own; only owners decide who else gets access.' -CurrentValue 'isResharingByExternalUsersEnabled = False (PreventExternalUsersFromResharing = True)'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Guests can share files, folders and sites they do not own with further people, so content reaches people its owner never chose (Microsoft''s default).' `
            -CurrentValue 'isResharingByExternalUsersEnabled = True' -RequiredValue 'PreventExternalUsersFromResharing = True (isResharingByExternalUsersEnabled = False)' -Remediation $ctrl.Remediation
    }
}

# ── SPO-5.5 External sharing limited by a domain allow list (CIS 7.2.6) ──────
# Graph sharingDomainRestrictionMode none / allowList / blockList with
# sharingAllowedDomainList. Satisfied with an allow list naming at least one
# domain, or with external sharing off.
function Test-TPControlSPODomainAllowList {
    [CmdletBinding()] param()
    $cid = 'SPO-5.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ctx = Get-TPCollabSpoContext
    $mode = if ($ctx) { [string](Get-TPObjectField -Item $ctx.Graph -Key 'SharingDomainRestrictionMode' -Default '') } else { '' }
    # Two statements: an if-block yielding an empty array assigns $null.
    $allowed = @()
    if ($ctx) { $allowed = @(@(Get-TPObjectField -Item $ctx.Graph -Key 'SharingAllowedDomainList' -Default @()) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) }
    $req = 'SharingDomainRestrictionMode = AllowList with at least one domain in SharingAllowedDomainList (or external sharing off)'
    if ($ctx -and $ctx.Cap -eq 'disabled') {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'External sharing is off for SharePoint, so no external domain can receive shared content.' -CurrentValue 'SharingCapability = disabled'
    } elseif (-not $ctx -or -not $ctx.Cap -or -not $mode) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The SharePoint sharing capability and domain restriction mode (Graph SharePoint tenant settings) were not collected; not assessed.'
    } elseif ($mode -eq 'allowList' -and $allowed.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "External sharing is limited to $($allowed.Count) allowed domain(s): $(($allowed | Select-Object -First 5) -join ', ')$(if ($allowed.Count -gt 5) { " and $($allowed.Count - 5) more" })." `
            -CurrentValue "SharingDomainRestrictionMode = allowList ($($allowed.Count) domain(s))"
    } elseif ($mode -eq 'allowList') {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The domain restriction mode is allowList but no allowed domain was returned, so which domains can receive shared content was not established; not assessed.'
    } elseif ($mode -in @('blockList', 'none')) {
        $what = if ($mode -eq 'blockList') { 'Sharing is open to every external domain except the blocked ones.' } else { 'Sharing is open to every external domain.' }
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$what A user can share SharePoint and OneDrive content with any domain, including one an attacker controls." `
            -CurrentValue "SharingDomainRestrictionMode = $mode" -RequiredValue $req -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "sharingDomainRestrictionMode returned '$mode', which is not a value Microsoft documents; not assessed."
    }
}

# ── SPO-5.6 External sharing restricted by security group (CIS 7.2.8) ────────
# Get-SPOTenant WhoCanShareAuthenticatedGuestAllowList: the security groups
# whose members may share with authenticated guests. Groups that may also share
# Anyone links (WhoCanShareAnonymousAllowList) do not count, as in the CIS
# PowerShell audit. External sharing off read from Graph settles it.
function Test-TPControlSPOSharingGroups {
    [CmdletBinding()] param()
    $cid = 'SPO-5.6'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ctx = Get-TPCollabSpoContext
    if (-not $ctx) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'SharePoint collector did not run; not assessed.'
        return
    }
    $noShell = Get-TPCollabNoShellDetail
    if ($ctx.Cap -eq 'disabled') {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'External sharing is off for SharePoint, so nobody can share externally.' -CurrentValue 'SharingCapability = disabled'
        return
    }
    if ($null -eq $ctx.Shell) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "SharePoint external sharing is not off, so who may share externally decides. $noShell"
        return
    }
    $unread = Get-TPSpoShellUnread -Shell $ctx.Shell -Keys 'WhoCanShareAuthenticatedGuestAllowListCount'
    $n = Get-TPObjectField -Item $ctx.Shell -Key 'WhoCanShareAuthenticatedGuestAllowListCount' -Default $null
    $anon = Get-TPObjectField -Item $ctx.Shell -Key 'WhoCanShareAnonymousAllowListCount' -Default $null
    if ($unread) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail ($unread -replace 'Count\b', '')
    } elseif ([int]$n -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Only members of $n security group(s) can share externally, and only with authenticated guests." -CurrentValue "WhoCanShareAuthenticatedGuestAllowList: $n group(s)"
    } elseif (-not $ctx.Cap) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'No security group is set to share with authenticated guests, but the SharePoint sharing capability (Graph SharePoint tenant settings) was not collected, so whether external sharing is off was not established; not assessed.'
    } else {
        $note = if ($null -ne $anon -and [int]$anon -gt 0) { " $anon group(s) are allowed to share with Anyone, which needs no sign-in and does not meet the requirement." } else { '' }
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "External sharing is not limited to members of a security group that shares with authenticated guests only: every user who can share can share outside the organization.$note" `
            -CurrentValue 'WhoCanShareAuthenticatedGuestAllowList: empty' -RequiredValue 'At least one security group in WhoCanShareAuthenticatedGuestAllowList (or external sharing off)' -Remediation $ctrl.Remediation
    }
}

# ── SPO-5.7 Default sharing link permission is View (CIS 7.2.11) ─────────────
# DefaultLinkPermission: View or Edit (Microsoft's default).
function Test-TPControlSPODefaultLinkPermission {
    [CmdletBinding()] param()
    $cid = 'SPO-5.7'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ctx = Get-TPCollabSpoContext
    if (-not $ctx) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'SharePoint collector did not run; not assessed.'
        return
    }
    $noShell = Get-TPCollabNoShellDetail
    if ($null -eq $ctx.Shell) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $noShell
        return
    }
    $unread = Get-TPSpoShellUnread -Shell $ctx.Shell -Keys 'DefaultLinkPermission'
    $v = [string](Get-TPObjectField -Item $ctx.Shell -Key 'DefaultLinkPermission' -Default '')
    if ($unread) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $unread
    } elseif ($v -eq 'View') {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Sharing links default to view only; a user must choose edit on purpose.' -CurrentValue 'DefaultLinkPermission = View'
    } elseif ($v -eq 'Edit') {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Sharing links default to edit (Microsoft''s default), so a link shared without changing the option lets every recipient change or delete the content.' `
            -CurrentValue 'DefaultLinkPermission = Edit' -RequiredValue 'DefaultLinkPermission = View' -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "DefaultLinkPermission returned '$v', which is not a value Microsoft documents (View, Edit); not assessed."
    }
}

#Requires -Version 7.0
#
# Invoke-NRGCollectTeams.ps1
# Collects Microsoft Teams meeting, external access, and client configuration.
#
# READ-ONLY. Uses MicrosoftTeams module Get-* cmdlets.
#
# Required session: Teams (Connect-MicrosoftTeams).
#
# NIST SP 800-53: AC-3 (access enforcement), AC-17 (remote access)
# MITRE ATT&CK:   T1534 (Internal Spearphishing), T1078 (Valid Accounts)
#

function Invoke-NRGCollectTeams {
    [CmdletBinding()] param()
    # Every section runs its own try/catch, so an empty or absent section is
    # ambiguous without SectionStatus (CLAUDE.md, "Empty is not clean").
    # Every property is read through Get-NRGObjectField with a $null default:
    # Get-Cs* objects vary by module version, and defaulting an absent
    # property to the SECURE value (as AllowPublicUsers / AllowFederatedUsers
    # did) turned "not returned" into a pass.
    $result = @{
        Success = $false
        Data    = @{
            FederationConfig     = $null
            ExternalAccessPolicy = $null
            MeetingPolicy        = $null
            MeetingConfiguration = $null
            ClientConfiguration  = $null
            GuestMeetingPolicy   = $null
            BroadcastPolicy      = $null
            EventsPolicy         = $null
            SectionStatus        = @{
                FederationConfig     = 'NotRun'
                ExternalAccessPolicy = 'NotRun'
                MeetingPolicy        = 'NotRun'
                MeetingConfiguration = 'NotRun'
                ClientConfiguration  = 'NotRun'
                GuestMeetingPolicy   = 'NotRun'
                BroadcastPolicy      = 'NotRun'
                EventsPolicy         = 'NotRun'
            }
        }
    }
    $f = { param($o, $k) Get-NRGObjectField -Item $o -Key $k -Default $null }
    $b = { param($o, $k) $v = Get-NRGObjectField -Item $o -Key $k -Default $null; if ($null -eq $v) { $null } else { [bool]$v } }
    # Runs one Get-Cs* read into its section. A cmdlet the session does not
    # expose is a failed read, never "none configured".
    $section = {
        param([string] $Name, [string] $Cmd, [hashtable] $CmdArgs, [scriptblock] $Shape)
        try {
            if (-not (Get-Command $Cmd -ErrorAction SilentlyContinue)) { throw "$Cmd is not available in this session." }
            $o = @(& $Cmd @CmdArgs -ErrorAction Stop) | Select-Object -First 1
            if ($null -eq $o) { throw "$Cmd returned nothing." }
            $result.Data[$Name] = & $Shape $o
            $result.Data.SectionStatus[$Name] = 'Collected'
        } catch {
            $result.Data.SectionStatus[$Name] = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source "Teams-$Name" -Message $_.Exception.Message
            }
        }
    }

    try {
        # Federation / external access. AllowedDomains is either an
        # AllowAllKnownDomains marker or a list whose items expose
        # .AllowedDomain (blocked items expose .Domain); null-filter so an
        # open (marker) tenant yields an empty list, never @($null) — Count 1
        # would read as "restricted to 1 domain".
        & $section 'FederationConfig' 'Get-CsTenantFederationConfiguration' @{} {
            param($fed)
            $allowedList = @(foreach ($x in @(& $f $fed 'AllowedDomains')) { Get-NRGObjectField -Item $x -Key 'AllowedDomain' } ) | Where-Object { $_ }
            $blockedList = @(foreach ($x in @(& $f $fed 'BlockedDomains')) { Get-NRGObjectField -Item $x -Key 'Domain' } ) | Where-Object { $_ }
            [ordered]@{
                AllowFederatedUsers                 = & $b $fed 'AllowFederatedUsers'
                AllowPublicUsers                    = & $b $fed 'AllowPublicUsers'
                AllowTeamsConsumer                  = & $b $fed 'AllowTeamsConsumer'
                AllowTeamsConsumerInbound           = & $b $fed 'AllowTeamsConsumerInbound'
                TreatDiscoveredPartnersAsUnverified = & $b $fed 'TreatDiscoveredPartnersAsUnverified'
                AllowedDomains                      = @($allowedList)
                BlockedDomains                      = @($blockedList)
            }
        }

        & $section 'ExternalAccessPolicy' 'Get-CsExternalAccessPolicy' @{ Identity = 'Global' } {
            param($ext)
            @{
                Identity                   = [string](& $f $ext 'Identity')
                EnableFederationAccess     = & $b $ext 'EnableFederationAccess'
                EnablePublicCloudAccess    = & $b $ext 'EnablePublicCloudAccess'
                EnableTeamsConsumerAccess  = & $b $ext 'EnableTeamsConsumerAccess'
                EnableTeamsConsumerInbound = & $b $ext 'EnableTeamsConsumerInbound'
            }
        }

        # Global meeting policy. Every field any TMS control reads is here —
        # four controls read fields this block never wrote and could only
        # ever report "not assessed".
        & $section 'MeetingPolicy' 'Get-CsTeamsMeetingPolicy' @{ Identity = 'Global' } {
            param($meet)
            $exp = & $f $meet 'NewMeetingRecordingExpirationDays'
            @{
                AllowAnonymousUsersToJoinMeeting           = & $b $meet 'AllowAnonymousUsersToJoinMeeting'
                AllowAnonymousUsersToStartMeeting          = & $b $meet 'AllowAnonymousUsersToStartMeeting'
                AutoAdmittedUsers                          = [string](& $f $meet 'AutoAdmittedUsers')
                AllowExternalParticipantGiveRequestControl = & $b $meet 'AllowExternalParticipantGiveRequestControl'
                AllowCloudRecording                        = & $b $meet 'AllowCloudRecording'
                AllowPSTNUsersToBypassLobby                = & $b $meet 'AllowPSTNUsersToBypassLobby'
                NewMeetingRecordingExpirationDays          = $(if ($null -ne $exp -and "$exp" -match '^-?\d+$') { [int]"$exp" } else { $null })
                AllowChannelMeetingScheduling              = & $b $meet 'AllowChannelMeetingScheduling'
                AllowWatermarkForScreenSharing             = & $b $meet 'AllowWatermarkForScreenSharing'
                AllowWatermarkForCameraVideo               = & $b $meet 'AllowWatermarkForCameraVideo'
                # Meeting chat is MeetingChatEnabledType (Enabled / Disabled /
                # EnabledExceptAnonymous / EnabledInMeetingOnlyForAllExceptAnonymous);
                # the name TMS-3.3 read, AllowMeetingChat, is not a property.
                MeetingChatEnabledType                     = [string](& $f $meet 'MeetingChatEnabledType')
            }
        }

        # Organization-wide meeting settings: DisableAnonymousJoin blocks
        # anonymous join for every meeting whatever the meeting policy says.
        & $section 'MeetingConfiguration' 'Get-CsTeamsMeetingConfiguration' @{} {
            param($mc)
            @{ DisableAnonymousJoin = & $b $mc 'DisableAnonymousJoin' }
        }

        & $section 'BroadcastPolicy' 'Get-CsTeamsMeetingBroadcastPolicy' @{ Identity = 'Global' } {
            param($bcast)
            [ordered]@{
                AllowBroadcastScheduling        = & $b $bcast 'AllowBroadcastScheduling'
                BroadcastAttendeeVisibilityMode = [string](& $f $bcast 'BroadcastAttendeeVisibilityMode')
            }
        }

        # Teams events (webinars, town halls) replaced live events, which
        # Microsoft retired on June 30, 2026. Both attendee settings default
        # to Everyone — public, anonymous attendance.
        & $section 'EventsPolicy' 'Get-CsTeamsEventsPolicy' @{ Identity = 'Global' } {
            param($ev)
            [ordered]@{
                AllowWebinars               = [string](& $f $ev 'AllowWebinars')
                EventAccessType             = [string](& $f $ev 'EventAccessType')
                AllowTownhalls              = [string](& $f $ev 'AllowTownhalls')
                TownhallEventAttendeeAccess = [string](& $f $ev 'TownhallEventAttendeeAccess')
            }
        }

        & $section 'ClientConfiguration' 'Get-CsTeamsClientConfiguration' @{} {
            param($client)
            @{
                AllowEmailIntoChannel = & $b $client 'AllowEmailIntoChannel'
                AllowDropBox          = & $b $client 'AllowDropBox'
                AllowBox              = & $b $client 'AllowBox'
                AllowGoogleDrive      = & $b $client 'AllowGoogleDrive'
                AllowShareFile        = & $b $client 'AllowShareFile'
                AllowEgnyte           = & $b $client 'AllowEgnyte'
                AllowGuestUser        = & $b $client 'AllowGuestUser'
            }
        }

        & $section 'GuestMeetingPolicy' 'Get-CsTeamsGuestMeetingConfiguration' @{} {
            param($guest)
            @{
                AllowIPVideo      = & $b $guest 'AllowIPVideo'
                AllowMeetNow      = & $b $guest 'AllowMeetNow'
                ScreenSharingMode = [string](& $f $guest 'ScreenSharingMode')
            }
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Teams-Collector' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'Teams' -Data $result
}

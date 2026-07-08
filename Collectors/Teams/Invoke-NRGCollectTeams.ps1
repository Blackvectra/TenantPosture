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
    $result = @{
        Success = $false
        Data    = @{
            FederationConfig    = $null
            ExternalAccessPolicy = $null
            MeetingPolicy       = $null
            ClientConfiguration = $null
            GuestMeetingPolicy  = $null
            BroadcastPolicy     = $null
        }
    }

    try {
        # Federation / external access
        if (Get-Command Get-CsTenantFederationConfiguration -ErrorAction SilentlyContinue) {
            try {
                $fed = Get-CsTenantFederationConfiguration -ErrorAction Stop
                if ($fed) {
                    # Get-Cs* objects vary by MicrosoftTeams module version and can
                    # arrive remoting-deserialized without every property — bare
                    # $fed.Prop then THROWS under StrictMode. Read via the shape-
                    # agnostic helper so one absent property doesn't nuke the whole
                    # FederationConfig block. (Same StrictMode class as the Graph
                    # shape fix, but Cs cmdlets bypass Invoke-NRGGraphRequest.)
                    # AllowedDomains is either an AllowAllKnownDomains marker or a
                    # list whose items expose .AllowedDomain (Blocked items expose
                    # .Domain). Enumerate the container and null-filter so an empty
                    # or marker container yields an empty array (Count 0), never a
                    # phantom @($null) — @($null).Count is 1, which TMS-1.1 would
                    # misread as "federation restricted to 1 domain" on an OPEN
                    # (wide-open) federation tenant: a false Satisfied.
                    $allowedRaw = Get-NRGObjectField -Item $fed -Key 'AllowedDomains'
                    $blockedRaw = Get-NRGObjectField -Item $fed -Key 'BlockedDomains'
                    $allowedList = @(foreach ($x in @($allowedRaw)) { Get-NRGObjectField -Item $x -Key 'AllowedDomain' }) | Where-Object { $_ }
                    $blockedList = @(foreach ($x in @($blockedRaw)) { Get-NRGObjectField -Item $x -Key 'Domain' }) | Where-Object { $_ }
                    $result.Data.FederationConfig = [ordered]@{
                        AllowFederatedUsers              = [bool](Get-NRGObjectField -Item $fed -Key 'AllowFederatedUsers' -Default $false)
                        AllowPublicUsers                 = [bool](Get-NRGObjectField -Item $fed -Key 'AllowPublicUsers' -Default $false)
                        AllowTeamsConsumer               = [bool](Get-NRGObjectField -Item $fed -Key 'AllowTeamsConsumer' -Default $false)
                        AllowTeamsConsumerInbound        = [bool](Get-NRGObjectField -Item $fed -Key 'AllowTeamsConsumerInbound' -Default $false)
                        TreatDiscoveredPartnersAsUnverified = [bool](Get-NRGObjectField -Item $fed -Key 'TreatDiscoveredPartnersAsUnverified' -Default $false)
                        AllowedDomains                   = @($allowedList)
                        BlockedDomains                   = @($blockedList)
                    }
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Teams-Federation' -Message $_.Exception.Message
                }
            }
        }

        # External access policy (global)
        if (Get-Command Get-CsExternalAccessPolicy -ErrorAction SilentlyContinue) {
            try {
                $ext = Get-CsExternalAccessPolicy -Identity Global -ErrorAction Stop
                if ($ext) {
                    # Shape-agnostic reads — see FederationConfig note above.
                    $result.Data.ExternalAccessPolicy = @{
                        Identity                  = [string](Get-NRGObjectField -Item $ext -Key 'Identity' -Default '')
                        EnableFederationAccess    = [bool](Get-NRGObjectField -Item $ext -Key 'EnableFederationAccess' -Default $false)
                        EnablePublicCloudAccess   = [bool](Get-NRGObjectField -Item $ext -Key 'EnablePublicCloudAccess' -Default $false)
                        EnableTeamsConsumerAccess = [bool](Get-NRGObjectField -Item $ext -Key 'EnableTeamsConsumerAccess' -Default $false)
                        EnableTeamsConsumerInbound = [bool](Get-NRGObjectField -Item $ext -Key 'EnableTeamsConsumerInbound' -Default $false)
                    }
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Teams-ExternalAccess' -Message $_.Exception.Message
                }
            }
        }

        # Global meeting policy
        if (Get-Command Get-CsTeamsMeetingPolicy -ErrorAction SilentlyContinue) {
            try {
                $meet = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop
                if ($meet) {
                    $result.Data.MeetingPolicy = @{
                        AllowAnonymousUsersToJoinMeeting = [bool]$meet.AllowAnonymousUsersToJoinMeeting
                        AllowAnonymousUsersToStartMeeting = [bool]$meet.AllowAnonymousUsersToStartMeeting
                        AutoAdmittedUsers                = [string]$meet.AutoAdmittedUsers
                        AllowExternalParticipantGiveRequestControl = [bool]$meet.AllowExternalParticipantGiveRequestControl
                        AllowCloudRecording              = [bool]$meet.AllowCloudRecording
                        # TMS-2.8 (PSTN lobby bypass) + TMS-4.1 (recording expiry).
                        # Field is NewMeetingRecordingExpirationDays (Get-CsTeamsMeetingPolicy).
                        AllowPSTNUsersToBypassLobby      = [bool]$meet.AllowPSTNUsersToBypassLobby
                        NewMeetingRecordingExpirationDays = [int]($meet.NewMeetingRecordingExpirationDays ?? -1)
                    }
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Teams-MeetingPolicy' -Message $_.Exception.Message
                }
            }
        }

        # Global meeting broadcast (live events) policy — TMS-4.4.
        # BroadcastAttendeeVisibilityMode 'Everyone' lets anonymous internet
        # users watch live events; AllowBroadcastScheduling $false disables
        # live events entirely. Both come from Get-CsTeamsMeetingBroadcastPolicy.
        if (Get-Command Get-CsTeamsMeetingBroadcastPolicy -ErrorAction SilentlyContinue) {
            try {
                $bcast = Get-CsTeamsMeetingBroadcastPolicy -Identity Global -ErrorAction Stop
                if ($bcast) {
                    # Shape-agnostic reads — see FederationConfig note above.
                    $result.Data.BroadcastPolicy = [ordered]@{
                        AllowBroadcastScheduling        = [bool](Get-NRGObjectField -Item $bcast -Key 'AllowBroadcastScheduling' -Default $false)
                        BroadcastAttendeeVisibilityMode = [string](Get-NRGObjectField -Item $bcast -Key 'BroadcastAttendeeVisibilityMode' -Default '')
                    }
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Teams-BroadcastPolicy' -Message $_.Exception.Message
                }
            }
        }

        # Client configuration
        if (Get-Command Get-CsTeamsClientConfiguration -ErrorAction SilentlyContinue) {
            try {
                $client = Get-CsTeamsClientConfiguration -ErrorAction Stop
                if ($client) {
                    $result.Data.ClientConfiguration = @{
                        AllowEmailIntoChannel = [bool]$client.AllowEmailIntoChannel
                        AllowDropBox          = [bool]$client.AllowDropBox
                        AllowBox              = [bool]$client.AllowBox
                        AllowGoogleDrive      = [bool]$client.AllowGoogleDrive
                        AllowShareFile        = [bool]$client.AllowShareFile
                    }
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Teams-Client' -Message $_.Exception.Message
                }
            }
        }

        # Guest meeting policy
        if (Get-Command Get-CsTeamsGuestMeetingConfiguration -ErrorAction SilentlyContinue) {
            try {
                $guest = Get-CsTeamsGuestMeetingConfiguration -ErrorAction Stop
                if ($guest) {
                    $result.Data.GuestMeetingPolicy = @{
                        AllowIPVideo  = [bool]$guest.AllowIPVideo
                        AllowMeetNow  = [bool]$guest.AllowMeetNow
                        ScreenSharingMode = [string]$guest.ScreenSharingMode
                    }
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Teams-GuestPolicy' -Message $_.Exception.Message
                }
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

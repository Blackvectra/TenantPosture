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
        }
    }

    try {
        # Federation / external access
        if (Get-Command Get-CsTenantFederationConfiguration -ErrorAction SilentlyContinue) {
            try {
                $fed = Get-CsTenantFederationConfiguration -ErrorAction Stop
                if ($fed) {
                    $result.Data.FederationConfig = @{
                        AllowFederatedUsers              = [bool]$fed.AllowFederatedUsers
                        AllowPublicUsers                 = [bool]$fed.AllowPublicUsers
                        AllowTeamsConsumer               = [bool]$fed.AllowTeamsConsumer
                        AllowTeamsConsumerInbound        = [bool]$fed.AllowTeamsConsumerInbound
                        TreatDiscoveredPartnersAsUnverified = [bool]$fed.TreatDiscoveredPartnersAsUnverified
                        AllowedDomains                   = @($fed.AllowedDomains.AllowedDomain)
                        BlockedDomains                   = @($fed.BlockedDomains.Domain)
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
                    $result.Data.ExternalAccessPolicy = @{
                        Identity                  = [string]$ext.Identity
                        EnableFederationAccess    = [bool]$ext.EnableFederationAccess
                        EnablePublicCloudAccess   = [bool]$ext.EnablePublicCloudAccess
                        EnableTeamsConsumerAccess = [bool]$ext.EnableTeamsConsumerAccess
                        EnableTeamsConsumerInbound = [bool]$ext.EnableTeamsConsumerInbound
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
                    }
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Teams-MeetingPolicy' -Message $_.Exception.Message
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

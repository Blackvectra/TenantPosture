#
# Invoke-NRGCollectTeams.ps1
# Collects Microsoft Teams governance settings via MicrosoftTeams module.
#
# Requires: MicrosoftTeams connection (Connect-MicrosoftTeams)
#
# Data keys stored:
#   Teams.ExternalAccess       — Get-CsExternalAccessPolicy -Identity Global
#   Teams.MeetingPolicy        — Get-CsTeamsMeetingPolicy -Identity Global
#   Teams.ClientConfig         — Get-CsTeamsClientConfiguration -Identity Global
#   Teams.GuestConfig          — Get-CsTeamsGuestAccessConfiguration
#   Teams.AppPermissionPolicy  — Get-CsTeamsAppPermissionPolicy -Identity Global
#
# NIST SP 800-53: AC-3, AC-17, AC-20, CM-7
# MITRE ATT&CK:   T1078, T1204, T1566
#

function Invoke-NRGCollectTeams {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'Teams'
        Timestamp  = (Get-Date -Format 'o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    try {
        # ── External access policy ─────────────────────────────────────────────
        try {
            $ext = Get-CsExternalAccessPolicy -Identity Global -ErrorAction Stop
            $result.Data['ExternalAccess'] = $ext
        } catch {
            $result.Exceptions += "ExternalAccess: $($_.Exception.Message)"
            $result.Data['ExternalAccess'] = $null
        }

        # ── Teams meeting policy (Global) ──────────────────────────────────────
        try {
            $mtg = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop
            $result.Data['MeetingPolicy'] = $mtg
        } catch {
            $result.Exceptions += "MeetingPolicy: $($_.Exception.Message)"
            $result.Data['MeetingPolicy'] = $null
        }

        # ── Teams client configuration ─────────────────────────────────────────
        try {
            $client = Get-CsTeamsClientConfiguration -Identity Global -ErrorAction Stop
            $result.Data['ClientConfig'] = $client
        } catch {
            $result.Exceptions += "ClientConfig: $($_.Exception.Message)"
            $result.Data['ClientConfig'] = $null
        }

        # ── Guest access configuration ─────────────────────────────────────────
        try {
            $guest = Get-CsTeamsGuestAccessConfiguration -ErrorAction Stop
            $result.Data['GuestConfig'] = $guest
        } catch {
            $result.Exceptions += "GuestConfig: $($_.Exception.Message)"
            $result.Data['GuestConfig'] = $null
        }

        # ── App permission policy (Global) ─────────────────────────────────────
        try {
            $app = Get-CsTeamsAppPermissionPolicy -Identity Global -ErrorAction Stop
            $result.Data['AppPermissionPolicy'] = $app
        } catch {
            $result.Exceptions += "AppPermissionPolicy: $($_.Exception.Message)"
            $result.Data['AppPermissionPolicy'] = $null
        }

        # ── Messaging policy (Global) ──────────────────────────────────────────
        try {
            $msg = Get-CsTeamsMessagingPolicy -Identity Global -ErrorAction Stop
            $result.Data['MessagingPolicy'] = $msg
        } catch {
            $result.Exceptions += "MessagingPolicy: $($_.Exception.Message)"
            $result.Data['MessagingPolicy'] = $null
        }

        $result.Success = $true

    } catch {
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'Invoke-NRGCollectTeams' -Message $_.Exception.Message
    }

    Set-NRGRawData -Key 'Teams' -Data $result
    return $result
}

#Requires -Version 7.0
#
# TP.TeamsTruth.Tests.ps1
# NRG Technology Services / NextLayerSec LLC — Author: Matthew Levorson
# Pins the Teams verdicts to what each Get-Cs* setting means (Microsoft
# Learn), driving the REAL collector with raw cmdlet shapes injected into
# module scope. Every case produced a wrong verdict before this change.
#
# Data keys: Teams (Invoke-TPCollectTeams), Purview, AAD-IdentityGovernance.
#

Describe 'Teams controls read the setting they name' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:Cmds = @('Get-CsTenantFederationConfiguration','Get-CsExternalAccessPolicy','Get-CsTeamsMeetingPolicy','Get-CsTeamsMeetingConfiguration',
                         'Get-CsTeamsMeetingBroadcastPolicy','Get-CsTeamsEventsPolicy','Get-CsTeamsClientConfiguration','Get-CsTeamsGuestMeetingConfiguration')
        # Each stand-in returns the module-scope object of the same name
        # ($script:TeamsObj['Get-CsTeamsMeetingPolicy'], ...).
        foreach ($n in $script:Cmds) {
            & $script:Mod { param($n) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create("param(`$Identity) `$script:TeamsObj['$n']")) } $n
        }
        function script:Collect { param([hashtable] $Objects)
            Clear-TPState
            & $script:Mod { param($o) $script:TeamsObj = $o } $Objects
            Invoke-TPCollectTeams | Out-Null
        }
        function script:Verdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
        # Microsoft defaults, as Get-Cs* returns them.
        function script:Defaults {
            @{
                'Get-CsTenantFederationConfiguration' = [pscustomobject]@{ AllowFederatedUsers = $true; AllowTeamsConsumer = $true; AllowTeamsConsumerInbound = $true; AllowedDomains = [pscustomobject]@{}; BlockedDomains = @() }
                'Get-CsTeamsMeetingPolicy' = [pscustomobject]@{ AllowAnonymousUsersToJoinMeeting = $true; AllowAnonymousUsersToStartMeeting = $false; AutoAdmittedUsers = 'EveryoneInCompanyExcludingGuests'
                    AllowExternalParticipantGiveRequestControl = $false; AllowPSTNUsersToBypassLobby = $false; NewMeetingRecordingExpirationDays = 120; AllowChannelMeetingScheduling = $true
                    AllowWatermarkForScreenSharing = $false; MeetingChatEnabledType = 'Enabled'; AllowCloudRecording = $true }
                'Get-CsTeamsMeetingConfiguration' = [pscustomobject]@{ DisableAnonymousJoin = $false }
                'Get-CsTeamsEventsPolicy' = [pscustomobject]@{ AllowWebinars = 'Enabled'; EventAccessType = 'Everyone'; AllowTownhalls = 'Enabled'; TownhallEventAttendeeAccess = 'Everyone' }
                'Get-CsTeamsClientConfiguration' = [pscustomobject]@{ AllowEmailIntoChannel = $true; AllowDropBox = $true; AllowBox = $true; AllowGoogleDrive = $true; AllowShareFile = $true; AllowEgnyte = $true; AllowGuestUser = $true }
            }
        }
    }
    AfterAll {
        foreach ($n in $script:Cmds) { & $script:Mod { param($n) Remove-Item -Path "function:script:$n" -ErrorAction SilentlyContinue } $n }
        Clear-TPState
    }

    It 'a property the module did not return is not assessed, never the secure value (was: federation "disabled")' {
        $o = Defaults; $o['Get-CsTenantFederationConfiguration'] = [pscustomobject]@{ AllowedDomains = [pscustomobject]@{}; BlockedDomains = @() }
        Collect $o
        (Verdict 'Test-TPControlTeamsExternalChat' 'TMS-2.7').State | Should -Be 'NotApplicable'
        (Verdict 'Test-TPControlTeamsFederationAllowlist' 'TMS-4.3').State | Should -Be 'NotApplicable'
    }
    It 'a failed section is recorded as Failed' {
        $o = Defaults; $o.Remove('Get-CsTeamsClientConfiguration')
        Collect $o
        (Get-TPRawData -Key 'Teams').Data.SectionStatus.ClientConfiguration | Should -Be 'Failed'
        (Verdict 'Test-TPControlTeamsEmailIntegration' 'TMS-2.4').State | Should -Be 'NotApplicable'
    }
    It 'TMS-1.4 reads AllowExternalParticipantGiveRequestControl (was: scored the lobby setting)' {
        $o = Defaults; $o['Get-CsTeamsMeetingPolicy'].AllowExternalParticipantGiveRequestControl = $true
        Collect $o
        (Verdict 'Test-TPControlTeams' 'TMS-1.4').State | Should -Be 'Gap'
    }
    It 'TMS-1.6 reads Teams guest access and who may invite (was: the request-control setting)' {
        $o = Defaults; Collect $o
        Set-TPRawData -Key 'AAD-IdentityGovernance' -Data @{ Success = $true; Data = @{ ExternalCollab = @{ AllowInvitesFrom = 'everyone' } } }
        (Verdict 'Test-TPControlTeams' 'TMS-1.6').State | Should -Be 'Gap'
        Collect $o
        Set-TPRawData -Key 'AAD-IdentityGovernance' -Data @{ Success = $true; Data = @{ ExternalCollab = @{ AllowInvitesFrom = 'adminsAndGuestInviters' } } }
        (Verdict 'Test-TPControlTeams' 'TMS-1.6').State | Should -Be 'Satisfied'
    }
    It 'TMS-1.5 reads retention over OneDrive and SharePoint (was: third-party storage, a duplicate of TMS-2.3)' {
        Clear-TPState
        Set-TPRawData -Key 'Purview' -Data @{ Success = $true; Data = @{ SectionStatus = @{ RetentionPolicies = 'Collected' }
            RetentionPolicies = @(@{ Name = 'Mail'; Enabled = $true; Workloads = @('Exchange') }) } }
        (Verdict 'Test-TPControlTeamsRecordingRetention' 'TMS-1.5').State | Should -Be 'Gap'
    }
    It 'TMS-3.2 does not pass lobby settings that admit guests or federated users (was: Satisfied)' {
        foreach ($case in @(@('EveryoneInCompany','Partial'), @('InvitedUsers','Partial'), @('EveryoneInSameAndFederatedCompany','Gap'), @('EveryoneInCompanyExcludingGuests','Satisfied'))) {
            $o = Defaults; $o['Get-CsTeamsMeetingPolicy'].AutoAdmittedUsers = $case[0]
            Collect $o
            (Verdict 'Test-TPControlTeamsAutoAdmit' 'TMS-3.2').State | Should -Be $case[1] -Because $case[0]
        }
    }
    It 'TMS-1.3: blocked org-wide by DisableAnonymousJoin; allowed but lobbied is part-way; straight in is a Gap' {
        $o = Defaults; $o['Get-CsTeamsMeetingConfiguration'].DisableAnonymousJoin = $true; Collect $o
        (Verdict 'Test-TPControlTeams' 'TMS-1.3').State | Should -Be 'Satisfied'
        $o = Defaults; Collect $o
        (Verdict 'Test-TPControlTeams' 'TMS-1.3').State | Should -Be 'Partial'
        $o = Defaults; $o['Get-CsTeamsMeetingPolicy'].AutoAdmittedUsers = 'Everyone'; Collect $o
        (Verdict 'Test-TPControlTeams' 'TMS-1.3').State | Should -Be 'Gap'
    }
    It 'TMS-3.3 / TMS-3.1 / TMS-2.6 are collected and scored (were: never collected, always not assessed)' {
        $o = Defaults; Collect $o
        (Verdict 'Test-TPControlTeamsMeetingChat' 'TMS-3.3').State | Should -Be 'Gap'
        (Verdict 'Test-TPControlTeamsWatermarks' 'TMS-3.1').State | Should -Be 'Gap'
        (Verdict 'Test-TPControlTeamsBroadChannel' 'TMS-2.6').State | Should -Be 'Gap'
        $o['Get-CsTeamsMeetingPolicy'].MeetingChatEnabledType = 'EnabledExceptAnonymous'; Collect $o
        (Verdict 'Test-TPControlTeamsMeetingChat' 'TMS-3.3').State | Should -Be 'Satisfied'
    }
    It 'TMS-2.3 counts Egnyte (was: ignored)' {
        $o = Defaults; $c = $o['Get-CsTeamsClientConfiguration']; $c.AllowDropBox = $false; $c.AllowBox = $false; $c.AllowGoogleDrive = $false; $c.AllowShareFile = $false
        Collect $o
        (Verdict 'Test-TPControlTeams3PStorage' 'TMS-2.3').State | Should -Be 'Gap'
    }
    It 'TMS-4.4 reads the events policy; public town halls and webinars are the default (was: retired live events only)' {
        $o = Defaults; Collect $o
        (Verdict 'Test-TPControlTeamsLiveEvents' 'TMS-4.4').State | Should -Be 'Gap'
        $o['Get-CsTeamsEventsPolicy'].EventAccessType = 'EveryoneInCompanyExcludingGuests'; Collect $o
        (Verdict 'Test-TPControlTeamsLiveEvents' 'TMS-4.4').State | Should -Be 'Partial'
    }
    It 'TMS-1.1 / TMS-2.7 / TMS-4.3 agree: allowlist passes, blocklist is part-way, open is a Gap (TMS-2.7 was Partial on an allowlist)' {
        $o = Defaults; $o['Get-CsTenantFederationConfiguration'].AllowedDomains = @([pscustomobject]@{ AllowedDomain = 'partner.com' }); Collect $o
        foreach ($p in @(@('Test-TPControlTeams','TMS-1.1'), @('Test-TPControlTeamsExternalChat','TMS-2.7'), @('Test-TPControlTeamsFederationAllowlist','TMS-4.3'))) {
            (Verdict $p[0] $p[1]).State | Should -Be 'Satisfied' -Because $p[1]
        }
        $o = Defaults; $o['Get-CsTenantFederationConfiguration'].BlockedDomains = @([pscustomobject]@{ Domain = 'bad.com' }); Collect $o
        (Verdict 'Test-TPControlTeamsExternalChat' 'TMS-2.7').State | Should -Be 'Partial'
        $o = Defaults; Collect $o
        (Verdict 'Test-TPControlTeamsExternalChat' 'TMS-2.7').State | Should -Be 'Gap'
    }
    It 'TMS-2.1 is reported retired; TMS-3.4 is not assessed without the DLP list (was: Gap)' {
        Clear-TPState
        (Verdict 'Test-TPControlTeamsSkype' 'TMS-2.1').Detail | Should -Match 'May 5, 2025'
        Set-TPRawData -Key 'Purview' -Data @{ Success = $true; Data = @{ DLPPolicies = @(); SectionStatus = @{ DLPPolicies = 'Failed' } } }
        (Verdict 'Test-TPControlTeamsChatCopy' 'TMS-3.4').State | Should -Be 'NotApplicable'
    }
}

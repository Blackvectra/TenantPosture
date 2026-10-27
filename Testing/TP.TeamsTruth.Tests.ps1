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
        (Verdict 'Test-TPControlTeamsRecordingRetention' 'TMS-1.5').State | Should -Be 'NotApplicable' -Because 'locations were not read; Workload cannot answer'
    }
    It 'TMS-1.5 judges enabled policies by location, never Workload (was: any policy whose Workload listed OneDrive and SharePoint passed)' {
        $pol = { param($n, $en, $od, $sp, $ad) @{ Name = $n; Enabled = $en; LocationsRead = $true
            Workloads = @('Exchange', 'SharePoint', 'OneDriveForBusiness', 'Skype', 'ModernGroup')
            Locations = @{ Exchange = @(); SharePoint = @($sp); OneDriveForBusiness = @($od); TeamsChannel = @(); TeamsChat = @(); AdaptiveScopes = @($ad) } } }
        $run = { param($p) Clear-TPState
            Set-TPRawData -Key 'Purview' -Data @{ Success = $true; Data = @{ SectionStatus = @{ RetentionPolicies = 'Collected' }; RetentionPolicies = @($p) } }
            Verdict 'Test-TPControlTeamsRecordingRetention' 'TMS-1.5' }
        (& $run @((& $pol 'All' $true 'All' 'All' $null))).State                 | Should -Be 'Satisfied'
        (& $run @((& $pol 'Mail' $true $null $null $null))).State                | Should -Be 'Gap' -Because 'Workload lists every workload; no location is set'
        (& $run @((& $pol 'Off' $false 'All' 'All' $null))).State                | Should -Be 'Gap' -Because 'a disabled policy retains nothing'
        (& $run @((& $pol 'OD' $true 'All' $null $null))).State                  | Should -Be 'Partial'
        (& $run @((& $pol 'Scoped' $true $null $null 'Execs'))).State            | Should -Be 'NotApplicable' -Because 'adaptive scope membership is not read'
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
    It 'TMS-4.4 counts a public live-events attendee setting through February 28, 2027 (events scheduled before the retirement stay attendable), and not after' {
        $o = Defaults
        $o['Get-CsTeamsEventsPolicy'].EventAccessType = 'EveryoneInCompanyExcludingGuests'
        $o['Get-CsTeamsEventsPolicy'].TownhallEventAttendeeAccess = 'EveryoneInCompanyExcludingGuests'
        # The fixture carries no broadcast policy by default (the section is absent); give it one.
        $o['Get-CsTeamsMeetingBroadcastPolicy'] = [pscustomobject]@{ AllowBroadcastScheduling = $true; BroadcastAttendeeVisibilityMode = 'Everyone' }
        Collect $o
        $f = Verdict 'Test-TPControlTeamsLiveEvents' 'TMS-4.4'
        if (& $script:Mod { Test-TPLiveEventsSupported }) {
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'through February 28, 2027'
        } else {
            $f.State | Should -Be 'Satisfied' -Because 'after the support window the setting governs nothing'
        }
    }
    It 'TMS-4.4 support window: Microsoft says through February 28, 2027, with no time zone, so the whole day counts everywhere (the window ends 2027-03-01T12:00Z, the start of March 1 at UTC-12)' {
        $utc = [System.DateTimeKind]::Utc
        (& $script:Mod { param($n) Test-TPLiveEventsSupported -Now $n } ([datetime]::new(2027, 2, 27, 0, 0, 0, $utc)))  | Should -BeTrue
        (& $script:Mod { param($n) Test-TPLiveEventsSupported -Now $n } ([datetime]::new(2027, 2, 28, 0, 0, 0, $utc)))  | Should -BeTrue -Because 'a midnight cutoff dropped the whole of February 28 (review finding)'
        (& $script:Mod { param($n) Test-TPLiveEventsSupported -Now $n } ([datetime]::new(2027, 2, 28, 23, 59, 59, $utc))) | Should -BeTrue
        (& $script:Mod { param($n) Test-TPLiveEventsSupported -Now $n } ([datetime]::new(2027, 3, 1, 11, 59, 59, $utc)))  | Should -BeTrue -Because 'it is still February 28 at UTC-12'
        (& $script:Mod { param($n) Test-TPLiveEventsSupported -Now $n } ([datetime]::new(2027, 3, 1, 12, 0, 0, $utc)))    | Should -BeFalse
        (& $script:Mod { param($n) Test-TPLiveEventsSupported -Now $n } ([datetime]::new(2027, 3, 2, 0, 0, 0, $utc)))     | Should -BeFalse
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

# CIS Microsoft 365 v7.0.0 Teams recommendations no earlier control read (TMS-5.x,
# Evaluators/Test-TPControlCollabCis.ps1). Each case drives the REAL Teams collector
# (and, for TMS-5.6, the real Defender collector) with raw cmdlet shapes and pins the
# boundary between the value the CIS audit passes and the rest.
Describe 'CIS v7 Teams settings (TMS-5.1 .. TMS-5.6)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:Cmds = @('Get-CsTenantFederationConfiguration','Get-CsExternalAccessPolicy','Get-CsTeamsMeetingPolicy','Get-CsTeamsMessagingPolicy')
        # Each stand-in is a scriptblock literal created inside the module, so it reads the
        # module-scope object named after the command it was installed as.
        foreach ($n in $script:Cmds) {
            & $script:Mod { param($n) Set-Item -Path "function:script:$n" -Value { param($Identity) $script:TeamsObj[$MyInvocation.MyCommand.Name] } } $n
        }
        function script:Collect { param([hashtable] $Objects)
            Clear-TPState
            & $script:Mod { param($o) $script:TeamsObj = $o } $Objects
            Invoke-TPCollectTeams | Out-Null
        }
        function script:Verdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[-1] }
        # Microsoft defaults as Get-Cs* returns them.
        function script:Defaults {
            @{
                'Get-CsTenantFederationConfiguration' = [pscustomobject]@{ AllowFederatedUsers = $true; AllowTeamsConsumer = $true; AllowTeamsConsumerInbound = $true; AllowedDomains = [pscustomobject]@{}; BlockedDomains = @(); ExternalAccessWithTrialTenants = 'Blocked' }
                'Get-CsExternalAccessPolicy' = [pscustomobject]@{ Identity = 'Global'; EnableFederationAccess = $true; EnableTeamsConsumerAccess = $true; EnableTeamsConsumerInbound = $true }
                'Get-CsTeamsMeetingPolicy' = [pscustomobject]@{ DesignatedPresenterRoleMode = 'EveryoneUserOverride'; AllowExternalNonTrustedMeetingChat = $true; AllowCloudRecording = $true }
                'Get-CsTeamsMessagingPolicy' = [pscustomobject]@{ Identity = 'Global'; AllowSecurityEndUserReporting = $true }
            }
        }
        # The Defender collector with Get-ReportSubmissionPolicy stood in for, through
        # Get-TPExoCommand, as the DEF-4.4 cases do. Every other Defender read fails
        # (no Exchange session here) and is caught by its own section.
        function script:CollectRsp { param([object] $Policy, [switch] $NoCmdlet)
            $row = $Policy
            $cmd = { [CmdletBinding()] param() $row }.GetNewClosure()
            Mock -ModuleName 'TenantPosture' Get-TPExoCommand -MockWith { [pscustomobject]@{ Command = $null; Source = 'ExchangeOnline' } }
            if (-not $NoCmdlet) {
                Mock -ModuleName 'TenantPosture' Get-TPExoCommand -ParameterFilter { $Name -eq 'Get-ReportSubmissionPolicy' } -MockWith {
                    [pscustomobject]@{ Source = 'ExchangeOnline'; Command = $cmd }
                }.GetNewClosure()
            }
            Invoke-TPCollectDefender 3>$null | Out-Null
        }
        # A report submission policy that meets CIS 8.6.1.
        function script:GoodRsp {
            [pscustomobject]@{ Identity = 'DefaultReportSubmissionPolicy'; ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true
                ReportJunkAddresses = @('reports@contoso.com'); ReportNotJunkAddresses = @('reports@contoso.com'); ReportPhishAddresses = @('reports@contoso.com')
                ReportChatMessageEnabled = $false; ReportChatMessageToCustomizedAddressEnabled = $true; ReportChatMessageAddresses = @('reports@contoso.com') }
        }
    }
    AfterAll {
        foreach ($n in $script:Cmds) { & $script:Mod { param($n) Remove-Item -Path "function:script:$n" -ErrorAction SilentlyContinue } $n }
        Clear-TPState
    }

    It 'TMS-5.1 (8.2.3): inbound contact blocked by the organization, the parent switch or the Global policy passes; all three open is a Gap' {
        $o = Defaults; Collect $o
        (Verdict 'Test-TPControlTeamsConsumerInbound' 'TMS-5.1').State | Should -Be 'Gap'
        $o = Defaults; $o['Get-CsTenantFederationConfiguration'].AllowTeamsConsumerInbound = $false; Collect $o
        (Verdict 'Test-TPControlTeamsConsumerInbound' 'TMS-5.1').State | Should -Be 'Satisfied'
        $o = Defaults; $o['Get-CsTenantFederationConfiguration'].AllowTeamsConsumer = $false; Collect $o
        (Verdict 'Test-TPControlTeamsConsumerInbound' 'TMS-5.1').State | Should -Be 'Satisfied' -Because 'turning the parent off also stops unmanaged accounts starting a conversation'
        $o = Defaults; $o['Get-CsExternalAccessPolicy'].EnableTeamsConsumerInbound = $false; Collect $o
        (Verdict 'Test-TPControlTeamsConsumerInbound' 'TMS-5.1').State | Should -Be 'Satisfied' -Because 'the CIS audit accepts the Global external access policy'
    }
    It 'TMS-5.1: an open organization with the Global policy unread is not assessed, never a Gap' {
        $o = Defaults; $o.Remove('Get-CsExternalAccessPolicy'); Collect $o
        $f = Verdict 'Test-TPControlTeamsConsumerInbound' 'TMS-5.1'
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'EnableTeamsConsumerInbound was not collected'
        @($f.FrameworkIds).Count | Should -BeGreaterThan 0
    }
    It 'TMS-5.2 (8.2.4): Blocked passes, Allowed is a Gap, not returned (module before 6.4.0) is not assessed' {
        $o = Defaults; Collect $o
        (Verdict 'Test-TPControlTeamsTrialTenants' 'TMS-5.2').State | Should -Be 'Satisfied'
        $o['Get-CsTenantFederationConfiguration'].ExternalAccessWithTrialTenants = 'Allowed'; Collect $o
        (Verdict 'Test-TPControlTeamsTrialTenants' 'TMS-5.2').State | Should -Be 'Gap'
        $o = Defaults; $o['Get-CsTenantFederationConfiguration'] = [pscustomobject]@{ AllowFederatedUsers = $true; AllowedDomains = [pscustomobject]@{}; BlockedDomains = @() }; Collect $o
        (Get-TPRawData -Key 'Teams').Data.FederationConfig.ExternalAccessWithTrialTenants | Should -BeNullOrEmpty
        (Verdict 'Test-TPControlTeamsTrialTenants' 'TMS-5.2').State | Should -Be 'NotApplicable'
    }
    It 'TMS-5.3 (8.5.6): only OrganizerOnlyUserOverride passes; people-in-org is part-way; Everyone is a Gap; unknown is not assessed' {
        foreach ($case in @(@('OrganizerOnlyUserOverride','Satisfied'), @('EveryoneInCompanyUserOverride','Partial'), @('EveryoneUserOverride','Gap'), @('SomethingNew','NotApplicable'))) {
            $o = Defaults; $o['Get-CsTeamsMeetingPolicy'].DesignatedPresenterRoleMode = $case[0]; Collect $o
            (Verdict 'Test-TPControlTeamsPresenterRole' 'TMS-5.3').State | Should -Be $case[1] -Because $case[0]
        }
    }
    It 'TMS-5.4 (8.5.8) and TMS-5.5 (8.5.9): False passes, True is a Gap, not returned is not assessed' {
        $o = Defaults; Collect $o
        (Verdict 'Test-TPControlTeamsExternalMeetingChat' 'TMS-5.4').State | Should -Be 'Gap'
        (Verdict 'Test-TPControlTeamsCloudRecording' 'TMS-5.5').State | Should -Be 'Gap'
        $o['Get-CsTeamsMeetingPolicy'].AllowExternalNonTrustedMeetingChat = $false; $o['Get-CsTeamsMeetingPolicy'].AllowCloudRecording = $false; Collect $o
        (Verdict 'Test-TPControlTeamsExternalMeetingChat' 'TMS-5.4').State | Should -Be 'Satisfied'
        (Verdict 'Test-TPControlTeamsCloudRecording' 'TMS-5.5').State | Should -Be 'Satisfied'
        $o['Get-CsTeamsMeetingPolicy'] = [pscustomobject]@{ AutoAdmittedUsers = 'OrganizerOnly' }; Collect $o
        (Verdict 'Test-TPControlTeamsExternalMeetingChat' 'TMS-5.4').State | Should -Be 'NotApplicable'
        (Verdict 'Test-TPControlTeamsCloudRecording' 'TMS-5.5').State | Should -Be 'NotApplicable'
    }
    It 'TMS-5.6 (8.6.1): the Teams switch and every report submission component pass together' {
        $o = Defaults; Collect $o
        CollectRsp -Policy (GoodRsp)
        $rsp = (Get-TPRawData -Key 'Defender-Policies').Data['ReportSubmissionPolicy']
        $rsp.Available | Should -BeTrue
        @($rsp.ReportPhishAddresses) | Should -Be @('reports@contoso.com')
        (Verdict 'Test-TPControlTeamsSecurityReporting' 'TMS-5.6').State | Should -Be 'Satisfied'
    }
    It 'TMS-5.6: reports sent to Microsoft, an empty reporting address list or the Teams switch off are shortfalls' {
        $o = Defaults; Collect $o
        $p = GoodRsp; $p.ReportChatMessageEnabled = $true; CollectRsp -Policy $p
        $f = Verdict 'Test-TPControlTeamsSecurityReporting' 'TMS-5.6'
        $f.State  | Should -Be 'Partial'
        $f.Detail | Should -Match 'ReportChatMessageEnabled = True'
        $p = GoodRsp; $p.ReportPhishAddresses = @(); CollectRsp -Policy $p
        $f = Verdict 'Test-TPControlTeamsSecurityReporting' 'TMS-5.6'
        $f.State  | Should -Be 'Partial'
        $f.Detail | Should -Match 'ReportPhishAddresses is empty'
        $o['Get-CsTeamsMessagingPolicy'].AllowSecurityEndUserReporting = $false; Collect $o
        CollectRsp -Policy (GoodRsp)
        (Verdict 'Test-TPControlTeamsSecurityReporting' 'TMS-5.6').State | Should -Be 'Partial'
    }
    It 'TMS-5.6: a cmdlet missing from the session, an unreturned switch or a results file without the read is not assessed' {
        $o = Defaults; Collect $o
        CollectRsp -NoCmdlet
        (Get-TPRawData -Key 'Defender-Policies').Data['ReportSubmissionPolicy'].Available | Should -BeFalse
        @(Get-TPExceptions | Where-Object { $_.Source -eq 'Defender-ReportSubmissionPolicy' }).Count | Should -Be 1
        $f = Verdict 'Test-TPControlTeamsSecurityReporting' 'TMS-5.6'
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'not available in the Exchange Online session'
        $p = GoodRsp; $p.PSObject.Properties.Remove('ReportJunkAddresses'); $p.PSObject.Properties.Remove('ReportChatMessageEnabled'); CollectRsp -Policy $p
        $f = Verdict 'Test-TPControlTeamsSecurityReporting' 'TMS-5.6'
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'ReportJunkAddresses was not returned'
        $f.Detail | Should -Match 'ReportChatMessageEnabled was not returned'
        Collect $o
        Set-TPRawData -Key 'Defender-Policies' -Data @{ Success = $true; Data = @{ SafeAttachments = @{ Available = $true } } }
        (Verdict 'Test-TPControlTeamsSecurityReporting' 'TMS-5.6').Detail | Should -Match 'predates'
    }
    It 'TMS-5.6: a report submission policy replayed from JSON keeps an empty address list as empty, never unread' {
        $o = Defaults; Collect $o
        $p = GoodRsp; $p.ReportJunkAddresses = @(); CollectRsp -Policy $p
        $def = (Get-TPRawData -Key 'Defender-Policies') | ConvertTo-Json -Depth 8 | ConvertFrom-Json
        Set-TPRawData -Key 'Defender-Policies' -Data $def
        $f = Verdict 'Test-TPControlTeamsSecurityReporting' 'TMS-5.6'
        $f.State  | Should -Be 'Partial'
        $f.Detail | Should -Match 'ReportJunkAddresses is empty'
    }
    It 'no Teams data at all: every TMS-5.x control is not assessed with its citations' {
        Clear-TPState
        foreach ($p in @(@('Test-TPControlTeamsConsumerInbound','TMS-5.1'), @('Test-TPControlTeamsTrialTenants','TMS-5.2'), @('Test-TPControlTeamsPresenterRole','TMS-5.3'),
                         @('Test-TPControlTeamsExternalMeetingChat','TMS-5.4'), @('Test-TPControlTeamsCloudRecording','TMS-5.5'), @('Test-TPControlTeamsSecurityReporting','TMS-5.6'))) {
            $f = Verdict $p[0] $p[1]
            $f.State | Should -Be 'NotApplicable' -Because $p[1]
            $f.Detail | Should -Match 'not assessed|Not assessed'
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0 -Because $p[1]
        }
    }
}

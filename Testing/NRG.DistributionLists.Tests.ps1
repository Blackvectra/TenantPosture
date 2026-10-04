#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.DistributionLists.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: The distribution-list scan (-DistributionListsOnly), end to end and
             read-only. The collector runs against a STUBBED Exchange boundary fed raw
             cmdlet shapes (omitted properties, string booleans, personal data on member
             objects, throttling, a failed section, a very large list), never derived
             fields: a fixture carrying a pre-computed flag would not exercise the parser.
             Pinned: each evaluator state, the worksheet and its two files, that the
             verdict and limitation read the same in both, that the files go through the
             restricted writer, that the commands in them are TEXT and are never run
             (write-cmdlet spies, plus a static allowlist over every file the scan loads),
             and that nothing but Exchange Online is connected.
    Data keys: EXO-DistributionLists (set by the collector under test).
    Graph scopes / cmdlets: none; every Exchange cmdlet is a stub.
#>

Describe 'Distribution-list scan' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        # Stand-ins for Exchange cmdlets the module does not define, placed in MODULE scope so the
        # collector (which resolves them through Get-NRGExoCommand) finds them, as NRG.ExchangeTruth does.
        function script:Inject { param([string] $Name, [string] $Body)
            & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } $Name $Body }
        # Unqualified 'function:' inside the module scope: 'function:script:X' silently removes nothing.
        function script:Remove { param([string] $Name)
            & $script:Mod { param($n) Remove-Item -Path "function:$n" -ErrorAction SilentlyContinue } $Name }

        $script:ReadStubs = [ordered]@{
            'Get-AcceptedDomain' = @'
$script:DlLog.Add('Get-AcceptedDomain')
if ($script:DlScn.Throw.ContainsKey('Get-AcceptedDomain')) { throw $script:DlScn.Throw['Get-AcceptedDomain'] }
foreach ($d in $script:DlScn.Accepted) { [pscustomobject]@{ DomainName = $d } }
'@
            'Get-DistributionGroup' = @'
$script:DlLog.Add('Get-DistributionGroup')
if ($script:DlScn.Throw.ContainsKey('Get-DistributionGroup')) { throw $script:DlScn.Throw['Get-DistributionGroup'] }
foreach ($x in $script:DlScn.Lists) { $x }
'@
            'Get-DynamicDistributionGroup' = @'
$script:DlLog.Add('Get-DynamicDistributionGroup')
if ($script:DlScn.Throw.ContainsKey('Get-DynamicDistributionGroup')) { throw $script:DlScn.Throw['Get-DynamicDistributionGroup'] }
foreach ($x in $script:DlScn.Dynamic) { $x }
'@
            'Get-DistributionGroupMember' = @'
param($Identity, $ResultSize)
$script:DlLog.Add('Get-DistributionGroupMember')
$script:DlScn.ResultSizes[$Identity] = $ResultSize
$script:DlScn.Calls[$Identity] = 1 + [int]$script:DlScn.Calls[$Identity]
if ($script:DlScn.MemberThrow.ContainsKey($Identity)) { throw $script:DlScn.MemberThrow[$Identity] }
if ($script:DlScn.MemberThrottle.ContainsKey($Identity) -and $script:DlScn.Calls[$Identity] -le $script:DlScn.MemberThrottle[$Identity]) { throw 'The server is busy: too many requests (429)' }
foreach ($m in $script:DlScn.Members[$Identity]) { $m }
'@
            'Get-DynamicDistributionGroupMember' = @'
param($Identity, $ResultSize)
$script:DlLog.Add('Get-DynamicDistributionGroupMember')
$script:DlScn.ResultSizes[$Identity] = $ResultSize
foreach ($m in $script:DlScn.Members[$Identity]) { $m }
'@
            'Get-Recipient' = @'
param($RecipientPreviewFilter, $ResultSize)
$script:DlLog.Add('Get-Recipient')
$script:DlScn.PreviewFilter = $RecipientPreviewFilter
foreach ($m in $script:DlScn.Preview) { $m }
'@
            'Get-TransportRule' = @'
$script:DlLog.Add('Get-TransportRule')
if ($script:DlScn.Throw.ContainsKey('Get-TransportRule')) { throw $script:DlScn.Throw['Get-TransportRule'] }
foreach ($x in $script:DlScn.Rules) { $x }
'@
            'Get-HostedConnectionFilterPolicy' = @'
$script:DlLog.Add('Get-HostedConnectionFilterPolicy')
if ($script:DlScn.Throw.ContainsKey('Get-HostedConnectionFilterPolicy')) { throw $script:DlScn.Throw['Get-HostedConnectionFilterPolicy'] }
foreach ($x in $script:DlScn.ConnFilter) { $x }
'@
            'Get-HostedContentFilterPolicy' = @'
$script:DlLog.Add('Get-HostedContentFilterPolicy')
if ($script:DlScn.Throw.ContainsKey('Get-HostedContentFilterPolicy')) { throw $script:DlScn.Throw['Get-HostedContentFilterPolicy'] }
foreach ($x in $script:DlScn.AntiSpam) { $x }
'@
            'Get-HostedContentFilterRule' = @'
$script:DlLog.Add('Get-HostedContentFilterRule')
if ($script:DlScn.Throw.ContainsKey('Get-HostedContentFilterRule')) { throw $script:DlScn.Throw['Get-HostedContentFilterRule'] }
foreach ($x in $script:DlScn.AntiSpamRules) { $x }
'@
        }
        # Every command the worksheet PRINTS is a write. If any of these is ever called, the log says so.
        $script:WriteSpies = @('Set-DistributionGroup', 'Set-DynamicDistributionGroup', 'Remove-DistributionGroupMember', 'Add-DistributionGroupMember',
            'New-DistributionGroup', 'Disable-TransportRule', 'Set-TransportRule', 'New-TransportRule', 'Remove-TransportRule',
            'Set-HostedConnectionFilterPolicy', 'Set-HostedContentFilterPolicy', 'Set-Mailbox', 'Update-DistributionGroupMember')
        # Anything but Exchange Online is a connection this scan must never make.
        $script:ConnectSpies = @('Connect-MgGraph', 'Connect-IPPSSession', 'Connect-MicrosoftTeams', 'Connect-SPOService')

        function script:Use-Scenario { param([hashtable] $S = @{})
            $d = @{ Lists = @(); Dynamic = @(); Members = @{}; MemberThrottle = @{}; MemberThrow = @{}; Rules = @(); ConnFilter = @(); AntiSpam = @(); AntiSpamRules = @()
                    Accepted = @('contoso.com', 'contoso.onmicrosoft.com'); Throw = @{}; ResultSizes = @{}; Calls = @{}; Preview = @(); PreviewFilter = '' }
            foreach ($k in $S.Keys) { $d[$k] = $S[$k] }
            & $script:Mod { param($s) $script:DlScn = $s; $script:DlLog = [System.Collections.Generic.List[string]]::new() } $d
            foreach ($n in $script:ReadStubs.Keys) { Inject $n $script:ReadStubs[$n] }
            foreach ($n in $script:WriteSpies) { Inject $n ('$script:DlLog.Add("WRITE:' + $n + '")') }
        }
        function script:Remove-Stubs {
            foreach ($n in @($script:ReadStubs.Keys) + $script:WriteSpies) { Remove $n }
        }
        function script:Get-CallLog { @(& $script:Mod { $script:DlLog.ToArray() }) }
        function script:Invoke-Scan { param([hashtable] $S = @{}, [hashtable] $Collect = @{})
            Clear-NRGState
            Use-Scenario $S
            $Collect['ThrottleBaseDelaySeconds'] = 0
            $r = Invoke-NRGCollectDistributionLists @Collect
            Test-NRGDistributionLists
            $r
        }
        function script:F { param([string] $Id, [string] $Instance = '*')
            @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Id -and $_.Instance -like $Instance }) }

        # Raw Get-DistributionGroup shape. -Omit drops a property the way Exchange omits one it does not return.
        function script:New-DlRaw { param([string] $Name, [string] $Address, [string[]] $Omit = @(), [hashtable] $With = @{}, [string] $Type = 'MailUniversalDistributionGroup')
            $o = [ordered]@{
                Name = $Name; DisplayName = $Name; PrimarySmtpAddress = $Address; RecipientTypeDetails = $Type
                ManagedBy = @('Owner One'); RequireSenderAuthenticationEnabled = $true
                AcceptMessagesOnlyFromSendersOrMembers = @(); AcceptMessagesOnlyFrom = @(); AcceptMessagesOnlyFromDLMembers = @()
                ModerationEnabled = $false; ModeratedBy = @(); MemberJoinRestriction = 'Closed'; MemberDepartRestriction = 'Closed'; HiddenFromAddressListsEnabled = $false
            }
            foreach ($k in $With.Keys) { $o[$k] = $With[$k] }
            foreach ($k in $Omit) { $o.Remove($k) }
            [pscustomobject]$o }
        function script:New-DlDynamic { param([string] $Name, [string] $Address, [hashtable] $With = @{})
            New-DlRaw -Name $Name -Address $Address -Type 'DynamicDistributionGroup' -With (@{ RecipientFilter = "(RecipientType -eq 'UserMailbox')" } + $With) -Omit @('MemberJoinRestriction', 'MemberDepartRestriction') }
        # Raw Get-DistributionGroupMember shape, with personal data the worksheet must never carry.
        function script:New-DlMember { param([string] $Display, [string] $Address, [string] $Type = 'UserMailbox', [hashtable] $With = @{}, [string[]] $Omit = @())
            $o = [ordered]@{ DisplayName = $Display; PrimarySmtpAddress = $Address; RecipientType = $Type; RecipientTypeDetails = $Type }
            if ($Type -in 'UserMailbox', 'SharedMailbox') { $o.UserPrincipalName = $Address }
            $o.Phone = '555-0100'; $o.Title = 'Chief Executive'; $o.Department = 'Executive'; $o.Manager = 'Some Manager'
            foreach ($k in $With.Keys) { $o[$k] = $With[$k] }
            foreach ($k in $Omit) { $o.Remove($k) }
            [pscustomobject]$o }
        function script:New-Rule { param([string] $Name, $Scl = -1, [hashtable] $With = @{}, [string[]] $Predicates = @(), [string[]] $Omit = @())
            $o = [ordered]@{ Name = $Name; State = 'Enabled'; Mode = 'Enforce'; Priority = 1; SetSCL = $Scl
                             Conditions = @($Predicates | ForEach-Object { "Microsoft.Exchange.MessagingPolicies.Rules.Tasks.${_}Predicate" }) }
            foreach ($k in $With.Keys) { $o[$k] = $With[$k] }
            foreach ($k in $Omit) { $o.Remove($k) }
            [pscustomobject]$o }
        $script:Approved = {
            [ordered]@{ DmarcReportingAddresses = @(); CommonAttachmentFileTypes = @(); PriorityUsers = @(); RequiredConditionalAccessTemplates = @()
                        DistributionListMaxMembers = @('2'); DistributionListMemberJoinRestriction = @('Closed', 'ApprovalRequired') } }
    }
    AfterEach { Remove-Stubs; Clear-NRGState }
    AfterAll  { Remove-Stubs; Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'collector: reads only, through the Exchange Online session' {

        It 'reads lists, members and bypass inputs with Get-* cmdlets only, and runs no write cmdlet' {
            $r = Invoke-Scan @{
                Lists = @(New-DlRaw 'Sales' 'sales@contoso.com'); Dynamic = @(New-DlDynamic 'Everyone' 'everyone@contoso.com')
                Members = @{ 'sales@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com'); 'everyone@contoso.com' = @(New-DlMember 'Dee' 'dee@contoso.com') }
                Rules = @(New-Rule 'Skip filter' -Predicates 'SenderDomainIs' -With @{ SenderDomainIs = @('partner.example') })
                ConnFilter = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = @(); IPBlockList = @() })
                AntiSpam = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @() }) }
            $r.Success | Should -BeTrue
            foreach ($k in 'Lists', 'DynamicLists', 'Members', 'AcceptedDomains', 'TransportRules', 'ConnectionFilter', 'AntiSpam') { $r.Data.SectionStatus[$k] | Should -Be 'Collected' -Because $k }
            $log = Get-CallLog
            $log.Count | Should -BeGreaterThan 5
            @($log | Where-Object { $_ -notmatch '^Get-' }) | Should -BeNullOrEmpty -Because 'every Exchange call is a read; a WRITE: entry means a stub write cmdlet ran'
            (Get-NRGRawData -Key 'EXO-DistributionLists').CollectorId | Should -Be 'EXO-DistributionLists'
        }

        It 'a member row carries only a display name, a UPN, the primary address, a type and a class: no phone, title, department or manager' {
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Sales' 'sales@contoso.com'); Members = @{ 'sales@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com') } }
            $m = $r.Data.Lists[0].Members[0]
            @($m.Keys | Sort-Object) | Should -Be @('Address', 'Class', 'DisplayName', 'RecipientType', 'UPN')
            $json = $r | ConvertTo-Json -Depth 12
            foreach ($pii in '555-0100', 'Chief Executive', 'Executive', 'Some Manager') { $json | Should -Not -Match ([regex]::Escape($pii)) -Because "$pii is on the raw member and must not be copied" }
        }

        It 'a member''s Address is its primary SMTP address, which is not always its UPN; a contact with no UPN keeps its address in both' {
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Sales' 'sales@contoso.com'); Members = @{ 'sales@contoso.com' = @(
                New-DlMember 'Ann' 'ann@contoso.com' -With @{ UserPrincipalName = 'ann.upn@contoso.onmicrosoft.com' }
                New-DlMember 'Vendor' 'v@vendor.example' 'MailContact') } }
            $m = @($r.Data.Lists[0].Members)
            $m[0].Address | Should -Be 'ann@contoso.com'; $m[0].UPN | Should -Be 'ann.upn@contoso.onmicrosoft.com'
            $m[1].Address | Should -Be 'v@vendor.example'; $m[1].UPN | Should -Be 'v@vendor.example'
        }

        It 'classifies members External / Internal / Unresolved from the raw shapes, never a blank as Internal' {
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Mixed' 'mixed@contoso.com'); Members = @{ 'mixed@contoso.com' = @(
                New-DlMember 'Insider' 'in@contoso.com'
                New-DlMember 'Vendor' 'v@vendor.example' 'MailContact' -With @{ ExternalEmailAddress = 'SMTP:v@vendor.example' }
                New-DlMember 'Forwarder' 'fw@contoso.com' 'MailUser' -With @{ ExternalEmailAddress = 'SMTP:fw@partner.example' }
                New-DlMember 'Guest' 'g_partner.example#EXT#@contoso.onmicrosoft.com' 'GuestMailUser'
                New-DlMember 'Subteam' 'sub@contoso.com' 'MailUniversalDistributionGroup'
                New-DlMember 'No address' '' 'MailContact' -Omit @('PrimarySmtpAddress')) } }
            $c = @{}; foreach ($m in $r.Data.Lists[0].Members) { $c[$m.DisplayName] = $m.Class }
            $c['Insider'] | Should -Be 'Internal'
            $c['Vendor'] | Should -Be 'External'
            $c['Forwarder'] | Should -Be 'External' -Because 'a mail user delivers to its external address even when its primary address is in-tenant'
            $c['Guest'] | Should -Be 'External'
            $c['Subteam'] | Should -Be 'Internal'
            $c['No address'] | Should -Be 'Unresolved' -Because 'Get-NRGRecipientClass reads a blank as Internal; a blank here means the address was not returned'
            $r.Data.Lists[0].ExternalMemberCount | Should -Be 3
            $r.Data.Lists[0].UnresolvedMemberCount | Should -Be 1
            $r.Data.Lists[0].NestedGroupCount | Should -Be 1
            @($r.Data.Lists[0].NestedGroups) | Should -Be @('Subteam')
        }

        It 'when accepted domains cannot be read, no user or contact is called Internal or External' {
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Sales' 'sales@contoso.com'); Throw = @{ 'Get-AcceptedDomain' = 'Access denied' }
                Members = @{ 'sales@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com'; New-DlMember 'Vendor' 'v@vendor.example' 'MailContact') } }
            $r.Data.SectionStatus.AcceptedDomains | Should -Be 'Failed'
            @($r.Data.Lists[0].Members | ForEach-Object { $_.Class }) | Should -Be @('Unresolved', 'Unresolved')
            $r.Data.Lists[0].ExternalMemberCount | Should -Be 0
        }

        It 'a property Exchange omitted stays not-read; it is never defaulted to the safe value' {
            $omit = 'RequireSenderAuthenticationEnabled', 'ManagedBy', 'ModerationEnabled', 'ModeratedBy', 'AcceptMessagesOnlyFromSendersOrMembers', 'AcceptMessagesOnlyFrom', 'AcceptMessagesOnlyFromDLMembers', 'MemberJoinRestriction', 'HiddenFromAddressListsEnabled'
            $l = (Invoke-Scan @{ Lists = @(New-DlRaw 'Bare' 'bare@contoso.com' -Omit $omit) }).Data.Lists[0]
            $l.RequireSenderAuthenticationEnabled | Should -BeNullOrEmpty
            $l.RequireSenderAuthenticationEnabled | Should -Be $null
            $l.OwnersKnown | Should -BeFalse
            $l.AllowedSendersKnown | Should -BeFalse
            $l.ModeratedByKnown | Should -BeFalse
            $l.ModerationEnabled | Should -Be $null
            $l.MemberJoinRestriction | Should -Be $null
            $l.HiddenFromAddressListsEnabled | Should -Be $null
        }

        It 'reads a string boolean as what it says: "False" is False (not [bool]"False"), anything unclear is not read' {
            $r = Invoke-Scan @{ Lists = @(
                New-DlRaw 'A' 'a@contoso.com' -With @{ RequireSenderAuthenticationEnabled = 'False' }
                New-DlRaw 'B' 'b@contoso.com' -With @{ RequireSenderAuthenticationEnabled = 'True' }
                New-DlRaw 'C' 'c@contoso.com' -With @{ RequireSenderAuthenticationEnabled = 'maybe' }) }
            $by = @{}; foreach ($l in $r.Data.Lists) { $by[$l.Name] = $l.RequireSenderAuthenticationEnabled }
            $by['A'] | Should -Be $false
            $by['B'] | Should -Be $true
            $by['C'] | Should -Be $null
        }

        It 'a failed list read is a Failed section and a not-assessed finding, never "no lists" and never clean' {
            $r = Invoke-Scan @{ Throw = @{ 'Get-DistributionGroup' = 'The operation timed out' }; Dynamic = @(New-DlDynamic 'Everyone' 'everyone@contoso.com')
                Members = @{ 'everyone@contoso.com' = @(New-DlMember 'Dee' 'dee@contoso.com') } }
            $r.Data.SectionStatus.Lists | Should -Be 'Failed'
            $r.Data.SectionStatus.DynamicLists | Should -Be 'Collected'
            (Get-NRGCoverage)['EXO-DistributionLists'].Status | Should -Be 'Partial'
            @(Get-NRGExceptions | Where-Object { $_.Source -eq 'EXO-DistributionLists-Lists' }).Count | Should -Be 1
            $gap = @(F 'DL-1.1' '')
            $gap.State | Should -Be 'NotApplicable'
            $gap.Detail | Should -Match 'Get-DistributionGroup failed'
            @(F 'DL-1.1' | Where-Object { $_.State -eq 'Satisfied' }).Count | Should -Be 1 -Because 'only the dynamic list that was read; the unread lists are not counted as clean'
        }

        It 'when both list reads fail the coverage is Failed' {
            Invoke-Scan @{ Throw = @{ 'Get-DistributionGroup' = 'x'; 'Get-DynamicDistributionGroup' = 'y' } } | Out-Null
            (Get-NRGCoverage)['EXO-DistributionLists'].Status | Should -Be 'Failed'
        }

        It 'retries a throttled member read and recovers' {
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Busy' 'busy@contoso.com'); MemberThrottle = @{ 'busy@contoso.com' = 2 }
                Members = @{ 'busy@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com') } }
            $r.Data.Lists[0].MemberStatus | Should -Be 'Collected'
            $r.Data.Lists[0].MemberCount | Should -Be 1
            $r.Data.Stats.ThrottleRetries | Should -Be 2
            $r.Data.SectionStatus.Members | Should -Be 'Collected'
        }

        It 'a read that stays throttled is a Failed member read with the reason, never an empty list' {
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Busy' 'busy@contoso.com'; New-DlRaw 'Fine' 'fine@contoso.com'); MemberThrottle = @{ 'busy@contoso.com' = 99 }
                Members = @{ 'fine@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com') } } @{ ThrottleRetries = 2 }
            $busy = $r.Data.Lists | Where-Object { $_.Name -eq 'Busy' }
            $busy.MemberStatus | Should -Be 'Failed'
            $busy.MemberError | Should -Match 'busy'
            $busy.MemberCount | Should -Be $null
            @($busy.Members).Count | Should -Be 0
            ($r.Data.Lists | Where-Object { $_.Name -eq 'Fine' }).MemberStatus | Should -Be 'Collected'
            $r.Data.SectionStatus.Members | Should -Be 'Failed'
            (Get-NRGCoverage)['EXO-DistributionLists'].Status | Should -Be 'Partial'
            (& $script:Mod { $script:DlScn.Calls['busy@contoso.com'] }) | Should -Be 3 -Because 'one try plus two retries'
        }

        It 'does not retry an error that is not throttling' {
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Gone' 'gone@contoso.com'); MemberThrow = @{ 'gone@contoso.com' = "The operation couldn't be performed because object 'gone' couldn't be found." } }
            ($r.Data.Lists[0]).MemberStatus | Should -Be 'Failed'
            (& $script:Mod { $script:DlScn.Calls['gone@contoso.com'] }) | Should -Be 1
            $r.Data.Stats.ThrottleRetries | Should -Be 0
        }

        It 'bounds a very large list at the stated cap, asks for one more to detect it, and says "more than"' {
            $many = @(1..900 | ForEach-Object { New-DlMember "U$_" "u$_@contoso.com" })
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Huge' 'huge@contoso.com'); Members = @{ 'huge@contoso.com' = $many } }
            $l = $r.Data.Lists[0]
            $l.MemberCount | Should -Be 500
            $l.MembersTruncated | Should -BeTrue
            $l.Contains('MemberCountIsLowerBound') | Should -BeFalse -Because 'it always equalled MembersTruncated; one flag says it'
            @($l.Members).Count | Should -Be 500
            (& $script:Mod { $script:DlScn.ResultSizes['huge@contoso.com'] }) | Should -Be 501
            $r.Data.Stats.ListsMembersTruncated | Should -Be 1
            $r.Data.Limits.MaxMembersPerList | Should -Be 500
        }

        It 'honors a smaller -MaxMembersPerList, and an exactly-full list is not called truncated' {
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Small' 'small@contoso.com'; New-DlRaw 'Exact' 'exact@contoso.com'); Members = @{
                'small@contoso.com' = @(1..20 | ForEach-Object { New-DlMember "U$_" "u$_@contoso.com" })
                'exact@contoso.com' = @(1..5 | ForEach-Object { New-DlMember "E$_" "e$_@contoso.com" }) } } @{ MaxMembersPerList = 5 }
            ($r.Data.Lists | Where-Object { $_.Name -eq 'Small' }).MembersTruncated | Should -BeTrue
            ($r.Data.Lists | Where-Object { $_.Name -eq 'Exact' }).MembersTruncated | Should -BeFalse
        }

        It 'a tenant above -MaxLists is reported as truncated, never complete' {
            $r = Invoke-Scan @{ Lists = @(1..5 | ForEach-Object { New-DlRaw "L$_" "l$_@contoso.com" }) } @{ MaxLists = 3 }
            @($r.Data.Lists).Count | Should -Be 3
            $r.Data.Limits.ListsTruncated | Should -BeTrue
            $r.Data.Limits.ListsSeen | Should -Be 5
            (F 'DL-1.1' '').Detail | Should -Match 'beyond the first 3 of 5'
        }

        It 'reads a dynamic list''s calculated membership, and falls back to a labeled filter preview when the member cmdlet is absent' {
            $d = New-DlDynamic 'Everyone' 'everyone@contoso.com'
            $r = Invoke-Scan @{ Dynamic = @($d); Members = @{ 'everyone@contoso.com' = @(New-DlMember 'Dee' 'dee@contoso.com') } }
            $r.Data.Lists[0].MembershipBasis | Should -Be 'DynamicCalculated' -Because 'Get-DynamicDistributionGroupMember returns the calculated list Microsoft stores on the group'
            $r.Data.Lists[0].MemberCount | Should -Be 1
            Get-CallLog | Should -Contain 'Get-DynamicDistributionGroupMember'
            Get-CallLog | Should -Not -Contain 'Get-Recipient'
            Remove 'Get-DynamicDistributionGroupMember'
            Clear-NRGState
            & $script:Mod { $script:DlLog.Clear(); $script:DlScn.Preview = @([pscustomobject]@{ DisplayName = 'Eve'; PrimarySmtpAddress = 'eve@contoso.com'; RecipientTypeDetails = 'UserMailbox'; UserPrincipalName = 'eve@contoso.com' }) }
            $r2 = Invoke-NRGCollectDistributionLists -ThrottleBaseDelaySeconds 0
            Get-CallLog | Should -Contain 'Get-Recipient'
            (& $script:Mod { $script:DlScn.PreviewFilter }) | Should -Match 'UserMailbox'
            $r2.Data.Lists[0].Members[0].DisplayName | Should -Be 'Eve'
            $r2.Data.Lists[0].MembershipBasis | Should -Be 'DynamicPreview' -Because 'the filter preview is not the stored membership, and says so'
        }

        It 'reuses the connection filter, anti-spam policies and accepted domains a full assessment already collected' {
            Use-Scenario @{}
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data @{ CollectorId = 'x'; Success = $true; Data = @{
                SectionStatus = @{ AcceptedDomains = 'Collected'; AntiSpamPolicies = 'Collected' }
                AcceptedDomains = @(@{ DomainName = 'reused.example' })
                AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @('x.example') })
                AntiSpamRules = @() } }
            Set-NRGRawData -Key 'EXO-ConnectionFilter' -Data @{ CollectorId = 'x'; Success = $true; Data = @{ ConnectionFilter = @(@{ Name = 'Default'; IsDefault = $true; IPAllowList = @('198.51.100.7') }) } }
            $r = Invoke-NRGCollectDistributionLists -ThrottleBaseDelaySeconds 0
            $log = Get-CallLog
            foreach ($n in 'Get-AcceptedDomain', 'Get-HostedConnectionFilterPolicy', 'Get-HostedContentFilterPolicy', 'Get-HostedContentFilterRule') { $log | Should -Not -Contain $n -Because "$n was already collected" }
            $log | Should -Contain 'Get-TransportRule'   # EXO-Inventory keeps SetSCL but not the conditions, so it is read here
            $r.Data.BypassInputs.Source.AcceptedDomains | Should -Match 'Reused'
            $r.Data.BypassInputs.Source.ConnectionFilter | Should -Match 'Reused'
            $r.Data.BypassInputs.Source.AntiSpam | Should -Match 'Reused'
            @($r.Data.AcceptedDomains) | Should -Be @('reused.example')
            @($r.Data.BypassInputs.ConnectionFilter[0].IPAllowList) | Should -Be @('198.51.100.7')
            $r.Data.BypassInputs.AntiSpamRulesRead | Should -BeTrue -Because 'an empty collected rule list is "read, none exist", not "not read"'
        }

        It 'reads those itself when it is the only thing that ran' {
            $r = Invoke-Scan @{ ConnFilter = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = @('203.0.113.9') })
                AntiSpam = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @('a@x.example'); AllowedSenderDomains = @()}) }
            $r.Data.BypassInputs.Source.ConnectionFilter | Should -Be 'Read'
            $r.Data.BypassInputs.Source.AntiSpam | Should -Be 'Read'
            Get-CallLog | Should -Contain 'Get-HostedConnectionFilterPolicy'
        }

        It 'keeps only SCL-setting transport rules, with their conditions; a rule whose conditions were not returned says so' {
            $r = Invoke-Scan @{ Rules = @(
                New-Rule 'Bypass' -Predicates 'SenderDomainIs', 'HeaderContains' -With @{ SenderDomainIs = @('partner.example'); HeaderContainsMessageHeader = 'Authentication-Results'; HeaderContainsWords = @('dmarc=pass') }
                New-Rule 'Mark spam' -Scl 9 -Predicates 'SubjectContainsWords'
                [pscustomobject]@{ Name = 'Footer'; State = 'Enabled'; Priority = 3 }
                New-Rule 'No conditions field' -Omit @('Conditions')) }
            $r.Data.Stats.TransportRulesTotal | Should -Be 4
            @($r.Data.BypassInputs.TransportRules).Count | Should -Be 3 -Because 'only rules that set an SCL'
            $b = $r.Data.BypassInputs.TransportRules | Where-Object { $_.Name -eq 'Bypass' }
            @($b.Predicates) | Should -Be @('SenderDomainIs', 'HeaderContains')
            $b.SetSCL | Should -Be -1
            $b.ConditionsKnown | Should -BeTrue
            ($r.Data.BypassInputs.TransportRules | Where-Object { $_.Name -eq 'No conditions field' }).ConditionsKnown | Should -BeFalse
        }

        It 'stores the anti-spam policies and rules as facts (the evaluator decides which apply), and says when the rules were not read' {
            $pol = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @() }
                     [pscustomobject]@{ Name = 'Applied'; IsDefault = $false; AllowedSenders = @('a@x.example'); AllowedSenderDomains = @() })
            $rule = [pscustomobject]@{ Name = 'r1'; HostedContentFilterPolicy = 'Applied'; State = 'Enabled'; RecipientDomainIs = @('contoso.com'); ExceptIfSentTo = @('boss@contoso.com') }
            $r = Invoke-Scan @{ AntiSpam = $pol; AntiSpamRules = @($rule, [pscustomobject]@{ Name = 'r2'; HostedContentFilterPolicy = 'Applied'; State = 'Disabled' }) }
            $r.Data.BypassInputs.AntiSpamRulesRead | Should -BeTrue
            @($r.Data.BypassInputs.AntiSpamPolicies | ForEach-Object { $_.Contains('InForce') }) | Should -Not -Contain $true -Because 'which policies apply is judged in the evaluator, through Get-NRGInForcePolicies'
            $r1 = @($r.Data.BypassInputs.AntiSpamRules | Where-Object { $_.Name -eq 'r1' })[0]
            $r1.HostedContentFilterPolicy | Should -Be 'Applied'; $r1.State | Should -Be 'Enabled'
            @($r1.RecipientDomainIs) | Should -Be @('contoso.com')
            $r1.HasExceptions | Should -BeTrue -Because 'ExceptIfSentTo is an exception'
            (@($r.Data.BypassInputs.AntiSpamRules | Where-Object { $_.Name -eq 'r2' })[0]).HasExceptions | Should -BeFalse
            $r2 = Invoke-Scan @{ AntiSpam = $pol; Throw = @{ 'Get-HostedContentFilterRule' = 'denied' } }
            $r2.Data.BypassInputs.AntiSpamRulesRead | Should -BeFalse
            @($r2.Data.BypassInputs.AntiSpamRules).Count | Should -Be 0
            $r2.Data.SectionStatus.AntiSpam | Should -Be 'Collected'
        }

        It 'counts an allowed sender once however many of the three overlapping properties name it' {
            # Microsoft: what is set in AcceptMessagesOnlyFrom or AcceptMessagesOnlyFromDLMembers is copied into AcceptMessagesOnlyFromSendersOrMembers.
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Named' 'named@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false
                AcceptMessagesOnlyFromSendersOrMembers = @('Pat', 'Lee', 'Team'); AcceptMessagesOnlyFrom = @('pat', 'Lee'); AcceptMessagesOnlyFromDLMembers = @('Team') }) }
            @($r.Data.Lists[0].AllowedSenders).Count | Should -Be 3
            (F 'DL-1.1' 'named@*').Detail | Should -Match 'limited to 3 specified sender\(s\)'
        }

        It 'IsDirSynced is read as True, False, or not returned (never defaulted)' {
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'S' 's@contoso.com' -With @{ IsDirSynced = $true }; New-DlRaw 'C' 'c@contoso.com' -With @{ IsDirSynced = 'False' }; New-DlRaw 'U' 'u@contoso.com') }
            $by = @{}; foreach ($l in $r.Data.Lists) { $by[$l.Name] = $l.IsDirSynced }
            $by['S'] | Should -BeTrue; $by['C'] | Should -BeFalse; $by['U'] | Should -Be $null
        }

        It 'a failed bypass read fails only its own section' {
            $r = Invoke-Scan @{ Lists = @(New-DlRaw 'Sales' 'sales@contoso.com'); Throw = @{ 'Get-TransportRule' = 'Access denied'; 'Get-HostedConnectionFilterPolicy' = 'Access denied' } }
            $r.Data.SectionStatus.TransportRules | Should -Be 'Failed'
            $r.Data.SectionStatus.ConnectionFilter | Should -Be 'Failed'
            $r.Data.SectionStatus.Lists | Should -Be 'Collected'
            $r.Data.SectionStatus.AntiSpam | Should -Be 'Collected'
        }

        It 'states what it covers and what it does not' {
            $r = Invoke-Scan @{}
            ($r.Data.Scope.NotIncluded -join ' ') | Should -Match 'Microsoft 365 Groups'
            ($r.Data.Scope.NotIncluded -join ' ') | Should -Match 'Safe Senders'
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'evaluator: each state' {

        It 'DL-1.1: authenticated senders only is Met; outside mail with no restriction is a Gap; limited to named senders is Partial; not returned is not assessed' {
            Invoke-Scan @{ Lists = @(
                New-DlRaw 'Safe' 'safe@contoso.com'
                New-DlRaw 'Open' 'open@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }
                New-DlRaw 'Named' 'named@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false; AcceptMessagesOnlyFromSendersOrMembers = @('Partner Pat') }
                New-DlRaw 'Unread' 'unread@contoso.com' -Omit @('RequireSenderAuthenticationEnabled')
                New-DlRaw 'UnknownAllowed' 'ua@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false } -Omit @('AcceptMessagesOnlyFromSendersOrMembers', 'AcceptMessagesOnlyFrom', 'AcceptMessagesOnlyFromDLMembers')) } | Out-Null
            (F 'DL-1.1' 'safe@*').State | Should -Be 'Satisfied'
            $o = F 'DL-1.1' 'open@*'; $o.State | Should -Be 'Gap'; $o.Severity | Should -Be 'High'
            $o.Detail | Should -Match 'accepts mail from anyone'
            $o.Detail | Should -Match 'DMARC does not change this'
            (F 'DL-1.1' 'named@*').State | Should -Be 'Partial'
            (F 'DL-1.1' 'unread@*').State | Should -Be 'NotApplicable'
            $ua = F 'DL-1.1' 'ua@*'; $ua.State | Should -Be 'Gap'
            $ua.Detail | Should -Match 'did not return an allowed-senders list'
        }

        It 'DL-1.1 treats a dynamic list like any other' {
            Invoke-Scan @{ Dynamic = @(New-DlDynamic 'Everyone' 'everyone@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }) } | Out-Null
            (F 'DL-1.1' 'everyone@*').State | Should -Be 'Gap'
        }

        It 'DL-2.1: an owner is Met; none is a Gap; ManagedBy not returned is not assessed (not "no owner")' {
            Invoke-Scan @{ Lists = @(New-DlRaw 'Owned' 'owned@contoso.com'; New-DlRaw 'Orphan' 'orphan@contoso.com' -With @{ ManagedBy = @() }; New-DlRaw 'Unread' 'unread@contoso.com' -Omit @('ManagedBy')) } | Out-Null
            (F 'DL-2.1' 'owned@*').State | Should -Be 'Satisfied'
            (F 'DL-2.1' 'orphan@*').State | Should -Be 'Gap'
            (F 'DL-2.1' 'unread@*').State | Should -Be 'NotApplicable'
        }

        It 'DL-2.2: moderation needs an approver; with none, Exchange sends to the owners; off is not judged' {
            Invoke-Scan @{ Lists = @(
                New-DlRaw 'ModBy' 'modby@contoso.com' -With @{ ModerationEnabled = $true; ModeratedBy = @('Mod One') }
                New-DlRaw 'OwnerOnly' 'ownerOnly@contoso.com' -With @{ ModerationEnabled = $true }
                New-DlRaw 'Nobody' 'nobody@contoso.com' -With @{ ModerationEnabled = $true; ManagedBy = @() }
                New-DlRaw 'Off' 'off@contoso.com'
                New-DlRaw 'Unread' 'unread@contoso.com' -Omit @('ModerationEnabled')
                New-DlRaw 'ModUnread' 'modunread@contoso.com' -With @{ ModerationEnabled = $true } -Omit @('ModeratedBy')) } | Out-Null
            (F 'DL-2.2' 'modby@*').State | Should -Be 'Satisfied'
            $oo = F 'DL-2.2' 'owneronly@*'; $oo.State | Should -Be 'Satisfied'; $oo.Detail | Should -Match 'go to its 1 owner'
            (F 'DL-2.2' 'nobody@*').State | Should -Be 'Gap'
            (F 'DL-2.2' 'off@*').Count | Should -Be 0 -Because 'moderation off is Microsoft''s default and nothing recommends turning it on'
            (F 'DL-2.2' 'unread@*').State | Should -Be 'NotApplicable'
            (F 'DL-2.2' 'modunread@*').State | Should -Be 'NotApplicable'
        }

        It 'DL-2.4 / 2.5: with no approved NRG standard there is ONE tenant-level "not assessed" each, and no list is judged' {
            Invoke-Scan @{ Lists = @(New-DlRaw 'A' 'a@contoso.com' -With @{ MemberJoinRestriction = 'Open' }; New-DlRaw 'B' 'b@contoso.com'); Members = @{
                'a@contoso.com' = @(New-DlMember 'Vendor' 'v@vendor.example' 'MailContact') } } | Out-Null
            foreach ($id in 'DL-2.4', 'DL-2.5') {
                $f = F $id
                $f.Count | Should -Be 1 -Because "$id is an NRG judgment"
                $f[0].State | Should -Be 'NotApplicable'
                $f[0].Instance | Should -BeNullOrEmpty
                $f[0].Detail | Should -Match 'no standard is approved'
            }
        }

        It 'DL-3.1: only the Authentication-Results header (or a source IP range) verifies a sender; any other header is text the sender chooses' {
            $cls = { param($rule) & $script:Mod { param($r) (Get-NRGDlTransportRuleClass -Rule $r).Class } $rule }
            $base = @{ Name = 'r'; State = 'Enabled'; Mode = 'Enforce'; SetSCL = -1; ConditionsKnown = $true }
            (& $cls ($base + @{ Predicates = @('SenderDomainIs', 'HeaderContains'); SenderDomainIs = @('partner.example'); HeaderContainsMessageHeader = 'X-Partner'; HeaderContainsWords = @('yes') })) | Should -Be 'SenderDomainOnly'
            (& $cls ($base + @{ Predicates = @('HeaderContains'); HeaderContainsMessageHeader = 'X-Partner'; HeaderContainsWords = @('yes') })) | Should -Be 'NoSenderCondition'
            (& $cls ($base + @{ Predicates = @('SenderDomainIs', 'HeaderContains'); SenderDomainIs = @('partner.example'); HeaderContainsMessageHeader = ' authentication-results '; HeaderContainsWords = @('dmarc=pass') })) | Should -Be 'Verified'
            (& $cls ($base + @{ Predicates = @('SenderDomainIs', 'HeaderMatches'); SenderDomainIs = @('partner.example'); HeaderMatchesMessageHeader = 'Authentication-Results' })) | Should -Be 'Verified'
            (& $cls ($base + @{ Predicates = @('SenderIpRanges'); SenderIpRanges = @('203.0.113.7') })) | Should -Be 'Verified'
            (& $cls ($base + @{ Predicates = @('FromScope'); FromScope = 'InOrganization' })) | Should -Be 'Other' -Because 'a sender-scope condition is a sender condition, so the rule is not "applies to any sender"'
        }

        It 'DL-3.1: a rule this scan cannot judge is "not assessed", never "none weak"; a fake header is a Gap; an Authentication-Results rule is Satisfied' {
            Invoke-Scan @{ Rules = @(New-Rule 'Scope only' -Predicates 'FromScope' -With @{ FromScope = 'InOrganization' }) } | Out-Null
            (F 'DL-3.1').State | Should -Be 'NotApplicable'
            (F 'DL-3.1').Detail | Should -Match 'cannot judge how broad they are'
            Invoke-Scan @{ Rules = @(New-Rule 'Fake header' -Predicates 'SenderDomainIs', 'HeaderContains' -With @{ SenderDomainIs = @('partner.example'); HeaderContainsMessageHeader = 'X-Partner'; HeaderContainsWords = @('yes') }) } | Out-Null
            (F 'DL-3.1').State | Should -Be 'Gap'
            Invoke-Scan @{ Rules = @(New-Rule 'Verified' -Predicates 'SenderDomainIs', 'HeaderContains' -With @{ SenderDomainIs = @('partner.example'); HeaderContainsMessageHeader = 'Authentication-Results'; HeaderContainsWords = @('dmarc=pass') }) } | Out-Null
            (F 'DL-3.1').State | Should -Be 'Satisfied'
            (F 'DL-3.1').Detail | Should -Match 'each with a condition that verifies the sender'
        }

        It 'DL-3.3: the default policy drops out when an enabled rule covers every accepted domain (the shared in-force rule); an exception keeps it' {
            $def = [pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @('stale.example') }
            $all = [pscustomobject]@{ Name = 'All staff'; IsDefault = $false; AllowedSenders = @(); AllowedSenderDomains = @() }
            $cover = [pscustomobject]@{ Name = 'r'; HostedContentFilterPolicy = 'All staff'; State = 'Enabled'; RecipientDomainIs = @('contoso.com', 'contoso.onmicrosoft.com') }
            Invoke-Scan @{ AntiSpam = @($def, $all); AntiSpamRules = @($cover) } | Out-Null
            (F 'DL-3.3').State | Should -Be 'Satisfied'
            (F 'DL-3.3').Detail | Should -Match 'bypass nothing'
            $partial = [pscustomobject]@{ Name = 'r'; HostedContentFilterPolicy = 'All staff'; State = 'Enabled'; RecipientDomainIs = @('contoso.com', 'contoso.onmicrosoft.com'); ExceptIfSentTo = @('boss@contoso.com') }
            Invoke-Scan @{ AntiSpam = @($def, $all); AntiSpamRules = @($partial) } | Out-Null
            (F 'DL-3.3').State | Should -Be 'Gap' -Because 'a rule with an exception does not cover everyone, so the default policy still applies'
            (F 'DL-3.3').Detail | Should -Match 'stale\.example'
        }

        It 'an entered but unusable standard is not assessed, and the finding says why' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGStandards -MockWith { $s = & $script:Approved; $s.DistributionListMaxMembers = @('lots'); $s }
            Invoke-Scan @{ Lists = @(New-DlRaw 'A' 'a@contoso.com') } | Out-Null
            (F 'DL-2.4').State | Should -Be 'NotApplicable'
            (F 'DL-2.4').Detail | Should -Match "'lots' is not a whole number"
        }

        Context 'with the standards approved' {
            BeforeEach { Mock -ModuleName 'NRG-Assessment' Get-NRGStandards -MockWith $script:Approved }

            It 'DL-2.3: external members are expected, so they are never a finding: not Met, not a Gap, not even "not assessed"' {
                Invoke-Scan @{ Lists = @(New-DlRaw 'Ext' 'ext@contoso.com'; New-DlRaw 'Clean' 'clean@contoso.com'; New-DlRaw 'Broken' 'broken@contoso.com')
                    Dynamic = @(New-DlDynamic 'Everyone' 'everyone@contoso.com')
                    MemberThrow = @{ 'broken@contoso.com' = 'object not found' }; Members = @{
                        'ext@contoso.com'      = @(New-DlMember 'Ann' 'ann@contoso.com'; New-DlMember 'Vendor' 'v@vendor.example' 'MailContact')
                        'clean@contoso.com'    = @(New-DlMember 'Ann' 'ann@contoso.com')
                        'everyone@contoso.com' = @(New-DlMember 'Vendor' 'v@vendor.example' 'MailContact') } } | Out-Null
                @(F 'DL-2.3').Count | Should -Be 0
            }

            It 'DL-2.3: a leftover DistributionListExternalMembers value in the standards file is ignored: nothing judges or removes an external member' {
                Mock -ModuleName 'NRG-Assessment' Get-NRGStandards -MockWith { $s = & $script:Approved; $s.DistributionListExternalMembers = @('Prohibited'); $s }
                Invoke-Scan @{ Lists = @(New-DlRaw 'Ext' 'ext@contoso.com'); Members = @{ 'ext@contoso.com' = @(New-DlMember 'Vendor' 'v@vendor.example' 'MailContact') } } | Out-Null
                @(F 'DL-2.3').Count | Should -Be 0
                $ws = Get-NRGDistributionListWorksheet -Metadata @{}
                @($ws.Lists | ForEach-Object { $_.Settings } | ForEach-Object { $_.Commands } | Where-Object { $_ -match 'Remove-DistributionGroupMember' }) | Should -BeNullOrEmpty
                (@($ws.Lists[0].Settings) | Where-Object { $_.ControlId -eq 'DL-2.3' }).Verdict | Should -Be 'Context'
            }

            It 'DL-2.4: over the cap is a Gap, at or under is Met, and a truncated count that cannot settle it is not assessed' {
                Invoke-Scan @{ Lists = @(New-DlRaw 'Over' 'over@contoso.com'; New-DlRaw 'Under' 'under@contoso.com'; New-DlRaw 'Cut' 'cut@contoso.com'); Members = @{
                    'over@contoso.com'  = @(1..3 | ForEach-Object { New-DlMember "O$_" "o$_@contoso.com" })
                    'under@contoso.com' = @(1..2 | ForEach-Object { New-DlMember "U$_" "u$_@contoso.com" })
                    'cut@contoso.com'   = @(1..9 | ForEach-Object { New-DlMember "C$_" "c$_@contoso.com" }) } } @{ MaxMembersPerList = 2 } | Out-Null
                (F 'DL-2.4' 'over@*').State | Should -Be 'Gap'
                (F 'DL-2.4' 'under@*').State | Should -Be 'Satisfied'
                (F 'DL-2.4' 'cut@*').State | Should -Be 'Gap' -Because 'more than 2 were read and the approved cap is 2'
            }

            It 'DL-2.4: when only the first N were read and N is not above the cap, the answer is not assessed' {
                Mock -ModuleName 'NRG-Assessment' Get-NRGStandards -MockWith { $s = & $script:Approved; $s.DistributionListMaxMembers = @('50'); $s }
                Invoke-Scan @{ Lists = @(New-DlRaw 'Cut' 'cut@contoso.com'); Members = @{ 'cut@contoso.com' = @(1..9 | ForEach-Object { New-DlMember "C$_" "c$_@contoso.com" }) } } @{ MaxMembersPerList = 5 } | Out-Null
                (F 'DL-2.4' 'cut@*').State | Should -Be 'NotApplicable'
                (F 'DL-2.4' 'cut@*').Detail | Should -Match 'Raise -MaxMembersPerList'
            }

            It 'DL-2.5: an accepted join setting is Met, another is a Gap, not returned is not assessed, and a dynamic list has none' {
                Invoke-Scan @{ Lists = @(New-DlRaw 'Closed' 'closed@contoso.com'; New-DlRaw 'Open' 'open@contoso.com' -With @{ MemberJoinRestriction = 'Open' }; New-DlRaw 'Approval' 'approval@contoso.com' -With @{ MemberJoinRestriction = 'ApprovalRequired' }
                    New-DlRaw 'Unread' 'unread@contoso.com' -Omit @('MemberJoinRestriction')); Dynamic = @(New-DlDynamic 'Dyn' 'dyn@contoso.com') } | Out-Null
                (F 'DL-2.5' 'closed@*').State | Should -Be 'Satisfied'
                (F 'DL-2.5' 'approval@*').State | Should -Be 'Satisfied'
                $o = F 'DL-2.5' 'open@*'; $o.State | Should -Be 'Gap'; $o.CurrentValue | Should -Be 'MemberJoinRestriction = Open'
                (F 'DL-2.5' 'unread@*').State | Should -Be 'NotApplicable'
                (F 'DL-2.5' 'dyn@*').Count | Should -Be 0
            }
        }

        It 'DL-3.1: an SCL -1 rule on the sender domain alone, or on no sender condition, is a Gap that names the rule' {
            Invoke-Scan @{ Lists = @(New-DlRaw 'A' 'a@contoso.com'); Rules = @(
                New-Rule 'Domain only' -Predicates 'SenderDomainIs' -With @{ SenderDomainIs = @('partner.example') }
                New-Rule 'To the CEO' -Predicates 'SentTo' -With @{ SentTo = @('ceo@contoso.com') }) } | Out-Null
            $f = F 'DL-3.1'; $f.Count | Should -Be 1
            $f.State | Should -Be 'Gap'; $f.Severity | Should -Be 'High'
            @($f.AffectedObjects | ForEach-Object { $_.Name }) | Should -Contain 'Domain only'
            @($f.AffectedObjects | ForEach-Object { $_.Name }) | Should -Contain 'To the CEO'
            $f.Detail | Should -Match 'never to use alone'
            $f.Detail | Should -Match 'not malware or high confidence phishing'
        }

        It 'DL-3.1: a rule with a verifying condition is the pattern Microsoft describes, so no Gap; it is still listed' {
            Invoke-Scan @{ Rules = @(
                New-Rule 'DMARC pass' -Predicates 'SenderDomainIs', 'HeaderContains' -With @{ SenderDomainIs = @('partner.example'); HeaderContainsMessageHeader = 'Authentication-Results'; HeaderContainsWords = @('dmarc=pass') }
                New-Rule 'From the relay' -Predicates 'SenderIpRanges' -With @{ SenderIpRanges = @('203.0.113.0/24') }) } | Out-Null
            $f = F 'DL-3.1'; $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'DMARC pass'
            $f.Detail | Should -Match 'still skip spam filtering'
        }

        It 'DL-3.1: only SCL -1 is a bypass, and a disabled or test-mode rule is not judged' {
            Invoke-Scan @{ Rules = @(
                New-Rule 'Five' -Scl 5 -Predicates 'SenderDomainIs' -With @{ SenderDomainIs = @('a.example') }
                New-Rule 'Nine' -Scl 9
                New-Rule 'Off' -Predicates 'SenderDomainIs' -With @{ SenderDomainIs = @('b.example'); State = 'Disabled' }
                New-Rule 'Testing' -Predicates 'SenderDomainIs' -With @{ SenderDomainIs = @('c.example'); Mode = 'AuditAndNotify' }) } | Out-Null
            $f = F 'DL-3.1'; $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match '2 further SCL -1 rule\(s\) are disabled or in test mode'
        }

        It 'DL-3.1: conditions not returned is not assessed; no SCL -1 rule is Met; rules not read is not assessed' {
            Invoke-Scan @{ Rules = @(New-Rule 'Opaque' -Omit @('Conditions')) } | Out-Null
            (F 'DL-3.1').State | Should -Be 'NotApplicable'
            (F 'DL-3.1').Detail | Should -Match 'conditions were not returned'
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ Rules = @() } | Out-Null
            (F 'DL-3.1').State | Should -Be 'Satisfied'
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ Throw = @{ 'Get-TransportRule' = 'denied' } } | Out-Null
            (F 'DL-3.1').State | Should -Be 'NotApplicable'
            (F 'DL-3.1').Detail | Should -Match 'mail flow rules were not read'
        }

        It 'DL-3.2: empty is Met; entries within a /24 are Partial; a range wider than a /24 or an unparsable entry is a Gap; unread is not assessed' {
            $cf = { param($ips) @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = $ips; IPBlockList = @() }) }
            Invoke-Scan @{ ConnFilter = (& $cf @()) } | Out-Null
            (F 'DL-3.2').State | Should -Be 'Satisfied'
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ ConnFilter = (& $cf @('203.0.113.0/24', '198.51.100.7', '192.0.2.1-192.0.2.200')) } | Out-Null
            (F 'DL-3.2').State | Should -Be 'Partial'
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ ConnFilter = (& $cf @('10.0.0.1-10.0.3.255')) } | Out-Null
            $w = F 'DL-3.2'; $w.State | Should -Be 'Gap'; $w.Detail | Should -Match 'Microsoft recommends a /24 or smaller'
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ ConnFilter = (& $cf @('2001:db8::/32', 'not an ip')) } | Out-Null
            (F 'DL-3.2').State | Should -Be 'Gap'
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ Throw = @{ 'Get-HostedConnectionFilterPolicy' = 'denied' } } | Out-Null
            (F 'DL-3.2').State | Should -Be 'NotApplicable'
        }

        It 'DL-3.3: an allowed sender or domain in a policy that applies is a Gap; a dormant custom policy''s entries are not judged; none is Met; unread is not assessed' {
            $pol = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @() }
                     [pscustomobject]@{ Name = 'Dormant'; IsDefault = $false; AllowedSenders = @('b@x.example'); AllowedSenderDomains = @() })
            Invoke-Scan @{ AntiSpam = $pol; AntiSpamRules = @([pscustomobject]@{ Name = 'r'; HostedContentFilterPolicy = 'Dormant'; State = 'Disabled' }) } | Out-Null
            $f = F 'DL-3.3'; $f.State | Should -Be 'Satisfied'; $f.Detail | Should -Match 'no enabled rule applies'
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ AntiSpam = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @('a@x.example'); AllowedSenderDomains = @('y.example') }) } | Out-Null
            $g = F 'DL-3.3'; $g.State | Should -Be 'Gap'; @($g.AffectedObjects).Count | Should -Be 2
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ Throw = @{ 'Get-HostedContentFilterPolicy' = 'denied' } } | Out-Null
            (F 'DL-3.3').State | Should -Be 'NotApplicable'
        }

        It 'DL-3.3: when the rules were not read, an entry on a custom policy is counted, and the finding says so' {
            Invoke-Scan @{ AntiSpam = @([pscustomobject]@{ Name = 'Custom'; IsDefault = $false; AllowedSenders = @('a@x.example'); AllowedSenderDomains = @() }); Throw = @{ 'Get-HostedContentFilterRule' = 'denied' } } | Out-Null
            $f = F 'DL-3.3'; $f.State | Should -Be 'Gap'
            $f.Detail | Should -Match 'rules were not read'
        }

        It 'DL-3.4: an own domain as a bypass-rule condition is a Gap; on an anti-spam allow list only it is Partial and carries the September 2022 note' {
            Invoke-Scan @{ Rules = @(New-Rule 'Own' -Predicates 'SenderDomainIs' -With @{ SenderDomainIs = @('mail.contoso.com') }) } | Out-Null
            $r = F 'DL-3.4'; $r.State | Should -Be 'Gap'; $r.Detail | Should -Match 'carries no requirement that the mail pass authentication'
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ AntiSpam = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @('ceo@contoso.com'); AllowedSenderDomains = @() }) } | Out-Null
            $a = F 'DL-3.4'; $a.State | Should -Be 'Partial'; $a.Detail | Should -Match 'September 2022'
        }

        It 'DL-3.4: Met only when every source was read and none is an own domain; a source not read is not assessed, never clean' {
            Invoke-Scan @{ Rules = @(New-Rule 'Partner' -Predicates 'SenderDomainIs' -With @{ SenderDomainIs = @('partner.example') }) } | Out-Null
            (F 'DL-3.4').State | Should -Be 'Satisfied'
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ Throw = @{ 'Get-TransportRule' = 'denied' } } | Out-Null
            $x = F 'DL-3.4'; $x.State | Should -Be 'NotApplicable'; $x.Detail | Should -Match 'mail flow rules were not read'
            Clear-NRGState; Remove-Stubs
            Invoke-Scan @{ Throw = @{ 'Get-AcceptedDomain' = 'denied' } } | Out-Null
            (F 'DL-3.4').State | Should -Be 'NotApplicable'
            (F 'DL-3.4').Detail | Should -Match 'accepted domains were not read'
        }

        It 'DL-3.5 and DL-4.1 are never assessed: always not assessed, never Met, whatever the tenant looks like' {
            Invoke-Scan @{ Lists = @(New-DlRaw 'A' 'a@contoso.com') } | Out-Null
            foreach ($id in 'DL-3.5', 'DL-4.1') { (F $id).State | Should -Be 'NotApplicable' }
            (F 'DL-4.1').Detail | Should -Match 'cannot detect'
            (F 'DL-3.5').Detail | Should -Match 'unmeasured, not absent'
        }

        It 'no collected data means every control is not assessed and none is Met' {
            Clear-NRGState
            Test-NRGDistributionLists
            $all = @(Get-NRGFindings | Where-Object { $_.ControlId -like 'DL-*' })
            $all.Count | Should -BeGreaterThan 8
            @($all | Where-Object { $_.State -ne 'NotApplicable' }) | Should -BeNullOrEmpty
            @($all | Where-Object { $_.Instance }) | Should -BeNullOrEmpty
        }

        It 'a collector that failed outright is not assessed too' {
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data @{ CollectorId = 'EXO-DistributionLists'; Success = $false; Data = @{ Lists = @() } }
            Test-NRGDistributionLists
            @(Get-NRGFindings | Where-Object { $_.ControlId -like 'DL-*' -and $_.State -ne 'NotApplicable' }) | Should -BeNullOrEmpty
        }

        It 'a tenant with no lists says nothing was assessed; it does not claim the lists are clean' {
            Invoke-Scan @{} | Out-Null
            $f = F 'DL-1.1'
            $f.Count | Should -Be 1
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'no distribution list'
        }

        It 'every finding carries the tool''s NIST mapping in the form the rollups read, and a Learn source on a shortfall' {
            Invoke-Scan @{ Lists = @(New-DlRaw 'Open' 'open@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }) } | Out-Null
            $f = F 'DL-1.1' 'open@*'
            @($f.FrameworkIds) | Should -Be @('NIST:AC-3, SI-8')
            @(Get-NRGNISTControlIdsFromFinding -Finding $f) | Should -Be @('AC-3', 'SI-8')
            $f.Remediation | Should -Match 'https://learn\.microsoft\.com/'
            $f.Category | Should -Be 'Email'
        }

        It 'every finding says what was read or not assessed, and cites no SCuBA or CIS id' {
            Invoke-Scan @{ Lists = @(New-DlRaw 'Open' 'open@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }); Rules = @(New-Rule 'R' -Predicates 'SenderDomainIs' -With @{ SenderDomainIs = @('p.example') }) } | Out-Null
            foreach ($f in @(Get-NRGFindings | Where-Object { $_.ControlId -like 'DL-*' })) {
                $f.Detail | Should -Match '^(Read:|Shortfall|Not assessed)' -Because "$($f.ControlId) $($f.Instance)"
                (@($f.FrameworkIds) -join ' ') | Should -Not -Match 'SCuBA|CIS|MS\.'
            }
        }

        It 'is not a Test-NRGControl* function, so a full assessment never runs it' {
            @(Get-Command -Module NRG-Assessment -Name 'Test-NRGControl*' | Where-Object { $_.Name -eq 'Test-NRGDistributionLists' }) | Should -BeNullOrEmpty
            (Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-NRGAssessment.ps1') -Raw) | Should -Match "Name 'Test-NRGControl\*'"
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'worksheet and files' {

        BeforeAll {
            $script:Build = {
                param([hashtable] $S, [string] $Name = 'ws', [hashtable] $Collect = @{})
                Invoke-Scan $S $Collect | Out-Null
                $meta = @{ TenantDomain = 'contoso.onmicrosoft.com'; TenantId = '00000000-0000-0000-0000-000000000000'; ToolVersion = 'test'; AssessmentDate = '2026-10-02 10:00' }
                $ws = Get-NRGDistributionListWorksheet -Metadata $meta
                $dir = Join-Path $TestDrive $Name
                $paths = Publish-NRGDistributionListWorksheet -Worksheet $ws -OutputBase (Join-Path $dir 'contoso-20261002-100000')
                [pscustomobject]@{ Worksheet = $ws; Txt = (Get-Content -LiteralPath $paths.TextPath -Raw); Csv = @(Import-Csv -LiteralPath $paths.CsvPath); CsvRaw = (Get-Content -LiteralPath $paths.CsvPath -Raw); Paths = $paths; Dir = $dir }
            }
            $script:Scn = @{
                Lists = @(
                    New-DlRaw 'All Staff' 'allstaff@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false; ManagedBy = @(); MemberJoinRestriction = 'Open' }
                    New-DlRaw 'Finance' 'finance@contoso.com')
                Members = @{ 'allstaff@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com'; New-DlMember 'Vendor Bob' 'bob@vendor.example' 'MailContact'); 'finance@contoso.com' = @(New-DlMember 'Cy' 'cy@contoso.com') }
                Rules = @((New-Rule 'Allow partner' -Predicates 'SenderDomainIs' -With @{ SenderDomainIs = @('partner.example') }), (New-Rule 'To all staff' -Predicates 'SentTo' -With @{ SentTo = @('allstaff@contoso.com') }))
                ConnFilter = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = @('203.0.113.0/24'); IPBlockList = @() })
                AntiSpam = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @() }) }
        }

        It 'writes exactly <base>-distribution-lists.txt and .csv, and nothing that could be executed' {
            $o = & $script:Build $script:Scn 'files'
            $o.Paths.TextPath | Should -Match '-distribution-lists\.txt$'
            $o.Paths.CsvPath | Should -Match '-distribution-lists\.csv$'
            @(Get-ChildItem -LiteralPath $o.Dir -File | ForEach-Object { $_.Extension } | Sort-Object -Unique) | Should -Be @('.csv', '.txt')
            @(Get-ChildItem -LiteralPath $o.Dir -File -Filter '*.ps1') | Should -BeNullOrEmpty
        }

        It 'per list: members, current settings, who can reach it today, the recommendation, its source and the mapped NIST control' {
            $o = & $script:Build $script:Scn 'content'
            $o.Txt | Should -Match 'LIST: All Staff <allstaff@contoso.com>'
            $o.Txt | Should -Match 'Vendor Bob <bob@vendor\.example>\s+\[MailContact, External\]'
            $o.Txt | Should -Match 'Outside senders: accepted from anyone'
            $o.Txt | Should -Match 'RequireSenderAuthenticationEnabled = False'
            $o.Txt | Should -Match 'Recommended: True \(only senders inside the organization\)'
            $o.Txt | Should -Match 'https://learn\.microsoft\.com/exchange/recipients-in-exchange-online'
            $o.Txt | Should -Match 'Mapped NIST 800-53 Rev 5 \(NRG mapping\): AC-3, SI-8'
            $o.Txt | Should -Match 'Other frameworks: no framework item verified'
            $row = $o.Csv | Where-Object { $_.RowType -eq 'Setting' -and $_.ListAddress -eq 'allstaff@contoso.com' -and $_.ControlId -eq 'DL-1.1' }
            $row.Verdict | Should -Be 'Gap'
            $row.Current | Should -Be 'RequireSenderAuthenticationEnabled = False'
            $row.Nist80053Mapping | Should -Be 'AC-3, SI-8'
            $row.OtherFrameworks | Should -Be 'no framework item verified'
            @($o.Csv | Where-Object { $_.RowType -eq 'Member' -and $_.ListAddress -eq 'allstaff@contoso.com' }).Count | Should -Be 2
        }

        It 'lists the tenant-wide bypasses and says which ones reach a list by name' {
            $o = & $script:Build $script:Scn 'bypass'
            $o.Txt | Should -Match 'TENANT-WIDE FILTERING BYPASSES'
            $o.Txt | Should -Match "\[DL-3\.1\].*--\s+Gap"
            $o.Txt | Should -Match "Mail flow rule 'To all staff' sets SCL -1 \(skips spam filtering\) for mail sent to this list"
            ($o.Worksheet.Lists | Where-Object { $_.Address -eq 'finance@contoso.com' }).Reach.Lines -join ' ' | Should -Not -Match 'To all staff'
        }

        It 'the most exposed list is first' {
            $o = & $script:Build $script:Scn 'order'
            @($o.Worksheet.Lists)[0].Address | Should -Be 'allstaff@contoso.com'
        }

        It 'prints every limitation, in the same words, in both files' {
            $o = & $script:Build $script:Scn 'limits'
            @($o.Worksheet.Limitations).Count | Should -BeGreaterOrEqual 8
            foreach ($lim in $o.Worksheet.Limitations) {
                $flat = ($lim -replace '\s+', ' ')
                ($o.Txt -replace '\s+', ' ') | Should -Match ([regex]::Escape($flat))
                @($o.Csv | Where-Object { $_.RowType -eq 'Limitation' -and $_.Detail -eq $lim }).Count | Should -Be 1 -Because $lim
            }
            ($o.Worksheet.Limitations -join ' ') | Should -Match 'Only Exchange Online was connected'
            ($o.Worksheet.Limitations -join ' ') | Should -Match 'lookalike domain or a display-name impersonation'
            ($o.Worksheet.Limitations -join ' ') | Should -Match 'Microsoft 365 Groups and Teams-connected lists were not read'
            ($o.Worksheet.Limitations -join ' ') | Should -Match 'never as met'
        }

        It 'the same verdict and the same finding text read identically in the text file and the CSV' {
            $o = & $script:Build $script:Scn 'parity'
            $settings = @($o.Csv | Where-Object { $_.RowType -in 'Setting', 'Tenant bypass' })
            $settings.Count | Should -BeGreaterThan 15
            $flatTxt = ($o.Txt -replace '\s+', ' ')
            foreach ($s in $settings) {
                $d = ($s.Detail -replace '\s+', ' ').Trim()
                if ($d) { $flatTxt | Should -Match ([regex]::Escape($d)) -Because "$($s.ListAddress) $($s.ControlId): the CSV finding text must appear in the text file" }
            }
            # verdict words: every list block's "[Verdict]" in the text matches the CSV row for that item
            foreach ($l in $o.Worksheet.Lists) {
                foreach ($r in @($l.Settings)) {
                    $csv = $o.Csv | Where-Object { $_.RowType -eq 'Setting' -and $_.ListAddress -eq $l.Address -and $_.Item -eq $r.Item }
                    $csv.Verdict | Should -Be $r.Verdict
                    $o.Txt | Should -Match ([regex]::Escape("$($r.Item)  [$($r.Verdict)]"))
                }
            }
        }

        It 'a not-assessed verdict is never presented as a pass in either file' {
            $o = & $script:Build $script:Scn 'nopass'
            foreach ($row in @($o.Csv | Where-Object { $_.ControlId -in 'DL-2.3', 'DL-2.4', 'DL-2.5', 'DL-3.5', 'DL-4.1' -and $_.RowType -in 'Setting', 'Tenant bypass' })) {
                $row.Verdict | Should -Not -Be 'Met' -Because "$($row.ControlId) has no approved standard or is never assessed"
            }
            $o.Txt | Should -Not -Match 'DL-3\.5\][^\n]{0,200}--\s+Met'
            $o.Txt | Should -Not -Match 'DL-4\.1\][^\n]{0,200}--\s+Met'
        }

        It 'is written through the restricted-file writer, ACL first, and refuses to write without it' {
            Mock -ModuleName 'NRG-Assessment' Set-NRGSensitiveFileContent -MockWith { }
            Invoke-Scan $script:Scn | Out-Null
            $ws = Get-NRGDistributionListWorksheet -Metadata @{ TenantDomain = 'contoso.onmicrosoft.com' }
            Publish-NRGDistributionListWorksheet -Worksheet $ws -OutputBase (Join-Path $TestDrive 'acl' 'x') | Out-Null
            Should -Invoke -ModuleName 'NRG-Assessment' Set-NRGSensitiveFileContent -Times 2 -Exactly
            Should -Invoke -ModuleName 'NRG-Assessment' Set-NRGSensitiveFileContent -Times 1 -Exactly -ParameterFilter { $Path -like '*-distribution-lists.txt' }
            Should -Invoke -ModuleName 'NRG-Assessment' Set-NRGSensitiveFileContent -Times 1 -Exactly -ParameterFilter { $Path -like '*-distribution-lists.csv' }
            Mock -ModuleName 'NRG-Assessment' Get-Command -ParameterFilter { $Name -eq 'Set-NRGSensitiveFileContent' } -MockWith { $null }
            { Publish-NRGDistributionListWorksheet -Worksheet $ws -OutputBase (Join-Path $TestDrive 'acl2' 'x') } | Should -Throw '*restricted-file writer*'
            Test-Path -LiteralPath (Join-Path $TestDrive 'acl2') | Should -BeFalse -Because 'nothing may be written when the writer is missing'
        }

        It 'restricts the files to the owner (0600 on a POSIX host)' -Skip:($IsWindows) {
            $o = & $script:Build $script:Scn 'perm'
            foreach ($p in $o.Paths.TextPath, $o.Paths.CsvPath) { (& stat -c '%a' $p) | Should -Be '600' }
        }

        It 'rejects an output base that tries to escape with ..' {
            $ws = Get-NRGDistributionListWorksheet -Metadata @{}
            { Publish-NRGDistributionListWorksheet -Worksheet $ws -OutputBase (Join-Path $TestDrive 'a' '..' '..' 'x') } | Should -Throw '*traversal*'
        }

        It 'neutralizes a spreadsheet formula in a tenant-controlled name, and strips terminal escapes and line breaks from both files' {
            $evil = '=HYPERLINK("http://evil.example","click")'
            $o = & $script:Build @{ Lists = @(New-DlRaw $evil 'evil@contoso.com' -With @{ ManagedBy = @("+cmd|' /c calc'!A0") })
                Members = @{ 'evil@contoso.com' = @(New-DlMember "@SUM(1+1)`r`nHidden line" 'x@contoso.com'; New-DlMember "`e[31mRED`e[0m" 'y@contoso.com') } } 'evil'
            $o.CsvRaw | Should -Not -Match '(?m)(^|,)"=HYPERLINK'
            $o.CsvRaw | Should -Match "'=HYPERLINK"
            @($o.Csv | Where-Object { $_.Member -like '@SUM*' }).Count | Should -Be 0 -Because 'a leading @ is neutralized with an apostrophe'
            @($o.Csv | Where-Object { $_.Member -like "'@SUM*" }).Count | Should -Be 1
            ($o.Txt + $o.CsvRaw) | Should -Not -Match "\x1B"
            $o.Txt | Should -Not -Match 'SUM\(1\+1\)\r?\nHidden line'
            $o.Txt | Should -Match 'SUM\(1\+1\) Hidden line'
        }

        Context 'the administrator commands are text' {

            It 'carries the exact PowerShell for a shortfall, marked "text only", with -WhatIf advised, and never runs it' {
                $o = & $script:Build $script:Scn 'cmds'
                # allstaff holds an external member, whom 'require authenticated senders' would stop sending, so that command is not printed for it.
                $o.Txt | Should -Not -Match "Set-DistributionGroup -Identity 'allstaff@contoso\.com' -RequireSenderAuthenticationEnabled"
                $o.Txt | Should -Match "Set-DistributionGroup -Identity 'allstaff@contoso\.com' -AcceptMessagesOnlyFromSendersOrMembers 'ann@contoso\.com','bob@vendor\.example'"
                $o.Txt | Should -Match "Set-DistributionGroup -Identity 'allstaff@contoso\.com' -ManagedBy '<owner>'"
                $o.Txt | Should -Match 'Commands for an administrator to review and run, with -WhatIf first \(text only; this tool never runs them\)'
                $o.Txt | Should -Match "Disable-TransportRule -Identity 'Allow partner'"
                $o.Txt | Should -Not -Match "Set-HostedConnectionFilterPolicy -Identity Default -IPAllowList @\{Remove='203\.0\.113\.0/24'\}" -Because 'a /24 entry is within what Microsoft recommends, so no command removes it'
                ($o.Csv | Where-Object { $_.RowType -eq 'Setting' -and $_.ListAddress -eq 'allstaff@contoso.com' -and $_.ControlId -eq 'DL-1.1' }).AdminCommand | Should -BeNullOrEmpty
                ($o.Csv | Where-Object { $_.RowType -eq 'Setting' -and $_.ListAddress -eq 'allstaff@contoso.com' -and $_.ControlId -eq 'DL-1.2' }).AdminCommand |
                    Should -Be "Set-DistributionGroup -Identity 'allstaff@contoso.com' -AcceptMessagesOnlyFromSendersOrMembers 'ann@contoso.com','bob@vendor.example'"
                # A list with no external member still gets the require-authentication command.
                $p = & $script:Build @{ Lists = @(New-DlRaw 'Internal Open' 'iopen@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }); Members = @{ 'iopen@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com') } } 'cmds-internal'
                ($p.Csv | Where-Object { $_.RowType -eq 'Setting' -and $_.ControlId -eq 'DL-1.1' }).AdminCommand | Should -Be "Set-DistributionGroup -Identity 'iopen@contoso.com' -RequireSenderAuthenticationEnabled `$true"
                @(Get-CallLog | Where-Object { $_ -like 'WRITE:*' }) | Should -BeNullOrEmpty -Because 'the scan printed write commands; it must never have run one'
            }

            It 'a dynamic list gets the dynamic cmdlet' {
                $o = & $script:Build @{ Dynamic = @(New-DlDynamic 'Everyone' 'everyone@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }) } 'dyn'
                $o.Txt | Should -Match "Set-DynamicDistributionGroup -Identity 'everyone@contoso\.com' -RequireSenderAuthenticationEnabled"
            }

            It 'with the standards approved, the join shortfall gets its command, and no command removes an external member' {
                Mock -ModuleName 'NRG-Assessment' Get-NRGStandards -MockWith $script:Approved
                $o = & $script:Build $script:Scn 'std'
                $o.Txt | Should -Match "Set-DistributionGroup -Identity 'allstaff@contoso\.com' -MemberJoinRestriction 'Closed'"
                $o.Txt | Should -Not -Match 'Remove-DistributionGroupMember' -Because 'external members stay; the owner decided not to ban them'
                @($o.Csv | Where-Object { $_.AdminCommand -match 'Remove-DistributionGroupMember' }) | Should -BeNullOrEmpty
                ($o.Csv | Where-Object { $_.RowType -eq 'Setting' -and $_.ListAddress -eq 'allstaff@contoso.com' -and $_.ControlId -eq 'DL-2.5' }).Verdict | Should -Be 'Gap'
                @(Get-CallLog | Where-Object { $_ -like 'WRITE:*' }) | Should -BeNullOrEmpty
            }

            It 'a tenant-controlled name cannot break out of the command: an apostrophe is doubled, a typographic quote or a line break is refused' {
                $o = & $script:Build @{ Lists = @(
                    New-DlRaw "O'Brien team" "o'brien@contoso.com" -With @{ RequireSenderAuthenticationEnabled = $false }
                    New-DlRaw 'Smart' "smart$([char]0x2019); Remove-Item -Recurse C:\@contoso.com" -With @{ RequireSenderAuthenticationEnabled = $false }
                    New-DlRaw 'Newline' "nl`nSet-Mailbox@contoso.com" -With @{ RequireSenderAuthenticationEnabled = $false }) } 'inject'
                $o.Txt | Should -Match "Set-DistributionGroup -Identity 'o''brien@contoso\.com' -RequireSenderAuthenticationEnabled"
                # The tenant's text is printed as DATA (list header, member rows); only a command line could execute.
                $cmdLines = @($o.Txt -split "`n" | Where-Object { $_ -match '^\s+> ' })
                $cmdLines.Count | Should -BeGreaterThan 0
                @($cmdLines | Where-Object { $_ -match 'Remove-Item|Set-Mailbox' }) | Should -BeNullOrEmpty -Because 'no command line may carry text from a tenant-controlled name'
                @($o.Csv | Where-Object { $_.AdminCommand -match 'Remove-Item|Set-Mailbox' }) | Should -BeNullOrEmpty
                $o.Txt | Should -Match 'cannot be quoted safely here; change this setting in the portal'
                @($o.Csv | Where-Object { $_.AdminCommand -match "Set-DistributionGroup -Identity '(smart|nl)" }) | Should -BeNullOrEmpty
            }

            It 'fills the placeholders in ONE pass: tenant text that looks like a placeholder is never substituted again (it would end the quoted literal early)' {
                $c = & $script:Mod { Format-NRGDlCommand -Template 'Remove-DistributionGroupMember -Identity {List} -Member {Member}' -Values @{ List = 'a{Member}b@contoso.com'; Member = "m'x@contoso.com" } }
                $c | Should -Be "Remove-DistributionGroupMember -Identity 'a{Member}b@contoso.com' -Member 'm''x@contoso.com'"
                $d = & $script:Mod { Format-NRGDlCommand -Template 'Set-X -Identity {List} -Y {Value}' -Values @{ List = 'p{Value}q@contoso.com'; Value = 'v' } }
                $d | Should -Be "Set-X -Identity 'p{Value}q@contoso.com' -Y 'v'"
                $e = & $script:Mod { Format-NRGDlCommand -Template 'Set-X -Identity {List}' -Values @{ List = 'a$1b$&c@contoso.com' } }
                $e | Should -Be "Set-X -Identity 'a`$1b`$&c@contoso.com'" -Because 'replacement-pattern characters in tenant text are literal'
            }

            It 'refuses to build a command from a value that cannot be quoted safely, or from an unrecognized parameter word' {
                foreach ($bad in "a$([char]0x2018)b@contoso.com", "a$([char]0x201B)b@contoso.com", "a`nb@contoso.com", '', $null) {
                    & $script:Mod { param($v) Format-NRGDlCommand -Template 'Set-X -Identity {List}' -Values @{ List = $v } } $bad | Should -BeNullOrEmpty -Because "[$bad]"
                }
                & $script:Mod { Format-NRGDlCommand -Template 'Set-HostedContentFilterPolicy -Identity {Policy} -{Parameter} @{Remove={Value}}' -Values @{ Policy = 'Default'; Parameter = 'BlockedSenders; calc'; Value = 'x' } } | Should -BeNullOrEmpty
                & $script:Mod { Format-NRGDlCommand -Template 'Set-HostedContentFilterPolicy -Identity {Policy} -{Parameter} @{Remove={Value}}' -Values @{ Policy = 'Default'; Parameter = 'AllowedSenderDomains'; Value = 'x.example' } } |
                    Should -Be "Set-HostedContentFilterPolicy -Identity 'Default' -AllowedSenderDomains @{Remove='x.example'}"
                & $script:Mod { Format-NRGDlCommand -Template '' -Values @{} } | Should -BeNullOrEmpty
            }

            It '{Senders}: every address is its own quoted literal, in order; an empty list or ONE bad address yields no command at all, never a partial one' {
                $tpl = 'Set-DistributionGroup -Identity {List} -AcceptMessagesOnlyFromSendersOrMembers {Senders}'
                (& $script:Mod { param($t) Format-NRGDlCommand -Template $t -Values @{ List = 'l@contoso.com'; Senders = @('a@x.example', "o'b@x.example") } } $tpl) |
                    Should -Be "Set-DistributionGroup -Identity 'l@contoso.com' -AcceptMessagesOnlyFromSendersOrMembers 'a@x.example','o''b@x.example'"
                (& $script:Mod { param($t) Format-NRGDlCommand -Template $t -Values @{ List = 'l@contoso.com'; Senders = @('only@x.example') } } $tpl) |
                    Should -Be "Set-DistributionGroup -Identity 'l@contoso.com' -AcceptMessagesOnlyFromSendersOrMembers 'only@x.example'"
                foreach ($bad in "x$([char]0x2018)y@x.example", "x$([char]0x201B)y@x.example", "x`ny@x.example", '', $null) {
                    $r = & $script:Mod { param($t, $b) Format-NRGDlCommand -Template $t -Values @{ List = 'l@contoso.com'; Senders = @('ok@x.example', $b, 'also@x.example') } } $tpl $bad
                    ($null -eq $r) | Should -BeTrue -Because "a command with a sender dropped would reject that sender; got [$r] for [$bad]"
                }
                ($null -eq (& $script:Mod { param($t) Format-NRGDlCommand -Template $t -Values @{ List = 'l@contoso.com'; Senders = @() } } $tpl)) | Should -BeTrue
                ($null -eq (& $script:Mod { param($t) Format-NRGDlCommand -Template $t -Values @{ List = 'l@contoso.com' } } $tpl)) | Should -BeTrue
                # Tenant text that looks like a placeholder is inserted once and never substituted again.
                (& $script:Mod { param($t) Format-NRGDlCommand -Template $t -Values @{ List = 'a{Senders}b@contoso.com'; Senders = @('s{List}t@x.example') } } $tpl) |
                    Should -Be "Set-DistributionGroup -Identity 'a{Senders}b@contoso.com' -AcceptMessagesOnlyFromSendersOrMembers 's{List}t@x.example'"
            }

            It 'a list address that contains a placeholder cannot reach the senders in the printed allow-list command' {
                $o = & $script:Build @{ Lists = @(New-DlRaw 'Tmpl' 'x{Senders}y@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }); Members = @{ 'x{Senders}y@contoso.com' = @(New-DlMember 'Vendor' 'bob@vendor.example' 'MailContact') } } 'tmpl'
                $o.Txt | Should -Match "Set-DistributionGroup -Identity 'x\{Senders\}y@contoso\.com' -AcceptMessagesOnlyFromSendersOrMembers 'bob@vendor\.example'"
                $o.Txt | Should -Not -Match "-Identity 'x'bob"
            }

            It 'runs none of the commands it prints: the write-cmdlet spies stay silent through collect, evaluate, build and publish' {
                Mock -ModuleName 'NRG-Assessment' Get-NRGStandards -MockWith $script:Approved
                $o = & $script:Build $script:Scn 'spy'
                ($o.Txt -split "`n" | Where-Object { $_ -match '^\s+> (Set|Remove|Disable)-' }).Count | Should -BeGreaterThan 3
                @(Get-CallLog | Where-Object { $_ -like 'WRITE:*' }) | Should -BeNullOrEmpty
                @(Get-CallLog | Where-Object { $_ -notmatch '^Get-' }) | Should -BeNullOrEmpty
            }
        }

        It 'a list whose members could not be read says so, and is not shown as empty' {
            $o = & $script:Build @{ Lists = @(New-DlRaw 'Broken' 'broken@contoso.com'); MemberThrow = @{ 'broken@contoso.com' = 'object not found' } } 'broken'
            $o.Txt | Should -Match 'Members NOT read: object not found\. This is not an empty list\.'
            ($o.Csv | Where-Object { $_.RowType -eq 'Members' }).Current | Should -Match 'NOT read'
            $o.Worksheet.Summary.ListsMembersNotRead | Should -Be 1
        }

        Context 'lists with external members are the target, so they are counted and ranked' {
            BeforeAll {
                $script:ExtScn = @{
                    Lists   = @(New-DlRaw 'Alpha Internal' 'alpha@contoso.com'; New-DlRaw 'Beta Vendors' 'beta@contoso.com'; New-DlRaw 'Gamma Vendors' 'gamma@contoso.com'; New-DlRaw 'Delta Broken' 'delta@contoso.com')
                    Members = @{
                        'alpha@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com')
                        'beta@contoso.com'  = @(New-DlMember 'Vendor One' 'one@vendor.example' 'MailContact')
                        'gamma@contoso.com' = @(New-DlMember 'Vendor Two' 'two@vendor.example' 'MailContact'; New-DlMember 'Vendor Three' 'three@vendor.example' 'MailContact')
                    }
                    MemberThrow = @{ 'delta@contoso.com' = 'object not found' }
                }
            }

            It 'counts a list with an external member, and does not count the list whose members could not be read' {
                $o = & $script:Build $script:ExtScn 'extcount'
                $o.Worksheet.Summary.ListsWithExternalMembers | Should -Be 2
                $o.Worksheet.Summary.ListsMembersNotRead | Should -Be 1
                $o.Txt | Should -Match 'Lists with an external member:\s+2\s+\(counted only among lists whose members were read\)'
            }

            It 'ranks the list with more external members first when the settings are otherwise equal' {
                $o = & $script:Build $script:ExtScn 'extorder'
                $names = @($o.Worksheet.Lists | ForEach-Object { $_.Name })
                $names.IndexOf('Gamma Vendors') | Should -BeLessThan $names.IndexOf('Beta Vendors')
            }

            It 'a failed member read is never counted as having no external members' {
                $o = & $script:Build @{ Lists = @(New-DlRaw 'Only' 'only@contoso.com'); MemberThrow = @{ 'only@contoso.com' = 'object not found' } } 'extfail'
                $o.Worksheet.Summary.ListsWithExternalMembers | Should -Be 0
                $o.Worksheet.Summary.ListsMembersNotRead | Should -Be 1
            }
        }

        Context 'the allowed-senders proposal: a snapshot of the members read now, offered only where it is safe to offer' {
            BeforeAll {
                # One list, one DL-1.2 row. -Auth / -With shape the list; members are raw Get-DistributionGroupMember shapes.
                $script:Prop = {
                    param([hashtable] $Scn, [string] $Name = 'prop')
                    $o = & $script:Build $Scn $Name
                    $row = $o.Csv | Where-Object { $_.RowType -eq 'Setting' -and $_.ControlId -eq 'DL-1.2' } | Select-Object -First 1
                    [pscustomobject]@{ O = $o; Row = $row; Cmd = [string]$row.AdminCommand; Detail = [string]$row.Detail; Verdict = [string]$row.Verdict }
                }
                $script:OpenList = { param([hashtable] $With = @{}, [string] $Addr = 'open@contoso.com') New-DlRaw 'Open' $Addr -With (@{ RequireSenderAuthenticationEnabled = $false } + $With) }
            }

            It 'offers the members read now as the allowed senders: internal, external and nested group, each its own quoted address, in member order' {
                $r = & $script:Prop @{ Lists = @(& $script:OpenList); Members = @{ 'open@contoso.com' = @(
                    New-DlMember 'Ann' 'ann@contoso.com'; New-DlMember 'Vendor Bob' 'bob@vendor.example' 'MailContact'; New-DlMember 'Subteam' 'sub@contoso.com' 'MailUniversalDistributionGroup') } } 'p1'
                $r.Verdict | Should -Be 'Proposal'
                $r.Cmd | Should -Be "Set-DistributionGroup -Identity 'open@contoso.com' -AcceptMessagesOnlyFromSendersOrMembers 'ann@contoso.com','bob@vendor.example','sub@contoso.com'"
                $r.Detail | Should -Match 'Proposed allow list: the 3 address\(es\) read now \(1 external, 1 nested group\(s\)\)'
                $r.Detail | Should -Match 'It is a snapshot: a member added later is not on it'
                $r.Detail | Should -Match 'does not authenticate an outside sender'
                $r.Detail | Should -Match '-WhatIf first'
                $r.O.Txt | Should -Match "(?m)^\s+> Set-DistributionGroup -Identity 'open@contoso\.com' -AcceptMessagesOnlyFromSendersOrMembers 'ann@contoso\.com','bob@vendor\.example','sub@contoso\.com'$"
                $r.O.Txt | Should -Match 'Allowed senders  \[Proposal\]'
                $r.O.Worksheet.Summary.AllowListsProposed | Should -Be 1
                $r.O.Txt | Should -Match 'Lists with an allow list proposed:\s+1'
                @(Get-CallLog | Where-Object { $_ -like 'WRITE:*' }) | Should -BeNullOrEmpty -Because 'the proposal is text; nothing was set'
            }

            It 'uses each member''s primary address, not its UPN, because an email address is what Microsoft documents as an identifier' {
                $r = & $script:Prop @{ Lists = @(& $script:OpenList); Members = @{ 'open@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com' -With @{ UserPrincipalName = 'ann.upn@contoso.onmicrosoft.com' }) } } 'p2'
                $r.Cmd | Should -Match "'ann@contoso\.com'$"
                $r.Cmd | Should -Not -Match 'ann\.upn'
            }

            It 'lists an address once however many members carry it, ignoring case' {
                $r = & $script:Prop @{ Lists = @(& $script:OpenList); Members = @{ 'open@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com'; New-DlMember 'Ann again' 'ANN@contoso.com'; New-DlMember 'Cy' 'cy@contoso.com') } } 'p3'
                $r.Cmd | Should -Match "-AcceptMessagesOnlyFromSendersOrMembers 'ann@contoso\.com','cy@contoso\.com'$"
            }

            It 'an apostrophe in an address is doubled, and text that looks like a placeholder stays text' {
                $r = & $script:Prop @{ Lists = @(& $script:OpenList); Members = @{ 'open@contoso.com' = @(New-DlMember "O'Brien" "o'brien@vendor.example" 'MailContact'; New-DlMember 'Odd' 'a{Senders}b@vendor.example' 'MailContact') } } 'p4'
                $r.Cmd | Should -Be "Set-DistributionGroup -Identity 'open@contoso.com' -AcceptMessagesOnlyFromSendersOrMembers 'o''brien@vendor.example','a{Senders}b@vendor.example'"
            }

            It 'a member address that cannot be quoted safely withholds the WHOLE command: an allow list with someone left out would reject them' {
                $r = & $script:Prop @{ Lists = @(& $script:OpenList); Members = @{ 'open@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com'; New-DlMember 'Smart' "smart$([char]0x2019)@vendor.example" 'MailContact') } } 'p5'
                $r.Cmd | Should -BeNullOrEmpty
                $r.Verdict | Should -Be 'Context'
                $r.Detail | Should -Match 'cannot be quoted safely'
                $r.Detail | Should -Match 'a command with a member left out would reject that member'
                $r.O.Txt | Should -Not -Match '(?m)^\s+> Set-DistributionGroup -Identity .* -AcceptMessagesOnlyFromSendersOrMembers'
                $r.O.Worksheet.Summary.AllowListsProposed | Should -Be 0
            }

            It 'withholds the command, and says why, whenever a command could reject people it should not' {
                $cases = @(
                    @{ Why = 'senders must already be authenticated'; Match = 'cannot send to it while that is True'
                       List = (New-DlRaw 'Open' 'open@contoso.com'); Members = @(New-DlMember 'Vendor' 'v@vendor.example' 'MailContact') }
                    @{ Why = 'an allow list already exists'; Match = 'already has 1 allowed sender\(s\) and this scan does not propose replacing'
                       List = (& $script:OpenList @{ AcceptMessagesOnlyFromSendersOrMembers = @('Partner Pat') }); Members = @(New-DlMember 'Ann' 'ann@contoso.com') }
                    @{ Why = 'the allowed-senders setting was not returned'; Match = 'did not return the allowed-senders setting'
                       List = (New-DlRaw 'Open' 'open@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false } -Omit @('AcceptMessagesOnlyFromSendersOrMembers', 'AcceptMessagesOnlyFrom', 'AcceptMessagesOnlyFromDLMembers')); Members = @(New-DlMember 'Ann' 'ann@contoso.com') }
                    @{ Why = 'the sender setting was not returned'; Match = 'did not return RequireSenderAuthenticationEnabled'
                       List = (New-DlRaw 'Open' 'open@contoso.com' -Omit @('RequireSenderAuthenticationEnabled')); Members = @(New-DlMember 'Ann' 'ann@contoso.com') }
                    @{ Why = 'the list has no members'; Match = 'has no members'
                       List = (& $script:OpenList); Members = @() }
                    @{ Why = 'a member returned no primary address'; Match = '1 member\(s\) returned no primary address'
                       List = (& $script:OpenList); Members = @((New-DlMember 'Ann' 'ann@contoso.com'), (New-DlMember 'No addr' '' 'MailContact' -Omit @('PrimarySmtpAddress'))) }
                )
                $n = 0
                foreach ($c in $cases) {
                    $n++
                    $r = & $script:Prop @{ Lists = @($c.List); Members = @{ 'open@contoso.com' = @($c.Members) } } "p6-$n"
                    $r.Cmd | Should -BeNullOrEmpty -Because $c.Why
                    $r.Verdict | Should -Be 'Context' -Because $c.Why
                    $r.Detail | Should -Match $c.Match -Because $c.Why
                    $r.O.Txt | Should -Not -Match '(?m)^\s+> Set-DistributionGroup -Identity .* -AcceptMessagesOnlyFromSendersOrMembers' -Because $c.Why
                    $r.O.Worksheet.Summary.AllowListsProposed | Should -Be 0 -Because $c.Why
                }
            }

            It 'a list read only in part is never turned into an allow list: it would reject the members it did not read' {
                Invoke-Scan @{ Lists = @(& $script:OpenList); Members = @{ 'open@contoso.com' = @(1..3 | ForEach-Object { New-DlMember "U$_" "u$_@contoso.com" }) } } @{ MaxMembersPerList = 2 } | Out-Null
                $ws = Get-NRGDistributionListWorksheet -Metadata @{}
                $row = @($ws.Lists[0].Settings | Where-Object { $_.ControlId -eq 'DL-1.2' })[0]
                @($row.Commands).Count | Should -Be 0
                $row.Detail | Should -Match 'only the first 2 members were read and the list has more'
            }

            It 'a list whose members could not be read gets no allow list, not an empty one' {
                $r = & $script:Prop @{ Lists = @(& $script:OpenList); MemberThrow = @{ 'open@contoso.com' = 'object not found' } } 'p7'
                $r.Cmd | Should -BeNullOrEmpty
                $r.Detail | Should -Match 'the members were not read'
            }

            It 'a dynamic list gets none: a snapshot of a calculated membership would not follow who is a member later' {
                $r = & $script:Prop @{ Dynamic = @(New-DlDynamic 'Everyone' 'everyone@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }); Members = @{ 'everyone@contoso.com' = @(New-DlMember 'Dee' 'dee@contoso.com') } } 'p8'
                $r.Cmd | Should -BeNullOrEmpty
                $r.Detail | Should -Match 'dynamic list'
            }

            It 'a command too long for one spreadsheet cell is withheld, in both files' {
                $long = @(1..420 | ForEach-Object { New-DlMember "V$_" ("vendor-with-a-deliberately-long-local-part-number-$_@a-long-external-domain-name.example") 'MailContact' })
                $r = & $script:Prop @{ Lists = @(& $script:OpenList); Members = @{ 'open@contoso.com' = $long } } 'p9'
                $r.Cmd | Should -BeNullOrEmpty
                $r.Detail | Should -Match 'longer than one spreadsheet cell holds'
                $r.O.Txt | Should -Not -Match '(?m)^\s+> Set-DistributionGroup -Identity .* -AcceptMessagesOnlyFromSendersOrMembers'
            }

            It 'the verdict, the finding text and the command read the same in the text file and the CSV' {
                $r = & $script:Prop @{ Lists = @(& $script:OpenList); Members = @{ 'open@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com'; New-DlMember 'Bob' 'bob@vendor.example' 'MailContact') } } 'p10'
                ($r.O.Txt -replace '\s+', ' ') | Should -Match ([regex]::Escape(($r.Detail -replace '\s+', ' ').Trim()))
                $r.O.Txt | Should -Match ([regex]::Escape($r.Cmd))
            }
        }

        Context 'external members are shown, not judged, and are not removed' {
            It 'the DL-2.3 row reports the count as context, with no verdict and no command' {
                $o = & $script:Build @{ Lists = @(New-DlRaw 'Ext' 'ext@contoso.com'); Members = @{ 'ext@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com'; New-DlMember 'Vendor' 'v@vendor.example' 'MailContact') } } 'ctx'
                $row = $o.Csv | Where-Object { $_.RowType -eq 'Setting' -and $_.ControlId -eq 'DL-2.3' }
                $row.Verdict | Should -Be 'Context'
                $row.Current | Should -Be '1 external of 2'
                $row.AdminCommand | Should -BeNullOrEmpty
                $row.Detail | Should -Match 'shown and not judged'
                $o.Txt | Should -Match 'External members  \[Context\]'
            }

            It 'DL-1.1 on a list with external members points at the allowed-senders option instead of requiring authentication' {
                Invoke-Scan @{ Lists = @(
                    New-DlRaw 'Open' 'open@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }
                    New-DlRaw 'Named' 'named@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false; AcceptMessagesOnlyFromSendersOrMembers = @('Partner Pat') }
                    New-DlRaw 'Plain' 'plain@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }); Members = @{
                        'open@contoso.com'  = @(New-DlMember 'Vendor' 'v@vendor.example' 'MailContact'; New-DlMember 'Ann' 'ann@contoso.com')
                        'named@contoso.com' = @(New-DlMember 'Vendor' 'v@vendor.example' 'MailContact')
                        'plain@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com') } } | Out-Null
                (F 'DL-1.1' 'open@*').Detail | Should -Match 'has 1 external member\(s\): requiring authenticated senders would stop them sending to it'
                (F 'DL-1.1' 'named@*').State | Should -Be 'Partial'
                (F 'DL-1.1' 'named@*').Detail | Should -Match 'has 1 external member\(s\)'
                (F 'DL-1.1' 'plain@*').Detail | Should -Not -Match 'external member'
            }
        }

        Context 'a worksheet never reads whole when it is not' {

            It 'says so, in both files and the summary, when -MaxLists left lists out of the worksheet' {
                $o = & $script:Build @{ Lists = @(1..5 | ForEach-Object { New-DlRaw "L$_" "l$_@contoso.com" }) } 'cap' @{ MaxLists = 3 }
                @($o.Worksheet.Lists).Count | Should -Be 3
                ($o.Worksheet.Limitations -join ' ') | Should -Match 'only the first 3 of 5 lists were read'
                ($o.Worksheet.Limitations -join ' ') | Should -Match 'not a clean result for them'
                $o.Worksheet.Summary.ListsBeyondCap | Should -Be 2
                ($o.Txt -replace '\s+', ' ') | Should -Match 'only the first 3 of 5 lists were read'
                $o.Txt | Should -Match 'Lists beyond -MaxLists, NOT in this file:\s+2'
                @($o.Csv | Where-Object { $_.RowType -eq 'Limitation' -and $_.Detail -match 'only the first 3 of 5 lists were read' }).Count | Should -Be 1
            }

            It 'an inventory that completed empty says so; a failed read says "not collected", not "no list"' {
                $o = & $script:Build @{} 'empty'
                ($o.Worksheet.Limitations -join ' ') | Should -Match 'Exchange returned no distribution list'
                $o.Worksheet.Summary.ListCount | Should -Be 0
                $f = & $script:Build @{ Throw = @{ 'Get-DistributionGroup' = 'denied'; 'Get-DynamicDistributionGroup' = 'denied' } } 'failed'
                ($f.Worksheet.Limitations -join ' ') | Should -Not -Match 'Exchange returned no distribution list'
                ($f.Worksheet.Limitations -join ' ') | Should -Match 'Not collected in this run: Lists, DynamicLists'
            }
        }

        It 'DL-2.5: with several approved join settings the command uses the most restrictive, never the first listed' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGStandards -MockWith { $s = & $script:Approved; $s.DistributionListMemberJoinRestriction = @('Open', 'Closed'); $s }
            $o = & $script:Build @{ Lists = @(New-DlRaw 'Gated' 'gated@contoso.com' -With @{ MemberJoinRestriction = 'ApprovalRequired' }) } 'join'
            $row = $o.Csv | Where-Object { $_.RowType -eq 'Setting' -and $_.ControlId -eq 'DL-2.5' }
            $row.Verdict | Should -Be 'Gap'
            $row.AdminCommand | Should -Be "Set-DistributionGroup -Identity 'gated@contoso.com' -MemberJoinRestriction 'Closed'"
            $row.Detail | Should -Match "uses 'Closed', the most restrictive of the approved values"
        }

        It 'DL-3.2: only an entry wider than a /24 (or unparsed) gets a removal command; a compliant entry is never offered for removal' {
            $o = & $script:Build @{ ConnFilter = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = @('203.0.113.0/24', '10.0.0.0/8') }) } 'ipw'
            $row = $o.Worksheet.Tenant | Where-Object { $_.ControlId -eq 'DL-3.2' }
            $row.Verdict | Should -Be 'Gap'
            $rm = @($row.Commands | Where-Object { $_ -match 'Remove=' })
            $rm.Count | Should -Be 1
            $rm[0] | Should -Match "Remove='10\.0\.0\.0/8'"
            ($row.Commands -join ' ') | Should -Not -Match '203\.0\.113\.0'
        }

        It 'DL-3.3: the printed command takes the policy name from its own field, so an apostrophe in the name cannot change which policy it names' {
            $pol = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @() }
                     [pscustomobject]@{ Name = "Bob's Policy"; IsDefault = $false; AllowedSenders = @(); AllowedSenderDomains = @('x.example') })
            $o = & $script:Build @{ AntiSpam = $pol; AntiSpamRules = @([pscustomobject]@{ Name = 'r'; HostedContentFilterPolicy = "Bob's Policy"; State = 'Enabled' }) } 'pol'
            $row = $o.Worksheet.Tenant | Where-Object { $_.ControlId -eq 'DL-3.3' }
            $row.Verdict | Should -Be 'Gap'
            @($row.Commands | Where-Object { $_ -match 'Remove=' }) | Should -Be @("Set-HostedContentFilterPolicy -Identity 'Bob''s Policy' -AllowedSenderDomains @{Remove='x.example'}")
        }

        It 'the CSV carries each recommendation''s explanation once, on a Reference row, not on every setting row' {
            $o = & $script:Build $script:Scn 'csvwhy'
            @($o.Csv | Where-Object { $_.RowType -in 'Setting', 'Tenant bypass' -and $_.Why }) | Should -BeNullOrEmpty
            $refs = @($o.Csv | Where-Object { $_.RowType -eq 'Reference' })
            $refs.Count | Should -BeGreaterThan 5
            @($refs | ForEach-Object { $_.ControlId } | Sort-Object -Unique).Count | Should -Be $refs.Count
            ($refs | Where-Object { $_.ControlId -eq 'DL-1.1' }).Why | Should -Match 'DMARC does not close this'
            ($refs | Where-Object { $_.ControlId -eq 'DL-1.2' }).AlsoSee | Should -Match 'fix-error-code-5-7-136'
        }

        It 'a list synchronized from on-premises gets no Exchange Online command and says where to make the change' {
            $o = & $script:Build @{ Lists = @(New-DlRaw 'Synced' 'synced@contoso.com' -With @{ IsDirSynced = $true; RequireSenderAuthenticationEnabled = $false; ManagedBy = @() }); Members = @{ 'synced@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com') } } 'sync'
            $o.Txt | Should -Match 'Source of truth: Synchronized from on-premises Active Directory'
            @($o.Csv | Where-Object { $_.ListAddress -eq 'synced@contoso.com' -and $_.AdminCommand }) | Should -BeNullOrEmpty
            $o.Txt | Should -Not -Match "Set-DistributionGroup -Identity 'synced@contoso\.com'"
            ($o.Csv | Where-Object { $_.RowType -eq 'Directory' }).Detail | Should -Match 'managed there'
            $o.Worksheet.Summary.AllowListsProposed | Should -Be 0
            # a list that is not synchronized still gets its commands
            $p = & $script:Build @{ Lists = @(New-DlRaw 'Local' 'local@contoso.com' -With @{ IsDirSynced = $false; ManagedBy = @() }) } 'nosync'
            @($p.Csv | Where-Object { $_.ListAddress -eq 'local@contoso.com' -and $_.AdminCommand }).Count | Should -BeGreaterThan 0
        }

        It '"Lists that accept mail from anyone" counts lists by their DL-1.1 verdict, not by a phrase in rendered text' {
            $o = & $script:Build @{ Lists = @(New-DlRaw 'A' 'a@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }; New-DlRaw 'B' 'b@contoso.com' -With @{ RequireSenderAuthenticationEnabled = $false }; New-DlRaw 'C' 'c@contoso.com') } 'anyone'
            $o.Worksheet.Summary.ListsReachableFromOutside | Should -Be 2
            @($o.Worksheet.Lists | Where-Object { $_.AcceptsFromAnyone }).Count | Should -Be 2
        }

        It 'a dynamic list''s member line says its members are the calculated list, which can differ from who receives mail now' {
            $o = & $script:Build @{ Dynamic = @(New-DlDynamic 'Everyone' 'everyone@contoso.com'); Members = @{ 'everyone@contoso.com' = @(New-DlMember 'Dee' 'dee@contoso.com') } } 'dynline'
            $o.Txt | Should -Match 'calculated list Microsoft stores on the group'
            ($o.Worksheet.Limitations -join ' ') | Should -Match 'calculated list Microsoft stores'
        }

        It 'an owner that was not returned reads "not returned", not "none"' {
            $o = & $script:Build @{ Lists = @(New-DlRaw 'Bare' 'bare@contoso.com' -Omit @('ManagedBy')) } 'owners'
            $o.Txt | Should -Match 'Owners:\s+not returned by Exchange'
        }

        It 'explains each recommendation once, with its source, in a reference section' {
            $o = & $script:Build $script:Scn 'ref'
            $o.Txt | Should -Match 'RECOMMENDATION REFERENCE'
            ([regex]::Matches($o.Txt, '(?m)^\[DL-1\.1\] ')).Count | Should -Be 1
        }

        It 'an unreadable collector run still produces an honest worksheet' {
            Clear-NRGState
            Test-NRGDistributionLists
            $ws = Get-NRGDistributionListWorksheet -Metadata @{ TenantDomain = 'x.onmicrosoft.com' }
            ($ws.Limitations -join ' ') | Should -Match 'Not collected in this run: the distribution-list inventory'
            @($ws.Lists).Count | Should -Be 0
            @($ws.Tenant | Where-Object { $_.Verdict -eq 'Met' }) | Should -BeNullOrEmpty
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'orchestrator and connection' {

        BeforeAll {
            $script:Tenant = @{ EXO = $true; TenantId = '11111111-1111-1111-1111-111111111111'; TenantDomain = 'contoso.onmicrosoft.com'; AuthMode = 'Interactive'; Reused = $false }
        }

        It 'connects, collects, evaluates and publishes, then disconnects; exit code 0' {
            Mock -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -MockWith { $script:Tenant }
            Mock -ModuleName 'NRG-Assessment' Disconnect-NRGServices -MockWith { }
            Use-Scenario @{ Lists = @(New-DlRaw 'Sales' 'sales@contoso.com'); Members = @{ 'sales@contoso.com' = @(New-DlMember 'Ann' 'ann@contoso.com') }
                ConnFilter = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = @() }); AntiSpam = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @() }) }
            $r = Invoke-NRGDistributionListScan -OutputPath (Join-Path $TestDrive 'run1') 6>$null
            $r.ExitCode | Should -Be 0
            Test-Path -LiteralPath $r.TextPath | Should -BeTrue
            Test-Path -LiteralPath $r.CsvPath | Should -BeTrue
            Split-Path -Leaf $r.TextPath | Should -Match '^contoso-\d{8}-\d{6}-distribution-lists\.txt$'
            Should -Invoke -ModuleName 'NRG-Assessment' Disconnect-NRGServices -Times 1 -Exactly
            (Get-Content -LiteralPath $r.TextPath -Raw) | Should -Match 'Tenant:\s+contoso\.onmicrosoft\.com \(11111111-1111-1111-1111-111111111111\)'
            @(Get-CallLog | Where-Object { $_ -notmatch '^Get-' }) | Should -BeNullOrEmpty
        }

        It 'when the session names no tenant domain, the worksheet uses the tenant''s routing domain from its accepted domains, never the operator''s' {
            Mock -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -MockWith { @{ EXO = $true; TenantId = '11111111-1111-1111-1111-111111111111'; TenantDomain = '' } }
            Mock -ModuleName 'NRG-Assessment' Disconnect-NRGServices -MockWith { }
            Use-Scenario @{ Accepted = @('contoso.com', 'contoso.mail.onmicrosoft.com', 'contoso.onmicrosoft.com') }
            $r = Invoke-NRGDistributionListScan -OutputPath (Join-Path $TestDrive 'run-derive') -UserPrincipalName 'admin@msp.example' 6>$null
            $r.TenantDomain | Should -Be 'contoso.onmicrosoft.com'
            Split-Path -Leaf $r.TextPath | Should -Match '^contoso-\d{8}-\d{6}-'
            (Get-Content -LiteralPath $r.TextPath -Raw) | Should -Match 'Tenant:\s+contoso\.onmicrosoft\.com'
        }

        It 'with no domain anywhere, the header shows only the tenant id and the file is named "tenant"' {
            Mock -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -MockWith { @{ EXO = $true; TenantId = '11111111-1111-1111-1111-111111111111'; TenantDomain = '' } }
            Mock -ModuleName 'NRG-Assessment' Disconnect-NRGServices -MockWith { }
            Use-Scenario @{ Accepted = @('contoso.com') }
            $r = Invoke-NRGDistributionListScan -OutputPath (Join-Path $TestDrive 'run-nodomain') 6>$null
            Split-Path -Leaf $r.TextPath | Should -Match '^tenant-\d{8}-\d{6}-'
            (Get-Content -LiteralPath $r.TextPath -Raw) | Should -Match '(?m)^Tenant:\s+11111111-1111-1111-1111-111111111111\s*$'
        }

        It '-KeepSession leaves the session open for a caller that wants to reuse it' {
            Mock -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -MockWith { $script:Tenant }
            Mock -ModuleName 'NRG-Assessment' Disconnect-NRGServices -MockWith { }
            Use-Scenario @{}
            Invoke-NRGDistributionListScan -OutputPath (Join-Path $TestDrive 'run2') -KeepSession 6>$null | Out-Null
            Should -Invoke -ModuleName 'NRG-Assessment' Disconnect-NRGServices -Times 0 -Exactly
        }

        It 'a sign-in failure is exit code 1, writes nothing, and still disconnects' {
            Mock -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -MockWith { throw 'Exchange Online sign-in failed: nope' }
            Mock -ModuleName 'NRG-Assessment' Disconnect-NRGServices -MockWith { }
            Use-Scenario @{}
            $r = Invoke-NRGDistributionListScan -OutputPath (Join-Path $TestDrive 'run3') 6>$null
            $r.ExitCode | Should -Be 1
            $r.Error | Should -Match 'sign-in failed'
            Test-Path -LiteralPath (Join-Path $TestDrive 'run3') | Should -BeFalse
            Should -Invoke -ModuleName 'NRG-Assessment' Disconnect-NRGServices -Times 1 -Exactly
            @(Get-CallLog) | Should -BeNullOrEmpty -Because 'nothing may be read when the sign-in failed'
        }

        It 'a section that did not collect is exit code 3, and the worksheet says so instead of reading clean' {
            Mock -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -MockWith { $script:Tenant }
            Mock -ModuleName 'NRG-Assessment' Disconnect-NRGServices -MockWith { }
            Use-Scenario @{ Lists = @(New-DlRaw 'Sales' 'sales@contoso.com'); Throw = @{ 'Get-TransportRule' = 'denied' }
                ConnFilter = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = @() }); AntiSpam = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @() }) }
            $r = Invoke-NRGDistributionListScan -OutputPath (Join-Path $TestDrive 'run4') 6>$null
            $r.ExitCode | Should -Be 3
            (Get-Content -LiteralPath $r.TextPath -Raw) | Should -Match 'Not collected in this run: TransportRules'
        }

        It 'lists left out by -MaxLists are exit code 3 with a console warning, never a clean 0' {
            Mock -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -MockWith { $script:Tenant }
            Mock -ModuleName 'NRG-Assessment' Disconnect-NRGServices -MockWith { }
            Use-Scenario @{ Lists = @(1..5 | ForEach-Object { New-DlRaw "L$_" "l$_@contoso.com" })
                ConnFilter = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = @() }); AntiSpam = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @() }) }
            $r = Invoke-NRGDistributionListScan -OutputPath (Join-Path $TestDrive 'run-cap') -MaxLists 3 6>$null
            $r.ExitCode | Should -Be 3
            (Get-Content -LiteralPath $r.TextPath -Raw) -replace '\s+', ' ' | Should -Match 'only the first 3 of 5 lists were read'
        }

        It 'a completed read that returned no list is exit code 2, and the console and worksheet say so' {
            Mock -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -MockWith { $script:Tenant }
            Mock -ModuleName 'NRG-Assessment' Disconnect-NRGServices -MockWith { }
            Use-Scenario @{ ConnFilter = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = @() }); AntiSpam = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; AllowedSenders = @(); AllowedSenderDomains = @() }) }
            $r = Invoke-NRGDistributionListScan -OutputPath (Join-Path $TestDrive 'run-empty') 6>$null
            $r.ExitCode | Should -Be 2
            (Get-Content -LiteralPath $r.TextPath -Raw) -replace '\s+', ' ' | Should -Match 'Exchange returned no distribution list'
        }

        It 'an app-only sign-in with a primary domain instead of the routing domain says so plainly, and connects to nothing' {
            Mock -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -MockWith { $script:Tenant }
            Mock -ModuleName 'NRG-Assessment' Disconnect-NRGServices -MockWith { }
            Use-Scenario @{}
            $g = '11111111-1111-1111-1111-111111111111'
            $r = Invoke-NRGDistributionListScan -OutputPath (Join-Path $TestDrive 'run-org') -AppId $g -TenantId $g -CertificateThumbprint ('A' * 40) -OrganizationDomain 'client.com' 6>$null
            $r.ExitCode | Should -Be 1
            $r.Error | Should -Match "'client\.com' is not one"
            $r.Error | Should -Match 'onmicrosoft\.com routing domain'
            Should -Invoke -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -Times 0 -Exactly
        }

        It 'a session that is not Exchange Online is exit code 1' {
            Mock -ModuleName 'NRG-Assessment' Connect-NRGExchangeOnly -MockWith { @{ EXO = $false } }
            Mock -ModuleName 'NRG-Assessment' Disconnect-NRGServices -MockWith { }
            Use-Scenario @{}
            (Invoke-NRGDistributionListScan -OutputPath (Join-Path $TestDrive 'run5') 6>$null).ExitCode | Should -Be 1
        }

        Context 'Connect-NRGExchangeOnly signs in to Exchange Online and nothing else' {

            BeforeEach {
                & $script:Mod { $script:ConnLog = [System.Collections.Generic.List[string]]::new(); $script:Sessions = @() }
                Inject 'Connect-ExchangeOnline' '$script:ConnLog.Add("Connect-ExchangeOnline")'
                Inject 'Get-ConnectionInformation' '$script:ConnLog.Add("Get-ConnectionInformation"); foreach ($s in $script:Sessions) { $s }'
                foreach ($n in $script:ConnectSpies) { Inject $n ('$script:ConnLog.Add("' + $n + '")') }
            }
            AfterEach { Remove 'Connect-ExchangeOnline'; Remove 'Get-ConnectionInformation'; foreach ($n in $script:ConnectSpies) { Remove $n } }

            It 'connects to Exchange Online only: no Graph, no Purview, no Teams, no SharePoint' {
                & $script:Mod { $script:Sessions = @([pscustomobject]@{ State = 'Connected'; TenantID = '11111111-1111-1111-1111-111111111111'; Organization = 'contoso.onmicrosoft.com'; Name = 'ExchangeOnline_1' }) }
                $r = Connect-NRGExchangeOnly -UserPrincipalName 'admin@contoso.com'
                $r.EXO | Should -BeTrue
                $r.TenantId | Should -Be '11111111-1111-1111-1111-111111111111'
                $r.TenantDomain | Should -Be 'contoso.onmicrosoft.com'
                $log = @(& $script:Mod { $script:ConnLog.ToArray() })
                $log | Should -Contain 'Connect-ExchangeOnline'
                foreach ($n in $script:ConnectSpies) { $log | Should -Not -Contain $n }
            }

            It 'Organization is empty for an interactive sign-in (Microsoft: set only for certificate and managed-identity connections), so the GDAP routing domain is used, else nothing is invented' {
                & $script:Mod { $script:Sessions = @([pscustomobject]@{ State = 'Connected'; TenantID = '11111111-1111-1111-1111-111111111111'; DelegatedOrganization = 'client.onmicrosoft.com' }) }
                (Connect-NRGExchangeOnly -UserPrincipalName 'admin@msp.com').TenantDomain | Should -Be 'client.onmicrosoft.com'
                & $script:Mod { $script:Sessions = @([pscustomobject]@{ State = 'Connected'; TenantID = '11111111-1111-1111-1111-111111111111'; UserPrincipalName = 'admin@msp.com' }) }
                (Connect-NRGExchangeOnly -UserPrincipalName 'admin@msp.com').TenantDomain | Should -BeNullOrEmpty -Because 'the operator''s own domain is not the client''s'
            }

            It 'refuses a session for another tenant, so a worksheet is never written about the wrong client' {
                & $script:Mod { $script:Sessions = @([pscustomobject]@{ State = 'Connected'; TenantID = '22222222-2222-2222-2222-222222222222'; Organization = 'other.onmicrosoft.com' }) }
                { Connect-NRGExchangeOnly -ExpectedTenantId '11111111-1111-1111-1111-111111111111' } | Should -Throw '*not the requested tenant*'
            }

            It 'reuses an already connected session only when it is verifiably the requested tenant' {
                & $script:Mod { $script:Sessions = @([pscustomobject]@{ State = 'Connected'; TenantID = '11111111-1111-1111-1111-111111111111'; Organization = 'contoso.onmicrosoft.com' }) }
                $r = Connect-NRGExchangeOnly -ExpectedTenantId '11111111-1111-1111-1111-111111111111'
                $r.Reused | Should -BeTrue
                @(& $script:Mod { $script:ConnLog.ToArray() }) | Should -Not -Contain 'Connect-ExchangeOnline'
            }

            It 'with no tenant to compare against, a leftover session is not silently reused' {
                & $script:Mod { $script:Sessions = @([pscustomobject]@{ State = 'Connected'; TenantID = '33333333-3333-3333-3333-333333333333'; Organization = 'leftover.onmicrosoft.com' }) }
                $r = Connect-NRGExchangeOnly
                $r.Reused | Should -BeFalse
                @(& $script:Mod { $script:ConnLog.ToArray() }) | Should -Contain 'Connect-ExchangeOnline'
            }

            It 'a Security & Compliance session for the right tenant is not mistaken for the Exchange Online one' {
                & $script:Mod { $script:Sessions = @(
                    [pscustomobject]@{ State = 'Connected'; TenantID = '11111111-1111-1111-1111-111111111111'; Organization = 'contoso.onmicrosoft.com'; Name = 'ExchangeOnlineProtection_1'; IsEopSession = $true }
                    [pscustomobject]@{ State = 'Connected'; TenantID = '22222222-2222-2222-2222-222222222222'; Organization = 'other.onmicrosoft.com'; Name = 'ExchangeOnline_1' }) }
                # The EOP session matches but is not Exchange Online; the Exchange Online one is another tenant: refuse it, do not reuse the wrong one.
                { Connect-NRGExchangeOnly -ExpectedTenantId '11111111-1111-1111-1111-111111111111' } | Should -Throw '*not the requested tenant*'
                @(& $script:Mod { $script:ConnLog.ToArray() }) | Should -Contain 'Connect-ExchangeOnline' -Because 'the matching EOP session was not accepted as a reusable Exchange Online session'
            }

            It 'cannot confirm a tenant it cannot read, and says nothing was collected' {
                & $script:Mod { $script:Sessions = @() }
                { Connect-NRGExchangeOnly -ExpectedTenantId '11111111-1111-1111-1111-111111111111' } | Should -Throw '*cannot be confirmed*'
            }

            It 'rejects malformed identifiers before any connection is attempted' {
                { Connect-NRGExchangeOnly -ExpectedTenantId 'not-a-guid' } | Should -Throw
                { Connect-NRGExchangeOnly -UserPrincipalName "a@b.com'; calc; '" } | Should -Throw
                @(& $script:Mod { $script:ConnLog.ToArray() }) | Should -Not -Contain 'Connect-ExchangeOnline'
            }
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'shared helpers' {

        It 'Get-NRGExoPreflightNotes reports an unsupported PowerShell, the Store build, and a module outside this PowerShell''s range' {
            $f76 = Get-NRGExoModuleFloor -PSVersion ([version]'7.6.6') -PSHomePath 'C:\Program Files\PowerShell\7'
            @(Get-NRGExoPreflightNotes -Floor $f76 -InstalledVersion ([version]'3.10.0')).Count | Should -Be 0
            @(Get-NRGExoPreflightNotes -Floor $f76 -InstalledVersion $null).Count | Should -Be 0
            $old = @(Get-NRGExoPreflightNotes -Floor $f76 -InstalledVersion ([version]'3.9.2'))
            $old.Count | Should -Be 1; $old[0].Level | Should -Be 'Error'
            $old[0].Text | Should -Match '3\.9\.2 is older than the 3\.10\.0 this PowerShell needs'
            $f74 = Get-NRGExoModuleFloor -PSVersion ([version]'7.4.6') -PSHomePath 'C:\Program Files\PowerShell\7'
            $new = @(Get-NRGExoPreflightNotes -Floor $f74 -InstalledVersion ([version]'3.10.0'))
            $new.Count | Should -Be 1; $new[0].Level | Should -Be 'Warning'; $new[0].Text | Should -Match 'newer than PowerShell'
            @(Get-NRGExoPreflightNotes -Floor $f74 -InstalledVersion ([version]'3.8.0')).Count | Should -Be 0
            $f72 = Get-NRGExoModuleFloor -PSVersion ([version]'7.2.24') -PSHomePath 'C:\Program Files\PowerShell\7'
            $u = @(Get-NRGExoPreflightNotes -Floor $f72 -InstalledVersion ([version]'3.9.0'))
            $u.Count | Should -Be 1 -Because 'an unsupported PowerShell is one error, not also a version complaint'
            $u[0].Level | Should -Be 'Error'
            $store = Get-NRGExoModuleFloor -PSVersion ([version]'7.6.6') -PSHomePath 'C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe'
            $st = @(Get-NRGExoPreflightNotes -Floor $store -InstalledVersion $null)
            $st.Count | Should -Be 1; $st[0].Level | Should -Be 'Warning'; $st[0].Text | Should -Match 'Microsoft Store build'
        }

        It 'Get-NRGInForcePolicies uses the accepted domains it is handed when there is no EXO-MailboxConfig, and behaves as before when it is not' {
            Clear-NRGState
            $pols = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true }, [pscustomobject]@{ Name = 'All'; IsDefault = $false })
            $rules = @([pscustomobject]@{ Name = 'r'; HostedContentFilterPolicy = 'All'; State = 'Enabled'; RecipientDomainIs = @('contoso.com'); SentTo = @(); SentToMemberOf = @(); HasExceptions = $false })
            $with = & $script:Mod { param($p, $r) @(Get-NRGInForcePolicies -Policies $p -Rules $r -RulePolicyKey 'HostedContentFilterPolicy' -PresetKind 'EOP' -AcceptedDomains @('contoso.com')) | ForEach-Object { $_.Name } } $pols $rules
            @($with) | Should -Be @('All')
            $without = & $script:Mod { param($p, $r) @(Get-NRGInForcePolicies -Policies $p -Rules $r -RulePolicyKey 'HostedContentFilterPolicy' -PresetKind 'EOP') | ForEach-Object { $_.Name } } $pols $rules
            @($without | Sort-Object) | Should -Be @('All', 'Default') -Because 'with no accepted domains known, the default policy is never dropped'
        }
    }

    Context 'read-only guarantees [Static]' {

        BeforeAll {
            $script:ScanFiles = @(
                'Collectors/EXO/Invoke-NRGCollectDistributionLists.ps1', 'Evaluators/Test-NRGDistributionLists.ps1', 'Lib/Get-NRGDistributionListBaseline.ps1',
                'Lib/Get-NRGDistributionListWorksheet.ps1', 'Publishers/Publish-NRGDistributionListWorksheet.ps1', 'Lib/Invoke-NRGDistributionListScan.ps1', 'Lib/Connect-NRGExchangeOnly.ps1')
            $script:Ast = @{}
            foreach ($f in $script:ScanFiles) {
                $e = $null; $t = $null
                $script:Ast[$f] = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root $f), [ref]$t, [ref]$e)
                if ($e -and $e.Count) { throw "$f does not parse: $($e[0].Message)" }
            }
            $script:Commands = {
                param($f) @($script:Ast[$f].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
            }
            # Local utilities and the module's own reviewed helpers the scan files may call. Anything else must be a Get-* read.
            $script:Benign = @('Where-Object', 'ForEach-Object', 'Select-Object', 'Sort-Object', 'Group-Object', 'Measure-Object', 'Out-Null', 'Write-Host', 'Write-Verbose', 'Write-Warning',
                'Start-Sleep', 'Join-Path', 'Split-Path', 'ConvertTo-Csv', 'ConvertTo-Json', 'Test-Path', 'Select-String', 'Import-Module', 'Register-NRGException', 'Register-NRGCoverage',
                'Set-NRGRawData', 'Add-NRGFinding', 'Set-NRGSensitiveFileContent', 'Clear-NRGState', 'Disconnect-NRGServices', 'Connect-NRGExchangeOnly', 'Connect-ExchangeOnline',
                'Test-NRGDistributionLists', 'Invoke-NRGCollectDistributionLists', 'Publish-NRGDistributionListWorksheet', 'Format-Table', 'ConvertFrom-Json')
        }

        It 'every command in the scan files is a Get-* read, a reviewed NRG helper, or a local utility' {
            $offenders = foreach ($f in $script:ScanFiles) {
                foreach ($c in (& $script:Commands $f | Sort-Object -Unique)) {
                    if ($c -match '^Get-' -or $c -in $script:Benign -or $c -match '(?i)NRG') { continue }
                    "$f -> $c"
                }
            }
            @($offenders) | Should -BeNullOrEmpty -Because 'a command the scan files call that is not a read is a write path; add it to the reviewed list only after reading it'
        }

        It 'no scan file contains a typographic quote or a Unicode line separator: PowerShell reads U+2018 .. U+201B as quote characters, even inside a single-quoted string' {
            # A character class typed with those characters is parsed as quotes and silently stops refusing them, which is how
            # the first version of the command-quoting guard let U+2018 through while still passing a test on U+2019.
            $bad = foreach ($f in $script:ScanFiles) {
                $text = Get-Content -LiteralPath (Join-Path $script:Root $f) -Raw -Encoding utf8
                foreach ($cp in 0x2018, 0x2019, 0x201A, 0x201B, 0x201C, 0x201D, 0x0085, 0x2028, 0x2029) {
                    if ($text.Contains([string][char]$cp)) { '{0}: U+{1:X4}' -f $f, $cp }
                }
            }
            @($bad) | Should -BeNullOrEmpty
        }

        It 'no scan file calls a write cmdlet that Exchange, Graph or the file system offers' {
            $write = '^(Set|New|Remove|Add|Enable|Disable|Update|Clear|Grant|Revoke|Restore|Move|Rename|Invoke-(Expression|Command|WebRequest|RestMethod)|Start-Process|Out-File|Export|Copy|Save|Send|Reset)-(?!NRG)'
            $hits = foreach ($f in $script:ScanFiles) { foreach ($c in (& $script:Commands $f)) { if ($c -match $write -and $c -notin @('Add-NRGFinding', 'Add-NRGDlFinding')) { "$f -> $c" } } }
            @($hits) | Should -BeNullOrEmpty
        }

        It 'the only Exchange cmdlet names the collector resolves are Get-* reads' {
            $src = Get-Content -LiteralPath (Join-Path $script:Root 'Collectors/EXO/Invoke-NRGCollectDistributionLists.ps1') -Raw
            $names = @([regex]::Matches($src, "Get-NRGExoCommand\s+-Name\s+'([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
            $names.Count | Should -BeGreaterThan 8
            @($names | Where-Object { $_ -notmatch '^Get-' }) | Should -BeNullOrEmpty
            $names | Should -Contain 'Get-DistributionGroupMember'
            $names | Should -Contain 'Get-TransportRule'
        }

        It 'the collector invokes a resolved command in exactly one place, behind the throttle-retry helper' {
            $ast = $script:Ast['Collectors/EXO/Invoke-NRGCollectDistributionLists.ps1']
            $dyn = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq 'Ampersand' -and -not $n.GetCommandName() }, $true))
            @($dyn | Where-Object { $_.Extent.Text -notmatch '^& \$(Command|fail|cell|mk)\b' }) | Should -BeNullOrEmpty
            @($dyn | Where-Object { $_.Extent.Text -match '^& \$Command' }).Count | Should -Be 1
        }

        It 'the publisher writes only through the restricted-file writer, and never emits a script' {
            $src = Get-Content -LiteralPath (Join-Path $script:Root 'Publishers/Publish-NRGDistributionListWorksheet.ps1') -Raw
            $code = ($src -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $code | Should -Not -Match 'Out-File|Set-Content|Add-Content|Export-Csv|WriteAllText|Invoke-Expression|\.ps1''|"\.ps1'
            $code | Should -Match 'Set-NRGSensitiveFileContent'
        }

        It 'the entry point''s -DistributionListsOnly block signs in to nothing but Exchange and runs before the Graph prerequisite check' {
            $src = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-NRGAssessment.ps1') -Raw
            $src | Should -Match '\[switch\]\s+\$DistributionListsOnly'
            $start = $src.IndexOf('if ($DistributionListsOnly) {')
            $start | Should -BeGreaterThan 0
            $end = $src.IndexOf('exit ([int]$dlResult.ExitCode)', $start)
            $end | Should -BeGreaterThan $start
            $block = $src.Substring($start, $end - $start)
            $block | Should -Match 'Invoke-NRGDistributionListScan'
            $block | Should -Not -Match 'Connect-NRGServices|Connect-MgGraph|Connect-IPPSSession|Connect-MicrosoftTeams|Connect-SPOService'
            $start | Should -BeLessThan $src.IndexOf('$moduleSpecs = @(') -Because 'the Graph / Teams prerequisite check must not gate an Exchange-only scan'
            $start | Should -BeGreaterThan $src.IndexOf('Start-NRGWebServer')
        }

        It 'the entry point refuses an unconfirmable tenant, falls back to the routing domain for app-only, and shares the Exchange preflight wording' {
            $src = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-NRGAssessment.ps1') -Raw
            $start = $src.IndexOf('if ($DistributionListsOnly) {')
            $end = $src.IndexOf('exit ([int]$dlResult.ExitCode)', $start)
            $block = $src.Substring($start, $end - $start)
            $block | Should -Match 'Could not resolve a tenant ID for \$TenantDomain'
            $block.IndexOf('Could not resolve a tenant ID') | Should -BeLessThan $block.IndexOf('Invoke-NRGDistributionListScan @dlParams') -Because 'the refusal must come before any sign-in'
            $block | Should -Match '-not \$dlAppOnly -and -not \$targetTenantId'
            $block | Should -Match '\$targetDelegatedOrg'
            $block | Should -Match 'Get-NRGExoPreflightNotes'
            $block | Should -Match "Level -eq 'Error'"
            $src | Should -Match 'Get-NRGExoPreflightNotes -Floor \$exoFloor -InstalledVersion \$null' -Because 'the full run reads the same floor and Store-build wording'
        }

        It 'the catalog holds the write commands as data, in no file the module loads for execution' {
            $loaded = @(Get-ChildItem -LiteralPath $script:Root -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -match '[\\/](Lib|Collectors|Evaluators|Publishers)[\\/]' })
            foreach ($f in $loaded) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                $bad = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Set-DistributionGroup', 'Set-DynamicDistributionGroup', 'Remove-DistributionGroupMember', 'Add-DistributionGroupMember', 'Disable-TransportRule', 'Set-HostedConnectionFilterPolicy', 'Set-HostedContentFilterPolicy') }, $true))
                $bad | Should -BeNullOrEmpty -Because "$($f.Name) must not call a distribution-list write cmdlet"
            }
            (Get-Content -LiteralPath (Join-Path $script:Root 'Config/distribution-list-baseline.json') -Raw) | Should -Match 'Set-DistributionGroup -Identity \{List\}'
        }
    }
}

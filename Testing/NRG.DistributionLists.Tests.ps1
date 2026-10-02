#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.DistributionLists.Tests.ps1: NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Pins the distribution-list scan (Invoke-NRGDistributionListScan.ps1):
             the Exchange-only connection, the read-only collector, the DL-* evaluators and
             the worksheet publisher.

             Fixtures carry the RAW shapes Exchange returns (recipient objects, empty and
             omitted properties, the 1000-row default, throttling errors), and the evaluator
             cases run through the REAL collector, so the member parser and the setting
             parsing are exercised, not fed pre-computed fields. The one boundary that is
             stubbed is the Exchange Online session (Get-NRGExoCommand and the Get-*
             cmdlets it hands back).

             The honesty rules under test: an empty or failed section is never "clean"; a
             value Exchange did not return is "not assessed", never the safe value; the
             collector and evaluators call only read (Get-*) cmdlets; the worksheet's
             commands are text, are never executed, and live in a config file rather than in
             any file the module runs; members are listed by UPN and display name only.
    Data keys consumed: EXO-DistributionLists. Graph scopes / cmdlets: none.
#>

Describe 'Distribution-list scan' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        # ── The Exchange boundary ────────────────────────────────────────────────
        # The stubs and the Get-NRGExoCommand mock run inside the module (or as global functions),
        # which cannot see this file's script scope. They read one state object that the test
        # parks in the AppDomain (the same reference as $script:Ex), so no global variable is used.
        function global:NRGTest-GetDistributionGroup {
            [CmdletBinding()]
            param($ResultSize, [switch] $IncludeManagedByWithDisplayNames, [switch] $IncludeAcceptMessagesOnlyFromWithDisplayNames,
                  [switch] $IncludeAcceptMessagesOnlyFromDLMembersWithDisplayNames, [switch] $IncludeAcceptMessagesOnlyFromSendersOrMembersWithDisplayNames,
                  [switch] $IncludeModeratedByWithDisplayNames)
            $st = [AppDomain]::CurrentDomain.GetData('NRGDL')
            $st.Calls.Add(@{ Cmd = 'Get-DistributionGroup'; ResultSize = $ResultSize; Switches = @($PSBoundParameters.Keys | Where-Object { $_ -like 'Include*' } | Sort-Object) })
            if ($st.GroupError) { throw $st.GroupError }
            @($st.Groups)
        }
        function global:NRGTest-GetDynamicDistributionGroup {
            [CmdletBinding()]
            param($ResultSize)
            $st = [AppDomain]::CurrentDomain.GetData('NRGDL')
            $st.Calls.Add(@{ Cmd = 'Get-DynamicDistributionGroup'; ResultSize = $ResultSize })
            if ($st.DynamicError) { throw $st.DynamicError }
            @($st.Dynamic)
        }
        $script:NewStubs = {
            @{
                'Get-AcceptedDomain'                 = { [CmdletBinding()] param()
                    $st = [AppDomain]::CurrentDomain.GetData('NRGDL')
                    $st.Calls.Add(@{ Cmd = 'Get-AcceptedDomain' })
                    if ($st.AcceptedError) { throw $st.AcceptedError }
                    @($st.Accepted) }
                'Get-DistributionGroup'              = 'NRGTest-GetDistributionGroup'
                'Get-DynamicDistributionGroup'       = 'NRGTest-GetDynamicDistributionGroup'
                'Get-DistributionGroupMember'        = { [CmdletBinding()] param($Identity, $ResultSize)
                    $st = [AppDomain]::CurrentDomain.GetData('NRGDL')
                    $st.Calls.Add(@{ Cmd = 'Get-DistributionGroupMember'; Identity = $Identity; ResultSize = $ResultSize })
                    $plan = $st.MemberPlan[[string]$Identity]
                    $n = 0; if ($st.Attempts.ContainsKey([string]$Identity)) { $n = $st.Attempts[[string]$Identity] }
                    $st.Attempts[[string]$Identity] = $n + 1
                    if ($plan -is [array] -and $n -lt $plan.Count -and $plan[$n] -is [string]) { throw $plan[$n] }
                    $rows = @($st.Members[[string]$Identity])
                    if ($ResultSize -is [int]) { $rows = @($rows | Select-Object -First $ResultSize) }
                    $rows }
                'Get-DynamicDistributionGroupMember' = { [CmdletBinding()] param($Identity, $ResultSize)
                    $st = [AppDomain]::CurrentDomain.GetData('NRGDL')
                    $st.Calls.Add(@{ Cmd = 'Get-DynamicDistributionGroupMember'; Identity = $Identity; ResultSize = $ResultSize })
                    $rows = @($st.Members[[string]$Identity])
                    if ($ResultSize -is [int]) { $rows = @($rows | Select-Object -First $ResultSize) }
                    $rows }
            }
        }
        Mock Get-NRGExoCommand -ModuleName 'NRG-Assessment' -MockWith {
            $st = [AppDomain]::CurrentDomain.GetData('NRGDL')
            $st.Resolved.Add(@{ Name = $Name; Session = $Session })
            $stub = $null
            if ($st.Stubs.ContainsKey($Name)) { $stub = $st.Stubs[$Name] }
            if ($stub -is [string]) { $stub = Get-Command -Name $stub }
            [pscustomobject]@{ Command = $stub; Source = $st.Source }
        }
        Mock Wait-NRGDLBackoff -ModuleName 'NRG-Assessment' -MockWith { }

        function script:ResetExchange {
            $script:Ex = @{
                Stubs = $null; Source = 'ExchangeOnline'
                Calls = [System.Collections.Generic.List[object]]::new()
                Resolved = [System.Collections.Generic.List[object]]::new()
                Accepted = @([pscustomobject]@{ DomainName = 'contoso.com'; InitialDomain = $false; Default = $true },
                             [pscustomobject]@{ DomainName = 'contoso.onmicrosoft.com'; InitialDomain = $true; Default = $false })
                AcceptedError = $null; GroupError = $null; DynamicError = $null
                Groups = @(); Dynamic = @(); Members = @{}; MemberPlan = @{}; Attempts = @{}
            }
            $script:Ex.Stubs = & $script:NewStubs
            [AppDomain]::CurrentDomain.SetData('NRGDL', $script:Ex)
            Clear-NRGState
        }

        # A group exactly as Get-DistributionGroup returns it; -Omit drops properties the way Exchange does.
        function script:RawGroup {
            param([hashtable] $Over = @{}, [string[]] $Omit = @())
            $h = [ordered]@{
                Name = 'all-staff'; DisplayName = 'All Staff'; PrimarySmtpAddress = 'all-staff@contoso.com'
                Guid = '11111111-1111-1111-1111-111111111111'; RecipientTypeDetails = 'MailUniversalDistributionGroup'
                ManagedBy = @('contoso.onmicrosoft.com/Users/Alex Owner')
                RequireSenderAuthenticationEnabled = $true
                AcceptMessagesOnlyFrom = @(); AcceptMessagesOnlyFromDLMembers = @(); AcceptMessagesOnlyFromSendersOrMembers = @()
                ModerationEnabled = $false; ModeratedBy = @()
                MemberJoinRestriction = 'Closed'; MemberDepartRestriction = 'Open'; HiddenFromAddressListsEnabled = $false
            }
            foreach ($k in $Over.Keys) { $h[$k] = $Over[$k] }
            foreach ($k in $Omit) { $h.Remove($k) }
            [pscustomobject]$h
        }
        # A recipient as Get-DistributionGroupMember returns it, with attributes the worksheet must never carry.
        function script:RawMember {
            param([string] $Details, [string] $Name, [string] $Smtp, [string] $External = '', [string] $Upn = '')
            $h = [ordered]@{
                RecipientType = $(if ($Details -eq 'UserMailbox') { 'UserMailbox' } elseif ($Details -eq 'MailContact') { 'MailContact' } elseif ($Details -like '*Group') { $Details } else { 'MailUser' })
                RecipientTypeDetails = $Details; DisplayName = $Name; Name = $Name; PrimarySmtpAddress = $Smtp
                Phone = '701-555-0100'; Office = 'HQ'; Title = 'Director'; Manager = 'someone@contoso.com'
            }
            if ($External) { $h['ExternalEmailAddress'] = "SMTP:$External" }
            if ($Upn)      { $h['WindowsLiveID'] = $Upn }
            [pscustomobject]$h
        }
        $script:Alex  = { RawMember 'UserMailbox' 'Alex Owner' 'alex@contoso.com' -Upn 'alex@contoso.com' }
        $script:Vendor = { RawMember 'MailContact' 'Vendor Contact' 'vendor.contact@fabrikam.example' -External 'vendor.contact@fabrikam.example' }

        # Collect + evaluate through the real code against the stubbed session.
        function script:RunScan {
            param([hashtable] $CollectorArgs = @{})
            $null = Invoke-NRGCollectDistributionLists @CollectorArgs
            Test-NRGDistributionListControls
            @(Get-NRGFindings)
        }
        function script:ForControl { param($Findings, [string] $Id, $Instance = $null)
            @($Findings | Where-Object { $_.ControlId -eq $Id -and ($null -eq $Instance -or $_.Instance -eq $Instance) }) }
    }

    AfterAll {
        Remove-Item function:global:NRGTest-GetDistributionGroup, function:global:NRGTest-GetDynamicDistributionGroup -ErrorAction SilentlyContinue
        [AppDomain]::CurrentDomain.SetData('NRGDL', $null)
        Clear-NRGState
    }
    BeforeEach { ResetExchange }

    # ══════════════════════════════════════════════════════════════════════════
    Context 'pure helpers' {

        It 'who can send: authenticated senders only' {
            $sa = & $script:Mod { Get-NRGDistributionListSenderAccess -List ([pscustomobject]@{ RequireSenderAuthenticationEnabled = $true; AcceptMessagesOnlyFrom = @() }) }
            $sa.Mode | Should -Be 'AuthenticatedOnly'
            $sa.Summary | Should -Match 'inside the organization'
        }
        It 'who can send: open to outside senders, and the summary says so' {
            $sa = & $script:Mod { Get-NRGDistributionListSenderAccess -List ([pscustomobject]@{ RequireSenderAuthenticationEnabled = $false; AcceptMessagesOnlyFrom = @(); AcceptMessagesOnlyFromDLMembers = @(); AcceptMessagesOnlyFromSendersOrMembers = @(); ModerationEnabled = $false }) }
            $sa.Mode | Should -Be 'OpenToOutside'
            $sa.Summary | Should -Match 'outside the organization'
            $sa.AllowListKnown | Should -BeTrue
        }
        It 'a string "False" is false, not true ([bool]"False" is $true)' {
            $sa = & $script:Mod { Get-NRGDistributionListSenderAccess -List ([pscustomobject]@{ RequireSenderAuthenticationEnabled = 'False' }) }
            $sa.Mode | Should -Be 'OpenToOutside'
            $sa.AllowListKnown | Should -BeFalse
            $sa.Summary | Should -Match 'could not be confirmed'
        }
        It 'an omitted setting is Unknown, never the safe value' {
            $sa = & $script:Mod { Get-NRGDistributionListSenderAccess -List ([pscustomobject]@{ Name = 'x' }) }
            $sa.Mode | Should -Be 'Unknown'
            $sa.Summary | Should -Match 'Not read'
        }
        It 'an allow-list wins, names are shown, and GUID-only entries are counted not printed' {
            $guid = '22222222-2222-2222-2222-222222222222'
            $sa = & $script:Mod { param($g) Get-NRGDistributionListSenderAccess -List ([pscustomobject]@{
                RequireSenderAuthenticationEnabled = $false
                AcceptMessagesOnlyFromSendersOrMembers = @($g, 'ceo-guid')
                AcceptMessagesOnlyFromSendersOrMembersWithDisplayNames = @('Pat CEO (pat@contoso.com)') }) } $guid
            $sa.Mode | Should -Be 'AllowList'
            $sa.AllowListNames | Should -Contain 'Pat CEO (pat@contoso.com)'
            $sa.Summary | Should -Not -Match $guid
            $sa.Summary | Should -Match 'not limited to authenticated senders'
        }
        It 'moderation turns an open list into OpenToOutsideModerated' {
            $sa = & $script:Mod { Get-NRGDistributionListSenderAccess -List ([pscustomobject]@{ RequireSenderAuthenticationEnabled = $false; AcceptMessagesOnlyFrom = @(); ModerationEnabled = $true; ModeratedBy = @('Mo Derator') }) }
            $sa.Mode | Should -Be 'OpenToOutsideModerated'
            $sa.Summary | Should -Match 'Mo Derator'
        }

        It 'member class: a mailbox in an accepted domain is Internal' {
            $c = & $script:Mod { param($m) Get-NRGDistributionListMemberClass -Member $m -AcceptedDomains @('contoso.com') } (RawMember 'UserMailbox' 'Alex' 'alex@contoso.com' -Upn 'alex@contoso.com')
            $c.Class | Should -Be 'Internal'
        }
        It 'member class: a mail contact is judged by where mail is delivered (ExternalEmailAddress)' {
            $c = & $script:Mod { param($m) Get-NRGDistributionListMemberClass -Member $m -AcceptedDomains @('contoso.com') } (RawMember 'MailContact' 'V' 'v@contoso.com' -External 'v@fabrikam.example')
            $c.Class | Should -Be 'External'
        }
        It 'member class: a guest is External by type' {
            $c = & $script:Mod { param($m) Get-NRGDistributionListMemberClass -Member $m -AcceptedDomains @('contoso.com') } (RawMember 'GuestMailUser' 'G' 'g@contoso.com' -Upn 'g_partner.com#EXT#@contoso.onmicrosoft.com')
            $c.Class | Should -Be 'External'
        }
        It 'member class: a blank address is Unresolved, not Internal (Get-NRGRecipientClass would say Internal)' {
            $c = & $script:Mod { param($m) Get-NRGDistributionListMemberClass -Member $m -AcceptedDomains @('contoso.com') } (RawMember 'MailUser' 'No Address' '')
            $c.Class | Should -Be 'Unresolved'
        }
        It 'member class: with no accepted domains nothing is classified (Get-NRGRecipientClass would call everything External)' {
            $c = & $script:Mod { param($m) Get-NRGDistributionListMemberClass -Member $m -AcceptedDomains @() } (RawMember 'UserMailbox' 'Alex' 'alex@contoso.com')
            $c.Class | Should -Be 'Unresolved'
            $c.Class | Should -Not -Be 'External'
        }
        It 'member class: a nested group is a group, not a person' {
            $c = & $script:Mod { param($m) Get-NRGDistributionListMemberClass -Member $m -AcceptedDomains @('contoso.com') } (RawMember 'MailUniversalDistributionGroup' 'Sales' 'sales@contoso.com')
            $c.IsGroup | Should -BeTrue
        }

        It 'quoting: an address is single-quoted, an apostrophe is doubled' {
            (& $script:Mod { ConvertTo-NRGDLQuotedLiteral -Value "o'brien@contoso.com" }) | Should -Be "'o''brien@contoso.com'"
        }
        It 'quoting: anything that could break out of the quotes is refused (returns $null, never a command)' -ForEach @(
            @{ V = "a@contoso.com'; Remove-Mailbox x" }
            @{ V = "a@contoso.com`nRemove-Mailbox x" }
            @{ V = "a`$(whoami)@contoso.com;x" }
            @{ V = "a@contoso.com$([char]0x2019); calc" }   # typographic quote: PowerShell treats it as an apostrophe
            @{ V = 'two words@contoso.com' }
            @{ V = '' }
        ) {
            (& $script:Mod { param($v) ConvertTo-NRGDLQuotedLiteral -Value $v } $V) | Should -BeNullOrEmpty
        }
        It 'text: newlines, bidirectional overrides and zero-width characters are removed' {
            $evil = "Pay`r`nroll$([char]0x202E)gnp.exe$([char]0x200B)"
            $t = & $script:Mod { param($v) ConvertTo-NRGDLText -Value $v } $evil
            $t | Should -Not -Match "[\r\n$([char]0x202E)$([char]0x200B)]"
            $t | Should -Be 'Pay rollgnp.exe'
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Context 'collector: reads lists and members, read-only, through the Exchange Online session' {

        It 'reads distribution, security and dynamic lists, with members, and every section reports Collected' {
            $script:Ex.Groups = @(
                (RawGroup @{}),
                (RawGroup @{ Name = 'sec'; DisplayName = 'Finance Security'; PrimarySmtpAddress = 'finance@contoso.com'; Guid = '22222222-2222-2222-2222-222222222222'; RecipientTypeDetails = 'MailUniversalSecurityGroup' }))
            $script:Ex.Dynamic = @([pscustomobject]@{ Name = 'dyn'; DisplayName = 'Everyone'; PrimarySmtpAddress = 'everyone@contoso.com'; Guid = '33333333-3333-3333-3333-333333333333'; RecipientTypeDetails = 'DynamicDistributionGroup'; RecipientFilter = "(RecipientType -eq 'UserMailbox')"; RequireSenderAuthenticationEnabled = $true; ManagedBy = @() })
            $script:Ex.Members['11111111-1111-1111-1111-111111111111'] = @((& $script:Alex), (& $script:Vendor), (RawMember 'MailUniversalDistributionGroup' 'Sales' 'sales@contoso.com'))
            $script:Ex.Members['22222222-2222-2222-2222-222222222222'] = @((& $script:Alex))
            $script:Ex.Members['33333333-3333-3333-3333-333333333333'] = @((& $script:Alex))
            $r = Invoke-NRGCollectDistributionLists
            $r.Success | Should -BeTrue
            $r.Data.SectionStatus.AcceptedDomains | Should -Be 'Collected'
            $r.Data.SectionStatus.DistributionGroups | Should -Be 'Collected'
            $r.Data.SectionStatus.DynamicGroups | Should -Be 'Collected'
            $r.Data.SectionStatus.Members | Should -Be 'Collected'
            @($r.Data.Lists).Count | Should -Be 3
            $r.Data.Stats.DistributionGroups | Should -Be 1
            $r.Data.Stats.MailEnabledSecurityGroups | Should -Be 1
            $r.Data.Stats.DynamicGroups | Should -Be 1
            $r.Data.TenantInitialDomain | Should -Be 'contoso.onmicrosoft.com'
            $all = $r.Data.Lists | Where-Object { $_['PrimarySmtpAddress'] -eq 'all-staff@contoso.com' }
            $all['MembersStatus'] | Should -Be 'Read'
            $all['MemberCount'] | Should -Be 2
            @($all['ExternalMembers']).Count | Should -Be 1
            @($all['ExternalMembers'])[0]['UserPrincipalName'] | Should -Be 'vendor.contact@fabrikam.example'
            @($all['NestedGroups']).Count | Should -Be 1
            ($r.Data.Lists | Where-Object { $_['PrimarySmtpAddress'] -eq 'everyone@contoso.com' })['Kind'] | Should -Be 'Dynamic distribution list'
            Get-NRGRawData -Key 'EXO-DistributionLists' | Should -Not -BeNullOrEmpty
        }

        It 'members carry a display name and one identifier and NOTHING else (no phone, office, title, manager)' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.Members['11111111-1111-1111-1111-111111111111'] = @((& $script:Alex), (& $script:Vendor))
            $r = Invoke-NRGCollectDistributionLists
            $list = @($r.Data.Lists)[0]
            foreach ($m in @($list['Members']) + @($list['ExternalMembers'])) {
                @($m.Keys | Sort-Object) | Should -Be @('DisplayName', 'UserPrincipalName')
            }
            $json = $r | ConvertTo-Json -Depth 12
            $json | Should -Not -Match '701-555-0100|Director|someone@contoso.com|"Office"'
        }

        It 'asks Exchange for ALL lists (the default is 1000) and for the member cap plus one, so a larger list reads as truncated' {
            $script:Ex.Groups = @(RawGroup)
            $null = Invoke-NRGCollectDistributionLists -MemberLimit 5
            @($script:Ex.Calls | Where-Object { $_.Cmd -eq 'Get-DistributionGroup' })[0].ResultSize | Should -Be 'Unlimited'
            @($script:Ex.Calls | Where-Object { $_.Cmd -eq 'Get-DynamicDistributionGroup' })[0].ResultSize | Should -Be 'Unlimited'
            @($script:Ex.Calls | Where-Object { $_.Cmd -eq 'Get-DistributionGroupMember' })[0].ResultSize | Should -Be 6
        }

        It 'a list larger than the cap is Truncated, never Read, and the count is the cap' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.Members['11111111-1111-1111-1111-111111111111'] = @(1..12 | ForEach-Object { RawMember 'UserMailbox' "User $_" "u$_@contoso.com" -Upn "u$_@contoso.com" })
            $r = Invoke-NRGCollectDistributionLists -MemberLimit 5
            $l = @($r.Data.Lists)[0]
            $l['MembersStatus'] | Should -Be 'Truncated'
            $l['MemberCount'] | Should -Be 5
            $l['MembersNote'] | Should -Match 'first 5'
            $r.Data.Stats.MemberReadsTruncated | Should -Be 1
        }

        It 'the display-name switches are passed only when the module has them' {
            $script:Ex.Groups = @(RawGroup)
            $null = Invoke-NRGCollectDistributionLists
            @($script:Ex.Calls | Where-Object { $_.Cmd -eq 'Get-DistributionGroup' })[0].Switches | Should -Contain 'IncludeManagedByWithDisplayNames'
            ResetExchange
            $script:Ex.Stubs['Get-DistributionGroup'] = { [CmdletBinding()] param($ResultSize) [AppDomain]::CurrentDomain.GetData('NRGDL').Calls.Add(@{ Cmd = 'Get-DistributionGroup'; ResultSize = $ResultSize; Switches = @() }); @() }
            { Invoke-NRGCollectDistributionLists } | Should -Not -Throw
            @($script:Ex.Calls | Where-Object { $_.Cmd -eq 'Get-DistributionGroup' })[0].Switches | Should -BeNullOrEmpty
        }

        It 'resolves every cmdlet through the Exchange Online session, never the unqualified name' {
            $script:Ex.Groups = @(RawGroup)
            $null = Invoke-NRGCollectDistributionLists
            foreach ($n in 'Get-AcceptedDomain', 'Get-DistributionGroup', 'Get-DynamicDistributionGroup', 'Get-DistributionGroupMember', 'Get-DynamicDistributionGroupMember') {
                @($script:Ex.Resolved | Where-Object { $_.Name -eq $n -and $_.Session -eq 'ExchangeOnline' }).Count | Should -BeGreaterThan 0 -Because "$n must be resolved from the Exchange Online session"
            }
            @($script:Ex.Resolved | Where-Object { $_.Session -ne 'ExchangeOnline' }).Count | Should -Be 0
        }

        It 'a session that cannot be pinned (Source Unknown) reads nothing and says so' {
            $script:Ex.Source = 'Unknown'
            $script:Ex.Groups = @(RawGroup)
            $r = Invoke-NRGCollectDistributionLists
            $r.Success | Should -BeFalse
            $r.Data.SectionStatus.DistributionGroups | Should -Be 'Failed'
            @($r.Data.Lists).Count | Should -Be 0
            ($r.Data.Errors -join ' ') | Should -Match 'could not be pinned'
            @($script:Ex.Calls | Where-Object { $_.Cmd -like 'Get-*Group*' }) | Should -BeNullOrEmpty
        }

        It 'a failed list query is Failed, not an empty inventory: Success is false and the error is recorded' {
            $script:Ex.GroupError = 'The term Get-DistributionGroup is not recognized'
            $script:Ex.DynamicError = 'Access denied'
            $r = Invoke-NRGCollectDistributionLists
            $r.Success | Should -BeFalse
            $r.Data.SectionStatus.DistributionGroups | Should -Be 'Failed'
            $r.Data.SectionStatus.DynamicGroups | Should -Be 'Failed'
            $r.Data.SectionStatus.Members | Should -Be 'NotRun'
            @($r.Data.Lists).Count | Should -Be 0
            ($r.Data.Errors -join ' ') | Should -Match 'Access denied'
            (Get-NRGCoverage)['EXO-DistributionLists'].Status | Should -Be 'Failed'
            @(Get-NRGExceptions | Where-Object { $_.Source -like 'DL-*' }).Count | Should -BeGreaterThan 0
        }

        It 'one kind failing leaves the other collected and the run Partial' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.DynamicError = 'Dynamic groups unavailable'
            $r = Invoke-NRGCollectDistributionLists
            $r.Success | Should -BeTrue
            $r.Data.SectionStatus.DistributionGroups | Should -Be 'Collected'
            $r.Data.SectionStatus.DynamicGroups | Should -Be 'Failed'
            (Get-NRGCoverage)['EXO-DistributionLists'].Status | Should -Be 'Partial'
        }

        It 'a throttled member read is retried with backoff and then succeeds' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.MemberPlan['11111111-1111-1111-1111-111111111111'] = @('The request was throttled. Try again later.', 'Too many requests (429)')
            $script:Ex.Members['11111111-1111-1111-1111-111111111111'] = @((& $script:Alex))
            $r = Invoke-NRGCollectDistributionLists
            @($r.Data.Lists)[0]['MembersStatus'] | Should -Be 'Read'
            $r.Data.Stats.ThrottledReads | Should -Be 1
            Should -Invoke Wait-NRGDLBackoff -ModuleName 'NRG-Assessment' -Times 2 -Exactly -Scope It
        }

        It 'a list that stays throttled is Failed, and after N throttled lists in a row member reads STOP (the rest are NotRead, not hammered)' {
            $groups = @(1..6 | ForEach-Object { RawGroup @{ Name = "l$_"; DisplayName = "List $_"; PrimarySmtpAddress = "l$_@contoso.com"; Guid = "aaaaaaaa-0000-0000-0000-00000000000$_" } })
            $script:Ex.Groups = $groups
            foreach ($g in $groups) { $script:Ex.MemberPlan[[string]$g.Guid] = @(1..8 | ForEach-Object { 'The request was throttled' }) }
            $r = Invoke-NRGCollectDistributionLists -MaxRetries 1 -ThrottleStopAfter 3
            $statuses = @($r.Data.Lists | ForEach-Object { $_['MembersStatus'] })
            ($statuses | Where-Object { $_ -eq 'Failed' }).Count | Should -Be 3
            ($statuses | Where-Object { $_ -eq 'NotRead' }).Count | Should -Be 3
            $r.Data.Stats.ThrottleStopped | Should -BeTrue
            $r.Data.SectionStatus.Members | Should -Be 'Failed'
            @($r.Data.Lists | Where-Object { $_['MembersStatus'] -eq 'NotRead' })[0]['MembersNote'] | Should -Match 'throttling'
            @($script:Ex.Calls | Where-Object { $_.Cmd -eq 'Get-DistributionGroupMember' }).Count | Should -Be 6   # 3 lists x (1 try + 1 retry), none after the stop
        }

        It 'a non-throttle failure is not retried' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.MemberPlan['11111111-1111-1111-1111-111111111111'] = @('The operation could not be performed because object was not found')
            $r = Invoke-NRGCollectDistributionLists
            @($r.Data.Lists)[0]['MembersStatus'] | Should -Be 'Failed'
            Should -Invoke Wait-NRGDLBackoff -ModuleName 'NRG-Assessment' -Times 0 -Exactly -Scope It
        }

        It 'the list cap: only the first N lists have members read, the rest say why' {
            $groups = @(1..3 | ForEach-Object { RawGroup @{ Name = "l$_"; DisplayName = "List $_"; PrimarySmtpAddress = "l$_@contoso.com"; Guid = "bbbbbbbb-0000-0000-0000-00000000000$_" } })
            $script:Ex.Groups = $groups
            foreach ($g in $groups) { $script:Ex.Members[[string]$g.Guid] = @((& $script:Alex)) }
            $r = Invoke-NRGCollectDistributionLists -MemberReadListLimit 1
            @($r.Data.Lists | Where-Object { $_['MembersStatus'] -eq 'Read' }).Count | Should -Be 1
            @($r.Data.Lists | Where-Object { $_['MembersStatus'] -eq 'NotRead' }).Count | Should -Be 2
            @($r.Data.Lists | Where-Object { $_['MembersStatus'] -eq 'NotRead' })[0]['MembersNote'] | Should -Match 'first 1 lists'
            $r.Data.SectionStatus.Members | Should -Be 'Failed'
        }

        It 'never queries members with a blank identity (Exchange would return every object)' {
            $script:Ex.Groups = @(RawGroup @{ Guid = ''; PrimarySmtpAddress = '' })
            $r = Invoke-NRGCollectDistributionLists
            @($r.Data.Lists)[0]['MembersStatus'] | Should -Be 'NotRead'
            @($script:Ex.Calls | Where-Object { $_.Cmd -eq 'Get-DistributionGroupMember' }) | Should -BeNullOrEmpty
        }

        It 'a dynamic list is read with the dynamic member cmdlet and labeled a snapshot' {
            $script:Ex.Dynamic = @([pscustomobject]@{ Name = 'dyn'; DisplayName = 'Everyone'; PrimarySmtpAddress = 'everyone@contoso.com'; Guid = '33333333-3333-3333-3333-333333333333'; RecipientTypeDetails = 'DynamicDistributionGroup'; RequireSenderAuthenticationEnabled = $true })
            $script:Ex.Members['33333333-3333-3333-3333-333333333333'] = @((& $script:Alex))
            $r = Invoke-NRGCollectDistributionLists
            @($script:Ex.Calls | Where-Object { $_.Cmd -eq 'Get-DynamicDistributionGroupMember' }).Count | Should -Be 1
            @($script:Ex.Calls | Where-Object { $_.Cmd -eq 'Get-DistributionGroupMember' }) | Should -BeNullOrEmpty
            @($r.Data.Lists)[0]['MembersNote'] | Should -Match 'snapshot'
        }

        It 'omitted properties stay unknown ($null), not defaulted to a safe value, and nothing throws under StrictMode' {
            $script:Ex.Groups = @([pscustomobject]@{ Name = 'bare'; PrimarySmtpAddress = 'bare@contoso.com'; Guid = '44444444-4444-4444-4444-444444444444' })
            $r = Invoke-NRGCollectDistributionLists
            $l = @($r.Data.Lists)[0]
            $l['RequireSenderAuthenticationEnabled'] | Should -BeNullOrEmpty
            $null -eq $l['RequireSenderAuthenticationEnabled'] | Should -BeTrue
            $null -eq $l['ManagedBy'] | Should -BeTrue
            $null -eq $l['MemberJoinRestriction'] | Should -BeTrue
            $null -eq $l['ModerationEnabled'] | Should -BeTrue
        }

        It 'an EMPTY owner list is kept apart from one that was not returned' {
            $script:Ex.Groups = @((RawGroup @{ ManagedBy = @() }), (RawGroup @{ Name = 'b'; PrimarySmtpAddress = 'b@contoso.com'; Guid = '55555555-5555-5555-5555-555555555555' } -Omit 'ManagedBy'))
            $r = Invoke-NRGCollectDistributionLists
            $a = $r.Data.Lists | Where-Object { $_['PrimarySmtpAddress'] -eq 'all-staff@contoso.com' }
            $b = $r.Data.Lists | Where-Object { $_['PrimarySmtpAddress'] -eq 'b@contoso.com' }
            $null -ne $a['ManagedBy'] | Should -BeTrue
            @($a['ManagedBy']).Count | Should -Be 0
            $null -eq $b['ManagedBy'] | Should -BeTrue
        }

        It 'if the accepted domains cannot be read, members are Unresolved (not Internal, not all External) and only guests are recognized as outside' {
            $script:Ex.AcceptedError = 'Throttled'
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.Members['11111111-1111-1111-1111-111111111111'] = @((& $script:Alex), (& $script:Vendor), (RawMember 'GuestMailUser' 'Guest' 'guest@partner.example' -Upn 'guest_partner.example#EXT#@contoso.onmicrosoft.com'))
            $r = Invoke-NRGCollectDistributionLists -MaxRetries 0
            $r.Data.SectionStatus.AcceptedDomains | Should -Be 'Failed'
            $l = @($r.Data.Lists)[0]
            @($l['ExternalMembers']).Count | Should -Be 1   # the guest, by type
            $l['UnresolvedMemberCount'] | Should -Be 2
        }

        It 'a zero-domain answer is a failure, not an inventory with nothing outside' {
            $script:Ex.Accepted = @()
            $script:Ex.Groups = @(RawGroup)
            $r = Invoke-NRGCollectDistributionLists
            $r.Data.SectionStatus.AcceptedDomains | Should -Be 'Failed'
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Context 'evaluator: DL-1.1 who can send' {
        It 'Gap (High): outside senders accepted, no allow-list, no moderation (the all-staff phishing list)' {
            $script:Ex.Groups = @(RawGroup @{ RequireSenderAuthenticationEnabled = $false })
            $f = ForControl (RunScan) 'DL-1.1' 'all-staff@contoso.com'
            $f.State | Should -Be 'Gap'
            $f.Severity | Should -Be 'High'
            $f.Detail | Should -Match 'outside the organization'
            $f.Detail | Should -Match 'All Staff \(all-staff@contoso.com\)'
        }
        It 'Partial: outside senders accepted but every message is moderated' {
            $script:Ex.Groups = @(RawGroup @{ RequireSenderAuthenticationEnabled = $false; ModerationEnabled = $true; ModeratedBy = @('Mo Derator') })
            (ForControl (RunScan) 'DL-1.1').State | Should -Be 'Partial'
        }
        It 'Satisfied: authenticated senders only' {
            $script:Ex.Groups = @(RawGroup)
            (ForControl (RunScan) 'DL-1.1').State | Should -Be 'Satisfied'
        }
        It 'Satisfied: a named sender allow-list, with the caution about outside contacts' {
            $script:Ex.Groups = @(RawGroup @{ RequireSenderAuthenticationEnabled = $false; AcceptMessagesOnlyFromSendersOrMembers = @('ceo@contoso.com') })
            $f = ForControl (RunScan) 'DL-1.1'
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'allow-list'
        }
        It 'NotApplicable (not assessed), never Satisfied, when the setting was not returned' {
            $script:Ex.Groups = @(RawGroup -Omit 'RequireSenderAuthenticationEnabled')
            $f = ForControl (RunScan) 'DL-1.1'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^All Staff .*Not assessed'
        }
        It 'a dynamic list is evaluated for sender exposure too' {
            $script:Ex.Dynamic = @([pscustomobject]@{ Name = 'dyn'; DisplayName = 'Everyone'; PrimarySmtpAddress = 'everyone@contoso.com'; Guid = '33333333-3333-3333-3333-333333333333'; RequireSenderAuthenticationEnabled = $false; ManagedBy = @('x') })
            (ForControl (RunScan) 'DL-1.1' 'everyone@contoso.com').State | Should -Be 'Gap'
        }
    }

    Context 'evaluator: DL-2.1 owners' {
        It 'Gap (Low): no owner' {
            $script:Ex.Groups = @(RawGroup @{ ManagedBy = @() })
            $f = ForControl (RunScan) 'DL-2.1'
            $f.State | Should -Be 'Gap'; $f.Severity | Should -Be 'Low'
        }
        It 'Satisfied: an owner, by display name when Exchange resolved it' {
            $script:Ex.Groups = @(RawGroup @{ ManagedByWithDisplayNames = @('Alex Owner (alex@contoso.com)') })
            $f = ForControl (RunScan) 'DL-2.1'
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'Alex Owner'
        }
        It 'NotApplicable when the owner list was not returned (NOT "no owner")' {
            $script:Ex.Groups = @(RawGroup -Omit 'ManagedBy')
            (ForControl (RunScan) 'DL-2.1').State | Should -Be 'NotApplicable'
        }
    }

    Context 'evaluator: DL-2.2 who can join' {
        It 'Gap: Open' {
            $script:Ex.Groups = @(RawGroup @{ MemberJoinRestriction = 'Open' })
            (ForControl (RunScan) 'DL-2.2').State | Should -Be 'Gap'
        }
        It 'Satisfied: Closed and ApprovalRequired' -ForEach @(@{ V = 'Closed' }, @{ V = 'ApprovalRequired' }) {
            $script:Ex.Groups = @(RawGroup @{ MemberJoinRestriction = $V })
            (ForControl (RunScan) 'DL-2.2').State | Should -Be 'Satisfied'
        }
        It 'NotApplicable when not returned or unrecognized' {
            $script:Ex.Groups = @((RawGroup -Omit 'MemberJoinRestriction'), (RawGroup @{ Name = 'o'; PrimarySmtpAddress = 'o@contoso.com'; Guid = '66666666-6666-6666-6666-666666666666'; MemberJoinRestriction = 'Sometimes' }))
            $f = ForControl (RunScan) 'DL-2.2'
            @($f).Count | Should -Be 2
            @($f | Where-Object State -ne 'NotApplicable').Count | Should -Be 0
        }
        It 'a dynamic list gets no join finding (it has no join step)' {
            $script:Ex.Dynamic = @([pscustomobject]@{ Name = 'dyn'; DisplayName = 'Everyone'; PrimarySmtpAddress = 'everyone@contoso.com'; Guid = '33333333-3333-3333-3333-333333333333'; RequireSenderAuthenticationEnabled = $true; ManagedBy = @('x') })
            (ForControl (RunScan) 'DL-2.2' 'everyone@contoso.com') | Should -BeNullOrEmpty
        }
    }

    Context 'evaluator: DL-3.1 outside members' {
        BeforeEach { $script:G = '11111111-1111-1111-1111-111111111111' }
        It 'Gap: an outside member, listed by display name and UPN only' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.Members[$script:G] = @((& $script:Alex), (& $script:Vendor))
            $f = ForControl (RunScan) 'DL-3.1'
            $f.State | Should -Be 'Gap'
            @($f.AffectedObjects).Count | Should -Be 1
            @($f.AffectedObjects[0].PSObject.Properties.Name | Sort-Object) | Should -Be @('DisplayName', 'UserPrincipalName')
            $f.Detail | Should -Match '1 of 2 direct member'
        }
        It 'Satisfied: every direct member read and none outside' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.Members[$script:G] = @((& $script:Alex))
            (ForControl (RunScan) 'DL-3.1').State | Should -Be 'Satisfied'
        }
        It 'NotApplicable (not Satisfied) when the members were not read' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.MemberPlan[$script:G] = @('Access denied')
            $f = ForControl (RunScan) 'DL-3.1'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Not assessed: .*not read'
        }
        It 'NotApplicable when the list was larger than the cap and none of the part read is outside; Gap when one of them is' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.Members[$script:G] = @(1..9 | ForEach-Object { RawMember 'UserMailbox' "U$_" "u$_@contoso.com" -Upn "u$_@contoso.com" })
            $f = ForControl (RunScan @{ MemberLimit = 4 }) 'DL-3.1'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'larger'
            ResetExchange
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.Members[$script:G] = @((& $script:Vendor)) + @(1..9 | ForEach-Object { RawMember 'UserMailbox' "U$_" "u$_@contoso.com" -Upn "u$_@contoso.com" })
            (ForControl (RunScan @{ MemberLimit = 4 }) 'DL-3.1').State | Should -Be 'Gap'
        }
        It 'NotApplicable when nested groups were not expanded, and the detail says direct members only' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.Members[$script:G] = @((& $script:Alex), (RawMember 'MailUniversalDistributionGroup' 'Sales' 'sales@contoso.com'))
            $f = ForControl (RunScan) 'DL-3.1'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'nested group'
        }
        It 'NotApplicable when a member could not be classified' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.Members[$script:G] = @((& $script:Alex), (RawMember 'MailUser' 'No Address' ''))
            $f = ForControl (RunScan) 'DL-3.1'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'could not be classified'
        }
        It 'an empty dynamic list is not "clean": Exchange may not have calculated it yet' {
            $script:Ex.Dynamic = @([pscustomobject]@{ Name = 'dyn'; DisplayName = 'Everyone'; PrimarySmtpAddress = 'everyone@contoso.com'; Guid = '33333333-3333-3333-3333-333333333333'; RequireSenderAuthenticationEnabled = $true; ManagedBy = @('x') })
            $f = ForControl (RunScan) 'DL-3.1' 'everyone@contoso.com'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'not calculated'
        }
    }

    Context 'evaluator: an empty or failed section is never clean' {
        It 'every control is NotApplicable (not assessed) when no list could be read, and none is Satisfied' {
            $script:Ex.GroupError = 'Access denied'; $script:Ex.DynamicError = 'Access denied'
            $f = RunScan
            @($f).Count | Should -Be 4
            @($f | Where-Object State -ne 'NotApplicable').Count | Should -Be 0
            $f[0].Detail | Should -Match 'Not assessed: no distribution list could be read'
        }
        It 'every control is NotApplicable when the collector never ran' {
            Test-NRGDistributionListControls
            $f = @(Get-NRGFindings)
            @($f).Count | Should -Be 4
            @($f | Where-Object State -ne 'NotApplicable').Count | Should -Be 0
            $f[0].Detail | Should -Match 'did not run'
        }
        It 'zero lists from a SUCCESSFUL read is still not a clean bill: the finding says a role-scoped account sees only its scope' {
            $f = RunScan
            @($f).Count | Should -Be 4
            @($f | Where-Object State -ne 'NotApplicable').Count | Should -Be 0
            $f[0].Detail | Should -Match 'role-scoped'
        }
        It 'one kind of list unread: the other kind is evaluated and the gap is named once per control' {
            $script:Ex.Groups = @(RawGroup @{ RequireSenderAuthenticationEnabled = $false })
            $script:Ex.DynamicError = 'Dynamic groups unavailable'
            $f = RunScan
            (ForControl $f 'DL-1.1' 'all-staff@contoso.com').State | Should -Be 'Gap'
            $note = @(ForControl $f 'DL-1.1' | Where-Object { -not $_.Instance })
            $note.Count | Should -Be 1
            $note[0].State | Should -Be 'NotApplicable'
            $note[0].Detail | Should -Match 'dynamic distribution lists could not be read'
        }
        It 'a check that throws is recorded and its control reports not assessed instead of vanishing' {
            Mock Test-NRGDistributionListOwners -ModuleName 'NRG-Assessment' -MockWith { throw 'boom' }
            $script:Ex.Groups = @(RawGroup)
            $f = RunScan
            $f2 = ForControl $f 'DL-2.1'
            @($f2).Count | Should -Be 1
            $f2[0].State | Should -Be 'NotApplicable'
            $f2[0].Detail | Should -Match 'did not finish'
            (ForControl $f 'DL-1.1').State | Should -Be 'Satisfied'   # the others still ran
            @(Get-NRGExceptions | Where-Object { $_.Source -eq 'Test-NRGDistributionListOwners' }).Count | Should -Be 1
        }
        It 'replayed results (JSON round trip, PSCustomObject shape) evaluate the same as a live run' {
            $script:Ex.Groups = @((RawGroup @{ RequireSenderAuthenticationEnabled = $false; ManagedBy = @() }))
            $script:Ex.Members['11111111-1111-1111-1111-111111111111'] = @((& $script:Vendor))
            $null = Invoke-NRGCollectDistributionLists
            $live = Get-NRGRawData -Key 'EXO-DistributionLists'
            $replayed = ($live | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data $replayed
            Test-NRGDistributionListControls
            $f = @(Get-NRGFindings)
            (ForControl $f 'DL-1.1').State | Should -Be 'Gap'
            (ForControl $f 'DL-2.1').State | Should -Be 'Gap'
            (ForControl $f 'DL-3.1').State | Should -Be 'Gap'
        }
        It 'the DL-* findings are not controls.json controls and carry no framework citation (heuristic hardening checks)' {
            $ids = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw | ConvertFrom-Json).controls.ControlId)
            @($ids | Where-Object { $_ -like 'DL-*' }).Count | Should -Be 0
            $script:Ex.Groups = @(RawGroup)
            @(RunScan | Where-Object { @($_.FrameworkIds).Count -gt 0 }).Count | Should -Be 0
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Context 'publisher: worksheet text and CSV' {
        BeforeEach {
            $script:Out = Join-Path ([IO.Path]::GetTempPath()) ("nrg-dl-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
            $script:Meta = [ordered]@{ TenantDomain = 'contoso.onmicrosoft.com'; AssessmentDate = '2026-10-02 10:00'; ToolVersion = '4.14.3' }
        }
        AfterEach { if ($script:Out) { Remove-Item -LiteralPath $script:Out -Recurse -Force -ErrorAction SilentlyContinue } }

        function script:PublishOut {
            param([switch] $NoMembers)
            $raw = Get-NRGRawData -Key 'EXO-DistributionLists'
            $p = Publish-NRGDistributionListWorksheet -Metadata $script:Meta -Findings @(Get-NRGFindings) -RawData $raw -OutputDirectory $script:Out -BaseName 'contoso-20261002-100000' -NoMembers:$NoMembers
            [pscustomobject]@{
                Result = $p
                Text   = (Get-Content -LiteralPath $p.TextPath -Raw)
                Csv    = @(Get-Content -LiteralPath $p.CsvPath -Raw -Encoding utf8 | ConvertFrom-Csv)
                CsvRaw = (Get-Content -LiteralPath $p.CsvPath -Raw -Encoding utf8)
            }
        }
        function script:SeedMixed {
            $script:Ex.Groups = @(
                (RawGroup @{ Name = 'open'; DisplayName = 'Open List'; PrimarySmtpAddress = 'open@contoso.com'; Guid = 'aaaaaaaa-0000-0000-0000-000000000001'; RequireSenderAuthenticationEnabled = $false; ManagedBy = @(); MemberJoinRestriction = 'Open' }),
                (RawGroup @{ Name = 'fine'; DisplayName = 'Fine List'; PrimarySmtpAddress = 'fine@contoso.com'; Guid = 'aaaaaaaa-0000-0000-0000-000000000002' }),
                (RawGroup @{ Name = 'unread'; DisplayName = 'Unread List'; PrimarySmtpAddress = 'unread@contoso.com'; Guid = 'aaaaaaaa-0000-0000-0000-000000000003' }))
            $script:Ex.Members['aaaaaaaa-0000-0000-0000-000000000001'] = @((& $script:Alex), (& $script:Vendor))
            $script:Ex.Members['aaaaaaaa-0000-0000-0000-000000000002'] = @((& $script:Alex))
            $script:Ex.MemberPlan['aaaaaaaa-0000-0000-0000-000000000003'] = @('Access denied')
            $null = RunScan
        }

        It 'writes <base>-distribution-lists.txt and .csv, one CSV row per list' {
            SeedMixed
            $o = PublishOut
            $o.Result.TextPath | Should -Match 'contoso-20261002-100000-distribution-lists\.txt$'
            $o.Result.CsvPath | Should -Match 'contoso-20261002-100000-distribution-lists\.csv$'
            Test-Path -LiteralPath $o.Result.TextPath | Should -BeTrue
            @($o.Csv).Count | Should -Be 3
            @($o.Csv[0].PSObject.Properties.Name) | Should -Be @('List', 'Address', 'Type', 'WhoCanSendToIt', 'Owners', 'MemberCount', 'ExternalMembers', 'Status', 'Severity', 'Finding', 'RecommendedSetting', 'ReadLimit')
        }

        It 'both files are written through the restricted-file writer (owner-only permissions)' -Skip:($IsWindows) {
            SeedMixed
            $o = PublishOut
            foreach ($p in $o.Result.TextPath, $o.Result.CsvPath) {
                ([int]([System.IO.File]::GetUnixFileMode($p)) -band 0x3F) | Should -Be 0 -Because "$p must not be group- or world-accessible"
            }
        }

        It 'states in the worksheet that it only read, that nothing else was assessed, and the member limit' {
            SeedMixed
            $o = PublishOut
            $o.Text | Should -Match 'did not create, add, remove or change'
            $o.Text | Should -Match 'this tool never runs them'
            $o.Text | Should -Match 'Not assessed:\s+Every other area of the tenant'
            $o.Text | Should -Match 'Microsoft 365 Groups'
            $o.Text | Should -Match 'Up to 2000 member'
            $o.Text | Should -Match 'INTERNAL USE'
        }

        It 'orders the worst first and puts the list with an unread section under NOT FULLY ASSESSED, never under nothing-to-change' {
            SeedMixed
            $o = PublishOut
            $o.Csv[0].List | Should -Be 'Open List'
            $o.Csv[0].Status | Should -Be 'NEEDS ATTENTION'
            ($o.Csv | Where-Object List -eq 'Unread List').Status | Should -Be 'NOT FULLY ASSESSED'
            ($o.Csv | Where-Object List -eq 'Fine List').Status | Should -Be 'OK IN WHAT WAS READ'
        }

        It 'a list whose every check passed reads OK in what was read, and the summary says that is not a statement the list is secure' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.Members['11111111-1111-1111-1111-111111111111'] = @((& $script:Alex))
            $null = RunScan
            $o = PublishOut
            $o.Csv[0].Status | Should -Be 'OK IN WHAT WAS READ'
            $o.Text | Should -Match 'not a statement that the list is secure'
            $o.Csv[0].RecommendedSetting | Should -Be 'No change'
        }

        It 'PARITY: every non-Satisfied finding Detail reads the same in the results JSON, the text and the CSV' {
            SeedMixed
            $o = PublishOut
            $jsonDetails = @((@(Get-NRGFindings) | ConvertTo-Json -Depth 8 | ConvertFrom-Json) | ForEach-Object { $_.Detail })
            $norm = { param($s) (& $script:Mod { param($v) ConvertTo-NRGDLText -Value $v -MaxLength 0 } $s) }
            $checked = 0
            foreach ($f in @(Get-NRGFindings | Where-Object { $_.State -ne 'Satisfied' -and $_.Instance })) {
                $d = & $norm $f.Detail
                $jsonDetails | Should -Contain $f.Detail
                $o.Text | Should -Match ([regex]::Escape($d))
                $row = $o.Csv | Where-Object Address -eq $f.Instance
                $row.Finding | Should -Match ([regex]::Escape($d))
                $checked++
            }
            $checked | Should -BeGreaterThan 3
        }

        It 'PARITY: the limitation (members not read) reads the same in the text and the CSV' {
            SeedMixed
            $o = PublishOut
            $row = $o.Csv | Where-Object List -eq 'Unread List'
            $row.ReadLimit | Should -Match 'Members not read'
            $o.Text | Should -Match 'Read limit:\s+Members not read'
            $row.ExternalMembers | Should -Be 'not read'
            $row.MemberCount | Should -Be 'not read'
        }

        It 'a section that could not be read still gets a CSV row and a NOT READ line (a CSV without it would read as complete)' {
            $script:Ex.Groups = @(RawGroup)
            $script:Ex.DynamicError = 'Dynamic groups unavailable'
            $script:Ex.Members['11111111-1111-1111-1111-111111111111'] = @((& $script:Alex))
            $null = RunScan
            $o = PublishOut
            $note = $o.Csv | Where-Object List -eq '(not read)'
            $note | Should -Not -BeNullOrEmpty
            $note.Finding | Should -Match 'DL-1.1, DL-2.1, DL-2.2, DL-3.1'
            $note.Finding | Should -Match 'dynamic distribution lists could not be read'
            $o.Text | Should -Match 'NOT READ:\s+Not assessed: the dynamic distribution lists could not be read'
        }

        It 'nothing readable at all produces a worksheet that says nothing was read, not an empty "all clear"' {
            $script:Ex.GroupError = 'Access denied'; $script:Ex.DynamicError = 'Access denied'
            $null = RunScan
            $o = PublishOut
            $o.Result.ListCount | Should -Be 0
            $o.Text | Should -Match 'NO LISTS'
            $o.Text | Should -Match 'NOT READ:.*no distribution list could be read'
            $o.Text | Should -Not -Match 'OK in what was read:\s+[1-9]'
            @($o.Csv).Count | Should -Be 1
            $o.Csv[0].List | Should -Be '(not read)'
        }

        It 'members are listed by UPN and display name only' {
            SeedMixed
            $o = PublishOut
            $o.Text | Should -Match 'MEMBERS BY LIST'
            $o.Text | Should -Match 'alex@contoso\.com\s+Alex Owner'
            $o.Text | Should -Not -Match '701-555-0100|Director|someone@contoso\.com|\bHQ\b'
            $o.CsvRaw | Should -Not -Match '701-555-0100|Director|someone@contoso\.com'
        }
        It '-NoMembers leaves the member listing out and keeps the counts' {
            SeedMixed
            $o = PublishOut -NoMembers
            $o.Text | Should -Not -Match 'MEMBERS BY LIST'
            $o.Csv[0].MemberCount | Should -Match '^2'
        }

        It 'CSV: a tenant-controlled name that starts like a formula is neutralized, and quotes are escaped' {
            $script:Ex.Groups = @(RawGroup @{ DisplayName = '=cmd|''/c calc''!A1'; Name = 'f'; PrimarySmtpAddress = 'f@contoso.com'; Guid = '77777777-7777-7777-7777-777777777777'; RequireSenderAuthenticationEnabled = $false })
            $null = RunScan
            $o = PublishOut
            $o.Csv[0].List | Should -Be "'=cmd|'/c calc'!A1"
            $o.Csv[0].List | Should -Not -Match '^='
        }
        It 'text: newlines and bidirectional overrides in a name cannot break out of its line' {
            $script:Ex.Groups = @(RawGroup @{ DisplayName = "Evil$([char]0x202E)`nSet-Mailbox x"; Name = 'e'; PrimarySmtpAddress = 'e@contoso.com'; Guid = '88888888-8888-8888-8888-888888888888'; RequireSenderAuthenticationEnabled = $false })
            $null = RunScan
            $o = PublishOut
            $o.Text | Should -Not -Match "‮"
            $o.Text | Should -Not -Match '(?m)^Set-Mailbox'
        }
        It 'refuses a BaseName that is a path' {
            SeedMixed
            { Publish-NRGDistributionListWorksheet -Metadata $script:Meta -Findings @(Get-NRGFindings) -RawData (Get-NRGRawData -Key 'EXO-DistributionLists') -OutputDirectory $script:Out -BaseName '..\evil' } | Should -Throw '*file name stem*'
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Context 'publisher: the hardening commands are text, never run' {
        BeforeEach {
            $script:Out = Join-Path ([IO.Path]::GetTempPath()) ("nrg-dl-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
            $script:Meta = [ordered]@{ TenantDomain = 'contoso.onmicrosoft.com'; AssessmentDate = '2026-10-02'; ToolVersion = '4.14.3' }
        }
        AfterEach { if ($script:Out) { Remove-Item -LiteralPath $script:Out -Recurse -Force -ErrorAction SilentlyContinue } }

        function script:PublishText {
            $raw = Get-NRGRawData -Key 'EXO-DistributionLists'
            $p = Publish-NRGDistributionListWorksheet -Metadata $script:Meta -Findings @(Get-NRGFindings) -RawData $raw -OutputDirectory $script:Out -BaseName 'c'
            Get-Content -LiteralPath $p.TextPath -Raw
        }

        It 'prints the exact command for the list, labeled as text for an administrator' {
            $script:Ex.Groups = @(RawGroup @{ RequireSenderAuthenticationEnabled = $false; MemberJoinRestriction = 'Open' })
            $null = RunScan
            $t = PublishText
            $t | Should -Match "(?m)^\s+Set-DistributionGroup -Identity 'all-staff@contoso\.com' -RequireSenderAuthenticationEnabled \`$true$"
            $t | Should -Match "(?m)^\s+Set-DistributionGroup -Identity 'all-staff@contoso\.com' -MemberJoinRestriction Closed$"
            $t | Should -Match 'TEXT ONLY: an administrator runs these after review; this tool did not'
            $t | Should -Match 'What could break: Outside senders'
        }
        It 'a command that needs a value from the reader, an alternative, and a removal are printed COMMENTED OUT' {
            $script:Ex.Groups = @(RawGroup @{ RequireSenderAuthenticationEnabled = $false; ManagedBy = @() })
            $script:Ex.Members['11111111-1111-1111-1111-111111111111'] = @((& $script:Vendor))
            $null = RunScan
            $t = PublishText
            $t | Should -Match "(?m)^\s+# Set-DistributionGroup -Identity 'all-staff@contoso\.com' -ManagedBy @\{Add='<owner-upn>'\}$"
            $t | Should -Match "(?m)^\s+# Set-DistributionGroup -Identity 'all-staff@contoso\.com' -ModerationEnabled"
            $t | Should -Match "(?m)^\s+# Remove-DistributionGroupMember -Identity 'all-staff@contoso\.com' -Member 'vendor\.contact@fabrikam\.example' -Confirm:\`$false$"
            # No line that starts a command and still contains a placeholder.
            $t | Should -Not -Match "(?m)^\s+(Set|Remove|Add)-\w+.*'<[a-z-]+>'"
        }
        It 'a dynamic list gets the dynamic cmdlet and an instruction (members cannot be removed one by one)' {
            $script:Ex.Dynamic = @([pscustomobject]@{ Name = 'dyn'; DisplayName = 'Everyone'; PrimarySmtpAddress = 'everyone@contoso.com'; Guid = '33333333-3333-3333-3333-333333333333'; RequireSenderAuthenticationEnabled = $false; ManagedBy = @('x'); RecipientTypeDetails = 'DynamicDistributionGroup' })
            $script:Ex.Members['33333333-3333-3333-3333-333333333333'] = @((& $script:Vendor))
            $null = RunScan
            $t = PublishText
            $t | Should -Match "(?m)^\s+Set-DynamicDistributionGroup -Identity 'everyone@contoso\.com' -RequireSenderAuthenticationEnabled \`$true$"
            $t | Should -Match 'Members of a dynamic list come from its recipient filter'
            $t | Should -Not -Match 'Remove-DistributionGroupMember -Identity ''everyone'
        }
        It 'an address that is not safe to paste gets NO command, and the worksheet says to find it by hand' {
            $script:Ex.Groups = @(RawGroup @{ PrimarySmtpAddress = "x@contoso.com'; Remove-Mailbox -Identity ceo #"; Guid = '99999999-9999-9999-9999-999999999999'; RequireSenderAuthenticationEnabled = $false })
            $null = RunScan
            $t = PublishText
            $t | Should -Match 'not safe to paste'
            $t | Should -Not -Match '(?m)^\s+Set-DistributionGroup -Identity'
            $t | Should -Not -Match '(?m)^\s+Remove-Mailbox'
        }
        It 'an apostrophe in an address is doubled, so the command stays one quoted value' {
            $script:Ex.Groups = @(RawGroup @{ PrimarySmtpAddress = "o'brien-team@contoso.com"; Guid = '12121212-1212-1212-1212-121212121212'; RequireSenderAuthenticationEnabled = $false })
            $null = RunScan
            (PublishText) | Should -Match "(?m)^\s+Set-DistributionGroup -Identity 'o''brien-team@contoso\.com' -RequireSenderAuthenticationEnabled"
        }
        It 'running the whole scan never calls a write cmdlet: a stub of each, in module scope, is never invoked' {
            $script:Ex.Groups = @(RawGroup @{ RequireSenderAuthenticationEnabled = $false; ManagedBy = @(); MemberJoinRestriction = 'Open' })
            $script:Ex.Members['11111111-1111-1111-1111-111111111111'] = @((& $script:Vendor))
            $script:Ex.WriteCalls = [System.Collections.Generic.List[string]]::new()
            & $script:Mod {
                foreach ($n in 'Set-DistributionGroup', 'Set-DynamicDistributionGroup', 'Add-DistributionGroupMember', 'Remove-DistributionGroupMember', 'Update-DistributionGroupMember', 'New-DistributionGroup', 'Remove-DistributionGroup', 'Set-Mailbox', 'Invoke-Expression') {
                    Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create("[AppDomain]::CurrentDomain.GetData('NRGDL').WriteCalls.Add('$n'); throw 'a write cmdlet was called'"))
                }
            }
            try {
                $null = RunScan
                $null = PublishText
                @($script:Ex.WriteCalls).Count | Should -Be 0
            } finally {
                & $script:Mod { foreach ($n in 'Set-DistributionGroup', 'Set-DynamicDistributionGroup', 'Add-DistributionGroupMember', 'Remove-DistributionGroupMember', 'Update-DistributionGroupMember', 'New-DistributionGroup', 'Remove-DistributionGroup', 'Set-Mailbox', 'Invoke-Expression') { Remove-Item -Path "function:script:$n" -ErrorAction SilentlyContinue } }
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Context 'connection: Exchange Online only, tenant pinned' {
        BeforeEach {
            $script:Conn = @{ Connected = @(); ConnectParams = $null; Disconnected = 0; TenantId = '' }
            [AppDomain]::CurrentDomain.SetData('NRGConn', $script:Conn)
            & $script:Mod {
                Set-Item -Path 'function:script:Connect-ExchangeOnline' -Value {
                    [CmdletBinding()] param([switch] $ShowBanner, [switch] $DisableWAM, $UserPrincipalName, $DelegatedOrganization)
                    $c = [AppDomain]::CurrentDomain.GetData('NRGConn')
                    $c.ConnectParams = @{} + $PSBoundParameters
                    $c.Connected = @([pscustomobject]@{ State = 'Connected'; IsEopSession = $false; TenantID = $c.TenantId; Organization = 'contoso.onmicrosoft.com'; UserPrincipalName = 'admin@contoso.com' })
                }
                Set-Item -Path 'function:script:Get-ConnectionInformation' -Value { [CmdletBinding()] param() @([AppDomain]::CurrentDomain.GetData('NRGConn').Connected) }
                Set-Item -Path 'function:script:Disconnect-ExchangeOnline' -Value { [CmdletBinding()] param($Confirm) $c = [AppDomain]::CurrentDomain.GetData('NRGConn'); $c.Disconnected++; $c.Connected = @() }
            }
            $script:Conn.TenantId = '0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a'
        }
        AfterEach {
            & $script:Mod { foreach ($n in 'Connect-ExchangeOnline', 'Get-ConnectionInformation', 'Disconnect-ExchangeOnline') { Remove-Item -Path "function:script:$n" -ErrorAction SilentlyContinue } }
            [AppDomain]::CurrentDomain.SetData('NRGConn', $null)
        }

        It 'connects Exchange Online, passes -DisableWAM when the module has it, and returns the tenant it proved' {
            $c = Connect-NRGExchangeOnlineOnly -UserPrincipalName 'admin@contoso.com'
            $c.Connected | Should -BeTrue
            $c.TenantId | Should -Be '0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a'
            $script:Conn.ConnectParams.ContainsKey('DisableWAM') | Should -BeTrue
            $script:Conn.ConnectParams.UserPrincipalName | Should -Be 'admin@contoso.com'
        }
        It 'GDAP: the client''s routing domain is passed as -DelegatedOrganization' {
            $null = Connect-NRGExchangeOnlineOnly -DelegatedOrganization 'client.onmicrosoft.com'
            $script:Conn.ConnectParams.DelegatedOrganization | Should -Be 'client.onmicrosoft.com'
        }
        It 'a session for a different tenant is disconnected and refused (nothing is read)' {
            { Connect-NRGExchangeOnlineOnly -ExpectedTenantId '99999999-9999-9999-9999-999999999999' } | Should -Throw '*not the requested tenant*'
            $script:Conn.Disconnected | Should -Be 1
        }
        It 'a tenant that cannot be read cannot be confirmed, so it is refused' {
            $script:Conn.TenantId = ''
            { Connect-NRGExchangeOnlineOnly -ExpectedTenantId '99999999-9999-9999-9999-999999999999' } | Should -Throw '*cannot be confirmed*'
        }
        It 'an Exchange session already open stops the scan (one window, one tenant) unless it is proven to be the right one or -ReuseSession is given' {
            $script:Conn.Connected = @([pscustomobject]@{ State = 'Connected'; IsEopSession = $false; TenantID = '0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a'; Organization = 'x'; UserPrincipalName = 'a@b.com' })
            { Connect-NRGExchangeOnlineOnly } | Should -Throw '*already open*'
            $script:Conn.ConnectParams | Should -BeNullOrEmpty
            $c = Connect-NRGExchangeOnlineOnly -ExpectedTenantId '0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a'
            $c.Reused | Should -BeTrue
            $script:Conn.ConnectParams | Should -BeNullOrEmpty
            { Connect-NRGExchangeOnlineOnly -ExpectedTenantId '99999999-9999-9999-9999-999999999999' } | Should -Throw '*already open*'
            (Connect-NRGExchangeOnlineOnly -ReuseSession).Reused | Should -BeTrue
        }
        It 'the connection code touches no other service: no Graph, Teams, Purview or SharePoint sign-in (parsed calls, so comments may name them)' {
            foreach ($f in 'Lib/Connect-NRGExchangeOnlineOnly.ps1', 'Invoke-NRGDistributionListScan.ps1') {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:RepoRoot $f), [ref]$null, [ref]$null)
                $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
                @($calls | Where-Object { $_ -match '^(Connect-MgGraph|Connect-NRGServices|Connect-NRGEmail\w*|Connect-MicrosoftTeams|Connect-IPPSSession|Connect-SPOService|Invoke-NRGGraphRequest|Get-Mg\w+)$' }) | Should -BeNullOrEmpty -Because $f
            }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    Context 'read-only, statically' {
        BeforeAll {
            $script:DlFiles = @(
                'Collectors/EXO/Invoke-NRGCollectDistributionLists.ps1',
                'Evaluators/Test-NRGDistributionListControls.ps1',
                'Publishers/Publish-NRGDistributionListWorksheet.ps1',
                'Lib/Get-NRGDistributionListRules.ps1',
                'Lib/Connect-NRGExchangeOnlineOnly.ps1',
                'Invoke-NRGDistributionListScan.ps1') | ForEach-Object { Join-Path $script:RepoRoot $_ }
            # Every command these files may call that is not one of this tool's own functions.
            # A new command fails this test until someone reads it and adds it here.
            $script:Allowed = @(
                'ForEach-Object', 'Where-Object', 'Select-Object', 'Sort-Object', 'Group-Object', 'Out-Null',
                'Get-Command', 'Get-Date', 'Get-Random', 'Get-Content', 'Get-Location', 'Get-Variable', 'Join-Path', 'Split-Path', 'Test-Path',
                'ConvertFrom-Json', 'ConvertTo-Json', 'Import-Module', 'Start-Sleep', 'Write-Progress', 'Write-Verbose', 'Write-Warning', 'Write-Host',
                'Set-StrictMode',
                # Session control, in the connection file only: they open and close the sign-in, they change no tenant object.
                'Connect-ExchangeOnline', 'Disconnect-ExchangeOnline', 'Get-ConnectionInformation')
        }
        It 'every command these files call is on the allowlist (no Set-, New-, Remove-, Add-, Update-, Enable-, Disable- against a tenant)' {
            $bad = foreach ($f in $script:DlFiles) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$null)
                foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                    $name = $c.GetCommandName()
                    if (-not $name) { continue }
                    if ($name -match 'NRG') { continue }
                    if ($name -notin $script:Allowed) { "$(Split-Path $f -Leaf):$($c.Extent.StartLineNumber) $name" }
                }
            }
            @($bad) | Should -BeNullOrEmpty
        }
        It 'the Exchange cmdlets the collector resolves are all Get-* (and there are exactly the five it needs)' {
            $src = Get-Content -LiteralPath $script:DlFiles[0] -Raw
            $names = @([regex]::Matches($src, "resolve\s+'([A-Za-z]+-[A-Za-z]+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
            $names | Should -Be @('Get-AcceptedDomain', 'Get-DistributionGroup', 'Get-DistributionGroupMember', 'Get-DynamicDistributionGroup', 'Get-DynamicDistributionGroupMember')
            @($names | Where-Object { $_ -notlike 'Get-*' }) | Should -BeNullOrEmpty
        }
        It 'no module-loaded file in the scan names a tenant-changing list/mailbox cmdlet at all, not even in a string or comment' {
            $banned = 'Set-DistributionGroup', 'Set-DynamicDistributionGroup', 'New-DistributionGroup', 'New-DynamicDistributionGroup', 'Remove-DistributionGroup',
                      'Remove-DynamicDistributionGroup', 'Add-DistributionGroupMember', 'Remove-DistributionGroupMember', 'Update-DistributionGroupMember',
                      'Set-UnifiedGroup', 'Add-UnifiedGroupLinks', 'Remove-UnifiedGroupLinks', 'Set-Mailbox', 'Set-MailContact', 'New-MailContact', 'Remove-MailContact',
                      'Invoke-Expression', 'Start-Process'
            $hits = foreach ($f in $script:DlFiles) {
                $src = Get-Content -LiteralPath $f -Raw
                foreach ($b in $banned) { if ($src -match [regex]::Escape($b)) { "$(Split-Path $f -Leaf) names $b" } }
            }
            @($hits) | Should -BeNullOrEmpty -Because 'the hardening commands are data in Config/distribution-list-hardening.json, in no file the module executes'
        }
        It 'the command templates live in a config file, every one is a single allowed command with only the two known placeholders' {
            $cfg = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/distribution-list-hardening.json') -Raw | ConvertFrom-Json
            @($cfg.Templates).Count | Should -BeGreaterThan 5
            $re = '^(Set-DistributionGroup|Set-DynamicDistributionGroup|Remove-DistributionGroupMember) -Identity \{Identity\}( -[A-Za-z]+(:\$false|( (\$true|\$false|[A-Za-z]+|\{Member\}|''<[a-z-]+>''|@\{Add=''<[a-z-]+>''\})))?)*$'
            foreach ($t in @($cfg.Templates)) {
                if ($t.Kind -eq 'Instruction') { $t.Command | Should -BeNullOrEmpty; continue }
                $t.Command | Should -Match $re -Because "template $($t.ControlId) $($t.AppliesTo) $($t.Kind)"
                $t.Command | Should -Not -Match '[;|&`]|\$\(|\r|\n'
                @('Primary', 'Alternative', 'ReviewFirst') | Should -Contain $t.Kind
                @('Distribution', 'Dynamic') | Should -Contain $t.AppliesTo
                $t.Impact | Should -Not -BeNullOrEmpty -Because 'a change an administrator is asked to make says what it can break'
            }
        }
        It 'the load-time check accepts every shipped template and rejects anything that is not one command of the expected shape' {
            $cfg = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/distribution-list-hardening.json') -Raw | ConvertFrom-Json
            foreach ($t in @($cfg.Templates)) {
                (& $script:Mod { param($c) Test-NRGDistributionListCommandTemplate -Command $c } ([string]$t.Command)) | Should -BeTrue -Because "$($t.ControlId) $($t.AppliesTo) $($t.Kind)"
            }
            foreach ($bad in @(
                'Set-DistributionGroup -Identity {Identity} -MemberJoinRestriction Closed; Remove-Mailbox -Identity x',
                'Set-DistributionGroup -Identity {Identity} -MemberJoinRestriction Closed | Out-Null',
                'Set-DistributionGroup -Identity {Identity} -ManagedBy $(whoami)',
                'Set-DistributionGroup -Identity {Identity} -ManagedBy `whoami',
                "Set-DistributionGroup -Identity {Identity} -MemberJoinRestriction Closed`nRemove-Mailbox x",
                "Set-DistributionGroup -Identity '{Identity}' -MemberJoinRestriction Closed",
                'Set-Mailbox -Identity {Identity} -HiddenFromAddressListsEnabled $true',
                'Invoke-Expression -Identity {Identity}',
                'Set-DistributionGroup -MemberJoinRestriction Closed',
                'Set-DistributionGroup -Identity {Identity} -ManagedBy {Other}',
                'Set-DistributionGroup -Identity {Identity} -ManagedBy @{Add=''x''}; calc',
                'Set-DistributionGroup -Identity {Identity} > out.txt')) {
                (& $script:Mod { param($c) Test-NRGDistributionListCommandTemplate -Command $c } $bad) | Should -BeFalse -Because $bad
            }
        }
        It 'a tampered template is not loaded (and the loss is warned about), so the worksheet cannot print it' {
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-dl-tpl-" + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.json')
            try {
                @{ Templates = @(
                    @{ ControlId = 'DL-2.2'; AppliesTo = 'Distribution'; Kind = 'Primary'; Intent = 'ok'; Command = 'Set-DistributionGroup -Identity {Identity} -MemberJoinRestriction Closed'; Impact = 'x' },
                    @{ ControlId = 'DL-2.2'; AppliesTo = 'Distribution'; Kind = 'Alternative'; Intent = 'bad'; Command = 'Set-DistributionGroup -Identity {Identity} -MemberJoinRestriction Closed; Remove-Mailbox -Identity ceo'; Impact = 'x' }
                ) } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding utf8
                $all = @(& $script:Mod { param($p) Get-NRGDistributionListHardeningTemplates -Path $p 3>&1 } $tmp)
                $warn = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
                $loaded = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
                $loaded.Count | Should -Be 1
                $loaded[0].Kind | Should -Be 'Primary'
                $warn.Count | Should -Be 1
                $warn[0].Message | Should -Match 'was not loaded'
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
        It 'the tests cannot be satisfied by an empty template list: every control that has a Gap or Partial has a primary change' {
            $cfg = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/distribution-list-hardening.json') -Raw | ConvertFrom-Json
            foreach ($id in 'DL-1.1', 'DL-2.1') {
                foreach ($kind in 'Distribution', 'Dynamic') {
                    @($cfg.Templates | Where-Object { $_.ControlId -eq $id -and $_.AppliesTo -eq $kind -and $_.Kind -eq 'Primary' }).Count | Should -Be 1
                }
            }
            @($cfg.Templates | Where-Object { $_.ControlId -eq 'DL-2.2' -and $_.AppliesTo -eq 'Distribution' -and $_.Kind -eq 'Primary' }).Count | Should -Be 1
        }
        It 'the collector keeps the repo rule: no nested bare dot-access on API data, no Write-Host, SectionStatus published' {
            $src = Get-Content -LiteralPath $script:DlFiles[0] -Raw
            $src | Should -Not -Match 'Write-Host'
            $src | Should -Match 'SectionStatus'
            $src | Should -Match "Set-NRGRawData -Key 'EXO-DistributionLists'"
            $src | Should -Match 'Register-NRGCoverage'
        }
        It 'the evaluator and publisher never use Write-Host' {
            foreach ($i in 1, 2) { (Get-Content -LiteralPath $script:DlFiles[$i] -Raw) | Should -Not -Match 'Write-Host' }
        }
        It 'the entry script loads the psm1 (not the manifest, which requires the Graph module) and writes the results file through the restricted writer' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-NRGDistributionListScan.ps1') -Raw
            $src | Should -Match "NRG-Assessment\.psm1"
            $src | Should -Not -Match "NRG-Assessment\.psd1'\)"
            $src | Should -Match 'Set-NRGSensitiveFileContent -Path \$jsonPath'
            $src | Should -Not -Match 'Out-File|Set-Content|\[System\.IO\.File\]::WriteAll'
            (Get-Content -LiteralPath $script:DlFiles[2] -Raw) | Should -Not -Match 'Out-File|Set-Content|\[System\.IO\.File\]::WriteAll'
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# The real entry script, in a child process, against a fake Exchange Online module on the
# module path. Proves the whole path end to end with NO Graph module present, and that the
# files land where the script says.
Describe 'Invoke-NRGDistributionListScan.ps1 end to end (child process, fake Exchange module)' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-dl-e2e-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        $modDir = Join-Path $script:Tmp 'mods' 'ExchangeOnlineManagement'
        New-Item -ItemType Directory -Force -Path $modDir | Out-Null
        @'
$script:Connected = $false
function Connect-ExchangeOnline { [CmdletBinding()] param([switch] $ShowBanner, [switch] $DisableWAM, $UserPrincipalName, $DelegatedOrganization) $script:Connected = $true }
function Disconnect-ExchangeOnline { [CmdletBinding()] param($Confirm) $script:Connected = $false }
function Get-ConnectionInformation { [CmdletBinding()] param()
    if ($script:Connected) { [pscustomobject]@{ State = 'Connected'; IsEopSession = $false; ModuleName = 'ExchangeOnlineManagement'; TenantID = '0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a'; Organization = 'fabrikam.onmicrosoft.com'; UserPrincipalName = 'admin@fabrikam.com' } } }
function Get-AcceptedDomain { [CmdletBinding()] param()
    [pscustomobject]@{ DomainName = 'fabrikam.com'; InitialDomain = $false }; [pscustomobject]@{ DomainName = 'fabrikam.onmicrosoft.com'; InitialDomain = $true } }
function Get-DistributionGroup { [CmdletBinding()] param($ResultSize, [switch] $IncludeManagedByWithDisplayNames)
    [pscustomobject]@{ Name = 'all'; DisplayName = 'All Staff'; PrimarySmtpAddress = 'all@fabrikam.com'; Guid = '11111111-1111-1111-1111-111111111111'; RecipientTypeDetails = 'MailUniversalDistributionGroup'
        ManagedBy = @(); RequireSenderAuthenticationEnabled = $false; AcceptMessagesOnlyFrom = @(); AcceptMessagesOnlyFromDLMembers = @(); AcceptMessagesOnlyFromSendersOrMembers = @()
        ModerationEnabled = $false; ModeratedBy = @(); MemberJoinRestriction = 'Open'; MemberDepartRestriction = 'Open'; HiddenFromAddressListsEnabled = $false } }
function Get-DynamicDistributionGroup { [CmdletBinding()] param($ResultSize) }
function Get-DistributionGroupMember { [CmdletBinding()] param($Identity, $ResultSize)
    [pscustomobject]@{ RecipientType = 'UserMailbox'; RecipientTypeDetails = 'UserMailbox'; DisplayName = 'Alex Owner'; PrimarySmtpAddress = 'alex@fabrikam.com'; WindowsLiveID = 'alex@fabrikam.com' }
    [pscustomobject]@{ RecipientType = 'MailContact'; RecipientTypeDetails = 'MailContact'; DisplayName = 'Vendor'; PrimarySmtpAddress = 'v@vendor.example'; ExternalEmailAddress = 'SMTP:v@vendor.example' } }
function Get-DynamicDistributionGroupMember { [CmdletBinding()] param($Identity, $ResultSize) }
Export-ModuleMember -Function *
'@ | Set-Content -LiteralPath (Join-Path $modDir 'ExchangeOnlineManagement.psm1') -Encoding utf8
        $out = Join-Path $script:Tmp 'out'
        $pwsh = (Get-Process -Id $PID).Path
        $env:NRG_E2E_MODS = Join-Path $script:Tmp 'mods'
        $script:ChildLog = & $pwsh -NoProfile -NonInteractive -Command "`$env:PSModulePath = `$env:NRG_E2E_MODS + [IO.Path]::PathSeparator + `$env:PSModulePath; & '$(Join-Path $script:RepoRoot 'Invoke-NRGDistributionListScan.ps1')' -OutputPath '$out' -MemberLimit 50 ; exit `$LASTEXITCODE" 2>&1
        $script:ExitCode = $LASTEXITCODE
        $script:OutDir = $out
        # Console colors are ANSI escape codes; one in a failure message makes the NUnit XML report invalid.
        $script:ChildText = ((@($script:ChildLog) | Out-String) -replace '\x1B\[[0-9;]*[A-Za-z]', '')
    }
    AfterAll {
        Remove-Item Env:NRG_E2E_MODS -ErrorAction SilentlyContinue
        if ($script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'runs with no Graph module and exits 0 (complete)' {
        $script:ExitCode | Should -Be 0 -Because $script:ChildText
    }
    It 'writes the worksheet, the CSV and the results JSON, named for the connected tenant' {
        @(Get-ChildItem -LiteralPath $script:OutDir -Filter 'fabrikam-*-distribution-lists.txt').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $script:OutDir -Filter 'fabrikam-*-distribution-lists.csv').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $script:OutDir -Filter 'fabrikam-*-distribution-lists-results.json').Count | Should -Be 1
    }
    It 'the worksheet carries the gap and the text-only command, and the console says everything else was not assessed' {
        $txt = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $script:OutDir -Filter '*-distribution-lists.txt')[0].FullName -Raw
        $txt | Should -Match 'NEEDS ATTENTION'
        $txt | Should -Match "Set-DistributionGroup -Identity 'all@fabrikam\.com' -RequireSenderAuthenticationEnabled \`$true"
        $script:ChildText | Should -Match 'was NOT assessed'
    }
    It 'the results JSON records that only Exchange was used and Graph was not' {
        $j = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $script:OutDir -Filter '*-results.json')[0].FullName -Raw | ConvertFrom-Json
        @($j.Metadata.Services) | Should -Contain 'ExchangeOnline'
        $j.Connections.Graph | Should -BeFalse
        $j.Metadata.AssessmentMode | Should -Be 'DistributionListScan'
    }
}

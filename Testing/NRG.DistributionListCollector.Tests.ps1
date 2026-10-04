#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.DistributionListCollector.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Invoke-NRGCollectDistributionLists reads every distribution list and its members
             through the Exchange Online boundary. The boundary is stubbed with RAW API shapes
             (properties OMITTED, not nulled; enums as strings; lists as arrays) because a
             fixture of pre-computed fields never exercises the reader. Each test is a way a
             read can look like a clean answer without being one:
               * a failed query read as "no lists";
               * an omitted property read as an empty one ("no owner" vs "owner not read");
               * a throttled call read as "no members";
               * a list bigger than the limit read as a complete list;
               * an unclassifiable address read as internal.
    Data keys set: EXO-DistributionLists.  Graph scopes / cmdlets: none (stubs only).
#>

Describe 'Distribution-list collector' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        # Retries must not wait in a test.
        & $script:Mod { $script:NRGDlSleep = { param($s) $script:SleptFor += $s }; $script:SleptFor = @() }

        $script:Fixtures = @{}   # per-test stub data, read by the global stubs below
        function global:Get-AcceptedDomain {
            param($ErrorAction)
            if ($script:Fixtures.ContainsKey('AcceptedDomainsError')) { throw $script:Fixtures.AcceptedDomainsError }
            @($script:Fixtures.AcceptedDomains)
        }
        function global:Get-DistributionGroup {
            param($ResultSize, $ErrorAction)
            if ($script:Fixtures.ContainsKey('GroupsError')) { throw $script:Fixtures.GroupsError }
            @($script:Fixtures.Groups)
        }
        function global:Get-DynamicDistributionGroup {
            param($ResultSize, $ErrorAction)
            if ($script:Fixtures.ContainsKey('DynamicError')) { throw $script:Fixtures.DynamicError }
            @($script:Fixtures.Dynamic)
        }
        function global:Get-DistributionGroupMember {
            param($Identity, $ResultSize, $ErrorAction)
            $script:Fixtures.MemberCalls += , @("$Identity", $ResultSize)
            & $script:Fixtures.MemberBehavior "$Identity" $ResultSize
        }
        function global:Get-DynamicDistributionGroupMember {
            param($Identity, $ResultSize, $ErrorAction)
            @($script:Fixtures.DynamicMembers)
        }
        # Write cmdlets: if the collector ever reaches one, the test fails loudly.
        foreach ($w in 'Set-DistributionGroup', 'Set-DynamicDistributionGroup', 'Add-DistributionGroupMember', 'Remove-DistributionGroupMember', 'New-DistributionGroup', 'Remove-DistributionGroup') {
            Set-Item -Path "function:global:$w" -Value { throw 'A WRITE CMDLET WAS CALLED' }
        }

        $script:Domain = @([pscustomobject]@{ DomainName = 'contoso.com'; Default = $true }, [pscustomobject]@{ DomainName = 'contoso.onmicrosoft.com'; Default = $false })
        $script:Mbx = { param($n) [pscustomobject]@{ DisplayName = "User $n"; PrimarySmtpAddress = "u$n@contoso.com"; WindowsLiveID = "u$n@contoso.com"; RecipientType = 'UserMailbox'; RecipientTypeDetails = 'UserMailbox'; Department = 'Secret'; Phone = '555-0100' } }
        $script:Dg = { param($name, $guid, $extra = @{})
            $o = [ordered]@{ Name = $name; DisplayName = $name; PrimarySmtpAddress = "$name@contoso.com"; Guid = [guid]$guid; RecipientTypeDetails = 'MailUniversalDistributionGroup'
                ManagedBy = @('Alice'); RequireSenderAuthenticationEnabled = $true; AcceptMessagesOnlyFrom = @(); AcceptMessagesOnlyFromDLMembers = @(); AcceptMessagesOnlyFromSendersOrMembers = @()
                ModerationEnabled = $false; ModeratedBy = @(); MemberJoinRestriction = 'Closed'; MemberDepartRestriction = 'Open'; HiddenFromAddressListsEnabled = $false }
            foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] }
            [pscustomobject]$o }
        $script:Reset = {
            $script:Fixtures = @{ AcceptedDomains = $script:Domain; Groups = @(); Dynamic = @(); DynamicMembers = @(); MemberCalls = @()
                MemberBehavior = { param($id, $rs) @(& $script:Mbx 1) } }
            & $script:Mod { $script:SleptFor = @() }
            Clear-NRGState
        }
    }
    AfterAll {
        foreach ($f in 'Get-AcceptedDomain', 'Get-DistributionGroup', 'Get-DynamicDistributionGroup', 'Get-DistributionGroupMember', 'Get-DynamicDistributionGroupMember',
                       'Set-DistributionGroup', 'Set-DynamicDistributionGroup', 'Add-DistributionGroupMember', 'Remove-DistributionGroupMember', 'New-DistributionGroup', 'Remove-DistributionGroup') {
            Remove-Item -Path "function:global:$f" -ErrorAction SilentlyContinue
        }
        Clear-NRGState
        Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
    }
    BeforeEach { & $script:Reset }

    Context 'A normal read' {
        It 'returns one record per list with its settings and members, and a Collected status for every section' {
            $script:Fixtures.Groups = @(& $script:Dg 'sales' '11111111-1111-1111-1111-111111111111')
            $r = Invoke-NRGCollectDistributionLists
            $r.Success | Should -BeTrue
            $r.Data.SectionStatus.DistributionGroups | Should -Be 'Collected'
            $r.Data.SectionStatus.DynamicDistributionGroups | Should -Be 'Collected'
            $r.Data.SectionStatus.AcceptedDomains | Should -Be 'Collected'
            $r.Data.SectionStatus.Members | Should -Be 'Collected'
            $r.Data.TenantDomain | Should -Be 'contoso.com'
            $l = $r.Data.Lists[0]
            $l.ListType | Should -Be 'Distribution'
            $l.PrimarySmtpAddress | Should -Be 'sales@contoso.com'
            $l.RequireSenderAuthenticationEnabled | Should -BeTrue
            $l.MemberJoinRestriction | Should -Be 'Closed'
            @($l.Owners) | Should -Be @('Alice')
            $l.MemberStatus | Should -Be 'Collected'
            $l.MemberCount | Should -Be 1
        }
        It 'stores the result as raw data under EXO-DistributionLists' {
            $script:Fixtures.Groups = @(& $script:Dg 'sales' '11111111-1111-1111-1111-111111111111')
            $null = Invoke-NRGCollectDistributionLists
            (Get-NRGRawData -Key 'EXO-DistributionLists').CollectorId | Should -Be 'EXO-DistributionLists'
        }
        It 'a tenant with genuinely no lists is Collected, with an empty list (not Failed)' {
            $r = Invoke-NRGCollectDistributionLists
            $r.Data.SectionStatus.DistributionGroups | Should -Be 'Collected'
            @($r.Data.Lists).Count | Should -Be 0
        }
        It 'types lists by RecipientTypeDetails and reads a dynamic list through its own member cmdlet' {
            $script:Fixtures.Groups = @(
                (& $script:Dg 'sec' '22222222-2222-2222-2222-222222222222' @{ RecipientTypeDetails = 'MailUniversalSecurityGroup' }),
                (& $script:Dg 'rooms' '33333333-3333-3333-3333-333333333333' @{ RecipientTypeDetails = 'RoomList' }))
            $script:Fixtures.Dynamic = @([pscustomobject]@{ Name = 'ddg'; DisplayName = 'DDG'; PrimarySmtpAddress = 'ddg@contoso.com'; RecipientTypeDetails = 'DynamicDistributionGroup'; ManagedBy = @('Bob'); RequireSenderAuthenticationEnabled = $true
                AcceptMessagesOnlyFrom = @(); AcceptMessagesOnlyFromDLMembers = @(); AcceptMessagesOnlyFromSendersOrMembers = @(); ModerationEnabled = $false; ModeratedBy = @(); HiddenFromAddressListsEnabled = $false; RecipientFilter = "(RecipientType -eq 'UserMailbox')" })
            $script:Fixtures.DynamicMembers = @(& $script:Mbx 9)
            $r = Invoke-NRGCollectDistributionLists
            ($r.Data.Lists | Where-Object Name -eq 'sec').ListType | Should -Be 'MailEnabledSecurity'
            ($r.Data.Lists | Where-Object Name -eq 'rooms').ListType | Should -Be 'RoomList'
            $d = $r.Data.Lists | Where-Object Name -eq 'ddg'
            $d.ListType | Should -Be 'Dynamic'
            $d.RecipientFilter | Should -Match 'UserMailbox'
            $d.MemberCount | Should -Be 1
            $d.MemberJoinRestriction | Should -BeNullOrEmpty -Because 'a dynamic list has no join setting; it is not read, not defaulted'
        }
    }

    Context 'A failed query is never "no lists"' {
        It 'Get-DistributionGroup failing marks that section Failed and registers the exception, while the dynamic lists still read' {
            $script:Fixtures.GroupsError = 'The operation could not be performed (access denied).'
            $script:Fixtures.Dynamic = @([pscustomobject]@{ Name = 'ddg'; DisplayName = 'DDG'; PrimarySmtpAddress = 'ddg@contoso.com'; RecipientTypeDetails = 'DynamicDistributionGroup' })
            $r = Invoke-NRGCollectDistributionLists
            $r.Data.SectionStatus.DistributionGroups | Should -Be 'Failed'
            $r.Data.SectionStatus.DynamicDistributionGroups | Should -Be 'Collected'
            @($r.Data.Lists).Count | Should -Be 1
            @(Get-NRGExceptions | Where-Object Source -eq 'EXO-DL-DistributionGroups').Count | Should -Be 1
            (Get-NRGCoverage)['EXO-DistributionLists'].Status | Should -Be 'Partial'
        }
        It 'both list queries failing is a Failed coverage record, never Collected' {
            $script:Fixtures.GroupsError = 'boom'; $script:Fixtures.DynamicError = 'boom'
            $r = Invoke-NRGCollectDistributionLists
            @($r.Data.Lists).Count | Should -Be 0
            $r.Data.SectionStatus.DistributionGroups | Should -Be 'Failed'
            $r.Data.SectionStatus.DynamicDistributionGroups | Should -Be 'Failed'
            (Get-NRGCoverage)['EXO-DistributionLists'].Status | Should -Be 'Failed'
        }
        It 'a failed accepted-domain read marks AcceptedDomains Failed and leaves every member unclassified, never external or internal' {
            $script:Fixtures.AcceptedDomainsError = 'The request was throttled.'
            $script:Fixtures.Groups = @(& $script:Dg 'sales' '11111111-1111-1111-1111-111111111111')
            $script:Fixtures.MemberBehavior = { param($id, $rs) @([pscustomobject]@{ DisplayName = 'Eve'; PrimarySmtpAddress = 'eve@evil.tld'; RecipientType = 'MailContact'; RecipientTypeDetails = 'MailContact'; ExternalEmailAddress = 'SMTP:eve@evil.tld' }) }
            $r = Invoke-NRGCollectDistributionLists -ThrottleRetries 0
            $r.Data.SectionStatus.AcceptedDomains | Should -Be 'Failed'
            $l = $r.Data.Lists[0]
            @($l.ExternalMembers).Count | Should -Be 0 -Because 'with no accepted domains, "outside the tenant" has no meaning'
            $l.UnclassifiedMemberCount | Should -Be 1
        }
    }

    Context 'Omitted properties are "not read", not "empty"' {
        It 'a list with no ManagedBy, no RequireSenderAuthenticationEnabled and no sender restrictions reports those as not read (null), and names them' {
            $script:Fixtures.Groups = @([pscustomobject]@{ Name = 'sparse'; DisplayName = 'Sparse'; PrimarySmtpAddress = 'sparse@contoso.com'; RecipientTypeDetails = 'MailUniversalDistributionGroup' })
            $r = Invoke-NRGCollectDistributionLists
            $l = $r.Data.Lists[0]
            $l.Owners | Should -BeNullOrEmpty
            $null -eq $l.Owners | Should -BeTrue -Because 'an omitted ManagedBy is $null (not read), not an empty array (no owner)'
            $null -eq $l.RequireSenderAuthenticationEnabled | Should -BeTrue
            $null -eq $l.AcceptMessagesOnlyFrom | Should -BeTrue
            @($l.PropertiesNotReturned) | Should -Contain 'ManagedBy'
            @($l.PropertiesNotReturned) | Should -Contain 'RequireSenderAuthenticationEnabled'
            @($l.PropertiesNotReturned) | Should -Contain 'MemberJoinRestriction'
        }
        It 'a ManagedBy that came back EMPTY is an empty list (no owner), distinct from omitted' {
            $script:Fixtures.Groups = @(& $script:Dg 'orphan' '44444444-4444-4444-4444-444444444444' @{ ManagedBy = @() })
            $l = (Invoke-NRGCollectDistributionLists).Data.Lists[0]
            $null -ne $l.Owners | Should -BeTrue
            @($l.Owners).Count | Should -Be 0
            @($l.PropertiesNotReturned) | Should -Not -Contain 'ManagedBy'
        }
        It 'a boolean replayed as the string False is False, never $true' {
            $script:Fixtures.Groups = @(& $script:Dg 'str' '55555555-5555-5555-5555-555555555555' @{ RequireSenderAuthenticationEnabled = 'False'; ModerationEnabled = 'True' })
            $l = (Invoke-NRGCollectDistributionLists).Data.Lists[0]
            $l.RequireSenderAuthenticationEnabled | Should -BeFalse
            $l.ModerationEnabled | Should -BeTrue
        }
        It 'an unparseable boolean is not read, never coerced' {
            $script:Fixtures.Groups = @(& $script:Dg 'weird' '66666666-6666-6666-6666-666666666666' @{ RequireSenderAuthenticationEnabled = 'maybe' })
            $null -eq (Invoke-NRGCollectDistributionLists).Data.Lists[0].RequireSenderAuthenticationEnabled | Should -BeTrue
        }
    }

    Context 'Throttling and very large lists' {
        It 'a throttled member read is retried with backoff and then succeeds' {
            $script:Fixtures.Groups = @(& $script:Dg 'sales' '11111111-1111-1111-1111-111111111111')
            $script:Fixtures.Calls = 0
            $script:Fixtures.MemberBehavior = { param($id, $rs)
                $script:Fixtures.Calls++
                if ($script:Fixtures.Calls -le 2) { throw 'The request was throttled: you have exceeded your budget. Try again later.' }
                @(& $script:Mbx 1) }
            $r = Invoke-NRGCollectDistributionLists
            $r.Data.Lists[0].MemberStatus | Should -Be 'Collected'
            $r.Data.Stats.ThrottleRetries | Should -Be 2
            @(& $script:Mod { $script:SleptFor }) | Should -Be @(2, 4)
        }
        It 'a read still throttled after the retries fails THAT LIST only, says so, and is never "no members"' {
            $script:Fixtures.Groups = @(& $script:Dg 'a' '11111111-1111-1111-1111-111111111111'; & $script:Dg 'b' '22222222-2222-2222-2222-222222222222')
            $script:Fixtures.MemberBehavior = { param($id, $rs) if ($id -like '11111111*') { throw 'Too many requests (429).' } else { @(& $script:Mbx 2) } }
            $r = Invoke-NRGCollectDistributionLists -ThrottleRetries 2
            $a = $r.Data.Lists | Where-Object Name -eq 'a'
            $b = $r.Data.Lists | Where-Object Name -eq 'b'
            $a.MemberStatus | Should -Be 'Failed'
            $a.MemberError | Should -Match '429'
            $null -eq $a.MemberCount | Should -BeTrue -Because 'a failed read has no count, not a count of zero'
            $b.MemberStatus | Should -Be 'Collected'
            $r.Data.SectionStatus.Members | Should -Be 'Failed'
            $r.Data.Stats.ListsMembersFailed | Should -Be 1
            @(Get-NRGExceptions | Where-Object Source -eq 'EXO-DL-Members').Count | Should -Be 1
        }
        It 'a non-throttle error is not retried' {
            $script:Fixtures.Groups = @(& $script:Dg 'a' '11111111-1111-1111-1111-111111111111')
            $script:Fixtures.MemberBehavior = { param($id, $rs) throw 'Couldn''t find object "x".' }
            $r = Invoke-NRGCollectDistributionLists
            $r.Data.Stats.ThrottleRetries | Should -Be 0
            $r.Data.Lists[0].MemberStatus | Should -Be 'Failed'
        }
        It 'a list larger than the limit is read up to the limit, marked Truncated, and the limit+1 trick is what detects it' {
            $script:Fixtures.Groups = @(& $script:Dg 'big' '77777777-7777-7777-7777-777777777777')
            $script:Fixtures.MemberBehavior = { param($id, $rs) 1..$rs | ForEach-Object { & $script:Mbx $_ } }
            $r = Invoke-NRGCollectDistributionLists -MemberReadLimit 10
            $l = $r.Data.Lists[0]
            $l.MemberStatus | Should -Be 'Truncated'
            $l.MembersTruncated | Should -BeTrue
            $l.MemberCount | Should -Be 10
            @($l.Members).Count | Should -Be 10
            $script:Fixtures.MemberCalls[0][1] | Should -Be 11 -Because 'one more than the limit is requested, so exactly-at-the-limit and over-the-limit differ'
            $r.Data.Stats.ListsMembersTruncated | Should -Be 1
            (Get-NRGCoverage)['EXO-DistributionLists'].Status | Should -Be 'Partial'
        }
        It 'a list exactly at the limit is NOT truncated' {
            $script:Fixtures.Groups = @(& $script:Dg 'exact' '88888888-8888-8888-8888-888888888888')
            $script:Fixtures.MemberBehavior = { param($id, $rs) 1..10 | ForEach-Object { & $script:Mbx $_ } }
            (Invoke-NRGCollectDistributionLists -MemberReadLimit 10).Data.Lists[0].MemberStatus | Should -Be 'Collected'
        }
    }

    Context 'Members: classification, and the least data' {
        It 'a member carries ONLY a UPN and a display name — no phone, department or any other attribute' {
            $script:Fixtures.Groups = @(& $script:Dg 'sales' '11111111-1111-1111-1111-111111111111')
            $r = Invoke-NRGCollectDistributionLists
            $m = $r.Data.Lists[0].Members[0]
            @($m.Keys | Sort-Object) | Should -Be @('DisplayName', 'UPN')
            ($r | ConvertTo-Json -Depth 8) | Should -Not -Match '555-0100|Secret'
        }
        It 'classifies an external contact (via ExternalEmailAddress), a nested group, an internal user and an address-less contact' {
            $script:Fixtures.Groups = @(& $script:Dg 'mix' '99999999-9999-9999-9999-999999999999')
            $script:Fixtures.MemberBehavior = { param($id, $rs) @(
                (& $script:Mbx 1),
                [pscustomobject]@{ DisplayName = 'Vendor'; PrimarySmtpAddress = 'vendor.contact@contoso.com'; ExternalEmailAddress = 'SMTP:vendor@fabrikam.com'; RecipientType = 'MailContact'; RecipientTypeDetails = 'MailContact' },
                [pscustomobject]@{ DisplayName = 'Eng'; PrimarySmtpAddress = 'eng@contoso.com'; RecipientType = 'MailUniversalDistributionGroup'; RecipientTypeDetails = 'MailUniversalDistributionGroup' },
                [pscustomobject]@{ DisplayName = 'Nobody'; RecipientType = 'MailContact'; RecipientTypeDetails = 'MailContact' }) }
            $l = (Invoke-NRGCollectDistributionLists).Data.Lists[0]
            @($l.Members).Count | Should -Be 4
            @($l.ExternalMembers).Count | Should -Be 1
            $l.ExternalMembers[0].DisplayName | Should -Be 'Vendor'
            @($l.NestedGroups).Count | Should -Be 1
            $l.UnclassifiedMemberCount | Should -Be 1 -Because 'a member with no address is unclassified, never internal'
        }
        It 'a member whose address only LOOKS internal (a lookalike domain) is external' {
            $script:Fixtures.Groups = @(& $script:Dg 'look' 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
            $script:Fixtures.MemberBehavior = { param($id, $rs) @([pscustomobject]@{ DisplayName = 'Lookalike'; PrimarySmtpAddress = 'x@contoso.com.evil.tld'; RecipientType = 'MailContact'; RecipientTypeDetails = 'MailContact' }) }
            @((Invoke-NRGCollectDistributionLists).Data.Lists[0].ExternalMembers).Count | Should -Be 1
        }
    }

    Context 'Pinned to the Exchange Online session' {
        It 'resolves every cmdlet through Get-NRGExoCommand, never by a bare call' {
            $path = Join-Path $script:Root 'Collectors/EXO/Invoke-NRGCollectDistributionLists.ps1'
            $text = Get-Content -LiteralPath $path -Raw
            foreach ($n in 'Get-DistributionGroup', 'Get-DynamicDistributionGroup', 'Get-DistributionGroupMember', 'Get-DynamicDistributionGroupMember', 'Get-AcceptedDomain') {
                $text | Should -Match ([regex]::Escape("'$n'")) -Because "$n is resolved by name through Get-NRGExoCommand"
            }
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
            $bare = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and "$($n.GetCommandName())" -match '^Get-(Dynamic)?(DistributionGroup|DistributionGroupMember|AcceptedDomain)$' }, $true))
            $bare.Count | Should -Be 0 -Because 'a bare call would bind to whichever session loaded last'
        }
    }

    Context 'No write cmdlet is ever reached' {
        It 'a full read never invoked a stubbed write cmdlet (they all throw)' {
            $script:Fixtures.Groups = @(& $script:Dg 'sales' '11111111-1111-1111-1111-111111111111' @{ RequireSenderAuthenticationEnabled = $false; ManagedBy = @() })
            { Invoke-NRGCollectDistributionLists } | Should -Not -Throw
            @(Get-NRGExceptions | Where-Object Message -Match 'WRITE CMDLET').Count | Should -Be 0
        }
    }


    Context 'Regressions found in review' {
        It 'an exception message longer than Register-NRGException accepts does not abandon the reads that come after it' {
            # Regression: the over-long message made Register-NRGException throw from inside a catch block,
            # which escaped the whole collector, so the dynamic lists were never read (NotRun) and Success was false.
            $script:Fixtures.GroupsError = ('x' * 3000)
            $script:Fixtures.Dynamic = @([pscustomobject]@{ Name = 'ddg'; DisplayName = 'DDG'; PrimarySmtpAddress = 'ddg@contoso.com'; RecipientTypeDetails = 'DynamicDistributionGroup' })
            $r = Invoke-NRGCollectDistributionLists -ThrottleRetries 0
            $r.Success | Should -BeTrue
            $r.Data.SectionStatus.DistributionGroups | Should -Be 'Failed'
            $r.Data.SectionStatus.DynamicDistributionGroups | Should -Be 'Collected' -Because 'one failed section must not stop the next read'
            $e = @(Get-NRGExceptions | Where-Object Source -eq 'EXO-DL-DistributionGroups')
            $e.Count | Should -Be 1
            $e[0].Message.Length | Should -BeLessOrEqual 2000
        }
        It 'a mail-enabled group that is not universal (MailNonUniversalGroup) is a nested group, not a person' {
            # Regression: only universal group types were recognized, so a synced non-universal group was
            # classified as a person and left out of the nested-group list.
            $script:Fixtures.Groups = @(& $script:Dg 'mix' '99999999-9999-9999-9999-999999999999')
            $script:Fixtures.MemberBehavior = { param($id, $rs) @([pscustomobject]@{ DisplayName = 'Legacy group'; PrimarySmtpAddress = 'legacy@contoso.com'; RecipientType = 'MailNonUniversalGroup'; RecipientTypeDetails = 'MailNonUniversalGroup' }) }
            $l = (Invoke-NRGCollectDistributionLists).Data.Lists[0]
            @($l.NestedGroups).Count | Should -Be 1
            @($l.ExternalMembers).Count | Should -Be 0
        }
        It 'no person recipient type is mistaken for a group' {
            foreach ($t in 'UserMailbox', 'SharedMailbox', 'MailUser', 'MailContact', 'GuestMailUser', 'RoomMailbox', 'EquipmentMailbox', 'RemoteUserMailbox') {
                $k = & $script:Mod { param($type) Get-NRGDlMemberKind -Member ([pscustomobject]@{ RecipientTypeDetails = $type; RecipientType = $type; PrimarySmtpAddress = 'p@contoso.com' }) -AcceptedDomains @('contoso.com') } $t
                $k.Kind | Should -Be 'Person' -Because $t
            }
        }
    }
}

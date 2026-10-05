#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.DistributionListRemediation.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: The remediation SAFETY MODEL of the distribution-list scan. Every recommendation that
             has a command is a bundle: the state this scan captured, a check, a preview, the apply,
             a check afterwards, and a rollback that restores the CAPTURED state. These tests pin:
               - no captured original state, no command (and not one command-shaped string anywhere);
               - the rollback writes back what was captured, never a generic inverse;
               - the preview is the apply plus -WhatIf and nothing else, and the two never share a line or a cell;
               - a tenant-wide change is stricter (backup, -Confirm, and withheld when it cannot be rolled back);
               - every printed command fits a fixed grammar, so no tenant text can add a second command.
             Nothing here connects to Exchange or runs a printed command.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Distribution-list remediation bundles' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        # A bundle from the REAL catalog entry, in module scope (the builder is internal).
        $script:Rem = { param([string] $Control, [hashtable] $P)
            & $script:Mod { param($c, $p) New-NRGDlRemediation -Entry (Get-NRGDistributionListBaseline).ById[$c] @p } $Control $P }

        # Every string anywhere inside a bundle (or any nested structure).
        $script:Strings = { param($o)
            if ($null -eq $o) { return }
            if ($o -is [string]) { $o; return }
            if ($o -is [System.Collections.IDictionary]) { foreach ($v in $o.Values) { & $script:Strings $v }; return }
            if ($o -is [System.Collections.IEnumerable]) { foreach ($v in $o) { & $script:Strings $v }; return }
        }
        # Anything that reads as a command line.
        $script:CommandLike = '(?i)\b(Get|Set|Enable|Disable|Remove|Add|Export|New)-[A-Za-z]+\b'
        # The only shape a printed command may have: a cmdlet, switches, typed values, and at most one read-only pipe. Quoted
        # literals are collapsed to L first, so tenant text cannot add a statement, a pipeline stage or a subexpression.
        $script:Shape = { param([string] $Cmd)
            $t = [regex]::Replace($Cmd, "'(?:[^']|'')*'", 'L')
            $t -match '^(Get|Set|Enable|Disable)-[A-Za-z]+( -[A-Za-z]+( (\$true|\$false|\$null|@\{(Add|Remove)=L(,L)*\}|L(,L)*))?)*( \| Format-List (\*|[A-Za-z]+(, [A-Za-z]+)*))?$' }
        $script:Steps = { param($b) @($b.Backup.Command, $b.Precheck.Command, $b.Preview.Command, $b.Apply.Command, $b.Verify.Command, $b.Rollback.Command | Where-Object { $_ }) }

        # One representative, fully known input per control and kind.
        $script:Cases = @(
            @{ Name = 'DL-1.1 distribution'; C = 'DL-1.1'; P = @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $false; AfterValue = $true } }
            @{ Name = 'DL-1.1 dynamic';      C = 'DL-1.1'; P = @{ Kind = 'Dynamic'; Target = 'l@contoso.com'; BeforeValue = $false; AfterValue = $true } }
            @{ Name = 'DL-1.2';              C = 'DL-1.2'; P = @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @(); AfterValue = @('a@x.example', 'b@y.example'); Context = ([ordered]@{ RequireSenderAuthenticationEnabled = 'False' }) } }
            @{ Name = 'DL-2.1 distribution'; C = 'DL-2.1'; P = @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @() } }
            @{ Name = 'DL-2.1 dynamic';      C = 'DL-2.1'; P = @{ Kind = 'Dynamic'; Target = 'l@contoso.com'; BeforeValue = @() } }
            @{ Name = 'DL-2.2 distribution'; C = 'DL-2.2'; P = @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @(); Context = ([ordered]@{ ModerationEnabled = 'True' }) } }
            @{ Name = 'DL-2.2 dynamic';      C = 'DL-2.2'; P = @{ Kind = 'Dynamic'; Target = 'l@contoso.com'; BeforeValue = @(); Context = ([ordered]@{ ModerationEnabled = 'True' }) } }
            @{ Name = 'DL-2.5';              C = 'DL-2.5'; P = @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = 'Open'; AfterValue = 'Closed' } }
            @{ Name = 'DL-3.1';              C = 'DL-3.1'; P = @{ Kind = 'Tenant'; Target = 'Allow partner'; BeforeValue = 'Enabled'; AfterValue = 'Disabled' } }
            @{ Name = 'DL-3.2';              C = 'DL-3.2'; P = @{ Kind = 'Tenant'; Target = 'Default'; BeforeValue = [string[]]@('1.2.3.4', '5.6.7.0/24', '10.0.0.1-10.0.2.255'); Remove = [string[]]@('10.0.0.1-10.0.2.255') } }
            @{ Name = 'DL-3.3';              C = 'DL-3.3'; P = @{ Kind = 'Tenant'; Target = 'Default'; Parameter = 'AllowedSenders'; BeforeValue = [string[]]@('a@x.example', 'b@y.example'); Remove = [string[]]@('a@x.example') } }
        )

        # ── Hand-built collector output and findings, so the worksheet is exercised without an Exchange stub ─────────
        function script:NewList { param([string] $Addr = 'l@contoso.com', [string] $Kind = 'Distribution', [hashtable] $With = @{}, [string[]] $Omit = @())
            $o = [ordered]@{
                Name = 'List'; PrimarySmtpAddress = $Addr; Kind = $Kind; RequireSenderAuthenticationEnabled = $false; AllowedSendersKnown = $true; AllowedSenders = @()
                OwnersKnown = $true; OwnerCount = 0; Owners = @(); ModerationEnabled = $true; ModeratedBy = @(); ModeratedByKnown = $true
                MemberJoinRestriction = 'Open'; MemberDepartRestriction = 'Closed'; HiddenFromAddressListsEnabled = $false; IsDirSynced = $false
                MemberStatus = 'Collected'; MemberCount = 1; MembersTruncated = $false; ExternalMemberCount = 0; NestedGroupCount = 0; NestedGroups = @()
                Members = @([ordered]@{ DisplayName = 'Ann'; UPN = 'ann@contoso.com'; Address = 'ann@contoso.com'; RecipientType = 'UserMailbox'; Class = 'Internal' })
            }
            foreach ($k in $With.Keys) { $o[$k] = $With[$k] }
            foreach ($k in $Omit) { $o.Remove($k) }
            $o }
        function script:NewRaw { param($Lists = @(), $Rules = @(), $Conn = @(), $AntiSpam = @())
            @{ CollectorId = 'EXO-DistributionLists'; CollectedAt = '2026-10-04T10:00:00.0000000Z'; Success = $true
               Data = @{ Lists = @($Lists); AcceptedDomains = @('contoso.com')
                         BypassInputs = @{ TransportRules = @($Rules); ConnectionFilter = @($Conn); AntiSpamPolicies = @($AntiSpam); AntiSpamRulesRead = $true; AntiSpamRules = @() }
                         Stats = @{ MembersRead = 1 }; Limits = @{ MaxMembersPerList = 500; MaxLists = 5000; ListsSeen = 1; ListsTruncated = $false }
                         SectionStatus = @{ Lists = 'Collected'; DynamicLists = 'Collected'; Members = 'Collected'; AcceptedDomains = 'Collected'; TransportRules = 'Collected'; ConnectionFilter = 'Collected'; AntiSpam = 'Collected' } } } }
        function script:NewFinding { param([string] $Id, [string] $State = 'Gap', [string] $Instance = '', $Objects = @())
            [pscustomobject]@{ ControlId = $Id; State = $State; Instance = $Instance; Detail = "Shortfall: $Id test finding."; CurrentValue = ''; AffectedObjects = @($Objects) } }
        function script:NewRule { param([string] $Name, [hashtable] $With = @{})
            $o = [ordered]@{ Name = $Name; State = 'Enabled'; Mode = 'Enforce'; Priority = '1'; SetSCL = -1; ConditionsKnown = $true; Predicates = @() }
            foreach ($k in $With.Keys) { $o[$k] = $With[$k] }
            $o }
        # The worksheet for hand-built raw data and findings, with the join standard approved so DL-2.5 can produce a bundle.
        function script:NewSheet { param($Raw, $Findings)
            $std = Get-NRGDistributionListStandards -Standards ([ordered]@{ DistributionListMaxMembers = @(); DistributionListMemberJoinRestriction = @('Closed') })
            $ws = Get-NRGDistributionListWorksheet -Raw $Raw -Findings @($Findings) -Metadata @{ TenantDomain = 'contoso.onmicrosoft.com'; ToolVersion = 'test' } -Standards $std
            $txt = & $script:Mod { param($w) ConvertTo-NRGDlWorksheetText -Worksheet $w } $ws
            $csvRaw = & $script:Mod { param($w) ConvertTo-NRGDlWorksheetCsv -Worksheet $w } $ws
            [pscustomobject]@{ Worksheet = $ws; Txt = $txt; CsvRaw = $csvRaw; Csv = @($csvRaw | ConvertFrom-Csv) } }
        # Every bundle on the worksheet, tenant rows and list rows.
        function script:AllBundles { param($Ws) @(@($Ws.Tenant) + @($Ws.Lists | ForEach-Object { $_.Settings }) | ForEach-Object { $_.Remediations } | Where-Object { $null -ne $_ }) }
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'the bundle: observed state, check, preview, apply, verify, rollback' {

        It 'every recommendation with a command builds a complete bundle, and its preview is the apply plus -WhatIf and nothing else' {
            foreach ($c in $script:Cases) {
                $b = & $script:Rem $c.C $c.P
                $b.Available | Should -BeTrue -Because $c.Name
                $base = $b.Apply.Command -replace ' -Confirm$', ''
                $b.Preview.Command | Should -Be "$base -WhatIf" -Because "$($c.Name): what was previewed must be what is applied"
                $b.Apply.Command | Should -Not -Match '-WhatIf' -Because $c.Name
                $b.Preview.Command | Should -Not -Be $b.Apply.Command
                $b.Precheck.Command | Should -Match '^Get-' -Because $c.Name
                $b.Verify.Command | Should -Be $b.Precheck.Command -Because 'the same read, before and after, so the two outputs compare'
                $b.Precheck.Expect | Should -Match 'STOP' -Because 'the check says what to do when the state is not what the scan read'
                $b.Observed.Keys.Count | Should -BeGreaterThan 0 -Because $c.Name
                $b.Target.Identity | Should -Not -BeNullOrEmpty
            }
        }

        It 'the check, the verify and the backup are reads: no step except the apply, the preview and the rollback names a write cmdlet' {
            foreach ($c in $script:Cases) {
                $b = & $script:Rem $c.C $c.P
                foreach ($read in @($b.Precheck.Command, $b.Verify.Command, $b.Backup.Command) | Where-Object { $_ }) {
                    $read | Should -Not -Match '(?i)\b(Set|Enable|Disable|Remove|Add|New)-[A-Za-z]+' -Because "$($c.Name): $read"
                }
            }
        }

        It 'the rollback writes back the CAPTURED value, not the generic inverse' {
            $rb = { param($c, $p) (& $script:Rem $c $p).Rollback.Command }
            # a boolean: the value that was read, whichever it was
            (& $rb 'DL-1.1' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $false; AfterValue = $true }) | Should -Be "Set-DistributionGroup -Identity 'l@contoso.com' -RequireSenderAuthenticationEnabled `$false"
            (& $rb 'DL-1.1' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $true;  AfterValue = $false }) | Should -Be "Set-DistributionGroup -Identity 'l@contoso.com' -RequireSenderAuthenticationEnabled `$true"
            # an enum: each of the three documented values comes back as itself, and 'ApprovalRequired' does not become 'Open'
            foreach ($v in 'Open', 'ApprovalRequired', 'Closed') {
                $after = if ($v -eq 'Closed') { 'Open' } else { 'Closed' }
                (& $rb 'DL-2.5' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $v; AfterValue = $after }) | Should -Be "Set-DistributionGroup -Identity 'l@contoso.com' -MemberJoinRestriction '$v'"
            }
            # a captured EMPTY list is restored as $null; a captured list is restored as itself
            (& $rb 'DL-1.2' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @(); AfterValue = @('a@x.example') }) | Should -Be "Set-DistributionGroup -Identity 'l@contoso.com' -AcceptMessagesOnlyFromSendersOrMembers `$null"
            (& $rb 'DL-1.2' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @('old@x.example', 'older@y.example'); AfterValue = @('a@x.example') }) |
                Should -Be "Set-DistributionGroup -Identity 'l@contoso.com' -AcceptMessagesOnlyFromSendersOrMembers 'old@x.example','older@y.example'"
            # a list changed by removing entries: exactly those entries are put back, and the expectation after the rollback is the WHOLE captured list
            $b = & $script:Rem 'DL-3.2' @{ Kind = 'Tenant'; Target = 'Default'; BeforeValue = [string[]]@('1.2.3.4', '5.6.7.0/24', '10.0.0.1-10.0.2.255'); Remove = [string[]]@('10.0.0.1-10.0.2.255', '5.6.7.0/24') }
            $b.Apply.Command | Should -Match "@\{Remove='10\.0\.0\.1-10\.0\.2\.255','5\.6\.7\.0/24'\}"
            $b.Rollback.Command | Should -Match "@\{Add='10\.0\.0\.1-10\.0\.2\.255','5\.6\.7\.0/24'\} -Confirm$"
            $b.Rollback.Expect | Should -Match 'holds exactly: 1\.2\.3\.4, 5\.6\.7\.0/24, 10\.0\.0\.1-10\.0\.2\.255'
            $b.Verify.Expect | Should -Match 'holds exactly: 1\.2\.3\.4\.' -Because 'what the list should hold after the apply'
            # a rule: only the state it was in, and only when that state is the one the rollback command restores
            (& $rb 'DL-3.1' @{ Kind = 'Tenant'; Target = 'R'; BeforeValue = 'Enabled'; AfterValue = 'Disabled' }) | Should -Be "Enable-TransportRule -Identity 'R' -Confirm"
        }

        It 'a rollback that can restore only one state is withheld when that is not the state that was captured' {
            $b = & $script:Rem 'DL-3.1' @{ Kind = 'Tenant'; Target = 'R'; BeforeValue = 'Disabled'; AfterValue = 'Disabled' }
            $b.Available | Should -BeFalse
            $b.Reason | Should -Match "restores 'Enabled'"
            @(& $script:Steps $b) | Should -BeNullOrEmpty
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'no captured original state, no command' {

        It 'with the original value not known, every recommendation is withheld, with a reason, and not one command-shaped string is left' {
            foreach ($c in $script:Cases) {
                $p = $c.P.Clone(); $p['BeforeValue'] = $null
                $b = & $script:Rem $c.C $p
                $b.Available | Should -BeFalse -Because $c.Name
                $b.Reason | Should -Match 'not returned by Exchange' -Because $c.Name
                foreach ($step in 'Backup', 'Precheck', 'Preview', 'Apply', 'Verify', 'Rollback') { $b[$step] | Should -BeNullOrEmpty -Because "$($c.Name): $step must not exist for a bundle that was withheld" }
                @(& $script:Strings $b | Where-Object { $_ -match $script:CommandLike }) | Should -BeNullOrEmpty -Because "$($c.Name): a withheld bundle carries no command anywhere"
                @(& $script:Strings $b | Where-Object { $_ -match '(?i)-WhatIf|-Confirm|\$true|\$false|\$null' }) | Should -BeNullOrEmpty
            }
        }

        It 'a known-empty list and an unknown value are different answers: an empty list is restorable, an unknown one is not' {
            $known = & $script:Rem 'DL-1.2' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @(); AfterValue = @('a@x.example') }
            $known.Available | Should -BeTrue
            $known.Rollback.Command | Should -Match '\$null$'
            @($known.Notes | Where-Object { $_ -match 'does not document clearing it with \$null' }).Count | Should -Be 1 -Because 'the one undocumented rollback says so'
            $unknown = & $script:Rem 'DL-1.2' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $null; AfterValue = @('a@x.example') }
            $unknown.Available | Should -BeFalse
            # and the other direction: an unknown Target is not a command either
            foreach ($t in $null, '', '  ') {
                $b = & $script:Rem 'DL-1.1' @{ Kind = 'Distribution'; Target = $t; BeforeValue = $false; AfterValue = $true }
                $b.Available | Should -BeFalse -Because "target [$t]"
                $b.Reason | Should -Match 'name of the object to change was not returned' -Because 'a missing name is said to be missing, not blamed on quoting'
                @(& $script:Strings $b | Where-Object { $_ -match $script:CommandLike }) | Should -BeNullOrEmpty
            }
        }

        It 'an enum value outside what the catalog restores, or no new value, is not a command either' {
            # an After that is missing leaves the apply with nothing to set
            $b = & $script:Rem 'DL-2.5' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = 'Open' }
            $b.Available | Should -BeFalse
            @(& $script:Steps $b) | Should -BeNullOrEmpty
            # a kind the control has no command for (join restriction does not exist on a dynamic list)
            $d = & $script:Rem 'DL-2.5' @{ Kind = 'Dynamic'; Target = 'l@contoso.com'; BeforeValue = 'Open'; AfterValue = 'Closed' }
            $d.Available | Should -BeFalse
            $d.Reason | Should -Match 'no command for a Dynamic object'
        }

        It 'an entry to remove that is not in the captured list withholds the bundle: the state is not what the recommendation was built from' {
            $b = & $script:Rem 'DL-3.2' @{ Kind = 'Tenant'; Target = 'Default'; BeforeValue = [string[]]@('1.2.3.4'); Remove = [string[]]@('9.9.9.9') }
            $b.Available | Should -BeFalse
            $b.Reason | Should -Match 'not in the list this scan captured'
            @(& $script:Steps $b) | Should -BeNullOrEmpty
        }

        It 'a value that cannot be quoted safely anywhere in a bundle withholds the WHOLE bundle: a list with an entry dropped would be worse than none' {
            $bad = @("a$([char]0x2018)b", "a$([char]0x2019)b", "a$([char]0x201B)b", "a`nb", "a$([char]0x202E)b", "a$([char]0x200B)b", "a$([char]0x0085)b")
            foreach ($v in $bad) {
                $label = ('{0}' -f (($v.ToCharArray() | ForEach-Object { '{0:X4}' -f [int]$_ }) -join ' '))
                $cases = @(
                    @{ C = 'DL-1.1'; P = @{ Kind = 'Distribution'; Target = "l$v@contoso.com"; BeforeValue = $false; AfterValue = $true } }
                    @{ C = 'DL-2.5'; P = @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $v; AfterValue = 'Closed' } }
                    @{ C = 'DL-1.2'; P = @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @(); AfterValue = @('ok@x.example', "o$v@x.example", 'also@x.example') } }
                    @{ C = 'DL-3.2'; P = @{ Kind = 'Tenant'; Target = 'Default'; BeforeValue = [string[]]@('1.2.3.4', "5.6.7.0/24$v"); Remove = [string[]]@("5.6.7.0/24$v") } }
                    @{ C = 'DL-3.3'; P = @{ Kind = 'Tenant'; Target = "Pol$v"; Parameter = 'AllowedSenderDomains'; BeforeValue = [string[]]@('x.example'); Remove = [string[]]@('x.example') } }
                    @{ C = 'DL-3.1'; P = @{ Kind = 'Tenant'; Target = "Rule$v"; BeforeValue = 'Enabled'; AfterValue = 'Disabled' } }
                )
                foreach ($k in $cases) {
                    $b = & $script:Rem $k.C $k.P
                    $b.Available | Should -BeFalse -Because "$($k.C) with U+[$label]"
                    $b.Reason | Should -Match 'cannot be quoted safely'
                    @(& $script:Steps $b) | Should -BeNullOrEmpty -Because "$($k.C) with U+[$label]: no partial command"
                }
            }
        }

        It 'an entry that is only displayed, not named in any command, cannot reach a command: the bundle stands and none of its commands carries the text' {
            $v = "a$([char]0x2019)b"
            $b = & $script:Rem 'DL-3.2' @{ Kind = 'Tenant'; Target = 'Default'; BeforeValue = [string[]]@('1.2.3.4', "5.6.7.0/24$v"); Remove = [string[]]@('1.2.3.4') }
            $b.Available | Should -BeTrue
            @(& $script:Steps $b | Where-Object { $_.Contains($v) }) | Should -BeNullOrEmpty
        }

        It 'an unrecognized parameter word withholds the anti-spam bundle' {
            $b = & $script:Rem 'DL-3.3' @{ Kind = 'Tenant'; Target = 'Default'; Parameter = 'BlockedSenders; calc'; BeforeValue = [string[]]@('x'); Remove = [string[]]@('x') }
            $b.Available | Should -BeFalse
        }

        It 'a caller-supplied reason (a synchronized list, an external member, a preset policy) withholds the bundle with that reason' {
            $b = & $script:Rem 'DL-1.1' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $false; AfterValue = $true; Withhold = 'Synchronized from on-premises Active Directory.' }
            $b.Available | Should -BeFalse
            $b.Reason | Should -Be 'Synchronized from on-premises Active Directory.'
            @(& $script:Steps $b) | Should -BeNullOrEmpty
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'a change that reaches every recipient is stricter' {

        It 'carries a backup, asks for confirmation on the apply and the rollback, and does not put -Confirm on the preview' {
            foreach ($c in @($script:Cases | Where-Object { $_.C -in 'DL-3.1', 'DL-3.2', 'DL-3.3' })) {
                $b = & $script:Rem $c.C $c.P
                $b.Impact | Should -Be 'TenantWide' -Because $c.Name
                $b.Backup.Command | Should -Match "^Get-[A-Za-z]+ -Identity '[^']+' \| Format-List \*$" -Because 'the backup is a read that prints every property: it writes no file, and the repo bans serializing objects to disk'
                $b.Backup.Command | Should -Not -Match 'Export-|Out-File|Set-Content|>' -Because 'a backup that writes a file is a write path'
                $b.Apply.Command | Should -Match ' -Confirm$'
                $b.Rollback.Command | Should -Match ' -Confirm$'
                $b.Preview.Command | Should -Not -Match '-Confirm'
                $b.Rollback.Available | Should -BeTrue
                $b.OneWay | Should -BeFalse
                $b.Notes -join ' ' | Should -Match 'Tenant-wide'
            }
            foreach ($c in @($script:Cases | Where-Object { $_.C -notin 'DL-3.1', 'DL-3.2', 'DL-3.3' })) {
                $b = & $script:Rem $c.C $c.P
                $b.Impact | Should -Be 'Standard' -Because $c.Name
                $b.Backup | Should -BeNullOrEmpty
                $b.Apply.Command | Should -Not -Match '-Confirm'
            }
        }

        It 'is withheld outright when no rollback can be built for it, rather than offered one-way' {
            $b = & $script:Mod {
                $e = (Get-NRGDistributionListBaseline).ById['DL-3.2']
                $e.Remediation.Kinds['Tenant'].Rollback = ''
                New-NRGDlRemediation -Entry $e -Kind Tenant -Target 'Default' -BeforeValue ([string[]]@('1.2.3.4', '10.0.0.0/8')) -Remove ([string[]]@('10.0.0.0/8'))
            }
            $b.Available | Should -BeFalse
            $b.Reason | Should -Match 'tenant-wide change is offered only with a rollback'
            @(& $script:Steps $b) | Should -BeNullOrEmpty
        }

        It 'a single-object change may be one-way when the captured state cannot be written back, and says so in words: the owner of an ownerless list' {
            $b = & $script:Rem 'DL-2.1' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @() }
            $b.Available | Should -BeTrue
            $b.OneWay | Should -BeTrue
            $b.Rollback.Available | Should -BeFalse
            $b.Rollback.Command | Should -BeNullOrEmpty
            $b.Rollback.Reason | Should -Match 'at least one owner'
            $b.RequiresInput | Should -Contain 'owner'
            $b.Notes -join ' ' | Should -Match '<owner>'
            $b.Apply.Command | Should -Match "-ManagedBy '<owner>'$"
        }

        It 'a command that needs an administrator-chosen name is the only one that carries a <placeholder>' {
            foreach ($c in $script:Cases) {
                $b = & $script:Rem $c.C $c.P
                $hasPlaceholder = @(& $script:Steps $b | Where-Object { $_ -match "'<\w+>'" }).Count -gt 0
                $hasPlaceholder | Should -Be (@($b.RequiresInput).Count -gt 0) -Because $c.Name
            }
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'every printed command has one fixed shape, so tenant text cannot add a second command' {

        It 'the grammar itself rejects a second statement, a pipeline into anything but a read, and a subexpression' {
            foreach ($ok in "Set-DistributionGroup -Identity 'a@b.c' -RequireSenderAuthenticationEnabled `$true -WhatIf",
                            "Get-DistributionGroup -Identity 'a@b.c' | Format-List Name, PrimarySmtpAddress",
                            "Set-HostedConnectionFilterPolicy -Identity 'Default' -IPAllowList @{Remove='1.2.3.4','5.6.7.8'} -Confirm") { (& $script:Shape $ok) | Should -BeTrue -Because $ok }
            foreach ($bad in "Set-X -Identity 'a'; Remove-Item x",
                             "Set-X -Identity 'a' | Remove-Item",
                             "Set-X -Identity `$(calc)",
                             "Set-X -Identity 'a' & calc",
                             "Set-X -Identity a",
                             "Set-X -Identity 'a'`nSet-Y",
                             "Get-X | Where-Object { `$_ }") { (& $script:Shape $bad) | Should -BeFalse -Because $bad }
        }

        It 'every command in every bundle fits the grammar, however hostile the tenant text in it' {
            $hostile = @("o'brien@contoso.com", "x'; Remove-Item -Recurse C:\ ; '@contoso.com", "a`$(calc)@contoso.com", 'a{After}b@contoso.com', 'a$1b$&c@contoso.com', 'a|b@contoso.com', 'a;b@contoso.com', 'a&b@contoso.com', 'a`b@contoso.com')
            foreach ($h in $hostile) {
                $built = @(
                    @{ C = 'DL-1.1'; P = @{ Kind = 'Distribution'; Target = $h; BeforeValue = $false; AfterValue = $true } }
                    @{ C = 'DL-1.2'; P = @{ Kind = 'Distribution'; Target = $h; BeforeValue = @(); AfterValue = @($h, 'b@y.example') } }
                    @{ C = 'DL-2.1'; P = @{ Kind = 'Distribution'; Target = $h; BeforeValue = @() } }
                    @{ C = 'DL-3.1'; P = @{ Kind = 'Tenant'; Target = $h; BeforeValue = 'Enabled'; AfterValue = 'Disabled' } }
                    @{ C = 'DL-3.2'; P = @{ Kind = 'Tenant'; Target = $h; BeforeValue = [string[]]@($h, '1.2.3.4'); Remove = [string[]]@($h) } }
                    @{ C = 'DL-3.3'; P = @{ Kind = 'Tenant'; Target = $h; Parameter = 'AllowedSenders'; BeforeValue = [string[]]@($h, 'z@x.example'); Remove = [string[]]@($h) } })
                foreach ($k in $built) {
                    $b = & $script:Rem $k.C $k.P
                    $b.Available | Should -BeTrue -Because "$($k.C): the text is quoted, not refused: [$h]"
                    foreach ($cmd in @(& $script:Steps $b)) { (& $script:Shape $cmd) | Should -BeTrue -Because "$($k.C) [$h]: $cmd" }
                }
            }
            foreach ($c in $script:Cases) { foreach ($cmd in @(& $script:Steps (& $script:Rem $c.C $c.P))) { (& $script:Shape $cmd) | Should -BeTrue -Because "$($c.Name): $cmd" } }
        }

        It 'no command carries a line break' {
            foreach ($c in $script:Cases) { foreach ($cmd in @(& $script:Steps (& $script:Rem $c.C $c.P))) { $cmd | Should -Not -Match '[\r\n]' } }
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'on the worksheet: a recommendation whose original state is not in the data is withheld, even when the finding says Gap' {

        It 'DL-1.1, DL-1.2, DL-2.1, DL-2.2 and DL-2.5 are withheld when the property they restore was not returned' {
            $cases = @(
                @{ Id = 'DL-1.1'; Omit = @('RequireSenderAuthenticationEnabled'); Findings = @(NewFinding 'DL-1.1' 'Gap' 'l@contoso.com') }
                @{ Id = 'DL-2.1'; With = @{ OwnersKnown = $false; RequireSenderAuthenticationEnabled = $true }; Findings = @(NewFinding 'DL-2.1' 'Gap' 'l@contoso.com') }
                @{ Id = 'DL-2.2'; With = @{ ModeratedByKnown = $false; RequireSenderAuthenticationEnabled = $true }; Findings = @(NewFinding 'DL-2.2' 'Gap' 'l@contoso.com') }
                @{ Id = 'DL-2.5'; With = @{ MemberJoinRestriction = ''; RequireSenderAuthenticationEnabled = $true }; Findings = @(NewFinding 'DL-2.5' 'Gap' 'l@contoso.com') }
                @{ Id = 'DL-2.5'; With = @{ MemberJoinRestriction = 'Sometimes'; RequireSenderAuthenticationEnabled = $true }; Findings = @(NewFinding 'DL-2.5' 'Gap' 'l@contoso.com') }
                @{ Id = 'DL-1.2'; With = @{ AllowedSendersKnown = $false }; Findings = @() }
            )
            foreach ($c in $cases) {
                $with = if ($c.ContainsKey('With')) { $c.With } else { @{} }
                $omit = if ($c.ContainsKey('Omit')) { $c.Omit } else { @() }
                $sheet = NewSheet (NewRaw -Lists @(NewList -With $with -Omit $omit)) $c.Findings
                $row = @($sheet.Worksheet.Lists[0].Settings | Where-Object { $_.ControlId -eq $c.Id })[0]
                $bundles = @($row.Remediations)
                @($bundles | Where-Object { $_.Available }).Count | Should -Be 0 -Because "$($c.Id) with $(($with.Keys + $omit) -join ',')"
                foreach ($b in $bundles) { @(& $script:Steps $b) | Should -BeNullOrEmpty }
                @($sheet.Csv | Where-Object { $_.ControlId -eq $c.Id -and $_.Step -in 'Apply', 'Preview', 'Rollback', 'Check' }).Count | Should -Be 0 -Because "$($c.Id): no command row in the CSV"
                $sheet.Txt | Should -Not -Match "(?m)^\s+> (Set|Enable|Disable)-" -Because "$($c.Id): no write command line in the text"
            }
        }

        It 'DL-3.1: a rule that is not in the collected rules, is named by two rules, has no state, or is not enabled gets no command' {
            $obj = @([ordered]@{ Source = 'Mail flow rule'; Name = 'R1'; Class = 'NoSenderCondition'; Detail = '' })
            $f = @(NewFinding 'DL-3.1' 'Gap' '' $obj)
            $cases = @(
                @{ Why = 'not in the rules read'; Rules = @(NewRule 'Other') }
                @{ Why = 'named by two rules'; Rules = @((NewRule 'R1'), (NewRule 'R1')) }
                @{ Why = 'no state'; Rules = @(NewRule 'R1' @{ State = '' }) }
                @{ Why = 'not enabled'; Rules = @(NewRule 'R1' @{ State = 'Disabled' }) }
            )
            foreach ($c in $cases) {
                $sheet = NewSheet (NewRaw -Lists @(NewList) -Rules $c.Rules) $f
                $row = @($sheet.Worksheet.Tenant | Where-Object { $_.ControlId -eq 'DL-3.1' })[0]
                @($row.Remediations).Count | Should -Be 1 -Because $c.Why
                $row.Remediations[0].Available | Should -BeFalse -Because $c.Why
                @(& $script:Steps $row.Remediations[0]) | Should -BeNullOrEmpty -Because $c.Why
            }
            $ok = NewSheet (NewRaw -Lists @(NewList) -Rules @(NewRule 'R1')) $f
            $b = @(@($ok.Worksheet.Tenant | Where-Object { $_.ControlId -eq 'DL-3.1' })[0].Remediations)[0]
            $b.Available | Should -BeTrue
            $b.Observed['State'] | Should -Be 'Enabled'
            $b.Observed['Mode'] | Should -Be 'Enforce'
            $b.Rollback.Command | Should -Be "Enable-TransportRule -Identity 'R1' -Confirm"
        }

        It 'DL-3.2: one bundle per policy, each rollback re-adds only that policy''s own entries, and a policy that cannot be tied to one captured list is withheld' {
            $obj = { param($pol, $name) [ordered]@{ Source = 'IP Allow List'; Name = $name; Policy = $pol; Class = 'WiderThan24'; Detail = '' } }
            $f = @(NewFinding 'DL-3.2' 'Gap' '' @((& $obj 'P1' '10.0.0.0/8'), (& $obj 'P1' '11.0.0.1-11.0.5.5'), (& $obj 'P2' '12.0.0.1-12.0.9.9')))
            $conn = @([pscustomobject]@{ Name = 'P1'; IsDefault = $true; IPAllowList = @('1.2.3.4', '10.0.0.0/8', '11.0.0.1-11.0.5.5') }
                      [pscustomobject]@{ Name = 'P2'; IsDefault = $false; IPAllowList = @('12.0.0.1-12.0.9.9') })
            $sheet = NewSheet (NewRaw -Lists @(NewList) -Conn $conn) $f
            $bundles = @(@($sheet.Worksheet.Tenant | Where-Object { $_.ControlId -eq 'DL-3.2' })[0].Remediations)
            $bundles.Count | Should -Be 2
            $p1 = $bundles | Where-Object { $_.Target.Identity -eq 'P1' }
            $p2 = $bundles | Where-Object { $_.Target.Identity -eq 'P2' }
            $p1.Apply.Command | Should -Be "Set-HostedConnectionFilterPolicy -Identity 'P1' -IPAllowList @{Remove='10.0.0.0/8','11.0.0.1-11.0.5.5'} -Confirm"
            $p1.Rollback.Command | Should -Be "Set-HostedConnectionFilterPolicy -Identity 'P1' -IPAllowList @{Add='10.0.0.0/8','11.0.0.1-11.0.5.5'} -Confirm"
            $p1.Observed['IPAllowList'] | Should -Be '1.2.3.4, 10.0.0.0/8, 11.0.0.1-11.0.5.5'
            $p2.Rollback.Command | Should -Not -Match '10\.0\.0\.0|11\.0\.0\.1'
            $p1.Backup.Command | Should -Be "Get-HostedConnectionFilterPolicy -Identity 'P1' | Format-List *"
            $p2.Backup.Command | Should -Be "Get-HostedConnectionFilterPolicy -Identity 'P2' | Format-List *"
            # a policy name the finding carries but the raw data does not, or no name at all
            foreach ($name in 'Ghost', '') {
                $g = NewSheet (NewRaw -Lists @(NewList) -Conn $conn) @(NewFinding 'DL-3.2' 'Gap' '' @((& $obj $name '10.0.0.0/8')))
                $gb = @(@($g.Worksheet.Tenant | Where-Object { $_.ControlId -eq 'DL-3.2' })[0].Remediations)
                $gb.Count | Should -Be 1
                $gb[0].Available | Should -BeFalse -Because "policy [$name]"
                @(& $script:Steps $gb[0]) | Should -BeNullOrEmpty
            }
        }

        It 'DL-3.3: a preset security policy is never offered a command, and a policy that is not in the data is withheld' {
            $obj = { param($pol, $name) [ordered]@{ Source = 'Anti-spam policy'; Name = $name; Policy = $pol; Class = 'allowed sender'; Detail = '' } }
            $pols = @([ordered]@{ Name = 'Standard Preset Security Policy'; IsDefault = $false; RecommendedPolicyType = 'Standard'; AllowedSenders = @('a@x.example'); AllowedSenderDomains = @() }
                      [ordered]@{ Name = 'Strict Preset Security Policy'; IsDefault = $false; RecommendedPolicyType = 'Strict'; AllowedSenders = @('b@x.example'); AllowedSenderDomains = @() }
                      [ordered]@{ Name = 'Default'; IsDefault = $true; RecommendedPolicyType = ''; AllowedSenders = @('c@x.example', 'd@x.example'); AllowedSenderDomains = @() })
            $f = @(NewFinding 'DL-3.3' 'Gap' '' @((& $obj 'Standard Preset Security Policy' 'a@x.example'), (& $obj 'Strict Preset Security Policy' 'b@x.example'), (& $obj 'Default' 'c@x.example'), (& $obj 'Default' 'd@x.example'), (& $obj 'Ghost' 'e@x.example')))
            $sheet = NewSheet (NewRaw -Lists @(NewList) -AntiSpam $pols) $f
            $bundles = @(@($sheet.Worksheet.Tenant | Where-Object { $_.ControlId -eq 'DL-3.3' })[0].Remediations)
            $bundles.Count | Should -Be 4
            @($bundles | Where-Object { $_.Available }).Count | Should -Be 1
            $d = $bundles | Where-Object { $_.Available }
            $d.Target.Identity | Should -Be 'Default'
            $d.Apply.Command | Should -Be "Set-HostedContentFilterPolicy -Identity 'Default' -AllowedSenders @{Remove='c@x.example','d@x.example'} -Confirm"
            $d.Rollback.Command | Should -Be "Set-HostedContentFilterPolicy -Identity 'Default' -AllowedSenders @{Add='c@x.example','d@x.example'} -Confirm"
            @($bundles | Where-Object { -not $_.Available -and $_.Reason -match 'preset security policy' }).Count | Should -Be 2
            foreach ($b in @($bundles | Where-Object { -not $_.Available })) { @(& $script:Steps $b) | Should -BeNullOrEmpty }
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'the worksheet model, the text file and the CSV agree, and keep the apply apart from the preview' {

        BeforeAll {
            $script:Mixed = {
                $obj31 = @([ordered]@{ Source = 'Mail flow rule'; Name = 'Allow partner'; Class = 'SenderDomainOnly'; Detail = '' }, [ordered]@{ Source = 'Mail flow rule'; Name = 'Ghost rule'; Class = 'NoSenderCondition'; Detail = '' })
                $obj32 = @([ordered]@{ Source = 'IP Allow List'; Name = '10.0.0.0/8'; Policy = 'Default'; Class = 'WiderThan24'; Detail = '' })
                $obj33 = @([ordered]@{ Source = 'Anti-spam policy'; Name = 'x.example'; Policy = 'Default'; Class = 'allowed domain'; Detail = '' })
                $lists = @(
                    (NewList 'open@contoso.com' -With @{ Name = 'Open' })
                    (NewList 'ext@contoso.com' -With @{ Name = 'Ext'; ExternalMemberCount = 1; Members = @([ordered]@{ DisplayName = 'Vendor'; UPN = 'v@vendor.example'; Address = 'v@vendor.example'; RecipientType = 'MailContact'; Class = 'External' }) })
                    (NewList 'dyn@contoso.com' 'Dynamic' -With @{ Name = 'Dyn'; MemberJoinRestriction = '' } -Omit @('MemberJoinRestriction'))
                    (NewList 'synced@contoso.com' -With @{ Name = 'Synced'; IsDirSynced = $true }))
                $f = @(
                    (NewFinding 'DL-1.1' 'Gap' 'open@contoso.com'), (NewFinding 'DL-1.1' 'Gap' 'ext@contoso.com'), (NewFinding 'DL-1.1' 'Gap' 'dyn@contoso.com'), (NewFinding 'DL-1.1' 'Gap' 'synced@contoso.com')
                    (NewFinding 'DL-2.1' 'Gap' 'open@contoso.com'), (NewFinding 'DL-2.2' 'Gap' 'open@contoso.com'), (NewFinding 'DL-2.5' 'Gap' 'open@contoso.com')
                    (NewFinding 'DL-3.1' 'Gap' '' $obj31), (NewFinding 'DL-3.2' 'Gap' '' $obj32), (NewFinding 'DL-3.3' 'Gap' '' $obj33))
                $rules = @((NewRule 'Allow partner'))
                $conn = @([pscustomobject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = @('10.0.0.0/8') })
                $pols = @([ordered]@{ Name = 'Default'; IsDefault = $true; RecommendedPolicyType = ''; AllowedSenders = @(); AllowedSenderDomains = @('x.example') })
                NewSheet (NewRaw -Lists $lists -Rules $rules -Conn $conn -AntiSpam $pols) $f
            }
        }

        It 'holds every invariant of the model over a mixed worksheet: withheld means no step, available means a rollback unless one-way, tenant-wide means backup and -Confirm' {
            $sheet = & $script:Mixed
            $bundles = @(AllBundles $sheet.Worksheet)
            $bundles.Count | Should -BeGreaterThan 8
            @($bundles | Where-Object { $_.Available }).Count | Should -BeGreaterThan 4
            @($bundles | Where-Object { -not $_.Available }).Count | Should -BeGreaterThan 2
            foreach ($b in $bundles) {
                if (-not $b.Available) {
                    $b.Reason | Should -Not -BeNullOrEmpty
                    @(& $script:Steps $b) | Should -BeNullOrEmpty
                    continue
                }
                $b.Observed.Keys.Count | Should -BeGreaterThan 0
                $b.ObservedAt | Should -Be '2026-10-04T10:00:00.0000000Z'
                $b.Preview.Command | Should -Be (($b.Apply.Command -replace ' -Confirm$', '') + ' -WhatIf')
                if ($b.OneWay) { $b.Impact | Should -Be 'Standard'; $b.Rollback.Available | Should -BeFalse; $b.Rollback.Reason | Should -Not -BeNullOrEmpty }
                else { $b.Rollback.Available | Should -BeTrue; $b.Rollback.Command | Should -Not -BeNullOrEmpty }
                if ($b.Impact -eq 'TenantWide') { $b.Backup | Should -Not -BeNullOrEmpty; $b.Apply.Command | Should -Match ' -Confirm$'; $b.OneWay | Should -BeFalse }
                foreach ($cmd in @(& $script:Steps $b)) { (& $script:Shape $cmd) | Should -BeTrue -Because $cmd }
            }
            # the list that holds an external member is not given the command that would stop that member sending; a synchronized list gets none
            $ext = @(@(($sheet.Worksheet.Lists | Where-Object { $_.Address -eq 'ext@contoso.com' }).Settings | Where-Object { $_.ControlId -eq 'DL-1.1' })[0].Remediations)
            $ext.Count | Should -Be 1; $ext[0].Available | Should -BeFalse; $ext[0].Reason | Should -Match 'external member'
            foreach ($row in @(($sheet.Worksheet.Lists | Where-Object { $_.Address -eq 'synced@contoso.com' }).Settings)) { @($row.Remediations | Where-Object { $_.Available }).Count | Should -Be 0 }
        }

        It 'the text prints the apply on its own labeled line, never the same line as the preview, and every command of the model is in the text exactly' {
            $sheet = & $script:Mixed
            $lines = @($sheet.Txt -split "`r?`n")
            @($lines | Where-Object { $_ -match '^\s+> .* -WhatIf$' }).Count | Should -BeGreaterThan 4
            foreach ($l in $lines) { if ($l -match '-WhatIf') { $l | Should -Not -Match "-Confirm" ; ([regex]::Matches($l, '(Set|Disable|Enable)-[A-Za-z]+')).Count | Should -BeLessOrEqual 1 } }
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^\s+2\. PREVIEW') { $lines[$i + 1] | Should -Match ' -WhatIf$' }
                if ($lines[$i] -match '^\s+3\. APPLY') {
                    $lines[$i] | Should -Match 'CHANGES THE TENANT'
                    $j = $i + 1; while ($lines[$j] -notmatch '^\s+> ') { $j++ }
                    $lines[$j] | Should -Not -Match '-WhatIf'
                }
            }
            foreach ($b in @(AllBundles $sheet.Worksheet | Where-Object { $_.Available })) {
                foreach ($cmd in @(& $script:Steps $b)) { @($lines | Where-Object { $_.Trim() -eq "> $cmd" }).Count | Should -BeGreaterOrEqual 1 -Because "the text must carry $cmd verbatim" }
                if (-not $b.OneWay) { $sheet.Txt | Should -Match 'ROLLBACK  \(restores the state this scan read' }
            }
            $sheet.Txt | Should -Match 'ROLLBACK  NOT AVAILABLE'
            $sheet.Txt | Should -Match 'REMEDIATION WITHHELD \[DL-1\.1\]'
            $sheet.Txt | Should -Match 'BACKUP  \(read-only'
        }

        It 'the CSV has one row per step and one command per cell: a preview and an apply never share a cell, and no cell chains commands' {
            $sheet = & $script:Mixed
            $rem = @($sheet.Csv | Where-Object { $_.RowType -eq 'Remediation' })
            $rem.Count | Should -BeGreaterThan 20
            foreach ($r in $rem) { $r.Step | Should -BeIn @('Observed', 'Backup', 'Check', 'Preview', 'Apply', 'Verify', 'Rollback', 'Note', 'Withheld') }
            foreach ($r in @($sheet.Csv | Where-Object { $_.Command -and $_.Step -ne 'Inspect' })) {
                $r.Command | Should -Not -Match '[;&\r\n]' -Because 'a cell that chained a preview and an apply would run both when pasted'
                (& $script:Shape $r.Command) | Should -BeTrue -Because $r.Command
                if ($r.Step -eq 'Preview') { $r.Command | Should -Match ' -WhatIf$' }
                if ($r.Step -eq 'Apply') { $r.Command | Should -Not -Match '-WhatIf' }
            }
            @($rem | Where-Object { $_.Step -eq 'Withheld' } | Where-Object { $_.Command }) | Should -BeNullOrEmpty -Because 'a withheld row has a reason and no command'
            @($rem | Where-Object { $_.Step -eq 'Withheld' -and -not $_.Detail }) | Should -BeNullOrEmpty
            # every command in the model is in the CSV, as its own cell, exactly once per bundle
            foreach ($b in @(AllBundles $sheet.Worksheet | Where-Object { $_.Available })) {
                foreach ($cmd in @(& $script:Steps $b)) { @($sheet.Csv | Where-Object { $_.Command -eq $cmd }).Count | Should -BeGreaterOrEqual 1 -Because $cmd }
            }
            $sheet.CsvRaw | Should -Not -Match 'AdminCommand'
        }

        It 'the read-only look at a tenant-wide setting is printed beside a shortfall, and is a read' {
            $sheet = & $script:Mixed
            $ins = @($sheet.Csv | Where-Object { $_.RowType -eq 'Inspect' })
            $ins.Count | Should -BeGreaterOrEqual 3
            foreach ($r in $ins) { $r.Command | Should -Match '^Get-' }
            $sheet.Txt | Should -Match 'Read-only look at the setting \(no change\)'
        }

        It 'prints the note that NRG observes and recommends and an administrator authorizes and executes' {
            $sheet = & $script:Mixed
            $sheet.Worksheet.CommandNote | Should -Match 'administrator authorizes and executes'
            $sheet.Worksheet.CommandNote | Should -Match 'remediation bundle'
            ($sheet.Txt -replace '\s+', ' ') | Should -Match ([regex]::Escape(($sheet.Worksheet.CommandNote -replace '\s+', ' ')))
        }
    }
}

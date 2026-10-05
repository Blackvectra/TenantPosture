#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.DistributionListRemediation.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: The remediation SAFETY MODEL of the distribution-list scan. A recommendation that has a command is one of three
             records: a reversible BUNDLE (it has a rollback Microsoft documents, and every bundle has one), a labeled MANUAL
             ACTION (a change this worksheet cannot offer a validated rollback for: an owner, because a list must keep one,
             and an empty list, because restoring it means clearing with $null, which Microsoft does not document), or a
             WITHHELD record (a reason, no command). These tests pin:
               - no captured original state, no command (and not one command-shaped string anywhere);
               - the rollback writes back what was captured, never a generic inverse;
               - the check, the verify and the rollback each carry a read-only Compare that prints True when the live value
                 equals the captured (or new) value, and the Compare is exercised here against stubbed Get-* objects, so
                 "was the captured value restored" is a value comparison, not a printout to interpret;
               - the preview is the apply plus -WhatIf and nothing else, and the two never share a line or a cell;
               - a tenant-wide change is stricter (capture, -Confirm, withheld without a rollback) and is never a manual action;
               - every printed command fits a fixed grammar, so no tenant text can add a second command.
             Nothing here connects to Exchange or runs a printed write command: the only printed text that is evaluated is a
             Compare expression, against Get-* stubs defined in this file.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Distribution-list remediation records' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        # A record from the REAL catalog entry, in module scope (the builder is internal).
        $script:Rem = { param([string] $Control, [hashtable] $P)
            & $script:Mod { param($c, $p) New-NRGDlRemediation -Entry (Get-NRGDistributionListBaseline).ById[$c] @p } $Control $P }

        # Every string anywhere inside a record (or any nested structure).
        $script:Strings = { param($o)
            if ($null -eq $o) { return }
            if ($o -is [string]) { $o; return }
            if ($o -is [System.Collections.IDictionary]) { foreach ($v in $o.Values) { & $script:Strings $v }; return }
            if ($o -is [System.Collections.IEnumerable]) { foreach ($v in $o) { & $script:Strings $v }; return }
        }
        # Anything that reads as a command line.
        $script:CommandLike = '(?i)\b(Get|Set|Enable|Disable|Remove|Add|Export|New)-[A-Za-z]+\b'
        # Quoted literals are collapsed to L first, so tenant text cannot add a statement, a pipeline stage or a subexpression.
        $script:Collapse = { param([string] $Cmd) [regex]::Replace($Cmd, "'(?:[^']|'')*'", 'L') }
        # The only shape a printed COMMAND may have: a cmdlet, switches, typed values, and at most one read-only Format-List.
        $script:Shape = { param([string] $Cmd)
            (& $script:Collapse $Cmd) -match '^(Get|Set|Enable|Disable)-[A-Za-z]+( -[A-Za-z]+( (\$true|\$false|\$null|@\{(Add|Remove)=L(,L)*\}|L(,L)*))?)*( \| Format-List (\*|[A-Za-z]+(, [A-Za-z]+)*))?$' }
        # The only shapes a COMPARE expression may have (read-only, prints True or False).
        $script:GetPart = '\(Get-[A-Za-z]+ -Identity L( -[A-Za-z]+)*\)\.[A-Za-z]+'
        $script:ShapeCompare = { param([string] $Cmd)
            $t = & $script:Collapse $Cmd
            $g = $script:GetPart
            # Every Compare starts with "(" or "[": a spreadsheet prefixes an apostrophe to a cell starting with - = + or @.
            ($t -match "^$g -eq (\`$true|\`$false)$") -or ($t -match "^\[string\]$g -eq L$") -or
            ($t -match "^\(@\(\(Get-[A-Za-z]+ -Identity L( -[A-Za-z]+)*\)\.[A-Za-z]+\)\)\.Count -eq \d+$") -or
            ($t -match "^\(-not \(Compare-Object -ReferenceObject @\(L(,L)*\) -DifferenceObject @\(\(Get-[A-Za-z]+ -Identity L( -[A-Za-z]+)*\)\.[A-Za-z]+ \| ForEach-Object \{ \[string\]\`$_ \}\)\)\)$") }
        # Every command a record carries, and every Compare it carries.
        $script:Steps = { param($b) @($b.Capture.Command, $b.Precheck.Command, $b.Preview.Command, $b.Apply.Command, $b.Verify.Command, $b.Rollback.Command | Where-Object { $_ }) }
        $script:Compares = { param($b) @($b.Precheck.Compare, $b.Verify.Compare, $b.Rollback.Compare | Where-Object { $_ }) }

        # Stand-ins for the Get-* cmdlets a Compare calls, returning whatever $script:Live holds. Only reads are stubbed.
        foreach ($n in 'Get-DistributionGroup', 'Get-DynamicDistributionGroup', 'Get-TransportRule', 'Get-HostedConnectionFilterPolicy', 'Get-HostedContentFilterPolicy') {
            Set-Item -Path "function:script:$n" -Value { param($Identity, [Parameter(ValueFromRemainingArguments)] $Rest) $script:Live }
        }
        # Evaluate a Compare expression against a live object: True or False.
        $script:Eval = { param([string] $Expr, $Live) $script:Live = $Live; [bool](& ([scriptblock]::Create($Expr))) }

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
        # Which records are reversible bundles and which are labeled manual actions, for the inputs above.
        $script:ManualControls = @('DL-1.2', 'DL-2.1', 'DL-2.2')

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
        # Every record on the worksheet, tenant rows and list rows.
        function script:AllBundles { param($Ws) @(@($Ws.Tenant) + @($Ws.Lists | ForEach-Object { $_.Settings }) | ForEach-Object { $_.Remediations } | Where-Object { $null -ne $_ }) }
    }
    AfterAll {
        foreach ($n in 'Get-DistributionGroup', 'Get-DynamicDistributionGroup', 'Get-TransportRule', 'Get-HostedConnectionFilterPolicy', 'Get-HostedContentFilterPolicy') { Remove-Item -Path "function:script:$n" -ErrorAction SilentlyContinue }
        Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'the record: observed state, check, preview, apply, verify, and a rollback or a labeled manual action' {

        It 'every recommendation with a command builds a complete record whose preview is the apply plus -WhatIf and nothing else' {
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
                $b.Precheck.Expect | Should -Match 'Compare must print True'
                $b.Observed.Keys.Count | Should -BeGreaterThan 0 -Because $c.Name
                $b.Target.Identity | Should -Not -BeNullOrEmpty
                $b.Captured.Property | Should -Be $b.Property
                $b.Captured.Json | Should -Not -BeNullOrEmpty
            }
        }

        It 'every record is a reversible bundle with a rollback, or a labeled manual action with none: nothing is "one-way" inside a bundle' {
            foreach ($c in $script:Cases) {
                $b = & $script:Rem $c.C $c.P
                $b.Kind | Should -BeIn @('Bundle', 'ManualAction') -Because $c.Name
                $b.PSObject.Properties.Name | Should -Not -Contain 'OneWay'
                if ($c.C -in $script:ManualControls) {
                    $b.Kind | Should -Be 'ManualAction' -Because "$($c.Name): no documented rollback, so it stays outside the reversible bundles"
                    $b.Rollback | Should -BeNullOrEmpty
                    $b.Undo | Should -Not -BeNullOrEmpty -Because 'a manual action says in words how to undo it'
                    $b.Reason | Should -Not -BeNullOrEmpty -Because 'and says why it is not a bundle'
                    $b.Notes -join ' ' | Should -Match 'MANUAL ACTION: this is not a reversible bundle'
                } else {
                    $b.Kind | Should -Be 'Bundle' -Because $c.Name
                    $b.Rollback.Available | Should -BeTrue
                    $b.Rollback.Command | Should -Not -BeNullOrEmpty
                    $b.Rollback.Compare | Should -Be $b.Precheck.Compare -Because 'the rollback is proved by the same comparison that proved the starting state'
                    $b.Undo | Should -BeNullOrEmpty
                }
            }
        }

        It 'the check, the verify and the capture are reads: no step except the apply, the preview and the rollback names a write cmdlet' {
            foreach ($c in $script:Cases) {
                $b = & $script:Rem $c.C $c.P
                foreach ($read in @($b.Precheck.Command, $b.Precheck.Compare, $b.Verify.Command, $b.Verify.Compare, $b.Capture.Command, $b.Rollback.Compare) | Where-Object { $_ }) {
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
            # a captured NON-empty allowed-senders list is restored by the overwrite form Microsoft documents: a reversible bundle
            $nb = & $script:Rem 'DL-1.2' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @('old@x.example', 'older@y.example'); AfterValue = @('a@x.example') }
            $nb.Kind | Should -Be 'Bundle'
            $nb.Rollback.Command | Should -Be "Set-DistributionGroup -Identity 'l@contoso.com' -AcceptMessagesOnlyFromSendersOrMembers 'old@x.example','older@y.example'"
            # a list changed by removing entries: exactly those entries are put back, and the Compare after the rollback is the WHOLE captured list
            $b = & $script:Rem 'DL-3.2' @{ Kind = 'Tenant'; Target = 'Default'; BeforeValue = [string[]]@('1.2.3.4', '5.6.7.0/24', '10.0.0.1-10.0.2.255'); Remove = [string[]]@('10.0.0.1-10.0.2.255', '5.6.7.0/24') }
            $b.Apply.Command | Should -Match "@\{Remove='10\.0\.0\.1-10\.0\.2\.255','5\.6\.7\.0/24'\}"
            $b.Rollback.Command | Should -Match "@\{Add='10\.0\.0\.1-10\.0\.2\.255','5\.6\.7\.0/24'\} -Confirm$"
            $b.Rollback.Compare | Should -Match "-ReferenceObject @\('1\.2\.3\.4','5\.6\.7\.0/24','10\.0\.0\.1-10\.0\.2\.255'\)"
            $b.Rollback.Expect | Should -Match 'holds exactly: 1\.2\.3\.4, 5\.6\.7\.0/24, 10\.0\.0\.1-10\.0\.2\.255'
            $b.Verify.Compare | Should -Match "-ReferenceObject @\('1\.2\.3\.4'\)"
            # a rule: only the state it was in, and only when that state is the one the rollback command restores
            (& $rb 'DL-3.1' @{ Kind = 'Tenant'; Target = 'R'; BeforeValue = 'Enabled'; AfterValue = 'Disabled' }) | Should -Be "Enable-TransportRule -Identity 'R' -Confirm"
        }

        It 'a rollback that can restore only one state is withheld when that is not the state that was captured' {
            $b = & $script:Rem 'DL-3.1' @{ Kind = 'Tenant'; Target = 'R'; BeforeValue = 'Disabled'; AfterValue = 'Disabled' }
            $b.Available | Should -BeFalse
            $b.Kind | Should -Be 'Withheld'
            $b.Reason | Should -Match "restores 'Enabled'"
            @(& $script:Steps $b) | Should -BeNullOrEmpty
        }

        It 'the exact captured value is kept typed and as JSON, so a rollback does not depend on parsing a sentence' {
            $b = & $script:Rem 'DL-3.2' @{ Kind = 'Tenant'; Target = 'Default'; BeforeValue = [string[]]@('1.2.3.4', "o'brien@x.example", '10.0.0.1-10.0.2.255'); Remove = [string[]]@('1.2.3.4') }
            @($b.Captured.Value) | Should -Be @('1.2.3.4', "o'brien@x.example", '10.0.0.1-10.0.2.255')
            ($b.Captured.Json | ConvertFrom-Json) | Should -Be @('1.2.3.4', "o'brien@x.example", '10.0.0.1-10.0.2.255')
            (& $script:Rem 'DL-1.1' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $false; AfterValue = $true }).Captured.Json | Should -Be 'false'
            (& $script:Rem 'DL-2.5' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = 'Open'; AfterValue = 'Closed' }).Captured.Json | Should -Be '"Open"'
            (& $script:Rem 'DL-2.1' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @() }).Captured.Json | Should -Be '[]'
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'a check establishes a fact: each Compare prints True or False by value' {

        It 'every Compare fits one of the fixed read-only shapes, and no command is a Compare or the other way round' {
            foreach ($c in $script:Cases) {
                $b = & $script:Rem $c.C $c.P
                foreach ($cmp in @(& $script:Compares $b)) { (& $script:ShapeCompare $cmp) | Should -BeTrue -Because "$($c.Name): $cmp"; (& $script:Shape $cmp) | Should -BeFalse -Because 'a Compare is not a command' }
                foreach ($cmd in @(& $script:Steps $b)) { (& $script:ShapeCompare $cmd) | Should -BeFalse -Because "$($c.Name): $cmd" }
            }
            (& $script:ShapeCompare "(Get-X -Identity 'a').P -eq `$true; Remove-Item x") | Should -BeFalse
            (& $script:ShapeCompare "(Get-X -Identity 'a').P -eq `$(calc)") | Should -BeFalse
        }

        It 'a boolean: True for the captured value before the change and after a rollback, False after the apply, and the other way for the verify' {
            $b = & $script:Rem 'DL-1.1' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $false; AfterValue = $true }
            $off = [pscustomobject]@{ RequireSenderAuthenticationEnabled = $false }; $on = [pscustomobject]@{ RequireSenderAuthenticationEnabled = $true }
            (& $script:Eval $b.Precheck.Compare $off) | Should -BeTrue;  (& $script:Eval $b.Precheck.Compare $on) | Should -BeFalse
            (& $script:Eval $b.Verify.Compare $on) | Should -BeTrue;     (& $script:Eval $b.Verify.Compare $off) | Should -BeFalse
            (& $script:Eval $b.Rollback.Compare $off) | Should -BeTrue -Because 'after the rollback the captured value is back'
            (& $script:Eval $b.Rollback.Compare $on) | Should -BeFalse -Because 'a rollback that did not take is caught, not interpreted'
        }

        It 'an enum: ApprovalRequired restored as ApprovalRequired is True, and Open is not an acceptable stand-in' {
            $b = & $script:Rem 'DL-2.5' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = 'ApprovalRequired'; AfterValue = 'Closed' }
            $live = { param($v) [pscustomobject]@{ MemberJoinRestriction = $v } }
            (& $script:Eval $b.Precheck.Compare (& $live 'ApprovalRequired')) | Should -BeTrue
            (& $script:Eval $b.Verify.Compare (& $live 'Closed')) | Should -BeTrue
            (& $script:Eval $b.Rollback.Compare (& $live 'ApprovalRequired')) | Should -BeTrue
            (& $script:Eval $b.Rollback.Compare (& $live 'Open')) | Should -BeFalse -Because 'the captured value was ApprovalRequired, not Open'
            (& $script:Eval $b.Rollback.Compare (& $live 'Closed')) | Should -BeFalse
        }

        It 'a list: equal ignoring order and case, False when one entry is missing or extra, and the whole captured list is what the rollback must restore' {
            $b = & $script:Rem 'DL-3.2' @{ Kind = 'Tenant'; Target = 'Default'; BeforeValue = [string[]]@('1.2.3.4', '5.6.7.0/24', '10.0.0.1-10.0.2.255'); Remove = [string[]]@('10.0.0.1-10.0.2.255') }
            $live = { param($items) [pscustomobject]@{ IPAllowList = @($items) } }
            (& $script:Eval $b.Precheck.Compare (& $live '10.0.0.1-10.0.2.255', '1.2.3.4', '5.6.7.0/24')) | Should -BeTrue -Because 'order is not meaningful'
            (& $script:Eval $b.Precheck.Compare (& $live '1.2.3.4', '5.6.7.0/24')) | Should -BeFalse -Because 'one entry missing'
            (& $script:Eval $b.Precheck.Compare (& $live '1.2.3.4', '5.6.7.0/24', '10.0.0.1-10.0.2.255', '9.9.9.9')) | Should -BeFalse -Because 'one entry extra'
            (& $script:Eval $b.Verify.Compare (& $live '1.2.3.4', '5.6.7.0/24')) | Should -BeTrue
            (& $script:Eval $b.Rollback.Compare (& $live '1.2.3.4', '5.6.7.0/24')) | Should -BeFalse -Because 'the rollback is not complete until the removed entry is back'
            (& $script:Eval $b.Rollback.Compare (& $live '1.2.3.4', '5.6.7.0/24', '10.0.0.1-10.0.2.255')) | Should -BeTrue
            # a list emptied by the apply: the verify is a zero count
            $e = & $script:Rem 'DL-3.3' @{ Kind = 'Tenant'; Target = 'Default'; Parameter = 'AllowedSenders'; BeforeValue = [string[]]@('a@x.example'); Remove = [string[]]@('a@x.example') }
            $e.Verify.Compare | Should -Match '\.Count -eq 0$'
            (& $script:Eval $e.Verify.Compare ([pscustomobject]@{ AllowedSenders = @() })) | Should -BeTrue
            (& $script:Eval $e.Verify.Compare ([pscustomobject]@{ AllowedSenders = @('a@x.example') })) | Should -BeFalse
            (& $script:Eval $e.Rollback.Compare ([pscustomobject]@{ AllowedSenders = @('a@x.example') })) | Should -BeTrue
        }

        It 'a value with an apostrophe or a dollar sign is compared as that exact text' {
            $odd = @("o'brien@x.example", 'a$b@x.example', 'plain@x.example')
            $b = & $script:Rem 'DL-3.3' @{ Kind = 'Tenant'; Target = 'Default'; Parameter = 'AllowedSenders'; BeforeValue = [string[]]$odd; Remove = [string[]]@('plain@x.example') }
            (& $script:Eval $b.Precheck.Compare ([pscustomobject]@{ AllowedSenders = $odd })) | Should -BeTrue
            (& $script:Eval $b.Precheck.Compare ([pscustomobject]@{ AllowedSenders = @("o'brien@x.example", 'a$c@x.example', 'plain@x.example') })) | Should -BeFalse
        }

        It 'a rule state: True only for the captured State' {
            $b = & $script:Rem 'DL-3.1' @{ Kind = 'Tenant'; Target = 'R'; BeforeValue = 'Enabled'; AfterValue = 'Disabled' }
            $live = { param($v) [pscustomobject]@{ State = $v } }
            (& $script:Eval $b.Precheck.Compare (& $live 'Enabled')) | Should -BeTrue
            (& $script:Eval $b.Verify.Compare (& $live 'Disabled')) | Should -BeTrue
            (& $script:Eval $b.Rollback.Compare (& $live 'Disabled')) | Should -BeFalse
        }

        It 'where Exchange returns names or GUIDs instead of the addresses that were set, the Compare is a COUNT, and the record says so' {
            $b = & $script:Rem 'DL-1.2' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @(); AfterValue = @('a@x.example', 'b@y.example') }
            $b.Precheck.Compare | Should -Match '^\(@\(.*\)\)\.Count -eq 0$'
            $b.Verify.Compare | Should -Match '^\(@\(.*\)\)\.Count -eq 2$'
            $b.Verify.Expect | Should -Match 'a count: Exchange returns names or GUIDs'
            $live = { param($n) [pscustomobject]@{ AcceptMessagesOnlyFromSendersOrMembers = @(for ($i = 0; $i -lt $n; $i++) { [guid]::NewGuid() }) } }
            (& $script:Eval $b.Precheck.Compare (& $live 0)) | Should -BeTrue
            (& $script:Eval $b.Verify.Compare (& $live 2)) | Should -BeTrue
            (& $script:Eval $b.Verify.Compare (& $live 1)) | Should -BeFalse
            $o = & $script:Rem 'DL-2.1' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @() }
            $o.Verify.Compare | Should -Match '\.ManagedBy\)\)\.Count -eq 1$' -Because 'adding one owner leaves one owner'
        }

        It 'a change that cannot be verified by value is not offered' {
            # a catalog copy whose property name cannot be used in a comparison
            $b = & $script:Mod {
                $e = (Get-NRGDistributionListBaseline).ById['DL-2.5']
                $e.Remediation.Kinds['Distribution'].Property = 'Member Join'
                New-NRGDlRemediation -Entry $e -Kind Distribution -Target 'l@contoso.com' -BeforeValue 'Open' -AfterValue 'Closed'
            }
            $b.Available | Should -BeFalse
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
                $b.Kind | Should -Be 'Withheld'
                $b.Reason | Should -Match 'not returned by Exchange' -Because $c.Name
                foreach ($step in 'Capture', 'Precheck', 'Preview', 'Apply', 'Verify', 'Rollback', 'Captured') { $b[$step] | Should -BeNullOrEmpty -Because "$($c.Name): $step must not exist for a record that was withheld" }
                $b.Undo | Should -BeNullOrEmpty
                @(& $script:Strings $b | Where-Object { $_ -match $script:CommandLike }) | Should -BeNullOrEmpty -Because "$($c.Name): a withheld record carries no command anywhere"
                @(& $script:Strings $b | Where-Object { $_ -match '(?i)-WhatIf|-Confirm|\$true|\$false|\$null|Compare-Object' }) | Should -BeNullOrEmpty
            }
        }

        It 'a known-empty list and an unknown value are different answers: an empty list is a manual action, an unknown one is withheld' {
            $known = & $script:Rem 'DL-1.2' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @(); AfterValue = @('a@x.example') }
            $known.Available | Should -BeTrue
            $known.Kind | Should -Be 'ManualAction'
            $known.Reason | Should -Match 'clearing it with \$null, which Microsoft''s cmdlet page does not document'
            $known.Rollback | Should -BeNullOrEmpty
            @(& $script:Strings $known | Where-Object { $_ -match '(?i)\bSet-DistributionGroup\b.*\$null' }) | Should -BeNullOrEmpty -Because 'no printed command writes $null back'
            $unknown = & $script:Rem 'DL-1.2' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $null; AfterValue = @('a@x.example') }
            $unknown.Available | Should -BeFalse
            $unknown.Kind | Should -Be 'Withheld'
            # and the other direction: an unknown Target is not a command either
            foreach ($t in $null, '', '  ') {
                $b = & $script:Rem 'DL-1.1' @{ Kind = 'Distribution'; Target = $t; BeforeValue = $false; AfterValue = $true }
                $b.Available | Should -BeFalse -Because "target [$t]"
                $b.Reason | Should -Match 'name of the object to change was not returned' -Because 'a missing name is said to be missing, not blamed on quoting'
                @(& $script:Strings $b | Where-Object { $_ -match $script:CommandLike }) | Should -BeNullOrEmpty
            }
        }

        It 'an enum value outside what the catalog restores, or no new value, is not a command either' {
            $b = & $script:Rem 'DL-2.5' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = 'Open' }
            $b.Available | Should -BeFalse
            @(& $script:Steps $b) | Should -BeNullOrEmpty
            $d = & $script:Rem 'DL-2.5' @{ Kind = 'Dynamic'; Target = 'l@contoso.com'; BeforeValue = 'Open'; AfterValue = 'Closed' }
            $d.Available | Should -BeFalse
            $d.Reason | Should -Match 'no command for a Dynamic object'
        }

        It 'an entry to remove that is not in the captured list withholds the record: the state is not what the recommendation was built from' {
            $b = & $script:Rem 'DL-3.2' @{ Kind = 'Tenant'; Target = 'Default'; BeforeValue = [string[]]@('1.2.3.4'); Remove = [string[]]@('9.9.9.9') }
            $b.Available | Should -BeFalse
            $b.Reason | Should -Match 'not in the list this scan captured'
            @(& $script:Steps $b) | Should -BeNullOrEmpty
        }

        It 'a value that cannot be quoted safely anywhere in a record withholds the WHOLE record: a list with an entry dropped would be worse than none' {
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
                    $b.Reason | Should -Match 'cannot be quoted safely|comparison'
                    @(& $script:Steps $b) | Should -BeNullOrEmpty -Because "$($k.C) with U+[$label]: no partial command"
                    @(& $script:Compares $b) | Should -BeNullOrEmpty
                }
            }
        }

        It 'an entry that is only displayed, not named in any command or comparison of the apply, cannot reach a command; it is compared as exact text' {
            $v = "a$([char]0x2019)b"
            # in the captured list the whole-list Compare names every entry, so one that cannot be quoted withholds the record
            $b = & $script:Rem 'DL-3.2' @{ Kind = 'Tenant'; Target = 'Default'; BeforeValue = [string[]]@('1.2.3.4', "5.6.7.0/24$v"); Remove = [string[]]@('1.2.3.4') }
            $b.Available | Should -BeFalse
            @(& $script:Steps $b) | Should -BeNullOrEmpty
        }

        It 'an unrecognized parameter word withholds the anti-spam record' {
            $b = & $script:Rem 'DL-3.3' @{ Kind = 'Tenant'; Target = 'Default'; Parameter = 'BlockedSenders; calc'; BeforeValue = [string[]]@('x'); Remove = [string[]]@('x') }
            $b.Available | Should -BeFalse
        }

        It 'a caller-supplied reason (a synchronized list, a business-purpose review, a preset policy) withholds the record with that reason' {
            $b = & $script:Rem 'DL-1.1' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = $false; AfterValue = $true; Withhold = 'Synchronized from on-premises Active Directory.' }
            $b.Available | Should -BeFalse
            $b.Reason | Should -Be 'Synchronized from on-premises Active Directory.'
            @(& $script:Steps $b) | Should -BeNullOrEmpty
        }
    }

    # ═════════════════════════════════════════════════════════════════════════════════
    Context 'a change that reaches every recipient is stricter, and is never a manual action' {

        It 'carries a required capture of the current configuration, asks for confirmation on the apply and the rollback, and does not put -Confirm on the preview' {
            foreach ($c in @($script:Cases | Where-Object { $_.C -in 'DL-3.1', 'DL-3.2', 'DL-3.3' })) {
                $b = & $script:Rem $c.C $c.P
                $b.Kind | Should -Be 'Bundle' -Because "$($c.Name): a tenant-wide change without a rollback is withheld, never a manual action"
                $b.Impact | Should -Be 'TenantWide' -Because $c.Name
                $b.PSObject.Properties.Name | Should -Not -Contain 'Backup' -Because 'it is a capture of the current configuration, not a backup'
                $b.Capture.Command | Should -Match "^Get-[A-Za-z]+ -Identity '[^']+' \| Format-List \*$" -Because 'the capture is a read that prints every property: it writes no file'
                $b.Capture.Command | Should -Not -Match 'Export-|Out-File|Set-Content|>'
                $b.Capture.Purpose | Should -Match 'REQUIRED before the Apply'
                $b.Capture.Purpose | Should -Match 'inspection, not a backup'
                $b.Capture.Purpose | Should -Match 'save its output'
                $b.Apply.Command | Should -Match ' -Confirm$'
                $b.Rollback.Command | Should -Match ' -Confirm$'
                $b.Preview.Command | Should -Not -Match '-Confirm'
                $b.Rollback.Available | Should -BeTrue
                $b.Notes -join ' ' | Should -Match 'Tenant-wide'
            }
            foreach ($c in @($script:Cases | Where-Object { $_.C -notin 'DL-3.1', 'DL-3.2', 'DL-3.3' })) {
                $b = & $script:Rem $c.C $c.P
                $b.Impact | Should -Be 'Standard' -Because $c.Name
                $b.Capture | Should -BeNullOrEmpty
                $b.Apply.Command | Should -Not -Match '-Confirm'
            }
        }

        It 'is withheld outright when no rollback can be built for it, rather than offered as a manual action' {
            $b = & $script:Mod {
                $e = (Get-NRGDistributionListBaseline).ById['DL-3.2']
                $e.Remediation.Kinds['Tenant'].Rollback = ''
                New-NRGDlRemediation -Entry $e -Kind Tenant -Target 'Default' -BeforeValue ([string[]]@('1.2.3.4', '10.0.0.0/8')) -Remove ([string[]]@('10.0.0.0/8'))
            }
            $b.Available | Should -BeFalse
            $b.Kind | Should -Be 'Withheld'
            $b.Reason | Should -Match 'tenant-wide change is offered only with a rollback'
            @(& $script:Steps $b) | Should -BeNullOrEmpty
        }

        It 'the owner of an ownerless list is a labeled manual action outside the bundles: no rollback command, the reason and the undo in words' {
            $b = & $script:Rem 'DL-2.1' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @() }
            $b.Kind | Should -Be 'ManualAction'
            $b.Available | Should -BeTrue
            $b.Rollback | Should -BeNullOrEmpty
            $b.Reason | Should -Match 'at least one owner'
            $b.Undo | Should -Match 'at least one owner'
            $b.Undo | Should -Not -Match $script:CommandLike -Because 'the undo is guidance in words, never a command'
            $b.RequiresInput | Should -Contain 'owner'
            $b.Notes -join ' ' | Should -Match '<owner>'
            $b.Apply.Command | Should -Match "-ManagedBy '<owner>'$"
            $b.Precheck.Compare | Should -Match '\.ManagedBy\)\)\.Count -eq 0$'
        }

        It 'a captured empty moderator list is a manual action, because restoring it would mean clearing with $null' {
            foreach ($k in 'Distribution', 'Dynamic') {
                $b = & $script:Rem 'DL-2.2' @{ Kind = $k; Target = 'l@contoso.com'; BeforeValue = @(); Context = ([ordered]@{ ModerationEnabled = 'True' }) }
                $b.Kind | Should -Be 'ManualAction' -Because $k
                $b.Rollback | Should -BeNullOrEmpty
                $b.Reason | Should -Match 'does not document'
                $b.Undo | Should -Match 'Microsoft documents'
                $b.Precheck.Expect | Should -Match 'ModerationEnabled = True' -Because 'the context is part of what the check must show'
            }
            # a captured non-empty moderator list can be written back, so it is an ordinary bundle
            $nb = & $script:Rem 'DL-2.2' @{ Kind = 'Distribution'; Target = 'l@contoso.com'; BeforeValue = @('mod1@contoso.com') }
            $nb.Kind | Should -Be 'Bundle'
            $nb.Rollback.Command | Should -Match "-ModeratedBy 'mod1@contoso\.com'$"
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
                            "Get-DistributionGroup -Identity 'a@b.c' | Format-List *",
                            "Set-HostedConnectionFilterPolicy -Identity 'Default' -IPAllowList @{Remove='1.2.3.4','5.6.7.8'} -Confirm") { (& $script:Shape $ok) | Should -BeTrue -Because $ok }
            foreach ($bad in "Set-X -Identity 'a'; Remove-Item x",
                             "Set-X -Identity 'a' | Remove-Item",
                             "Set-X -Identity `$(calc)",
                             "Set-X -Identity 'a' & calc",
                             "Set-X -Identity a",
                             "Set-X -Identity 'a'`nSet-Y",
                             "Get-X | Where-Object { `$_ }") { (& $script:Shape $bad) | Should -BeFalse -Because $bad }
        }

        It 'every command and every Compare in every record fits its grammar, however hostile the tenant text in it' {
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
                    foreach ($cmp in @(& $script:Compares $b)) { (& $script:ShapeCompare $cmp) | Should -BeTrue -Because "$($k.C) [$h]: $cmp" }
                }
            }
            foreach ($c in $script:Cases) {
                $b = & $script:Rem $c.C $c.P
                foreach ($cmd in @(& $script:Steps $b)) { (& $script:Shape $cmd) | Should -BeTrue -Because "$($c.Name): $cmd" }
                foreach ($cmp in @(& $script:Compares $b)) { (& $script:ShapeCompare $cmp) | Should -BeTrue -Because "$($c.Name): $cmp" }
            }
        }

        It 'no command or Compare carries a line break' {
            foreach ($c in $script:Cases) { $b = & $script:Rem $c.C $c.P; foreach ($cmd in @(@(& $script:Steps $b) + @(& $script:Compares $b))) { $cmd | Should -Not -Match '[\r\n]' } }
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
                @($sheet.Csv | Where-Object { $_.ControlId -eq $c.Id -and $_.Step -in 'Apply', 'Change', 'Preview', 'Rollback', 'Check', 'CheckCompare' }).Count | Should -Be 0 -Because "$($c.Id): no command row in the CSV"
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
            @($p1.Captured.Value) | Should -Be @('1.2.3.4', '10.0.0.0/8', '11.0.0.1-11.0.5.5')
            $p2.Rollback.Command | Should -Not -Match '10\.0\.0\.0|11\.0\.0\.1'
            $p1.Capture.Command | Should -Be "Get-HostedConnectionFilterPolicy -Identity 'P1' | Format-List *"
            $p2.Capture.Command | Should -Be "Get-HostedConnectionFilterPolicy -Identity 'P2' | Format-List *"
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

        It 'a list with external members is withheld for a BUSINESS-PURPOSE review, not because the setting is technically unsuitable' {
            $sheet = NewSheet (NewRaw -Lists @(NewList -With @{ ExternalMemberCount = 2; RequireSenderAuthenticationEnabled = $false; OwnerCount = 1; Owners = @('Owner One') })) @(NewFinding 'DL-1.1' 'Gap' 'l@contoso.com')
            $row = @($sheet.Worksheet.Lists[0].Settings | Where-Object { $_.ControlId -eq 'DL-1.1' })[0]
            $b = @($row.Remediations)
            $b.Count | Should -Be 1
            $b[0].Available | Should -BeFalse
            $b[0].Kind | Should -Be 'Withheld'
            $b[0].Reason | Should -Match 'Business-purpose review required'
            $b[0].Reason | Should -Match 'different fact from who legitimately needs to send to it'
            $b[0].Reason | Should -Match 'whether or not they are members'
            $b[0].Reason | Should -Not -Match 'would stop them sending|technically' -Because 'an external member is not an external sender'
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

        It 'holds every invariant of the model over a mixed worksheet: withheld means no step, a bundle has a rollback, a manual action has none, tenant-wide means a capture and -Confirm' {
            $sheet = & $script:Mixed
            $bundles = @(AllBundles $sheet.Worksheet)
            $bundles.Count | Should -BeGreaterThan 8
            @($bundles | Where-Object { $_.Kind -eq 'Bundle' }).Count | Should -BeGreaterThan 3
            @($bundles | Where-Object { $_.Kind -eq 'ManualAction' }).Count | Should -BeGreaterThan 1
            @($bundles | Where-Object { $_.Kind -eq 'Withheld' }).Count | Should -BeGreaterThan 2
            foreach ($b in $bundles) {
                $b.Kind | Should -BeIn @('Bundle', 'ManualAction', 'Withheld')
                if ($b.Kind -eq 'Withheld') {
                    $b.Available | Should -BeFalse
                    $b.Reason | Should -Not -BeNullOrEmpty
                    @(& $script:Steps $b) | Should -BeNullOrEmpty
                    continue
                }
                $b.Available | Should -BeTrue
                $b.Observed.Keys.Count | Should -BeGreaterThan 0
                $b.ObservedAt | Should -Be '2026-10-04T10:00:00.0000000Z'
                $b.Captured.Json | Should -Not -BeNullOrEmpty
                $b.Preview.Command | Should -Be (($b.Apply.Command -replace ' -Confirm$', '') + ' -WhatIf')
                if ($b.Kind -eq 'ManualAction') {
                    $b.Impact | Should -Be 'Standard' -Because 'a tenant-wide change is never a manual action'
                    $b.Rollback | Should -BeNullOrEmpty
                    $b.Undo | Should -Not -BeNullOrEmpty
                    $b.Reason | Should -Not -BeNullOrEmpty
                } else {
                    $b.Rollback.Available | Should -BeTrue
                    $b.Rollback.Command | Should -Not -BeNullOrEmpty
                    $b.Rollback.Compare | Should -Be $b.Precheck.Compare
                }
                if ($b.Impact -eq 'TenantWide') { $b.Capture | Should -Not -BeNullOrEmpty; $b.Apply.Command | Should -Match ' -Confirm$'; $b.Kind | Should -Be 'Bundle' }
                foreach ($cmd in @(& $script:Steps $b)) { (& $script:Shape $cmd) | Should -BeTrue -Because $cmd }
                foreach ($cmp in @(& $script:Compares $b)) { (& $script:ShapeCompare $cmp) | Should -BeTrue -Because $cmp }
            }
            # the list that holds an external member is withheld for a business-purpose review; a synchronized list gets none
            $ext = @(@(($sheet.Worksheet.Lists | Where-Object { $_.Address -eq 'ext@contoso.com' }).Settings | Where-Object { $_.ControlId -eq 'DL-1.1' })[0].Remediations)
            $ext.Count | Should -Be 1; $ext[0].Available | Should -BeFalse; $ext[0].Reason | Should -Match 'Business-purpose review required'
            foreach ($row in @(($sheet.Worksheet.Lists | Where-Object { $_.Address -eq 'synced@contoso.com' }).Settings)) { @($row.Remediations | Where-Object { $_.Available }).Count | Should -Be 0 }
            # the summary counts the three kinds
            $sheet.Worksheet.Summary.RemediationBundles | Should -Be @($bundles | Where-Object { $_.Kind -eq 'Bundle' }).Count
            $sheet.Worksheet.Summary.ManualActions | Should -Be @($bundles | Where-Object { $_.Kind -eq 'ManualAction' }).Count
            $sheet.Worksheet.Summary.RemediationsWithheld | Should -Be @($bundles | Where-Object { $_.Kind -eq 'Withheld' }).Count
            $sheet.Txt | Should -Match 'Remediation: reversible bundles / manual actions \(no rollback command\) / withheld:\s+\d+ / \d+ / \d+'
        }

        It 'the text labels a bundle, a manual action and a withheld record differently, prints the apply on its own labeled line, and every command of the model is in the text exactly' {
            $sheet = & $script:Mixed
            $lines = @($sheet.Txt -split "`r?`n")
            $lines | Where-Object { $_ -match '^\s+REMEDIATION BUNDLE \[DL-' } | Should -Not -BeNullOrEmpty
            @($lines | Where-Object { $_ -match '^\s+REMEDIATION BUNDLE \[DL-' }) | ForEach-Object { $_ | Should -Match '--  reversible; scope: (one object|TENANT-WIDE)$' }
            @($lines | Where-Object { $_ -match '^\s+MANUAL ACTION \[DL-' }) | ForEach-Object { $_ | Should -Match '--  NOT a reversible bundle: no rollback command is offered$' }
            $lines | Where-Object { $_ -match '^\s+REMEDIATION WITHHELD \[DL-' } | Should -Not -BeNullOrEmpty
            @($lines | Where-Object { $_ -match '^\s+> .* -WhatIf$' }).Count | Should -BeGreaterThan 4
            foreach ($l in $lines) { if ($l -match '-WhatIf') { $l | Should -Not -Match "-Confirm" ; ([regex]::Matches($l, '(Set|Disable|Enable)-[A-Za-z]+')).Count | Should -BeLessOrEqual 1 } }
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^\s+2\. PREVIEW') { $lines[$i + 1] | Should -Match ' -WhatIf$' }
                if ($lines[$i] -match '^\s+3\. (APPLY|CHANGE)') {
                    $lines[$i] | Should -Match 'CHANGES THE TENANT'
                    $j = $i + 1; while ($lines[$j] -notmatch '^\s+> ') { $j++ }
                    $lines[$j] | Should -Not -Match '-WhatIf'
                }
            }
            foreach ($b in @(AllBundles $sheet.Worksheet | Where-Object { $_.Available })) {
                foreach ($cmd in @(@(& $script:Steps $b) + @(& $script:Compares $b))) { @($lines | Where-Object { $_.Trim() -eq "> $cmd" }).Count | Should -BeGreaterOrEqual 1 -Because "the text must carry $cmd verbatim" }
                if ($b.Kind -eq 'Bundle') { $sheet.Txt | Should -Match 'ROLLBACK  \(restores the captured value; run the check first, then the Compare after\)' }
            }
            $sheet.Txt | Should -Match 'UNDO  \(in words; this worksheet prints no rollback command for it\)'
            $sheet.Txt | Should -Match 'CAPTURE CURRENT CONFIGURATION  \(read-only; REQUIRED before the apply\)'
            $sheet.Txt | Should -Match 'Captured value, exact \(JSON\):'
            ($sheet.Txt -replace '\s+', ' ') | Should -Match 'inspection, not a backup'
            $sheet.Txt | Should -Not -Match 'ROLLBACK  NOT AVAILABLE|BACKUP  \('
            # a manual action never prints a rollback command under its own heading
            $ma = @($lines | Select-String -Pattern '^\s+MANUAL ACTION \[DL-' | ForEach-Object { $_.LineNumber - 1 })
            foreach ($start in $ma) {
                $end = $start + 1; while ($end -lt $lines.Count -and $lines[$end] -notmatch '^\s+(MANUAL ACTION|REMEDIATION BUNDLE|REMEDIATION WITHHELD) \[DL-' -and $lines[$end] -notmatch '^[A-Z]{3,}') { $end++ }
                (@($lines[$start..($end - 1)]) -join "`n") | Should -Not -Match '(?m)^\s+ROLLBACK  '
            }
        }

        It 'the CSV has one row per step and one command per cell: a preview and an apply never share a cell, a manual action has its own row type, and the exact captured value is a JSON column' {
            $sheet = & $script:Mixed
            $rem = @($sheet.Csv | Where-Object { $_.RowType -in 'Remediation', 'Manual action' })
            $rem.Count | Should -BeGreaterThan 25
            foreach ($r in $rem) { $r.Step | Should -BeIn @('Observed', 'Capture', 'Check', 'CheckCompare', 'Preview', 'Apply', 'Change', 'Verify', 'VerifyCompare', 'Rollback', 'RollbackCompare', 'Undo', 'Note', 'Withheld') }
            foreach ($r in @($rem | Where-Object { $_.RowType -eq 'Manual action' })) {
                $r.Step | Should -Not -BeIn @('Apply', 'Rollback', 'RollbackCompare') -Because 'a manual action has a Change and an Undo in words, never an Apply or a Rollback'
            }
            @($sheet.Csv | Where-Object { $_.RowType -eq 'Remediation' -and $_.Step -in 'Change', 'Undo' }).Count | Should -Be 0
            @($sheet.Csv | Where-Object { $_.RowType -eq 'Manual action' -and $_.Step -eq 'Change' }).Count | Should -BeGreaterThan 0
            foreach ($r in @($sheet.Csv | Where-Object { $_.Command -and $_.Step -ne 'Inspect' })) {
                $r.Command | Should -Not -Match "^['=+\-@]" -Because 'a spreadsheet prefixes an apostrophe to a cell starting with one of these, which would break the pasted command'
                $r.Command | Should -Not -Match '[;&\r\n]' -Because 'a cell that chained a preview and an apply would run both when pasted'
                if ($r.Step -like '*Compare') { (& $script:ShapeCompare $r.Command) | Should -BeTrue -Because $r.Command }
                else { (& $script:Shape $r.Command) | Should -BeTrue -Because $r.Command }
                if ($r.Step -eq 'Preview') { $r.Command | Should -Match ' -WhatIf$' }
                if ($r.Step -in 'Apply', 'Change') { $r.Command | Should -Not -Match '-WhatIf' }
            }
            @($rem | Where-Object { $_.Step -eq 'Withheld' } | Where-Object { $_.Command }) | Should -BeNullOrEmpty -Because 'a withheld row has a reason and no command'
            @($rem | Where-Object { $_.Step -eq 'Withheld' -and -not $_.Detail }) | Should -BeNullOrEmpty
            foreach ($r in @($rem | Where-Object { $_.Step -eq 'Observed' })) { { $r.CapturedJson | ConvertFrom-Json } | Should -Not -Throw -Because 'the exact captured value is valid JSON'; $r.CapturedJson | Should -Not -BeNullOrEmpty }
            # every command and Compare in the model is in the CSV as its own cell
            foreach ($b in @(AllBundles $sheet.Worksheet | Where-Object { $_.Available })) {
                foreach ($cmd in @(@(& $script:Steps $b) + @(& $script:Compares $b))) { @($sheet.Csv | Where-Object { $_.Command -eq $cmd }).Count | Should -BeGreaterOrEqual 1 -Because $cmd }
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

#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.DistributionListCatalog.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Integrity of the distribution-list recommendation catalog
             (Config/distribution-list-baseline.json) and of the two NRG standards
             it depends on (Config/tp-standards.json). Same discipline as the
             Conditional Access baseline: every source a real Learn link, every cited
             800-53 control present in the catalog, every judgment that is NRG's own
             routed through a standard that ships empty, and no framework id invented.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Distribution-list recommendation catalog' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:CatalogPath = Join-Path $script:Root 'Config' 'distribution-list-baseline.json'
        $script:CatalogText = Get-Content -LiteralPath $script:CatalogPath -Raw -Encoding utf8
        $script:Catalog = $script:CatalogText | ConvertFrom-Json
        $script:Recs = @($script:Catalog.recommendations)
        $script:Nist = Get-Content -LiteralPath (Join-Path $script:Root 'Config' 'nist-800-53-catalog.json') -Raw -Encoding utf8 | ConvertFrom-Json
        $script:StdText = Get-Content -LiteralPath (Join-Path $script:Root 'Config' 'tp-standards.json') -Raw -Encoding utf8
        $script:Std = $script:StdText | ConvertFrom-Json
    }
    AfterAll { Clear-TPState }

    Context 'shape' {
        It 'carries a recommendation for every DL-* control the evaluator emits' {
            $ids = @($script:Recs | ForEach-Object { $_.ControlId })
            foreach ($id in 'DL-1.1', 'DL-2.1', 'DL-2.2', 'DL-2.3', 'DL-2.4', 'DL-2.5', 'DL-3.1', 'DL-3.2', 'DL-3.3', 'DL-3.4', 'DL-3.5', 'DL-4.1') { $ids | Should -Contain $id }
        }
        It 'has unique, well-formed ids (the series Add-TPFinding accepts)' {
            $ids = @($script:Recs | ForEach-Object { $_.ControlId })
            $ids.Count | Should -Be (@($ids | Sort-Object -Unique).Count)
            foreach ($id in $ids) { $id | Should -Match '^DL-\d+\.\d+$' }
        }
        It 'gives every entry a title, setting, recommended value, why, severity, basis and kind' {
            foreach ($r in $script:Recs) {
                foreach ($f in 'Title', 'Setting', 'Recommended', 'Why', 'Severity', 'Basis', 'Kind') { [string]$r.$f | Should -Not -BeNullOrEmpty -Because "$($r.ControlId) needs $f" }
                $r.Severity | Should -BeIn @('Critical', 'High', 'Medium', 'Low', 'Informational')
                $r.Basis | Should -BeIn @('Microsoft', 'TP')
                $r.Kind | Should -BeIn @('Finding', 'Context')
            }
        }
        It 'is not in controls.json: this is a separate series, not a baseline control' {
            $controls = Get-Content -LiteralPath (Join-Path $script:Root 'Config' 'controls.json') -Raw -Encoding utf8
            $controls | Should -Not -Match '"ControlId"\s*:\s*"DL-'
        }
    }

    Context 'sources' {
        It 'every SourceUrl and AlsoSee is a real learn.microsoft.com link, with no locale segment' {
            foreach ($r in $script:Recs) {
                $r.SourceUrl | Should -Match '^https://learn\.microsoft\.com/[^\s]+$' -Because "$($r.ControlId) SourceUrl"
                $r.SourceUrl | Should -Not -Match '/en-us/' -Because 'a locale in a cited link breaks for readers in other locales'
                foreach ($u in @($r.AlsoSee)) {
                    $u | Should -Match '^https://learn\.microsoft\.com/[^\s]+$' -Because "$($r.ControlId) AlsoSee"
                    $u | Should -Not -Match '/en-us/'
                }
            }
        }
        It 'records the date every source was opened' {
            $script:Catalog.Verified | Should -Match '^\d{4}-\d{2}-\d{2}$'
        }
    }

    Context 'NIST mapping' {
        It 'every cited 800-53 control exists in the Rev 5 catalog the NIST matrix uses' {
            foreach ($r in $script:Recs) {
                @($r.Nist80053).Count | Should -BeGreaterThan 0 -Because "$($r.ControlId) needs a mapped control"
                foreach ($n in @($r.Nist80053)) {
                    $n | Should -Match '^[A-Z]{2}-\d{1,3}(\(\d{1,3}\))?$'
                    $script:Nist.controls.PSObject.Properties[$n] | Should -Not -BeNullOrEmpty -Because "$n is cited by $($r.ControlId) but absent from nist-800-53-catalog.json"
                }
            }
        }
        It 'says the mapping is the tool''s own and not a quotation of NIST' {
            $script:Catalog.NistMappingNote | Should -Match 'Not a quotation of NIST'
            $script:Catalog._comment | Should -Match 'not a quotation of NIST'
        }
        It 'adds nothing to the NIST catalog: every control it cites is already used elsewhere, so the catalog gains no orphan' {
            # nist-800-53-catalog.json is pinned by TP.NISTMatrix.Tests.ps1 to carry no entry nothing references.
            # The five controls cited here are all base controls controls.json already cites.
            $cited = @($script:Recs | ForEach-Object { @($_.Nist80053) } | Sort-Object -Unique)
            ($cited -join ',') | Should -Be 'AC-2,AC-3,AC-6,SC-7,SI-8'
        }
    }

    Context 'no framework id is invented' {
        It 'cites no CISA ScubaGear rule id and no CIS control number' {
            # ScubaGear ids look like MS.EXO.4.1v1; CIS controls are numbered like 2.1.5. Neither has a
            # distribution-list item, so none may appear; the worksheet says "no framework item verified".
            $script:CatalogText | Should -Not -Match 'MS\.[A-Z0-9]+\.\d+\.\d+v\d+'
            $script:CatalogText | Should -Not -Match '\bCIS(\s+Microsoft)?[^"]{0,40}\b\d+\.\d+(\.\d+)?\b(?!v)\s*(control|benchmark|recommendation)'
            foreach ($r in $script:Recs) { $r.PSObject.Properties.Name | Should -Not -Contain 'Scuba'; $r.PSObject.Properties.Name | Should -Not -Contain 'CIS' }
            $script:Catalog.FrameworkNote | Should -Be 'no framework item verified'
        }
        It 'says plainly why no framework item is cited' {
            $script:Catalog._comment | Should -Match 'ScubaGear 2\.0\.0 has none'
        }
    }

    Context 'NRG judgments come from standards that ship empty' {
        It 'every Basis TP entry names a standard that exists in tp-standards.json and in the loader' {
            $std = Get-TPStandards -Path (Join-Path $script:Root 'Config' 'tp-standards.json')
            foreach ($r in @($script:Recs | Where-Object { $_.Basis -eq 'TP' })) {
                [string]$r.StandardKey | Should -Not -BeNullOrEmpty -Because "$($r.ControlId) is an NRG judgment and must name its standard"
                $script:Std.PSObject.Properties[[string]$r.StandardKey] | Should -Not -BeNullOrEmpty
                $std.Contains([string]$r.StandardKey) | Should -BeTrue
            }
        }
        It 'no Basis Microsoft entry borrows a standard, and no entry recommends a value of its own invention' {
            foreach ($r in @($script:Recs | Where-Object { $_.Basis -eq 'Microsoft' })) { $r.PSObject.Properties.Name | Should -Not -Contain 'StandardKey' }
        }
        It 'the two distribution-list standards ship empty (unapproved means not assessed, never met)' {
            $s = Get-TPStandards -Path (Join-Path $script:Root 'Config' 'tp-standards.json')
            foreach ($k in 'DistributionListMaxMembers', 'DistributionListMemberJoinRestriction') {
                $s.Contains($k) | Should -BeTrue
                @($s[$k]).Count | Should -Be 0 -Because "$k must stay empty until the owner approves a value"
                @($script:Std.$k.Values).Count | Should -Be 0
            }
        }
        It 'the unapproved standards read as not approved, with no issue to report' {
            $d = Get-TPDistributionListStandards -Standards (Get-TPStandards -Path (Join-Path $script:Root 'Config' 'tp-standards.json'))
            $d.MaxMembers.Approved | Should -BeFalse; $d.JoinRestriction.Approved | Should -BeFalse
            $d.MaxMembers.Issue | Should -BeNullOrEmpty
        }
        It 'there is no external-members standard: the owner decided external members stay, so nothing can ban them' {
            (Get-Content -LiteralPath (Join-Path $script:Root 'Config' 'tp-standards.json') -Raw -Encoding utf8) | Should -Not -Match 'DistributionListExternalMembers'
            (Get-TPStandards -Path (Join-Path $script:Root 'Config' 'tp-standards.json')).Contains('DistributionListExternalMembers') | Should -BeFalse
            (Get-TPDistributionListStandards -Standards (Get-TPStandards -Path (Join-Path $script:Root 'Config' 'tp-standards.json'))).Contains('ExternalMembers') | Should -BeFalse
            @($script:Recs | Where-Object { $_.StandardKey -eq 'DistributionListExternalMembers' }) | Should -BeNullOrEmpty
        }
        It 'DL-2.3 is context: no standard, no finding, and no command that removes a member' {
            $r = $script:Recs | Where-Object { $_.ControlId -eq 'DL-2.3' }
            $r.Kind | Should -Be 'Context'
            $r.EmitsFinding | Should -BeFalse
            $r.PSObject.Properties.Name | Should -Not -Contain 'StandardKey'
            $r.PSObject.Properties.Name | Should -Not -Contain 'Remediation'
            $r.PSObject.Properties.Name | Should -Not -Contain 'Inspect'
            $script:CatalogText | Should -Not -Match 'Remove-DistributionGroupMember'
        }
        It 'DL-1.2 carries the allowed-senders command with an {After} list and a rollback that writes back {Before}, and cites the cmdlet reference and the outside-sender page' {
            $r = $script:Recs | Where-Object { $_.ControlId -eq 'DL-1.2' }
            $r.Remediation.Kinds.Distribution.Apply | Should -Be 'Set-DistributionGroup -Identity {Target} -AcceptMessagesOnlyFromSendersOrMembers {After}'
            $r.Remediation.Kinds.Distribution.Rollback | Should -Be 'Set-DistributionGroup -Identity {Target} -AcceptMessagesOnlyFromSendersOrMembers {Before}'
            $r.Remediation.Kinds.Distribution.Undo | Should -Match 'does not document it' -Because 'writing $null back is the one rollback Microsoft does not document, so the worksheet gives the undo in words instead of a command'
            $r.Remediation.Kinds.PSObject.Properties.Name | Should -Not -Contain 'Dynamic'
            $r.SourceUrl | Should -Be 'https://learn.microsoft.com/powershell/module/exchange/set-distributiongroup'
            @($r.AlsoSee) | Should -Contain 'https://learn.microsoft.com/troubleshoot/exchange/email-delivery/ndr/fix-error-code-5-7-136-in-exchange-online'
            $r.Why | Should -Match 'rejected'
            $r.Why | Should -Match 'SNAPSHOT'
        }
    }

    Context 'remediation templates: a bundle is built from these, and a rollback is never a generic inverse' {
        BeforeAll {
            # Every cmdlet a printed command can name. A new one is added here deliberately, after reading it: this list also feeds the
            # Exchange RBAC documentation (docs/EXCHANGE-RBAC-DISTRIBUTION-LISTS.md) and the read-only guarantees.
            $script:ReadCmdlets  = @('Get-DistributionGroup', 'Get-DynamicDistributionGroup', 'Get-TransportRule', 'Get-HostedConnectionFilterPolicy', 'Get-HostedContentFilterPolicy')
            $script:WriteCmdlets = @('Set-DistributionGroup', 'Set-DynamicDistributionGroup', 'Disable-TransportRule', 'Enable-TransportRule', 'Set-HostedConnectionFilterPolicy', 'Set-HostedContentFilterPolicy')
            $script:Kinds = @(foreach ($r in $script:Recs) { if ($r.PSObject.Properties['Remediation']) { foreach ($k in $r.Remediation.Kinds.PSObject.Properties) { [pscustomobject]@{ Id = $r.ControlId; Kind = $k.Name; Impact = [string]$r.Remediation.Impact; T = $k.Value } } } })
        }
        It 'only the three tenant-wide controls are TenantWide, and the others are Standard' {
            foreach ($r in @($script:Recs | Where-Object { $_.PSObject.Properties['Remediation'] })) {
                $r.Remediation.Impact | Should -BeIn @('Standard', 'TenantWide')
                if ($r.ControlId -in 'DL-3.1', 'DL-3.2', 'DL-3.3') { $r.Remediation.Impact | Should -Be 'TenantWide' -Because "$($r.ControlId) changes filtering for every recipient" }
                else { $r.Remediation.Impact | Should -Be 'Standard' }
            }
            @($script:Kinds | Where-Object { $_.Impact -eq 'TenantWide' } | ForEach-Object { $_.Id } | Sort-Object -Unique) | Should -Be @('DL-3.1', 'DL-3.2', 'DL-3.3')
        }
        It 'every template names a known kind, a property, and only the known placeholders' {
            $script:Kinds.Count | Should -BeGreaterThan 8
            foreach ($k in $script:Kinds) {
                $k.Kind | Should -BeIn @('Distribution', 'Dynamic', 'Tenant')
                [string]$k.T.TargetKind | Should -Not -BeNullOrEmpty
                [string]$k.T.Property | Should -Match '^([A-Za-z]+|\{Parameter\})$' -Because "$($k.Id) $($k.Kind)"
                foreach ($f in 'Get', 'Apply', 'Rollback') {
                    foreach ($m in [regex]::Matches([string]$k.T.$f, '\{(\w+)\}')) { $m.Groups[1].Value | Should -BeIn @('Target', 'After', 'Before', 'Remove', 'Parameter') -Because "$($k.Id) $($k.Kind) $f" }
                }
                foreach ($c in @($k.T.Show)) { $c | Should -Match '^[A-Za-z]+$' }
            }
        }
        It 'the check is a Get-* read with no pipeline (the builder adds Format-List), and only the reviewed cmdlets are named anywhere' {
            foreach ($k in $script:Kinds) {
                $k.T.Get | Should -Match '^Get-' -Because "$($k.Id) $($k.Kind)"
                $k.T.Get | Should -Not -Match '[|;&`]'
                ($k.T.Get -split ' ')[0] | Should -BeIn $script:ReadCmdlets
                ($k.T.Apply -split ' ')[0] | Should -BeIn $script:WriteCmdlets
                if ($k.T.Rollback) { ($k.T.Rollback -split ' ')[0] | Should -BeIn $script:WriteCmdlets }
            }
            foreach ($r in @($script:Recs | Where-Object { $_.PSObject.Properties['Inspect'] })) { foreach ($i in @($r.Inspect.PSObject.Properties.Value)) { $i | Should -Match '^Get-' -Because "$($r.ControlId) Inspect is a read-only look" } }
        }
        It 'a template carries no -WhatIf and no -Confirm: the builder adds them, so the preview is the apply plus -WhatIf and nothing else' {
            foreach ($k in $script:Kinds) { foreach ($f in 'Get', 'Apply', 'Rollback') { [string]$k.T.$f | Should -Not -Match '-WhatIf|-Confirm|[|;&`]' -Because "$($k.Id) $($k.Kind) $f" } }
        }
        It 'a rollback writes back the CAPTURED value ({Before}), re-adds or removes exactly what the apply changed, or declares the one state it restores: never a literal inverse' {
            foreach ($k in $script:Kinds) {
                $rb = [string]$k.T.Rollback
                if (-not $rb) {
                    $k.Impact | Should -Be 'Standard' -Because "$($k.Id): a tenant-wide change without a rollback is withheld, so the catalog must not ship one"
                    [string]$k.T.ManualReason | Should -Not -BeNullOrEmpty -Because "$($k.Id) $($k.Kind) has no rollback, so it is a labeled manual action and must say why"
                    [string]$k.T.Undo | Should -Not -BeNullOrEmpty -Because "$($k.Id) $($k.Kind) must say in words how to undo it"
                    continue
                }
                if ($rb -match '^Set-') {
                    $rb | Should -Match '(\{Before\}|@\{Add=\{Remove\}\}|@\{Remove=\{After\}\})$' -Because "$($k.Id) $($k.Kind): a Set-* rollback must write a captured value or undo exactly the entries the apply changed, not a literal"
                } else {
                    [string]$k.T.RollbackRestores | Should -Not -BeNullOrEmpty -Because "$($k.Id): $rb can restore only one state and must say which"
                }
            }
        }
        It 'a command that needs an administrator-chosen value says so, and nothing else carries a <placeholder>' {
            foreach ($k in $script:Kinds) {
                $inText = @([regex]::Matches(([string]$k.T.Apply + ' ' + [string]$k.T.Rollback), '<(\w+)>') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
                @($k.T.RequiresInput | Sort-Object -Unique) | Should -Be $inText -Because "$($k.Id) $($k.Kind)"
            }
        }
        It 'a rollback that would restore an EMPTY multi-valued property writes $null, which Microsoft does not document, so the builder makes it a manual action and the template says how to undo it in words' {
            # Exactly these templates restore a list through {Before}: the builder turns each into a manual action when the captured list is empty.
            $viaBefore = @($script:Kinds | Where-Object { [string]$_.T.Rollback -match '-(AcceptMessagesOnlyFromSendersOrMembers|ModeratedBy) \{Before\}$' } | ForEach-Object { "$($_.Id)/$($_.Kind)" } | Sort-Object)
            ($viaBefore -join ',') | Should -Be 'DL-1.2/Distribution,DL-2.2/Distribution,DL-2.2/Dynamic'
            foreach ($k in @($script:Kinds | Where-Object { "$($_.Id)/$($_.Kind)" -in $viaBefore })) {
                [string]$k.T.Undo | Should -Match 'not document' -Because "$($k.Id)/$($k.Kind): the undo says why no rollback command is printed"
                [string]$k.T.Undo | Should -Not -Match '(?m)^Set-|^Get-' -Because 'the undo is guidance in words, never a command'
                $k.T.ShowsNames | Should -BeTrue -Because 'Exchange returns names or GUIDs for these, so the comparison is a count'
            }
            # the one-way owner template is a manual action too, and a count of one after the change
            foreach ($k in @($script:Kinds | Where-Object { $_.Id -eq 'DL-2.1' })) { [int]$k.T.AfterCount | Should -Be 1; $k.T.ShowsNames | Should -BeTrue }
            foreach ($k in @($script:Kinds | Where-Object { $_.T.PSObject.Properties['RollbackReason'] -or $_.T.PSObject.Properties['EmptyRestoreNote'] })) { throw "$($k.Id): RollbackReason and EmptyRestoreNote are replaced by ManualReason and Undo" }
        }
    }

    Context 'claims stay as strong as the sources' {
        It 'does not call Open the Exchange Online default: only the Exchange Server 2013 page says so' {
            $e = $script:Recs | Where-Object { $_.ControlId -eq 'DL-2.5' }
            $e.Why | Should -Match 'Exchange Server 2013'
            $e.Why | Should -Match 'without naming one'
            $e.Basis | Should -Be 'TP'
        }
        It 'discloses that Microsoft''s pages disagree on whether the IP Allow List can still fail DMARC' {
            ($script:Recs | Where-Object { $_.ControlId -eq 'DL-3.2' }).Why | Should -Match 'differ on whether'
        }
        It 'keeps the September 2022 own-domain note, so an own-domain allow entry is not overstated' {
            ($script:Recs | Where-Object { $_.ControlId -eq 'DL-3.4' }).Why | Should -Match 'September 2022'
        }
        It 'says DMARC reject does not cover a lookalike domain or a display-name impersonation' {
            $w = ($script:Recs | Where-Object { $_.ControlId -eq 'DL-4.1' }).Why
            $w | Should -Match 'lookalike'
            $w | Should -Match 'display name'
            $w | Should -Match 'cannot detect'
        }
        It 'uses US spelling in every string' {
            $script:CatalogText | Should -Not -Match '(?i)\b(licence|organisation|behaviour|defence|enrolment|catalogue|analyse|normalise|authorised|sanitised|labelled|grey)\b'
        }
    }
}

Describe 'Catalog loader and standards interpretation' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
    }
    AfterAll { Clear-TPState }

    It 'loads every recommendation, keyed by id, with the command templates as data' {
        $b = Get-TPDistributionListBaseline
        $b.Available | Should -BeTrue
        $b.ById.Contains('DL-1.1') | Should -BeTrue
        $b.ById['DL-1.1'].Remediation.Kinds['Distribution'].Apply | Should -Match '^Set-DistributionGroup -Identity \{Target\}'
        $b.ById['DL-1.1'].Remediation.Impact | Should -Be 'Standard'
        $b.ById['DL-3.2'].Remediation.Impact | Should -Be 'TenantWide'
        $b.ById['DL-3.2'].Inspect['Tenant'] | Should -Match '^Get-'
        $b.ById['DL-2.3'].Remediation | Should -BeNullOrEmpty
        $b.ById['DL-1.2'].EmitsFinding | Should -BeFalse
        $b.ById['DL-3.5'].EmitsFinding | Should -BeTrue
        $b.ById['DL-1.1'].EmitsFinding | Should -BeTrue
    }
    It 'a missing or unreadable catalog is "not loaded", never an empty clean catalog' {
        (Get-TPDistributionListBaseline -Path (Join-Path $TestDrive 'nope.json')).Available | Should -BeFalse
        Set-Content -LiteralPath (Join-Path $TestDrive 'bad.json') -Value '{ not json'
        $b = Get-TPDistributionListBaseline -Path (Join-Path $TestDrive 'bad.json')
        $b.Available | Should -BeFalse
        $b.Error | Should -Not -BeNullOrEmpty
    }

    Context 'standards' {
        BeforeAll {
            $script:Std = { param([hashtable] $v) $s = [ordered]@{}; foreach ($k in 'DistributionListMaxMembers', 'DistributionListMemberJoinRestriction') { $s[$k] = @($(if ($v.ContainsKey($k)) { $v[$k] } else { @() })) }; Get-TPDistributionListStandards -Standards $s }
        }
        It 'accepts one whole number as the member cap' {
            $r = & $script:Std @{ DistributionListMaxMembers = @('500') }
            $r.MaxMembers.Approved | Should -BeTrue; $r.MaxMembers.Value | Should -Be 500
        }
        It 'refuses a cap that is not one positive whole number, and says why' {
            foreach ($bad in @('abc'), @('0'), @('-5'), @('5.5'), @('500', '600')) {
                $r = & $script:Std @{ DistributionListMaxMembers = $bad }
                $r.MaxMembers.Approved | Should -BeFalse -Because ($bad -join ',')
                $r.MaxMembers.Issue | Should -Not -BeNullOrEmpty
            }
        }
        It 'accepts any of the three documented join settings and no other' {
            $r = & $script:Std @{ DistributionListMemberJoinRestriction = @('closed', 'ApprovalRequired') }
            $r.JoinRestriction.Approved | Should -BeTrue
            @($r.JoinRestriction.Allowed) | Should -Be @('Closed', 'ApprovalRequired')
            $x = & $script:Std @{ DistributionListMemberJoinRestriction = @('Closed', 'Locked') }
            $x.JoinRestriction.Approved | Should -BeFalse
            $x.JoinRestriction.Issue | Should -Match 'Locked'
        }
        It 'a standards dictionary lacking the keys (an older mock) reads as not approved, never throws' {
            $r = Get-TPDistributionListStandards -Standards ([ordered]@{ PriorityUsers = @() })
            $r.MaxMembers.Approved | Should -BeFalse; $r.JoinRestriction.Approved | Should -BeFalse
        }
    }
}

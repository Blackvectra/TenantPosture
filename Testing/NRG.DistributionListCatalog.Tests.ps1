#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.DistributionListCatalog.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Integrity of the distribution-list recommendation catalog
             (Config/distribution-list-baseline.json) and of the two NRG standards
             it depends on (Config/nrg-standards.json). Same discipline as the
             Conditional Access baseline: every source a real Learn link, every cited
             800-53 control present in the catalog, every judgment that is NRG's own
             routed through a standard that ships empty, and no framework id invented.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Distribution-list recommendation catalog' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:CatalogPath = Join-Path $script:Root 'Config' 'distribution-list-baseline.json'
        $script:CatalogText = Get-Content -LiteralPath $script:CatalogPath -Raw -Encoding utf8
        $script:Catalog = $script:CatalogText | ConvertFrom-Json
        $script:Recs = @($script:Catalog.recommendations)
        $script:Nist = Get-Content -LiteralPath (Join-Path $script:Root 'Config' 'nist-800-53-catalog.json') -Raw -Encoding utf8 | ConvertFrom-Json
        $script:StdText = Get-Content -LiteralPath (Join-Path $script:Root 'Config' 'nrg-standards.json') -Raw -Encoding utf8
        $script:Std = $script:StdText | ConvertFrom-Json
    }
    AfterAll { Clear-NRGState }

    Context 'shape' {
        It 'carries a recommendation for every DL-* control the evaluator emits' {
            $ids = @($script:Recs | ForEach-Object { $_.ControlId })
            foreach ($id in 'DL-1.1', 'DL-2.1', 'DL-2.2', 'DL-2.3', 'DL-2.4', 'DL-2.5', 'DL-3.1', 'DL-3.2', 'DL-3.3', 'DL-3.4', 'DL-3.5', 'DL-4.1') { $ids | Should -Contain $id }
        }
        It 'has unique, well-formed ids (the series Add-NRGFinding accepts)' {
            $ids = @($script:Recs | ForEach-Object { $_.ControlId })
            $ids.Count | Should -Be (@($ids | Sort-Object -Unique).Count)
            foreach ($id in $ids) { $id | Should -Match '^DL-\d+\.\d+$' }
        }
        It 'gives every entry a title, setting, recommended value, why, severity, basis and kind' {
            foreach ($r in $script:Recs) {
                foreach ($f in 'Title', 'Setting', 'Recommended', 'Why', 'Severity', 'Basis', 'Kind') { [string]$r.$f | Should -Not -BeNullOrEmpty -Because "$($r.ControlId) needs $f" }
                $r.Severity | Should -BeIn @('Critical', 'High', 'Medium', 'Low', 'Informational')
                $r.Basis | Should -BeIn @('Microsoft', 'NRG')
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
            # nist-800-53-catalog.json is pinned by NRG.NISTMatrix.Tests.ps1 to carry no entry nothing references.
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
        It 'every Basis NRG entry names a standard that exists in nrg-standards.json and in the loader' {
            $std = Get-NRGStandards -Path (Join-Path $script:Root 'Config' 'nrg-standards.json')
            foreach ($r in @($script:Recs | Where-Object { $_.Basis -eq 'NRG' })) {
                [string]$r.StandardKey | Should -Not -BeNullOrEmpty -Because "$($r.ControlId) is an NRG judgment and must name its standard"
                $script:Std.PSObject.Properties[[string]$r.StandardKey] | Should -Not -BeNullOrEmpty
                $std.Contains([string]$r.StandardKey) | Should -BeTrue
            }
        }
        It 'no Basis Microsoft entry borrows a standard, and no entry recommends a value of its own invention' {
            foreach ($r in @($script:Recs | Where-Object { $_.Basis -eq 'Microsoft' })) { $r.PSObject.Properties.Name | Should -Not -Contain 'StandardKey' }
        }
        It 'the two distribution-list standards ship empty (unapproved means not assessed, never met)' {
            $s = Get-NRGStandards -Path (Join-Path $script:Root 'Config' 'nrg-standards.json')
            foreach ($k in 'DistributionListMaxMembers', 'DistributionListMemberJoinRestriction') {
                $s.Contains($k) | Should -BeTrue
                @($s[$k]).Count | Should -Be 0 -Because "$k must stay empty until the owner approves a value"
                @($script:Std.$k.Values).Count | Should -Be 0
            }
        }
        It 'the unapproved standards read as not approved, with no issue to report' {
            $d = Get-NRGDistributionListStandards -Standards (Get-NRGStandards -Path (Join-Path $script:Root 'Config' 'nrg-standards.json'))
            $d.MaxMembers.Approved | Should -BeFalse; $d.JoinRestriction.Approved | Should -BeFalse
            $d.MaxMembers.Issue | Should -BeNullOrEmpty
        }
        It 'there is no external-members standard: the owner decided external members stay, so nothing can ban them' {
            (Get-Content -LiteralPath (Join-Path $script:Root 'Config' 'nrg-standards.json') -Raw -Encoding utf8) | Should -Not -Match 'DistributionListExternalMembers'
            (Get-NRGStandards -Path (Join-Path $script:Root 'Config' 'nrg-standards.json')).Contains('DistributionListExternalMembers') | Should -BeFalse
            (Get-NRGDistributionListStandards -Standards (Get-NRGStandards -Path (Join-Path $script:Root 'Config' 'nrg-standards.json'))).Contains('ExternalMembers') | Should -BeFalse
            @($script:Recs | Where-Object { $_.StandardKey -eq 'DistributionListExternalMembers' }) | Should -BeNullOrEmpty
        }
        It 'DL-2.3 is context: no standard, no finding, and no command that removes a member' {
            $r = $script:Recs | Where-Object { $_.ControlId -eq 'DL-2.3' }
            $r.Kind | Should -Be 'Context'
            $r.EmitsFinding | Should -BeFalse
            $r.PSObject.Properties.Name | Should -Not -Contain 'StandardKey'
            @($r.AdminCommands.PSObject.Properties.Value | Where-Object { $_ }) | Should -BeNullOrEmpty
            ($script:Recs | ForEach-Object { @($_.AdminCommands.PSObject.Properties.Value) } | Where-Object { $_ -match 'Remove-DistributionGroupMember' }) | Should -BeNullOrEmpty
        }
        It 'DL-1.2 carries the allowed-senders command with a {Senders} list, and cites the cmdlet reference and the outside-sender page' {
            $r = $script:Recs | Where-Object { $_.ControlId -eq 'DL-1.2' }
            $r.AdminCommands.Distribution | Should -Be 'Set-DistributionGroup -Identity {List} -AcceptMessagesOnlyFromSendersOrMembers {Senders}'
            $r.SourceUrl | Should -Be 'https://learn.microsoft.com/powershell/module/exchange/set-distributiongroup'
            @($r.AlsoSee) | Should -Contain 'https://learn.microsoft.com/troubleshoot/exchange/email-delivery/ndr/fix-error-code-5-7-136-in-exchange-online'
            $r.Why | Should -Match 'rejected'
            $r.Why | Should -Match 'SNAPSHOT'
        }
    }

    Context 'claims stay as strong as the sources' {
        It 'does not call Open the Exchange Online default: only the Exchange Server 2013 page says so' {
            $e = $script:Recs | Where-Object { $_.ControlId -eq 'DL-2.5' }
            $e.Why | Should -Match 'Exchange Server 2013'
            $e.Why | Should -Match 'without naming one'
            $e.Basis | Should -Be 'NRG'
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
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }
    AfterAll { Clear-NRGState }

    It 'loads every recommendation, keyed by id, with the command templates as data' {
        $b = Get-NRGDistributionListBaseline
        $b.Available | Should -BeTrue
        $b.ById.Contains('DL-1.1') | Should -BeTrue
        $b.ById['DL-1.1'].AdminCommands['Distribution'] | Should -Match '^Set-DistributionGroup -Identity \{List\}'
        $b.ById['DL-1.2'].EmitsFinding | Should -BeFalse
        $b.ById['DL-3.5'].EmitsFinding | Should -BeTrue
        $b.ById['DL-1.1'].EmitsFinding | Should -BeTrue
    }
    It 'a missing or unreadable catalog is "not loaded", never an empty clean catalog' {
        (Get-NRGDistributionListBaseline -Path (Join-Path $TestDrive 'nope.json')).Available | Should -BeFalse
        Set-Content -LiteralPath (Join-Path $TestDrive 'bad.json') -Value '{ not json'
        $b = Get-NRGDistributionListBaseline -Path (Join-Path $TestDrive 'bad.json')
        $b.Available | Should -BeFalse
        $b.Error | Should -Not -BeNullOrEmpty
    }

    Context 'standards' {
        BeforeAll {
            $script:Std = { param([hashtable] $v) $s = [ordered]@{}; foreach ($k in 'DistributionListMaxMembers', 'DistributionListMemberJoinRestriction') { $s[$k] = @($(if ($v.ContainsKey($k)) { $v[$k] } else { @() })) }; Get-NRGDistributionListStandards -Standards $s }
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
            $r = Get-NRGDistributionListStandards -Standards ([ordered]@{ PriorityUsers = @() })
            $r.MaxMembers.Approved | Should -BeFalse; $r.JoinRestriction.Approved | Should -BeFalse
        }
    }
}

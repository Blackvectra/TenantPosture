#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.DistributionListRbacDoc.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: docs/EXCHANGE-RBAC-DISTRIBUTION-LISTS.md says which Exchange Online cmdlets the distribution-list
             scan calls and what access they need. The cmdlet list rots silently when the collector gains a
             read, so this derives it from the collector and the catalog and fails when the page is stale.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Exchange permissions page for the distribution-list scan' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Doc = Get-Content -LiteralPath (Join-Path $script:Root 'docs' 'EXCHANGE-RBAC-DISTRIBUTION-LISTS.md') -Raw -Encoding utf8
        $collector = Get-Content -LiteralPath (Join-Path $script:Root 'Collectors' 'EXO' 'Invoke-NRGCollectDistributionLists.ps1') -Raw -Encoding utf8
        $script:Called = @([regex]::Matches($collector, "Get-NRGExoCommand\s+-Name\s+'([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $catalog = Get-Content -LiteralPath (Join-Path $script:Root 'Config' 'distribution-list-baseline.json') -Raw -Encoding utf8 | ConvertFrom-Json
        $templates = @(foreach ($r in $catalog.recommendations) { if ($r.PSObject.Properties['Remediation']) { foreach ($k in $r.Remediation.Kinds.PSObject.Properties) { $k.Value } } })
        $script:Printed = @($templates | ForEach-Object { @($_.Apply, $_.Rollback) } | Where-Object { $_ } | ForEach-Object { ($_ -split ' ')[0] } | Sort-Object -Unique)
        $script:Checked = @($templates | ForEach-Object { ($_.Get -split ' ')[0] } | Sort-Object -Unique)
        # The cmdlet column of the "What the scan calls" table.
        $section = ($script:Doc -split '(?m)^## What the scan calls')[1] -split '(?m)^### What the scan does not need' | Select-Object -First 1
        $script:TableCmdlets = @([regex]::Matches($section, '(?m)^\| `(Get-[A-Za-z]+)` \|') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    }

    It 'the collector calls the cmdlets the page lists, and the page lists no other' {
        $script:Called.Count | Should -BeGreaterOrEqual 10
        $script:TableCmdlets | Should -Be $script:Called -Because 'a cmdlet added to the collector must be added to the page, and one removed must go'
    }

    It 'every cmdlet the scan calls is a read' {
        @($script:Called | Where-Object { $_ -notmatch '^Get-' }) | Should -BeNullOrEmpty
    }

    It 'the verification snippet checks the same cmdlets, so the check an administrator runs is the check that matters' {
        $m = [regex]::Match($script:Doc, '(?s)\$cmdlets = (.*?)foreach \(\$c in')
        $m.Success | Should -BeTrue
        $snippet = @([regex]::Matches($m.Groups[1].Value, "'(Get-[A-Za-z]+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $snippet | Should -Be $script:Called
    }

    It 'the read cmdlets the printed checks use are among the cmdlets the scan reads or are named as the administrator''s own' {
        # The Get-* an administrator runs to check state before and after a change. They are covered by the same read access,
        # and a new one must be a deliberate decision, so the set is pinned here.
        ($script:Checked -join ',') | Should -Be 'Get-DistributionGroup,Get-DynamicDistributionGroup,Get-HostedConnectionFilterPolicy,Get-HostedContentFilterPolicy,Get-TransportRule'
        foreach ($c in $script:Checked) { $script:Called | Should -Contain $c -Because "$c is run by an administrator to check a bundle, and the scan reads the same object type" }
    }

    It 'names every write cmdlet the worksheet prints, and says the scan needs none of the roles that run them' {
        $script:Printed.Count | Should -BeGreaterOrEqual 5
        $section = ($script:Doc -split '(?m)^### What the scan does not need')[1] -split '(?m)^## ' | Select-Object -First 1
        foreach ($c in $script:Printed) { $section | Should -Match ([regex]::Escape($c)) -Because "$c is printed in a bundle" }
        $section | Should -Match 'its account needs none of the roles that run them'
        $section | Should -Match 'the identity that observes is not the identity that changes things'
    }

    It 'says Microsoft publishes no per-cmdlet role table, and that this is not yet validated in a tenant' {
        $script:Doc | Should -Match 'Microsoft publishes \*\*no per-cmdlet role table\*\*'
        $script:Doc | Should -Match 'Status: not yet validated against a live tenant'
        $script:Doc | Should -Match '\| \(not yet run\) \|' -Because 'the validation record stays empty until a tenant check is recorded; fill it and change the status line together'
    }

    It 'every link is a learn.microsoft.com page with no locale, and the page uses US spelling' {
        foreach ($u in [regex]::Matches($script:Doc, '\]\((https?://[^)\s]+)\)') | ForEach-Object { $_.Groups[1].Value }) {
            $u | Should -Match '^https://learn\.microsoft\.com/'
            $u | Should -Not -Match '/en-us/'
        }
        $script:Doc | Should -Not -Match '(?i)\b(licence|organisation|behaviour|defence|enrolment|catalogue|analyse|normalise|authorised|sanitised|labelled|grey)\b'
    }
}

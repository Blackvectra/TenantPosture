#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.ScubaAlignment.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Keep the ScubaGear citations honest. Config/scuba-alignment.json records, per
             NRG control, the current ScubaGear rule id, how well the evaluator's coverage
             matches it, and the versions checked. These tests keep controls.json and that
             file in step, forbid references to rules the official migration file removed or
             renamed, and require the versions to be recorded. A migrated citation is not
             proof of equivalence; the relation says what the evaluator covers.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'ScubaGear citations match the recorded alignment' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Align = Get-Content (Join-Path $script:Root 'Config' 'scuba-alignment.json') -Raw | ConvertFrom-Json -Depth 20
        $script:Controls = @((Get-Content (Join-Path $script:Root 'Config' 'controls.json') -Raw | ConvertFrom-Json -Depth 30).controls)
        $script:Cited = @{}
        foreach ($c in $script:Controls) { $s = $c.References.PSObject.Properties['SCuBA']; if ($s -and $s.Value) { $script:Cited[$c.ControlId] = [string]$s.Value } }
        $script:ByControl = @{}
        foreach ($m in @($script:Align.Mappings)) { $script:ByControl[$m.Control] = $m }
    }

    It 'records the tool, its version, the migration file and its hash' {
        $script:Align.Source.Tool | Should -Be 'CISA ScubaGear'
        $script:Align.Source.ToolVersion | Should -Match '^\d+\.\d+\.\d+$'
        $script:Align.Source.MigrationFile | Should -Match 'scuba-baseline-policy-migrations\.csv$'
        $script:Align.Source.MigrationFileSha256 | Should -Match '^[0-9a-f]{64}$'
        $script:Align.Source.CheckedOn | Should -Match '^\d{4}-\d{2}-\d{2}$'
    }
    It 'every control that cites a ScubaGear rule has an alignment entry whose current id is the citation' {
        foreach ($k in $script:Cited.Keys) {
            $script:ByControl.ContainsKey($k) | Should -BeTrue -Because "$k cites $($script:Cited[$k]) with no recorded alignment"
            $script:ByControl[$k].Current | Should -Be $script:Cited[$k] -Because "$k's citation must be the current id recorded for it"
        }
    }
    It 'an alignment entry with no current id belongs to a control that no longer cites SCuBA (obsolete reference removed, control kept)' {
        foreach ($m in @($script:Align.Mappings | Where-Object { -not $_.Current })) {
            $script:Cited.ContainsKey($m.Control) | Should -BeFalse -Because "$($m.Control): the obsolete reference must be removed"
            ($script:Controls | Where-Object ControlId -eq $m.Control) | Should -Not -BeNullOrEmpty -Because 'the NRG control itself stays'
        }
    }
    It 'every relation and strength is one of the documented values, and every entry explains itself' {
        foreach ($m in @($script:Align.Mappings)) {
            $m.Relation | Should -BeIn @('Equivalent', 'Partial', 'Manual', 'Unsupported')
            [string]$m.RequirementStrength | Should -BeIn @('', 'SHALL', 'SHOULD')
            [string]$m.Note | Should -Not -BeNullOrEmpty
        }
    }
    It 'no citation uses a rule id the official migration removed or renamed' {
        foreach ($k in $script:Cited.Keys) {
            $id = $script:Cited[$k]
            $id | Should -Not -Match '^MS\.DEFENDER\.' -Because "$k cites $id; Defender rules moved to MS.SECURITYSUITE.* in ScubaGear 2.0"
            $script:Align.Source.ObsoleteIdsMappedToNone | Should -Not -Contain $id
        }
    }
    It 'a migration to a range is never copied as the citation: the recorded id is one specific rule decided per requirement' {
        foreach ($m in @($script:Align.Mappings | Where-Object { $_.CitedIdStatus -eq 'migrated' -and $_.MigrationNewId -like '*-*' -and $_.Current })) {
            [string]$m.Current | Should -Not -Match '\s-\s' -Because "$($m.Control): the migration maps $($m.CitedBefore) to a range ($($m.MigrationNewId)); pick the rule the evaluator actually covers"
            $m.Current | Should -Not -Be $m.MigrationNewId
        }
    }
    It 'Get-TPScubaAlignment reads the file and keys it by control' {
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $a = Get-TPScubaAlignment
        $a.Available | Should -BeTrue
        $a.Mappings.Contains('AAD-1.1') | Should -BeTrue
        [string]$a.Mappings['DNS-1.3'].Relation | Should -Be 'Partial'
        Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue
    }
    It 'the framework entry names the ScubaGear version the citations were checked against' {
        $fw = Get-Content (Join-Path $script:Root 'Config' 'frameworks.json') -Raw | ConvertFrom-Json -Depth 10
        $s = @(@($fw.frameworks ?? $fw.Frameworks ?? $fw) | Where-Object { $_.Id -eq 'SCuBA' })[0]
        $s.Version | Should -Be $script:Align.Source.ToolVersion
    }
    It 'controls.json still conforms to its schema with the current ScubaGear rule ids (the schema pattern must know every product prefix)' {
        $ok = Test-Json -Json (Get-Content (Join-Path $script:Root 'Config' 'controls.json') -Raw) -SchemaFile (Join-Path $script:Root 'Config' 'schema' 'controls.schema.json') -ErrorAction SilentlyContinue
        $ok | Should -BeTrue
    }
    It 'the alignment document exists and lists every relation group' {
        $d = Get-Content (Join-Path $script:Root 'docs' 'TP-SCUBA-ALIGNMENT.md') -Raw
        foreach ($g in 'Equivalent', 'Partial', 'Manual', 'Unsupported') { $d | Should -Match $g }
        $d | Should -Match 'migrated citation does not establish equivalence'
    }
}

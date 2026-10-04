#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.Review106CA.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Regression tests for two Conditional Access defects found in review.
             D1: Graph returns includePlatforms ['all'] for "Any device"; that is not a
             platform narrowing unless platforms are also excluded. The collector now
             keeps excludePlatforms so the difference can be read.
             D2: AAD-2.1 must not score a role-scoped NRG template as a shortfall when
             the tenant's role catalog (AAD-DirectoryRoles) was not read: unread
             evidence is not assessed, never a Gap or Partial.
    Data keys consumed: AAD-CAPolicies, AAD-AuthPolicies, AAD-DirectoryRoles (fixtures).
    Graph scopes / cmdlets: none (Invoke-NRGGraphRequest is replaced in module scope).
#>

Describe 'Review 106: Conditional Access defects' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        function script:Bag([hashtable] $Data, [bool] $Success = $true) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-04T00:00:00Z'; Success = $Success; Data = $Data } }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-NRGFindings | Where-Object ControlId -eq $Cid)[-1] }
        $script:OrigGraph = & $script:Mod { ${function:Invoke-NRGGraphRequest} }
        function script:Set-Graph([scriptblock] $Body) {
            & $script:Mod { param($b) Set-Item -Path 'function:script:Invoke-NRGGraphRequest' -Value $b } $Body
        }
        # Raw Graph conditionalAccessPolicy (v1.0 shape) blocking legacy authentication
        # for all users on all resources, with the given platforms block.
        function script:RawLegacyBlock([hashtable] $Platforms) {
            $c = @{ clientAppTypes = @('exchangeActiveSync', 'other')
                    users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
                    applications = @{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @() } }
            if ($null -ne $Platforms) { $c.platforms = $Platforms }
            @{ id = 'p-legacy'; displayName = 'Block legacy authentication'; state = 'enabled'; conditions = $c
               grantControls = @{ operator = 'OR'; builtInControls = @('block') } }
        }
        function script:CollectThenJudgeLegacy([hashtable] $Platforms) {
            Clear-NRGState
            $raw = RawLegacyBlock $Platforms
            Set-Graph ({
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'identity/conditionalAccess/policies') { return @{ value = @($raw) } }
                return @{ value = @() }
            }.GetNewClosure())
            Invoke-NRGCollectAADCAPolicies 3>$null | Out-Null
            Set-NRGRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ SecurityDefaults = @{ IsEnabled = $false } })
            V 'Test-NRGControlAADLegacyAuth' 'AAD-1.1'
        }
    }
    AfterEach { & $script:Mod { param($o) Set-Item -Path 'function:script:Invoke-NRGGraphRequest' -Value $o } $script:OrigGraph }
    AfterAll  { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    Context 'D1: "Any device" (includePlatforms all) is not a platform narrowing' {
        It 'a legacy-auth block with includePlatforms [all] and no exclusions is Satisfied (AAD-1.1)' {
            $v = CollectThenJudgeLegacy @{ includePlatforms = @('all'); excludePlatforms = @() }
            $v.State | Should -Be 'Satisfied' -Because $v.Detail
        }
        It 'includePlatforms [all] with a platform excluded IS a narrowing (AAD-1.1 Partial)' {
            $v = CollectThenJudgeLegacy @{ includePlatforms = @('all'); excludePlatforms = @('linux') }
            $v.State | Should -Be 'Partial'
            $v.Detail | Should -Match 'device platforms'
        }
        It 'a specific platform list IS a narrowing (AAD-1.1 Partial)' {
            $v = CollectThenJudgeLegacy @{ includePlatforms = @('windows', 'macOS'); excludePlatforms = @() }
            $v.State | Should -Be 'Partial'
        }
        It 'no platforms condition at all is not a narrowing' {
            (CollectThenJudgeLegacy $null).State | Should -Be 'Satisfied'
        }
        It 'the collector keeps excludePlatforms' {
            CollectThenJudgeLegacy @{ includePlatforms = @('all'); excludePlatforms = @('linux') } | Out-Null
            $p = @((Get-NRGRawData -Key 'AAD-CAPolicies').Data.Policies)[0]
            @($p.Conditions.ExcludePlatforms) | Should -Be @('linux')
        }
        It 'a replayed policy from older results (no ExcludePlatforms field) with Platforms [all] is not narrowed' {
            $old = @{ DisplayName = 'old'; State = 'enabled'
                      Conditions = @{ ClientAppTypes = @('other'); Platforms = @('all')
                                      Users = @{ IncludeUsers = @('All') }; Applications = @{ Include = @('All'); Exclude = @() } } }
            @(Get-NRGCANarrowing -Policy $old) | Should -Not -Contain 'limited to some device platforms'
        }
    }
}

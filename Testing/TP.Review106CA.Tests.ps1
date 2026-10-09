#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.Review106CA.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Regression tests for two Conditional Access defects found in review.
             D1: Graph returns includePlatforms ['all'] for "Any device"; that is not a
             platform narrowing unless platforms are also excluded. The collector now
             keeps excludePlatforms so the difference can be read.
             D2: AAD-2.1 must not score a role-scoped NRG template as a shortfall when
             the tenant's role catalog (AAD-DirectoryRoles) was not read: unread
             evidence is not assessed, never a Gap or Partial.
    Data keys consumed: AAD-CAPolicies, AAD-AuthPolicies, AAD-DirectoryRoles (fixtures).
    Graph scopes / cmdlets: none (Invoke-TPGraphRequest is replaced in module scope).
#>

Describe 'Review 106: Conditional Access defects' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        function script:Bag([hashtable] $Data, [bool] $Success = $true) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-04T00:00:00Z'; Success = $Success; Data = $Data } }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-TPFindings | Where-Object ControlId -eq $Cid)[-1] }
        $script:OrigGraph = & $script:Mod { ${function:Invoke-TPGraphRequest} }
        function script:Set-Graph([scriptblock] $Body) {
            & $script:Mod { param($b) Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $b } $Body
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
            Clear-TPState
            $raw = RawLegacyBlock $Platforms
            Set-Graph ({
                param([Parameter(Position = 0)][string] $Uri, [Parameter(Position = 1)][string] $Method = 'GET', $Headers, [string] $OutputType = 'HashTable')
                if ($Uri -match 'identity/conditionalAccess/policies') { return @{ value = @($raw) } }
                return @{ value = @() }
            }.GetNewClosure())
            Invoke-TPCollectAADCAPolicies 3>$null | Out-Null
            Set-TPRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ SecurityDefaults = @{ IsEnabled = $false } })
            V 'Test-TPControlAADLegacyAuth' 'AAD-1.1'
        }
    }
    AfterEach { & $script:Mod { param($o) Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $o } $script:OrigGraph }
    AfterAll  { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

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
            $p = @((Get-TPRawData -Key 'AAD-CAPolicies').Data.Policies)[0]
            @($p.Conditions.ExcludePlatforms) | Should -Be @('linux')
        }
        It 'a replayed policy from older results (no ExcludePlatforms field) with Platforms [all] is not narrowed' {
            $old = @{ DisplayName = 'old'; State = 'enabled'
                      Conditions = @{ ClientAppTypes = @('other'); Platforms = @('all')
                                      Users = @{ IncludeUsers = @('All') }; Applications = @{ Include = @('All'); Exclude = @() } } }
            @(Get-TPCANarrowing -Policy $old) | Should -Not -Contain 'limited to some device platforms'
        }
    }

    Context 'D2: AAD-2.1 does not score role-scoped templates when the role catalog was not read' {
        BeforeAll {
            function script:Pol([string] $Name, [string[]] $ClientApps, [string[]] $Grant, [string[]] $ExRoles = @()) {
                @{ Id = $Name; DisplayName = $Name; State = 'enabled'
                   Conditions = @{ ClientAppTypes = $ClientApps; SignInRiskLevels = @(); UserRiskLevels = @(); AuthFlows = @(); Platforms = @()
                                   Users = @{ IncludeUsers = @('All'); IncludeGroups = @(); IncludeRoles = @(); ExcludeUsers = @(); ExcludeGroups = @(); ExcludeRoles = $ExRoles }
                                   Applications = @{ Include = @('All'); Exclude = @(); UserActions = @() }
                                   Locations = @{ Include = @(); Exclude = @() }; Devices = @{ FilterMode = ''; FilterRule = '' } }
                   GrantControls = @{ Operator = 'OR'; BuiltInControls = $Grant; AuthStrengthId = ''; TermsOfUse = @() }
                   SessionControls = @{} }
            }
            function script:Approve([string[]] $Templates) {
                $std = [ordered]@{ DmarcReportingAddresses = @(); CommonAttachmentFileTypes = @(); PriorityUsers = @(); RequiredConditionalAccessTemplates = @($Templates) }
                Mock -ModuleName TenantPosture Get-TPStandards { $std }.GetNewClosure()
            }
            function script:SetCa([object[]] $Policies) {
                Clear-TPState
                Set-TPRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($Policies); NamedLocations = @(); SectionStatus = @{ NamedLocations = 'Collected' } })
                Set-TPRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ SecurityDefaults = @{ IsEnabled = $false } })
            }
        }
        It 'an all-users MFA policy with no AAD-DirectoryRoles data is not a shortfall for mfa-admins' {
            Approve @('mfa-all-users', 'mfa-admins')
            SetCa @((Pol 'legacy' @('other') @('block')), (Pol 'mfa' @('all') @('mfa')))
            $v = V 'Test-TPControlAADCA' 'AAD-2.1'
            $v.Detail | Should -Not -Match 'Shortfall'
            $v.State | Should -Be 'Satisfied' -Because $v.Detail
        }
        It 'a role-dependent template the policies cannot prove without the catalog is Not assessed, never a shortfall' {
            Approve @('mfa-all-users', 'admin-phish-resistant-mfa')
            SetCa @((Pol 'legacy' @('other') @('block')), (Pol 'mfa' @('all') @('mfa')))
            $v = V 'Test-TPControlAADCA' 'AAD-2.1'
            $v.State | Should -Be 'NotApplicable' -Because $v.Detail
            $v.Detail | Should -Match 'Not assessed:.*admin-phish-resistant-mfa'
            $v.Detail | Should -Not -Match 'Shortfall'
        }
        It 'the view reports the role-dependent template NotRead when the role catalog was not read' {
            SetCa @((Pol 'legacy' @('other') @('block')), (Pol 'mfa' @('all') @('mfa') -ExRoles @('role-x')))
            $view = & $script:Mod { Get-TPConditionalAccessView }
            $row = @($view.Baseline | Where-Object { $_.Id -eq 'mfa-admins' })[0]
            $row.Status | Should -Be 'NotRead'
        }
        It 'with the role catalog read and no admin coverage, mfa-admins is still a shortfall' {
            Approve @('mfa-admins')
            SetCa @((Pol 'legacy' @('other') @('block')), (Pol 'mfa' @('all') @('mfa') -ExRoles @('role-ga')))
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data (Bag @{ RoleDefinitions = @(@{ Id = 'role-ga'; DisplayName = 'Global Administrator'; IsPriv = $true }) })
            $v = V 'Test-TPControlAADCA' 'AAD-2.1'
            $v.Detail | Should -Match 'Shortfall:.*mfa-admins'
        }
    }
}

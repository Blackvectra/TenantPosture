#Requires -Version 7.0
#
# NRG.CollectorResilience.Tests.ps1
#
# Guards the collector null-safety class of bug that produced false findings on
# real tenants: a Graph object with an ABSENT optional block (a CA policy with
# no platforms/locations condition; a role assignment whose principal is a GROUP
# or SERVICE PRINCIPAL with no userPrincipalName) made a bare deep read like
# $_.conditions.platforms.includePlatforms or $a.principal.userPrincipalName
# THROW — on PS 7.4 at the missing key, on 7.5+ at $null.leaf, on PSCustomObject
# responses on every version. One such row aborted the whole projection, so the
# collector recorded ZERO items while Success stayed $true, and every downstream
# evaluator emitted confident false gaps ("0 CA policies", "0 Global
# Administrators" on a tenant with 4).
#
# These tests feed the collectors the exact sparse/mixed shapes that crashed
# them and assert (1) every row is collected, (2) Success reflects reality.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Get-ChildItem (Join-Path $script:RepoRoot 'Lib') -Filter '*.ps1' | ForEach-Object { . $_.FullName }
    function Register-NRGException { param($Source, $Message) }
    function Register-NRGCoverage  { param($Family, $Status, $Note) }
    function Set-NRGRawData        { param($Key, $Data) }
}

Describe 'CA policy collector resilience' {
    BeforeAll {
        . (Join-Path $script:RepoRoot 'Collectors/AAD/Invoke-NRGCollectAADCAPolicies.ps1')
    }

    It 'collects policies that have NO platforms/locations/applications conditions' {
        function Invoke-NRGGraphRequest {
            param($Method, $Uri, $ErrorAction)
            if ($Uri -match 'conditionalAccess/policies') {
                return @{ value = @(
                    # bare policy — only clientAppTypes; NO platforms/locations/apps/session
                    @{ id = '1'; displayName = 'Block legacy'; state = 'enabled'
                       conditions = @{ clientAppTypes = @('other') }
                       grantControls = @{ operator = 'OR'; builtInControls = @('block') } }
                    # MFA-all policy
                    @{ id = '2'; displayName = 'MFA all'; state = 'enabled'
                       conditions = @{ users = @{ includeUsers = @('All') } }
                       grantControls = @{ operator = 'OR'; builtInControls = @('mfa') } }
                ) }
            }
            return @{ value = @() }
        }
        $r = Invoke-NRGCollectAADCAPolicies
        $r.Success | Should -BeTrue
        @($r.Data.Policies).Count | Should -Be 2 -Because 'a missing platforms condition must not abort the whole collection'
        @($r.Data.Policies | Where-Object { $_.GrantControls.BuiltInControls -contains 'mfa' }).Count | Should -Be 1
    }

    It 'reports Success=$false when the policies fetch itself throws (no false Satisfied/Gap)' {
        function Invoke-NRGGraphRequest {
            param($Method, $Uri, $ErrorAction)
            if ($Uri -match 'conditionalAccess/policies') { throw 'Graph 500' }
            return @{ value = @() }
        }
        $r = Invoke-NRGCollectAADCAPolicies
        $r.Success | Should -BeFalse -Because 'a failed CA fetch must route evaluators to NotApplicable, never a false gap'
    }
}

Describe 'Directory roles collector resilience' {
    BeforeAll {
        . (Join-Path $script:RepoRoot 'Collectors/AAD/Invoke-NRGCollectAADRoles.ps1')
        $script:GA = '62e90394-69f5-4237-9190-012177145e10'
    }

    It 'counts Global Admins assigned via users, GROUPS, and service principals' {
        $ga = $script:GA
        function Invoke-NRGGraphRequest {
            param($Method, $Uri, $ErrorAction)
            if ($Uri -match 'roleDefinitions')            { return @{ value = @(@{ id = $ga; displayName = 'Global Administrator'; isBuiltIn = $true; isEnabled = $true }) } }
            if ($Uri -match 'roleEligibilitySchedules')   { return @{ value = @() } }
            if ($Uri -match 'roleAssignments') {
                return @{ value = @(
                    @{ id = 'a1'; roleDefinitionId = $ga; principalId = 'u1'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Alice'; userPrincipalName = 'alice@x.org' } }
                    @{ id = 'a2'; roleDefinitionId = $ga; principalId = 'u2'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Bob'; userPrincipalName = 'bob@x.org' } }
                    # GROUP — no userPrincipalName (the thrower)
                    @{ id = 'a3'; roleDefinitionId = $ga; principalId = 'g1'; principal = @{ '@odata.type' = '#microsoft.graph.group'; displayName = 'IT Admins' } }
                    # SERVICE PRINCIPAL — no userPrincipalName
                    @{ id = 'a4'; roleDefinitionId = $ga; principalId = 's1'; principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'Automation SP' } }
                ) }
            }
            return @{ value = @() }
        }
        $r = Invoke-NRGCollectAADRoles
        $r.Success | Should -BeTrue
        @($r.Data.RoleAssignments).Count | Should -Be 4 -Because 'a group/SP principal without a UPN must not abort the enumeration'
        @($r.Data.RoleAssignments | Where-Object { $_.RoleDefinitionName -eq 'Global Administrator' }).Count |
            Should -Be 4 -Because 'this is the "tenant with 4 GAs reported 0" regression'
    }

    It 'counts PIM-eligible Global Admins when there are ZERO permanent assignments' {
        $ga = $script:GA
        function Invoke-NRGGraphRequest {
            param($Method, $Uri, $ErrorAction)
            if ($Uri -match 'roleDefinitions')          { return @{ value = @(@{ id = $ga; displayName = 'Global Administrator'; isBuiltIn = $true; isEnabled = $true }) } }
            if ($Uri -match 'roleAssignments')          { return @{ value = @() } }   # PIM tenant: none permanent
            if ($Uri -match 'roleEligibilitySchedules') {
                return @{ value = @(
                    @{ id = 'e1'; roleDefinitionId = $ga; principalId = 'u3'; principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Carol'; userPrincipalName = 'carol@x.org' }; scheduleInfo = @{ startDateTime = '2026-01-01' } }
                ) }
            }
            return @{ value = @() }
        }
        $r = Invoke-NRGCollectAADRoles
        $r.Success | Should -BeTrue -Because 'a PIM tenant with only eligible assignments is a valid, fully-collected state'
        @($r.Data.RoleEligibilitySchedules | Where-Object { $_.RoleDefinitionName -eq 'Global Administrator' }).Count | Should -Be 1
    }
}

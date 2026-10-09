#Requires -Version 7.0
#
# TP.PIMPolicies.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Pins the PIM policy-to-role mapping and the privileged-role scoping of
# AAD-3.3..3.6, plus the role-name-resolution guard behind AAD-10.2 / AAD-11.2.
#
# Found on a live tenant (2026-09-24): Graph names every directory-role PIM
# policy "DirectoryRole", so AAD-3.5 looked for 'Global' in the display name
# and could never find the Global Administrator policy; AAD-3.3..3.6 weighed
# all ~50 roles equally; MFA required via a Conditional Access authentication
# context was never counted. Separately, two role assignments held by the
# Microsoft first-party "Microsoft Office 365 Portal" service principal carry
# hidden internal roles roleDefinitions never lists, and that alone made
# AAD-10.2 (26 synced privileged accounts) and AAD-11.2 report "not assessed".
#
# The Graph mock is injected into MODULE scope, and so are the scenario
# variables it reads (via & $script:Mod { ... }) — the mock resolves $script:
# against the module, not this file.

Describe 'PIM policy scoping (AAD-3.3 .. AAD-3.6)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:GA   = '62e90394-69f5-4237-9190-012177145e10'   # Global Administrator (built-in template)
        $script:HD   = '729827e3-9c14-49f7-bb1b-9608f156bbb8'   # Helpdesk Administrator
        $script:DIR  = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'   # Directory Readers

        & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } 'Invoke-TPGraphRequest' @'
[CmdletBinding()]
param([string] $Uri, [string] $Method = 'GET', $Body, $Headers, [string] $OutputType = 'HashTable')
if ($Uri -match 'policies/roleManagementPolicies\?')     { $script:PimListUri = $Uri; return @{ value = @($script:PimPolicies) } }
if ($Uri -match 'policies/roleManagementPolicies/') {
    $id = [uri]::UnescapeDataString(($Uri -split 'roleManagementPolicies/')[1].Split('?')[0])
    if ($script:PimById -and $script:PimById.ContainsKey($id)) { return $script:PimById[$id] }
    throw 'Graph 404 NotFound'
}
if ($Uri -like '*policies/roleManagementPolicyAssignments*') {
    if ($script:AssignmentsFail) { throw 'Graph 400 BadRequest' }
    return @{ value = @($script:PimAssignments) }
}
return @{ value = @() }
'@

        function New-Policy {
            param([string]$Id, [string[]]$EnabledRules = @('Justification'), [bool]$AuthCtx = $false,
                  [bool]$Approval = $false, [string]$MaxDuration = 'PT8H')
            @{
                id = $Id; displayName = 'DirectoryRole'; scopeId = '/'; scopeType = 'DirectoryRole'
                rules = @(
                    @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'; id = 'Enablement_EndUser_Assignment'; enabledRules = $EnabledRules }
                    @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule'; id = 'AuthenticationContext_EndUser_Assignment'; isEnabled = $AuthCtx }
                    @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'; id = 'Approval_EndUser_Assignment'; setting = @{ isApprovalRequired = $Approval } }
                    @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'; id = 'Expiration_EndUser_Assignment'; maximumDuration = $MaxDuration }
                )
            }
        }

        function Set-Scenario {
            param([object[]]$Policies, [object[]]$Assignments = @(), [bool]$AssignmentsFail = $false, [hashtable]$ById = @{})
            Clear-TPState
            & $script:Mod { param($p, $a, $f, $b) $script:PimPolicies = $p; $script:PimAssignments = $a; $script:AssignmentsFail = $f; $script:PimById = $b } $Policies $Assignments $AssignmentsFail $ById
            # Role catalog as AAD-DirectoryRoles publishes it (IsPriv drives scoping).
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data @{ Success = $true; Data = @{ RoleDefinitions = @(
                @{ Id = $script:GA;  DisplayName = 'Global Administrator';   IsPriv = $true;  IsBuiltIn = $true; IsEnabled = $true }
                @{ Id = $script:HD;  DisplayName = 'Helpdesk Administrator'; IsPriv = $true;  IsBuiltIn = $true; IsEnabled = $true }
                @{ Id = $script:DIR; DisplayName = 'Directory Readers';      IsPriv = $false; IsBuiltIn = $true; IsEnabled = $true }
            ) } }
            $null = Invoke-TPCollectAADIdentityGovernance
        }

        function Asg([string]$PolicyId, [string]$RoleId) { @{ policyId = $PolicyId; roleDefinitionId = $RoleId; scopeId = '/'; scopeType = 'DirectoryRole' } }
        function Verdict([string]$Cid) { Get-TPFindings | Where-Object { $_.ControlId -eq $Cid } | Select-Object -First 1 }
    }

    It 'attaches RoleDefinitionId to each policy from roleManagementPolicyAssignments' {
        Set-Scenario -Policies @((New-Policy 'p-ga')) -Assignments @((Asg 'p-ga' $script:GA))
        $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
        $gov.Data.PIMRolePolicies[0].RoleDefinitionId | Should -Be $script:GA
        $gov.Data.SectionStatus.PIMPolicyAssignments | Should -Be 'Collected'
    }

    It 'counts MFA required via an authentication context as MFA' {
        Set-Scenario -Policies @((New-Policy 'p-ga' -EnabledRules @('Justification') -AuthCtx $true)) -Assignments @((Asg 'p-ga' $script:GA))
        (Get-TPRawData -Key 'AAD-IdentityGovernance').Data.PIMRolePolicies[0].RequiresMFA | Should -BeTrue
        Test-TPControlAADPIMMFA
        (Verdict 'AAD-3.3').State | Should -Be 'Satisfied'
    }

    It 'AAD-3.3 scores privileged roles only and names the ones without MFA' {
        Set-Scenario -Policies @(
            (New-Policy 'p-ga'  -EnabledRules @('MultiFactorAuthentication','Justification'))
            (New-Policy 'p-hd'  -EnabledRules @('Justification'))
            (New-Policy 'p-dir' -EnabledRules @('Justification'))
        ) -Assignments @((Asg 'p-ga' $script:GA), (Asg 'p-hd' $script:HD), (Asg 'p-dir' $script:DIR))
        Test-TPControlAADPIMMFA
        $f = Verdict 'AAD-3.3'
        $f.State  | Should -Be 'Gap'
        $f.Detail | Should -Match '1 of 2 privileged-role'
        $f.Detail | Should -Match 'Helpdesk Administrator'
        $f.Detail | Should -Not -Match 'Directory Readers' -Because 'a non-privileged role without MFA is not this control''s concern'
    }

    It 'AAD-3.5 finds the Global Administrator policy by role and reports its approval setting' {
        Set-Scenario -Policies @((New-Policy 'p-ga' -Approval $false), (New-Policy 'p-hd' -Approval $true)) `
                     -Assignments @((Asg 'p-ga' $script:GA), (Asg 'p-hd' $script:HD))
        Test-TPControlAADPIMApproval
        (Verdict 'AAD-3.5').State | Should -Be 'Gap' -Because 'approval not required is the setting not configured, never half credit'

        Set-Scenario -Policies @((New-Policy 'p-ga' -Approval $true)) -Assignments @((Asg 'p-ga' $script:GA))
        Test-TPControlAADPIMApproval
        (Verdict 'AAD-3.5').State | Should -Be 'Satisfied'
    }

    It 'reads a policy the list did not return by its ID, and never asks the list for $top' {
        # Live tenant, 2026-09-25: $top=50 returned 50 of ~130 role policies and
        # no nextLink, so the Global Administrator policy was never seen.
        Set-Scenario -Policies @((New-Policy 'p-hd' -Approval $true)) `
                     -Assignments @((Asg 'p-ga' $script:GA), (Asg 'p-hd' $script:HD)) `
                     -ById @{ 'p-ga' = (New-Policy 'p-ga' -Approval $true) }
        (& $script:Mod { $script:PimListUri }) | Should -Not -Match '\$top'
        $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
        @($gov.Data.PIMRolePolicies).Count | Should -Be 2
        Test-TPControlAADPIMApproval
        (Verdict 'AAD-3.5').State | Should -Be 'Satisfied'
    }

    It 'falls back to all-role scoring, and says so, when the assignment query fails' {
        Set-Scenario -Policies @((New-Policy 'p-ga' -EnabledRules @('Justification'))) -AssignmentsFail $true
        (Get-TPRawData -Key 'AAD-IdentityGovernance').Data.SectionStatus.PIMPolicyAssignments | Should -Be 'Failed'
        Test-TPControlAADPIMMFA
        $f = Verdict 'AAD-3.3'
        $f.State  | Should -Be 'Gap'
        $f.Detail | Should -Match 'mapping was unavailable'
        Test-TPControlAADPIMApproval
        (Verdict 'AAD-3.5').State | Should -Be 'NotApplicable' -Because 'without the map the GA policy cannot be identified, and guessing is not assessing'
    }

    It 'never passes AAD-3.4 on an unreadable justification setting' {
        Clear-TPState
        Set-TPRawData -Key 'AAD-IdentityGovernance' -Data @{ Success = $true; Data = @{ PIMRolePolicies = @(
            @{ PolicyId = 'p1'; RequiresJustification = $null; RequiresMFA = $true; MaxDurationHours = 8 }) } }
        Test-TPControlAADPIMJustification
        (Verdict 'AAD-3.4').State | Should -Be 'NotApplicable'
    }
}

Describe 'Role-name resolution guard (AAD-10.2 / AAD-11.2)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        function Set-Roles([object[]]$Assignments) {
            Clear-TPState
            $priv = @($Assignments | Where-Object { $_.IsPriv })
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data @{ Success = $true; Data = @{
                RoleAssignments = $Assignments; PrivRoles = $priv
                SectionStatus = @{ RoleAssignments = 'Collected' } } }
        }
        function User([string]$Role, [bool]$Synced, [bool]$Priv = $true) {
            @{ PrincipalType = '#microsoft.graph.user'; RoleDefinitionName = $Role; OnPremisesSyncEnabled = $Synced
               PrincipalUPN = 'a@contoso.com'; PrincipalDisplayName = 'A'; IsPriv = $Priv }
        }
        # Microsoft first-party SP holding a hidden internal role: name never resolves.
        $script:HiddenSP = @{ PrincipalType = '#microsoft.graph.servicePrincipal'; RoleDefinitionName = 'd65e02d2-0214-4674-8e5d-766fb330e2c0'
                              OnPremisesSyncEnabled = $null; PrincipalDisplayName = 'Microsoft Office 365 Portal'; IsPriv = $false }
        function Verdict([string]$Cid) { Get-TPFindings | Where-Object { $_.ControlId -eq $Cid } | Select-Object -First 1 }
    }

    It 'an unresolvable service-principal role does not blank out AAD-10.2' {
        Set-Roles @((User 'Global Administrator' $true), $script:HiddenSP)
        Test-TPControlAADPrivCloudOnly
        (Verdict 'AAD-10.2').State | Should -Be 'Gap'
    }

    It 'an unresolvable service-principal role does not blank out AAD-11.2' {
        Set-Roles @((User 'Global Administrator' $false), $script:HiddenSP)
        Test-TPControlAADNoGuestInPrivRoles
        (Verdict 'AAD-11.2').State | Should -Be 'Satisfied'
    }

    It 'still refuses to score when a USER assignment name did not resolve (a real lookup failure)' {
        Set-Roles @((User '62e90394-69f5-4237-9190-012177145e10' $false))
        Test-TPControlAADPrivCloudOnly
        (Verdict 'AAD-10.2').State | Should -Be 'NotApplicable'
        Test-TPControlAADNoGuestInPrivRoles
        (Verdict 'AAD-11.2').State | Should -Be 'NotApplicable'
    }
}

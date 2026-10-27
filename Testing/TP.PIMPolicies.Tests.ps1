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
                  [bool]$Approval = $false, [string]$MaxDuration = 'PT8H', [string]$Claim = '')
            @{
                id = $Id; displayName = 'DirectoryRole'; scopeId = '/'; scopeType = 'DirectoryRole'
                rules = @(
                    @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'; id = 'Enablement_EndUser_Assignment'; enabledRules = $EnabledRules }
                    @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule'; id = 'AuthenticationContext_EndUser_Assignment'; isEnabled = $AuthCtx; claimValue = $Claim }
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

    # An authentication context is a label: what it requires is the Conditional
    # Access policy that targets its claim value. It counts as MFA only when an
    # enabled policy for everyone requires MFA on that context.
    It 'counts an authentication context as MFA only when its Conditional Access policy requires MFA of everyone' {
        $ctxPol = { param([string[]] $Grant, [string] $State = 'enabled', [string[]] $Users = @('All'), [string] $Claim = 'c1')
            @{ DisplayName = "ctx $Claim"; State = $State
               Conditions = @{ ClientAppTypes = @('all'); Users = @{ IncludeUsers = $Users; ExcludeUsers = @(); ExcludeGroups = @(); ExcludeRoles = @() }
                               Applications = @{ Include = @(); Exclude = @(); AuthenticationContext = @($Claim) } }
               GrantControls = @{ Operator = 'OR'; BuiltInControls = $Grant } } }
        $setCa = { param([object[]] $Pols) Set-TPRawData -Key 'AAD-CAPolicies' -Data @{ Success = $true; Data = @{ Policies = @($Pols); SectionStatus = @{ PolicyCompleteness = 'Collected' } } } }

        Set-Scenario -Policies @((New-Policy 'p-ga' -EnabledRules @('Justification') -AuthCtx $true -Claim 'c1')) -Assignments @((Asg 'p-ga' $script:GA))
        $p = (Get-TPRawData -Key 'AAD-IdentityGovernance').Data.PIMRolePolicies[0]
        $p.RequiresMFA | Should -BeTrue
        $p.MfaViaEnablement | Should -BeFalse
        $p.AuthContextEnabled | Should -BeTrue
        $p.AuthContextClaimValue | Should -Be 'c1'

        & $setCa @((& $ctxPol @('mfa')))
        Test-TPControlAADPIMMFA
        (Verdict 'AAD-3.3').State | Should -Be 'Satisfied'

        Clear-TPFindings; & $setCa @((& $ctxPol @('compliantDevice')))
        Test-TPControlAADPIMMFA
        $f = Verdict 'AAD-3.3'
        $f.State | Should -Be 'Gap' -Because 'a context backed by a compliant-device grant does not require MFA'
        $f.Detail | Should -Match "authentication context 'c1'"

        Clear-TPFindings; & $setCa @((& $ctxPol @('mfa') -Claim 'c2'))
        Test-TPControlAADPIMMFA
        (Verdict 'AAD-3.3').State | Should -Be 'Gap' -Because 'no enabled policy targets c1, so it requires nothing'

        Clear-TPFindings; & $setCa @((& $ctxPol @('mfa') -State 'enabledForReportingButNotEnforced'))
        Test-TPControlAADPIMMFA
        (Verdict 'AAD-3.3').State | Should -Be 'Gap' -Because 'a report-only policy enforces nothing'

        Clear-TPFindings; & $setCa @((& $ctxPol @('mfa') -Users @('some-group-id')))
        Test-TPControlAADPIMMFA
        (Verdict 'AAD-3.3').State | Should -Be 'Gap' -Because 'a policy for some users leaves the other eligible users without MFA on activation'

        Clear-TPFindings; Set-TPRawData -Key 'AAD-CAPolicies' -Data @{ Success = $false; Data = @{} }
        Test-TPControlAADPIMMFA
        (Verdict 'AAD-3.3').State | Should -Be 'NotApplicable' -Because 'the Conditional Access policies were not read'
    }

    It 'a results file from before the MFA and authentication-context routes were recorded apart is not assessed' {
        Clear-TPState
        Set-TPRawData -Key 'AAD-IdentityGovernance' -Data @{ Success = $true; Data = @{ PIMRolePolicies = @(
            @{ PolicyId = 'p1'; RequiresMFA = $true; RequiresJustification = $true; MaxDurationHours = 8 }) } }
        Test-TPControlAADPIMMFA
        (Verdict 'AAD-3.3').State | Should -Be 'NotApplicable'
        Clear-TPState
        Set-TPRawData -Key 'AAD-IdentityGovernance' -Data @{ Success = $true; Data = @{ PIMRolePolicies = @(
            @{ PolicyId = 'p1'; RequiresMFA = $false; RequiresJustification = $true; MaxDurationHours = 8 }) } }
        Test-TPControlAADPIMMFA
        (Verdict 'AAD-3.3').State | Should -Be 'Gap' -Because 'neither route on is a Gap whatever the file''s age'
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

    # AAD-3.6 (owner's decision 2026-10-26, Microsoft Zero Trust Phase 1 Step 6: "Set maximum
    # activation duration (for example: 1-4 hours for high-impact roles)"): Global, Privileged
    # Role, Security, Exchange and SharePoint Administrator at 4 hours or less; the other
    # privileged roles at 8 hours or less. Durations are read in full (PT30M, PT1H30M, P1D).
    Context 'AAD-3.6 maximum activation duration' {
        BeforeAll {
            $script:HighIds = [ordered]@{
                'Global Administrator' = $script:GA; 'Privileged Role Administrator' = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
                'Security Administrator' = '194ae4cb-b126-40b2-bd5b-6091b380977d'; 'Exchange Administrator' = '29232cdf-9323-42fd-ade2-1d097af3e4de'
                'SharePoint Administrator' = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' }
            function script:Run36([hashtable] $Durations, [string] $Helpdesk = 'PT8H', [string[]] $Skip = @()) {
                $pols = @(); $asg = @()
                foreach ($n in @($script:HighIds.Keys)) {
                    if ($n -in $Skip) { continue }
                    $d = if ($Durations.ContainsKey($n)) { $Durations[$n] } else { 'PT4H' }
                    $pid_ = "p-$($script:HighIds[$n])"; $pols += New-Policy $pid_ -MaxDuration $d; $asg += Asg $pid_ $script:HighIds[$n]
                }
                $pols += New-Policy 'p-hd' -MaxDuration $Helpdesk; $asg += Asg 'p-hd' $script:HD
                Set-Scenario -Policies $pols -Assignments $asg
                $defs = @(foreach ($n in @($script:HighIds.Keys)) { @{ Id = $script:HighIds[$n]; DisplayName = $n; IsPriv = $true; IsBuiltIn = $true; IsEnabled = $true } })
                $defs += @{ Id = $script:HD; DisplayName = 'Helpdesk Administrator'; IsPriv = $true; IsBuiltIn = $true; IsEnabled = $true }
                Set-TPRawData -Key 'AAD-DirectoryRoles' -Data @{ Success = $true; Data = @{ RoleDefinitions = $defs } }
                Clear-TPFindings
                Test-TPControlAADPIMDuration
                Verdict 'AAD-3.6'
            }
        }

        It 'the collector reads every part of the ISO 8601 duration' {
            $null = Run36 @{ 'Global Administrator' = 'PT1H30M'; 'Security Administrator' = 'PT30M' } -Helpdesk 'P1D'
            $pp = @((Get-TPRawData -Key 'AAD-IdentityGovernance').Data.PIMRolePolicies)
            ($pp | Where-Object { $_.PolicyId -eq "p-$($script:GA)" }).MaxDurationHours | Should -Be 1.5
            ($pp | Where-Object { $_.PolicyId -eq "p-$($script:GA)" }).MaxDuration | Should -Be 'PT1H30M'
            ($pp | Where-Object { $_.PolicyId -eq 'p-194ae4cb-b126-40b2-bd5b-6091b380977d' }).MaxDurationHours | Should -Be 0.5
            ($pp | Where-Object { $_.PolicyId -eq 'p-hd' }).MaxDurationHours | Should -Be 24
            $conv = { param($d) & $script:Mod { param($x) ConvertTo-TPDurationHours -Duration $x } $d }
            & $conv 'PT4H30M' | Should -Be 4.5
            & $conv 'PT8H'    | Should -Be 8
            $null -eq (& $conv 'P1Y')   | Should -BeTrue -Because 'a year has no fixed length in hours'
            $null -eq (& $conv 'PT')    | Should -BeTrue
            $null -eq (& $conv '8h')    | Should -BeTrue
        }

        It 'high-impact roles at 4 hours (or minutes) and the others at 8 is Satisfied, naming the set' {
            $f = Run36 @{ 'Security Administrator' = 'PT30M'; 'Exchange Administrator' = 'PT1H30M' }
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'Global Administrator, Privileged Role Administrator, Security Administrator, Exchange Administrator, SharePoint Administrator'
        }

        It 'a high-impact role over 4 hours, even by minutes, is a shortfall; 8 hours is still fine for the others' {
            $f = Run36 @{ 'Global Administrator' = 'PT4H30M' }
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Global Administrator \(4.5 hours; limit 4 hours\)'
            (Run36 @{ 'Global Administrator' = 'PT5H' }).State | Should -Be 'Partial'
            (Run36 @{} -Helpdesk 'PT9H').State | Should -Be 'Partial'
            (Run36 @{} -Helpdesk 'PT8H').State | Should -Be 'Satisfied'
        }

        It 'a high-impact role with no mapped policy, or an unreadable duration, is not assessed' {
            $f = Run36 @{} -Skip @('SharePoint Administrator')
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'SharePoint Administrator, because no PIM policy was mapped'
            (Run36 @{ 'Exchange Administrator' = 'forever' }).State | Should -Be 'NotApplicable'
        }

        It 'an older results file (hour part only): a value equal to the limit is not assessed, over it is a shortfall, under it passes' {
            $mk = { param([object[]] $Pols)
                Clear-TPState
                Set-TPRawData -Key 'AAD-IdentityGovernance' -Data @{ Success = $true; Data = @{ PIMRolePolicies = @($Pols) } }
                Set-TPRawData -Key 'AAD-DirectoryRoles' -Data @{ Success = $true; Data = @{ RoleDefinitions = @(
                    foreach ($n in @($script:HighIds.Keys)) { @{ Id = $script:HighIds[$n]; DisplayName = $n; IsPriv = $true } }) } }
                Test-TPControlAADPIMDuration; Verdict 'AAD-3.6' }
            $pols = { param([int] $ga) @(foreach ($n in @($script:HighIds.Keys)) { @{ PolicyId = "p-$n"; RoleDefinitionId = $script:HighIds[$n]; MaxDurationHours = $(if ($n -eq 'Global Administrator') { $ga } else { 2 }) } }) }
            (& $mk (& $pols 4)).State | Should -Be 'NotApplicable' -Because 'PT4H30M was stored as 4'
            (& $mk (& $pols 5)).State | Should -Be 'Partial'
            (& $mk (& $pols 3)).State | Should -Be 'Satisfied'
        }

        It 'without the policy-to-role map the high-impact half is not assessed, and 9 hours is still a shortfall' {
            Set-Scenario -Policies @((New-Policy 'p-x' -MaxDuration 'PT2H')) -AssignmentsFail $true
            Test-TPControlAADPIMDuration
            $f = Verdict 'AAD-3.6'; $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'mapping was unavailable'
            Set-Scenario -Policies @((New-Policy 'p-x' -MaxDuration 'PT9H')) -AssignmentsFail $true
            Test-TPControlAADPIMDuration
            (Verdict 'AAD-3.6').State | Should -Be 'Gap'
        }
    }
}

Describe 'Role-name resolution guard (AAD-10.2 / AAD-11.2)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        # AAD-10.2 judges role ids against the tenant role catalog (CIS 1.1.1);
        # -NoCatalog leaves the catalog unread.
        function Set-Roles([object[]]$Assignments, [switch]$NoCatalog) {
            Clear-TPState
            $priv = @($Assignments | Where-Object { $_.IsPriv })
            $catalog = if ($NoCatalog) { @() } else { @(@{ Id = '62e90394-69f5-4237-9190-012177145e10'; DisplayName = 'Global Administrator'; IsPriv = $true }) }
            Set-TPRawData -Key 'AAD-DirectoryRoles' -Data @{ Success = $true; Data = @{
                RoleAssignments = $Assignments; PrivRoles = $priv; RoleDefinitions = $catalog
                SectionStatus = @{ RoleAssignments = 'Collected'; RoleEligibilitySchedules = 'Collected'; PrivilegedRoleFlags = 'Collected' } } }
        }
        function User([string]$Role, [bool]$Synced, [bool]$Priv = $true) {
            $rid = if ($Role -eq 'Global Administrator') { '62e90394-69f5-4237-9190-012177145e10' } else { $Role }
            @{ PrincipalType = '#microsoft.graph.user'; PrincipalUserType = 'Member'; RoleDefinitionName = $Role; RoleDefinitionId = $rid; OnPremisesSyncEnabled = $Synced; OnPremisesSyncReturned = $true
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
        Set-Roles @((User '62e90394-69f5-4237-9190-012177145e10' $false)) -NoCatalog
        Test-TPControlAADPrivCloudOnly
        (Verdict 'AAD-10.2').State | Should -Be 'NotApplicable'
        Test-TPControlAADNoGuestInPrivRoles
        (Verdict 'AAD-11.2').State | Should -Be 'NotApplicable'
    }
}

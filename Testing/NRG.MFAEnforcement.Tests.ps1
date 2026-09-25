#Requires -Version 7.0
#
# NRG.MFAEnforcement.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# AAD-1.2 "MFA Required for All Users" (Critical) made two false statements:
#  1. It read security defaults from AAD-Users.Data.SecurityDefaultsEnabled,
#     a key no collector writes (they are collected into
#     AAD-AuthPolicies.Data.SecurityDefaults.IsEnabled). A tenant enforcing
#     MFA through security defaults was scored on registration instead, and
#     the finding printed "Security Defaults: disabled" without reading it.
#  2. It only recognized the 'mfa' built-in grant, so a Conditional Access
#     policy requiring MFA through an AUTHENTICATION STRENGTH read as "no
#     enforcing CA policy" (Partial). It also accepted "MFA OR compliant
#     device", which does not require MFA.

Describe 'AAD-1.2 MFA enforcement' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:Bag([hashtable] $Data, [bool] $Success = $true) {
            [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-24T00:00:00Z'; Success = $Success; Data = $Data }
        }
        # Two enabled members; $Registered of them MFA-registered.
        function script:Set-Users([int] $Registered) {
            $u = @(
                @{ UserPrincipalName = 'a@corp.example'; AccountEnabled = $true; UserType = 'Member' }
                @{ UserPrincipalName = 'b@corp.example'; AccountEnabled = $true; UserType = 'Member' }
            )
            $reg = @(0..1 | ForEach-Object { @{ UserPrincipalName = $u[$_].UserPrincipalName; IsMfaRegistered = ($_ -lt $Registered) } })
            Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = $u; MFARegistration = @{ RegistrationDetails = $reg } })
        }
        function script:Set-SecDefaults($Enabled) {
            $d = @{}
            if ($null -ne $Enabled) { $d.SecurityDefaults = @{ IsEnabled = [bool]$Enabled } }
            Set-NRGRawData -Key 'AAD-AuthPolicies' -Data (Bag $d)
        }
        function script:New-Ca([string[]] $BuiltIn = @(), [string] $StrengthId = '', [string] $Operator = 'OR', [string] $State = 'enabled', [string[]] $Apps = @('All')) {
            @{ DisplayName = 'Require MFA'; State = $State
               Conditions = @{ Users = @{ IncludeUsers = @('All') }; Applications = @{ Include = $Apps } }
               GrantControls = @{ Operator = $Operator; BuiltInControls = $BuiltIn; AuthStrengthId = $StrengthId } }
        }
        function script:Get-Verdict {
            Test-NRGControlAADMFA | Out-Null
            @(Get-NRGFindings | Where-Object ControlId -eq 'AAD-1.2')[0]
        }
    }

    BeforeEach { Clear-NRGState }

    It 'security defaults ON satisfies AAD-1.2 even with incomplete registration' {
        Set-Users -Registered 1
        Set-SecDefaults $true
        (Get-Verdict).State | Should -Be 'Satisfied'
    }

    It 'never claims "Security Defaults: disabled" when they were not read' {
        Set-Users -Registered 2
        Set-SecDefaults $null
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @() })
        $f = Get-Verdict
        $f.CurrentValue | Should -Not -Match 'Security Defaults: disabled'
        $f.CurrentValue | Should -Match 'Security Defaults: not read'
    }

    It 'says disabled only when it was read as disabled' {
        Set-Users -Registered 2
        Set-SecDefaults $false
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @() })
        (Get-Verdict).CurrentValue | Should -Match 'Security Defaults: disabled'
    }

    It 'an authentication-strength grant for All users / All apps counts as enforcing MFA' {
        Set-Users -Registered 2
        Set-SecDefaults $false
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @(New-Ca -StrengthId '00000000-0000-0000-0000-000000000002') })
        (Get-Verdict).State | Should -Be 'Satisfied'
    }

    It '"MFA OR compliant device" does not require MFA' {
        Set-Users -Registered 2
        Set-SecDefaults $false
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @(New-Ca -BuiltIn @('mfa', 'compliantDevice') -Operator 'OR') })
        (Get-Verdict).State | Should -Be 'Partial'
    }

    It '"MFA AND compliant device" requires MFA' {
        Set-Users -Registered 2
        Set-SecDefaults $false
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @(New-Ca -BuiltIn @('mfa', 'compliantDevice') -Operator 'AND') })
        (Get-Verdict).State | Should -Be 'Satisfied'
    }

    It 'a policy scoped to some apps, or in report-only, is not universal enforcement' {
        Set-Users -Registered 2
        Set-SecDefaults $false
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @(
            (New-Ca -BuiltIn @('mfa') -Apps @('00000003-0000-0ff1-ce00-000000000000')),
            (New-Ca -BuiltIn @('mfa') -State 'enabledForReportingButNotEnforced')) })
        (Get-Verdict).State | Should -Be 'Partial'
    }

    It 'full registration with Conditional Access not collected is not assessed, not a Partial' {
        Set-Users -Registered 2
        Set-SecDefaults $false
        (Get-Verdict).State | Should -Be 'NotApplicable'
    }
}

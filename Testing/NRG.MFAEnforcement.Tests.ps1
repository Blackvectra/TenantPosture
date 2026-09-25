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
#  3. With security defaults on it said "MFA enforced for all users" and passed
#     whatever the registration. Security Defaults prompts ordinary users only
#     when Microsoft decides it is necessary (only 16 administrator roles do
#     MFA at every sign-in), so it is Partial even with every user registered,
#     and an unregistered user is a Partial on either path.
#  4. With security defaults NOT READ and no CA policy On it scored the CA
#     path's Gap — treating an unread state as disabled. It is not assessed.

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

    # Security Defaults has had no registration grace period since July 29,
    # 2024: an unregistered user is asked to register at the next sign-in, so
    # whoever holds the password enrolls the second factor — the same exposure
    # the Conditional Access path scores Partial. This test used to pin
    # Satisfied here, which credited MFA the tenant's users had not set up.
    It 'security defaults ON with incomplete registration is Partial, as on the Conditional Access path' {
        Set-Users -Registered 1
        Set-SecDefaults $true
        $f = Get-Verdict
        $f.State  | Should -Be 'Partial'
        $f.Detail | Should -Match 'whoever holds their password'
        $f.Detail | Should -Match '^Security Defaults is enabled\.'
    }

    # Microsoft: only the 16 named administrator roles do MFA "every time
    # they sign in"; other users are prompted "whenever necessary. Microsoft
    # decides when". A Satisfied here credited IA-2(2) / MS.AAD.3.2v1 / PCI
    # 8.4 (MFA on access to non-privileged accounts), which Security Defaults
    # does not enforce: MFA at every sign-in for some accounts but not all.
    It 'security defaults ON with every user registered is Partial (every-sign-in MFA for the named admin roles only), never Satisfied' {
        Set-Users -Registered 2
        Set-SecDefaults $true
        $f = Get-Verdict
        $f.State        | Should -Be 'Partial'
        $f.Detail       | Should -Match 'not at every sign-in'
        $f.Detail       | Should -Match 'Only the 16 administrator roles'
        $f.Detail       | Should -Not -Match 'enforced for all users'
        $f.CurrentValue | Should -Match '100% registered'
        $f.RequiredValue | Should -Not -Match 'or Security Defaults' -Because 'Security Defaults does not meet the requirement by itself'
        $f.Remediation  | Should -Match 'turn off Security Defaults'
        $f.Remediation  | Should -Not -Match 'Or enable Security Defaults'
        (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
    }

    It 'security defaults ON with MFA registration not collected is not assessed, never Satisfied' {
        $u = @(@{ UserPrincipalName = 'a@corp.example'; AccountEnabled = $true; UserType = 'Member' })
        Set-NRGRawData -Key 'AAD-Users' -Data (Bag @{ Users = $u; MFARegistration = @{ RegistrationDetails = @() }; SectionStatus = @{ MFARegistration = 'Failed' } })
        Set-SecDefaults $true
        $f = Get-Verdict
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'not collected'
    }

    # Microsoft: no CA policy can be turned on while Security Defaults is
    # enabled. With the state unread and no policy On, it may be on (Partial)
    # or off (Gap); scoring the Gap treated "not read" as "disabled".
    It 'Security Defaults not read and no CA policy On is not assessed, never the Gap that assumes it is off' {
        Set-Users -Registered 2
        Set-SecDefaults $null
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @((New-Ca -BuiltIn @('mfa') -State 'enabledForReportingButNotEnforced')) })
        $f = Get-Verdict
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match '^Security Defaults state was not read\.'
        $f.Detail | Should -Not -Match 'Security Defaults: disabled'
        (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
    }

    It 'Security Defaults not read beside a CA policy that is On keeps the CA verdict (Security Defaults cannot be on), and never says "disabled"' {
        Set-Users -Registered 2
        Set-SecDefaults $null
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @((New-Ca -BuiltIn @('compliantDevice') -Operator 'AND')) })
        $f = Get-Verdict
        $f.State  | Should -Be 'Gap' -Because 'no policy requires MFA: not configured, not half credit'
        $f.Detail | Should -Match 'Security Defaults: not read'
        $f.Detail | Should -Not -Match 'Security Defaults: disabled'
    }

    It 'says disabled only when it was read as disabled' {
        Set-Users -Registered 2
        Set-SecDefaults $false
        Set-NRGRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @() })
        (Get-Verdict).Detail | Should -Match 'Security Defaults: disabled'
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

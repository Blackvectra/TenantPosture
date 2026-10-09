#Requires -Version 7.0
#
# TP.CAPolicyTiers.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Pins the three-tier verdict for the "is there a Conditional Access policy
# doing X" controls AAD-10.4, AAD-11.4, AAD-11.7, AAD-11.8 and AAD-11.9:
#   None (no policy, or only disabled ones) -> Gap
#   Audit mode (report-only only)           -> Partial
#   Enabled                                 -> Satisfied
# These used to score Partial — half credit — when NOTHING was configured,
# which raised the compliance score for a control the tenant does not have.
# With Security Defaults enabled no CA policy can be turned on, so each is a
# Gap naming Security Defaults, whatever report-only policy exists.

Describe 'CA policy tiers — None / Audit mode / Enabled' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        function script:Invoke-Case {
            param([string]$Evaluator, [string]$ControlId, [object[]]$Policies)
            Clear-TPState
            Set-TPRawData -Key 'AAD-CAPolicies' -Data ([ordered]@{
                CollectorId = 'AAD'; CollectedAt = '2026-09-24T00:00:00Z'; Success = $true
                Data = @{ Policies = @($Policies); SectionStatus = @{ TokenProtection = 'Collected' } }
            })
            & $Evaluator | Out-Null
            @(Get-TPFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
        }

        # A policy that matches each control, built from the shape the collector stores.
        function script:New-Matching {
            param([string]$ControlId, [string]$State)
            $p = [ordered]@{
                DisplayName = "$ControlId policy"; State = $State
                Conditions = @{ Users = @{ IncludeRoles = @() }; ClientApplications = @{} }
                GrantControls = @{ BuiltInControls = @(); TermsOfUse = @() }
                SessionControls = @{}
            }
            switch ($ControlId) {
                'AAD-10.4' { $p.SessionControls = @{ SignInFrequency = @{ IsEnabled = $true; FrequencyInterval = 'timeBased'; Value = 12; Type = 'hours' } } }
                # Token protection is sessionControls.secureSignInSession (beta),
                # stored as SecureSignInSession by the collector.
                'AAD-11.4' { $p.SessionControls = @{ SecureSignInSession = $true } }
                # Matched on configuration, never on the policy's NAME.
                'AAD-11.7' { $p.Conditions = @{ Users = @{ IncludeRoles = @('62e90394-69f5-4237-9190-012177145e10') }; Devices = @{ FilterMode = 'include'; FilterRule = 'device.extensionAttribute1 -eq "PAW"' }; ClientApplications = @{} } }
                'AAD-11.8' { $p.GrantControls = @{ BuiltInControls = @(); TermsOfUse = @('tou-1') } }
                'AAD-11.9' { $p.Conditions = @{ Users = @{ IncludeRoles = @() }; ClientApplications = @{ IncludeServicePrincipals = @('sp-1') } } }
            }
            [pscustomobject]$p
        }
    }

    $cases = @(
        @{ Cid = 'AAD-10.4'; Fn = 'Test-TPControlAADSignInFrequency' }
        @{ Cid = 'AAD-11.4'; Fn = 'Test-TPControlAADTokenProtection' }
        @{ Cid = 'AAD-11.7'; Fn = 'Test-TPControlAADPrivilegedWorkstation' }
        @{ Cid = 'AAD-11.8'; Fn = 'Test-TPControlAADTermsOfUse' }
        @{ Cid = 'AAD-11.9'; Fn = 'Test-TPControlAADWorkloadIdentityCA' }
    )

    It '<Cid>: no policy is a Gap reading "None" — never half credit' -TestCases $cases {
        $f = Invoke-Case $Fn $Cid @()
        $f.State        | Should -Be 'Gap'
        $f.CurrentValue | Should -Be 'None'
        $f.Detail       | Should -Match '^None:'
    }

    It '<Cid>: a matching policy that is disabled is still a Gap' -TestCases $cases {
        (Invoke-Case $Fn $Cid @(New-Matching $Cid 'disabled')).State | Should -Be 'Gap'
    }

    It '<Cid>: report-only is Partial reading "Audit mode"' -TestCases $cases {
        $f = Invoke-Case $Fn $Cid @(New-Matching $Cid 'enabledForReportingButNotEnforced')
        $f.State        | Should -Be 'Partial'
        $f.CurrentValue | Should -Match '^Audit mode'
        $f.Detail       | Should -Match '^Audit mode:'
    }

    It '<Cid>: an enabled policy is Satisfied reading "Enabled", even beside a report-only one' -TestCases $cases {
        $f = Invoke-Case $Fn $Cid @((New-Matching $Cid 'enabledForReportingButNotEnforced'), (New-Matching $Cid 'enabled'))
        $f.State        | Should -Be 'Satisfied'
        $f.CurrentValue | Should -Match '^Enabled'
    }

    It '<Cid>: carries its framework citations in every tier' -TestCases $cases {
        (@((Invoke-Case $Fn $Cid @()).FrameworkIds) -join ' ') | Should -Match 'NIST:'
    }

    It '<Cid>: missing CA data stays NotApplicable' -TestCases $cases {
        Clear-TPState
        & $Fn | Out-Null
        @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0].State | Should -Be 'NotApplicable'
    }

    # While Security Defaults is enabled a CA policy can be created but not
    # turned on, so a report-only policy is not part-way to enforcement: its
    # next step is blocked. It used to earn Partial and the advice "switch the
    # policy to On", which cannot be done with Security Defaults on.
    It '<Cid>: Security Defaults on is a Gap naming Security Defaults, never "switch the policy to On", even beside a report-only policy' -TestCases $cases {
        $null = Invoke-Case $Fn $Cid @(New-Matching $Cid 'enabledForReportingButNotEnforced')
        Clear-TPFindings
        Set-TPRawData -Key 'AAD-AuthPolicies' -Data ([ordered]@{
            CollectorId = 'AAD'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $true
            Data = @{ SecurityDefaults = @{ IsEnabled = $true } }
        })
        & $Fn | Out-Null
        $f = @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0]
        $f.State       | Should -Be 'Gap'
        $f.Detail      | Should -Match 'Security Defaults is enabled'
        $f.Detail      | Should -Match "$([regex]::Escape($Cid)) policy \[report-only\]"
        $f.Detail      | Should -Not -Match 'switch the policy to On'
        $f.Remediation | Should -Match 'turn off Security Defaults'
        (@($f.FrameworkIds) -join ' ') | Should -Match 'NIST:'
    }
}

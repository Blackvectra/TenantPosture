#Requires -Version 7.0
#
# NRG.CAPolicyTiers.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Pins the three-tier verdict for the "is there a Conditional Access policy
# doing X" controls AAD-10.4, AAD-11.4, AAD-11.7, AAD-11.8 and AAD-11.9:
#   None (no policy, or only disabled ones) -> Gap
#   Audit mode (report-only only)           -> Partial
#   Enabled                                 -> Satisfied
# These used to score Partial — half credit — when NOTHING was configured,
# which raised the compliance score for a control the tenant does not have.

Describe 'CA policy tiers — None / Audit mode / Enabled' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:Invoke-Case {
            param([string]$Evaluator, [string]$ControlId, [object[]]$Policies)
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data ([ordered]@{
                CollectorId = 'AAD'; CollectedAt = '2026-09-24T00:00:00Z'; Success = $true
                Data = @{ Policies = @($Policies) }
            })
            & $Evaluator | Out-Null
            @(Get-NRGFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
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
                'AAD-10.4' { $p.SessionControls = @{ SignInFrequency = @{ IsEnabled = $true } } }
                'AAD-11.4' { $p.SessionControls = @{ TokenProtection = @{ IsEnabled = $true } } }
                'AAD-11.7' { $p.DisplayName = 'Admins - PAW only' }
                'AAD-11.8' { $p.GrantControls = @{ BuiltInControls = @(); TermsOfUse = @('tou-1') } }
                'AAD-11.9' { $p.Conditions = @{ Users = @{ IncludeRoles = @() }; ClientApplications = @{ IncludeServicePrincipals = @('sp-1') } } }
            }
            [pscustomobject]$p
        }
    }

    $cases = @(
        @{ Cid = 'AAD-10.4'; Fn = 'Test-NRGControlAADSignInFrequency' }
        @{ Cid = 'AAD-11.4'; Fn = 'Test-NRGControlAADTokenProtection' }
        @{ Cid = 'AAD-11.7'; Fn = 'Test-NRGControlAADPrivilegedWorkstation' }
        @{ Cid = 'AAD-11.8'; Fn = 'Test-NRGControlAADTermsOfUse' }
        @{ Cid = 'AAD-11.9'; Fn = 'Test-NRGControlAADWorkloadIdentityCA' }
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
        Clear-NRGState
        & $Fn | Out-Null
        @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid })[0].State | Should -Be 'NotApplicable'
    }
}

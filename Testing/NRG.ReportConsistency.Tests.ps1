#Requires -Version 7.0
#
# NRG.ReportConsistency.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Two pairs of controls in one live-tenant report gave different numbers for
# the same fact, and in each pair one number was wrong:
#
#   AAD-1.2 "49.5% registered" vs AAD-12.1 "83 of 268 users (31%)" — the
#   registration report includes guests and disabled accounts, which AAD-12.1
#   counted as "users with no MFA". Both now count enabled members.
#
#   EXO-2.6 "18 of 28 shared mailboxes can sign in" vs EXO-6.2 "12 of 28" —
#   EXO-6.2 joined mailbox SMTP to user UPN, which differ for shared
#   mailboxes, and treated an unmatched mailbox as "sign-in blocked".

Describe 'Controls that report the same fact agree' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        function Verdict([string]$Cid) { Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid } | Select-Object -First 1 }
        function Member([string]$Upn, [bool]$Enabled = $true) { @{ UserPrincipalName = $Upn; DisplayName = $Upn; AccountEnabled = $Enabled; UserType = 'Member' } }
        function Reg([string]$Upn, [bool]$Mfa) { @{ UserPrincipalName = $Upn; UserDisplayName = $Upn; IsEnabled = $true; IsMfaRegistered = $Mfa } }
    }

    Context 'AAD-12.1 counts enabled members, as AAD-1.2 does' {

        It 'excludes guests and disabled accounts from the MFA population' {
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-Users' -Data @{ Success = $true; Data = @{
                Users = @( (Member 'a@contoso.com'), (Member 'b@contoso.com'), (Member 'gone@contoso.com' -Enabled $false) )
                MFARegistration = @{ RegistrationDetails = @(
                    (Reg 'a@contoso.com' $true), (Reg 'b@contoso.com' $false), (Reg 'gone@contoso.com' $false),
                    (Reg 'vendor_x.com#EXT#@contoso.onmicrosoft.com' $false), (Reg 'vendor_y.com#EXT#@contoso.onmicrosoft.com' $false) ) }
                SectionStatus = @{ MFARegistration = 'Collected' } } }
            Test-NRGControlInventoryMFAUsers
            $f = Verdict 'AAD-12.1'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match '1 of 2 enabled member'
            @($f.AffectedObjects).Count | Should -Be 1 -Because 'only the enabled member without MFA — not the guests, not the disabled account'
        }
    }

    Context 'EXO-6.2 joins on UPN and never calls an unmatched mailbox blocked' {

        BeforeEach {
            Clear-NRGState
            Set-NRGRawData -Key 'AAD-Users' -Data @{ Success = $true; Data = @{ Users = @(
                (Member 'sales@contoso.onmicrosoft.com' $true), (Member 'info@contoso.onmicrosoft.com' $false) ) } }
        }

        It 'finds a sign-in-enabled shared mailbox whose UPN differs from its SMTP address' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data @{ Success = $true; Data = @{
                AllSharedMailboxes = @(
                    @{ DisplayName = 'Sales'; PrimarySmtp = 'sales@contoso.com'; UPN = 'sales@contoso.onmicrosoft.com' }
                    @{ DisplayName = 'Info';  PrimarySmtp = 'info@contoso.com';  UPN = 'info@contoso.onmicrosoft.com' } )
                SectionStatus = @{ AllSharedMailboxes = 'Collected'; SharedMailboxes = 'Collected' } } }
            Test-NRGControlInventorySharedMailboxSignIn
            $f = Verdict 'EXO-6.2'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match '^1 of 2'
        }

        It 'reports NotApplicable, not Satisfied, when mailboxes cannot be matched to accounts' {
            Set-NRGRawData -Key 'EXO-Inventory' -Data @{ Success = $true; Data = @{
                AllSharedMailboxes = @( @{ DisplayName = 'Orphan'; PrimarySmtp = 'orphan@contoso.com'; UPN = 'orphan@contoso.com' } )
                SectionStatus = @{ AllSharedMailboxes = 'Collected'; SharedMailboxes = 'Collected' } } }
            Test-NRGControlInventorySharedMailboxSignIn
            (Verdict 'EXO-6.2').State | Should -Be 'NotApplicable'
        }
    }

    Context 'every finding is visible to the framework rollups' {

        # NIST families / matrix, CMMC and the 800-171 SSP only see a finding
        # through prefixed citations ("NIST:IA-2(1)"). Omitted or bare IDs hid
        # AAD-1.2 (a Critical MFA Gap) and ten passing controls on a live tenant.
        It 'fills citations from controls.json when an evaluator passes none' {
            Clear-NRGState
            Add-NRGFinding -ControlId 'INT-1.1' -State 'Satisfied' -Category 'Endpoint' -Title 't' -Severity 'High'
            @((Get-NRGFindings)[0].FrameworkIds | Where-Object { $_ -like 'NIST:*' }).Count | Should -BeGreaterThan 0
        }
        It 'replaces bare, unprefixed IDs with the control''s citations' {
            Clear-NRGState
            Add-NRGFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 't' -Severity 'Critical' -FrameworkIds @('IA-2(1)','IA-2(2)')
            @((Get-NRGFindings)[0].FrameworkIds | Where-Object { $_ -like 'NIST:*' }).Count | Should -BeGreaterThan 0
        }
        It 'keeps prefixed citations an evaluator did pass' {
            Clear-NRGState
            Add-NRGFinding -ControlId 'AAD-1.2' -State 'Gap' -Category 'Identity' -Title 't' -Severity 'Critical' -FrameworkIds @('NIST:IA-2')
            (Get-NRGFindings)[0].FrameworkIds | Should -Be @('NIST:IA-2')
        }
    }
}

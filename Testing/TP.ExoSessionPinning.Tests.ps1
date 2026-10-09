#Requires -Version 7.0
#
# TP.ExoSessionPinning.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Exchange Online and Security & Compliance sessions both export cmdlets such
# as Get-AdminAuditLogConfig. With both connected, an unqualified call runs the
# session loaded LAST (Purview, in this tool). Microsoft documents that in
# Security & Compliance PowerShell UnifiedAuditLogIngestionEnabled "is always
# False, even when auditing is turned on" — so on a live tenant PVW-1.1 read
# "Unified Audit Log disabled" (Critical) on every run that included Purview.
#
# The two sessions are simulated with two real imported modules exporting the
# same cmdlet name; the Exchange-session copy says auditing is ON, the
# Purview copy says OFF (as Microsoft documents), and Purview loads last.

Describe 'Get-TPExoCommand pins a cmdlet to the requested session' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'

        New-Module -Name 'tmpEXO_exo1.abc' -ScriptBlock {
            function Get-AdminAuditLogConfig { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = $true; AdminAuditLogEnabled = $true; AdminAuditLogAgeLimit = '90.00:00:00' } }
            Export-ModuleMember -Function *
        } | Import-Module -Global -Force
        New-Module -Name 'tmpEXO_scc2.def' -ScriptBlock {
            function Get-AdminAuditLogConfig { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = $false; AdminAuditLogEnabled = $true; AdminAuditLogAgeLimit = '90.00:00:00' } }
            Export-ModuleMember -Function *
        } | Import-Module -Global -Force

        function Set-Connections([object[]]$Conns) {
            & $script:Mod { param($c) $script:FakeConns = $c
                Set-Item -Path 'function:script:Get-ConnectionInformation' -Value { @($script:FakeConns) } } $Conns
        }
        $script:ExoConn = [pscustomobject]@{ State = 'Connected'; IsEopSession = $false; ModuleName = 'C:\Users\op\AppData\Local\Temp\tmpEXO_exo1.abc' }
        $script:SccConn = [pscustomobject]@{ State = 'Connected'; IsEopSession = $true;  ModuleName = 'C:\Users\op\AppData\Local\Temp\tmpEXO_scc2.def' }
    }

    AfterAll {
        Remove-Module 'tmpEXO_exo1.abc', 'tmpEXO_scc2.def' -Force -ErrorAction SilentlyContinue
    }

    It 'the premise: an unqualified call resolves to the session loaded last (Purview)' {
        (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled | Should -BeFalse
    }

    It 'returns the Exchange Online copy, labelled ExchangeOnline, when both sessions are connected' {
        Set-Connections @($script:ExoConn, $script:SccConn)
        $r = & $script:Mod { Get-TPExoCommand -Name 'Get-AdminAuditLogConfig' -Session ExchangeOnline }
        $r.Source | Should -Be 'ExchangeOnline'
        (& $r.Command).UnifiedAuditLogIngestionEnabled | Should -BeTrue
    }

    It 'recognizes the Security & Compliance session by name and endpoint when IsEopSession is not returned' {
        # Live tenant, 2026-09-25: the module reported no IsEopSession, the
        # Purview session was read as Exchange Online, and six Purview-only
        # sections were skipped.
        $exoNoFlag = [pscustomobject]@{ State = 'Connected'; Name = 'ExchangeOnline_1'; ConnectionUri = 'https://outlook.office365.com'; ModuleName = $script:ExoConn.ModuleName }
        $sccNoFlag = [pscustomobject]@{ State = 'Connected'; Name = 'ExchangeOnlineProtection_2'; ConnectionUri = 'https://nam12b.ps.compliance.protection.outlook.com'; ModuleName = $script:SccConn.ModuleName }
        Set-Connections @($exoNoFlag, $sccNoFlag)
        $scc = & $script:Mod { Get-TPExoCommand -Name 'Get-AdminAuditLogConfig' -Session SecurityCompliance }
        $scc.Source | Should -Be 'SecurityCompliance'
        (& $scc.Command).UnifiedAuditLogIngestionEnabled | Should -BeFalse
        $exo = & $script:Mod { Get-TPExoCommand -Name 'Get-AdminAuditLogConfig' -Session ExchangeOnline }
        $exo.Source | Should -Be 'ExchangeOnline'
        (& $exo.Command).UnifiedAuditLogIngestionEnabled | Should -BeTrue
    }

    It 'labels the source Unknown when both are connected but the Exchange module cannot be found' {
        Set-Connections @(
            [pscustomobject]@{ State = 'Connected'; IsEopSession = $false; ModuleName = 'C:\Temp\tmpEXO_missing' },
            $script:SccConn)
        $r = & $script:Mod { Get-TPExoCommand -Name 'Get-AdminAuditLogConfig' -Session ExchangeOnline }
        $r.Source | Should -Be 'Unknown'
    }
}

Describe 'PVW-1.1 / PPL-3.5 never report audit OFF from a value that cannot be trusted' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        function Set-Purview([object]$UalOn, [string]$Source, [string]$Status = 'Collected') {
            Clear-TPState
            $data = @{ SectionStatus = @{ AuditConfig = $Status }; DLPPolicies = @(); DLPRules = @(); RetentionPolicies = @(); SensitivityLabels = @(); ProtectionAlerts = @() }
            if ($null -ne $UalOn) {
                $data.AuditConfig = @{ UnifiedAuditLogIngestionEnabled = $UalOn; AdminAuditLogEnabled = $true; AdminAuditLogAgeLimit = '90.00:00:00'; Source = $Source }
                $data.UnifiedAuditEnabled = $UalOn
            }
            Set-TPRawData -Key 'Purview' -Data @{ Success = $true; Data = $data }
            Test-TPControlPurview
            Get-TPFindings | Where-Object { $_.ControlId -eq 'PVW-1.1' } | Select-Object -First 1
        }
    }

    It 'Gap when the Exchange Online session says auditing is off' {
        (Set-Purview $false 'ExchangeOnline').State | Should -Be 'Gap'
    }
    It 'NotApplicable, not Gap, when the off value came from the Security & Compliance session' {
        (Set-Purview $false 'SecurityCompliance').State | Should -Be 'NotApplicable'
    }
    It 'NotApplicable when the source could not be determined' {
        (Set-Purview $false 'Unknown').State | Should -Be 'NotApplicable'
    }
    It 'Satisfied on an on value from any session (Security & Compliance can only ever say off)' {
        (Set-Purview $true 'Unknown').State | Should -Be 'Satisfied'
    }
    It 'NotApplicable, not Gap, when the audit section was not collected' {
        (Set-Purview $null '' 'Failed').State | Should -Be 'NotApplicable'
    }

    It 'PPL-3.5 does not report Copilot auditing off when the value is unknown' {
        Clear-TPState
        Set-TPRawData -Key 'Purview' -Data @{ Success = $true; Data = @{ SectionStatus = @{ AuditConfig = 'Collected' } } }
        Set-TPRawData -Key 'M365Copilot' -Data @{ Success = $true; Data = @{ CopilotLicensedUserCount = 5; AuditCopilotEnabled = $null; CopilotInteractionRetention = $null } }
        Test-TPControlAICopilotInteractionData
        (Get-TPFindings | Where-Object { $_.ControlId -eq 'PPL-3.5' } | Select-Object -First 1).State | Should -Be 'NotApplicable'
    }
}

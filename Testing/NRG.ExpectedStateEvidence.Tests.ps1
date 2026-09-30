#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.ExpectedStateEvidence.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: A baseline control is Satisfied only when EVERY mandatory component of
             its expected state is supported. Where the finding established one
             half (the OAuth switch, the auditing switch, recipients existing, a
             policy existing) and the other half is a shortfall, the control is
             Partial; where the other half could not be read it is not assessed;
             and each verified half stays in the Detail so an unknown does not
             erase useful evidence. Covers EXO-1.1 (switch + bypass), EXO-3.3 and
             the monitoring-address helper shared with DEF-3.4.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Expected state: every mandatory component, each half kept visible' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Raw = { param([string] $Id, $Data) @{ CollectorId = $Id; CollectedAt = (Get-Date).ToString('o'); Success = $true; Data = $Data } }
        $script:Verdict = { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-NRGState }

    Context 'Monitoring addresses' {
        It 'keeps addresses and @domains, lower-cased, and drops anything else' {
            $r = @(Set-NRGMonitoringAddresses -Addresses 'Alerts@Nrg.Example', '@nrg.example', 'not-an-address', 'a b' -WarningAction SilentlyContinue)
            $r | Should -Contain 'alerts@nrg.example'
            $r | Should -Contain '@nrg.example'
            $r | Should -Not -Contain 'not-an-address'
            @(Get-NRGMonitoringAddresses) | Should -Contain 'alerts@nrg.example'
        }
        It 'nothing is configured when nothing valid was given, and nothing is invented' {
            $null = Set-NRGMonitoringAddresses -Addresses 'garbage' -WarningAction SilentlyContinue
            @(Get-NRGMonitoringAddresses).Count | Should -Be 0
        }
        It 'routing matches an exact address or a whole domain, case-insensitively' {
            $p1 = [pscustomobject]@{ Name = 'a'; NotifyUser = @('SOC@NRG.example') }
            $p2 = [pscustomobject]@{ Name = 'b'; NotifyUser = @('x@nrg.example') }
            $p3 = [pscustomobject]@{ Name = 'c'; NotifyUser = @('x@other.example') }
            $p4 = [pscustomobject]@{ Name = 'd'; NotifyUser = @() }
            $r = Get-NRGAlertRouting -Policies @($p1, $p2, $p3, $p4) -Addresses @('soc@nrg.example')
            @($r.Routed | ForEach-Object { $_.Name }) | Should -Be @('a')
            $r2 = Get-NRGAlertRouting -Policies @($p1, $p2, $p3, $p4) -Addresses @('@nrg.example')
            @($r2.Routed | ForEach-Object { $_.Name }) | Should -Be @('a', 'b')
            @($r2.Unrouted | ForEach-Object { $_.Name }) | Should -Be @('c', 'd')
        }
        It 'an empty list is "not configured", never "everything routed"' {
            (Get-NRGAlertRouting -Policies @([pscustomobject]@{ Name = 'a'; NotifyUser = @('x@y.example') }) -Addresses @()).Configured | Should -BeFalse
        }
    }

    Context 'EXO-3.3 forwarding-rule alert: coverage and routing separately' {
        BeforeAll {
            $script:Pvw = { param($Notify) & $script:Raw 'Purview' @{ SectionStatus = @{ ProtectionAlerts = 'Collected' }
                ProtectionAlerts = @([pscustomobject]@{ Name = 'Creation of forwarding/redirect rule'; Category = 'ThreatManagement'; Severity = 'Medium'; Disabled = $false; NotifyUser = @($Notify); ThreatType = ''; Operation = @('New-InboxRule') }) } }
        }
        It 'no monitoring address configured: verified coverage kept, routing not assessed' {
            Set-NRGRawData -Key 'Purview' -Data (& $script:Pvw 'someone@corp.example')
            $v = & $script:Verdict 'Test-NRGControlEXOAlertForwarding' 'EXO-3.3'
            $v.State | Should -Be 'NotApplicable'
            $v.Detail | Should -Match 'Verified: 1 enabled alert policy'
            $v.Detail | Should -Match 'Not assessed: whether they notify the NRG monitoring address'
        }
        It 'notifies the configured address: Satisfied' {
            $null = Set-NRGMonitoringAddresses -Addresses 'soc@nrg.example'
            Set-NRGRawData -Key 'Purview' -Data (& $script:Pvw 'SOC@nrg.example')
            (& $script:Verdict 'Test-NRGControlEXOAlertForwarding' 'EXO-3.3').State | Should -Be 'Satisfied'
        }
        It 'has recipients but none is the configured address: a shortfall, Gap when nothing routes' {
            $null = Set-NRGMonitoringAddresses -Addresses 'soc@nrg.example'
            Set-NRGRawData -Key 'Purview' -Data (& $script:Pvw 'someone@corp.example')
            $v = & $script:Verdict 'Test-NRGControlEXOAlertForwarding' 'EXO-3.3'
            $v.State | Should -Be 'Gap'
            $v.Detail | Should -Match 'Verified:'
            $v.Detail | Should -Match 'Shortfall:'
        }
    }

    Context 'EXO-1.1 mailbox auditing: the switch and the bypass list' {
        BeforeAll {
            $script:Exo = { param([bool] $OrgAuditDisabled = $false) & $script:Raw 'EXO-MailboxConfig' @{ SectionStatus = @{ OrganizationConfig = 'Collected' }
                OrganizationConfig = [pscustomobject]@{ AuditDisabled = $OrgAuditDisabled } } }
            $script:Inv = { param([string] $Status, $Accounts = @()) & $script:Raw 'EXO-Inventory' @{ SectionStatus = @{ AuditBypassAccounts = $Status }; AuditBypassAccounts = @($Accounts) } }
        }
        It 'switch on, bypass list read and empty: Satisfied' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo)
            Set-NRGRawData -Key 'EXO-Inventory' -Data (& $script:Inv 'Collected')
            (& $script:Verdict 'Test-NRGControlEXOMailboxAudit' 'EXO-1.1').State | Should -Be 'Satisfied'
        }
        It 'switch on, an account in the bypass list: Partial, with the verified switch kept' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo)
            Set-NRGRawData -Key 'EXO-Inventory' -Data (& $script:Inv 'Collected' @([pscustomobject]@{ Name = 'svc-import' }))
            $v = & $script:Verdict 'Test-NRGControlEXOMailboxAudit' 'EXO-1.1'
            $v.State  | Should -Be 'Partial'
            $v.Detail | Should -Match 'Verified: the organization-level mailbox auditing switch is on'
            $v.Detail | Should -Match 'Shortfall: 1 account'
        }
        It 'switch on, bypass list not read: not assessed, with the switch still reported as verified' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo)
            Set-NRGRawData -Key 'EXO-Inventory' -Data (& $script:Inv 'Failed')
            $v = & $script:Verdict 'Test-NRGControlEXOMailboxAudit' 'EXO-1.1'
            $v.State  | Should -Be 'NotApplicable'
            $v.Detail | Should -Match 'Verified: the organization-level mailbox auditing switch is on'
            $v.Detail | Should -Match 'Not assessed: whether any mailbox is in the audit bypass list'
        }
        It 'no inventory at all behaves the same: the bypass half is unknown, never assumed clean' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo)
            (& $script:Verdict 'Test-NRGControlEXOMailboxAudit' 'EXO-1.1').State | Should -Be 'NotApplicable'
        }
        It 'switch off is a Gap whatever the bypass list says' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo $true)
            Set-NRGRawData -Key 'EXO-Inventory' -Data (& $script:Inv 'Collected')
            (& $script:Verdict 'Test-NRGControlEXOMailboxAudit' 'EXO-1.1').State | Should -Be 'Gap'
        }
    }

    Context 'INT-2.2 ASR: rule modes read, judged only against an approved list' {
        BeforeAll {
            $script:Settings = @(
                @{ id = '0'; settingInstance = @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'; settingDefinitionId = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules'
                    groupSettingCollectionValue = @(@{ children = @(
                        @{ settingDefinitionId = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealing'; choiceSettingValue = @{ value = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealing_block'; children = @() } }
                        @{ settingDefinitionId = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficemacros'; choiceSettingValue = @{ value = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficemacros_audit'; children = @() } }
                        @{ settingDefinitionId = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwebshells'; choiceSettingValue = @{ value = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwebshells_weird'; children = @() } }
                        @{ settingDefinitionId = 'device_vendor_msft_policy_config_defender_unrelated'; choiceSettingValue = @{ value = 'device_vendor_msft_policy_config_defender_unrelated_block'; children = @() } }
                    ) }) } })
            $script:Es = { param($Status, $Modes) & $script:Raw 'Intune-EndpointSecurity' @{
                SectionStatus = @{ ASRPolicies = 'Collected' }
                ASRPolicies = @([pscustomobject]@{ DisplayName = 'ASR'; IsAssigned = $true; AsrSettingsStatus = $Status; AsrRuleModes = $Modes }) } }
        }
        It 'parses Block, Audit and Off generically, marks an unrecognized mode Unknown, and ignores non-ASR settings' {
            $m = Get-NRGAsrRuleModes -Settings $script:Settings
            $m['blockcredentialstealing'] | Should -Be 'Block'
            $m['blockofficemacros'] | Should -Be 'Audit'
            $m['blockwebshells'] | Should -Be 'Unknown:weird'
            @($m.Keys) | Should -Not -Contain 'unrelated'
        }
        It 'no approved required list: modes are reported, the rule-set half stays not assessed, never Satisfied' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGAsrRequiredRules { @() }
            Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (& $script:Es 'Read' ([ordered]@{ a = 'Block'; b = 'Audit' }))
            $v = & $script:Verdict 'Test-NRGControlIntuneASR' 'INT-2.2'
            $v.State  | Should -Be 'NotApplicable'
            $v.Detail | Should -Match '1 in Audit, 1 in Block'
            $v.Detail | Should -Match 'no required rule list is approved'
        }
        It 'settings that could not be read: not assessed, and never assumed Block' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGAsrRequiredRules { @([pscustomobject]@{ Id = 'a'; Name = 'Rule A' }) }
            Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (& $script:Es 'Failed' $null)
            $v = & $script:Verdict 'Test-NRGControlIntuneASR' 'INT-2.2'
            $v.State  | Should -Be 'NotApplicable'
            $v.Detail | Should -Match 'could not be read'
        }
        It 'approved list, every required rule in Block: Satisfied' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGAsrRequiredRules { @([pscustomobject]@{ Id = 'a'; Name = 'Rule A' }, [pscustomobject]@{ Id = 'b'; Name = 'Rule B' }) }
            Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (& $script:Es 'Read' ([ordered]@{ rule_a = 'Block'; rule_b = 'Block' }))
            (& $script:Verdict 'Test-NRGControlIntuneASR' 'INT-2.2').State | Should -Be 'Satisfied'
        }
        It 'approved list, some required rules not in Block: Partial, naming each rule and its mode' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGAsrRequiredRules { @([pscustomobject]@{ Id = 'a'; Name = 'Rule A' }, [pscustomobject]@{ Id = 'b'; Name = 'Rule B' }, [pscustomobject]@{ Id = 'c'; Name = 'Rule C' }) }
            Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (& $script:Es 'Read' ([ordered]@{ rule_a = 'Block'; rule_b = 'Audit' }))
            $v = & $script:Verdict 'Test-NRGControlIntuneASR' 'INT-2.2'
            $v.State  | Should -Be 'Partial'
            $v.Detail | Should -Match 'Rule B \(Audit\)'
            $v.Detail | Should -Match 'Rule C \(NotConfigured\)'
        }
        It 'approved list, none in Block: Gap' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGAsrRequiredRules { @([pscustomobject]@{ Id = 'a'; Name = 'Rule A' }) }
            Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (& $script:Es 'Read' ([ordered]@{ rule_a = 'Audit' }))
            (& $script:Verdict 'Test-NRGControlIntuneASR' 'INT-2.2').State | Should -Be 'Gap'
        }
        It 'the shipped required-rule list is empty: the tool does not invent NRG''s standard' {
            $j = Get-Content -LiteralPath (Join-Path $script:Root 'Config/asr-required-rules.json') -Raw | ConvertFrom-Json
            @($j.Rules).Count | Should -Be 0
        }
    }
}

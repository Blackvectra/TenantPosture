#Requires -Version 7.0
#
# NRG.PurviewSections.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Six Purview evaluators (PVW-2.2, 2.3, 2.6, 4.2, 4.3, 4.4) read data no
# collector gathered, so they could never produce a verdict — and PVW-4.3
# scored a false Partial ("labels defined but none published") from the
# missing list. The Purview collector now queries each through the Security
# & Compliance session with its own SectionStatus. These tests pin the
# projection of each cmdlet's documented output, that a failed or
# wrong-session query is never read as "none configured", and the evaluators
# that consume them.

Describe 'Purview Security & Compliance sections' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        $script:RealExoCmd = & $script:Mod { ${function:Get-NRGExoCommand} }

        # Each S&C cmdlet is served by a scriptblock; Get-NRGExoCommand is
        # replaced in MODULE scope to hand them out with the session the test
        # chooses. Cmdlets not in the table resolve to nothing (not connected).
        & $script:Mod {
            Set-Item -Path 'function:script:Get-NRGExoCommand' -Value {
                param([string] $Name, [string] $Session = 'ExchangeOnline')
                $sb = $script:T_Cmds[$Name]
                if (-not $sb) { return [pscustomobject]@{ Command = $null; Source = 'Unknown' } }
                [pscustomobject]@{ Command = $sb; Source = $script:T_Source }
            }
        }
        function script:Invoke-Purview([hashtable] $Cmds, [string] $Source = 'SecurityCompliance') {
            & $script:Mod { param($c, $s)
                Clear-NRGState; $script:T_Cmds = $c; $script:T_Source = $s
                # The older sections resolve their cmdlet with Get-Command.
                if ($c.ContainsKey('Get-Label')) { Set-Item -Path 'function:script:Get-Label' -Value $c['Get-Label'] }
                else { Remove-Item -Path 'function:script:Get-Label' -ErrorAction SilentlyContinue }
            } $Cmds $Source
            Invoke-NRGCollectPurview 3>$null | Out-Null
            Get-NRGRawData -Key 'Purview'
        }
        function script:Get-Verdict([string] $Fn, [string] $Cid) {
            & $Fn | Out-Null
            @(Get-NRGFindings | Where-Object ControlId -eq $Cid)[0]
        }
        $script:Full = @{
            'Get-UnifiedAuditLogRetentionPolicy' = { @([pscustomobject]@{ Name = 'All 1y'; RetentionDuration = 'TwelveMonths'; RecordTypes = @() },
                                                      [pscustomobject]@{ Name = 'Odd'; RetentionDuration = 'SomethingNew' }) }
            'Get-AutoSensitivityLabelPolicy'     = { @([pscustomobject]@{ Name = 'PII'; Mode = 'Enable' }) }
            'Get-LabelPolicy'                    = { @([pscustomobject]@{ Name = 'Global'; Labels = @('Confidential') }) }
            'Get-ComplianceTag'                  = { @([pscustomobject]@{ Name = 'Contract'; IsRecordLabel = $true }, [pscustomobject]@{ Name = 'Keep 7y' }) }
            'Get-SupervisoryReviewPolicyV2'      = { @([pscustomobject]@{ Name = 'Offensive language'; Enabled = $true }) }
            'Get-PolicyConfig'                   = { [pscustomobject]@{ InformationBarrierMode = 'SingleSegment' } }
            'Get-Label'                          = { @([pscustomobject]@{ Name = 'Confidential'; DisplayName = 'Confidential'; IsValid = $true }) }
        }
    }

    AfterAll {
        & $script:Mod { param($f)
            Set-Item -Path 'function:script:Get-NRGExoCommand' -Value $f
            Remove-Item -Path 'function:script:Get-Label' -ErrorAction SilentlyContinue
        } $script:RealExoCmd
    }

    It 'projects each documented cmdlet and marks every section Collected' {
        $r = Invoke-Purview $script:Full
        foreach ($s in 'AuditRetentionPolicies','AutoLabelPolicies','LabelPolicies','RetentionLabels','CommCompliancePolicies','InformationBarriersMode') {
            $r.Data.SectionStatus[$s] | Should -Be 'Collected' -Because $s
        }
        @($r.Data.AuditRetentionPolicies)[0].RetentionDays | Should -Be 365
        @($r.Data.AuditRetentionPolicies)[1].RetentionDays | Should -BeNullOrEmpty -Because 'an unknown duration never counts as long-term'
        @($r.Data.RetentionLabels | Where-Object { $_.IsRecordLabel }).Count | Should -Be 1
        $r.Data.InformationBarriersMode | Should -Be 'SingleSegment'
    }

    It 'a throwing query is Failed, never an empty "none configured"' {
        $c = $script:Full.Clone(); $c['Get-LabelPolicy'] = { throw 'Access denied' }
        $r = Invoke-Purview $c
        $r.Data.SectionStatus.LabelPolicies | Should -Be 'Failed'
        (Get-Verdict 'Test-NRGControlPurviewLabelsPublished' 'PVW-4.3').State | Should -Be 'NotApplicable'
    }

    It 'a cmdlet that resolves only in the Exchange session is not run' {
        $r = Invoke-Purview @{ 'Get-SupervisoryReviewPolicyV2' = { @([pscustomobject]@{ Name = 'x' }) } } -Source 'ExchangeOnline'
        $r.Data.SectionStatus.CommCompliancePolicies | Should -Be 'NotRun'
    }

    It 'PVW-4.3: labels plus a publishing policy is Satisfied; labels with none published is Partial' {
        Invoke-Purview $script:Full | Out-Null
        (Get-Verdict 'Test-NRGControlPurviewLabelsPublished' 'PVW-4.3').State | Should -Be 'Satisfied'
        $c = $script:Full.Clone(); $c['Get-LabelPolicy'] = { @() }
        Invoke-Purview $c | Out-Null
        (Get-Verdict 'Test-NRGControlPurviewLabelsPublished' 'PVW-4.3').State | Should -Be 'Partial'
    }

    It 'PVW-4.2 / 2.6 / 4.4 / 2.2 / 2.3 reach a verdict from collected data' {
        Invoke-Purview $script:Full | Out-Null
        (Get-Verdict 'Test-NRGControlPurviewAuditRetention'      'PVW-4.2').State | Should -Be 'Satisfied'
        (Get-Verdict 'Test-NRGControlPurviewAutoLabel'           'PVW-2.6').State | Should -Be 'Satisfied'
        (Get-Verdict 'Test-NRGControlPurviewRecordsManagement'   'PVW-4.4').State | Should -Be 'Satisfied'
        (Get-Verdict 'Test-NRGControlPurviewCommCompliance'      'PVW-2.2').State | Should -Be 'Satisfied'
        (Get-Verdict 'Test-NRGControlPurviewInfoBarriers'        'PVW-2.3').State | Should -Be 'Satisfied'
    }

    It 'when every Security & Compliance query fails, none of them claims anything' {
        $c = @{}; foreach ($k in $script:Full.Keys) { $c[$k] = { throw 'The term is not recognized / access denied' } }
        Invoke-Purview $c | Out-Null
        foreach ($p in @(
            @('Test-NRGControlPurviewLabelsPublished','PVW-4.3'), @('Test-NRGControlPurviewAuditRetention','PVW-4.2'),
            @('Test-NRGControlPurviewAutoLabel','PVW-2.6'), @('Test-NRGControlPurviewRecordsManagement','PVW-4.4'),
            @('Test-NRGControlPurviewCommCompliance','PVW-2.2'), @('Test-NRGControlPurviewInfoBarriers','PVW-2.3'))) {
            (Get-Verdict $p[0] $p[1]).State | Should -Be 'NotApplicable' -Because $p[1]
        }
    }

    Context 'PVW-1.2 scores audit retention and PVW-1.3 scores DLP (they were swapped)' {
        BeforeAll {
            function script:Set-Pvw([hashtable] $Data) {
                Clear-NRGState
                $base = @{ UnifiedAuditEnabled = $true; AuditConfig = @{ Source = 'ExchangeOnline' }; DLPPolicies = @(); AuditRetentionPolicies = @()
                           SectionStatus = @{ AuditConfig = 'Collected'; DLPPolicies = 'Collected'; AuditRetentionPolicies = 'Collected' } }
                foreach ($k in $Data.Keys) { $base[$k] = $Data[$k] }
                Set-NRGRawData -Key 'Purview' -Data ([ordered]@{ CollectorId = 'Purview'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $true; Data = $base })
                Test-NRGControlPurview | Out-Null
            }
            function script:St([string] $Cid) { (@(Get-NRGFindings | Where-Object ControlId -eq $Cid)[0]).State }
        }
        It 'PVW-1.2: audit on with default retention passes; a policy under 90 days is part-way; off is scored once under PVW-1.1' {
            Set-Pvw @{};                                                        St 'PVW-1.2' | Should -Be 'Satisfied'
            Set-Pvw @{ AuditRetentionPolicies = @(@{ Name = 'short'; RetentionDays = 30 }) }; St 'PVW-1.2' | Should -Be 'Partial'
            Set-Pvw @{ UnifiedAuditEnabled = $false };                          St 'PVW-1.2' | Should -Be 'NotApplicable'
            St 'PVW-1.1' | Should -Be 'Gap'
        }
        It 'PVW-1.2 does not pass when audit retention policies were not read' {
            Set-Pvw @{ SectionStatus = @{ AuditConfig = 'Collected'; DLPPolicies = 'Collected'; AuditRetentionPolicies = 'Failed' } }
            St 'PVW-1.2' | Should -Be 'NotApplicable'
        }
        It 'PVW-1.3: an enforced DLP policy passes, test mode is part-way, none is a Gap' {
            Set-Pvw @{ DLPPolicies = @(@{ Name = 'PII'; Enabled = $true; Mode = 'Enable' }) };                   St 'PVW-1.3' | Should -Be 'Satisfied'
            Set-Pvw @{ DLPPolicies = @(@{ Name = 'PII'; Enabled = $false; Mode = 'TestWithNotifications' }) };   St 'PVW-1.3' | Should -Be 'Partial'
            Set-Pvw @{ DLPPolicies = @(@{ Name = 'PII'; Enabled = $false; Mode = 'Disable' }) };                 St 'PVW-1.3' | Should -Be 'Gap'
            Set-Pvw @{};                                                                                           St 'PVW-1.3' | Should -Be 'Gap'
        }
    }
}

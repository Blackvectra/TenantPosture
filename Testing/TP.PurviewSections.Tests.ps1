#Requires -Version 7.0
#
# TP.PurviewSections.Tests.ps1
# TenantPosture
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
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:RealExoCmd = & $script:Mod { ${function:Get-TPExoCommand} }

        # Each S&C cmdlet is served by a scriptblock; Get-TPExoCommand is
        # replaced in MODULE scope to hand them out with the session the test
        # chooses. Cmdlets not in the table resolve to nothing (not connected).
        & $script:Mod {
            Set-Item -Path 'function:script:Get-TPExoCommand' -Value {
                param([string] $Name, [string] $Session = 'ExchangeOnline')
                $sb = $script:T_Cmds[$Name]
                if (-not $sb) { return [pscustomobject]@{ Command = $null; Source = 'Unknown' } }
                [pscustomobject]@{ Command = $sb; Source = $script:T_Source }
            }
        }
        function script:Invoke-Purview([hashtable] $Cmds, [string] $Source = 'SecurityCompliance') {
            & $script:Mod { param($c, $s)
                Clear-TPState; $script:T_Cmds = $c; $script:T_Source = $s
                # The older sections resolve their cmdlet with Get-Command.
                if ($c.ContainsKey('Get-Label')) { Set-Item -Path 'function:script:Get-Label' -Value $c['Get-Label'] }
                else { Remove-Item -Path 'function:script:Get-Label' -ErrorAction SilentlyContinue }
            } $Cmds $Source
            Invoke-TPCollectPurview 3>$null | Out-Null
            Get-TPRawData -Key 'Purview'
        }
        function script:Get-Verdict([string] $Fn, [string] $Cid) {
            & $Fn | Out-Null
            @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0]
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
            Set-Item -Path 'function:script:Get-TPExoCommand' -Value $f
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
        (Get-Verdict 'Test-TPControlPurviewLabelsPublished' 'PVW-4.3').State | Should -Be 'NotApplicable'
    }

    It 'a cmdlet that resolves only in the Exchange session is not run, and says so' {
        # Live tenant, 2026-09-25: six sections were skipped this way and left
        # 'NotRun' with nothing in Exceptions, so six controls read "not
        # collected" with no reason anywhere in the results.
        $r = Invoke-Purview @{ 'Get-SupervisoryReviewPolicyV2' = { @([pscustomobject]@{ Name = 'x' }) } } -Source 'ExchangeOnline'
        $r.Data.SectionStatus.CommCompliancePolicies | Should -Be 'Failed'
        @(Get-TPExceptions | Where-Object { $_.Source -eq 'Purview-CommCompliancePolicies' }).Count | Should -BeGreaterThan 0
    }

    It 'PVW-4.3: labels plus a publishing policy is Satisfied; labels with none published is Partial' {
        Invoke-Purview $script:Full | Out-Null
        (Get-Verdict 'Test-TPControlPurviewLabelsPublished' 'PVW-4.3').State | Should -Be 'Satisfied'
        $c = $script:Full.Clone(); $c['Get-LabelPolicy'] = { @() }
        Invoke-Purview $c | Out-Null
        (Get-Verdict 'Test-TPControlPurviewLabelsPublished' 'PVW-4.3').State | Should -Be 'Partial'
    }

    It 'PVW-4.2 / 2.6 / 4.4 / 2.2 / 2.3 reach a verdict from collected data' {
        Invoke-Purview $script:Full | Out-Null
        (Get-Verdict 'Test-TPControlPurviewAuditRetention'      'PVW-4.2').State | Should -Be 'Satisfied'
        (Get-Verdict 'Test-TPControlPurviewAutoLabel'           'PVW-2.6').State | Should -Be 'Satisfied'
        (Get-Verdict 'Test-TPControlPurviewRecordsManagement'   'PVW-4.4').State | Should -Be 'Satisfied'
        (Get-Verdict 'Test-TPControlPurviewCommCompliance'      'PVW-2.2').State | Should -Be 'Satisfied'
        (Get-Verdict 'Test-TPControlPurviewInfoBarriers'        'PVW-2.3').State | Should -Be 'Satisfied'
    }

    It 'when every Security & Compliance query fails, none of them claims anything' {
        $c = @{}; foreach ($k in $script:Full.Keys) { $c[$k] = { throw 'The term is not recognized / access denied' } }
        Invoke-Purview $c | Out-Null
        foreach ($p in @(
            @('Test-TPControlPurviewLabelsPublished','PVW-4.3'), @('Test-TPControlPurviewAuditRetention','PVW-4.2'),
            @('Test-TPControlPurviewAutoLabel','PVW-2.6'), @('Test-TPControlPurviewRecordsManagement','PVW-4.4'),
            @('Test-TPControlPurviewCommCompliance','PVW-2.2'), @('Test-TPControlPurviewInfoBarriers','PVW-2.3'))) {
            (Get-Verdict $p[0] $p[1]).State | Should -Be 'NotApplicable' -Because $p[1]
        }
    }

    Context 'PVW-1.2 scores audit retention and PVW-1.3 scores DLP (they were swapped)' {
        BeforeAll {
            function script:Set-Pvw([hashtable] $Data) {
                Clear-TPState
                $base = @{ UnifiedAuditEnabled = $true; AuditConfig = @{ Source = 'ExchangeOnline' }; DLPPolicies = @(); AuditRetentionPolicies = @()
                           SectionStatus = @{ AuditConfig = 'Collected'; DLPPolicies = 'Collected'; AuditRetentionPolicies = 'Collected' } }
                foreach ($k in $Data.Keys) { $base[$k] = $Data[$k] }
                Set-TPRawData -Key 'Purview' -Data ([ordered]@{ CollectorId = 'Purview'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $true; Data = $base })
                Test-TPControlPurview | Out-Null
            }
            function script:St([string] $Cid) { (@(Get-TPFindings | Where-Object ControlId -eq $Cid)[0]).State }
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

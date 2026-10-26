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
            'Get-AutoSensitivityLabelPolicy'     = { @([pscustomobject]@{ Name = 'PII'; Mode = 'Enable'; Enabled = $true }) }
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

    It 'a section whose cmdlet is not in the session records WHY, and the finding that depends on it says so' {
        # The 2026-10-14 live run: Get-AutoSensitivityLabelPolicy was not available to the signed-in
        # account (a missing Purview role). PVW-2.6 read "AutoLabelPolicies was not collected; not
        # assessed." and the reason sat only in the Exceptions array, so the ticket could not say what to do.
        $cmds = @{}; foreach ($k in $script:Full.Keys) { if ($k -ne 'Get-AutoSensitivityLabelPolicy') { $cmds[$k] = $script:Full[$k] } }
        $r = Invoke-Purview $cmds
        $r.Data.SectionStatus['AutoLabelPolicies'] | Should -Be 'Failed'
        $r.Data.SectionErrors['AutoLabelPolicies'] | Should -Match 'Get-AutoSensitivityLabelPolicy is not available'
        $r.Data.SectionErrors['AutoLabelPolicies'] | Should -Match 'role'
        $f = Get-Verdict 'Test-TPControlPurviewAutoLabel' 'PVW-2.6'
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match '^AutoLabelPolicies was not collected; not assessed\.' -Because 'the sentence every consumer keys on stays the prefix'
        $f.Detail | Should -Match 'Reason recorded by the collector: Get-AutoSensitivityLabelPolicy is not available'
        @($f.FrameworkIds).Count | Should -BeGreaterThan 0 -Because 'an uncited not-assessed finding vanishes from the NIST rollup'
    }
    It 'a cmdlet that throws records its message as the reason' {
        $cmds = @{}; foreach ($k in $script:Full.Keys) { $cmds[$k] = $script:Full[$k] }
        $cmds['Get-ComplianceTag'] = { throw 'The request was throttled. Try again later.' }
        $r = Invoke-Purview $cmds
        $r.Data.SectionStatus['RetentionLabels'] | Should -Be 'Failed'
        $r.Data.SectionErrors['RetentionLabels'] | Should -Match 'throttled'
        (Get-Verdict 'Test-TPControlPurviewRecordsManagement' 'PVW-4.4').Detail | Should -Match 'Reason recorded by the collector: The request was throttled'
    }
    It 'a results file from before SectionErrors keeps the plain sentence, and a reason never changes the state' {
        & $script:Mod { Clear-TPState }
        Set-TPRawData -Key 'Purview' -Data ([ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-01T00:00:00Z'; Success = $true
            Data = @{ AutoLabelPolicies = @(); SectionStatus = @{ AutoLabelPolicies = 'Failed' } } })
        $f = Get-Verdict 'Test-TPControlPurviewAutoLabel' 'PVW-2.6'
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Be 'AutoLabelPolicies was not collected; not assessed.'
    }
    It 'the helper falls back to the registered exception on a live run and caps a long reason' {
        & $script:Mod { Clear-TPState; Register-TPException -Source 'Purview-AutoLabelPolicies' -Message ('x' * 700) }
        $d = & $script:Mod { Get-TPSectionNotCollectedDetail -Raw ([ordered]@{ Success = $true; Data = @{} }) -Section 'AutoLabelPolicies' -CollectorSource 'Purview-AutoLabelPolicies' }
        $d | Should -Match '^AutoLabelPolicies was not collected; not assessed\. Reason recorded by the collector: x{600}\.\.\.$'
        & $script:Mod { Clear-TPState }
        (& $script:Mod { Get-TPSectionNotCollectedDetail -Raw $null -Section 'AutoLabelPolicies' }) | Should -Be 'AutoLabelPolicies was not collected; not assessed.'
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
            Set-Pvw @{ DLPPolicies = @(@{ Name = 'PII'; Enabled = $true; Mode = 'Enable'; Workloads = @('Exchange') }) }; St 'PVW-1.3' | Should -Be 'Satisfied'
            Set-Pvw @{ DLPPolicies = @(@{ Name = 'PII'; Enabled = $false; Mode = 'TestWithNotifications' }) };   St 'PVW-1.3' | Should -Be 'Partial'
            Set-Pvw @{ DLPPolicies = @(@{ Name = 'PII'; Enabled = $false; Mode = 'Disable' }) };                 St 'PVW-1.3' | Should -Be 'Gap'
            Set-Pvw @{};                                                                                           St 'PVW-1.3' | Should -Be 'Gap'
        }
    }
}

# Four Purview and Copilot controls passed on something that does not enforce:
#   PVW-2.5 judged Get-RetentionCompliancePolicy's Workload, which Microsoft documents "shows all
#           workloads ... It doesn't show the actual workload on which the policy is applied", and
#           counted disabled policies, so any tenant with one retention policy passed.
#   PVW-2.6 and PPL-3.1 judged an auto-labeling policy's Mode only; Enabled is a separate switch
#           (Set-AutoSensitivityLabelPolicy -Enabled), so a policy turned off counted.
#   PPL-3.2 counted disabled, test-mode and name-only "Copilot" DLP policies with no rule read.
# These tests drive the real collectors with the raw cmdlet shapes and the real evaluators.

Describe 'Purview and Copilot controls judge what enforces' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:RealExoCmd = & $script:Mod { ${function:Get-TPExoCommand} }

        # The Security & Compliance sections resolve their cmdlet through Get-TPExoCommand; the
        # older sections (retention, DLP) through Get-Command, so those stand-ins are defined in
        # module scope. Every stand-in is an advanced function so -ErrorAction binds as it does
        # on the real cmdlet.
        & $script:Mod {
            Set-Item -Path 'function:script:Get-TPExoCommand' -Value {
                param([string] $Name, [string] $Session = 'ExchangeOnline')
                $sb = $script:T_Sc[$Name]
                if (-not $sb) { return [pscustomobject]@{ Command = $null; Source = 'Unknown' } }
                [pscustomobject]@{ Command = $sb; Source = 'SecurityCompliance' }
            }
        }
        function script:Invoke-Purview {
            param([object[]] $Retention = @(), [object[]] $AutoLabel = @(), [object[]] $Dlp = @(), [object[]] $DlpRules = @(), [switch] $NoDistributionDetail)
            & $script:Mod { param($ret, $auto, $dlp, $rules, $noDetail)
                Clear-TPState
                $script:T_Ret = $ret; $script:T_Dlp = $dlp; $script:T_Rules = $rules; $script:T_Auto = $auto
                $script:T_RetCalls = [System.Collections.Generic.List[object]]::new()
                $script:T_Sc = @{ 'Get-AutoSensitivityLabelPolicy' = { [CmdletBinding()] param() $script:T_Auto } }
                if ($noDetail) {
                    Set-Item -Path 'function:script:Get-RetentionCompliancePolicy' -Value { [CmdletBinding()] param() $script:T_RetCalls.Add($PSBoundParameters); $script:T_Ret }
                } else {
                    Set-Item -Path 'function:script:Get-RetentionCompliancePolicy' -Value { [CmdletBinding()] param([switch] $DistributionDetail) $script:T_RetCalls.Add([bool]$DistributionDetail); $script:T_Ret }
                }
                Set-Item -Path 'function:script:Get-DlpCompliancePolicy' -Value { [CmdletBinding()] param() $script:T_Dlp }
                Set-Item -Path 'function:script:Get-DlpComplianceRule'   -Value { [CmdletBinding()] param() $script:T_Rules }
            } $Retention $AutoLabel $Dlp $DlpRules ([bool]$NoDistributionDetail)
            Invoke-TPCollectPurview 3>$null | Out-Null
            Get-TPRawData -Key 'Purview'
        }
        function script:Get-Verdict([string] $Fn, [string] $Cid) {
            & $script:Mod { param($c) $script:TPFindings.RemoveAll({ param($f) $f.ControlId -eq $c }) | Out-Null } $Cid
            & $Fn | Out-Null
            @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0]
        }
        # Get-RetentionCompliancePolicy -DistributionDetail row. Location values are
        # MultiValuedProperty entries whose Name is the location ("All" for every one).
        function script:RetPolicy([string] $Name, $Enabled = $true, [string[]] $Exchange = @(), [string[]] $SharePoint = @(), [string[]] $OneDrive = @(), [string[]] $TeamsChannel = @(), [string[]] $TeamsChat = @(), [string[]] $Adaptive = @()) {
            $loc = { param($l) @($l | ForEach-Object { [pscustomobject]@{ Name = $_; DisplayName = $_ } }) }
            [pscustomobject]@{
                Name = $Name; Enabled = $Enabled; Mode = 'Enforce'
                Workload = 'Exchange, SharePoint, OneDriveForBusiness, Skype, ModernGroup'
                ExchangeLocation = (& $loc $Exchange); SharePointLocation = (& $loc $SharePoint); OneDriveLocation = (& $loc $OneDrive)
                TeamsChannelLocation = (& $loc $TeamsChannel); TeamsChatLocation = (& $loc $TeamsChat); AdaptiveScopeLocation = (& $loc $Adaptive)
            }
        }
    }

    AfterAll {
        & $script:Mod { param($f)
            Set-Item -Path 'function:script:Get-TPExoCommand' -Value $f
            foreach ($n in 'Get-RetentionCompliancePolicy', 'Get-DlpCompliancePolicy', 'Get-DlpComplianceRule', 'Get-AutoSensitivityLabelPolicy') { Remove-Item -Path "function:$n" -ErrorAction SilentlyContinue }
            Remove-Item -Path 'function:Invoke-TPGraphRequest' -ErrorAction SilentlyContinue
            Clear-TPState
        } $script:RealExoCmd
        Remove-Module TenantPosture -Force -ErrorAction SilentlyContinue
    }

    Context 'PVW-2.5 retention: locations of enabled policies, never Workload' {
        It 'reads with -DistributionDetail and keeps every location' {
            $r = Invoke-Purview -Retention @(RetPolicy 'Mail' -Exchange 'All' -TeamsChannel 'All')
            (& $script:Mod { $script:T_RetCalls[0] }) | Should -BeTrue -Because 'Microsoft: -DistributionDetail returns accurate *Location values'
            $p = @($r.Data.RetentionPolicies)[0]
            $p.LocationsRead | Should -BeTrue
            $p.Enabled | Should -BeTrue
            @($p.Locations.Exchange) | Should -Be @('All')
            @($p.Locations.SharePoint).Count | Should -Be 0
            @($p.Locations.TeamsChannel) | Should -Be @('All')
        }
        It 'one policy scoped to Exchange is Partial even though its Workload names every workload (was: Satisfied)' {
            Invoke-Purview -Retention @(RetPolicy 'Mail only' -Exchange 'All') | Out-Null
            $f = Get-Verdict 'Test-TPControlPurviewRetention' 'PVW-2.5'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Shortfall: SharePoint sites: no enabled retention policy'
            $f.Detail | Should -Match 'OneDrive accounts: no enabled retention policy'
            $f.Detail | Should -Match 'Teams channel messages or chats: no enabled retention policy'
        }
        It 'a disabled policy covering everything retains nothing: Gap, named (was: Satisfied)' {
            Invoke-Purview -Retention @(RetPolicy 'Everything' -Enabled $false -Exchange 'All' -SharePoint 'All' -OneDrive 'All' -TeamsChannel 'All') | Out-Null
            $f = Get-Verdict 'Test-TPControlPurviewRetention' 'PVW-2.5'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'Disabled policies retain nothing and were not counted: Everything'
        }
        It 'enabled policies covering all four locations are Satisfied (Teams through chats or channel messages)' {
            Invoke-Purview -Retention @((RetPolicy 'Mail' -Exchange 'All'), (RetPolicy 'Files' -SharePoint 'All' -OneDrive 'All'), (RetPolicy 'Teams' -TeamsChat 'All')) | Out-Null
            $f = Get-Verdict 'Test-TPControlPurviewRetention' 'PVW-2.5'
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'Exchange mailboxes: covered by Mail'
        }
        It 'an enabled adaptive-scope policy leaves an uncovered location not assessed, never missing' {
            Invoke-Purview -Retention @((RetPolicy 'Mail' -Exchange 'All' -SharePoint 'All' -OneDrive 'All'), (RetPolicy 'Adaptive' -Adaptive 'Finance users')) | Out-Null
            $f = Get-Verdict 'Test-TPControlPurviewRetention' 'PVW-2.5'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Not assessed: Teams channel messages or chats: .*adaptive-scope policies \(Adaptive\)'
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0
        }
        It 'locations read without -DistributionDetail are not assessed' {
            $r = Invoke-Purview -Retention @(RetPolicy 'Mail' -Exchange 'All') -NoDistributionDetail
            @($r.Data.RetentionPolicies)[0].LocationsRead | Should -BeFalse
            (Get-Verdict 'Test-TPControlPurviewRetention' 'PVW-2.5').State | Should -Be 'NotApplicable'
        }
        It 'a results file from before the location read is not assessed; no policies at all is still a Gap' {
            & $script:Mod { Clear-TPState }
            Set-TPRawData -Key 'Purview' -Data ([ordered]@{ Success = $true; Data = @{ SectionStatus = @{ RetentionPolicies = 'Collected' }
                RetentionPolicies = @(@{ Name = 'Old'; Enabled = $true; Workloads = @('Exchange', 'SharePoint', 'OneDriveForBusiness', 'Teams') }) } })
            $f = Get-Verdict 'Test-TPControlPurviewRetention' 'PVW-2.5'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Workload property lists every workload'
            Invoke-Purview -Retention @() | Out-Null
            (Get-Verdict 'Test-TPControlPurviewRetention' 'PVW-2.5').State | Should -Be 'Gap'
        }
        It 'a failed retention read is not assessed' {
            & $script:Mod { Clear-TPState }
            Set-TPRawData -Key 'Purview' -Data ([ordered]@{ Success = $true; Data = @{ SectionStatus = @{ RetentionPolicies = 'Failed' }; RetentionPolicies = @() } })
            (Get-Verdict 'Test-TPControlPurviewRetention' 'PVW-2.5').State | Should -Be 'NotApplicable'
        }
    }

    Context 'PVW-2.6 auto-labeling: Enabled AND Mode Enable' {
        It 'stores Enabled beside Mode, and $null when the property is not returned' {
            $r = Invoke-Purview -AutoLabel @([pscustomobject]@{ Name = 'PII'; Mode = 'Enable'; Enabled = $false }, [pscustomobject]@{ Name = 'Old'; Mode = 'Enable' })
            $rows = @($r.Data.AutoLabelPolicies)
            $rows[0].Enabled | Should -BeFalse
            $rows[1].Enabled | Should -BeNullOrEmpty
        }
        It 'Mode Enable with Enabled False is turned off: Gap, named (was: Satisfied)' {
            Invoke-Purview -AutoLabel @([pscustomobject]@{ Name = 'PII'; Mode = 'Enable'; Enabled = $false }) | Out-Null
            $f = Get-Verdict 'Test-TPControlPurviewAutoLabel' 'PVW-2.6'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'Turned off .*PII'
        }
        It 'Mode Enable with Enabled True is Satisfied' {
            Invoke-Purview -AutoLabel @([pscustomobject]@{ Name = 'PII'; Mode = 'Enable'; Enabled = $true }) | Out-Null
            (Get-Verdict 'Test-TPControlPurviewAutoLabel' 'PVW-2.6').State | Should -Be 'Satisfied'
        }
        It 'simulation with Enabled True is Partial; simulation turned off is a Gap' {
            Invoke-Purview -AutoLabel @([pscustomobject]@{ Name = 'Sim'; Mode = 'TestWithoutNotifications'; Enabled = $true }) | Out-Null
            (Get-Verdict 'Test-TPControlPurviewAutoLabel' 'PVW-2.6').State | Should -Be 'Partial'
            Invoke-Purview -AutoLabel @([pscustomobject]@{ Name = 'Sim'; Mode = 'TestWithoutNotifications'; Enabled = $false }) | Out-Null
            (Get-Verdict 'Test-TPControlPurviewAutoLabel' 'PVW-2.6').State | Should -Be 'Gap'
        }
        It 'Enabled not returned (an older results file) is not assessed, never a pass' {
            & $script:Mod { Clear-TPState }
            Set-TPRawData -Key 'Purview' -Data ([ordered]@{ Success = $true; Data = @{ SectionStatus = @{ AutoLabelPolicies = 'Collected' }; AutoLabelPolicies = @(@{ Name = 'PII'; Mode = 'Enable' }) } })
            $f = Get-Verdict 'Test-TPControlPurviewAutoLabel' 'PVW-2.6'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Enabled flag .* was not returned'
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0
        }
    }

    Context 'PPL-3.1 Copilot auto-labeling requires Enabled' {
        BeforeAll {
            function script:Invoke-Copilot([object[]] $AutoLabel, [switch] $NoAutoCmd) {
                & $script:Mod { param($auto, $noCmd)
                    Clear-TPState
                    Set-TPRawData -Key 'Purview' -Data ([ordered]@{ Success = $true; Data = @{ SectionStatus = @{ SensitivityLabels = 'Collected' }; SensitivityLabels = @(@{ Name = 'Confidential' }) } })
                    Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value {
                        [CmdletBinding()] param([string] $Method, [string] $Uri, $Body, $Headers)
                        if ($Uri -match 'subscribedSkus') { return [pscustomobject]@{ value = @([pscustomobject]@{ skuId = 's1'; skuPartNumber = 'Microsoft_365_Copilot'; consumedUnits = 5; prepaidUnits = [pscustomobject]@{ enabled = 10 }; servicePlans = @() }) } }
                        [pscustomobject]@{ value = @() }
                    }
                    $script:T_Auto = $auto
                    if ($noCmd) { Remove-Item -Path 'function:Get-AutoSensitivityLabelPolicy' -ErrorAction SilentlyContinue }
                    else { Set-Item -Path 'function:script:Get-AutoSensitivityLabelPolicy' -Value { [CmdletBinding()] param() $script:T_Auto } }
                } $AutoLabel ([bool]$NoAutoCmd)
                Invoke-TPCollectM365Copilot 3>$null | Out-Null
                Get-Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1'
            }
        }
        It 'a Mode Enable policy turned off is not enforcement: Partial (was: Satisfied)' {
            $f = Invoke-Copilot -AutoLabel @([pscustomobject]@{ Name = 'PII'; Mode = 'Enable'; Enabled = $false })
            (Get-TPRawData -Key 'M365Copilot').Data.AutoLabelPoliciesRead | Should -BeTrue
            $f.State | Should -Be 'Partial'
        }
        It 'Mode Enable with Enabled True is Satisfied' {
            (Invoke-Copilot -AutoLabel @([pscustomobject]@{ Name = 'PII'; Mode = 'Enable'; Enabled = $true })).State | Should -Be 'Satisfied'
        }
        It 'auto-labeling not read is not assessed (was: Partial "no auto-labeling policy")' {
            $f = Invoke-Copilot -AutoLabel @() -NoAutoCmd
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'auto-labeling policies were not read'
        }
        It 'a results file from before the Enabled read cannot pass on Mode alone' {
            & $script:Mod { Clear-TPState }
            Set-TPRawData -Key 'Purview' -Data ([ordered]@{ Success = $true; Data = @{ SectionStatus = @{ SensitivityLabels = 'Collected' }; SensitivityLabels = @(@{ Name = 'C' }) } })
            Set-TPRawData -Key 'M365Copilot' -Data ([ordered]@{ Success = $true; Data = @{ CopilotLicensedUserCount = 5; SensitivityLabelsEnabled = $true; SensitivityLabelCount = 1; AutoLabelPoliciesEnabled = $true } })
            (Get-Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').State | Should -Be 'NotApplicable'
            Set-TPRawData -Key 'M365Copilot' -Data ([ordered]@{ Success = $true; Data = @{ CopilotLicensedUserCount = 5; SensitivityLabelsEnabled = $true; SensitivityLabelCount = 1; AutoLabelPoliciesEnabled = $false } })
            (Get-Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').State | Should -Be 'Partial' -Because 'no Mode-Enable policy at all stays a finding whatever Enabled says'
        }
    }

    Context 'PPL-3.2 Copilot DLP: an enforcing Copilot-location policy with an enabled rule' {
        BeforeAll {
            function script:DlpPolicy([string] $Name, [string] $Mode = 'Enable', $Planes = @('CopilotExperiences'), [switch] $NoPlanes) {
                $o = [ordered]@{ Name = $Name; Mode = $Mode; Workload = 'Applications' }
                if (-not $NoPlanes) { $o.EnforcementPlanes = $Planes }
                [pscustomobject]$o
            }
            function script:DlpRule([string] $Name, [string] $Policy, [bool] $Disabled = $false) {
                [pscustomobject]@{ Name = $Name; ParentPolicy = $Policy; ParentPolicyName = $Policy; Disabled = $Disabled; ContentContainsSensitiveInformation = @(); BlockAccess = $false }
            }
            function script:Ppl32([object[]] $Dlp, [object[]] $Rules) {
                Invoke-Purview -Dlp $Dlp -DlpRules $Rules | Out-Null
                Set-TPRawData -Key 'M365Copilot' -Data ([ordered]@{ Success = $true; Data = @{ CopilotLicensedUserCount = 5 } })
                Get-Verdict 'Test-TPControlAICopilotDLP' 'PPL-3.2'
            }
        }
        It 'stores EnforcementPlanes and whether they were returned' {
            $r = Invoke-Purview -Dlp @((DlpPolicy 'Copilot'), (DlpPolicy 'Mail' -NoPlanes))
            $p = @($r.Data.DLPPolicies)
            $p[0].PlanesRead | Should -BeTrue
            @($p[0].EnforcementPlanes) | Should -Be @('CopilotExperiences')
            $p[1].PlanesRead | Should -BeFalse
        }
        It 'an enforcing Copilot policy with an enabled rule is Satisfied' {
            (Ppl32 @(DlpPolicy 'Copilot SIT') @(DlpRule 'r1' 'Copilot SIT')).State | Should -Be 'Satisfied'
        }
        It 'a Copilot policy turned off is a Gap (was: Satisfied)' {
            (Ppl32 @(DlpPolicy 'Copilot SIT' -Mode 'Disable') @(DlpRule 'r1' 'Copilot SIT')).State | Should -Be 'Gap'
        }
        It 'a Copilot policy in simulation is Partial' {
            (Ppl32 @(DlpPolicy 'Copilot SIT' -Mode 'TestWithNotifications') @(DlpRule 'r1' 'Copilot SIT')).State | Should -Be 'Partial'
        }
        It 'an enforcing Copilot policy whose every rule is disabled is a Gap' {
            (Ppl32 @(DlpPolicy 'Copilot SIT') @(DlpRule 'r1' 'Copilot SIT' -Disabled $true)).State | Should -Be 'Gap'
        }
        It 'a policy NAMED Copilot whose planes say otherwise is not a Copilot policy: Gap (was: Partial)' {
            (Ppl32 @(DlpPolicy 'Copilot mail' -Planes @('Entra')) @(DlpRule 'r1' 'Copilot mail')).State | Should -Be 'Gap'
        }
        It 'an Applications or Copilot-named policy whose planes were not returned is not assessed (was: Satisfied)' {
            $f = Ppl32 @(DlpPolicy 'Copilot SIT' -NoPlanes) @(DlpRule 'r1' 'Copilot SIT')
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'EnforcementPlanes were not returned'
        }
        It 'no Copilot policy at all is a Gap; DLP not read is not assessed' {
            (Ppl32 @() @()).State | Should -Be 'Gap'
            & $script:Mod { Clear-TPState }
            Set-TPRawData -Key 'Purview' -Data ([ordered]@{ Success = $true; Data = @{ SectionStatus = @{ DLPPolicies = 'Failed' }; DLPPolicies = @() } })
            Set-TPRawData -Key 'M365Copilot' -Data ([ordered]@{ Success = $true; Data = @{ CopilotLicensedUserCount = 5 } })
            (Get-Verdict 'Test-TPControlAICopilotDLP' 'PPL-3.2').State | Should -Be 'NotApplicable'
        }
        It 'rules not read leaves a Copilot policy not assessed' {
            & $script:Mod { Clear-TPState }
            Set-TPRawData -Key 'Purview' -Data ([ordered]@{ Success = $true; Data = @{ SectionStatus = @{ DLPPolicies = 'Collected'; DLPRules = 'Failed' }
                DLPPolicies = @(@{ Name = 'Copilot SIT'; Mode = 'Enable'; Workloads = @('Applications'); PlanesRead = $true; EnforcementPlanes = @('CopilotExperiences') }); DLPRules = @() } })
            Set-TPRawData -Key 'M365Copilot' -Data ([ordered]@{ Success = $true; Data = @{ CopilotLicensedUserCount = 5 } })
            (Get-Verdict 'Test-TPControlAICopilotDLP' 'PPL-3.2').State | Should -Be 'NotApplicable'
        }
    }
}

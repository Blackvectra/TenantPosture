#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
#
# NRG.CollectorShapeRegressions.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Regression pins for a live-tenant run (2026-09-24, NRGTS tenant) that hit the
# exact "Microsoft APIs OMIT optional properties" StrictMode landmine
# NRG.ExternalShapes.Tests.ps1 exists to prevent, in three collectors the
# static guard doesn't reach because the reads are single-level (bare
# `$_.Key`), not the nested `$_.a.b` pattern that guard scans for:
#
#   - Invoke-NRGCollectDefender: Get-SafeAttachmentPolicy /
#     Get-SafeLinksPolicy rows omitting IsDefault/OperationMode threw and
#     landed DEF-1.1/DEF-1.2/DEF-4.7 in State='Error' on a live tenant.
#   - Invoke-NRGCollectEXOMailboxConfig: Get-DkimSigningConfig rows omitting
#     Selector1 threw the same way.
#   - Invoke-NRGCollectM365Copilot: Measure-Object -Property on
#     [ordered]@{} rows threw "Cannot process argument ... ConsumedUnits" —
#     a different bug (Measure-Object -Property reads the ETS/Get-Member
#     adapter, which does not expose Hashtable keys), same live symptom
#     class (a Critical/High collector section dying instead of degrading).
#
# Fixtures below carry the OMISSION shape — a policy/config object that
# simply does not have the field — never a $null-valued field, per the
# ExternalShapes suite's own rule: a fixture that sets the property to
# $null passes against the broken code.

Describe 'Collector shape regressions — live-tenant-confirmed omissions' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        # ExchangeOnlineManagement isn't installed in this test environment, so
        # Pester's Mock -ModuleName has nothing to shim over — Get-Command must
        # resolve the name before a mock can be attached. Stub them out first;
        # each Mock below then replaces the stub for the duration of its test.
        $script:CreatedStubs = @()
        foreach ($cmd in @(
            'Get-SafeAttachmentPolicy', 'Get-SafeAttachmentRule',
            'Get-SafeLinksPolicy', 'Get-SafeLinksRule',
            'Get-AntiPhishPolicy', 'Get-AntiPhishRule',
            'Get-MalwareFilterPolicy', 'Get-DkimSigningConfig'
        )) {
            if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
                Set-Item -Path "function:global:$cmd" -Value { @() }
                $script:CreatedStubs += $cmd
            }
        }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }

    # The stubs are GLOBAL; left behind they make later suites see Exchange
    # cmdlets that "succeed" with nothing (it made SectionHonesty fail when
    # run after this file).
    AfterAll {
        foreach ($cmd in $script:CreatedStubs) { Remove-Item -Path "function:global:$cmd" -ErrorAction SilentlyContinue }
    }

    Context 'Invoke-NRGCollectDefender — Safe Attachments / Safe Links rows omitting fields' {

        BeforeEach {
            # A row shaped like the live tenant's Get-SafeAttachmentPolicy /
            # Get-SafeLinksPolicy return: no IsDefault, no OperationMode.
            # Omitted, not $null — see file header.
            Mock -CommandName Get-SafeAttachmentPolicy -ModuleName NRG-Assessment -MockWith {
                @([pscustomobject]@{ Name = 'Default'; Enable = $true; Action = 'Block' })
            }
            Mock -CommandName Get-SafeAttachmentRule -ModuleName NRG-Assessment -MockWith { @() }
            # Full realistic shape for every OTHER field the collector reads —
            # only IsDefault is omitted, matching what was actually observed
            # (Get-SafeLinksPolicy's return was otherwise intact). A fixture
            # that omits fields nothing has ever shown missing would just be
            # testing the fixture, not the bug.
            Mock -CommandName Get-SafeLinksPolicy -ModuleName NRG-Assessment -MockWith {
                @([pscustomobject]@{
                    Name = 'Default'; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $true
                    EnableSafeLinksForOffice = $true; ScanUrls = $true; EnableForInternalSenders = $true
                    AllowClickThrough = $false; TrackClicks = $true; DisableUrlRewrite = $false
                    DeliverMessageAfterScan = $true
                })
            }
            Mock -CommandName Get-SafeLinksRule -ModuleName NRG-Assessment -MockWith { @() }
            Mock -CommandName Get-AntiPhishPolicy -ModuleName NRG-Assessment -MockWith {
                @([pscustomobject]@{
                    Name = 'Default'; Enabled = $true; EnableMailboxIntelligence = $true
                    EnableMailboxIntelligenceProtection = $true; EnableOrganizationDomainsProtection = $true
                    EnableTargetedUserProtection = $true; EnableSimilarUsersSafetyTips = $true
                    EnableSimilarDomainsSafetyTips = $true; EnableUnusualCharactersSafetyTips = $true
                    EnableSpoofIntelligence = $true; EnableFirstContactSafetyTips = $true
                    EnableUnauthenticatedSender = $true; EnableViaTag = $true; HonorDmarcPolicy = $true
                    PhishThresholdLevel = 3; TargetedUserProtectionAction = 'Quarantine'
                    TargetedDomainProtectionAction = 'Quarantine'; MailboxIntelligenceProtectionAction = 'Quarantine'
                    SpoofQuarantineTag = 'AdminOnlyAccessPolicy'; TargetedUsersToProtect = @(); TargetedDomainsToProtect = @()
                })
            }
            Mock -CommandName Get-AntiPhishRule -ModuleName NRG-Assessment -MockWith { @() }
            Mock -CommandName Get-MalwareFilterPolicy -ModuleName NRG-Assessment -MockWith {
                @([pscustomobject]@{
                    Name = 'Default'; EnableFileFilter = $true; FileTypes = @('exe')
                    EnableInternalSenderAdminNotifications = $false
                })
            }
        }

        It 'does not throw and reports SafeAttachments Available when IsDefault/OperationMode are omitted' {
            $result = Invoke-NRGCollectDefender
            $result.Data['SafeAttachments'].Available | Should -Be $true
            $result.Data['SafeAttachments'].Policies[0].IsDefault     | Should -Be $false
            $result.Data['SafeAttachments'].Policies[0].OperationMode | Should -Be 'Delay'
            $result.Data['SafeAttachments'].EnabledNonDefaultCount    | Should -Be 1
        }

        It 'does not throw and reports SafeLinks Available when IsDefault is omitted' {
            $result = Invoke-NRGCollectDefender
            $result.Data['SafeLinks'].Available | Should -Be $true
            $result.Data['SafeLinks'].Policies[0].IsDefault        | Should -Be $false
            $result.Data['SafeLinks'].EnabledNonDefaultCount       | Should -Be 1
        }

        It 'does not throw and reports AntiPhishing/MalwareFilter Available when IsDefault is omitted' {
            $result = Invoke-NRGCollectDefender
            $result.Data['AntiPhishing'].Available  | Should -Be $true
            $result.Data['AntiPhishing'].Policies[0].IsDefault | Should -Be $false
            $result.Data['MalwareFilter'].Available | Should -Be $true
            $result.Data['MalwareFilter'].Policies[0].IsDefault | Should -Be $false
        }
    }

    Context 'Invoke-NRGCollectEXOMailboxConfig — DKIM config row omitting Selector1' {

        BeforeEach {
            # Only the DKIM cmdlet is mocked; every other section's cmdlets are
            # unavailable in this environment and fail into their own
            # try/catch (SectionStatus = 'Failed'), which is exactly how a
            # real tenant missing a scope/license degrades — it does not
            # affect whether the DKIM section itself throws.
            Mock -CommandName Get-DkimSigningConfig -ModuleName NRG-Assessment -MockWith {
                @([pscustomobject]@{ Domain = 'contoso.com'; Status = 'Valid' })
            }
        }

        It 'does not throw and reports DkimSigningConfigs Collected when Selector1/Selector2 are omitted' {
            $result = Invoke-NRGCollectEXOMailboxConfig
            $result.Data.SectionStatus.DkimSigningConfigs | Should -Be 'Collected'
            $result.Data.DkimSigningConfigs[0].Selector1   | Should -Be ''
            $result.Data.DkimSigningConfigs[0].Selector2   | Should -Be ''
            $result.Data.DkimSigningConfigs[0].Domain      | Should -Be 'contoso.com'
        }
    }

    Context 'Invoke-NRGCollectM365Copilot — Measure-Object over ordered-hashtable SKU rows' {

        BeforeEach {
            Mock -CommandName Invoke-NRGGraphRequest -ModuleName NRG-Assessment -MockWith {
                @{
                    value = @(
                        @{ skuId = 'sku-1'; skuPartNumber = 'Microsoft_365_Copilot'; consumedUnits = 5; prepaidUnits = @{ enabled = 10 }; servicePlans = @() }
                        @{ skuId = 'sku-2'; skuPartNumber = 'Microsoft_365_Copilot_Addon'; consumedUnits = 3; prepaidUnits = @{ enabled = 4 }; servicePlans = @() }
                    )
                }
            }
        }

        It 'does not throw "Cannot process argument ConsumedUnits" and sums licensed users correctly' {
            $result = Invoke-NRGCollectM365Copilot
            $result.Data.LicensedSkus.Count       | Should -Be 2
            $result.Data.CopilotLicensedUserCount | Should -Be 8
            $result.Errors -join ' ' | Should -Not -Match 'ConsumedUnits'
        }
    }
}

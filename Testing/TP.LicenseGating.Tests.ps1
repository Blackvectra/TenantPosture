#Requires -Version 7.0
#
# TP.LicenseGating.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The scoring rule (owner's decision, 2026-09-25):
#   - Licensed but not configured -> Gap. No half credit for what is not there.
#   - Not licensed               -> not scored; reported as "requires <license>"
#                                   (an upgrade opportunity, not a deduction).
#   - Partial only for configuration that is genuinely part-way.
#
# Before this, only three Defender evaluators routed unlicensed controls out
# of the score; every other unlicensed control scored a Gap and was docked
# while ALSO being listed as a license gap. And the license profile read
# Microsoft 365 Business STANDARD (skuPartNumber O365_BUSINESS_PREMIUM) as
# Business Premium, while E3 tenants failed "Business Premium or E3+".

Describe 'License gating and the not-configured rule' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        # Service plans from Microsoft's licensing reference.
        $script:BusinessStandard = @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD','INTUNE_O365','TEAMS1','SHAREPOINTSTANDARD','RMS_S_BASIC') })
        $script:BusinessPremium  = @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM','INTUNE_A','ATP_ENTERPRISE','MDE_SMB','MFA_PREMIUM') })
        $script:O365E3           = @(@{ SkuPartNumber = 'ENTERPRISEPACK'; ServicePlans = @('EXCHANGE_S_ENTERPRISE','SHAREPOINTENTERPRISE','TEAMS1') })

        function script:Profile($skus) { Get-TPTenantLicenseProfile -SubscribedSkus $skus }
        function script:Add-F([string]$Cid, [string]$State, [string]$Detail = 'Nothing configured.') {
            Add-TPFinding -ControlId $Cid -State $State -Category 'Identity' -Title "$Cid title" -Severity 'High' -Detail $Detail
        }
        function script:One([string]$Cid) { @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0] }
    }

    BeforeEach { Clear-TPState }

    Context 'license profile' {
        It 'Business Standard (O365_BUSINESS_PREMIUM) is NOT Business Premium' {
            $p = Profile $script:BusinessStandard
            $p.HasBusinessPremium | Should -BeFalse
            $p.HasEntraP1         | Should -BeFalse
            $p.HasIntune          | Should -BeFalse
            $p.TierLabel          | Should -Be 'Microsoft 365 Business Standard'
            Test-TPLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $p | Should -BeFalse
        }
        It 'Business Premium without Teams is Business Premium' {
            (Profile @(@{ SkuPartNumber = 'Office_365_w/o_Teams_Bundle_Business_Premium'; ServicePlans = @('AAD_PREMIUM','INTUNE_A') })).HasBusinessPremium | Should -BeTrue
        }
        It 'Office 365 E3 satisfies "M365 Business Premium or E3+" and is labeled Office 365 E3' {
            $p = Profile $script:O365E3
            Test-TPLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or E3+' -LicenseProfile $p | Should -BeTrue
            $p.TierLabel | Should -Be 'Office 365 E3'
        }
    }

    Context 'gating pass' {
        It 'an unlicensed Gap leaves the score and becomes an upgrade opportunity' {
            Add-F 'AAD-3.2' 'Gap' 'PIM is available but no eligible assignments.'   # Entra ID P2
            Add-F 'AAD-1.1' 'Satisfied' 'ok'
            $before = (Get-TPCoverageScore -Findings @(Get-TPFindings)).Score
            (Set-TPLicenseGating -LicenseProfile (Profile $script:BusinessStandard)) | Should -Be 1
            $f = One 'AAD-3.2'
            $f.State        | Should -Be 'NotApplicable'
            $f.Detail       | Should -Match 'upgrade opportunity'
            $f.Detail       | Should -Match 'requires Entra ID P2'
            $f.Detail       | Should -Match 'Result before the license check: Gap'
            $f.CurrentValue | Should -Be 'Requires Entra ID P2 (not licensed)'
            (Get-TPCoverageScore -Findings @(Get-TPFindings)).Score | Should -BeGreaterThan $before
        }

        It 'a licensed Gap stays a Gap — not configured is not partly configured' {
            Add-F 'INT-2.5' 'Gap'    # M365 Business Premium or Intune Plan 1
            Set-TPLicenseGating -LicenseProfile (Profile $script:BusinessPremium) | Out-Null
            (One 'INT-2.5').State | Should -Be 'Gap'
        }

        It 'never moves anything when license data was not collected' {
            Add-F 'AAD-3.2' 'Gap'
            (Set-TPLicenseGating -LicenseProfile (Profile @())) | Should -Be 0
            (One 'AAD-3.2').State | Should -Be 'Gap'
        }

        It 'a configured (passing) control keeps its verdict whatever the license says' {
            Add-F 'AAD-3.2' 'Satisfied' 'ok'
            Set-TPLicenseGating -LicenseProfile (Profile $script:BusinessStandard) | Out-Null
            (One 'AAD-3.2').State | Should -Be 'Satisfied'
        }

        It 'a third-party EDR declaration wins: a Cortex client is not pitched Defender for Endpoint' {
            Add-F 'INT-2.1' 'Gap'
            Set-TPThirdPartyEdr -Product 'Cortex XDR' | Out-Null
            Set-TPLicenseGating -LicenseProfile (Profile $script:BusinessStandard) | Out-Null
            (One 'INT-2.1').Detail | Should -Match '^Third-party EDR declared:'
            (One 'INT-2.1').Detail | Should -Not -Match 'upgrade opportunity'
        }

        It 'the scope section files gated controls as license gated' {
            Add-F 'AAD-3.2' 'Gap'
            Set-TPLicenseGating -LicenseProfile (Profile $script:BusinessStandard) | Out-Null
            $s = Get-TPAssessmentScope -Findings @(Get-TPFindings)
            @($s.LicenceBlocked | ForEach-Object { $_.ControlId }) | Should -Contain 'AAD-3.2'
        }

        It 'works on findings loaded by -FromResults (hashtables)' {
            $loaded = @(@{ ControlId = 'AAD-3.2'; State = 'Gap'; Detail = 'x'; CurrentValue = '' })
            (Set-TPLicenseGating -Findings $loaded -LicenseProfile (Profile $script:BusinessStandard)) | Should -Be 1
            $loaded[0].State | Should -Be 'NotApplicable'
        }
    }

    Context 'not configured scores Gap, not Partial' {
        BeforeAll {
            function script:Bag([hashtable] $Data) {
                [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $true; Data = $Data }
            }
        }
        It 'Endpoint DLP (DEF-4.5): none is a Gap, and a policy listing EndpointDevices after other workloads is found' {
            Set-TPRawData -Key 'Purview' -Data (Bag @{ DLPPolicies = @(); SectionStatus = @{ DLPPolicies = 'Collected' } })
            Test-TPControlDefenderEndpointDLP | Out-Null
            (One 'DEF-4.5').State | Should -Be 'Gap'
            Clear-TPState
            # The collector's trimmed projection of Workload 'Exchange, SharePoint, EndpointDevices'.
            Set-TPRawData -Key 'Purview' -Data (Bag @{ DLPPolicies = @(@{ Name = 'p'; Workloads = @('Exchange','SharePoint','EndpointDevices') }); SectionStatus = @{ DLPPolicies = 'Collected' } })
            Test-TPControlDefenderEndpointDLP | Out-Null
            (One 'DEF-4.5').State | Should -Be 'Satisfied'
        }
        It 'the Purview collector trims workload names' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Collectors/Purview/Invoke-TPCollectPurview.ps1') -Raw
            $src | Should -Not -Match "Workloads\s*=\s*if \(\`$_\.Workload\) \{ \(\`$_\.Workload -split ','\) \}"
            $src | Should -Match "-split ',' \| ForEach-Object \{ \`$_\.Trim\(\) \}"
        }
    }
}

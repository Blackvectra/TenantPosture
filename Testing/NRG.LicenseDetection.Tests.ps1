#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
<#
.SYNOPSIS
    Pester tests for Get-NRGTenantLicenseProfile and the publisher suppression
    chain. Covers the v4.6.1 false-negative bug: a Microsoft 365 Business
    Premium tenant (SkuPartNumber = SPB) generated remediation output that
    labeled every BP-gated control as "REQUIRES: M365 Business Premium...",
    misleading operators into thinking the tool had not detected BP.

.DESCRIPTION
    The helper at Lib/Get-NRGTenantLicenseProfile.ps1 is the single source of
    truth for license-tier detection. These tests pin the canonical behaviour:

      * SPB resolves to Business Premium (the user's reported tenant)
      * E3 / E5 / EMS chains resolve to the correct tier
      * Entra ID P2 detection works via Microsoft_Entra_Suite, AAD_PREMIUM_P2,
        and SPE_E5 service-plan bundling
      * Service-plan-level detection works when SkuPartNumber alone is
        ambiguous (e.g. M365 E5 contains ATP_ENTERPRISE)
      * Suppression set matches controls.json LicenseRequirement strings
        exactly, case-insensitively
      * Negative path: tenants without BP correctly report HasBusinessPremium
        = $false and suppress no BP-gated controls
      * The v4.6.1 MFA_PREMIUM-as-MDCA bug is regressed (MFA Premium is a
        service plan inside Entra P1/P2 — it does NOT indicate MDCA)
#>

Describe 'NRG-Assessment License Detection — v4.6.2' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }

        # Dot-source the helper directly so the test does not depend on the
        # full module loading (some CI environments lack the Microsoft.Graph
        # modules required by Connect-NRGServices).
        $helperPath = Join-Path $script:RepoRoot 'Lib' 'Get-NRGTenantLicenseProfile.ps1'
        . $helperPath
    }

    Context 'SPB (Microsoft 365 Business Premium) — the regressed case' {

        It 'Resolves Business Premium from SkuPartNumber = SPB' {
            $skus = @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM','INTUNE_A','ATP_ENTERPRISE','WIN_DEF_ATP') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            $p.HasBusinessPremium | Should -BeTrue
            $p.HasEntraP1         | Should -BeTrue
            $p.HasIntune          | Should -BeTrue
            $p.HasDfOP1           | Should -BeTrue
            $p.HasMDEP1           | Should -BeTrue
            $p.TierLabel          | Should -Match 'Business Premium'
        }

        It 'Suppresses every BP-gated LicenseRequirement string from controls.json' {
            $skus = @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM','INTUNE_A','ATP_ENTERPRISE') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            $expected = @(
                'M365 Business Premium or Entra ID P1',
                'M365 Business Premium or Entra ID P1 + Intune',
                'M365 Business Premium or Intune Plan 1',
                'Defender for Office 365 Plan 1 (M365 Business Premium)',
                'M365 Business Premium or E3+',
                'M365 Business Premium or E3+ (Copilot requires M365 Copilot add-on)'
            )
            foreach ($req in $expected) {
                $p.SuppressedLicenseRequirements.Contains($req) |
                    Should -BeTrue -Because "LicenseRequirement '$req' should be suppressed on a tenant with SPB"
            }
        }

        It 'Test-NRGLicenseRequirementMet returns true for BP-gated controls' {
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM','INTUNE_A') })
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $p |
                Should -BeTrue
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Intune Plan 1' -LicenseProfile $p |
                Should -BeTrue
        }

        It 'Replays the exact user-reported nrgtechservices.com tenant SKU set' {
            # Captured from /root/.claude/uploads/.../nextlayersec20260525134902results.json
            # AAD-Inventory.Data.SubscribedSkus
            $skus = @(
                @{ SkuPartNumber = 'Microsoft_365_Copilot';     ServicePlans = @('M365_COPILOT_BUSINESS_CHAT') }
                @{ SkuPartNumber = 'FLOW_FREE';                 ServicePlans = @('EXCHANGE_S_FOUNDATION') }
                @{ SkuPartNumber = 'SPB';                       ServicePlans = @('AAD_PREMIUM','INTUNE_A','ATP_ENTERPRISE','MFA_PREMIUM','WIN_DEF_ATP') }
                @{ SkuPartNumber = 'THREAT_INTELLIGENCE_DEPT';  ServicePlans = @('THREAT_INTELLIGENCE','ATP_ENTERPRISE','MTP') }
                @{ SkuPartNumber = 'AAD_PREMIUM_P2';            ServicePlans = @('AAD_PREMIUM','AAD_PREMIUM_P2','MFA_PREMIUM') }
                @{ SkuPartNumber = 'RMSBASIC';                  ServicePlans = @('RMS_S_BASIC') }
                @{ SkuPartNumber = 'Microsoft_Entra_Suite';     ServicePlans = @('AAD_PREMIUM_P2','Entra_Identity_Governance') }
                @{ SkuPartNumber = 'POWERAPPS_DEV';             ServicePlans = @('POWERAPPS_DEV_VIRAL') }
            )
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            $p.HasBusinessPremium | Should -BeTrue
            $p.HasEntraP2         | Should -BeTrue
            $p.HasDfOP2           | Should -BeTrue
            $p.TierLabel          | Should -Match 'Business Premium'
            $p.TierLabel          | Should -Match 'Copilot'
        }
    }

    Context 'Higher tiers — M365 E3 and E5' {

        It 'M365 E5 (SPE_E5) detects E5 tier and grants all subordinate licenses' {
            $skus = @(@{ SkuPartNumber = 'SPE_E5'; ServicePlans = @('AAD_PREMIUM','AAD_PREMIUM_P2','INTUNE_A','ATP_ENTERPRISE','THREAT_INTELLIGENCE','ADALLOM_S_STANDALONE') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            $p.TierLabel  | Should -Be 'Microsoft 365 E5'
            $p.HasEntraP1 | Should -BeTrue
            $p.HasEntraP2 | Should -BeTrue
            $p.HasIntune  | Should -BeTrue
            $p.HasDfOP1   | Should -BeTrue
            $p.HasDfOP2   | Should -BeTrue
            $p.HasMDCA    | Should -BeTrue
        }

        It 'M365 E3 (SPE_E3) detects E3 tier and grants P1 + Intune but NOT P2' {
            $skus = @(@{ SkuPartNumber = 'SPE_E3'; ServicePlans = @('AAD_PREMIUM','INTUNE_A') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            $p.TierLabel  | Should -Be 'Microsoft 365 E3'
            $p.HasEntraP1 | Should -BeTrue
            $p.HasEntraP2 | Should -BeFalse
            $p.HasIntune  | Should -BeTrue
            # E3 holders should have "BP or P1" suppressed (P1 alone satisfies)
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $p |
                Should -BeTrue
        }

        It 'Entra Suite alone provides P2 without BP' {
            $skus = @(@{ SkuPartNumber = 'Microsoft_Entra_Suite'; ServicePlans = @('AAD_PREMIUM_P2','Entra_Identity_Governance') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            $p.HasBusinessPremium | Should -BeFalse
            $p.HasEntraP2         | Should -BeTrue
            Test-NRGLicenseRequirementMet -LicenseRequirement 'Entra ID P2' -LicenseProfile $p | Should -BeTrue
        }
    }

    Context 'Negative cases — tenants WITHOUT the license should not suppress' {

        It 'FLOW_FREE-only tenant does not detect Business Premium' {
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'FLOW_FREE'; ServicePlans = @('EXCHANGE_S_FOUNDATION') })
            $p.HasBusinessPremium | Should -BeFalse
            $p.HasEntraP1         | Should -BeFalse
            $p.HasIntune          | Should -BeFalse
            $p.SuppressedLicenseRequirements.Count | Should -Be 0
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $p |
                Should -BeFalse
        }

        It 'Empty SKU list yields an empty suppression set' {
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus @()
            $p.HasBusinessPremium | Should -BeFalse
            $p.SuppressedLicenseRequirements.Count | Should -Be 0
        }

        It 'Null profile means "unknown" — Test- returns false to err on the side of disclosure' {
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Business Premium or Entra ID P1' -LicenseProfile $null |
                Should -BeFalse
        }

        It 'Null / empty / Included* requirements are always considered met' {
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus @()
            Test-NRGLicenseRequirementMet -LicenseRequirement $null    -LicenseProfile $p | Should -BeTrue
            Test-NRGLicenseRequirementMet -LicenseRequirement ''       -LicenseProfile $p | Should -BeTrue
            Test-NRGLicenseRequirementMet -LicenseRequirement 'Included (all plans)' -LicenseProfile $p | Should -BeTrue
        }
    }

    Context 'Regression — v4.6.1 MFA_PREMIUM-as-MDCA bug' {

        It 'MFA_PREMIUM service plan must NOT trigger HasMDCA' {
            # v4.6.1 inline detector wrongly listed MFA_PREMIUM in the MDCA
            # regex. MFA_PREMIUM is a service plan inside Entra ID P1/P2 — it
            # has nothing to do with Microsoft Defender for Cloud Apps.
            $skus = @(@{ SkuPartNumber = 'AAD_PREMIUM_P2'; ServicePlans = @('AAD_PREMIUM','AAD_PREMIUM_P2','MFA_PREMIUM') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            $p.HasMDCA | Should -BeFalse
        }

        It 'ADALLOM_S_STANDALONE service plan correctly triggers HasMDCA' {
            $skus = @(@{ SkuPartNumber = 'SPE_E5'; ServicePlans = @('ADALLOM_S_STANDALONE') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            $p.HasMDCA | Should -BeTrue
        }
    }

    Context 'Suppression set matches every BP-gated LicenseRequirement in controls.json' {
        # If controls.json adds a new BP-gated string that the helper does not
        # know about, BP tenants will see "Requires: <new string>" on those
        # controls. This test catches that drift at PR review time.

        It 'Every controls.json LicenseRequirement value containing "Business Premium" is covered for a BP tenant' {
            $controlsPath = Join-Path $script:RepoRoot 'Config' 'controls.json'
            # controls.json wraps the list under a top-level "controls" key
            $controlsDoc = Get-Content -LiteralPath $controlsPath -Raw | ConvertFrom-Json
            $ctrls = $controlsDoc.controls

            $bpReqs = @($ctrls |
                Where-Object { $_.LicenseRequirement -and $_.LicenseRequirement -match 'Business Premium' } |
                ForEach-Object { $_.LicenseRequirement } |
                Sort-Object -Unique)

            $bpReqs.Count | Should -BeGreaterThan 0

            $p = Get-NRGTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM','INTUNE_A','ATP_ENTERPRISE','WIN_DEF_ATP') })

            $missing = @()
            foreach ($req in $bpReqs) {
                if (-not $p.SuppressedLicenseRequirements.Contains($req)) {
                    $missing += $req
                }
            }
            $missing | Should -BeNullOrEmpty -Because 'Every Business Premium LicenseRequirement string in controls.json must be in the BP suppression set. If this fails, add the new string to Get-NRGTenantLicenseProfile.ps1.'
        }
    }

    Context 'v4.6.4 — drifted LicenseRequirement strings must suppress on the holding tenant' {
        # Each of these 7 strings is the EXACT controls.json value. Prior
        # versions of Get-NRGTenantLicenseProfile did not map any of them to a
        # tier flag → BP / E5 / Copilot tenants still saw "Requires: <X>"
        # noise on the report.

        It 'Defender for Office 365 Plan 2 (M365 E5 or add-on) — suppressed on E5' {
            $skus = @(@{ SkuPartNumber = 'ENTERPRISEPREMIUM'; ServicePlans = @('THREAT_INTELLIGENCE','ATP_ENTERPRISE') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            Test-NRGLicenseRequirementMet -LicenseRequirement 'Defender for Office 365 Plan 2 (M365 E5 or add-on)' -LicenseProfile $p |
                Should -BeTrue
        }

        It 'M365 E5 Compliance add-on — suppressed when E5 compliance service plan present' {
            $skus = @(@{ SkuPartNumber = 'SPE_E5'; ServicePlans = @('EQUIVIO_ANALYTICS','RECORDS_MANAGEMENT') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 E5 Compliance add-on' -LicenseProfile $p |
                Should -BeTrue
        }

        It 'M365 E5 or E5 Compliance add-on — suppressed when E5 compliance present' {
            $skus = @(@{ SkuPartNumber = 'ENTERPRISEPREMIUM'; ServicePlans = @('INSIDER_RISK_MANAGEMENT') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 E5 or E5 Compliance add-on' -LicenseProfile $p |
                Should -BeTrue
        }

        It 'Microsoft Sentinel (add-on) or Defender XDR — suppressed on E5 / DfO P2 tenant' {
            $skus = @(@{ SkuPartNumber = 'SPE_E5'; ServicePlans = @('THREAT_INTELLIGENCE','MTP') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            Test-NRGLicenseRequirementMet -LicenseRequirement 'Microsoft Sentinel (add-on) or Defender XDR' -LicenseProfile $p |
                Should -BeTrue
        }

        It 'Entra Workload Identities Premium (add-on) — suppressed when SKU present' {
            $skus = @(@{ SkuPartNumber = 'Microsoft_Entra_Workload_Identities_Premium'; ServicePlans = @() })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            Test-NRGLicenseRequirementMet -LicenseRequirement 'Entra Workload Identities Premium (add-on)' -LicenseProfile $p |
                Should -BeTrue
        }

        It 'M365 Copilot add-on license ($30/user/month) — exact special-char string suppresses on Copilot tenant' {
            $skus = @(@{ SkuPartNumber = 'Microsoft_365_Copilot'; ServicePlans = @('M365_COPILOT_BUSINESS_CHAT') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            # Literal string with dollar sign and parentheses — make sure we
            # match it as a raw string, not a regex pattern.
            Test-NRGLicenseRequirementMet -LicenseRequirement 'M365 Copilot add-on license ($30/user/month)' -LicenseProfile $p |
                Should -BeTrue
        }

        It 'Power Platform + Copilot Studio license — suppressed when PowerApps Per User SKU present' {
            $skus = @(@{ SkuPartNumber = 'POWERAPPS_PER_USER'; ServicePlans = @('POWERAPPS_PER_USER') })
            $p = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
            Test-NRGLicenseRequirementMet -LicenseRequirement 'Power Platform + Copilot Studio license' -LicenseProfile $p |
                Should -BeTrue
        }
    }
}

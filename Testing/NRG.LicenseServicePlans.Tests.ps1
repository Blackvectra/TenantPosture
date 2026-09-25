#Requires -Version 7.0
#
# NRG.LicenseServicePlans.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# License detection reads SERVICE PLANS (Config/license-service-plans.json),
# not product part numbers. Unlicensed controls are taken out of the score, so
# a detection error in the "not held" direction hides a real gap. Found by
# audit, all against Microsoft's own licensing reference:
#   - "Exchange Online Plan 2 or M365 E3" (EXO-9.1) was never marked met for
#     ANY tenant, so the hold/retention control was never scored anywhere.
#   - Microsoft 365 E5 did not satisfy "Defender for Endpoint Plan 1+" although
#     it carries Plan 2 (WINDEFATP), which includes Plan 1.
#   - Office 365 E3/E5 were read as Entra ID P1/P2 (they carry neither), so
#     Conditional Access gaps were pitched as "covered by current licensing".
#   - Office 365 E5 was labeled "Microsoft 365 E5".
#   - Every "E5 Compliance" control was met by ANY one compliance plan.
# The fixtures below are the service-plan lists Microsoft publishes for each
# product ("Product names and service plan identifiers for licensing").

Describe 'License detection by service plan' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        $script:M365E5 = @(@{ SkuPartNumber = 'SPE_E5'; ServicePlans = @(
            'AAD_PREMIUM','AAD_PREMIUM_P2','ADALLOM_S_O365','ADALLOM_S_STANDALONE','ATA','ATP_ENTERPRISE',
            'BI_AZURE_P2','BPOS_S_TODO_3','Bing_Chat_Enterprise','CDS_O365_P3','CLIPCHAMP',
            'COMMUNICATIONS_COMPLIANCE','COMMUNICATIONS_DLP','CUSTOMER_KEY','ContentExplorer_Standard',
            'Content_Explorer','CustomerLockboxA_Enterprise','DATA_INVESTIGATIONS','DYN365_CDS_O365_P3',
            'Defender_for_Iot_Enterprise','Deskless','EQUIVIO_ANALYTICS','EXCEL_PREMIUM','EXCHANGE_ANALYTICS',
            'EXCHANGE_S_ENTERPRISE','FLOW_O365_P3','FORMS_PLAN_E5','GRAPH_CONNECTORS_SEARCH_INDEX',
            'INFORMATION_BARRIERS','INFO_GOVERNANCE','INSIDER_RISK','INSIDER_RISK_MANAGEMENT','INTUNE_A',
            'INTUNE_O365','KAIZALA_STANDALONE','LOCKBOX_ENTERPRISE','M365_ADVANCED_AUDITING','M365_AUDIT_PLATFORM',
            'M365_LIGHTHOUSE_CUSTOMER_PLAN1','MCOEV','MCOMEETADV','MCOSTANDARD','MESH_AVATARS_ADDITIONAL_FOR_TEAMS',
            'MESH_AVATARS_FOR_TEAMS','MESH_IMMERSIVE_FOR_TEAMS','MFA_PREMIUM','MICROSOFTBOOKINGS',
            'MICROSOFTENDPOINTDLP','MICROSOFT_COMMUNICATION_COMPLIANCE','MICROSOFT_LOOP','MICROSOFT_SEARCH',
            'MIP_S_CLP1','MIP_S_CLP2','MIP_S_Exchange','ML_CLASSIFICATION','MTP','MYANALYTICS_P2','Nucleus',
            'OFFICESUBSCRIPTION','PAM_ENTERPRISE','POWERAPPS_O365_P3','POWER_VIRTUAL_AGENTS_O365_P3',
            'PREMIUM_ENCRYPTION','PROJECTWORKMANAGEMENT','PROJECT_O365_P3','PURVIEW_DISCOVERY','RECORDS_MANAGEMENT',
            'RMS_S_ENTERPRISE','RMS_S_PREMIUM','RMS_S_PREMIUM2','SAFEDOCS','SHAREPOINTENTERPRISE','SHAREPOINTWAC',
            'STREAM_O365_E5','SWAY','TEAMS1','THREAT_INTELLIGENCE','UNIVERSAL_PRINT_01','VIVAENGAGE_CORE',
            'VIVA_LEARNING_SEEDED','WHITEBOARD_PLAN3','WIN10_PRO_ENT_SUB','WINDEFATP',
            'WINDOWSUPDATEFORBUSINESS_DEPLOYMENTSERVICE','Windows_Autopatch','YAMMER_ENTERPRISE'
        ) })
        $script:M365E3 = @(@{ SkuPartNumber = 'SPE_E3'; ServicePlans = @(
            'AAD_PREMIUM','ADALLOM_S_DISCOVERY','ATP_ENTERPRISE','BPOS_S_TODO_2','Bing_Chat_Enterprise','CDS_O365_P2',
            'CLIPCHAMP','ContentExplorer_Standard','DYN365_CDS_O365_P2','Deskless','EXCHANGE_S_ENTERPRISE',
            'FLOW_O365_P2','FORMS_PLAN_E3','GRAPH_CONNECTORS_SEARCH_INDEX','INTUNE_A','INTUNE_O365','KAIZALA_O365_P3',
            'M365_LIGHTHOUSE_CUSTOMER_PLAN1','M365_LIGHTHOUSE_PARTNER_PLAN1','MCOSTANDARD','MDE_LITE',
            'MESH_AVATARS_ADDITIONAL_FOR_TEAMS','MESH_AVATARS_FOR_TEAMS','MESH_IMMERSIVE_FOR_TEAMS','MFA_PREMIUM',
            'MICROSOFTBOOKINGS','MICROSOFT_LOOP','MICROSOFT_SEARCH','MIP_S_CLP1','MYANALYTICS_P2','Nucleus',
            'OFFICESUBSCRIPTION','POWERAPPS_O365_P2','POWER_VIRTUAL_AGENTS_O365_P2','PROJECTWORKMANAGEMENT',
            'PROJECT_O365_P2','RMS_S_ENTERPRISE','RMS_S_PREMIUM','SHAREPOINTENTERPRISE','SHAREPOINTWAC',
            'STREAM_O365_E3','SWAY','TEAMS1','UNIVERSAL_PRINT_01','VIVAENGAGE_CORE','VIVA_LEARNING_SEEDED',
            'WHITEBOARD_PLAN2','WIN10_PRO_ENT_SUB','WINDOWSUPDATEFORBUSINESS_DEPLOYMENTSERVICE','Windows_Autopatch',
            'YAMMER_ENTERPRISE'
        ) })
        $script:O365E3 = @(@{ SkuPartNumber = 'ENTERPRISEPACK'; ServicePlans = @(
            'ATP_ENTERPRISE','BPOS_S_TODO_2','Bing_Chat_Enterprise','CDS_O365_P2','ContentExplorer_Standard',
            'DYN365_CDS_O365_P2','Deskless','EXCHANGE_S_ENTERPRISE','FLOW_O365_P2','FORMS_PLAN_E3','INTUNE_O365',
            'KAIZALA_O365_P3','M365_LIGHTHOUSE_CUSTOMER_PLAN1','MCOSTANDARD','MESH_AVATARS_ADDITIONAL_FOR_TEAMS',
            'MESH_AVATARS_FOR_TEAMS','MESH_IMMERSIVE_FOR_TEAMS','MICROSOFTBOOKINGS','MICROSOFT_SEARCH','MIP_S_CLP1',
            'MYANALYTICS_P2','Nucleus','OFFICESUBSCRIPTION','POWERAPPS_O365_P2','POWER_VIRTUAL_AGENTS_O365_P2',
            'PROJECTWORKMANAGEMENT','PROJECT_O365_P2','RMS_S_ENTERPRISE','SHAREPOINTENTERPRISE','SHAREPOINTWAC',
            'STREAM_O365_E3','SWAY','TEAMS1','VIVAENGAGE_CORE','VIVA_LEARNING_SEEDED','WHITEBOARD_PLAN2',
            'YAMMER_ENTERPRISE'
        ) })
        $script:O365E5 = @(@{ SkuPartNumber = 'ENTERPRISEPREMIUM'; ServicePlans = @(
            'ADALLOM_S_O365','ATP_ENTERPRISE','BI_AZURE_P2','BPOS_S_TODO_3','CDS_O365_P3','COMMUNICATIONS_COMPLIANCE',
            'COMMUNICATIONS_DLP','CUSTOMER_KEY','ContentExplorer_Standard','Content_Explorer','DATA_INVESTIGATIONS',
            'DYN365_CDS_O365_P3','Deskless','EQUIVIO_ANALYTICS','EXCEL_PREMIUM','EXCHANGE_ANALYTICS',
            'EXCHANGE_S_ENTERPRISE','FLOW_O365_P3','FORMS_PLAN_E5','GRAPH_CONNECTORS_SEARCH_INDEX',
            'INFORMATION_BARRIERS','INFO_GOVERNANCE','INTUNE_O365','KAIZALA_STANDALONE','LOCKBOX_ENTERPRISE',
            'M365_ADVANCED_AUDITING','MCOEV','MCOMEETADV','MCOSTANDARD','MICROSOFTBOOKINGS',
            'MICROSOFT_COMMUNICATION_COMPLIANCE','MICROSOFT_SEARCH','MICROSOFT_TEAMS_EVENTS','MIP_S_CLP1',
            'MIP_S_CLP2','MIP_S_Exchange','MTP','MYANALYTICS_P2','OFFICESUBSCRIPTION','PAM_ENTERPRISE',
            'POWERAPPS_O365_P3','POWER_VIRTUAL_AGENTS_O365_P3','PREMIUM_ENCRYPTION','PROJECTWORKMANAGEMENT',
            'PROJECT_O365_P3','RECORDS_MANAGEMENT','RMS_S_ENTERPRISE','SHAREPOINTENTERPRISE','SHAREPOINTWAC',
            'STREAM_O365_E5','SWAY','TEAMS1','THREAT_INTELLIGENCE','VIVAENGAGE_CORE','VIVA_LEARNING_SEEDED',
            'WHITEBOARD_PLAN3','YAMMER_ENTERPRISE'
        ) })
        $script:BusinessPremium = @(@{ SkuPartNumber = 'SPB'; ServicePlans = @(
            'AAD_PREMIUM','AAD_SMB','ADALLOM_S_DISCOVERY','ATP_ENTERPRISE','BPOS_S_DlpAddOn','BPOS_S_TODO_1',
            'Bing_Chat_Enterprise','CDS_O365_P3','CLIPCHAMP','DYN365BC_MS_INVOICING','DYN365_CDS_O365_P3','Deskless',
            'EXCHANGE_S_ARCHIVE_ADDON','EXCHANGE_S_FOUNDATION','EXCHANGE_S_STANDARD','FLOW_O365_P1','FORMS_PLAN_E1',
            'INTUNE_A','INTUNE_O365','INTUNE_SMBIZ','KAIZALA_O365_P2','M365_LIGHTHOUSE_CUSTOMER_PLAN1',
            'M365_LIGHTHOUSE_PARTNER_PLAN1','MCOSTANDARD','MDE_SMB','MESH_AVATARS_ADDITIONAL_FOR_TEAMS',
            'MESH_AVATARS_FOR_TEAMS','MFA_PREMIUM','MICROSOFTBOOKINGS','MICROSOFT_LOOP','MICROSOFT_SEARCH',
            'MYANALYTICS_P2','Nucleus','O365_SB_Relationship_Management','OFFICE_BUSINESS',
            'OFFICE_SHARED_COMPUTER_ACTIVATION','POWERAPPS_O365_P1','POWER_VIRTUAL_AGENTS_O365_P3',
            'PROJECTWORKMANAGEMENT','PROJECT_O365_P3','PURVIEW_DISCOVERY','RMS_S_ENTERPRISE','RMS_S_PREMIUM',
            'SHAREPOINTSTANDARD','SHAREPOINTWAC','STREAM_O365_E1','SWAY','TEAMS1','UNIVERSAL_PRINT_01',
            'VIVAENGAGE_CORE','VIVA_LEARNING_SEEDED','WHITEBOARD_PLAN1','WINBIZ',
            'WINDOWSUPDATEFORBUSINESS_DEPLOYMENTSERVICE','YAMMER_ENTERPRISE'
        ) })
        $script:BusinessStandard = @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @(
            'BPOS_S_TODO_1','Bing_Chat_Enterprise','CDS_O365_P2','CLIPCHAMP','DYN365BC_MS_INVOICING',
            'DYN365_CDS_O365_P2','Deskless','EXCHANGE_S_STANDARD','FLOW_O365_P1','FORMS_PLAN_E1','INTUNE_O365',
            'KAIZALA_O365_P2','M365_LIGHTHOUSE_CUSTOMER_PLAN1','MCOSTANDARD','MESH_AVATARS_ADDITIONAL_FOR_TEAMS',
            'MESH_AVATARS_FOR_TEAMS','MICROSOFTBOOKINGS','MICROSOFT_LOOP','MICROSOFT_SEARCH','MYANALYTICS_P2',
            'Nucleus','O365_SB_Relationship_Management','OFFICE_BUSINESS','POWERAPPS_O365_P1',
            'POWER_VIRTUAL_AGENTS_O365_P2','PROJECTWORKMANAGEMENT','PROJECT_O365_P2','RMS_S_BASIC',
            'SHAREPOINTSTANDARD','SHAREPOINTWAC','STREAM_O365_SMB','SWAY','TEAMS1','VIVAENGAGE_CORE',
            'VIVA_LEARNING_SEEDED','WHITEBOARD_PLAN1','YAMMER_ENTERPRISE'
        ) })
        $script:BusinessBasic = @(@{ SkuPartNumber = 'O365_BUSINESS_ESSENTIALS'; ServicePlans = @(
            'BPOS_S_TODO_1','EXCHANGE_S_STANDARD','FLOW_O365_P1','FORMS_PLAN_E1','MCOSTANDARD',
            'OFFICEMOBILE_SUBSCRIPTION','POWERAPPS_O365_P1','PROJECTWORKMANAGEMENT','SHAREPOINTSTANDARD',
            'SHAREPOINTWAC','SWAY','TEAMS1','YAMMER_ENTERPRISE'
        ) })

        function script:Prof($skus) { Get-NRGTenantLicenseProfile -SubscribedSkus $skus }
        function script:Met([string] $Cid, $Prof) {
            $req = (Get-NRGControlById -ControlId $Cid).LicenseRequirement
            Test-NRGLicenseRequirementMet -LicenseRequirement $req -LicenseProfile $Prof -ControlId $Cid
        }
        function script:Gate([string] $Cid, $Prof) {
            Clear-NRGState
            Add-NRGFinding -ControlId $Cid -State 'Gap' -Category 'Identity' -Title $Cid -Severity 'High' -Detail 'Nothing configured.'
            Set-NRGLicenseGating -LicenseProfile $Prof | Out-Null
            (@(Get-NRGFindings | Where-Object ControlId -eq $Cid)[0]).State
        }
    }

    Context 'Microsoft 365 E5' {
        It 'keeps hold/retention (EXO-9.1) and ASR (INT-2.2) gaps in the score' {
            $p = Prof $script:M365E5
            Gate 'EXO-9.1' $p | Should -Be 'Gap'
            Gate 'INT-2.2' $p | Should -Be 'Gap'
            Gate 'INT-2.1' $p | Should -Be 'Gap'
            $p.HasMDEP1 | Should -BeTrue
            $p.TierLabel | Should -Be 'Microsoft 365 E5'
        }
        It 'holds every E5 compliance feature the controls name' {
            $p = Prof $script:M365E5
            foreach ($c in 'EXO-2.5','DEF-4.5','PVW-4.1','PVW-4.2','PVW-2.2','PVW-2.3','PVW-2.4','PVW-2.6','AAD-1.4','DEF-4.4') { Met $c $p | Should -BeTrue -Because $c }
        }
    }

    Context 'Office 365 E3 / E5 carry no Entra ID P1/P2 and no Defender for Endpoint' {
        It 'Office 365 E3: Conditional Access controls need a license; not labeled Microsoft 365' {
            $p = Prof $script:O365E3
            $p.HasEntraP1 | Should -BeFalse
            $p.TierLabel  | Should -Be 'Office 365 E3'
            Met 'AAD-1.2' $p | Should -BeFalse
            Gate 'AAD-1.2' $p | Should -Be 'NotApplicable'
            Met 'EXO-9.1' $p | Should -BeTrue
            Met 'PVW-1.3' $p | Should -BeTrue -Because 'DLP comes with Exchange Online Plan 2'
        }
        It 'Office 365 E5: labeled Office 365 E5; P2, Defender for Endpoint and Endpoint DLP not held; Customer Lockbox held' {
            $p = Prof $script:O365E5
            $p.TierLabel | Should -Be 'Office 365 E5'
            $p.HasEntraP2 | Should -BeFalse
            Met 'AAD-1.4' $p | Should -BeFalse
            Met 'INT-2.1' $p | Should -BeFalse
            Met 'DEF-4.5' $p | Should -BeFalse
            Met 'EXO-2.5' $p | Should -BeTrue
            Met 'PVW-4.1' $p | Should -BeTrue
        }
    }

    Context 'Business Premium and Business Standard' {
        It 'Business Premium: archiving covers holds, Defender for Business covers EDR, no E5 compliance' {
            $p = Prof $script:BusinessPremium
            Met 'EXO-9.1' $p | Should -BeTrue -Because 'Business Premium includes Exchange Online Archiving'
            Met 'INT-2.1' $p | Should -BeTrue -Because 'Defender for Business includes EDR'
            Met 'INT-2.2' $p | Should -BeTrue
            Met 'AAD-1.2' $p | Should -BeTrue
            Met 'PVW-1.3' $p | Should -BeTrue
            Met 'PVW-1.4' $p | Should -BeTrue
            Met 'PVW-2.6' $p | Should -BeFalse
            Met 'EXO-2.5' $p | Should -BeFalse
            Met 'AAD-1.4' $p | Should -BeFalse
        }
        It 'Business Standard: no DLP or labels, but audit retention is included in every plan' {
            $p = Prof $script:BusinessStandard
            Met 'PVW-1.3' $p | Should -BeFalse
            Met 'PVW-1.4' $p | Should -BeFalse
            Met 'EXO-9.1' $p | Should -BeFalse
            Gate 'PVW-1.2' $p | Should -Be 'Gap' -Because 'Audit (Standard) is in every plan, so an audit gap is never an upgrade opportunity'
            Gate 'DEF-4.3' $p | Should -Be 'Gap' -Because 'single-event alert policies are in every plan'
        }
    }

    Context 'per-control rules' {
        It 'one compliance add-on does not unlock every "E5 Compliance" control' {
            $p = Prof @(@{ SkuPartNumber = 'E5_EDISCOVERY_AUDIT_ADDON'; ServicePlans = @('M365_ADVANCED_AUDITING','EQUIVIO_ANALYTICS') })
            Met 'PVW-4.1' $p | Should -BeTrue
            Met 'EXO-2.5' $p | Should -BeFalse
            Met 'PVW-2.4' $p | Should -BeFalse
        }
        It 'every non-Included LicenseRequirement in controls.json can be satisfied by some rule' {
            $rules = & (Get-Module NRG-Assessment) { Get-NRGLicensePlanRules }
            $controls = (Get-Content (Join-Path $script:RepoRoot 'Config/controls.json') -Raw | ConvertFrom-Json).controls
            foreach ($c in $controls | Where-Object { $_.LicenseRequirement -notmatch '^Included' }) {
                ($rules.Requirements.ContainsKey($c.LicenseRequirement) -or $rules.Controls.ContainsKey($c.ControlId)) |
                    Should -BeTrue -Because "$($c.ControlId) requires '$($c.LicenseRequirement)', and a requirement no rule can satisfy is 'not licensed' on every tenant"
            }
        }
        It 'every per-control rule names a real control' {
            $rules = & (Get-Module NRG-Assessment) { Get-NRGLicensePlanRules }
            foreach ($cid in $rules.Controls.Keys) { Get-NRGControlById -ControlId $cid | Should -Not -BeNullOrEmpty -Because $cid }
        }
    }

    Context 'no license data' {
        It 'is reported as unknown and moves nothing out of the score' {
            $p = Prof @()
            $p.HasLicenseData | Should -BeFalse
            $p.TierLabel | Should -Match 'Unknown'
            Gate 'AAD-1.4' $p | Should -Be 'Gap'
        }
        It 'part-number fallback (no plan data): Microsoft 365 E5 has Defender for Endpoint Plan 1; Office 365 E3 has no Entra P1' {
            (Prof @(@{ SkuPartNumber = 'SPE_E5' })).HasMDEP1 | Should -BeTrue
            (Prof @(@{ SkuPartNumber = 'ENTERPRISEPACK' })).HasEntraP1 | Should -BeFalse
        }
    }

    Context 'HTML license card' {
        BeforeAll {
            function script:Render([object[]] $Skus) {
                Clear-NRGState
                if ($Skus) { Set-NRGRawData -Key 'AAD-Inventory' -Data ([pscustomobject]@{ CollectorId = 'x'; CollectedAt = 'n'; Success = $true; Data = @{ SubscribedSkus = $Skus } }) }
                Add-NRGFinding -ControlId 'AAD-1.4' -State 'Gap' -Category 'Identity' -Title 'Sign-in risk' -Severity 'High' -Detail 'none'
                Add-NRGFinding -ControlId 'PPL-3.3' -State 'Gap' -Category 'Governance' -Title 'Copilot' -Severity 'Medium' -Detail 'none'
                Set-NRGLicenseGating | Out-Null
                $out = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-lic-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.html')
                Publish-NRGAssessmentHTML -Metadata @{ TenantDomain = 'example.test'; AssessmentDate = '2026-09-25'; Operator = 't'; ToolVersion = 'test' } `
                    -Findings @(Get-NRGFindings) -Connections @{ Graph = $true } -OutputPath $out -ClientName 'Test Co' | Out-Null
                $h = Get-Content -Raw $out; Remove-Item $out -ErrorAction SilentlyContinue; $h
            }
        }
        It 'says licensing was not read, and blocks nothing, when no SKU data was collected' {
            $h = Render @()
            $h | Should -Match 'Tenant licensing was not read'
            $h | Should -Not -Match 'control(s)? blocked'
        }
        It 'does not pitch Business Premium to a Microsoft 365 E5 tenant' {
            $h = Render $script:M365E5
            $h | Should -Not -Match 'require <strong>Microsoft 365 Business Premium'
        }
    }
}

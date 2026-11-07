#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
#
# TP.CopilotLicensing.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# D1 (2026-11-06): a failed Copilot license read is not a tenant with no
# Copilot. The M365Copilot collector started CopilotLicensedUserCount at 0 and
# kept it when subscribedSkus threw, Success stayed true on the user read
# alone, and PPL-3.1, 3.2 and 3.5 then reported "No Microsoft 365 Copilot
# licenses detected". These tests drive the REAL collector against mocked Graph
# responses (no tenant, no network) and the REAL evaluators on its output, and
# pin the shared reading in Lib/Get-TPCopilotLicensingState.ps1:
#   - each read records Collected / Failed / Truncated, with its reason;
#   - purchased capacity, SKU consumed units and enumerated unique holders are
#     separate measurements with availability, source and completeness;
#   - a missing value is $null, never an authoritative zero;
#   - a truncated or failed enumeration is incomplete coverage, and rows read
#     before a failure are kept as an incomplete count;
#   - PPL-3.3's ratio needs a complete numerator and denominator over one
#     population, above zero;
#   - an older results file (no status) keeps positive evidence only, and a
#     saved file is never changed by being read.

Describe 'Copilot licensing reads (D1)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'

        $script:CopilotSku = '0b2f1c5e-0000-4000-8000-00000000c001'
        $script:CopilotSku2 = '0b2f1c5e-0000-4000-8000-00000000c002'
        $script:BpSku = '0b2f1c5e-0000-4000-8000-0000000000b9'
        $script:UsersFirst = 'https://graph.microsoft.com/v1.0/users?$select=id,assignedLicenses,userType,accountEnabled&$top=999'

        function script:Sku { param([string] $Id, [string] $Part, [object] $Prepaid = 'omit', [object] $Consumed = 'omit')
            $o = [ordered]@{ skuId = $Id; skuPartNumber = $Part; servicePlans = @() }
            if ($Prepaid -ne 'omit') { $o['prepaidUnits'] = @{ enabled = $Prepaid } }
            if ($Consumed -ne 'omit') { $o['consumedUnits'] = $Consumed }
            [pscustomobject]$o
        }
        function script:User { param([string] $Id, [string[]] $Skus = @(), [bool] $Enabled = $true, [string] $Type = 'Member')
            [pscustomobject]@{ id = $Id; userType = $Type; accountEnabled = $Enabled; assignedLicenses = @($Skus | ForEach-Object { [pscustomobject]@{ skuId = $_ } }) }
        }

        # Scenario: what each Graph URL answers. SkuMode 'throw' fails the license read;
        # Pages maps a users URL to @{ Users; Next } or 'throw'.
        function script:Set-Scenario { param([object] $Skus, [hashtable] $Pages)
            $script:ScenarioSkus = $Skus; $script:ScenarioPages = $Pages }

        function script:Run-Collector {
            Clear-TPState
            Mock -ModuleName TenantPosture Invoke-TPGraphRequest -MockWith {
                if ($Uri -like '*subscribedSkus*') {
                    if ($script:ScenarioSkus -eq 'throw') { throw 'Forbidden (403): Organization.Read.All not consented' }
                    return [pscustomobject]@{ value = @($script:ScenarioSkus) }
                }
                if ($Uri -like '*/users*') {
                    $page = $script:ScenarioPages[$Uri]
                    if ($null -eq $page) { throw "unexpected users URL $Uri" }
                    if ($page -eq 'throw') { throw 'Service unavailable (503) while paging users' }
                    $o = [ordered]@{ value = @($page.Users) }
                    if ($page.Next) { $o['@odata.nextLink'] = $page.Next }
                    return [pscustomobject]$o
                }
                throw "not mocked: $Uri"
            }
            $r = Invoke-TPCollectM365Copilot
            return $r
        }
        function script:Verdict { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
        function script:AllVerdicts {
            [ordered]@{
                'PPL-3.1' = (Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1')
                'PPL-3.2' = (Verdict 'Test-TPControlAICopilotDLP' 'PPL-3.2')
                'PPL-3.3' = (Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3')
                'PPL-3.5' = (Verdict 'Test-TPControlAICopilotInteractionData' 'PPL-3.5')
            }
        }
        function script:State { param([object] $Raw) & $script:Mod { param($r) Get-TPCopilotLicensingState -Raw $r } $Raw }
        function script:Scope {
            $f = @(Get-TPFindings)
            Get-TPAssessmentScope -Findings $f -Coverage (Get-TPCoverage) -RawData (& $script:Mod { $script:TPRawData })
        }
        function script:Bucket { param($Scope, [string] $Cid)
            foreach ($b in 'CollectionIncomplete', 'NotApplicableToTenant', 'LicenseBlocked', 'NoProgrammaticCheck', 'NoResult', 'StandardNotApproved', 'ThirdPartyAttested', 'SkippedByOperator') {
                if (@($Scope[$b] | Where-Object { $_.ControlId -eq $Cid }).Count) { return $b }
            }
            return 'Scored'
        }
        function script:LegacyRaw { param([hashtable] $Data) [ordered]@{ CollectorId = 'M365Copilot'; CollectedAt = '2026-09-01T00:00:00Z'; Success = $true; Data = $Data } }
        $script:ChatWords = 'eligible Microsoft 365 subscription'
    }
    BeforeEach { Clear-TPState }
    AfterAll   { Clear-TPState }

    Context 'License read failed, user read succeeded (the D1 defect)' {
        BeforeAll {
            Set-Scenario 'throw' @{ $script:UsersFirst = @{ Users = @((User 'u1' @($script:CopilotSku)), (User 'u2')) } }
        }
        It 'records the failure, keeps no default zero, and reports the coverage as incomplete' {
            $r = Run-Collector
            $r.Data.SectionStatus.Licensing | Should -Be 'Failed'
            $r.Data.SectionErrors['Licensing'] | Should -Match 'subscribedSkus query failed: Forbidden'
            $r.Data.SectionStatus.Users | Should -Be 'Collected'
            $r.Success | Should -BeTrue -Because 'the user read produced usable evidence'
            (Get-TPCoverage)['M365Copilot'].Status | Should -Be 'Partial'
            (Get-TPCoverage)['M365Copilot'].Note | Should -Match 'Licensing Failed'
            $r.Data.CopilotLicensedUserCount | Should -BeNullOrEmpty -Because 'a value that was not read stays null'
            $m = $r.Data.LicensingMeasurements
            $m.RecognizedSkuCount.Completeness | Should -Be 'NotRead'; $m.RecognizedSkuCount.Value | Should -BeNullOrEmpty
            $m.AssignedUsers.Completeness | Should -Be 'NotRead' -Because 'holders cannot be counted without the recognized SKU set'
            $m.EnabledMembers.Value | Should -Be 2; $m.EnabledMembers.Completeness | Should -Be 'Complete'
        }
        It 'leaves PPL-3.1, 3.2, 3.3 and 3.5 not assessed, cited, with the recorded reason; never "no licenses detected"' {
            $null = Run-Collector
            $v = AllVerdicts
            foreach ($cid in $v.Keys) {
                $f = $v[$cid]
                $f.State | Should -Be 'NotApplicable' -Because $cid
                $f.Detail | Should -Match '^Licensing was not collected; not assessed\. Reason recorded by the collector: subscribedSkus query failed' -Because $cid
                $f.Detail | Should -Not -Match 'licenses detected|No Copilot SKUs|not applicable here' -Because $cid
                [string]$f.FrameworkIds | Should -Not -BeNullOrEmpty -Because "$cid keeps its citations"
            }
        }
        It 'is filed by the scope classifier as collection incomplete' {
            $null = Run-Collector
            $null = AllVerdicts
            $sc = Scope
            foreach ($cid in 'PPL-3.1', 'PPL-3.2', 'PPL-3.3', 'PPL-3.5') { (Bucket $sc $cid) | Should -Be 'CollectionIncomplete' -Because $cid }
        }
    }

    Context 'Successful reads' {
        It 'a collected subscription list with no recognized Copilot SKU is "no recognized SKU", not "no Copilot", and is not applicable to the tenant' {
            Set-Scenario @((Sku $script:BpSku 'SPB' 25 20)) @{ $script:UsersFirst = @{ Users = @((User 'u1' @($script:BpSku))) } }
            $r = Run-Collector
            $r.Data.SectionStatus.Licensing | Should -Be 'Collected'
            $r.Data.LicensingMeasurements.RecognizedSkuCount.Value | Should -Be 0
            $r.Data.LicensingMeasurements.RecognizedSkuCount.Completeness | Should -Be 'Complete'
            (State $r).RecognizedSku | Should -Be 'None'
            $v = AllVerdicts
            foreach ($cid in $v.Keys) {
                $v[$cid].State | Should -Be 'NotApplicable'
                $v[$cid].Detail | Should -Match 'holds no subscription that this tool recognizes as Microsoft Copilot'
                $v[$cid].Detail | Should -Match $script:ChatWords -Because 'eligible Copilot Chat access without a paid add-on is stated, with its eligibility'
                $v[$cid].Detail | Should -Match 'does not show that AI tools are absent or unused'
            }
            $sc = Scope
            foreach ($cid in 'PPL-3.1', 'PPL-3.2', 'PPL-3.3', 'PPL-3.5') { (Bucket $sc $cid) | Should -Be 'NotApplicableToTenant' -Because "$cid was read and does not apply; it is not a collection gap" }
        }
        It 'a recognized SKU with purchased seats and an explicit zero from a complete enumeration is NoneAssigned, capacity kept apart' {
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 10 0)) @{ $script:UsersFirst = @{ Users = @((User 'u1'), (User 'u2')) } }
            $r = Run-Collector
            $m = $r.Data.LicensingMeasurements
            $m.PurchasedSeats.Value | Should -Be 10; $m.PurchasedSeats.Kind | Should -Be 'PurchasedCapacity'
            $m.SkuConsumedUnits.Value | Should -Be 0; $m.SkuConsumedUnits.Kind | Should -Be 'SkuAssignments'
            $m.AssignedUsers.Value | Should -Be 0; $m.AssignedUsers.Completeness | Should -Be 'Complete'
            $s = State $r
            $s.Assignment | Should -Be 'NoneAssigned'; $s.AssignmentEvidence | Should -Be 'EnumeratedUsers'
            (Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').Detail | Should -Match 'present but no seat is assigned \(a complete enumeration'
        }
        It 'multiple SKUs: consumed units are not a unique-user count, and the ratio uses enabled members on both sides' {
            # u1 holds both SKUs, u2-u5 hold SKU 1, u6 is disabled and holds SKU 2; m1-m4 hold none.
            $users = @((User 'u1' @($script:CopilotSku, $script:CopilotSku2)), (User 'u2' @($script:CopilotSku)), (User 'u3' @($script:CopilotSku)),
                (User 'u4' @($script:CopilotSku)), (User 'u5' @($script:CopilotSku)), (User 'u6' @($script:CopilotSku2) -Enabled $false),
                (User 'm1'), (User 'm2'), (User 'm3'), (User 'm4'), (User 'g1' @($script:CopilotSku) -Type 'Guest'))
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 10 6), (Sku $script:CopilotSku2 'Microsoft_365_Copilot_Addon' 4 2)) @{ $script:UsersFirst = @{ Users = $users } }
            $r = Run-Collector
            $m = $r.Data.LicensingMeasurements
            $m.SkuConsumedUnits.Value | Should -Be 8 -Because 'per-SKU assignments summed: u1 counts twice'
            $m.PurchasedSeats.Value | Should -Be 14
            $m.AssignedUsers.Value | Should -Be 7 -Because 'unique accounts holding a recognized SKU, guest and disabled included'
            $m.AssignedEnabledMembers.Value | Should -Be 5
            $m.EnabledMembers.Value | Should -Be 9
            $r.Data.CopilotLicensedUserCount | Should -Be 7 -Because 'the compatibility field is the unique holder count, never the consumed-unit sum'
            $r.Data.TotalUserCount | Should -Be 9
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'Satisfied' -Because '5 of 9 is under the unchanged 95% threshold'
            $f.CurrentValue | Should -Match '^5 of 9 enabled member account\(s\) hold a Copilot seat'
            (Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').Detail | Should -Match 'Copilot is licensed to 7 account\(s\)'
        }
    }

    Context 'Incomplete user enumeration' {
        It 'a page cap leaves the enumeration Truncated, coverage Partial, counts incomplete and PPL-3.3 not assessed' {
            $pages = @{}
            $url = $script:UsersFirst
            for ($i = 1; $i -le 201; $i++) { $nextUrl = "https://graph.microsoft.com/v1.0/users?page=$($i + 1)"; $pages[$url] = @{ Users = @((User "u$i" @($script:CopilotSku))); Next = $nextUrl }; $url = $nextUrl }
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 500 300)) $pages
            $r = Run-Collector
            $r.Data.SectionStatus.Users | Should -Be 'Truncated'
            $r.Data.UserEnumeration.StopReason | Should -Be 'PageCap'
            $r.Data.UserEnumeration.PagesRead | Should -Be 200
            (Get-TPCoverage)['M365Copilot'].Status | Should -Be 'Partial' -Because 'a truncated enumeration is incomplete coverage even with no endpoint error'
            $r.Data.LicensingMeasurements.EnabledMembers.Completeness | Should -Be 'Incomplete'
            $r.Data.LicensingMeasurements.AssignedUsers.Value | Should -Be 200
            $r.Data.LicensingMeasurements.AssignedUsers.Completeness | Should -Be 'Incomplete'
            $r.Data.TotalUserCount | Should -BeNullOrEmpty; $r.Data.CopilotLicensedUserCount | Should -BeNullOrEmpty
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'did not complete .*page cap.*not assessed'
            (Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').Detail | Should -Match 'licensed to at least 200 account\(s\) \(the user enumeration did not complete\)'
        }
        It 'a repeating next link stops the enumeration as Truncated, not as a complete read' {
            $loop = 'https://graph.microsoft.com/v1.0/users?page=2'
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 5 1)) @{ $script:UsersFirst = @{ Users = @((User 'u1' @($script:CopilotSku))); Next = $loop }; $loop = @{ Users = @((User 'u2')); Next = $loop } }
            $r = Run-Collector
            $r.Data.SectionStatus.Users | Should -Be 'Truncated'
            $r.Data.UserEnumeration.StopReason | Should -Be 'RepeatedNextLink'
            (Get-TPCoverage)['M365Copilot'].Status | Should -Be 'Partial'
            (Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3').State | Should -Be 'NotApplicable'
        }
        It 'a failure after partial retrieval keeps the rows read as an incomplete count and says so' {
            $p2 = 'https://graph.microsoft.com/v1.0/users?page=2'
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 'omit' 'omit')) @{ $script:UsersFirst = @{ Users = @((User 'u1' @($script:CopilotSku)), (User 'u2' @($script:CopilotSku)), (User 'u3')); Next = $p2 }; $p2 = 'throw' }
            $r = Run-Collector
            $r.Data.SectionStatus.Users | Should -Be 'Failed'
            $r.Data.UserEnumeration.PagesRead | Should -Be 1
            $r.Data.SectionErrors['Users'] | Should -Match 'after 3 account\(s\) on 1 page\(s\) were read'
            $r.Data.LicensingMeasurements.EnabledMembers.Value | Should -Be 3
            $r.Data.LicensingMeasurements.EnabledMembers.Completeness | Should -Be 'Incomplete'
            $r.Data.LicensingMeasurements.AssignedUsers.Value | Should -Be 2
            $r.Data.LicensingMeasurements.AssignedUsers.Completeness | Should -Be 'Incomplete'
            $r.Success | Should -BeTrue
            (Get-TPCoverage)['M365Copilot'].Status | Should -Be 'Partial'
            $s = State $r
            $s.Assignment | Should -Be 'Assigned'; $s.AssignedCount | Should -Be 2; $s.AssignedCountComplete | Should -BeFalse
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match '^Users was not collected; not assessed\. Reason recorded by the collector: users query failed'
        }
    }

    Context 'Assignment evidence: explicit zero versus unknown' {
        It 'a recognized SKU whose consumed units were not returned, with no user enumeration, is unknown and not assessed' {
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 10 'omit')) @{ $script:UsersFirst = 'throw' }
            $r = Run-Collector
            $r.Data.LicensingMeasurements.SkuConsumedUnits.Completeness | Should -Be 'NotRead'
            $r.Data.LicensedSkus[0].ConsumedUnits | Should -BeNullOrEmpty -Because 'an omitted field is not stored as 0'
            $s = State $r
            $s.RecognizedSku | Should -Be 'Present'; $s.Assignment | Should -Be 'Unknown'; $s.Reason | Should -Be 'AssignmentEvidenceMissing'
            $f = Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'whether any seat is assigned could not be determined.*not assessed'
            (Bucket (Scope) 'PPL-3.1') | Should -Be 'CollectionIncomplete'
        }
        It 'the same SKU reporting zero consumed units is an explicit zero: NoneAssigned from the SKU measurement' {
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 10 0)) @{ $script:UsersFirst = 'throw' }
            $r = Run-Collector
            $s = State $r
            $s.Assignment | Should -Be 'NoneAssigned'; $s.AssignmentEvidence | Should -Be 'SkuConsumedUnits'
            (Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').Detail | Should -Match 'its consumed units read zero'
        }
        It 'a complete enumeration with no holder beside consumed seats is a disagreement, not an answer' {
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 10 3)) @{ $script:UsersFirst = @{ Users = @((User 'u1')) } }
            $r = Run-Collector
            (State $r).Reason | Should -Be 'MeasurementsDisagree'
            (Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').State | Should -Be 'NotApplicable'
        }
        It 'a zero denominator is handled explicitly: seats held only by a disabled account give no ratio' {
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 2 1)) @{ $script:UsersFirst = @{ Users = @((User 'd1' @($script:CopilotSku) -Enabled $false)) } }
            $r = Run-Collector
            $s = State $r
            $s.Assignment | Should -Be 'Assigned'
            $s.Ratio.Available | Should -BeFalse; $s.Ratio.Reason | Should -Be 'ZeroDenominator'
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'counted no enabled member account'
        }
        It 'a complete denominator beside a numerator that was not recorded gives no ratio, never a default zero' {
            # A results file whose enabled-member count is complete but whose count of
            # enabled members holding a seat is absent (a damaged or hand-edited file):
            # the ratio needs both, so a missing numerator is not read as 0 of N.
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 10 2)) @{ $script:UsersFirst = @{ Users = @((User 'u1' @($script:CopilotSku)), (User 'u2' @($script:CopilotSku)), (User 'u3')) } }
            $r = Run-Collector
            $r.Data.LicensingMeasurements.Remove('AssignedEnabledMembers')
            & $script:Mod { Clear-TPState }
            Set-TPRawData -Key 'M365Copilot' -Data $r
            $s = State $r
            $s.Assignment | Should -Be 'Assigned'
            $s.Ratio.Available | Should -BeFalse; $s.Ratio.Reason | Should -Be 'AssignmentsNotEstablished'
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'NotApplicable'
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0
        }
        It 'both reads failing is a failed collector with no counts' {
            Set-Scenario 'throw' @{ $script:UsersFirst = 'throw' }
            $r = Run-Collector
            $r.Success | Should -BeFalse
            (Get-TPCoverage)['M365Copilot'].Status | Should -Be 'Failed'
            foreach ($k in $r.Data.LicensingMeasurements.Keys) { $r.Data.LicensingMeasurements[$k].Value | Should -BeNullOrEmpty -Because $k }
        }
    }

    Context 'Older results files (no recorded status)' {
        It 'a recorded positive count is kept as an observation with unknown completeness' {
            Set-TPRawData -Key 'M365Copilot' -Data (LegacyRaw @{ CopilotLicensedUserCount = 5; TotalUserCount = 50 })
            $s = State (Get-TPRawData -Key 'M365Copilot')
            $s.Basis | Should -Be 'Legacy'; $s.Assignment | Should -Be 'Assigned'; $s.AssignedCount | Should -Be 5; $s.AssignedCountComplete | Should -BeFalse
            (Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').Detail | Should -Match 'recorded as licensed to 5 account\(s\) \(completeness not recorded\)'
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'NotApplicable' -Because 'the ratio needs complete counts, which an older file cannot show'
            $f.Detail | Should -Match 'does not record whether the license and user reads completed'
        }
        It 'a recorded zero with no status is ambiguous: not assessed, never "no Copilot" (the ExchangeTruth shape without its status)' {
            Set-TPRawData -Key 'M365Copilot' -Data (LegacyRaw @{ CopilotLicensedUserCount = 0; TotalUserCount = 124; LicensedSkus = @('SPB') })
            $s = State (Get-TPRawData -Key 'M365Copilot')
            $s.Assignment | Should -Be 'Unknown'; $s.RecognizedSku | Should -Be 'Unknown'; $s.Reason | Should -Be 'StatusNotRecorded'
            foreach ($pair in @(@('Test-TPControlAICopilotLicensedOnly', 'PPL-3.3'), @('Test-TPControlAICopilotSensitivityLabels', 'PPL-3.1'))) {
                $f = Verdict $pair[0] $pair[1]
                $f.State | Should -Be 'NotApplicable'
                $f.Detail | Should -Match 'not assessed'
                $f.Detail | Should -Not -Match 'holds no subscription|no seat is assigned'
            }
        }
        It 'legacy SKU rows without assignment evidence prove a subscription, not zero assignments' {
            Set-TPRawData -Key 'M365Copilot' -Data (LegacyRaw @{ CopilotLicensedUserCount = 0; LicensedSkus = @(@{ SkuId = $script:CopilotSku; SkuPartNumber = 'M365_Copilot'; PrepaidUnits = 10; ConsumedUnits = 0 }) })
            $s = State (Get-TPRawData -Key 'M365Copilot')
            $s.RecognizedSku | Should -Be 'Present'; $s.Assignment | Should -Be 'Unknown' -Because 'the old collector wrote 0 whether or not anything was read'
            (Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').Detail | Should -Match 'not assessed'
        }
        It 'legacy SKU rows reporting consumed units are positive evidence' {
            Set-TPRawData -Key 'M365Copilot' -Data (LegacyRaw @{ LicensedSkus = @(@{ SkuId = $script:CopilotSku; SkuPartNumber = 'M365_Copilot'; ConsumedUnits = 4 }) })
            $s = State (Get-TPRawData -Key 'M365Copilot')
            $s.Assignment | Should -Be 'Assigned'; $s.AssignmentEvidence | Should -Be 'LegacySkuConsumedUnits'; $s.AssignedCount | Should -BeNullOrEmpty
        }
        It 'a legacy structured row naming another product is not Copilot evidence, whatever it consumed' {
            Set-TPRawData -Key 'M365Copilot' -Data (LegacyRaw @{ LicensedSkus = @(@{ SkuId = 'aaaaaaaa-0000-4000-8000-000000000001'; SkuPartNumber = 'SPB'; ConsumedUnits = 40 }) })
            $s = State (Get-TPRawData -Key 'M365Copilot')
            $s.RecognizedSku | Should -Be 'Unknown'; $s.Assignment | Should -Be 'Unknown'; $s.Reason | Should -Be 'StatusNotRecorded'
            (Verdict 'Test-TPControlAICopilotSensitivityLabels' 'PPL-3.1').State | Should -Be 'NotApplicable'
        }
        It 'a legacy structured row with no part number is not Copilot evidence' {
            Set-TPRawData -Key 'M365Copilot' -Data (LegacyRaw @{ LicensedSkus = @(@{ SkuId = $script:CopilotSku; ConsumedUnits = 3 }) })
            $s = State (Get-TPRawData -Key 'M365Copilot')
            $s.RecognizedSku | Should -Be 'Unknown'; $s.Assignment | Should -Be 'Unknown'
        }
        It 'reading a saved results file leaves its bytes unchanged' {
            $dir = Join-Path ([IO.Path]::GetTempPath()) ("tp-d1-" + [guid]::NewGuid().ToString('N'))
            $null = [IO.Directory]::CreateDirectory($dir)
            try {
                $file = Join-Path $dir 'legacy-results.json'
                ([ordered]@{ Metadata = @{ TenantId = '00000000-0000-4000-8000-0000000000d1' }; Findings = @(); RawData = @{ 'M365Copilot' = (LegacyRaw @{ CopilotLicensedUserCount = 0; TotalUserCount = 12; LicensedSkus = @() }) } } |
                    ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $file -Encoding utf8
                $before = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
                $saved = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json -Depth 20
                $s = State $saved.RawData.'M365Copilot'
                $s.Assignment | Should -Be 'Unknown'; $s.Reason | Should -Be 'StatusNotRecorded'
                (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash | Should -Be $before
            } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'Never-read denominator' {
        # PPL-3.3 needs the enabled-member count from a complete enumeration. Each
        # shape here has usable assignment evidence and no such count.
        It 'new format, user read failed before any row: no ratio, the recorded reason, cited, never 0 of 0' {
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 10 3)) @{ $script:UsersFirst = 'throw' }
            $r = Run-Collector
            $r.Data.SectionStatus.Users | Should -Be 'Failed'
            $r.Data.LicensingMeasurements.EnabledMembers.Value | Should -BeNullOrEmpty
            $r.Data.LicensingMeasurements.EnabledMembers.Completeness | Should -Be 'NotRead'
            $r.Data.TotalUserCount | Should -BeNullOrEmpty -Because 'no default denominator'
            $s = State $r
            $s.Assignment | Should -Be 'Assigned'; $s.AssignmentEvidence | Should -Be 'SkuConsumedUnits'
            $s.Ratio.Available | Should -BeFalse; $s.Ratio.Reason | Should -Be 'UsersNotComplete'
            $s.Ratio.Denominator | Should -BeNullOrEmpty
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Users was not collected; not assessed\. Reason recorded by the collector: users query failed'
            $f.Detail | Should -Not -Match '\b0 of\b'
            [string]$f.CurrentValue | Should -BeNullOrEmpty
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0
            (Bucket (Scope) 'PPL-3.3') | Should -Be 'CollectionIncomplete'
        }
        It 'new format, user section recorded NotRun: no ratio and not assessed' {
            $raw = [ordered]@{ CollectorId = 'M365Copilot'; Success = $true; Data = [ordered]@{
                    SectionStatus = [ordered]@{ Licensing = 'Collected'; Users = 'NotRun' }; SectionErrors = [ordered]@{}
                    LicensedSkus = @(@{ SkuId = $script:CopilotSku; SkuPartNumber = 'M365_Copilot'; ConsumedUnits = 3 })
                    LicensingMeasurements = [ordered]@{
                        RecognizedSkuCount = [ordered]@{ Value = 1; Completeness = 'Complete' }
                        SkuConsumedUnits   = [ordered]@{ Value = 3; Completeness = 'Complete' } }
                    CopilotLicensedUserCount = $null; TotalUserCount = $null } }
            Set-TPRawData -Key 'M365Copilot' -Data $raw
            $s = State $raw
            $s.Ratio.Available | Should -BeFalse; $s.Ratio.Reason | Should -Be 'UsersNotComplete'
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Users was not collected; not assessed\.'
            $f.Detail | Should -Not -Match '\b0 of\b'
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0
            (Bucket (Scope) 'PPL-3.3') | Should -Be 'CollectionIncomplete'
        }
        It 'legacy, no status, positive count and no or default-zero denominator: no ratio' -ForEach @(
            @{ Label = 'denominator absent'; Data = @{ CopilotLicensedUserCount = 5 } }
            @{ Label = 'denominator recorded as the old default 0'; Data = @{ CopilotLicensedUserCount = 5; TotalUserCount = 0 } }
        ) {
            Set-TPRawData -Key 'M365Copilot' -Data (LegacyRaw $Data)
            $s = State (Get-TPRawData -Key 'M365Copilot')
            $s.Assignment | Should -Be 'Assigned'
            $s.Ratio.Available | Should -BeFalse; $s.Ratio.Reason | Should -Be 'StatusNotRecorded'
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'does not record whether the license and user reads completed'
            $f.Detail | Should -Not -Match '\b0 of\b'
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0
            (Bucket (Scope) 'PPL-3.3') | Should -Be 'CollectionIncomplete'
        }
    }

    Context 'Population (PPL-3.3): one account once, enabled members on both sides' {
        It 'the corrected population changes the verdict: 11 holders of 10 members was Partial, 8 of 10 members is Satisfied' {
            # m1-m8 enabled members holding a seat, m9-m10 enabled members without one,
            # d1-d2 disabled holders, g1 a guest holder.
            $users = @(1..8 | ForEach-Object { User "m$_" @($script:CopilotSku) }) + @((User 'm9'), (User 'm10'),
                (User 'd1' @($script:CopilotSku) -Enabled $false), (User 'd2' @($script:CopilotSku) -Enabled $false),
                (User 'g1' @($script:CopilotSku) -Type 'Guest'))
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 20 11)) @{ $script:UsersFirst = @{ Users = $users } }
            $r = Run-Collector
            $m = $r.Data.LicensingMeasurements
            $m.AssignedUsers.Value | Should -Be 11 -Because 'every enumerated account holding a seat, guests and disabled included'
            $m.AssignedEnabledMembers.Value | Should -Be 8
            $m.EnabledMembers.Value | Should -Be 10
            $m.SkuConsumedUnits.Value | Should -Be 11
            # The population used before D1 (all holders over enabled members) is 1.1, at or above 0.95: Partial.
            ([double]$m.AssignedUsers.Value / [double]$m.EnabledMembers.Value) | Should -BeGreaterOrEqual 0.95
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'Satisfied' -Because '8 of 10 enabled members is under the unchanged threshold'
            $f.CurrentValue | Should -Match '^8 of 10 enabled member account\(s\)'
        }
        It 'a row Graph repeats is one account, and an account on two SKUs is one holder' {
            $p2 = 'https://graph.microsoft.com/v1.0/users?page=2'
            $u1 = User 'U1' @($script:CopilotSku, $script:CopilotSku2)
            $u1again = User 'u1' @($script:CopilotSku, $script:CopilotSku2)
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 5 1), (Sku $script:CopilotSku2 'Microsoft_365_Copilot_Addon' 5 1)) @{
                $script:UsersFirst = @{ Users = @($u1, (User 'u2')); Next = $p2 }; $p2 = @{ Users = @($u1again, (User 'u3')) } }
            $r = Run-Collector
            $r.Data.UserEnumeration.RowsRead | Should -Be 4
            $r.Data.UserEnumeration.DistinctAccounts | Should -Be 3
            $r.Data.UserEnumeration.DuplicateRows | Should -Be 1
            $m = $r.Data.LicensingMeasurements
            $m.AssignedUsers.Value | Should -Be 1; $m.AssignedEnabledMembers.Value | Should -Be 1
            $m.EnabledMembers.Value | Should -Be 3
            $m.SkuConsumedUnits.Value | Should -Be 2 -Because 'per-SKU assignments are a separate measurement'
            $r.Data.CopilotLicensedUserCount | Should -Be 1
            (Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3').CurrentValue | Should -Match '^1 of 3 '
        }
        It 'a row with no account id is left out and makes the counts incomplete' {
            $noId = [pscustomobject]@{ userType = 'Member'; accountEnabled = $true; assignedLicenses = @([pscustomobject]@{ skuId = $script:CopilotSku }) }
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 5 2)) @{ $script:UsersFirst = @{ Users = @((User 'u1' @($script:CopilotSku)), $noId, (User 'u2')) } }
            $r = Run-Collector
            $r.Data.UserEnumeration.RowsWithoutId | Should -Be 1
            $m = $r.Data.LicensingMeasurements
            $m.AssignedUsers.Completeness | Should -Be 'Incomplete'
            $m.EnabledMembers.Completeness | Should -Be 'Incomplete'
            $r.Data.CopilotLicensedUserCount | Should -BeNullOrEmpty; $r.Data.TotalUserCount | Should -BeNullOrEmpty
            (State $r).Ratio.Available | Should -BeFalse
            (Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3').State | Should -Be 'NotApplicable'
        }
        It 'an account whose accountEnabled was not returned is never assumed enabled' {
            $noFlag = [pscustomobject]@{ id = 'u3'; userType = 'Member'; assignedLicenses = @([pscustomobject]@{ skuId = $script:CopilotSku }) }
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 5 2)) @{ $script:UsersFirst = @{ Users = @((User 'u1' @($script:CopilotSku)), (User 'u2'), $noFlag) } }
            $r = Run-Collector
            $r.Data.UserEnumeration.AccountEnabledUnknown | Should -Be 1
            $m = $r.Data.LicensingMeasurements
            $m.AssignedUsers.Value | Should -Be 2; $m.AssignedUsers.Completeness | Should -Be 'Complete'
            $m.EnabledMembers.Value | Should -Be 2; $m.EnabledMembers.Completeness | Should -Be 'Incomplete'
            $m.AssignedEnabledMembers.Completeness | Should -Be 'Incomplete'
            $r.Data.TotalUserCount | Should -BeNullOrEmpty
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Not -Match '\b\d+ of \d+\b'
        }
    }

    Context 'Null compatibility through the results file' {
        It 'an incomplete run serialized and read back keeps null counts, never 0, and the same verdict' {
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 10 3)) @{ $script:UsersFirst = 'throw' }
            $r = Run-Collector
            # The entry point writes ConvertTo-Json -Depth 12 and -FromResults reads it back -AsHashtable.
            $json = @{ RawData = @{ 'M365Copilot' = $r } } | ConvertTo-Json -Depth 12
            $json | Should -Match '"CopilotLicensedUserCount":\s*null'
            $json | Should -Match '"TotalUserCount":\s*null'
            $back = ($json | ConvertFrom-Json -AsHashtable).RawData['M365Copilot']
            $back.Data.CopilotLicensedUserCount | Should -BeNullOrEmpty; $back.Data.TotalUserCount | Should -BeNullOrEmpty
            & $script:Mod { Clear-TPState }
            Set-TPRawData -Key 'M365Copilot' -Data $back
            $s = State $back
            $s.Ratio.Available | Should -BeFalse; $s.Ratio.Reason | Should -Be 'UsersNotComplete'
            (Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3').State | Should -Be 'NotApplicable'
        }
        It 'a complete run read back gives the same counts and verdict' {
            Set-Scenario @((Sku $script:CopilotSku 'M365_Copilot' 10 2)) @{ $script:UsersFirst = @{ Users = @((User 'u1' @($script:CopilotSku)), (User 'u2' @($script:CopilotSku)), (User 'u3'), (User 'u4'), (User 'u5')) } }
            $r = Run-Collector
            $back = ((@{ RawData = @{ 'M365Copilot' = $r } } | ConvertTo-Json -Depth 12) | ConvertFrom-Json -AsHashtable).RawData['M365Copilot']
            & $script:Mod { Clear-TPState }
            Set-TPRawData -Key 'M365Copilot' -Data $back
            $back.Data.CopilotLicensedUserCount | Should -Be 2; $back.Data.TotalUserCount | Should -Be 5
            $f = Verdict 'Test-TPControlAICopilotLicensedOnly' 'PPL-3.3'
            $f.State | Should -Be 'Satisfied'; $f.CurrentValue | Should -Match '^2 of 5 '
        }
        It 'only the collector and the licensing helper touch the compatibility counts in shipped code' {
            $allowed = @('Invoke-TPCollectM365Copilot.ps1', 'Get-TPCopilotLicensingState.ps1')
            $hits = @(Get-ChildItem -Path $script:RepoRoot -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1', '*.py', '*.js' |
                Where-Object { $_.FullName -notmatch '[\\/](Testing|\.git)[\\/]' -and $allowed -notcontains $_.Name } |
                Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match 'CopilotLicensedUserCount|TotalUserCount' } |
                ForEach-Object { $_.FullName.Substring($script:RepoRoot.Length) })
            $hits | Should -BeNullOrEmpty -Because 'a new consumer must handle the null contract deliberately and be added here'
        }
    }

    Context 'Static guards' {
        It 'no evaluator reads the compatibility counts directly' {
            foreach ($file in Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'Evaluators') -Filter '*.ps1') {
                $text = Get-Content -LiteralPath $file.FullName -Raw
                $text | Should -Not -Match 'CopilotLicensedUserCount|TotalUserCount' -Because "$($file.Name) must read Copilot seats through Get-TPCopilotLicensingState"
            }
        }
        It 'the Copilot Chat sentence is eligibility-qualified and carries none of the scope classifier''s collection-gap words' {
            $note = & $script:Mod { Get-TPCopilotChatEligibilityNote }
            $note | Should -Match 'eligible Microsoft 365 subscription'
            $note | Should -Not -Match 'free|every user|all users'
            $note | Should -Not -Match 'not collected|did not complete|did not run|not assessed|unavailable|could not be|not available|not read\b|not returned'
        }
    }
}

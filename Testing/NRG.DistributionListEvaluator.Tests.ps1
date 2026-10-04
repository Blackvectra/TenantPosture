#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.DistributionListEvaluator.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Pins the DL-* series (Test-NRGControlDistributionLists), the recommendation catalog
             it reads (Config/distribution-list-baseline.json) and the NRG standards it is
             gated by (Config/nrg-standards.json). The rules, each a past failure of this tool:
               * missing evidence is NotApplicable, never Satisfied;
               * a setting that is NRG's own judgment is judged only against an APPROVED
                 value, and an empty standard means "not assessed", never met;
               * every finding says what was read and what was not, and carries its
                 Microsoft source and NIST mapping (or says no framework item was verified);
               * the NIST ids are the tool's mapping, every one exists in the Rev 5 catalog,
                 and no CIS or SCuBA identifier is invented.
    Data keys consumed: EXO-DistributionLists.  Graph scopes / cmdlets: none.
#>

Describe 'DL-* evaluator, catalog and standards' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        $script:Baseline = Get-NRGDistributionListBaseline
        $script:BaselineRaw = Get-Content -LiteralPath (Join-Path $script:Root 'Config/distribution-list-baseline.json') -Raw -Encoding utf8 | ConvertFrom-Json

        # A list record in the shape the collector emits, with everything compliant unless overridden.
        $script:L = { param([hashtable] $o = @{})
            $d = [ordered]@{ Name = 'x'; DisplayName = 'X'; PrimarySmtpAddress = 'x@contoso.com'; Guid = '11111111-1111-1111-1111-111111111111'; ListType = 'Distribution'
                RecipientTypeDetails = 'MailUniversalDistributionGroup'; IsDirSynced = $false; RecipientFilter = ''; Owners = @('Alice'); RequireSenderAuthenticationEnabled = $true
                AcceptMessagesOnlyFrom = @(); AcceptMessagesOnlyFromDLMembers = @(); AcceptMessagesOnlyFromSendersOrMembers = @(); ModerationEnabled = $false; ModeratedBy = @()
                MemberJoinRestriction = 'Closed'; MemberDepartRestriction = 'Open'; HiddenFromAddressListsEnabled = $false; PropertiesNotReturned = @()
                MemberStatus = 'Collected'; MemberCount = 3; MembersTruncated = $false; MemberError = ''; Members = @(); ExternalMembers = @(); NestedGroups = @(); UnclassifiedMemberCount = 0 }
            foreach ($k in $o.Keys) { $d[$k] = $o[$k] }
            [pscustomobject]$d }
        $script:Sec = { param([hashtable] $o = @{}) $s = @{ DistributionGroups = 'Collected'; DynamicDistributionGroups = 'Collected'; AcceptedDomains = 'Collected'; Members = 'Collected' }; foreach ($k in $o.Keys) { $s[$k] = $o[$k] }; $s }
        $script:Std = { param([hashtable] $o = @{})
            $raw = [ordered]@{ DistributionListMaxMembers = @(); DistributionListAllowedJoinRestrictions = @(); DistributionListAllowedDepartRestrictions = @(); DistributionListExternalMembers = @() }
            foreach ($k in $o.Keys) { $raw[$k] = $o[$k] }
            Get-NRGDistributionListStandards -Standards $raw }
        # Runs the evaluator on one list and returns that list's finding for one control.
        $script:Eval = { param($List, [string] $Id, $Standards = $null, [hashtable] $Sections = @{})
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data @{ CollectorId = 'EXO-DistributionLists'; CollectedAt = (Get-Date).ToString('o'); Success = $true
                Data = @{ Lists = @($List); SectionStatus = (& $script:Sec $Sections); Stats = @{ MemberReadLimit = 5000 } } }
            if ($null -eq $Standards) { $Standards = & $script:Std }
            Test-NRGControlDistributionLists -Standards $Standards
            @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Id -and $_.Instance -ne '(scan)' })[0] }
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-NRGState }

    Context 'DL-1.1 external senders (RequireSenderAuthenticationEnabled)' {
        It 'True -> Satisfied' { (& $script:Eval (& $script:L) 'DL-1.1').State | Should -Be 'Satisfied' }
        It 'False with no sender restriction at all -> Gap, High: accepts mail from anyone' {
            $f = & $script:Eval (& $script:L @{ RequireSenderAuthenticationEnabled = $false }) 'DL-1.1'
            $f.State | Should -Be 'Gap'; $f.Severity | Should -Be 'High'
            $f.Detail | Should -Match 'accepts mail from anyone'
        }
        It 'False but restricted to named senders -> Partial (not Gap), and the same sender in two properties is counted once' {
            $f = & $script:Eval (& $script:L @{ RequireSenderAuthenticationEnabled = $false; AcceptMessagesOnlyFrom = @('Carol'); AcceptMessagesOnlyFromSendersOrMembers = @('Carol') }) 'DL-1.1'
            $f.State | Should -Be 'Partial'
            $f.Detail | Should -Match 'only from the 1 sender\(s\)'
        }
        It 'omitted RequireSenderAuthenticationEnabled -> NotApplicable, never Satisfied' {
            $f = & $script:Eval (& $script:L @{ RequireSenderAuthenticationEnabled = $null; PropertiesNotReturned = @('RequireSenderAuthenticationEnabled') }) 'DL-1.1'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'was not returned'
        }
        It 'False with the allow-list properties not read -> NotApplicable: "no restriction" cannot be claimed from unread data' {
            $f = & $script:Eval (& $script:L @{ RequireSenderAuthenticationEnabled = $false; AcceptMessagesOnlyFrom = $null; AcceptMessagesOnlyFromDLMembers = $null; AcceptMessagesOnlyFromSendersOrMembers = $null }) 'DL-1.1'
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'could not be read'
        }
        It 'a dynamic list is judged by the same rule' {
            (& $script:Eval (& $script:L @{ ListType = 'Dynamic'; RequireSenderAuthenticationEnabled = $false }) 'DL-1.1').State | Should -Be 'Gap'
        }
    }

    Context 'DL-1.2 owner' {
        It 'an empty ManagedBy -> Gap' { (& $script:Eval (& $script:L @{ Owners = @() }) 'DL-1.2').State | Should -Be 'Gap' }
        It 'an owner named -> Satisfied, and it says it did not check the owner is active' {
            $f = & $script:Eval (& $script:L) 'DL-1.2'
            $f.State | Should -Be 'Satisfied'; $f.Detail | Should -Match 'current, active account'
        }
        It 'ManagedBy omitted -> NotApplicable, never a Gap and never Satisfied' {
            $f = & $script:Eval (& $script:L @{ Owners = $null }) 'DL-1.2'
            $f.State | Should -Be 'NotApplicable'
        }
        It 'a directory-synced ownerless list says to fix it where the list is mastered' {
            (& $script:Eval (& $script:L @{ Owners = @(); IsDirSynced = $true }) 'DL-1.2').Detail | Should -Match 'directory-synced'
        }
    }

    Context 'DL-1.3 moderation has an approver' {
        It 'moderation off -> NotApplicable, reported only' {
            $f = & $script:Eval (& $script:L) 'DL-1.3'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'reported only'
        }
        It 'on with a moderator -> Satisfied' { (& $script:Eval (& $script:L @{ ModerationEnabled = $true; ModeratedBy = @('Mod') }) 'DL-1.3').State | Should -Be 'Satisfied' }
        It 'on with no moderator but an owner -> Satisfied (Microsoft: the owners approve)' {
            $f = & $script:Eval (& $script:L @{ ModerationEnabled = $true; ModeratedBy = @() }) 'DL-1.3'
            $f.State | Should -Be 'Satisfied'; $f.Detail | Should -Match 'owner\(s\) for approval'
        }
        It 'on with neither moderator nor owner -> Gap' { (& $script:Eval (& $script:L @{ ModerationEnabled = $true; ModeratedBy = @(); Owners = @() }) 'DL-1.3').State | Should -Be 'Gap' }
        It 'on, owners not read -> NotApplicable' { (& $script:Eval (& $script:L @{ ModerationEnabled = $true; ModeratedBy = @(); Owners = $null }) 'DL-1.3').State | Should -Be 'NotApplicable' }
    }

    Context 'DL-1.4 / DL-1.5 join and leave: judged only against an approved NRG standard' {
        It 'with NO standard approved, every value (even Closed) is NotApplicable, "because none is approved", never Satisfied' {
            foreach ($v in 'Open', 'Closed', 'ApprovalRequired') {
                $f = & $script:Eval (& $script:L @{ MemberJoinRestriction = $v }) 'DL-1.4'
                $f.State | Should -Be 'NotApplicable' -Because "value $v with no approved standard"
                $f.Detail | Should -Match 'because none is approved'
                $f.Detail | Should -Match "MemberJoinRestriction is $v"
            }
        }
        It 'the not-approved text still states the Microsoft default so the reader has the documented baseline' {
            (& $script:Eval (& $script:L @{ MemberJoinRestriction = 'Open' }) 'DL-1.4').Detail | Should -Match 'default for universal distribution groups is Closed'
            (& $script:Eval (& $script:L) 'DL-1.5').Detail | Should -Match 'default for universal distribution groups is Open'
        }
        It 'with a standard approved: an accepted value is Satisfied, another is a Gap' {
            $std = & $script:Std @{ DistributionListAllowedJoinRestrictions = @('Closed', 'ApprovalRequired') }
            (& $script:Eval (& $script:L @{ MemberJoinRestriction = 'ApprovalRequired' }) 'DL-1.4' $std).State | Should -Be 'Satisfied'
            $g = & $script:Eval (& $script:L @{ MemberJoinRestriction = 'Open' }) 'DL-1.4' $std
            $g.State | Should -Be 'Gap'; $g.Detail | Should -Match 'accepts only Closed, ApprovalRequired'
        }
        It 'the leave setting is gated by its own standard' {
            $std = & $script:Std @{ DistributionListAllowedDepartRestrictions = @('Closed') }
            (& $script:Eval (& $script:L @{ MemberDepartRestriction = 'Open' }) 'DL-1.5' $std).State | Should -Be 'Gap'
            (& $script:Eval (& $script:L @{ MemberDepartRestriction = 'Closed' }) 'DL-1.5' $std).State | Should -Be 'Satisfied'
        }
        It 'a dynamic list has no join setting: Does not apply, never a pass' {
            $f = & $script:Eval (& $script:L @{ ListType = 'Dynamic'; MemberJoinRestriction = $null }) 'DL-1.4' (& $script:Std @{ DistributionListAllowedJoinRestrictions = @('Closed') })
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'does not apply to a Dynamic list'
        }
        It 'an omitted join setting -> NotApplicable even with a standard approved' {
            (& $script:Eval (& $script:L @{ MemberJoinRestriction = $null }) 'DL-1.4' (& $script:Std @{ DistributionListAllowedJoinRestrictions = @('Closed') })).State | Should -Be 'NotApplicable'
        }
    }

    Context 'DL-1.6 hidden: reported only' {
        It 'never a verdict, and says hiding does not stop mail' {
            $f = & $script:Eval (& $script:L @{ HiddenFromAddressListsEnabled = $true }) 'DL-1.6'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'reported only'; $f.Detail | Should -Match 'still send to the list'
        }
    }

    Context 'DL-2.1 member count: NRG cap' {
        It 'no cap approved -> NotApplicable "because none is approved", count still shown' {
            $f = & $script:Eval (& $script:L @{ MemberCount = 900 }) 'DL-2.1'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'because none is approved'; $f.Detail | Should -Match '900 direct member'
        }
        It 'a cap approved: over -> Gap, within -> Satisfied' {
            $std = & $script:Std @{ DistributionListMaxMembers = @('500') }
            (& $script:Eval (& $script:L @{ MemberCount = 501 }) 'DL-2.1' $std).State | Should -Be 'Gap'
            (& $script:Eval (& $script:L @{ MemberCount = 500 }) 'DL-2.1' $std).State | Should -Be 'Satisfied'
        }
        It 'a truncated list that is already over the cap is a Gap; a truncated one under the cap is NOT shown to comply' {
            $std = & $script:Std @{ DistributionListMaxMembers = @('5') }
            (& $script:Eval (& $script:L @{ MemberStatus = 'Truncated'; MembersTruncated = $true; MemberCount = 10 }) 'DL-2.1' $std).State | Should -Be 'Gap'
            $std2 = & $script:Std @{ DistributionListMaxMembers = @('50') }
            $f = & $script:Eval (& $script:L @{ MemberStatus = 'Truncated'; MembersTruncated = $true; MemberCount = 10 }) 'DL-2.1' $std2
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'cannot be shown to be within'
        }
        It 'a failed member read is NotApplicable, with the cause' {
            $f = & $script:Eval (& $script:L @{ MemberStatus = 'Failed'; MemberCount = $null; MemberError = 'throttled (429)' }) 'DL-2.1' (& $script:Std @{ DistributionListMaxMembers = @('5') })
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match '429'
        }
    }

    Context 'DL-2.2 external members: NRG standard' {
        BeforeAll { $script:Ext = @(@{ UPN = 'v@fabrikam.com'; DisplayName = 'Vendor' }) }
        It 'no standard approved -> NotApplicable; the external member is still NAMED (reported, not assessed)' {
            $f = & $script:Eval (& $script:L @{ ExternalMembers = $script:Ext }) 'DL-2.2'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'v@fabrikam.com'; $f.Detail | Should -Match 'because none is approved'
            @($f.AffectedObjects).Count | Should -Be 1
        }
        It 'Prohibited approved: an external member -> Gap with the member as the affected object' {
            $f = & $script:Eval (& $script:L @{ ExternalMembers = $script:Ext }) 'DL-2.2' (& $script:Std @{ DistributionListExternalMembers = @('Prohibited') })
            $f.State | Should -Be 'Gap'; @($f.AffectedObjects).Count | Should -Be 1
        }
        It 'Prohibited approved: none external and everything classified and fully read -> Satisfied' {
            (& $script:Eval (& $script:L) 'DL-2.2' (& $script:Std @{ DistributionListExternalMembers = @('Prohibited') })).State | Should -Be 'Satisfied'
        }
        It 'Prohibited approved: none found but the list was truncated -> NotApplicable, not a clean bill of health' {
            $f = & $script:Eval (& $script:L @{ MemberStatus = 'Truncated'; MembersTruncated = $true }) 'DL-2.2' (& $script:Std @{ DistributionListExternalMembers = @('Prohibited') })
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'read limit'
        }
        It 'Prohibited approved: unclassifiable members -> NotApplicable, never "no external members"' {
            $f = & $script:Eval (& $script:L @{ UnclassifiedMemberCount = 2 }) 'DL-2.2' (& $script:Std @{ DistributionListExternalMembers = @('Prohibited') })
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match '2 member\(s\) could not be classified'
        }
        It 'accepted domains not read -> NotApplicable even with the standard approved' {
            $f = & $script:Eval (& $script:L) 'DL-2.2' (& $script:Std @{ DistributionListExternalMembers = @('Prohibited') }) @{ AcceptedDomains = 'Failed' }
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'accepted domains were not read'
        }
        It 'members not read -> NotApplicable' {
            (& $script:Eval (& $script:L @{ MemberStatus = 'Failed'; MemberCount = $null }) 'DL-2.2' (& $script:Std @{ DistributionListExternalMembers = @('Prohibited') })).State | Should -Be 'NotApplicable'
        }
    }

    Context 'DL-2.3 nested groups: reported only' {
        It 'names the nested groups and says their members are not expanded' {
            $f = & $script:Eval (& $script:L @{ NestedGroups = @(@{ UPN = 'eng@contoso.com'; DisplayName = 'Eng' }) }) 'DL-2.3'
            $f.State | Should -Be 'NotApplicable'; $f.Detail | Should -Match 'eng@contoso.com'; $f.Detail | Should -Match 'not expanded'
        }
    }

    Context 'DL-0.1 the scan itself' {
        It 'no raw data -> a single NotApplicable "not assessed" and no list finding' {
            Clear-NRGState
            Test-NRGControlDistributionLists
            $all = @(Get-NRGFindings)
            $all.Count | Should -Be 1
            $all[0].ControlId | Should -Be 'DL-0.1'; $all[0].State | Should -Be 'NotApplicable'
        }
        It 'a collector that did not succeed -> the same' {
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data @{ Success = $false; Data = @{ Lists = @(); SectionStatus = @{} } }
            Test-NRGControlDistributionLists
            @(Get-NRGFindings).Count | Should -Be 1
            (Get-NRGFindings)[0].State | Should -Be 'NotApplicable'
        }
        It 'a failed list section is NotApplicable and names the section; an empty Lists array is not "no lists"' {
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data @{ Success = $true; Data = @{ Lists = @(); SectionStatus = (& $script:Sec @{ DistributionGroups = 'Failed' }); Stats = @{ MemberReadLimit = 5000 } } }
            Test-NRGControlDistributionLists
            $s = Get-NRGFindings | Where-Object ControlId -eq 'DL-0.1'
            $s.State | Should -Be 'NotApplicable'; $s.Detail | Should -Match 'were not read \(section Failed\)'
        }
        It 'every section collected -> Satisfied, and it still states the scope limits (Unified groups, nested members)' {
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data @{ Success = $true; Data = @{ Lists = @((& $script:L)); SectionStatus = (& $script:Sec); Stats = @{ MemberReadLimit = 5000 } } }
            Test-NRGControlDistributionLists
            $s = Get-NRGFindings | Where-Object ControlId -eq 'DL-0.1'
            $s.State | Should -Be 'Satisfied'; $s.Detail | Should -Match 'Unified'; $s.Detail | Should -Match 'nested group are not expanded'
        }
        It 'a truncated list makes the scan NotApplicable and names the limit' {
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data @{ Success = $true; Data = @{ Lists = @((& $script:L @{ MemberStatus = 'Truncated'; MembersTruncated = $true })); SectionStatus = (& $script:Sec); Stats = @{ MemberReadLimit = 7 } } }
            Test-NRGControlDistributionLists
            $s = Get-NRGFindings | Where-Object ControlId -eq 'DL-0.1'
            $s.State | Should -Be 'NotApplicable'; $s.Detail | Should -Match '7-member read limit'
        }
    }

    Context 'Missing evidence is never a pass (the honesty guard)' {
        It 'a list with EVERY property omitted and the members unread yields only NotApplicable findings, from every rule' {
            $bare = & $script:L @{ Owners = $null; RequireSenderAuthenticationEnabled = $null; AcceptMessagesOnlyFrom = $null; AcceptMessagesOnlyFromDLMembers = $null; AcceptMessagesOnlyFromSendersOrMembers = $null
                ModerationEnabled = $null; ModeratedBy = $null; MemberJoinRestriction = $null; MemberDepartRestriction = $null; HiddenFromAddressListsEnabled = $null
                MemberStatus = 'Failed'; MemberCount = $null; MemberError = 'down' }
            $everything = & $script:Std @{ DistributionListMaxMembers = @('5'); DistributionListAllowedJoinRestrictions = @('Closed'); DistributionListAllowedDepartRestrictions = @('Closed'); DistributionListExternalMembers = @('Prohibited') }
            $null = & $script:Eval $bare 'DL-1.1' $everything @{ Members = 'Failed' }
            $states = @(Get-NRGFindings | Where-Object { $_.Instance -ne '(scan)' } | ForEach-Object { "$($_.ControlId)=$($_.State)" })
            $states.Count | Should -Be (@($script:Baseline.Recommendations).Count)
            @($states | Where-Object { $_ -notmatch '=NotApplicable$' }) | Should -BeNullOrEmpty -Because 'no data means no verdict, even with every NRG standard approved'
        }
        It 'every catalog recommendation has an evaluator rule (none falls through to "no evaluator rule exists")' {
            $null = & $script:Eval (& $script:L) 'DL-1.1'
            @(Get-NRGFindings | Where-Object Detail -Match 'no evaluator rule exists').Count | Should -Be 0
        }
        It 'a missing catalog yields no list findings and an exception, never a pass' {
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data @{ Success = $true; Data = @{ Lists = @((& $script:L)); SectionStatus = (& $script:Sec); Stats = @{} } }
            Test-NRGControlDistributionLists -Baseline ([ordered]@{ Available = $false; Recommendations = @() }) -Standards (& $script:Std)
            @(Get-NRGFindings).Count | Should -Be 0
            @(Get-NRGExceptions | Where-Object Source -eq 'DL-Evaluator').Count | Should -Be 1
        }
    }

    Context 'Every finding states what was read and not read, and carries its citation' {
        BeforeAll {
            $script:AllStates = @(
                (& $script:L @{ RequireSenderAuthenticationEnabled = $false; Owners = @(); ModerationEnabled = $true; ModeratedBy = @(); MemberJoinRestriction = 'Open'; ExternalMembers = @(@{ UPN = 'v@fabrikam.com'; DisplayName = 'V' }); NestedGroups = @(@{ UPN = 'g@contoso.com'; DisplayName = 'G' }) }))
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data @{ Success = $true; Data = @{ Lists = $script:AllStates; SectionStatus = (& $script:Sec); Stats = @{ MemberReadLimit = 5000 } } }
            Test-NRGControlDistributionLists -Standards (& $script:Std @{ DistributionListMaxMembers = @('1'); DistributionListAllowedJoinRestrictions = @('Closed'); DistributionListAllowedDepartRestrictions = @('Closed'); DistributionListExternalMembers = @('Prohibited') })
            $script:Fs = @(Get-NRGFindings)
        }
        It 'every finding Detail contains "Read:" and "Not read:"' {
            foreach ($f in $script:Fs) { $f.Detail | Should -Match 'Read: .* Not read: ' -Because "$($f.ControlId) $($f.Instance)" }
        }
        It 'every finding Detail carries the catalog source URL' {
            foreach ($f in $script:Fs) { $f.Detail | Should -Match 'Source: https://learn\.microsoft\.com/' -Because $f.ControlId }
        }
        It 'a mapped finding carries NIST: FrameworkIds and labels the mapping as the tool''s; an unmapped one says no framework item was verified' {
            foreach ($rec in $script:Baseline.Recommendations) {
                $f = $script:Fs | Where-Object { $_.ControlId -eq $rec.Id } | Select-Object -First 1
                if (@($rec.Nist80053).Count -gt 0) {
                    @($f.FrameworkIds) | Should -Be @($rec.Nist80053 | ForEach-Object { "NIST:$_" }) -Because $rec.Id
                    $f.Detail | Should -Match "this tool's mapping, not NIST text" -Because $rec.Id
                } else {
                    @($f.FrameworkIds).Count | Should -Be 0 -Because $rec.Id
                    $f.Detail | Should -Match 'no framework item verified' -Because $rec.Id
                }
            }
        }
        It 'mapped NIST ids appear with their official Rev 5 titles' {
            ($script:Fs | Where-Object ControlId -eq 'DL-1.1' | Select-Object -First 1).Detail | Should -Match 'AC-3 Access Enforcement; SC-7 Boundary Protection; SI-8 Spam Protection'
        }
        It 'the findings are NOT baseline controls: no DL id exists in controls.json' {
            $ids = @((Get-Content -LiteralPath (Join-Path $script:Root 'Config/controls.json') -Raw | ConvertFrom-Json).controls.ControlId)
            @($ids | Where-Object { $_ -like 'DL-*' }).Count | Should -Be 0
        }
    }

    Context 'Catalog integrity (mirrors Config/conditional-access-baseline.json)' {
        It 'has the DL-1.1..DL-2.3 recommendations with unique ids' {
            $ids = @($script:Baseline.Recommendations.Id)
            $ids.Count | Should -BeGreaterThan 7
            ($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
            foreach ($i in $ids) { $i | Should -Match '^DL-\d+\.\d+$' }
        }
        It 'every SourceUrl and AlsoSee is a learn.microsoft.com link' {
            foreach ($r in $script:Baseline.Recommendations) {
                $r.SourceUrl | Should -Match '^https://learn\.microsoft\.com/' -Because $r.Id
                foreach ($u in @($r.AlsoSee)) { $u | Should -Match '^https://learn\.microsoft\.com/' -Because $r.Id }
            }
        }
        It 'every cited NIST id exists in Config/nist-800-53-catalog.json (so it prints with an official Rev 5 title)' {
            $cat = Get-Content -LiteralPath (Join-Path $script:Root 'Config/nist-800-53-catalog.json') -Raw -Encoding utf8 | ConvertFrom-Json
            foreach ($r in $script:Baseline.Recommendations) {
                foreach ($n in @($r.Nist80053)) {
                    $cat.controls.PSObject.Properties[$n] | Should -Not -BeNullOrEmpty -Because "$($r.Id) cites $n"
                    (Get-NRGNISTControlTitle -ControlId $n) | Should -Not -BeNullOrEmpty
                }
            }
        }
        It 'a mapping is labeled as the tool''s mapping; an unmapped recommendation says no framework item was verified' {
            foreach ($r in $script:Baseline.Recommendations) {
                if (@($r.Nist80053).Count -gt 0) { $r.NistMappingNote | Should -Match 'Tool mapping, not NIST text' -Because $r.Id }
                else { $r.NistMappingNote | Should -Match 'No framework item verified' -Because $r.Id }
            }
        }
        It 'invents no CIS benchmark number and no SCuBA rule id anywhere in the catalog' {
            $raw = Get-Content -LiteralPath (Join-Path $script:Root 'Config/distribution-list-baseline.json') -Raw
            $raw | Should -Not -Match 'MS\.[A-Z]+\.\d' -Because 'a SCuBA policy id has that shape'
            $raw | Should -Not -Match '(?i)CIS[^"]{0,40}\b\d+\.\d+(\.\d+)?\b' -Because 'no CIS benchmark item was verified for distribution lists'
            $script:BaselineRaw.FrameworkCoverage.CIS_Microsoft_365_Foundations | Should -Match 'No CIS benchmark item'
            $script:BaselineRaw.FrameworkCoverage.CISA_SCuBA | Should -Match 'No SCuBA rule'
        }
        It 'a recommendation is Microsoft-sourced (default or guidance), an NRG standard, or has no recommendation; nothing else' {
            foreach ($r in $script:Baseline.Recommendations) { $r.RecommendedValueSource | Should -BeIn @('MicrosoftDefault', 'MicrosoftGuidance', 'NRGStandard', 'None') -Because $r.Id }
        }
        It 'every NRG-judgment recommendation names a StandardKey that exists in nrg-standards.json; no other one does' {
            $std = Get-Content -LiteralPath (Join-Path $script:Root 'Config/nrg-standards.json') -Raw | ConvertFrom-Json
            foreach ($r in $script:Baseline.Recommendations) {
                if ($r.RecommendedValueSource -eq 'NRGStandard') {
                    $r.StandardKey | Should -Not -BeNullOrEmpty -Because $r.Id
                    $std.PSObject.Properties[$r.StandardKey] | Should -Not -BeNullOrEmpty -Because "$($r.Id) -> $($r.StandardKey)"
                } else { $r.StandardKey | Should -BeNullOrEmpty -Because $r.Id }
            }
        }
        It 'every recommendation has a Why' { foreach ($r in $script:Baseline.Recommendations) { $r.Why.Length | Should -BeGreaterThan 40 -Because $r.Id } }
        It 'US spelling in the catalog' {
            $raw = Get-Content -LiteralPath (Join-Path $script:Root 'Config/distribution-list-baseline.json') -Raw
            $raw | Should -Not -Match '(?i)\b(organisation|behaviour|licence|authorised|unauthorised|colour|catalogue|analyse)\b'
        }
    }

    Context 'The NRG standards ship empty and are validated' {
        It 'the four DistributionList* lists exist in nrg-standards.json and are EMPTY (owner approval pending)' {
            $std = Get-Content -LiteralPath (Join-Path $script:Root 'Config/nrg-standards.json') -Raw | ConvertFrom-Json
            foreach ($k in 'DistributionListMaxMembers', 'DistributionListAllowedJoinRestrictions', 'DistributionListAllowedDepartRestrictions', 'DistributionListExternalMembers') {
                $std.PSObject.Properties[$k] | Should -Not -BeNullOrEmpty -Because $k
                @($std.$k.Values).Count | Should -Be 0 -Because "$k is NRG's judgment and ships empty until the owner approves it"
            }
        }
        It 'Get-NRGStandards returns the four DL keys' {
            $s = Get-NRGStandards -Path (Join-Path $script:Root 'Config' 'nrg-standards.json')
            foreach ($k in 'DistributionListMaxMembers', 'DistributionListAllowedJoinRestrictions', 'DistributionListAllowedDepartRestrictions', 'DistributionListExternalMembers') { $s.Contains($k) | Should -BeTrue }
        }
        It 'the shipped file means: nothing approved' {
            $p = Get-NRGDistributionListStandards -Standards (Get-NRGStandards -Path (Join-Path $script:Root 'Config' 'nrg-standards.json'))
            $null -eq $p.MaxMembers | Should -BeTrue
            @($p.AllowedJoin).Count | Should -Be 0; @($p.AllowedDepart).Count | Should -Be 0
            $p.ExternalMembersProhibited | Should -BeFalse
        }
        It 'a missing standards object means not approved, never a failure' {
            $p = Get-NRGDistributionListStandards -Standards ([ordered]@{})
            $null -eq $p.MaxMembers | Should -BeTrue
        }
        It 'parses an approved value and canonicalizes case' {
            $p = & $script:Std @{ DistributionListMaxMembers = @(' 250 '); DistributionListAllowedJoinRestrictions = @('closed', 'APPROVALREQUIRED', 'closed'); DistributionListAllowedDepartRestrictions = @('open'); DistributionListExternalMembers = @('prohibited') }
            $p.MaxMembers | Should -Be 250
            @($p.AllowedJoin) | Should -Be @('Closed', 'ApprovalRequired')
            @($p.AllowedDepart) | Should -Be @('Open')
            $p.ExternalMembersProhibited | Should -BeTrue
        }
        It 'drops an invalid value and says so, rather than guessing' {
            $p = & $script:Std @{ DistributionListMaxMembers = @('lots'); DistributionListAllowedJoinRestrictions = @('Wide open'); DistributionListExternalMembers = @('Allowed') }
            $null -eq $p.MaxMembers | Should -BeTrue
            @($p.AllowedJoin).Count | Should -Be 0
            $p.ExternalMembersProhibited | Should -BeFalse
            @($p.Notes).Count | Should -Be 3
        }
        It 'rejects a cap of zero, a negative number and a decimal' {
            foreach ($v in '0', '-5', '2.5', '1e3', '') { $null -eq (& $script:Std @{ DistributionListMaxMembers = @($v) }).MaxMembers | Should -BeTrue -Because "'$v'" }
        }
    }

    Context 'Command text: built as safe text, never run' {
        BeforeAll {
            $script:Rec = { param([string] $Id) $script:Baseline.Recommendations | Where-Object Id -eq $Id }
            $script:Cmd = { param([string] $Id, $List, $Std = $null) if ($null -eq $Std) { $Std = & $script:Std }; Get-NRGDistributionListFixCommand -Recommendation (& $script:Rec $Id) -List $List -Standards $Std }
        }
        It 'names the list by its address in a single-quoted literal' {
            & $script:Cmd 'DL-1.1' (& $script:L) | Should -Be "Set-DistributionGroup -Identity 'x@contoso.com' -RequireSenderAuthenticationEnabled `$true"
        }
        It 'a dynamic list gets the dynamic cmdlet; a recommendation with no dynamic form gets no command' {
            & $script:Cmd 'DL-1.1' (& $script:L @{ ListType = 'Dynamic' }) | Should -Match '^Set-DynamicDistributionGroup '
            & $script:Cmd 'DL-1.4' (& $script:L @{ ListType = 'Dynamic' }) (& $script:Std @{ DistributionListAllowedJoinRestrictions = @('Closed') }) | Should -BeNullOrEmpty
        }
        It 'a name that could break out of the quotes is never put in a command: it falls back to the GUID, then to a placeholder' {
            $evil = @("o'brien@contoso.com", "x@contoso.com'; Remove-Mailbox -Identity bob; '", "x@contoso.com`nRemove-Mailbox bob", ('x@contoso.com' + [char]0x2019 + '; calc; ' + [char]0x2018), 'a b@contoso.com', 'x@contoso.com $(calc)')
            foreach ($a in $evil) {
                $c = & $script:Cmd 'DL-1.1' (& $script:L @{ PrimarySmtpAddress = $a; Guid = '' })
                $c | Should -Match "^Set-DistributionGroup -Identity '<identify this list by its address or GUID>' " -Because "address: $a"
                $c | Should -Not -Match 'Remove-Mailbox|calc'
                $c | Should -Not -Match "`n"
            }
            & $script:Cmd 'DL-1.1' (& $script:L @{ PrimarySmtpAddress = "o'brien@contoso.com" }) | Should -Match "-Identity '11111111-1111-1111-1111-111111111111'"
        }
        It 'a typographic quote is doubled by the literal helper (PowerShell reads U+2018..U+201B as single quotes)' {
            # Built from code points: a typographic quote inside a quoted string literal would itself end the literal.
            $rsq = [string][char]0x2019; $lsq = [string][char]0x2018
            & $script:Mod { param($v) ConvertTo-NRGDlPsLiteral -Value $v } ("a${rsq}b") | Should -Be ("'a${rsq}${rsq}b'")
            & $script:Mod { param($v) ConvertTo-NRGDlPsLiteral -Value $v } ("${lsq}a") | Should -Be ("'${lsq}${lsq}a'")
            & $script:Mod { param($v) ConvertTo-NRGDlPsLiteral -Value $v } "a'b" | Should -Be "'a''b'"
            $null -eq (& $script:Mod { param($v) ConvertTo-NRGDlPsLiteral -Value $v } "a`nb") | Should -BeTrue
        }
        It '{Approved} is filled only from an approved standard and only with an allow-listed word' {
            & $script:Cmd 'DL-1.4' (& $script:L) | Should -BeNullOrEmpty -Because 'no standard approved, no command'
            & $script:Cmd 'DL-1.4' (& $script:L) (& $script:Std @{ DistributionListAllowedJoinRestrictions = @('ApprovalRequired', 'Closed') }) | Should -Match '-MemberJoinRestriction ApprovalRequired$'
            & $script:Cmd 'DL-1.4' (& $script:L) (& $script:Std @{ DistributionListAllowedJoinRestrictions = @('Open; Remove-Mailbox x') }) | Should -BeNullOrEmpty
        }
        It 'the catalog holds only these verbs and only these placeholders' {
            $r = Get-Content -LiteralPath (Join-Path $script:Root 'Config/distribution-list-baseline.json') -Raw | ConvertFrom-Json
            foreach ($rec in $r.Recommendations) {
                foreach ($c in @($rec.Commands.Distribution, $rec.Commands.Dynamic) | Where-Object { $_ }) {
                    $c | Should -Match '^(Set-(Dynamic)?DistributionGroup|Get-(Dynamic)?DistributionGroupMember|Remove-DistributionGroupMember) ' -Because "$($rec.Id): $c"
                    $c | Should -Not -Match '[;|&`]' -Because "$($rec.Id): a command is one statement"
                    $c | Should -Not -Match 'Invoke-Expression|\biex\b|Start-Process'
                    $left = ($c -replace '\{Identity\}|\{Approved\}', '' -replace "'<[a-z-]+>'", '' -replace '@\{Add=\}', '')
                    $left | Should -Not -Match '[{}<>]' -Because "$($rec.Id): only {Identity}, {Approved} and quoted <placeholder> values are allowed"
                }
            }
        }
    }


    Context 'Structure: rules return verdicts, and the status is structural, not parsed from prose' {
        It 'a rule function returns a verdict and writes NO finding (verdicts are separate from emission)' {
            Clear-NRGState
            $v = & $script:Mod { param($l) $std = Get-NRGDistributionListStandards -Standards ([ordered]@{})
                $c = Get-NRGDlListContext -List $l -Standards $std -AcceptedDomainsSection 'Collected'
                Get-NRGDlVerdictOwner -Ctx $c } (& $script:L @{ Owners = @() })
            $v.State | Should -Be 'Gap'
            @(Get-NRGFindings).Count | Should -Be 0
        }
        It 'every NotApplicable list finding names its kind at the START of the Detail' {
            $bare = & $script:L @{ Owners = $null; RequireSenderAuthenticationEnabled = $null; ModerationEnabled = $null; HiddenFromAddressListsEnabled = $null; MemberJoinRestriction = $null; MemberDepartRestriction = $null; MemberStatus = 'Failed'; MemberCount = $null }
            $dyn = & $script:L @{ Name = 'd'; DisplayName = 'D'; PrimarySmtpAddress = 'd@contoso.com'; Guid = '22222222-2222-2222-2222-222222222222'; ListType = 'Dynamic'; MemberJoinRestriction = $null; MemberDepartRestriction = $null }
            $normal = & $script:L @{ Name = 'n'; DisplayName = 'N'; PrimarySmtpAddress = 'n@contoso.com'; Guid = '33333333-3333-3333-3333-333333333333' }
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data @{ Success = $true; Data = @{ Lists = @($bare, $dyn, $normal); SectionStatus = (& $script:Sec); Stats = @{ MemberReadLimit = 5000 } } }
            Test-NRGControlDistributionLists -Standards (& $script:Std)
            $na = @(Get-NRGFindings | Where-Object { $_.State -eq 'NotApplicable' -and $_.Instance -ne '(scan)' })
            $na.Count | Should -BeGreaterThan 10
            foreach ($f in $na) { (& $script:Mod { param($d) Get-NRGDlKindFromDetail -Detail $d } $f.Detail) | Should -Not -BeNullOrEmpty -Because "$($f.ControlId) $($f.Instance): $($f.Detail.Substring(0, 60))" }
            $kinds = @($na | ForEach-Object { & $script:Mod { param($d) Get-NRGDlKindFromDetail -Detail $d } $_.Detail } | Sort-Object -Unique)
            $kinds | Should -Contain 'Reported only'
            $kinds | Should -Contain 'Does not apply'
            $kinds | Should -Contain 'Not assessed'
            $kinds | Should -Contain 'Not assessed (no approved NRG standard)'
        }
        It 'the label is read only from the start: a list name, or other text, containing a label changes nothing' {
            $read = { param($d) & $script:Mod { param($x) Get-NRGDlKindFromDetail -Detail $x } $d }
            (& $read 'Reported only. List x: y') | Should -Be 'Reported only'
            (& $read 'Does not apply. List x: y') | Should -Be 'Does not apply'
            (& $read 'Not assessed. List x: y') | Should -Be 'Not assessed'
            (& $read 'Not assessed (no approved NRG standard). List x: y') | Should -Be 'Not assessed (no approved NRG standard)'
            (& $read "List 'Reported only. x' (Distribution): was not returned.") | Should -BeNullOrEmpty
            (& $read 'Not assessed in full: a section failed.') | Should -BeNullOrEmpty
            (& $read 'reported only. lower case') | Should -BeNullOrEmpty
            (& $read '') | Should -BeNullOrEmpty
        }
        It 'Format-NRGDlDetail writes the label that Get-NRGDlKindFromDetail reads back' {
            foreach ($k in 'NotAssessed', 'ReportedOnly', 'NoStandard', 'DoesNotApply') {
                $d = & $script:Mod { param($kind, $rec) Format-NRGDlDetail -Rec $rec -Lead 'List x: y.' -Kind $kind } $k $script:Baseline.Recommendations[0]
                (& $script:Mod { param($x) Get-NRGDlKindFromDetail -Detail $x } $d) | Should -Be (& $script:Mod { param($kind) $script:NRGDlKindLabels[$kind] } $k)
            }
        }
    }
}

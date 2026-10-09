#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.SignInHonesty.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: A sign-in triage conclusion states what it rests on. Failed or
             truncated reads make the result "not cleared", never "clean"; a
             Critical heuristic is "critical indicators", never a "confirmed
             compromise"; coverage is registered from what completed, not
             asserted before any query ran.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Sign-in triage — what a conclusion is allowed to claim' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Bag = { param([string] $Key, [bool] $Ok = $true, $Data = $null)
            @{ CollectorId = $Key; CollectedAt = (Get-Date).ToString('o'); Success = $Ok; Data = $(if ($Ok) { $Data } else { $null }) } }
        $script:AllOk = {
            Set-TPRawData -Key 'IR-SignIn-Recent' -Data (& $script:Bag 'IR-SignIn-Recent' $true @{ WindowDays = 7; Count = 4200; Truncated = $false; Events = @() })
            Set-TPRawData -Key 'IR-SignIn-AnonIp' -Data (& $script:Bag 'IR-SignIn-AnonIp' $true @{ Count = 0; Events = @() })
            Set-TPRawData -Key 'IR-SignIn-Travel' -Data (& $script:Bag 'IR-SignIn-Travel' $true @{ Count = 0; Events = @() })
        }
        $script:Meta = @{ TenantId = '00000000-0000-0000-0000-000000000000'; ConnectedAdmin = 'a@contoso.com'; WindowDays = 7; ToolVersion = '4.14.3'; AssessmentDate = 'September 30, 2026'; DeepDivedUsers = @() }
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-honesty-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        $script:Report = {
            param([hashtable] $Meta, [object[]] $Findings)
            $h = Join-Path $script:Tmp ([guid]::NewGuid().ToString('N') + '.html'); $m = [System.IO.Path]::ChangeExtension($h, '.md')
            Publish-TPSignInTriageReport -Metadata $Meta -Findings $Findings -RankedUsers @() -OutputPath $h -MarkdownPath $m | Out-Null
            [ordered]@{ Html = (Get-Content -LiteralPath $h -Raw); Md = (Get-Content -LiteralPath $m -Raw) }
        }
    }
    AfterAll {
        Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    BeforeEach { Clear-TPState; Clear-TPSignInTriageState }

    Context 'completeness' {
        It 'is complete only when Recent, AnonIp and Travel completed and the read was not truncated' {
            & $script:AllOk
            $c = Get-TPSignInCollectionCompleteness
            $c.Complete | Should -BeTrue
            $c.EventsRead | Should -Be 4200
            $c.WindowDays | Should -Be 7
        }
        It 'a failed read, or an absent one, is incomplete and named' {
            & $script:AllOk
            Set-TPRawData -Key 'IR-SignIn-AnonIp' -Data (& $script:Bag 'IR-SignIn-AnonIp' $false)
            $c = Get-TPSignInCollectionCompleteness
            $c.Complete | Should -BeFalse
            ($c.Reasons -join ' ') | Should -Match 'IR-SignIn-AnonIp did not complete'
            Clear-TPState
            (Get-TPSignInCollectionCompleteness).Complete | Should -BeFalse -Because 'no data at all is not a clean tenant'
        }
        It 'a read that hit its event cap is incomplete: older events in the window were not read' {
            & $script:AllOk
            Set-TPRawData -Key 'IR-SignIn-Recent' -Data (& $script:Bag 'IR-SignIn-Recent' $true @{ WindowDays = 7; Count = 5000; Truncated = $true; Events = @() })
            $c = Get-TPSignInCollectionCompleteness
            $c.Complete | Should -BeFalse
            ($c.Reasons -join ' ') | Should -Match 'stopped at 5000 events'
        }
        It 'RiskyUsers (Entra ID P2) is optional and never makes a read incomplete' {
            & $script:AllOk
            Set-TPRawData -Key 'IR-SignIn-RiskyUsers' -Data (& $script:Bag 'IR-SignIn-RiskyUsers' $false)
            (Get-TPSignInCollectionCompleteness).Complete | Should -BeTrue
        }
    }

    Context 'SIGNIN-2.1 with nothing scored' {
        It 'complete reads: Satisfied, worded as describing the events read, never "the tenant looks clean"' {
            & $script:AllOk
            Test-TPSignInControlRankUsers
            $f = @(Get-TPFindings | Where-Object { $_.ControlId -eq 'SIGNIN-2.1' })[0]
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match '4200 sign-in events read over the last 7 days'
            $f.Detail | Should -Not -Match 'looks clean'
        }
        It 'failed or truncated reads: not cleared, never Satisfied' {
            & $script:AllOk
            Set-TPRawData -Key 'IR-SignIn-Travel' -Data (& $script:Bag 'IR-SignIn-Travel' $false)
            Test-TPSignInControlRankUsers
            $f = @(Get-TPFindings | Where-Object { $_.ControlId -eq 'SIGNIN-2.1' })[0]
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Not cleared'
            $f.Detail | Should -Match 'not evidence that none occurred'
        }
    }

    Context 'report verdict' {
        It 'a Critical finding is "critical indicators", never a confirmed compromise, and says it is heuristic' {
            Add-TPFinding -ControlId 'SIGNIN-1.1' -State 'Gap' -Category 'Email' -Title 'Failed-then-success' -Severity 'Critical' -Detail 'A cluster of failures then a success.'
            $crit = @(Get-TPFindings)
            $r = & $script:Report ($script:Meta + @{ CollectionComplete = $true; CollectionGaps = @() }) $crit
            $r.Html | Should -Match 'CRITICAL INDICATORS'
            $r.Html | Should -Not -CMatch 'CONFIRMED COMPROMISE'
            $r.Md   | Should -Match 'Heuristic indicators, not a confirmed compromise'
            $r.Md   | Should -Not -CMatch 'CONFIRMED COMPROMISE'
        }
        It 'no findings with incomplete evidence is NOT CLEARED, not the green verdict' {
            $r = & $script:Report ($script:Meta + @{ CollectionComplete = $false; CollectionGaps = @('IR-SignIn-Recent did not complete') }) @()
            $r.Html | Should -Match 'NOT CLEARED'
            $r.Html | Should -Not -Match 'NO STRONG INDICATORS'
            $r.Md   | Should -Match 'Not cleared: IR-SignIn-Recent did not complete'
        }
        It 'no findings with complete evidence is the green verdict, scoped to the events read' {
            $r = & $script:Report ($script:Meta + @{ CollectionComplete = $true; CollectionGaps = @() }) @()
            $r.Md | Should -Match 'NO STRONG INDICATORS IN THE EVENTS READ'
            $r.Md | Should -Match 'not the whole tenant'
        }
        It 'a High finding stays a review verdict whether or not evidence is complete' {
            Add-TPFinding -ControlId 'SIGNIN-1.2' -State 'Gap' -Category 'Email' -Title 'Anonymous IP' -Severity 'High' -Detail 'A sign-in from an anonymizing IP.'
            $high = @(Get-TPFindings)
            (& $script:Report ($script:Meta + @{ CollectionComplete = $false; CollectionGaps = @('x') }) $high).Md | Should -Match 'SUSPECT ACTIVITY'
        }
        It 'an older metadata block with no completeness keys keeps its previous behavior' {
            (& $script:Report $script:Meta @()).Md | Should -Match 'NO STRONG INDICATORS IN THE EVENTS READ'
        }
    }

    Context 'collector coverage is registered from what completed' {
        BeforeAll {
            $script:Src = Get-Content -LiteralPath (Join-Path $script:Root 'Email-IR/Collectors/Invoke-TPEmailCollectSignIns.ps1') -Raw
        }
        It 'no coverage is asserted before a query runs' {
            $head = $script:Src.Substring(0, $script:Src.IndexOf('# ── Recent sign-ins'))
            $head | Should -Not -Match "Register-TPCoverage -Family 'Email-IR' -Status 'Collected'"
        }
        It 'registers Failed, Partial or Collected at the end, and records truncation on the recent bag' {
            $script:Src | Should -Match "Register-TPCoverage -Family 'Email-IR' -Status 'Failed'"
            $script:Src | Should -Match "Register-TPCoverage -Family 'Email-IR' -Status 'Partial'"
            $script:Src | Should -Match "Register-TPCoverage -Family 'Email-IR' -Status 'Collected'"
            $script:Src | Should -Match 'Truncated\s+=\s+\$wasTruncated'
        }
        It 'the entry point hands completeness to the report' {
            $entry = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPSignInTriage.ps1') -Raw
            $entry | Should -Match "reportMetadata\['CollectionComplete'\]"
            $entry | Should -Match 'Get-TPSignInCollectionCompleteness'
        }
    }
}

Describe 'Deep-dive findings say whose mailbox they describe and what they rest on' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:AllKeys = @('IR-MailboxProfile', 'IR-MailboxSentItems', 'IR-MailboxInbox', 'IR-MailboxRecoverable', 'IR-MailboxRules', 'IR-MailboxForwarding', 'IR-UserConsents', 'IR-UserAuthMethods')
        # One user's dive: read these keys, leave the others failed (as the entry point resets them).
        $script:Dive = {
            param([string[]] $Read)
            foreach ($k in $script:AllKeys) { Set-TPRawData -Key $k -Data @{ CollectorId = $k; Success = $false; Data = $null } }
            foreach ($k in $Read) { Set-TPRawData -Key $k -Data @{ CollectorId = $k; Success = $true; Data = @{ } } }
        }
        $script:Required = @('IR-MailboxProfile', 'IR-MailboxSentItems', 'IR-MailboxInbox', 'IR-MailboxRules')
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-subject-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
    }
    AfterAll {
        Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    BeforeEach { Clear-TPState }

    It 'two users'' findings are tagged with their own account and their own evidence, not each other''s' {
        $before = @(Get-TPFindings).Count
        & $script:Dive $script:Required
        Add-TPFinding -ControlId 'EMAIL-1.1' -State 'Gap' -Category 'Email' -Title 'Suspicious inbox rule' -Severity 'High' -Detail 'A rule deletes mail from finance.'
        $null = Set-TPFindingSubject -Since $before -Subject 'alice@corp.com' -Evidence (Get-TPDeepDiveEvidence)

        $before = @(Get-TPFindings).Count
        & $script:Dive @('IR-MailboxProfile', 'IR-MailboxSentItems')      # Bob's inbox and rules reads failed
        Add-TPFinding -ControlId 'EMAIL-1.1' -State 'Gap' -Category 'Email' -Title 'Suspicious inbox rule' -Severity 'High' -Detail 'A rule deletes mail from finance.'
        $null = Set-TPFindingSubject -Since $before -Subject 'bob@corp.com' -Evidence (Get-TPDeepDiveEvidence)

        $f = @(Get-TPFindings)
        $f.Count | Should -Be 2
        $f[0].Subject | Should -Be 'alice@corp.com'
        $f[0].Evidence.Complete | Should -BeTrue
        $f[1].Subject | Should -Be 'bob@corp.com'
        $f[1].Evidence.Complete | Should -BeFalse
        @($f[1].Evidence.RequiredMissing) | Should -Be @('IR-MailboxInbox', 'IR-MailboxRules')
        @($f[1].Evidence.SourcesRead) | Should -Be @('IR-MailboxProfile', 'IR-MailboxSentItems')
    }

    It 'a finding that already names a subject is never re-attributed to another user' {
        Add-TPFinding -ControlId 'EMAIL-1.1' -State 'Gap' -Category 'Email' -Title 't' -Severity 'High' -Detail 'd'
        $null = Set-TPFindingSubject -Since 0 -Subject 'alice@corp.com' -Evidence $null
        (Set-TPFindingSubject -Since 0 -Subject 'bob@corp.com' -Evidence $null) | Should -Be 0
        @(Get-TPFindings)[0].Subject | Should -Be 'alice@corp.com'
    }

    It 'findings from before the dive are left alone' {
        Add-TPFinding -ControlId 'SIGNIN-1.2' -State 'Gap' -Category 'Email' -Title 'triage' -Severity 'High' -Detail 'd'
        $before = @(Get-TPFindings).Count
        Add-TPFinding -ControlId 'EMAIL-1.1' -State 'Gap' -Category 'Email' -Title 'dive' -Severity 'High' -Detail 'd'
        $null = Set-TPFindingSubject -Since $before -Subject 'alice@corp.com' -Evidence $null
        @(Get-TPFindings)[0].PSObject.Properties['Subject'] | Should -BeNullOrEmpty
        @(Get-TPFindings)[1].Subject | Should -Be 'alice@corp.com'
    }

    It 'the report names the account and says when required evidence was not read' {
        $before = 0
        & $script:Dive @('IR-MailboxProfile')
        Add-TPFinding -ControlId 'EMAIL-1.1' -State 'Gap' -Category 'Email' -Title 'Suspicious inbox rule' -Severity 'High' -Detail 'A rule deletes mail.'
        $null = Set-TPFindingSubject -Since $before -Subject 'bob@corp.com' -Evidence (Get-TPDeepDiveEvidence)
        $meta = @{ TenantId = 'x'; ConnectedAdmin = 'a@corp.com'; WindowDays = 7; ToolVersion = '1'; AssessmentDate = 'd'; DeepDivedUsers = @('bob@corp.com'); CollectionComplete = $true; CollectionGaps = @() }
        $h = Join-Path $script:Tmp 'r.html'; $m = Join-Path $script:Tmp 'r.md'
        Publish-TPSignInTriageReport -Metadata $meta -Findings @(Get-TPFindings) -RankedUsers @() -OutputPath $h -MarkdownPath $m | Out-Null
        (Get-Content -LiteralPath $h -Raw) | Should -Match 'Account:</b> bob@corp\.com\.\s*Evidence incomplete: required source\(s\) not read: IR-MailboxSentItems, IR-MailboxInbox, IR-MailboxRules'
        $md = Get-Content -LiteralPath $m -Raw
        $md | Should -Match 'EMAIL-1\.1: Suspicious inbox rule — bob@corp\.com'
        $md | Should -Match 'Evidence incomplete: required source\(s\) not read'
    }

    It 'the triage entry point keeps per-user evidence, records a failed dive, and stops implying the last user''s mailbox is the tenant''s' {
        $entry = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPSignInTriage.ps1') -Raw
        $entry | Should -Match 'Set-TPFindingSubject -Since \$findingsBefore -Subject \$upn'
        $entry | Should -Match "Status = 'Failed'"
        $entry | Should -Match 'DeepDives\s+='
        $entry | Should -Match "-notmatch '\^IR-\(Mailbox\|User\)'"
        $entry | Should -Match 'deep-dive for .* was'
        $mail = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPEmailAssessment.ps1') -Raw
        $mail | Should -Match 'Set-TPFindingSubject'
    }
}

Describe 'Email assessment: findings stay attributed when the profile read fails' {
    It 'falls back to the requested mailbox, never a metadata key the script does not set' {
        $root = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        $text = Get-Content -LiteralPath (Join-Path $root 'Invoke-TPEmailAssessment.ps1') -Raw
        $text | Should -Not -Match 'ConnectedAdmin'
        $text | Should -Match 'else \{ \[string\]\$UserPrincipalName \}'
    }
}

Describe 'Partial reads are carried through to the conclusion (A03)' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Ok = { param([string] $Key, $Data) Set-TPRawData -Key $Key -Data @{ CollectorId = $Key; CollectedAt = (Get-Date).ToString('o'); Success = $true; Data = $Data } }
        $script:AllRequired = {
            param($InboxTruncated = $false)
            foreach ($k in 'IR-MailboxProfile', 'IR-MailboxSentItems', 'IR-MailboxRules') { & $script:Ok $k @{ Count = 0 } }
            & $script:Ok 'IR-MailboxInbox' @{ Count = 10; Truncated = $InboxTruncated }
        }
    }
    AfterAll { Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-TPState }

    It 'a required mailbox source that stopped at its page cap makes the evidence incomplete, and names it' {
        & $script:AllRequired $true
        $e = Get-TPDeepDiveEvidence
        $e.Complete | Should -BeFalse
        ($e.RequiredPartial -join ' ') | Should -Match 'IR-MailboxInbox'
        ($e.SourcesPartial -join ' ') | Should -Match 'page cap'
    }
    It 'every required source read in full is complete' {
        & $script:AllRequired $false
        (Get-TPDeepDiveEvidence).Complete | Should -BeTrue
    }
    It 'an optional source with a limitation is noted but does not make required evidence incomplete' {
        & $script:AllRequired $false
        & $script:Ok 'IR-MailboxRecoverable' @{ Count = 0; CollectionLimitation = 'Recoverable Items folder not accessible via delegated Graph in this tenant' }
        $e = Get-TPDeepDiveEvidence
        ($e.SourcesPartial -join ' ') | Should -Match 'not accessible'
        $e.Complete | Should -BeTrue
    }
    It 'a truncated anonymous-IP read makes sign-in completeness incomplete, with its source named' {
        & $script:Ok 'IR-SignIn-Recent' @{ WindowDays = 7; Count = 10; Truncated = $false; Events = @() }
        & $script:Ok 'IR-SignIn-AnonIp' @{ Count = 1000; Source = 'server-side filter, first page (1000 events)'; Truncated = $true; Events = @() }
        & $script:Ok 'IR-SignIn-Travel' @{ Count = 0; Source = 'client-side over the recent read'; Truncated = $false; Events = @() }
        $c = Get-TPSignInCollectionCompleteness
        $c.Complete | Should -BeFalse
        ($c.Reasons -join ' ') | Should -Match 'IR-SignIn-AnonIp is partial'
    }

    Context 'collectors, with the Graph boundary mocked to keep returning a next link' {
        It 'sent items stop at the cap and say so, instead of reporting a complete window' {
            Mock -ModuleName 'TenantPosture' Invoke-TPGraphRequest {
                [ordered]@{ value = @(@{ id = 'm'; subject = 's'; sentDateTime = '2026-09-29T10:00:00Z'; toRecipients = @(); ccRecipients = @(); bccRecipients = @(); hasAttachments = $false; bodyPreview = '' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/next' }
            }
            Invoke-TPEmailCollectMailbox -WindowDays 7
            $bag = Get-TPRawData -Key 'IR-MailboxSentItems'
            $bag.Success | Should -BeTrue
            $bag.Data.Truncated | Should -BeTrue
            $bag.Data.PagesRead | Should -Be 5
            $bag.Data.EarliestObserved | Should -Match '2026-09-29'
            (Get-TPDeepDiveEvidence).Complete | Should -BeFalse
        }
        It 'a sent-items read that ended with no next link is not marked truncated' {
            Mock -ModuleName 'TenantPosture' Invoke-TPGraphRequest { [ordered]@{ value = @() } }
            Invoke-TPEmailCollectMailbox -WindowDays 7
            (Get-TPRawData -Key 'IR-MailboxSentItems').Data.Truncated | Should -BeFalse
        }
        It 'mailbox coverage is registered from what completed, in its own family' {
            Mock -ModuleName 'TenantPosture' Invoke-TPGraphRequest { throw 'Graph unavailable' }
            Invoke-TPEmailCollectMailbox -WindowDays 7
            $cov = Get-TPCoverage
            $cov['Email-IR-Mailbox'].Status | Should -Be 'Failed'
        }
    }
}

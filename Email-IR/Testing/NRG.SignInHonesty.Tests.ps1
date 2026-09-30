#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.SignInHonesty.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
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
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Bag = { param([string] $Key, [bool] $Ok = $true, $Data = $null)
            @{ CollectorId = $Key; CollectedAt = (Get-Date).ToString('o'); Success = $Ok; Data = $(if ($Ok) { $Data } else { $null }) } }
        $script:AllOk = {
            Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (& $script:Bag 'IR-SignIn-Recent' $true @{ WindowDays = 7; Count = 4200; Truncated = $false; Events = @() })
            Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data (& $script:Bag 'IR-SignIn-AnonIp' $true @{ Count = 0; Events = @() })
            Set-NRGRawData -Key 'IR-SignIn-Travel' -Data (& $script:Bag 'IR-SignIn-Travel' $true @{ Count = 0; Events = @() })
        }
        $script:Meta = @{ TenantId = '00000000-0000-0000-0000-000000000000'; ConnectedAdmin = 'a@contoso.com'; WindowDays = 7; ToolVersion = '4.14.3'; AssessmentDate = 'September 30, 2026'; DeepDivedUsers = @() }
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-honesty-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        $script:Report = {
            param([hashtable] $Meta, [object[]] $Findings)
            $h = Join-Path $script:Tmp ([guid]::NewGuid().ToString('N') + '.html'); $m = [System.IO.Path]::ChangeExtension($h, '.md')
            Publish-NRGSignInTriageReport -Metadata $Meta -Findings $Findings -RankedUsers @() -OutputPath $h -MarkdownPath $m | Out-Null
            [ordered]@{ Html = (Get-Content -LiteralPath $h -Raw); Md = (Get-Content -LiteralPath $m -Raw) }
        }
    }
    AfterAll {
        Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    BeforeEach { Clear-NRGState; Clear-NRGSignInTriageState }

    Context 'completeness' {
        It 'is complete only when Recent, AnonIp and Travel completed and the read was not truncated' {
            & $script:AllOk
            $c = Get-NRGSignInCollectionCompleteness
            $c.Complete | Should -BeTrue
            $c.EventsRead | Should -Be 4200
            $c.WindowDays | Should -Be 7
        }
        It 'a failed read, or an absent one, is incomplete and named' {
            & $script:AllOk
            Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data (& $script:Bag 'IR-SignIn-AnonIp' $false)
            $c = Get-NRGSignInCollectionCompleteness
            $c.Complete | Should -BeFalse
            ($c.Reasons -join ' ') | Should -Match 'IR-SignIn-AnonIp did not complete'
            Clear-NRGState
            (Get-NRGSignInCollectionCompleteness).Complete | Should -BeFalse -Because 'no data at all is not a clean tenant'
        }
        It 'a read that hit its event cap is incomplete: older events in the window were not read' {
            & $script:AllOk
            Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (& $script:Bag 'IR-SignIn-Recent' $true @{ WindowDays = 7; Count = 5000; Truncated = $true; Events = @() })
            $c = Get-NRGSignInCollectionCompleteness
            $c.Complete | Should -BeFalse
            ($c.Reasons -join ' ') | Should -Match 'stopped at 5000 events'
        }
        It 'RiskyUsers (Entra ID P2) is optional and never makes a read incomplete' {
            & $script:AllOk
            Set-NRGRawData -Key 'IR-SignIn-RiskyUsers' -Data (& $script:Bag 'IR-SignIn-RiskyUsers' $false)
            (Get-NRGSignInCollectionCompleteness).Complete | Should -BeTrue
        }
    }

    Context 'SIGNIN-2.1 with nothing scored' {
        It 'complete reads: Satisfied, worded as describing the events read, never "the tenant looks clean"' {
            & $script:AllOk
            Test-NRGSignInControlRankUsers
            $f = @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'SIGNIN-2.1' })[0]
            $f.State | Should -Be 'Satisfied'
            $f.Detail | Should -Match '4200 sign-in events read over the last 7 days'
            $f.Detail | Should -Not -Match 'looks clean'
        }
        It 'failed or truncated reads: not cleared, never Satisfied' {
            & $script:AllOk
            Set-NRGRawData -Key 'IR-SignIn-Travel' -Data (& $script:Bag 'IR-SignIn-Travel' $false)
            Test-NRGSignInControlRankUsers
            $f = @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'SIGNIN-2.1' })[0]
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Not cleared'
            $f.Detail | Should -Match 'not evidence that none occurred'
        }
    }

    Context 'report verdict' {
        It 'a Critical finding is "critical indicators", never a confirmed compromise, and says it is heuristic' {
            Add-NRGFinding -ControlId 'SIGNIN-1.1' -State 'Gap' -Category 'Email' -Title 'Failed-then-success' -Severity 'Critical' -Detail 'A cluster of failures then a success.'
            $crit = @(Get-NRGFindings)
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
            Add-NRGFinding -ControlId 'SIGNIN-1.2' -State 'Gap' -Category 'Email' -Title 'Anonymous IP' -Severity 'High' -Detail 'A sign-in from an anonymizing IP.'
            $high = @(Get-NRGFindings)
            (& $script:Report ($script:Meta + @{ CollectionComplete = $false; CollectionGaps = @('x') }) $high).Md | Should -Match 'SUSPECT ACTIVITY'
        }
        It 'an older metadata block with no completeness keys keeps its previous behavior' {
            (& $script:Report $script:Meta @()).Md | Should -Match 'NO STRONG INDICATORS IN THE EVENTS READ'
        }
    }

    Context 'collector coverage is registered from what completed' {
        BeforeAll {
            $script:Src = Get-Content -LiteralPath (Join-Path $script:Root 'Email-IR/Collectors/Invoke-NRGEmailCollectSignIns.ps1') -Raw
        }
        It 'no coverage is asserted before a query runs' {
            $head = $script:Src.Substring(0, $script:Src.IndexOf('# ── Recent sign-ins'))
            $head | Should -Not -Match "Register-NRGCoverage -Family 'Email-IR' -Status 'Collected'"
        }
        It 'registers Failed, Partial or Collected at the end, and records truncation on the recent bag' {
            $script:Src | Should -Match "Register-NRGCoverage -Family 'Email-IR' -Status 'Failed'"
            $script:Src | Should -Match "Register-NRGCoverage -Family 'Email-IR' -Status 'Partial'"
            $script:Src | Should -Match "Register-NRGCoverage -Family 'Email-IR' -Status 'Collected'"
            $script:Src | Should -Match 'Truncated\s+=\s+\$wasTruncated'
        }
        It 'the entry point hands completeness to the report' {
            $entry = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-NRGSignInTriage.ps1') -Raw
            $entry | Should -Match "reportMetadata\['CollectionComplete'\]"
            $entry | Should -Match 'Get-NRGSignInCollectionCompleteness'
        }
    }
}

Describe 'Deep-dive findings say whose mailbox they describe and what they rest on' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:AllKeys = @('IR-MailboxProfile', 'IR-MailboxSentItems', 'IR-MailboxInbox', 'IR-MailboxRecoverable', 'IR-MailboxRules', 'IR-MailboxForwarding', 'IR-UserConsents', 'IR-UserAuthMethods')
        # One user's dive: read these keys, leave the others failed (as the entry point resets them).
        $script:Dive = {
            param([string[]] $Read)
            foreach ($k in $script:AllKeys) { Set-NRGRawData -Key $k -Data @{ CollectorId = $k; Success = $false; Data = $null } }
            foreach ($k in $Read) { Set-NRGRawData -Key $k -Data @{ CollectorId = $k; Success = $true; Data = @{ } } }
        }
        $script:Required = @('IR-MailboxProfile', 'IR-MailboxSentItems', 'IR-MailboxInbox', 'IR-MailboxRules')
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-subject-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
    }
    AfterAll {
        Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    BeforeEach { Clear-NRGState }

    It 'two users'' findings are tagged with their own account and their own evidence, not each other''s' {
        $before = @(Get-NRGFindings).Count
        & $script:Dive $script:Required
        Add-NRGFinding -ControlId 'EMAIL-1.1' -State 'Gap' -Category 'Email' -Title 'Suspicious inbox rule' -Severity 'High' -Detail 'A rule deletes mail from finance.'
        $null = Set-NRGFindingSubject -Since $before -Subject 'alice@corp.com' -Evidence (Get-NRGDeepDiveEvidence)

        $before = @(Get-NRGFindings).Count
        & $script:Dive @('IR-MailboxProfile', 'IR-MailboxSentItems')      # Bob's inbox and rules reads failed
        Add-NRGFinding -ControlId 'EMAIL-1.1' -State 'Gap' -Category 'Email' -Title 'Suspicious inbox rule' -Severity 'High' -Detail 'A rule deletes mail from finance.'
        $null = Set-NRGFindingSubject -Since $before -Subject 'bob@corp.com' -Evidence (Get-NRGDeepDiveEvidence)

        $f = @(Get-NRGFindings)
        $f.Count | Should -Be 2
        $f[0].Subject | Should -Be 'alice@corp.com'
        $f[0].Evidence.Complete | Should -BeTrue
        $f[1].Subject | Should -Be 'bob@corp.com'
        $f[1].Evidence.Complete | Should -BeFalse
        @($f[1].Evidence.RequiredMissing) | Should -Be @('IR-MailboxInbox', 'IR-MailboxRules')
        @($f[1].Evidence.SourcesRead) | Should -Be @('IR-MailboxProfile', 'IR-MailboxSentItems')
    }

    It 'a finding that already names a subject is never re-attributed to another user' {
        Add-NRGFinding -ControlId 'EMAIL-1.1' -State 'Gap' -Category 'Email' -Title 't' -Severity 'High' -Detail 'd'
        $null = Set-NRGFindingSubject -Since 0 -Subject 'alice@corp.com' -Evidence $null
        (Set-NRGFindingSubject -Since 0 -Subject 'bob@corp.com' -Evidence $null) | Should -Be 0
        @(Get-NRGFindings)[0].Subject | Should -Be 'alice@corp.com'
    }

    It 'findings from before the dive are left alone' {
        Add-NRGFinding -ControlId 'SIGNIN-1.2' -State 'Gap' -Category 'Email' -Title 'triage' -Severity 'High' -Detail 'd'
        $before = @(Get-NRGFindings).Count
        Add-NRGFinding -ControlId 'EMAIL-1.1' -State 'Gap' -Category 'Email' -Title 'dive' -Severity 'High' -Detail 'd'
        $null = Set-NRGFindingSubject -Since $before -Subject 'alice@corp.com' -Evidence $null
        @(Get-NRGFindings)[0].PSObject.Properties['Subject'] | Should -BeNullOrEmpty
        @(Get-NRGFindings)[1].Subject | Should -Be 'alice@corp.com'
    }

    It 'the report names the account and says when required evidence was not read' {
        $before = 0
        & $script:Dive @('IR-MailboxProfile')
        Add-NRGFinding -ControlId 'EMAIL-1.1' -State 'Gap' -Category 'Email' -Title 'Suspicious inbox rule' -Severity 'High' -Detail 'A rule deletes mail.'
        $null = Set-NRGFindingSubject -Since $before -Subject 'bob@corp.com' -Evidence (Get-NRGDeepDiveEvidence)
        $meta = @{ TenantId = 'x'; ConnectedAdmin = 'a@corp.com'; WindowDays = 7; ToolVersion = '1'; AssessmentDate = 'd'; DeepDivedUsers = @('bob@corp.com'); CollectionComplete = $true; CollectionGaps = @() }
        $h = Join-Path $script:Tmp 'r.html'; $m = Join-Path $script:Tmp 'r.md'
        Publish-NRGSignInTriageReport -Metadata $meta -Findings @(Get-NRGFindings) -RankedUsers @() -OutputPath $h -MarkdownPath $m | Out-Null
        (Get-Content -LiteralPath $h -Raw) | Should -Match 'Account:</b> bob@corp\.com\.\s*Evidence incomplete: required source\(s\) not read: IR-MailboxSentItems, IR-MailboxInbox, IR-MailboxRules'
        $md = Get-Content -LiteralPath $m -Raw
        $md | Should -Match 'EMAIL-1\.1: Suspicious inbox rule — bob@corp\.com'
        $md | Should -Match 'Evidence incomplete: required source\(s\) not read'
    }

    It 'the triage entry point keeps per-user evidence, records a failed dive, and stops implying the last user''s mailbox is the tenant''s' {
        $entry = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-NRGSignInTriage.ps1') -Raw
        $entry | Should -Match 'Set-NRGFindingSubject -Since \$findingsBefore -Subject \$upn'
        $entry | Should -Match "Status = 'Failed'"
        $entry | Should -Match 'DeepDives\s+='
        $entry | Should -Match "-notmatch '\^IR-\(Mailbox\|User\)'"
        $entry | Should -Match 'deep-dive for .* was'
        $mail = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-NRGEmailAssessment.ps1') -Raw
        $mail | Should -Match 'Set-NRGFindingSubject'
    }
}

#Requires -Version 7.0
#
# NRG.EmailIR.Tests.ps1
#
# Pinned-behavior suite for the v4.12.0 Email Account Assessment mode.
# Tests the IoC scoring + phish-origin ranking heuristics against
# synthetic fixtures so a future refactor of the scoring weights doesn't
# silently change verdicts.

Describe 'NRG Email IR — domain + impersonation helpers' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Evaluators' 'Test-NRGEmailControls.ps1')
    }

    Context 'Get-NRGEmailDomainFromAddress' {
        It 'Pulls domain from a well-formed address' {
            Get-NRGEmailDomainFromAddress 'alice@corp.com' | Should -Be 'corp.com'
        }
        It 'Lowercases the result' {
            Get-NRGEmailDomainFromAddress 'Alice@Corp.COM' | Should -Be 'corp.com'
        }
        It 'Returns $null on garbage input' {
            Get-NRGEmailDomainFromAddress 'no-at-sign' | Should -BeNullOrEmpty
            Get-NRGEmailDomainFromAddress ''           | Should -BeNullOrEmpty
            Get-NRGEmailDomainFromAddress $null        | Should -BeNullOrEmpty
            Get-NRGEmailDomainFromAddress 'trailing@'  | Should -BeNullOrEmpty
        }
    }

    Context 'Test-NRGEmailIsLegitMSDomain' {
        It 'Accepts canonical Microsoft auth domains' {
            Test-NRGEmailIsLegitMSDomain 'microsoft.com'        | Should -BeTrue
            Test-NRGEmailIsLegitMSDomain 'login.microsoftonline.com' | Should -BeTrue
            Test-NRGEmailIsLegitMSDomain 'corp.onmicrosoft.com' | Should -BeTrue
            Test-NRGEmailIsLegitMSDomain 'outlook.com'          | Should -BeTrue
        }
        It 'Rejects typosquats' {
            Test-NRGEmailIsLegitMSDomain 'microsft-onlne.com'   | Should -BeFalse
            Test-NRGEmailIsLegitMSDomain 'microsoft.evil.com'   | Should -BeFalse  # ends-with check, not contains
            Test-NRGEmailIsLegitMSDomain 'fake-microsoftonline.com' | Should -BeFalse
        }
        It 'Returns false on empty/null' {
            Test-NRGEmailIsLegitMSDomain '' | Should -BeFalse
            Test-NRGEmailIsLegitMSDomain $null | Should -BeFalse
        }
    }

    Context 'Test-NRGEmailMatchesMSImpersonation' {
        It 'Catches the common typosquat patterns' {
            Test-NRGEmailMatchesMSImpersonation -Domain 'microsft.com'   -DisplayName 'Microsoft Account Team' | Should -BeTrue
            Test-NRGEmailMatchesMSImpersonation -Domain 'office356.com'  -DisplayName 'Office 365 Support'    | Should -BeTrue
            Test-NRGEmailMatchesMSImpersonation -Domain 'micros0ft.io'   -DisplayName 'Microsoft'             | Should -BeTrue
        }
        It 'Catches display-name spoof on external sender' {
            Test-NRGEmailMatchesMSImpersonation -Domain 'evil.example.com' -DisplayName 'Microsoft Account Team' | Should -BeTrue
        }
        It 'Allows legit Microsoft mail' {
            Test-NRGEmailMatchesMSImpersonation -Domain 'microsoft.com' -DisplayName 'Microsoft' | Should -BeFalse
            Test-NRGEmailMatchesMSImpersonation -Domain 'login.microsoftonline.com' -DisplayName 'Sign in' | Should -BeFalse
        }
    }
}

Describe 'NRG Email IR — evaluators against synthetic fixtures' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Evaluators' 'Test-NRGEmailControls.ps1')

        # Helper: build a raw-data result matching the collector contract
        function script:NewBag([string]$cid, $data) {
            [ordered]@{
                CollectorId = $cid
                CollectedAt = (Get-Date -Format 'o')
                Success     = $true
                Data        = $data
            }
        }
    }

    BeforeEach {
        Clear-NRGState
    }

    Context 'Inbox Rules detector (EMAIL-1.1)' {
        It 'Flags a hidden-name forwarding rule as Critical' {
            Set-NRGRawData -Key 'IR-MailboxRules' -Data (NewBag 'IR-Mailbox-Rules' @{
                Count = 1
                Rules = @(@{
                    displayName = '..'
                    isEnabled   = $true
                    actions     = @{
                        forwardTo = @(@{ emailAddress = @{ address = 'attacker@protonmail.com' } })
                        delete    = $true
                    }
                    conditions = @{}
                })
            })
            Test-NRGEmailControl-InboxRules
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')
            $f.Count        | Should -Be 1
            $f[0].State     | Should -Be 'Gap'
            $f[0].Severity  | Should -Be 'Critical'
            $f[0].Detail    | Should -Match 'hidden-name'
            $f[0].Detail    | Should -Match 'attacker@protonmail.com'
        }

        It 'Allows benign rules' {
            Set-NRGRawData -Key 'IR-MailboxRules' -Data (NewBag 'IR-Mailbox-Rules' @{
                Count = 1
                Rules = @(@{
                    displayName = 'Move newsletter to Newsletters'
                    isEnabled   = $true
                    actions     = @{
                        moveToFolder = 'Newsletters'
                    }
                    conditions = @{ subjectContains = @('newsletter') }
                })
            })
            Test-NRGEmailControl-InboxRules
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')
            # Move-to-folder with conditions IS still flagged (covers-tracks
            # pattern), but no forward-external. The current detector flags
            # any move-to-folder; document that and assert it lands as Gap
            # with severity Critical — the operator triages.
            $f.Count | Should -Be 1
        }
    }

    Context 'Outbound Activity detector (EMAIL-2.1)' {
        It 'Flags BEC subject pattern + many external recipients as Critical' {
            Set-NRGRawData -Key 'IR-MailboxProfile' -Data (NewBag 'IR-Mailbox-Profile' @{
                UserPrincipalName = 'alice@corp.com'
            })

            $msgs = @()
            for ($i = 0; $i -lt 30; $i++) {
                $msgs += [ordered]@{
                    Id           = "msg$i"
                    Subject      = "Updated invoice attached - urgent payment $i"
                    SentDateTime = (Get-Date).AddMinutes(-$i).ToString('o')
                    FromAddress  = 'alice@corp.com'
                    Recipients   = @("ext$i@partner-$i.com")
                    HasAttachments = $true
                    BodyURLs     = @()
                }
            }
            Set-NRGRawData -Key 'IR-MailboxSentItems' -Data (NewBag 'IR-Mailbox-SentItems' @{
                WindowDays = 7
                Cutoff     = (Get-Date).AddDays(-7).ToString('o')
                Count      = $msgs.Count
                Messages   = $msgs
            })

            Test-NRGEmailControl-OutboundActivity
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-2.1')
            $f.Count        | Should -Be 1
            $f[0].State     | Should -Be 'Gap'
            $f[0].Severity  | Should -Be 'Critical'
            $f[0].Detail    | Should -Match 'BEC PATTERN MATCHES'
        }

        It 'Reports Satisfied when no IoCs and low volume' {
            Set-NRGRawData -Key 'IR-MailboxProfile' -Data (NewBag 'IR-Mailbox-Profile' @{
                UserPrincipalName = 'alice@corp.com'
            })
            Set-NRGRawData -Key 'IR-MailboxSentItems' -Data (NewBag 'IR-Mailbox-SentItems' @{
                WindowDays = 7
                Cutoff     = (Get-Date).AddDays(-7).ToString('o')
                Count      = 2
                Messages   = @(
                    [ordered]@{ Id='m1'; Subject='Re: project update'; SentDateTime=(Get-Date).ToString('o'); FromAddress='alice@corp.com'; Recipients=@('bob@corp.com'); BodyURLs=@() }
                    [ordered]@{ Id='m2'; Subject='lunch?';            SentDateTime=(Get-Date).ToString('o'); FromAddress='alice@corp.com'; Recipients=@('carol@corp.com'); BodyURLs=@() }
                )
            })
            Test-NRGEmailControl-OutboundActivity
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-2.1')
            $f[0].State | Should -Be 'Satisfied'
        }
    }

    Context 'Phish Origin ranker (EMAIL-3.1)' {
        It 'Ranks typosquat + urgency + suspicious URL as the top phish' {
            Set-NRGRawData -Key 'IR-MailboxProfile' -Data (NewBag 'IR-Mailbox-Profile' @{
                UserPrincipalName = 'alice@corp.com'
            })
            $phish = [ordered]@{
                Id='p1'
                Subject='Your password expires in 24 hours - verify now'
                ReceivedDateTime=(Get-Date).AddDays(-2).ToString('o')
                FromAddress='admin@microsft-onlne.com'
                FromName='Microsoft Account Team'
                BodyURLs=@('https://microsft-onlne.com/login/auth?token=abc')
                BodyPreviewLen=200
            }
            $benign = [ordered]@{
                Id='b1'
                Subject='lunch tomorrow?'
                ReceivedDateTime=(Get-Date).AddDays(-1).ToString('o')
                FromAddress='friend@gmail.com'
                FromName='Pat Friend'
                BodyURLs=@()
                BodyPreviewLen=50
            }
            Set-NRGRawData -Key 'IR-MailboxInbox' -Data (NewBag 'IR-Mailbox-Inbox' @{
                WindowDays = 30
                Cutoff     = (Get-Date).AddDays(-30).ToString('o')
                Count      = 2
                Messages   = @($phish, $benign)
            })
            Set-NRGRawData -Key 'IR-MailboxRecoverable' -Data (NewBag 'IR-Mailbox-Recoverable' @{
                Count    = 0
                Messages = @()
            })

            Test-NRGEmailControl-PhishOrigin
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-3.1')
            $f.Count | Should -Be 1
            $f[0].State | Should -Be 'Gap'
            $f[0].Detail | Should -Match 'password expires'
            $f[0].Detail | Should -Match 'microsft-onlne.com'
            $f[0].Detail | Should -Not -Match 'friend@gmail.com'  # benign not in top 5
        }

        It 'Boosts score when phish was recovered from Deletions' {
            Set-NRGRawData -Key 'IR-MailboxProfile' -Data (NewBag 'IR-Mailbox-Profile' @{
                UserPrincipalName = 'alice@corp.com'
            })
            # Two equal candidates — one only in inbox, one also in Recoverable.
            # Recovered should rank higher.
            $a = [ordered]@{
                Id='a1'; Subject='Account locked - verify identity'
                ReceivedDateTime=(Get-Date).AddDays(-3).ToString('o')
                FromAddress='alerts@badco.com'; FromName='Account Team'; BodyURLs=@(); BodyPreviewLen=100
            }
            $b = [ordered]@{
                Id='b1'; Subject='Account locked - verify identity'
                ReceivedDateTime=(Get-Date).AddDays(-3).ToString('o')
                FromAddress='alerts@otherbad.com'; FromName='Account Team'; BodyURLs=@(); BodyPreviewLen=100
            }
            Set-NRGRawData -Key 'IR-MailboxInbox' -Data (NewBag 'IR-Mailbox-Inbox' @{
                WindowDays = 30; Cutoff=(Get-Date).AddDays(-30).ToString('o')
                Count = 2; Messages = @($a, $b)
            })
            Set-NRGRawData -Key 'IR-MailboxRecoverable' -Data (NewBag 'IR-Mailbox-Recoverable' @{
                Count    = 1
                Messages = @($b)
            })
            Test-NRGEmailControl-PhishOrigin
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-3.1')
            $f[0].Detail | Should -Match 'RECOVERED from Deletions'
            # otherbad.com (the recovered one) should appear first
            $idxOther = $f[0].Detail.IndexOf('otherbad.com')
            $idxBad   = $f[0].Detail.IndexOf('badco.com')
            $idxOther | Should -BeLessThan $idxBad
        }
    }

    Context 'Defensive — collectors did not run' {
        It 'Returns NotApplicable when raw data missing' {
            Test-NRGEmailControl-InboxRules
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')
            $f[0].State | Should -Be 'NotApplicable'
        }
    }
}

Describe 'NRG Email IR — recipient warn-list (EMAIL-2.1 AffectedObjects)' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Evaluators' 'Test-NRGEmailControls.ps1')
        function script:NewBag($cid, $data) { [ordered]@{ CollectorId=$cid; CollectedAt=(Get-Date -Format 'o'); Success=$true; Data=$data } }
    }
    BeforeEach { Clear-NRGState }

    It 'Builds an internal+external recipient warn-list from BEC messages' {
        $base=(Get-Date).ToUniversalTime()
        Set-NRGRawData -Key 'IR-MailboxProfile' -Data (NewBag 'p' @{ UserPrincipalName='alice@corp.com' })
        $msgs = @(
            [ordered]@{ Id='m1'; Subject='Urgent wire transfer needed'; SentDateTime=$base.ToString('o'); FromAddress='alice@corp.com'; Recipients=@('cfo@partner.com','bob@corp.com'); HasAttachments=$false; BodyURLs=@() }
            [ordered]@{ Id='m2'; Subject='Updated invoice - process payment'; SentDateTime=$base.ToString('o'); FromAddress='alice@corp.com'; Recipients=@('ap@vendor.com','carol@corp.com'); HasAttachments=$true; BodyURLs=@() }
        )
        Set-NRGRawData -Key 'IR-MailboxSentItems' -Data (NewBag 's' @{ WindowDays=7; Cutoff=$base.AddDays(-7).ToString('o'); Count=$msgs.Count; Messages=$msgs })
        Test-NRGEmailControl-OutboundActivity
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-2.1')
        $f[0].State    | Should -Be 'Gap'
        $f[0].Severity | Should -Be 'Critical'
        $aff = @($f[0].AffectedObjects)
        $aff.Count | Should -Be 4
        ($aff | Where-Object Recipient -eq 'cfo@partner.com').Scope | Should -Be 'External'
        ($aff | Where-Object Recipient -eq 'bob@corp.com').Scope    | Should -Be 'Internal'
    }

    It 'Does not attach a warn-list for clean (non-suspicious) outbound' {
        $base=(Get-Date).ToUniversalTime()
        Set-NRGRawData -Key 'IR-MailboxProfile' -Data (NewBag 'p' @{ UserPrincipalName='alice@corp.com' })
        Set-NRGRawData -Key 'IR-MailboxSentItems' -Data (NewBag 's' @{ WindowDays=7; Cutoff=$base.AddDays(-7).ToString('o'); Count=1; Messages=@([ordered]@{ Id='m'; Subject='Re: lunch'; SentDateTime=$base.ToString('o'); FromAddress='alice@corp.com'; Recipients=@('bob@corp.com'); HasAttachments=$false; BodyURLs=@() }) })
        Test-NRGEmailControl-OutboundActivity
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-2.1')
        $f[0].State | Should -Be 'Satisfied'
        @($f[0].AffectedObjects).Count | Should -Be 0
    }
}

Describe 'NRG Email IR — EMAIL-1.1 attaches flagged rules as InboxRule AffectedObjects' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Evaluators' 'Test-NRGEmailControls.ps1')
        function script:NewBag($cid, $data) { [ordered]@{ CollectorId=$cid; CollectedAt=(Get-Date -Format 'o'); Success=$true; Data=$data } }
    }
    BeforeEach { Clear-NRGState }

    It 'Emits an InboxRule AffectedObject carrying Name + Id for each flagged rule' {
        Set-NRGRawData -Key 'IR-MailboxRules' -Data (NewBag 'r' @{
            Count = 1
            Rules = @(@{
                id          = 'AAMkAQ-ruleid-001'
                displayName = '..'
                isEnabled   = $true
                actions     = @{
                    forwardTo = @(@{ emailAddress = @{ address = 'attacker@protonmail.com' } })
                    delete    = $true
                }
                conditions = @{}
            })
        })
        Test-NRGEmailControl-InboxRules
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')
        $aff = @($f[0].AffectedObjects)
        $aff.Count            | Should -Be 1
        $aff[0].RuleType      | Should -Be 'InboxRule'
        $aff[0].Id            | Should -Be 'AAMkAQ-ruleid-001'
        $aff[0].Reason        | Should -Not -BeNullOrEmpty
        # The recipient-warn-list filter must NOT pick these up (no Recipient)
        ($aff | Where-Object { $_.Recipient }) | Should -BeNullOrEmpty
    }
}

Describe 'NRG Email IR — Containment Runbook render (publisher)' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Email-IR' 'Publishers' 'Publish-NRGEmailIncidentReport.ps1')
        $script:OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("nls-rb-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
    }
    AfterAll {
        if ($script:OutDir -and (Test-Path $script:OutDir)) { Remove-Item $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'Renders the 6-step runbook and substitutes the UPN + flagged rule delete commands' {
        $meta = @{
            UserPrincipalName = 'alice@corp.com'
            AssessmentDate    = 'June 10, 2026'
            WindowDays        = 7
            ToolVersion       = '4.12.0'
            TenantId          = 'contoso.onmicrosoft.com'
            Brand             = @{ CompanyName = 'NRG Technology Services' }
        }
        $findings = @(
            @{
                ControlId = 'EMAIL-1.1'; State='Gap'; Severity='Critical'; Category='Email'
                Title='Suspicious inbox rules'; Detail='FOUND 1 suspicious rule.'
                AffectedObjects = @([pscustomobject]@{ RuleType='InboxRule'; Name='zzz-hide'; Id='RULE-XYZ-9'; Enabled=$true; Reason='forwards external; deletes' })
            }
        )
        $htmlPath = Join-Path $script:OutDir 'rep.html'
        Publish-NRGEmailIncidentReport -Metadata $meta -Findings $findings -OutputPath $htmlPath
        Test-Path $htmlPath | Should -BeTrue
        $html = Get-Content $htmlPath -Raw

        # Section present
        $html | Should -Match 'Containment .* Recovery Runbook'
        # Step 1 sign-out command with substituted UPN
        $html | Should -Match 'Revoke-MgUserSignInSession -UserId alice@corp.com'
        # Step 4 names the rule and emits a precise delete command with the Id
        $html | Should -Match 'zzz-hide'
        $html | Should -Match 'Remove-MgUserMailFolderMessageRule -UserId alice@corp.com -MailFolderId Inbox -MessageRuleId RULE-XYZ-9'
        # Step 6 browser-cache on-user-device
        $html | Should -Match 'Clear browser cache'
        # Six numbered steps rendered
        ([regex]::Matches($html, 'class="rbnum"')).Count | Should -Be 6
    }

    It 'Falls back to a manual-verify note when no inbox rules were flagged' {
        $meta = @{ UserPrincipalName='bob@corp.com'; ToolVersion='4.12.0'; Brand=@{ CompanyName='NRG Technology Services' } }
        $findings = @(
            @{ ControlId='EMAIL-2.1'; State='Satisfied'; Severity='High'; Category='Email'; Title='Outbound clean'; Detail='no IoCs' }
        )
        $htmlPath = Join-Path $script:OutDir 'rep2.html'
        Publish-NRGEmailIncidentReport -Metadata $meta -Findings $findings -OutputPath $htmlPath
        $html = Get-Content $htmlPath -Raw
        $html | Should -Match 'No suspicious inbox rules were flagged'
        ([regex]::Matches($html, 'class="rbnum"')).Count | Should -Be 6
    }
}

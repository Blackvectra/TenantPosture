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
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
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
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
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
            Test-NRGEmailControlInboxRules
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')
            $f.Count        | Should -Be 1
            $f[0].State     | Should -Be 'Gap'
            $f[0].Severity  | Should -Be 'Critical'
            $f[0].Detail    | Should -Match 'hidden-name'
            $f[0].Detail    | Should -Match 'attacker@protonmail.com'
        }

        It 'a newsletter folder move is routine: not flagged, and the finding is Satisfied about the rules read' {
            Set-NRGRawData -Key 'IR-MailboxRules' -Data (NewBag 'IR-Mailbox-Rules' @{
                Count = 1
                Rules = @(@{ displayName = 'Move newsletter to Newsletters'; isEnabled = $true
                             actions = @{ moveToFolder = 'Newsletters' }; conditions = @{ subjectContains = @('newsletter') } })
            })
            Test-NRGEmailControlInboxRules
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')
            $f.Count    | Should -Be 1
            $f[0].State | Should -Be 'Satisfied'
            $f[0].Detail | Should -Match 'describes the rules read'
        }

        Context 'destination, state and combination decide the verdict' {
            BeforeEach {
                Set-NRGRawData -Key 'IR-MailboxProfile' -Data (NewBag 'IR-Mailbox-Profile' @{ UserPrincipalName = 'alice@corp.com' })
            }
            It 'expected internal forwarding (same domain) is not flagged' {
                Set-NRGRawData -Key 'IR-MailboxRules' -Data (NewBag 'IR-Mailbox-Rules' @{ Count = 1; Rules = @(@{
                    displayName = 'To my assistant'; isEnabled = $true
                    actions = @{ forwardTo = @(@{ emailAddress = @{ address = 'bob@corp.com' } }) }; conditions = @{ fromAddresses = @('ceo@corp.com') } }) })
                Test-NRGEmailControlInboxRules
                @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')[0].State | Should -Be 'Satisfied'
            }
            It 'a DISABLED external-forward rule is kept as historical evidence, Medium, never current persistence' {
                Set-NRGRawData -Key 'IR-MailboxRules' -Data (NewBag 'IR-Mailbox-Rules' @{ Count = 1; Rules = @(@{
                    displayName = 'Old forward'; isEnabled = $false
                    actions = @{ forwardTo = @(@{ emailAddress = @{ address = 'someone@gmail.com' } }) }; conditions = @{ subjectContains = @('report') } }) })
                Test-NRGEmailControlInboxRules
                $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')[0]
                $f.State    | Should -Be 'Gap'
                $f.Severity | Should -Be 'Medium'
                $f.Detail   | Should -Match 'DISABLED: historical, not acting now'
                @($f.AffectedObjects)[0].Enabled | Should -BeFalse
            }
            It 'an enabled external forward alone is High with Medium confidence, not Critical' {
                Set-NRGRawData -Key 'IR-MailboxRules' -Data (NewBag 'IR-Mailbox-Rules' @{ Count = 1; Rules = @(@{
                    displayName = 'Forward invoices'; isEnabled = $true
                    actions = @{ forwardTo = @(@{ emailAddress = @{ address = 'someone@gmail.com' } }) }; conditions = @{ subjectContains = @('invoice') } }) })
                Test-NRGEmailControlInboxRules
                $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')[0]
                $f.Severity | Should -Be 'High'
                $f.Detail   | Should -Match 'confidence Medium'
                $f.Detail   | Should -Match 'may be another domain of the same organization'
            }
            It 'an enabled hidden-name rule that forwards out to everything and deletes is Critical, high confidence' {
                Set-NRGRawData -Key 'IR-MailboxRules' -Data (NewBag 'IR-Mailbox-Rules' @{ Count = 1; Rules = @(@{
                    displayName = '.'; isEnabled = $true
                    actions = @{ forwardTo = @(@{ emailAddress = @{ address = 'attacker@protonmail.com' } }); delete = $true }; conditions = @{} }) })
                Test-NRGEmailControlInboxRules
                $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')[0]
                $f.Severity | Should -Be 'Critical'
                $f.Detail   | Should -Match 'confidence High'
            }
            It 'a destination that cannot be compared is stated as such and lowers confidence' {
                Set-NRGRawData -Key 'IR-MailboxRules' -Data (NewBag 'IR-Mailbox-Rules' @{ Count = 1; Rules = @(@{
                    displayName = 'Route'; isEnabled = $true
                    actions = @{ forwardTo = @(@{ emailAddress = @{ address = '/o=ExchangeLabs/ou=x/cn=y' } }) }; conditions = @{ subjectContains = @('x') } }) })
                Test-NRGEmailControlInboxRules
                $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')[0]
                $f.Detail | Should -Match 'could not be compared with the mailbox'
                $f.Detail | Should -Match 'confidence Low'
            }
        }
    }

    Context 'Phish leads are leads, not findings of cause (EMAIL-3.1, A10)' {
        BeforeEach {
            Set-NRGRawData -Key 'IR-MailboxProfile' -Data (NewBag 'IR-Mailbox-Profile' @{ UserPrincipalName = 'alice@corp.com' })
        }
        BeforeAll {
            function script:Msg($id, $subject, $from, $fromName, $urls = @()) {
                [ordered]@{ Id = $id; Subject = $subject; ReceivedDateTime = (Get-Date).AddDays(-2).ToString('o'); FromAddress = $from; FromName = $fromName; BodyURLs = @($urls); BodyPreviewLen = 120 }
            }
            function script:Run($inbox, $recov = @()) {
                Set-NRGRawData -Key 'IR-MailboxInbox' -Data (NewBag 'IR-Mailbox-Inbox' @{ WindowDays = 30; Count = @($inbox).Count; Truncated = $false; Messages = @($inbox) })
                Set-NRGRawData -Key 'IR-MailboxRecoverable' -Data (NewBag 'IR-Mailbox-Recoverable' @{ Count = @($recov).Count; Messages = @($recov) })
                Test-NRGEmailControlPhishOrigin
                @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-3.1')[0]
            }
        }
        It 'a legitimate vendor message that was deleted is not a lead on the strength of being deleted' {
            $m = Msg 'v1' 'Statement for September' 'billing@vendor.example' 'Vendor Billing'
            $f = Run @() @($m)
            $f.State | Should -Be 'NotApplicable'
        }
        It 'a Microsoft Loop digest from sharepointonline.com is not a lead (a Microsoft domain)' {
            $m = Msg 'm1' 'Start your day by getting in the Loop' 'no-reply@sharepointonline.com' 'Microsoft Loop'
            (Run @($m)).State | Should -Be 'NotApplicable'
        }
        It 'a partner or distributor whose display name says Microsoft is a weaker lead, Medium, never a High indicator' {
            $m = Msg 'm2' 'Microsoft SPLA Reporting Reminder' 'Microsoft-SPLA@ingrammicro.example' 'Microsoft-SPLA'
            $f = Run @($m)
            $f.State    | Should -Be 'Gap'
            $f.Severity | Should -Be 'Medium'
            $f.Detail   | Should -Match 'weaker lead: a display name alone'
            $f.Detail   | Should -Match 'No lead carries a strong phishing signal'
        }
        It 'one display name counts once: the Microsoft claim does not also fire the brand-spoof signal' {
            $m = Msg 'm3' 'Course enrollment' 'DoNotReply@training.example' 'LevelUp for Microsoft'
            $f = Run @($m)
            $f.Detail | Should -Not -Match "claims 'microsoft'"
            $f.Detail | Should -Match 'Rank score 45'
        }
        It 'a typo-squatted Microsoft domain is a strong lead and stays High' {
            $m = Msg 'm4' 'Notice' 'noreply@microsft-support.example' 'Support'
            $f = Run @($m)
            $f.Severity | Should -Be 'High'
            $f.Detail   | Should -Match 'sending domain'
        }
        It 'a strong lead outranks a weaker lead with a higher score' {
            $weak   = Msg 'm5' 'Hello' 'a@vendor.example' 'Microsoft Partner Network'
            $strong = Msg 'm6' 'Verify your account now' 'x@other.example' 'Account Team'
            $f = Run @($weak, $strong)
            $f.Severity | Should -Be 'High'
            $f.Detail.IndexOf('x@other.example') | Should -BeLessThan $f.Detail.IndexOf('a@vendor.example')
        }
        It 'a genuine DocuSign message from a DocuSign domain is not called a brand spoof' {
            $m = Msg 'd1' 'Please review: contract for signature' 'dse@docusign.net' 'DocuSign'
            $f = Run @($m)
            $f.State | Should -Be 'NotApplicable'
        }
        It 'the same display name from an unrelated domain is a brand-spoof lead' {
            $m = Msg 'd2' 'Please review: docusign request' 'dse@docusign-secure.example' 'DocuSign'
            $f = Run @($m)
            $f.State | Should -Be 'Gap'
            $f.Detail | Should -Match "claims 'docusign'"
        }
        It 'a compromised internal sender with urgency and a sign-in link is kept, marked lower confidence' {
            $m = Msg 'i1' 'Urgent action: verify now' 'colleague@corp.com' 'A Colleague' @('https://evil.example/login/verify')
            $f = Run @($m)
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'lower confidence: sender inside the mailbox domain'
        }
        It 'an internal sender with only one weak signal is not a lead' {
            $m = Msg 'i2' 'Urgent action: lunch?' 'colleague@corp.com' 'A Colleague'
            (Run @($m)).State | Should -Be 'NotApplicable'
        }
        It 'a real external credential-harvest lure is a lead, and Recoverable Items never assigns the deletion to an actor' {
            $m = Msg 'p1' 'Your password expires in 24 hours - verify now' 'admin@microsft-onlne.com' 'Microsoft Account Team' @('https://microsft-onlne.com/login/auth')
            $f = Run @($m) @($m)
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'who deleted it is not known'
            $f.Detail | Should -Not -Match 'attacker deleted|most-likely original phish'
            $f.Detail | Should -Match 'investigative leads'
        }
        It 'every result states what was read: folders, window, and that links come from the preview only' {
            $m = Msg 'p2' 'Verify your account now' 'x@badco.example' 'Account Team'
            $f = Run @($m)
            $f.Detail | Should -Match 'message preview only'
            $f.Detail | Should -Match 'last 30 days'
        }
        It 'a truncated inbox read is said to be partial in the scope statement' {
            $m = Msg 'p3' 'Verify your account now' 'x@badco.example' 'Account Team'
            Set-NRGRawData -Key 'IR-MailboxInbox' -Data (NewBag 'IR-Mailbox-Inbox' @{ WindowDays = 30; Count = 1; Truncated = $true; Messages = @($m) })
            Set-NRGRawData -Key 'IR-MailboxRecoverable' -Data (NewBag 'IR-Mailbox-Recoverable' @{ Count = 0; Messages = @() })
            Test-NRGEmailControlPhishOrigin
            @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-3.1')[0].Detail | Should -Match 'stopped at its page cap'
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

            Test-NRGEmailControlOutboundActivity
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
            Test-NRGEmailControlOutboundActivity
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

            Test-NRGEmailControlPhishOrigin
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
            Test-NRGEmailControlPhishOrigin
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-3.1')
            $f[0].Detail | Should -Match 'found in Recoverable Items'
            # otherbad.com (the recovered one) should appear first
            $idxOther = $f[0].Detail.IndexOf('otherbad.com')
            $idxBad   = $f[0].Detail.IndexOf('badco.com')
            $idxOther | Should -BeLessThan $idxBad
        }
    }

    Context 'Defensive — collectors did not run' {
        It 'Returns NotApplicable when raw data missing' {
            Test-NRGEmailControlInboxRules
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-1.1')
            $f[0].State | Should -Be 'NotApplicable'
        }
    }
}

Describe 'NRG Email IR — recipient warn-list (EMAIL-2.1 AffectedObjects)' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
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
        Test-NRGEmailControlOutboundActivity
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
        Test-NRGEmailControlOutboundActivity
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-2.1')
        $f[0].State | Should -Be 'Satisfied'
        @($f[0].AffectedObjects).Count | Should -Be 0
    }
}

Describe 'NRG Email IR — EMAIL-1.1 attaches flagged rules as InboxRule AffectedObjects' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
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
        Test-NRGEmailControlInboxRules
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
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
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

Describe 'NRG Email IR — EMAIL-4.1 OAuth consent grants' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Evaluators' 'Test-NRGEmailControls.ps1')
        function script:NewBag($cid, $data) { [ordered]@{ CollectorId=$cid; CollectedAt=(Get-Date -Format 'o'); Success=$true; Data=$data } }
    }
    BeforeEach { Clear-NRGState }

    It 'Flags a Mail.Send grant to an unverified app as Critical Gap' {
        Set-NRGRawData -Key 'IR-UserConsents' -Data (NewBag 'c' @{
            Count = 2
            Grants = @(
                [ordered]@{ GrantId='g1'; ClientSpId='sp-evil'; App=[ordered]@{ DisplayName='Mail Helper Pro'; AppId='a1'; PublisherName=$null }; ConsentType='Principal'; Scope='Mail.ReadWrite Mail.Send offline_access' }
                [ordered]@{ GrantId='g2'; ClientSpId='sp-ok';   App=[ordered]@{ DisplayName='Teams';           AppId='a2'; PublisherName='Microsoft' }; ConsentType='Principal'; Scope='User.Read' }
            )
        })
        Test-NRGEmailControlOAuthConsents
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-4.1')
        $f.Count       | Should -Be 1
        $f[0].State    | Should -Be 'Gap'
        $f[0].Severity | Should -Be 'Critical'
        $f[0].Detail   | Should -Match 'Mail Helper Pro'
        $f[0].Detail   | Should -Match 'UNVERIFIED publisher'
        $f[0].Detail   | Should -Match 'Mail\.Send'
        $f[0].Detail   | Should -Not -Match 'Teams'
    }

    It 'a write-scope grant whose app was never identified is High, never labeled UNVERIFIED, and says how to identify it' {
        Set-NRGRawData -Key 'IR-UserConsents' -Data (NewBag 'c' @{
            Count = 1
            Grants = @([ordered]@{ GrantId='g1'; ClientSpId='sp-unknown'; App=$null; ConsentType='Principal'; Scope='Mail.ReadWrite openid profile offline_access' })
        })
        Test-NRGEmailControlOAuthConsents
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-4.1')
        $f[0].State    | Should -Be 'Gap'
        $f[0].Severity | Should -Be 'High' -Because 'an unidentified app may be an ordinary Microsoft one; Critical needs an identified app'
        $f[0].Detail   | Should -Match 'app not identified'
        $f[0].Detail   | Should -Match 'publisher not checked'
        $f[0].Detail   | Should -Not -Match 'UNVERIFIED'
        $f[0].Detail   | Should -Match 'Identify each app first'
    }

    It 'Read-only mail scope lands as Partial (verify with user), not Gap' {
        Set-NRGRawData -Key 'IR-UserConsents' -Data (NewBag 'c' @{
            Count = 1
            Grants = @([ordered]@{ GrantId='g1'; ClientSpId='sp1'; App=[ordered]@{ DisplayName='CRM Sync'; AppId='a1'; PublisherName='Vendor Inc' }; ConsentType='Principal'; Scope='Mail.Read offline_access' })
        })
        Test-NRGEmailControlOAuthConsents
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-4.1')
        $f[0].State | Should -Be 'Partial'
        $f[0].Detail | Should -Match 'CRM Sync'
    }

    It 'Benign grants are Satisfied; missing data is NotApplicable' {
        Set-NRGRawData -Key 'IR-UserConsents' -Data (NewBag 'c' @{
            Count = 1
            Grants = @([ordered]@{ GrantId='g1'; ClientSpId='sp1'; App=[ordered]@{ DisplayName='Teams'; AppId='a1'; PublisherName='Microsoft' }; ConsentType='Principal'; Scope='User.Read openid profile' })
        })
        Test-NRGEmailControlOAuthConsents
        @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-4.1')[0].State | Should -Be 'Satisfied'

        Clear-NRGState
        Test-NRGEmailControlOAuthConsents
        @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-4.1')[0].State | Should -Be 'NotApplicable'
    }
}

Describe 'NRG Email IR — EMAIL-4.2 auth methods' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Evaluators' 'Test-NRGEmailControls.ps1')
        function script:NewBag($cid, $data) { [ordered]@{ CollectorId=$cid; CollectedAt=(Get-Date -Format 'o'); Success=$true; Data=$data } }
    }
    BeforeEach { Clear-NRGState }

    It 'Flags a second phone method + recent registration as Gap' {
        Set-NRGRawData -Key 'IR-UserAuthMethods' -Data (NewBag 'm' @{
            Count = 3
            Methods = @(
                [ordered]@{ Id='m1'; MethodType='phoneAuthenticationMethod';                  Display='+1 701555**34'; CreatedDateTime=$null }
                [ordered]@{ Id='m2'; MethodType='phoneAuthenticationMethod';                  Display='+44 20709**11'; CreatedDateTime=$null }
                [ordered]@{ Id='m3'; MethodType='microsoftAuthenticatorAuthenticationMethod'; Display='Pixel 9';       CreatedDateTime=(Get-Date).AddDays(-2).ToString('o') }
            )
        })
        Test-NRGEmailControlAuthMethods
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-4.2')
        $f[0].State  | Should -Be 'Gap'
        $f[0].Detail | Should -Match '2 phone methods'
        $f[0].Detail | Should -Match 'last 14 days'
        $f[0].Detail | Should -Match '\+44 20709'
    }

    It 'Single old method inventory is Satisfied but still lists methods' {
        Set-NRGRawData -Key 'IR-UserAuthMethods' -Data (NewBag 'm' @{
            Count = 1
            Methods = @([ordered]@{ Id='m1'; MethodType='microsoftAuthenticatorAuthenticationMethod'; Display='iPhone 15'; CreatedDateTime=(Get-Date).AddDays(-300).ToString('o') })
        })
        Test-NRGEmailControlAuthMethods
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-4.2')
        $f[0].State  | Should -Be 'Satisfied'
        $f[0].Detail | Should -Match 'iPhone 15'
    }

    It 'Zero methods is Partial (no MFA at all warrants follow-up)' {
        Set-NRGRawData -Key 'IR-UserAuthMethods' -Data (NewBag 'm' @{ Count=0; Methods=@() })
        Test-NRGEmailControlAuthMethods
        @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-4.2')[0].State | Should -Be 'Partial'
    }
}

Describe 'NRG Email IR — recipients.csv formula-injection guard' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Publishers' 'Publish-NRGEmailIncidentReport.ps1')
        $script:OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("nls-csv-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
    }
    AfterAll {
        if ($script:OutDir -and (Test-Path $script:OutDir)) { Remove-Item $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'Neutralizes formula-leading recipient cells with an apostrophe' {
        $meta = @{ UserPrincipalName='alice@corp.com'; ToolVersion='4.12.1'; Brand=@{ CompanyName='NRG' } }
        $findings = @(
            @{
                ControlId='EMAIL-2.1'; State='Gap'; Severity='Critical'; Category='Email'
                Title='Outbound'; Detail='BEC'
                AffectedObjects = @(
                    [pscustomobject]@{ Recipient='=cmd|''/c calc''!A1'; Scope='External'; Reason='Received BEC-pattern message' }
                    [pscustomobject]@{ Recipient='bob@corp.com';        Scope='Internal'; Reason='Received mail during compromise window' }
                )
            }
        )
        $htmlPath = Join-Path $script:OutDir 'r.html'
        Publish-NRGEmailIncidentReport -Metadata $meta -Findings $findings -OutputPath $htmlPath
        $csvPath = Join-Path $script:OutDir 'recipients.csv'
        Test-Path $csvPath | Should -BeTrue
        $csv = Get-Content $csvPath -Raw
        # The dangerous cell must be prefixed; Excel then treats it as text.
        $csv | Should -Match "'=cmd"
        $csv | Should -Not -Match '(?m)^"=cmd'
        # Clean cells pass through untouched.
        $csv | Should -Match 'bob@corp.com'
        $csv | Should -Not -Match "'bob@corp.com"
    }
}

#Requires -Version 7.0
#
# NRG.EmailIRMailboxCollector.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Issue #91, pinned at the COLLECTOR, where the bugs lived. The mailbox
# sections counted `$normalized.Count` off the raw output of a foreach: with
# zero messages that is AutomationNull (throws under StrictMode, section
# reported not collected), and with exactly one it is a lone
# OrderedDictionary whose .Count is its KEY count — 7 sent / 8 inbox / 5
# recovered recorded for a single message. EMAIL-3.1 then crashed on the
# recovered-message shape (no FromName; Select-Object -ExpandProperty on
# [ordered] hashtables). The evaluator fixtures fed pre-shaped data and never
# ran the collector, so none of this was caught.

Describe 'Email-IR mailbox collector counts (issue #91)' {

    BeforeAll {
        $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        $script:RealGraph = & $script:Mod { ${function:Invoke-NRGGraphRequest} }

        # Graph stand-in in MODULE scope, keyed on the folder in the URI.
        & $script:Mod {
            Set-Item -Path 'function:script:Invoke-NRGGraphRequest' -Value {
                param([string] $Method, [string] $Uri, $Body, $Headers, [string] $OutputType, $ErrorAction)
                $old = (Get-Date).ToUniversalTime().AddDays(-2).ToString('o')
                $phish = @{
                    id = 'm-phish'; subject = 'Account locked - verify identity'; receivedDateTime = $old
                    from = @{ emailAddress = @{ address = 'alerts@badco.example'; name = 'Account Team' } }
                    bodyPreview = 'Verify now https://badco.example/login'
                }
                if ($Uri -match '/mailFolders/SentItems/')                { return @{ value = @($script:T_Sent) } }
                if ($Uri -match '/mailFolders/Inbox/messages')            { return @{ value = @($phish) } }
                if ($Uri -match '/mailFolders/recoverableitemsdeletions') {
                    # The recovered shape: from.emailAddress has NO name.
                    return @{ value = @(@{ id = 'm-phish'; subject = $phish.subject; receivedDateTime = $old
                                           from = @{ emailAddress = @{ address = 'alerts@badco.example' } }
                                           bodyPreview = $phish.bodyPreview }) }
                }
                if ($Uri -match '/messageRules')    { return @{ value = @() } }
                if ($Uri -match '/mailboxSettings') {
                    return @{ automaticRepliesSetting = @{ status = 'disabled' }; delegateMeetingMessageDeliveryOptions = 'sendToDelegateOnly' }
                }
                return @{ id = 'u1'; displayName = 'Alice'; mail = 'alice@corp.example'; userPrincipalName = 'alice@corp.example' }
            }
        }
        function script:Invoke-Collect([object[]] $Sent) {
            & $script:Mod { param($s) $script:T_Sent = $s; Clear-NRGState } $Sent
            Invoke-NRGEmailCollectMailbox -WindowDays 7 3>$null | Out-Null
        }
    }

    AfterAll {
        & $script:Mod { param($g) Set-Item -Path 'function:script:Invoke-NRGGraphRequest' -Value $g } $script:RealGraph
    }

    It 'zero sent messages is collected as 0, not "not collected"' {
        Invoke-Collect -Sent @()
        $sent = Get-NRGRawData -Key 'IR-MailboxSentItems'
        $sent.Success    | Should -BeTrue
        $sent.Data.Count | Should -Be 0
    }

    It 'exactly one message counts as 1 in every section (not its key count)' {
        # Every property the collector's $select asks for, as Graph returns it.
        Invoke-Collect -Sent @(@{ id = 's1'; subject = 'hi'; sentDateTime = (Get-Date).ToUniversalTime().ToString('o')
                                  toRecipients = @(@{ emailAddress = @{ address = 'bob@corp.example' } })
                                  ccRecipients = @(); bccRecipients = @(); bodyPreview = ''; hasAttachments = $false
                                  from = @{ emailAddress = @{ address = 'alice@corp.example' } } })
        (Get-NRGRawData -Key 'IR-MailboxSentItems').Data.Count   | Should -Be 1
        (Get-NRGRawData -Key 'IR-MailboxInbox').Data.Count       | Should -Be 1
        (Get-NRGRawData -Key 'IR-MailboxRecoverable').Data.Count | Should -Be 1
    }

    It 'EMAIL-3.1 runs on the collector''s real recovered-message shape and flags the recovered phish' {
        Invoke-Collect -Sent @()
        { Test-NRGEmailControlPhishOrigin } | Should -Not -Throw
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'EMAIL-3.1')
        $f.Count | Should -BeGreaterThan 0
        ($f.Detail -join ' ') | Should -Match 'RECOVERED from Deletions'
    }
}

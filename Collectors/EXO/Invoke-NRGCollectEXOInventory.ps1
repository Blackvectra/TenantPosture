#Requires -Version 7.0
#
# Invoke-NRGCollectEXOInventory.ps1  (v4.5.6)
# Per-mailbox inventory for named findings the EXO/Inventory evaluators consume.
#
# READ-ONLY: Uses EXO V3 Get-* cmdlets and Graph GET for AAD cross-reference only.
#
# Returns: structured hashtable under key 'EXO-Inventory' via Set-NRGRawData.
# Reads:   Get-Mailbox, Get-CASMailbox, Get-InboxRule, Get-AcceptedDomain,
#          Get-Recipient (resolves legacy-DN rule recipients),
#          plus AAD-Users raw data (set by Invoke-NRGCollectAADUsers).
#
# Data populated:
#   - ForwardingMailboxes      mailboxes with ForwardingSmtpAddress OR
#                              ForwardingAddress set; one row per mechanism,
#                              each classified External/Internal/Unresolved
#   - InboxRulesForwarding     mailbox rules forwarding to external recipients
#                              (actual exfil vector after credential compromise)
#   - UnparseableRules         rules Exchange could not interpret — a coverage
#                              gap, never evidence of a rule that does nothing
#   - SharedMailboxSignIn      shared mailboxes whose AAD account is not blocked
#                              (sign-in attack surface — should be BlockCredential)
#   - AllSharedMailboxes       inventory join key for evaluators
#   - AuditDisabledMailboxes   mailboxes with AuditEnabled = $false
#   - SmtpAuthEnabledPerUser   per-user SMTP AUTH override bypassing org disable
#
# NIST SP 800-53: AU-2 (audit events), AC-6 (least privilege), SI-8 (spam protection)
# MITRE ATT&CK:   T1114.003 (Email Forwarding Rule), T1098 (Account Manipulation),
#                 T1078 (Valid Accounts)
#

function Invoke-NRGCollectEXOInventory {
    [CmdletBinding()] param(
        # Cap how many mailboxes we scan inbox rules on for very large tenants.
        # A real attacker only needs one compromised mailbox to set up exfil, so
        # sampling is not a substitute; we want full coverage when feasible.
        # 0 = unlimited.
        [int] $InboxRuleScanLimit = 2000
    )

    $result = @{
        Success = $false
        Data = @{
            ForwardingMailboxes    = @()
            InboxRulesForwarding   = @()
            SharedMailboxSignIn    = @()
            AllSharedMailboxes     = @()
            AuditDisabledMailboxes = @()
            SmtpAuthEnabledPerUser = @()
            SmtpAuthEnabledPerUserCount = 0
            AuditBypassAccounts    = @()
            InboundConnectors      = @()
            OutboundConnectors     = @()
            TransportRules         = @()
            TenantAllowBlockList   = @()
            MailboxRecoverability  = $null
            # Rules Exchange returned a "contains errors" warning for. Their
            # action properties come back empty, so they are rules we could not
            # read — never rules with nothing in them.
            UnparseableRules       = @()
            Stats = @{
                MailboxesScanned         = 0
                MailboxesRuleScanFailed  = 0
                InboxRulesEvaluated      = 0
                UnparseableRuleWarnings  = 0
                AcceptedDomainsKnown     = 0
                ScanLimitReached         = $false
                HiddenRulesIncluded      = $false
            }
            # Per-section collection outcome. Every list above defaults to @(),
            # and each query below has its own try/catch so one failure does not
            # abort the rest — but that means an EMPTY list is ambiguous: it can
            # mean "scanned, found nothing" (good) or "the query failed" (unknown).
            # Success alone cannot distinguish them, so evaluators that would
            # otherwise read an empty list as compliance MUST consult this map.
            # Reporting "no external forwarding found" after a throttled
            # Get-Mailbox is a false clean bill of health on the primary BEC
            # exfiltration check.
            SectionStatus = @{
                ForwardingMailboxes    = 'NotRun'
                InboxRulesForwarding   = 'NotRun'
                SharedMailboxes        = 'NotRun'
                AuditDisabledMailboxes = 'NotRun'
                SmtpAuthEnabledPerUser = 'NotRun'
                AuditBypassAccounts    = 'NotRun'
                MailFlowConnectors     = 'NotRun'
                TransportRules         = 'NotRun'
                TenantAllowBlockList   = 'NotRun'
                MailboxRecoverability  = 'NotRun'
            }
        }
    }

    try {
        # ── Build the tenant's accepted-domain set up front ──────────────────
        # We use it to classify rule recipients as internal vs external.
        $acceptedDomains = @()
        # Set when Get-AcceptedDomain itself failed (as opposed to legitimately
        # returning no domains). $acceptedDomains staying @() gives the
        # classifier no basis for a verdict — Get-NRGRecipientClass treats an
        # empty accepted-domain set as "nothing is internal" and returns
        # External for every recipient, so a throttled read here would score
        # every internal forward and delegation as BEC exfiltration. The
        # sections built from it below are marked 'Failed' rather than
        # 'Collected' so evaluators do not trust that verdict.
        $acceptedDomainsFailed = $false
        try {
            $acc = @(Get-AcceptedDomain -ErrorAction Stop)
            # Read the field before calling a method on it: a null DomainName
            # would throw here and leave $acceptedDomains empty, which classifies
            # every recipient in the tenant as External.
            $acceptedDomains = @($acc | ForEach-Object {
                [string](Get-NRGObjectField -Item $_ -Key 'DomainName' -Default '')
            } | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
            $result.Data.Stats.AcceptedDomainsKnown = $acceptedDomains.Count
        } catch {
            $acceptedDomainsFailed = $true
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-Inventory-AcceptedDomains' -Message $_.Exception.Message
            }
        }

        # ── Recipient classification: External / Internal / Unresolved ───────
        # Tri-state on purpose. The old boolean collapsed "we know it is
        # internal" and "we could not tell" into the same $false, which is the
        # same class of mistake as reading an empty list as compliance.
        #
        # Exchange renders rule recipients as:
        #     "Display Name" [SMTP:user@dom.tld]     <- address appears TWICE
        #     "Display Name" [EX:/o=ExchangeLabs/...] <- legacy DN, no address
        # while ForwardingSmtpAddress is a bare  smtp:user@dom.tld.
        #
        # A naive  -split '@'  on the first form yields THREE elements, so the
        # old  if ($atSplit.Count -ne 2) { return $false }  guard rejected every
        # genuine external rule recipient and classified it internal. Mailbox
        # forwarding parsed correctly only by luck, because its shape has one
        # '@'. That is why EXO-7.2 reported clean on a tenant with external
        # forwarding rules: the list was not empty-from-failure, it was
        # empty-from-wrong-answer, so every SectionStatus guard passed.

        # Distinct-recipient cache; resolution costs an EXO round trip and the
        # same recipient recurs across mailboxes.
        $recipientClassCache = @{}

        # Read-only resolution for legacy DNs and unparseable display names.
        # Injected rather than called inline so the classifier is testable
        # without a live Exchange session — the absence of exactly that was
        # why the old parser shipped broken.
        # Get-Recipient exists in the Security & Compliance session too; an
        # unqualified call resolves there once Purview is connected, and legacy
        # DNs stop resolving (2 unresolved rules without Purview, 13 with, on a
        # live tenant). Pin it to the Exchange Online session.
        $getRecipientCmd = (Get-NRGExoCommand -Name 'Get-Recipient' -Session ExchangeOnline).Command
        $recipientResolver = {
            param([string] $Lookup)
            if (-not $getRecipientCmd) { return $null }
            @(& $getRecipientCmd -Identity $Lookup -ErrorAction Stop) | Select-Object -First 1
        }.GetNewClosure()

        $classifyRecipient = {
            param([string] $Recipient)
            Get-NRGRecipientClass -Recipient $Recipient -AcceptedDomains $acceptedDomains `
                -Cache $recipientClassCache -Resolver $recipientResolver
        }

        # ── Forwarding via ForwardingSmtpAddress OR ForwardingAddress ────────
        # Both properties forward mail and either one alone is a complete exfil
        # channel. Filtering on ForwardingSmtpAddress only made every mailbox
        # using ForwardingAddress invisible to the whole assessment — and
        # ForwardingAddress points at a recipient object, which a mail contact
        # satisfies, so that blind spot covers forwarding to an external
        # contact: exactly the case the control exists to catch.
        try {
            $fwd = @(Get-Mailbox -ResultSize Unlimited `
                -Filter "ForwardingSmtpAddress -ne `$null -or ForwardingAddress -ne `$null" -ErrorAction Stop)

            $fwdRows = [System.Collections.Generic.List[object]]::new()
            foreach ($mbx in $fwd) {
                # A mailbox can carry both. Emit one row per mechanism rather
                # than picking a winner — hiding either one hides a live
                # forwarding path. Evaluators count distinct mailboxes.
                $targets = @()
                $smtpTarget = [string](Get-NRGObjectField -Item $mbx -Key 'ForwardingSmtpAddress' -Default '')
                $objTarget  = [string](Get-NRGObjectField -Item $mbx -Key 'ForwardingAddress' -Default '')
                if (-not [string]::IsNullOrWhiteSpace($smtpTarget)) { $targets += , @('ForwardingSmtpAddress', $smtpTarget) }
                if (-not [string]::IsNullOrWhiteSpace($objTarget))  { $targets += , @('ForwardingAddress', $objTarget) }

                foreach ($t in $targets) {
                    $class = & $classifyRecipient $t[1]
                    $fwdRows.Add(@{
                        DisplayName                = [string]$mbx.DisplayName
                        UPN                        = [string]$mbx.UserPrincipalName
                        ForwardingAddress          = [string]$t[1]
                        ForwardingMechanism        = [string]$t[0]
                        Classification             = $class
                        IsExternal                 = ($class -eq 'External')
                        DeliverToMailboxAndForward = [bool]$mbx.DeliverToMailboxAndForward
                        MailboxType                = [string]$mbx.RecipientTypeDetails
                    })
                }
            }
            $result.Data.ForwardingMailboxes = @($fwdRows)
            # Every row above was classified against $acceptedDomains; if that
            # read failed, every classification is a false External and this
            # section is not evidence, whatever the mailbox query itself did.
            $result.Data.SectionStatus.ForwardingMailboxes = if ($acceptedDomainsFailed) { 'Failed' } else { 'Collected' }
        } catch {
            $result.Data.SectionStatus.ForwardingMailboxes = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-ForwardingMailboxes' -Message $_.Exception.Message
            }
        }

        # ── Inbox rules with ForwardTo / ForwardAsAttachmentTo / RedirectTo ──
        # This is the post-credential-compromise exfil pattern: attacker creates
        # an Outlook rule that quietly forwards or redirects mail to a domain
        # they control. ForwardingSmtpAddress alone misses this entirely.
        try {
            $boxes = if ($InboxRuleScanLimit -le 0) {
                @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop)
            } else {
                @(Get-Mailbox -ResultSize $InboxRuleScanLimit -ErrorAction Stop)
            }
            $result.Data.Stats.MailboxesScanned = $boxes.Count
            if ($InboxRuleScanLimit -gt 0 -and $boxes.Count -eq $InboxRuleScanLimit) {
                $result.Data.Stats.ScanLimitReached = $true
            }

            # -IncludeHidden surfaces rules planted through EWS or Graph rather
            # than Outlook. That is the actual attacker path, and without it the
            # sweep cannot see the rules it exists to find. Probed rather than
            # assumed: on an EXO module that lacks the parameter a hard splat
            # would throw per mailbox and fail the entire sweep.
            $supportsIncludeHidden = $false
            $gcInboxRule = Get-Command Get-InboxRule -ErrorAction SilentlyContinue
            if ($gcInboxRule -and $gcInboxRule.Parameters -and $gcInboxRule.Parameters.ContainsKey('IncludeHidden')) {
                $supportsIncludeHidden = $true
            }
            $result.Data.Stats.HiddenRulesIncluded = $supportsIncludeHidden

            $rulesFound      = [System.Collections.Generic.List[object]]::new()
            $unparseableList = [System.Collections.Generic.List[object]]::new()
            foreach ($mbx in $boxes) {
                try {
                    $ruleParams = @{
                        Mailbox         = $mbx.UserPrincipalName
                        ErrorAction     = 'Stop'
                        WarningAction   = 'SilentlyContinue'
                        WarningVariable = 'ruleWarn'
                    }
                    if ($supportsIncludeHidden) { $ruleParams['IncludeHidden'] = $true }
                    $ruleWarn = $null
                    $rules = @(Get-InboxRule @ruleParams)

                    # Exchange warns rather than throws on a rule whose actions
                    # it cannot interpret, and returns the rule with its action
                    # properties empty. Swallowing that warning turns a rule we
                    # could NOT read into a rule with no forwarding — a coverage
                    # gap reported as a pass, on the BEC persistence check.
                    foreach ($w in @($ruleWarn)) {
                        if ($null -eq $w) { continue }
                        if ($unparseableList.Count -ge 250) { break }
                        $unparseableList.Add([ordered]@{
                            Mailbox = [string]$mbx.UserPrincipalName
                            Warning = [string]$w
                        })
                    }

                    foreach ($r in $rules) {
                        $result.Data.Stats.InboxRulesEvaluated++

                        # Aggregate every recipient surface: ForwardTo,
                        # ForwardAsAttachmentTo, RedirectTo. Each is a string[]
                        # of SMTP / display-name entries.
                        $recipients = @()
                        if ($r.ForwardTo)             { $recipients += @($r.ForwardTo) }
                        if ($r.ForwardAsAttachmentTo) { $recipients += @($r.ForwardAsAttachmentTo) }
                        if ($r.RedirectTo)            { $recipients += @($r.RedirectTo) }
                        if ($recipients.Count -eq 0)  { continue }

                        $classified = @($recipients | ForEach-Object {
                            $rcptStr = [string]$_
                            @{ Recipient = $rcptStr; Class = (& $classifyRecipient $rcptStr) }
                        })
                        $externalHits = @($classified | Where-Object { $_.Class -eq 'External' } |
                            ForEach-Object { [string]$_.Recipient })
                        $unresolvedHits = @($classified | Where-Object { $_.Class -eq 'Unresolved' } |
                            ForEach-Object { [string]$_.Recipient })

                        # Only surface a rule when it's forwarding or when it's
                        # disabled (disabled rules can be re-enabled silently —
                        # attackers stage them ahead of activation).
                        if ($externalHits.Count -gt 0 -or $unresolvedHits.Count -gt 0 -or -not $r.Enabled) {
                            $rulesFound.Add([ordered]@{
                                Mailbox      = [string]$mbx.UserPrincipalName
                                DisplayName  = [string]$mbx.DisplayName
                                RuleName     = [string]$r.Name
                                Enabled      = [bool]$r.Enabled
                                Priority     = $r.Priority
                                Recipients   = @($recipients | ForEach-Object { [string]$_ })
                                ExternalRecipients = $externalHits
                                UnresolvedRecipients = $unresolvedHits
                                IsExternal   = ($externalHits.Count -gt 0)
                                IsUnresolved = ($unresolvedHits.Count -gt 0)
                                ForwardAction = @(
                                    if ($r.ForwardTo)             { 'ForwardTo' }
                                    if ($r.ForwardAsAttachmentTo) { 'ForwardAsAttachmentTo' }
                                    if ($r.RedirectTo)            { 'RedirectTo' }
                                ) -join ','
                            })
                        }
                    }
                } catch {
                    # Per-mailbox failure is non-fatal — record it and continue.
                    # But COUNT it: a sweep where most mailboxes threw is not a
                    # clean sweep, and the section status alone cannot say so.
                    $result.Data.Stats.MailboxesRuleScanFailed++
                    if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                        Register-NRGException -Source 'EXO-InboxRule' `
                            -Message "[$($mbx.UserPrincipalName)] $($_.Exception.Message)"
                    }
                }
            }
            $result.Data.InboxRulesForwarding = @($rulesFound)
            $result.Data.UnparseableRules     = @($unparseableList)
            $result.Data.Stats.UnparseableRuleWarnings = $unparseableList.Count
            # Same basis problem as ForwardingMailboxes above: every recipient
            # here was run through the same accepted-domain classifier.
            $result.Data.SectionStatus.InboxRulesForwarding = if ($acceptedDomainsFailed) { 'Failed' } else { 'Collected' }
        } catch {
            $result.Data.SectionStatus.InboxRulesForwarding = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-InboxRulesForwarding' -Message $_.Exception.Message
            }
        }

        # ── Shared mailboxes — cross-reference AAD for real sign-in state ────
        # The previous proxy via LicenseReconciliationNeeded was unreliable.
        # AAD-Users raw data (set by Invoke-NRGCollectAADUsers) holds the truth:
        # accountEnabled = $true on a shared mailbox account means sign-in is
        # possible. Each licensed shared mailbox with accountEnabled is an
        # attack-surface entry that should be BlockCredential / disabled.
        try {
            $shared = @(Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -ErrorAction Stop)
            $result.Data.AllSharedMailboxes = @($shared | ForEach-Object {
                @{
                    DisplayName          = [string]$_.DisplayName
                    PrimarySmtp          = [string]$_.PrimarySmtpAddress
                    Guid                 = [string]$_.Guid
                    UPN                  = [string]$_.UserPrincipalName
                    ExternalEmailAddress = [string](Get-NRGObjectField -Item $_ -Key 'ExternalEmailAddress' -Default '')
                }
            })

            # Pull AAD user data; if collector didn't run, fall back to the
            # weaker LicenseReconciliationNeeded heuristic.
            $aadUsers = $null
            if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) {
                $aad = Get-NRGRawData -Key 'AAD-Users'
                if ($aad -and $aad.Success -and $aad.Data.Users) {
                    $aadUsers = @{}
                    foreach ($u in @($aad.Data.Users)) {
                        if ($u.UserPrincipalName) {
                            $aadUsers[[string]$u.UserPrincipalName] = $u
                        }
                    }
                }
            }

            $signInRisky = foreach ($mbx in $shared) {
                $upn = [string]$mbx.UserPrincipalName
                $aadHit = if ($aadUsers) { $aadUsers[$upn] } else { $null }
                if ($aadHit) {
                    # accountEnabled comes through Graph; if missing assume $true
                    # for shared mailboxes (default state) which is the unsafe side
                    $enabled = if ($null -ne $aadHit.AccountEnabled) { [bool]$aadHit.AccountEnabled } else { $true }
                    if (-not $enabled) { continue }
                    [ordered]@{
                        DisplayName = [string]$mbx.DisplayName
                        UPN         = $upn
                        PrimarySmtp = [string]$mbx.PrimarySmtpAddress
                        SignInState = 'Enabled'
                        Source      = 'AAD-Users'
                    }
                } else {
                    # No AAD data — fall back to the per-mailbox heuristic
                    # Get-Mailbox omitted LicenseReconciliationNeeded on a live tenant and
                    # the dot-access threw under StrictMode, failing the whole section
                    # (and EXO-2.6 then read the empty sign-in list as a pass).
                    $licRecon = Get-NRGObjectField -Item $mbx -Key 'LicenseReconciliationNeeded' -Default $false
                    $skuAsg   = Get-NRGObjectField -Item $mbx -Key 'SkuAssigned' -Default $false
                    if ([bool]$licRecon -or [bool]$skuAsg) {
                        [ordered]@{
                            DisplayName = [string]$mbx.DisplayName
                            UPN         = $upn
                            PrimarySmtp = [string]$mbx.PrimarySmtpAddress
                            SignInState = 'Probable'  # weaker signal
                            Source      = 'LicenseProxy'
                        }
                    }
                }
            }
            $result.Data.SharedMailboxSignIn = @($signInRisky)
            $result.Data.SectionStatus.SharedMailboxes = 'Collected'
        } catch {
            $result.Data.SectionStatus.SharedMailboxes = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-SharedMailbox' -Message $_.Exception.Message
            }
        }

        # ── Audit explicitly disabled per mailbox ────────────────────────────
        try {
            $noAudit = @(Get-Mailbox -ResultSize Unlimited -Filter "AuditEnabled -eq `$false" -ErrorAction Stop)
            $result.Data.AuditDisabledMailboxes = @($noAudit | ForEach-Object {
                @{
                    DisplayName = [string]$_.DisplayName
                    UPN         = [string]$_.UserPrincipalName
                    MailboxType = [string]$_.RecipientTypeDetails
                }
            })
            $result.Data.SectionStatus.AuditDisabledMailboxes = 'Collected'
        } catch {
            $result.Data.SectionStatus.AuditDisabledMailboxes = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AuditDisabled' -Message $_.Exception.Message
            }
        }

        # ── Mailbox audit bypass (EXO-6.3, EXO-7.3) ──────────────────────────
        # With mailbox auditing on by default, Exchange IGNORES a mailbox's
        # AuditEnabled = False (Microsoft: "Manage mailbox auditing"). The only
        # per-user way to stop mailbox actions being logged is an audit
        # bypass association, which silences everything the account does in
        # any mailbox. That is what these controls must read.
        try {
            $bypass = @(Get-MailboxAuditBypassAssociation -ResultSize Unlimited -ErrorAction Stop |
                Where-Object { (Get-NRGObjectField -Item $_ -Key 'AuditBypassEnabled' -Default $false) -eq $true })
            $result.Data.AuditBypassAccounts = @($bypass | ForEach-Object {
                @{
                    Name     = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
                    Identity = [string](Get-NRGObjectField -Item $_ -Key 'Identity' -Default '')
                }
            })
            $result.Data.SectionStatus.AuditBypassAccounts = 'Collected'
        } catch {
            $result.Data.SectionStatus.AuditBypassAccounts = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AuditBypass' -Message $_.Exception.Message
            }
        }

        # ── Per-user SMTP AUTH overrides (bypass org-level disable) ──────────
        try {
            $smtpEnabled = @(Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop |
                Where-Object { (Get-NRGObjectField -Item $_ -Key 'SmtpClientAuthenticationDisabled' -Default $null) -eq $false })
            # The named list is capped; the count is not. Reporting the capped
            # list's length said "100 users" on a tenant with 250.
            $result.Data.SmtpAuthEnabledPerUserCount = $smtpEnabled.Count
            $result.Data.SmtpAuthEnabledPerUser = @($smtpEnabled | Select-Object -First 100 | ForEach-Object {
                $id = [string](Get-NRGObjectField -Item $_ -Key 'PrimarySmtpAddress' -Default '')
                if (-not $id) { $id = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '') }
                @{
                    DisplayName = [string](Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '')
                    UPN         = $id
                }
            })
            $result.Data.SectionStatus.SmtpAuthEnabledPerUser = 'Collected'
        } catch {
            $result.Data.SectionStatus.SmtpAuthEnabledPerUser = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-SMTPAuthPerUser' -Message $_.Exception.Message
            }
        }

        # ── Mailbox recoverability (EXO-9.1, EXO-9.2) ────────────────────────
        # What survives a deletion. Two independent windows:
        #
        #   A hold — litigation hold, an In-Place hold, or a retention policy —
        #   preserves content past a user hard-delete and past the mailbox
        #   itself being removed. Without one, a departing employee's mailbox is
        #   gone 30 days after the account is deleted, and a hard-deleted item
        #   is gone as soon as the recoverable-items window closes.
        #
        #   RetainDeletedItemsFor is that window. It defaults to 14 days and
        #   caps at 30. Fourteen days is a fortnight to notice that mail is
        #   missing, which is routinely not long enough — ransomware and BEC are
        #   frequently discovered later than that.
        #
        # Counts and a capped named list, not a full dump: this is inventory,
        # not a mailbox export, and the JSON already carries UPNs elsewhere.
        try {
            $mbx = @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop |
                     Where-Object { $_.RecipientTypeDetails -notin @('DiscoveryMailbox') })
            # Organization-wide Purview retention policies are stamped on the
            # ORGANIZATION's InPlaceHolds ("mbx<guid>:<n>"), not on each
            # mailbox; a mailbox excluded from one carries "-mbx<guid>". The
            # mailbox's RetentionPolicy is the MRM policy ("Default MRM
            # Policy" on every mailbox) — it moves and deletes mail and holds
            # nothing, so counting it made every mailbox look held.
            $orgHolds = @()
            $orgHoldsRead = $false
            try {
                $orgCfg = Get-OrganizationConfig -ErrorAction Stop
                $orgHolds = @(@(Get-NRGObjectField -Item $orgCfg -Key 'InPlaceHolds' -Default @()) |
                    ForEach-Object { ([string]$_ -split ':')[0] } | Where-Object { $_ -and -not $_.StartsWith('-') })
                $orgHoldsRead = $true
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'EXO-OrgHolds' -Message $_.Exception.Message
                }
            }
            $noHold = @()
            $shortWindow = @()
            $windowDays = @()
            foreach ($m in $mbx) {
                $lit   = [bool](Get-NRGObjectField -Item $m -Key 'LitigationHoldEnabled' -Default $false)
                $inPl  = @(@(Get-NRGObjectField -Item $m -Key 'InPlaceHolds' -Default @()) | ForEach-Object { [string]$_ } | Where-Object { $_ })
                $excluded = @($inPl | Where-Object { $_.StartsWith('-') } | ForEach-Object { ($_.Substring(1) -split ':')[0] })
                $ownHold  = @($inPl | Where-Object { -not $_.StartsWith('-') }).Count -gt 0
                $orgHold  = @($orgHolds | Where-Object { $_ -notin $excluded }).Count -gt 0
                $held  = $lit -or $ownHold -or $orgHold
                $upn   = [string](Get-NRGObjectField -Item $m -Key 'UserPrincipalName')
                if (-not $held) { $noHold += @{ UPN = $upn; DisplayName = [string](Get-NRGObjectField -Item $m -Key 'DisplayName') } }

                # RetainDeletedItemsFor arrives as a timespan-ish object whose
                # shape varies by EXO module version; read it as a string and
                # take the day component rather than trusting a .Days property.
                $raw = [string](Get-NRGObjectField -Item $m -Key 'RetainDeletedItemsFor')
                $days = $null
                if ($raw -match '^(\d+)\.') { $days = [int]$Matches[1] }
                elseif ($raw -match '^(\d+):') { $days = 0 }
                if ($null -ne $days) {
                    $windowDays += $days
                    if ($days -lt 30) { $shortWindow += @{ UPN = $upn; Days = $days } }
                }
            }
            $result.Data.MailboxRecoverability = @{
                TotalMailboxes      = $mbx.Count
                OrgHoldsRead        = $orgHoldsRead
                WithHold            = ($mbx.Count - $noHold.Count)
                WithoutHold         = $noHold.Count
                WithoutHoldSample   = @($noHold | Select-Object -First 100)
                ShortRetentionCount = $shortWindow.Count
                ShortRetentionSample= @($shortWindow | Select-Object -First 100)
                MinRetentionDays    = $(if ($windowDays.Count) { ($windowDays | Measure-Object -Minimum).Minimum } else { $null })
            }
            $result.Data.SectionStatus.MailboxRecoverability = 'Collected'
        } catch {
            $result.Data.SectionStatus.MailboxRecoverability = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-MailboxRecoverability' -Message $_.Exception.Message
            }
        }

        # ── Mail flow connectors (EXO-8.1) ───────────────────────────────────
        # An inbound or outbound connector is how mail is routed into or out of
        # the tenant, and a connector an attacker adds is durable persistence
        # that survives a password reset: it is not in anybody's mailbox and
        # nothing about it looks like an inbox rule.
        try {
            $inb = @()
            # A missing cmdlet (EXO not connected, or the signed-in role cannot run it -
            # Exchange RBAC hides such cmdlets) is a FAILED read, never "none exist".
            if (-not (Get-Command Get-InboundConnector -ErrorAction SilentlyContinue)) { throw 'Get-InboundConnector is not available in this session.' }
            $inb = @(Get-InboundConnector -ErrorAction Stop)
            $result.Data.InboundConnectors = @($inb | ForEach-Object {
                @{
                    Name             = [string](Get-NRGObjectField -Item $_ -Key 'Name')
                    Enabled          = [bool](Get-NRGObjectField -Item $_ -Key 'Enabled' -Default $false)
                    ConnectorType    = [string](Get-NRGObjectField -Item $_ -Key 'ConnectorType')
                    SenderDomains    = @(Get-NRGObjectField -Item $_ -Key 'SenderDomains' -Default @()) | ForEach-Object { [string]$_ }
                    SenderIPAddresses= @(Get-NRGObjectField -Item $_ -Key 'SenderIPAddresses' -Default @()) | ForEach-Object { [string]$_ }
                    RequireTls       = [bool](Get-NRGObjectField -Item $_ -Key 'RequireTls' -Default $false)
                    RestrictDomainsToIPAddresses = [bool](Get-NRGObjectField -Item $_ -Key 'RestrictDomainsToIPAddresses' -Default $false)
                    WhenCreated      = [string](Get-NRGObjectField -Item $_ -Key 'WhenCreated')
                }
            })

            $outb = @()
            # A missing cmdlet (EXO not connected, or the signed-in role cannot run it -
            # Exchange RBAC hides such cmdlets) is a FAILED read, never "none exist".
            if (-not (Get-Command Get-OutboundConnector -ErrorAction SilentlyContinue)) { throw 'Get-OutboundConnector is not available in this session.' }
            # Test-mode connectors are omitted unless asked for (Exchange warns
            # "at least one test mode connector which is not included"), and a
            # connector left out is a connector never reviewed.
            $outb = @(Get-OutboundConnector -IncludeTestModeConnectors $true -ErrorAction Stop)
            $result.Data.OutboundConnectors = @($outb | ForEach-Object {
                @{
                    Name          = [string](Get-NRGObjectField -Item $_ -Key 'Name')
                    Enabled       = [bool](Get-NRGObjectField -Item $_ -Key 'Enabled' -Default $false)
                    ConnectorType = [string](Get-NRGObjectField -Item $_ -Key 'ConnectorType')
                    SmartHosts    = @(Get-NRGObjectField -Item $_ -Key 'SmartHosts' -Default @()) | ForEach-Object { [string]$_ }
                    RecipientDomains = @(Get-NRGObjectField -Item $_ -Key 'RecipientDomains' -Default @()) | ForEach-Object { [string]$_ }
                    TlsSettings   = [string](Get-NRGObjectField -Item $_ -Key 'TlsSettings')
                    IsTransportRuleScoped = [bool](Get-NRGObjectField -Item $_ -Key 'IsTransportRuleScoped' -Default $false)
                    TestMode      = [bool](Get-NRGObjectField -Item $_ -Key 'TestMode' -Default $false)
                    WhenCreated   = [string](Get-NRGObjectField -Item $_ -Key 'WhenCreated')
                }
            })
            $result.Data.SectionStatus.MailFlowConnectors = 'Collected'
        } catch {
            $result.Data.SectionStatus.MailFlowConnectors = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-MailFlowConnectors' -Message $_.Exception.Message
            }
        }

        # ── Transport rule CONTENTS (EXO-8.2) ────────────────────────────────
        # EXO-3.5 audits whether transport-rule CHANGES are logged. It does not
        # look at what the rules do. A transport rule that redirects or blind-
        # copies mail to an external address is org-wide exfiltration that
        # bypasses the per-mailbox forwarding controls entirely — EXO-1.3 and
        # EXO-7.1 never see it, because no mailbox is forwarding.
        try {
            $rules = @()
            # A missing cmdlet (EXO not connected, or the signed-in role cannot run it -
            # Exchange RBAC hides such cmdlets) is a FAILED read, never "none exist".
            if (-not (Get-Command Get-TransportRule -ErrorAction SilentlyContinue)) { throw 'Get-TransportRule is not available in this session.' }
            $rules = @(Get-TransportRule -ErrorAction Stop)
            $result.Data.TransportRules = @($rules | ForEach-Object {
                @{
                    Name         = [string](Get-NRGObjectField -Item $_ -Key 'Name')
                    State        = [string](Get-NRGObjectField -Item $_ -Key 'State')
                    Priority     = [string](Get-NRGObjectField -Item $_ -Key 'Priority')
                    Mode         = [string](Get-NRGObjectField -Item $_ -Key 'Mode')
                    # The three redirection verbs. Each takes a recipient list;
                    # any entry outside an accepted domain is an external hop.
                    RedirectMessageTo = @(Get-NRGObjectField -Item $_ -Key 'RedirectMessageTo' -Default @()) | ForEach-Object { [string]$_ }
                    BlindCopyTo       = @(Get-NRGObjectField -Item $_ -Key 'BlindCopyTo'       -Default @()) | ForEach-Object { [string]$_ }
                    CopyTo            = @(Get-NRGObjectField -Item $_ -Key 'CopyTo'            -Default @()) | ForEach-Object { [string]$_ }
                    # A rule that routes through a named connector is the other
                    # way mail leaves without a forwarding flag anywhere.
                    RouteMessageOutboundConnector = [string](Get-NRGObjectField -Item $_ -Key 'RouteMessageOutboundConnector')
                    # SCL -1 skips spam filtering outright.
                    SetSCL       = [string](Get-NRGObjectField -Item $_ -Key 'SetSCL')
                    WhenChanged  = [string](Get-NRGObjectField -Item $_ -Key 'WhenChanged')
                }
            })
            $result.Data.SectionStatus.TransportRules = 'Collected'
        } catch {
            $result.Data.SectionStatus.TransportRules = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-TransportRules' -Message $_.Exception.Message
            }
        }

        # ── Tenant Allow/Block List (DEF-5.1) ────────────────────────────────
        # Separate surface from the anti-spam allowed-sender list EXO-5.3
        # checks. An allow entry here overrides filtering verdicts outright, and
        # entries added during an incident to "unblock" a sender routinely
        # outlive the incident.
        try {
            $tabl = @()
            # Pinned to the Exchange Online session: the Security & Compliance
            # copy fails "Value cannot be null. Parameter name: exchangeConfigUnit".
            $tablCmd = (Get-NRGExoCommand -Name 'Get-TenantAllowBlockListItems' -Session ExchangeOnline).Command
            if ($tablCmd) {
                # Track how many of the six list-type/allow combinations actually
                # succeeded. A per-combination failure used to be logged to
                # -Verbose only and then ignored, so the section still reported
                # 'Collected' with an empty Allow list even when every read
                # failed — the exact condition DEF-5.1 scores as clean.
                $tablFailures = 0
                # -Allow / -Block are switches; -Allow:$false does not mean
                # "blocks only". IP (IPv6) entries are a list type of their own.
                foreach ($t in @('Sender', 'Url', 'FileHash', 'IP')) {
                    foreach ($mode in @('Allow', 'Block')) {
                        $allow = $mode -eq 'Allow'
                        try {
                            $modeArg = @{ $mode = $true }
                            $items = @(& $tablCmd -ListType $t @modeArg -ErrorAction Stop)
                            foreach ($i in $items) { $tabl += @{
                                ListType   = $t
                                Action     = $mode
                                Value      = [string](Get-NRGObjectField -Item $i -Key 'Value')
                                ExpirationDate = [string](Get-NRGObjectField -Item $i -Key 'ExpirationDate')
                                # A never-expiring ALLOW is the durable one.
                                NoExpiration   = [bool](Get-NRGObjectField -Item $i -Key 'NoExpiration' -Default $false)
                                Notes      = [string](Get-NRGObjectField -Item $i -Key 'Notes')
                            } }
                        } catch {
                            # One list type unavailable (license/role) must not
                            # lose the others; the section only fails if the
                            # cmdlet itself is unusable, handled by the outer catch.
                            $tablFailures++
                            Write-Verbose "TABL $t/$allow unavailable: $($_.Exception.Message)"
                            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                                Register-NRGException -Source 'EXO-TenantAllowBlockList' -Message "[$t/$allow] $($_.Exception.Message)"
                            }
                        }
                    }
                }
                # Spoofed-sender entries live on their own cmdlet and an allow
                # there never expires — the most durable bypass in the list.
                $spoofCmd = (Get-NRGExoCommand -Name 'Get-TenantAllowBlockListSpoofItems' -Session ExchangeOnline).Command
                if ($spoofCmd) {
                    try {
                        foreach ($i in @(& $spoofCmd -ErrorAction Stop)) {
                            $act = [string](Get-NRGObjectField -Item $i -Key 'Action' -Default '')
                            $tabl += @{
                                ListType       = 'Spoof'
                                Action         = $act
                                Value          = "$([string](Get-NRGObjectField -Item $i -Key 'SpoofedUser' -Default '')) via $([string](Get-NRGObjectField -Item $i -Key 'SendingInfrastructure' -Default ''))"
                                ExpirationDate = ''
                                NoExpiration   = $true
                                Notes          = [string](Get-NRGObjectField -Item $i -Key 'SpoofType' -Default '')
                            }
                        }
                    } catch {
                        $tablFailures++
                        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                            Register-NRGException -Source 'EXO-TenantAllowBlockList' -Message "[Spoof] $($_.Exception.Message)"
                        }
                    }
                } else { $tablFailures++ }
                $result.Data.TenantAllowBlockList = @($tabl)
                # Any failed read means the Allow list this section exists to
                # surface for DEF-5.1 cannot be trusted as complete — an unread
                # allow entry is indistinguishable from "no allow entries" once
                # the list is treated as clean.
                $result.Data.SectionStatus.TenantAllowBlockList = if ($tablFailures -eq 0) { 'Collected' } else { 'Failed' }
            }
        } catch {
            $result.Data.SectionStatus.TenantAllowBlockList = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-TenantAllowBlockList' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            $note = "Scanned $($result.Data.Stats.MailboxesScanned) mailboxes / $($result.Data.Stats.InboxRulesEvaluated) inbox rules"
            Register-NRGCoverage -Family 'EXO-Inventory' -Status 'Collected' -Note $note
        }
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'EXO-Inventory' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'EXO-Inventory' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'EXO-Inventory' -Data $result
    }
    return $result
}

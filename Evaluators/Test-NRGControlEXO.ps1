#Requires -Version 7.0
#
# Test-NRGControlEXO.ps1  (v4.5.6)
# Evaluates Exchange Online security controls.
# SCORING ONLY — no API calls.
#
# NIST SP 800-53: AU-2, SI-8, SC-7, SC-8
# MITRE ATT&CK:   T1114, T1114.003, T1078, T1566
#

# ── EXO-1.1 Mailbox Audit Logging ────────────────────────────────────────────
function Test-NRGControlEXOMailboxAudit {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'EXO data not collected'
        return
    }

    $orgDisabled = Get-NRGNestedProperty -Object $exoData -Path 'Data.OrganizationConfig.AuditDisabled' -Default $null
    $sample      = Get-NRGNestedProperty -Object $exoData -Path 'Data.MailboxAuditSummary.SampleMailboxAudit' -Default $null

    if ($orgDisabled -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'Mailbox audit logging is DISABLED at the organization level. No mailbox activity will be logged.' `
            -CurrentValue 'AuditDisabled = $true' -RequiredValue 'AuditDisabled = $false' `
            -Remediation $control.Remediation
    } elseif ($sample -and -not $sample.AllEnabled) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "Organization-level audit is enabled but some mailboxes have audit disabled (sample of $($sample.SampleCount) mailboxes)." `
            -CurrentValue 'Some mailboxes audit-disabled' -RequiredValue 'All mailboxes audit-enabled'
    } elseif ($orgDisabled -eq $false -or ($sample -and $sample.AllEnabled)) {
        # The expected state has two parts: the organization switch AND no mailbox in
        # the audit bypass list. The switch is verified above; the bypass half comes
        # from the inventory read (the same evidence EXO-6.3 scores), and each half
        # stays visible whatever the other says.
        $inv = Get-NRGRawData -Key 'EXO-Inventory'
        $bypass = if ($inv -and (Get-NRGObjectField -Item $inv -Key 'Success' -Default $false)) { Get-NRGMailboxAuditBypassState -Inventory $inv } else { $null }
        $switchText = 'the organization-level mailbox auditing switch is on'
        if ($null -eq $bypass -or $bypass.Kind -notin @('Bypass', 'Clean')) {
            Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                -Title $control.Title -FrameworkIds $citations `
                -Detail "Verified: $switchText. Not assessed: whether any mailbox is in the audit bypass list, because the bypass associations could not be read." `
                -CurrentValue 'Organization auditing on; bypass associations not read' `
                -RequiredValue 'Organization auditing enabled and no mailbox in the audit bypass list'
        } elseif ($bypass.Kind -eq 'Bypass') {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
                -Detail "Verified: $switchText. Shortfall: $($bypass.Names.Count) account(s) are in the audit bypass list, so nothing they do in any mailbox is recorded." `
                -CurrentValue "Organization auditing on; $($bypass.Names.Count) account(s) in audit bypass" `
                -RequiredValue 'Organization auditing enabled and no mailbox in the audit bypass list' `
                -Remediation $control.Remediation
        } else {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
                -Detail "Mailbox audit logging is enabled at the organization level and no account is in the audit bypass list."
        }
    } else {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'Audit status could not be determined'
    }
}

# ── EXO-1.2 SMTP Client Authentication Disabled ──────────────────────────────
function Test-NRGControlEXOSmtpAuth {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.2'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'EXO data not collected'
        return
    }

    # The org switch comes from Get-TransportConfig. $null means it was not
    # read — never "enabled" (a failed TransportConfig query scored Gap).
    $tenantDisabled = Get-NRGNestedProperty -Object $exoData -Path 'Data.TransportConfig.SmtpClientAuthenticationDisabled' -Default $null
    if ($null -eq $tenantDisabled) {
        $tenantDisabled = Get-NRGNestedProperty -Object $exoData -Path 'Data.SmtpAuthConfig.TenantDisabled' -Default $null
    }
    if ($null -eq $tenantDisabled) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'The organization SMTP AUTH setting (Get-TransportConfig SmtpClientAuthenticationDisabled) was not read; not assessed.'
        return
    }

    if ($tenantDisabled -ne $true) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'SMTP AUTH is enabled for the whole organization, so every mailbox that does not override it can submit mail over SMTP AUTH. It is a password-spray and spam-relay target, and wherever basic authentication is still accepted for it, sign-in bypasses MFA and Conditional Access.' `
            -CurrentValue 'SmtpClientAuthenticationDisabled = $false' `
            -RequiredValue 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true' `
            -Remediation $control.Remediation
        return
    }

    # Disabled org-wide: exceptions come from the per-mailbox read here, or
    # from the inventory sweep when this one did not complete.
    $perMailbox = $null; $sample = @()
    if (Test-NRGSectionCollected $exoData 'SmtpAuthConfig') {
        $sa = Get-NRGObjectField -Item $exoData.Data -Key 'SmtpAuthConfig' -Default $null
        if ($sa) {
            $perMailbox = [int](Get-NRGObjectField -Item $sa -Key 'PerMailboxEnabledCount' -Default 0)
            $sample = @(Get-NRGObjectField -Item $sa -Key 'SampleEnabled' -Default @())
        }
    }
    if ($null -eq $perMailbox) {
        $inv = Get-NRGRawData -Key 'EXO-Inventory'
        if ($inv -and $inv.Success -and (Test-NRGSectionCollected $inv 'SmtpAuthEnabledPerUser')) {
            $list = @(Get-NRGObjectField -Item $inv.Data -Key 'SmtpAuthEnabledPerUser' -Default @())
            $perMailbox = [int](Get-NRGObjectField -Item $inv.Data -Key 'SmtpAuthEnabledPerUserCount' -Default $list.Count)
            $sample = @($list | Select-Object -First 5 | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'UPN' -Default '') })
        }
    }
    if ($null -eq $perMailbox) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'SMTP AUTH is disabled for the organization, but the per-mailbox overrides (Get-CASMailbox) were not read, so whether any mailbox re-enables it was not assessed.'
        return
    }
    if ($perMailbox -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail 'SMTP AUTH is disabled for the organization and no mailbox re-enables it.'
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "SMTP AUTH is disabled for the organization, but $perMailbox mailbox(es) re-enable it$(if ($sample) { " (for example $($sample -join ', '))" })." `
            -CurrentValue "$perMailbox mailboxes with SMTP AUTH enabled" `
            -RequiredValue 'Zero per-mailbox SMTP AUTH exceptions' -Remediation $control.Remediation
    }
}

# ── EXO-1.3 External Auto-Forwarding Blocked ─────────────────────────────────
function Test-NRGControlEXOAutoForward {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.3'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'EXO data not collected'
        return
    }
    if (-not (Test-NRGSectionCollected $exoData 'OutboundSpamPolicies') -or
        -not (Test-NRGSectionCollected $exoData 'RemoteDomains')) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'Outbound spam policies or remote domains were not collected; external auto-forwarding not assessed.'
        return
    }

    $remotes = @(Get-NRGObjectField -Item $exoData.Data -Key 'RemoteDomains' -Default @())
    $wildcardRemote = $remotes | Where-Object { (Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false) -eq $true } | Select-Object -First 1
    # The policies that apply to senders: a custom policy with an enabled
    # rule, an enabled preset, and the default. A custom "On" policy lets its
    # senders forward however the default is set.
    $inForce = @(Get-NRGInForcePolicies -Policies @(Get-NRGObjectField -Item $exoData.Data -Key 'OutboundSpamPolicies' -Default @()) `
        -Rules (Get-NRGObjectField -Item $exoData.Data -Key 'OutboundSpamRules' -Default $null) `
        -RulePolicyKey 'HostedOutboundSpamFilterPolicy' -PresetKind 'EOP')
    if ($inForce.Count -eq 0 -or -not $wildcardRemote) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'No outbound spam policy or no default remote domain was found in the collected data; external auto-forwarding not assessed.'
        return
    }

    # Microsoft ("Control automatic external email forwarding"): Off blocks
    # inbox-rule AND admin mailbox forwarding. 'Automatic' is Off for most
    # organizations but can still mean On for ones that used it before 2021,
    # so it is not treated as a block — Microsoft recommends setting Off
    # explicitly. The default remote domain blocking forwarding stops
    # inbox-rule and user forwarding but NOT forwarding an admin sets on a
    # mailbox, so on its own it is part-way.
    $mode = { param($p) [string](Get-NRGObjectField -Item $p -Key 'AutoForwardingMode' -Default '') }
    $blocks  = @($inForce | Where-Object { (& $mode $_) -eq 'Off' })
    $open    = @($inForce | Where-Object { (& $mode $_) -ne 'Off' })
    $remoteBlocked = -not [bool](Get-NRGObjectField -Item $wildcardRemote -Key 'AutoForwardEnabled' -Default $true)
    $namedAllow = @($remotes | Where-Object { (Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false) -ne $true -and
        [bool](Get-NRGObjectField -Item $_ -Key 'AutoForwardEnabled' -Default $false) } |
        ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'DomainName' -Default '') })
    $desc = { param($l) (@($l) | ForEach-Object { "$([string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '?')) ($(& $mode $_))" }) -join '; ' }
    $namedNote = if ($namedAllow.Count) { " Remote domains that explicitly allow forwarding: $($namedAllow -join ', ') — confirm each is intended." } else { '' }
    $autoNote = if (@($open | Where-Object { (& $mode $_) -eq 'Automatic' }).Count) { ' Automatic (system-controlled) is Off for most organizations but can still allow forwarding in ones that used it before 2021; Microsoft recommends setting Off explicitly.' } else { '' }
    $required = 'AutoForwardingMode Off in every outbound spam policy in force'

    if ($open.Count -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail "Every outbound spam policy in force blocks automatic external forwarding (inbox rules and mailbox forwarding): $(& $desc $blocks).$namedNote" `
            -CurrentValue (& $desc $blocks)
    } elseif ($remoteBlocked -or $blocks.Count -gt 0) {
        $why = @()
        if ($blocks.Count) { $why += "blocked for senders under $(& $desc $blocks) but not for senders under $(& $desc $open)" }
        if ($remoteBlocked) { $why += 'the default remote domain blocks inbox-rule and user forwarding, but not forwarding an administrator sets on a mailbox' }
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail "External auto-forwarding is only partly blocked: $($why -join '; ').$autoNote$namedNote" `
            -CurrentValue "Not blocked by: $(& $desc $open); default remote domain AutoForwardEnabled = $(-not $remoteBlocked)" `
            -RequiredValue $required -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail "External auto-forwarding is not blocked: no outbound spam policy in force is set to Off ($(& $desc $open)), and the default remote domain allows it. Users or compromised accounts can forward all email to external addresses.$autoNote" `
            -CurrentValue (& $desc $open) -RequiredValue $required -Remediation $control.Remediation
    }
}

# ── EXO-1.4 DKIM Signing Enabled ─────────────────────────────────────────────
function Test-NRGControlEXODKIM {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.4'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'EXO data not collected'
        return
    }
    if (-not (Test-NRGSectionCollected $exoData 'DkimSigningConfigs')) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'DKIM signing configuration (Get-DkimSigningConfig) was not collected; not assessed.'
        return
    }

    $dkimConfigs = @(Get-NRGObjectField -Item $exoData.Data -Key 'DkimSigningConfigs' -Default @() | Where-Object { $null -ne $_ })
    $cfgByDomain = @{}
    foreach ($c in $dkimConfigs) { $cfgByDomain[([string](Get-NRGObjectField -Item $c -Key 'Domain' -Default '')).ToLowerInvariant()] = $c }

    # Every authoritative accepted domain should sign. A domain with no DKIM
    # configuration at all is unsigned (Microsoft signs only the
    # onmicrosoft.com domain by default), so it is judged, not skipped.
    # Accepted domains unread: judge the configurations that exist.
    $domains = @()
    if (Test-NRGSectionCollected $exoData 'AcceptedDomains') {
        $domains = @(@(Get-NRGObjectField -Item $exoData.Data -Key 'AcceptedDomains' -Default @()) |
            Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'DomainType' -Default 'Authoritative') -eq 'Authoritative' } |
            ForEach-Object { ([string](Get-NRGObjectField -Item $_ -Key 'DomainName' -Default '')).ToLowerInvariant() } |
            Where-Object { $_ -and $_ -notmatch '\.onmicrosoft\.com$' })
    }
    if ($domains.Count -eq 0) { $domains = @($cfgByDomain.Keys | Where-Object { $_ -and $_ -notmatch '\.onmicrosoft\.com$' }) }
    if ($domains.Count -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'The tenant has no custom sending domain (only the onmicrosoft.com domain, which Microsoft signs by default), so there is no custom domain to sign.'
        return
    }

    $keyBits = { param($c)
        $sizes = @('Selector1KeySize','Selector2KeySize','KeySize') | ForEach-Object { Get-NRGObjectField -Item $c -Key $_ -Default $null } |
            Where-Object { $null -ne $_ -and "$_" -match '^\d+$' } | ForEach-Object { [int]"$_" }
        if (@($sizes).Count) { ($sizes | Measure-Object -Maximum).Maximum } else { $null } }
    $unsigned = @($domains | Where-Object { -not $cfgByDomain.ContainsKey($_) -or -not [bool](Get-NRGObjectField -Item $cfgByDomain[$_] -Key 'Enabled' -Default $false) })
    $signed   = @($domains | Where-Object { $_ -notin $unsigned })
    # Weak: no selector holds a 2048-bit key. One 1024-bit selector beside a
    # 2048-bit one is a rotation in progress, not a weakness.
    $weak     = @($signed | Where-Object { $b = & $keyBits $cfgByDomain[$_]; $null -ne $b -and $b -lt 2048 })

    if ($unsigned.Count -eq 0 -and $weak.Count -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail "DKIM signing is enabled for every custom domain: $($signed -join ', ')."
    } elseif ($unsigned.Count -gt 0 -and $signed.Count -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'High' -FrameworkIds $citations `
            -Detail "DKIM signs $($signed.Count) domain(s) but not $($unsigned.Count): $($unsigned -join ', ')." `
            -CurrentValue "DKIM not signing: $($unsigned -join ', ')" -RequiredValue 'DKIM enabled for all domains' -Remediation $control.Remediation
    } elseif ($unsigned.Count -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "DKIM is enabled, but $($weak.Count) domain(s) have no 2048-bit key: $($weak -join ', '). Rotate-DkimSigningConfig -KeySize 2048 upgrades them." `
            -CurrentValue 'Key size < 2048 bits' -RequiredValue '2048-bit DKIM keys' -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail "DKIM signing is not enabled for any custom domain: $($unsigned -join ', ')." `
            -CurrentValue 'DKIM not signing any custom domain' -RequiredValue 'DKIM enabled for all domains' `
            -Remediation $control.Remediation
    }
}

# ── EXO-1.5 Anti-Phishing Impersonation Protection ───────────────────────────
function Test-NRGControlEXOAntiPhish {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.5'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    # Impersonation protection is a Defender for Office 365 feature, and the
    # policies in force (with their rules and presets) come from the Defender
    # collector. Judging only the default policy reported its settings for
    # recipients a preset or custom policy actually governs.
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations -Detail 'Defender data not collected'
        return
    }
    $ap = Get-NRGObjectField -Item $def.Data -Key 'AntiPhishing' -Default $null
    if (-not $ap -or -not (Get-NRGObjectField -Item $ap -Key 'Available' -Default $false)) {
        Add-NRGDefenderUnavailableFinding -ControlId 'EXO-1.5' -Control $control -FrameworkIds $citations -Section $ap -Feature 'Anti-phishing impersonation protection'
        return
    }
    $inForce = Get-NRGInForcePolicies -Policies @(Get-NRGObjectField -Item $ap -Key 'Policies' -Default @()) `
        -Rules (Get-NRGObjectField -Item $ap -Key 'Rules' -Default $null) -RulePolicyKey 'AntiPhishPolicy' -PresetKind 'EOP'
    $f = { param($p, $k) Get-NRGObjectField -Item $p -Key $k -Default $null }
    $pass = { param($p)
        (& $f $p 'EnableOrganizationDomainsProtection') -eq $true -and [string](& $f $p 'TargetedDomainProtectionAction') -notin @('','NoAction') -and
        (& $f $p 'EnableMailboxIntelligence') -eq $true -and (& $f $p 'EnableMailboxIntelligenceProtection') -eq $true -and
        [string](& $f $p 'MailboxIntelligenceProtectionAction') -notin @('','NoAction') }
    $value = { param($p)
        $miss = @()
        if ((& $f $p 'EnableOrganizationDomainsProtection') -ne $true) { $miss += 'org-domain protection off' }
        elseif ([string](& $f $p 'TargetedDomainProtectionAction') -in @('','NoAction')) { $miss += 'domain impersonation action NoAction' }
        if ((& $f $p 'EnableMailboxIntelligence') -ne $true) { $miss += 'mailbox intelligence off' }
        elseif ((& $f $p 'EnableMailboxIntelligenceProtection') -ne $true) { $miss += 'intelligence-based protection off' }
        elseif ([string](& $f $p 'MailboxIntelligenceProtectionAction') -in @('','NoAction')) { $miss += 'intelligence action NoAction' }
        if ($miss.Count) { $miss -join ', ' } else { 'domain and mailbox-intelligence impersonation protection acting' } }
    Add-NRGPolicySetFinding -ControlId 'EXO-1.5' -Control $control -FrameworkIds $citations -Policies $inForce -Pass $pass -Value $value `
        -PassDetail 'Impersonation of your own domains and of each user''s usual contacts is detected and acted on.' `
        -FailDetail 'Protection that detects without acting (action NoAction) or is switched off lets domain and contact impersonation reach the inbox.' `
        -RequiredValue 'EnableOrganizationDomainsProtection and EnableMailboxIntelligenceProtection on, each with an action other than NoAction, in every anti-phishing policy in force'
}

# ── EXO-1.6 Modern Auth (OAuth2) Enabled ─────────────────────────────────────
function Test-NRGControlEXOModernAuth {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.6'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'EXO data not collected'
        return
    }

    $modernAuth = Get-NRGNestedProperty -Object $exoData -Path 'Data.OrganizationConfig.OAuth2ClientProfileEnabled' -Default $null

    if ($modernAuth -eq $true) {
        # Two components: modern authentication on (verified above) and PASSWORD
        # ("Basic") authentication not available to legacy protocols. SMTP AUTH being
        # enabled does not by itself mean passwords are accepted: SMTP AUTH also
        # carries OAuth. So the second component is judged from what governs
        # passwords: the SMTP AUTH switch AND its per-mailbox overrides (a mailbox
        # setting can re-enable SMTP AUTH beside an organization-level disable) and
        # the tenant's legacy-authentication block (Security Defaults or a
        # Conditional Access policy blocking 'Other clients'). Missing evidence
        # stays unknown.
        $oauthText = 'modern authentication (OAuth2) is enabled for Exchange Online'
        $smtpOrgDisabled = Get-NRGNestedProperty -Object $exoData -Path 'Data.TransportConfig.SmtpClientAuthenticationDisabled' -Default $null
        if ($null -eq $smtpOrgDisabled) { $smtpOrgDisabled = Get-NRGNestedProperty -Object $exoData -Path 'Data.SmtpAuthConfig.TenantDisabled' -Default $null }
        $overrides = $null; $overrideSample = @()
        if (Test-NRGSectionCollected $exoData 'SmtpAuthConfig') {
            $sa = Get-NRGObjectField -Item $exoData.Data -Key 'SmtpAuthConfig' -Default $null
            if ($sa) {
                $overrides = [int](Get-NRGObjectField -Item $sa -Key 'PerMailboxEnabledCount' -Default 0)
                $overrideSample = @(Get-NRGObjectField -Item $sa -Key 'SampleEnabled' -Default @())
            }
        }
        $legacyBlock = Get-NRGLegacyAuthBlockState

        $smtpPath = if ($smtpOrgDisabled -eq $true -and $overrides -eq 0) { 'Closed' }
                    elseif ($smtpOrgDisabled -eq $false -or ($null -ne $overrides -and $overrides -gt 0)) { 'Available' }
                    else { 'Unknown' }
        $smtpText = switch ($smtpPath) {
            'Closed'    { 'SMTP AUTH is disabled for the organization and no mailbox overrides it' }
            'Available' {
                if ($smtpOrgDisabled -eq $false) { 'SMTP AUTH is enabled for the organization (it carries OAuth as well as passwords)' }
                else { "SMTP AUTH is disabled for the organization but $overrides mailbox(es) override it$(if ($overrideSample.Count -gt 0) { ' (for example ' + (($overrideSample | Select-Object -First 3) -join ', ') + ')' })" }
            }
            default     { if ($smtpOrgDisabled -eq $true) { 'SMTP AUTH is disabled for the organization but the per-mailbox overrides were not read' } else { 'the SMTP AUTH setting was not read' } }
        }
        $reqText = 'Modern authentication enabled and password authentication not available to legacy protocols'

        if ($legacyBlock.Kind -eq 'Blocked') {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
                -Detail "Modern authentication (OAuth2) is enabled for Exchange Online, and password authentication to legacy protocols is blocked: $($legacyBlock.Detail). ($smtpText; with the block in place that does not allow passwords.)"
        } elseif ($smtpPath -eq 'Closed') {
            Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
                -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
                -Detail "Modern authentication (OAuth2) is enabled for Exchange Online and $smtpText, so SMTP cannot be used with a password."
        } elseif ($smtpPath -eq 'Available' -and $legacyBlock.Kind -in @('NotBlocked', 'PartlyBlocked')) {
            Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
                -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
                -Detail "Verified: $oauthText. Shortfall: $smtpText, and $($legacyBlock.Detail), so a password can still be used to submit mail for the accounts SMTP AUTH is available to. Not read: Exchange authentication policies, which could restrict it further." `
                -CurrentValue "OAuth2 enabled; $smtpText; $($legacyBlock.Detail)" `
                -RequiredValue $reqText `
                -Remediation $control.Remediation
        } else {
            Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
                -Title $control.Title -FrameworkIds $citations `
                -Detail "Verified: $oauthText. Not assessed: whether password authentication is available to legacy protocols. $($smtpText.Substring(0,1).ToUpperInvariant() + $smtpText.Substring(1)), and $($legacyBlock.Detail)." `
                -CurrentValue "OAuth2 enabled; password availability not established" `
                -RequiredValue $reqText
        }
    } elseif ($modernAuth -eq $false) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'Modern authentication is DISABLED. This forces clients to use basic authentication, bypassing MFA.' `
            -CurrentValue 'OAuth2ClientProfileEnabled = $false' `
            -RequiredValue 'Set-OrganizationConfig -OAuth2ClientProfileEnabled $true' `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'Modern auth state could not be determined'
    }
}

# ── EXO-1.7 Honor DMARC Policy (Anti-phish) ──────────────────────────────────
function Test-NRGControlEXOHonorDMARC {
    [CmdletBinding()] param()

    $controlId = 'EXO-1.7'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations -Detail 'Defender data not collected'
        return
    }
    $ap = Get-NRGObjectField -Item $def.Data -Key 'AntiPhishing' -Default $null
    if (-not $ap -or -not (Get-NRGObjectField -Item $ap -Key 'Available' -Default $false)) {
        $why = [string](Get-NRGObjectField -Item $ap -Key 'Error' -Default '')
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail "Anti-phishing policies were not collected$(if ($why) { " ($why)" }); not assessed."
        return
    }
    $inForce = Get-NRGInForcePolicies -Policies @(Get-NRGObjectField -Item $ap -Key 'Policies' -Default @()) `
        -Rules (Get-NRGObjectField -Item $ap -Key 'Rules' -Default $null) -RulePolicyKey 'AntiPhishPolicy' -PresetKind 'EOP'
    Add-NRGPolicySetFinding -ControlId 'EXO-1.7' -Control $control -FrameworkIds $citations -Policies $inForce `
        -Pass { param($p) (Get-NRGObjectField -Item $p -Key 'HonorDmarcPolicy' -Default $false) -eq $true } `
        -Value { param($p) "HonorDmarcPolicy = $([bool](Get-NRGObjectField -Item $p -Key 'HonorDmarcPolicy' -Default $false))" } `
        -PassDetail 'Inbound mail failing DMARC is handled as the sending domain''s p=quarantine / p=reject policy asks.' `
        -FailDetail 'Where DMARC is not honored, mail failing a sender''s p=reject policy can still be delivered.' `
        -RequiredValue 'HonorDmarcPolicy = $true in every anti-phishing policy in force'
}

# " N of the M existing mailboxes have it on." when the per-mailbox read
# ran; empty otherwise, never a guess.
function Get-NRGProtocolExistingNote {
    [CmdletBinding()]
    param($ExoData, [string] $CountKey, [string] $Protocol)
    if (-not (Test-NRGSectionCollected $ExoData 'CASMailboxProtocols')) { return '' }
    $prot = Get-NRGObjectField -Item $ExoData.Data -Key 'CASMailboxProtocols' -Default $null
    $on   = Get-NRGObjectField -Item $prot -Key $CountKey -Default $null
    if ($null -eq $on) { return '' }
    return " $([int]$on) of the $([int](Get-NRGObjectField -Item $prot -Key 'Total' -Default 0)) existing mailboxes have $Protocol on."
}

# ── EXO-2.3 POP3 Access Disabled ─────────────────────────────────────────────
function Test-NRGControlEXOPop3 {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.3'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'EXO data not collected'
        return
    }
    $plans = @($exoData.Data['CASMailboxPlans'] ?? @())
    if ($plans.Count -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'CAS mailbox plan data not collected (Get-CASMailboxPlan needs EXO admin rights) — POP3 state not assessed.'
        return
    }
    $popOn = @($plans | Where-Object { (Get-NRGObjectField -Item $_ -Key 'PopEnabled') -eq $true })
    if ($popOn.Count -gt 0) {
        $names = @($popOn | ForEach-Object { Get-NRGObjectField -Item $_ -Key 'Name' })
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail "POP3 is enabled on $($popOn.Count) of $($plans.Count) CAS mailbox plan(s), so every new mailbox gets it.$(Get-NRGProtocolExistingNote -ExoData $exoData -CountKey 'PopEnabledCount' -Protocol 'POP3') Exchange Online stopped accepting basic authentication for POP3 in October 2022, so it now signs in with OAuth; what remains is a mail-download channel most organizations never use, through which any app a user authorizes can copy the whole mailbox. Turn it off where it is not needed." `
            -CurrentValue "POP3 enabled on: $($names -join ', ')" `
            -RequiredValue 'POP3 disabled on all mailbox plans and mailboxes' `
            -Remediation $control.Remediation
        return
    }
    # The plans set the default for NEW mailboxes only. Existing mailboxes
    # keep whatever they had, so the plans alone cannot say POP3 is off.
    $prot = if (Test-NRGSectionCollected $exoData 'CASMailboxProtocols') { Get-NRGObjectField -Item $exoData.Data -Key 'CASMailboxProtocols' -Default $null } else { $null }
    $onCount = Get-NRGObjectField -Item $prot -Key 'PopEnabledCount' -Default $null
    if ($null -eq $onCount) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category -Title $control.Title -FrameworkIds $citations `
            -Detail "POP3 is off in every CAS mailbox plan (the default for new mailboxes), but existing mailboxes (Get-CASMailbox) were not read, so whether any still has POP3 on was not assessed."
    } elseif ([int]$onCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail "POP3 is off in all $($plans.Count) CAS mailbox plan(s) and on none of the $([int](Get-NRGObjectField -Item $prot -Key 'Total' -Default 0)) existing mailboxes." `
            -CurrentValue 'POP3 disabled on all mailbox plans and mailboxes'
    } else {
        $sample = @(Get-NRGObjectField -Item $prot -Key 'PopSample' -Default @())
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "POP3 is off for new mailboxes (every CAS mailbox plan), but $onCount existing mailbox(es) still have it on." `
            -CurrentValue "$onCount mailbox(es) with POP3 enabled" -RequiredValue 'POP3 disabled on all mailbox plans and mailboxes' `
            -Remediation "$($control.Remediation) Existing mailboxes: Get-CASMailbox -ResultSize Unlimited | Where-Object PopEnabled | Set-CASMailbox -PopEnabled `$false" `
            -AffectedObjects $sample
    }
}

# ── EXO-2.4 IMAP Access Disabled ─────────────────────────────────────────────
function Test-NRGControlEXOImap {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.4'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'EXO data not collected'
        return
    }
    $plans = @($exoData.Data['CASMailboxPlans'] ?? @())
    if ($plans.Count -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'CAS mailbox plan data not collected (Get-CASMailboxPlan needs EXO admin rights) — IMAP4 state not assessed.'
        return
    }
    $imapOn = @($plans | Where-Object { (Get-NRGObjectField -Item $_ -Key 'ImapEnabled') -eq $true })
    if ($imapOn.Count -gt 0) {
        $names = @($imapOn | ForEach-Object { Get-NRGObjectField -Item $_ -Key 'Name' })
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail "IMAP4 is enabled on $($imapOn.Count) of $($plans.Count) CAS mailbox plan(s), so every new mailbox gets it.$(Get-NRGProtocolExistingNote -ExoData $exoData -CountKey 'ImapEnabledCount' -Protocol 'IMAP4') Exchange Online stopped accepting basic authentication for IMAP4 in October 2022, so it now signs in with OAuth; what remains is a mail-download channel most organizations never use, through which any app a user authorizes can copy the whole mailbox. Turn it off where it is not needed." `
            -CurrentValue "IMAP4 enabled on: $($names -join ', ')" `
            -RequiredValue 'IMAP4 disabled on all mailbox plans and mailboxes' `
            -Remediation $control.Remediation
        return
    }
    # The plans set the default for NEW mailboxes only. Existing mailboxes
    # keep whatever they had, so the plans alone cannot say IMAP4 is off.
    $prot = if (Test-NRGSectionCollected $exoData 'CASMailboxProtocols') { Get-NRGObjectField -Item $exoData.Data -Key 'CASMailboxProtocols' -Default $null } else { $null }
    $onCount = Get-NRGObjectField -Item $prot -Key 'ImapEnabledCount' -Default $null
    if ($null -eq $onCount) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category -Title $control.Title -FrameworkIds $citations `
            -Detail "IMAP4 is off in every CAS mailbox plan (the default for new mailboxes), but existing mailboxes (Get-CASMailbox) were not read, so whether any still has IMAP4 on was not assessed."
    } elseif ([int]$onCount -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail "IMAP4 is off in all $($plans.Count) CAS mailbox plan(s) and on none of the $([int](Get-NRGObjectField -Item $prot -Key 'Total' -Default 0)) existing mailboxes." `
            -CurrentValue 'IMAP4 disabled on all mailbox plans and mailboxes'
    } else {
        $sample = @(Get-NRGObjectField -Item $prot -Key 'ImapSample' -Default @())
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "IMAP4 is off for new mailboxes (every CAS mailbox plan), but $onCount existing mailbox(es) still have it on." `
            -CurrentValue "$onCount mailbox(es) with IMAP4 enabled" -RequiredValue 'IMAP4 disabled on all mailbox plans and mailboxes' `
            -Remediation "$($control.Remediation) Existing mailboxes: Get-CASMailbox -ResultSize Unlimited | Where-Object ImapEnabled | Set-CASMailbox -ImapEnabled `$false" `
            -AffectedObjects $sample
    }
}

# ── EXO-2.5 Customer Lockbox Enabled ─────────────────────────────────────────
function Test-NRGControlEXOCustomerLockbox {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.5'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exoData -or -not $exoData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'EXO data not collected'
        return
    }

    # Customer Lockbox state is in org config — pull it from the collector
    # output. Prior versions referenced $orgConfig without ever assigning it
    # (lost in PR conflict resolution) — under StrictMode this silently
    # killed the evaluator via the loader's try/catch.
    $orgConfig = $exoData.Data['OrganizationConfig']
    if (-not $orgConfig) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'Organization config not collected'
        return
    }

    # CustomerLockBoxEnabled may not be present if E5 not licensed.
    # The collector stores OrganizationConfig as a hashtable, so use
    # ContainsKey rather than PSObject.Properties (which works on both but
    # is the wrong idiom for a hashtable).
    $lockboxEnabled = if ($orgConfig -is [System.Collections.IDictionary]) {
        if ($orgConfig.Contains('CustomerLockBoxEnabled')) { $orgConfig['CustomerLockBoxEnabled'] } else { $null }
    } elseif ($orgConfig.PSObject.Properties['CustomerLockBoxEnabled']) {
        $orgConfig.PSObject.Properties['CustomerLockBoxEnabled'].Value
    } else { $null }
    if ($lockboxEnabled -eq $true) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail 'Customer Lockbox is enabled. Microsoft support requires explicit admin approval to access tenant data.'
    } elseif ($lockboxEnabled -eq $false) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'Customer Lockbox is disabled. Microsoft support can access tenant data during support cases without approval.' `
            -CurrentValue 'CustomerLockBoxEnabled = $false' -RequiredValue 'CustomerLockBoxEnabled = $true' `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'CustomerLockBoxEnabled was not returned by Get-OrganizationConfig; not assessed.'
    }
}

# ── EXO-2.6 Shared Mailboxes Block Direct Sign-In ────────────────────────────
function Test-NRGControlEXOSharedMailbox {
    [CmdletBinding()] param()

    $controlId = 'EXO-2.6'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    # v4.13.0: implemented for real. This was previously a manual-review
    # placeholder because the check needs EXO shared mailboxes joined against
    # AAD AccountEnabled — but
    # Invoke-NRGCollectEXOInventory already performs exactly that join and
    # publishes the result as SharedMailboxSignIn, tagging each hit with the
    # evidence it rests on:
    #   Source = 'AAD-Users'    confirmed enabled via Graph accountEnabled
    #   Source = 'LicenseProxy' inferred from a license/reconciliation signal
    #                           because AAD user data was unavailable
    # Those are not the same claim, so they do not produce the same verdict.
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail 'EXO inventory not collected'
        return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $inv 'AllSharedMailboxes')) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category -Title $control.Title -FrameworkIds $citations -Detail 'AllSharedMailboxes was not collected; not assessed.'
        return
    }

    $allShared = @($inv.Data['AllSharedMailboxes'] ?? @())
    # The section status is authoritative whatever the list holds: on a live
    # tenant the enumeration succeeded, the sign-in loop threw, SectionStatus
    # read Failed, and the empty sign-in list was scored as "none enabled".
    if (-not (Test-NRGInventorySectionCollected -Inventory $inv -Section 'SharedMailboxes')) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title `
            -FrameworkIds $citations `
            -Detail "Shared mailbox sign-in state was not collected (the collector's SharedMailboxes section did not complete; see Exceptions) — not assessed.$(if ($allShared.Count -gt 0) { " $($allShared.Count) shared mailbox(es) were enumerated." })"
        return
    }

    if ($allShared.Count -eq 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail 'No shared mailboxes exist in this tenant, so none can be signed into directly.'
        return
    }

    $risky     = @($inv.Data['SharedMailboxSignIn'] ?? @())
    $confirmed = @($risky | Where-Object { $_.Source -eq 'AAD-Users' })
    $probable  = @($risky | Where-Object { $_.Source -ne 'AAD-Users' })

    $affected = @($risky | ForEach-Object {
        [ordered]@{
            DisplayName = [string]$_.DisplayName
            UPN         = [string]$_.UPN
            SignInState = [string]$_.SignInState
            Evidence    = if ($_.Source -eq 'AAD-Users') { 'Confirmed via Entra accountEnabled' }
                          else { 'Inferred from license state — AAD user data unavailable' }
        }
    })

    if ($confirmed.Count -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail "$($confirmed.Count) of $($allShared.Count) shared mailbox(es) have direct sign-in enabled. A shared mailbox is accessed by delegation, so an enabled sign-in is an account with a password that no one owns, no one monitors, and that is typically excluded from MFA — a standing foothold for password spray." `
            -CurrentValue "$($confirmed.Count) shared mailbox(es) with sign-in enabled" `
            -RequiredValue 'All shared mailbox accounts disabled (BlockCredential) — access via delegation only' `
            -Remediation $control.Remediation -AffectedObjects $affected
    }
    elseif ($probable.Count -gt 0) {
        # Only the weaker license-based signal fired. Report it, but do not
        # dress a heuristic up as a confirmed finding.
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "$($probable.Count) of $($allShared.Count) shared mailbox(es) carry a license or reconciliation flag suggesting an active account, but Entra user data was unavailable so sign-in state could not be confirmed. Verify these directly before treating them as clean." `
            -CurrentValue "$($probable.Count) shared mailbox(es) flagged by license heuristic (unconfirmed)" `
            -RequiredValue 'All shared mailbox accounts confirmed disabled (BlockCredential)' `
            -Remediation $control.Remediation -AffectedObjects $affected
    }
    else {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' -FrameworkIds $citations `
            -Detail "$($allShared.Count) shared mailbox(es) found — none have direct sign-in enabled. Access is by delegation only, as intended."
    }
}

function Test-NRGControlEXOConnectionFilter {
    [CmdletBinding()] param()
    $cid = 'EXO-3.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $cf = Get-NRGRawData -Key 'EXO-ConnectionFilter'
    if (-not $cf -or -not $cf.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Connection filter data not collected'; return
    }
    $defaultCF = @(@(Get-NRGObjectField -Item $cf.Data -Key 'ConnectionFilter' -Default @()) |
        Where-Object { (Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false) -eq $true }) | Select-Object -First 1
    if (-not $defaultCF) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'No default connection filter found'; return }
    $safeListRaw = Get-NRGObjectField -Item $defaultCF -Key 'EnableSafeList' -Default $null
    if ($null -eq $safeListRaw) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EnableSafeList was not collected on the default connection filter; not assessed.'; return }
    $safeListEnabled = [bool]$safeListRaw
    if (-not $safeListEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Microsoft safe list bypass is disabled on connection filter.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Safe list bypass is enabled — Microsoft-maintained IP list bypasses spam filtering entirely. Third-party senders on that list skip all EOP filtering.' -CurrentValue 'EnableSafeList = $true' -RequiredValue 'Set-HostedConnectionFilterPolicy -EnableSafeList $false' -Remediation $ctrl.Remediation
    }
}

# ── EXO-3.2 Outbound Spam User Sending Limits ────────────────────────────────
function Test-NRGControlEXOOutboundLimits {
    [CmdletBinding()] param()
    $cid = 'EXO-3.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected'; return
    }
    if (-not (Test-NRGSectionCollected $exo 'OutboundSpamPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Outbound spam policies were not collected; not assessed.'; return
    }
    $inForce = @(Get-NRGInForcePolicies -Policies @(Get-NRGObjectField -Item $exo.Data -Key 'OutboundSpamPolicies' -Default @()) `
        -Rules (Get-NRGObjectField -Item $exo.Data -Key 'OutboundSpamRules' -Default $null) `
        -RulePolicyKey 'HostedOutboundSpamFilterPolicy' -PresetKind 'EOP')
    if ($inForce.Count -eq 0) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'No outbound spam policy found'; return }

    # What matters is that an administrator hears when a user is restricted
    # for sending spam — a strong compromise signal. Microsoft now delivers
    # that through the default alert policy "User restricted from sending
    # email" (on by default); the policy-level NotifyOutboundSpam is the older
    # route. Either one satisfies. NotifyOutboundSpam = $false alone is the
    # documented default and says nothing when the alert policy is on.
    $notifying = @($inForce | Where-Object {
        (Get-NRGObjectField -Item $_ -Key 'NotifyOutboundSpam' -Default $false) -eq $true -and
        @(Get-NRGObjectField -Item $_ -Key 'NotifyOutboundSpamRecipients' -Default @('(not recorded)')).Count -gt 0 })
    $alertKnown = $false; $alertOn = @()
    $pvw = Get-NRGRawData -Key 'Purview'
    if ($pvw -and $pvw.Success -and (Get-NRGNestedProperty -Object $pvw -Path 'Data.SectionStatus.ProtectionAlerts' -Default $null) -eq 'Collected') {
        $alertKnown = $true
        $alertOn = @(@(Get-NRGObjectField -Item $pvw.Data -Key 'ProtectionAlerts' -Default @()) | Where-Object {
            ([string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')) -match 'restricted from sending' -and
            -not [bool](Get-NRGObjectField -Item $_ -Key 'Disabled' -Default $false) })
    }
    if ($alertOn.Count -gt 0 -or ($notifying.Count -eq $inForce.Count)) {
        $how = @()
        if ($alertOn.Count) { $how += "alert policy '$([string](Get-NRGObjectField -Item $alertOn[0] -Key 'Name' -Default ''))' is enabled" }
        if ($notifying.Count) { $how += "outbound spam notification is set on $(@($notifying | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '') }) -join ', ')" }
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "An administrator is told when a user is restricted for sending spam: $($how -join '; ')." `
            -CurrentValue ($how -join '; ')
        return
    }
    if (-not $alertKnown) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The outbound spam policies in force do not notify an administrator, but alert policies (Get-ProtectionAlert, Security & Compliance session) were not read, and the default alert policy "User restricted from sending email" delivers that notification on its own. Not assessed.'
        return
    }
    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
        -Detail 'No administrator is told when a user is restricted for sending spam: the "User restricted from sending email" alert policy is disabled or missing, and no outbound spam policy in force notifies anyone. A compromised mailbox blasting spam goes unseen until a downstream block or client complaint.' `
        -CurrentValue 'No enabled restricted-sender alert; NotifyOutboundSpam off' `
        -RequiredValue 'Alert policy "User restricted from sending email" enabled, or NotifyOutboundSpam with recipients on every outbound policy in force' `
        -Remediation $ctrl.Remediation
}

# ── EXO-3.3 Alert Policy — Forwarding Rules ──────────────────────────────────
function Test-NRGControlEXOAlertForwarding {
    [CmdletBinding()] param()
    $cid = 'EXO-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    # v4.13.1: scores Purview.ProtectionAlerts (Get-ProtectionAlert) policy
    # configuration, not fired /security/alerts_v2 incidents — a live
    # "Suspicious email forwarding" alert is evidence of an active BEC
    # incident, not evidence that an alert policy exists, and no fired alert
    # on a healthy tenant is not evidence one is missing. Mirrors EXO-3.4 /
    # DEF-4.3, which read policy configuration for the same reason.
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Purview data not collected'
        return
    }
    $status = Get-NRGNestedProperty -Object $pvw -Path 'Data.SectionStatus.ProtectionAlerts' -Default $null
    if ($status -ne 'Collected') {
        $why = if ($status -eq 'Failed') { 'the Get-ProtectionAlert query failed (see Exceptions)' }
               else { 'Get-ProtectionAlert was unavailable — this requires a Security & Compliance (IPPS) session' }
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Alert policy configuration could not be read: $why. Forwarding rule alerting was not assessed."
        return
    }

    $policies = @($pvw.Data['ProtectionAlerts'] ?? @())
    $pattern  = 'forward|redirect'
    $matched  = @($policies | Where-Object {
        (@([string]$_.Name, [string]$_.ThreatType, (@($_.Operation) -join ' ')) -join ' ') -match $pattern
    })
    $active = @($matched | Where-Object { -not $_.Disabled })

    if ($active.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No enabled alert policy was found covering new forwarding or redirect rule creation. A malicious forwarding rule is a common BEC persistence mechanism, and without this alert it can be created and go unseen until mail is already being exfiltrated. (Detection matches policy name, operation and threat type against forwarding/redirect wording, so a custom-named policy may exist and not be matched — verify in the portal before remediating.)' `
            -CurrentValue "0 of $($policies.Count) alert policies match forwarding/redirect" `
            -RequiredValue 'An enabled alert policy for new forwarding/redirect rule creation' `
            -Remediation $ctrl.Remediation
        return
    }

    $silent = @($active | Where-Object { @($_.NotifyUser).Count -eq 0 })
    if ($silent.Count -eq 0) {
        $routing = Get-NRGAlertRouting -Policies $active -Addresses (Get-NRGMonitoringAddresses)
        if (-not $routing.Configured) {
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
                -Title $ctrl.Title -FrameworkIds $cit `
                -Detail "Verified: $($active.Count) enabled alert policy(ies) cover new forwarding/redirect rule creation, each with notification recipients. Not assessed: whether they notify the NRG monitoring address, because no monitoring address is configured (-MonitoringAddress, MonitoringAddresses in clients.json, or MonitoringAddresses in branding.psd1)." `
                -CurrentValue "$($active.Count) forwarding-rule policies enabled with recipients; routing to NRG not checked" `
                -RequiredValue 'Forwarding/redirect rule alert enabled and routed to the NRG monitoring address'
        } elseif ($routing.Unrouted.Count -eq 0) {
            Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
                -Detail "$($active.Count) enabled alert policy(ies) cover new forwarding/redirect rule creation and notify a configured NRG monitoring address."
        } else {
            $affected = @($routing.Unrouted | ForEach-Object {
                [ordered]@{ DisplayName = [string]$_.Name; Severity = [string]$_.Severity; Recipients = (@($_.NotifyUser) -join ', ') }
            })
            $st = if ($routing.Routed.Count -gt 0) { 'Partial' } else { 'Gap' }
            Add-NRGFinding -ControlId $cid -State $st -Category $ctrl.Category `
                -Title $ctrl.Title -Severity $(if ($st -eq 'Gap') { $ctrl.Severity } else { 'Medium' }) -FrameworkIds $cit `
                -Detail "Verified: $($active.Count) enabled alert policy(ies) cover new forwarding/redirect rule creation and have recipients. Shortfall: $($routing.Unrouted.Count) of $($active.Count) do not notify a configured NRG monitoring address." `
                -CurrentValue "$($routing.Routed.Count) of $($active.Count) forwarding-rule policies notify the NRG monitoring address" `
                -RequiredValue 'Forwarding/redirect rule alert enabled and routed to the NRG monitoring address' `
                -Remediation $ctrl.Remediation -AffectedObjects $affected
        }
    } else {
        $affected = @($silent | ForEach-Object {
            [ordered]@{ DisplayName = [string]$_.Name; Severity = [string]$_.Severity; Recipients = 'none configured' }
        })
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($silent.Count) of $($active.Count) matching alert policy(ies) are enabled but notify nobody, so a new forwarding rule is recorded without anyone being told." `
            -CurrentValue "$($silent.Count) matching policies with no recipients" `
            -RequiredValue 'Forwarding/redirect rule alert enabled with notification recipients' `
            -Remediation $ctrl.Remediation -AffectedObjects $affected
    }
}

# ── EXO-3.4 Alert Policy — Unusual Mail Volume ───────────────────────────────
function Test-NRGControlEXOAlertVolume {
    [CmdletBinding()] param()
    $cid = 'EXO-3.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    # v4.13.0: implemented against Get-ProtectionAlert policy configuration
    # (Purview.ProtectionAlerts). Matching is by policy name / threat type /
    # operation against phish-reporting and mail-volume wording, because no
    # machine-readable "this is the unusual mail volume policy" flag exists.
    # A custom-named policy can therefore be under-detected, which the Gap text
    # states so the reader knows to confirm before acting.
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Purview data not collected'
        return
    }
    $status = Get-NRGNestedProperty -Object $pvw -Path 'Data.SectionStatus.ProtectionAlerts' -Default $null
    if ($status -ne 'Collected') {
        $why = if ($status -eq 'Failed') { 'the Get-ProtectionAlert query failed (see Exceptions)' }
               else { 'Get-ProtectionAlert was unavailable — this requires a Security & Compliance (IPPS) session' }
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Alert policy configuration could not be read: $why. Mail volume alerting was not assessed."
        return
    }

    $policies = @($pvw.Data['ProtectionAlerts'] ?? @())
    $pattern  = 'unusual.*(mail|email)|(mail|email).*volume|reported as phish|phish.*report|suspicious email sending'
    $matched  = @($policies | Where-Object {
        (@([string]$_.Name, [string]$_.ThreatType, (@($_.Operation) -join ' ')) -join ' ') -match $pattern
    })
    $active = @($matched | Where-Object { -not $_.Disabled })

    if ($active.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No enabled alert policy was found covering unusual mail volume or user-reported phish. A compromised mailbox sending outbound spam is often first visible as a volume spike, and without this alert that spike is only noticed once the tenant is being throttled or blocklisted. (Detection matches policy name, operation and threat type against mail-volume and phish-reporting wording, so a custom-named policy may exist and not be matched — verify in the portal before remediating.)' `
            -CurrentValue "0 of $($policies.Count) alert policies match mail volume / phish reporting" `
            -RequiredValue 'An enabled alert policy for unusual mail volume or user-reported phish' `
            -Remediation $ctrl.Remediation
        return
    }

    $silent = @($active | Where-Object { @($_.NotifyUser).Count -eq 0 })
    if ($silent.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($active.Count) enabled alert policy(ies) cover unusual mail volume / user-reported phish, each with notification recipients."
    } else {
        $affected = @($silent | ForEach-Object {
            [ordered]@{ DisplayName = [string]$_.Name; Severity = [string]$_.Severity; Recipients = 'none configured' }
        })
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($silent.Count) of $($active.Count) matching alert policy(ies) are enabled but notify nobody, so a mail volume spike is recorded without anyone being told." `
            -CurrentValue "$($silent.Count) matching policies with no recipients" `
            -RequiredValue 'Mail volume / phish reporting alert enabled with notification recipients' `
            -Remediation $ctrl.Remediation -AffectedObjects $affected
    }
}


# ── EXO-3.5 Transport Rules Audit Enabled ────────────────────────────────────
function Test-NRGControlEXOTransportAudit {
    [CmdletBinding()] param()
    $cid = 'EXO-3.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected'; return
    }
    # Transport rule changes (New-/Set-/Remove-TransportRule) are Exchange
    # admin audit records, searchable only through the Unified Audit Log.
    # OrganizationConfig.AuditDisabled — read here before — is the MAILBOX
    # audit switch and says nothing about them.
    $aal = if (Test-NRGSectionCollected $exo 'AdminAuditLogConfig') { Get-NRGObjectField -Item $exo.Data -Key 'AdminAuditLogConfig' -Default $null } else { $null }
    $ual = Get-NRGObjectField -Item $aal -Key 'UnifiedAuditLogIngestionEnabled' -Default $null
    $adm = Get-NRGObjectField -Item $aal -Key 'AdminAuditLogEnabled' -Default $null
    if ($null -eq $ual) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The audit configuration (Get-AdminAuditLogConfig in Exchange Online) was not read; not assessed.'
        return
    }
    if ([bool]$ual -and $adm -ne $false) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Unified Audit Log ingestion and admin audit logging are on, so transport rule creation, changes and removal are recorded and searchable.' -CurrentValue 'UnifiedAuditLogIngestionEnabled = True'
    } else {
        $what = if (-not [bool]$ual) { 'Unified Audit Log ingestion is OFF' } else { 'admin audit logging is OFF' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$what, so transport rule creation and modification — a common way to hide or reroute mail after a compromise — cannot be searched." -CurrentValue "UnifiedAuditLogIngestionEnabled = $ual; AdminAuditLogEnabled = $adm" -RequiredValue 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' -Remediation 'Purview portal > Audit > Start recording user and admin activity. Or in Exchange Online PowerShell: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true'
    }
}

# ── EXO-4.1 Mailbox Audit Log Age Limit ──────────────────────────────────────
function Test-NRGControlEXOAuditAgeLimit {
    [CmdletBinding()] param()
    $cid = 'EXO-4.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'EXO data not collected'; return
    }
    # Microsoft: "The AuditLogAgeLimit property is no longer applicable for
    # managing mailbox audit log retention" — mailbox audit records live in
    # the Unified Audit Log, kept 180 days under Audit (Standard) and one year
    # for E5 / Audit (Premium) users. Scoring the per-mailbox AuditLogAgeLimit
    # (90 by default) marked every tenant down on a setting that no longer
    # decides anything. Retention holds only while records are produced.
    $orgOff = if (Test-NRGSectionCollected $exo 'OrganizationConfig') { Get-NRGNestedProperty -Object $exo -Path 'Data.OrganizationConfig.AuditDisabled' -Default $null } else { $null }
    $ual = if (Test-NRGSectionCollected $exo 'AdminAuditLogConfig') { Get-NRGNestedProperty -Object $exo -Path 'Data.AdminAuditLogConfig.UnifiedAuditLogIngestionEnabled' -Default $null } else { $null }
    if ($null -eq $orgOff -or $null -eq $ual) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Mailbox audit status (Get-OrganizationConfig) or audit log ingestion (Get-AdminAuditLogConfig) was not read, so whether mailbox audit records are retained was not assessed.'
        return
    }
    if ($orgOff -eq $true -or -not [bool]$ual) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "No mailbox audit records are being retained because $(if ($orgOff -eq $true) { 'mailbox auditing is off for the organization (scored under EXO-5.1)' } else { 'Unified Audit Log ingestion is off (scored under EXO-3.5)' }); retention is not scored separately."
        return
    }
    # A custom audit retention policy (Audit Premium) takes precedence over
    # the defaults and can SHORTEN Exchange record retention below 180 days.
    $short = @(); $policiesRead = $false
    $pvw = Get-NRGRawData -Key 'Purview'
    if ($pvw -and $pvw.Success -and (Get-NRGNestedProperty -Object $pvw -Path 'Data.SectionStatus.AuditRetentionPolicies' -Default $null) -eq 'Collected') {
        $policiesRead = $true
        $short = @(@(Get-NRGObjectField -Item $pvw.Data -Key 'AuditRetentionPolicies' -Default @()) | Where-Object {
            $d = Get-NRGObjectField -Item $_ -Key 'RetentionDays' -Default $null
            $types = @(Get-NRGObjectField -Item $_ -Key 'RecordTypes' -Default @() | ForEach-Object { [string]$_ })
            $null -ne $d -and [int]$d -lt 180 -and ($types.Count -eq 0 -or @($types | Where-Object { $_ -match '^Exchange' }).Count -gt 0) })
    }
    if ($short.Count -gt 0) {
        $names = @($short | ForEach-Object { "$([string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '?')) ($([string](Get-NRGObjectField -Item $_ -Key 'RetentionDuration' -Default '')))" })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "Custom audit retention policies keep Exchange audit records for less than 180 days: $($names -join '; '). A custom policy takes precedence over the default, so mailbox activity older than that cannot be investigated." `
            -CurrentValue ($names -join '; ') -RequiredValue 'Exchange audit records retained at least 180 days' -Remediation $ctrl.Remediation
        return
    }
    $policyNote = if ($policiesRead) { ' No custom audit retention policy shortens it.' } else { ' Custom audit retention policies (Audit Premium, Security & Compliance session) were not read; one could shorten retention for the users it covers.' }
    Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
        -Detail "Mailbox auditing and Unified Audit Log ingestion are on, so mailbox audit records are retained for 180 days (Audit Standard) or one year for users with E5 / Audit (Premium). The per-mailbox AuditLogAgeLimit no longer governs this.$policyNote" `
        -CurrentValue 'Retention set by Purview Audit (180 days minimum by default)'
}

# ── EXO-4.2 Admin Audit Log Enabled ─────────────────────────────────────────
function Test-NRGControlEXOAdminAudit {
    [CmdletBinding()] param()
    $cid = 'EXO-4.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'EXO data not collected'; return
    }
    # AdminAuditLogEnabled (Get-AdminAuditLogConfig) is the admin audit
    # switch. OrganizationConfig.AuditDisabled, read here before, is the
    # mailbox audit switch.
    $adm = if (Test-NRGSectionCollected $exo 'AdminAuditLogConfig') { Get-NRGNestedProperty -Object $exo -Path 'Data.AdminAuditLogConfig.AdminAuditLogEnabled' -Default $null } else { $null }
    if ($null -eq $adm) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AdminAuditLogEnabled (Get-AdminAuditLogConfig) was not read; not assessed.'
        return
    }
    if ([bool]$adm) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Admin audit logging is enabled — Exchange cmdlets run by administrators are recorded.' -CurrentValue 'AdminAuditLogEnabled = True'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Admin audit logging is disabled. Exchange cmdlets run by administrators — including an attacker holding an admin account — are not recorded.' `
            -CurrentValue 'AdminAuditLogEnabled = False' -RequiredValue 'AdminAuditLogEnabled = True' -Remediation $ctrl.Remediation
    }
}

# ── EXO-4.3 Safe Attachments for SharePoint OneDrive Teams ───────────────────
function Test-NRGControlEXOSafeAttachmentsSPO {
    [CmdletBinding()] param()
    $cid = 'EXO-4.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Defender data not collected'; return
    }
    # The setting is EnableATPForSPOTeamsODB on Get-AtpPolicyForO365 — the
    # tenant-wide switch, separate from any Safe Attachments mail policy.
    # An enabled mail policy says nothing about it.
    $atp = Get-NRGObjectField -Item $def.Data -Key 'AtpPolicyForO365' -Default $null
    $on  = Get-NRGObjectField -Item $atp -Key 'EnableATPForSPOTeamsODB' -Default $null
    if (-not (Get-NRGObjectField -Item $atp -Key 'Available' -Default $false) -or $null -eq $on) {
        Add-NRGDefenderUnavailableFinding -ControlId 'EXO-4.3' -Control $ctrl -FrameworkIds $cit -Section $atp -Feature 'Safe Attachments for SharePoint, OneDrive and Teams'
        return
    }
    if ([bool]$on) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Safe Attachments for SharePoint, OneDrive and Teams is on: files found malicious are blocked from being opened, shared or downloaded.' -CurrentValue 'EnableATPForSPOTeamsODB = True'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Safe Attachments for SharePoint, OneDrive and Teams is off: a malicious file uploaded to a site or shared in Teams stays openable and shareable.' `
            -CurrentValue 'EnableATPForSPOTeamsODB = False' -RequiredValue 'Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true' -Remediation $ctrl.Remediation
    }
}

# ── EXO-4.4 Anti-Spam Inbound Policy Configured ─────────────────────────────
function Test-NRGControlEXOAntiSpamInbound {
    [CmdletBinding()] param()
    $cid = 'EXO-4.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'EXO data not collected'; return
    }
    $policies = @($exo.Data['AntiSpamPolicies'] ?? @())
    $default  = $policies | Where-Object { $_.IsDefault } | Select-Object -First 1
    if (-not $default) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'No default anti-spam policy found'; return
    }
    $gaps = @()
    if ($default.SpamAction     -ne 'MoveToJmf' -and $default.SpamAction -ne 'Quarantine') { $gaps += "SpamAction=$($default.SpamAction)" }
    # BulkThreshold 6, not Microsoft's default of 7: the control's own
    # Remediation instructs -BulkThreshold 6, and an evaluator that passes 7
    # while the remediation says 6 contradicts itself in the client's report.
    if ($default.BulkThreshold  -gt 6)  { $gaps += "BulkThreshold=$($default.BulkThreshold)" }
    if ($default.ZapEnabled -ne $true)  { $gaps += 'ZapEnabled=False' }
    if ($gaps.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Default inbound anti-spam policy is properly configured.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "Anti-spam policy has sub-optimal settings: $($gaps -join ', ')" `
            -CurrentValue ($gaps -join ', ') -RequiredValue 'SpamAction=MoveToJmf/Quarantine, BulkThreshold≤6, ZapEnabled=True' `
            -Remediation $ctrl.Remediation
    }
}

# ── EXO-5.1 Per-User Mailbox Audit Logging Enabled ────────────────────────────
function Test-NRGControlEXOPerUserAudit {
    [CmdletBinding()] param()
    $cid = 'EXO-5.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected'; return
    }
    # The authoritative signal is the org-wide master switch. Since 2019 Microsoft
    # enables mailbox audit by default for every mailbox; default audit ignores the
    # per-mailbox AuditEnabled flag, so per-mailbox=$false is NOT a gap while the org
    # switch is on. AuditDisabled=$true means an admin explicitly turned off the
    # org-wide default — that IS the real, assessable gap.
    $auditDisabled = Get-NRGNestedProperty -Object $exo -Path 'Data.OrganizationConfig.AuditDisabled' -Default $null
    if ($null -eq $auditDisabled) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Organization audit configuration not collected; not assessed.'; return
    }
    $sampleAll = Get-NRGNestedProperty -Object $exo -Path 'Data.MailboxAuditSummary.SampleMailboxAudit.AllEnabled' -Default $null
    if (-not [bool]$auditDisabled) {
        $extra = ''
        if ($null -ne $sampleAll) {
            $sampleWord = if ([bool]$sampleAll) { 'all true' } else { 'mixed' }
            $extra = " Sampled mailboxes: per-mailbox AuditEnabled = $sampleWord (informational; default audit applies regardless)."
        }
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Organization-wide mailbox audit logging is enabled (AuditDisabled = False) — every mailbox is audited by default.$extra"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Organization-wide mailbox audit logging is DISABLED (AuditDisabled = True). No mailbox actions (mail access, deletes, rule changes) are recorded, crippling incident-response forensics.' -CurrentValue 'OrganizationConfig.AuditDisabled = True' -RequiredValue 'AuditDisabled = False (org-wide audit on)' -Remediation $ctrl.Remediation
    }
}

# ── EXO-5.2 Priority Account Email Protection Configured ─────────────────────
function Test-NRGControlEXOPriorityAccountProtection {
    [CmdletBinding()] param()
    $cid = 'EXO-5.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Defender data not collected'; return
    }
    $ap = Get-NRGObjectField -Item $def.Data -Key 'AntiPhishing' -Default $null
    if (-not $ap -or -not (Get-NRGObjectField -Item $ap -Key 'Available' -Default $false)) {
        Add-NRGDefenderUnavailableFinding -ControlId 'EXO-5.2' -Control $ctrl -FrameworkIds $cit -Section $ap -Feature 'Anti-phishing user impersonation protection'
        return
    }
    # Protection is real only in a policy that applies (enabled rule, enabled
    # preset, or the default), with users listed AND an action other than
    # NoAction — NoAction is Microsoft's default and detects without acting.
    $inForce = @(Get-NRGInForcePolicies -Policies @(Get-NRGObjectField -Item $ap -Key 'Policies' -Default @()) `
        -Rules (Get-NRGObjectField -Item $ap -Key 'Rules' -Default $null) -RulePolicyKey 'AntiPhishPolicy' -PresetKind 'EOP')
    $users = { param($p) @(Get-NRGObjectField -Item $p -Key 'TargetedUsersToProtect' -Default @() | Where-Object { $_ }) }
    $listed = { param($p) (Get-NRGObjectField -Item $p -Key 'EnableTargetedUserProtection' -Default $false) -eq $true -and @(& $users $p).Count -gt 0 }
    $acting = { param($p) [string](Get-NRGObjectField -Item $p -Key 'TargetedUserProtectionAction' -Default 'NoAction') -notin @('','NoAction') }
    $protecting = @($inForce | Where-Object { (& $listed $_) -and (& $acting $_) })
    if ($protecting.Count -gt 0) {
        $total = @($protecting | ForEach-Object { & $users $_ } | ForEach-Object { $_ }).Count
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "User impersonation protection is in force and acting for $total named account(s) across $($protecting.Count) policy(ies): $(@($protecting | ForEach-Object { "$([string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '?')) ($([string](Get-NRGObjectField -Item $_ -Key 'TargetedUserProtectionAction' -Default '')))" }) -join '; ')."
        return
    }
    $why = @()
    $all = @(Get-NRGObjectField -Item $ap -Key 'Policies' -Default @())
    $noAction = @($inForce | Where-Object { (& $listed $_) -and -not (& $acting $_) })
    $notApplied = @($all | Where-Object { (& $listed $_) -and $_ -notin $inForce })
    if ($noAction.Count) { $why += "users are listed but the action is NoAction in $(@($noAction | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '?') }) -join ', ')" }
    if ($notApplied.Count) { $why += "users are listed in $(@($notApplied | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '?') }) -join ', '), which applies to no one (its rule is disabled)" }
    $whyText = if ($why.Count) { " ($($why -join '; '))" } else { '' }
    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
        -Detail "No anti-phishing policy in force acts on impersonation of named priority accounts$whyText. Executive-impersonation (CEO fraud / BEC) email is not specifically stopped." `
        -CurrentValue 'No in-force policy protecting named users with an action' -RequiredValue 'Executives in TargetedUsersToProtect, protection on, action Quarantine (or MoveToJmf), in a policy whose rule is enabled' -Remediation $ctrl.Remediation
}

# ── EXO-5.3 Exchange Online Protection Safe Senders Not Overriding ────────────
function Test-NRGControlEXOSafeSenderOverride {
    [CmdletBinding()] param()
    $cid = 'EXO-5.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected'; return
    }
    if (-not (Test-NRGSectionCollected $exo 'AntiSpamPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Anti-spam policies were not collected; not assessed.'; return
    }
    $policies = @(Get-NRGObjectField -Item $exo.Data -Key 'AntiSpamPolicies' -Default @() | Where-Object { $null -ne $_ })
    # Results collected before AllowedSenderDomains was read do not carry it;
    # a missing list is unknown, not empty (it always read as empty before,
    # so this control passed on every tenant).
    # Key presence, not value: an empty list comes back from the field
    # helper as $null, indistinguishable from "not collected".
    $unread = @($policies | Where-Object {
        if ($_ -is [System.Collections.IDictionary]) { -not $_.Contains('AllowedSenderDomains') }
        else { -not $_.PSObject.Properties['AllowedSenderDomains'] } })
    if ($policies.Count -eq 0 -or $unread.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The allowed sender and domain lists of the anti-spam policies were not collected; not assessed.'; return
    }
    $inForce = @(Get-NRGInForcePolicies -Policies $policies -Rules (Get-NRGObjectField -Item $exo.Data -Key 'AntiSpamRules' -Default $null) `
        -RulePolicyKey 'HostedContentFilterPolicy' -PresetKind 'EOP')
    $hits = @($inForce | ForEach-Object {
        $n = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '?')
        $d = @(Get-NRGObjectField -Item $_ -Key 'AllowedSenderDomains' -Default @() | Where-Object { $_ })
        $s = @(Get-NRGObjectField -Item $_ -Key 'AllowedSenders' -Default @() | Where-Object { $_ })
        if ($d.Count -or $s.Count) { [ordered]@{ Policy = $n; AllowedSenderDomains = ($d -join ', '); AllowedSenders = ($s -join ', ') } } })
    if ($hits.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "No anti-spam policy in force allows senders or sender domains past spam filtering ($($inForce.Count) policy(ies) checked)."
    } else {
        $domainCount = @($hits | ForEach-Object { if ($_.AllowedSenderDomains) { $_.AllowedSenderDomains -split ', ' } }).Count
        $senderCount = @($hits | ForEach-Object { if ($_.AllowedSenders) { $_.AllowedSenders -split ', ' } }).Count
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$domainCount allowed sender domain(s) and $senderCount allowed sender(s) in $($hits.Count) anti-spam policy(ies) in force skip spam filtering. Allowed entries are a common attacker target — mail spoofing or sent from a compromised allowed domain reaches inboxes unfiltered." `
            -CurrentValue "$domainCount domain(s), $senderCount sender(s) allowed" -RequiredValue 'No allowed senders or sender domains in any anti-spam policy in force' -Remediation $ctrl.Remediation -AffectedObjects $hits
    }
}

# ── EXO-7.1 Mailbox Forwarding to External Addresses ─────────────────────────
# Consumes EXO-Inventory.ForwardingMailboxes. ForwardingSmtpAddress is a
# server-side persistent exfil channel — common BEC TTP (MITRE T1114.003).
function Test-NRGControlEXOMailboxForwarding {
    [CmdletBinding()] param()
    $cid = 'EXO-7.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'EXO inventory data not collected'
        return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $inv 'ForwardingMailboxes')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'ForwardingMailboxes was not collected; not assessed.'
        return
    }

    # External subset only — see EXO-6.1. The collector classifies each row;
    # scoring the unfiltered list reports internal forwarding as external
    # exfiltration and produces a Gap on a tenant that has none.
    # Field access via the helper — a missing property throws under StrictMode,
    # and Classification / ForwardingMechanism do not exist in result JSON
    # produced before this collector change.
    $allFwd     = @($inv.Data['ForwardingMailboxes'] ?? @())
    $fwd        = @($allFwd | Where-Object { Get-NRGObjectField -Item $_ -Key 'IsExternal' -Default $false })
    $unresolved = @($allFwd | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Classification' -Default '') -eq 'Unresolved' })
    $count      = @($fwd | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'UPN' -Default '') } | Sort-Object -Unique).Count

    if ($count -eq 0 -and $unresolved.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -FrameworkIds $cit `
            -Detail "$($unresolved.Count) forwarding target(s) could not be resolved to an address and so could not be classified. Not assessed rather than reported clean."
        return
    }

    if ($count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "No mailbox forwards to an external address ($($allFwd.Count) forwarding configuration(s) found, all to accepted domains)."
        return
    }

    $affected = @($fwd | ForEach-Object {
        [ordered]@{
            DisplayName  = [string](Get-NRGObjectField -Item $_ -Key 'UPN' -Default '')
            ForwardingTo = [string](Get-NRGObjectField -Item $_ -Key 'ForwardingAddress' -Default '')
            Mechanism    = [string](Get-NRGObjectField -Item $_ -Key 'ForwardingMechanism' -Default 'ForwardingSmtpAddress')
        }
    })

    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
        -Detail "$count mailbox(es) auto-forward to external addresses — common BEC persistence (MITRE T1114.003)." `
        -CurrentValue "$count mailbox(es) forwarding externally" `
        -RequiredValue 'Zero mailboxes with ForwardingSmtpAddress to external recipients' `
        -Remediation 'EAC > Recipients > Mailboxes > select mailbox > Manage email forwarding > clear "Forward all email sent to this mailbox". Or: Set-Mailbox -Identity <UPN> -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false. Also recommend an EXO transport rule blocking auto-forward to external recipients (Set-RemoteDomain Default -AutoForwardEnabled $false; mail flow rule: if sender is internal and recipient is external and message type is auto-forward, then reject).' `
        -AffectedObjects $affected
}

# ── EXO-7.2 Inbox Rules Forwarding Externally ────────────────────────────────
# Consumes EXO-Inventory.InboxRulesForwarding. Outlook rules that ForwardTo /
# RedirectTo / ForwardAsAttachmentTo external recipients — classic
# post-credential-compromise persistence (MITRE T1114.003) or insider exfil.
function Test-NRGControlEXOInboxRulesForwarding {
    [CmdletBinding()] param()
    $cid = 'EXO-7.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'EXO inventory data not collected'
        return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $inv 'InboxRulesForwarding')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'InboxRulesForwarding was not collected; not assessed.'
        return
    }

    # Only count rules that actually forward externally — the collector also
    # tracks disabled-rule fingerprints, but for this control we score on the
    # active exfil surface.
    $allRules    = @($inv.Data['InboxRulesForwarding'] ?? @())
    $rules       = @($allRules | Where-Object { $_.IsExternal })
    $count       = $rules.Count
    # A disabled rule forwards nothing now, but it is one click from
    # forwarding and attackers stage rules disabled; named separately.
    $disabledExt = @($rules | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Enabled' -Default $true) -eq $false })
    $enabledExt  = $count - $disabledExt.Count

    # The sweep is capped (InboxRuleScanLimit) and per-mailbox reads can
    # fail. A clean result over part of the tenant is not a clean tenant.
    $scanned  = [int](Get-NRGNestedProperty -Object $inv -Path 'Data.Stats.MailboxesScanned' -Default 0)
    $capped   = (Get-NRGNestedProperty -Object $inv -Path 'Data.Stats.ScanLimitReached' -Default $false) -eq $true
    $failedMb = [int](Get-NRGNestedProperty -Object $inv -Path 'Data.Stats.MailboxesRuleScanFailed' -Default 0)
    $partialNote = ''
    if ($capped)       { $partialNote += " Only the first $scanned mailboxes were swept (scan limit reached); the rest were not checked." }
    if ($failedMb -gt 0) { $partialNote += " Inbox rules could not be read on $failedMb mailbox(es)." }
    if ($count -eq 0 -and $partialNote) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Not assessed across the tenant: no externally forwarding rule was found in the mailboxes that were read.$partialNote Re-run with a higher -InboxRuleScanLimit (0 = all) before treating this control as clean."
        return
    }

    # Rules whose recipients could not be classified, and rules Exchange
    # itself could not interpret. Both are rules we did not read — not rules
    # that forward nowhere. Counting them as clean is a coverage gap reported
    # as a pass on the primary BEC persistence check.
    # Get-NRGObjectField, not dot-access: under StrictMode a missing property
    # THROWS, and result JSON replayed from a run before this field existed
    # does not carry it.
    $unresolvedRules = @($allRules | Where-Object { Get-NRGObjectField -Item $_ -Key 'IsUnresolved' -Default $false })
    $unparseable     = @($inv.Data['UnparseableRules'] ?? @())
    $blindSpots      = $unresolvedRules.Count + $unparseable.Count

    # An empty list means "no attacker rules found" only if the mailbox sweep
    # actually ran. The sweep is the most failure-prone query in the collector
    # (per-mailbox Get-InboxRule across the tenant, routinely throttled), and
    # claiming a clean result after it failed is a false all-clear on the
    # primary BEC persistence check.
    if ($count -eq 0 -and -not (Test-NRGInventorySectionCollected -Inventory $inv -Section 'InboxRulesForwarding')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -FrameworkIds $cit `
            -Detail 'Inbox rule sweep did not complete (see Exceptions) — forwarding rules could not be assessed. Re-run before treating this control as clean.'
        return
    }

    if ($count -eq 0 -and $blindSpots -gt 0) {
        $detail = @(
            'Not assessed.'
            if ($unparseable.Count -gt 0) { "$($unparseable.Count) inbox rule(s) could not be interpreted by Exchange, so their forwarding actions were never read." }
            if ($unresolvedRules.Count -gt 0) { "$($unresolvedRules.Count) rule(s) forward to a recipient that could not be resolved to an address." }
            'A rule the tool could not read is not a rule that forwards nowhere — review these manually before treating this control as clean.'
        ) -join ' '
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail $detail
        return
    }

    if ($count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'No inbox rules forward mail externally, and every rule recipient resolved to an accepted domain.'
        return
    }

    $affected = @($rules | ForEach-Object {
        [ordered]@{
            DisplayName = [string]$_.Mailbox
            RuleName    = [string]$_.RuleName
            Recipients  = (@($_.ExternalRecipients) -join ', ')
        }
    })

    $blindNote = if ($blindSpots -gt 0) { " A further $blindSpots rule(s) could not be read or classified and are not counted here." } else { '' }
    $blindNote += $partialNote
    if ($disabledExt.Count -gt 0) { $blindNote = " $($disabledExt.Count) of them are disabled — not forwarding now, but staged; confirm who created them.$blindNote" }
    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
        -Detail "$count inbox rule(s) forward externally ($enabledExt enabled) — attacker persistence (T1114.003) or insider data exfil.$blindNote" `
        -CurrentValue "$count inbox rule(s) forwarding externally" `
        -RequiredValue 'Zero inbox rules forwarding to external recipients' `
        -Remediation 'Find: foreach ($m in Get-Mailbox -ResultSize Unlimited) { Get-InboxRule -Mailbox $m.UserPrincipalName | Where-Object { $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo } | Select-Object @{n=''Mailbox'';e={$m.UserPrincipalName}}, Name, ForwardTo, RedirectTo, ForwardAsAttachmentTo }. Disable: Disable-InboxRule -Mailbox <UPN> -Identity <RuleName>. Block at transport layer: Set-RemoteDomain Default -AutoForwardEnabled $false plus a mail flow rule rejecting auto-forwarded mail to external recipients.' `
        -AffectedObjects $affected
}

# ── EXO-7.3 Per-User Audit Explicitly Disabled ───────────────────────────────
# Consumes EXO-Inventory.AuditDisabledMailboxes. Since Jan 2019, mailbox
# auditing is ON by default org-wide; an explicit AuditEnabled = $false is a
# deliberate override that creates an IR blind spot.
function Test-NRGControlEXOAuditDisabledMailboxes {
    [CmdletBinding()] param()
    $cid = 'EXO-7.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO inventory not collected'; return
    }
    $st = Get-NRGMailboxAuditBypassState -Inventory $inv
    if ($st.Kind -eq 'Bypass') {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($st.Names.Count) account(s) have a mailbox audit bypass: nothing they do in any mailbox — their own, a shared mailbox, or one they administer — is recorded. A BEC incident involving these accounts cannot be investigated." `
            -CurrentValue "$($st.Names.Count) account(s) with AuditBypassEnabled = True" -RequiredValue 'No mailbox audit bypass associations' `
            -Remediation 'For each account: Set-MailboxAuditBypassAssociation -Identity <account> -AuditBypassEnabled $false. Bypass is only appropriate for high-volume service accounts whose actions are logged elsewhere.' -AffectedObjects $st.Names
    } elseif ($st.Kind -eq 'Clean') {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail $st.Detail
    } else {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $st.Detail
    }
}

# ── EXO-7.4 Per-User SMTP AUTH Override (Legacy Auth) ────────────────────────
# Consumes EXO-Inventory.SmtpAuthEnabledPerUser. A per-mailbox
# SmtpClientAuthenticationDisabled = $false overrides the tenant-level disable
# and re-enables basic-auth SMTP — bypasses MFA and CA. Common attack surface
# for password spray against legacy mail clients and copiers/scanners.
function Test-NRGControlEXOSmtpAuthExceptions {
    [CmdletBinding()] param()
    $cid = 'EXO-7.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'EXO inventory data not collected'
        return
    }
    if (-not (Test-NRGSectionCollected $inv 'SmtpAuthEnabledPerUser')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'SmtpAuthEnabledPerUser was not collected; not assessed.'
        return
    }
    $st = Get-NRGSmtpAuthOverrideState -Inventory $inv
    if ($st.OrgDisabled -eq $false) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'SMTP AUTH is enabled for the whole organization, so there is no tenant-level disable for a mailbox to override. Scored under EXO-1.2.'
        return
    }
    $count = $st.Count
    if ($count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "No mailbox overrides the organization SMTP AUTH setting$(if ($st.OrgDisabled -ne $true) { ' (the organization setting itself was not read)' })."
        return
    }

    # UPNs go to AffectedObjects, never into Detail (rendered verbatim).
    $affected = @($st.List | ForEach-Object {
        [ordered]@{
            DisplayName  = [string](Get-NRGObjectField -Item $_ -Key 'UPN' -Default '')
            OverrideType = 'SmtpAuth'
        }
    })
    $capNote = if ($count -gt $affected.Count) { " The first $($affected.Count) are listed." } else { '' }
    $detail  = "$count mailbox(es) override the tenant-level SMTP AUTH disable — legacy auth blast radius. See AffectedObjects for the per-user list.$capNote"
    $remediation = 'For each affected mailbox: Set-CASMailbox -Identity <UPN> -SmtpClientAuthenticationDisabled $true. Recommend migrating senders to OAuth-based SMTP or the Microsoft Graph sendMail API. For multifunction devices/scanners, prefer SMTP relay via a connector with an IP allowlist, or Direct Send — neither requires SMTP AUTH.'

    if ($count -le 5) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail $detail `
            -CurrentValue "$count per-user SMTP AUTH exception(s)" `
            -RequiredValue 'Zero per-user SMTP AUTH exceptions' `
            -Remediation $remediation `
            -AffectedObjects $affected
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail $detail `
            -CurrentValue "$count per-user SMTP AUTH exception(s)" `
            -RequiredValue 'Zero per-user SMTP AUTH exceptions' `
            -Remediation $remediation `
            -AffectedObjects $affected
    }
}

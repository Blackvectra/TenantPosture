#Requires -Version 7.0
#
# Test-NRGControlMailFlow.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The three mail-path controls the tool was missing — connectors,
#          transport-rule contents, and the Tenant Allow/Block List.
#
#          Every existing forwarding control looks at a MAILBOX. EXO-1.3 checks
#          the org-wide auto-forward setting, EXO-7.1 lists mailboxes with a
#          forwarding address, EXO-7.2 lists inbox rules that forward. All three
#          are blind to the two routes that do not touch a mailbox at all:
#
#            A transport rule that redirects or blind-copies mail externally
#            applies org-wide, at the transport layer, with no forwarding flag
#            on any mailbox for the other controls to find.
#
#            A connector reroutes mail into or out of the tenant entirely. It
#            survives a password reset, it is not in anyone's mailbox, and
#            nothing about it resembles an inbox rule.
#
#          Both are established persistence and exfiltration techniques, and
#          both were unassessed. The Tenant Allow/Block List is the third: an
#          allow entry there overrides a filtering verdict outright, and
#          entries added during an incident routinely outlive it.
#
# Controls: EXO-8.1 (mail flow connectors), EXO-8.2 (transport rule contents),
#           DEF-5.1 (Tenant Allow/Block List).
#
# Consumes: EXO-Inventory raw data. No Graph, no direct EXO calls.
#

function Get-NRGAcceptedDomainSet {
    <#
        The accepted-domain set for this tenant, used to decide whether a
        recipient is external. Falls back to an empty set, and every caller
        treats an empty set as "cannot determine" rather than "everything is
        external" — an unknown domain list would otherwise flag every rule in
        the tenant and bury the real one.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param()

    Set-StrictMode -Version Latest
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($key in @('EXO-MailboxConfig', 'EXO-Inventory', 'AAD-Inventory')) {
        $raw = Get-NRGRawData -Key $key
        if (-not $raw) { continue }
        foreach ($path in @('Data.AcceptedDomains', 'Data.Domains', 'Data.OrganizationConfig.AcceptedDomains')) {
            foreach ($d in @(Get-NRGNestedProperty -Object $raw -Path $path -Default @())) {
                if ($null -eq $d) { continue }
                $name = if ($d -is [string]) { $d } else { [string](Get-NRGObjectField -Item $d -Key 'DomainName' -Default (Get-NRGObjectField -Item $d -Key 'Name')) }
                if ($name) { $null = $set.Add($name.TrimStart('@')) }
            }
        }
    }
    return $set
}

function Test-NRGRecipientIsExternal {
    <#
        Is this recipient outside the tenant? Returns $null — not $false — when
        the accepted-domain list is unavailable, so a caller can tell "internal"
        apart from "unknown" and decline to render a verdict rather than
        guessing in either direction.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [string] $Recipient,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.HashSet[string]] $AcceptedDomains
    )
    Set-StrictMode -Version Latest
    if ([string]::IsNullOrWhiteSpace($Recipient)) { return $null }
    if ($AcceptedDomains.Count -eq 0) { return $null }
    # A transport-rule recipient can be an SMTP address, a display name, or a
    # distinguished name. Only an SMTP address can be judged.
    if ($Recipient -notmatch '@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*>?\s*$') { return $null }
    return (-not $AcceptedDomains.Contains($Matches[1]))
}

# ── EXO-8.1 Mail Flow Connectors Reviewed ────────────────────────────────────
function Test-NRGControlEXOMailFlowConnectors {
    [CmdletBinding()] param()
    $cid = 'EXO-8.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO inventory not collected'
        return
    }
    if (-not (Test-NRGSectionCollected $inv 'MailFlowConnectors')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Mail flow connectors were not collected; not assessed.'
        return
    }

    $inbound  = @(Get-NRGNestedProperty -Object $inv -Path 'Data.InboundConnectors'  -Default @())
    $outbound = @(Get-NRGNestedProperty -Object $inv -Path 'Data.OutboundConnectors' -Default @())
    $enabledIn  = @($inbound  | Where-Object { Get-NRGObjectField -Item $_ -Key 'Enabled' -Default $false })
    $enabledOut = @($outbound | Where-Object { Get-NRGObjectField -Item $_ -Key 'Enabled' -Default $false })

    # No connectors is the common and correct state for a tenant with no hybrid
    # or third-party mail gateway, and the section status above already proved
    # the query ran.
    if (($enabledIn.Count + $enabledOut.Count) -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -CurrentValue 'No enabled inbound or outbound connectors' `
            -Detail 'No mail flow connectors are enabled. Mail routes through Exchange Online with no custom inbound or outbound path.'
        return
    }

    # Connectors are legitimate infrastructure. The finding is never "you have
    # a connector" — it is the specific weakenings that make one dangerous.
    $concerns = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $enabledIn) {
        $name = [string](Get-NRGObjectField -Item $c -Key 'Name')
        if (-not (Get-NRGObjectField -Item $c -Key 'RequireTls' -Default $false)) {
            $concerns.Add(@{ Connector = $name; Direction = 'Inbound'; Issue = 'Does not require TLS — mail accepted over cleartext.' })
        }
        $ips = @(Get-NRGObjectField -Item $c -Key 'SenderIPAddresses' -Default @())
        $doms = @(Get-NRGObjectField -Item $c -Key 'SenderDomains' -Default @())
        if ($ips.Count -eq 0 -and ($doms -contains '*' -or $doms.Count -eq 0)) {
            $concerns.Add(@{ Connector = $name; Direction = 'Inbound'; Issue = 'Scoped to no sender IP range and no specific sender domain — accepts mail claiming any domain from anywhere.' })
        }
    }
    foreach ($c in $enabledOut) {
        $name = [string](Get-NRGObjectField -Item $c -Key 'Name')
        $tls  = [string](Get-NRGObjectField -Item $c -Key 'TlsSettings')
        if (-not $tls -or $tls -eq 'None') {
            $concerns.Add(@{ Connector = $name; Direction = 'Outbound'; Issue = 'No TLS setting — organizational mail can leave in cleartext.' })
        }
        $rcpt = @(Get-NRGObjectField -Item $c -Key 'RecipientDomains' -Default @())
        if ($rcpt -contains '*') {
            $concerns.Add(@{ Connector = $name; Direction = 'Outbound'; Issue = 'Routes ALL outbound mail (recipient domain *) through a smart host. Verify the smart host is yours.' })
        }
    }

    $summary = "$($enabledIn.Count) inbound, $($enabledOut.Count) outbound connector(s) enabled"
    if ($concerns.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit -CurrentValue $summary `
            -Detail "$summary, each TLS-enforced and scoped. Confirm every one is expected — a connector nobody recognizes is durable persistence that survives a password reset." `
            -AffectedObjects (@($enabledIn + $enabledOut))
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity $ctrl.Severity -FrameworkIds $cit `
            -CurrentValue "$summary; $($concerns.Count) weakening(s)" `
            -RequiredValue 'Every enabled connector TLS-enforced, scoped to known senders/recipients, and recognized' `
            -Detail "$summary. $($concerns.Count) configuration weakening(s) found: $((@($concerns | ForEach-Object { "$($_.Connector) ($($_.Direction)) — $($_.Issue)" }) | Select-Object -First 5) -join ' ')" `
            -Remediation $ctrl.Remediation -AffectedObjects $concerns.ToArray()
    }
}

# ── EXO-8.2 Transport Rules Do Not Redirect Mail Externally ──────────────────
function Test-NRGControlEXOTransportRuleContents {
    [CmdletBinding()] param()
    $cid = 'EXO-8.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO inventory not collected'
        return
    }
    if (-not (Test-NRGSectionCollected $inv 'TransportRules')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Transport rules were not collected; not assessed.'
        return
    }

    $rules  = @(Get-NRGNestedProperty -Object $inv -Path 'Data.TransportRules' -Default @())
    $active = @($rules | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'State') -ne 'Disabled' })

    if ($active.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit -CurrentValue 'No enabled transport rules' `
            -Detail 'No enabled transport rules exist, so none can redirect mail externally.'
        return
    }

    $domains = Get-NRGAcceptedDomainSet
    if ($domains.Count -eq 0) {
        # Without the accepted-domain list every recipient is unclassifiable.
        # Flagging all of them would bury a real finding; claiming none are
        # external would be a false pass. Neither is a verdict.
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail "$($active.Count) enabled transport rule(s) found, but the tenant's accepted-domain list was not collected, so external recipients cannot be identified. Not assessed."
        return
    }

    $flagged   = [System.Collections.Generic.List[object]]::new()
    $unknown   = [System.Collections.Generic.List[object]]::new()
    $scl       = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $active) {
        $name = [string](Get-NRGObjectField -Item $r -Key 'Name')
        foreach ($verb in @('RedirectMessageTo', 'BlindCopyTo', 'CopyTo')) {
            foreach ($rcpt in @(Get-NRGObjectField -Item $r -Key $verb -Default @())) {
                $ext = Test-NRGRecipientIsExternal -Recipient ([string]$rcpt) -AcceptedDomains $domains
                if ($ext -eq $true) {
                    $flagged.Add(@{ Rule = $name; Action = $verb; Recipient = [string]$rcpt })
                } elseif ($null -eq $ext -and $rcpt) {
                    # A display name or DN we cannot resolve to a domain. Named,
                    # not counted as a pass or a failure.
                    $unknown.Add(@{ Rule = $name; Action = $verb; Recipient = [string]$rcpt })
                }
            }
        }
        $s = [string](Get-NRGObjectField -Item $r -Key 'SetSCL')
        if ($s -eq '-1') { $scl.Add(@{ Rule = $name; Issue = 'Sets SCL -1, bypassing spam filtering for matching mail.' }) }
    }

    if ($flagged.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity $ctrl.Severity -FrameworkIds $cit `
            -CurrentValue "$($flagged.Count) rule action(s) redirecting mail to external recipients" `
            -RequiredValue 'No enabled transport rule redirects, blind-copies or copies mail to an external recipient' `
            -Detail "Enabled transport rules send mail outside the tenant: $((@($flagged | ForEach-Object { "$($_.Rule) -> $($_.Recipient) ($($_.Action))" }) | Select-Object -First 5) -join '; '). This is org-wide exfiltration at the transport layer — no mailbox carries a forwarding flag, so the per-mailbox forwarding controls cannot see it." `
            -Remediation $ctrl.Remediation -AffectedObjects $flagged.ToArray()
    } elseif ($unknown.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Medium' -FrameworkIds $cit `
            -CurrentValue "$($active.Count) enabled rules; $($unknown.Count) recipient(s) unresolvable" `
            -RequiredValue 'Every transport-rule recipient resolvable and internal' `
            -Detail "No transport rule redirects to a recognizably external address, but $($unknown.Count) recipient(s) are group or display names that cannot be resolved to a domain from tenant settings alone: $((@($unknown | ForEach-Object { "$($_.Rule) -> $($_.Recipient)" }) | Select-Object -First 5) -join '; '). Confirm each resolves internally." `
            -Remediation $ctrl.Remediation -AffectedObjects $unknown.ToArray()
    } else {
        $note = if ($scl.Count -gt 0) { " Note: $($scl.Count) rule(s) set SCL -1, bypassing spam filtering — verify each is intentional and narrowly scoped." } else { '' }
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -CurrentValue "$($active.Count) enabled rule(s), none redirecting externally" `
            -Detail "No enabled transport rule redirects, blind-copies or copies mail to an external recipient.$note" `
            -AffectedObjects $scl.ToArray()
    }
}

# ── DEF-5.1 Tenant Allow/Block List Reviewed ─────────────────────────────────
function Test-NRGControlDefenderTenantAllowBlockList {
    [CmdletBinding()] param()
    $cid = 'DEF-5.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $inv = Get-NRGRawData -Key 'EXO-Inventory'
    if (-not $inv -or -not $inv.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO inventory not collected'
        return
    }
    if (-not (Test-NRGSectionCollected $inv 'TenantAllowBlockList')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Tenant Allow/Block List was not collected; not assessed.'
        return
    }

    $items  = @(Get-NRGNestedProperty -Object $inv -Path 'Data.TenantAllowBlockList' -Default @())
    $allows = @($items | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Action') -eq 'Allow' })

    if ($allows.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -CurrentValue "$($items.Count) list entries, no allow entries" `
            -Detail 'No allow entries in the Tenant Allow/Block List. Nothing is overriding a filtering verdict.'
        return
    }

    # A permanent allow is the one that matters. A time-boxed allow expires on
    # its own; a never-expiring one is a filtering bypass that outlives whoever
    # added it and the incident that justified it.
    $permanent = @($allows | Where-Object {
        [bool](Get-NRGObjectField -Item $_ -Key 'NoExpiration' -Default $false) -or
        -not [string](Get-NRGObjectField -Item $_ -Key 'ExpirationDate')
    })

    if ($permanent.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity $ctrl.Severity -FrameworkIds $cit `
            -CurrentValue "$($permanent.Count) never-expiring allow entr(ies) of $($allows.Count) total" `
            -RequiredValue 'Every allow entry time-boxed with a documented reason' `
            -Detail "Never-expiring allow entries override filtering indefinitely: $((@($permanent | ForEach-Object { "$($_.ListType) $($_.Value)" }) | Select-Object -First 5) -join '; '). An allow added to unblock a sender during an incident outlives the incident, and mail from that sender is never filtered again." `
            -Remediation $ctrl.Remediation -AffectedObjects $permanent.ToArray()
    } else {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title `
            -Severity 'Informational' -FrameworkIds $cit `
            -CurrentValue "$($allows.Count) allow entr(ies), all time-boxed" `
            -Detail "All $($allows.Count) allow entries carry an expiry date, so no filtering bypass is permanent." `
            -AffectedObjects $allows
    }
}

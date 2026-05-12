#
# Test-NRGControlDefender.ps1
# Evaluates Microsoft Defender for Office 365 policy controls.
#
# Controls:
#   DEF-1.1  Anti-phishing policy with impersonation protection
#   DEF-1.2  Safe Attachments policy with Block action
#   DEF-1.3  Safe Links policy enabled tenant-wide
#
# Reads from module state:
#   Get-NRGRawData -Key 'Defender'
#
# NIST SP 800-53: SI-3, SI-4, SI-8
# MITRE ATT&CK:   T1566 (Phishing), T1204.002 (Malicious File), T1189 (Drive-by Compromise)
#

function Test-NRGControlDefender {
    [CmdletBinding()] param()

    $raw = Get-NRGRawData -Key 'Defender'

    if (-not $raw -or -not $raw.Success) {
        $detail = if ($raw) { "Collector failed: $($raw.Exceptions -join '; ')" } else { 'Defender collector did not run.' }
        foreach ($id in @('DEF-1.1','DEF-1.2','DEF-1.3')) {
            $ctrl = Get-NRGControlById -ControlId $id
            Add-NRGFinding -ControlId $id -State 'NotApplicable' `
                -Category ($ctrl.Category) -Title ($ctrl.Title) -Detail $detail
        }
        return
    }

    #--------------------------------------------------------------------------
    # DEF-1.1  Anti-phishing policy with impersonation protection
    # SI-4 | T1566.001 (Spearphishing Attachment)
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'DEF-1.1'

    if (-not $raw.Data['AntiPhishing'].Available) {
        Add-NRGFinding -ControlId 'DEF-1.1' -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail "Anti-phishing cmdlets unavailable. Requires Defender for Office 365 Plan 1+. Error: $($raw.Exceptions | Where-Object { $_ -like 'AntiPhishing*' })"
    }
    else {
        $apPolicies = @($raw.Data['AntiPhishing'].Policies)
        $apRules    = @($raw.Data['AntiPhishing'].Rules)

        $strongPolicies = @($apPolicies | Where-Object {
            (-not $_.IsDefault -or $apPolicies.Count -eq 1) -and
            $_.EnableMailboxIntelligence -eq $true -and
            ($_.EnableOrganizationDomainsProtection -eq $true -or
             $_.EnableMailboxIntelligenceProtection -eq $true)
        })

        $activePolicyNames = @($apRules | Where-Object { $_.State -eq 'Enabled' } |
            Select-Object -ExpandProperty AntiPhishPolicy)

        $enforcedStrongPolicies = @($strongPolicies | Where-Object {
            $_.Name -in $activePolicyNames -or $_.IsDefault
        })

        if ($enforcedStrongPolicies.Count -gt 0) {
            $policyName = $enforcedStrongPolicies[0].Name
            $threshold  = $enforcedStrongPolicies[0].PhishThresholdLevel
            Add-NRGFinding -ControlId 'DEF-1.1' -State 'Satisfied' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
                -Detail 'Anti-phishing policy with impersonation protection active.' `
                -CurrentValue "Policy: '$policyName' | Mailbox intelligence: enabled | PhishThreshold: $threshold" `
                -RequiredValue 'Non-default policy with mailbox intelligence and domain impersonation enabled' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'DEF-1.1')
        }
        elseif ($strongPolicies.Count -gt 0) {
            $policyName = $strongPolicies[0].Name
            Add-NRGFinding -ControlId 'DEF-1.1' -State 'Partial' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'High' `
                -Detail 'Anti-phishing policy with impersonation protection exists but has no active rule applying it to recipients.' `
                -CurrentValue "Policy '$policyName' configured but no enabled rule targets recipients" `
                -RequiredValue 'Policy + active rule covering all accepted domains or all recipients' `
                -Remediation 'Create an anti-phishing rule: New-AntiPhishRule -AntiPhishPolicy [name] -RecipientDomainIs [domain] -Priority 0. Or use the Security portal.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'DEF-1.1')
        }
        else {
            $defaultPolicy  = $apPolicies | Where-Object { $_.IsDefault }
            $miEnabled      = if ($defaultPolicy) { "$($defaultPolicy.EnableMailboxIntelligence)" } else { 'N/A' }
            $orgDomEnabled  = if ($defaultPolicy) { "$($defaultPolicy.EnableOrganizationDomainsProtection)" } else { 'N/A' }
            Add-NRGFinding -ControlId 'DEF-1.1' -State 'Gap' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'No anti-phishing policy with impersonation protection found. Default policy lacks user/domain impersonation controls.' `
                -CurrentValue "Default policy only. Mailbox intelligence: $miEnabled. Org domain protection: $orgDomEnabled" `
                -RequiredValue 'Custom anti-phishing policy: EnableMailboxIntelligence, EnableOrganizationDomainsProtection, EnableMailboxIntelligenceProtection all True' `
                -Remediation $ctrl.Remediation `
                -RemediationLink $ctrl.RemediationLink `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'DEF-1.1')
        }
    }

    #--------------------------------------------------------------------------
    # DEF-1.2  Safe Attachments policy with Block action
    # SI-3 | T1204.002 (Malicious File)
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'DEF-1.2'

    if (-not $raw.Data['SafeAttachments'].Available) {
        Add-NRGFinding -ControlId 'DEF-1.2' -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail "Safe Attachments cmdlets unavailable. Requires Defender for Office 365 Plan 1+. Error: $($raw.Exceptions | Where-Object { $_ -like 'SafeAttachments*' })"
    }
    else {
        $saPolicies = @($raw.Data['SafeAttachments'].Policies)
        $saRules    = @($raw.Data['SafeAttachments'].Rules)

        $blockPolicies = @($saPolicies | Where-Object {
            $_.Enable -eq $true -and
            ($_.Action -eq 'Block' -or $_.Action -eq 'Replace') -and
            -not $_.IsDefault
        })

        $activeRuleNames = @($saRules | Where-Object { $_.State -eq 'Enabled' } |
            Select-Object -ExpandProperty SafeAttachmentPolicy)

        $enforcedBlock = @($blockPolicies | Where-Object { $_.Name -in $activeRuleNames })

        if ($enforcedBlock.Count -gt 0) {
            $p = $enforcedBlock[0]
            Add-NRGFinding -ControlId 'DEF-1.2' -State 'Satisfied' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
                -Detail 'Safe Attachments Block policy active and applied to recipients.' `
                -CurrentValue "Policy: '$($p.Name)' | Action: $($p.Action) | Enabled: $($p.Enable)" `
                -RequiredValue 'Enabled Safe Attachments policy with Action=Block and active rule' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'DEF-1.2')
        }
        elseif ($blockPolicies.Count -gt 0) {
            Add-NRGFinding -ControlId 'DEF-1.2' -State 'Partial' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'High' `
                -Detail 'Safe Attachments Block policy exists but has no active rule applying it to recipients.' `
                -CurrentValue "Policy '$($blockPolicies[0].Name)' Action=$($blockPolicies[0].Action) configured but no enabled rule" `
                -RequiredValue 'Safe Attachments Block policy + active rule covering all recipients' `
                -Remediation 'Create rule: New-SafeAttachmentRule -SafeAttachmentPolicy [name] -RecipientDomainIs [domain] -Priority 0' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'DEF-1.2')
        }
        else {
            $dynamicPolicies = @($saPolicies | Where-Object {
                $_.Enable -eq $true -and $_.Action -eq 'DynamicDelivery' -and -not $_.IsDefault
            })
            if ($dynamicPolicies.Count -gt 0) {
                Add-NRGFinding -ControlId 'DEF-1.2' -State 'Partial' `
                    -Category $ctrl.Category -Title $ctrl.Title -Severity 'High' `
                    -Detail 'Safe Attachments using DynamicDelivery (not Block). DynamicDelivery delivers message body while scanning — malicious attachments may reach users before scan completes.' `
                    -CurrentValue "Action: DynamicDelivery on $($dynamicPolicies.Count) policy(ies)" `
                    -RequiredValue 'Action: Block — holds entire message until scan completes' `
                    -Remediation 'Change policy Action to Block. DynamicDelivery is acceptable for high-volume environments but Block provides stronger protection.' `
                    -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'DEF-1.2')
            }
            else {
                Add-NRGFinding -ControlId 'DEF-1.2' -State 'Gap' `
                    -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
                    -Detail 'No enabled Safe Attachments policy with Block action found. Malicious attachments are delivered without sandbox detonation.' `
                    -CurrentValue 'No active Safe Attachments Block policy' `
                    -RequiredValue 'Custom Safe Attachments policy: Enable=True, Action=Block, applied to all recipients' `
                    -Remediation $ctrl.Remediation `
                    -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'DEF-1.2')
            }
        }
    }

    #--------------------------------------------------------------------------
    # DEF-1.3  Safe Links policy enabled tenant-wide
    # SI-3 | T1189 (Drive-by Compromise)
    # FIX: pre-compute conditional values — inline 'if' is not valid PS5.1
    #      parameter syntax and causes "term 'if' is not recognized" error
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'DEF-1.3'

    if (-not $raw.Data['SafeLinks'].Available) {
        Add-NRGFinding -ControlId 'DEF-1.3' -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail "Safe Links cmdlets unavailable. Requires Defender for Office 365 Plan 1+. Error: $($raw.Exceptions | Where-Object { $_ -like 'SafeLinks*' })"
    }
    else {
        $slPolicies = @($raw.Data['SafeLinks'].Policies)
        $slRules    = @($raw.Data['SafeLinks'].Rules)

        $strongPolicies = @($slPolicies | Where-Object {
            $_.EnableSafeLinksForEmail -eq $true -and
            $_.ScanUrls -eq $true -and
            -not $_.IsDefault
        })

        $activeRuleNames = @($slRules | Where-Object { $_.State -eq 'Enabled' } |
            Select-Object -ExpandProperty SafeLinksPolicy)

        $enforcedStrong = @($strongPolicies | Where-Object { $_.Name -in $activeRuleNames })

        if ($enforcedStrong.Count -gt 0) {
            $p = $enforcedStrong[0]

            # Pre-compute all conditional values — inline if() is not valid PS5.1 parameter syntax
            $clickThrough     = if ($p.AllowClickThrough -eq $false) { 'blocked' } else { 'ALLOWED (gap)' }
            $internalScan     = if ($p.EnableForInternalSenders -eq $true) { 'enabled' } else { 'disabled' }
            $teamsScan        = if ($p.EnableSafeLinksForTeams -eq $true) { 'enabled' } else { 'disabled' }
            $slState          = if ($p.AllowClickThrough -eq $false) { 'Satisfied' } else { 'Partial' }
            $slSeverity       = if ($slState -eq 'Satisfied') { 'Informational' } else { 'High' }
            $slDetail         = if ($slState -eq 'Satisfied') {
                'Safe Links enabled with URL scanning, click-through blocked.'
            } else {
                "Safe Links enabled but AllowClickThrough=True — users can bypass Safe Links warnings and reach malicious URLs."
            }
            $slRemediation    = if ($slState -eq 'Partial') {
                'Set AllowClickThrough=$false on the Safe Links policy to prevent users bypassing URL block warnings.'
            } else { $null }

            Add-NRGFinding -ControlId 'DEF-1.3' -State $slState `
                -Category $ctrl.Category -Title $ctrl.Title `
                -Severity $slSeverity `
                -Detail $slDetail `
                -CurrentValue "Policy: '$($p.Name)' | ScanUrls: $($p.ScanUrls) | ClickThrough: $clickThrough | InternalSenders: $internalScan | Teams: $teamsScan" `
                -RequiredValue 'ScanUrls=True, AllowClickThrough=False, EnableForInternalSenders=True, applied to all recipients' `
                -Remediation $slRemediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'DEF-1.3')
        }
        elseif ($strongPolicies.Count -gt 0) {
            Add-NRGFinding -ControlId 'DEF-1.3' -State 'Partial' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'High' `
                -Detail 'Safe Links policy configured but no active rule applies it to recipients.' `
                -CurrentValue "Policy '$($strongPolicies[0].Name)' configured, no enabled rule found" `
                -RequiredValue 'Safe Links policy + active rule covering all recipients' `
                -Remediation 'Create rule: New-SafeLinksRule -SafeLinksPolicy [name] -RecipientDomainIs [domain] -Priority 0' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'DEF-1.3')
        }
        else {
            Add-NRGFinding -ControlId 'DEF-1.3' -State 'Gap' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'No enabled Safe Links policy with URL scanning found. Time-of-click URL protection is not active.' `
                -CurrentValue 'No active Safe Links policy with ScanUrls=True' `
                -RequiredValue 'Custom Safe Links policy: EnableSafeLinksForEmail=True, ScanUrls=True, AllowClickThrough=False, active rule applied' `
                -Remediation $ctrl.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'DEF-1.3')
        }
    }
}

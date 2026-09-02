#Requires -Version 7.0
#
# Test-NRGControlDefender.ps1  (v4.5.5)
# Evaluates Defender for Office 365 controls.
# SCORING ONLY — no API calls.
#
# NIST SP 800-53: SI-3, SI-4, SI-8
# MITRE ATT&CK:   T1566, T1204.002
#

function Test-NRGControlDefender {
    [CmdletBinding()] param()

    $defData = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $defData -or -not $defData.Success) {
        # Register NotApplicable for all Defender controls
        foreach ($cid in @('DEF-1.1','DEF-1.2','DEF-1.3','DEF-1.4','DEF-1.5','DEF-1.6')) {
            $ctrl = Get-NRGControlById -ControlId $cid
            if ($ctrl) {
                Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
                    -Title $ctrl.Title -Detail 'Defender policy data not collected'
            }
        }
        return
    }

    # ── DEF-1.1 Safe Attachments Enabled ─────────────────────────────────
    $ctrl = Get-NRGControlById -ControlId 'DEF-1.1'
    if ($ctrl) {
        $citations = Get-NRGFrameworkCitations -ControlId 'DEF-1.1'
        $sa = $defData.Data['SafeAttachments']

        if (-not $sa -or -not $sa.Available) {
            # "Unavailable" is ambiguous: either the tenant lacks Defender for
            # Office 365 P1 (Safe Attachments literally cannot exist — an upgrade
            # opportunity, NOT a misconfiguration) or the read failed on a
            # licensed tenant (a real collection problem). Decide honestly from
            # the license profile instead of asserting a confident High gap.
            $lic = Get-NRGControlLicenseStatus -ControlId 'DEF-1.1'
            if ($lic -eq 'Met') {
                $why = if ($sa -and $sa.Error) { "Collector error: $($sa.Error)" } else { 'No policy data returned.' }
                Add-NRGFinding -ControlId 'DEF-1.1' -State 'Error' -Category $ctrl.Category `
                    -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $citations `
                    -Detail "Safe Attachments could not be collected even though the tenant is licensed for Defender for Office 365 Plan 1. $why Re-run collection and verify Exchange Online / Defender connectivity." `
                    -CurrentValue 'Collection failed' -Remediation $ctrl.Remediation
            } else {
                Add-NRGFinding -ControlId 'DEF-1.1' -State 'NotApplicable' -Category $ctrl.Category `
                    -Title $ctrl.Title -FrameworkIds $citations `
                    -Detail 'Safe Attachments requires Defender for Office 365 Plan 1, which is not part of this tenant''s licensing. Not scored as a gap — surfaced as a licensing upgrade opportunity.' `
                    -CurrentValue 'Defender for Office 365 P1 not licensed' `
                    -RequiredValue 'Defender for Office 365 Plan 1' -Remediation $ctrl.Remediation
            }
        } elseif ($sa.AnyBlockEnabled) {
            Add-NRGFinding -ControlId 'DEF-1.1' -State 'Satisfied' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $citations `
                -Detail "Safe Attachments configured with Block action on $($sa.BlockActionCount) policy(ies)."
        } elseif ($sa.EnabledNonDefaultCount -gt 0) {
            Add-NRGFinding -ControlId 'DEF-1.1' -State 'Partial' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $citations `
                -Detail "Safe Attachments enabled but action is not 'Block' on any policy (Dynamic Delivery or Monitor only)." `
                -CurrentValue 'No Block action policies' -RequiredValue "Safe Attachments with Action = 'Block'"
        } else {
            Add-NRGFinding -ControlId 'DEF-1.1' -State 'Gap' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $citations `
                -Detail 'No Safe Attachments policies are enabled. Malicious attachments are not sandboxed.' `
                -Remediation $ctrl.Remediation
        }
    }

    # ── DEF-1.2 Safe Links Enabled for Email ─────────────────────────────
    $ctrl = Get-NRGControlById -ControlId 'DEF-1.2'
    if ($ctrl) {
        $citations = Get-NRGFrameworkCitations -ControlId 'DEF-1.2'
        $sl = $defData.Data['SafeLinks']

        if (-not $sl -or -not $sl.Available) {
            # Same license-vs-collection disambiguation as DEF-1.1.
            $lic = Get-NRGControlLicenseStatus -ControlId 'DEF-1.2'
            if ($lic -eq 'Met') {
                $why = if ($sl -and $sl.Error) { "Collector error: $($sl.Error)" } else { 'No policy data returned.' }
                Add-NRGFinding -ControlId 'DEF-1.2' -State 'Error' -Category $ctrl.Category `
                    -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $citations `
                    -Detail "Safe Links could not be collected even though the tenant is licensed for Defender for Office 365 Plan 1. $why Re-run collection and verify Exchange Online / Defender connectivity." `
                    -CurrentValue 'Collection failed' -Remediation $ctrl.Remediation
            } else {
                Add-NRGFinding -ControlId 'DEF-1.2' -State 'NotApplicable' -Category $ctrl.Category `
                    -Title $ctrl.Title -FrameworkIds $citations `
                    -Detail 'Safe Links requires Defender for Office 365 Plan 1, which is not part of this tenant''s licensing. Not scored as a gap — surfaced as a licensing upgrade opportunity.' `
                    -CurrentValue 'Defender for Office 365 P1 not licensed' `
                    -RequiredValue 'Defender for Office 365 Plan 1' -Remediation $ctrl.Remediation
            }
        } elseif ($sl.EnabledNonDefaultCount -gt 0) {
            $defaultPol = @($sl.Policies | Where-Object { $_.IsDefault }) | Select-Object -First 1
            $gaps = @()
            if ($defaultPol) {
                if ($defaultPol.AllowClickThrough)        { $gaps += 'AllowClickThrough=True' }
                if (-not $defaultPol.TrackClicks)         { $gaps += 'TrackClicks=False' }
                if (-not $defaultPol.EnableForInternalSenders) { $gaps += 'InternalSenders=False' }
                if ($defaultPol.DisableUrlRewrite)        { $gaps += 'UrlRewrite=Disabled' }
            }

            if ($gaps.Count -eq 0) {
                Add-NRGFinding -ControlId 'DEF-1.2' -State 'Satisfied' -Category $ctrl.Category `
                    -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $citations `
                    -Detail 'Safe Links enabled for email with hardened settings (click-through blocked, tracking enabled, internal senders covered).'
            } else {
                Add-NRGFinding -ControlId 'DEF-1.2' -State 'Partial' -Category $ctrl.Category `
                    -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $citations `
                    -Detail "Safe Links enabled but hardening gaps: $($gaps -join ', ')" `
                    -CurrentValue "Issues: $($gaps -join ', ')" `
                    -RequiredValue 'AllowClickThrough=False, TrackClicks=True, InternalSenders=True'
            }
        } else {
            Add-NRGFinding -ControlId 'DEF-1.2' -State 'Gap' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $citations `
                -Detail 'No Safe Links policies are enabled for email. URLs are not scanned or rewritten.' `
                -Remediation $ctrl.Remediation
        }
    }

    # ── DEF-1.3 Spoof Intelligence Enabled ───────────────────────────────
    $ctrl = Get-NRGControlById -ControlId 'DEF-1.3'
    if ($ctrl) {
        $citations = Get-NRGFrameworkCitations -ControlId 'DEF-1.3'
        $ap = $defData.Data['AntiPhishing']
        $defaultPol = if ($ap -and $ap.Available) {
            @($ap.Policies | Where-Object { $_.IsDefault }) | Select-Object -First 1
        } else { $null }

        if (-not $defaultPol) {
            Add-NRGFinding -ControlId 'DEF-1.3' -State 'NotApplicable' -Category $ctrl.Category `
                -Title $ctrl.Title -Detail 'Anti-phishing data not available'
        } elseif ($defaultPol.EnableSpoofIntelligence) {
            Add-NRGFinding -ControlId 'DEF-1.3' -State 'Satisfied' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $citations `
                -Detail 'Spoof intelligence enabled — spoofed senders are evaluated and flagged.'
        } else {
            Add-NRGFinding -ControlId 'DEF-1.3' -State 'Gap' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $citations `
                -Detail 'Spoof intelligence is DISABLED. Spoofed senders pass without evaluation — increases phishing delivery risk.' `
                -CurrentValue 'EnableSpoofIntelligence = $false' `
                -RequiredValue 'Set-AntiPhishPolicy -EnableSpoofIntelligence $true' `
                -Remediation $ctrl.Remediation
        }
    }

    # ── DEF-1.4 Honor DMARC Policy ───────────────────────────────────────
    $ctrl = Get-NRGControlById -ControlId 'DEF-1.4'
    if ($ctrl) {
        $citations = Get-NRGFrameworkCitations -ControlId 'DEF-1.4'
        $ap = $defData.Data['AntiPhishing']
        $defaultPol = if ($ap -and $ap.Available) {
            @($ap.Policies | Where-Object { $_.IsDefault }) | Select-Object -First 1
        } else { $null }

        if (-not $defaultPol) {
            Add-NRGFinding -ControlId 'DEF-1.4' -State 'NotApplicable' -Category $ctrl.Category `
                -Title $ctrl.Title -Detail 'Anti-phishing data not available'
        } elseif ($defaultPol.HonorDmarcPolicy) {
            Add-NRGFinding -ControlId 'DEF-1.4' -State 'Satisfied' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $citations `
                -Detail 'EOP honors sending domain DMARC policy. p=reject/quarantine actions are applied on inbound mail.'
        } else {
            Add-NRGFinding -ControlId 'DEF-1.4' -State 'Gap' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity 'High' -FrameworkIds $citations `
                -Detail 'EOP does NOT honor DMARC policy. Messages from p=reject domains may still be delivered — undermines the entire DMARC ecosystem.' `
                -CurrentValue 'HonorDmarcPolicy = $false' `
                -RequiredValue 'Set-AntiPhishPolicy -Identity Default -HonorDmarcPolicy $true' `
                -Remediation $ctrl.Remediation
        }
    }

    # ── DEF-1.5 Phish Threshold Level ────────────────────────────────────
    $ctrl = Get-NRGControlById -ControlId 'DEF-1.5'
    if ($ctrl) {
        $citations = Get-NRGFrameworkCitations -ControlId 'DEF-1.5'
        $ap = $defData.Data['AntiPhishing']
        $defaultPol = if ($ap -and $ap.Available) {
            @($ap.Policies | Where-Object { $_.IsDefault }) | Select-Object -First 1
        } else { $null }

        if (-not $defaultPol) {
            Add-NRGFinding -ControlId 'DEF-1.5' -State 'NotApplicable' -Category $ctrl.Category `
                -Title $ctrl.Title -Detail 'Anti-phishing data not available'
        } else {
            $threshold = $defaultPol.PhishThresholdLevel ?? 1
            if ($threshold -ge 2) {
                Add-NRGFinding -ControlId 'DEF-1.5' -State 'Satisfied' -Category $ctrl.Category `
                    -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $citations `
                    -Detail "Phish threshold level set to $threshold (Aggressive or higher). Catches more sophisticated phishing attempts."
            } else {
                Add-NRGFinding -ControlId 'DEF-1.5' -State 'Partial' -Category $ctrl.Category `
                    -Title $ctrl.Title -Severity 'Low' -FrameworkIds $citations `
                    -Detail "Phish threshold level is $threshold (Standard). CIS M365 and CISA SCuBA recommend level 2 (Aggressive) or higher." `
                    -CurrentValue "PhishThresholdLevel = $threshold" -RequiredValue 'PhishThresholdLevel ≥ 2'
            }
        }
    }

    # ── DEF-1.6 First Contact Safety Tip ────────────────────────────────
    $ctrl = Get-NRGControlById -ControlId 'DEF-1.6'
    if ($ctrl) {
        $citations = Get-NRGFrameworkCitations -ControlId 'DEF-1.6'
        $ap = $defData.Data['AntiPhishing']
        $defaultPol = if ($ap -and $ap.Available) {
            @($ap.Policies | Where-Object { $_.IsDefault }) | Select-Object -First 1
        } else { $null }

        if (-not $defaultPol) {
            Add-NRGFinding -ControlId 'DEF-1.6' -State 'NotApplicable' -Category $ctrl.Category `
                -Title $ctrl.Title -Detail 'Anti-phishing data not available'
        } elseif ($defaultPol.EnableFirstContactSafetyTips) {
            Add-NRGFinding -ControlId 'DEF-1.6' -State 'Satisfied' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $citations `
                -Detail 'First contact safety tip enabled — users see a warning banner when receiving email from a new sender.'
        } else {
            Add-NRGFinding -ControlId 'DEF-1.6' -State 'Gap' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity 'Low' -FrameworkIds $citations `
                -Detail 'First contact safety tip disabled. Users receive no visual warning for first-time senders — increases social engineering risk.' `
                -CurrentValue 'EnableFirstContactSafetyTips = $false' `
                -RequiredValue 'Set-AntiPhishPolicy -EnableFirstContactSafetyTips $true' `
                -Remediation $ctrl.Remediation
        }
    }
}

# ── DEF-2.1 Preset Security Policies Applied ─────────────────────────────────
function Test-NRGControlDefenderPresetPolicies {
    [CmdletBinding()] param()
    $cid = 'DEF-2.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $def 'AntiPhishing')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AntiPhishing was not collected; not assessed.'
        return
    }
    # Preset policies appear as built-in named policies: Standard Preset / Strict Preset.
    # v4.11.1: dropped unused $sl/$sa reads (left over from a refactor that
    # moved Safe Links / Safe Attachments to their own evaluators).
    $ap = $def.Data['AntiPhishing']
    $presetActive = $false
    if ($ap -and $ap.Available) {
        $presetActive = @($ap.Policies | Where-Object { $_.Name -match 'Standard|Strict|Preset' }).Count -gt 0
    }
    if ($presetActive) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Standard or Strict preset security policy is active in this tenant.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'No preset security policies detected. Custom policies are in use — verify all Defender settings are explicitly configured.' -CurrentValue 'Custom policies only' -RequiredValue 'Standard or Strict preset applied'
    }
}

# ── DEF-2.2 Anti-Malware ZAP Enabled ─────────────────────────────────────────
function Test-NRGControlDefenderZAP {
    [CmdletBinding()] param()
    $cid = 'DEF-2.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    $defaultPolicy = @($exo.Data['AntiSpamPolicies'] | Where-Object { $_.IsDefault }) | Select-Object -First 1
    if (-not $defaultPolicy) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No default anti-spam policy found'; return
    }
    if ($defaultPolicy.ZapEnabled -eq $true) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Zero-hour auto purge (ZAP) is enabled. Malicious mail delivered before detection is retroactively removed.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'ZAP is disabled. Malware or phishing delivered before detection is NOT retroactively removed from user mailboxes.' -CurrentValue 'ZapEnabled = $false' -RequiredValue 'Set-HostedContentFilterPolicy -Identity Default -SpamZapEnabled $true -PhishZapEnabled $true' -Remediation $ctrl.Remediation
    }
}

# ── DEF-2.3 Anti-Malware Common Attachments Blocked ─────────────────────────
function Test-NRGControlDefenderCommonAttachments {
    [CmdletBinding()] param()
    $cid = 'DEF-2.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    $mf = $def.Data['MalwareFilter']
    if (-not $mf -or -not $mf.Available) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Malware filter data not available'; return
    }
    if ($mf.FileFilterEnabledCount -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Common attachment filter enabled on $($mf.FileFilterEnabledCount) malware policy(ies). High-risk file types blocked regardless of content scan."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Common attachments filter is disabled. High-risk file types (.exe, .js, .vbs, etc.) are not blocked at the mail gateway.' -Remediation $ctrl.Remediation
    }
}

# ── DEF-2.4 Quarantine Policy Admin Managed ──────────────────────────────────
function Test-NRGControlDefenderQuarantine {
    [CmdletBinding()] param()
    $cid = 'DEF-2.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    # High confidence phish should go to quarantine, not junk
    $defaultPolicy = @($exo.Data['AntiSpamPolicies'] | Where-Object { $_.IsDefault }) | Select-Object -First 1
    if (-not $defaultPolicy) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No default spam policy found'; return
    }
    $hcPhishAction = [string]($defaultPolicy.PhishSpamAction ?? 'MoveToJmf')
    if ($hcPhishAction -eq 'Quarantine') {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Phishing is directed to quarantine — users cannot self-release phishing attempts.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Phishing action is '$hcPhishAction' — phishing delivered to junk folder where users can click links." -CurrentValue "PhishSpamAction = $hcPhishAction" -RequiredValue 'PhishSpamAction = Quarantine' -Remediation $ctrl.Remediation
    }
}

# ── DEF-2.5 High Confidence Spam to Quarantine ──────────────────────────────
function Test-NRGControlDefenderHCSpam {
    [CmdletBinding()] param()
    $cid = 'DEF-2.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    $defaultPolicy = @($exo.Data['AntiSpamPolicies'] | Where-Object { $_.IsDefault }) | Select-Object -First 1
    if (-not $defaultPolicy) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No default policy found'; return }
    $hcAction = [string]($defaultPolicy.HighConfidenceSpamAction ?? 'MoveToJmf')
    if ($hcAction -eq 'Quarantine') {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'High confidence spam directed to quarantine.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "High confidence spam action is '$hcAction'. Should be Quarantine to prevent user interaction with confirmed spam." -CurrentValue "HighConfidenceSpamAction = $hcAction" -RequiredValue 'Quarantine' -Remediation $ctrl.Remediation
    }
}

# ── DEF-2.6 Bulk Mail Threshold Configured ──────────────────────────────────
function Test-NRGControlDefenderBulkThreshold {
    [CmdletBinding()] param()
    $cid = 'DEF-2.6'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $exo = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EXO data not collected'; return
    }
    $defaultPolicy = @($exo.Data['AntiSpamPolicies'] | Where-Object { $_.IsDefault }) | Select-Object -First 1
    if (-not $defaultPolicy) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No default policy found'; return }
    $threshold = $defaultPolicy.BulkThreshold ?? 7
    if ($threshold -le 6) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Bulk complaint threshold set to $threshold (aggressive)."
    } elseif ($threshold -le 7) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "Bulk threshold is $threshold (default). CIS recommends ≤6 for better bulk mail filtering." -CurrentValue "BulkThreshold = $threshold" -RequiredValue '≤6'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Bulk threshold is $threshold — too permissive, significant bulk mail reaches inboxes." -Remediation $ctrl.Remediation
    }
}

# ── DEF-3.1 Unauthenticated Sender Indicator ─────────────────────────────────
function Test-NRGControlDefenderUnauthSender {
    [CmdletBinding()] param()
    $cid = 'DEF-3.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    $ap  = $def.Data['AntiPhishing']
    $pol = if ($ap -and $ap.Available) { @($ap.Policies | Where-Object { $_.IsDefault }) | Select-Object -First 1 } else { $null }
    if (-not $pol) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No default anti-phishing policy'; return }
    if ($pol.EnableUnauthenticatedSender -eq $true) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Unauthenticated sender indicator enabled — Outlook shows ? on unverified sender photos.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Unauthenticated sender indicator disabled. Users receive no visual warning that a sender cannot be authenticated.' `
            -CurrentValue 'EnableUnauthenticatedSender = $false' `
            -RequiredValue 'Set-AntiPhishPolicy -EnableUnauthenticatedSender $true' -Remediation $ctrl.Remediation
    }
}

# ── DEF-3.2 Via Tag Enabled ──────────────────────────────────────────────────
function Test-NRGControlDefenderViaTag {
    [CmdletBinding()] param()
    $cid = 'DEF-3.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    $ap  = $def.Data['AntiPhishing']
    $pol = if ($ap -and $ap.Available) { @($ap.Policies | Where-Object { $_.IsDefault }) | Select-Object -First 1 } else { $null }
    if (-not $pol) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No default anti-phishing policy'; return }
    if ($pol.EnableViaTag -eq $true) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Via tag enabled — Outlook shows the sending service in From address when sender uses a relay.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Via tag disabled. Users cannot see when email is sent through a relay service on behalf of a domain.' `
            -CurrentValue 'EnableViaTag = $false' `
            -RequiredValue 'Set-AntiPhishPolicy -EnableViaTag $true' -Remediation $ctrl.Remediation
    }
}

# ── DEF-3.3 Defender for Cloud Apps Connected ────────────────────────────────
function Test-NRGControlDefenderMDCA {
    [CmdletBinding()] param()
    $cid = 'DEF-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    # MDCA connection status requires a dedicated collector that doesn't exist
    # yet. v4.11.1: removed the unused $ca proxy read — the finding is
    # ADVISORY-ONLY (manual review) so no data dependency is needed.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Medium' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — Defender for Cloud Apps connection state is not exposed to the APIs this assessment uses. Confirm in Defender XDR > Settings > Cloud Apps > Connected apps that the Microsoft 365 connector is active.' `
        -Remediation $ctrl.Remediation
}

# ── DEF-3.4 Defender Alerts Email Notification ──────────────────────────────
function Test-NRGControlDefenderAlertNotification {
    [CmdletBinding()] param()
    $cid = 'DEF-3.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    # v4.13.0: implemented. Reads alert POLICY configuration from
    # Get-ProtectionAlert (collected into Purview.ProtectionAlerts), which is a
    # different question from EXO-ConnectionFilter's /security/alerts_v2 feed:
    # that lists alerts which have fired, this asks whether anyone is configured
    # to be told when they do. An enabled policy with an empty NotifyUser raises
    # an alert into an empty room.
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Purview data not collected'
        return
    }

    $status = Get-NRGNestedProperty -Object $pvw -Path 'Data.SectionStatus.ProtectionAlerts' -Default $null
    if ($status -ne 'Collected') {
        $why = if ($status -eq 'Failed') {
            'the Get-ProtectionAlert query failed (see Exceptions)'
        } else {
            'Get-ProtectionAlert was unavailable — this requires a Security & Compliance (IPPS) session'
        }
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail "Alert policy configuration could not be read: $why. Alert notification state was not assessed."
        return
    }

    $policies = @($pvw.Data['ProtectionAlerts'] ?? @())
    if ($policies.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No alert policies are configured. Nothing in the tenant will raise a security alert, so a compromise produces no notification to anyone.' `
            -CurrentValue 'Zero alert policies' -RequiredValue 'High and Critical alert policies enabled with email recipients' `
            -Remediation $ctrl.Remediation
        return
    }

    $enabled = @($policies | Where-Object { -not $_.Disabled })
    $high    = @($enabled  | Where-Object { $_.Severity -in @('High','Critical') })
    $silent  = @($high     | Where-Object { @($_.NotifyUser).Count -eq 0 })

    if ($high.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($enabled.Count) alert policy(ies) are enabled but none are High or Critical severity, so the most serious events do not raise a prioritised alert." `
            -CurrentValue "$($enabled.Count) enabled policies, 0 at High/Critical" `
            -RequiredValue 'High and Critical alert policies enabled with email recipients' `
            -Remediation $ctrl.Remediation
        return
    }

    if ($silent.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "All $($high.Count) enabled High/Critical alert policy(ies) have email recipients configured."
    } else {
        $affected = @($silent | ForEach-Object {
            [ordered]@{
                DisplayName = [string]$_.Name
                Severity    = [string]$_.Severity
                Recipients  = 'none configured'
            }
        })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($silent.Count) of $($high.Count) enabled High/Critical alert policy(ies) have no email recipients. These alerts fire into the portal where nobody is watching — during an incident the tenant is generating exactly the signal that is needed and delivering it to no one." `
            -CurrentValue "$($silent.Count) High/Critical policies with no recipients" `
            -RequiredValue 'Every enabled High/Critical alert policy has at least one notification recipient' `
            -Remediation $ctrl.Remediation -AffectedObjects $affected
    }
}

function Test-NRGControlDefenderDLPWorkloads {
    [CmdletBinding()] param()
    $cid = 'DEF-4.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview DLP data not collected'; return
    }
    $dlpPolicies = @($pvw.Data['DLPPolicies'] ?? @())
    if ($dlpPolicies.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No DLP policies configured. Sensitive data can be emailed, shared via Teams, or uploaded to SharePoint with no controls.' -Remediation $ctrl.Remediation; return
    }
    $required = @('Exchange','SharePoint','OneDriveForBusiness','Teams')
    $covered  = @($dlpPolicies | ForEach-Object { $_.Workloads ?? @() } | Sort-Object -Unique)
    $missing  = @($required | Where-Object { $_ -notin $covered })
    if ($missing.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "DLP policies cover all required workloads: Exchange, SharePoint, OneDrive, Teams."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "DLP policies missing coverage for: $($missing -join ', '). Data can leave those channels without policy enforcement." -CurrentValue "Missing: $($missing -join ', ')" -RequiredValue 'Exchange + SharePoint + OneDrive + Teams all covered' -Remediation $ctrl.Remediation
    }
}

# ── DEF-4.2 DLP Policy Uses Sensitive Information Types ──────────────────────
function Test-NRGControlDefenderDLPSITs {
    [CmdletBinding()] param()
    $cid = 'DEF-4.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview DLP data not collected'; return
    }
    # Sensitive information types live on the DLP RULE
    # (ContentContainsSensitiveInformation), not the parent policy —
    # Get-DlpCompliancePolicy exposes no SIT field. This previously read
    # $policy.SensitiveInfoTypes, a property that never exists, so under
    # StrictMode it threw and the control reported Error on every tenant.
    $dlpPolicies = @($pvw.Data['DLPPolicies'] ?? @())
    $ruleStatus  = Get-NRGNestedProperty -Object $pvw -Path 'Data.SectionStatus.DLPRules' -Default $null
    $dlpRules    = @($pvw.Data['DLPRules'] ?? @())

    if ($ruleStatus -ne 'Collected') {
        $why = if ($ruleStatus -eq 'Failed') { 'the Get-DlpComplianceRule query failed (see Exceptions)' }
               else { 'Get-DlpComplianceRule was unavailable — this requires a Security & Compliance (IPPS) session' }
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail "DLP rule configuration could not be read: $why. Sensitive information type coverage was not assessed."
        return
    }

    if ($dlpPolicies.Count -eq 0 -and $dlpRules.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No DLP policies or rules exist, so no content is inspected for regulated data of any kind.' `
            -CurrentValue 'Zero DLP rules' -RequiredValue 'DLP rules referencing sensitive information types' `
            -Remediation $ctrl.Remediation
        return
    }

    $activeRules = @($dlpRules | Where-Object { -not $_.Disabled })
    $withSITs    = @($activeRules | Where-Object { @($_.SensitiveInfoTypes).Count -gt 0 })

    if ($withSITs.Count -gt 0) {
        $sitNames = @($withSITs | ForEach-Object { $_.SensitiveInfoTypes } | Sort-Object -Unique)
        $shown    = @($sitNames | Select-Object -First 8) -join ', '
        $more     = if ($sitNames.Count -gt 8) { " (+$($sitNames.Count - 8) more)" } else { '' }
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($withSITs.Count) of $($activeRules.Count) enabled DLP rule(s) match on sensitive information types: $shown$more." `
            -CurrentValue "$($sitNames.Count) distinct sensitive information type(s) in use"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($activeRules.Count) enabled DLP rule(s) exist but none match on a sensitive information type. Without SITs the rules cannot automatically detect credit card numbers, national identifiers, or health data — they only act on the other conditions configured." `
            -CurrentValue "0 of $($activeRules.Count) enabled rules use sensitive information types" `
            -RequiredValue 'At least one enabled DLP rule matching on sensitive information types' `
            -Remediation $ctrl.Remediation
    }
}

# ── DEF-4.3 Risky Application Alerts Configured ──────────────────────────────
function Test-NRGControlDefenderRiskyAppAlerts {
    [CmdletBinding()] param()
    $cid = 'DEF-4.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    # v4.13.0: implemented against Get-ProtectionAlert policy configuration.
    #
    # Matching caveat, stated plainly because it affects how much weight the
    # finding deserves: there is no machine-readable "this policy covers OAuth
    # consent" flag, so a policy is matched by its Name / Operation / ThreatType
    # against consent and application-permission wording. A tenant using custom
    # or non-English policy names can therefore be under-detected. The Gap text
    # says so, and the check is deliberately broad rather than exact so that it
    # errs toward finding a policy rather than declaring one missing.
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Purview data not collected'
        return
    }

    $status = Get-NRGNestedProperty -Object $pvw -Path 'Data.SectionStatus.ProtectionAlerts' -Default $null
    if ($status -ne 'Collected') {
        $why = if ($status -eq 'Failed') {
            'the Get-ProtectionAlert query failed (see Exceptions)'
        } else {
            'Get-ProtectionAlert was unavailable — this requires a Security & Compliance (IPPS) session'
        }
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail "Alert policy configuration could not be read: $why. OAuth consent alerting was not assessed."
        return
    }

    $policies = @($pvw.Data['ProtectionAlerts'] ?? @())
    $pattern  = 'consent|oauth|application permission|app permission|service principal|risky app'

    $matched = @($policies | Where-Object {
        $hay = @(
            [string]$_.Name
            [string]$_.ThreatType
            (@($_.Operation) -join ' ')
        ) -join ' '
        $hay -match $pattern
    })
    $active = @($matched | Where-Object { -not $_.Disabled })

    if ($active.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "No enabled alert policy was found covering OAuth consent or application permission grants. Consent phishing grants an attacker-controlled app standing access to mail and files without ever taking a password, and without an alert that grant is silent. (Detection matches policy name, operation and threat type against consent and application-permission wording, so a custom-named policy may exist and not be matched — verify in the portal before remediating.)" `
            -CurrentValue "0 of $($policies.Count) alert policies match OAuth/consent coverage" `
            -RequiredValue 'An enabled alert policy covering OAuth consent / application permission grants' `
            -Remediation $ctrl.Remediation
        return
    }

    $silent = @($active | Where-Object { @($_.NotifyUser).Count -eq 0 })
    if ($silent.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($active.Count) enabled alert policy(ies) cover OAuth consent / application permission activity, each with notification recipients configured."
    } else {
        $affected = @($silent | ForEach-Object {
            [ordered]@{ DisplayName = [string]$_.Name; Severity = [string]$_.Severity; Recipients = 'none configured' }
        })
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($silent.Count) of $($active.Count) OAuth/consent alert policy(ies) are enabled but have no notification recipients, so a consent-phishing grant is recorded without anyone being told." `
            -CurrentValue "$($silent.Count) matching policies with no recipients" `
            -RequiredValue 'OAuth consent alert policy enabled with notification recipients' `
            -Remediation $ctrl.Remediation -AffectedObjects $affected
    }
}

function Test-NRGControlDefenderPriorityAccounts {
    [CmdletBinding()] param()
    $cid = 'DEF-4.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $def 'AntiPhishing')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AntiPhishing was not collected; not assessed.'
        return
    }
    # The Defender "Priority account" user tag has no supported read surface (no Graph
    # endpoint, no EXO cmdlet). Rather than fabricate a result, surface the closest
    # machine-readable proxy — named-user impersonation protection in anti-phishing —
    # and direct the assessor to confirm the tag itself in the portal. Kept as an
    # advisory (Partial), never a false Satisfied/Gap.
    $ap = $def.Data['AntiPhishing']
    $proxyProtected = $false
    if ($ap -and $ap.Available) {
        $proxyProtected = @($ap.Policies | Where-Object {
            (Get-NRGObjectField -Item $_ -Key 'EnableTargetedUserProtection') -and
            @(Get-NRGObjectField -Item $_ -Key 'TargetedUsersToProtect' -Default @()).Count -gt 0
        }).Count -gt 0
    }
    $proxyNote = if ($proxyProtected) { 'Related signal: named-user impersonation protection IS configured in anti-phishing (see EXO-5.2).' } else { 'Related signal: no named-user impersonation protection is configured (see EXO-5.2).' }
    Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual verification required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail "The Defender 'Priority account' user tag is not exposed by any supported Graph/EXO read API, so it cannot be assessed programmatically. Verify in Defender portal > Settings > Email & collaboration > User tags that executives and high-value mailboxes carry the Priority account tag. $proxyNote" `
        -Remediation $ctrl.Remediation
}

# ── DEF-4.5 Endpoint DLP Policy Active ───────────────────────────────────────
function Test-NRGControlDefenderEndpointDLP {
    [CmdletBinding()] param()
    $cid = 'DEF-4.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $pvw 'DLPPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'DLPPolicies was not collected; not assessed.'
        return
    }
    $endpointDLP = @($pvw.Data['DLPPolicies'] ?? @() | Where-Object { $_.Workloads -contains 'Devices' -or $_.Workloads -contains 'EndpointDevices' })
    if ($endpointDLP.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($endpointDLP.Count) Endpoint DLP policy(ies) active. Sensitive data actions on endpoints (copy to USB, print, upload) are monitored or blocked."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'No Endpoint DLP policies detected. Users can copy sensitive files to USB drives, personal cloud storage, or print them without policy controls. Requires Defender for Endpoint + E5 Compliance or Microsoft 365 E5.' -Remediation $ctrl.Remediation
    }
}

# ── DEF-4.6 Attack Simulation Training Active ─────────────────────────────────
function Test-NRGControlDefenderAttackSim {
    [CmdletBinding()] param()
    $cid = 'DEF-4.6'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    $sim = $def.Data['AttackSimulations']
    if (-not $sim -or -not $sim.Available) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Attack Simulation Training data unavailable (requires AttackSimulation.Read.All consent + Defender for Office 365 P2; API is Global-cloud only); not assessed.'; return
    }
    $launched = [int](Get-NRGObjectField -Item $sim -Key 'LaunchedCount' -Default 0)
    $total    = [int](Get-NRGObjectField -Item $sim -Key 'Count' -Default 0)
    if ($launched -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Attack Simulation Training is in use — $launched launched/completed campaign(s) found. Users are being phishing-tested and trained."
    } else {
        $detail = if ($total -gt 0) { "Attack Simulation Training exists only as draft(s) ($total draft, 0 launched). No users have actually been phishing-tested." } else { 'No Attack Simulation Training campaigns exist. Users are never phishing-tested, so susceptibility to social-engineering attacks is unmeasured and untrained.' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail $detail -CurrentValue "$launched launched, $total total campaign(s)" -RequiredValue 'At least one launched/recurring simulation campaign' -Remediation $ctrl.Remediation
    }
}

# ── DEF-4.7 Safe Links Policy Protects Office Applications ───────────────────
function Test-NRGControlDefenderSafeLinksOffice {
    [CmdletBinding()] param()
    $cid = 'DEF-4.7'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $def = Get-NRGRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    $sl = $def.Data['SafeLinks']
    if (-not $sl -or -not $sl.Available) {
        # Same license-vs-collection disambiguation as DEF-1.1 — never a
        # confident High gap when the tenant simply lacks the MDO P1 license.
        $lic = Get-NRGControlLicenseStatus -ControlId $cid
        if ($lic -eq 'Met') {
            $why = if ($sl -and $sl.Error) { "Collector error: $($sl.Error)" } else { 'No policy data returned.' }
            Add-NRGFinding -ControlId $cid -State 'Error' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Safe Links could not be collected even though the tenant is licensed for Defender for Office 365 Plan 1. $why Re-run collection and verify connectivity." -CurrentValue 'Collection failed' -Remediation $ctrl.Remediation
        } else {
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Safe Links for Office applications requires Defender for Office 365 Plan 1, which is not part of this tenant''s licensing. Not scored as a gap — surfaced as a licensing upgrade opportunity.' -CurrentValue 'Defender for Office 365 P1 not licensed' -RequiredValue 'Defender for Office 365 Plan 1' -Remediation $ctrl.Remediation
        }
        return
    }
    $officeProtected = @($sl.Policies | Where-Object { $_.EnableSafeLinksForO365 -eq $true -or $_.EnableSafeLinksForOffice -eq $true }).Count -gt 0
    if ($officeProtected) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Safe Links protection is enabled for Office applications (Word, Excel, PowerPoint, Teams).'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Safe Links not protecting Office applications. Malicious links embedded in Word/Excel/PowerPoint documents are not scanned at click time.' -Remediation $ctrl.Remediation
    }
}

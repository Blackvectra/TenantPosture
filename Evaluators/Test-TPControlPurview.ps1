#Requires -Version 7.0
#
# Test-TPControlPurview.ps1
# Evaluates Purview controls. Reads: Get-TPRawData -Key 'Purview'
#
# Controls: PVW-1.1 through PVW-4.4 (18 controls).
#   Config/controls.json is authoritative — each control's EvaluatorFunction
#   names the function in this file that scores it.
#

function Test-TPControlPurview {
    [CmdletBinding()] param()
    $raw = Get-TPRawData -Key 'Purview'
    if (-not $raw -or -not $raw.Success) {
        foreach ($cid in @('PVW-1.1','PVW-1.2','PVW-1.3','PVW-1.4')) {
            $c = Get-TPControlById -ControlId $cid
            if ($c) {
                Add-TPFinding -ControlId $cid -State 'NotApplicable' `
                    -Category 'Compliance' -Title $c.Title `
                    -Detail 'Purview collector did not run.'
            }
        }
        return
    }

    $d = $raw.Data

    # PVW-1.1 — Unified Audit Log ingestion
    $c = Get-TPControlById -ControlId 'PVW-1.1'
    if ($c) {
        $ual       = Get-TPObjectField -Item $d -Key 'UnifiedAuditEnabled'
        $ualSource = [string](Get-TPNestedProperty -Object $d -Path 'AuditConfig.Source' -Default 'Unknown')
        if ($ual -eq $true) {
            # True is authoritative from any session: Security & Compliance
            # PowerShell can only ever report False.
            Add-TPFinding -ControlId 'PVW-1.1' -State 'Satisfied' `
                -Category 'Compliance' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'Unified Audit Log: enabled' `
                -RequiredValue 'UnifiedAuditLogIngestionEnabled = true' `
                -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PVW-1.1')
        } elseif ($null -eq $ual -or -not (Test-TPSectionCollected $raw 'AuditConfig')) {
            Add-TPFinding -ControlId 'PVW-1.1' -State 'NotApplicable' `
                -Category 'Compliance' -Title $c.Title `
                -Detail 'Audit configuration was not collected; Unified Audit Log status not assessed. Verify in Purview > Audit.' `
                -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PVW-1.1')
        } elseif ($ualSource -ne 'ExchangeOnline') {
            # Microsoft: "the UnifiedAuditLogIngestionEnabled property is always
            # False [in Security & Compliance PowerShell], even when auditing is
            # turned on." A False from that session — or one we cannot place —
            # is not evidence that auditing is off.
            Add-TPFinding -ControlId 'PVW-1.1' -State 'NotApplicable' `
                -Category 'Compliance' -Title $c.Title `
                -Detail "Unified Audit Log status could not be read from the Exchange Online session (source: $ualSource). Security & Compliance PowerShell always reports it as off, so no verdict is given. Verify with Get-AdminAuditLogConfig in Exchange Online PowerShell, or in Purview > Audit." `
                -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PVW-1.1')
        } else {
            Add-TPFinding -ControlId 'PVW-1.1' -State 'Gap' `
                -Category 'Compliance' -Title $c.Title -Severity $c.Severity `
                -Detail 'Unified Audit Log ingestion is disabled. Sign-in activity, admin changes, file access, and email events cannot be reconstructed for incident response.' `
                -CurrentValue 'UnifiedAuditLogIngestionEnabled = false' `
                -RequiredValue 'UnifiedAuditLogIngestionEnabled = true' `
                -Remediation 'Purview compliance portal > Audit > Turn on auditing. Or: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' `
                -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PVW-1.1')
        }
    }

    # PVW-1.2 — Audit log retention of at least 90 days.
    # This block scored DLP and PVW-1.3 scored retention POLICIES (the data
    # lifecycle question PVW-2.5 already asks), so neither control matched its
    # own title. Audit (Standard) keeps records 180 days in every plan
    # (Purview service description), so the only ways to fall short are an
    # audit log that is off (PVW-1.1's finding, not double-counted here) or an
    # audit retention policy that shortens retention below 90 days.
    $c = Get-TPControlById -ControlId 'PVW-1.2'
    if ($c) {
        $cit = Get-TPFrameworkCitations -ControlId 'PVW-1.2'
        $ual       = Get-TPObjectField -Item $d -Key 'UnifiedAuditEnabled'
        $ualSource = [string](Get-TPNestedProperty -Object $d -Path 'AuditConfig.Source' -Default 'Unknown')
        if ($ual -ne $true -and ($null -eq $ual -or $ualSource -ne 'ExchangeOnline' -or -not (Test-TPSectionCollected $raw 'AuditConfig'))) {
            Add-TPFinding -ControlId 'PVW-1.2' -State 'NotApplicable' -Category 'Compliance' -Title $c.Title -FrameworkIds $cit `
                -Detail 'Unified Audit Log status was not read, so audit retention was not assessed.'
        } elseif ($ual -ne $true) {
            Add-TPFinding -ControlId 'PVW-1.2' -State 'NotApplicable' -Category 'Compliance' -Title $c.Title -FrameworkIds $cit `
                -Detail 'The Unified Audit Log is off, so no audit records are retained at all. That is scored once, under PVW-1.1; turning it on gives 180-day retention by default.'
        } elseif (-not (Test-TPSectionCollected $raw 'AuditRetentionPolicies')) {
            Add-TPFinding -ControlId 'PVW-1.2' -State 'NotApplicable' -Category 'Compliance' -Title $c.Title -FrameworkIds $cit `
                -Detail 'The audit log is on (180-day default retention), but audit retention policies were not collected, so a policy shortening retention below 90 days could not be ruled out. Check Purview > Audit > Audit retention policies.'
        } else {
            $short = @(@(Get-TPObjectField -Item $d -Key 'AuditRetentionPolicies' -Default @()) | Where-Object {
                $days = Get-TPObjectField -Item $_ -Key 'RetentionDays' -Default $null
                $null -ne $days -and [int]$days -lt 90
            })
            if ($short.Count -gt 0) {
                $names = ($short | ForEach-Object { "$(Get-TPObjectField -Item $_ -Key 'Name' -Default '?') ($(Get-TPObjectField -Item $_ -Key 'RetentionDays' -Default '?') days)" }) -join '; '
                Add-TPFinding -ControlId 'PVW-1.2' -State 'Partial' -Category 'Compliance' -Title $c.Title -Severity $c.Severity -FrameworkIds $cit `
                    -Detail "The audit log is on, but $($short.Count) audit retention policy(ies) keep some records for less than 90 days: $names. Records those policies match are deleted before the 90-day minimum." `
                    -CurrentValue "$($short.Count) policy(ies) under 90 days" -RequiredValue 'All audit records retained at least 90 days' -Remediation $c.Remediation
            } else {
                Add-TPFinding -ControlId 'PVW-1.2' -State 'Satisfied' -Category 'Compliance' -Title $c.Title -Severity 'Informational' -FrameworkIds $cit `
                    -CurrentValue 'Audit log on; no retention policy shorter than 90 days (default 180 days)'
            }
        }
    }

    # PVW-1.3 — DLP policy active for sensitive data
    $c = Get-TPControlById -ControlId 'PVW-1.3'
    if ($c -and -not (Test-TPSectionCollected $raw 'DLPPolicies')) {
        # The section was never read (IPPS not connected, or the role cannot
        # run the cmdlet). An empty list here is not "none configured".
        Add-TPFinding -ControlId 'PVW-1.3' -State 'NotApplicable' -Category 'Compliance' -Title $c.Title `
            -Detail 'DLP policies were not collected; not assessed.' -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PVW-1.3')
    } elseif ($c) {
        $all     = @($d.DLPPolicies)
        # Only Mode 'Enable' enforces; TestWith(out)Notifications detects and
        # does not block. The collector sets Enabled from Mode -eq 'Enable';
        # Mode is checked too so results from any other source read the same.
        $modeOf  = { param($p) [string](Get-TPObjectField -Item $p -Key 'Mode' -Default '') }
        $testing = @($all | Where-Object { (& $modeOf $_) -like 'Test*' }).Count
        $enforcedList = @($all | Where-Object { (Get-TPObjectField -Item $_ -Key 'Enabled' -Default $false) -eq $true -and ((& $modeOf $_) -eq 'Enable' -or -not (& $modeOf $_)) })
        $enabled = $enforcedList.Count
        if ($enabled -gt 0) {
            $rest = $all.Count - $enabled
            $restNote = if ($rest -gt 0) { " The other $rest are in test mode or turned off." } else { '' }
            Add-TPFinding -ControlId 'PVW-1.3' -State 'Satisfied' `
                -Category 'Compliance' -Title $c.Title -Severity 'Informational' `
                -Detail "$enabled of $($all.Count) DLP policies are enforced: $((@($enforcedList | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '') }) | Select-Object -First 5) -join ', ').$restNote" `
                -CurrentValue "$enabled of $($all.Count) DLP policies enforced" `
                -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PVW-1.3')
        } elseif ($testing -gt 0) {
            # Simulation mode: detects and reports but does not block — genuinely part-way.
            Add-TPFinding -ControlId 'PVW-1.3' -State 'Partial' `
                -Category 'Compliance' -Title $c.Title -Severity 'Medium' `
                -Detail "$testing DLP policy(ies) are in test (simulation) mode and none is enforced: sensitive data is detected but not blocked." `
                -CurrentValue "0 enforced, $testing in test mode" `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PVW-1.3')
        } else {
            $detail = if ($all.Count -gt 0) {
                "$($all.Count) DLP policy(ies) exist but all are turned off. Sensitive information (SSN, credit card, financial data) is not monitored."
            } else {
                'No DLP policies configured. Sensitive information (SSN, credit card, financial data) is not monitored across email, SharePoint, OneDrive, or Teams.'
            }
            Add-TPFinding -ControlId 'PVW-1.3' -State 'Gap' `
                -Category 'Compliance' -Title $c.Title -Severity $c.Severity `
                -Detail $detail -CurrentValue "0 of $($all.Count) enforced" `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PVW-1.3')
        }
    }

    # PVW-1.4 — Sensitivity labels PUBLISHED: a label policy must publish them
    # to users. Counting defined labels passed tenants whose labels nobody can
    # apply (PVW-4.3 reported the same data Partial "none published").
    $c = Get-TPControlById -ControlId 'PVW-1.4'
    if ($c) {
        $cit14 = Get-TPFrameworkCitations -ControlId 'PVW-1.4'
        if (-not (Test-TPSectionCollected $raw 'LabelPolicies') -or -not (Test-TPSectionCollected $raw 'SensitivityLabels')) {
            Add-TPFinding -ControlId 'PVW-1.4' -State 'NotApplicable' -Category 'Compliance' -Title $c.Title -FrameworkIds $cit14 `
                -Detail 'Sensitivity labels or label policies were not collected; not assessed.'
        } else {
            $labels   = @($d.SensitivityLabels | Where-Object { $_ })
            $policies = @(Get-TPObjectField -Item $d -Key 'LabelPolicies' -Default @() | Where-Object { $_ })
            if ($labels.Count -gt 0 -and $policies.Count -gt 0) {
                Add-TPFinding -ControlId 'PVW-1.4' -State 'Satisfied' -Category 'Compliance' -Title $c.Title -Severity 'Informational' -FrameworkIds $cit14 `
                    -CurrentValue "$($labels.Count) label(s), $($policies.Count) publishing policy(ies)"
            } else {
                $what = if ($labels.Count -gt 0) { "$($labels.Count) sensitivity label(s) are defined but no label policy publishes them, so users cannot apply them." } else { 'No sensitivity labels are defined or published. Users cannot classify documents or emails by sensitivity.' }
                Add-TPFinding -ControlId 'PVW-1.4' -State 'Gap' -Category 'Compliance' -Title $c.Title -Severity $c.Severity -FrameworkIds $cit14 `
                    -Detail $what -Remediation $c.Remediation
            }
        }
    }
}

# ── PVW-2.1 Admin Audit Log Enabled (separate from UAL ingestion) ────────────
# v4.6.4 DEDUPE FIX: PVW-2.1 previously checked the SAME
# UnifiedAuditLogIngestionEnabled property as PVW-1.1 and PVW-3.2, so a tenant
# with audit disabled would generate THREE Gap findings for the same root cause.
# Repoint PVW-2.1 to the distinct AdminAuditLogEnabled property (admin role
# changes / cmdlet audit history) which is a different audit pipeline.
function Test-TPControlPurviewAuditSearch {
    [CmdletBinding()] param()
    $cid = 'PVW-2.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Purview data not collected'; return }
    # Audit log SEARCH has records only when Unified Audit Log ingestion is
    # on — the control's description and remediation are exactly that. It
    # read AdminAuditLogEnabled instead, which Exchange Online always reports
    # True, so it passed beside a PVW-1.1 "UAL disabled" Gap.
    $ual = Get-TPNestedProperty -Object $pvw -Path 'Data.UnifiedAuditEnabled' -Default $null
    $src = [string](Get-TPNestedProperty -Object $pvw -Path 'Data.AuditConfig.Source' -Default 'Unknown')
    if ($ual -eq $true) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Unified Audit Log ingestion is on, so the audit log is searchable.' -CurrentValue 'UnifiedAuditLogIngestionEnabled = true'
    } elseif ($null -eq $ual -or $src -ne 'ExchangeOnline' -or -not (Test-TPSectionCollected $pvw 'AuditConfig')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Unified Audit Log status was not read from the Exchange Online session; audit search not assessed.'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Unified Audit Log ingestion is off, so audit log search returns nothing for user and admin activity.' -CurrentValue 'UnifiedAuditLogIngestionEnabled = false' -RequiredValue 'UnifiedAuditLogIngestionEnabled = true' -Remediation $ctrl.Remediation
    }
}

# ── PVW-2.2 Communication Compliance Policy Active ───────────────────────────
function Test-TPControlPurviewCommCompliance {
    [CmdletBinding()] param()
    $cid = 'PVW-2.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $pvw 'CommCompliancePolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CommCompliancePolicies was not collected; not assessed.'
        return
    }
    # A policy explicitly Enabled = $false is not active; unknown counts.
    $all = @($pvw.Data['CommCompliancePolicies'] ?? @())
    $policies = @($all | Where-Object { (Get-TPObjectField -Item $_ -Key 'Enabled' -Default $null) -ne $false })
    if ($policies.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($policies.Count) communication compliance policy(ies) active."
    } else {
        $what = if ($all.Count -gt 0) { "$($all.Count) communication compliance policy(ies) exist but all are turned off." } else { 'No communication compliance policies configured.' }
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$what Required for regulatory environments (finance, healthcare, government)." -Remediation $ctrl.Remediation
    }
}

# ── PVW-2.3 Information Barriers Mode ────────────────────────────────────────
function Test-TPControlPurviewInfoBarriers {
    [CmdletBinding()] param()
    $cid = 'PVW-2.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $pvw 'InformationBarriersMode')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'InformationBarriersMode was not collected; not assessed.'
        return
    }
    $ibMode = [string]($pvw.Data['InformationBarriersMode'] ?? 'Legacy')
    if ($ibMode -match 'SingleSegment|MultiSegment|Mixed') {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Information barriers mode: $ibMode"
    } else {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "Information barriers in Legacy mode ($ibMode). Consider upgrading to Single or Multi-segment mode if barriers are deployed." -Remediation $ctrl.Remediation
    }
}

# ── PVW-2.4 Insider Risk Management Policy ───────────────────────────────────
function Test-TPControlPurviewInsiderRisk {
    [CmdletBinding()] param()
    $cid = 'PVW-2.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    # Insider Risk Management policies are not exposed through the Security &
    # Compliance PowerShell or Graph surfaces this assessment reads. This used
    # to report "InsiderRiskPolicies was not collected" — a collection
    # failure that no re-run could ever fix. Say what it actually is.
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — Insider Risk Management policies are not exposed to the APIs this assessment uses. Review them in the Microsoft Purview portal > Insider Risk Management > Policies.' `
        -Remediation $ctrl.Remediation
}

# ── PVW-2.5 Retention Policy Covers Key Workloads ────────────────────────────
function Test-TPControlPurviewRetention {
    [CmdletBinding()] param()
    $cid = 'PVW-2.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    if (-not (Test-TPSectionCollected $pvw 'RetentionPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Retention policies were not collected; not assessed.'; return
    }
    $retPolicies = @($pvw.Data['RetentionPolicies'] ?? @())
    $coveredWorkloads = @($retPolicies | ForEach-Object { $_.Workloads ?? @() } | Select-Object -Unique)
    $requiredWorkloads = @('Exchange','SharePoint','OneDriveForBusiness','Teams')
    $missing = @($requiredWorkloads | Where-Object { $_ -notin $coveredWorkloads })
    if ($missing.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Retention policies cover all key workloads: $($requiredWorkloads -join ', ')"
    } elseif ($retPolicies.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "Retention policies exist but are missing coverage for: $($missing -join ', ')" -CurrentValue "Missing: $($missing -join ', ')" -RequiredValue 'Exchange, SharePoint, OneDrive, Teams all covered'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No retention policies configured. Data cannot be preserved for legal or regulatory requirements.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-2.6 Auto-Labeling Policy Active ──────────────────────────────────────
function Test-TPControlPurviewAutoLabel {
    [CmdletBinding()] param()
    $cid = 'PVW-2.6'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview label data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $pvw 'AutoLabelPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AutoLabelPolicies was not collected; not assessed.'
        return
    }
    # Mode: Enable (labels content) / TestWith[out]Notifications (simulation:
    # labels nothing) / Disable. Enabled -> Satisfied; simulation only ->
    # Partial, like a report-only CA policy; nothing -> Gap.
    $autoLabels = @($pvw.Data['AutoLabelPolicies'] ?? @())
    $active     = @($autoLabels | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Mode' -Default '') -eq 'Enable' })
    $simulating = @($autoLabels | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Mode' -Default '') -like 'Test*' })
    if ($active.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($active.Count) auto-labeling policy(ies) enforcing. Sensitive content labeled without user action."
    } elseif ($simulating.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($simulating.Count) auto-labeling policy(ies) in simulation mode only — nothing is labeled until the policy is turned on." -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No auto-labeling policy is turned on. Sensitive data classification depends entirely on user action.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-3.1 Audit Logs Exported to SIEM ──────────────────────────────────────
function Test-TPControlPurviewSIEMExport {
    [CmdletBinding()] param()
    $cid = 'PVW-3.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Medium' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — whether an external SIEM is consuming the audit log is not observable from Microsoft 365. Confirm in Purview > Audit > Export settings, or check the Microsoft Sentinel connector state.' `
        -Remediation $ctrl.Remediation
}

# ── PVW-3.2 eDiscovery Case Management Configured ────────────────────────────
# v4.6.4 DEDUPE FIX: PVW-3.2 previously aliased UnifiedAuditLogIngestionEnabled
# → triple-counted with PVW-1.1 and PVW-2.1. Repoint to a separate eDiscovery
# signal. We don't currently collect eDiscovery case data (no IPP cmdlet wired
# up in the Purview collector), so when IPP is not connected we mark
# NotApplicable rather than fabricating a Satisfied/Gap result.
function Test-TPControlPurviewEDiscovery {
    [CmdletBinding()] param()
    $cid = 'PVW-3.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    # eDiscovery READINESS (roles assigned, a documented legal-hold workflow)
    # is not measurable from the tenant: a count of cases only says whether
    # there has been litigation. The old detail blamed "IPPSSession not
    # connected" even when it was.
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — confirm compliance staff hold the eDiscovery Manager / Administrator role and that the legal-hold workflow is documented. Case counts do not measure readiness.' `
        -Remediation $ctrl.Remediation
}

# ── PVW-3.3 Microsoft Purview Compliance Score Reviewed ──────────────────────
function Test-TPControlPurviewComplianceScore {
    [CmdletBinding()] param()
    $cid = 'PVW-3.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — Compliance Manager improvement actions are not exposed to the APIs this assessment uses. Review them at compliance.microsoft.com > Compliance Manager and confirm each is assigned to an owner with a target date.' `
        -Remediation $ctrl.Remediation
}

# ── PVW-3.4 Data Classification Sensitive Info Types Active ──────────────────
function Test-TPControlPurviewSensitiveInfoTypes {
    [CmdletBinding()] param()
    $cid = 'PVW-3.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Purview data not collected'; return
    }
    # Sensitive information types live on the DLP RULES. Counting POLICIES
    # ("2 DLP policies using sensitive information types") passed tenants whose
    # rules use none, while DEF-4.2 read the rules and reported the Gap.
    if ((Get-TPNestedProperty -Object $pvw -Path 'Data.SectionStatus.DLPRules' -Default $null) -ne 'Collected') {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'DLPRules was not collected; sensitive information type use not assessed.'
        return
    }
    if (-not (Test-TPSectionCollected $pvw 'DLPPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'DLPPolicies was not collected, so whether any DLP rule is in an enforcing policy is unknown; sensitive information type use not assessed.'
        return
    }
    # Only enabled rules in an ENFORCING policy (Mode Enable) count; rules in a test-mode or disabled
    # policy are reported but not credited (Get-TPDlpRuleStates).
    $states  = @(Get-TPDlpRuleStates -Policies @($pvw.Data['DLPPolicies'] ?? @()) -Rules @($pvw.Data['DLPRules'] ?? @()))
    $active  = @($states | Where-Object { $_.State -eq 'Enforcing' })
    $testR   = @($states | Where-Object { $_.State -eq 'TestMode' })
    # Unknown: the parent policy was not found, so its Mode is unknown. Only such a rule that matches a
    # type could change the verdict; one matching none cannot meet the requirement in any mode.
    $unknownR = @($states | Where-Object { $_.State -eq 'Unknown' -and @($_.SITs).Count -gt 0 })
    $withSit = @($active | Where-Object { @($_.SITs).Count -gt 0 })
    if ($withSit.Count -gt 0) {
        $verified = @("$($withSit.Count) enabled rule(s) in enforcing DLP policies detect sensitive information types ($($withSit.Count) of $($active.Count) enforcing rules).")
        if ($testR.Count -gt 0) { $verified += "Not counted (policy in test mode or off): $($testR.Count) rule(s) in $((@($testR | ForEach-Object { $_.Policy } | Sort-Object -Unique)) -join ', ')." }
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -CurrentValue "$($withSit.Count) of $($active.Count) enforcing rules use SITs"
    } elseif ($unknownR.Count -gt 0) {
        # A rule whose parent policy was not found may be the enforcing one: not a Gap.
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "No rule in an enforcing DLP policy matches a sensitive information type, but $($unknownR.Count) enabled rule(s) that match one belong to a policy that was not found among the collected policies or whose Mode was empty or not recognized, so whether they enforce is unknown; not assessed."
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "No enabled DLP rule matches on a sensitive information type ($($active.Count) enabled rule(s)). Regulated data (SSN, card numbers, health data) is not being detected." -CurrentValue "0 of $($active.Count) enabled rules use SITs" -RequiredValue 'Enabled DLP rules matching sensitive information types' -Remediation $ctrl.Remediation
    }
}

# ── PVW-4.1 Purview Audit (Premium) Enabled ───────────────────────────────────
function Test-TPControlPurviewAuditPremium {
    [CmdletBinding()] param()
    $cid = 'PVW-4.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $pvw 'AuditConfig')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AuditConfig was not collected; not assessed.'
        return
    }
    # AdvancedAuditEnabled is not a key the collector populates — Get-AdminAuditLogConfig
    # (Collectors/Purview/Invoke-TPCollectPurview.ps1) only writes
    # UnifiedAuditLogIngestionEnabled / AdminAuditLogEnabled / AdminAuditLogAgeLimit.
    # Defaulting the read to $false made this control score Partial on every
    # tenant regardless of real Audit Premium status. Default to $null instead
    # so "never collected" is distinguishable from a real $false and reported
    # honestly rather than as a confident, uncomputed verdict.
    $premiumRaw = Get-TPNestedProperty -Object $pvw -Path 'Data.AuditConfig.AdvancedAuditEnabled' -Default $null
    if ($null -eq $premiumRaw) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Purview Audit (Premium) status is not collected by this tool; requires manual verification in the Purview compliance portal.'
        return
    }
    $premiumEnabled = [bool]$premiumRaw
    if ($premiumEnabled) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Purview Audit (Premium) is enabled. High-value events including MailItemsAccessed and SearchQueryInitiated are captured.'
    } else {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'Purview Audit (Standard) only. Premium audit events like MailItemsAccessed (required for mail exfil investigations) and SearchQueryInitiated are not captured. Requires E5 or E5 Compliance add-on.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-4.2 Audit Log Retention Extended Beyond 90 Days ──────────────────────
function Test-TPControlPurviewAuditRetention {
    [CmdletBinding()] param()
    $cid = 'PVW-4.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $pvw 'AuditRetentionPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AuditRetentionPolicies was not collected; not assessed.'
        return
    }
    $retentionPolicies = @($pvw.Data['AuditRetentionPolicies'] ?? @())
    $longTerm = @($retentionPolicies | Where-Object { [int]($_.RetentionDays ?? 0) -ge 365 })
    if ($longTerm.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($longTerm.Count) audit log retention policy(ies) extending logs ≥365 days."
    } else {
        # Not configured is a Gap (the default retention is what the control
        # asks to extend), not half credit.
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No audit log retention policy keeps records for a year or more. The default policy applies: 180 days with Audit (Standard); with Audit (Premium), Exchange, SharePoint and Entra records are kept one year and everything else 180 days. Breaches discovered later than that cannot be investigated.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-4.3 Microsoft Purview Sensitivity Labels Published ────────────────────
function Test-TPControlPurviewLabelsPublished {
    [CmdletBinding()] param()
    $cid = 'PVW-4.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview label data not collected'; return }
    # Empty is not clean: a failed Get-Label left an empty list and this
    # reported "No sensitivity labels configured" (Gap). And LabelPolicies was
    # never collected at all, so any tenant WITH labels read "labels defined
    # but none published" (Partial) — a statement nothing had checked.
    if (-not (Test-TPSectionCollected $pvw 'SensitivityLabels')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'SensitivityLabels was not collected; not assessed.'
        return
    }
    $labels        = @($pvw.Data['SensitivityLabels'] ?? @())
    if ($labels.Count -gt 0 -and -not (Test-TPSectionCollected $pvw 'LabelPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "$($labels.Count) sensitivity label(s) defined, but label publishing policies were not collected; whether they are published was not assessed."
        return
    }
    $labelPolicies = @($pvw.Data['LabelPolicies'] ?? @())
    if ($labels.Count -gt 0 -and $labelPolicies.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($labels.Count) sensitivity label(s) defined, $($labelPolicies.Count) label policy(ies) published to users."
    } elseif ($labels.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "$($labels.Count) sensitivity label(s) defined but no label policies published. Labels exist but users cannot apply them." -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No sensitivity labels configured. Without labels, data classification is impossible and DLP cannot enforce label-based protection.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-4.4 Records Management Policy Active ─────────────────────────────────
function Test-TPControlPurviewRecordsManagement {
    [CmdletBinding()] param()
    $cid = 'PVW-4.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $pvw 'RetentionLabels')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'RetentionLabels was not collected; not assessed.'
        return
    }
    $retentionLabels = @($pvw.Data['RetentionLabels'] ?? @())
    $recordLabels    = @($retentionLabels | Where-Object { $_.IsRecordLabel -eq $true })
    if ($recordLabels.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($recordLabels.Count) records management label(s) configured. Immutable records can be declared for regulatory or legal requirements."
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No records management labels configured. For regulated environments (government, healthcare, finance) immutable record declarations may be required.' -Remediation $ctrl.Remediation
    }
}
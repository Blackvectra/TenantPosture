#Requires -Version 7.0
#
# Test-NRGControlPurview.ps1
# Evaluates Purview controls. Reads: Get-NRGRawData -Key 'Purview'
#
# Controls: PVW-1.1 through PVW-4.4 (18 controls).
#   Config/controls.json is authoritative — each control's EvaluatorFunction
#   names the function in this file that scores it.
#

function Test-NRGControlPurview {
    [CmdletBinding()] param()
    $raw = Get-NRGRawData -Key 'Purview'
    if (-not $raw -or -not $raw.Success) {
        foreach ($cid in @('PVW-1.1','PVW-1.2','PVW-1.3','PVW-1.4')) {
            $c = Get-NRGControlById -ControlId $cid
            if ($c) {
                Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
                    -Category 'Compliance' -Title $c.Title `
                    -Detail 'Purview collector did not run.'
            }
        }
        return
    }

    $d = $raw.Data

    # PVW-1.1 — Unified Audit Log ingestion
    $c = Get-NRGControlById -ControlId 'PVW-1.1'
    if ($c) {
        $ual       = Get-NRGObjectField -Item $d -Key 'UnifiedAuditEnabled'
        $ualSource = [string](Get-NRGNestedProperty -Object $d -Path 'AuditConfig.Source' -Default 'Unknown')
        if ($ual -eq $true) {
            # True is authoritative from any session: Security & Compliance
            # PowerShell can only ever report False.
            Add-NRGFinding -ControlId 'PVW-1.1' -State 'Satisfied' `
                -Category 'Compliance' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'Unified Audit Log: enabled' `
                -RequiredValue 'UnifiedAuditLogIngestionEnabled = true' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.1')
        } elseif ($null -eq $ual -or -not (Test-NRGSectionCollected $raw 'AuditConfig')) {
            Add-NRGFinding -ControlId 'PVW-1.1' -State 'NotApplicable' `
                -Category 'Compliance' -Title $c.Title `
                -Detail 'Audit configuration was not collected; Unified Audit Log status not assessed. Verify in Purview > Audit.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.1')
        } elseif ($ualSource -ne 'ExchangeOnline') {
            # Microsoft: "the UnifiedAuditLogIngestionEnabled property is always
            # False [in Security & Compliance PowerShell], even when auditing is
            # turned on." A False from that session — or one we cannot place —
            # is not evidence that auditing is off.
            Add-NRGFinding -ControlId 'PVW-1.1' -State 'NotApplicable' `
                -Category 'Compliance' -Title $c.Title `
                -Detail "Unified Audit Log status could not be read from the Exchange Online session (source: $ualSource). Security & Compliance PowerShell always reports it as off, so no verdict is given. Verify with Get-AdminAuditLogConfig in Exchange Online PowerShell, or in Purview > Audit." `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.1')
        } else {
            Add-NRGFinding -ControlId 'PVW-1.1' -State 'Gap' `
                -Category 'Compliance' -Title $c.Title -Severity $c.Severity `
                -Detail 'Unified Audit Log ingestion is disabled. Sign-in activity, admin changes, file access, and email events cannot be reconstructed for incident response.' `
                -CurrentValue 'UnifiedAuditLogIngestionEnabled = false' `
                -RequiredValue 'UnifiedAuditLogIngestionEnabled = true' `
                -Remediation 'Purview compliance portal > Audit > Turn on auditing. Or: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.1')
        }
    }

    # PVW-1.2 — DLP policies
    $c = Get-NRGControlById -ControlId 'PVW-1.2'
    if ($c -and -not (Test-NRGSectionCollected $raw 'DLPPolicies')) {
        # The section was never read (IPPS not connected, or the role cannot
        # run the cmdlet). An empty list here is not "none configured".
        Add-NRGFinding -ControlId 'PVW-1.2' -State 'NotApplicable' -Category 'Compliance' -Title $c.Title `
            -Detail 'DLP policies were not collected; not assessed.' -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.2')
    } elseif ($c) {
        $count = @($d.DLPPolicies | Where-Object { $_.Enabled -eq $true }).Count
        $total = @($d.DLPPolicies).Count
        if ($count -gt 0) {
            Add-NRGFinding -ControlId 'PVW-1.2' -State 'Satisfied' `
                -Category 'Compliance' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "$count of $total DLP policies enabled"
        } elseif ($total -gt 0) {
            Add-NRGFinding -ControlId 'PVW-1.2' -State 'Partial' `
                -Category 'Compliance' -Title $c.Title -Severity 'Medium' `
                -Detail "$total DLP policies exist but none are enabled (likely in audit/test mode)." `
                -CurrentValue "0 of $total enabled" `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.2')
        } else {
            Add-NRGFinding -ControlId 'PVW-1.2' -State 'Gap' `
                -Category 'Compliance' -Title $c.Title -Severity $c.Severity `
                -Detail 'No DLP policies configured. Sensitive information (SSN, credit card, financial data) is not monitored across email, SharePoint, OneDrive, or Teams.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.2')
        }
    }

    # PVW-1.3 — Retention policies
    $c = Get-NRGControlById -ControlId 'PVW-1.3'
    if ($c -and -not (Test-NRGSectionCollected $raw 'RetentionPolicies')) {
        # The section was never read (IPPS not connected, or the role cannot
        # run the cmdlet). An empty list here is not "none configured".
        Add-NRGFinding -ControlId 'PVW-1.3' -State 'NotApplicable' -Category 'Compliance' -Title $c.Title `
            -Detail 'Retention policies were not collected; not assessed.' -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.3')
    } elseif ($c) {
        $count = @($d.RetentionPolicies | Where-Object { $_.Enabled -eq $true }).Count
        if ($count -gt 0) {
            Add-NRGFinding -ControlId 'PVW-1.3' -State 'Satisfied' `
                -Category 'Compliance' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "$count retention policies enabled"
        } else {
            Add-NRGFinding -ControlId 'PVW-1.3' -State 'Gap' `
                -Category 'Compliance' -Title $c.Title -Severity $c.Severity `
                -Detail 'No active retention policies. Email and document retention is left to user discretion.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.3')
        }
    }

    # PVW-1.4 — Sensitivity labels
    $c = Get-NRGControlById -ControlId 'PVW-1.4'
    if ($c -and -not (Test-NRGSectionCollected $raw 'SensitivityLabels')) {
        # The section was never read (IPPS not connected, or the role cannot
        # run the cmdlet). An empty list here is not "none configured".
        Add-NRGFinding -ControlId 'PVW-1.4' -State 'NotApplicable' -Category 'Compliance' -Title $c.Title `
            -Detail 'Sensitivity labels were not collected; not assessed.' -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.4')
    } elseif ($c) {
        $count = @($d.SensitivityLabels | Where-Object { $_.IsValid -eq $true }).Count
        if ($count -gt 0) {
            Add-NRGFinding -ControlId 'PVW-1.4' -State 'Satisfied' `
                -Category 'Compliance' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "$count sensitivity labels published"
        } else {
            Add-NRGFinding -ControlId 'PVW-1.4' -State 'Gap' `
                -Category 'Compliance' -Title $c.Title -Severity $c.Severity `
                -Detail 'No sensitivity labels published. Users cannot classify documents or emails by sensitivity.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.4')
        }
    }
}

# ── PVW-2.1 Admin Audit Log Enabled (separate from UAL ingestion) ────────────
# v4.6.4 DEDUPE FIX: PVW-2.1 previously checked the SAME
# UnifiedAuditLogIngestionEnabled property as PVW-1.1 and PVW-3.2, so a tenant
# with audit disabled would generate THREE Gap findings for the same root cause.
# Repoint PVW-2.1 to the distinct AdminAuditLogEnabled property (admin role
# changes / cmdlet audit history) which is a different audit pipeline.
function Test-NRGControlPurviewAuditSearch {
    [CmdletBinding()] param()
    $cid = 'PVW-2.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    $adminEnabled = Get-NRGNestedProperty -Object $pvw -Path 'Data.AuditConfig.AdminAuditLogEnabled' -Default $null
    if ($null -eq $adminEnabled) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AdminAuditLogEnabled property unavailable (Get-AdminAuditLogConfig not reachable — typically IPPSSession not connected).'
        return
    }
    if ($adminEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Admin audit log is enabled — cmdlet invocations against EXO are recorded for incident response review.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Admin audit logging is disabled — administrative cmdlet history is not retained. This is distinct from UAL ingestion (PVW-1.1) and covers EXO management plane activity specifically.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-2.2 Communication Compliance Policy Active ───────────────────────────
function Test-NRGControlPurviewCommCompliance {
    [CmdletBinding()] param()
    $cid = 'PVW-2.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $pvw 'CommCompliancePolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CommCompliancePolicies was not collected; not assessed.'
        return
    }
    # A policy explicitly Enabled = $false is not active; unknown counts.
    $policies = @(@($pvw.Data['CommCompliancePolicies'] ?? @()) | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Enabled' -Default $null) -ne $false })
    if ($policies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($policies.Count) communication compliance policy(ies) active."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No communication compliance policies configured. Required for regulatory environments (finance, healthcare, government). Requires E5 Compliance.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-2.3 Information Barriers Mode ────────────────────────────────────────
function Test-NRGControlPurviewInfoBarriers {
    [CmdletBinding()] param()
    $cid = 'PVW-2.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $pvw 'InformationBarriersMode')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'InformationBarriersMode was not collected; not assessed.'
        return
    }
    $ibMode = [string]($pvw.Data['InformationBarriersMode'] ?? 'Legacy')
    if ($ibMode -match 'SingleSegment|MultiSegment|Mixed') {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Information barriers mode: $ibMode"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "Information barriers in Legacy mode ($ibMode). Consider upgrading to Single or Multi-segment mode if barriers are deployed." -Remediation $ctrl.Remediation
    }
}

# ── PVW-2.4 Insider Risk Management Policy ───────────────────────────────────
function Test-NRGControlPurviewInsiderRisk {
    [CmdletBinding()] param()
    $cid = 'PVW-2.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    # Insider Risk Management policies are not exposed through the Security &
    # Compliance PowerShell or Graph surfaces this assessment reads. This used
    # to report "InsiderRiskPolicies was not collected" — a collection
    # failure that no re-run could ever fix. Say what it actually is.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — Insider Risk Management policies are not exposed to the APIs this assessment uses. Review them in the Microsoft Purview portal > Insider Risk Management > Policies.' `
        -Remediation $ctrl.Remediation
}

# ── PVW-2.5 Retention Policy Covers Key Workloads ────────────────────────────
function Test-NRGControlPurviewRetention {
    [CmdletBinding()] param()
    $cid = 'PVW-2.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    $retPolicies = @($pvw.Data['RetentionPolicies'] ?? @())
    $coveredWorkloads = @($retPolicies | ForEach-Object { $_.Workloads ?? @() } | Select-Object -Unique)
    $requiredWorkloads = @('Exchange','SharePoint','OneDriveForBusiness','Teams')
    $missing = @($requiredWorkloads | Where-Object { $_ -notin $coveredWorkloads })
    if ($missing.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Retention policies cover all key workloads: $($requiredWorkloads -join ', ')"
    } elseif ($retPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "Retention policies exist but are missing coverage for: $($missing -join ', ')" -CurrentValue "Missing: $($missing -join ', ')" -RequiredValue 'Exchange, SharePoint, OneDrive, Teams all covered'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No retention policies configured. Data cannot be preserved for legal or regulatory requirements.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-2.6 Auto-Labeling Policy Active ──────────────────────────────────────
function Test-NRGControlPurviewAutoLabel {
    [CmdletBinding()] param()
    $cid = 'PVW-2.6'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview label data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $pvw 'AutoLabelPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AutoLabelPolicies was not collected; not assessed.'
        return
    }
    # Mode: Enable (labels content) / TestWith[out]Notifications (simulation:
    # labels nothing) / Disable. Enabled -> Satisfied; simulation only ->
    # Partial, like a report-only CA policy; nothing -> Gap.
    $autoLabels = @($pvw.Data['AutoLabelPolicies'] ?? @())
    $active     = @($autoLabels | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Mode' -Default '') -eq 'Enable' })
    $simulating = @($autoLabels | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Mode' -Default '') -like 'Test*' })
    if ($active.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($active.Count) auto-labeling policy(ies) enforcing. Sensitive content labeled without user action."
    } elseif ($simulating.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($simulating.Count) auto-labeling policy(ies) in simulation mode only — nothing is labeled until the policy is turned on." -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No auto-labeling policy is turned on. Sensitive data classification depends entirely on user action.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-3.1 Audit Logs Exported to SIEM ──────────────────────────────────────
function Test-NRGControlPurviewSIEMExport {
    [CmdletBinding()] param()
    $cid = 'PVW-3.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
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
function Test-NRGControlPurviewEDiscovery {
    [CmdletBinding()] param()
    $cid = 'PVW-3.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    # eDiscovery READINESS (roles assigned, a documented legal-hold workflow)
    # is not measurable from the tenant: a count of cases only says whether
    # there has been litigation. The old detail blamed "IPPSSession not
    # connected" even when it was.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — confirm compliance staff hold the eDiscovery Manager / Administrator role and that the legal-hold workflow is documented. Case counts do not measure readiness.' `
        -Remediation $ctrl.Remediation
}

# ── PVW-3.3 Microsoft Purview Compliance Score Reviewed ──────────────────────
function Test-NRGControlPurviewComplianceScore {
    [CmdletBinding()] param()
    $cid = 'PVW-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — Compliance Manager improvement actions are not exposed to the APIs this assessment uses. Review them at compliance.microsoft.com > Compliance Manager and confirm each is assigned to an owner with a target date.' `
        -Remediation $ctrl.Remediation
}

# ── PVW-3.4 Data Classification Sensitive Info Types Active ──────────────────
function Test-NRGControlPurviewSensitiveInfoTypes {
    [CmdletBinding()] param()
    $cid = 'PVW-3.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Purview label data not collected'; return
    }
    $dlpPolicies = @($pvw.Data['DLPPolicies'] ?? @())
    if ($dlpPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($dlpPolicies.Count) DLP policy(ies) using sensitive information types for detection."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No DLP policies using sensitive information types detected. Sensitive data (SSN, PII, credit cards) is not being classified or protected.' `
            -Remediation $ctrl.Remediation
    }
}

# ── PVW-4.1 Purview Audit (Premium) Enabled ───────────────────────────────────
function Test-NRGControlPurviewAuditPremium {
    [CmdletBinding()] param()
    $cid = 'PVW-4.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $pvw 'AuditConfig')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AuditConfig was not collected; not assessed.'
        return
    }
    # AdvancedAuditEnabled is not a key the collector populates — Get-AdminAuditLogConfig
    # (Collectors/Purview/Invoke-NRGCollectPurview.ps1) only writes
    # UnifiedAuditLogIngestionEnabled / AdminAuditLogEnabled / AdminAuditLogAgeLimit.
    # Defaulting the read to $false made this control score Partial on every
    # tenant regardless of real Audit Premium status. Default to $null instead
    # so "never collected" is distinguishable from a real $false and reported
    # honestly rather than as a confident, uncomputed verdict.
    $premiumRaw = Get-NRGNestedProperty -Object $pvw -Path 'Data.AuditConfig.AdvancedAuditEnabled' -Default $null
    if ($null -eq $premiumRaw) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Purview Audit (Premium) status is not collected by this tool; requires manual verification in the Purview compliance portal.'
        return
    }
    $premiumEnabled = [bool]$premiumRaw
    if ($premiumEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Purview Audit (Premium) is enabled. High-value events including MailItemsAccessed and SearchQueryInitiated are captured.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'Purview Audit (Standard) only. Premium audit events like MailItemsAccessed (required for mail exfil investigations) and SearchQueryInitiated are not captured. Requires E5 or E5 Compliance add-on.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-4.2 Audit Log Retention Extended Beyond 90 Days ──────────────────────
function Test-NRGControlPurviewAuditRetention {
    [CmdletBinding()] param()
    $cid = 'PVW-4.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $pvw 'AuditRetentionPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AuditRetentionPolicies was not collected; not assessed.'
        return
    }
    $retentionPolicies = @($pvw.Data['AuditRetentionPolicies'] ?? @())
    $longTerm = @($retentionPolicies | Where-Object { [int]($_.RetentionDays ?? 0) -ge 365 })
    if ($longTerm.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($longTerm.Count) audit log retention policy(ies) extending logs ≥365 days."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'No audit log retention policy keeps records for a year or more. The default policy applies: 180 days with Audit (Standard); with Audit (Premium), Exchange, SharePoint and Entra records are kept one year and everything else 180 days. Breaches discovered later than that cannot be investigated.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-4.3 Microsoft Purview Sensitivity Labels Published ────────────────────
function Test-NRGControlPurviewLabelsPublished {
    [CmdletBinding()] param()
    $cid = 'PVW-4.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview label data not collected'; return }
    # Empty is not clean: a failed Get-Label left an empty list and this
    # reported "No sensitivity labels configured" (Gap). And LabelPolicies was
    # never collected at all, so any tenant WITH labels read "labels defined
    # but none published" (Partial) — a statement nothing had checked.
    if (-not (Test-NRGSectionCollected $pvw 'SensitivityLabels')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'SensitivityLabels was not collected; not assessed.'
        return
    }
    $labels        = @($pvw.Data['SensitivityLabels'] ?? @())
    if ($labels.Count -gt 0 -and -not (Test-NRGSectionCollected $pvw 'LabelPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "$($labels.Count) sensitivity label(s) defined, but label publishing policies were not collected; whether they are published was not assessed."
        return
    }
    $labelPolicies = @($pvw.Data['LabelPolicies'] ?? @())
    if ($labels.Count -gt 0 -and $labelPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($labels.Count) sensitivity label(s) defined, $($labelPolicies.Count) label policy(ies) published to users."
    } elseif ($labels.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "$($labels.Count) sensitivity label(s) defined but no label policies published. Labels exist but users cannot apply them." -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No sensitivity labels configured. Without labels, data classification is impossible and DLP cannot enforce label-based protection.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-4.4 Records Management Policy Active ─────────────────────────────────
function Test-NRGControlPurviewRecordsManagement {
    [CmdletBinding()] param()
    $cid = 'PVW-4.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $pvw 'RetentionLabels')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'RetentionLabels was not collected; not assessed.'
        return
    }
    $retentionLabels = @($pvw.Data['RetentionLabels'] ?? @())
    $recordLabels    = @($retentionLabels | Where-Object { $_.IsRecordLabel -eq $true })
    if ($recordLabels.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($recordLabels.Count) records management label(s) configured. Immutable records can be declared for regulatory or legal requirements."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No records management labels configured. For regulated environments (government, healthcare, finance) immutable record declarations may be required.' -Remediation $ctrl.Remediation
    }
}
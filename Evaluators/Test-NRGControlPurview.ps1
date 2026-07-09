#Requires -Version 7.0
#
# Test-NRGControlPurview.ps1
# Evaluates Purview controls. Reads: Get-NRGRawData -Key 'Purview'
#
# Controls:
#   PVW-1.1  Unified Audit Log ingestion enabled
#   PVW-1.2  DLP policies active for sensitive information types
#   PVW-1.3  Retention policies configured
#   PVW-1.4  Sensitivity labels published
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
        if ($d.UnifiedAuditEnabled -eq $true) {
            Add-NRGFinding -ControlId 'PVW-1.1' -State 'Satisfied' `
                -Category 'Compliance' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'Unified Audit Log: enabled' `
                -RequiredValue 'UnifiedAuditLogIngestionEnabled = true'
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
    if ($c) {
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
    if ($c) {
        $count = @($d.RetentionPolicies | Where-Object { $_.Enabled -eq $true }).Count
        if ($count -gt 0) {
            Add-NRGFinding -ControlId 'PVW-1.3' -State 'Satisfied' `
                -Category 'Compliance' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "$count retention policies enabled"
        } else {
            Add-NRGFinding -ControlId 'PVW-1.3' -State 'Partial' `
                -Category 'Compliance' -Title $c.Title -Severity 'Low' `
                -Detail 'No active retention policies. Email and document retention is left to user discretion.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.3')
        }
    }

    # PVW-1.4 — Sensitivity labels
    $c = Get-NRGControlById -ControlId 'PVW-1.4'
    if ($c) {
        $count = @($d.SensitivityLabels | Where-Object { $_.IsValid -eq $true }).Count
        if ($count -gt 0) {
            Add-NRGFinding -ControlId 'PVW-1.4' -State 'Satisfied' `
                -Category 'Compliance' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "$count sensitivity labels published"
        } else {
            Add-NRGFinding -ControlId 'PVW-1.4' -State 'Partial' `
                -Category 'Compliance' -Title $c.Title -Severity 'Low' `
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
    $policies = @($pvw.Data['CommCompliancePolicies'] ?? @())
    if ($policies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($policies.Count) communication compliance policy(ies) active."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'No communication compliance policies configured. Required for regulatory environments (finance, healthcare, government). Requires E5 Compliance.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-2.3 Information Barriers Mode ────────────────────────────────────────
function Test-NRGControlPurviewInfoBarriers {
    [CmdletBinding()] param()
    $cid = 'PVW-2.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
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
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return }
    $irPolicies = @($pvw.Data['InsiderRiskPolicies'] ?? @())
    if ($irPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($irPolicies.Count) insider risk management policy(ies) active."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'No insider risk management policies configured. Data theft by departing employees and policy violations go undetected. Requires E5 Compliance.' -Remediation $ctrl.Remediation
    }
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
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "Retention policies exist but missing coverage for: $($missing -join ', ')" -CurrentValue "Missing: $($missing -join ', ')" -RequiredValue 'Exchange, SharePoint, OneDrive, Teams all covered'
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
    $autoLabels = @($pvw.Data['AutoLabelPolicies'] ?? @())
    if ($autoLabels.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($autoLabels.Count) auto-labeling policy(ies) active. Sensitive content labeled without user action."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'No auto-labeling policies configured. Sensitive data classification depends entirely on user action.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-3.1 Audit Logs Exported to SIEM ──────────────────────────────────────
# v4.6.4 ADVISORY MARK: no programmatic check, manual review required.
function Test-NRGControlPurviewSIEMExport {
    [CmdletBinding()] param()
    $cid = 'PVW-3.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Medium' -FrameworkIds $cit `
        -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). Audit log SIEM export status cannot be determined via Graph API alone. Verify via Purview > Audit > Export settings or Microsoft Sentinel connector status.' `
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
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Purview data not collected'; return
    }
    $cases = Get-NRGNestedProperty -Object $pvw -Path 'Data.EDiscoveryCases' -Default $null
    if ($null -eq $cases) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'eDiscovery case inventory not collected (IPPSSession not connected or Get-ComplianceCase unavailable). Verify manually via compliance.microsoft.com > eDiscovery.'
        return
    }
    $caseCount = @($cases).Count
    if ($caseCount -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$caseCount eDiscovery case(s) configured — case management capability is in use. Verify eDiscovery roles are assigned to appropriate compliance personnel."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail 'No eDiscovery cases configured. Legal hold and investigation workflows have never been exercised — confirm the workflow is documented and that compliance personnel hold the eDiscovery Manager / Administrator role.' `
            -Remediation $ctrl.Remediation
    }
}

# ── PVW-3.3 Microsoft Purview Compliance Score Reviewed ──────────────────────
# v4.6.4 ADVISORY MARK: no programmatic check, manual review required.
function Test-NRGControlPurviewComplianceScore {
    [CmdletBinding()] param()
    $cid = 'PVW-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). Compliance Score requires manual review at compliance.microsoft.com > Compliance Manager. Verify improvement actions are assigned and tracked.' `
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
    $premiumEnabled = [bool](Get-NRGNestedProperty -Object $pvw -Path 'Data.AuditConfig.AdvancedAuditEnabled' -Default $false)
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
    $retentionPolicies = @($pvw.Data['AuditRetentionPolicies'] ?? @())
    $longTerm = @($retentionPolicies | Where-Object { [int]($_.RetentionDays ?? 0) -ge 365 })
    if ($longTerm.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($longTerm.Count) audit log retention policy(ies) extending logs ≥365 days."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'No audit log retention policy extending beyond 90 days found. Default retention is 90 days. Breaches discovered weeks or months later cannot be investigated. Requires Audit Premium or custom retention policy.' -Remediation $ctrl.Remediation
    }
}

# ── PVW-4.3 Microsoft Purview Sensitivity Labels Published ────────────────────
function Test-NRGControlPurviewLabelsPublished {
    [CmdletBinding()] param()
    $cid = 'PVW-4.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview label data not collected'; return }
    $labels        = @($pvw.Data['SensitivityLabels'] ?? @())
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
    $retentionLabels = @($pvw.Data['RetentionLabels'] ?? @())
    $recordLabels    = @($retentionLabels | Where-Object { $_.IsRecordLabel -eq $true })
    if ($recordLabels.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($recordLabels.Count) records management label(s) configured. Immutable records can be declared for regulatory or legal requirements."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'No records management labels configured. For regulated environments (government, healthcare, finance) immutable record declarations may be required.' -Remediation $ctrl.Remediation
    }
}
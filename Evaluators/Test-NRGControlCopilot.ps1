#Requires -Version 7.0
#
# Test-NRGControlCopilot.ps1  (v4.5.5)
# Evaluators for Microsoft 365 Copilot and AI governance controls.
# This is an emerging area — these controls represent the current state
# of what can be assessed via Graph API and PowerShell as of early 2026.
#
# Workload: PPL (Power Platform umbrella covers Copilot Studio)
# New workload prefix: AI for Microsoft 365 Copilot specific controls
#

# ── AI-1.1 Microsoft 365 Copilot Sensitivity Label Enforcement ───────────────
function Test-NRGControlAICopilotSensitivityLabels {
    [CmdletBinding()] param()
    $cid = 'PPL-3.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview-Labels'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return
    }
    $labels = @($pvw.Data.SensitivityLabels ?? @())
    $copilotEnabled = @($labels | Where-Object { $_.Scope -contains 'AIPFile' -or $_.ScopeTypes -contains 'AIPFiles' }).Count -gt 0
    if ($labels.Count -gt 0 -and $copilotEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Sensitivity labels with file scope configured — M365 Copilot respects these labels when accessing data. $($labels.Count) label(s) active."
    } elseif ($labels.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'Sensitivity labels exist but may not be scoped to protect files from Copilot over-sharing. Verify labels include file/email scope and are applied to sensitive data.' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No sensitivity labels configured. Microsoft 365 Copilot can access and summarize any file the user can access — including files they may not realize are sensitive. Without labels, there is no boundary enforcement.' -Remediation $ctrl.Remediation
    }
}

# ── AI-1.2 Copilot DLP Policy Active ─────────────────────────────────────────
function Test-NRGControlAICopilotDLP {
    [CmdletBinding()] param()
    $cid = 'PPL-3.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview-Labels'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return
    }
    $dlpPolicies = @($pvw.Data.DLPPolicies ?? @())
    $copilotDLP  = @($dlpPolicies | Where-Object {
        $_.Workloads -contains 'Copilot' -or $_.Name -match 'Copilot|AI'
    })
    if ($copilotDLP.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($copilotDLP.Count) DLP policy(ies) targeting Copilot interactions found."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'No DLP policies specifically targeting Microsoft 365 Copilot interactions detected. Users can prompt Copilot to summarize, extract, or transmit sensitive data without policy controls. Verify in Purview > DLP > Copilot location.' -Remediation $ctrl.Remediation
    }
}

# ── AI-1.3 Copilot Enabled Only for Licensed Users ────────────────────────────
function Test-NRGControlAICopilotLicensedOnly {
    [CmdletBinding()] param()
    $cid = 'PPL-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    $copilotPolicy = $auth.Data.CopilotPolicy ?? $null
    if ($copilotPolicy) {
        $controlled = [bool]($copilotPolicy.IsEnabledForLicensedUsersOnly ?? $false)
        if ($controlled) {
            Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Microsoft 365 Copilot access is restricted to licensed users only.'
            return
        }
    }
    Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'Copilot license assignment control requires manual verification: M365 Admin Center > Settings > Copilot > Control which users have access. Ensure Copilot is not enabled for users without a Copilot license.' -Remediation $ctrl.Remediation
}

# ── AI-1.4 Copilot Studio Agent Data Governance ───────────────────────────────
function Test-NRGControlAICopilotStudio {
    [CmdletBinding()] param()
    $cid = 'PPL-3.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ppl = Get-NRGRawData -Key 'PowerPlatform-TenantSettings'
    if (-not $ppl -or -not $ppl.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Power Platform data not collected'; return
    }
    $copilotStudioPolicy = $ppl.Data.TenantSettings.DisableCopilotStudioPublishing ?? $null
    if ($null -ne $copilotStudioPolicy -and -not $copilotStudioPolicy) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'High' -FrameworkIds $cit -Detail 'Copilot Studio publishing is not restricted. Any user can build and publish agents that connect to organizational data sources, Microsoft Graph, and third-party services — with no admin approval or DLP controls required.' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'Copilot Studio governance requires manual verification: Power Platform Admin Center > Copilot Studio > Policies. Verify agent publishing requires admin approval and connectors are governed by DLP policies.' -Remediation $ctrl.Remediation
    }
}

# ── AI-1.5 Microsoft 365 Copilot Interaction History Not Stored Externally ────
function Test-NRGControlAICopilotInteractionData {
    [CmdletBinding()] param()
    $cid = 'PPL-3.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    # Copilot interaction data (prompts + responses) storage is a compliance concern
    # Purview Content Explorer can search Copilot interactions — proxy check
    $pvw = Get-NRGRawData -Key 'Purview-AuditConfig'
    if (-not $pvw -or -not $pvw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return
    }
    $auditEnabled = [bool]($pvw.Data.AuditConfig.UnifiedAuditLogIngestionEnabled ?? $false)
    if ($auditEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Unified audit log is active — Copilot interactions are captured in the audit log and searchable via Purview Content Explorer for compliance and eDiscovery purposes.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Audit logging disabled — Copilot prompts and responses are not being captured. Compliance investigations involving Copilot usage cannot be conducted.' -Remediation $ctrl.Remediation
    }
}

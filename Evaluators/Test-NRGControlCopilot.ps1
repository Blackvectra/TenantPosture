#Requires -Version 7.0
#
# Test-NRGControlCopilot.ps1  (v4.6.1)
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Evaluators for Microsoft 365 Copilot and AI governance controls.
# Reads raw data set by Invoke-NRGCollectM365Copilot (key 'M365Copilot').
#
# Controls evaluated:
#   PPL-3.1  M365 Copilot Sensitivity Label Enforcement
#   PPL-3.2  DLP Policy Active for Copilot Interactions
#   PPL-3.3  Copilot Access Restricted to Licensed Users
#   PPL-3.4  Copilot Studio Agent Publishing Governed
#   PPL-3.5  Copilot Interaction Audit Logging Active
#
# Each function follows the standard NRG evaluator contract:
#   1) Resolve control via Get-NRGControlById; bail if missing.
#   2) Read raw data via Get-NRGRawData -Key 'M365Copilot'.
#   3) If raw data missing or unsuccessful, register NotApplicable and return.
#   4) Decide State; call Add-NRGFinding with full param block including FrameworkIds.
#
# NIST SP 800-53: AC-3 (access enforcement), AC-16 (security attributes),
#                 AU-2 (event logging), SC-28 (info-at-rest protection)
# MITRE ATT&CK:   T1530 (data from cloud storage), T1005 (data from local system)
#

# Helper: safe read of nested raw-data property
function script:Get-NRGCopilotRaw {
    $raw = $null
    if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) {
        $raw = Get-NRGRawData -Key 'M365Copilot'
    }
    return $raw
}

# Helper: was Purview raw data actually collected? PPL-3.2 (DLP) and PPL-3.5
# (audit) have NO Graph fallback — Invoke-NRGCollectM365Copilot sources both
# exclusively from the Purview/IPPS collector, and Purview is skipped by
# default while the Copilot collector always runs. An empty DLP list or a
# disabled audit flag with Purview absent means "not evaluated", not "no
# coverage" — check the Purview raw data directly rather than scoring it.
function script:Test-NRGCopilotPurviewCollected {
    if (-not (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue)) { return $false }
    $purviewRaw = Get-NRGRawData -Key 'Purview'
    return [bool]($purviewRaw -and $purviewRaw.Success)
}

# ── PPL-3.1  M365 Copilot Sensitivity Label Enforcement ──────────────────────
function Test-NRGControlAICopilotSensitivityLabels {
    [CmdletBinding()] param()
    $cid = 'PPL-3.1'
    $ctrl = Get-NRGControlById -ControlId $cid
    if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $raw = Get-NRGCopilotRaw
    if (-not $raw -or -not $raw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'M365Copilot collector did not run successfully.'
        return
    }

    $d = $raw.Data
    $licensed = [int]($d.CopilotLicensedUserCount ?? 0)

    if ($licensed -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No Microsoft 365 Copilot licenses detected — sensitivity label enforcement for Copilot is not applicable to this tenant.'
        return
    }

    $labelsEnabled  = [bool]($d.SensitivityLabelsEnabled ?? $false)
    $labelCount     = [int]($d.SensitivityLabelCount ?? 0)
    $autoLabel      = [bool]($d.AutoLabelPoliciesEnabled ?? $false)

    if ($labelsEnabled -and $labelCount -gt 0 -and $autoLabel) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
            -FrameworkIds $cit `
            -CurrentValue "Labels: $labelCount; Auto-label policies: enabled" `
            -RequiredValue 'Sensitivity labels published with auto-labeling for sensitive data' `
            -Detail "Sensitivity labels are configured ($labelCount label(s)) and auto-labeling policies are enabled — Microsoft 365 Copilot will respect these classification boundaries when accessing and summarizing content."
    } elseif ($labelsEnabled -and $labelCount -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' `
            -FrameworkIds $cit `
            -CurrentValue "Labels: $labelCount; Auto-label policies: disabled" `
            -RequiredValue 'Auto-labeling policies active so unlabeled-but-sensitive content is still suppressed' `
            -Detail "Sensitivity labels exist ($labelCount) but no auto-labeling policy is active. Users must manually classify content; Copilot can surface sensitive files that were never labeled." `
            -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
            -FrameworkIds $cit `
            -CurrentValue 'No sensitivity labels configured' `
            -RequiredValue 'Sensitivity labels with Files & emails scope + auto-labeling' `
            -Detail "Copilot is licensed to $licensed user(s) but no sensitivity labels are configured. Copilot can surface any document the user can access — HR, financial, contractual — with no label-based suppression. Over-sharing risk is materially amplified." `
            -Remediation $ctrl.Remediation
    }
}

# ── PPL-3.2  Copilot DLP Policy Active ────────────────────────────────────────
function Test-NRGControlAICopilotDLP {
    [CmdletBinding()] param()
    $cid = 'PPL-3.2'
    $ctrl = Get-NRGControlById -ControlId $cid
    if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $raw = Get-NRGCopilotRaw
    if (-not $raw -or -not $raw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'M365Copilot collector did not run successfully.'
        return
    }

    $d = $raw.Data
    $licensed = [int]($d.CopilotLicensedUserCount ?? 0)

    if ($licensed -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No Copilot licenses detected — DLP coverage of Copilot interactions is not applicable.'
        return
    }

    $dlp = @($d.CopilotDLPPolicies ?? @())
    $locs = @($d.CopilotDLPLocations ?? @())
    $copilotInLocs = ($locs -contains 'Copilot') -or
                     ($locs -contains 'M365Copilot') -or
                     ($locs -contains 'CopilotExperiences')

    if ($dlp.Count -gt 0 -and $copilotInLocs) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
            -FrameworkIds $cit `
            -CurrentValue "$($dlp.Count) DLP policy(ies) cover Copilot workload" `
            -RequiredValue 'At least one enabled DLP policy with Copilot location included' `
            -Detail "DLP coverage detected for Microsoft 365 Copilot interactions ($($dlp.Count) policy/policies). Sensitive-information types in prompts and responses are subject to policy controls."
    } elseif ($dlp.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' `
            -FrameworkIds $cit `
            -CurrentValue "$($dlp.Count) DLP policy(ies) reference Copilot but Copilot location not confirmed" `
            -RequiredValue 'DLP policy with Locations explicitly including Microsoft 365 Copilot' `
            -Detail "DLP policies referencing Copilot were found ($($dlp.Count)) but the Copilot location is not in the confirmed workload set. Verify in Purview > DLP > Policy > Locations that Microsoft 365 Copilot is included." `
            -Remediation $ctrl.Remediation
    } elseif (-not (Test-NRGCopilotPurviewCollected)) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -FrameworkIds $cit `
            -Detail "Copilot is licensed to $licensed user(s) but DLP coverage could not be evaluated — the Purview/IPPS session did not collect data (there is no Graph fallback for Copilot DLP policies). Run the assessment with Purview included to verify DLP coverage for Copilot interactions."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
            -FrameworkIds $cit `
            -CurrentValue 'No DLP policies cover Copilot' `
            -RequiredValue 'DLP policy with Copilot location enabled' `
            -Detail "Copilot is licensed to $licensed user(s) but no DLP policy covers Copilot interactions. Users can prompt Copilot to summarize, translate, or reformat sensitive data — bypassing every other data control." `
            -Remediation $ctrl.Remediation
    }
}

# ── PPL-3.3  Copilot Enabled Only for Licensed Users ──────────────────────────
function Test-NRGControlAICopilotLicensedOnly {
    [CmdletBinding()] param()
    $cid = 'PPL-3.3'
    $ctrl = Get-NRGControlById -ControlId $cid
    if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $raw = Get-NRGCopilotRaw
    if (-not $raw -or -not $raw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'M365Copilot collector did not run successfully.'
        return
    }

    $d = $raw.Data
    $licensed = [int]($d.CopilotLicensedUserCount ?? 0)
    $total    = [int]($d.TotalUserCount ?? 0)
    $skus     = @($d.LicensedSkus ?? @())

    if ($skus.Count -eq 0 -and $licensed -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No Copilot SKUs visible — licensing posture cannot be evaluated.'
        return
    }

    # Judgment call: M365 Copilot is licensed per-user, not tenant-wide, so the
    # platform guarantees licensed-only access at the entitlement layer. What we
    # CAN check is whether the assignment looks intentional (subset of users) vs.
    # blanket (every user has a Copilot SKU — which usually indicates lack of
    # governance review).
    if ($total -gt 0) {
        $ratio = if ($total -gt 0) { [double]$licensed / [double]$total } else { 0.0 }

        if ($licensed -eq 0) {
            Add-NRGFinding -ControlId $cid -State 'Satisfied' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
                -FrameworkIds $cit `
                -CurrentValue "0 of $total users licensed" `
                -RequiredValue 'Copilot license assigned only to approved users' `
                -Detail 'No users currently have a Copilot license. Platform-enforced licensing means no user can invoke Copilot.'
        } elseif ($ratio -ge 0.95) {
            Add-NRGFinding -ControlId $cid -State 'Partial' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' `
                -FrameworkIds $cit `
                -CurrentValue "$licensed of $total users licensed ($([math]::Round($ratio * 100,1))%)" `
                -RequiredValue 'Group-based or PIM-time-bound assignment with documented business need' `
                -Detail "Copilot is licensed for $licensed of $total users — effectively the entire tenant. This pattern usually indicates blanket assignment without per-user governance review. Confirm via Entra ID > Groups > license assignment whether Copilot is gated by an approval group." `
                -Remediation $ctrl.Remediation
        } else {
            Add-NRGFinding -ControlId $cid -State 'Satisfied' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
                -FrameworkIds $cit `
                -CurrentValue "$licensed of $total users licensed ($([math]::Round($ratio * 100,1))%)" `
                -RequiredValue 'Copilot licensing scoped to a subset of users' `
                -Detail "Copilot is scoped to $licensed of $total users — licensing is bounded rather than blanket-assigned. Verify the assignment group reflects documented business need."
        }
    } else {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'User count could not be determined — licensing posture cannot be evaluated.'
    }
}

# ── PPL-3.4  Copilot Studio Agent Publishing Governed ─────────────────────────
function Test-NRGControlAICopilotStudio {
    [CmdletBinding()] param()
    $cid = 'PPL-3.4'
    $ctrl = Get-NRGControlById -ControlId $cid
    if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $raw = Get-NRGCopilotRaw
    if (-not $raw -or -not $raw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'M365Copilot collector did not run successfully.'
        return
    }

    $d = $raw.Data
    $bots = @($d.CopilotStudioBots ?? @())
    $extPub = [bool]($d.ExternalPublishingEnabled ?? $false)

    if ($bots.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No Copilot Studio bots detected via Graph application enumeration. Power Platform admin APIs may not be accessible to the assessment principal; verify manually in Power Platform Admin Center > Copilot Studio if bots are present.'
        return
    }

    if ($extPub) {
        $externalBots = @($bots | Where-Object {
            $_.PublisherDomain -and $_.PublisherDomain -notmatch 'onmicrosoft\.com$'
        })
        Add-NRGFinding -ControlId $cid -State 'Gap' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
            -FrameworkIds $cit `
            -CurrentValue "$($externalBots.Count) of $($bots.Count) bot(s) appear to allow external publishing" `
            -RequiredValue 'All Copilot Studio bots internal-only; external publishing disabled by tenant policy' `
            -Detail "External publishing is enabled at the tenant level for Copilot Studio, and $($externalBots.Count) of $($bots.Count) detected agent(s) carry a non-tenant publisher domain. External publishing means anyone on the internet can interact with the agent. In most environments this indicates unintended exposure of an agent connected to SharePoint, Microsoft Graph, or a third-party service." `
            -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
            -FrameworkIds $cit `
            -CurrentValue "$($bots.Count) Copilot Studio bot(s) detected, all internal-only" `
            -RequiredValue 'Internal-only Copilot Studio publishing' `
            -Detail "$($bots.Count) Copilot Studio bot(s) detected. No external publisher domains observed in the Graph applications inventory."
    }
}

# ── PPL-3.5  Copilot Interaction Audit Logging Active ─────────────────────────
function Test-NRGControlAICopilotInteractionData {
    [CmdletBinding()] param()
    $cid = 'PPL-3.5'
    $ctrl = Get-NRGControlById -ControlId $cid
    if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    $raw = Get-NRGCopilotRaw
    if (-not $raw -or -not $raw.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'M365Copilot collector did not run successfully.'
        return
    }

    $d = $raw.Data
    $licensed = [int]($d.CopilotLicensedUserCount ?? 0)

    if ($licensed -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No Copilot licenses detected — interaction audit applicability is not yet relevant.'
        return
    }

    $auditRaw = Get-NRGObjectField -Item $d -Key 'AuditCopilotEnabled'
    $audit = [bool]$auditRaw
    $retention = $d.CopilotInteractionRetention

    if ($null -eq $auditRaw -and (Test-NRGCopilotPurviewCollected)) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -FrameworkIds $cit `
            -Detail 'Unified Audit Log status could not be read from the Exchange Online session (Security & Compliance PowerShell always reports it as off), so Copilot interaction auditing is not assessed. Verify in Purview > Audit.'
    } elseif (-not $audit -and -not (Test-NRGCopilotPurviewCollected)) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -FrameworkIds $cit `
            -Detail "Copilot is licensed to $licensed user(s) but Unified Audit Log status for Copilot interactions could not be evaluated — the Purview/IPPS session did not collect data. Run the assessment with Purview included to verify Copilot audit logging."
    } elseif (-not $audit) {
        Add-NRGFinding -ControlId $cid -State 'Gap' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
            -FrameworkIds $cit `
            -CurrentValue 'Unified Audit Log ingestion disabled' `
            -RequiredValue 'Unified Audit Log enabled; Copilot prompts and responses recorded' `
            -Detail 'Copilot prompts and responses are not being captured. An insider using Copilot to extract sensitive data leaves no audit trail — compliance investigations involving Copilot usage cannot be reconstructed.' `
            -Remediation $ctrl.Remediation
    } elseif ($null -eq $retention -or [string]$retention -eq '') {
        Add-NRGFinding -ControlId $cid -State 'Partial' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' `
            -FrameworkIds $cit `
            -CurrentValue 'Audit enabled; no explicit Copilot retention policy' `
            -RequiredValue 'Audit enabled plus a retention policy covering Copilot interactions' `
            -Detail 'Unified audit logging is active so Copilot interactions are recorded — but no Purview retention policy explicitly covers Copilot. Platform-default retention (~180 days for E3, longer for E5 Audit Premium) may not meet legal-hold or regulated-industry requirements.' `
            -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
            -FrameworkIds $cit `
            -CurrentValue 'Audit enabled; explicit Copilot retention policy in place' `
            -RequiredValue 'Audit enabled + retention policy covering Copilot' `
            -Detail 'Unified audit logging is active and a retention policy covers Copilot interactions. Prompts/responses are searchable in Purview Content Explorer and Audit Search for compliance and eDiscovery.'
    }
}

#Requires -Version 7.0
#
# Test-TPControlCopilot.ps1  (v4.6.1)
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: Evaluators for Microsoft 365 Copilot and AI governance controls.
# Reads raw data set by Invoke-TPCollectM365Copilot (key 'M365Copilot').
#
# Controls evaluated:
#   PPL-3.1  M365 Copilot Sensitivity Label Enforcement
#   PPL-3.2  DLP Policy Active for Copilot Interactions
#   PPL-3.3  Copilot Access Restricted to Licensed Users
#   PPL-3.4  Copilot Studio Agent Publishing Governed
#   PPL-3.5  Copilot Interaction Audit Logging Active
#
# Each function follows the standard NRG evaluator contract:
#   1) Resolve control via Get-TPControlById; bail if missing.
#   2) Read raw data via Get-TPRawData -Key 'M365Copilot'.
#   3) If raw data missing or unsuccessful, register NotApplicable and return.
#   4) Decide State; call Add-TPFinding with full param block including FrameworkIds.
#
# NIST SP 800-53: AC-3 (access enforcement), AC-16 (security attributes),
#                 AU-2 (event logging), SC-28 (info-at-rest protection)
# MITRE ATT&CK:   T1530 (data from cloud storage), T1005 (data from local system)
#

# Helper: safe read of nested raw-data property
function script:Get-TPCopilotRaw {
    $raw = $null
    if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) {
        $raw = Get-TPRawData -Key 'M365Copilot'
    }
    return $raw
}

# Helper: was Purview raw data actually collected? PPL-3.2 (DLP) and PPL-3.5
# (audit) have NO Graph fallback — Invoke-TPCollectM365Copilot sources both
# exclusively from the Purview/IPPS collector, and Purview is skipped by
# default while the Copilot collector always runs. An empty DLP list or a
# disabled audit flag with Purview absent means "not evaluated", not "no
# coverage" — check the Purview raw data directly rather than scoring it.
# A Purview SECTION was read (not merely the collector ran): an empty list
# from a section that never ran is not "none configured".
function script:Test-TPCopilotPurviewSection {
    param([string] $Section)
    if (-not (Get-Command Get-TPRawData -ErrorAction SilentlyContinue)) { return $false }
    $p = Get-TPRawData -Key 'Purview'
    return [bool]($p -and $p.Success -and (Test-TPSectionCollected $p $Section))
}

function script:Test-TPCopilotPurviewCollected {
    if (-not (Get-Command Get-TPRawData -ErrorAction SilentlyContinue)) { return $false }
    $purviewRaw = Get-TPRawData -Key 'Purview'
    return [bool]($purviewRaw -and $purviewRaw.Success)
}

# ── PPL-3.1  M365 Copilot Sensitivity Label Enforcement ──────────────────────
function Test-TPControlAICopilotSensitivityLabels {
    [CmdletBinding()] param()
    $cid = 'PPL-3.1'
    $ctrl = Get-TPControlById -ControlId $cid
    if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid

    $raw = Get-TPCopilotRaw
    if (-not $raw -or -not $raw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'M365Copilot collector did not run successfully.'
        return
    }

    $d = $raw.Data
    $licensed = [int]($d.CopilotLicensedUserCount ?? 0)

    if ($licensed -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No Microsoft 365 Copilot licenses detected — sensitivity label enforcement for Copilot is not applicable to this tenant.'
        return
    }

    # Labels were read from Purview (section collected) or the Graph fallback;
    # otherwise "no sensitivity labels" is unknown, not a Gap.
    if (-not (Test-TPCopilotPurviewSection 'SensitivityLabels') -and (Get-TPObjectField -Item $d -Key 'LabelsRead' -Default $false) -ne $true) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Copilot is licensed to $licensed user(s), but sensitivity labels were not collected (Purview section not read and the Graph fallback failed); not assessed."
        return
    }
    $labelsEnabled  = [bool]($d.SensitivityLabelsEnabled ?? $false)
    $labelCount     = [int]($d.SensitivityLabelCount ?? 0)
    $autoLabel      = [bool]($d.AutoLabelPoliciesEnabled ?? $false)
    # $true: the auto-labeling read happened and judged Enabled beside Mode. $false: it did not
    # happen or failed. $null: a results file from before the flag, whose AutoLabelPoliciesEnabled
    # judged Mode only, so a policy turned off could have counted.
    $autoRead       = Get-TPObjectField -Item $d -Key 'AutoLabelPoliciesRead' -Default $null

    if ($labelsEnabled -and $labelCount -gt 0 -and ($autoRead -eq $false -or ($autoLabel -and $autoRead -ne $true))) {
        $why = if ($autoRead -eq $false) { 'auto-labeling policies were not read (Get-AutoSensitivityLabelPolicy was unavailable or failed)' } else { 'this results file predates the read of each auto-labeling policy''s Enabled flag, so a policy in Mode Enable that is turned off could have counted' }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -RequiredValue 'Sensitivity labels published with an auto-labeling policy turned on (Enabled True) in Mode Enable' `
            -Detail "Sensitivity labels are configured ($labelCount label(s)), but $why; auto-labeling not assessed."
        return
    }

    if ($labelsEnabled -and $labelCount -gt 0 -and $autoLabel) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
            -FrameworkIds $cit `
            -CurrentValue "Labels: $labelCount; Auto-label policies: enabled" `
            -RequiredValue 'Sensitivity labels published with an auto-labeling policy turned on (Enabled True) in Mode Enable' `
            -Detail "Sensitivity labels are configured ($labelCount label(s)) and an auto-labeling policy is turned on and enforcing (Enabled True, Mode Enable) — Microsoft 365 Copilot will respect these classification boundaries when accessing and summarizing content."
    } elseif ($labelsEnabled -and $labelCount -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' `
            -FrameworkIds $cit `
            -CurrentValue "Labels: $labelCount; Auto-label policies: disabled" `
            -RequiredValue 'Auto-labeling policies active so unlabeled-but-sensitive content is still suppressed' `
            -Detail "Sensitivity labels exist ($labelCount) but no auto-labeling policy is turned on and enforcing (Enabled True, Mode Enable). Users must manually classify content; Copilot can surface sensitive files that were never labeled." `
            -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
            -FrameworkIds $cit `
            -CurrentValue 'No sensitivity labels configured' `
            -RequiredValue 'Sensitivity labels with Files & emails scope + auto-labeling' `
            -Detail "Copilot is licensed to $licensed user(s) but no sensitivity labels are configured. Copilot can surface any document the user can access — HR, financial, contractual — with no label-based suppression. Over-sharing risk is materially amplified." `
            -Remediation $ctrl.Remediation
    }
}

# ── PPL-3.2  Copilot DLP Policy Active ────────────────────────────────────────
function Test-TPControlAICopilotDLP {
    [CmdletBinding()] param()
    $cid = 'PPL-3.2'
    $ctrl = Get-TPControlById -ControlId $cid
    if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid

    $raw = Get-TPCopilotRaw
    if (-not $raw -or -not $raw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'M365Copilot collector did not run successfully.'
        return
    }

    $d = $raw.Data
    $licensed = [int]($d.CopilotLicensedUserCount ?? 0)

    if ($licensed -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No Copilot licenses detected — DLP coverage of Copilot interactions is not applicable.'
        return
    }

    # Judged from the Purview DLP policies and rules directly. A policy is scoped to Microsoft 365
    # Copilot only when its EnforcementPlanes name CopilotExperiences (the plane Microsoft's Copilot
    # policy carries: New-DlpCompliancePolicy, example 4); a policy NAME proves nothing, and the
    # 'Applications' workload is the location type, not the Copilot location itself. Only an
    # enforcing policy (Mode Enable) with an enabled rule counts (Get-TPDlpRuleStates), as DEF-4.5.
    if (-not (Test-TPCopilotPurviewSection 'DLPPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -FrameworkIds $cit `
            -Detail "Copilot is licensed to $licensed user(s) but DLP coverage could not be evaluated — the Purview/IPPS session did not collect data (there is no Graph fallback for Copilot DLP policies). Run the assessment with Purview included to verify DLP coverage for Copilot interactions."
        return
    }
    $pvd = (Get-TPRawData -Key 'Purview').Data
    $policies = @(@(Get-TPObjectField -Item $pvd -Key 'DLPPolicies' -Default @()) | Where-Object { $null -ne $_ })
    $nameOf = { param($p) [string](Get-TPObjectField -Item $p -Key 'Name' -Default '') }
    $copilot = @(); $unconfirmed = @()
    foreach ($p in $policies) {
        $planesRead = (Get-TPObjectField -Item $p -Key 'PlanesRead' -Default $false) -eq $true
        $planes = @(@(Get-TPObjectField -Item $p -Key 'EnforcementPlanes' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $wl = @(@(Get-TPObjectField -Item $p -Key 'Workloads' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        if ($planes -contains 'CopilotExperiences') { $copilot += $p }
        elseif (-not $planesRead -and ((@($wl | Where-Object { $_ -in @('Applications', 'Copilot', 'M365Copilot', 'CopilotExperiences') }).Count -gt 0) -or (& $nameOf $p) -match '\bCopilot\b')) { $unconfirmed += $p }
    }
    $req = 'An enforcing DLP policy (Mode Enable) scoped to the Microsoft 365 Copilot and Copilot Chat location, with at least one enabled rule'
    if ($copilot.Count -eq 0 -and $unconfirmed.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
            -FrameworkIds $cit `
            -CurrentValue 'No DLP policies cover Copilot' `
            -RequiredValue $req `
            -Detail "Copilot is licensed to $licensed user(s) but no DLP policy is scoped to the Microsoft 365 Copilot location. Users can prompt Copilot to summarize, translate, or reformat sensitive data — bypassing every other data control." `
            -Remediation $ctrl.Remediation
        return
    }
    if (-not (Test-TPCopilotPurviewSection 'DLPRules')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -RequiredValue $req `
            -Detail "DLP rules were not collected, so whether the Copilot DLP policy(ies) ($(@(($copilot + $unconfirmed) | ForEach-Object { & $nameOf $_ } | Select-Object -First 5) -join ', ')) have an enabled rule was not assessed."
        return
    }
    $rules = @(Get-TPDlpRuleStates -Policies $policies -Rules @(@(Get-TPObjectField -Item $pvd -Key 'DLPRules' -Default @()) | Where-Object { $null -ne $_ }))
    $stateOf = { param($p, $st) @($rules | Where-Object { $_.Policy -eq (& $nameOf $p) -and $_.State -eq $st }) }
    $enforcing = @($copilot | Where-Object { @(& $stateOf $_ 'Enforcing').Count -gt 0 })
    # Simulation (TestWith*) is part-way, as the not-configured rule allows; Disable and
    # PendingDeletion are turned off and fall to the Gap below.
    $testMode  = @($copilot | Where-Object { @(& $stateOf $_ 'TestMode' | Where-Object { [string]$_.PolicyMode -like 'Test*' }).Count -gt 0 })
    $unknown   = @($copilot | Where-Object { @(& $stateOf $_ 'Unknown').Count -gt 0 })
    $names = { param($l) (@($l | ForEach-Object { & $nameOf $_ } | Select-Object -First 5) -join ', ') }
    if ($enforcing.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
            -FrameworkIds $cit `
            -CurrentValue "Enforcing Copilot DLP policy(ies): $(& $names $enforcing)" `
            -RequiredValue $req `
            -Detail "An enforcing DLP policy scoped to Microsoft 365 Copilot (EnforcementPlanes CopilotExperiences, Mode Enable) has an enabled rule: $(& $names $enforcing). What each rule restricts (sensitive information types in prompts, labeled content) is not judged here."
    } elseif ($unknown.Count -gt 0 -or ($copilot.Count -eq 0 -and $unconfirmed.Count -gt 0)) {
        $why = if ($unknown.Count -gt 0) { "the Mode of Copilot DLP policy(ies) $(& $names $unknown) was not read or not recognized" } else { "the policies' EnforcementPlanes were not returned, so whether $(& $names $unconfirmed) is scoped to the Microsoft 365 Copilot location (and not another Applications location) could not be confirmed; a policy name or the Applications workload alone is not the Copilot location" }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -RequiredValue $req `
            -Detail "Copilot DLP coverage not assessed: $why."
    } elseif ($testMode.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' `
            -FrameworkIds $cit `
            -CurrentValue "Copilot DLP policy(ies) in test mode: $(& $names $testMode)" `
            -RequiredValue $req `
            -Detail "DLP policy(ies) scoped to Microsoft 365 Copilot exist but none enforces: $(& $names $testMode) is in test mode (simulation), so Copilot prompts and responses are monitored, not restricted." `
            -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
            -FrameworkIds $cit `
            -CurrentValue "Copilot DLP policy(ies) turned off or with no enabled rule: $(& $names $copilot)" `
            -RequiredValue $req `
            -Detail "DLP policy(ies) scoped to Microsoft 365 Copilot exist ($(& $names $copilot)) but none is enforcing with an enabled rule (turned off, pending deletion, or every rule disabled), so nothing is restricted." `
            -Remediation $ctrl.Remediation
    }
}

# ── PPL-3.3  Copilot Enabled Only for Licensed Users ──────────────────────────
function Test-TPControlAICopilotLicensedOnly {
    [CmdletBinding()] param()
    $cid = 'PPL-3.3'
    $ctrl = Get-TPControlById -ControlId $cid
    if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid

    $raw = Get-TPCopilotRaw
    if (-not $raw -or -not $raw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'M365Copilot collector did not run successfully.'
        return
    }

    $d = $raw.Data
    $licensed = [int]($d.CopilotLicensedUserCount ?? 0)
    $total    = [int]($d.TotalUserCount ?? 0)
    $skus     = @($d.LicensedSkus ?? @())

    if ($skus.Count -eq 0 -and $licensed -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
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
            # Nothing licensed is nothing to restrict — not applicable, like
            # PPL-3.1/3.2/3.5. It is not a pass, and "no user can invoke
            # Copilot" was false: Microsoft 365 Copilot Chat needs no license.
            Add-TPFinding -ControlId $cid -State 'NotApplicable' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
                -FrameworkIds $cit `
                -CurrentValue "0 of $total users licensed" `
                -Detail "No Microsoft 365 Copilot licenses are assigned (0 of $total users), so there is no licensed Copilot access to restrict. Microsoft 365 Copilot Chat is available to users without this license and is not governed by it."
        } elseif ($ratio -ge 0.95) {
            Add-TPFinding -ControlId $cid -State 'Partial' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' `
                -FrameworkIds $cit `
                -CurrentValue "$licensed of $total users licensed ($([math]::Round($ratio * 100,1))%)" `
                -RequiredValue 'Group-based or PIM-time-bound assignment with documented business need' `
                -Detail "Copilot is licensed for $licensed of $total users — effectively the entire tenant. This pattern usually indicates blanket assignment without per-user governance review. Confirm via Entra ID > Groups > license assignment whether Copilot is gated by an approval group." `
                -Remediation $ctrl.Remediation
        } else {
            Add-TPFinding -ControlId $cid -State 'Satisfied' `
                -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
                -FrameworkIds $cit `
                -CurrentValue "$licensed of $total users licensed ($([math]::Round($ratio * 100,1))%)" `
                -RequiredValue 'Copilot licensing scoped to a subset of users' `
                -Detail "Copilot is scoped to $licensed of $total users — licensing is bounded rather than blanket-assigned. Verify the assignment group reflects documented business need."
        }
    } else {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'User count could not be determined — licensing posture cannot be evaluated.'
    }
}

# ── PPL-3.4  Copilot Studio Agent Publishing Governed ─────────────────────────
function Test-TPControlAICopilotStudio {
    [CmdletBinding()] param()
    $cid = 'PPL-3.4'
    $ctrl = Get-TPControlById -ControlId $cid
    if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid

    $raw = Get-TPCopilotRaw
    if (-not $raw -or -not $raw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'M365Copilot collector did not run successfully.'
        return
    }

    # Whether an agent is published to external channels (a public website,
    # other tenants) is a Copilot Studio / Power Platform setting that Graph
    # does not expose. The old verdict inferred it from an app registration's
    # publisherDomain — which is simply the tenant's verified domain — and
    # called an agent on contoso.com "externally published". Nothing readable
    # here answers the question either way.
    $bots = @(Get-TPObjectField -Item $raw.Data -Key 'CopilotStudioBots' -Default @())
    $seen = if ($bots.Count -gt 0) { " $($bots.Count) Copilot Studio app registration(s) were found: $((@($bots) | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '?') } | Select-Object -First 5) -join ', ')." } else { '' }
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual review required)" -FrameworkIds $cit `
        -Detail "This control requires manual verification — Copilot Studio agent publishing channels are not exposed by a supported read API.$seen Check Power Platform admin center > Copilot Studio (and the Copilot Studio authentication / channel settings of each agent) that no agent is published without authentication."
}

# ── PPL-3.5  Copilot Interaction Audit Logging Active ─────────────────────────
function Test-TPControlAICopilotInteractionData {
    [CmdletBinding()] param()
    $cid = 'PPL-3.5'
    $ctrl = Get-TPControlById -ControlId $cid
    if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid

    $raw = Get-TPCopilotRaw
    if (-not $raw -or -not $raw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'M365Copilot collector did not run successfully.'
        return
    }

    $d = $raw.Data
    $licensed = [int]($d.CopilotLicensedUserCount ?? 0)

    if ($licensed -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No Copilot licenses detected — interaction audit applicability is not yet relevant.'
        return
    }

    $auditRaw = Get-TPObjectField -Item $d -Key 'AuditCopilotEnabled'
    $audit = [bool]$auditRaw
    $retention = $d.CopilotInteractionRetention

    if ($null -eq $auditRaw -and (Test-TPCopilotPurviewCollected)) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -FrameworkIds $cit `
            -Detail 'Unified Audit Log status could not be read from the Exchange Online session (Security & Compliance PowerShell always reports it as off), so Copilot interaction auditing is not assessed. Verify in Purview > Audit.'
    } elseif (-not $audit -and -not (Test-TPCopilotPurviewCollected)) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' `
            -Category $ctrl.Category -Title $ctrl.Title `
            -FrameworkIds $cit `
            -Detail "Copilot is licensed to $licensed user(s) but Unified Audit Log status for Copilot interactions could not be evaluated — the Purview/IPPS session did not collect data. Run the assessment with Purview included to verify Copilot audit logging."
    } elseif (-not $audit) {
        Add-TPFinding -ControlId $cid -State 'Gap' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity `
            -FrameworkIds $cit `
            -CurrentValue 'Unified Audit Log ingestion disabled' `
            -RequiredValue 'Unified Audit Log enabled; Copilot prompts and responses recorded' `
            -Detail 'Copilot prompts and responses are not being captured. An insider using Copilot to extract sensitive data leaves no audit trail — compliance investigations involving Copilot usage cannot be reconstructed.' `
            -Remediation $ctrl.Remediation
    } elseif (($null -eq $retention -or [string]$retention -eq '') -and -not (Test-TPCopilotPurviewSection 'RetentionPolicies')) {
        # Audit is on, but retention policies were not read: whether one
        # covers Copilot is unknown, not "none".
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Unified audit logging is on, but Purview retention policies were not collected, so whether Copilot interactions are retained beyond the default was not assessed.'
    } elseif ($null -eq $retention -or [string]$retention -eq '') {
        Add-TPFinding -ControlId $cid -State 'Partial' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' `
            -FrameworkIds $cit `
            -CurrentValue 'Audit enabled; no explicit Copilot retention policy' `
            -RequiredValue 'Audit enabled plus a retention policy covering Copilot interactions' `
            -Detail 'Unified audit logging is active so Copilot interactions are recorded — but no Purview retention policy explicitly covers Copilot. Platform-default retention (~180 days for E3, longer for E5 Audit Premium) may not meet legal-hold or regulated-industry requirements.' `
            -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'Satisfied' `
            -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' `
            -FrameworkIds $cit `
            -CurrentValue 'Audit enabled; explicit Copilot retention policy in place' `
            -RequiredValue 'Audit enabled + retention policy covering Copilot' `
            -Detail 'Unified audit logging is active and a retention policy covers Copilot interactions. Prompts/responses are searchable in Purview Content Explorer and Audit Search for compliance and eDiscovery.'
    }
}

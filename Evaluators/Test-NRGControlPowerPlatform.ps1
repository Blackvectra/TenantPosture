#Requires -Version 7.0
#
# Test-NRGControlPowerPlatform.ps1
# Evaluates Power Platform controls. Reads: Get-NRGRawData -Key 'PowerPlatform'
#
# Controls:
#   PPL-1.1  Environment count within governance baseline
#   PPL-1.2  DLP policy active (requires Microsoft.PowerApps.Administration module)
#   PPL-1.3  Default environment tenant isolation
#

function Test-NRGControlPowerPlatform {
    [CmdletBinding()] param()
    $raw = Get-NRGRawData -Key 'PowerPlatform'
    if (-not $raw -or -not $raw.Success) {
        foreach ($cid in @('PPL-1.1','PPL-1.2','PPL-1.3')) {
            $c = Get-NRGControlById -ControlId $cid
            if ($c) {
                Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
                    -Category 'Power Platform' -Title $c.Title `
                    -Detail 'Power Platform collector did not run.'
            }
        }
        return
    }

    $d = $raw.Data

    # PPL-1.1 — Environment count
    $c = Get-NRGControlById -ControlId 'PPL-1.1'
    if ($c) {
        $envCount = @($d.Environments).Count
        if ($envCount -eq 0) {
            Add-NRGFinding -ControlId 'PPL-1.1' -State 'Satisfied' `
                -Category 'Power Platform' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'No Power Platform environments'
        } elseif ($envCount -le 10) {
            Add-NRGFinding -ControlId 'PPL-1.1' -State 'Satisfied' `
                -Category 'Power Platform' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "$envCount environments — within governance baseline"
        } else {
            Add-NRGFinding -ControlId 'PPL-1.1' -State 'Partial' `
                -Category 'Power Platform' -Title $c.Title -Severity 'Medium' `
                -Detail "$envCount environments exist. Review for unused or trial environments that may host shadow IT data flows." `
                -CurrentValue "$envCount environments" `
                -RequiredValue 'Documented inventory; remove unused environments' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PPL-1.1')
        }
    }

    # PPL-1.2 — DLP policy
    $c = Get-NRGControlById -ControlId 'PPL-1.2'
    if ($c) {
        if (-not $d.DLPAvailable) {
            Add-NRGFinding -ControlId 'PPL-1.2' -State 'NotApplicable' `
                -Category 'Power Platform' -Title $c.Title `
                -Detail 'Power Platform DLP data not available. Install Microsoft.PowerApps.Administration.PowerShell for full DLP assessment: Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -Force'
        } else {
            $count = @($d.DLPPolicies).Count
            if ($count -gt 0) {
                Add-NRGFinding -ControlId 'PPL-1.2' -State 'Satisfied' `
                    -Category 'Power Platform' -Title $c.Title -Severity 'Informational' `
                    -CurrentValue "$count DLP policies active"
            } else {
                Add-NRGFinding -ControlId 'PPL-1.2' -State 'Gap' `
                    -Category 'Power Platform' -Title $c.Title -Severity $c.Severity `
                    -Detail 'No Power Platform DLP policies. Flows can connect arbitrary external services and exfiltrate data.' `
                    -Remediation $c.Remediation `
                    -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PPL-1.2')
            }
        }
    }

    # PPL-1.3 — Environment creation restricted to admins
    # v4.12.2: implemented against Get-TenantSettings
    # (powerPlatform.governance.disableEnvironmentCreationByNonAdminUsers),
    # collected into PowerPlatform.TenantGovernance. Was a manual-review
    # placeholder; the flag is documented and the admin module is already a
    # dependency of this collector.
    $c = Get-NRGControlById -ControlId 'PPL-1.3'
    if ($c) {
        $govStatus = Get-NRGNestedProperty -Object $raw -Path 'Data.SectionStatus.TenantGovernance' -Default $null
        $restricted = Get-NRGNestedProperty -Object $raw -Path 'Data.TenantGovernance.EnvironmentCreationRestricted' -Default $null

        if ($govStatus -ne 'Collected' -or $null -eq $restricted) {
            $why = if ($govStatus -eq 'Failed') {
                'the Get-TenantSettings query failed (see Exceptions)'
            } else {
                'Get-TenantSettings was unavailable — it needs the Microsoft.PowerApps.Administration.PowerShell module, which the BAP-API fallback path cannot substitute for'
            }
            Add-NRGFinding -ControlId 'PPL-1.3' -State 'NotApplicable' `
                -Category 'Power Platform' -Title $c.Title `
                -Detail "Tenant governance settings could not be read: $why. Environment creation restriction was not assessed."
        }
        elseif ($restricted) {
            $trial = Get-NRGNestedProperty -Object $raw -Path 'Data.TenantGovernance.TrialEnvironmentCreationRestricted' -Default $null
            if ($trial -eq $false) {
                Add-NRGFinding -ControlId 'PPL-1.3' -State 'Partial' `
                    -Category 'Power Platform' -Title $c.Title -Severity 'Medium' `
                    -Detail 'Standard environment creation is restricted to admins, but TRIAL environment creation is still open to non-admins. A trial environment is a fully functional environment outside the governance baseline, so this leaves the same gap by another route.' `
                    -CurrentValue 'Environment creation restricted; trial creation unrestricted' `
                    -RequiredValue 'Both standard and trial environment creation restricted to admins' `
                    -Remediation $c.Remediation
            } else {
                Add-NRGFinding -ControlId 'PPL-1.3' -State 'Satisfied' `
                    -Category 'Power Platform' -Title $c.Title -Severity 'Informational' `
                    -Detail 'Environment creation is restricted to tenant, Power Platform and Dynamics 365 admins.'
            }
        }
        else {
            Add-NRGFinding -ControlId 'PPL-1.3' -State 'Gap' `
                -Category 'Power Platform' -Title $c.Title -Severity $c.Severity `
                -Detail 'Any licensed user can create Power Platform environments. Each new environment is a data boundary outside the tenant DLP baseline, created without review, and typically invisible to the security team until it already holds business data.' `
                -CurrentValue 'Environment creation open to non-admin users' `
                -RequiredValue 'Environment creation restricted to admins' `
                -Remediation $c.Remediation
        }
    }
}

# ── PPL-2.1 Power Platform Connector Classification Reviewed ─────────────────
function Test-NRGControlPPLConnectorClassification {
    [CmdletBinding()] param()
    $cid = 'PPL-2.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ppl = Get-NRGRawData -Key 'PowerPlatform'
    if (-not $ppl -or -not $ppl.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Power Platform DLP data not collected'; return
    }
    # Invoke-NRGCollectPowerPlatform now stores per-policy connector
    # classification (Business/Blocked connectors) from Get-DlpPolicy.
    $policies      = @($ppl.Data['DLPPolicies'] ?? @())
    $businessConns = @($policies | ForEach-Object { @(Get-NRGObjectField -Item $_ -Key 'BusinessConnectors' -Default @()).Count } | Measure-Object -Sum).Sum
    $blockedConns  = @($policies | ForEach-Object { @(Get-NRGObjectField -Item $_ -Key 'BlockedConnectors'  -Default @()).Count } | Measure-Object -Sum).Sum
    if ($policies.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit -Detail 'No Power Platform DLP policies configured.'
    } elseif ($businessConns -gt 0 -or $blockedConns -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Power Platform DLP classifies connectors ($businessConns business, $blockedConns blocked across $($policies.Count) policy(ies))."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Power Platform DLP policies exist but classify no connectors as business or blocked — all connectors have equal access.' `
            -CurrentValue "$($policies.Count) DLP policy(ies), 0 classified connectors" `
            -RequiredValue 'Connectors classified into business/blocked groups' -Remediation $ctrl.Remediation
    }
}

# ── PPL-2.2 Power Automate Governance Policy ──────────────────────────────────
function Test-NRGControlPPLAutomate {
    [CmdletBinding()] param()
    $cid = 'PPL-2.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ppl = Get-NRGRawData -Key 'PowerPlatform'
    if (-not $ppl -or -not $ppl.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Power Platform settings not collected'; return
    }
    $guestFlows     = Get-NRGNestedProperty -Object $raw -Path 'Data.TenantSettings.DisableFlowsForGuestUsers' -Default $false
    $gaps = @()
    if (-not $guestFlows) { $gaps += 'Guest users can create flows' }
    if ($gaps.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Power Automate governance settings configured — guest users cannot create flows.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "Power Automate governance gaps: $($gaps -join '; ')" -Remediation $ctrl.Remediation
    }
}

# ── PPL-2.3 Power Apps Governance Policy ──────────────────────────────────────
function Test-NRGControlPPLPowerApps {
    [CmdletBinding()] param()
    $cid = 'PPL-2.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ppl = Get-NRGRawData -Key 'PowerPlatform'
    if (-not $ppl -or -not $ppl.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Power Platform settings not collected'; return
    }
    $canvasAppsEnabled = -not (Get-NRGNestedProperty -Object $raw -Path 'Data.TenantSettings.DisablePortalsCreationByNonAdminUsers' -Default $false)
    if (-not $canvasAppsEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Non-admin users are restricted from creating Power Apps portals.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail 'Non-admin users can create Power Apps portals. Unmanaged portals may expose organizational data to unauthenticated users.' `
            -Remediation $ctrl.Remediation
    }
}
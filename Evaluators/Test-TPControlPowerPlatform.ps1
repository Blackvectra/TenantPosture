#Requires -Version 7.0
#
# Test-TPControlPowerPlatform.ps1
# Evaluates Power Platform controls. Reads: Get-TPRawData -Key 'PowerPlatform'
#
# Controls: PPL-1.1 through PPL-3.5 (11 controls).
#   Config/controls.json is authoritative — each control's EvaluatorFunction
#   names the function in this file that scores it.
#

function Test-TPControlPowerPlatform {
    [CmdletBinding()] param()
    $raw = Get-TPRawData -Key 'PowerPlatform'
    if (-not $raw -or -not $raw.Success) {
        foreach ($cid in @('PPL-1.1','PPL-1.2','PPL-1.3')) {
            $c = Get-TPControlById -ControlId $cid
            if ($c) {
                Add-TPFinding -ControlId $cid -State 'NotApplicable' `
                    -Category 'Power Platform' -Title $c.Title `
                    -Detail 'Power Platform collector did not run.'
            }
        }
        return
    }

    $d = $raw.Data

    # PPL-1.1 — Tenant isolation. This block scored the ENVIRONMENT COUNT
    # ("1 environments — within governance baseline") and passed tenants with
    # isolation switched off, while the control's title, remediation and
    # citations (incl. CMMC 3.13.1 in the SSP) are about tenant isolation.
    $c = Get-TPControlById -ControlId 'PPL-1.1'
    if ($c) {
        $cit = Get-TPFrameworkCitations -ControlId 'PPL-1.1'
        $iso = Get-TPObjectField -Item $d -Key 'TenantIsolation' -Default $null
        if (-not (Test-TPSectionCollected $raw 'TenantIsolation') -or $null -eq $iso) {
            Add-TPFinding -ControlId 'PPL-1.1' -State 'NotApplicable' -Category 'Power Platform' -Title $c.Title -FrameworkIds $cit `
                -Detail 'TenantIsolation was not collected; tenant isolation not assessed.'
        } elseif ((Get-TPObjectField -Item $iso -Key 'IsDisabled' -Default $true) -eq $false) {
            $allowed = @(Get-TPObjectField -Item $iso -Key 'Rules' -Default @()).Count
            Add-TPFinding -ControlId 'PPL-1.1' -State 'Satisfied' -Category 'Power Platform' -Title $c.Title -Severity 'Informational' -FrameworkIds $cit `
                -Detail "Power Platform tenant isolation is on: connections to and from other tenants are blocked except $allowed allow-listed tenant rule(s)." -CurrentValue "Isolation on; $allowed allowed tenant rule(s)"
        } else {
            Add-TPFinding -ControlId 'PPL-1.1' -State 'Gap' -Category 'Power Platform' -Title $c.Title -Severity $c.Severity -FrameworkIds $cit `
                -Detail 'Power Platform tenant isolation is off: flows and apps can connect to other tenants with any account, a data-exfiltration path outside Microsoft 365 DLP.' `
                -CurrentValue 'Tenant isolation off' -RequiredValue 'Tenant isolation on, with an explicit allow list' -Remediation $c.Remediation
        }
    }

    # PPL-1.2 — DLP policy
    $c = Get-TPControlById -ControlId 'PPL-1.2'
    if ($c) {
        if (-not (Get-TPObjectField -Item $d -Key 'DLPAvailable' -Default $false)) {
            Add-TPFinding -ControlId 'PPL-1.2' -State 'NotApplicable' `
                -Category 'Power Platform' -Title $c.Title `
                -Detail 'Power Platform DLP policies were not collected (see Exceptions); DLP not assessed.'
        } else {
            $count = @(Get-TPObjectField -Item $d -Key 'DLPPolicies' -Default @()).Count
            if ($count -gt 0) {
                Add-TPFinding -ControlId 'PPL-1.2' -State 'Satisfied' `
                    -Category 'Power Platform' -Title $c.Title -Severity 'Informational' `
                    -CurrentValue "$count DLP policies active" `
                    -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PPL-1.2')
            } else {
                Add-TPFinding -ControlId 'PPL-1.2' -State 'Gap' `
                    -Category 'Power Platform' -Title $c.Title -Severity $c.Severity `
                    -Detail 'No Power Platform DLP policies. Flows can connect arbitrary external services and exfiltrate data.' `
                    -Remediation $c.Remediation `
                    -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PPL-1.2')
            }
        }
    }

    # PPL-1.3 — Environment creation restricted to admins
    # Reads disableEnvironmentCreationByNonAdminUsers from the documented
    # listtenantsettings admin API, collected into PowerPlatform.TenantGovernance.
    $c = Get-TPControlById -ControlId 'PPL-1.3'
    if ($c) {
        $govStatus = Get-TPNestedProperty -Object $raw -Path 'Data.SectionStatus.TenantGovernance' -Default $null
        $restricted = Get-TPNestedProperty -Object $raw -Path 'Data.TenantGovernance.EnvironmentCreationRestricted' -Default $null

        if ($govStatus -ne 'Collected' -or $null -eq $restricted) {
            $why = if ($govStatus -eq 'Failed') {
                'the tenant settings query failed (see Exceptions)'
            } else {
                'the Power Platform admin API was not reached (see Exceptions)'
            }
            Add-TPFinding -ControlId 'PPL-1.3' -State 'NotApplicable' `
                -Category 'Power Platform' -Title $c.Title `
                -Detail "Tenant governance settings could not be read: $why. Environment creation restriction was not assessed."
        }
        elseif ($restricted) {
            $trial = Get-TPNestedProperty -Object $raw -Path 'Data.TenantGovernance.TrialEnvironmentCreationRestricted' -Default $null
            if ($trial -eq $false) {
                Add-TPFinding -ControlId 'PPL-1.3' -State 'Partial' `
                    -Category 'Power Platform' -Title $c.Title -Severity 'Medium' `
                    -Detail 'Standard environment creation is restricted to admins, but TRIAL environment creation is still open to non-admins. A trial environment is a fully functional environment outside the governance baseline, so this leaves the same gap by another route.' `
                    -CurrentValue 'Environment creation restricted; trial creation unrestricted' `
                    -RequiredValue 'Both standard and trial environment creation restricted to admins' `
                    -Remediation $c.Remediation `
                    -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PPL-1.3')
            } else {
                Add-TPFinding -ControlId 'PPL-1.3' -State 'Satisfied' `
                    -Category 'Power Platform' -Title $c.Title -Severity 'Informational' `
                    -Detail 'Environment creation is restricted to tenant, Power Platform and Dynamics 365 admins.' `
                    -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PPL-1.3')
            }
        }
        else {
            Add-TPFinding -ControlId 'PPL-1.3' -State 'Gap' `
                -Category 'Power Platform' -Title $c.Title -Severity $c.Severity `
                -Detail 'Any licensed user can create Power Platform environments. Each new environment is a data boundary outside the tenant DLP baseline, created without review, and typically invisible to the security team until it already holds business data.' `
                -CurrentValue 'Environment creation open to non-admin users' `
                -RequiredValue 'Environment creation restricted to admins' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-TPFrameworkCitations -ControlId 'PPL-1.3')
        }
    }
}

# ── PPL-2.1 Power Platform Connector Classification Reviewed ─────────────────
function Test-TPControlPPLConnectorClassification {
    [CmdletBinding()] param()
    $cid = 'PPL-2.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ppl = Get-TPRawData -Key 'PowerPlatform'
    if (-not $ppl -or -not $ppl.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Power Platform DLP data not collected'; return
    }
    # Invoke-TPCollectPowerPlatform now stores per-policy connector
    # classification (Business/Blocked connectors) from Get-DlpPolicy.
    # A failed DLP read is not "no DLP policies configured".
    if (-not (Get-TPObjectField -Item $ppl.Data -Key 'DLPAvailable' -Default $true) -or -not (Test-TPSectionCollected $ppl 'DLPPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Power Platform DLP policies were not collected; connector classification not assessed.'
        return
    }
    $policies      = @($ppl.Data['DLPPolicies'] ?? @())
    $businessConns = @($policies | ForEach-Object { @(Get-TPObjectField -Item $_ -Key 'BusinessConnectors' -Default @()).Count } | Measure-Object -Sum).Sum
    $blockedConns  = @($policies | ForEach-Object { @(Get-TPObjectField -Item $_ -Key 'BlockedConnectors'  -Default @()).Count } | Measure-Object -Sum).Sum
    if ($policies.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit -Detail 'No Power Platform DLP policies configured.'
    } elseif ($businessConns -gt 0 -or $blockedConns -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Power Platform DLP classifies connectors ($businessConns business, $blockedConns blocked across $($policies.Count) policy(ies))."
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Power Platform DLP policies exist but classify no connectors as business or blocked — all connectors have equal access.' `
            -CurrentValue "$($policies.Count) DLP policy(ies), 0 classified connectors" `
            -RequiredValue 'Connectors classified into business/blocked groups' -Remediation $ctrl.Remediation
    }
}

# ── PPL-2.2 Power Automate Governance Policy ──────────────────────────────────
function Test-TPControlPPLAutomate {
    [CmdletBinding()] param()
    $cid = 'PPL-2.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ppl = Get-TPRawData -Key 'PowerPlatform'
    if (-not $ppl -or -not $ppl.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Power Platform settings not collected'; return
    }
    # $ppl, not $raw. This function never set $raw — that name belongs to
    # Test-TPControlPowerPlatform — so under StrictMode the read THREW and
    # PPL-2.2 produced no finding on any run, while still counting toward the
    # control total. A control that silently evaluates to nothing is worse than
    # one that fails loudly: the report simply has no row for it.
    if (-not (Test-TPSectionCollected $ppl 'TenantSettings')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'TenantSettings was not collected; not assessed.'
        return
    }
    # Microsoft's tenant settings API documents no "disable flows for guest
    # users" setting, so the collector cannot read one. Reading it with a
    # $false default turned "not readable" into "guests can create flows"
    # and scored Partial on every tenant. Only a value actually returned
    # may score.
    $guestFlows = Get-TPNestedProperty -Object $ppl -Path 'Data.TenantSettings.DisableFlowsForGuestUsers' -Default $null
    if ($null -eq $guestFlows) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Whether guest users can create Power Automate flows is not exposed by the Power Platform tenant settings API; requires manual verification in Power Platform admin center > Tenant settings.'
        return
    }
    $gaps = @()
    if (-not $guestFlows) { $gaps += 'Guest users can create flows' }
    if ($gaps.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Power Automate governance settings configured — guest users cannot create flows.'
    } else {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "Power Automate governance gaps: $($gaps -join '; ')" -Remediation $ctrl.Remediation
    }
}

# ── PPL-2.3 Power Apps Governance Policy ──────────────────────────────────────
function Test-TPControlPPLPowerApps {
    [CmdletBinding()] param()
    $cid = 'PPL-2.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ppl = Get-TPRawData -Key 'PowerPlatform'
    if (-not $ppl -or -not $ppl.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Power Platform settings not collected'; return
    }
    # $ppl, not $raw — same never-set-variable bug as PPL-2.2 above. PPL-2.3
    # threw under StrictMode and produced no finding on any run.
    if (-not (Test-TPSectionCollected $ppl 'TenantSettings')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'TenantSettings was not collected; not assessed.'
        return
    }
    # A $false default here scored "portals open to non-admins" (Partial)
    # whenever the flag was simply not returned.
    $portalsRestricted = Get-TPNestedProperty -Object $ppl -Path 'Data.TenantSettings.DisablePortalsCreationByNonAdminUsers' -Default $null
    if ($null -eq $portalsRestricted) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'The tenant settings response did not include the portal-creation setting; not assessed.'
        return
    }
    $canvasAppsEnabled = -not [bool]$portalsRestricted
    if (-not $canvasAppsEnabled) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Non-admin users are restricted from creating Power Apps portals.'
    } else {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail 'Non-admin users can create Power Apps portals. Unmanaged portals may expose organizational data to unauthenticated users.' `
            -Remediation $ctrl.Remediation
    }
}
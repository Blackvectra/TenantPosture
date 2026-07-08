#Requires -Version 7.0
#
# Test-NRGControlSharePoint.ps1
# Evaluates SharePoint Online controls. Reads: Get-NRGRawData -Key 'SharePoint'
#
# Controls:
#   SPO-1.1  External sharing restricted (not Anyone)
#   SPO-1.2  Legacy auth protocols disabled
#   SPO-1.3  Unmanaged sync app restricted
#   SPO-1.4  Resharing by external users disabled
#   SPO-1.5  Default site creation restricted (info)
#

function Test-NRGControlSharePoint {
    [CmdletBinding()] param()
    $raw = Get-NRGRawData -Key 'SharePoint'
    if (-not $raw -or -not $raw.Success -or -not $raw.Data.TenantSettings) {
        foreach ($cid in @('SPO-1.1','SPO-1.2','SPO-1.3','SPO-1.4','SPO-1.5')) {
            $c = Get-NRGControlById -ControlId $cid
            if ($c) {
                Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
                    -Category 'SharePoint' -Title $c.Title `
                    -Detail 'SharePoint collector did not run or tenant settings unavailable.'
            }
        }
        return
    }

    $s = $raw.Data.TenantSettings

    # SPO-1.1 — External sharing
    $c = Get-NRGControlById -ControlId 'SPO-1.1'
    if ($c) {
        $cap = [string]$s.SharingCapability
        switch ($cap) {
            'disabled' {
                Add-NRGFinding -ControlId 'SPO-1.1' -State 'Satisfied' `
                    -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                    -CurrentValue 'External sharing: disabled'
            }
            'existingExternalUserSharingOnly' {
                Add-NRGFinding -ControlId 'SPO-1.1' -State 'Satisfied' `
                    -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                    -CurrentValue 'External sharing: existing guests only'
            }
            'externalUserSharingOnly' {
                Add-NRGFinding -ControlId 'SPO-1.1' -State 'Partial' `
                    -Category 'SharePoint' -Title $c.Title -Severity 'Medium' `
                    -Detail 'New and existing guests can be shared with. Anonymous (Anyone) links remain disabled.' `
                    -CurrentValue 'External sharing: new and existing guests' `
                    -RequiredValue 'existingExternalUserSharingOnly or disabled' `
                    -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.1')
            }
            'externalUserAndGuestSharing' {
                Add-NRGFinding -ControlId 'SPO-1.1' -State 'Gap' `
                    -Category 'SharePoint' -Title $c.Title -Severity $c.Severity `
                    -Detail 'Anonymous (Anyone) links are enabled. Files can be shared with anyone holding a URL — primary data exfiltration vector.' `
                    -CurrentValue 'External sharing: Anyone (anonymous links)' `
                    -RequiredValue 'existingExternalUserSharingOnly or stricter' `
                    -Remediation $c.Remediation `
                    -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.1')
            }
            default {
                Add-NRGFinding -ControlId 'SPO-1.1' -State 'Partial' `
                    -Category 'SharePoint' -Title $c.Title -Severity 'Medium' `
                    -Detail "External sharing setting returned an unrecognized value: $cap" `
                    -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.1')
            }
        }
    }

    # SPO-1.2 — Legacy auth
    $c = Get-NRGControlById -ControlId 'SPO-1.2'
    if ($c) {
        if ($s.IsLegacyAuthProtocolsEnabled -eq $false) {
            Add-NRGFinding -ControlId 'SPO-1.2' -State 'Satisfied' `
                -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'Legacy auth protocols: disabled'
        } else {
            Add-NRGFinding -ControlId 'SPO-1.2' -State 'Gap' `
                -Category 'SharePoint' -Title $c.Title -Severity $c.Severity `
                -Detail 'Legacy auth protocols enabled for SharePoint. Basic auth and legacy clients bypass MFA enforcement.' `
                -CurrentValue 'IsLegacyAuthProtocolsEnabled = true' `
                -RequiredValue 'IsLegacyAuthProtocolsEnabled = false' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.2')
        }
    }

    # SPO-1.3 — Unmanaged sync restricted
    $c = Get-NRGControlById -ControlId 'SPO-1.3'
    if ($c) {
        if ($s.IsUnmanagedSyncAppForTenantRestricted -eq $true) {
            Add-NRGFinding -ControlId 'SPO-1.3' -State 'Satisfied' `
                -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'Unmanaged sync: restricted to domain-joined devices'
        } else {
            Add-NRGFinding -ControlId 'SPO-1.3' -State 'Partial' `
                -Category 'SharePoint' -Title $c.Title -Severity 'Medium' `
                -Detail 'OneDrive sync is not restricted to managed devices. Personal devices can sync corporate data.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.3')
        }
    }

    # SPO-1.4 — Resharing by external users
    $c = Get-NRGControlById -ControlId 'SPO-1.4'
    if ($c) {
        if ($s.IsResharingByExternalUsersEnabled -eq $false) {
            Add-NRGFinding -ControlId 'SPO-1.4' -State 'Satisfied' `
                -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'External resharing: disabled'
        } else {
            Add-NRGFinding -ControlId 'SPO-1.4' -State 'Partial' `
                -Category 'SharePoint' -Title $c.Title -Severity 'Medium' `
                -Detail 'External users can reshare content they receive — extends sharing reach beyond what admins authorized.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.4')
        }
    }

    # SPO-1.5 — Site creation
    $c = Get-NRGControlById -ControlId 'SPO-1.5'
    if ($c) {
        if ($s.IsSiteCreationEnabled -eq $false) {
            Add-NRGFinding -ControlId 'SPO-1.5' -State 'Satisfied' `
                -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'User site creation: disabled'
        } else {
            Add-NRGFinding -ControlId 'SPO-1.5' -State 'Partial' `
                -Category 'SharePoint' -Title $c.Title -Severity 'Low' `
                -Detail 'Users can create sites. Consider restricting based on governance posture.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.5')
        }
    }
}

# ── SPO-2.1 OneDrive Sync Client Restricted ───────────────────────────────────
function Test-NRGControlSPOOneDriveSync {
    [CmdletBinding()] param()
    $cid = 'SPO-2.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    $syncDomain = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.AllowedDomainGuidsForSyncApp' -Default @()
    if (@($syncDomain).Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'OneDrive sync restricted to domain-joined devices or specific tenant GUIDs.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'OneDrive sync is not restricted to managed devices. Personal devices can sync all organizational data.' -Remediation $ctrl.Remediation
    }
}

# ── SPO-2.2 External Sharing Link Expiration ──────────────────────────────────
function Test-NRGControlSPOLinkExpiration {
    [CmdletBinding()] param()
    $cid = 'SPO-2.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Setting not exposed by Graph /admin/sharepoint/settings (requires SharePoint Management Shell); not assessed.'
}

# ── SPO-2.3 SharePoint Apps Only From Store ───────────────────────────────────
function Test-NRGControlSPOAppsFromStore {
    [CmdletBinding()] param()
    $cid = 'SPO-2.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    $appsFromStore = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.AppsForSharePointEnabled' -Default $true
    if (-not $appsFromStore) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Third-party app installation from the SharePoint store is disabled.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'Users can install apps from the SharePoint store. Review approved app catalog and disable if store apps are not needed.' -Remediation $ctrl.Remediation
    }
}

# ── SPO-2.4 Custom Script Disabled ───────────────────────────────────────────
function Test-NRGControlSPOCustomScript {
    [CmdletBinding()] param()
    $cid = 'SPO-2.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Setting not exposed by Graph /admin/sharepoint/settings (requires SharePoint Management Shell); not assessed.'
}

# ── SPO-2.5 Third-Party Storage Services Disabled ────────────────────────────
function Test-NRGControlSPO3PStorage {
    [CmdletBinding()] param()
    $cid = 'SPO-2.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    # v4.6.4 ADVISORY MARK: no programmatic check, manual review required.
    # Check OneDriveForGuestsEnabled as proxy for third-party storage
    Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual review required)" -Severity 'Low' -FrameworkIds $cit -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). Third-party storage service status requires manual verification: SharePoint Admin Center > Settings > Third-party storage services.' -Remediation $ctrl.Remediation
}

# ── SPO-2.6 Email Attestation for Sharing ────────────────────────────────────
function Test-NRGControlSPOEmailAttestation {
    [CmdletBinding()] param()
    $cid = 'SPO-2.6'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Setting not exposed by Graph /admin/sharepoint/settings (requires SharePoint Management Shell); not assessed.'
}

# ── SPO-2.7 Reauthentication Required for Sharing Links ──────────────────────
function Test-NRGControlSPOReauth {
    [CmdletBinding()] param()
    $cid = 'SPO-2.7'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    $reauthDays = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.EmailAttestationReAuthDays' -Default 0
    if ($reauthDays -gt 0 -and $reauthDays -le 30) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Reauthentication required every $reauthDays day(s) for sharing links."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'Reauthentication for sharing links not configured. Verify in SharePoint Admin Center > Access control.' -Remediation $ctrl.Remediation
    }
}

# ── SPO-2.8 OneDrive Sync to Domain-Joined Only ──────────────────────────────
function Test-NRGControlSPODomainSync {
    [CmdletBinding()] param()
    $cid = 'SPO-2.8'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    $allowedGuids = @(Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.AllowedDomainGuidsForSyncApp' -Default @())
    if ($allowedGuids.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "OneDrive sync restricted to $($allowedGuids.Count) authorized tenant GUID(s)."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'OneDrive sync is not restricted by tenant domain GUID. Personal, unmanaged, and non-domain devices can sync corporate data.' -Remediation $ctrl.Remediation
    }
}

# ── SPO-3.1 Site Collection Admin Access Reviewed ────────────────────────────
function Test-NRGControlSPOSiteAdmins {
    [CmdletBinding()] param()
    $cid = 'SPO-3.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    # v4.6.4 ADVISORY MARK: no programmatic check, manual review required.
    Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Medium' -FrameworkIds $cit `
        -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). Site collection admin enumeration requires iterating all sites (impractical at scale). Verify via SharePoint Admin Center > Sites > Active sites > filter by admins, or run Get-SPOSite -Limit ALL | Get-SPOUser -Group "Site Collection Administrators".' `
        -Remediation $ctrl.Remediation
}

# ── SPO-3.2 SharePoint Sharing Notifications Enabled ─────────────────────────
function Test-NRGControlSPOSharingNotifications {
    [CmdletBinding()] param()
    $cid = 'SPO-3.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title $ctrl.Title `
        -Detail 'Setting not exposed by Graph /admin/sharepoint/settings (requires SharePoint Management Shell); not assessed.'
}

# ── SPO-3.3 OneDrive Version History Enabled ──────────────────────────────────
function Test-NRGControlSPOVersionHistory {
    [CmdletBinding()] param()
    $cid = 'SPO-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    # v4.6.4 CRITICAL FIX: prior code returned hardcoded Satisfied without
    # actually inspecting any version-history config — that's a production
    # false-negative. Downgrade to NotApplicable with explicit manual-review
    # marker until a real per-site-collection check is implemented in v4.7.0.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -FrameworkIds $cit `
        -Detail 'ADVISORY ONLY — no programmatic check is implemented for this control (v4.6.4). Version history retention varies per site collection and cannot be assumed from tenant-level data. Verify via SharePoint Admin Center > Settings that version limits have not been reduced to zero on any site collection.'
}

# ── SPO-3.4 SharePoint Guest Access Expiration Enabled ────────────────────────
function Test-NRGControlSPOGuestExpiry {
    [CmdletBinding()] param()
    $cid = 'SPO-3.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $spo = Get-NRGRawData -Key 'SharePoint'
    if (-not $spo -or -not $spo.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'SharePoint data not collected'; return
    }
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title $ctrl.Title `
        -Detail 'Setting not exposed by Graph /admin/sharepoint/settings (requires SharePoint Management Shell); not assessed.'
}
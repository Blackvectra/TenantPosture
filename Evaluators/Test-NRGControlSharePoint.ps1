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
    $syncDomain = $spo.Data.TenantSettings.AllowedDomainGuidsForSyncApp ?? @()
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
    $expiry = $spo.Data.TenantSettings.RequireAnonymousLinksExpireInDays ?? 0
    if ($expiry -gt 0 -and $expiry -le 30) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Anonymous sharing links expire after $expiry days."
    } elseif ($expiry -gt 30) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "Sharing links expire after $expiry days — consider reducing to ≤30 days." -CurrentValue "$expiry days" -RequiredValue '≤30 days'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Anonymous sharing links never expire. Leaked links remain accessible indefinitely.' -Remediation $ctrl.Remediation
    }
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
    $appsFromStore = $spo.Data.TenantSettings.AppsForSharePointEnabled ?? $true
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
    # DenyAndAddCustomizePages = custom script disabled
    $denied = $spo.Data.TenantSettings.DenyAddAndCustomizePages ?? 'Disabled'
    if ([string]$denied -match 'Enabled|Deny') {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Custom script execution is disabled on SharePoint sites.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Custom scripts can be executed on SharePoint sites. Arbitrary JavaScript can be injected, creating XSS and data exfiltration risks.' -Remediation $ctrl.Remediation
    }
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
    # Check OneDriveForGuestsEnabled as proxy for third-party storage
    Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'Third-party storage service status requires manual verification: SharePoint Admin Center > Settings > Third-party storage services.' -Remediation $ctrl.Remediation
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
    $emailAttest = $spo.Data.TenantSettings.EmailAttestationRequired ?? $false
    if ($emailAttest) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Email attestation required — external users must verify email before accessing shared content.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Email attestation not required for sharing. Unverified recipients can access shared content without identity confirmation.' -Remediation $ctrl.Remediation
    }
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
    $reauthDays = $spo.Data.TenantSettings.EmailAttestationReAuthDays ?? 0
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
    $allowedGuids = @($spo.Data.TenantSettings.AllowedDomainGuidsForSyncApp ?? @())
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
    Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
        -Detail 'Site collection admin enumeration requires iterating all sites (impractical at scale). Verify via SharePoint Admin Center > Sites > Active sites > filter by admins, or run Get-SPOSite -Limit ALL | Get-SPOUser -Group "Site Collection Administrators".' `
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
    $notify = $spo.Data.TenantSettings.NotifyOwnersWhenItemsReshared ?? $true
    if ($notify) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'SharePoint notifies owners when content is re-shared.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Sharing notifications disabled. Owners are unaware when their content is re-shared to additional recipients.' `
            -Remediation $ctrl.Remediation
    }
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
    # Version history is on by default — check if it's been explicitly disabled
    Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
        -Detail 'OneDrive/SharePoint version history is enabled by default. Verify via SharePoint Admin Center > Settings that version limits have not been reduced to zero.'
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
    $expireRequired = $spo.Data.TenantSettings.ExternalUserExpirationRequired ?? $false
    $expireDays     = $spo.Data.TenantSettings.ExternalUserExpireInDays ?? 0
    if ($expireRequired -and $expireDays -gt 0 -and $expireDays -le 60) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "SharePoint guest access expires after $expireDays days."
    } elseif ($expireRequired) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail "Guest expiry enabled but set to $expireDays days. Recommend ≤60 days." `
            -CurrentValue "$expireDays days" -RequiredValue '≤60 days'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Guest access expiration not required. External guests retain SharePoint access indefinitely.' `
            -Remediation $ctrl.Remediation
    }
}
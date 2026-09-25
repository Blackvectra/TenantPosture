#Requires -Version 7.0
#
# Test-NRGControlSharePoint.ps1
# Evaluates SharePoint Online controls. Reads: Get-NRGRawData -Key 'SharePoint'
# (SPO-1.5 also reads Security Defaults via Get-NRGSecurityDefaultsState.)
#
# Controls: SPO-1.1 through SPO-3.4 (17 controls).
#   Config/controls.json is authoritative — each control's EvaluatorFunction
#   names the function in this file that scores it.
#

function Test-NRGControlSharePoint {
    [CmdletBinding()] param()
    $raw = Get-NRGRawData -Key 'SharePoint'
    if (-not $raw -or -not $raw.Success -or -not $raw.Data['TenantSettings']) {
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

    $s = $raw.Data['TenantSettings']

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
                # An empty or unknown value is not a half-restricted tenant.
                Add-NRGFinding -ControlId 'SPO-1.1' -State 'NotApplicable' `
                    -Category 'SharePoint' -Title $c.Title `
                    -Detail "External sharing setting was not read (value: '$cap'); not assessed." `
                    -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.1')
            }
        }
    }

    # SPO-1.2 .. SPO-1.5. Each block previously scored a DIFFERENT setting
    # than the control's title, description and citations name (SPO-1.2
    # "Default Sharing Link Not Anonymous" scored legacy auth, SPO-1.3 "Legacy
    # Authentication Blocked" scored unmanaged sync, SPO-1.4 "Guest Access
    # Expiration" scored external resharing, SPO-1.5 "Unmanaged Device Access"
    # scored site creation) — a false statement on every run. Each now reads
    # the setting its own Remediation cmdlet sets.
    $cap = [string]$s.SharingCapability
    $shell = Get-NRGObjectField -Item $raw.Data -Key 'TenantSettingsSPO' -Default $null
    $noShell = 'Requires the SharePoint Online Management Shell (Get-SPOTenant); not connected. Not exposed by Graph. Re-run with -IncludeSharePointShell to read it.'

    # SPO-1.2 — Default sharing link not "Anyone" (Set-SPOTenant -DefaultSharingLinkType)
    $c = Get-NRGControlById -ControlId 'SPO-1.2'
    if ($c) {
        $cit = Get-NRGFrameworkCitations -ControlId 'SPO-1.2'
        $linkType = [string](Get-NRGObjectField -Item $shell -Key 'DefaultSharingLinkType' -Default '')
        if ($cap -in @('disabled','existingExternalUserSharingOnly','externalUserSharingOnly')) {
            # "Anyone" links are off tenant-wide, so no default can be Anyone.
            Add-NRGFinding -ControlId 'SPO-1.2' -State 'Satisfied' -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                -Detail "Anyone links are disabled tenant-wide (sharing capability '$cap'), so the default sharing link cannot be Anyone." `
                -CurrentValue "SharingCapability = $cap" -FrameworkIds $cit
        } elseif ($cap -ne 'externalUserAndGuestSharing') {
            Add-NRGFinding -ControlId 'SPO-1.2' -State 'NotApplicable' -Category 'SharePoint' -Title $c.Title -FrameworkIds $cit `
                -Detail "External sharing setting was not read (value: '$cap'); not assessed."
        } elseif (-not $linkType) {
            Add-NRGFinding -ControlId 'SPO-1.2' -State 'NotApplicable' -Category 'SharePoint' -Title $c.Title -FrameworkIds $cit `
                -Detail "Anyone links are enabled tenant-wide; the default link type was not read. $noShell"
        } elseif ($linkType -eq 'AnonymousAccess') {
            Add-NRGFinding -ControlId 'SPO-1.2' -State 'Gap' -Category 'SharePoint' -Title $c.Title -Severity $c.Severity `
                -Detail 'The default sharing link is "Anyone with the link": every share a user makes without changing the option creates an unauthenticated link.' `
                -CurrentValue 'DefaultSharingLinkType = AnonymousAccess' -RequiredValue 'DefaultSharingLinkType = Internal or Direct' `
                -Remediation $c.Remediation -FrameworkIds $cit
        } elseif ($linkType -in @('Internal','Direct')) {
            Add-NRGFinding -ControlId 'SPO-1.2' -State 'Satisfied' -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "DefaultSharingLinkType = $linkType" -FrameworkIds $cit
        } else {
            Add-NRGFinding -ControlId 'SPO-1.2' -State 'NotApplicable' -Category 'SharePoint' -Title $c.Title -FrameworkIds $cit `
                -Detail "Default sharing link type '$linkType' is not a recognized value; not assessed."
        }
    }

    # SPO-1.3 — Legacy authentication blocked (Set-SPOTenant -LegacyAuthProtocolsEnabled)
    $c = Get-NRGControlById -ControlId 'SPO-1.3'
    if ($c) {
        $cit = Get-NRGFrameworkCitations -ControlId 'SPO-1.3'
        $legacy = Get-NRGObjectField -Item $s -Key 'IsLegacyAuthProtocolsEnabled' -Default $null
        if ($null -eq $legacy) {
            Add-NRGFinding -ControlId 'SPO-1.3' -State 'NotApplicable' -Category 'SharePoint' -Title $c.Title -FrameworkIds $cit `
                -Detail 'Graph did not return isLegacyAuthProtocolsEnabled, so whether SharePoint accepts legacy authentication was not assessed.'
        } elseif ($legacy -eq $false) {
            Add-NRGFinding -ControlId 'SPO-1.3' -State 'Satisfied' -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                -CurrentValue 'Legacy authentication protocols: disabled' -FrameworkIds $cit
        } else {
            Add-NRGFinding -ControlId 'SPO-1.3' -State 'Gap' -Category 'SharePoint' -Title $c.Title -Severity $c.Severity `
                -Detail 'Legacy authentication protocols are enabled for SharePoint. Legacy clients sign in without modern authentication, bypassing MFA and Conditional Access.' `
                -CurrentValue 'IsLegacyAuthProtocolsEnabled = true' -RequiredValue 'IsLegacyAuthProtocolsEnabled = false' `
                -Remediation $c.Remediation -FrameworkIds $cit
        }
    }

    # SPO-1.4 — Guest access expiration (Set-SPOTenant -ExternalUserExpirationRequired)
    $c = Get-NRGControlById -ControlId 'SPO-1.4'
    if ($c) {
        $cit = Get-NRGFrameworkCitations -ControlId 'SPO-1.4'
        if ($cap -eq 'disabled') {
            Add-NRGFinding -ControlId 'SPO-1.4' -State 'NotApplicable' -Category 'SharePoint' -Title $c.Title -FrameworkIds $cit `
                -Detail 'External sharing is disabled, so there is no guest access to expire.'
        } elseif ($null -eq $shell) {
            Add-NRGFinding -ControlId 'SPO-1.4' -State 'NotApplicable' -Category 'SharePoint' -Title $c.Title -FrameworkIds $cit -Detail $noShell
        } else {
            $required = [bool](Get-NRGObjectField -Item $shell -Key 'ExternalUserExpirationRequired' -Default $false)
            $expDays  = [int](Get-NRGObjectField -Item $shell -Key 'ExternalUserExpireInDays' -Default 0)
            if ($required -and $expDays -gt 0) {
                Add-NRGFinding -ControlId 'SPO-1.4' -State 'Satisfied' -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                    -Detail "Guest access expires after $expDays day(s)." -FrameworkIds $cit
            } else {
                Add-NRGFinding -ControlId 'SPO-1.4' -State 'Gap' -Category 'SharePoint' -Title $c.Title -Severity $c.Severity `
                    -Detail 'Guest access to SharePoint never expires. External users keep access to shared content indefinitely.' `
                    -CurrentValue "ExternalUserExpirationRequired = $required" -RequiredValue 'ExternalUserExpirationRequired = True with ExternalUserExpireInDays set' `
                    -Remediation $c.Remediation -FrameworkIds $cit
            }
        }
    }

    # SPO-1.5 — Unmanaged device access (Set-SPOTenant -ConditionalAccessPolicy)
    $c = Get-NRGControlById -ControlId 'SPO-1.5'
    if ($c) {
        $cit = Get-NRGFrameworkCitations -ControlId 'SPO-1.5'
        $cap15 = [string](Get-NRGObjectField -Item $shell -Key 'ConditionalAccessPolicy' -Default '')
        # Microsoft: "Blocking or limiting access on unmanaged devices relies
        # on Microsoft Entra Conditional Access policies"
        # (learn.microsoft.com/sharepoint/control-access-from-unmanaged-devices),
        # and no CA policy can be turned on while Security Defaults is enabled.
        # So beside Security Defaults a restricting value is not credited, and
        # the remediation says Conditional Access comes first.
        $sd15 = (Get-NRGSecurityDefaultsState) -eq $true
        $restricting15 = $cap15 -in @('AllowLimitedAccess','BlockAccess','AuthenticationContext')
        if ($null -eq $shell -or -not $cap15) {
            Add-NRGFinding -ControlId 'SPO-1.5' -State 'NotApplicable' -Category 'SharePoint' -Title $c.Title -FrameworkIds $cit -Detail $noShell
        } elseif ($sd15 -and ($restricting15 -or $cap15 -eq 'AllowFullAccess')) {
            # The generic remediation (Set-SPOTenant ... AllowLimitedAccess)
            # is already done when the value restricts, and would not close
            # this Gap, so that case names the step that would.
            $sdDetail = if ($restricting15) {
                "SharePoint's unmanaged-device setting is $cap15, but Microsoft documents that blocking or limiting access from unmanaged devices relies on Microsoft Entra Conditional Access policies, and none can be in force here, so the setting is not credited."
            } else {
                'Unmanaged devices get full access to SharePoint and OneDrive, including download and sync. Restricting them relies on Microsoft Entra Conditional Access policies.'
            }
            $sdFix = if ($restricting15) {
                "The SharePoint setting is already $cap15 and needs no change. What it relies on is a Microsoft Entra Conditional Access policy (the SharePoint admin center creates one when the setting is saved there); once Security Defaults is off, confirm that policy exists and is On."
            } else { $c.Remediation }
            Add-NRGSecurityDefaultsFinding -ControlId 'SPO-1.5' -Category 'SharePoint' -Title $c.Title -FrameworkIds $cit -State 'Gap' -Severity $c.Severity `
                -Detail $sdDetail `
                -CurrentValue "ConditionalAccessPolicy = $cap15; Security Defaults enabled (no Conditional Access policy in force)" `
                -RequiredValue 'AllowLimitedAccess (browser-only) or BlockAccess, enforced by an enabled Conditional Access policy' `
                -Remediation $sdFix -NeedsConditionalAccess
        } elseif ($cap15 -eq 'AllowFullAccess') {
            Add-NRGFinding -ControlId 'SPO-1.5' -State 'Gap' -Category 'SharePoint' -Title $c.Title -Severity $c.Severity `
                -Detail 'Unmanaged devices get full access to SharePoint and OneDrive, including download and sync.' `
                -CurrentValue 'ConditionalAccessPolicy = AllowFullAccess' -RequiredValue 'AllowLimitedAccess (browser-only) or BlockAccess' `
                -Remediation $c.Remediation -FrameworkIds $cit
        } elseif ($restricting15) {
            Add-NRGFinding -ControlId 'SPO-1.5' -State 'Satisfied' -Category 'SharePoint' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "ConditionalAccessPolicy = $cap15" -FrameworkIds $cit
        } else {
            Add-NRGFinding -ControlId 'SPO-1.5' -State 'NotApplicable' -Category 'SharePoint' -Title $c.Title -FrameworkIds $cit `
                -Detail "Unmanaged device access setting '$cap15' is not a recognized value; not assessed."
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
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $spo 'TenantSettings')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'TenantSettings was not collected; not assessed.'
        return
    }
    # The restriction flag decides it: Remove-SPOTenantSyncClientRestriction
    # turns the feature off but KEEPS the domain GUIDs, so a leftover GUID list
    # read as "restricted" on a tenant where sync is open to any device.
    $restricted = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.IsUnmanagedSyncAppForTenantRestricted' -Default $null
    if ($null -eq $restricted) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Graph did not return isUnmanagedSyncAppForTenantRestricted, so the OneDrive sync restriction was not assessed.'
        return
    }
    $syncDomain = @(Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.AllowedDomainGuidsForSyncApp' -Default @())
    if ($restricted -eq $true) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "OneDrive sync is restricted to computers joined to $($syncDomain.Count) allowed Active Directory domain(s)."
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
    $sp = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettingsSPO' -Default $null
    if ($null -eq $sp) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Requires SharePoint Online Management Shell (Connect-SPOService); not connected. Not exposed by Graph. Re-run with -IncludeSharePointShell to read it.'; return
    }
    $cap = [string](Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.SharingCapability' -Default '')
    if ($cap -and $cap -ne 'externalUserAndGuestSharing') {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Anyone links are disabled tenant-wide (sharing capability '$cap'), so there are no Anyone links to expire."
        return
    }
    $days = [int](Get-NRGObjectField -Item $sp -Key 'RequireAnonymousLinksExpireInDays' -Default -1)
    if ($days -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Anonymous ('Anyone') sharing links expire after $days day(s)."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Anonymous ('Anyone') sharing links never expire (RequireAnonymousLinksExpireInDays = $days). Shared links remain live indefinitely and cannot be recalled once distributed." -CurrentValue "RequireAnonymousLinksExpireInDays = $days (no expiry)" -RequiredValue 'A finite expiry (e.g. 30 days)' -Remediation $ctrl.Remediation
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
    # AppsForSharePointEnabled is not among the fields Invoke-NRGCollectSharePoint
    # reads from /admin/sharepoint/settings or Get-SPOTenant — there is no
    # collected value to score here, so the field defaulting to $true made
    # every tenant read Partial regardless of the real setting. Advisory
    # controls with no real check must emit NotApplicable, never Satisfied or
    # Partial.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title "$($ctrl.Title) (Not collected)" -FrameworkIds $cit -Detail 'App installation from the SharePoint store is not collected by this tool. Review in SharePoint Admin Center > Advanced > API access, or the app catalog settings.'
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
    # Custom script is a PER-SITE flag (Set-SPOSite -DenyAddAndCustomizePages),
    # not a tenant Get-SPOTenant property, so there is no single tenant-wide value
    # to read. Modern tenants block custom script by default; verifying every site
    # requires Get-SPOSite enumeration (out of scope for a tenant-settings read).
    # Advisory: NotApplicable, never Partial. Partial is worth 0.5 toward the
    # compliance score, so an advisory control scored Partial hands every
    # tenant free credit for a verdict this function never computed — and this
    # one computes nothing at all, it only describes where to look. That is the
    # "advisory controls never claim compliance" rule; it was being broken here.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title "$($ctrl.Title) (Per-site review required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail 'Custom-script permission is controlled per site collection (DenyAddAndCustomizePages), not by a tenant-wide switch. Custom script is blocked by default on modern tenants. Confirm no site collection has been re-enabled for custom script.' `
        -Remediation $ctrl.Remediation
}

# ── SPO-2.5 Third-Party Storage Services Disabled ────────────────────────────
function Test-NRGControlSPO3PStorage {
    [CmdletBinding()] param()
    $cid = 'SPO-2.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    # v4.13.0: implemented, and RE-SCOPED to what is actually readable.
    #
    # The control previously claimed to check the admin-center "third-party
    # storage services" toggle, but no Get-SPOTenant property exposes it, which
    # is why it sat as a manual-review placeholder. The connectors that ARE
    # readable are the Teams client third-party storage providers
    # (Get-CsTeamsClientConfiguration: AllowDropBox / AllowBox / AllowGoogleDrive
    # / AllowShareFile), already collected by the Teams collector. Those are the
    # same providers, surfaced through the collaboration client rather than the
    # SharePoint admin page, so the finding assesses them and says plainly which
    # surface it covered — rather than implying it verified a setting it cannot
    # read.
    $tms = Get-NRGRawData -Key 'Teams'
    if (-not $tms -or -not $tms.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail 'Teams client configuration not collected — third-party cloud storage connector state could not be assessed.'
        return
    }
    $client = Get-NRGNestedProperty -Object $tms -Path 'Data.ClientConfiguration' -Default $null
    if (-not $client) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail 'Teams client configuration unavailable (Get-CsTeamsClientConfiguration did not return) — third-party cloud storage connector state could not be assessed.'
        return
    }

    $st = Get-NRGTeamsStorageProviderState -ClientConfiguration $client
    if ($st.Unread.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "The Teams client configuration did not report $($st.Unread -join ', '), so third-party storage connector state was not assessed."
        return
    }
    $enabled = @($st.Enabled)

    $portalNote = 'Scope note: this verifies the Teams client third-party storage connectors (Get-CsTeamsClientConfiguration). The Microsoft 365 admin center "Third-party storage services" toggle is not exposed to PowerShell and is a separate manual check.'

    if ($enabled.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "No third-party cloud storage providers are enabled in the Teams client ($($st.Checked -join ', ') all off).$($st.Note) $portalNote"
    } else {
        $affected = @($enabled | ForEach-Object { [ordered]@{ DisplayName = $_; Status = 'Enabled' } })
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($enabled.Count) third-party cloud storage provider(s) are enabled in the Teams client: $($enabled -join ', '). Corporate files can be moved into storage the tenant does not control, does not audit and cannot retain or legally hold. $portalNote" `
            -CurrentValue "Enabled: $($enabled -join ', ')" `
            -RequiredValue 'All third-party cloud storage providers disabled' `
            -Remediation $ctrl.Remediation -AffectedObjects $affected
    }
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
    $sp = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettingsSPO' -Default $null
    if ($null -eq $sp) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Requires SharePoint Online Management Shell (Connect-SPOService); not connected. Not exposed by Graph. Re-run with -IncludeSharePointShell to read it.'; return
    }
    if ([string](Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.SharingCapability' -Default '') -eq 'disabled') {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'External sharing is disabled, so there are no external recipients to attest.'
        return
    }
    $required = [bool](Get-NRGObjectField -Item $sp -Key 'EmailAttestationRequired' -Default $false)
    $reauth   = [int](Get-NRGObjectField -Item $sp -Key 'EmailAttestationReAuthDays' -Default 0)
    if ($required) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "External recipients must periodically re-verify their email to keep access (re-attestation every $reauth day(s))."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Email attestation is not required for external sharing. Recipients of verification-code links are never asked to re-prove control of their mailbox, so forwarded or intercepted links grant lasting access.' -CurrentValue 'EmailAttestationRequired = False' -RequiredValue 'EmailAttestationRequired = True' -Remediation $ctrl.Remediation
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
    # EmailAttestationReAuthDays comes from Get-SPOTenant (TenantSettingsSPO),
    # not the Graph TenantSettings block — Graph's /admin/sharepoint/settings
    # never returns this field. Same source as SPO-2.6, which reads this exact
    # value under the correct key.
    $sp = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettingsSPO' -Default $null
    if ($null -eq $sp) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Requires SharePoint Online Management Shell (Connect-SPOService); not connected. Not exposed by Graph. Re-run with -IncludeSharePointShell to read it.'; return
    }
    if ([string](Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.SharingCapability' -Default '') -eq 'disabled') {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'External sharing is disabled, so there are no sharing links to reauthenticate.'
        return
    }
    # EmailAttestationReAuthDays applies ONLY when EmailAttestationRequired is
    # on (Set-SPOTenant docs); a leftover day count with attestation off used
    # to read as "Reauthentication required every N day(s)".
    $attest     = [bool](Get-NRGObjectField -Item $sp -Key 'EmailAttestationRequired' -Default $false)
    $reauthDays = [int](Get-NRGObjectField -Item $sp -Key 'EmailAttestationReAuthDays' -Default 0)
    if ($attest -and $reauthDays -gt 0 -and $reauthDays -le 30) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "External recipients must reauthenticate every $reauthDays day(s)."
    } elseif ($attest -and $reauthDays -gt 30) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "External recipients reauthenticate every $reauthDays days — longer than the recommended 30." -CurrentValue "EmailAttestationReAuthDays = $reauthDays" -RequiredValue '30 days or fewer' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'External recipients are never asked to reauthenticate (email attestation is off).' -CurrentValue "EmailAttestationRequired = $attest" -RequiredValue 'EmailAttestationRequired = True, EmailAttestationReAuthDays <= 30' -Remediation $ctrl.Remediation
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
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $spo 'TenantSettings')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'TenantSettings was not collected; not assessed.'
        return
    }
    # These are Active Directory DOMAIN GUIDs (Set-SPOTenantSyncClientRestriction
    # -DomainGuids), not tenant GUIDs, and the setting limits which computers
    # can sync — it does not block syncing to another tenant. The flag decides:
    # a disabled restriction keeps its GUID list.
    $restricted   = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.IsUnmanagedSyncAppForTenantRestricted' -Default $null
    if ($null -eq $restricted) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Graph did not return isUnmanagedSyncAppForTenantRestricted, so the OneDrive sync restriction was not assessed.'
        return
    }
    $allowedGuids = @(Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.AllowedDomainGuidsForSyncApp' -Default @())
    if ($restricted -eq $true -and $allowedGuids.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "OneDrive sync is restricted to computers joined to $($allowedGuids.Count) allowed Active Directory domain(s)."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'OneDrive sync is not restricted to computers joined to allowed Active Directory domains. Personal and unmanaged computers can sync corporate data.' -Remediation $ctrl.Remediation
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
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Medium' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — enumerating site collection administrators means querying every site individually, which does not scale to a full tenant within an assessment run. Review them in SharePoint Admin Center > Sites > Active sites.' `
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
    $sp = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettingsSPO' -Default $null
    if ($null -eq $sp) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail 'Requires SharePoint Online Management Shell (Connect-SPOService); not connected. Not exposed by Graph. Re-run with -IncludeSharePointShell to read it.'; return
    }
    $notify = [bool](Get-NRGObjectField -Item $sp -Key 'NotifyOwnersWhenItemsReshared' -Default $false)
    if ($notify) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Site owners are notified when their content is reshared — unexpected resharing is visible for review.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Owners are not notified when items are reshared. Content can spread to new external parties without the owner ever knowing.' -CurrentValue 'NotifyOwnersWhenItemsReshared = False' -RequiredValue 'NotifyOwnersWhenItemsReshared = True' -Remediation $ctrl.Remediation
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
    # Assesses the ORG-WIDE version-history default (Get-SPOTenant) applied to new
    # document libraries / OneDrive accounts — the setting behind SharePoint Admin
    # Center > Settings > Version history limits, and the org's ransomware-recovery
    # baseline. Per-site overrides aren't covered (that needs per-site enumeration);
    # the tenant default is the governing, assessable signal.
    $sp = $spo.Data['TenantSettingsSPO']
    if (-not $sp) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'SharePoint Management Shell (Get-SPOTenant) data not collected — version-history default not assessed. Requires a Connect-SPOService session (re-run with -IncludeSharePointShell).'
        return
    }
    $autoTrim  = (Get-NRGObjectField -Item $sp -Key 'EnableAutoExpirationVersionTrim') -eq $true
    $majorLimit = [int](Get-NRGObjectField -Item $sp -Key 'MajorVersionLimit' -Default 0)
    if ($autoTrim) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Automatic version-history trimming is the org default (EnableAutoExpirationVersionTrim = $true). New document libraries keep an intelligent version set — files can be rolled back after ransomware encryption.' `
            -CurrentValue 'Automatic version expiration (intelligent retention)'
    } elseif ($majorLimit -ge 100) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "The org default keeps $majorLimit major versions per file — adequate for ransomware recovery (>= 100)." `
            -CurrentValue "MajorVersionLimit = $majorLimit"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "The org-wide version-history default keeps only $majorLimit major version(s) per file and automatic trimming is off. Too few versions to reliably roll back files after ransomware encryption or accidental overwrite." `
            -CurrentValue "MajorVersionLimit = $majorLimit, EnableAutoExpirationVersionTrim = `$false" `
            -RequiredValue 'Automatic version trimming, or >= 100 major versions' `
            -Remediation $ctrl.Remediation
    }
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
    $sp = Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettingsSPO' -Default $null
    if ($null -eq $sp) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail 'Requires SharePoint Online Management Shell (Connect-SPOService); not connected. Not exposed by Graph. Re-run with -IncludeSharePointShell to read it.'; return
    }
    if ([string](Get-NRGNestedProperty -Object $spo -Path 'Data.TenantSettings.SharingCapability' -Default '') -eq 'disabled') {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'External sharing is disabled, so there is no guest access to expire.'
        return
    }
    $required = [bool](Get-NRGObjectField -Item $sp -Key 'ExternalUserExpirationRequired' -Default $false)
    $expDays  = [int](Get-NRGObjectField -Item $sp -Key 'ExternalUserExpireInDays' -Default 0)
    if ($required -and $expDays -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Guest (external user) access automatically expires after $expDays day(s) of inactivity."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Guest access never automatically expires (ExternalUserExpirationRequired off). External users retain access to shared content indefinitely, accumulating stale standing access.' -CurrentValue "ExternalUserExpirationRequired = $required" -RequiredValue 'ExternalUserExpirationRequired = True with a finite ExternalUserExpireInDays' -Remediation $ctrl.Remediation
    }
}
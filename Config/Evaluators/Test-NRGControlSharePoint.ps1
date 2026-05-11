#
# Test-NRGControlSharePoint.ps1
# Evaluates SharePoint Online tenant security controls.
#
# Controls:
#   SPO-1.1  Tenant external sharing restricted
#   SPO-1.2  Default sharing link type is internal
#   SPO-1.3  Anyone link expiration enforced
#   SPO-1.4  External user resharing disabled
#   SPO-1.5  Unmanaged device access policy blocks or limits SharePoint
#   SPO-2.1  OneDrive default sharing scoped to organisation
#   SPO-2.2  Guest sharing of items by non-owners disabled
#
# Reads: Get-NRGRawData -Key 'SharePoint'
#
# NIST SP 800-53: AC-3, AC-17, AC-22, SC-8
# MITRE ATT&CK:   T1530, T1567
#

function Test-NRGControlSharePoint {
    [CmdletBinding()] param()

    $raw = Get-NRGRawData -Key 'SharePoint'

    if (-not $raw -or -not $raw.Success) {
        $detail = if ($raw) { "Collector failed: $($raw.Exceptions -join '; ')" } else { 'SharePoint collector did not run.' }
        foreach ($id in @('SPO-1.1','SPO-1.2','SPO-1.3','SPO-1.4','SPO-1.5','SPO-2.1','SPO-2.2')) {
            $ctrl = Get-NRGControlById -ControlId $id
            Add-NRGFinding -ControlId $id -State 'NotApplicable' `
                -Category 'SharePoint' -Title ($ctrl.Title) -Detail $detail
        }
        return
    }

    $s = $raw.Data['TenantSettings']

    if (-not $s) {
        # API returned null — likely missing scope or SPO not provisioned
        foreach ($id in @('SPO-1.1','SPO-1.2','SPO-1.3','SPO-1.4','SPO-1.5','SPO-2.1','SPO-2.2')) {
            $ctrl = Get-NRGControlById -ControlId $id
            Add-NRGFinding -ControlId $id -State 'NotApplicable' `
                -Category 'SharePoint' -Title ($ctrl.Title) `
                -Detail 'SharePoint tenant settings not accessible. Verify SharePointTenantSettings.Read.All permission is granted.'
        }
        return
    }

    #--------------------------------------------------------------------------
    # SPO-1.1  Tenant external sharing restricted
    # AC-22, AC-3 | T1530
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'SPO-1.1'
    $sharing = $s.sharingCapability
    if ($sharing -in @('disabled','existingExternalUserSharingOnly')) {
        Add-NRGFinding -ControlId 'SPO-1.1' -State 'Satisfied' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "Sharing capability: $sharing" `
            -RequiredValue 'disabled or existingExternalUserSharingOnly'
    } elseif ($sharing -eq 'externalUserSharingOnly') {
        Add-NRGFinding -ControlId 'SPO-1.1' -State 'Partial' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity 'High' `
            -Detail 'SharePoint allows sharing with new external users (authenticated). Consider restricting to existing external users only.' `
            -CurrentValue "Sharing capability: $sharing" `
            -RequiredValue 'existingExternalUserSharingOnly or disabled' `
            -Remediation 'SharePoint admin center > Policies > Sharing > Set to "Existing guests only" or "Only people in your organization".' `
            -FrameworkIds @('AC-22','AC-3')
    } else {
        Add-NRGFinding -ControlId 'SPO-1.1' -State 'Gap' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'SharePoint allows sharing with anyone (no sign-in required). This exposes all content to unauthenticated external access.' `
            -CurrentValue "Sharing capability: $sharing" `
            -RequiredValue 'existingExternalUserSharingOnly or disabled' `
            -Remediation $ctrl.Remediation `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.1')
    }

    #--------------------------------------------------------------------------
    # SPO-1.2  Default sharing link type is internal (not Anyone)
    # AC-22 | T1530
    #--------------------------------------------------------------------------
    $ctrl       = Get-NRGControlById -ControlId 'SPO-1.2'
    $linkType   = $s.defaultSharingLinkType
    $safeTypes  = @('none','internal','direct')
    if ($linkType -in $safeTypes) {
        Add-NRGFinding -ControlId 'SPO-1.2' -State 'Satisfied' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "Default link type: $linkType" `
            -RequiredValue 'none, internal, or direct'
    } else {
        Add-NRGFinding -ControlId 'SPO-1.2' -State 'Gap' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'Default sharing link is set to "Anyone" — users share with anyone by default, creating unintentional public exposure.' `
            -CurrentValue "Default link type: $linkType" `
            -RequiredValue 'internal or direct' `
            -Remediation 'SharePoint admin center > Policies > Sharing > Default link type > Set to "Only people in your organization" or "Specific people".' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.2')
    }

    #--------------------------------------------------------------------------
    # SPO-1.3  Anyone link expiration enforced (if Anyone links are enabled)
    # AC-22 | T1530
    #--------------------------------------------------------------------------
    $ctrl     = Get-NRGControlById -ControlId 'SPO-1.3'
    $anyoneOk = $s.isAnyoneLinkEnabled -eq $false -or $sharing -in @('disabled','existingExternalUserSharingOnly')
    if ($anyoneOk) {
        Add-NRGFinding -ControlId 'SPO-1.3' -State 'Satisfied' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue 'Anyone links disabled or not applicable for current sharing policy' `
            -RequiredValue 'Expiration set, or Anyone links disabled'
    } else {
        $expDays = $s.anonymousLinkExpirationInDays
        if ($expDays -and $expDays -gt 0 -and $expDays -le 30) {
            Add-NRGFinding -ControlId 'SPO-1.3' -State 'Satisfied' `
                -Category 'SharePoint' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "Anyone link expiration: $expDays days" `
                -RequiredValue '30 days or less'
        } elseif ($expDays -and $expDays -gt 30) {
            Add-NRGFinding -ControlId 'SPO-1.3' -State 'Partial' `
                -Category 'SharePoint' -Title $ctrl.Title -Severity 'Medium' `
                -Detail "Anyone link expiration is set to $expDays days — exceeds the recommended 30-day limit." `
                -CurrentValue "Expiration: $expDays days" `
                -RequiredValue '30 days or less' `
                -Remediation 'SharePoint admin center > Policies > Sharing > Anyone links expiration > Set to 30 days or less.'
        } else {
            Add-NRGFinding -ControlId 'SPO-1.3' -State 'Gap' `
                -Category 'SharePoint' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'Anyone links have no expiration. Once shared, a link provides permanent unauthenticated access.' `
                -CurrentValue 'No expiration configured' `
                -RequiredValue '30-day expiration on Anyone links' `
                -Remediation 'SharePoint admin center > Policies > Sharing > Anyone links > Set expiration to 30 days.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.3')
        }
    }

    #--------------------------------------------------------------------------
    # SPO-1.4  External user resharing disabled
    # AC-22 | T1530
    #--------------------------------------------------------------------------
    $ctrl      = Get-NRGControlById -ControlId 'SPO-1.4'
    $resharing = $s.isResharingByExternalUsersEnabled
    if ($resharing -eq $false) {
        Add-NRGFinding -ControlId 'SPO-1.4' -State 'Satisfied' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue 'External user resharing: disabled' `
            -RequiredValue 'isResharingByExternalUsersEnabled = false'
    } elseif ($resharing -eq $true) {
        Add-NRGFinding -ControlId 'SPO-1.4' -State 'Gap' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'External users can reshare content they have access to. This allows viral spread of internal content beyond intended recipients.' `
            -CurrentValue 'External user resharing: enabled' `
            -RequiredValue 'isResharingByExternalUsersEnabled = false' `
            -Remediation 'SharePoint admin center > Policies > Sharing > Uncheck "Allow guests to share items they don''t own".' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.4')
    } else {
        Add-NRGFinding -ControlId 'SPO-1.4' -State 'NotApplicable' `
            -Category 'SharePoint' -Title $ctrl.Title `
            -Detail 'Resharing policy state could not be determined from collected data.'
    }

    #--------------------------------------------------------------------------
    # SPO-1.5  Unmanaged device access policy configured
    # AC-17, AC-3 | T1530
    #--------------------------------------------------------------------------
    $ctrl    = Get-NRGControlById -ControlId 'SPO-1.5'
    $caPolicy = $s.conditionalAccessPolicy
    if ($caPolicy -in @('allowLimitedAccess','blockAccess')) {
        $stateLabel = if ($caPolicy -eq 'blockAccess') { 'blocked' } else { 'limited (read-only)' }
        Add-NRGFinding -ControlId 'SPO-1.5' -State 'Satisfied' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "Unmanaged device policy: $stateLabel ($caPolicy)" `
            -RequiredValue 'allowLimitedAccess or blockAccess'
    } elseif ($caPolicy -eq 'allowFullAccess' -or -not $caPolicy) {
        Add-NRGFinding -ControlId 'SPO-1.5' -State 'Gap' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'SharePoint grants full access to unmanaged (non-compliant, non-domain-joined) devices. Data can be downloaded to any unmanaged endpoint.' `
            -CurrentValue "Unmanaged device policy: allowFullAccess" `
            -RequiredValue 'allowLimitedAccess (web-only) or blockAccess' `
            -Remediation 'SharePoint admin center > Policies > Access control > Unmanaged devices > Allow limited, web-only access. Or Block access.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-1.5')
    } else {
        Add-NRGFinding -ControlId 'SPO-1.5' -State 'NotApplicable' `
            -Category 'SharePoint' -Title $ctrl.Title `
            -Detail "Unmanaged device policy state unknown: $caPolicy"
    }

    #--------------------------------------------------------------------------
    # SPO-2.1  OneDrive default sharing scoped to organisation
    # AC-22 | T1530
    #--------------------------------------------------------------------------
    $ctrl          = Get-NRGControlById -ControlId 'SPO-2.1'
    $odLinkScope   = $s.defaultOneDriveSharingLinkScope
    if ($odLinkScope -in @('organization','specificPeople') -or -not $odLinkScope) {
        $currentVal = if ($odLinkScope) { $odLinkScope } else { 'not set (inherits SharePoint policy)' }
        Add-NRGFinding -ControlId 'SPO-2.1' -State 'Satisfied' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "OneDrive default sharing scope: $currentVal" `
            -RequiredValue 'organization or specificPeople'
    } else {
        Add-NRGFinding -ControlId 'SPO-2.1' -State 'Gap' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail "OneDrive default sharing link scope is '$odLinkScope' — files shared by default with anyone, not just internal users." `
            -CurrentValue "OneDrive default scope: $odLinkScope" `
            -RequiredValue 'organization' `
            -Remediation 'SharePoint admin center > OneDrive settings > Default link type > Set to "People in your organization".' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-2.1')
    }

    #--------------------------------------------------------------------------
    # SPO-2.2  Guest user resharing of content they don't own disabled
    # AC-22 | T1530
    #--------------------------------------------------------------------------
    $ctrl         = Get-NRGControlById -ControlId 'SPO-2.2'
    $guestReshare = $s.isGuestUserShareToGuestEnabled
    if ($guestReshare -eq $false) {
        Add-NRGFinding -ControlId 'SPO-2.2' -State 'Satisfied' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue 'Guest-to-guest sharing: disabled' `
            -RequiredValue 'isGuestUserShareToGuestEnabled = false'
    } elseif ($guestReshare -eq $true) {
        Add-NRGFinding -ControlId 'SPO-2.2' -State 'Gap' `
            -Category 'SharePoint' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'Guest users can share content with other guests they invite. Internal content can spread virally to unknown external parties.' `
            -CurrentValue 'Guest-to-guest sharing: enabled' `
            -RequiredValue 'isGuestUserShareToGuestEnabled = false' `
            -Remediation 'SharePoint admin center > Policies > Sharing > Uncheck "Guests can share items they don''t own".' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'SPO-2.2')
    } else {
        Add-NRGFinding -ControlId 'SPO-2.2' -State 'NotApplicable' `
            -Category 'SharePoint' -Title $ctrl.Title `
            -Detail 'Guest sharing state could not be determined — sharing may be disabled at the tenant level.'
    }
}

#
# Test-NRGControl-AAD.ps1
# Evaluates AAD controls against collected raw data.
# SCORING ONLY - no data collection.
#
# Each function reads from Get-NRGRawData and calls Add-NRGFinding.
#

function Test-NRGControl-AAD-LegacyAuth {
    [CmdletBinding()] param()

    $controlId = 'AAD-1.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $caData = (Get-NRGRawData -Key 'AAD-CAPolicies')
    if (-not $caData -or -not $caData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Conditional Access data not collected'
        return
    }

    # Block-legacy-auth = a CA policy with ClientAppTypes containing 'other' or 'exchangeActiveSync' AND grant=Block
    $blockingPolicies = @($caData.Data.Policies | Where-Object {
        $_.State -eq 'enabled' -and
        ($_.Conditions.ClientAppTypes -contains 'other' -or $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync') -and
        $_.GrantControls.BuiltInControls -contains 'block'
    })

    if ($blockingPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail "Legacy authentication blocked by $($blockingPolicies.Count) Conditional Access policy(ies)." `
            -CurrentValue 'Blocked via CA' -RequiredValue 'Blocked' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail 'No enabled Conditional Access policy blocks legacy authentication. Exact-domain accounts can be password-sprayed via POP/IMAP/SMTP.' `
            -CurrentValue 'Not blocked' -RequiredValue 'Blocked tenant-wide via CA' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation `
            -RemediationLink $control.RemediationLink
    }
}

function Test-NRGControl-AAD-PhishResistantMFA {
    [CmdletBinding()] param()

    $controlId = 'AAD-1.2'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }

    $caData = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $caData -or -not $caData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'CA data not collected'
        return
    }

    # Look for policies that:
    # - Target privileged roles
    # - Require an Authentication Strength (phish-resistant)
    $privPolicies = @($caData.Data.Policies | Where-Object {
        $_.State -eq 'enabled' -and
        $_.Conditions.Users.IncludeRoles.Count -gt 0 -and
        $_.GrantControls.AuthenticationStrength
    })

    if ($privPolicies.Count -gt 0) {
        $strengthNames = ($privPolicies | ForEach-Object { $_.GrantControls.AuthenticationStrength.DisplayName }) -join ', '
        Add-NRGFinding -ControlId $controlId -State 'Satisfied' -Category $control.Category `
            -Title $control.Title -Severity 'Informational' `
            -Detail "Phishing-resistant authentication strengths applied to privileged role(s): $strengthNames" `
            -CurrentValue 'Enforced via Auth Strength' -RequiredValue 'FIDO2 or Certificate-based' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId)
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity `
            -Detail 'No Conditional Access policy enforces a phishing-resistant Authentication Strength on privileged roles.' `
            -CurrentValue 'Not enforced' -RequiredValue 'FIDO2 / WHfB / Cert-based for all admin roles' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId $controlId) `
            -Remediation $control.Remediation
    }
}

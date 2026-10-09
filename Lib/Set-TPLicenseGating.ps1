#Requires -Version 7.0
#
# Set-TPLicenseGating.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: A control the tenant is not licensed for is an upgrade
#   opportunity, not a failure. Move every Gap/Partial on such a control out
#   of the score and into the licensing section, with the reason stated.
#
# Data keys: none written. Reads the license profile (AAD-Inventory
#   SubscribedSkus) through Get-TPTenantLicenseProfile, and each control's
#   LicenseRequirement from Config/controls.json.
# Graph / cmdlets: none.
#
# The rule (owner's decision):
#   - Licensed but not configured -> Gap. No credit for what is not there.
#   - Not licensed               -> not scored; reported as "requires <license>".
#   - Partial only for configuration that is genuinely part-way.
#
# Before this, only three Defender evaluators routed unlicensed controls out
# of the score themselves; every other unlicensed, unconfigured control
# scored a Gap and was docked, while the report ALSO listed it as a license
# gap — counted against the tenant for something it could not configure.
#
# Only POSITIVE license evidence moves a finding: with no SKU data at all
# (Graph /subscribedSkus not collected), nothing is moved — "we could not
# read the licenses" is not "the tenant is unlicensed". A finding that PASSED
# is never moved (a configured feature is evidence regardless of license),
# and a finding that is already NotApplicable (e.g. a third-party EDR
# declaration, applied first) is left alone so Cortex clients are not pitched
# Defender for Endpoint.

$script:TPUpgradeMarker = 'surfaced as a licensing upgrade opportunity'

function Set-TPLicenseGating {
    [CmdletBinding()]
    param(
        # Findings to rewrite in place. Defaults to the module's findings;
        # -FromResults passes the findings it loaded from the results JSON.
        [object[]] $Findings,
        # Test seam; defaults to the collected license profile.
        [object] $LicenseProfile
    )
    Initialize-TPState
    $targets = if ($PSBoundParameters.ContainsKey('Findings')) { @($Findings | Where-Object { $null -ne $_ }) } else { @($script:TPFindings) }
    $prof = if ($PSBoundParameters.ContainsKey('LicenseProfile')) { $LicenseProfile } else {
        try { Get-TPTenantLicenseProfile } catch { $null }
    }
    if ($null -eq $prof) { return 0 }
    $skuCount = @(Get-TPObjectField -Item $prof -Key 'SkuPartNumbers' -Default @()).Count
    $spCount  = @(Get-TPObjectField -Item $prof -Key 'ServicePlans' -Default @()).Count
    if ($skuCount -eq 0 -and $spCount -eq 0) { return 0 }

    $changed = 0
    foreach ($f in $targets) {
        $state = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
        if ($state -notin @('Gap', 'Partial')) { continue }
        $cid  = [string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '')
        $ctrl = $null
        try { $ctrl = Get-TPControlById -ControlId $cid } catch { $ctrl = $null }
        if (-not $ctrl) { continue }
        $req = [string](Get-TPObjectField -Item $ctrl -Key 'LicenseRequirement' -Default '')
        if ([string]::IsNullOrWhiteSpace($req) -or $req -match '^Included') { continue }
        # -Finding: a Security Defaults verdict whose remaining fix needs no
        # license (an AAD-1.2 registration shortfall) stays scored; with
        # every user registered, what remains needs Conditional Access, so
        # that finding is gated like any other (Test-TPSecurityDefaultsLicenseFree).
        if (Test-TPLicenseRequirementMet -LicenseRequirement $req -LicenseProfile $prof -ControlId $cid -Finding $f) { continue }

        $before = [string](Get-TPObjectField -Item $f -Key 'Detail' -Default '')
        $f.State        = 'NotApplicable'
        $f.Detail       = "Not scored: this control requires $req, which this tenant does not hold — $script:TPUpgradeMarker, not counted against the score. Result before the license check: $state$(if ($before) { " — $before" })"
        $f.CurrentValue = "Requires $req (not licensed)"
        $changed++
    }
    return $changed
}

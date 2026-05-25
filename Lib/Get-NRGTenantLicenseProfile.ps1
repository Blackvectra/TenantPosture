#Requires -Version 7.0
#
# Get-NRGTenantLicenseProfile.ps1  (v4.6.2)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Single source of truth for tenant license-tier detection. Reads the
#          AAD-Inventory raw data (SubscribedSkus) collected via Graph
#          /subscribedSkus and returns a structured profile plus a suppression
#          HashSet of controls.json LicenseRequirement strings that the tenant
#          has already met. Publishers MUST call this instead of re-implementing
#          regex against SkuPartNumber — duplicated detection logic drifts.
#
# Data consumed: AAD-Inventory (via Get-NRGRawData)
# Functions emitted:
#   Get-NRGTenantLicenseProfile        -> tier profile object
#   Test-NRGLicenseRequirementMet      -> $true/$false for a controls.json
#                                         LicenseRequirement string against
#                                         the supplied profile
#
# Bug history (v4.6.1):
#   The detection logic was inlined inside Publish-NRGAssessmentHTML.ps1 and
#   only applied the suppression set to the "License Gap Analysis" card.
#   Priority Actions, per-finding workload rows, the Markdown summary, the
#   remediation script, and the remediation playbook all printed
#   "Requires: M365 Business Premium..." next to gaps even when the tenant
#   already owned Business Premium (SkuPartNumber=SPB). This helper closes
#   the gap so every publisher sees the same answer.
#
#   The same v4.6.1 code also mis-attributed MFA_PREMIUM (a service plan
#   inside Entra ID P1/P2) to Microsoft Defender for Cloud Apps detection.
#   Fixed here — MDCA matches on ADALLOM_STANDALONE and the ADALLOM_S_*
#   service plan family.
#
# SKU reference (canonical skuPartNumber values, not display names):
#   SPB                     Microsoft 365 Business Premium
#   O365_BUSINESS_PREMIUM   Office 365 Business Premium (legacy alias)
#   M365_BUSINESS_PREMIUM   Defensive alias for forward compatibility
#   AAD_PREMIUM             Entra ID P1 standalone (also a service plan name)
#   AAD_PREMIUM_P2          Entra ID P2 standalone (also a service plan name)
#   EMS / EMSPREMIUM        Enterprise Mobility + Security E3 / E5
#   SPE_E3 / SPE_E5         Microsoft 365 E3 / E5
#   ENTERPRISEPACK / ENTERPRISEPREMIUM   Office 365 E3 / E5
#   INTUNE_A                Microsoft Intune Plan 1 standalone
#   ATP_ENTERPRISE          Defender for Office 365 P1 (service plan name)
#   THREAT_INTELLIGENCE_DEPT  Defender for Office 365 P2 (standalone)
#   ADALLOM_STANDALONE      Defender for Cloud Apps (MDCA, standalone)
#   ENTRA_ID_GOVERNANCE     Entra ID Governance add-on
#   Microsoft_Entra_Suite   Entra Suite (P2 + Verified ID + Internet/Private
#                           Access + Identity Governance)
#

function Get-NRGTenantLicenseProfile {
    [CmdletBinding()]
    param(
        # Optional override — by default reads from module-scope AAD-Inventory.
        # The override exists for unit testing: pass a hashtable list mimicking
        # AAD-Inventory.Data.SubscribedSkus and the helper works without a
        # live tenant.
        [Parameter()] [object[]] $SubscribedSkus
    )

    if (-not $PSBoundParameters.ContainsKey('SubscribedSkus')) {
        $SubscribedSkus = @()
        if (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) {
            try {
                $inv = Get-NRGRawData -Key 'AAD-Inventory'
                if ($inv -and $inv.Success -and $inv.Data -and $inv.Data.SubscribedSkus) {
                    $SubscribedSkus = @($inv.Data.SubscribedSkus)
                }
            } catch {
                # Empty profile — fail safe.
            }
        }
    }

    # Extract part numbers — tolerate hashtable, IDictionary, and PSCustomObject
    $partNumbers = @($SubscribedSkus | ForEach-Object {
        if ($null -eq $_) { return }
        if ($_ -is [System.Collections.IDictionary]) { [string]$_.SkuPartNumber }
        elseif ($_.PSObject.Properties['SkuPartNumber']) { [string]$_.SkuPartNumber }
    } | Where-Object { $_ })

    # Extract service plans — Graph SDK objects expose servicePlanName, the
    # collector stores plain strings.
    $servicePlans = @($SubscribedSkus | ForEach-Object {
        if ($null -eq $_) { return }
        $sps = if ($_ -is [System.Collections.IDictionary]) { $_.ServicePlans }
               elseif ($_.PSObject.Properties['ServicePlans']) { $_.ServicePlans }
               else { @() }
        foreach ($sp in @($sps)) {
            if ($null -eq $sp) { continue }
            if ($sp -is [string]) { $sp }
            elseif ($sp.PSObject.Properties['servicePlanName']) { [string]$sp.servicePlanName }
            elseif ($sp.PSObject.Properties['ServicePlanName']) { [string]$sp.ServicePlanName }
        }
    } | Where-Object { $_ })

    # ── Tier flags ───────────────────────────────────────────────────────────
    # Anchored regexes (^...$) — defensive: bare "SPB" would match "NOT_SPB"
    # in an obscure future SKU, anchoring eliminates that class of false
    # positive at zero cost.

    $hasBusinessPremium = [bool]($partNumbers -match '^(SPB|O365_BUSINESS_PREMIUM|M365_BUSINESS_PREMIUM)$')

    $hasEntraP1 = $hasBusinessPremium -or
                  [bool]($partNumbers -match '^(AAD_PREMIUM|EMS|EMSPREMIUM|SPE_E3|SPE_E5|ENTERPRISEPACK|ENTERPRISEPREMIUM|Microsoft_Entra_Suite)$') -or
                  [bool]($servicePlans -match '^AAD_PREMIUM$')

    $hasEntraP2 = [bool]($partNumbers -match '^(AAD_PREMIUM_P2|EMSPREMIUM|SPE_E5|ENTERPRISEPREMIUM|Microsoft_Entra_Suite|ENTRA_ID_GOVERNANCE|IDENTITY_GOVERNANCE)$') -or
                  [bool]($servicePlans -match '^AAD_PREMIUM_P2$')

    $hasIntune = $hasBusinessPremium -or
                 [bool]($partNumbers -match '^(INTUNE_A|INTUNE_A_VL|EMS|EMSPREMIUM|SPE_E3|SPE_E5)$') -or
                 [bool]($servicePlans -match '^INTUNE_A$')

    $hasMDEP1 = $hasBusinessPremium -or
                [bool]($partNumbers -match '^(MDE_SMB|WIN_DEF_ATP)$') -or
                [bool]($servicePlans -match '^(WIN_DEF_ATP|MDE_SMB|MDE_LITE)$')
    $hasMDEP2 = [bool]($partNumbers -match '^(DEFENDER_ENDPOINT|WINDEFATP|SPE_E5|ENTERPRISEPREMIUM)$') -or
                [bool]($servicePlans -match '^(MDE_P2|WINDEFATP|TVM)$')

    $hasDfOP1 = $hasBusinessPremium -or
                [bool]($servicePlans -match '^ATP_ENTERPRISE$') -or
                [bool]($partNumbers -match '^(EOP_ENTERPRISE_PREMIUM|ATPS_ENTERPRISE)$')
    $hasDfOP2 = [bool]($partNumbers -match '^(THREAT_INTELLIGENCE_DEPT|SPE_E5|ENTERPRISEPREMIUM)$') -or
                [bool]($servicePlans -match '^(THREAT_INTELLIGENCE|MTP)$')

    # MDCA = Microsoft Defender for Cloud Apps. v4.6.1 incorrectly listed
    # MFA_PREMIUM (a P1/P2 service plan) — fixed.
    $hasMDCA = [bool]($partNumbers -match '^(ADALLOM_STANDALONE|SPE_E5|ENTERPRISEPREMIUM)$') -or
               [bool]($servicePlans -match '^(ADALLOM_S_STANDALONE|ADALLOM_S_O365|MCAS)$')

    # ── Headline tier label for report header ───────────────────────────────
    $tierLabel = if ($partNumbers -match '^(SPE_E5|ENTERPRISEPREMIUM)$') { 'Microsoft 365 E5' }
                 elseif ($partNumbers -match '^SPE_E3$')                  { 'Microsoft 365 E3' }
                 elseif ($hasBusinessPremium)                             { 'Microsoft 365 Business Premium' }
                 elseif ($partNumbers -match '^(O365_BUSINESS_ESSENTIALS|O365_BUSINESS|O365_BUSINESS_STANDARD)$') { 'Microsoft 365 Business Standard' }
                 elseif ($partNumbers -match '^EXCHANGESTANDARD$')        { 'Exchange Online Plan 1' }
                 else                                                     { 'Microsoft 365 Basic / Other' }

    # Append major add-ons to the label so the report header is informative
    # without burying the headline tier.
    $addons = @()
    if ($hasEntraP2 -and -not ($partNumbers -match '^(SPE_E5|ENTERPRISEPREMIUM)$')) {
        if ($partNumbers -match '^Microsoft_Entra_Suite$') { $addons += 'Entra Suite (P2)' }
        elseif ($partNumbers -match '^AAD_PREMIUM_P2$')    { $addons += 'Entra ID P2' }
    }
    if ($partNumbers -match '^Microsoft_365_Copilot$') { $addons += 'Copilot' }
    if ($addons.Count -gt 0) { $tierLabel = "$tierLabel + $($addons -join ' + ')" }

    # ── Suppression set ──────────────────────────────────────────────────────
    # These strings MUST match controls.json LicenseRequirement values exactly
    # (case-insensitive). The HashSet uses OrdinalIgnoreCase so casing drift
    # in controls.json does not silently disable suppression.
    $suppressedLicReqs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if ($hasBusinessPremium) {
        @(
            'Defender for Office 365 Plan 1 (M365 Business Premium)',
            'M365 Business Premium or E3+',
            'M365 Business Premium or E3+ (Copilot requires M365 Copilot add-on)',
            'M365 Business Premium or Entra ID P1',
            'M365 Business Premium or Entra ID P1 + Intune',
            'M365 Business Premium or Intune Plan 1',
            'Microsoft Defender for Endpoint Plan 1+'
        ) | ForEach-Object { $null = $suppressedLicReqs.Add($_) }
    }
    if ($hasEntraP1 -and -not $hasBusinessPremium) {
        # M365 E3 / EMS holders without BP: P1 alone satisfies "BP or P1".
        $null = $suppressedLicReqs.Add('M365 Business Premium or Entra ID P1')
    }
    if ($hasEntraP2) {
        @(
            'Entra ID P2',
            'Entra ID P2 + Workload Identities add-on',
            'Included (all plans) — Access Reviews require Entra P2'
        ) | ForEach-Object { $null = $suppressedLicReqs.Add($_) }
    }
    if ($hasIntune) {
        @(
            'M365 Business Premium or Intune Plan 1',
            'M365 Business Premium or Entra ID P1 + Intune'
        ) | ForEach-Object { $null = $suppressedLicReqs.Add($_) }
    }
    if ($hasMDEP1) { $null = $suppressedLicReqs.Add('Microsoft Defender for Endpoint Plan 1+') }
    if ($hasMDEP2) { $null = $suppressedLicReqs.Add('Microsoft Defender for Endpoint Plan 2') }
    if ($hasDfOP1) { $null = $suppressedLicReqs.Add('Defender for Office 365 Plan 1 (M365 Business Premium)') }
    if ($hasDfOP2) { $null = $suppressedLicReqs.Add('Defender for Office 365 Plan 2') }
    if ($hasMDCA)  { $null = $suppressedLicReqs.Add('Microsoft Defender for Cloud Apps (M365 E5 or add-on)') }

    return [pscustomobject]([ordered]@{
        TierLabel                     = $tierLabel
        HasBusinessPremium            = $hasBusinessPremium
        HasEntraP1                    = $hasEntraP1
        HasEntraP2                    = $hasEntraP2
        HasIntune                     = $hasIntune
        HasMDEP1                      = $hasMDEP1
        HasMDEP2                      = $hasMDEP2
        HasDfOP1                      = $hasDfOP1
        HasDfOP2                      = $hasDfOP2
        HasMDCA                       = $hasMDCA
        SkuPartNumbers                = $partNumbers
        ServicePlans                  = $servicePlans
        SuppressedLicenseRequirements = $suppressedLicReqs
    })
}

function Test-NRGLicenseRequirementMet {
    <#
    .SYNOPSIS
        Returns $true if the tenant already holds the license for this
        controls.json LicenseRequirement string.
    .DESCRIPTION
        Publishers should NOT inline the suppression check. Call this and
        only emit "Requires: ..." labels when it returns $false. Treats
        null/empty/"Included*" requirements as already met.
    .PARAMETER LicenseRequirement
        The exact string from controls.json LicenseRequirement field.
    .PARAMETER Profile
        The output of Get-NRGTenantLicenseProfile. Required — passing null
        means "no SKU data" and we conservatively return $false so the
        publisher labels the gap as license-gated rather than silently
        suppressing a real upgrade need.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $LicenseRequirement,
        [Parameter()] [AllowNull()] [object] $Profile
    )

    if ([string]::IsNullOrEmpty($LicenseRequirement)) { return $true }
    if ($LicenseRequirement -match '^Included') { return $true }
    if ($null -eq $Profile -or -not $Profile.SuppressedLicenseRequirements) { return $false }
    return [bool]$Profile.SuppressedLicenseRequirements.Contains($LicenseRequirement)
}

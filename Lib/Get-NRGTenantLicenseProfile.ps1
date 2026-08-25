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
    if ($hasDfOP2) {
        # v4.6.4 FIX: prior code only added the short string 'Defender for Office 365 Plan 2'
        # but controls.json now uses the parenthetical variant. Add BOTH so we
        # tolerate either form without silently failing to suppress.
        $null = $suppressedLicReqs.Add('Defender for Office 365 Plan 2')
        $null = $suppressedLicReqs.Add('Defender for Office 365 Plan 2 (M365 E5 or add-on)')
    }
    if ($hasMDCA)  { $null = $suppressedLicReqs.Add('Microsoft Defender for Cloud Apps (M365 E5 or add-on)') }

    # v4.6.4 FIX: 7 controls.json LicenseRequirement strings previously had no
    # matching suppression entry — so even tenants holding the right SKU were
    # incorrectly told they were missing a license. Map each to the right tier
    # flag now.
    # E5 / E5-Compliance umbrella: only fully suppressed when the tenant
    # actually holds an E5 SKU (THREAT_INTELLIGENCE_DEPT, SPE_E5, or
    # ENTERPRISEPREMIUM all imply E5 Compliance).
    $hasE5Compliance = [bool]($partNumbers -match '^(SPE_E5|ENTERPRISEPREMIUM|INFORMATION_PROTECTION_COMPLIANCE)$') -or
                       [bool]($servicePlans -match '^(EQUIVIO_ANALYTICS|RECORDS_MANAGEMENT|INFORMATION_BARRIERS|COMMUNICATIONS_COMPLIANCE|INSIDER_RISK_MANAGEMENT)$')
    if ($hasE5Compliance) {
        $null = $suppressedLicReqs.Add('M365 E5 Compliance add-on')
        $null = $suppressedLicReqs.Add('M365 E5 or E5 Compliance add-on')
    }
    # Sentinel / Defender XDR: XDR ships with E5; Sentinel itself is a separate
    # Azure SKU not in SubscribedSkus, so we suppress only on E5 / Defender XDR.
    if ($hasDfOP2 -or $partNumbers -match '^(SPE_E5|ENTERPRISEPREMIUM)$') {
        $null = $suppressedLicReqs.Add('Microsoft Sentinel (add-on) or Defender XDR')
    }
    # Entra Workload Identities Premium add-on — only suppress when the actual
    # add-on SKU is present (separate purchase from Entra P1/P2).
    if ([bool]($partNumbers -match '^Microsoft_Entra_Workload_Identities_Premium$')) {
        $null = $suppressedLicReqs.Add('Entra Workload Identities Premium (add-on)')
    }
    # M365 Copilot add-on — exact string includes special chars and a $ amount;
    # HashSet uses OrdinalIgnoreCase but we still must match the literal string.
    if ([bool]($partNumbers -match '^Microsoft_365_Copilot$')) {
        $null = $suppressedLicReqs.Add('M365 Copilot add-on license')
    }
    # Power Platform + Copilot Studio — Copilot Studio is sold as part-number
    # Microsoft_Copilot_Studio_in_Microsoft_Teams or POWERAPPS_PER_USER.
    if ([bool]($partNumbers -match '^(POWERAPPS_PER_USER|Microsoft_Copilot_Studio|POWER_AUTOMATE_PLAN)') -or
        [bool]($servicePlans -match '^(POWERAPPS_PER_USER|POWER_AUTOMATE_USER_RPA)$')) {
        $null = $suppressedLicReqs.Add('Power Platform + Copilot Studio license')
    }

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
    .PARAMETER LicenseProfile
        The output of Get-NRGTenantLicenseProfile. Required — passing null
        means "no SKU data" and we conservatively return $false so the
        publisher labels the gap as license-gated rather than silently
        suppressing a real upgrade need.

        Renamed from -Profile in v4.9.x to avoid shadowing PowerShell's
        built-in $Profile automatic variable, which PSScriptAnalyzer
        flags via PSAvoidAssignmentToAutomaticVariable. No alias is
        kept because the runner's older PSA still trips on the alias
        name itself; the only callers are internal tests, which have
        been migrated in lockstep.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $LicenseRequirement,
        [Parameter()] [AllowNull()] [object] $LicenseProfile
    )

    if ([string]::IsNullOrEmpty($LicenseRequirement)) { return $true }
    if ($LicenseRequirement -match '^Included') { return $true }
    if ($null -eq $LicenseProfile -or -not $LicenseProfile.SuppressedLicenseRequirements) { return $false }
    if ($LicenseProfile.SuppressedLicenseRequirements.Contains($LicenseRequirement)) { return $true }

    # Matching is otherwise exact, which makes it brittle against the one kind
    # of edit these strings actually receive: a trailing price annotation.
    # "M365 Copilot add-on license ($30/user/month)" and "M365 Copilot add-on
    # license" are the same requirement, but an exact-match miss silently flips
    # the answer to "not licensed" — and the visible effect is a Copilot tenant
    # being told on its own report that it needs to buy Copilot. Retry once
    # with a trailing price parenthetical removed.
    #
    # Deliberately narrow: the parenthetical must contain a currency amount, so
    # meaningful qualifiers like "(add-on)" or "(M365 E5 or add-on)" — which
    # distinguish genuinely different requirements — are never stripped.
    $priceStripped = [regex]::Replace($LicenseRequirement, '\s*\([^()]*\$\s*\d[^()]*\)\s*$', '')
    if ($priceStripped -ne $LicenseRequirement -and $priceStripped) {
        return [bool]$LicenseProfile.SuppressedLicenseRequirements.Contains($priceStripped)
    }
    return $false
}

function Get-NRGControlLicenseStatus {
    <#
    .SYNOPSIS
        Evaluator-facing license gate. Given a ControlId, answers whether the
        tenant holds the license that control's assessment requires.
    .DESCRIPTION
        Returns one of three strings so an evaluator can pick an HONEST state
        when the workload's data is unavailable, instead of emitting a
        confident (and often false) gap:

          'Met'     — the tenant holds the required license (or the control has
                      no license requirement). Unavailable data is therefore a
                      real collection problem, not a licensing gap → the
                      evaluator should emit 'Error'.
          'NotMet'  — the tenant demonstrably lacks the license, so the control
                      literally cannot be configured — it is not a
                      misconfiguration → the evaluator should emit
                      'NotApplicable' (license-gated, an upgrade opportunity),
                      keeping it out of the compliance score.
          'Unknown' — no SubscribedSkus data was collected, so licensing cannot
                      be determined → the evaluator should stay conservative
                      ('NotApplicable' advisory), never a confident gap.

        Reads the license profile from the already-collected AAD-Inventory raw
        data via Get-NRGTenantLicenseProfile — no extra Graph call.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $ControlId)

    $req = ''
    if (Get-Command Get-NRGControlById -ErrorAction SilentlyContinue) {
        try {
            $c = Get-NRGControlById -ControlId $ControlId
            if ($c -and $c.LicenseRequirement) { $req = [string]$c.LicenseRequirement }
        } catch { }
    }
    if ([string]::IsNullOrEmpty($req) -or $req -match '^Included') { return 'Met' }

    $prof = $null
    if (Get-Command Get-NRGTenantLicenseProfile -ErrorAction SilentlyContinue) {
        try { $prof = Get-NRGTenantLicenseProfile } catch { $prof = $null }
    }
    if ($null -eq $prof) { return 'Unknown' }

    # No SKU data collected at all → we can't tell; stay conservative.
    $skuCount = @($prof.SkuPartNumbers).Count
    $spCount  = @($prof.ServicePlans).Count
    if ($skuCount -eq 0 -and $spCount -eq 0) { return 'Unknown' }

    if (Test-NRGLicenseRequirementMet -LicenseRequirement $req -LicenseProfile $prof) { return 'Met' }
    return 'NotMet'
}

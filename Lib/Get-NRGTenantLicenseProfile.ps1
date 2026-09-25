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
#   O365_BUSINESS_PREMIUM   Microsoft 365 Business STANDARD (despite the name —
#                           Microsoft's licensing reference; no Entra P1, Intune
#                           or Defender plans). It was matched as Business
#                           Premium, so every Business Standard tenant was
#                           labeled Business Premium and scored as licensed for
#                           P1 / Intune / Defender controls it cannot configure.
#   O365_BUSINESS_ESSENTIALS  Microsoft 365 Business Basic
#   O365_BUSINESS / SMB_BUSINESS  Microsoft 365 Apps for business
#   Office_365_w/o_Teams_Bundle_Business_Premium, Microsoft_365_Business_Premium_(no Teams)
#                           Business Premium without Teams (EEA / global)
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

$script:NRGLicensePlanRules = $null

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
    # collector stores plain strings. Trimmed: Microsoft's own reference lists
    # 'ATP_ENTERPRISE ' with a trailing space in some SKUs.
    $servicePlans = @($SubscribedSkus | ForEach-Object {
        if ($null -eq $_) { return }
        $sps = if ($_ -is [System.Collections.IDictionary]) { $_['ServicePlans'] }
               elseif ($_.PSObject.Properties['ServicePlans']) { $_.ServicePlans }
               else { @() }
        foreach ($sp in @($sps)) {
            if ($null -eq $sp) { continue }
            if ($sp -is [string]) { $sp.Trim() }
            elseif ($sp.PSObject.Properties['servicePlanName']) { ([string]$sp.servicePlanName).Trim() }
            elseif ($sp.PSObject.Properties['ServicePlanName']) { ([string]$sp.ServicePlanName).Trim() }
        }
    } | Where-Object { $_ })

    $planSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($servicePlans), [System.StringComparer]::OrdinalIgnoreCase)
    $hasPlanData = $planSet.Count -gt 0
    $has = { param([string[]] $Names) foreach ($n in $Names) { if ($planSet.Contains($n)) { return $true } }; return $false }

    # ── Tier flags ───────────────────────────────────────────────────────────
    # SERVICE PLANS are the authority: they are what the tenant can actually
    # use, whatever the product is called, and they cover every government,
    # education, no-Teams and EEA variant without a part-number list. Part
    # numbers are the fallback only when no plan data exists (older results).
    #
    # Part-number reading got the enterprise suites wrong in both directions:
    # Office 365 E3/E5 (ENTERPRISEPACK / ENTERPRISEPREMIUM) carry NO Entra ID
    # P1/P2 and no Defender for Endpoint, yet were read as having them; and
    # Microsoft 365 E5 carries Defender for Endpoint Plan 2 (WINDEFATP), which
    # includes Plan 1, yet "Plan 1+" was not met. Since unlicensed controls are
    # taken out of the score, that second error hid real gaps on E5 tenants.

    $hasBusinessPremium = [bool]($partNumbers -match '^(SPB|M365_BUSINESS_PREMIUM|Office_365_w/o_Teams_Bundle_Business_Premium)$') -or
                          [bool]($partNumbers -match '^Microsoft_365_\s*Business_\s*Premium')
    # Enterprise E3 / E5 (Microsoft 365 or Office 365), including government
    # variants (…_GOV, …_USGOV_*).
    $hasE3Plus = [bool]($partNumbers -match '^(SPE_E3|SPE_E5|ENTERPRISEPACK|ENTERPRISEPREMIUM|M365_G3|M365_G5|Microsoft_365_E3|Microsoft_365_E5|O365_w/o_Teams_Bundle_M3|O365_w/o_Teams_Bundle_M5)')
    $m365E5    = '^(SPE_E5|M365_G5|Microsoft_365_E5|O365_w/o_Teams_Bundle_M5)'
    $m365E3    = '^(SPE_E3|M365_G3|Microsoft_365_E3|O365_w/o_Teams_Bundle_M3)'

    if ($hasPlanData) {
        $hasEntraP1 = & $has 'AAD_PREMIUM','AAD_PREMIUM_P2'
        $hasEntraP2 = & $has 'AAD_PREMIUM_P2'
        $hasIntune  = & $has 'INTUNE_A','INTUNE_A_GOV','INTUNE_A_VL','INTUNE_EDU','INTUNE_SMBIZ'
        $hasMDEP1   = & $has 'MDE_LITE','MDE_SMB','WINDEFATP'
        $hasMDEP2   = & $has 'WINDEFATP'
        $hasDfOP1   = & $has 'ATP_ENTERPRISE','ATP_ENTERPRISE_GOV','THREAT_INTELLIGENCE','THREAT_INTELLIGENCE_GOV'
        $hasDfOP2   = & $has 'THREAT_INTELLIGENCE','THREAT_INTELLIGENCE_GOV'
        $hasMDCA    = & $has 'ADALLOM_S_STANDALONE','ADALLOM_S_STANDALONE_DOD'
    } else {
        $hasEntraP1 = $hasBusinessPremium -or
                      [bool]($partNumbers -match '^(AAD_PREMIUM|AAD_PREMIUM_P2|EMS|EMSPREMIUM|Microsoft_Entra_Suite)$') -or
                      [bool]($partNumbers -match $m365E3) -or [bool]($partNumbers -match $m365E5)
        $hasEntraP2 = [bool]($partNumbers -match '^(AAD_PREMIUM_P2|EMSPREMIUM|Microsoft_Entra_Suite)$') -or [bool]($partNumbers -match $m365E5)
        $hasIntune  = $hasBusinessPremium -or [bool]($partNumbers -match '^(INTUNE_A|INTUNE_A_VL|EMS|EMSPREMIUM)$') -or
                      [bool]($partNumbers -match $m365E3) -or [bool]($partNumbers -match $m365E5)
        $hasMDEP2   = [bool]($partNumbers -match '^(WIN_DEF_ATP|DEFENDER_ENDPOINT|MDATP_XPLAT)$') -or [bool]($partNumbers -match $m365E5)
        $hasMDEP1   = $hasMDEP2 -or $hasBusinessPremium -or [bool]($partNumbers -match '^(MDE_SMB|DEFENDER_ENDPOINT_P1)') -or [bool]($partNumbers -match $m365E3)
        $hasDfOP2   = [bool]($partNumbers -match '^(THREAT_INTELLIGENCE|ENTERPRISEPREMIUM)') -or [bool]($partNumbers -match $m365E5)
        $hasDfOP1   = $hasDfOP2 -or $hasBusinessPremium -or [bool]($partNumbers -match '^(ATP_ENTERPRISE|EOP_ENTERPRISE_PREMIUM|ATPS_ENTERPRISE)')
        $hasMDCA    = [bool]($partNumbers -match '^(ADALLOM_STANDALONE|EMSPREMIUM)$') -or [bool]($partNumbers -match $m365E5)
    }

    # ── Headline tier label for report header ───────────────────────────────
    $tierLabel = if ($partNumbers -match $m365E5)                        { 'Microsoft 365 E5' }
                 elseif ($partNumbers -match '^ENTERPRISEPREMIUM')         { 'Office 365 E5' }
                 elseif ($partNumbers -match $m365E3)                      { 'Microsoft 365 E3' }
                 elseif ($partNumbers -match '^ENTERPRISEPACK')            { 'Office 365 E3' }
                 elseif ($hasBusinessPremium)                              { 'Microsoft 365 Business Premium' }
                 elseif ($partNumbers -match '^O365_BUSINESS_PREMIUM$')    { 'Microsoft 365 Business Standard' }
                 elseif ($partNumbers -match '^O365_BUSINESS_ESSENTIALS$') { 'Microsoft 365 Business Basic' }
                 elseif ($partNumbers -match '^(O365_BUSINESS|SMB_BUSINESS)$') { 'Microsoft 365 Apps for business' }
                 elseif ($partNumbers -match '^EXCHANGESTANDARD$')         { 'Exchange Online Plan 1' }
                 elseif ($partNumbers.Count -eq 0)                         { 'Unknown (licensing not read)' }
                 else                                                      { 'Microsoft 365 Basic / Other' }

    # Append major add-ons to the label so the report header is informative
    # without burying the headline tier.
    $addons = @()
    if ($hasEntraP2 -and -not ($partNumbers -match $m365E5)) {
        if ($partNumbers -match '^Microsoft_Entra_Suite') { $addons += 'Entra Suite (P2)' }
        elseif ($partNumbers -match '^(AAD_PREMIUM_P2|EMSPREMIUM)$') { $addons += 'Entra ID P2' }
    }
    if ($partNumbers -match '^Microsoft_365_Copilot') { $addons += 'Copilot' }
    if ($addons.Count -gt 0) { $tierLabel = "$tierLabel + $($addons -join ' + ')" }

    # ── Suppression set ──────────────────────────────────────────────────────
    # LicenseRequirement strings (controls.json) the tenant satisfies. The
    # HashSet uses OrdinalIgnoreCase so casing drift in controls.json does not
    # silently disable suppression.
    $suppressedLicReqs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if ($hasPlanData) {
        # Every requirement string is decided by its service-plan rule
        # (Config/license-service-plans.json). Per-control rules are applied
        # by Test-NRGLicenseRequirementMet -ControlId.
        $rules = Get-NRGLicensePlanRules
        foreach ($req in @($rules.Requirements.Keys)) {
            if (Test-NRGLicensePlanRule -Rule $rules.Requirements[$req] -PlanSet $planSet) { $null = $suppressedLicReqs.Add($req) }
        }
    } else {
        if ($hasBusinessPremium -or $hasE3Plus) {
            @('M365 Business Premium or E3+',
              'M365 Business Premium or E3+ (Copilot requires M365 Copilot add-on)') | ForEach-Object { $null = $suppressedLicReqs.Add($_) }
        }
        if ($hasBusinessPremium -or $hasE3Plus) {
            $null = $suppressedLicReqs.Add('Exchange Online Plan 2 or Exchange Online Archiving (M365 Business Premium, E3, E5)')
        }
        if ($hasEntraP1) { $null = $suppressedLicReqs.Add('M365 Business Premium or Entra ID P1') }
        if ($hasEntraP1 -and $hasIntune) { $null = $suppressedLicReqs.Add('M365 Business Premium or Entra ID P1 + Intune') }
        if ($hasIntune)  { $null = $suppressedLicReqs.Add('M365 Business Premium or Intune Plan 1') }
        if ($hasEntraP2) { $null = $suppressedLicReqs.Add('Entra ID P2') }
        if ($hasMDEP1)   { $null = $suppressedLicReqs.Add('Microsoft Defender for Endpoint Plan 1+') }
        if ($hasMDEP2 -or $hasBusinessPremium) { $null = $suppressedLicReqs.Add('Microsoft Defender for Endpoint Plan 2 or Defender for Business (M365 Business Premium)') }
        if ($hasDfOP1)   { $null = $suppressedLicReqs.Add('Defender for Office 365 Plan 1 (M365 Business Premium)') }
        if ($hasDfOP2)   { $null = $suppressedLicReqs.Add('Defender for Office 365 Plan 2 (M365 E5 or add-on)') }
        if ($hasMDCA)    { $null = $suppressedLicReqs.Add('Microsoft Defender for Cloud Apps (M365 E5 or add-on)') }
        if ([bool]($partNumbers -match $m365E5) -or [bool]($partNumbers -match '^(ENTERPRISEPREMIUM|INFORMATION_PROTECTION_COMPLIANCE)$')) {
            $null = $suppressedLicReqs.Add('M365 E5 Compliance add-on')
            $null = $suppressedLicReqs.Add('M365 E5 or E5 Compliance add-on')
        }
        if ($hasDfOP2 -or [bool]($partNumbers -match $m365E5)) { $null = $suppressedLicReqs.Add('Microsoft Sentinel (add-on) or Defender XDR') }
        if ([bool]($partNumbers -match '^Microsoft_365_Copilot')) { $null = $suppressedLicReqs.Add('M365 Copilot add-on license') }
        if ([bool]($partNumbers -match '^(Microsoft_Entra_Workload_Identities_Premium|Workload_Identities_P2|Workload_Identities_Premium)')) {
            $null = $suppressedLicReqs.Add('Entra Workload Identities Premium (add-on)')
        }
        if ([bool]($partNumbers -match '^(POWERAPPS_PER_USER|Microsoft_Copilot_Studio|Power_Virtual_Agents|POWER_AUTOMATE_PLAN)')) {
            $null = $suppressedLicReqs.Add('Power Platform + Copilot Studio license')
        }
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
        HasLicenseData                = ($partNumbers.Count -gt 0 -or $hasPlanData)
        SkuPartNumbers                = $partNumbers
        ServicePlans                  = $servicePlans
        SuppressedLicenseRequirements = $suppressedLicReqs
    })
}

function Get-NRGLicensePlanRules {
    <#
    .SYNOPSIS
        Loads Config/license-service-plans.json once: which service plans
        satisfy each LicenseRequirement string, plus per-control overrides.
    #>
    [CmdletBinding()]
    param()
    if ($script:NRGLicensePlanRules) { return $script:NRGLicensePlanRules }
    $moduleRoot = $PSScriptRoot ? (Split-Path -Parent $PSScriptRoot) : (Get-Location).Path
    $path = Join-Path $moduleRoot 'Config' 'license-service-plans.json'
    $req  = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ctl  = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $json = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable
    foreach ($k in $json['requirements'].Keys) { $req[$k] = $json['requirements'][$k] }
    foreach ($k in $json['controls'].Keys) { if ($k -notlike '_*') { $ctl[$k] = $json['controls'][$k] } }
    $script:NRGLicensePlanRules = [pscustomobject]@{ Requirements = $req; Controls = $ctl }
    return $script:NRGLicensePlanRules
}

function Test-NRGLicensePlanRule {
    <#
    .SYNOPSIS
        True when every group of the rule has at least one plan in the set.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([object[]] $Rule, [System.Collections.Generic.HashSet[string]] $PlanSet)
    if (-not $Rule -or $Rule.Count -eq 0 -or -not $PlanSet) { return $false }
    foreach ($group in $Rule) {
        $hit = $false
        foreach ($plan in @($group)) { if ($PlanSet.Contains(([string]$plan).Trim())) { $hit = $true; break } }
        if (-not $hit) { return $false }
    }
    return $true
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
        [Parameter()] [AllowNull()] [object] $LicenseProfile,
        # Optional. Several controls share one requirement string but need
        # different features (Customer Lockbox and Endpoint DLP are both
        # "M365 E5 or E5 Compliance add-on"); with the ControlId, the
        # control's own service-plan rule decides when plan data exists.
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ControlId
    )

    if ([string]::IsNullOrEmpty($LicenseRequirement)) { return $true }
    if ($LicenseRequirement -match '^Included') { return $true }
    if ($null -eq $LicenseProfile) { return $false }

    if ($ControlId) {
        $plans = @(Get-NRGObjectField -Item $LicenseProfile -Key 'ServicePlans' -Default @()) | Where-Object { $_ }
        if (@($plans).Count -gt 0) {
            $rules = Get-NRGLicensePlanRules
            if ($rules.Controls.ContainsKey($ControlId)) {
                $set = [System.Collections.Generic.HashSet[string]]::new([string[]]@($plans | ForEach-Object { ([string]$_).Trim() }), [System.StringComparer]::OrdinalIgnoreCase)
                return (Test-NRGLicensePlanRule -Rule $rules.Controls[$ControlId] -PlanSet $set)
            }
        }
    }

    if (-not $LicenseProfile.SuppressedLicenseRequirements) { return $false }
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

    if (Test-NRGLicenseRequirementMet -LicenseRequirement $req -LicenseProfile $prof -ControlId $ControlId) { return 'Met' }
    return 'NotMet'
}

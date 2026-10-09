#Requires -Version 7.0
#
# TenantPosture.psm1  (version sourced from TenantPosture.psd1 at runtime)
# Module loader — dot-sources all functions from Lib, Collectors, Evaluators, Publishers.
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# SECURITY HARDENING (v4.5.5):
#   - StrictMode Latest: catches uninitialized variables, property access on $null
#   - EAP Stop at module scope: dot-source failures surface immediately
#   - LiteralPath everywhere: prevents wildcard expansion on folder/file paths
#   - Path traversal check: each dot-sourced file must resolve inside $PSScriptRoot
#   - Import-PowerShellDataFile uses -LiteralPath: prevents wildcard in branding path
#   - StrictMode stays on (Set-StrictMode -Version Latest is not disabled);
#     collectors that touch potentially-null properties use null-coalescing
#     operators or explicit null checks — never a global strict-mode disable.
#
# OWASP ASVS V16.4.1 — strict mode for early error detection
# OWASP A01          — path traversal prevention on dot-sourced files
#

# Disable WAM broker before any EOM module loads
$env:MSAL_ALLOW_BROKER = '0'
$env:MSAL_DISABLE_TOKENBROKER = '1'

$ErrorActionPreference = 'Stop'

# OWASP ASVS V16.4.1 — strict mode catches uninitialized variables, property
# access on $null, and indexing past array end. Activated module-wide so every
# dot-sourced collector/evaluator/publisher runs under the same semantics. The
# Pester invariant in Testing/TP.Security.Tests.ps1 enforces presence of this
# directive in production code going forward.
Set-StrictMode -Version Latest

# Version is resolved from the sibling manifest at load time rather than kept
# as a literal here. The literal drifted across four releases (it read 4.11.1
# while the manifest said 4.12.1), and because $TPAssessmentVersion is exported
# via VariablesToExport, module-direct callers and the report metadata saw the
# stale value. Fallback to 'unknown' is defensive: manifest parsing should never
# fail at load time, but if it does the module should load with a clearly
# flagged version rather than silently shipping a wrong one.
$script:TPModuleRoot        = $PSScriptRoot
$script:TPAssessmentVersion = try {
    $manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'TenantPosture.psd1') -ErrorAction Stop
    [string]$manifest.ModuleVersion
} catch {
    'unknown'
}

# Thread-safe collections for module state
$script:TPFindings   = [System.Collections.Generic.List[object]]::new()
$script:TPExceptions = [System.Collections.Generic.List[object]]::new()
$script:TPCoverage   = [System.Collections.Generic.Dictionary[string,string]]::new()
$script:TPRawData    = [System.Collections.Hashtable]::Synchronized(@{})

# ── Branding ──────────────────────────────────────────────────────────────────
# LiteralPath prevents wildcard expansion on the path.
# OWASP A01 / ASVS V12.3.1
# The active profile. TP_PROFILE names Config/profiles/<name>.psd1 (a short
# lower-case token, never a path); otherwise Config/branding.psd1; otherwise
# neutral defaults. A profile is data only (Import-PowerShellDataFile), never
# executed. The NRG and NLS practices ship as profiles; the neutral default is
# what the public tool runs with.
$brandPath = Join-Path $PSScriptRoot 'Config' 'branding.psd1'
$script:TPProfileName = 'branding'
$envProfile = [string]$env:TP_PROFILE
if ($envProfile) {
    if ($envProfile -cmatch '\A[a-z0-9][a-z0-9-]{0,31}\z') {
        $candidate = Join-Path $PSScriptRoot 'Config' 'profiles' "$envProfile.psd1"
        if (Test-Path -LiteralPath $candidate) { $brandPath = $candidate; $script:TPProfileName = $envProfile }
        else { Write-Warning "TP_PROFILE '$envProfile' has no Config/profiles/$envProfile.psd1; using Config/branding.psd1." }
    } else {
        Write-Warning "TP_PROFILE is not a profile name (lower-case letters, digits and hyphens only); using Config/branding.psd1."
    }
}
$script:TPBrand = if (Test-Path -LiteralPath $brandPath) {
    try {
        Import-PowerShellDataFile -LiteralPath $brandPath -ErrorAction Stop
    } catch {
        Write-Warning "Branding file invalid, using defaults: $_"
        $null
    }
} else {
    $null
}

if (-not $script:TPBrand) {
    $script:TPBrand = @{
        CompanyName      = 'TenantPosture'
        Phone            = ''
        Website          = ''
        Email            = ''
        PrimaryColor     = '#1a3a6b'
        SecondaryColor   = '#e87722'
        AccentColor      = '#4a7ba6'
        LogoUrl          = ''
        DefaultFramework = 'All'
    }
}
if ($script:TPBrand -is [System.Collections.IDictionary] -and -not $script:TPBrand.Contains('ProfileName')) {
    $script:TPBrand['ProfileName'] = $script:TPProfileName
}

# ── Module file loader ────────────────────────────────────────────────────────
# Each dot-sourced file is verified to resolve inside $PSScriptRoot before loading.
# This prevents a malformed filename from causing a path traversal load.
# OWASP A01 / ASVS V12.3.1
               # v4.12.0: Email-IR (incident response mode for compromised
               # single-user mailboxes) lives in its own top-level subtree
               # for visible separation from the posture assessment.
$loadOrder = @('Lib', 'Collectors', 'Evaluators', 'Publishers',
               'Email-IR/Lib', 'Email-IR/Collectors', 'Email-IR/Evaluators', 'Email-IR/Publishers')

foreach ($folder in $loadOrder) {
    $folderPath = Join-Path $PSScriptRoot $folder

    if (-not (Test-Path -LiteralPath $folderPath)) {
        Write-Warning "Module folder not found: $folder"
        continue
    }

    $files = Get-ChildItem -LiteralPath $folderPath -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue

    foreach ($file in $files) {
        # OWASP ASVS V12.3.1 / CWE-22 — verify the resolved path is inside
        # PSScriptRoot before dot-sourcing. Use Resolve-Path which follows
        # symlinks (vs. [Path]::GetFullPath, which canonicalizes but does
        # NOT resolve symlinks). A symlink under a Collectors/ subdirectory
        # pointing outside the module root would have passed the prior
        # GetFullPath check; Resolve-Path catches it.
        try {
            $resolvedFile   = (Resolve-Path -LiteralPath $file.FullName).ProviderPath
            $resolvedModule = (Resolve-Path -LiteralPath $PSScriptRoot).ProviderPath
        } catch {
            Write-Warning "Skipping file with unresolvable path: $($file.FullName)"
            continue
        }

        if (-not $resolvedFile.StartsWith($resolvedModule, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning "Skipping file outside module root (symlink/path traversal?): $($file.FullName) -> $resolvedFile"
            continue
        }

        try {
            # Redirect information stream (3>) to suppress verbose module load noise
            . $file.FullName 3>$null
        } catch {
            $loadMsg = "Failed to load $($file.Name): $($_.Exception.Message)"
            Write-Warning $loadMsg
            # v4.6.3 P2: surface load failures into the run's exception list so
            # Get-TPExceptions / the JSON output includes them. Without this,
            # a dot-source failure was a Write-Warning only — operators only
            # noticed if they were watching the console. Note Register-TPException
            # may not exist yet if Add-TPFinding.ps1 was the file that failed —
            # guard with Get-Command.
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                try { Register-TPException -Source 'ModuleLoader' -Message $loadMsg } catch { }
            }
        }
    }
}

# ── Exported function list ────────────────────────────────────────────────────
$script:ExportedFunctions = @(
    # ── Lib helpers ───────────────────────────────────────────────────────────
    'Add-TPFinding', 'Get-TPFindings', 'Clear-TPFindings', 'Clear-TPState',
    'Register-TPException', 'Get-TPExceptions',
    'Register-TPCoverage', 'Get-TPCoverage',
    'Set-TPRawData', 'Get-TPRawData',
    'Connect-TPServices', 'Disconnect-TPServices',
    'ConvertTo-TPHtmlSafe', 'ConvertTo-TPSafeUrl',
    'Start-TPWebServer',
    'Get-TPControlDefinitions', 'Get-TPControlById',
    'Get-TPFrameworkCitations', 'Get-TPFrameworkDefinitions',
    'Get-TPFindingRiskCost', 'Get-TPAggregateRisk',
    'Get-TPRemediationRoadmap',
    'Set-TPSensitiveFileAcl', 'Set-TPSensitiveFileContent',
    'Get-TPTenantLicenseProfile', 'Test-TPLicenseRequirementMet', 'Get-TPControlLicenseStatus',
    'Get-TPSafeProperty', 'Get-TPNestedProperty', 'Test-TPSectionCollected',
    'Test-TPSignatureStatus',
    'Get-TPMaturityTier',
    'Get-TPCoverageScore',
    'Invoke-TPCollectAADAppPermissions',
    'Test-TPControlAppPermTenantTakeover', 'Test-TPControlAppPermDataAccess',
    'Get-TPAppPermissionRiskCatalog', 'Get-TPAppPermissionContext', 'Get-TPAppPermissionTierMap',
    'Get-TPAssessmentScope',
    'Get-TPNISTFamilyCoverage', 'Get-TPNISTControlIdsFromFinding',
    'Get-TPNISTPhysicalPosture', 'Get-TPNISTPhysicalDefinitions',
    'Get-TPNISTControlCatalog', 'Get-TPNISTControlTitle', 'Get-TPNISTFamilyTitle',
    'Publish-TPNISTMatrix',
    'Get-TPSSPPosture', 'Get-TPSSPAnswers', 'Get-TPNIST171Catalog',
    'Get-TPNIST171RequirementIdsFromCmmc', 'Get-TPOperationalImpactCatalog',
    'Get-TPControlOperationalImpact', 'Publish-TPSSP', 'Group-TPSSPImpact', 'Get-TPSSPImpactLabel',
    'Get-TPSSPQuestionnaireItems', 'Publish-TPSSPQuestionnaire',
    'Get-TPHipaaReadiness', 'Get-TPHipaaCatalog', 'Get-TPHipaaCitationsFromText', 'Publish-TPHipaaReadiness',
    'ConvertTo-TPSSPClientSlug', 'ConvertTo-TPSSPAnswerPsd1', 'ConvertTo-TPSSPPsd1String',
    'Get-TPManualReviewItems', 'Get-TPManualReviewAnswers',
    'ConvertTo-TPManualReviewAnswerPsd1', 'Publish-TPManualReviewQuestionnaire',
    'Get-TPNISTImprovementPlan', 'Publish-TPImprovementPlan',
    'Publish-TPDeviceGuide',
    'Publish-TPDeviceBaseline',
    'Invoke-TPCollectDeviceCompliance', 'Test-TPControlDevice', 'Get-TPDeviceControlDefinitions', 'Get-TPDeviceFrameworkIds',
    'Get-TPObjectField',
    'Test-TPDnsLookupSucceeded',
    'Get-TPRecipientClass',
    'Invoke-TPGraphRequest',
    'Invoke-TPEvaluatorSafe',
    'Resolve-TPDns',
    'Resolve-TPTenantId',
    'Set-TPThirdPartyEdr',
    'Set-TPThirdPartyAwareness',
    'New-TPProfile',
    'Get-TPProfile',
    'Set-TPLicenseGating',
    'Get-TPBaselineDefinition', 'Get-TPBaselineRequiredControls', 'ConvertTo-TPBaselineClientSlug',
    'Get-TPBaselineExceptions', 'Get-TPBaselineCompliance', 'Get-TPBaselineRegressions',
    'Get-TPControlStatus', 'Publish-TPReportSite', 'Publish-TPActionPlan', 'Get-TPFindingLimitKind', 'Get-TPScubaAlignment', 'Get-TPExclusionCoverage', 'Get-TPCAEffectiveCoverage', 'Get-TPCANarrowing', 'Get-TPCACoverageVerdict', 'Get-TPCAPrincipalExclusions', 'Get-TPDlpRuleStates', 'Get-TPDlpSensitiveTypeNames', 'Get-TPDlpLocationScope', 'Get-TPStandards', 'Add-TPExpectedStateFinding', 'Get-TPDmarcReportAddresses', 'Test-TPDmarcReportAddress', 'Get-TPAvSettings', 'Test-TPAvSettingSet', 'Get-TPAsrRuleModes', 'Get-TPAsrRequiredRules', 'Test-TPAsrRuleSet', 'Set-TPMonitoringAddresses', 'Get-TPMonitoringAddresses', 'Get-TPAlertRouting', 'Get-TPBaselinePlan', 'Compare-TPBaselinePlan', 'Format-TPBaselinePlanSummary', 'Get-TPWorkloadSkipMap', 'Get-TPOptionalCollectorCatalog', 'Get-TPClientCollectorFlags',
    'Get-TPBaselineReasonCodes', 'Resolve-TPBaselineReason', 'ConvertTo-TPBaselineReasonCode', 'Get-TPReasonSentence', 'Get-TPBaselineCoverage',
    'Get-TPBaselineExceptionPath', 'Get-TPBaselineException', 'New-TPBaselineException', 'Set-TPBaselineException', 'Remove-TPBaselineException',
    'Get-TPModuleHealth',
    'Repair-TPModuleHealth',
    'Get-TPModuleInstallScope', 'Get-TPExoModuleFloor', 'Get-TPExoPreflightNotes', 'Get-TPCloudFileHint', 'Get-TPMsalConflictHint', 'Get-TPGapSummary', 'Format-TPGapSummary', 'Get-TPControlViewMap', 'Get-TPEvidenceLimitMap', 'Get-TPEvidenceLimitNote', 'Get-TPEvidenceLimitMd', 'Test-TPSafeModuleVersionPath', 'Get-TPConnectErrorText', 'Get-TPExoConnectHint',
    'Get-TPControlAutomationAudit',
    # ── Distribution-list scan, the -DistributionListsOnly mode: read-only and Exchange Online only ──
    'Invoke-TPCollectDistributionLists', 'Test-TPDistributionLists', 'Get-TPDistributionListBaseline', 'Get-TPDistributionListStandards',
    'Get-TPDistributionListWorksheet', 'Publish-TPDistributionListWorksheet', 'Invoke-TPDistributionListScan', 'Connect-TPExchangeOnly',

    # ── Collectors — AAD ──────────────────────────────────────────────────────
    'Invoke-TPCollectAADAuthPolicies', 'Invoke-TPCollectAADCAPolicies',
    'Invoke-TPCollectAADUsers', 'Invoke-TPCollectAADRoles',
    'Invoke-TPCollectAADPIM', 'Invoke-TPCollectAADIdentityGovernance',
    'Invoke-TPCollectAADInventory',

    # ── Collectors — EXO / Defender / DNS ─────────────────────────────────────
    'Invoke-TPCollectEXOMailboxConfig', 'Invoke-TPCollectEXOConnectionFilter',
    'Invoke-TPCollectEXOInventory',
    'Invoke-TPCollectDefender', 'Invoke-TPCollectDNSEmailRecords',

    # ── Collectors — Phase 2+ ─────────────────────────────────────────────────
    'Invoke-TPCollectSharePoint', 'Invoke-TPCollectTeams',
    'Invoke-TPCollectPurview',
    'Invoke-TPCollectIntuneEndpointSecurity',
    'Invoke-TPCollectIntuneDeviceCompliance',
    'Invoke-TPCollectIntuneAppProtection',
    'Invoke-TPCollectPowerPlatform',
    'Invoke-TPCollectM365Copilot',

    # ── Evaluators — AAD ──────────────────────────────────────────────────────
    'Test-TPControlAADLegacyAuth', 'Test-TPControlAADMFA',
    'Test-TPControlAADPhishResistantMFA', 'Test-TPControlAADCA',
    'Test-TPControlAADPrivAccess', 'Test-TPControlAADSignInRisk',
    'Test-TPControlAADUserRisk', 'Test-TPControlAADNamedLocations',
    'Test-TPControlAADDeviceComplianceCA', 'Test-TPControlAADNoPermanentAdmins',
    'Test-TPControlAADPIMMFA', 'Test-TPControlAADPIMJustification',
    'Test-TPControlAADPIMApproval', 'Test-TPControlAADPIMDuration',
    'Test-TPControlAADGuestInvite', 'Test-TPControlAADExternalCollab',
    'Test-TPControlAADGuestPermissions', 'Test-TPControlAADSSPR',
    'Test-TPControlAADSSPRMethods', 'Test-TPControlAADUserAppReg',
    'Test-TPControlAADUserConsent', 'Test-TPControlAADAdminConsentWorkflow',
    'Test-TPControlAADPasswordProtection', 'Test-TPControlAADBreakGlass',
    'Test-TPControlAADPIMAlerts', 'Test-TPControlAADAccessReviews',
    'Test-TPControlAADAuthenticatorNumberMatch', 'Test-TPControlAADPasswordless',
    'Test-TPControlAADIdentityProtection', 'Test-TPControlAADPrivCloudOnly',
    'Test-TPControlAADBreakGlassMonitoring', 'Test-TPControlAADSignInFrequency',
    'Test-TPControlAADDeviceCode', 'Test-TPControlAADNoGuestInPrivRoles',
    'Test-TPControlAADRiskyServicePrincipals', 'Test-TPControlAADTokenProtection',
    'Test-TPControlAADContinuousAccess', 'Test-TPControlAADCrossTenantAccess',
    'Test-TPControlAADPrivilegedWorkstation', 'Test-TPControlAADTermsOfUse',
    'Test-TPControlAADWorkloadIdentityCA',

    # ── Evaluators — DNS ──────────────────────────────────────────────────────
    'Test-TPControlDNSSPF', 'Test-TPControlDNSDKIM', 'Test-TPControlDNSDMARC',
    'Test-TPControlDNSMTASTS', 'Test-TPControlDNSTLSRPT', 'Test-TPControlDNSDNSSEC',
    'Test-TPControlDNSDkimRotation', 'Test-TPControlDNSCAA',
    'Test-TPControlDNSTLSCertExpiry', 'Test-TPControlDNSCertTransparency',

    # ── Evaluators — EXO ──────────────────────────────────────────────────────
    'Test-TPControlEXOMailboxHoldCoverage',
    'Test-TPControlEXODeletedItemRetention',
    'Test-TPControlSPODepartedUserRetention',
    'Test-TPControlEXOMailFlowConnectors', 'Test-TPControlEXOTransportRuleContents',
    'Test-TPControlDefenderTenantAllowBlockList', 'Test-TPControlAADAppCredentialExpiry',
    'Get-TPAcceptedDomainSet', 'Test-TPRecipientIsExternal',
    'Test-TPControlEXOMailboxAudit', 'Test-TPControlEXOSmtpAuth',
    'Test-TPControlEXOAutoForward', 'Test-TPControlEXODKIM',
    'Test-TPControlEXOAntiPhish', 'Test-TPControlEXOModernAuth',
    'Test-TPControlEXOHonorDMARC', 'Test-TPControlEXOPop3',
    'Test-TPControlEXOImap', 'Test-TPControlEXOCustomerLockbox',
    'Test-TPControlEXOSharedMailbox', 'Test-TPControlEXOConnectionFilter',
    'Test-TPControlEXOOutboundLimits', 'Test-TPControlEXOAlertForwarding',
    'Test-TPControlEXOAlertVolume', 'Test-TPControlEXOTransportAudit',
    'Test-TPControlEXOAuditAgeLimit', 'Test-TPControlEXOAdminAudit',
    'Test-TPControlEXOSafeAttachmentsSPO', 'Test-TPControlEXOAntiSpamInbound',
    'Test-TPControlEXOPerUserAudit', 'Test-TPControlEXOPriorityAccountProtection',
    'Test-TPControlEXOSafeSenderOverride',
    'Test-TPControlEXOMailboxForwarding', 'Test-TPControlEXOInboxRulesForwarding',
    'Test-TPControlEXOAuditDisabledMailboxes', 'Test-TPControlEXOSmtpAuthExceptions',

    # ── Evaluators — Defender ─────────────────────────────────────────────────
    'Test-TPControlDefender',
    'Test-TPControlDefenderPresetPolicies', 'Test-TPControlDefenderZAP',
    'Test-TPControlDefenderCommonAttachments', 'Test-TPControlDefenderQuarantine',
    'Test-TPControlDefenderHCSpam', 'Test-TPControlDefenderBulkThreshold',
    'Test-TPControlDefenderUnauthSender', 'Test-TPControlDefenderViaTag',
    'Test-TPControlDefenderMDCA', 'Test-TPControlDefenderAlertNotification',
    'Test-TPControlDefenderDLPWorkloads', 'Test-TPControlDefenderDLPSITs',
    'Test-TPControlDefenderRiskyAppAlerts', 'Test-TPControlDefenderPriorityAccounts',
    'Test-TPControlDefenderEndpointDLP', 'Test-TPControlDefenderAttackSim',
    'Test-TPControlDefenderSafeLinksOffice',

    # ── Evaluators — SharePoint ───────────────────────────────────────────────
    'Test-TPControlSharePoint',
    'Test-TPControlSPOOneDriveSync', 'Test-TPControlSPOLinkExpiration',
    'Test-TPControlSPOAppsFromStore', 'Test-TPControlSPOCustomScript',
    'Test-TPControlSPO3PStorage', 'Test-TPControlSPOEmailAttestation',
    'Test-TPControlSPOReauth', 'Test-TPControlSPODomainSync',
    'Test-TPControlSPOSiteAdmins', 'Test-TPControlSPOSharingNotifications',
    'Test-TPControlSPOVersionHistory', 'Test-TPControlSPOGuestExpiry',

    # ── Evaluators — Teams ────────────────────────────────────────────────────
    'Test-TPControlTeams',
    'Test-TPControlTeamsSkype', 'Test-TPControlTeamsUnverifiedApps',
    'Test-TPControlTeams3PStorage', 'Test-TPControlTeamsEmailIntegration',
    'Test-TPControlTeamsRecordingExternal', 'Test-TPControlTeamsBroadChannel',
    'Test-TPControlTeamsExternalChat', 'Test-TPControlTeamsPSTN',
    'Test-TPControlTeamsWatermarks', 'Test-TPControlTeamsAutoAdmit',
    'Test-TPControlTeamsMeetingChat', 'Test-TPControlTeamsChatCopy',
    'Test-TPControlTeamsMeetingRecordingScope', 'Test-TPControlTeamsAnonymousStart',
    'Test-TPControlTeamsFederationAllowlist', 'Test-TPControlTeamsLiveEvents', 'Test-TPControlTeamsRecordingRetention',

    # ── Evaluators — Purview ──────────────────────────────────────────────────
    'Test-TPControlPurview',
    'Test-TPControlPurviewAuditSearch', 'Test-TPControlPurviewCommCompliance',
    'Test-TPControlPurviewInfoBarriers', 'Test-TPControlPurviewInsiderRisk',
    'Test-TPControlPurviewRetention', 'Test-TPControlPurviewAutoLabel',
    'Test-TPControlPurviewSIEMExport', 'Test-TPControlPurviewEDiscovery',
    'Test-TPControlPurviewComplianceScore', 'Test-TPControlPurviewSensitiveInfoTypes',
    'Test-TPControlPurviewAuditPremium', 'Test-TPControlPurviewAuditRetention',
    'Test-TPControlPurviewLabelsPublished', 'Test-TPControlPurviewRecordsManagement',

    # ── Evaluators — Intune ───────────────────────────────────────────────────
    'Test-TPControlIntune',
    'Test-TPControlIntuneEDR', 'Test-TPControlIntuneASR',
    'Test-TPControlIntuneFirewall', 'Test-TPControlIntuneMacEncryption',
    'Test-TPControlIntuneWindowsUpdate', 'Test-TPControlIntuneEnrollmentRestrictions',
    'Test-TPControlIntuneAppConfig', 'Test-TPControlIntuneConditionalLaunch',
    'Test-TPControlIntuneWindowsLAPS', 'Test-TPControlIntuneWindowsHello',
    'Test-TPControlIntuneUpdateCompliance', 'Test-TPControlIntuneMobilePIN',

    # ── Evaluators — Power Platform ───────────────────────────────────────────
    'Test-TPControlPowerPlatform',
    'Test-TPControlPPLConnectorClassification',
    'Test-TPControlPPLAutomate', 'Test-TPControlPPLPowerApps',

    # ── Evaluators — Inventory / Object-level ─────────────────────────────────
    'Test-TPControlInventoryMFAUsers', 'Test-TPControlInventoryStaleGuests',
    'Test-TPControlInventoryStaleMembers', 'Test-TPControlInventoryOAuthApps',
    'Test-TPControlInventoryExternalForwarding',
    'Test-TPControlInventorySharedMailboxSignIn',
    'Test-TPControlInventoryMailboxAuditDisabled',
    'Test-TPControlInventorySMTPAuthUsers', 'Test-TPControlInventorySecureScore',

    # ── Evaluators — AI / Copilot ─────────────────────────────────────────────
    'Test-TPControlAICopilotSensitivityLabels', 'Test-TPControlAICopilotDLP',
    'Test-TPControlAICopilotLicensedOnly', 'Test-TPControlAICopilotStudio',
    'Test-TPControlAICopilotInteractionData',

    # ── Publishers ────────────────────────────────────────────────────────────
    'Publish-TPAssessmentHTML', 'Publish-TPAssessmentSummary',
    'Publish-TPRemediationPlaybook', 'Publish-TPRemediationScript',
    'Publish-TPComplianceMatrix', 'Publish-TPDeltaReport',
    'Publish-TPMonthlyReport',

    # ── v4.12.0 Email Incident Response mode ─────────────────────────────────
    'Connect-TPEmailServices', 'Disconnect-TPEmailServices',
    'Invoke-TPEmailCollectMailbox',
    'Get-TPEmailDomainFromAddress', 'Test-TPEmailIsLegitMSDomain', 'Test-TPEmailMatchesMSImpersonation',
    'Test-TPEmailControlInboxRules', 'Test-TPEmailControlForwarding',
    'Test-TPEmailControlOutboundActivity', 'Test-TPEmailControlPhishOrigin',
    'Test-TPEmailControlThreatIntel',
    'Publish-TPEmailIncidentReport',
    'Connect-TPEmailAdminServices',
    'Disconnect-TPEmailAdminServices',
    'Invoke-TPEmailCollectSignIns',
    'Clear-TPSignInTriageState',
    'Get-TPSignInCollectionCompleteness',
    'Get-TPDeepDiveEvidenceKeys',
    'Get-TPDeepDiveEvidence',
    'Set-TPFindingSubject',
    'Test-TPSignInControlFailedToSuccess',
    'Test-TPSignInControlAnonymousIp',
    'Test-TPSignInControlImpossibleTravel',
    'Test-TPSignInControlRiskyUsers',
    'Test-TPSignInControlGeoAnomaly',
    'Test-TPSignInControlRankUsers',
    'Test-TPSignInControlIPIntel',
    'Publish-TPSignInTriageReport',
    'Get-TPIPSignInIntel',
    'Invoke-TPEmailCollectUserSecurity',
    'Test-TPEmailControlOAuthConsents',
    'Test-TPEmailControlAuthMethods'
)

Export-ModuleMember -Function $script:ExportedFunctions -Variable TPAssessmentVersion, TPBrand

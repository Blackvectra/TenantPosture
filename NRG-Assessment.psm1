#Requires -Version 7.0
#
# NRG-Assessment.psm1  (version sourced from NRG-Assessment.psd1 at runtime)
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
# Pester invariant in Testing/NRG.Security.Tests.ps1 enforces presence of this
# directive in production code going forward.
Set-StrictMode -Version Latest

# Version is resolved from the sibling manifest at load time rather than kept
# as a literal here. The literal drifted across four releases (it read 4.11.1
# while the manifest said 4.12.1), and because $NRGAssessmentVersion is exported
# via VariablesToExport, module-direct callers and the report metadata saw the
# stale value. Fallback to 'unknown' is defensive: manifest parsing should never
# fail at load time, but if it does the module should load with a clearly
# flagged version rather than silently shipping a wrong one.
$script:NRGModuleRoot        = $PSScriptRoot
$script:NRGAssessmentVersion = try {
    $manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'NRG-Assessment.psd1') -ErrorAction Stop
    [string]$manifest.ModuleVersion
} catch {
    'unknown'
}

# Thread-safe collections for module state
$script:NRGFindings   = [System.Collections.Generic.List[object]]::new()
$script:NRGExceptions = [System.Collections.Generic.List[object]]::new()
$script:NRGCoverage   = [System.Collections.Generic.Dictionary[string,string]]::new()
$script:NRGRawData    = [System.Collections.Hashtable]::Synchronized(@{})

# ── Branding ──────────────────────────────────────────────────────────────────
# LiteralPath prevents wildcard expansion on the path.
# OWASP A01 / ASVS V12.3.1
$brandPath = Join-Path $PSScriptRoot 'Config' 'branding.psd1'
$script:NRGBrand = if (Test-Path -LiteralPath $brandPath) {
    try {
        Import-PowerShellDataFile -LiteralPath $brandPath -ErrorAction Stop
    } catch {
        Write-Warning "Branding file invalid, using defaults: $_"
        $null
    }
} else {
    $null
}

if (-not $script:NRGBrand) {
    $script:NRGBrand = @{
        CompanyName    = 'NRG Technology Services'
        Phone          = '(701) 250-9400'
        Website        = 'nrgtechservices.com'
        Email          = 'sales@nrgtechservices.com'
        PrimaryColor   = '#1a3a6b'
        SecondaryColor = '#e87722'
        AccentColor    = '#4a7ba6'
        LogoUrl        = ''
    }
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
            # Get-NRGExceptions / the JSON output includes them. Without this,
            # a dot-source failure was a Write-Warning only — operators only
            # noticed if they were watching the console. Note Register-NRGException
            # may not exist yet if Add-NRGFinding.ps1 was the file that failed —
            # guard with Get-Command.
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                try { Register-NRGException -Source 'ModuleLoader' -Message $loadMsg } catch { }
            }
        }
    }
}

# ── Exported function list ────────────────────────────────────────────────────
$script:ExportedFunctions = @(
    # ── Lib helpers ───────────────────────────────────────────────────────────
    'Add-NRGFinding', 'Get-NRGFindings', 'Clear-NRGFindings', 'Clear-NRGState',
    'Register-NRGException', 'Get-NRGExceptions',
    'Register-NRGCoverage', 'Get-NRGCoverage',
    'Set-NRGRawData', 'Get-NRGRawData',
    'Connect-NRGServices', 'Disconnect-NRGServices',
    'ConvertTo-NRGHtmlSafe', 'ConvertTo-NRGSafeUrl',
    'Start-NRGWebServer',
    'Get-NRGControlDefinitions', 'Get-NRGControlById',
    'Get-NRGFrameworkCitations', 'Get-NRGFrameworkDefinitions',
    'Get-NRGFindingRiskCost', 'Get-NRGAggregateRisk',
    'Get-NRGRemediationRoadmap',
    'Set-NRGSensitiveFileAcl', 'Set-NRGSensitiveFileContent',
    'Get-NRGTenantLicenseProfile', 'Test-NRGLicenseRequirementMet', 'Get-NRGControlLicenseStatus',
    'Get-NRGSafeProperty', 'Get-NRGNestedProperty', 'Test-NRGSectionCollected',
    'Test-NRGSignatureStatus',
    'Get-NRGMaturityTier',
    'Get-NRGCoverageScore',
    'Invoke-NRGCollectAADAppPermissions',
    'Test-NRGControlAppPermTenantTakeover', 'Test-NRGControlAppPermDataAccess',
    'Get-NRGAppPermissionRiskCatalog', 'Get-NRGAppPermissionContext', 'Get-NRGAppPermissionTierMap',
    'Get-NRGAssessmentScope',
    'Get-NRGNISTFamilyCoverage', 'Get-NRGNISTControlIdsFromFinding',
    'Get-NRGNISTPhysicalPosture', 'Get-NRGNISTPhysicalDefinitions',
    'Get-NRGNISTControlCatalog', 'Get-NRGNISTControlTitle', 'Get-NRGNISTFamilyTitle',
    'Publish-NRGNISTMatrix',
    'Get-NRGSSPPosture', 'Get-NRGSSPAnswers', 'Get-NRGNIST171Catalog',
    'Get-NRGNIST171RequirementIdsFromCmmc', 'Get-NRGOperationalImpactCatalog',
    'Get-NRGControlOperationalImpact', 'Publish-NRGSSP', 'Group-NRGSSPImpact', 'Get-NRGSSPImpactLabel',
    'Get-NRGSSPQuestionnaireItems', 'Publish-NRGSSPQuestionnaire',
    'ConvertTo-NRGSSPClientSlug', 'ConvertTo-NRGSSPAnswerPsd1', 'ConvertTo-NRGSSPPsd1String',
    'Get-NRGManualReviewItems', 'Get-NRGManualReviewAnswers',
    'ConvertTo-NRGManualReviewAnswerPsd1', 'Publish-NRGManualReviewQuestionnaire',
    'Get-NRGNISTImprovementPlan', 'Publish-NRGImprovementPlan',
    'Publish-NRGDeviceGuide',
    'Publish-NRGDeviceBaseline',
    'Invoke-NRGCollectDeviceCompliance', 'Test-NRGControlDevice', 'Get-NRGDeviceControlDefinitions', 'Get-NRGDeviceFrameworkIds',
    'Get-NRGObjectField',
    'Test-NRGDnsLookupSucceeded',
    'Get-NRGRecipientClass',
    'Invoke-NRGGraphRequest',
    'Invoke-NRGEvaluatorSafe',
    'Resolve-NRGDns',
    'Resolve-NRGTenantId',
    'Set-NRGThirdPartyEdr',
    'Set-NRGLicenseGating',
    'Get-NRGBaselineDefinition', 'Get-NRGBaselineRequiredControls', 'ConvertTo-NRGBaselineClientSlug',
    'Get-NRGBaselineExceptions', 'Get-NRGBaselineCompliance', 'Get-NRGBaselineRegressions',
    'Get-NRGControlStatus', 'Get-NRGExclusionCoverage', 'Get-NRGCAEffectiveCoverage', 'Get-NRGCANarrowing', 'Get-NRGCACoverageVerdict', 'Get-NRGCAPrincipalExclusions', 'Get-NRGDlpRuleStates', 'Get-NRGStandards', 'Add-NRGExpectedStateFinding', 'Get-NRGDmarcReportAddresses', 'Test-NRGDmarcReportAddress', 'Get-NRGAvSettings', 'Test-NRGAvSettingSet', 'Get-NRGAsrRuleModes', 'Get-NRGAsrRequiredRules', 'Test-NRGAsrRuleSet', 'Set-NRGMonitoringAddresses', 'Get-NRGMonitoringAddresses', 'Get-NRGAlertRouting', 'Get-NRGBaselinePlan', 'Compare-NRGBaselinePlan', 'Format-NRGBaselinePlanSummary', 'Get-NRGWorkloadSkipMap', 'Get-NRGOptionalCollectorCatalog', 'Get-NRGClientCollectorFlags',
    'Get-NRGBaselineReasonCodes', 'Resolve-NRGBaselineReason', 'ConvertTo-NRGBaselineReasonCode', 'Get-NRGReasonSentence', 'Get-NRGBaselineCoverage',
    'Get-NRGBaselineExceptionPath', 'Get-NRGBaselineException', 'New-NRGBaselineException', 'Set-NRGBaselineException', 'Remove-NRGBaselineException',
    'Get-NRGModuleHealth',
    'Repair-NRGModuleHealth',
    'Get-NRGModuleInstallScope', 'Get-NRGExoModuleFloor', 'Get-NRGConnectErrorText', 'Get-NRGExoConnectHint',
    'Get-NRGControlAutomationAudit',

    # ── Collectors — AAD ──────────────────────────────────────────────────────
    'Invoke-NRGCollectAADAuthPolicies', 'Invoke-NRGCollectAADCAPolicies',
    'Invoke-NRGCollectAADUsers', 'Invoke-NRGCollectAADRoles',
    'Invoke-NRGCollectAADPIM', 'Invoke-NRGCollectAADIdentityGovernance',
    'Invoke-NRGCollectAADInventory',

    # ── Collectors — EXO / Defender / DNS ─────────────────────────────────────
    'Invoke-NRGCollectEXOMailboxConfig', 'Invoke-NRGCollectEXOConnectionFilter',
    'Invoke-NRGCollectEXOInventory',
    'Invoke-NRGCollectDefender', 'Invoke-NRGCollectDNSEmailRecords',

    # ── Collectors — Phase 2+ ─────────────────────────────────────────────────
    'Invoke-NRGCollectSharePoint', 'Invoke-NRGCollectTeams',
    'Invoke-NRGCollectPurview',
    'Invoke-NRGCollectIntuneEndpointSecurity',
    'Invoke-NRGCollectIntuneDeviceCompliance',
    'Invoke-NRGCollectIntuneAppProtection',
    'Invoke-NRGCollectPowerPlatform',
    'Invoke-NRGCollectM365Copilot',

    # ── Evaluators — AAD ──────────────────────────────────────────────────────
    'Test-NRGControlAADLegacyAuth', 'Test-NRGControlAADMFA',
    'Test-NRGControlAADPhishResistantMFA', 'Test-NRGControlAADCA',
    'Test-NRGControlAADPrivAccess', 'Test-NRGControlAADSignInRisk',
    'Test-NRGControlAADUserRisk', 'Test-NRGControlAADNamedLocations',
    'Test-NRGControlAADDeviceComplianceCA', 'Test-NRGControlAADNoPermanentAdmins',
    'Test-NRGControlAADPIMMFA', 'Test-NRGControlAADPIMJustification',
    'Test-NRGControlAADPIMApproval', 'Test-NRGControlAADPIMDuration',
    'Test-NRGControlAADGuestInvite', 'Test-NRGControlAADExternalCollab',
    'Test-NRGControlAADGuestPermissions', 'Test-NRGControlAADSSPR',
    'Test-NRGControlAADSSPRMethods', 'Test-NRGControlAADUserAppReg',
    'Test-NRGControlAADUserConsent', 'Test-NRGControlAADAdminConsentWorkflow',
    'Test-NRGControlAADPasswordProtection', 'Test-NRGControlAADBreakGlass',
    'Test-NRGControlAADPIMAlerts', 'Test-NRGControlAADAccessReviews',
    'Test-NRGControlAADAuthenticatorNumberMatch', 'Test-NRGControlAADPasswordless',
    'Test-NRGControlAADIdentityProtection', 'Test-NRGControlAADPrivCloudOnly',
    'Test-NRGControlAADBreakGlassMonitoring', 'Test-NRGControlAADSignInFrequency',
    'Test-NRGControlAADDeviceCode', 'Test-NRGControlAADNoGuestInPrivRoles',
    'Test-NRGControlAADRiskyServicePrincipals', 'Test-NRGControlAADTokenProtection',
    'Test-NRGControlAADContinuousAccess', 'Test-NRGControlAADCrossTenantAccess',
    'Test-NRGControlAADPrivilegedWorkstation', 'Test-NRGControlAADTermsOfUse',
    'Test-NRGControlAADWorkloadIdentityCA',

    # ── Evaluators — DNS ──────────────────────────────────────────────────────
    'Test-NRGControlDNSSPF', 'Test-NRGControlDNSDKIM', 'Test-NRGControlDNSDMARC',
    'Test-NRGControlDNSMTASTS', 'Test-NRGControlDNSTLSRPT', 'Test-NRGControlDNSDNSSEC',
    'Test-NRGControlDNSDkimRotation', 'Test-NRGControlDNSCAA',
    'Test-NRGControlDNSTLSCertExpiry', 'Test-NRGControlDNSCertTransparency',

    # ── Evaluators — EXO ──────────────────────────────────────────────────────
    'Test-NRGControlEXOMailboxHoldCoverage',
    'Test-NRGControlEXODeletedItemRetention',
    'Test-NRGControlSPODepartedUserRetention',
    'Test-NRGControlEXOMailFlowConnectors', 'Test-NRGControlEXOTransportRuleContents',
    'Test-NRGControlDefenderTenantAllowBlockList', 'Test-NRGControlAADAppCredentialExpiry',
    'Get-NRGAcceptedDomainSet', 'Test-NRGRecipientIsExternal',
    'Test-NRGControlEXOMailboxAudit', 'Test-NRGControlEXOSmtpAuth',
    'Test-NRGControlEXOAutoForward', 'Test-NRGControlEXODKIM',
    'Test-NRGControlEXOAntiPhish', 'Test-NRGControlEXOModernAuth',
    'Test-NRGControlEXOHonorDMARC', 'Test-NRGControlEXOPop3',
    'Test-NRGControlEXOImap', 'Test-NRGControlEXOCustomerLockbox',
    'Test-NRGControlEXOSharedMailbox', 'Test-NRGControlEXOConnectionFilter',
    'Test-NRGControlEXOOutboundLimits', 'Test-NRGControlEXOAlertForwarding',
    'Test-NRGControlEXOAlertVolume', 'Test-NRGControlEXOTransportAudit',
    'Test-NRGControlEXOAuditAgeLimit', 'Test-NRGControlEXOAdminAudit',
    'Test-NRGControlEXOSafeAttachmentsSPO', 'Test-NRGControlEXOAntiSpamInbound',
    'Test-NRGControlEXOPerUserAudit', 'Test-NRGControlEXOPriorityAccountProtection',
    'Test-NRGControlEXOSafeSenderOverride',
    'Test-NRGControlEXOMailboxForwarding', 'Test-NRGControlEXOInboxRulesForwarding',
    'Test-NRGControlEXOAuditDisabledMailboxes', 'Test-NRGControlEXOSmtpAuthExceptions',

    # ── Evaluators — Defender ─────────────────────────────────────────────────
    'Test-NRGControlDefender',
    'Test-NRGControlDefenderPresetPolicies', 'Test-NRGControlDefenderZAP',
    'Test-NRGControlDefenderCommonAttachments', 'Test-NRGControlDefenderQuarantine',
    'Test-NRGControlDefenderHCSpam', 'Test-NRGControlDefenderBulkThreshold',
    'Test-NRGControlDefenderUnauthSender', 'Test-NRGControlDefenderViaTag',
    'Test-NRGControlDefenderMDCA', 'Test-NRGControlDefenderAlertNotification',
    'Test-NRGControlDefenderDLPWorkloads', 'Test-NRGControlDefenderDLPSITs',
    'Test-NRGControlDefenderRiskyAppAlerts', 'Test-NRGControlDefenderPriorityAccounts',
    'Test-NRGControlDefenderEndpointDLP', 'Test-NRGControlDefenderAttackSim',
    'Test-NRGControlDefenderSafeLinksOffice',

    # ── Evaluators — SharePoint ───────────────────────────────────────────────
    'Test-NRGControlSharePoint',
    'Test-NRGControlSPOOneDriveSync', 'Test-NRGControlSPOLinkExpiration',
    'Test-NRGControlSPOAppsFromStore', 'Test-NRGControlSPOCustomScript',
    'Test-NRGControlSPO3PStorage', 'Test-NRGControlSPOEmailAttestation',
    'Test-NRGControlSPOReauth', 'Test-NRGControlSPODomainSync',
    'Test-NRGControlSPOSiteAdmins', 'Test-NRGControlSPOSharingNotifications',
    'Test-NRGControlSPOVersionHistory', 'Test-NRGControlSPOGuestExpiry',

    # ── Evaluators — Teams ────────────────────────────────────────────────────
    'Test-NRGControlTeams',
    'Test-NRGControlTeamsSkype', 'Test-NRGControlTeamsUnverifiedApps',
    'Test-NRGControlTeams3PStorage', 'Test-NRGControlTeamsEmailIntegration',
    'Test-NRGControlTeamsRecordingExternal', 'Test-NRGControlTeamsBroadChannel',
    'Test-NRGControlTeamsExternalChat', 'Test-NRGControlTeamsPSTN',
    'Test-NRGControlTeamsWatermarks', 'Test-NRGControlTeamsAutoAdmit',
    'Test-NRGControlTeamsMeetingChat', 'Test-NRGControlTeamsChatCopy',
    'Test-NRGControlTeamsMeetingRecordingScope', 'Test-NRGControlTeamsAnonymousStart',
    'Test-NRGControlTeamsFederationAllowlist', 'Test-NRGControlTeamsLiveEvents', 'Test-NRGControlTeamsRecordingRetention',

    # ── Evaluators — Purview ──────────────────────────────────────────────────
    'Test-NRGControlPurview',
    'Test-NRGControlPurviewAuditSearch', 'Test-NRGControlPurviewCommCompliance',
    'Test-NRGControlPurviewInfoBarriers', 'Test-NRGControlPurviewInsiderRisk',
    'Test-NRGControlPurviewRetention', 'Test-NRGControlPurviewAutoLabel',
    'Test-NRGControlPurviewSIEMExport', 'Test-NRGControlPurviewEDiscovery',
    'Test-NRGControlPurviewComplianceScore', 'Test-NRGControlPurviewSensitiveInfoTypes',
    'Test-NRGControlPurviewAuditPremium', 'Test-NRGControlPurviewAuditRetention',
    'Test-NRGControlPurviewLabelsPublished', 'Test-NRGControlPurviewRecordsManagement',

    # ── Evaluators — Intune ───────────────────────────────────────────────────
    'Test-NRGControlIntune',
    'Test-NRGControlIntuneEDR', 'Test-NRGControlIntuneASR',
    'Test-NRGControlIntuneFirewall', 'Test-NRGControlIntuneMacEncryption',
    'Test-NRGControlIntuneWindowsUpdate', 'Test-NRGControlIntuneEnrollmentRestrictions',
    'Test-NRGControlIntuneAppConfig', 'Test-NRGControlIntuneConditionalLaunch',
    'Test-NRGControlIntuneWindowsLAPS', 'Test-NRGControlIntuneWindowsHello',
    'Test-NRGControlIntuneUpdateCompliance', 'Test-NRGControlIntuneMobilePIN',

    # ── Evaluators — Power Platform ───────────────────────────────────────────
    'Test-NRGControlPowerPlatform',
    'Test-NRGControlPPLConnectorClassification',
    'Test-NRGControlPPLAutomate', 'Test-NRGControlPPLPowerApps',

    # ── Evaluators — Inventory / Object-level ─────────────────────────────────
    'Test-NRGControlInventoryMFAUsers', 'Test-NRGControlInventoryStaleGuests',
    'Test-NRGControlInventoryStaleMembers', 'Test-NRGControlInventoryOAuthApps',
    'Test-NRGControlInventoryExternalForwarding',
    'Test-NRGControlInventorySharedMailboxSignIn',
    'Test-NRGControlInventoryMailboxAuditDisabled',
    'Test-NRGControlInventorySMTPAuthUsers', 'Test-NRGControlInventorySecureScore',

    # ── Evaluators — AI / Copilot ─────────────────────────────────────────────
    'Test-NRGControlAICopilotSensitivityLabels', 'Test-NRGControlAICopilotDLP',
    'Test-NRGControlAICopilotLicensedOnly', 'Test-NRGControlAICopilotStudio',
    'Test-NRGControlAICopilotInteractionData',

    # ── Publishers ────────────────────────────────────────────────────────────
    'Publish-NRGAssessmentHTML', 'Publish-NRGAssessmentSummary',
    'Publish-NRGRemediationPlaybook', 'Publish-NRGRemediationScript',
    'Publish-NRGComplianceMatrix', 'Publish-NRGDeltaReport',
    'Publish-NRGMonthlyReport',

    # ── v4.12.0 Email Incident Response mode ─────────────────────────────────
    'Connect-NRGEmailServices', 'Disconnect-NRGEmailServices',
    'Invoke-NRGEmailCollectMailbox',
    'Get-NRGEmailDomainFromAddress', 'Test-NRGEmailIsLegitMSDomain', 'Test-NRGEmailMatchesMSImpersonation',
    'Test-NRGEmailControlInboxRules', 'Test-NRGEmailControlForwarding',
    'Test-NRGEmailControlOutboundActivity', 'Test-NRGEmailControlPhishOrigin',
    'Test-NRGEmailControlThreatIntel',
    'Publish-NRGEmailIncidentReport',
    'Connect-NRGEmailAdminServices',
    'Disconnect-NRGEmailAdminServices',
    'Invoke-NRGEmailCollectSignIns',
    'Clear-NRGSignInTriageState',
    'Get-NRGSignInCollectionCompleteness',
    'Get-NRGDeepDiveEvidenceKeys',
    'Get-NRGDeepDiveEvidence',
    'Set-NRGFindingSubject',
    'Test-NRGSignInControlFailedToSuccess',
    'Test-NRGSignInControlAnonymousIp',
    'Test-NRGSignInControlImpossibleTravel',
    'Test-NRGSignInControlRiskyUsers',
    'Test-NRGSignInControlGeoAnomaly',
    'Test-NRGSignInControlRankUsers',
    'Test-NRGSignInControlIPIntel',
    'Publish-NRGSignInTriageReport',
    'Get-NRGIPSignInIntel',
    'Invoke-NRGEmailCollectUserSecurity',
    'Test-NRGEmailControlOAuthConsents',
    'Test-NRGEmailControlAuthMethods'
)

Export-ModuleMember -Function $script:ExportedFunctions -Variable NRGAssessmentVersion, NRGBrand

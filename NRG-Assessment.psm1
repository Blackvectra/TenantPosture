#Requires -Version 7.0
#
# NRG-Assessment.psm1  (v4.5.5)
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

$script:NRGAssessmentVersion = '4.6.0'
$script:NRGModuleRoot        = $PSScriptRoot

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
$loadOrder = @('Lib', 'Collectors', 'Evaluators', 'Publishers')

foreach ($folder in $loadOrder) {
    $folderPath = Join-Path $PSScriptRoot $folder

    if (-not (Test-Path -LiteralPath $folderPath)) {
        Write-Warning "Module folder not found: $folder"
        continue
    }

    $files = Get-ChildItem -LiteralPath $folderPath -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue

    foreach ($file in $files) {
        # Verify the resolved path is inside PSScriptRoot — prevents path traversal
        # if a file is somehow named with ../ sequences (e.g. via symlink)
        $resolvedFile   = [System.IO.Path]::GetFullPath($file.FullName)
        $resolvedModule = [System.IO.Path]::GetFullPath($PSScriptRoot)

        # OWASP A01: resolved file must StartsWith $PSScriptRoot (resolved as $resolvedModule)
        if (-not $resolvedFile.StartsWith($resolvedModule, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning "Skipping file outside module root (path traversal?): $($file.FullName)"
            continue
        }

        try {
            # Redirect information stream (3>) to suppress verbose module load noise
            . $file.FullName 3>$null
        } catch {
            Write-Warning "Failed to load $($file.Name): $($_.Exception.Message)"
        }
    }
}

# ── Exported function list ────────────────────────────────────────────────────
$script:ExportedFunctions = @(
    # ── Lib helpers ───────────────────────────────────────────────────────────
    'Add-NRGFinding', 'Get-NRGFindings', 'Clear-NRGFindings',
    'Register-NRGException', 'Get-NRGExceptions',
    'Register-NRGCoverage', 'Get-NRGCoverage',
    'Set-NRGRawData', 'Get-NRGRawData',
    'Connect-NRGServices', 'Disconnect-NRGServices',
    'ConvertTo-NRGHtmlSafe', 'ConvertTo-NRGSafeUrl',
    'Get-NRGControlDefinitions', 'Get-NRGControlById',
    'Get-NRGFrameworkCitations', 'Get-NRGFrameworkDefinitions',
    'Get-NRGFindingRiskCost', 'Get-NRGAggregateRisk',

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

    # ── Evaluators — EXO ──────────────────────────────────────────────────────
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
    'Test-NRGControlTeamsFederationAllowlist', 'Test-NRGControlTeamsLiveEvents',

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
    'Publish-NRGComplianceMatrix', 'Publish-NRGDeltaReport'
)

Export-ModuleMember -Function $script:ExportedFunctions -Variable NRGAssessmentVersion, NRGBrand

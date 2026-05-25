@{
    # Module identity
    ModuleVersion     = '4.6.1'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'Matthew Levorson'
    CompanyName       = 'NRG Technology Services / NextLayerSec LLC'
    Copyright         = '(c) 2026 NRG Technology Services. All rights reserved.'
    Description       = 'Read-only Microsoft 365 security assessment framework for MSPs. Multi-framework, multi-tenant, client-ready reporting.'

    # Runtime requirements
    PowerShellVersion = '7.0'
    CompatiblePSEditions = @('Core')

    # Root module
    RootModule        = 'NRG-Assessment.psm1'

    # All functions exported by this module.
    # IMPORTANT: this list must stay in sync with $script:ExportedFunctions in
    # NRG-Assessment.psm1. PowerShell intersects the two lists, so a function
    # missing here is silently dropped from the exported surface.
    FunctionsToExport = @(
        # ── Lib ───────────────────────────────────────────────────────────────
        'Add-NRGFinding',
        'Get-NRGFindings',
        'Clear-NRGFindings',
        'Register-NRGException',
        'Get-NRGExceptions',
        'Register-NRGCoverage',
        'Get-NRGCoverage',
        'Set-NRGRawData',
        'Get-NRGRawData',
        'Connect-NRGServices',
        'Disconnect-NRGServices',
        'ConvertTo-NRGHtmlSafe',
        'ConvertTo-NRGSafeUrl',
        'Get-NRGControlDefinitions',
        'Get-NRGControlById',
        'Get-NRGFindingRiskCost',
        'Get-NRGAggregateRisk',
        'Get-NRGFrameworkCitations',
        'Get-NRGFrameworkDefinitions',

        # ── Collectors — AAD ──────────────────────────────────────────────────
        'Invoke-NRGCollectAADAuthPolicies',
        'Invoke-NRGCollectAADCAPolicies',
        'Invoke-NRGCollectAADUsers',
        'Invoke-NRGCollectAADRoles',
        'Invoke-NRGCollectAADPIM',
        'Invoke-NRGCollectAADIdentityGovernance',
        'Invoke-NRGCollectAADInventory',

        # ── Collectors — EXO / Defender / DNS ─────────────────────────────────
        'Invoke-NRGCollectEXOMailboxConfig',
        'Invoke-NRGCollectEXOConnectionFilter',
        'Invoke-NRGCollectEXOInventory',
        'Invoke-NRGCollectDefender',
        'Invoke-NRGCollectDNSEmailRecords',

        # ── Collectors — Phase 2+ ─────────────────────────────────────────────
        'Invoke-NRGCollectSharePoint',
        'Invoke-NRGCollectTeams',
        'Invoke-NRGCollectPurview',
        'Invoke-NRGCollectIntuneEndpointSecurity',
        'Invoke-NRGCollectIntuneDeviceCompliance',
        'Invoke-NRGCollectIntuneAppProtection',
        'Invoke-NRGCollectPowerPlatform',
        'Invoke-NRGCollectM365Copilot',

        # ── Evaluators — AAD ──────────────────────────────────────────────────
        'Test-NRGControlAADLegacyAuth',
        'Test-NRGControlAADMFA',
        'Test-NRGControlAADPhishResistantMFA',
        'Test-NRGControlAADCA',
        'Test-NRGControlAADPrivAccess',
        'Test-NRGControlAADSignInRisk',
        'Test-NRGControlAADUserRisk',
        'Test-NRGControlAADNamedLocations',
        'Test-NRGControlAADDeviceComplianceCA',
        'Test-NRGControlAADNoPermanentAdmins',
        'Test-NRGControlAADPIMMFA',
        'Test-NRGControlAADPIMJustification',
        'Test-NRGControlAADPIMApproval',
        'Test-NRGControlAADPIMDuration',
        'Test-NRGControlAADGuestInvite',
        'Test-NRGControlAADExternalCollab',
        'Test-NRGControlAADGuestPermissions',
        'Test-NRGControlAADSSPR',
        'Test-NRGControlAADSSPRMethods',
        'Test-NRGControlAADUserAppReg',
        'Test-NRGControlAADUserConsent',
        'Test-NRGControlAADAdminConsentWorkflow',
        'Test-NRGControlAADPasswordProtection',
        'Test-NRGControlAADBreakGlass',
        'Test-NRGControlAADPIMAlerts',
        'Test-NRGControlAADAccessReviews',
        'Test-NRGControlAADAuthenticatorNumberMatch',
        'Test-NRGControlAADPasswordless',
        'Test-NRGControlAADIdentityProtection',
        'Test-NRGControlAADPrivCloudOnly',
        'Test-NRGControlAADBreakGlassMonitoring',
        'Test-NRGControlAADSignInFrequency',
        'Test-NRGControlAADDeviceCode',
        'Test-NRGControlAADNoGuestInPrivRoles',
        'Test-NRGControlAADRiskyServicePrincipals',
        'Test-NRGControlAADTokenProtection',
        'Test-NRGControlAADContinuousAccess',
        'Test-NRGControlAADCrossTenantAccess',
        'Test-NRGControlAADPrivilegedWorkstation',
        'Test-NRGControlAADTermsOfUse',
        'Test-NRGControlAADWorkloadIdentityCA',

        # ── Evaluators — DNS ──────────────────────────────────────────────────
        'Test-NRGControlDNSSPF',
        'Test-NRGControlDNSDKIM',
        'Test-NRGControlDNSDMARC',
        'Test-NRGControlDNSMTASTS',
        'Test-NRGControlDNSTLSRPT',
        'Test-NRGControlDNSDNSSEC',
        'Test-NRGControlDNSDkimRotation',
        'Test-NRGControlDNSCAA',
        'Test-NRGControlDNSTLSCertExpiry',
        'Test-NRGControlDNSCertTransparency',

        # ── Evaluators — EXO ──────────────────────────────────────────────────
        'Test-NRGControlEXOMailboxAudit',
        'Test-NRGControlEXOSmtpAuth',
        'Test-NRGControlEXOAutoForward',
        'Test-NRGControlEXODKIM',
        'Test-NRGControlEXOAntiPhish',
        'Test-NRGControlEXOModernAuth',
        'Test-NRGControlEXOHonorDMARC',
        'Test-NRGControlEXOPop3',
        'Test-NRGControlEXOImap',
        'Test-NRGControlEXOCustomerLockbox',
        'Test-NRGControlEXOSharedMailbox',
        'Test-NRGControlEXOConnectionFilter',
        'Test-NRGControlEXOOutboundLimits',
        'Test-NRGControlEXOAlertForwarding',
        'Test-NRGControlEXOAlertVolume',
        'Test-NRGControlEXOTransportAudit',
        'Test-NRGControlEXOAuditAgeLimit',
        'Test-NRGControlEXOAdminAudit',
        'Test-NRGControlEXOSafeAttachmentsSPO',
        'Test-NRGControlEXOAntiSpamInbound',
        'Test-NRGControlEXOPerUserAudit',
        'Test-NRGControlEXOPriorityAccountProtection',
        'Test-NRGControlEXOSafeSenderOverride',
        'Test-NRGControlEXOMailboxForwarding',
        'Test-NRGControlEXOInboxRulesForwarding',
        'Test-NRGControlEXOAuditDisabledMailboxes',
        'Test-NRGControlEXOSmtpAuthExceptions',

        # ── Evaluators — Defender ─────────────────────────────────────────────
        'Test-NRGControlDefender',
        'Test-NRGControlDefenderPresetPolicies',
        'Test-NRGControlDefenderZAP',
        'Test-NRGControlDefenderCommonAttachments',
        'Test-NRGControlDefenderQuarantine',
        'Test-NRGControlDefenderHCSpam',
        'Test-NRGControlDefenderBulkThreshold',
        'Test-NRGControlDefenderUnauthSender',
        'Test-NRGControlDefenderViaTag',
        'Test-NRGControlDefenderMDCA',
        'Test-NRGControlDefenderAlertNotification',
        'Test-NRGControlDefenderDLPWorkloads',
        'Test-NRGControlDefenderDLPSITs',
        'Test-NRGControlDefenderRiskyAppAlerts',
        'Test-NRGControlDefenderPriorityAccounts',
        'Test-NRGControlDefenderEndpointDLP',
        'Test-NRGControlDefenderAttackSim',
        'Test-NRGControlDefenderSafeLinksOffice',

        # ── Evaluators — SharePoint ───────────────────────────────────────────
        'Test-NRGControlSharePoint',
        'Test-NRGControlSPOOneDriveSync',
        'Test-NRGControlSPOLinkExpiration',
        'Test-NRGControlSPOAppsFromStore',
        'Test-NRGControlSPOCustomScript',
        'Test-NRGControlSPO3PStorage',
        'Test-NRGControlSPOEmailAttestation',
        'Test-NRGControlSPOReauth',
        'Test-NRGControlSPODomainSync',
        'Test-NRGControlSPOSiteAdmins',
        'Test-NRGControlSPOSharingNotifications',
        'Test-NRGControlSPOVersionHistory',
        'Test-NRGControlSPOGuestExpiry',

        # ── Evaluators — Teams ────────────────────────────────────────────────
        'Test-NRGControlTeams',
        'Test-NRGControlTeamsSkype',
        'Test-NRGControlTeamsUnverifiedApps',
        'Test-NRGControlTeams3PStorage',
        'Test-NRGControlTeamsEmailIntegration',
        'Test-NRGControlTeamsRecordingExternal',
        'Test-NRGControlTeamsBroadChannel',
        'Test-NRGControlTeamsExternalChat',
        'Test-NRGControlTeamsPSTN',
        'Test-NRGControlTeamsWatermarks',
        'Test-NRGControlTeamsAutoAdmit',
        'Test-NRGControlTeamsMeetingChat',
        'Test-NRGControlTeamsChatCopy',
        'Test-NRGControlTeamsMeetingRecordingScope',
        'Test-NRGControlTeamsAnonymousStart',
        'Test-NRGControlTeamsFederationAllowlist',
        'Test-NRGControlTeamsLiveEvents',

        # ── Evaluators — Purview ──────────────────────────────────────────────
        'Test-NRGControlPurview',
        'Test-NRGControlPurviewAuditSearch',
        'Test-NRGControlPurviewCommCompliance',
        'Test-NRGControlPurviewInfoBarriers',
        'Test-NRGControlPurviewInsiderRisk',
        'Test-NRGControlPurviewRetention',
        'Test-NRGControlPurviewAutoLabel',
        'Test-NRGControlPurviewSIEMExport',
        'Test-NRGControlPurviewEDiscovery',
        'Test-NRGControlPurviewComplianceScore',
        'Test-NRGControlPurviewSensitiveInfoTypes',
        'Test-NRGControlPurviewAuditPremium',
        'Test-NRGControlPurviewAuditRetention',
        'Test-NRGControlPurviewLabelsPublished',
        'Test-NRGControlPurviewRecordsManagement',

        # ── Evaluators — Intune ───────────────────────────────────────────────
        'Test-NRGControlIntune',
        'Test-NRGControlIntuneEDR',
        'Test-NRGControlIntuneASR',
        'Test-NRGControlIntuneFirewall',
        'Test-NRGControlIntuneMacEncryption',
        'Test-NRGControlIntuneWindowsUpdate',
        'Test-NRGControlIntuneEnrollmentRestrictions',
        'Test-NRGControlIntuneAppConfig',
        'Test-NRGControlIntuneConditionalLaunch',
        'Test-NRGControlIntuneWindowsLAPS',
        'Test-NRGControlIntuneWindowsHello',
        'Test-NRGControlIntuneUpdateCompliance',
        'Test-NRGControlIntuneMobilePIN',

        # ── Evaluators — Power Platform ───────────────────────────────────────
        'Test-NRGControlPowerPlatform',
        'Test-NRGControlPPLConnectorClassification',
        'Test-NRGControlPPLAutomate',
        'Test-NRGControlPPLPowerApps',

        # ── Evaluators — Inventory ────────────────────────────────────────────
        'Test-NRGControlInventoryMFAUsers',
        'Test-NRGControlInventoryStaleGuests',
        'Test-NRGControlInventoryStaleMembers',
        'Test-NRGControlInventoryOAuthApps',
        'Test-NRGControlInventoryExternalForwarding',
        'Test-NRGControlInventorySharedMailboxSignIn',
        'Test-NRGControlInventoryMailboxAuditDisabled',
        'Test-NRGControlInventorySMTPAuthUsers',
        'Test-NRGControlInventorySecureScore',

        # ── Evaluators — AI / Copilot ─────────────────────────────────────────
        'Test-NRGControlAICopilotSensitivityLabels',
        'Test-NRGControlAICopilotDLP',
        'Test-NRGControlAICopilotLicensedOnly',
        'Test-NRGControlAICopilotStudio',
        'Test-NRGControlAICopilotInteractionData',

        # ── Publishers ────────────────────────────────────────────────────────
        'Publish-NRGAssessmentHTML',
        'Publish-NRGAssessmentSummary',
        'Publish-NRGRemediationPlaybook',
        'Publish-NRGRemediationScript',
        'Publish-NRGComplianceMatrix',
        'Publish-NRGDeltaReport'
    )

    VariablesToExport = @('NRGAssessmentVersion', 'NRGBrand')
    CmdletsToExport   = @()
    AliasesToExport   = @()

    # Required modules — must be present before this module loads
    RequiredModules = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' },
        @{ ModuleName = 'ExchangeOnlineManagement';       ModuleVersion = '3.0.0' }
    )

    # Module metadata
    PrivateData = @{
        PSData = @{
            Tags         = @('M365', 'Security', 'Assessment', 'MSP', 'CIS', 'SCuBA', 'NIST', 'CMMC')
            ProjectUri   = 'https://github.com/Blackvectra/NRG-Assessment-Tool'
            ReleaseNotes = @'
v4.6.1: 217 exported functions. Closes Phase 2 + Phase 4 roadmap gaps.

PRs:
  #12 DNS extended evaluators (4 new): DNS-2.1 DkimRotation, DNS-2.2 CAA,
      DNS-2.3 TLSCertExpiry, DNS-2.4 CertTransparency. Consumes the extended
      collector data that was previously unread.
  #13 EXO Inventory evaluators (4 new): EXO-7.1 MailboxForwarding,
      EXO-7.2 InboxRulesForwarding, EXO-7.3 AuditDisabledMailboxes,
      EXO-7.4 SmtpAuthExceptions. Consumes the inventory collector data.
  #14 Framework citations: SCuBA 126→136 (10 honest mappings; 52 marked
      "" with description note where no SCuBA equivalent exists). CMMC
      141→188 (100% via NIST→CMMC L2 standard mapping).
  #15 Copilot governance: new M365Copilot collector (reuses Purview raw
      data; Graph subscribedSkus + users + applications). 5 stub evaluators
      replaced with real logic (sensitivity labels, DLP, licensing ratio,
      Studio external publish, interaction-data retention).
  #16 Apply-NRGBaseline.ps1: interactive write-mode tool with WhatIf,
      idempotency check, rollback log, approval gates. V1 includes 6
      representative apply functions (AAD-1.1 legacy auth, AAD-2.1 MFA,
      EXO-1.1 mailbox audit, EXO-1.2 SMTP AUTH, EXO-1.3 auto-forward,
      DEF-1.1 Defender preset). CA-policy creators deploy in
      enabledForReportingButNotEnforced — operator promotes after sign-in
      log validation.

Test infrastructure fixes:
  * Pester "All evaluators exist" updated for PR #6 file renames.
  * Pester "Read-Only Posture" excludes Apply-NRGBaseline (which IS the
    write-mode tool by design).

Migration: any caller of Invoke-NRGCollectIntune must switch to one of
Invoke-NRGCollectIntuneEndpointSecurity / Invoke-NRGCollectIntuneDeviceCompliance /
Invoke-NRGCollectIntuneAppProtection.
'@
        }
    }
}

@{
    # Module identity
    ModuleVersion     = '4.12.1'
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
        'Clear-NRGState',
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
        'Start-NRGWebServer',
        'Register-NRGTenantApp',
        'Get-NRGControlDefinitions',
        'Get-NRGControlById',
        'Get-NRGFindingRiskCost',
        'Get-NRGAggregateRisk',
        'Get-NRGFrameworkCitations',
        'Get-NRGFrameworkDefinitions',
        'Set-NRGSensitiveFileAcl',
        'Set-NRGSensitiveFileContent',
        'Get-NRGTenantLicenseProfile',
        'Test-NRGLicenseRequirementMet',
        'Get-NRGSafeProperty',
        'Get-NRGNestedProperty',
        'Test-NRGSignatureStatus',
        'Get-NRGMaturityTier',
        'Get-NRGCoverageScore',
        'Get-NRGObjectField',
        'Invoke-NRGGraphRequest',
        'Invoke-NRGEvaluatorSafe',

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
        'Publish-NRGDeltaReport',
        'Publish-NRGMonthlyReport',

        # ── v4.12.0 Email Incident Response (Email-IR/ subtree) ───────────────
        'Connect-NRGEmailServices',
        'Disconnect-NRGEmailServices',
        'Invoke-NRGEmailCollectMailbox',
        'Get-NRGEmailDomainFromAddress',
        'Test-NRGEmailIsLegitMSDomain',
        'Test-NRGEmailMatchesMSImpersonation',
        'Test-NRGEmailControl-InboxRules',
        'Test-NRGEmailControl-Forwarding',
        'Test-NRGEmailControl-OutboundActivity',
        'Test-NRGEmailControl-PhishOrigin',
        'Test-NRGEmailControl-ThreatIntel',
        'Publish-NRGEmailIncidentReport',
        'Connect-NRGEmailAdminServices',
        'Disconnect-NRGEmailAdminServices',
        'Invoke-NRGEmailCollectSignIns',
        'Clear-NRGSignInTriageState',
        'Test-NRGSignInControl-FailedToSuccess',
        'Test-NRGSignInControl-AnonymousIp',
        'Test-NRGSignInControl-ImpossibleTravel',
        'Test-NRGSignInControl-RiskyUsers',
        'Test-NRGSignInControl-GeoAnomaly',
        'Test-NRGSignInControl-RankUsers',
        'Test-NRGSignInControl-IPIntel',
        'Publish-NRGSignInTriageReport',
        'Get-NRGIPSignInIntel',
        'Invoke-NRGEmailCollectUserSecurity',
        'Test-NRGEmailControl-OAuthConsents',
        'Test-NRGEmailControl-AuthMethods'
    )

    VariablesToExport = @('NRGAssessmentVersion', 'NRGBrand')
    CmdletsToExport   = @()
    AliasesToExport   = @()

    # Required modules — must be present before this module loads.
    # Audit fix (v4.6.x LOW): MicrosoftTeams added because Connect-NRGServices
    # imports it at runtime (Teams collector wraps Get-CsTenant / Get-CsTeams*),
    # and ExchangeOnlineManagement is pinned to the same 3.2.0 floor that
    # Install-NRGPrerequisites enforces (3.4.0+ has the WAM broker
    # NullReferenceException that the prereq script downgrades around).
    # RequiredModules is intentionally minimal. Graph + EXO are mandatory for
    # any assessment to function. MicrosoftTeams used to be listed here but
    # was demoted to a soft dependency: Connect-NRGServices imports it
    # on-demand inside the Teams collector and skips Teams gracefully if not
    # installed. Listing it here as a hard requirement blocked the entire
    # module from loading on operator workstations that hadn't installed
    # Teams yet — the wrong failure mode for an optional collector.
    # See: v4.6.6 hotfix.
    #
    # MaximumVersion caps (ScubaGear RequiredVersions.ps1 pattern): both SDKs
    # have shipped behavior changes inside a major that broke this tool —
    # Invoke-MgGraphRequest's default output shape flipped to PSCustomObject
    # (the StrictMode nextLink crash), and an EXO module bump caused an MSAL
    # assembly manifest conflict. A cap makes adopting the next major a
    # deliberate, tested edit instead of a surprise on the operator's next
    # Update-Module.
    RequiredModules = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.20.0'; MaximumVersion = '2.99.99' },
        @{ ModuleName = 'ExchangeOnlineManagement';       ModuleVersion = '3.2.0';  MaximumVersion = '3.99.99' }
    )

    # Module metadata
    PrivateData = @{
        PSData = @{
            Tags         = @('M365', 'Security', 'Assessment', 'MSP', 'CIS', 'SCuBA', 'NIST', 'CMMC')
            ProjectUri   = 'https://github.com/Blackvectra/NRG-Assessment-Tool'
            ReleaseNotes = @'
v4.6.4 EMERGENCY (Part A): orchestrator + Apply + evaluator + control-def fixes.

Critical fixes:
  * Pre-initialize $script:NRGFatalExitCode and $script:NRGSuccessExitCode in
    Invoke-NRGAssessment.ps1 so StrictMode reads at exit never throw on the
    success path (v4.6.3 crashed every successful run with exit code 1 AFTER
    the report was written).
  * Apply-NRGAADMFA + Apply-NRGAADLegacyAuth: replace unguarded
    $_.Conditions.* / $_.GrantControls.* chained access with
    Get-NRGNestedProperty under StrictMode. Prior code blew up the
    idempotency Where-Object scan on the first CA policy with a null nested
    object → DUPLICATE CA policies created on every apply.
  * Test-NRGControl-Inventory.ps1 OAuth INV-1.4: fix
    `$highRisk | Where-Object { $_.AppName -eq $_.AppName }` self-comparison
    (always true) — every OAuth app was tagged [HIGH RISK SCOPE] whenever
    any high-risk app existed. Now uses an actual lookup.

PII fixes (HTML report client-deliverable):
  * EXO-7.4 (SmtpAuthExceptions) and AAD-10.2 (PrivCloudOnly) — move full
    UPN list out of the rendered Detail field into structured
    AffectedObjects (escaped). Detail keeps count only.

Dedupe + advisory marking:
  * Purview triple-counting: PVW-1.1 remains canonical UAL check; PVW-2.1
    repointed to AdminAuditLogEnabled; PVW-3.2 repointed to eDiscovery
    cases (or NotApplicable). A tenant with audit disabled now gets ONE
    Gap finding, not three.
  * 15 placeholder evaluators marked "(Manual review required)" in Title
    and ADVISORY ONLY in Detail until real checks land in v4.7.0. Includes
    SPO-3.3 downgrade from hardcoded Satisfied to NotApplicable.

Control definition fixes (controls.json):
  * 11 fabricated SCuBA pillars cleared (MS.PURVIEW.* on PVW-1.1/1.3/2.1/3.4,
    MS.INTUNE.* on INT-1.1/1.2/2.1/2.5/3.3/4.1/4.3) — those pillars do not
    exist in SCuBA. Set SCuBA = "" with a description note.
  * AAD-1.2 / AAD-1.3 SCuBA citations corrected to current ScubaGear IDs
    (MS.AAD.3.2v2 for MFA-for-all, MS.AAD.3.6v1 for phishing-resistant MFA).
  * EXO-2.7 silent no-op duplicate of EXO-1.6 removed.

License-detection fixes:
  * Get-NRGTenantLicenseProfile.SuppressedLicenseRequirements now handles
    7 controls.json strings that previously drifted out of the map:
    DfO Plan 2 with parenthetical, M365 E5 Compliance add-on, M365 E5 or
    E5 Compliance add-on, Sentinel/Defender XDR, Entra Workload Identities
    Premium, M365 Copilot ($30/user/month), Power Platform + Copilot Studio.
  * Pester unit tests added in Testing/NRG.LicenseDetection.Tests.ps1
    exercising each of the 7 strings.

----- prior release notes -----

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

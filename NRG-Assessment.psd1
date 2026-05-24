@{
    # Module identity
    ModuleVersion     = '4.5.5'
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

    # All functions exported by this module
    FunctionsToExport = @(
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
        'Invoke-NRGCollectAADAuthPolicies',
        'Invoke-NRGCollectAADCAPolicies',
        'Invoke-NRGCollectAADUsers',
        'Invoke-NRGCollectAADRoles',
        'Invoke-NRGCollectAADPIM',
        'Invoke-NRGCollectAADIdentityGovernance',
        'Invoke-NRGCollectEXOMailboxConfig',
        'Invoke-NRGCollectEXOConnectionFilter',
        'Invoke-NRGCollectDefender',
        'Invoke-NRGCollectDNSEmailRecords',
        'Invoke-NRGCollectSharePoint',
        'Invoke-NRGCollectTeams',
        'Invoke-NRGCollectPurview',
        'Invoke-NRGCollectIntune',
        'Invoke-NRGCollectPowerPlatform',
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
        'Test-NRGControlDNSSPF',
        'Test-NRGControlDNSDKIM',
        'Test-NRGControlDNSDMARC',
        'Test-NRGControlDNSMTASTS',
        'Test-NRGControlDNSTLSRPT',
        'Test-NRGControlDNSDNSSEC',
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
        'Test-NRGControlIntune',
        'Test-NRGControlIntuneEDR',
        'Test-NRGControlIntuneASR',
        'Test-NRGControlIntuneFirewall',
        'Test-NRGControlIntuneMacEncryption',
        'Test-NRGControlIntuneWindowsUpdate',
        'Test-NRGControlIntuneEnrollmentRestrictions',
        'Test-NRGControlIntuneAppConfig',
        'Test-NRGControlIntuneConditionalLaunch',
        'Test-NRGControlPowerPlatform',
        'Test-NRGControlPPLConnectorClassification',
        'Test-NRGControlPPLAutomate',
        'Test-NRGControlPPLPowerApps',
        'Publish-NRGAssessmentHTML',
        'Publish-NRGAssessmentSummary'
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
            ReleaseNotes = 'v4.5.5: 143 controls across 9 workloads, 153 exported functions, full OWASP/ASVS hardening, 77-test Pester suite'
        }
    }
}

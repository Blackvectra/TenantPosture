# NRG and the CIS Microsoft 365 Foundations Benchmark: alignment of citations

Checked against **CIS Microsoft 365 Foundations Benchmark v7.0.0** (160 recommendations) on 2026-10-25, recommendation by recommendation against its audit procedure and evaluator by evaluator against the code. The citations live in `Config/controls.json` (`References.CIS`); the recommendation list is `Config/framework-baselines/cis-m365-v7.0.0.txt`; the controls left uncited, each with its reason, are `Config/cis-m365-uncited-controls.json`. `TP.FrameworkAccuracy.Tests.ps1` fails on a number that is not in v7.0.0 and on a baseline document that disagrees with `controls.json`; `TP.FrameworkCoverage.Tests.ps1` fails on an uncited control that is not on the list.

## Why the citations changed

Every control carried a CIS number, because the coverage test required one. The numbers came from earlier editions: 78 of the 159 distinct numbers do not exist in v7.0.0, most of the rest name a different recommendation in v7.0.0 (CIS renumbers between editions), and the Intune, Power Platform and DNS controls carried numbers for sections the benchmark does not have. Nothing checked them, so the CIS card in the report scored the tenant against recommendations a client could not look up.

## The rule

A control cites recommendation R only when (1) its evaluator judges the setting R audits, or some of the settings R lists, and (2) every state the evaluator scores Satisfied also passes R's audit for those settings. A looser threshold (anti-phishing level 2 against R's 3, before the change below), a different setting with a similar name, or a pass that R's audit would fail leaves the control uncited, with the reason recorded. A control that only ever reports not assessed may cite R when R is its subject, because it can never credit the client with R.

| Relation | Meaning | Controls |
|---|---|---|
| Equivalent | The evaluator checks what R audits, and every pass meets R. | 56 |
| Subset | The evaluator checks some of the settings R lists, and every pass meets R for those settings. R can still fail on a setting the tool does not read. | 19 |
| Not cited | No v7.0.0 recommendation describes the check, or the evaluator passes something R fails. | 132 |

75 controls cite 56 of the 160 recommendations. The CIS card in the report scores only those controls, so it is a narrower number than before, and an honest one: it covers what the tool verified against this benchmark.

**Scope differences kept as citations.** EXO-1.3, EXO-5.3, EXO-8.2 and DEF-2.3 judge the policies and rules in force (`Get-TPInForcePolicies`; enabled transport rules), while the CIS audit reads every policy, or only the Default malware policy. A disabled rule or a policy no recipient falls under changes nothing about what happens to mail, so the judgment is the same requirement; it is recorded here because a CIS audit run by hand can disagree with the tool on such a tenant.

**Evaluators tightened to earn a citation (2026-10-25).** DEF-1.5 requires phishing threshold 3 (it accepted 2); AAD-12.1 judges `isMfaCapable` (it read `isMfaRegistered`); EXO-1.4 requires DKIM `Status = Valid` on every accepted domain, relay domains included (it judged authoritative domains on `Enabled` alone); SPO-1.4 and SPO-3.4 require guest expiry of 30 days (any expiry passed); SPO-2.6 and SPO-2.7 require re-verification within 15 days (any period, and 30, passed); PVW-1.3 requires the enforced DLP policy to cover Exchange, SharePoint, OneDrive or Teams (an Endpoint-only policy passed); AAD-3.1 allows two to four Global Administrators (it allowed eight; the NRG baseline moved to v1.1 with it, by the owner's decision). Each changes verdicts: a tenant that passed before can now fail.

## Cited controls

| Control | v7.0.0 | Recommendation | Relation | Why |
|---|---|---|---|---|
| AAD-1.2 MFA Required for All Users | 5.2.2.2 | Ensure multifactor authentication is enabled for all users (Automated) | Equivalent | Satisfied only via an enabled CA policy with IncludeUsers All, Include All applications and no application exclusions (Test-TPCAAllUsers/Test-TPCAAllApps/Get-TPCANarrowing), grant necessarily requiring mfa or authStrength, plus every enabled member registered; Security Defaults scores Partial, never Satisfied, so every pass meets 5.2.2.2 (IncludeUsers All, IncludeApplications All, mfa OR authenticationStrength, state enabled). |
| AAD-2.2 Named Locations Defined | 5.2.2.14 | Ensure trusted 'named locations' are defined (Automated) | Equivalent | Satisfied when at least one named location has isTrusted true; only ipNamedLocation carries isTrusted and Graph requires at least one ipRange on it, which is exactly 5.2.2.14 (isTrusted true, ipRanges contains at least one range). |
| AAD-3.1 Global Administrator Count 2-4, Cloud-Only | 1.1.3 | Ensure that between two and four global admins are designated (Automated) | Equivalent | Satisfied requires two to four Global Administrators, permanent and eligible together, all cloud-only, and reports a group holding the role as not assessed rather than counting it, so every pass meets 1.1.3's two to four (since NRG baseline v1.1, 2026-10-25; it allowed eight before). |
| AAD-3.5 PIM GA Activation Requires Approval | 5.3.4 | Ensure approval is required for Global Administrator role activation (Automated) | Subset | Satisfied when the Global Administrator role management policy's Approval rule has isApprovalRequired true, which is 5.3.4 step 3; the evaluator does not check step 4 (approvalStages.primaryApprovers contains at least one user). |
| AAD-4.1 Guest Invite Permissions Restricted | 5.1.6.3 | Ensure guest user invitations are limited (Automated) | Equivalent | Satisfied for allowInvitesFrom adminsAndGuestInviters, admins or none; 'admins' is not a Graph allowInvitesFrom value, so in practice this is exactly R's "adminsAndGuestInviters or none". |
| AAD-4.2 External Collaboration Settings Restricted | 5.1.2.3 | Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes' (Automated) | Equivalent | The only thing judged is defaultUserRolePermissions.allowedToCreateTenants (Satisfied when not true), which is 5.1.2.3; note the tool also scores Satisfied when the property was not returned ($null), a not-read value R could not pass. |
| AAD-4.3 B2B Guest Default Permissions Restricted | 5.1.6.2 | Ensure that guest user access is restricted (Automated) | Equivalent | Satisfied only for guestUserRoleId 2af84b1e (Restricted Guest User), which R lists as passing; the tool is stricter (it scores the default Guest User role as a Gap). NOTE: the evaluator labels a0b1b346 as limited access and 10dae51f as same-as-members, but Microsoft Graph documents a0b1b346 = User (same as members) and 10dae51f = Guest User (limited), matching the CIS text; the labels in the Gap details are swapped. |
| AAD-5.1 Self-Service Password Reset Enabled | 5.2.4.1 | Ensure 'Self service password reset enabled' is set to 'All' (Manual) | Equivalent | Always NotApplicable "requires manual verification" for the SSPR enabled scope (Selected/All); same subject as 5.2.4.1 (Manual), never passes. |
| AAD-5.2 SSPR Requires Multiple Authentication Methods | 5.2.4.2 | Ensure that 2 methods are required for password reset (Manual) | Equivalent | Always NotApplicable "requires manual verification" for "Number of methods required to reset = 2"; same subject as 5.2.4.2 (Manual), never passes. |
| AAD-6.1 User App Registration Disabled | 5.1.2.2 | Ensure users cannot register applications (Automated) | Equivalent | Satisfied when defaultUserRolePermissions.allowedToCreateApps is false (not-read is NotApplicable), which is 5.1.2.2's audit value. |
| AAD-6.3 Admin Consent Workflow Enabled | 5.1.5.2 | Ensure the admin consent workflow is enabled (Automated) | Equivalent | Satisfied when adminConsentRequestPolicy.isEnabled is true, which is 5.1.5.2's audit. |
| AAD-7.1 Password Protection Lockout Configured | 5.2.3.8 | Ensure that Account 'Lockout threshold' is '10' or less (Automated) | Equivalent | Satisfied when Password Rule Settings LockoutThreshold <= 10 (absent value read as Microsoft's default 10), the same groupSettings value and threshold as 5.2.3.8. |
| AAD-7.3 Smart Lockout Duration at Least 60 Seconds | 5.2.3.9 | Ensure that Account 'Lockout duration in seconds' is at least 60 seconds (Automated) | Equivalent | Satisfied when Password Rule Settings LockoutDurationInSeconds >= 60 (absent value read as Microsoft's default 60), the value 5.2.3.9 audits. |
| AAD-7.4 Custom Banned Password List Enforced | 5.2.3.2 | Ensure custom banned passwords lists are used (Automated) | Equivalent | Satisfied when EnableBannedPasswordCheck is True and the custom list holds at least one entry, which is 5.2.3.2's audit (the entries themselves are not collected). |
| AAD-7.5 Passwords Set to Never Expire | 1.3.1 | Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)' (Automated) | Equivalent | Satisfied when passwordValidityPeriodInDays is 2147483647 on every verified domain, the Get-MgDomain value 1.3.1 audits; an unset value is Microsoft's 90-day default. |
| AAD-7.2 Break-Glass Accounts Configured | 1.1.2 | Ensure two emergency access accounts have been defined (Manual) | Subset | Satisfied when >= 2 cloud-only Global Administrators are excluded from every enabled CA policy reaching them; 1.1.2 (Manual) requires two cloud-only GA emergency accounts with at least one excluded from all CA rules, and also items the tool does not check (unlicensed, .onmicrosoft.com domain, not disabled, generic naming, written procedure). |
| AAD-9.1 Authenticator Number Matching Enabled | 5.2.3.1 | Ensure Microsoft Authenticator is configured to protect against MFA fatigue (Automated) | Subset | Always NotApplicable "Enforced by the platform" for Authenticator number matching, which 5.2.3.1's subject (Authenticator MFA-fatigue protection) notes as platform-enforced; it never passes, but it does not read the app-name/location settings R audits (the collector already reads displayAppInformationRequiredState). |
| AAD-10.3 Break-Glass Account Sign-In Monitoring | 2.2.1 | Ensure emergency access account activity is monitored (Manual) | Equivalent | Always NotApplicable manual verification that an alert fires on any break-glass sign-in; same subject as 2.2.1 (Manual), never passes. |
| AAD-12.1 Users Without MFA — Named List | 5.2.3.4 | Ensure all member users are 'MFA capable' (Automated) | Equivalent | Satisfied requires every enabled member user (the directory-sync account excluded, as 5.2.3.4's note allows) to be isMfaCapable in the registration report, the value 5.2.3.4 audits (since 2026-10-25; it read isMfaRegistered before); a results file without the value is not assessed. |
| DEF-1.1 Safe Attachments Enabled with Block Action | 2.1.4 | Ensure Safe Attachments policy is enabled (Automated) | Subset | Satisfied requires Enable = True and Action = Block in every Safe Attachments policy in force, meeting 2.1.4's Enable/Action values; QuarantineTag = AdminOnlyAccessPolicy is not judged. |
| DEF-1.2 Safe Links Enabled and Hardened | 2.1.1 | Ensure Safe Links for Office Applications is Enabled (Automated) | Subset | Satisfied requires EnableSafeLinksForEmail True, AllowClickThrough False, TrackClicks True, EnableForInternalSenders True and DisableUrlRewrite not True in every policy in force, matching 2.1.1's values for those five; EnableSafeLinksForTeams/Office, ScanUrls and DeliverMessageAfterScan are not judged. |
| DEF-1.3 Spoof Intelligence Enabled | 2.1.7 | Ensure that an anti-phishing policy has been created (Automated) | Subset | Satisfied requires EnableSpoofIntelligence = True in every anti-phishing policy in force, matching 2.1.7's EnableSpoofIntelligence True. |
| DEF-1.4 Honor DMARC Policy (Defender Layer) | 2.1.7 | Ensure that an anti-phishing policy has been created (Automated) | Subset | Satisfied requires HonorDmarcPolicy = True in every anti-phishing policy in force, matching 2.1.7's HonorDmarcPolicy True (duplicates EXO-1.7). |
| DEF-1.5 Phishing Threshold Level Aggressive | 2.1.7 | Ensure that an anti-phishing policy has been created (Automated) | Subset | Satisfied requires PhishThresholdLevel 3 or higher in every anti-phishing policy in force, meeting 2.1.7's threshold of at least 3 (since 2026-10-25; it accepted 2 before). |
| DEF-1.6 First Contact Safety Tip Enabled | 2.1.7 | Ensure that an anti-phishing policy has been created (Automated) | Subset | Satisfied requires EnableFirstContactSafetyTips = True in every anti-phishing policy in force, matching 2.1.7's EnableFirstContactSafetyTips True. |
| DEF-2.3 Anti-Malware Common Attachments Blocked | 2.1.2 | Ensure the Common Attachment Types Filter is enabled (Automated) | Equivalent | Satisfied requires EnableFileFilter = True and FileTypes containing all 53 approved types (Microsoft's default list, Config/tp-standards.json) in every malware policy in force, meeting 2.1.2. Scope caveat: 2.1.2 audits the Default policy only, and the tool does not read the Default when a custom or preset policy covers every accepted domain. |
| DEF-3.3 Defender for Cloud Apps Connected | 2.4.3 | Ensure Microsoft Defender for Cloud Apps is enabled and configured (Manual) | Subset | Always NotApplicable (requires manual verification) and its subject, the Defender for Cloud Apps Microsoft 365 connector, is part of 2.4.3, so it cannot over-credit. |
| DEF-4.1 DLP Policy Covers All Key Workloads | 3.2.1 | Ensure DLP policies are enabled (Automated) | Equivalent | Satisfied requires Mode = Enable DLP policies covering Exchange, SharePoint, OneDrive and Teams each with Include All and no exclusions, which meets 3.2.1 (a policy with Mode Enable and at least one of those locations) and also 3.2.2 (Teams, Mode Enable, TeamsLocation All). |
| DEF-4.4 Priority Accounts Tagged in Defender | 2.4.1 | Ensure Priority account protection is enabled and configured (Automated) | Subset | Satisfied requires at least one account tagged Priority (Get-User -IsVIP) and EnablePriorityAccountProtection not read as False, covering 2.4.1 steps 1-2; the step-3 alert policies are not judged, a Plan 1 tenant where the switch cannot be read still passes, and whether the tagged set matches the organization's priority accounts is left to the reviewer. |
| DEF-4.7 Safe Links Protects Office Applications | 2.1.1 | Ensure Safe Links for Office Applications is Enabled (Automated) | Subset | Satisfied requires EnableSafeLinksForOffice = True in every Safe Links policy in force, matching 2.1.1's EnableSafeLinksForOffice True (the setting in its title). |
| DNS-1.1 SPF Record Published | 2.1.8 | Ensure that SPF records are published for all Exchange Domains (Automated) | Equivalent | Satisfied requires exactly one v=spf1 record whose all term (or redirect target's) is -all with at most 10 lookup terms, for every non-onmicrosoft accepted domain, which meets 2.1.8 (-all or ~all, redirect target compliant); ~all is only Partial, stricter than 2.1.8. |
| EXO-1.1 Mailbox Audit Logging Enabled | 6.1.1 | Ensure 'AuditDisabled' organizationally is set to 'False' (Automated) | Equivalent | Satisfied requires OrganizationConfig.AuditDisabled = False (plus no Get-MailboxAuditBypassAssociation entry), which meets 6.1.1's AuditDisabled = False; the bypass half also meets 6.1.3, the alternative citation. |
| EXO-1.2 SMTP Client Authentication Disabled | 6.5.4 | Ensure SMTP AUTH is disabled (Automated) | Equivalent | Satisfied requires Get-TransportConfig SmtpClientAuthenticationDisabled = True and zero per-mailbox re-enables, which meets 6.5.4 (SmtpClientAuthenticationDisabled True). |
| EXO-1.3 External Auto-Forwarding Blocked | 6.2.1 | Ensure all forms of mail forwarding are blocked and/or disabled (Automated) | Subset | Satisfied requires AutoForwardingMode = Off in every outbound spam policy in force, which is 6.2.1 step 2; step 1 (transport-rule redirects) is EXO-8.2's. Scope caveat: only policies in force are judged (a custom policy whose rule is disabled, or the Default when a custom policy covers every accepted domain, is not read), while 6.2.1 says verify each outbound policy. |
| EXO-1.4 DKIM Signing Enabled for All Domains | 2.1.9 | Ensure that DKIM is enabled for all Exchange Online Domains (Automated) | Equivalent | Satisfied requires DKIM Enabled with Status Valid on every accepted domain except the onmicrosoft.com domains, relay domains included, as 2.1.9 audits (since 2026-10-25; it judged authoritative domains on Enabled alone before). |
| EXO-1.6 Modern Authentication Enabled | 6.5.1 | Ensure modern authentication for Exchange Online is enabled (Automated) | Equivalent | Satisfied requires OrganizationConfig.OAuth2ClientProfileEnabled = True (plus legacy auth blocked or SMTP AUTH closed), which meets 6.5.1 (OAuth2ClientProfileEnabled True). |
| EXO-1.7 Honor DMARC Policy Enabled | 2.1.7 | Ensure that an anti-phishing policy has been created (Automated) | Subset | Satisfied requires HonorDmarcPolicy = True in every anti-phishing policy in force, which meets 2.1.7's HonorDmarcPolicy True; 2.1.7's other anti-phishing settings are not judged here. |
| EXO-2.5 Customer Lockbox Enabled | 1.3.6 | Ensure the customer lockbox feature is enabled (Automated) | Equivalent | Satisfied requires Get-OrganizationConfig CustomerLockBoxEnabled = True, exactly 1.3.6's audit. |
| EXO-3.1 Connection Filter Safe List Bypass Disabled | 2.1.13 | Ensure the connection filter safe list is off (Automated) | Equivalent | Satisfied requires EnableSafeList = False on the default connection filter policy, exactly 2.1.13's audit (Get-HostedConnectionFilterPolicy -Identity Default EnableSafeList False). |
| EXO-3.2 Outbound Spam Sending Limits Configured | 2.1.15 | Ensure outbound anti-spam message limits are in place (Automated) | Equivalent | Satisfied requires every outbound spam policy in force to set RecipientLimitExternalPerHour 1-500, RecipientLimitInternalPerHour 1-1000, RecipientLimitPerDay 1-1000 and ActionWhenThresholdReached BlockUser; 2.1.15 audits the same four settings and accepts lower limits. |
| EXO-3.5 Transport Rules Changes Audited | 3.1.1 | Ensure Microsoft 365 audit log search is Enabled (Automated) | Equivalent | Satisfied requires Get-AdminAuditLogConfig UnifiedAuditLogIngestionEnabled = True (read from the Exchange Online session) and AdminAuditLogEnabled not False, which meets 3.1.1 (UnifiedAuditLogIngestionEnabled True). |
| EXO-4.3 Safe Attachments for SharePoint OneDrive Teams Enabled | 2.1.5 | Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled (Automated) | Subset | Satisfied requires Get-AtpPolicyForO365 EnableATPForSPOTeamsODB = True, one of 2.1.5's three settings; EnableSafeDocs True and AllowSafeDocsOpen False are not judged. |
| EXO-5.1 Per-User Mailbox Audit Logging Enabled for All Mailboxes | 6.1.1 | Ensure 'AuditDisabled' organizationally is set to 'False' (Automated) | Equivalent | Satisfied requires OrganizationConfig.AuditDisabled = False, exactly 6.1.1; it does not read per-mailbox audit actions or AuditEnabled, so 6.1.2 (the draft's id) is not met. |
| EXO-5.3 No Allowed Sender Domains Bypassing Anti-Spam Filtering | 2.1.14 | Ensure inbound anti-spam policies do not contain allowed domains (Automated) | Equivalent | Satisfied requires AllowedSenderDomains (and AllowedSenders) empty in every inbound anti-spam policy in force, which meets 2.1.14's AllowedSenderDomains undefined. Scope caveat: only policies in force are judged, while 2.1.14 says each inbound policy must pass (a custom policy with a disabled rule, or the Default when a custom policy covers every accepted domain, is not read). |
| EXO-2.6 Shared Mailboxes Block Direct Sign-In | 1.2.2 | Ensure sign-in to shared mailboxes is blocked (Automated) | Equivalent | Satisfied only when accountEnabled was read as false for every shared mailbox's Entra account (a mailbox whose state was not read leaves it not assessed), which is 1.2.2's audit; EXO-6.2 judges the same setting and names each mailbox. |
| EXO-6.2 Shared Mailboxes with Sign-In Enabled — Named List | 1.2.2 | Ensure sign-in to shared mailboxes is blocked (Automated) | Equivalent | Satisfied requires every shared mailbox (Get-Mailbox SharedMailbox) to match an Entra member account with accountEnabled not True (unmatched mailboxes make it not assessed), which meets 1.2.2 (AccountEnabled False for all shared mailboxes). |
| EXO-6.3 Mailboxes with Audit Logging Disabled — Named List | 6.1.3 | Ensure 'AuditBypassEnabled' is not enabled on mailboxes (Automated) | Equivalent | Satisfied (Get-TPMailboxAuditBypassState Clean) requires Get-MailboxAuditBypassAssociation to return no AuditBypassEnabled account and org auditing on, which meets 6.1.3. |
| EXO-7.3 No Mailboxes with Per-User Audit Explicitly Disabled | 6.1.3 | Ensure 'AuditBypassEnabled' is not enabled on mailboxes (Automated) | Equivalent | Same helper as EXO-6.3: Satisfied requires no Get-MailboxAuditBypassAssociation entry with AuditBypassEnabled True and org auditing on, which meets 6.1.3. |
| EXO-8.2 No Transport Rule Redirects Mail Externally | 6.2.1 | Ensure all forms of mail forwarding are blocked and/or disabled (Automated) | Subset | Satisfied requires no enabled transport rule with RedirectMessageTo (also BlindCopyTo/CopyTo) to an external recipient, which is 6.2.1 step 1; step 2 (AutoForwardingMode) is EXO-1.3's. Scope caveat: disabled rules are not judged, while 6.2.1's Get-TransportRule audit lists every rule. SetSCL -1 is noted but not scored, so 6.2.2 is not met. |
| PPL-3.5 Copilot Interaction Audit Logging Active | 3.1.1 | Ensure Microsoft 365 audit log search is Enabled (Automated) | Subset | Satisfied requires AuditCopilotEnabled = True, which the collector sets only from UnifiedAuditLogIngestionEnabled = True (False from S&C is not trusted), plus a Copilot retention policy; every Satisfied state therefore meets 3.1.1, and the control judges 3.1.1's setting as one of its two halves (draft left it uncited). |
| PVW-1.1 Unified Audit Log Enabled | 3.1.1 | Ensure Microsoft 365 audit log search is Enabled (Automated) | Equivalent | Satisfied only when UnifiedAuditLogIngestionEnabled = True (False from S&C is not trusted), exactly 3.1.1's audit. |
| PVW-1.3 DLP Policy Active for Sensitive Data | 3.2.1 | Ensure DLP policies are enabled (Automated) | Equivalent | Satisfied requires a DLP policy in Mode Enable whose workloads include Exchange, SharePoint, OneDrive or Teams, 3.2.1's criteria (since 2026-10-25; an Endpoint-only policy passed before). |
| PVW-1.4 Sensitivity Labels Published | 3.3.1 | Ensure Information Protection sensitivity label policies are published (Automated) | Equivalent | Satisfied when at least one sensitivity label exists and at least one Get-LabelPolicy policy exists, meeting 3.3.1's "at least one sensitivity label policy published"; caveat: the collector does not filter Type -eq PublishedSensitivityLabel as R's script does. |
| PVW-2.1 Purview Audit Log Search Enabled | 3.1.1 | Ensure Microsoft 365 audit log search is Enabled (Automated) | Equivalent | Satisfied only when UnifiedAuditLogIngestionEnabled = True (same read as PVW-1.1), exactly 3.1.1's audit. |
| PVW-4.3 Sensitivity Labels Defined and Published | 3.3.1 | Ensure Information Protection sensitivity label policies are published (Automated) | Equivalent | Same check as PVW-1.4: Satisfied when labels exist and at least one Get-LabelPolicy policy exists, meeting 3.3.1; same Type-filter caveat. |
| SPO-1.1 External Sharing Restricted | 7.2.3 | Ensure external content sharing is restricted (Automated) | Equivalent | Satisfied only when Graph SharingCapability is disabled or existingExternalUserSharingOnly (externalUserSharingOnly is Partial, externalUserAndGuestSharing a Gap); 7.2.3 passes ExternalUserSharingOnly, ExistingExternalUserSharingOnly or Disabled, so every Satisfied state passes R (tool is stricter). |
| SPO-1.3 SharePoint Legacy Authentication Blocked | 7.2.1 | Ensure modern authentication for SharePoint applications is required (Automated) | Equivalent | Satisfied only when Graph isLegacyAuthProtocolsEnabled = false, the same setting 7.2.1 audits (Get-SPOTenant LegacyAuthProtocolsEnabled = False). |
| SPO-1.4 Guest Access Expiration Configured | 7.2.9 | Ensure guest access to a site or OneDrive will expire automatically (Automated) | Equivalent | Satisfied requires ExternalUserExpirationRequired True with ExternalUserExpireInDays 30 or less (30 is the setting's minimum), 7.2.9's value (since 2026-10-25; any expiry passed before). |
| SPO-2.5 Third-Party Cloud Storage Connectors Disabled | 8.1.1 | Ensure external file sharing in Teams is enabled for only approved cloud storage services (Automated) | Subset | The evaluator reads the Teams client storage providers (Get-CsTeamsClientConfiguration AllowDropBox/AllowBox/AllowGoogleDrive/AllowShareFile, plus AllowEgnyte when reported) and is Satisfied only when all are off, which meets 8.1.1 (only authorized providers True); it explicitly does NOT read the Microsoft 365-on-the-web toggle that 1.3.7 audits (service principal c1f33bc0-... AccountEnabled), so the draft's 1.3.7 is wrong. Caveat: when the module does not report AllowEgnyte the tool still passes without checking it (same helper as TMS-2.3). |
| SPO-2.6 Email Attestation Required for Sharing | 7.2.10 | Ensure reauthentication with verification code is restricted (Automated) | Equivalent | Satisfied requires EmailAttestationRequired True with EmailAttestationReAuthDays 15 or fewer, 7.2.10's values (since 2026-10-25; any period passed before). |
| SPO-2.7 Reauthentication Required for Sharing Links | 7.2.10 | Ensure reauthentication with verification code is restricted (Automated) | Equivalent | Satisfied requires EmailAttestationRequired True with EmailAttestationReAuthDays 1 to 15, 7.2.10's values (since 2026-10-25; it allowed 30 before, which CISA SCuBA MS.SHAREPOINT.3.3v2 still allows). |
| SPO-3.4 SharePoint Guest Access Expiration Required | 7.2.9 | Ensure guest access to a site or OneDrive will expire automatically (Automated) | Equivalent | Same setting and threshold as SPO-1.4: ExternalUserExpirationRequired True with ExternalUserExpireInDays 30 (since 2026-10-25). |
| TMS-1.1 External Federation Access Restricted | 8.2.1 | Ensure external domains are restricted in the Teams admin center (Automated) | Equivalent | Satisfied when Get-CsTenantFederationConfiguration AllowFederatedUsers = False or AllowedDomains is a non-empty allow list (open and blocklist are Gap/Partial); both are 8.2.1's org-settings passing states (Off; Allow only specific external domains). Tool does not judge whether listed domains are authorized and scores 8.2.1's third passing state (AllowedDomains empty) as Gap, which is stricter. |
| TMS-1.2 Teams Consumer Account Access Disabled | 8.2.2 | Ensure communication with unmanaged Teams users is disabled (Automated) | Equivalent | Satisfied only when AllowTeamsConsumer = False, 8.2.2's org-settings passing state; 8.2.3 (AllowTeamsConsumerInbound = False) also states that turning the parent off disables inbound contact, so it is a secondary fit, but the scored setting is 8.2.2's. |
| TMS-1.3 Anonymous Meeting Join Disabled | 8.5.1 | Ensure anonymous users can't join a meeting (Automated) | Equivalent | Satisfied when the Global meeting policy AllowAnonymousUsersToJoinMeeting = False (8.5.1's audit) or the stricter org-wide DisableAnonymousJoin = True; Partial/Gap otherwise. |
| TMS-1.4 External Participants Cannot Take Screen Control | 8.5.7 | Ensure external participants can't give or request control (Automated) | Equivalent | Satisfied only when Global meeting policy AllowExternalParticipantGiveRequestControl = False, exactly 8.5.7's audit. |
| TMS-2.2 Unverified App Publisher Blocked | 8.4.1 | Ensure app permission policies are configured (Manual) | Subset | Always NotApplicable ("requires manual verification"), so it cannot over-credit; its subject (Teams org-wide app settings limiting third-party apps) is part of 8.4.1's org-wide app settings audit. |
| TMS-2.3 Third-Party Cloud Storage Disabled in Teams | 8.1.1 | Ensure external file sharing in Teams is enabled for only approved cloud storage services (Automated) | Equivalent | Satisfied only when AllowDropBox, AllowBox, AllowGoogleDrive, AllowShareFile (and AllowEgnyte when reported) are all False, stricter than 8.1.1's "only authorized providers True"; caveat: AllowEgnyte is skipped (with a note) when the module does not report it. |
| TMS-2.4 Teams Email Integration Disabled | 8.1.2 | Ensure users can't send emails to a channel email address (Automated) | Equivalent | Satisfied only when AllowEmailIntoChannel = False, exactly 8.1.2's audit. |
| TMS-2.7 External User Chat Restricted | 8.2.1 | Ensure external domains are restricted in the Teams admin center (Automated) | Equivalent | Reads the same federation mode as TMS-1.1 (AllowFederatedUsers / AllowedDomains; Satisfied = Disabled or AllowList), which is 8.2.1; the draft's 8.2.3 audits AllowTeamsConsumerInbound, which this evaluator never reads. |
| TMS-2.8 PSTN Users Cannot Bypass Lobby | 8.5.4 | Ensure users dialing in can't bypass the lobby (Automated) | Equivalent | Satisfied only when AllowPSTNUsersToBypassLobby = False, exactly 8.5.4's audit. |
| TMS-3.2 Auto-Admit Only Authenticated Organization Users | 8.5.3 | Ensure only people in my org can bypass the lobby (Automated) | Equivalent | Satisfied only for AutoAdmittedUsers OrganizerOnly or EveryoneInCompanyExcludingGuests (InvitedUsers is Partial); 8.5.3 passes InvitedUsers, EveryoneInCompanyExcludingGuests or OrganizerOnly, so every Satisfied state passes R. |
| TMS-3.3 Meeting Chat Disabled for Anonymous Participants | 8.5.5 | Ensure meeting chat does not allow anonymous users (Automated) | Equivalent | Satisfied when MeetingChatEnabledType = Disabled or matches 'ExceptAnonymous' (EnabledExceptAnonymous / EnabledInMeetingOnlyForAllExceptAnonymous), the values 8.5.5 accepts. |
| TMS-4.2 Anonymous Users Cannot Start Meetings | 8.5.2 | Ensure anonymous users and dial-in callers can't start a meeting (Automated) | Equivalent | Satisfied only when Global meeting policy AllowAnonymousUsersToStartMeeting = False, exactly 8.5.2's audit. |
| TMS-4.3 Teams External Domain Federation Restricted to Allowlist | 8.2.1 | Ensure external domains are restricted in the Teams admin center (Automated) | Equivalent | Satisfied when federation mode is AllowList or Disabled (AllowFederatedUsers False, or True with a non-empty AllowedDomains), both 8.2.1 org-settings passing states. |

## Controls not cited

The reasons are in `Config/cis-m365-uncited-controls.json`. Several are one change away from a citation, and each needs a decision first:

- AAD-1.1 (5.2.2.3): CIS audits a Conditional Access policy blocking `exchangeActiveSync` and `other`; the tool also passes Security Defaults, an owner decision recorded in CLAUDE.md.
- AAD-6.2 (5.1.5.1): CIS requires "Do not allow user consent"; the tool passes `microsoft-user-default-low` by design.
- AAD-1.3 (5.2.2.5) and AAD-10.2 (1.1.1): the shared privileged-role list lacks Global Reader and Password Administrator, which 5.2.2.5 names; changing it moves several controls at once.
- DNS-1.3 (2.1.10): CIS requires a `ruf=` reporting address and includes the `.onmicrosoft.com` domain, which the DNS collector does not read.

## Recommendations no control checks

104 of the 160 recommendations have no citing control. Some are settings the collectors already read and no evaluator scores (5.2.3.3 on-premises password protection, 2.1.12 the connection filter IP allow list); the rest need a new read. Section 9 (Microsoft Fabric) is outside what the tool assesses.

**1. Microsoft 365 admin center** (11)

- 1.1.1 Ensure Administrative accounts are cloud-only (Automated)
- 1.1.4 Ensure administrative accounts use licenses with a reduced application footprint (Automated)
- 1.2.1 Ensure that only organizationally managed/approved public groups exist (Automated)
- 1.3.2 Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices (Automated)
- 1.3.3 Ensure 'External sharing' of calendars is not available (Automated)
- 1.3.4 Ensure 'User owned apps and services' is restricted (Automated)
- 1.3.5 Ensure internal phishing protection for Forms is enabled (Automated)
- 1.3.7 Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web' (Automated)
- 1.3.8 Ensure that Sways cannot be shared with people outside of your organization (Manual)
- 1.3.9 Ensure shared bookings pages are restricted to select users (Automated)

**2. Microsoft 365 Defender** (9)

- 2.1.3 Ensure notifications for internal users sending malware is Enabled (Automated)
- 2.1.6 Ensure Exchange Online Spam Policies are set to notify administrators (Automated)
- 2.1.10 Ensure DMARC records for all Exchange Online domains are published (Automated)
- 2.1.11 Ensure comprehensive attachment filtering is applied (Automated)
- 2.1.12 Ensure the connection filter IP allow list is not used (Automated)
- 2.4.2 Ensure Priority accounts have 'Strict protection' presets applied (Automated)
- 2.4.4 Ensure Zero-hour auto purge for Microsoft Teams is on (Automated)
- 2.4.5 Ensure 'AIR' remediation is enabled (Manual)

**3. Microsoft Purview** (2)

- 3.2.2 Ensure DLP policies are enabled for Microsoft Teams (Automated)
- 3.2.3 Ensure DLP policies are published for Copilot users (Automated)

**4. Microsoft Intune admin center** (2)

- 4.1 Ensure devices without a compliance policy are marked 'not compliant' (Automated)
- 4.2 Ensure device enrollment for personally owned devices is blocked by default (Automated)

**5. Microsoft Entra admin center** (50)

- 5.1.2.1 Ensure 'Per-user MFA' is disabled (Manual)
- 5.1.2.4 Ensure access to the Entra admin center is restricted (Manual)
- 5.1.2.5 Ensure the option to remain signed in is hidden (Manual)
- 5.1.2.6 Ensure 'LinkedIn account connections' is disabled (Manual)
- 5.1.3.1 Ensure users cannot create security groups (Automated)
- 5.1.3.2 Ensure that 'Restrict user ability to access groups features in My Groups' is set to 'Yes' (Manual)
- 5.1.3.3 Ensure that 'Owners can manage group membership requests in My Groups' is set to 'No' (Manual)
- 5.1.3.4 Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No' (Automated)
- 5.1.4.1 Ensure the ability to join devices to Entra is restricted (Automated)
- 5.1.4.2 Ensure the maximum number of devices per user is limited (Automated)
- 5.1.4.3 Ensure the GA role is not added as a local administrator during Entra join (Automated)
- 5.1.4.4 Ensure local administrator assignment is limited during Entra join (Automated)
- 5.1.4.5 Ensure Local Administrator Password Solution is enabled (Automated)
- 5.1.4.6 Ensure users are restricted from recovering BitLocker keys (Automated)
- 5.1.5.1 Ensure user consent to apps accessing company data on their behalf is not allowed (Automated)
- 5.1.5.3 Ensure password addition is blocked for applications (Automated)
- 5.1.5.4 Ensure password lifetime for applications does not exceed 180 days (Automated)
- 5.1.5.5 Ensure new application passwords are system-generated (Automated)
- 5.1.5.6 Ensure maximum certificate lifetime for applications does not exceed 180 days (Automated)
- 5.1.6.1 Ensure that collaboration invitations are sent to allowed domains only (Automated)
- 5.1.8.1 Ensure that password hash sync is enabled for hybrid deployments (Automated)
- 5.2.2.1 Ensure multifactor authentication is enabled for all users in administrative roles (Automated)
- 5.2.2.3 Enable Conditional Access policies to block legacy authentication (Automated)
- 5.2.2.4 Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users (Automated)
- 5.2.2.5 Ensure 'Phishing-resistant MFA strength' is required for Administrators (Automated)
- 5.2.2.6 Enable Identity Protection user risk policies (Automated)
- 5.2.2.7 Enable Identity Protection sign-in risk policies (Automated)
- 5.2.2.8 Ensure 'sign-in risk' is blocked for medium and high risk (Automated)
- 5.2.2.9 Ensure a managed device is required for authentication (Automated)
- 5.2.2.10 Ensure a managed device is required to register security information (Automated)
- 5.2.2.11 Ensure sign-in frequency for Intune Enrollment is set to 'Every time' (Automated)
- 5.2.2.12 Ensure the device code sign-in flow is blocked (Automated)
- 5.2.2.13 Ensure that periodic reauthentication is required for all users (Automated)
- 5.2.2.15 Ensure exclusionary geographic access controls are utilized (Automated)
- 5.2.2.16 Ensure Token Protection is enforced for session tokens (Automated)
- 5.2.2.17 Ensure authentication transfer is blocked (Automated)
- 5.2.3.3 Ensure password protection is enabled for on-prem Active Directory (Automated)
- 5.2.3.5 Ensure weak authentication methods are disabled (Automated)
- 5.2.3.6 Ensure system-preferred multifactor authentication is enabled (Automated)
- 5.2.3.7 Ensure the email OTP authentication method is disabled (Automated)
- 5.2.3.10 Ensure Microsoft Authenticator on companion applications is disabled (Automated)
- 5.2.4.3 Ensure SSPR registration and authentication re-confirmation are required (Manual)
- 5.2.4.4 Ensure that users are notified on password resets (Manual)
- 5.2.4.5 Ensure all admins are notified when other admins reset their password (Manual)
- 5.3.1 Ensure privileged role assignments are activated and not assigned (Automated)
- 5.3.2 Ensure 'Access reviews' for guest users are configured (Automated)
- 5.3.3 Ensure 'Access reviews' for privileged roles are configured (Automated)
- 5.3.5 Ensure approval is required for Privileged Role Administrator activation (Automated)

**6. Exchange admin center** (8)

- 6.1.2 Ensure mailbox audit actions are configured (Automated)
- 6.2.2 Ensure mail transport rules do not whitelist specific domains (Automated)
- 6.2.3 Ensure email from external senders is identified (Automated)
- 6.3.1 Ensure users installing Outlook add-ins is not allowed (Automated)
- 6.3.2 Ensure the ability to add personal email accounts and calendars is disabled (Automated)
- 6.5.2 Ensure MailTips are enabled for end users (Automated)
- 6.5.3 Ensure additional storage providers are restricted in Outlook on the web (Automated)
- 6.5.5 Ensure Direct Send submissions are rejected (Automated)

**7. SharePoint admin center** (8)

- 7.2.2 Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled (Automated)
- 7.2.4 Ensure OneDrive content sharing is restricted (Automated)
- 7.2.5 Ensure that SharePoint guest users cannot share items they don't own (Automated)
- 7.2.6 Ensure SharePoint external sharing is restricted (Automated)
- 7.2.7 Ensure link sharing is restricted in SharePoint and OneDrive (Automated)
- 7.2.8 Ensure external sharing is restricted by security group (Automated)
- 7.2.11 Ensure the SharePoint default sharing link permission is set (Automated)
- 7.3.1 Ensure Office 365 SharePoint infected files are disallowed for download (Automated)

**8. Microsoft Teams admin center** (6)

- 8.2.3 Ensure external Teams users cannot initiate conversations (Automated)
- 8.2.4 Ensure the organization cannot communicate with accounts in trial Teams tenants (Automated)
- 8.5.6 Ensure only organizers and co-organizers can present (Automated)
- 8.5.8 Ensure external meeting chat is off (Automated)
- 8.5.9 Ensure meeting recording is off by default (Automated)
- 8.6.1 Ensure users can report security concerns in Teams (Automated)

**9. Microsoft Fabric** (12)

- 9.1.1 Ensure guest user access is restricted (Automated)
- 9.1.2 Ensure external user invitations are restricted (Automated)
- 9.1.3 Ensure guest access to content is restricted (Automated)
- 9.1.4 Ensure 'Publish to web' is restricted (Automated)
- 9.1.5 Ensure 'Interact with and share R and Python' visuals is 'Disabled' (Automated)
- 9.1.6 Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled' (Automated)
- 9.1.7 Ensure shareable links are restricted (Automated)
- 9.1.8 Ensure enabling of external data sharing is restricted (Automated)
- 9.1.9 Ensure 'Block ResourceKey Authentication' is 'Enabled' (Automated)
- 9.1.10 Ensure access to APIs by service principals is restricted (Automated)
- 9.1.11 Ensure service principals cannot create and use profiles (Automated)
- 9.1.12 Ensure service principals ability to create workspaces, connections and deployment pipelines is restricted (Automated)

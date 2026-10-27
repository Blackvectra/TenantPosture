# Microsoft Teams Baseline

**TenantPosture — Baseline Documentation**
*Product: Microsoft Teams*

---

## Introduction

This baseline lists the 28 Microsoft Teams controls evaluated by TenantPosture. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 5 High · 15 Medium · 8 Low

---

## Controls

### TMS-1.1 — External Federation Access Restricted

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Teams federation is not open to all domains.

**Business risk:**
Open federation allows any Teams user on any tenant to contact your users directly, enabling large-scale social engineering.

**Remediation:**
Set-CsTenantFederationConfiguration -AllowFederatedUsers $false, or restrict to an allowlist of trusted domains.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-17, SC-7 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.2.1 |
| CIS Controls v8.1 | 4.8, 6.7 |
| CISA SCuBA | MS.TEAMS.2.1v2 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.23, A.8.22 |
| SOC 2 | CC6.6 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 1.4 |
| MITRE ATT&CK | T1566, T1534 |

---

### TMS-1.2 — Teams Consumer Account Access Disabled

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Personal Microsoft accounts (Teams consumer) cannot contact or join meetings in the tenant.

**Business risk:**
Consumer accounts are unverifiable. Allowing them enables social engineering from identities that cannot be audited or revoked.

**Remediation:**
Set-CsTenantFederationConfiguration -AllowTeamsConsumer $false -AllowTeamsConsumerInbound $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-17 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.2.2 |
| CIS Controls v8.1 | 4.8 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.23 |
| SOC 2 | CC6.2, CC6.6 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1566, T1534 |

---

### TMS-1.3 — Anonymous Meeting Join Disabled

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Anonymous users cannot join Teams meetings without admission by an authenticated participant.

**Business risk:**
Anonymous join allows unauthenticated individuals to eavesdrop on internal meetings via leaked meeting links.

**Remediation:**
Set-CsTeamsMeetingPolicy -AllowAnonymousUsersToJoinMeeting $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, AC-17 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.5.1 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.16 |
| SOC 2 | CC6.1, CC6.2 |
| HIPAA | §164.312(a)(2)(i) |
| PCI DSS | Req 8.2.1 |
| MITRE ATT&CK | T1078 |

---

### TMS-1.4 — External Participants Cannot Take Screen Control

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Meeting policy prevents external participants from taking or requesting screen share control.

**Business risk:**
Screen control transfer to external participants can expose sensitive on-screen data.

**Remediation:**
Set-CsTeamsMeetingPolicy -AllowExternalParticipantGiveRequestControl $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.5.7 |
| CIS Controls v8.1 | 4.1 |
| CISA SCuBA | MS.TEAMS.1.1v1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18, A.8.3 |
| SOC 2 | CC6.1, C1.1 |
| HIPAA | §164.312(a)(1), §164.502 |
| PCI DSS | Req 7.2.5 |
| MITRE ATT&CK | T1078 |

---

### TMS-1.5 — Recording Storage in Organization

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
Meeting recordings are stored in SharePoint/OneDrive with organization retention policies applied.

**Business risk:**
Without defined storage and retention, recordings containing sensitive discussions may be retained indefinitely.

**Remediation:**
Ensure Purview retention policies cover SharePoint to capture Teams recording data.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-9, AU-11 |
| CIS Controls v8.1 | 3.4 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.5.23, A.8.10 |
| SOC 2 | CC6.7, C1.1 |
| HIPAA | Not cited: no Security Rule specification matches what this control checks (docs/HIPAA-CITATION-CORRECTIONS.md) |
| PCI DSS | Req 3.5.1 |
| MITRE ATT&CK | T1213 |

---

### TMS-1.6 — Teams Guest Access Controlled

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Teams guest access is disabled or limited to verified external collaborators with controlled invitation permissions.

**Business risk:**
Unrestricted guest access allows any user to invite external parties to internal Teams and files without IT oversight.

**Remediation:**
Set-CsTeamsClientConfiguration -AllowGuestUser $false, or configure guest invitation permissions in Entra External Identities.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2, AC-3 |
| CIS Controls v8.1 | 4.8 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | CC6.2 |
| HIPAA | §164.308(a)(4) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1078 |

---

### TMS-2.1 — Skype Consumer Contact Disabled

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Contact from Skype consumer users is disabled in Teams federation settings.

**Business risk:**
Skype consumer accounts are unverifiable and cannot be audited. They enable social engineering from identities outside any corporate identity provider.

**Remediation:**
Set-CsTenantFederationConfiguration -AllowPublicUsers $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-17 |
| CIS Controls v8.1 | 4.8 |
| CMMC 2.0 | AC.L2-3.1.12 |
| ISO/IEC 27001:2022 | A.5.23 |
| SOC 2 | CC6.6 |
| HIPAA | §164.308(a)(4)(ii)(B), §164.312(e)(1) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1566, T1534 |

---

### TMS-2.2 — Unverified App Publisher Blocked

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Teams app permission policy restricts installation to Microsoft and verified third-party publishers only.

**Business risk:**
Apps from unverified publishers have not been vetted. Malicious Teams apps can access meeting transcripts, chat, and files.

**Remediation:**
Teams admin center > Teams apps > Manage apps > Org-wide app settings: turn off letting users install third-party apps by default and block new third-party apps until reviewed; then set each approved app's availability (Available to) per app. App permission policies no longer apply after the migration to app centric management.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-7 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.4.1 |
| CIS Controls v8.1 | 2.5 |
| CISA SCuBA | MS.TEAMS.5.2v2 |
| CMMC 2.0 | CM.L2-3.4.6 |
| ISO/IEC 27001:2022 | A.5.23, A.8.19 |
| SOC 2 | CC6.8, CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B), §164.308(a)(5)(ii)(B) |
| PCI DSS | Req 6.4.3 |
| MITRE ATT&CK | T1195 |

---

### TMS-2.3 — Third-Party Cloud Storage Disabled in Teams

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Dropbox, Box, Google Drive, and ShareFile integrations are disabled in Teams client configuration.

**Business risk:**
Third-party storage allows data to move from Teams to unmanaged cloud services outside DLP and retention policy coverage.

**Remediation:**
Set-CsTeamsClientConfiguration -AllowDropbox $false -AllowBox $false -AllowGoogleDrive $false -AllowShareFile $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.1.1 |
| CIS Controls v8.1 | 4.8 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.5.23 |
| SOC 2 | CC6.7 |
| HIPAA | §164.308(a)(4)(ii)(B), §164.312(e)(1) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1048, T1567 |

---

### TMS-2.4 — Teams Email Integration Disabled

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Email into Teams channels is disabled — channel email addresses cannot receive inbound email.

**Business risk:**
Channel email addresses bypass email security controls. Phishing payloads can be injected directly into Teams without going through EOP.

**Remediation:**
Set-CsTeamsClientConfiguration -AllowEmailIntoChannels $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SI-8 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.1.2 |
| CIS Controls v8.1 | 4.8 |
| CISA SCuBA | MS.TEAMS.4.1v1 |
| CMMC 2.0 | SI.L2-3.14.7 |
| ISO/IEC 27001:2022 | A.5.23 |
| SOC 2 | CC6.7 |
| HIPAA | §164.308(a)(4)(ii)(B), §164.312(e)(1) |
| PCI DSS | Req 4.2 |
| MITRE ATT&CK | T1566 |

---

### TMS-2.5 — Cloud Recording Disabled for External Participants

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
External participants cannot initiate or control meeting cloud recordings.

**Business risk:**
External participants recording meetings capture confidential discussions with no internal awareness or consent controls.

**Remediation:**
Set-CsTeamsMeetingPolicy -AllowCloudRecordingForCalls $false for externally-scoped policies

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-9 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | AU.L2-3.3.8 |
| ISO/IEC 27001:2022 | A.8.10, A.8.12 |
| SOC 2 | C1.1 |
| HIPAA | §164.502, §164.312(e)(1) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1113 |

---

### TMS-2.6 — Broad Channel Meeting Invite Restricted

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Channel meeting scheduling that invites all channel members is restricted or requires deliberate selection.

**Business risk:**
Channel meetings can inadvertently include all members — including external guests — in sensitive meeting invites.

**Remediation:**
Review AllowChannelMeetingScheduling in meeting policy — restrict if channels have broad guest membership.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | AC.L1-3.1.1 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | CC6.2 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1078 |

---

### TMS-2.7 — External User Chat Restricted

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
External users cannot initiate unsolicited chats with internal users via Teams federation.

**Business risk:**
Unrestricted external chat enables social engineering directly in Teams, bypassing email phishing controls entirely.

**Remediation:**
Set-CsTenantFederationConfiguration -AllowFederatedUsers $false or restrict to allowlist.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-17 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.2.1 |
| CIS Controls v8.1 | 4.8 |
| CISA SCuBA | MS.TEAMS.2.3v2 |
| CMMC 2.0 | AC.L2-3.1.12 |
| ISO/IEC 27001:2022 | A.5.23 |
| SOC 2 | CC6.7 |
| HIPAA | §164.308(a)(4)(ii)(B), §164.312(e)(1) |
| PCI DSS | Req 4.2 |
| MITRE ATT&CK | T1566, T1534 |

---

### TMS-2.8 — PSTN Users Cannot Bypass Lobby

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
PSTN dial-in users are not permitted to bypass the Teams meeting lobby.

**Business risk:**
PSTN users have no identity verification. Auto-admit to meetings allows uninvited callers to join sensitive discussions.

**Remediation:**
Set-CsTeamsMeetingPolicy -AllowPSTNUsersToBypassLobby $false

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, IA-3 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.5.4 |
| CIS Controls v8.1 | 4.1 |
| CISA SCuBA | MS.TEAMS.1.5v1 |
| CMMC 2.0 | AC.L1-3.1.1 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(1) |
| PCI DSS | Req 7.2 |
| MITRE ATT&CK | T1078 |

---

### TMS-3.1 — Teams Meeting Watermarks Enabled

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Teams Premium (add-on)

**Description:**
Content watermarking is enabled for Teams meetings to deter and trace content leaks.

**Business risk:**
Meeting content shared without watermarks cannot be traced if leaked. Watermarks deter deliberate leaks and enable forensic attribution.

**Remediation:**
Set-CsTeamsMeetingPolicy -AllowWatermarkForScreenSharing $true

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | AC.L2-3.1.3 |
| ISO/IEC 27001:2022 | A.8.11 |
| SOC 2 | C1.1 |
| HIPAA | §164.502(b), §164.312(c)(1) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1113 |

---

### TMS-3.2 — Auto-Admit Only Authenticated Organization Users

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Teams meetings auto-admit only authenticated internal users — all others wait in lobby.

**Business risk:**
Auto-admitting Everyone or All Federated allows uninvited external participants to join internal meetings without any approval.

**Remediation:**
Set-CsTeamsMeetingPolicy -AutoAdmittedUsers EveryoneInCompanyExcludingGuests

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, IA-3 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.5.3 |
| CIS Controls v8.1 | 4.1 |
| CISA SCuBA | MS.TEAMS.1.3v1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.17, A.5.18 |
| SOC 2 | CC6.1, CC6.2 |
| HIPAA | §164.312(d), §164.308(a)(4) |
| PCI DSS | Req 8.3 |
| MITRE ATT&CK | T1078 |

---

### TMS-3.3 — Meeting Chat Disabled for Anonymous Participants

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Anonymous meeting participants cannot use meeting chat (EnabledExceptAnonymous or Disabled).

**Business risk:**
Anonymous participants with chat access can send phishing links and malicious content to all authenticated meeting participants.

**Remediation:**
Set-CsTeamsMeetingPolicy -AllowMeetingChat EnabledExceptAnonymous

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.5.5 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | C1.1 |
| HIPAA | §164.502, §164.312(a)(1) |
| PCI DSS | Req 7.2 |
| MITRE ATT&CK | T1566 |

---

### TMS-3.4 — Meeting Chat Copy Prevention via DLP

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
DLP policies prevent copying sensitive meeting chat content to unauthorized locations.

**Business risk:**
Meeting chat containing sensitive discussions can be copied to personal notes, email, or external storage without DLP controls.

**Remediation:**
Purview > DLP > Create policy targeting Teams with sensitive info types to restrict copy/paste of protected content.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4, SC-28 |
| CIS Controls v8.1 | 3.13 |
| CMMC 2.0 | AC.L2-3.1.3 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7, C1.1 |
| HIPAA | §164.312(e)(1), §164.502(b) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1048 |

---

### TMS-4.1 — Meeting Recording Expiration Configured

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Meeting recordings in Teams are configured to expire after 60-90 days rather than persisting indefinitely.

**Business risk:**
Meeting recordings capture sensitive discussions, strategic planning, and personnel matters. Recordings that never expire accumulate indefinitely and expand the blast radius of any SharePoint/OneDrive compromise.

**Remediation:**
Set-CsTeamsMeetingPolicy -Identity Global -NewMeetingRecordingExpirationDays 60.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-11 |
| CIS Controls v8.1 | 3.4 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.5.33, A.8.10 |
| SOC 2 | A1.2, C1.1 |
| HIPAA | §164.502 |
| PCI DSS | Req 3.2.1 |
| MITRE ATT&CK | T1113 |

---

### TMS-4.2 — Anonymous Users Cannot Start Meetings

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Anonymous (unauthenticated) users cannot independently start Teams meetings.

**Business risk:**
If anonymous users can start meetings, attackers can open a meeting in an organization's tenant without any authenticated identity — creating an untracked communication channel.

**Remediation:**
Set-CsTeamsMeetingPolicy -AllowAnonymousUsersToStartMeeting $false.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, IA-3 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.5.2 |
| CIS Controls v8.1 | 4.1 |
| CISA SCuBA | MS.TEAMS.1.2v2 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.16 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(2)(i), §164.312(d) |
| PCI DSS | Req 8.2.1 |
| MITRE ATT&CK | T1078 |

---

### TMS-4.3 — Teams External Domain Federation Restricted to Allowlist

**Severity:** High  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Teams federation with external domains is restricted to a defined allowlist rather than open to all domains.

**Business risk:**
Open federation allows any Teams user at any organization worldwide to contact your users via Teams chat and calls. Social engineering and BEC campaigns can be delivered through Teams without going through email filtering.

**Remediation:**
Teams Admin Center > External access > Allow only specific external domains. Add business partner domains only.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-17 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.2.1 |
| CIS Controls v8.1 | 4.8, 6.7 |
| CISA SCuBA | MS.TEAMS.2.1v2 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.23, A.8.22 |
| SOC 2 | CC6.6 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 1.4 |
| MITRE ATT&CK | T1566, T1534 |

---

### TMS-4.4 — Teams Events Cannot Be Attended by Anonymous Internet Users

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Teams town halls and webinars (which replaced live events, retired by Microsoft on June 30, 2026) are restricted to the organization and its guests, not open to anonymous internet attendees.

**Business risk:**
Live events with anonymous broadcast enabled allow any internet user to view internal organizational meetings, presentations, and discussions without authentication.

**Remediation:**
Set-CsTeamsEventsPolicy -Identity Global -EventAccessType EveryoneInCompanyExcludingGuests -TownhallEventAttendeeAccess EveryoneInOrganizationAndGuests (or -AllowWebinars Disabled / -AllowTownhalls Disabled). Grant a separate policy to the few organizers who genuinely run public events.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | AC.L1-3.1.1 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | C1.1 |
| HIPAA | §164.502, §164.308(a)(4) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1078 |

---

### TMS-5.1 — External Unmanaged Teams Users Cannot Initiate Conversations

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Unmanaged (personal or free) Teams accounts cannot search for users in the organization or start a chat or meeting with them: AllowTeamsConsumerInbound is False, communication with unmanaged accounts is off entirely, or the Global external access policy sets EnableTeamsConsumerInbound to False.

**Business risk:**
Unmanaged Teams accounts take minutes to create and carry no accountability. Letting them start conversations hands phishing, malware delivery (DarkGate) and social engineering (Midnight Blizzard) a direct channel to staff outside email filtering.

**Remediation:**
Set-CsTenantFederationConfiguration -AllowTeamsConsumerInbound $false (or Set-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerInbound $false). Teams admin center > Users > External access: clear "External users with Teams accounts not managed by an organization can contact users in my organization".

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-20, SC-7 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.2.3 |
| CIS Controls v8.1 | 4.8 |
| CMMC 2.0 | AC.L1-3.1.20 |
| ISO/IEC 27001:2022 | A.5.14, A.8.22 |
| SOC 2 | CC6.6 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 1.4 |
| MITRE ATT&CK | T1566, T1534 |

---

### TMS-5.2 — Communication With Trial-Only Teams Tenants Blocked

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
ExternalAccessWithTrialTenants is Blocked, so users in Teams tenants that hold only trial licenses cannot chat, call or meet with users in the organization (Microsoft's default).

**Business risk:**
Trial tenants are free, short-lived and used for spam and phishing over Teams. Allowing them lets attackers reach staff from tenants with no purchased license and no accountability.

**Remediation:**
Set-CsTenantFederationConfiguration -ExternalAccessWithTrialTenants Blocked (MicrosoftTeams module 6.4.0 or later). Add a needed trial domain to AllowedTrialTenantDomains instead of allowing every trial tenant.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-20, SC-7 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.2.4 |
| CIS Controls v8.1 | 4.8 |
| CMMC 2.0 | AC.L1-3.1.20 |
| ISO/IEC 27001:2022 | A.5.14, A.8.22 |
| SOC 2 | CC6.6 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 1.4 |
| MITRE ATT&CK | T1566, T1534 |

---

### TMS-5.3 — Only Organizers and Co-organizers Can Present

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
The Global meeting policy sets the default "Who can present" to only organizers and co-organizers (DesignatedPresenterRoleMode = OrganizerOnlyUserOverride); everyone else joins as an attendee unless the organizer changes it.

**Business risk:**
When everyone joins as a presenter, any participant, including an external or anonymous one, can take over the screen and share malicious content, links or confidential material with the whole meeting.

**Remediation:**
Set-CsTeamsMeetingPolicy -Identity Global -DesignatedPresenterRoleMode OrganizerOnlyUserOverride. Teams admin center > Meetings > Meeting policies > Global > Who can present: Only organizers and co-organizers.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, AC-6 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.5.6 |
| CIS Controls v8.1 | 6.8 |
| CMMC 2.0 | AC.L2-3.1.5 |
| ISO/IEC 27001:2022 | A.5.15, A.8.2 |
| SOC 2 | CC6.3 |
| HIPAA | §164.312(a)(1) |
| PCI DSS | Req 7.2 |
| MITRE ATT&CK | T1534 |

---

### TMS-5.4 — External Meeting Chat Disabled

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Users cannot read or send chat in meetings hosted by organizations the tenant has no trusted relationship with (Global meeting policy AllowExternalNonTrustedMeetingChat = False).

**Business risk:**
Chat in an untrusted organization's meeting carries links and files from unknown senders to staff outside email filtering, a route for phishing and malware.

**Remediation:**
Set-CsTeamsMeetingPolicy -Identity Global -AllowExternalNonTrustedMeetingChat $false. Teams admin center > Meetings > Meeting policies > Global > External meeting chat: Off.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-20, SC-7 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.5.8 |
| CIS Controls v8.1 | 4.8 |
| CMMC 2.0 | AC.L1-3.1.20 |
| ISO/IEC 27001:2022 | A.5.14, A.8.22 |
| SOC 2 | CC6.6 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 1.4 |
| MITRE ATT&CK | T1566, T1534 |

---

### TMS-5.5 — Meeting Recording Off by Default

**Severity:** Low  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Meeting recording is off in the Global meeting policy (AllowCloudRecording = False); users who need to record are assigned a separate meeting policy that allows it.

**Business risk:**
Recordings capture confidential discussion, shared screens and personal information into stored files. Allowing every user to record by default spreads that content beyond the people who need it.

**Remediation:**
Set-CsTeamsMeetingPolicy -Identity Global -AllowCloudRecording $false, and grant a separate policy that allows recording to the users who need it.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3, AC-6 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.5.9 |
| CIS Controls v8.1 | 3.3 |
| CMMC 2.0 | AC.L2-3.1.5 |
| ISO/IEC 27001:2022 | A.5.15, A.8.2 |
| SOC 2 | CC6.3 |
| HIPAA | §164.312(a)(1) |
| PCI DSS | Req 7.2 |
| MITRE ATT&CK | T1123 |

---

### TMS-5.6 — Users Can Report Security Concerns in Teams

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Users can report a suspicious Teams message (Global messaging policy AllowSecurityEndUserReporting = True), and the user reported settings keep reports in the organization: Teams reports go to the reporting mailbox only (ReportChatMessageEnabled = False, ReportChatMessageToCustomizedAddressEnabled = True) and junk, not-junk and phishing reports go to a named reporting mailbox.

**Business risk:**
Without a reporting path, a malicious Teams message a user recognizes never reaches the security team, and reports sent only to Microsoft are not visible to the people who must respond.

**Remediation:**
Set-CsTeamsMessagingPolicy -Identity Global -AllowSecurityEndUserReporting $true; Set-ReportSubmissionPolicy -Identity DefaultReportSubmissionPolicy -ReportChatMessageEnabled $false -ReportChatMessageToCustomizedAddressEnabled $true -ReportJunkToCustomizedAddress $true -ReportNotJunkToCustomizedAddress $true -ReportPhishToCustomizedAddress $true -ReportJunkAddresses <mailbox> -ReportNotJunkAddresses <mailbox> -ReportPhishAddresses <mailbox> (and the report submission rule for the same mailbox).

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IR-6, SI-4 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 8.6.1 |
| CIS Controls v8.1 | 17.3 |
| CMMC 2.0 | IR.L2-3.6.2 |
| ISO/IEC 27001:2022 | A.6.8 |
| SOC 2 | CC7.3 |
| HIPAA | §164.308(a)(6)(ii) |
| PCI DSS | Req 12.10.1 |
| MITRE ATT&CK | T1566, T1534 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

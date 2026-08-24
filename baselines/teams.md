# Microsoft Teams Baseline

**NRG-Assessment — Baseline Documentation**
*Product: Microsoft Teams*

---

## Introduction

This baseline lists the 22 Microsoft Teams controls evaluated by NRG-Assessment. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 5 High · 11 Medium · 6 Low

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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.2.1 |
| CIS Controls v8.1 | 4.8, 6.7 |
| CISA SCuBA | MS.TEAMS.2.1v2 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.23, A.8.22 |
| SOC 2 | CC6.6 |
| HIPAA | §164.308(a)(4)(ii)(A), §164.312(e)(1) |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.2.2 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.1 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.3 |
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

**License required:** Included (M365 Business Standard+)

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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.6.1 |
| CIS Controls v8.1 | 3.4 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.5.23, A.8.10 |
| SOC 2 | CC6.7, C1.1 |
| HIPAA | §164.308(a)(4)(ii)(A), §164.310(d)(2)(ii) |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.2.3 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.2.4 |
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
Teams Admin Center > Teams apps > Permission policies > Block all apps from unknown publishers.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-7 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.3.1 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.3.2 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.3.3 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.4 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.5 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.2.5 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.6 |
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

**License required:** Included (M365 Business Standard+)

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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.7 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.2 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.8 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.3.4 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.9 |
| CIS Controls v8.1 | 3.4 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.5.33, A.8.10 |
| SOC 2 | A1.2, C1.1 |
| HIPAA | §164.316(b)(2)(i), §164.502 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.3 |
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
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.2.6 |
| CIS Controls v8.1 | 4.8, 6.7 |
| CISA SCuBA | MS.TEAMS.2.1v2 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.23, A.8.22 |
| SOC 2 | CC6.6 |
| HIPAA | §164.308(a)(4)(ii)(A) |
| PCI DSS | Req 1.4 |
| MITRE ATT&CK | T1566, T1534 |

---

### TMS-4.4 — Live Events Cannot Broadcast to Anonymous Internet Users

**Severity:** Medium  |  **Category:** Collaboration  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Teams Live Events are not configured to allow public anonymous streaming to unauthenticated internet users.

**Business risk:**
Live events with anonymous broadcast enabled allow any internet user to view internal organizational meetings, presentations, and discussions without authentication.

**Remediation:**
Set-CsTeamsMeetingBroadcastPolicy -Identity Global -BroadcastAttendeeVisibilityMode EveryoneInCompany (or -AllowBroadcastScheduling $false to disable live events entirely).

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CIS Microsoft 365 Foundations Benchmark v6.0.1 | 8.5.10 |
| CIS Controls v8.1 | 4.1 |
| CMMC 2.0 | AC.L1-3.1.1 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | C1.1 |
| HIPAA | §164.502, §164.308(a)(4) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1078 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

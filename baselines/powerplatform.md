# Microsoft Power Platform Baseline

**TenantPosture — Baseline Documentation**
*Product: Microsoft Power Platform*

---

## Introduction

This baseline lists the 21 Microsoft Power Platform controls evaluated by TenantPosture. Each control produces a finding of **Satisfied**, **Partial**, **Gap**, **Not Applicable** or **Error**.

This file is generated from `Config/controls.json`, which is the single source of truth for control IDs, titles, severities, remediation and framework citations. Do not edit it by hand — change the control definition and regenerate, or the two will disagree. `Testing/*.BaselineDocs.Tests.ps1` fails the build if they do.

**Severity breakdown:** 9 High · 11 Medium · 1 Low

---

## Controls

### PPL-1.1 — Power Platform Tenant Isolation Enabled

**Severity:** Medium  |  **Category:** Data  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Power Platform tenant isolation restricts cross-tenant connector connections.

**Business risk:**
Without isolation, Power Automate flows can connect to external tenant resources, enabling data exfiltration via legitimate connectors.

**Remediation:**
Power Platform Admin Center > Policies > Tenant Isolation: enable and configure inbound/outbound restrictions.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4, SC-7 |
| CIS Controls v8.1 | 4.1 |
| CISA SCuBA | MS.POWERPLATFORM.3.1v1 |
| CMMC 2.0 | SC.L1-3.13.1 |
| ISO/IEC 27001:2022 | A.5.23, A.8.22 |
| SOC 2 | CC6.6 |
| HIPAA | §164.312(a)(1) |
| PCI DSS | Req 1.4 |
| MITRE ATT&CK | T1048, T1567 |

---

### PPL-1.2 — Power Platform DLP Policy Active

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
A DLP policy for Power Platform classifies connectors as Business, Non-Business, or Blocked.

**Business risk:**
Without DLP, flows can move data between any connectors including personal cloud storage and social media.

**Remediation:**
Power Platform Admin Center > Policies > Data policies: create environment policy. Move business connectors to Business group, block consumer connectors.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4, SC-7 |
| CIS Controls v8.1 | 3.13 |
| CISA SCuBA | MS.POWERPLATFORM.2.1v1 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1048 |

---

### PPL-1.3 — Power Platform Environment Creation Restricted

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Non-admin users cannot create new Power Platform environments.

**Business risk:**
Unrestricted environment creation allows data exfiltration through ungoverned flows outside DLP policy scope.

**Remediation:**
Power Platform Admin Center > Settings: restrict environment creation to admins only.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-5, AC-6 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.POWERPLATFORM.1.1v1 |
| CMMC 2.0 | CM.L2-3.4.5 |
| ISO/IEC 27001:2022 | A.5.23, A.8.32 |
| SOC 2 | CC6.3, CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 7.2.4 |
| MITRE ATT&CK | T1578 |

---

### PPL-2.1 — Power Platform Connector Classification Reviewed

**Severity:** Medium  |  **Category:** Data  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Connectors in Power Platform DLP policies are classified as Business, Non-Business, or Blocked.

**Business risk:**
Unclassified connectors default to Non-Business — flows can still mix data between business connectors and unclassified ones.

**Remediation:**
Power Platform Admin Center > Data policies > Edit existing policy > Review all connectors and assign to Business or Blocked groups.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4 |
| CIS Controls v8.1 | 3.13 |
| CISA SCuBA | MS.POWERPLATFORM.2.1v1 |
| CMMC 2.0 | MP.L2-3.8.1 |
| ISO/IEC 27001:2022 | A.5.23, A.8.30 |
| SOC 2 | CC6.6 |
| HIPAA | §164.308(a)(1)(ii)(D) |
| PCI DSS | Req 6.4.3 |
| MITRE ATT&CK | T1048 |

---

### PPL-2.2 — Power Automate Governance Policy Active

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Guest users are restricted from creating Power Automate flows.

**Business risk:**
Guest users creating flows can automate data movement between organizational data sources and external destinations without IT oversight.

**Remediation:**
Power Platform Admin Center > Tenant settings > Power Automate > Disable for guests.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-5, AC-3 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.POWERPLATFORM.1.1v1 |
| CMMC 2.0 | AC.L1-3.1.2 |
| ISO/IEC 27001:2022 | A.5.23, A.8.32 |
| SOC 2 | CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 6.5.3 |
| MITRE ATT&CK | T1048, T1567 |

---

### PPL-2.3 — Power Apps Portal Creation Restricted

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (M365 Business Standard+)

**Description:**
Non-admin users are restricted from creating public-facing Power Apps portals.

**Business risk:**
Power Apps portals are internet-accessible by default. Non-admin portal creation can inadvertently expose organizational data to the internet.

**Remediation:**
Power Platform Admin Center > Settings > Power Apps > Disable portal creation by non-admins.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-5, AC-6 |
| CIS Controls v8.1 | 6.8 |
| CISA SCuBA | MS.POWERPLATFORM.5.1v1 |
| CMMC 2.0 | CM.L2-3.4.5 |
| ISO/IEC 27001:2022 | A.5.23, A.8.32 |
| SOC 2 | CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 6.5.3 |
| MITRE ATT&CK | T1578, T1190 |

---

### PPL-3.1 — M365 Copilot Sensitivity Label Enforcement

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+ (Copilot requires M365 Copilot add-on)

**Description:**
Sensitivity labels are published with Files & emails scope and an auto-labeling policy is active, enabling Microsoft 365 Copilot to respect data classification boundaries when grounding on tenant content.

**Business risk:**
Without sensitivity labels, Copilot can access and surface any data the user can reach — including HR files, financial records, and confidential strategies — with no awareness of sensitivity. Copilot dramatically amplifies over-sharing risk.

**Remediation:**
Purview > Information protection > Labels > Create/verify labels with Files & emails scope. Enable Copilot integration in label settings. Reference: Microsoft Copilot security baseline.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-16, SC-28 |
| CIS Controls v8.1 | 3.7 |
| CMMC 2.0 | MP.L2-3.8.4 |
| ISO/IEC 27001:2022 | A.8.11, A.8.12 |
| SOC 2 | C1.1, CC6.1 |
| HIPAA | §164.502(b), §164.312(a)(1) |
| PCI DSS | Req 3.4, Req 7.2 |
| MITRE ATT&CK | T1005 |

---

### PPL-3.2 — DLP Policy Active for Copilot Interactions

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** M365 E5 Compliance add-on

**Description:**
At least one enabled Data Loss Prevention policy includes the Microsoft 365 Copilot location, blocking sensitive-information types in Copilot prompts and responses.

**Business risk:**
Without DLP covering Copilot, users can extract sensitive data by prompting Copilot to summarize, translate, or reformat confidential content — bypassing all other data controls.

**Remediation:**
Purview > DLP > Create policy > Locations: Include Microsoft 365 Copilot. Add sensitive info types as conditions. Requires M365 E5 Compliance or equivalent.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-28, AC-4 |
| CIS Controls v8.1 | 3.13 |
| CMMC 2.0 | SC.L2-3.13.16 |
| ISO/IEC 27001:2022 | A.8.12 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 3.4 |
| MITRE ATT&CK | T1005, T1048 |

---

### PPL-3.3 — Copilot Access Restricted to Licensed Users

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 Copilot add-on license

**Description:**
Microsoft 365 Copilot license assignment is scoped to a defined subset of users with documented business need — not blanket-assigned tenant-wide.

**Business risk:**
Uncontrolled Copilot access means unlicensed users may gain Copilot capabilities through shared accounts or feature rollouts, bypassing governance controls.

**Remediation:**
M365 Admin Center > Settings > Microsoft 365 Copilot > Control access. Assign licenses only to approved users with a documented business need.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2 |
| CIS Controls v8.1 | 6.8 |
| CMMC 2.0 | AC.L1-3.1.1 |
| ISO/IEC 27001:2022 | A.5.18, A.8.3 |
| SOC 2 | CC6.3 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 7.2.1 |
| MITRE ATT&CK | T1078 |

---

### PPL-3.4 — Copilot Studio Agent Publishing Governed

**Severity:** High  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Power Platform + Copilot Studio license

**Description:**
Copilot Studio (Power Virtual Agents) bots are not externally published to anonymous channels; bot publisher domains are confined to the tenant's onmicrosoft.com domain.

**Business risk:**
Ungoverned Copilot Studio agents can be built to query sensitive SharePoint libraries, connect to external APIs, and respond to any user in the organization — creating unreviewed data exposure channels at scale.

**Remediation:**
Power Platform Admin Center > Copilot Studio > Policies > Require admin approval for agent publishing. Apply DLP policies to Copilot Studio environment connectors.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-7, AC-6 |
| CIS Controls v8.1 | 6.8 |
| CMMC 2.0 | CM.L2-3.4.6 |
| ISO/IEC 27001:2022 | A.8.32 |
| SOC 2 | CC8.1 |
| HIPAA | §164.308(a)(4)(ii)(B) |
| PCI DSS | Req 6.5.3 |
| MITRE ATT&CK | T1078, T1190 |

---

### PPL-3.5 — Copilot Interaction Audit Logging Active

**Severity:** High  |  **Category:** Governance  |  **Automated:** Yes

**License required:** M365 Business Premium or E3+

**Description:**
Unified Audit Log ingestion is enabled and a Purview retention policy explicitly covers Copilot interactions so prompts/responses are searchable beyond platform-default retention.

**Business risk:**
Without Copilot interaction logging, an insider using Copilot to extract sensitive data leaves no audit trail — the interaction is functionally invisible to security and compliance teams.

**Remediation:**
Ensure Unified Audit Log is enabled (Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true). Copilot interactions are searchable in Purview > Content explorer and Audit > Search.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AU-2, AU-12 |
| CIS Microsoft 365 Foundations Benchmark v7.0.0 | 3.1.1 |
| CIS Controls v8.1 | 8.2, 8.10 |
| CMMC 2.0 | AU.L2-3.3.1 |
| ISO/IEC 27001:2022 | A.8.15 |
| SOC 2 | CC7.2 |
| HIPAA | §164.312(b) |
| PCI DSS | Req 10.2 |
| MITRE ATT&CK | T1114, T1562.008 |

---

### PPL-4.1 — Copilot Studio Agents Not Open to Everyone or Any Tenant

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
No Copilot Studio agent's access control (the Dataverse bot accesscontrolpolicy, 'which users may interact with the agent') is Any or Any (multi-tenant); every agent is limited to the users it is shared with (Agent readers) or to named security groups (Group membership). Agents from managed solutions are counted and set aside.

**Business risk:**
An agent open to anyone, or to users of any tenant, answers whoever reaches it with whatever its knowledge sources and tools can reach, including SharePoint content and connector actions, with no per-user decision about who should have that access.

**Remediation:**
Copilot Studio > the agent > Settings > Security > Access control: choose 'Only people I share with' (Agent readers) or a security group, turn multi-tenant support off, and share the agent only with the users or security groups that need it. Publish the agent so the change takes effect.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-3 |
| CMMC 2.0 | AC.L1-3.1.1 |
| ISO/IEC 27001:2022 | A.5.15 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(a)(1) |
| PCI DSS | Req 7.2 |
| MITRE ATT&CK | T1213 |

---

### PPL-4.2 — Copilot Studio Agents Require User Authentication

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Every Copilot Studio agent authenticates its users: authenticationmode is Integrated (Authenticate with Microsoft, where users are always signed in), or manual authentication (Custom Entra ID or Generic OAuth2) with 'Require users to sign in' on (authenticationtrigger Always). No authentication is a Gap.

**Business risk:**
Microsoft documents that an agent with No authentication lets anyone who has the link chat with it, and that an agent with manual authentication and sign-in not required does not ask users to sign in until a topic needs it. Either way the agent's knowledge and tools are reachable without an identity, and its use cannot be attributed.

**Remediation:**
Copilot Studio > the agent > Settings > Security > Authentication: select Authenticate with Microsoft, or Authenticate manually with Microsoft Entra ID and turn on Require users to sign in. Publish the agent. Optionally enforce it tenant-wide with a Power Platform data policy that requires authentication for agents.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-2 |
| CMMC 2.0 | IA.L1-3.5.2 |
| ISO/IEC 27001:2022 | A.8.5 |
| SOC 2 | CC6.1 |
| HIPAA | §164.312(d) |
| PCI DSS | Req 8.3 |
| MITRE ATT&CK | T1213 |

---

### PPL-4.3 — Copilot Studio HTTP Requests Use HTTPS on Port 443

**Severity:** Medium  |  **Category:** Network  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
No active Copilot Studio topic contains an HTTP request node (HttpRequestAction) whose URL uses plain http or an explicit port other than 443. Only the scheme and port are recorded, never the address. A URL assembled entirely from variables cannot be read and leaves the agent not assessed.

**Business risk:**
A plain-HTTP request sends whatever the topic puts in it (user input, conversation data, headers) unencrypted; a request to an unusual port is a common sign of a misconfigured or unvetted endpoint and of a command-and-control or exfiltration channel. HTTP request nodes also sit outside connector data policies unless the HTTP connector is blocked.

**Remediation:**
Change each flagged HTTP request node to an https URL on the standard port, or replace it with a governed Power Platform connector. Where agents should not make raw HTTP calls, block HTTP requests for agents in a Power Platform data policy (Copilot Studio data policies: Block HTTP requests).

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | SC-7, SC-8 |
| CMMC 2.0 | SC.L2-3.13.8 |
| ISO/IEC 27001:2022 | A.8.20, A.8.24 |
| SOC 2 | CC6.7 |
| HIPAA | §164.312(e)(1) |
| PCI DSS | Req 4.2.1 |
| MITRE ATT&CK | T1071.001, T1048, T1571 |

---

### PPL-4.4 — Copilot Studio Email Tools Do Not Let the AI Set Recipients or Content

**Severity:** High  |  **Category:** Data  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
No active Copilot Studio tool that sends, forwards or replies to email (Office 365 Outlook, Outlook.com, Mail, Gmail or SMTP connector) leaves its recipient (To, and Cc or Bcc when used), subject or body to be filled dynamically with AI, which Microsoft documents as the default for any input without a custom value. A Power Fx formula counts as not fixed.

**Business risk:**
An email tool whose recipient and content the agent fills from the conversation can be steered by a prompt (including one hidden in a document or web page the agent reads) into mailing internal data to an outside address, from a corporate mailbox.

**Remediation:**
Remove email-sending tools from agents that do not need them. Where an agent must send email, set the recipient (and where possible the subject and body template) as fixed custom values in the tool's inputs, and block the email connectors for agents that should not send mail with a Power Platform data policy.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-4 |
| CMMC 2.0 | AC.L2-3.1.3 |
| ISO/IEC 27001:2022 | A.5.14 |
| SOC 2 | CC6.7 |
| PCI DSS | Req 7.2 |
| MITRE ATT&CK | T1048 |

---

### PPL-4.5 — Copilot Studio Connector Tools Use End-User Credentials

**Severity:** Medium  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Every active Copilot Studio connector tool uses End user credentials, so it acts with the permissions of the person chatting. A tool whose definition does not record the end-user (Invoker) connection mode is reported as using the maker's stored connection (Maester's reading of the agent definition, not yet confirmed against a live tenant).

**Business risk:**
Microsoft documents that a tool using maker-provided credentials acts with the maker's account for every user, which can overshare data or capabilities: an end user can read or change what only the maker is allowed to, without any separation of duties.

**Remediation:**
Copilot Studio > the agent > Tools > the tool > Additional details > Credentials to use: End user credentials. To enforce it, Power Platform admin center > the environment (or environment group) > Settings > Features > Copilot Studio agents > Control maker credential options: End-user credentials only.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | AC-6 |
| CMMC 2.0 | AC.L2-3.1.5 |
| ISO/IEC 27001:2022 | A.5.18 |
| SOC 2 | CC6.3 |
| PCI DSS | Req 7.2 |
| MITRE ATT&CK | T1550.001, T1213 |

---

### PPL-4.6 — No Hard-Coded Credentials in Copilot Studio Topics

**Severity:** High  |  **Category:** Identity  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
No Copilot Studio topic or tool definition matches a credential pattern (API key assignments, bearer and basic authorization values, connection-string secrets, password or secret assignments, AWS access key ids, private key blocks, JSON web tokens). Heuristic: a match names the pattern type and component id only, and the matched value is never kept.

**Business risk:**
A credential written into a topic can be read by anyone who can edit or export the agent and can sometimes be drawn out through prompt injection; it outlives rotations elsewhere and gives direct access to the system it unlocks.

**Remediation:**
Remove the credential from the named component and rotate it at its source. Authenticate through a connection or connector, the agent's authentication settings, or an environment variable backed by Azure Key Vault.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | IA-5(7) |
| CMMC 2.0 | IA.L2-3.5.10 |
| ISO/IEC 27001:2022 | A.5.17 |
| SOC 2 | CC6.1 |
| PCI DSS | Req 8.6.2 |
| MITRE ATT&CK | T1552 |

---

### PPL-4.7 — Copilot Studio MCP Tool Integrations Reviewed

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Lists every Model Context Protocol (MCP) tool on a Copilot Studio agent with its endpoint host for review. Whether an MCP server was reviewed is not recorded anywhere the tool can read, so MCP tools found are a manual review item (never a pass); Satisfied only when every environment was read and no MCP tool exists.

**Business risk:**
An MCP server supplies the agent with tool descriptions and results it acts on. A compromised or untrusted server can inject instructions, exfiltrate the data the agent passes to it, or trigger actions through the agent: a supply-chain risk outside the tenant's control.

**Remediation:**
Review each listed MCP server: owner, purpose, publisher, data it receives and authentication. Remove integrations that are not approved, and use a Power Platform data policy to block the MCP connectors agents should not use.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-7(1) |
| CMMC 2.0 | CM.L2-3.4.6 |
| ISO/IEC 27001:2022 | A.5.21 |
| SOC 2 | CC9.2 |
| PCI DSS | Req 12.8 |
| MITRE ATT&CK | T1195, T1199 |

---

### PPL-4.8 — Copilot Studio Generative Agents Have Custom Instructions

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Every Copilot Studio agent that uses generative orchestration carries custom instructions. Only whether instructions exist is read, never their text. Generative orchestration and instructions are read from fields Microsoft Learn does not describe (Maester's usage), not yet confirmed against a live tenant.

**Business risk:**
An agent that plans its own steps with no instructions relies entirely on the model's defaults for what it answers, which tools it calls and when; that widens the room for off-topic or harmful answers and for prompt-injected tool use.

**Remediation:**
Copilot Studio > the agent > Overview > Instructions: state the agent's purpose, scope, the tools and knowledge it should use, what it must refuse, and the response format. Publish the agent.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-6 |
| CMMC 2.0 | CM.L2-3.4.2 |
| ISO/IEC 27001:2022 | A.8.9 |
| SOC 2 | CC7.1 |
| PCI DSS | Req 2.2 |
| MITRE ATT&CK | T1213 |

---

### PPL-4.9 — Copilot Studio Agents Have an Active Owner

**Severity:** Medium  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
Every Copilot Studio agent is owned by an enabled member account: the owner's Entra object id (from the Dataverse user that owns the agent) is found enabled in the Entra ID member list. A disabled or missing owner is a Gap; an agent owned by a team or an application user, or a member list not read in full, is not assessed.

**Business risk:**
An agent whose owner has left keeps running with its configuration, sharing and connections, but nobody is accountable for reviewing it, responding to an incident involving it, or retiring it.

**Remediation:**
Assign each flagged agent to an active owner (Power Platform admin center or Copilot Studio > the agent > Share, or reassign the record's owner in Dataverse), or retire the agent if it is no longer needed.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-8(4) |
| CMMC 2.0 | CM.L2-3.4.1 |
| ISO/IEC 27001:2022 | A.5.9 |
| SOC 2 | CC6.2 |
| PCI DSS | Req 12.5.1 |
| MITRE ATT&CK | T1078 |

---

### PPL-4.10 — Published Copilot Studio Agents Not Dormant

**Severity:** Low  |  **Category:** Governance  |  **Automated:** Yes

**License required:** Included (all plans)

**Description:**
No published, active Copilot Studio agent has gone longer than the approved number of days (CopilotStudioDormantDays in Config/tp-standards.json) without its record being modified. Judged on the agent's last-modified date, not on usage. With no approved threshold the control is not assessed and lists each published agent's last-modified date.

**Business risk:**
A published agent nobody has touched in a long time still answers users with the sharing, connections and permissions it was given then, which may no longer match policy, and is easily forgotten in a review.

**Remediation:**
Review each flagged agent with its owner: confirm it is still needed and its configuration still fits current policy (and record the review), or unpublish and retire it.

**Framework mappings:**

| Framework | Reference |
|---|---|
| NIST SP 800-53 Rev 5 | CM-7(1) |
| CMMC 2.0 | CM.L2-3.4.6 |
| ISO/IEC 27001:2022 | A.5.9 |
| SOC 2 | CC6.2 |
| PCI DSS | Req 2.2.4 |
| MITRE ATT&CK | T1213 |

---

*Generated from `Config/controls.json` · NRG Technology Services / NextLayerSec LLC*

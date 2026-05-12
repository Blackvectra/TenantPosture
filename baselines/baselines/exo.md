# Exchange Online Baseline

**NRG Assessment Tool — Baseline Documentation**
*Product: Exchange Online*

---

## Introduction

This baseline defines the security configuration requirements for Exchange Online. Email is the primary attack vector for phishing, BEC, and malware delivery against M365 tenants. Controls in this baseline cover email authentication, mailbox security, transport configuration, and anti-spam posture.

---

## Controls

### EXO-1.1 — SPF Record Configured with Hard Fail

**Criticality:** High

**Description:**
All sending domains must have a valid SPF record that ends in `-all` (hard fail). A `~all` (soft fail) record does not reject unauthorized senders and does not satisfy this control.

**Rationale:**
SPF `-all` instructs receiving mail servers to reject mail from IPs not listed in the SPF record. `~all` only marks — it does not block. Without `-all`, exact-domain spoofing from unlisted IPs passes SPF evaluation.

**Check:**
DNS TXT query for `<domain>` returns a record beginning `v=spf1` that ends in `-all`. `~all` scores `Partial`. No SPF record scores `Gap`.

**Remediation:**
Update SPF record to end in `-all`. Enumerate all legitimate sending sources before making this change — any unlisted source will hard fail after the change.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-8, SC-5 |
| CIS M365 v3 | 2.1.9 |
| SCuBA EXO | MS.EXO.1.1v1 |
| CISA BOD 18-01 | SPF -all requirement |
| MITRE ATT&CK | T1566, T1036.005 |

---

### EXO-1.2 — DKIM Signing Enabled

**Criticality:** High

**Description:**
DKIM signing must be enabled for all accepted domains in Exchange Online. Both DKIM selectors (`selector1` and `selector2`) must have valid CNAME records published in DNS.

**Rationale:**
DKIM provides cryptographic proof that email content has not been modified in transit and that the signing domain authorized the message. Without DKIM, messages can be modified in transit and DMARC alignment is weakened.

**Check:**
`Get-DkimSigningConfig` returns `Enabled = True` for the domain. Both selector CNAME records resolve in DNS.

**Remediation:**
```powershell
# Enable DKIM signing
Set-DkimSigningConfig -Identity 'domain.com' -Enabled $true

# Get CNAME values to publish in DNS
Get-DkimSigningConfig -Identity 'domain.com' |
    Select-Object Domain, Selector1CNAME, Selector2CNAME
```

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-8, SC-8 |
| CIS M365 v3 | 2.1.10 |
| SCuBA EXO | MS.EXO.2.1v1 |
| CISA BOD 18-01 | DKIM requirement |
| MITRE ATT&CK | T1566, T1036 |

---

### EXO-1.3 — DMARC Policy at Enforcement

**Criticality:** High

**Description:**
All sending domains must have a DMARC record with `p=reject` or `p=quarantine`. `p=none` is a monitoring posture only — it does not prevent exact-domain spoofing and does not satisfy this control.

**Rationale:**
`p=none` provides no protection. Only `p=quarantine` or `p=reject` instructs receiving mail servers to act on DMARC failures. `p=reject` is the only posture that prevents exact-domain spoofing at the receiving mail server level.

**Check:**
DNS TXT query for `_dmarc.<domain>` returns a record with `p=reject` (Satisfied) or `p=quarantine` (Partial). `p=none` or no record scores `Gap`.

**Remediation:**
Progress through monitoring phases:
1. `p=none` with `rua=` aggregate reporting — establish baseline
2. `p=quarantine; pct=25` — partial enforcement
3. `p=quarantine; pct=100` — full quarantine
4. `p=reject` — full enforcement

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-8, SC-5 |
| CIS M365 v3 | 2.1.11 |
| SCuBA EXO | MS.EXO.3.1v1 |
| CISA BOD 18-01 | DMARC p=reject for .gov |
| MITRE ATT&CK | T1566.001, T1036.005 |

---

### EXO-1.4 — DMARC Aggregate Reporting Configured

**Criticality:** Medium

**Description:**
DMARC records must include an `rua=` tag pointing to a monitored mailbox or reporting service. Without aggregate reporting, DMARC failures are invisible to the domain owner.

**Rationale:**
DMARC reports are the only visibility mechanism for unauthorized use of your domain. Without `rua=`, you cannot identify legitimate sending sources being missed by SPF/DKIM, and you cannot safely advance to `p=reject`.

**Check:**
DMARC record contains a valid `rua=mailto:` tag. Scored separately from enforcement policy.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AU-2, SI-4 |
| CIS M365 v3 | 2.1.11 |
| SCuBA EXO | MS.EXO.3.2v1 |
| MITRE ATT&CK | T1566 |

---

### EXO-1.5 — MTA-STS Policy Published

**Criticality:** Medium

**Description:**
MTA-STS (Mail Transfer Agent Strict Transport Security) must be published for all sending domains. MTA-STS requires TLS for inbound mail delivery and prevents TLS downgrade attacks.

**Rationale:**
Without MTA-STS, SMTP connections to your mail server can be downgraded to plaintext by an on-path attacker. MTA-STS tells sending mail servers to enforce TLS and validate the certificate against a published policy.

**Check:**
DNS TXT query for `_mta-sts.<domain>` returns a valid record. HTTPS request to `https://mta-sts.<domain>/.well-known/mta-sts.txt` returns a valid policy with `mode: enforce`.

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SC-8, SC-8(1) |
| CIS M365 v3 | 2.1.15 |
| SCuBA EXO | MS.EXO.4.1v1 |
| MITRE ATT&CK | T1040, T1557 |

---

### EXO-2.1 — External Forwarding Disabled

**Criticality:** High

**Description:**
Automatic external email forwarding must be disabled at the tenant level. The outbound spam filter policy must set `AutoForwardingMode = Off` or `AuditAndNotify`. Mailbox-level forwarding rules to external addresses must be blocked.

**Rationale:**
Automatic forwarding to external addresses is the primary BEC data exfiltration method. Attackers who compromise a mailbox immediately set forwarding rules to collect all incoming mail silently. This is one of the highest-impact misconfigurations in M365.

**Check:**
```powershell
Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode
```
`AutoForwardingMode = Off` → Satisfied. `AuditAndNotify` → Partial. `On` → Gap.

**Remediation:**
```powershell
Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off
```

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AC-4, SI-8 |
| CIS M365 v3 | 2.1.4 |
| SCuBA EXO | MS.EXO.5.1v1 |
| CMMC 2.0 | AC.L2-3.1.3 |
| MITRE ATT&CK | T1114.003 |

---

### EXO-2.2 — Mailbox Auditing Enabled

**Criticality:** High

**Description:**
Mailbox auditing must be enabled by default for all users. The `AuditEnabled` default must be `True` at the organization level. E3/E5 licenses include expanded audit log actions; audit bypass associations must not exist.

**Rationale:**
Mailbox audit logs are the primary forensic source for email-based incidents. Without auditing, it is impossible to determine what an attacker read, forwarded, or deleted from a compromised mailbox.

**Check:**
```powershell
Get-OrganizationConfig | Select-Object AuditDisabled
# AuditDisabled = False is the satisfying state
```

**Remediation:**
```powershell
Set-OrganizationConfig -AuditDisabled $false
```

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AU-2, AU-12 |
| CIS M365 v3 | 2.1.3 |
| SCuBA EXO | MS.EXO.6.1v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| MITRE ATT&CK | T1114 |

---

### EXO-2.3 — SMTP Client Authentication Disabled

**Criticality:** High

**Description:**
SMTP client AUTH (legacy authenticated SMTP submission on port 587) must be disabled at the tenant level. Individual mailboxes may require it only for legacy devices or applications — it must not be enabled by default.

**Rationale:**
SMTP AUTH is a legacy protocol that does not support Modern Authentication. It is a common vector for credential stuffing attacks and bypasses Conditional Access policies. Enabling it tenant-wide negates MFA enforcement for email submission.

**Check:**
```powershell
Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled
# True = Satisfied
```

**Remediation:**
```powershell
Set-TransportConfig -SmtpClientAuthenticationDisabled $true
# Re-enable per-mailbox only for confirmed legacy device requirements:
Set-CasMailbox -Identity "printer@domain.com" -SmtpClientAuthenticationDisabled $false
```

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | IA-2, SC-8 |
| CIS M365 v3 | 2.1.1 |
| SCuBA EXO | MS.EXO.7.1v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| MITRE ATT&CK | T1078, T1110 |

---

### EXO-2.4 — Modern Authentication Enabled

**Criticality:** High

**Description:**
Modern Authentication (OAuth 2.0) must be enabled for Exchange Online. This is the prerequisite for Conditional Access enforcement on email clients.

**Rationale:**
Without Modern Auth, Outlook and mobile clients fall back to Basic Authentication regardless of Conditional Access policies. Modern Auth is required for MFA to apply to email client connections.

**Check:**
```powershell
Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled
# True = Satisfied
```

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | IA-2, SC-8 |
| CIS M365 v3 | 2.1.2 |
| SCuBA EXO | MS.EXO.8.1v1 |
| CMMC 2.0 | IA.L2-3.5.3 |
| MITRE ATT&CK | T1078 |

---

### EXO-2.5 — Unified Audit Log Enabled

**Criticality:** High

**Description:**
The Unified Audit Log (UAL) must be enabled for the tenant. The UAL captures Exchange Online, SharePoint, Entra ID, and other M365 activity in a single searchable log.

**Rationale:**
The UAL is the primary forensic source for M365 incident response. Without it, sign-in activity, file access, and administrative changes cannot be reconstructed.

**Check:**
```powershell
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
# True = Satisfied
```

**Remediation:**
```powershell
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | AU-2, AU-12 |
| CIS M365 v3 | 2.3.1 |
| SCuBA EXO | MS.EXO.9.1v1 |
| CMMC 2.0 | AU.L2-3.3.1 |
| MITRE ATT&CK | T1562.008 |

---

### EXO-3.1 — Anti-Spam Policies Configured

**Criticality:** Medium

**Description:**
Inbound anti-spam policies must be active with bulk complaint level (BCL) threshold of 6 or lower, and quarantine action for high-confidence spam. Default policy thresholds must not be relaxed beyond baseline.

**Check:**
```powershell
Get-HostedContentFilterPolicy | Select-Object Name, BulkThreshold, SpamAction, HighConfidenceSpamAction
```

**Framework Mappings:**

| Framework | Control |
|---|---|
| NIST SP 800-53 | SI-8 |
| CIS M365 v3 | 2.1.7 |
| SCuBA Defender | MS.DEFENDER.1.4v1 |
| MITRE ATT&CK | T1566 |

---

## Related Baselines

- [Microsoft Entra ID](aad.md) — Identity and Conditional Access
- [Defender for Office 365](defender.md) — Anti-phishing and Safe Links/Attachments
